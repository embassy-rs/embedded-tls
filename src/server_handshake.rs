//! Driver-agnostic server handshake logic.
//!
//! The async and blocking drivers in `asynch.rs` and `blocking.rs` differ only
//! in how they read from and write to the transport. Everything else — parsing
//! the ClientHello, deriving keys, encoding the server flight, and validating
//! the client's response — lives here, so it is written once and fixed once.
//!
//! This mirrors how the client handshake is already structured: thin per-driver
//! dispatch over shared logic (see `connection::State::process`).

use crate::TlsError;
use crate::alert::{AlertDescription, AlertLevel};
use crate::config::{PrivateKey, TlsCipherSuite};
use crate::connection::decrypt_record;
use crate::crypto::TlsHash;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::handshake::ServerHandshake as ServerHandshakeMessage;
#[cfg(feature = "rustpki")]
use crate::handshake::certificate::{
    Certificate as OwnedCertificate, CertificateRef as ClientCertificate,
};
use crate::key_schedule::KeySchedule;
use crate::record::ServerRecord;
use crate::server::{
    MAX_ALPN_NAME, MAX_KEY_SHARE, OwnedAlpn, OwnedKeyShare, compute_ecdh, encode_certificate,
    encode_certificate_request, encode_certificate_verify, encode_encrypted_extensions,
    encode_finished, encode_hello_retry_request, encode_server_hello,
};
use crate::server_config::TlsServerConfig;
#[cfg(feature = "rustpki")]
use crate::server_verify::{verify_client_certificate, verify_client_signature};
use crate::write_buffer::WriteBuffer;
use embassy_crypto::rng_fill_bytes;

/// A bare ChangeCipherSpec record, sent for middlebox compatibility
/// (RFC 8446 appendix D.4).
pub(crate) const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Key exchange groups this build can compute, in preference order.
const SERVER_GROUPS: &[NamedGroup] = &[NamedGroup::X25519, NamedGroup::Secp256r1];

/// Capacity for the client's certificate chain. Two kilobytes holds a typical
/// P-256 leaf plus one intermediate; a larger chain is rejected with
/// `OutOfMemory` rather than silently truncated.
#[cfg(feature = "rustpki")]
const CLIENT_CERT_SIZE: usize = 2048;

/// One record of the server flight, in the order they are sent.
#[derive(Clone, Copy)]
pub(crate) enum FlightRecord {
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

const FLIGHT_WITH_CLIENT_AUTH: [FlightRecord; 5] = [
    FlightRecord::EncryptedExtensions,
    FlightRecord::CertificateRequest,
    FlightRecord::Certificate,
    FlightRecord::CertificateVerify,
    FlightRecord::Finished,
];

const FLIGHT: [FlightRecord; 4] = [
    FlightRecord::EncryptedExtensions,
    FlightRecord::Certificate,
    FlightRecord::CertificateVerify,
    FlightRecord::Finished,
];

/// Bytes ready for the transport, plus whether sending them advances the
/// write sequence counter. Only encrypted records do.
pub(crate) struct Outgoing<'b> {
    pub bytes: &'b [u8],
    pub encrypted: bool,
}

/// Server-side handshake state that outlives individual records.
///
/// The record buffer is reused between reads, so anything taken from a
/// ClientHello must be copied out before the next read.
pub(crate) struct ServerHandshake<'a, CipherSuite: TlsCipherSuite> {
    config: &'a TlsServerConfig<'a>,
    session_id: [u8; 32],
    session_id_len: usize,
    key_share: Option<OwnedKeyShare>,
    alpn: OwnedAlpn,
    did_hrr: bool,
    /// Group to name in a HelloRetryRequest: always one the client offered.
    retry_group: Option<NamedGroup>,
    server_public_key: heapless::Vec<u8, 65>,
    shared_secret: heapless::Vec<u8, 32>,
    group: NamedGroup,
    selected_alpn: Option<usize>,
    traffic_hash: Option<CipherSuite::Hash>,
    /// Owned copy of the client's certificate. The record buffer is reused
    /// between reads, so it cannot be borrowed until the CertificateVerify.
    #[cfg(feature = "rustpki")]
    client_certificate: Option<OwnedCertificate<CLIENT_CERT_SIZE>>,
    /// Transcript captured when the client's Certificate arrived; the
    /// CertificateVerify signature is computed over exactly this.
    #[cfg(feature = "rustpki")]
    client_cert_transcript: Option<CipherSuite::Hash>,
    client_cert_verified: bool,
}

impl<'a, CipherSuite: TlsCipherSuite> ServerHandshake<'a, CipherSuite> {
    pub(crate) fn new(config: &'a TlsServerConfig<'a>) -> Self {
        Self {
            config,
            session_id: [0u8; 32],
            session_id_len: 0,
            key_share: None,
            alpn: OwnedAlpn::new(),
            did_hrr: false,
            retry_group: None,
            server_public_key: heapless::Vec::new(),
            shared_secret: heapless::Vec::new(),
            group: NamedGroup::Secp256r1,
            selected_alpn: None,
            traffic_hash: None,
            #[cfg(feature = "rustpki")]
            client_certificate: None,
            #[cfg(feature = "rustpki")]
            client_cert_transcript: None,
            client_cert_verified: false,
        }
    }

    pub(crate) fn did_hrr(&self) -> bool {
        self.did_hrr
    }

    pub(crate) fn needs_hello_retry(&self) -> bool {
        self.key_share.is_none()
    }

    pub(crate) fn flight(&self) -> &'static [FlightRecord] {
        if self.config.client_auth_ca.is_some() {
            &FLIGHT_WITH_CLIENT_AUTH
        } else {
            &FLIGHT
        }
    }

    /// Copy everything the server needs out of the ClientHello before the
    /// record buffer is reused.
    pub(crate) fn absorb_client_hello(
        &mut self,
        record: &ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError> {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 1 — reading ClientHello");

        let ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(ch)) = record else {
            return Err(TlsError::InvalidHandshake);
        };

        if !ch.cipher_suites.contains(&CipherSuite::CODE_POINT) {
            warn!("Client did not offer the server's cipher suite");
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::HandshakeFailure,
            ));
        }

        self.session_id_len = ch.session_id.len().min(32);
        self.session_id[..self.session_id_len]
            .copy_from_slice(&ch.session_id[..self.session_id_len]);

        for proto in &ch.alpn_protocols {
            if self.alpn.count >= 4 {
                break;
            }
            if proto.len() > MAX_ALPN_NAME {
                // Not a legal ALPN name; skip it rather than store a prefix
                // that could half-match one of ours.
                continue;
            }
            let len = proto.len();
            self.alpn.data[self.alpn.count][..len].copy_from_slice(proto);
            self.alpn.lens[self.alpn.count] = len;
            self.alpn.count += 1;
        }

        // Prefer X25519, then P-256.
        self.key_share = take_key_share(ch, NamedGroup::X25519);
        if self.key_share.is_none() {
            self.key_share = take_key_share(ch, NamedGroup::Secp256r1);
        }

        // RFC 8446 4.1.4: a HelloRetryRequest must name a group the client
        // actually offered, so pick from the intersection now.
        self.retry_group = SERVER_GROUPS
            .iter()
            .find(|group| ch.supported_groups.contains(group))
            .copied();

        #[cfg(feature = "defmt")]
        defmt::info!(
            "TLS server: step 2 — key_share found={}",
            self.key_share.is_some()
        );

        Ok(())
    }

    /// Encode a HelloRetryRequest asking the client to retry with P-256.
    pub(crate) fn encode_hello_retry_request<'b>(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError> {
        let retry_group = self.retry_group.ok_or(TlsError::AbortHandshake(
            AlertLevel::Fatal,
            AlertDescription::HandshakeFailure,
        ))?;

        key_schedule.replace_transcript_with_message_hash()?;
        self.did_hrr = true;

        let session_id = &self.session_id[..self.session_id_len];
        let (wks, rks) = key_schedule.as_split();
        let bytes = tx_buf.write_handshake_record(false, wks, rks.transcript_hash(), |buf| {
            encode_hello_retry_request(buf, session_id, CipherSuite::CODE_POINT, retry_group)
        })?;

        Ok(Outgoing {
            bytes,
            encrypted: false,
        })
    }

    /// Handle a record received after a HelloRetryRequest. Returns true once a
    /// usable ClientHello has been absorbed.
    pub(crate) fn absorb_hello_retry_response(
        &mut self,
        record: &ServerRecord<'_, CipherSuite>,
    ) -> Result<bool, TlsError> {
        match record {
            ServerRecord::ChangeCipherSpec(_) => Ok(false),
            ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(ch)) => {
                let retry_group = self.retry_group.ok_or(TlsError::InvalidKeyShare)?;
                self.key_share = take_key_share(ch, retry_group);
                if self.key_share.is_none() {
                    return Err(TlsError::InvalidKeyShare);
                }
                Ok(true)
            }
            _ => Err(TlsError::InvalidHandshake),
        }
    }

    /// Perform the key exchange and initialise the early secret.
    pub(crate) fn compute_keys(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 3 — computing ECDH");

        let key_share = self.key_share.as_ref().ok_or(TlsError::InvalidKeyShare)?;
        let entry = KeyShareEntry {
            group: key_share.group,
            opaque: &key_share.bytes[..key_share.len],
        };
        let (public_key, shared_secret, group) = compute_ecdh(&entry)?;

        self.server_public_key = public_key;
        self.shared_secret = shared_secret;
        self.group = group;

        key_schedule.initialize_early_secret(None)
    }

    /// Encode the ServerHello. Sent unencrypted, so it does not advance the
    /// write sequence counter.
    pub(crate) fn encode_server_hello<'b>(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError> {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 4 — sending ServerHello");

        let mut server_random = [0u8; 32];
        rng_fill_bytes(&mut server_random);

        let session_id = &self.session_id[..self.session_id_len];
        let public_key = &self.server_public_key;
        let group = self.group;

        let (wks, rks) = key_schedule.as_split();
        let bytes = tx_buf.write_handshake_record(false, wks, rks.transcript_hash(), |buf| {
            encode_server_hello(
                buf,
                &server_random,
                session_id,
                CipherSuite::CODE_POINT,
                public_key,
                group,
            )
        })?;

        Ok(Outgoing {
            bytes,
            encrypted: false,
        })
    }

    pub(crate) fn init_handshake_secret(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        key_schedule.initialize_handshake_secret_server(&self.shared_secret)
    }

    /// Pick the first server protocol the client also offered.
    pub(crate) fn negotiate_alpn(&mut self) {
        let Some(server_protocols) = self.config.alpn_protocols else {
            return;
        };
        for server_protocol in server_protocols {
            for i in 0..self.alpn.count {
                if *server_protocol == &self.alpn.data[i][..self.alpn.lens[i]] {
                    self.selected_alpn = Some(i);
                    return;
                }
            }
        }
    }

    /// Encode one record of the server flight. All are encrypted, so all
    /// advance the write sequence counter.
    pub(crate) fn encode_flight_record<'b>(
        &mut self,
        which: FlightRecord,
        private_key: &PrivateKey,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError> {
        let bytes = match which {
            FlightRecord::EncryptedExtensions => {
                let alpn: Option<&[u8]> = self
                    .selected_alpn
                    .map(|i| &self.alpn.data[i][..self.alpn.lens[i]] as &[u8]);
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_encrypted_extensions(buf, alpn)
                })?
            }
            FlightRecord::CertificateRequest => {
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(
                    true,
                    wks,
                    rks.transcript_hash(),
                    encode_certificate_request,
                )?
            }
            FlightRecord::Certificate => {
                let cert_chain = self.config.cert_chain;
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_certificate(buf, cert_chain)
                })?
            }
            FlightRecord::CertificateVerify => {
                let transcript_hash = key_schedule.transcript_hash().clone().finalize();
                let signature_scheme = private_key.signature_scheme();

                let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
                let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
                msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
                msg.extend_from_slice(ctx_str)
                    .map_err(|_| TlsError::EncodeError)?;
                msg.extend_from_slice(transcript_hash.as_ref())
                    .map_err(|_| TlsError::EncodeError)?;

                // 146 bytes covers the longest signature the built-in keys
                // produce: RSA-2048 PSS at 256 would not fit, but RSA is not a
                // supported server key here.
                let mut signature: heapless::Vec<u8, 146> = heapless::Vec::new();
                private_key.sign(&msg, &mut signature)?;
                let signature_bytes = signature.as_slice();

                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_certificate_verify(buf, signature_scheme.as_u16(), signature_bytes)
                })?
            }
            FlightRecord::Finished => {
                let finished = key_schedule.create_client_finished()?;
                let verify_data: heapless::Vec<u8, 64> =
                    heapless::Vec::from_slice(finished.verify.as_ref())
                        .map_err(|_| TlsError::EncodeError)?;
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_finished(buf, &verify_data)
                })?
            }
        };

        Ok(Outgoing {
            bytes,
            encrypted: true,
        })
    }

    /// Capture the transcript at the end of the server flight; the application
    /// traffic secrets are derived from it, not from the post-client-Finished
    /// transcript.
    pub(crate) fn capture_traffic_hash(&mut self, key_schedule: &mut KeySchedule<CipherSuite>) {
        self.traffic_hash = Some(key_schedule.transcript_hash().clone());
    }

    /// Process one record of the client's response. Returns true once the
    /// client's Finished has been verified.
    /// Process one record of the client's response. Returns true once the
    /// client's Finished has been verified.
    ///
    /// When mutual TLS is required, the client's Certificate must chain to the
    /// configured trust anchor and its CertificateVerify must prove possession
    /// of the matching private key. A client that sends neither, or only one of
    /// the two, is rejected.
    pub(crate) fn process_client_record(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        record: ServerRecord<'_, CipherSuite>,
    ) -> Result<bool, TlsError> {
        if let ServerRecord::ChangeCipherSpec(_) = &record {
            return Ok(false);
        }

        let mut finished_ok = false;
        let requires_client_auth = self.config.client_auth_ca.is_some();
        #[cfg(feature = "rustpki")]
        let trust_anchor = self.config.client_auth_ca;
        #[cfg(feature = "rustpki")]
        let client_certificate = &mut self.client_certificate;
        #[cfg(feature = "rustpki")]
        let client_cert_transcript = &mut self.client_cert_transcript;
        #[cfg(feature = "rustpki")]
        let client_cert_verified = &mut self.client_cert_verified;

        decrypt_record(
            key_schedule.read_state(),
            record,
            |key_schedule, record| match record {
                ServerRecord::Handshake(ServerHandshakeMessage::Finished(finished)) => {
                    if !key_schedule.verify_server_finished(&finished)? {
                        warn!("Client Finished verification failed");
                        return Err(TlsError::InvalidSignature);
                    }
                    finished_ok = true;
                    Ok(())
                }
                #[cfg(feature = "rustpki")]
                ServerRecord::Handshake(ServerHandshakeMessage::Certificate(certificate)) => {
                    let Some(trust_anchor) = trust_anchor else {
                        // Client auth was not requested, so nothing to check.
                        return Ok(());
                    };
                    verify_client_certificate::<crate::config::NoClock>(
                        trust_anchor,
                        &certificate,
                    )?;
                    // The record buffer is reused, so the certificate has to be
                    // copied out before the CertificateVerify is processed.
                    *client_certificate = Some(certificate.try_into()?);
                    // The CertificateVerify signature covers the transcript up
                    // to and including this Certificate message.
                    *client_cert_transcript = Some(key_schedule.transcript_hash().clone());
                    Ok(())
                }
                #[cfg(feature = "rustpki")]
                ServerRecord::Handshake(ServerHandshakeMessage::CertificateVerify(verify)) => {
                    if trust_anchor.is_none() {
                        return Ok(());
                    }
                    let transcript =
                        client_cert_transcript
                            .as_ref()
                            .ok_or(TlsError::AbortHandshake(
                                AlertLevel::Fatal,
                                AlertDescription::UnexpectedMessage,
                            ))?;
                    let stored = client_certificate.as_ref().ok_or(TlsError::AbortHandshake(
                        AlertLevel::Fatal,
                        AlertDescription::UnexpectedMessage,
                    ))?;
                    let certificate: ClientCertificate<'_> = stored.try_into()?;
                    verify_client_signature::<CipherSuite>(transcript, &certificate, &verify)?;
                    *client_cert_verified = true;
                    Ok(())
                }
                #[cfg(not(feature = "rustpki"))]
                ServerRecord::Handshake(ServerHandshakeMessage::Certificate(_)) => Ok(()),
                #[cfg(not(feature = "rustpki"))]
                ServerRecord::Handshake(ServerHandshakeMessage::CertificateVerify(_)) => Ok(()),
                ServerRecord::ChangeCipherSpec(_) => Ok(()),
                _ => Err(TlsError::InvalidHandshake),
            },
        )?;

        if finished_ok && requires_client_auth && !self.client_cert_verified {
            // Client auth was required, but the client never presented a
            // certificate it could prove possession of.
            warn!("Client did not complete certificate authentication");
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::CertificateRequired,
            ));
        }

        Ok(finished_ok)
    }

    pub(crate) fn finalize(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        let traffic_hash = self.traffic_hash.take().ok_or(TlsError::InternalError)?;
        key_schedule.replace_transcript_hash(traffic_hash);
        key_schedule.initialize_master_secret_server()
    }
}

/// Copy the first key share for `group` out of the ClientHello.
fn take_key_share(
    client_hello: &crate::handshake::client_hello::ParsedClientHello<'_>,
    group: NamedGroup,
) -> Option<OwnedKeyShare> {
    for share in &client_hello.key_shares {
        if share.group == group {
            // Reject rather than truncate: a truncated 65-byte prefix of a
            // longer opaque can still parse as a valid uncompressed point, so
            // truncating would accept a malformed key_share.
            if share.opaque.len() > MAX_KEY_SHARE {
                return None;
            }
            let len = share.opaque.len();
            let mut key_share = OwnedKeyShare {
                group,
                bytes: [0u8; MAX_KEY_SHARE],
                len,
            };
            key_share.bytes[..len].copy_from_slice(share.opaque);
            return Some(key_share);
        }
    }
    None
}

/// Map a handshake failure onto the alert the peer should be told about.
///
/// Returns `None` for transport failures: the connection is already gone, so
/// there is nothing left to send an alert down.
pub(crate) fn alert_for(error: &TlsError) -> Option<(AlertLevel, AlertDescription)> {
    match error {
        TlsError::Io(_) | TlsError::ConnectionClosed => None,
        TlsError::AbortHandshake(level, description) => Some((*level, *description)),
        TlsError::InvalidSupportedVersions => {
            Some((AlertLevel::Fatal, AlertDescription::ProtocolVersion))
        }
        TlsError::InvalidCertificate | TlsError::InvalidCertificateEntry => {
            Some((AlertLevel::Fatal, AlertDescription::BadCertificate))
        }
        TlsError::InvalidSignature => Some((AlertLevel::Fatal, AlertDescription::DecryptError)),
        TlsError::DecodeError | TlsError::ParseError(_) => {
            Some((AlertLevel::Fatal, AlertDescription::DecodeError))
        }
        TlsError::InvalidKeyShare | TlsError::InvalidHandshake => {
            Some((AlertLevel::Fatal, AlertDescription::IllegalParameter))
        }
        _ => Some((AlertLevel::Fatal, AlertDescription::HandshakeFailure)),
    }
}
