//! Driver-agnostic server handshake logic.
//!
//! The async and blocking drivers in `asynch.rs` and `blocking.rs` differ only
//! in how they read from and write to the transport. Everything else, parsing
//! the ClientHello, deriving keys, encoding the server flight, and validating
//! the client's response, lives here, so it is written once and fixed once.
//!
//! This mirrors how the client handshake is already structured: thin per-driver
//! dispatch over shared logic (see `connection::State::process`).

use crate::TlsError;
use crate::alert::{AlertDescription, AlertLevel};
use crate::config::{PrivateKey, TlsCipherSuite, TlsVerifier};
use crate::connection::decrypt_record;
use crate::crypto::TlsHash;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::handshake::ServerHandshake as ServerHandshakeMessage;
use crate::key_schedule::KeySchedule;
use crate::record::ServerRecord;
use crate::server::{
    MAX_KEY_SHARE, OwnedKeyShare, compute_ecdh, encode_certificate, encode_certificate_request,
    encode_certificate_verify, encode_encrypted_extensions, encode_finished,
    encode_hello_retry_request, encode_server_hello,
};
use crate::server_config::TlsServerConfig;
use crate::write_buffer::WriteBuffer;
use embassy_crypto::rng_fill_bytes;

/// A bare ChangeCipherSpec record, sent for middlebox compatibility
/// (RFC 8446 appendix D.4).
pub(crate) const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Key exchange groups this build can compute, in preference order.
const SERVER_GROUPS: &[NamedGroup] = &[NamedGroup::X25519, NamedGroup::Secp256r1];

/// (code point, bit) pairs for the signature schemes this crate can verify.
/// Single source of truth shared by the client-hello mask and validation.
const SIGALG_BITS: &[(u16, u8)] = &[
    (0x0403, 1 << 0),
    (0x0503, 1 << 1),
    (0x0807, 1 << 2),
    (0x0804, 1 << 3),
    (0x0805, 1 << 4),
    (0x0806, 1 << 5),
];

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
    did_hrr: bool,
    /// Group to name in a HelloRetryRequest: always one the client offered.
    retry_group: Option<NamedGroup>,
    server_public_key: heapless::Vec<u8, 65>,
    shared_secret: heapless::Vec<u8, 32>,
    group: NamedGroup,
    selected_alpn: Option<&'a [u8]>,
    client_hello_fingerprint: Option<<CipherSuite::Hash as TlsHash>::Output>,
    client_sigalg_mask: u8,
    traffic_hash: Option<CipherSuite::Hash>,
    requires_client_auth: bool,
    /// Transcript captured when the client's Certificate arrived; the
    /// CertificateVerify signature is computed over exactly this.
    client_cert_transcript: Option<CipherSuite::Hash>,
    client_cert_verified: bool,
}

impl<'a, CipherSuite: TlsCipherSuite> ServerHandshake<'a, CipherSuite> {
    pub(crate) fn new(config: &'a TlsServerConfig<'a>, requires_client_auth: bool) -> Self {
        Self {
            config,
            requires_client_auth,
            session_id: [0u8; 32],
            session_id_len: 0,
            key_share: None,
            did_hrr: false,
            retry_group: None,
            server_public_key: heapless::Vec::new(),
            shared_secret: heapless::Vec::new(),
            group: NamedGroup::Secp256r1,
            selected_alpn: None,
            client_hello_fingerprint: None,
            client_sigalg_mask: 0,
            traffic_hash: None,
            client_cert_transcript: None,
            client_cert_verified: false,
        }
    }

    pub(crate) fn did_hrr(&self) -> bool {
        self.did_hrr
    }

    fn client_sigalg_mask(
        ch: &crate::handshake::client_hello::ParsedClientHello<'_>,
    ) -> Result<u8, TlsError> {
        match ch.signature_algorithms {
            None | Some([]) => {
                return Err(TlsError::AbortHandshake(
                    AlertLevel::Fatal,
                    AlertDescription::MissingExtension,
                ));
            }
            _ => {}
        }
        let mut mask = 0u8;
        for &(code, bit) in SIGALG_BITS {
            if ch.offers_signature_scheme(code) {
                mask |= bit;
            }
        }
        Ok(mask)
    }

    /// Compact, fixed-size fingerprint of the ClientHello fields that must be
    /// identical between CH1 and CH2 (RFC 8446 4.1.2). Variable-length fields
    /// are hashed with a length prefix so bytes cannot shift between fields.
    fn client_hello_fingerprint(
        ch: &crate::handshake::client_hello::ParsedClientHello<'_>,
    ) -> <CipherSuite::Hash as TlsHash>::Output {
        let mut hash = CipherSuite::Hash::new();
        hash.update(&ch.random);

        hash.update(&(ch.session_id.len() as u16).to_be_bytes());
        hash.update(ch.session_id);

        hash.update(&(ch.cipher_suites.len() as u16).to_be_bytes());
        hash.update(ch.cipher_suites);

        hash.update(&(ch.supported_groups.len() as u16).to_be_bytes());
        for group in &ch.supported_groups {
            hash.update(&group.as_u16().to_be_bytes());
        }

        hash.update(&(ch.alpn_protocols.len() as u16).to_be_bytes());
        for proto in &ch.alpn_protocols {
            hash.update(&(proto.len() as u16).to_be_bytes());
            hash.update(proto);
        }

        match ch.signature_algorithms {
            Some(raw) => {
                hash.update(&(raw.len() as u16).to_be_bytes());
                hash.update(raw);
            }
            None => {
                hash.update(&0u16.to_be_bytes());
            }
        }

        hash.finalize()
    }

    pub(crate) fn validate_server_signature_scheme(
        &self,
        private_key: &crate::config::PrivateKey,
    ) -> Result<(), TlsError> {
        let Some(bit) = SIGALG_BITS.iter().find_map(|&(code, bit)| {
            if private_key.signature_scheme().as_u16() == code {
                Some(bit)
            } else {
                None
            }
        }) else {
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::HandshakeFailure,
            ));
        };
        if self.client_sigalg_mask & bit == 0 {
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::HandshakeFailure,
            ));
        }
        Ok(())
    }

    pub(crate) fn needs_hello_retry(&self) -> bool {
        self.key_share.is_none()
    }

    pub(crate) fn flight(&self) -> &'static [FlightRecord] {
        if self.requires_client_auth {
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
        defmt::info!("TLS server: step 1, reading ClientHello");

        let ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(ch)) = record else {
            return Err(TlsError::InvalidHandshake);
        };

        if !ch.offers(CipherSuite::CODE_POINT) {
            warn!("Client did not offer the server's cipher suite");
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::HandshakeFailure,
            ));
        }

        self.session_id_len = ch.session_id.len().min(32);
        self.session_id[..self.session_id_len]
            .copy_from_slice(&ch.session_id[..self.session_id_len]);

        // Select at absorb time: server preference order, choosing a protocol
        // the client also offered. The configured name outlives the handshake,
        // so only its reference is stored.
        if let Some(server_protocols) = self.config.alpn_protocols {
            for server_protocol in server_protocols {
                if ch.alpn_protocols.contains(server_protocol) {
                    self.selected_alpn = Some(*server_protocol);
                    break;
                }
            }
            // RFC 7301 3.2: if the client offered ALPN, the server has ALPN
            // configured, and nothing matches, the handshake must fail.
            if !ch.alpn_protocols.is_empty() && self.selected_alpn.is_none() {
                return Err(TlsError::AbortHandshake(
                    AlertLevel::Fatal,
                    AlertDescription::NoApplicationProtocol,
                ));
            }
        }

        self.client_sigalg_mask = Self::client_sigalg_mask(ch)?;

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

        self.client_hello_fingerprint = Some(Self::client_hello_fingerprint(ch));

        #[cfg(feature = "defmt")]
        defmt::info!(
            "TLS server: step 2, key_share found={}",
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

                // CH2's key_share must contain exactly the group named in the HRR.
                if ch.key_shares.len() != 1 || ch.key_shares[0].group != retry_group {
                    return Err(TlsError::AbortHandshake(
                        AlertLevel::Fatal,
                        AlertDescription::IllegalParameter,
                    ));
                }

                // Server's choices from CH1 must still be valid for CH2.
                if !ch.offers(CipherSuite::CODE_POINT) {
                    return Err(TlsError::AbortHandshake(
                        AlertLevel::Fatal,
                        AlertDescription::HandshakeFailure,
                    ));
                }
                if let Some(selected) = self.selected_alpn {
                    if !ch.alpn_protocols.contains(&selected) {
                        return Err(TlsError::AbortHandshake(
                            AlertLevel::Fatal,
                            AlertDescription::IllegalParameter,
                        ));
                    }
                }
                // missing_extension handled during CH1; keep CH2 consistent.
                self.client_sigalg_mask = Self::client_sigalg_mask(ch)?;

                // Invariant fields must be unchanged (RFC 8446 4.1.2).
                let finalized = Self::client_hello_fingerprint(ch);
                let fingerprint_mismatch = match self.client_hello_fingerprint {
                    Some(stored) => stored.as_ref() != finalized.as_ref(),
                    None => true,
                };
                if fingerprint_mismatch {
                    return Err(TlsError::AbortHandshake(
                        AlertLevel::Fatal,
                        AlertDescription::IllegalParameter,
                    ));
                }

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
        defmt::info!("TLS server: step 3, computing ECDH");

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
        defmt::info!("TLS server: step 4, sending ServerHello");

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
                let alpn: Option<&[u8]> = self.selected_alpn;
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_encrypted_extensions(buf, alpn)
                })?
            }
            FlightRecord::CertificateRequest => {
                let schemes = crate::server::verifiable_client_cert_schemes();
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_certificate_request(buf, schemes)
                })?
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
        let hash = key_schedule.transcript_hash().clone();
        self.traffic_hash = Some(hash.clone());
        key_schedule.capture_traffic_hash(hash);
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
    #[allow(clippy::extra_unused_type_parameters)]
    pub(crate) fn process_client_record<Verifier>(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        mut verifier: Option<&mut Verifier>,
        record: ServerRecord<'_, CipherSuite>,
    ) -> Result<bool, TlsError>
    where
        Verifier: TlsVerifier<CipherSuite>,
    {
        if let ServerRecord::ChangeCipherSpec(_) = &record {
            return Ok(false);
        }

        let mut finished_ok = false;
        let requires_client_auth = self.requires_client_auth;
        let client_cert_transcript = &mut self.client_cert_transcript;
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
                ServerRecord::Handshake(ServerHandshakeMessage::Certificate(certificate)) => {
                    let Some(verifier) = verifier.as_mut() else {
                        // Client auth was not requested, so nothing to check.
                        return Ok(());
                    };
                    // The CertificateVerify signature covers the transcript up
                    // to and including this Certificate message.
                    let transcript = key_schedule.transcript_hash().clone();

                    verifier.verify_certificate(&transcript, certificate)?;

                    *client_cert_transcript = Some(transcript);
                    Ok(())
                }
                ServerRecord::Handshake(ServerHandshakeMessage::CertificateVerify(verify)) => {
                    let Some(verifier) = verifier.as_mut() else {
                        return Ok(());
                    };
                    if client_cert_transcript.is_none() {
                        return Err(TlsError::AbortHandshake(
                            AlertLevel::Fatal,
                            AlertDescription::UnexpectedMessage,
                        ));
                    }
                    verifier.verify_signature(verify)?;
                    *client_cert_verified = true;
                    Ok(())
                }

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

#[cfg(all(test, feature = "server"))]
mod hrr_validation_tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use crate::handshake::client_hello::ParsedClientHello;
    use crate::parse_buffer::ParseBuffer;
    use crate::server_config::TlsServerConfig;

    fn build_client_hello(
        random: [u8; 32],
        cipher_suites: &[u16],
        alpn: &[&[u8]],
        key_share_groups: &[NamedGroup],
        supported_groups: &[NamedGroup],
        sigalgs: &[u16],
    ) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&crate::handshake::LEGACY_VERSION.to_be_bytes());
        out.extend_from_slice(&random);
        out.push(0); // session id
        out.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in cipher_suites {
            out.extend_from_slice(&suite.to_be_bytes());
        }
        out.extend_from_slice(&[0x01, 0x00]); // compression

        let mut extensions = std::vec::Vec::new();
        // supported_versions
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&0x0003u16.to_be_bytes());
        extensions.push(0x02);
        extensions.extend_from_slice(&[0x03, 0x04]);

        // supported_groups
        let mut sg = std::vec::Vec::new();
        for g in supported_groups {
            sg.extend_from_slice(&g.as_u16().to_be_bytes());
        }
        extensions.extend_from_slice(&0x000au16.to_be_bytes());
        extensions.extend_from_slice(&((sg.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(sg.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sg);

        // key_share
        let mut shares = std::vec::Vec::new();
        for group in key_share_groups {
            shares.extend_from_slice(&group.as_u16().to_be_bytes());
            shares.extend_from_slice(&0x0004u16.to_be_bytes());
            shares.extend_from_slice(&[0xAA; 4]);
        }
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&shares);

        // ALPN
        if !alpn.is_empty() {
            let mut proto_bytes = std::vec::Vec::new();
            for p in alpn {
                proto_bytes.push(p.len() as u8);
                proto_bytes.extend_from_slice(p);
            }
            let mut alpn_ext = std::vec::Vec::new();
            alpn_ext.extend_from_slice(&(proto_bytes.len() as u16).to_be_bytes());
            alpn_ext.extend_from_slice(&proto_bytes);
            extensions.extend_from_slice(&0x0010u16.to_be_bytes());
            extensions.extend_from_slice(&((alpn_ext.len()) as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_ext);
        }

        // signature_algorithms
        if !sigalgs.is_empty() {
            let mut sa = std::vec::Vec::new();
            for s in sigalgs {
                sa.extend_from_slice(&s.to_be_bytes());
            }
            extensions.extend_from_slice(&0x000du16.to_be_bytes());
            extensions.extend_from_slice(&((sa.len() + 2) as u16).to_be_bytes());
            extensions.extend_from_slice(&(sa.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sa);
        }

        out.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(&extensions);
        out
    }

    fn parse_ch(bytes: &[u8]) -> ParsedClientHello<'_> {
        let mut buf = ParseBuffer::new(bytes);
        ParsedClientHello::parse(&mut buf).unwrap()
    }

    #[test]
    fn hrr_unchanged_ch2_succeeds() {
        let random = [7u8; 32];
        let suites = [0x1301u16];
        let ch1 = build_client_hello(
            random,
            &suites,
            &[b"h2"],
            &[NamedGroup::Secp384r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );
        let ch2 = build_client_hello(
            random,
            &suites,
            &[b"h2"],
            &[NamedGroup::Secp256r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );

        let refs: &[&[u8]] = &[];
        let mut cfg = TlsServerConfig::new(refs);
        cfg = cfg.with_alpn(&[b"h2"]);
        let mut hs = ServerHandshake::<Aes128GcmSha256>::new(&cfg, false);

        let r1 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch1)));
        hs.absorb_client_hello(&r1).unwrap();
        assert!(hs.needs_hello_retry());

        let r2 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch2)));
        assert!(hs.absorb_hello_retry_response(&r2).unwrap());
    }

    #[test]
    fn hrr_changed_cipher_suites_rejected() {
        let random = [7u8; 32];
        let ch1 = build_client_hello(
            random,
            &[0x1301],
            &[b"h2"],
            &[NamedGroup::Secp384r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );
        let ch2 = build_client_hello(
            random,
            &[0x1302],
            &[b"h2"],
            &[NamedGroup::Secp256r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );

        let refs: &[&[u8]] = &[];
        let mut cfg = TlsServerConfig::new(refs);
        cfg = cfg.with_alpn(&[b"h2"]);
        let mut hs = ServerHandshake::<Aes128GcmSha256>::new(&cfg, false);

        let r1 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch1)));
        hs.absorb_client_hello(&r1).unwrap();

        let r2 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch2)));
        assert!(hs.absorb_hello_retry_response(&r2).is_err());
    }

    #[test]
    fn hrr_changed_random_rejected() {
        let ch1 = build_client_hello(
            [7u8; 32],
            &[0x1301],
            &[b"h2"],
            &[NamedGroup::Secp384r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );
        let ch2 = build_client_hello(
            [8u8; 32],
            &[0x1301],
            &[b"h2"],
            &[NamedGroup::Secp256r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );

        let refs: &[&[u8]] = &[];
        let mut cfg = TlsServerConfig::new(refs);
        cfg = cfg.with_alpn(&[b"h2"]);
        let mut hs = ServerHandshake::<Aes128GcmSha256>::new(&cfg, false);

        let r1 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch1)));
        hs.absorb_client_hello(&r1).unwrap();

        let r2 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch2)));
        assert!(hs.absorb_hello_retry_response(&r2).is_err());
    }

    #[test]
    fn hrr_changed_alpn_rejected() {
        let random = [7u8; 32];
        let ch1 = build_client_hello(
            random,
            &[0x1301],
            &[b"h2"],
            &[NamedGroup::Secp384r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );
        let ch2 = build_client_hello(
            random,
            &[0x1301],
            &[b"http/1.1"],
            &[NamedGroup::Secp256r1],
            &[NamedGroup::Secp384r1, NamedGroup::Secp256r1],
            &[0x0403],
        );

        let refs: &[&[u8]] = &[];
        let mut cfg = TlsServerConfig::new(refs);
        cfg = cfg.with_alpn(&[b"h2"]);
        let mut hs = ServerHandshake::<Aes128GcmSha256>::new(&cfg, false);

        let r1 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch1)));
        hs.absorb_client_hello(&r1).unwrap();

        let r2 = ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(parse_ch(&ch2)));
        assert!(hs.absorb_hello_retry_response(&r2).is_err());
    }
}
