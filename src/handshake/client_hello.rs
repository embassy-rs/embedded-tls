use core::marker::PhantomData;

use embassy_crypto::p256::SecretKey;
use embassy_crypto::rng_fill_bytes;
use heapless::Vec;

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::crypto::{ByteArray, TlsHash};
use crate::extensions::extension_data::alpn::AlpnProtocolNameList;
use crate::extensions::extension_data::key_share::{KeyShareClientHello, KeyShareEntry};
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyClientHello;
use crate::extensions::extension_data::psk_key_exchange_modes::{
    PskKeyExchangeMode, PskKeyExchangeModes,
};
use crate::extensions::extension_data::server_name::ServerNameList;
use crate::extensions::extension_data::signature_algorithms::SignatureAlgorithms;
use crate::extensions::extension_data::supported_groups::{NamedGroup, SupportedGroups};
use crate::extensions::extension_data::supported_versions::{SupportedVersionsClientHello, TLS13};
use crate::extensions::messages::ClientHelloExtension;
use crate::handshake::{LEGACY_VERSION, Random};
use crate::key_schedule::{HashOutput, WriteKeySchedule};
#[cfg(feature = "server")]
use crate::parse_buffer::ParseBuffer;

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: SecretKey,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'config TlsConfig<'config>) -> Result<Self, TlsError> {
        let mut random = [0; 32];
        rng_fill_bytes(&mut random);

        let secret = SecretKey::generate().map_err(|_| TlsError::CryptoError)?;

        Ok(Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret,
        })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        let public_key = self
            .secret
            .public_key()
            .map_err(|_| TlsError::CryptoError)?
            .to_sec1();

        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.random)
            .map_err(|_| TlsError::EncodeError)?;

        // session id (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // cipher suites (2+)
        buf.push_u16(2).map_err(|_| TlsError::EncodeError)?;
        buf.push_u16(CipherSuite::CODE_POINT)
            .map_err(|_| TlsError::EncodeError)?;

        // compression methods, 1 byte of 0
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions (1+)
        buf.with_u16_length(|buf| {
            // Section 4.2.1.  Supported Versions
            // Implementations of this specification MUST send this extension in the
            // ClientHello containing all versions of TLS which they are prepared to
            // negotiate
            ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: self.config.signature_schemes.clone(),
            })
            .encode(buf)?;

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientHelloExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientHelloExtension::SupportedGroups(SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            })
            .encode(buf)?;

            ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::KeyShare(KeyShareClientHello {
                client_shares: Vec::from_slice(&[KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: &public_key,
                }])
                .unwrap(),
            })
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                let mut protos = Vec::new();
                for p in alpn_protocols {
                    // Surfacing the overflow matters: silently dropping the
                    // extras would negotiate against a list the caller never
                    // asked for.
                    protos.push(*p).map_err(|_| TlsError::OutOfMemory)?;
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: protos,
                })
                .encode(buf)?;
            }

            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            if let Some((_, identities)) = &self.config.psk {
                ClientHelloExtension::PreSharedKey(PreSharedKeyClientHello {
                    identities: identities.clone(),
                    hash_size: HashOutput::<CipherSuite>::LEN,
                })
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn finalize(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        // Special case for PSK which needs to:
        //
        // 1. Add the client hello without the binders to the transcript
        // 2. Create the binders for each identity using the transcript
        // 3. Add the rest of the client hello.
        //
        // This causes a few issues since lengths must be correctly inside the payload,
        // but won't actually be added to the record buffer until the end.
        if let Some((_, identities)) = &self.config.psk {
            let binders_len = identities.len() * (1 + HashOutput::<CipherSuite>::LEN);

            let binders_pos = enc_buf.len() - binders_len;

            // NOTE: Exclude the binders_len itself from the digest
            transcript.update(&enc_buf[0..binders_pos - 2]);

            // Append after the client hello data. Sizes have already been set.
            let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
            // Create a binder and encode for each identity
            for _id in identities {
                let binder = write_key_schedule.create_psk_binder(transcript)?;
                binder.encode(&mut buf)?;
            }

            transcript.update(&enc_buf[binders_pos - 2..]);
        } else {
            transcript.update(enc_buf);
        }

        Ok(())
    }
}
/// Parsed `ClientHello` for server-side processing.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "server")]
pub struct ParsedClientHello<'a> {
    pub session_id: &'a [u8],
    /// Cipher suite code points the client offered, so the server can check
    /// its own suite is among them before naming it in the ServerHello.
    pub cipher_suites: Vec<u16, 16>,
    /// Groups the client says it supports, so a HelloRetryRequest can name one
    /// of them rather than a group the client never offered.
    pub supported_groups: Vec<NamedGroup, 16>,
    pub key_shares: Vec<KeyShareEntry<'a>, 4>,
    pub alpn_protocols: Vec<&'a [u8], 4>,
}

#[cfg(feature = "server")]
impl<'a> ParsedClientHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let legacy_version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;
        if legacy_version != LEGACY_VERSION {
            return Err(TlsError::InvalidHandshake);
        }

        // Random (skip, not needed by server currently)
        buf.slice(32).map_err(|_| TlsError::InvalidHandshake)?;

        // Session ID
        let session_id_len = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;
        let session_id = buf
            .slice(session_id_len as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?
            .as_slice();

        // Cipher suites. Retained rather than skipped: the server must not
        // name a suite in its ServerHello that the client did not offer.
        let cipher_suites_len = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)? as usize;
        let mut suites_buf = buf
            .slice(cipher_suites_len)
            .map_err(|_| TlsError::InvalidHandshake)?;
        let mut cipher_suites = Vec::new();
        while !suites_buf.is_empty() {
            let code_point = suites_buf
                .read_u16()
                .map_err(|_| TlsError::InvalidHandshake)?;
            // Overflow past capacity is not an error: the server only needs to
            // find its own suite, and a client offering more than 16 has
            // already offered it if it is going to.
            let _ = cipher_suites.push(code_point);
        }

        // Compression methods
        let compression_len = buf.read_u8().map_err(|_| TlsError::InvalidHandshake)?;
        buf.slice(compression_len as usize)
            .map_err(|_| TlsError::InvalidHandshake)?;

        // Extensions
        let extensions = ClientHelloExtension::parse_vector::<24>(buf)?;

        let mut key_shares = Vec::new();
        let mut supported_groups = Vec::new();
        let mut alpn_protocols = Vec::new();
        let mut has_tls13 = false;

        for ext in &extensions {
            match ext {
                ClientHelloExtension::KeyShare(ks) => {
                    for share in &ks.client_shares {
                        // Only retain groups this build can actually compute.
                        // A client leading with post-quantum hybrids would
                        // otherwise fill every slot with unusable groups and
                        // crowd out the usable share behind them, forcing a
                        // needless HelloRetryRequest.
                        let usable =
                            matches!(share.group, NamedGroup::Secp256r1 | NamedGroup::X25519);
                        if usable {
                            let _ = key_shares.push(share.clone());
                        }
                    }
                }
                ClientHelloExtension::SupportedGroups(sg) => {
                    for group in &sg.supported_groups {
                        let _ = supported_groups.push(*group);
                    }
                }
                ClientHelloExtension::SupportedVersions(sv) => {
                    for v in &sv.versions {
                        if *v == TLS13 {
                            has_tls13 = true;
                        }
                    }
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    for proto in &alpn.protocols {
                        let _ = alpn_protocols.push(*proto);
                    }
                }
                _ => {}
            }
        }

        if !has_tls13 {
            return Err(TlsError::InvalidSupportedVersions);
        }

        Ok(Self {
            session_id,
            cipher_suites,
            supported_groups,
            key_shares,
            alpn_protocols,
        })
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.3 ClientHello carrying `key_share` entries for
    /// `groups`, in order. Key exchange payloads are dummy bytes: parsing does
    /// not inspect them.
    fn client_hello_with_key_share_groups(groups: &[NamedGroup]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        out.extend_from_slice(&[0u8; 32]); // random
        out.push(0); // empty session id
        out.extend_from_slice(&[0x00, 0x02]); // cipher_suites length
        out.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        out.extend_from_slice(&[0x01, 0x00]); // one null compression method

        // supported_versions: u16 vector of one u16 version, u8-length-prefixed
        let mut extensions = std::vec::Vec::new();
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&0x0003u16.to_be_bytes());
        extensions.push(0x02);
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

        // key_share: u16 vector of (group u16, u16-length-prefixed opaque)
        let mut shares = std::vec::Vec::new();
        for group in groups {
            shares.extend_from_slice(&group.as_u16().to_be_bytes());
            shares.extend_from_slice(&0x0004u16.to_be_bytes());
            shares.extend_from_slice(&[0xAA; 4]);
        }
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&shares);

        out.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(&extensions);
        out
    }

    #[test]
    fn then_unusable_key_share_groups_are_not_retained() {
        // P-384 is a group this server cannot compute. Retaining it would let a
        // client fill the key share capacity with groups the server has to
        // discard, crowding out the usable share behind them.
        let bytes =
            client_hello_with_key_share_groups(&[NamedGroup::Secp384r1, NamedGroup::X25519]);
        let mut buf = ParseBuffer::new(&bytes);

        let hello = ParsedClientHello::parse(&mut buf).expect("parses");

        const EXPECTED_RETAINED: usize = 1;
        assert_eq!(hello.key_shares.len(), EXPECTED_RETAINED);
        assert_eq!(hello.key_shares[0].group, NamedGroup::X25519);
    }

    #[test]
    fn then_offered_cipher_suites_are_retained() {
        let bytes = client_hello_with_key_share_groups(&[NamedGroup::Secp256r1]);
        let mut buf = ParseBuffer::new(&bytes);

        let hello = ParsedClientHello::parse(&mut buf).expect("parses");

        const EXPECTED_SUITE: u16 = 0x1301;
        assert!(hello.cipher_suites.contains(&EXPECTED_SUITE));
    }
}
