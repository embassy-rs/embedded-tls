use core::marker::PhantomData;

use embassy_crypto::rng_fill_bytes;
use heapless::Vec;

#[cfg(not(feature = "x25519"))]
use embassy_crypto::p256::SecretKey;
#[cfg(feature = "x25519")]
use embassy_crypto::x25519::SecretKey;
#[cfg(all(feature = "mlkem"))]
use ml_kem::{DecapsulationKey, FromSeed, KeyExport, MlKem768};

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

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: SecretKey,
    #[cfg(feature = "mlkem")]
    pub(crate) kem: DecapsulationKey<MlKem768>,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'config TlsConfig<'config>) -> Result<Self, TlsError> {
        // RFC 9846, section 9.2: a ClientHello without a pre-shared key must offer signature
        // schemes, and a server that receives one without either aborts the handshake.
        if config.signature_schemes.is_empty() && config.psk.is_none() {
            return Err(TlsError::MissingPsk);
        }

        let mut random = [0; 32];
        rng_fill_bytes(&mut random);

        let secret = SecretKey::generate().map_err(|_| TlsError::CryptoError)?;

        #[cfg(feature = "mlkem")]
        let mut kem_seed = [0; 64];
        #[cfg(feature = "mlkem")]
        rng_fill_bytes(&mut kem_seed);
        #[cfg(feature = "mlkem")]
        let kem = MlKem768::from_seed(&kem_seed.into()).0;

        Ok(Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret,
            #[cfg(feature = "mlkem")]
            kem,
        })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
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

            // RFC 9846, section 4.3.3: only a client that wants a certificate sends this, and an
            // empty list is malformed. A build without signature features is PSK-only.
            if !self.config.signature_schemes.is_empty() {
                ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                    supported_signature_algorithms: self.config.signature_schemes.clone(),
                })
                .encode(buf)?;
            }

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

            self.encode_key_share(buf)?;

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

    fn encode_key_share(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        #[cfg(not(feature = "x25519"))]
        let public_key = self
            .secret
            .public_key()
            .map_err(|_| TlsError::CryptoError)?
            .to_sec1();
        #[cfg(feature = "x25519")]
        let public_key = self
            .secret
            .public_key()
            .map_err(|_| TlsError::CryptoError)?
            .to_bytes();

        // concat(pubkey + ek) for SecP256r1MlKem768 (65+1184 = 1249 bytes)
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        let mut hybrid: Vec<u8, 1249> = Vec::new();
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        hybrid.extend_from_slice(&public_key).unwrap();
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        hybrid.extend(self.kem.encapsulation_key().to_bytes());

        // concat(ek + pubkey) for x25519MlKem768 (1184+32 = 1216 bytes)
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        let mut hybrid: Vec<u8, 1216> = Vec::new();
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        hybrid.extend(self.kem.encapsulation_key().to_bytes());
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        hybrid.extend_from_slice(&public_key).unwrap();

        ClientHelloExtension::KeyShare(KeyShareClientHello {
            client_shares: Vec::from_slice(&[
                #[cfg(not(feature = "x25519"))]
                KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: &public_key,
                },
                #[cfg(all(feature = "mlkem", not(feature = "x25519")))]
                KeyShareEntry {
                    group: NamedGroup::SecP256r1MLKEM768,
                    opaque: &hybrid,
                },
                #[cfg(feature = "x25519")]
                KeyShareEntry {
                    group: NamedGroup::X25519,
                    opaque: &public_key,
                },
                #[cfg(all(feature = "mlkem", feature = "x25519"))]
                KeyShareEntry {
                    group: NamedGroup::X25519MLKEM768,
                    opaque: &hybrid,
                },
            ])
            .unwrap(),
        })
        .encode(buf)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use crate::extensions::ExtensionType;
    use crate::extensions::extension_data::signature_algorithms::SignatureScheme;

    /// The extension types in the `ClientHello` that `config` produces, in order.
    fn extension_types(config: &TlsConfig) -> std::vec::Vec<u16> {
        let hello = ClientHello::<Aes128GcmSha256>::new(config).unwrap();
        let mut bytes = [0; 4096];
        let mut buf = CryptoBuffer::wrap(&mut bytes);
        hello.encode(&mut buf).unwrap();
        // The version, random, empty session ID, one cipher suite, one compression method and
        // the extensions' length come first.
        let mut extensions = &buf.as_slice()[2 + 32 + 1 + 4 + 2 + 2..];
        let mut types = std::vec::Vec::new();
        while let [high, low, len_high, len_low, rest @ ..] = extensions {
            types.push(u16::from_be_bytes([*high, *low]));
            extensions = &rest[usize::from(u16::from_be_bytes([*len_high, *len_low]))..];
        }
        types
    }

    #[test]
    fn signature_algorithms_is_left_out_when_no_scheme_is_enabled() {
        let mut config = TlsConfig::new().with_psk(&[0; 32], &[b"client"]);
        config.signature_schemes.clear();
        assert!(!extension_types(&config).contains(&(ExtensionType::SignatureAlgorithms as u16)));
    }

    // RFC 9846, section 9.2: a ClientHello without a pre-shared key must offer signature schemes.
    #[test]
    fn client_hello_without_a_scheme_or_a_pre_shared_key_is_refused() {
        let mut config = TlsConfig::new();
        config.signature_schemes.clear();
        assert!(matches!(
            ClientHello::<Aes128GcmSha256>::new(&config),
            Err(TlsError::MissingPsk)
        ));
    }

    #[test]
    fn signature_algorithms_is_sent_when_a_scheme_is_enabled() {
        let mut config = TlsConfig::new();
        config.signature_schemes.clear();
        config
            .signature_schemes
            .push(SignatureScheme::Ed25519)
            .unwrap();
        assert!(extension_types(&config).contains(&(ExtensionType::SignatureAlgorithms as u16)));
    }
}
