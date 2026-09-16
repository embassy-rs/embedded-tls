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
    #[cfg(not(feature = "x25519"))]
    pub(crate) secret: SecretKey,
    #[cfg(feature = "x25519")]
    pub(crate) secret: SecretKey,
    #[cfg(feature = "mlkem")]
    pub(crate) kem: DecapsulationKey<MlKem768>,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'config TlsConfig<'config>) -> Result<Self, TlsError> {
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
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: alpn_protocols,
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
