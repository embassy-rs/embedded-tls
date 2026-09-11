use heapless::Vec;

use crate::cipher_suites::CipherSuite;
use crate::connection::KeyExchangeSecret;
use crate::crypto_engine::CryptoEngine;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::extensions::messages::ServerHelloExtension;
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};
#[cfg(feature = "mlkem")]
use ml_kem::Decapsulate;
use p256::ecdh::EphemeralSecret;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHello<'a>, TlsError> {
        //let mut buf = ParseBuffer::new(&buf[0..content_length]);
        //let mut buf = ParseBuffer::new(&buf);

        let _version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random)?;

        let session_id_length = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        //info!("sh 1");

        let session_id = buf
            .slice(session_id_length as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?;
        //info!("sh 2");

        let cipher_suite = CipherSuite::parse(buf).map_err(|_| TlsError::InvalidCipherSuite)?;

        ////info!("sh 3");
        // skip compression method, it's 0.
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

        // debug!("server random {:x}", random);
        // debug!("server session-id {:x}", session_id.as_slice());
        debug!("server cipher_suite {:?}", cipher_suite);
        debug!("server extensions {:?}", extensions);

        unused(session_id);
        Ok(Self { extensions })
    }

    pub fn key_share(&self) -> Option<&KeyShareEntry<'_>> {
        self.extensions.iter().find_map(|e| {
            if let ServerHelloExtension::KeyShare(entry) = e {
                Some(&entry.0)
            } else {
                None
            }
        })
    }

    pub fn calculate_shared_secret(&self, secret: KeyExchangeSecret) -> Option<Vec<u8, 64>> {
        let server_key_share = self.key_share()?;
        match server_key_share.group {
            #[cfg(all(not(feature = "x25519")))]
            NamedGroup::Secp256r1 => {
                #[cfg(feature = "mlkem")]
                let KeyExchangeSecret::Secp256r1MlKem768(secret, _) = secret;
                #[cfg(not(feature = "mlkem"))]
                let KeyExchangeSecret::Secp256r1(secret) = secret;
                let server_public_key =
                    p256::PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
                let shared = secret.diffie_hellman(&server_public_key);
                Vec::from_slice(shared.raw_secret_bytes()).ok()
            }
            #[cfg(all(feature = "mlkem", not(feature = "x25519")))]
            NamedGroup::SecP256r1MLKEM768 => {
                let KeyExchangeSecret::Secp256r1MlKem768(secret, kem) = secret;
                let server_public_key =
                    p256::PublicKey::from_sec1_bytes(&server_key_share.opaque[..65]).ok()?;
                let pubkey_secret = secret.diffie_hellman(&server_public_key);
                let decap_secret = kem.decapsulate_slice(&server_key_share.opaque[65..]).ok()?;
                let mut shared = Vec::new();
                shared
                    .extend_from_slice(pubkey_secret.raw_secret_bytes())
                    .ok()?;
                shared.extend_from_slice(&decap_secret).ok()?;
                Some(shared)
            }
            #[cfg(feature = "x25519")]
            NamedGroup::X25519 => {
                #[cfg(feature = "mlkem")]
                let KeyExchangeSecret::X25519MlKem768(secret, _) = secret;
                #[cfg(not(feature = "mlkem"))]
                let KeyExchangeSecret::X25519(secret) = secret;
                let mut server_public_key_bytes = [0u8; 32];
                server_public_key_bytes.copy_from_slice(server_key_share.opaque);
                let server_public_key = x25519_dalek::PublicKey::from(server_public_key_bytes);
                let shared = secret.diffie_hellman(&server_public_key);
                Vec::from_slice(shared.as_bytes()).ok()
            }
            #[cfg(all(feature = "mlkem", feature = "x25519"))]
            NamedGroup::X25519MLKEM768 => {
                let KeyExchangeSecret::X25519MlKem768(secret, kem) = secret;
                let mut server_public_key_bytes = [0u8; 32];
                server_public_key_bytes.copy_from_slice(&server_key_share.opaque[1088..]);
                let server_public_key = x25519_dalek::PublicKey::from(server_public_key_bytes);
                let pubkey_secret = secret.diffie_hellman(&server_public_key).to_bytes();
                let decap_secret = kem
                    .decapsulate_slice(&server_key_share.opaque[..1088])
                    .ok()?;
                let mut shared = Vec::new();
                shared.extend_from_slice(&decap_secret).ok()?;
                shared.extend_from_slice(&pubkey_secret).ok()?;
                Some(shared)
            }
            g => {
                warn!("Unknown group: {:?}", g);
                None
            }
        }
    }

    #[allow(dead_code)]
    pub fn initialize_crypto_engine(&self, secret: &EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key = p256::PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}
