#[cfg(not(feature = "x25519"))]
use embassy_crypto::p256::{PublicKey, SecretKey};
#[cfg(feature = "x25519")]
use embassy_crypto::x25519::{PublicKey, SecretKey};
use heapless::Vec;
#[cfg(feature = "mlkem")]
use ml_kem::{Decapsulate, DecapsulationKey, MlKem768};

use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::extensions::messages::ServerHelloExtension;
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHello<'a>, TlsError> {
        let _version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random)?;

        let session_id_length = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        let session_id = buf
            .slice(session_id_length as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        let cipher_suite = CipherSuite::parse(buf).map_err(|_| TlsError::InvalidCipherSuite)?;

        // skip compression method, it's 0.
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

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

    /// The ECDH shared secret between our ephemeral key and the server's key share.
    pub fn calculate_shared_secret(
        &self,
        secret: &SecretKey,
        #[cfg(feature = "mlkem")] _kem: &DecapsulationKey<MlKem768>,
    ) -> Option<Vec<u8, 64>> {
        let server_key_share = self.key_share()?;
        match server_key_share.group {
            #[cfg(not(feature = "x25519"))]
            NamedGroup::Secp256r1 => {
                let server_public_key =
                    PublicKey::from_sec1(server_key_share.opaque.try_into().ok()?).ok()?;
                let shared = secret.diffie_hellman(&server_public_key).ok()?;
                Vec::from_slice(shared.as_bytes()).ok()
            }
            #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
            NamedGroup::SecP256r1MLKEM768 => {
                let mut server_public_key_bytes = [0u8; 65];
                server_public_key_bytes.copy_from_slice(&server_key_share.opaque[..65]);
                let server_public_key = PublicKey::from_bytes(&server_public_key_bytes);
                let pubkey_secret = secret.diffie_hellman(&server_public_key).ok()?;
                let decap_secret = _kem
                    .decapsulate_slice(&server_key_share.opaque[65..])
                    .ok()?;
                let mut hybrid = Vec::new();
                hybrid.extend_from_slice(pubkey_secret.as_bytes()).ok()?; // 32 bytes X coordinate
                hybrid.extend_from_slice(&decap_secret).ok()?;
                Some(hybrid)
            }
            #[cfg(feature = "x25519")]
            NamedGroup::X25519 => {
                let server_public_key =
                    PublicKey::from_bytes(server_key_share.opaque.try_into().ok()?);
                let shared = secret.diffie_hellman(&server_public_key).ok()?;
                Vec::from_slice(shared.as_bytes()).ok()
            }
            #[cfg(all(feature = "x25519", feature = "mlkem"))]
            NamedGroup::X25519MLKEM768 => {
                let mut server_public_key_bytes = [0u8; 32];
                server_public_key_bytes.copy_from_slice(&server_key_share.opaque[1088..]);
                let server_public_key = PublicKey::from_bytes(&server_public_key_bytes);
                let pubkey_secret = secret.diffie_hellman(&server_public_key).ok()?;
                let decap_secret = _kem
                    .decapsulate_slice(&server_key_share.opaque[..1088])
                    .ok()?;
                let mut hybrid = Vec::new();
                hybrid.extend_from_slice(&decap_secret).ok()?;
                hybrid.extend_from_slice(pubkey_secret.as_bytes()).ok()?;
                Some(hybrid)
            }
            g => {
                warn!("Unknown group: {:?}", g);
                None
            }
        }
    }
}
