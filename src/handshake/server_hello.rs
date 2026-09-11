use embassy_crypto::p256::{PublicKey, SecretKey, SharedSecret};
use heapless::Vec;

use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::key_share::KeyShareEntry;
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

    /// The ECDH shared secret between our ephemeral key and the server's P-256 key share.
    pub fn calculate_shared_secret(&self, secret: &SecretKey) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key =
            PublicKey::from_sec1(server_key_share.opaque.try_into().ok()?).ok()?;
        secret.diffie_hellman(&server_public_key).ok()
    }
}
