//! Server-side TLS handshake encoding helpers.

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::extensions::ExtensionType;
use crate::extensions::extension_data::key_share::{KeyShareEntry, KeyShareServerHello};
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::extensions::extension_data::supported_versions::{SupportedVersionsServerHello, TLS13};
use crate::extensions::messages::ServerHelloExtension;
use crate::handshake::HandshakeType;
use crate::handshake::LEGACY_VERSION;

/// Largest key share this server accepts: 65 bytes for an uncompressed P-256
/// point, 32 for X25519.
pub(crate) const MAX_KEY_SHARE: usize = 65;

/// Owned copy of a key share extracted from `ParsedClientHello`.
/// Needed because the record buffer is reused between reads (e.g. HRR flow).
pub(crate) struct OwnedKeyShare {
    pub group: NamedGroup,
    pub bytes: [u8; MAX_KEY_SHARE],
    pub len: usize,
}

/// Longest legal ALPN protocol name: the wire encoding length-prefixes each
/// name with a single byte.
pub(crate) const MAX_ALPN_NAME: usize = 255;

/// Owned copy of ALPN protocols extracted from `ParsedClientHello`.
///
/// Names are stored whole. Truncating them would let a configured protocol
/// compare equal to a longer offered one that merely shares a prefix, so the
/// server would echo a protocol the client never offered.
pub(crate) struct OwnedAlpn {
    pub data: [[u8; MAX_ALPN_NAME]; 4],
    pub lens: [usize; 4],
    pub count: usize,
}

impl OwnedAlpn {
    pub fn new() -> Self {
        Self {
            data: [[0u8; MAX_ALPN_NAME]; 4],
            lens: [0; 4],
            count: 0,
        }
    }
}

/// Encode a `ServerHello` handshake message (type byte + u24 length + payload).
pub fn encode_server_hello(
    buf: &mut CryptoBuffer<'_>,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    server_public_key: &[u8],
    group: NamedGroup,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::ServerHello as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Legacy version
        buf.push_u16(LEGACY_VERSION)?;

        // Random
        buf.extend_from_slice(random)?;

        // Session ID (echo client's)
        buf.push(session_id.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(session_id)?;

        // Cipher suite
        buf.push_u16(cipher_suite)?;

        // Compression method (null)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Extensions
        buf.with_u16_length(|buf| {
            // Supported Versions extension
            ServerHelloExtension::SupportedVersions(SupportedVersionsServerHello {
                selected_version: TLS13,
            })
            .encode(buf)?;

            // Key Share extension
            ServerHelloExtension::KeyShare(KeyShareServerHello(KeyShareEntry {
                group,
                opaque: server_public_key,
            }))
            .encode(buf)?;

            Ok(())
        })
    })
}

/// Encode a `HelloRetryRequest` handshake message.
pub fn encode_hello_retry_request(
    buf: &mut CryptoBuffer<'_>,
    session_id: &[u8],
    cipher_suite: u16,
    selected_group: NamedGroup,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::ServerHello as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Legacy version
        buf.push_u16(LEGACY_VERSION)?;

        // Fixed random value for HRR
        let hrr_random = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];
        buf.extend_from_slice(&hrr_random)?;

        // Session ID (echo client's)
        buf.push(session_id.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(session_id)?;

        // Cipher suite
        buf.push_u16(cipher_suite)?;

        // Compression method (null)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Extensions
        buf.with_u16_length(|buf| {
            // Supported Versions extension
            ServerHelloExtension::SupportedVersions(SupportedVersionsServerHello {
                selected_version: TLS13,
            })
            .encode(buf)?;

            // Key Share extension — HRR uses KeyShareHelloRetryRequest format:
            // just the selected group (2 bytes), NOT a full KeyShareEntry.
            ExtensionType::KeyShare.encode(buf)?;
            buf.with_u16_length(|buf| buf.push_u16(selected_group.as_u16()))?;

            Ok(())
        })
    })
}

/// Encode an `EncryptedExtensions` handshake message.
pub fn encode_encrypted_extensions(
    buf: &mut CryptoBuffer<'_>,
    selected_alpn: Option<&[u8]>,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::EncryptedExtensions as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        if let Some(protocol) = selected_alpn {
            // Extensions list with ALPN
            buf.with_u16_length(|buf| {
                // ALPN extension type = 0x0010
                buf.push_u16(0x0010)?;
                // Extension data length
                buf.with_u16_length(|buf| {
                    // Protocol name list length
                    buf.with_u16_length(|buf| {
                        // Single protocol name
                        buf.push(protocol.len() as u8)
                            .map_err(|_| TlsError::EncodeError)?;
                        buf.extend_from_slice(protocol)
                    })
                })
            })
        } else {
            // Empty extensions list
            buf.push_u16(0)?;
            Ok(())
        }
    })
}

/// Encode a `CertificateRequest` handshake message.
pub fn encode_certificate_request(buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
    buf.push(HandshakeType::CertificateRequest as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // certificate_request_context (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions
        buf.with_u16_length(|buf| {
            // signature_algorithms extension (type 0x000D)
            buf.push_u16(0x000D)?;
            buf.with_u16_length(|buf| {
                // SignatureSchemeList
                buf.with_u16_length(|buf| {
                    // ecdsa_secp256r1_sha256 = 0x0403
                    buf.push_u16(0x0403)?;
                    // ecdsa_secp384r1_sha384 = 0x0503
                    buf.push_u16(0x0503)?;
                    // rsa_pss_rsae_sha256 = 0x0804
                    buf.push_u16(0x0804)?;
                    Ok(())
                })
            })
        })
    })
}

/// Encode a Certificate handshake message with the given DER cert chain.
pub fn encode_certificate(
    buf: &mut CryptoBuffer<'_>,
    cert_chain: &[&[u8]],
) -> Result<(), TlsError> {
    buf.push(HandshakeType::Certificate as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Request context (empty for server)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Certificate list
        buf.with_u24_length(|buf| {
            for cert_der in cert_chain {
                // Certificate data
                buf.with_u24_length(|buf| buf.extend_from_slice(cert_der))?;
                // Extensions (empty)
                buf.push_u16(0)?;
            }
            Ok(())
        })
    })
}

/// Encode a `CertificateVerify` handshake message.
pub fn encode_certificate_verify(
    buf: &mut CryptoBuffer<'_>,
    signature_scheme: u16,
    signature: &[u8],
) -> Result<(), TlsError> {
    buf.push(HandshakeType::CertificateVerify as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        buf.push_u16(signature_scheme)?;
        buf.with_u16_length(|buf| buf.extend_from_slice(signature))
    })
}

/// Encode a Finished handshake message.
pub fn encode_finished(buf: &mut CryptoBuffer<'_>, verify_data: &[u8]) -> Result<(), TlsError> {
    buf.push(HandshakeType::Finished as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| buf.extend_from_slice(verify_data))
}

/// Compute ECDH shared secret for a given key share.
///
/// Returns (`server_public_key_bytes`, `shared_secret_bytes`, group). Key
/// generation and the exchange itself go through the registered
/// `embassy-crypto` driver, so a hardware accelerator is used where one is
/// registered.
pub(crate) fn compute_ecdh(
    key_share: &KeyShareEntry<'_>,
) -> Result<(heapless::Vec<u8, 65>, heapless::Vec<u8, 32>, NamedGroup), TlsError> {
    match key_share.group {
        NamedGroup::Secp256r1 => {
            let client_pk_bytes: &[u8; 65] = key_share
                .opaque
                .try_into()
                .map_err(|_| TlsError::InvalidKeyShare)?;
            let client_pk = embassy_crypto::p256::PublicKey::from_sec1(client_pk_bytes)
                .map_err(|_| TlsError::InvalidKeyShare)?;

            let server_secret =
                embassy_crypto::p256::SecretKey::generate().map_err(|_| TlsError::CryptoError)?;
            let server_pk = server_secret
                .public_key()
                .map_err(|_| TlsError::CryptoError)?;
            let shared = server_secret
                .diffie_hellman(&client_pk)
                .map_err(|_| TlsError::InvalidKeyShare)?;

            let mut pk_bytes = heapless::Vec::new();
            pk_bytes
                .extend_from_slice(&server_pk.to_sec1())
                .map_err(|_| TlsError::EncodeError)?;
            let mut secret_bytes = heapless::Vec::new();
            secret_bytes
                .extend_from_slice(shared.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;

            Ok((pk_bytes, secret_bytes, NamedGroup::Secp256r1))
        }
        NamedGroup::X25519 => {
            let client_key_bytes: &[u8; 32] = key_share
                .opaque
                .try_into()
                .map_err(|_| TlsError::InvalidKeyShare)?;
            let client_pk = embassy_crypto::x25519::PublicKey::from_bytes(client_key_bytes);

            let server_secret =
                embassy_crypto::x25519::SecretKey::generate().map_err(|_| TlsError::CryptoError)?;
            let server_pk = server_secret
                .public_key()
                .map_err(|_| TlsError::CryptoError)?;
            // An all-zero shared secret means a low-order point (RFC 8446 7.4.2);
            // embassy-crypto rejects that for us as Error::InvalidKey.
            let shared = server_secret
                .diffie_hellman(&client_pk)
                .map_err(|_| TlsError::InvalidKeyShare)?;

            let mut pk_bytes = heapless::Vec::new();
            pk_bytes
                .extend_from_slice(server_pk.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;
            let mut secret_bytes = heapless::Vec::new();
            secret_bytes
                .extend_from_slice(shared.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;

            Ok((pk_bytes, secret_bytes, NamedGroup::X25519))
        }
        _ => Err(TlsError::InvalidKeyShare),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn then_over_long_p256_key_share_is_rejected() {
        // 100 bytes whose first 65 form a plausible uncompressed point.
        let opaque = [0x04u8; 100];
        let entry = KeyShareEntry {
            group: NamedGroup::Secp256r1,
            opaque: &opaque,
        };

        let result = compute_ecdh(&entry);

        assert!(matches!(result, Err(TlsError::InvalidKeyShare)));
    }

    #[test]
    fn then_low_order_x25519_point_is_rejected() {
        // The all-zero point has order 1: every shared secret it produces is
        // all zeros (RFC 7748 section 6).
        let low_order = [0u8; 32];
        let entry = KeyShareEntry {
            group: NamedGroup::X25519,
            opaque: &low_order,
        };

        let result = compute_ecdh(&entry);

        assert!(matches!(result, Err(TlsError::InvalidKeyShare)));
    }
}

#[cfg(test)]
mod ecdh_smoke {
    use super::*;

    #[test]
    fn x25519_server_share_is_32_bytes() {
        let client = embassy_crypto::x25519::SecretKey::generate().expect("keygen");
        let client_pub = client.public_key().expect("pub").to_bytes();
        let entry = KeyShareEntry {
            group: NamedGroup::X25519,
            opaque: &client_pub,
        };
        let (pk, secret, group) = compute_ecdh(&entry).expect("ecdh");
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(pk.len(), 32, "server public key length");
        assert_eq!(secret.len(), 32, "shared secret length");
    }
}
