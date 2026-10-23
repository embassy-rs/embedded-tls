//! Client certificate verification for server-side mutual TLS.
//!
//! Chain walking is delegated to [`CertVerifier`], the same implementation the
//! client applies to server certificates, so the server inherits its validity
//! and path checks rather than carrying a second copy of them.
//!
//! Two things differ from the client side:
//!
//! - No hostname matching. A client certificate carries no hostname the server
//!   can meaningfully check against, so `set_hostname_verification` is never
//!   called on the verifier.
//! - The `CertificateVerify` context string is the client one
//!   (RFC 8446 section 4.4.3).
//!
//! Additionally, the server enforces the client-certificate key-usage
//! constraints that rustls/rustpki apply: an Extended Key Usage extension, if
//! present, must contain `id-kp-clientAuth` (or `anyExtendedKeyUsage`); a Key
//! Usage extension, if present, must have `digitalSignature` set.

use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::crypto::{TlsHash, certificate_verify_message};
use crate::der_certificate::DecodedCertificate;
use crate::handshake::certificate::CertificateRef as ClientCertificate;
use crate::pki::CertVerifier;
use der::Decode;
use der::Reader;
use der::Tagged;

/// Largest client certificate this server will parse, in bytes.
const MAX_CLIENT_CERT_SIZE: usize = 4096;

const EXTENDED_KEY_USAGE_OID_BYTES: &[u8] = &[0x55, 0x1D, 0x25]; // 2.5.29.37
const KEY_USAGE_OID_BYTES: &[u8] = &[0x55, 0x1D, 0x0F]; // 2.5.29.15
const CLIENT_AUTH_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]; // 1.3.6.1.5.5.7.3.2
const ANY_EXTENDED_KEY_USAGE_OID_BYTES: &[u8] = &[0x55, 0x1D, 0x25, 0x00]; // 2.5.29.37.0

fn oid_matches(bytes: &[u8], expected: &[u8]) -> bool {
    bytes == expected
}

fn check_client_cert_extensions(cert_der: &[u8]) -> Result<(), TlsError> {
    let decoded = DecodedCertificate::from_der(cert_der).map_err(|_| TlsError::DecodeError)?;
    let tbs = &decoded.tbs_certificate;

    let extensions = match &tbs.extensions {
        Some(exts) => exts,
        None => return Ok(()),
    };

    for ext in extensions.iter() {
        let extn_id = ext.extn_id.as_bytes();
        if oid_matches(extn_id, EXTENDED_KEY_USAGE_OID_BYTES) {
            // extnValue is an OCTET STRING wrapping a SEQUENCE OF OID.
            ext.extn_value
                .tag()
                .assert_eq(der::Tag::OctetString)
                .map_err(|_| TlsError::DecodeError)?;
            let mut reader =
                der::SliceReader::new(ext.extn_value.value()).map_err(|_| TlsError::DecodeError)?;
            let header = der::Header::decode(&mut reader).map_err(|_| TlsError::DecodeError)?;
            header
                .tag()
                .assert_eq(der::Tag::Sequence)
                .map_err(|_| TlsError::DecodeError)?;
            let content = reader
                .read_slice(header.length())
                .map_err(|_| TlsError::DecodeError)?;
            let mut oid_reader =
                der::SliceReader::new(content).map_err(|_| TlsError::DecodeError)?;
            let mut acceptable = false;
            while !oid_reader.is_finished() {
                let oid = der::asn1::ObjectIdentifier::<32>::decode(&mut oid_reader)
                    .map_err(|_| TlsError::DecodeError)?;
                if oid.as_bytes() == CLIENT_AUTH_OID_BYTES
                    || oid.as_bytes() == ANY_EXTENDED_KEY_USAGE_OID_BYTES
                {
                    acceptable = true;
                }
            }
            if !acceptable {
                return Err(TlsError::InvalidCertificate);
            }
        } else if oid_matches(extn_id, KEY_USAGE_OID_BYTES) {
            ext.extn_value
                .tag()
                .assert_eq(der::Tag::OctetString)
                .map_err(|_| TlsError::DecodeError)?;
            let mut reader =
                der::SliceReader::new(ext.extn_value.value()).map_err(|_| TlsError::DecodeError)?;
            let header = der::Header::decode(&mut reader).map_err(|_| TlsError::DecodeError)?;
            header
                .tag()
                .assert_eq(der::Tag::BitString)
                .map_err(|_| TlsError::DecodeError)?;
            let content = reader
                .read_slice(header.length())
                .map_err(|_| TlsError::DecodeError)?;
            // First byte is the number of unused bits in the final byte.
            if content.is_empty() {
                return Err(TlsError::InvalidCertificate);
            }
            let data = &content[1..];
            if data.is_empty() || (data[0] & 0x80) == 0 {
                return Err(TlsError::InvalidCertificate);
            }
        }
    }

    Ok(())
}

/// Validate that the presented client certificate chains to `trust_anchor`.
///
/// `Clock` supplies the current time for validity checking, exactly as on the
/// client side; a device with no wall clock uses `InsecureIgnoreDates` and skips expiry.
pub(crate) fn verify_client_certificate<CipherSuite, Clock>(
    trust_anchor: &[u8],
    transcript: &CipherSuite::Hash,
    certificate: ClientCertificate<'_>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    if certificate.entries.is_empty() {
        return Err(TlsError::InvalidCertificate);
    }

    let leaf_der = match certificate.entries.first().unwrap() {
        crate::handshake::certificate::CertificateEntryRef::X509(der) => *der,
        crate::handshake::certificate::CertificateEntryRef::RawPublicKey(_) => {
            return Err(TlsError::DecodeError);
        }
    };
    check_client_cert_extensions(leaf_der)?;

    let mut verifier: CertVerifier<'_, CipherSuite, Clock, MAX_CLIENT_CERT_SIZE> =
        CertVerifier::without_hostname_verification(Certificate::X509(trust_anchor));

    verifier.verify_certificate(transcript, certificate)
}

/// Verify the client's `CertificateVerify` signature over the handshake
/// transcript, proving possession of the presented certificate's private key.
pub(crate) fn verify_client_signature<CipherSuite: TlsCipherSuite>(
    transcript: &CipherSuite::Hash,
    certificate: &ClientCertificate<'_>,
    verify: &crate::handshake::certificate_verify::CertificateVerifyRef<'_>,
) -> Result<(), TlsError> {
    let msg = certificate_verify_message(
        b"TLS 1.3, client CertificateVerify\x00",
        transcript.clone().finalize().as_ref(),
    )?;

    crate::pki::verify_signature(&msg[..], certificate, verify)
}

#[cfg(all(test, feature = "rustpki", feature = "p256"))]
mod tests {
    use super::*;
    use crate::SignatureScheme;
    use crate::config::Aes128GcmSha256;
    use crate::handshake::certificate::CertificateEntryRef;
    use crate::handshake::certificate::CertificateRef;
    use crate::handshake::certificate_verify::CertificateVerifyRef;

    #[test]
    fn client_cert_verify_with_mismatched_rsa_scheme_does_not_panic() {
        let cert_der = pem_parser::pem_to_der(include_str!("../tests/data/client-cert.pem"));
        let mut certificate = CertificateRef::with_context(&[]);
        certificate
            .add(CertificateEntryRef::X509(&cert_der))
            .unwrap();

        let transcript = embassy_crypto::Sha256::new();
        let verify = CertificateVerifyRef {
            signature_scheme: SignatureScheme::RsaPssRsaeSha256,
            signature: &[],
        };

        let result = verify_client_signature::<Aes128GcmSha256>(&transcript, &certificate, &verify);
        assert!(result.is_err());
    }
}
