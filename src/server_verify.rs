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

use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::crypto::{TlsHash, certificate_verify_message};
use crate::handshake::certificate::CertificateRef as ClientCertificate;
use crate::pki::CertVerifier;

/// Largest client certificate this server will parse, in bytes.
const MAX_CLIENT_CERT_SIZE: usize = 4096;

/// Validate that the presented client certificate chains to `trust_anchor`.
///
/// `Clock` supplies the current time for validity checking, exactly as on the
/// client side; a device with no wall clock uses `NoClock` and skips expiry.
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
