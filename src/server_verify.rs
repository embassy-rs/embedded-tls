//! Client certificate verification for server-side mutual TLS.
//!
//! Reuses the chain walking and signature checking the client already applies
//! to server certificates, with two deliberate differences:
//!
//! - No hostname matching. A client certificate carries no hostname the server
//!   can meaningfully check against.
//! - The `CertificateVerify` context string is the client one (RFC 8446
//!   section 4.4.3).

use crate::TlsError;
use crate::config::{TlsCipherSuite, TlsClock};
use crate::crypto::TlsHash;
use crate::handshake::certificate::{CertificateEntryRef, CertificateRef as ClientCertificate};
use crate::handshake::certificate_verify::CertificateVerifyRef;
use heapless::Vec;

/// Validate that the presented client certificate chains to `trust_anchor`.
///
/// `Clock` supplies the current time for validity checking, exactly as on the
/// client side; a device with no wall clock uses `NoClock` and skips expiry.
pub(crate) fn verify_client_certificate<Clock: TlsClock>(
    trust_anchor: &[u8],
    certificate: &ClientCertificate<'_>,
) -> Result<(), TlsError> {
    if certificate.entries.is_empty() {
        return Err(TlsError::InvalidCertificate);
    }

    let anchor = CertificateEntryRef::X509(trust_anchor);
    let mut links = 0usize;
    for (issuer, subject) in crate::pki::CertificateChain::new(&anchor, certificate) {
        crate::pki::verify_certificate(issuer, subject, Clock::now())?;
        links += 1;
    }

    // A chain that produced no links was never actually verified against the
    // anchor, so it must not be treated as trusted.
    if links == 0 {
        return Err(TlsError::InvalidCertificate);
    }

    Ok(())
}

/// Verify the client's `CertificateVerify` signature over the handshake
/// transcript, proving possession of the presented certificate's private key.
pub(crate) fn verify_client_signature<CipherSuite: TlsCipherSuite>(
    transcript: &CipherSuite::Hash,
    certificate: &ClientCertificate<'_>,
    verify: &CertificateVerifyRef<'_>,
) -> Result<(), TlsError> {
    let ctx_str = b"TLS 1.3, client CertificateVerify\x00";
    let mut msg: Vec<u8, 146> = Vec::new();
    msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(ctx_str)
        .map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(transcript.clone().finalize().as_ref())
        .map_err(|_| TlsError::EncodeError)?;

    crate::pki::verify_signature(&msg[..], certificate, verify)
}
