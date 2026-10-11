//! Runs a case's chain through each verifier under test.

use super::cases::Case;
use embassy_crypto_rustcrypto as _;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateEntryRef, CertificateRef, TlsClock, TlsError,
    TlsVerifier, pki, webpki,
};
use jiff::Timestamp;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub type Verify = fn(&[u8], &[Vec<u8>], Option<&str>) -> Result<(), TlsError>;

/// The verifiers under test.
// CERT_SIZE does not matter here: the entries are added, not parsed, so the verifier copies none.
pub const VERIFIERS: [(&str, Verify); 2] = [
    ("rustpki", |a, c, h| {
        verify(pki::CertVerifier::<_, LimboClock, 8192>::new, a, c, h)
    }),
    ("webpki", |a, c, h| {
        verify(webpki::CertVerifier::<_, LimboClock, 8192>::new, a, c, h)
    }),
];

/// A case's outcome: `Ok` when the verifier accepted the chain, else its errors, or "panicked".
pub type Outcome = Result<(), String>;

// `TlsClock::now` takes no `self`, so each case's time reaches the verifier through this.
thread_local! {
    static NOW: Cell<u64> = const { Cell::new(0) };
}

struct LimboClock;

impl TlsClock for LimboClock {
    fn now() -> Option<u64> {
        Some(NOW.get())
    }
}

/// Runs one case. A verifier takes one trust anchor, so a chain passes when any anchor accepts it.
pub fn check(case: &Case, verify: Verify) -> Outcome {
    let now = case.validation_time.unwrap_or_else(Timestamp::now);
    NOW.set(u64::try_from(now.as_second()).unwrap_or_default());
    let chain: Vec<Vec<u8>> = std::iter::once(&case.peer_certificate)
        .chain(&case.untrusted_intermediates)
        .map(|pem| pem_parser::pem_to_der(pem))
        .collect();
    let host = case
        .expected_peer_name
        .as_ref()
        .map(|name| name.value.as_str());

    let mut errors = Vec::new();
    for anchor in &case.trusted_certs {
        let anchor = pem_parser::pem_to_der(anchor);
        match catch_unwind(AssertUnwindSafe(|| verify(&anchor, &chain, host))) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => errors.push(format!("{e:?}")),
            Err(_) => return Err("panicked".to_string()),
        }
    }
    Err(errors.join(" "))
}

/// Runs `chain`, the peer certificate first, through the verifier that `new` makes for `anchor`.
fn verify<'a, V: TlsVerifier<Aes128GcmSha256>>(
    new: impl FnOnce(Certificate<&'a [u8]>) -> V,
    anchor: &'a [u8],
    chain: &[Vec<u8>],
    host: Option<&str>,
) -> Result<(), TlsError> {
    let mut verifier = new(Certificate::X509(anchor));
    let mut certificate = CertificateRef::with_context(&[]);
    for der in chain {
        certificate.add(CertificateEntryRef::X509(der))?;
    }
    if let Some(host) = host {
        verifier.set_hostname_verification(host)?;
    }
    verifier.verify_certificate(&embedded_tls::embassy_crypto::Sha256::new(), certificate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limbo::cases::{Expected, case};

    const CA: &str = include_str!("../../../tests/data/ca-cert.pem");
    const OTHER_ROOT: &str = include_str!("../../../tests/data/other-root-cert.pem");
    const SERVER: &str = include_str!("../../../tests/data/server-cert.pem");

    /// The server certificate that `ca-cert.pem` issued, checked in 2026, without a host name.
    fn server_case(anchors: &[&str], time: &str) -> Case {
        let mut case = case("a::server", "SERVER", &[], Expected::Success);
        case.peer_certificate = SERVER.to_string();
        case.trusted_certs = anchors.iter().map(|pem| pem.to_string()).collect();
        case.validation_time = Some(time.parse().unwrap());
        case
    }

    #[test]
    fn a_chain_passes_when_any_trust_anchor_accepts_it() {
        let case = server_case(&[OTHER_ROOT, CA], "2026-10-11T00:00:00Z");
        for (name, verify) in VERIFIERS {
            assert_eq!(check(&case, verify), Ok(()), "{name}");
        }
    }

    #[test]
    fn a_chain_fails_when_no_trust_anchor_accepts_it() {
        let case = server_case(&[OTHER_ROOT], "2026-10-11T00:00:00Z");
        for (name, verify) in VERIFIERS {
            assert!(
                matches!(check(&case, verify), Err(e) if e != "panicked"),
                "{name}"
            );
        }
    }

    #[test]
    fn the_case_s_time_reaches_the_verifier() {
        // ca-cert.pem and server-cert.pem expire in 2051.
        let case = server_case(&[CA], "2060-01-01T00:00:00Z");
        for (name, verify) in VERIFIERS {
            assert!(
                matches!(check(&case, verify), Err(e) if e != "panicked"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_verifier_that_panics_fails_the_case() {
        let case = server_case(&[CA], "2026-10-11T00:00:00Z");
        let panics: Verify = |_, _, _| panic!("a verifier fault");
        assert_eq!(check(&case, panics), Err("panicked".to_string()));
    }
}
