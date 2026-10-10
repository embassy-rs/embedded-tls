#[cfg(not(any(
    feature = "p256",
    feature = "p384",
    feature = "ed25519",
    feature = "rsa"
)))]
compile_error!(
    "the `webpki` feature needs at least one signature algorithm feature: `p256`, `p384`, `ed25519` or `rsa`"
);

use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::crypto::{TlsHash, certificate_verify_message};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
        MAX_CERTIFICATE_ENTRIES,
    },
    certificate_verify::CertificateVerifyRef,
};
use core::marker::PhantomData;
use core::time::Duration;
#[cfg(feature = "defmt")]
use defmt::Debug2Format;
use pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};

mod algorithms;

/// Verifies the server's certificate chain with rustls-webpki.
///
/// Signatures are checked through embassy-crypto, for the algorithms that the `p256`,
/// `p384` and `ed25519` features enable, and through the `rsa` crate with the `rsa` feature.
/// The server's first certificate is its own, and the rest are intermediates in any order.
/// rustls-webpki builds a path through at most six intermediates.
///
/// The verifier keeps a copy of the server's whole chain until it checks the
/// `CertificateVerify` signature, so `CERT_SIZE` must hold every certificate the server sends.
/// A chain that does not fit fails with [`TlsError::OutOfMemory`] after it has been verified.
pub struct CertVerifier<'a, CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    ca: Certificate<&'a [u8]>,
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<'a, CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<'a, CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new(ca: Certificate<&'a [u8]>) -> Self {
        Self {
            ca,
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<'_, CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        // A name rustls-webpki cannot match is refused here, not as a bad certificate later.
        ServerName::try_from(hostname).map_err(|_| TlsError::InvalidCertificate)?;
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        verify_certificate(self.host.as_deref(), &self.ca, &cert, Clock::now())?;
        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let msg = certificate_verify_message(
            b"TLS 1.3, server CertificateVerify\x00",
            handshake_hash.finalize().as_ref(),
        )?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)
    }
}

/// The algorithm for a `CertificateVerify` signed with `scheme`.
///
/// RSA-PKCS#1 is refused: RFC 9846, section 4.3.3, defines the `rsa_pkcs1` schemes for
/// signatures in certificates only, not for `CertificateVerify`, even when the client offers them.
fn algorithm(
    scheme: SignatureScheme,
) -> Result<&'static dyn SignatureVerificationAlgorithm, TlsError> {
    match scheme {
        #[cfg(feature = "p256")]
        SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&algorithms::ECDSA_P256_SHA256),
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&algorithms::ECDSA_P384_SHA384),
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => Ok(&algorithms::ED25519),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => Ok(&algorithms::RSA_PSS_SHA256),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => Ok(&algorithms::RSA_PSS_SHA384),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => Ok(&algorithms::RSA_PSS_SHA512),
        _ => Err(TlsError::InvalidSignatureScheme),
    }
}

/// Logs why rustls-webpki refused a certificate or a signature, and returns `error` as `mapped`.
fn refused(error: &webpki::Error, mapped: TlsError) -> TlsError {
    #[cfg(feature = "defmt")]
    warn!("rustls-webpki refused: {:?}", Debug2Format(error));
    #[cfg(not(feature = "defmt"))]
    warn!("rustls-webpki refused: {:?}", error);
    mapped
}

/// The server's own certificate, which must be the first entry and X.509.
fn end_entity<'a>(certificate: &ServerCertificate<'a>) -> Result<CertificateDer<'a>, TlsError> {
    match certificate.entries.first() {
        Some(CertificateEntryRef::X509(der)) => Ok(CertificateDer::from(*der)),
        _ => Err(TlsError::DecodeError),
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let der = end_entity(certificate)?;
    let cert =
        webpki::EndEntityCert::try_from(&der).map_err(|e| refused(&e, TlsError::DecodeError))?;
    cert.verify_signature(
        algorithm(verify.signature_scheme)?,
        message,
        verify.signature,
    )
    .map_err(|e| refused(&e, TlsError::InvalidSignature))
}

fn verify_certificate(
    host: Option<&str>,
    ca: &Certificate<&[u8]>,
    certificate: &ServerCertificate,
    now: Option<u64>,
) -> Result<(), TlsError> {
    let Certificate::X509(ca) = ca else {
        return Err(TlsError::DecodeError);
    };
    let ca = CertificateDer::from(*ca);
    let anchor =
        webpki::anchor_from_trusted_cert(&ca).map_err(|e| refused(&e, TlsError::DecodeError))?;

    let leaf = end_entity(certificate)?;
    let mut intermediates = heapless::Vec::<CertificateDer<'_>, MAX_CERTIFICATE_ENTRIES>::new();
    for entry in certificate.entries.iter().skip(1) {
        let CertificateEntryRef::X509(der) = entry else {
            return Err(TlsError::DecodeError);
        };
        intermediates
            .push(CertificateDer::from(*der))
            .map_err(|_| TlsError::InsufficientSpace)?;
    }

    let Some(now) = now else {
        warn!("No time provided, so the certificate's validity cannot be checked");
        return Err(TlsError::InvalidCertificate);
    };

    let cert =
        webpki::EndEntityCert::try_from(&leaf).map_err(|e| refused(&e, TlsError::DecodeError))?;
    cert.verify_for_usage(
        algorithms::ALL,
        core::slice::from_ref(&anchor),
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| refused(&e, TlsError::InvalidCertificate))?;

    if let Some(host) = host {
        let name = ServerName::try_from(host).map_err(|_| TlsError::InvalidCertificate)?;
        cert.verify_is_valid_for_subject_name(&name)
            .map_err(|e| refused(&e, TlsError::InvalidCertificate))?;
    }
    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod cert_verifier_tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    #[cfg(feature = "rsa")]
    use openssl::rsa::Padding;
    #[cfg(feature = "rsa")]
    use openssl::sign::RsaPssSaltlen;
    use openssl::sign::Signer;
    use std::time::SystemTime;

    /// The DER bytes of `tests/data/<name>.pem`.
    macro_rules! der {
        ($name:literal) => {
            pem_parser::pem_to_der(include_str!(concat!("../tests/data/", $name, ".pem")))
        };
    }

    macro_rules! assert_matches {
        ($result:expr, $expected:pat) => {
            let result = $result;
            assert!(matches!(result, $expected), "{result:?}");
        };
    }

    type Verifier<'a> = CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>;

    /// The body of a TLS 1.3 Certificate message holding `chain`, as a server sends it.
    ///
    /// The verifier keeps its copy of the chain from these bytes, which
    /// `CertificateRef::add` leaves empty.
    fn message(chain: &[&[u8]]) -> std::vec::Vec<u8> {
        let u24 = |n: usize| u32::try_from(n).unwrap().to_be_bytes()[1..].to_vec();
        let mut entries = std::vec::Vec::new();
        for der in chain {
            entries.extend_from_slice(&u24(der.len()));
            entries.extend_from_slice(der);
            entries.extend_from_slice(&[0, 0]);
        }
        let mut message = std::vec![0];
        message.extend_from_slice(&u24(entries.len()));
        message.extend_from_slice(&entries);
        message
    }

    fn parse(message: &[u8]) -> ServerCertificate<'_> {
        ServerCertificate::parse(&mut crate::parse_buffer::ParseBuffer::from(message)).unwrap()
    }

    /// Runs `chain` through the verifier for `host`, with `ca` as the trust anchor.
    fn verify(ca: &[u8], chain: &[&[u8]], host: &str) -> Result<(), TlsError> {
        let message = message(chain);
        let mut verifier = Verifier::new(Certificate::X509(ca));
        verifier.set_hostname_verification(host)?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))
    }

    /// The content a server signs in its `CertificateVerify`, for an empty transcript.
    fn signed_content() -> std::vec::Vec<u8> {
        let transcript = embassy_crypto::Sha256::new().finalize();
        certificate_verify_message(
            b"TLS 1.3, server CertificateVerify\x00",
            transcript.as_ref(),
        )
        .unwrap()
        .to_vec()
    }

    fn key(pem: &str) -> PKey<Private> {
        PKey::private_key_from_pem(pem.as_bytes()).unwrap()
    }

    /// Signs the `CertificateVerify` content with `digest`, and with RSA-PKCS#1 for an RSA key.
    fn sign(key: &PKey<Private>, digest: MessageDigest) -> std::vec::Vec<u8> {
        let mut signer = Signer::new(digest, key).unwrap();
        signer.sign_oneshot_to_vec(&signed_content()).unwrap()
    }

    #[cfg(feature = "ed25519")]
    fn sign_ed25519(key: &PKey<Private>) -> std::vec::Vec<u8> {
        let mut signer = Signer::new_without_digest(key).unwrap();
        signer.sign_oneshot_to_vec(&signed_content()).unwrap()
    }

    #[cfg(feature = "rsa")]
    fn sign_rsa_pss(key: &PKey<Private>, digest: MessageDigest) -> std::vec::Vec<u8> {
        let mut signer = Signer::new(digest, key).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .unwrap();
        signer.set_rsa_mgf1_md(digest).unwrap();
        signer.sign_oneshot_to_vec(&signed_content()).unwrap()
    }

    /// Verifies `chain`, then a `CertificateVerify` with `scheme` and `signature`.
    fn verify_handshake(
        ca: &[u8],
        chain: &[&[u8]],
        scheme: SignatureScheme,
        signature: &[u8],
    ) -> Result<(), TlsError> {
        let message = message(chain);
        let mut verifier = Verifier::new(Certificate::X509(ca));
        verifier.set_hostname_verification("localhost")?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))?;
        verifier.verify_signature(CertificateVerifyRef {
            signature_scheme: scheme,
            signature,
        })
    }

    /// Verifies a `CertificateVerify` from `rsa-server-key.pem`, claiming `scheme`.
    #[cfg(feature = "rsa")]
    fn verify_rsa(scheme: SignatureScheme, signature: &[u8]) -> Result<(), TlsError> {
        verify_handshake(
            &der!("rsa-ca-cert"),
            &[&der!("rsa-server-cert")],
            scheme,
            signature,
        )
    }

    #[cfg(feature = "rsa")]
    fn rsa_key() -> PKey<Private> {
        key(include_str!("../tests/data/rsa-server-key.pem"))
    }

    #[test]
    fn server_cert_signed_by_the_ca_is_accepted() {
        assert_matches!(
            verify(&der!("ca-cert"), &[&der!("server-cert")], "localhost"),
            Ok(())
        );
    }

    #[test]
    fn server_cert_and_intermediate_are_accepted() {
        let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
        assert_matches!(verify(&der!("ca-cert"), &chain, "localhost"), Ok(()));
    }

    #[test]
    fn chain_that_does_not_reach_the_ca_is_rejected() {
        let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
        assert_matches!(
            verify(&der!("other-root-cert"), &chain, "localhost"),
            Err(TlsError::InvalidCertificate)
        );
    }

    // The server's own certificate comes first (RFC 9846, section 4.5.1). The intermediate is a
    // CA and is not valid for the name, so taking it as the server's certificate must fail.
    #[test]
    fn chain_with_the_intermediate_first_is_rejected() {
        let chain = [&der!("im-cert")[..], &der!("im-server-cert")];
        assert_matches!(
            verify(&der!("ca-cert"), &chain, "localhost"),
            Err(TlsError::InvalidCertificate)
        );
    }

    /// Runs a chain whose entry at `position` is a raw public key, with the server's certificate
    /// and intermediate around it.
    fn verify_with_raw_public_key(position: usize) -> Result<(), TlsError> {
        let (ca, server_cert, intermediate) =
            (der!("ca-cert"), der!("im-server-cert"), der!("im-cert"));
        let mut entries = std::vec![
            CertificateEntryRef::X509(&server_cert),
            CertificateEntryRef::X509(&intermediate),
        ];
        entries.insert(position, CertificateEntryRef::RawPublicKey(&[1, 2, 3]));
        // A Certificate message cannot hold a raw public key entry, so this one is built by hand.
        let mut chain = ServerCertificate::with_context(&[]);
        for entry in entries {
            chain.add(entry).unwrap();
        }
        let mut verifier = Verifier::new(Certificate::X509(&ca));
        verifier.set_hostname_verification("localhost")?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), chain)
    }

    #[test]
    fn raw_public_key_as_the_server_certificate_is_rejected() {
        assert_matches!(verify_with_raw_public_key(0), Err(TlsError::DecodeError));
    }

    #[test]
    fn raw_public_key_among_the_intermediates_is_rejected() {
        assert_matches!(verify_with_raw_public_key(1), Err(TlsError::DecodeError));
    }

    #[test]
    fn server_cert_for_another_name_is_rejected() {
        assert_matches!(
            verify(&der!("ca-cert"), &[&der!("server-cert")], "example.com"),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[test]
    fn host_name_that_is_not_a_dns_name_or_ip_address_is_refused_before_the_handshake() {
        let ca = der!("ca-cert");
        let mut verifier = Verifier::new(Certificate::X509(&ca));
        assert_matches!(
            verifier.set_hostname_verification("not a host"),
            Err(TlsError::InvalidCertificate)
        );
    }

    // TLS 1.3 names no scheme for P-256 with SHA-384, so the client does not advertise it.
    #[cfg(feature = "p256")]
    #[test]
    fn server_cert_signed_with_p256_and_sha384_is_rejected() {
        assert_matches!(
            verify(
                &der!("ca-cert"),
                &[&der!("sha384-server-cert")],
                "localhost"
            ),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[cfg(feature = "p384")]
    #[test]
    fn server_cert_signed_with_p384_and_sha384_is_accepted() {
        assert_matches!(
            verify(
                &der!("p384-ca-cert"),
                &[&der!("p384-server-cert")],
                "localhost"
            ),
            Ok(())
        );
    }

    #[cfg(feature = "p384")]
    #[test]
    fn server_cert_signed_with_p384_and_sha256_is_rejected() {
        let chain = [&der!("p384-sha256-server-cert")[..]];
        assert_matches!(
            verify(&der!("p384-ca-cert"), &chain, "localhost"),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn server_cert_signed_with_ed25519_is_accepted() {
        assert_matches!(
            verify(&der!("ed-ca-cert"), &[&der!("ed-server-cert")], "localhost"),
            Ok(())
        );
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn server_cert_signed_with_rsa_is_accepted() {
        assert_matches!(
            verify(
                &der!("rsa-ca-cert"),
                &[&der!("rsa-server-cert")],
                "localhost"
            ),
            Ok(())
        );
    }

    /// Verifies `server_cert` against `ca` with the last byte of its signature changed.
    #[cfg(any(feature = "rsa", feature = "p384", feature = "ed25519"))]
    fn verify_with_a_changed_signature(
        ca: &[u8],
        mut server_cert: std::vec::Vec<u8>,
    ) -> Result<(), TlsError> {
        let last = server_cert.len() - 1;
        server_cert[last] = !server_cert[last];
        verify(ca, &[&server_cert], "localhost")
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn server_cert_with_a_changed_rsa_signature_is_rejected() {
        assert_matches!(
            verify_with_a_changed_signature(&der!("rsa-ca-cert"), der!("rsa-server-cert")),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[cfg(feature = "p384")]
    #[test]
    fn server_cert_with_a_changed_p384_signature_is_rejected() {
        assert_matches!(
            verify_with_a_changed_signature(&der!("p384-ca-cert"), der!("p384-server-cert")),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn server_cert_with_a_changed_ed25519_signature_is_rejected() {
        assert_matches!(
            verify_with_a_changed_signature(&der!("ed-ca-cert"), der!("ed-server-cert")),
            Err(TlsError::InvalidCertificate)
        );
    }

    #[cfg(feature = "p256")]
    #[test]
    fn certificate_verify_with_p256_is_accepted() {
        let key = key(include_str!("../tests/data/server-key.pem"));
        let result = verify_handshake(
            &der!("ca-cert"),
            &[&der!("server-cert")],
            SignatureScheme::EcdsaSecp256r1Sha256,
            &sign(&key, MessageDigest::sha256()),
        );
        assert_matches!(result, Ok(()));
    }

    #[cfg(feature = "p256")]
    #[test]
    fn certificate_verify_with_a_wrong_signature_is_rejected() {
        let key = key(include_str!("../tests/data/server-key.pem"));
        let mut signature = sign(&key, MessageDigest::sha256());
        let last = signature.len() - 1;
        signature[last] ^= 1;
        let result = verify_handshake(
            &der!("ca-cert"),
            &[&der!("server-cert")],
            SignatureScheme::EcdsaSecp256r1Sha256,
            &signature,
        );
        assert_matches!(result, Err(TlsError::InvalidSignature));
    }

    #[cfg(feature = "p384")]
    #[test]
    fn certificate_verify_with_p384_is_accepted() {
        let key = key(include_str!("../tests/data/p384-key-server-key.pem"));
        let result = verify_handshake(
            &der!("p384-ca-cert"),
            &[&der!("p384-key-server-cert")],
            SignatureScheme::EcdsaSecp384r1Sha384,
            &sign(&key, MessageDigest::sha384()),
        );
        assert_matches!(result, Ok(()));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn certificate_verify_with_ed25519_is_accepted() {
        let key = key(include_str!("../tests/data/ed-server-key.pem"));
        let result = verify_handshake(
            &der!("ed-ca-cert"),
            &[&der!("ed-server-cert")],
            SignatureScheme::Ed25519,
            &sign_ed25519(&key),
        );
        assert_matches!(result, Ok(()));
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_with_rsa_pss_and_sha256_is_accepted() {
        let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha256());
        assert_matches!(
            verify_rsa(SignatureScheme::RsaPssRsaeSha256, &signature),
            Ok(())
        );
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_with_rsa_pss_and_sha384_is_accepted() {
        let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha384());
        assert_matches!(
            verify_rsa(SignatureScheme::RsaPssRsaeSha384, &signature),
            Ok(())
        );
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_with_rsa_pss_and_sha512_is_accepted() {
        let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha512());
        assert_matches!(
            verify_rsa(SignatureScheme::RsaPssRsaeSha512, &signature),
            Ok(())
        );
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_claiming_another_hash_than_it_used_is_rejected() {
        let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha256());
        assert_matches!(
            verify_rsa(SignatureScheme::RsaPssRsaeSha384, &signature),
            Err(TlsError::InvalidSignature)
        );
    }

    // RFC 9846, section 4.3.3: the rsa_pkcs1 schemes are for signatures in certificates only, so a
    // CertificateVerify that claims one is refused even when the client offers them.
    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_with_rsa_pkcs1_is_rejected() {
        let signature = sign(&rsa_key(), MessageDigest::sha256());
        assert_matches!(
            verify_rsa(SignatureScheme::RsaPkcs1Sha256, &signature),
            Err(TlsError::InvalidSignatureScheme)
        );
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn certificate_verify_with_a_1024_bit_rsa_key_is_rejected() {
        let key = key(include_str!("../tests/data/rsa1024-server-key.pem"));
        let result = verify_handshake(
            &der!("rsa-ca-cert"),
            &[&der!("rsa1024-server-cert")],
            SignatureScheme::RsaPssRsaeSha256,
            &sign_rsa_pss(&key, MessageDigest::sha256()),
        );
        assert_matches!(result, Err(TlsError::InvalidSignature));
    }

    #[cfg(feature = "p256")]
    #[test]
    fn certificate_verify_claiming_rsa_for_an_ecdsa_key_is_rejected() {
        let key = key(include_str!("../tests/data/server-key.pem"));
        let result = verify_handshake(
            &der!("ca-cert"),
            &[&der!("server-cert")],
            SignatureScheme::RsaPssRsaeSha256,
            &sign(&key, MessageDigest::sha256()),
        );
        assert!(result.is_err(), "{result:?}");
    }
}
