#[cfg(not(any(
    feature = "p256",
    feature = "p384",
    feature = "ed25519",
    feature = "rsa"
)))]
compile_error!(
    "the `rustpki` feature needs at least one signature algorithm feature: `p256`, `p384`, `ed25519` or `rsa`"
);

use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
#[cfg(feature = "p256")]
use crate::crypto::verify_ecdsa_p256;
#[cfg(feature = "p384")]
use crate::crypto::verify_ecdsa_p384;
#[cfg(feature = "ed25519")]
use crate::crypto::verify_ed25519;
use crate::crypto::{TlsHash, certificate_verify_message};
#[cfg(feature = "p256")]
use crate::der_certificate::ECDSA_SHA256;
#[cfg(feature = "p384")]
use crate::der_certificate::ECDSA_SHA384;
#[cfg(feature = "ed25519")]
use crate::der_certificate::ED25519;
use crate::der_certificate::{
    HOSTNAME_MAXLEN, MAX_SAN_DNS_NAMES, Time, extract_common_name,
    extract_san_dns_names,
    DecodedCertificate, ECDSA_SHA256, HOSTNAME_MAXLEN, MAX_SAN_DNS_NAMES, Time,
    extract_san_dns_names, try_extract_subject_common_name,
};
#[cfg(feature = "rsa")]
use crate::der_certificate::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
        MAX_CERTIFICATE_ENTRIES,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use core::marker::PhantomData;
#[cfg(feature = "defmt")]
use defmt::Debug2Format;
use der::Decode;

pub struct CertificateNames {
    pub common_name: Option<heapless::String<HOSTNAME_MAXLEN>>,
    pub san_dns_names: heapless::Vec<heapless::String<HOSTNAME_MAXLEN>, MAX_SAN_DNS_NAMES>,
}

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
        let now = Clock::now();

        let ca = match &self.ca {
            Certificate::X509(der) => ParsedCertificate::from_der(der)?,
            Certificate::RawPublicKey(_) => return Err(TlsError::DecodeError),
        };

        // (RFC9846, Section 4.5.1):
        //
        // "The sender's certificate MUST come in the first CertificateEntry in the list."
        let (end_entity, chain) = cert
            .entries
            .split_first()
            .ok_or(TlsError::InvalidCertificate)?;

        // (RFC9846, Section 4.5.1)
        //
        // "If the corresponding certificate type extension ("server_certificate_type" or "client_certificate_type") was
        // not negotiated in EncryptedExtensions, or the X.509 certificate type was negotiated, then each CertificateEntry
        // contains a DER-encoded X.509 certificate."
        let end_entity = match end_entity {
            CertificateEntryRef::X509(der) => ParsedCertificate::from_der(der)?,
            CertificateEntryRef::RawPublicKey(_) => return Err(TlsError::DecodeError),
        };

        let mut candidates = Vec::<_, MAX_CERTIFICATE_ENTRIES>::new();
        for entry in chain {
            // See above, certificates should be X.509
            let CertificateEntryRef::X509(der) = entry else {
                continue;
            };
            let candidate = match ParsedCertificate::from_der(der) {
                Ok(candidate) => candidate,
                Err(err) => {
                    warn!("Invalid certificate {err:?}");
                    // Ignore invalid certificates
                    continue
                },
            };

            // Validate certificate time if we have a clock
            match now {
                Some(time) => {
                    if !is_valid_at(&candidate.decoded, time) {
                        warn!("Certificate is not valid at time {time}");
                        continue;
                    }
                }
                None => warn!("No time provided, could not check certificate's validity"),
            }

            candidates
                .push(candidate)
                .map_err(|_| TlsError::InsufficientSpace)?;
        }

        // The CA is the first trusted cert.
        // Every certificate in the chain becomes trusted if it can be certified by any already
        // trusted certificate.
        let mut trusted_certs = Vec::<_, MAX_CERTIFICATE_ENTRIES>::new();
        trusted_certs
            .push(ca)
            .map_err(|_| TlsError::InsufficientSpace)?;

        // (RFC9846, Section 4.5.1):
        //
        // "implementations SHOULD be prepared to handle potentially extraneous
        // certificates and arbitrary orderings from any TLS version"
        loop {
            let trusted_before = trusted_certs.len();

            let mut idx = 0;
            while idx < candidates.len() {
                match certified_by_any(&trusted_certs, &candidates[idx]) {
                    CertificateVerification::Certifies => {
                        let certificate = candidates.swap_remove(idx);
                        trusted_certs
                            .push(certificate)
                            .map_err(|_| TlsError::InsufficientSpace)?;
                    },
                    // A failure to validate an intermediate certificate can be ignored
                    // (see note above).
                    CertificateVerification::DoesNotCertify => idx += 1,
                }
            }

            if trusted_certs.len() == trusted_before {
                break;
            }
        }

        // Now that we know what certificates we trust, validate that the end-entity certificate:
        // 1. Is valid
        match now {
            Some(time) => {
                if !is_valid_at(&end_entity.decoded, time) {
                    error!("End-entity certificate is outside of its validity period");
                    return Err(TlsError::InvalidCertificate);
                }
            },
            None => warn!("No time provided, could not check end-entity certificate's validity"),
        }

        // 2. Is certified by any of the trusted certificates
        match certified_by_any(&trusted_certs, &end_entity) {
            CertificateVerification::Certifies => (),
            CertificateVerification::DoesNotCertify => {
                error!("No trusted certificate certifies the end-entity certificate");
                return Err(TlsError::InvalidCertificate);
            }
        }

        // 3. Is the certificate for the server we're trying to reach
        let names = CertificateNames {
            common_name: try_extract_subject_common_name(&end_entity.decoded.tbs_certificate)
                .map_err(|_| TlsError::DecodeError)?,
            san_dns_names: extract_san_dns_names(&end_entity.decoded.tbs_certificate)
                .map_err(|_| TlsError::DecodeError)?,
        };
        debug!(
            "End-entity CommonName: {:?}, SANs: {:?}",
            names.common_name, names.san_dns_names
        );

        if !tls_hostname_match(&names, &self.host) {
            error!(
                "Hostname ({:?}) does not match certificate names (CN={:?}, SANs={:?})",
                self.host, names.common_name, names.san_dns_names
            );
            return Err(TlsError::InvalidCertificate);
        }

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
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let certificate =
        if let Some(CertificateEntryRef::X509(certificate)) = certificate.entries.first() {
            certificate
        } else {
            return Err(TlsError::DecodeError);
        };

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    let verified = match verify.signature_scheme {
        #[cfg(feature = "p256")]
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            verify_ecdsa_p256(public_key, message, verify.signature).is_ok()
        }
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => {
            verify_ecdsa_p384(public_key, message, verify.signature).is_ok()
        }
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => {
            verify_ed25519(public_key, message, verify.signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => {
            use rsa::sha2::Sha256;
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha256>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verifying_key.verify(message, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => {
            use rsa::sha2::Sha384;
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha384>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verifying_key.verify(message, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => {
            use rsa::sha2::Sha512;
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha512>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verifying_key.verify(message, &signature).is_ok()
        }
        _ => {
            error!(
                "InvalidSignatureScheme: {:?} Are you missing a feature?",
                verify.signature_scheme
            );
            return Err(TlsError::InvalidSignatureScheme);
        }
    };

    if !verified {
        return Err(TlsError::InvalidSignature);
    }

    Ok(())
}

fn get_certificate_tlv_bytes<'a>(input: &[u8]) -> der::Result<&[u8]> {
    use der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(input)?;
    let top_header = der::Header::decode(&mut reader)?;
    top_header.tag().assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag().assert_eq(der::Tag::Sequence)?;

    reader.tlv_bytes()
}

fn get_cert_time(time: &Time) -> u64 {
    match time {
        Time::UtcTime(utc_time) => utc_time.to_unix_duration().as_secs(),
        Time::GeneralTime(generalized_time) => generalized_time.to_unix_duration().as_secs(),
    }
}

/// A certificate decoded from its DER representation.
struct ParsedCertificate<'a> {
    decoded: DecodedCertificate<'a>,
    /// We keep the DER bytes to be able check a signature over it.
    tbs_der: &'a [u8],
}

impl<'a> ParsedCertificate<'a> {
    fn from_der(der: &'a [u8]) -> Result<Self, TlsError> {
        let decoded = DecodedCertificate::from_der(der).map_err(|err| {
            warn!("Failed to decode certificate: {:?}", err);
            TlsError::DecodeError
        })?;

        // Get the DER-encoded content of the certificate, so we can check signature
        let tbs_der = get_certificate_tlv_bytes(der).map_err(|_| TlsError::DecodeError)?;

        Ok(Self { decoded, tbs_der })
    }
}


enum CertificateVerification {
    DoesNotCertify,
    Certifies,
}

/// (RFC5280, Section 7)
///
/// "The validity period for a certificate is the period of time from
/// notBefore through notAfter, inclusive."
fn is_valid_at(certificate: &DecodedCertificate, now: u64) -> bool {
    let validity = &certificate.tbs_certificate.validity;
    get_cert_time(&validity.not_before) <= now && now <= get_cert_time(&validity.not_after)
}

/// Checks whether any of the `trusted_certs` directly certifies `certificate`.
fn certified_by_any(
    trusted_certs: &[ParsedCertificate<'_>],
    certificate: &ParsedCertificate<'_>,
) -> CertificateVerification {
    // (RFC9846, Section 4.5.1)
    //
    // "Each following certificate SHOULD directly certify the one immediately preceding it."
    //
    // .. so we start with the most recently added certificate :)
    for trusted in trusted_certs.iter().rev() {
        match verify_certificate(trusted, certificate) {
            Ok(CertificateVerification::Certifies) => { return CertificateVerification::Certifies; }
            Ok(CertificateVerification::DoesNotCertify) => {}
            Err(err) => { debug!("Failed to verify certificate: {err}"); },
        }
    }

    CertificateVerification::DoesNotCertify
}

/// Checks that a `verifier` directly certifies a `certificate`.
fn verify_certificate(
    verifier: &ParsedCertificate<'_>,
    certificate: &ParsedCertificate<'_>,
) -> Result<CertificateVerification, TlsError> {
    let verifier_parsed = &verifier.decoded;
    let certificate_parsed = &certificate.decoded;

    let verifier_public_key = verifier_parsed
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    // (RFC 5280, Section 4.1.2.4)
    //
    // "Name chaining is performed by matching the issuer
    // distinguished name in one certificate with the subject name in a CA
    // certificate."
    //
    // (RFC 5280, Section 7.1)
    //
    // "Two distinguished names DN1 and DN2 match if they
    // have the same number of RDNs, for each RDN in DN1 there is a matching
    // RDN in DN2, and the matching RDNs appear in the same order in both
    // DNs."
    //
    // This is what PartialEq does, but maybe it is a bit fragile to leave that behavior
    // to the implementation and we should do it explicitly?
    if verifier_parsed.tbs_certificate.subject != certificate_parsed.tbs_certificate.issuer {
        return Ok(CertificateVerification::DoesNotCertify);
    }

    let certificate_data = certificate.tbs_der;

    // Verifier's signature over certificate must verify with the verifier's public key
    let verified = match certificate_parsed.signature_algorithm {
        ECDSA_SHA256 => {
            let signature = parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?;

            verify_ecdsa_p256(ca_public_key, certificate_data, signature).is_ok()
        }
        #[cfg(feature = "p384")]
        ECDSA_SHA384 => {
            let signature = parsed_certificate
                .signature
                .as_bytes()
                .ok_or(TlsError::ParseError(ParseError::InvalidData))?;

            verify_ecdsa_p384(ca_public_key, certificate_data, signature).is_ok()
        }
        #[cfg(feature = "ed25519")]
        ED25519 => {
            let signature = parsed_certificate
                .signature
                .as_bytes()
                .ok_or(TlsError::ParseError(ParseError::InvalidData))?;

            verify_ed25519(ca_public_key, certificate_data, signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA256 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let verifying_key =
                VerifyingKey::<Sha256>::from_pkcs1_der(ca_public_key).map_err(|e| {
                    #[cfg(feature = "defmt")]
                    error!("VerifyingKey: {:?}", Debug2Format(&e));
                    #[cfg(not(feature = "defmt"))]
                    error!("VerifyingKey: {}", e);
                    TlsError::DecodeError
                })?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                );

                verifying_key.verify(certificate_data, &signature).is_ok()
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA384 => {
                use rsa::sha2::Sha384;
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };

                let verifying_key = VerifyingKey::<Sha384>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verifying_key.verify(certificate_data, &signature).is_ok()
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA512 => {
                use rsa::sha2::Sha512;
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };

                let verifying_key = VerifyingKey::<Sha512>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verifying_key.verify(certificate_data, &signature).is_ok()
            }
            _ => {
                error!(
                    "Unsupported signature alg: {:?}",
                    parsed_certificate.signature_algorithm
                );
                return Err(TlsError::InvalidSignatureScheme);
            }
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA384 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let verifying_key = VerifyingKey::<Sha384>::from_pkcs1_der(verifier_public_key)
                .map_err(|_| TlsError::DecodeError)?;

            let signature = Signature::try_from(
                certificate_parsed
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
            )
            .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA512 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let verifying_key = VerifyingKey::<Sha512>::from_pkcs1_der(verifier_public_key)
                .map_err(|_| TlsError::DecodeError)?;

            let signature = Signature::try_from(
                certificate_parsed
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
            )
            .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        _ => {
            error!(
                "Unsupported signature alg: {:?}",
                certificate_parsed.signature_algorithm
            );
            return Err(TlsError::InvalidSignatureScheme);
        }
    };

    match verified {
        true => Ok(CertificateVerification::Certifies),
        false => Ok(CertificateVerification::DoesNotCertify),
    }
}

/// Match a hostname against the certificate's names.
///
/// Per RFC 6125 Section 6.4.4, if the certificate contains Subject Alternative
/// Names (SANs), only the SANs are used for matching and the Common Name (CN)
/// is ignored. If no SANs are present, the CN is used as a fallback.
fn tls_hostname_match(
    names: &CertificateNames,
    hostname: &Option<heapless::String<HOSTNAME_MAXLEN>>,
) -> bool {
    let hostname = match hostname.as_ref() {
        Some(h) => h,
        None => {
            return names.common_name.is_none() && names.san_dns_names.is_empty();
        }
    };

    for san in &names.san_dns_names {
        if tls_hostname_match_impl(san.as_bytes(), hostname.as_bytes()) {
            return true;
        }
    }

    match names.common_name.as_ref() {
        Some(cn) => tls_hostname_match_impl(cn.as_bytes(), hostname.as_bytes()),
        None => false,
    }
}

fn tls_hostname_match_impl(cn: &[u8], host: &[u8]) -> bool {
    let mut cn_labels = 1;
    let mut host_labels = 1;
    let mut stars = 0;

    for &b in cn {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'*' => {}
            _ => return false,
        }
        if b == b'.' {
            cn_labels += 1;
        }
        if b == b'*' {
            stars += 1;
        }
    }

    for &b in host {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' => {}
            _ => return false,
        }
        if b == b'.' {
            host_labels += 1;
        }
    }

    if stars == 0 {
        if cn.len() != host.len() {
            return false;
        }
        for i in 0..cn.len() {
            if cn[i].to_ascii_lowercase() != host[i].to_ascii_lowercase() {
                return false;
            }
        }
        return true;
    }

    // RFC 6125 wildcard rules
    if stars != 1 {
        return false;
    }
    if !cn.starts_with(b"*.") {
        return false;
    }
    if cn_labels < 3 {
        return false;
    }
    if cn_labels != host_labels {
        return false;
    }

    let suffix = &cn[2..];
    let mut dot_idx = None;
    for i in 0..host.len() {
        if host[i] == b'.' {
            dot_idx = Some(i);
            break;
        }
    }
    let dot_idx = match dot_idx {
        Some(i) => i,
        None => return false,
    };
    let host_suffix = &host[dot_idx + 1..];

    if suffix.len() != host_suffix.len() {
        return false;
    }

    for i in 0..suffix.len() {
        if suffix[i].to_ascii_lowercase() != host_suffix[i].to_ascii_lowercase() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::tls_hostname_match_impl;

    #[test]
    fn exact_match() {
        assert!(tls_hostname_match_impl(b"example.com", b"example.com"));
        assert!(tls_hostname_match_impl(b"EXAMPLE.COM", b"example.com"));
        assert!(tls_hostname_match_impl(b"example.com", b"EXAMPLE.COM"));
    }

    #[test]
    fn exact_mismatch() {
        assert!(!tls_hostname_match_impl(b"example.com", b"example.org"));
        assert!(!tls_hostname_match_impl(b"example.com", b"sub.example.com"));
    }

    #[test]
    fn valid_wildcard_match() {
        assert!(tls_hostname_match_impl(
            b"*.example.com",
            b"api.example.com"
        ));
        assert!(tls_hostname_match_impl(
            b"*.example.com",
            b"WWW.example.com"
        ));
    }

    #[test]
    fn wildcard_single_label_only() {
        assert!(!tls_hostname_match_impl(
            b"*.example.com",
            b"a.b.example.com"
        ));
    }

    #[test]
    fn wildcard_requires_same_label_count() {
        assert!(!tls_hostname_match_impl(b"*.example.com", b"example.com"));
        assert!(!tls_hostname_match_impl(
            b"*.example.com",
            b"deep.api.example.com"
        ));
    }

    #[test]
    fn wildcard_must_be_leftmost_label() {
        assert!(!tls_hostname_match_impl(
            b"api.*.example.com",
            b"api.test.example.com"
        ));
        assert!(!tls_hostname_match_impl(
            b"foo*.example.xx",
            b"foobar.example.xx"
        ));
    }

    #[test]
    fn wildcard_requires_minimum_three_labels() {
        assert!(!tls_hostname_match_impl(b"*.com", b"example.com"));
        assert!(!tls_hostname_match_impl(b"*.org", b"test.org"));
    }

    #[test]
    fn multiple_wildcards_rejected() {
        assert!(!tls_hostname_match_impl(
            b"*.*.example.com",
            b"a.b.example.com"
        ));
        assert!(!tls_hostname_match_impl(
            b"**.example.com",
            b"api.example.com"
        ));
    }

    #[test]
    fn idna_a_label_supported() {
        assert!(tls_hostname_match_impl(
            b"xn--bcher-kva.example",
            b"xn--bcher-kva.example"
        ));

        assert!(tls_hostname_match_impl(
            b"*.xn--bcher-kva.example",
            b"api.xn--bcher-kva.example"
        ));
    }

    #[test]
    fn unicode_rejected() {
        assert!(!tls_hostname_match_impl(
            "bücher.example".as_bytes(),
            "bücher.example".as_bytes()
        ));
        assert!(!tls_hostname_match_impl(
            "*.bücher.example".as_bytes(),
            "api.bücher.example".as_bytes()
        ));
    }

    #[test]
    fn invalid_characters_rejected() {
        assert!(!tls_hostname_match_impl(b"example!.com", b"example!.com"));
        assert!(!tls_hostname_match_impl(b"example.com", b"exa mple.com"));
    }
}
