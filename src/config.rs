use crate::TlsError;
use crate::cipher_suites::CipherSuite;
use crate::crypto::{TlsAead, TlsHash};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::extensions::extension_data::supported_groups::NamedGroup;
pub use crate::handshake::certificate::{CertificateEntryRef, CertificateRef};
pub use crate::handshake::certificate_verify::CertificateVerifyRef;
use heapless::Vec;

pub use crate::extensions::extension_data::max_fragment_length::MaxFragmentLength;

pub const TLS_RECORD_OVERHEAD: usize = 128;

/// Represents a TLS 1.3 cipher suite
pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: TlsAead;
    type Hash: TlsHash;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = embassy_crypto::Aes128Gcm;
    type Hash = embassy_crypto::Sha256;
}

pub struct Aes256GcmSha384;
impl TlsCipherSuite for Aes256GcmSha384 {
    const CODE_POINT: u16 = CipherSuite::TlsAes256GcmSha384 as u16;
    type Cipher = embassy_crypto::Aes256Gcm;
    type Hash = embassy_crypto::Sha384;
}

/// A TLS 1.3 verifier.
///
/// The verifier is responsible for verifying certificates and signatures. Since certificate verification is
/// an expensive process, this trait allows clients to choose how much verification should take place,
/// and also to skip the verification if the server is verified through other means (I.e. a pre-shared key).
pub trait TlsVerifier<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    /// Host verification is enabled by passing a server hostname.
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), crate::TlsError>;

    /// Verify a certificate.
    ///
    /// The handshake transcript up to this point and the server certificate is provided
    /// for the implementation to use. The verifier is responsible for resolving the CA
    /// certificate internally.
    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: CertificateRef,
    ) -> Result<(), TlsError>;

    /// Verify the certificate signature.
    ///
    /// The signature verification uses the transcript and certificate provided earlier to decode the provided signature.
    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), crate::TlsError>;
}

impl<CipherSuite, T> TlsVerifier<CipherSuite> for &mut T
where
    CipherSuite: TlsCipherSuite,
    T: TlsVerifier<CipherSuite>,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), crate::TlsError> {
        T::set_hostname_verification(self, hostname)
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {
        T::verify_certificate(self, transcript, cert)
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), crate::TlsError> {
        T::verify_signature(self, verify)
    }
}

/// A verifier that accepts any server certificate without checking it.
///
/// Only use this when the server is authenticated by other means, such as a pre-shared key,
/// or for testing.
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoVerify;

impl<CipherSuite> TlsVerifier<CipherSuite> for NoVerify
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), crate::TlsError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        _transcript: &CipherSuite::Hash,
        _cert: CertificateRef,
    ) -> Result<(), TlsError> {
        Ok(())
    }

    fn verify_signature(&mut self, _verify: CertificateVerifyRef) -> Result<(), crate::TlsError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "TlsConfig does nothing unless consumed"]
pub struct TlsConfig<'a> {
    pub(crate) server_name: Option<&'a str>,
    pub(crate) alpn_protocols: Option<&'a [&'a [u8]]>,
    pub(crate) psk: Option<(&'a [u8], Vec<&'a [u8], 4>)>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 25>,
    pub(crate) named_groups: Vec<NamedGroup, 13>,
    pub(crate) max_fragment_length: Option<MaxFragmentLength>,
}

pub trait TlsClock {
    fn now() -> Option<u64>;
}

pub struct NoClock;

impl TlsClock for NoClock {
    fn now() -> Option<u64> {
        None
    }
}

/// A signing key held outside this crate — an HSM, TPM, secure element, or any
/// other device that signs without releasing the private key.
///
/// Implement this when the private key cannot be loaded into memory, and pass it
/// as [`PrivateKey::External`]. The implementation receives the message to be
/// signed and writes the TLS encoding of the signature (the same encoding the
/// built-in variants produce: DER `SEQUENCE { r, s }` for ECDSA, the raw 64-byte
/// `R || S` for Ed25519).
pub trait SigningKey {
    /// The signature scheme this key signs with.
    fn signature_scheme(&self) -> SignatureScheme;

    /// Sign `message`, writing the TLS encoding of the signature to `out`.
    ///
    /// Returns the number of bytes written, or [`TlsError::EncodeError`] if `out`
    /// is too small to hold the signature.
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, TlsError>;
}

/// A private key used to sign the `CertificateVerify` message for client certificate authentication.
///
/// Signing is performed by the `embassy-crypto` driver registered for the key's algorithm.
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    /// ECDSA over P-256 with SHA-256 (`ecdsa_secp256r1_sha256`).
    #[cfg(feature = "p256")]
    EcdsaP256(embassy_crypto::p256::SigningKey),
    /// ECDSA over P-384 with SHA-384 (`ecdsa_secp384r1_sha384`).
    #[cfg(feature = "p384")]
    EcdsaP384(embassy_crypto::p384::SigningKey),
    /// Ed25519 (`ed25519`).
    #[cfg(feature = "ed25519")]
    Ed25519(embassy_crypto::ed25519::SigningKey),
    /// RSA, signing with RSASSA-PSS over SHA-256 (`rsa_pss_rsae_sha256`).
    #[cfg(feature = "rsa")]
    Rsa(rsa::RsaPrivateKey),
    /// A key held outside this crate, signed by a [`SigningKey`] implementation.
    ///
    /// Use this when the private key never leaves its hardware — an HSM, TPM or
    /// secure element — and so cannot be represented by the variants above.
    External(&'static dyn SigningKey),
}

impl PrivateKey {
    /// Load an EC private key from its DER-encoded SEC1 `ECPrivateKey` (RFC 5915) structure.
    ///
    /// This is the format of `-----BEGIN EC PRIVATE KEY-----` PEM files. The curve is selected
    /// by the size of the private scalar.
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, TlsError> {
        let scalar =
            crate::crypto::sec1_private_key(der).map_err(|_| TlsError::InvalidPrivateKey)?;
        Self::from_ec_bytes(scalar)
    }

    /// Load an EC private key from its raw big-endian scalar.
    ///
    /// The curve is selected by the size of the scalar: 32 bytes for P-256, 48 bytes for P-384.
    pub fn from_ec_bytes(scalar: &[u8]) -> Result<Self, TlsError> {
        match scalar.len() {
            #[cfg(feature = "p256")]
            32 => embassy_crypto::p256::SigningKey::from_bytes(unwrap!(scalar.try_into()))
                .map(Self::EcdsaP256)
                .map_err(|_| TlsError::InvalidPrivateKey),
            #[cfg(feature = "p384")]
            48 => embassy_crypto::p384::SigningKey::from_bytes(unwrap!(scalar.try_into()))
                .map(Self::EcdsaP384)
                .map_err(|_| TlsError::InvalidPrivateKey),
            _ => Err(TlsError::InvalidPrivateKey),
        }
    }

    /// The signature scheme this key signs with.
    #[must_use]
    pub fn signature_scheme(&self) -> SignatureScheme {
        // A place expression, so that the match is exhaustive when no algorithm is enabled.
        match *self {
            #[cfg(feature = "p256")]
            Self::EcdsaP256(_) => SignatureScheme::EcdsaSecp256r1Sha256,
            #[cfg(feature = "p384")]
            Self::EcdsaP384(_) => SignatureScheme::EcdsaSecp384r1Sha384,
            #[cfg(feature = "ed25519")]
            Self::Ed25519(_) => SignatureScheme::Ed25519,
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => SignatureScheme::RsaPssRsaeSha256,
            Self::External(key) => key.signature_scheme(),
        }
    }

    /// Sign `message`, writing the TLS encoding of the signature to `out`.
    #[cfg_attr(
        not(any(
            feature = "p256",
            feature = "p384",
            feature = "ed25519",
            feature = "rsa"
        )),
        allow(unused_variables)
    )]
    pub(crate) fn sign<const N: usize>(
        &self,
        message: &[u8],
        out: &mut Vec<u8, N>,
    ) -> Result<(), TlsError> {
        match *self {
            #[cfg(feature = "p256")]
            Self::EcdsaP256(ref key) => crate::crypto::sign_ecdsa_p256(key, message, out),
            #[cfg(feature = "p384")]
            Self::EcdsaP384(ref key) => crate::crypto::sign_ecdsa_p384(key, message, out),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(ref key) => crate::crypto::sign_ed25519(key, message, out),
            #[cfg(feature = "rsa")]
            Self::Rsa(ref key) => {
                use rsa::signature::{RandomizedSigner, SignatureEncoding};

                let signing_key = rsa::pss::SigningKey::<rsa::sha2::Sha256>::new(key.clone());
                let signature = signing_key
                    .try_sign_with_rng(&mut crate::crypto::RsaRng, message)
                    .map_err(|_| TlsError::CryptoError)?;
                out.clear();
                out.extend_from_slice(&signature.to_bytes())
                    .map_err(|_| TlsError::EncodeError)
            }
            Self::External(key) => {
                out.clear();
                out.resize_default(N).map_err(|_| TlsError::EncodeError)?;
                let len = key.sign(message, out)?;
                out.truncate(len);
                Ok(())
            }
        }
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PrivateKey")
            .field(&self.signature_scheme())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PrivateKey {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "PrivateKey({:?})", self.signature_scheme());
    }
}

/// Everything needed to open a connection: the configuration, the certificate verifier
/// and, optionally, the client certificate and key for mutual authentication.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, Verifier> {
    pub(crate) config: &'a TlsConfig<'a>,
    pub(crate) verifier: Verifier,
    pub(crate) client_cert: Option<Certificate<&'a [u8]>>,
    pub(crate) private_key: Option<&'a PrivateKey>,
}

impl<'a, Verifier> TlsContext<'a, Verifier> {
    /// Create a new context with a given config, using `verifier` to verify the server
    /// certificate and its signature.
    ///
    /// Pass [`NoVerify`] to skip certificate verification entirely. Only do that when the
    /// server is authenticated by other means, such as a pre-shared key, or for testing.
    #[must_use]
    pub fn new(config: &'a TlsConfig<'a>, verifier: Verifier) -> Self {
        Self {
            config,
            verifier,
            client_cert: None,
            private_key: None,
        }
    }

    /// Present `cert` and sign with `key` if the server requests client certificate authentication.
    #[must_use]
    pub fn with_client_cert(mut self, cert: Certificate<&'a [u8]>, key: &'a PrivateKey) -> Self {
        self.client_cert = Some(cert);
        self.private_key = Some(key);
        self
    }
}

impl<'a> TlsConfig<'a> {
    pub fn new() -> Self {
        let mut config = Self {
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: None,
            psk: None,
            server_name: None,
            alpn_protocols: None,
        };

        if cfg!(feature = "alloc") {
            config = config.enable_rsa_signatures();
        }

        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp256r1Sha256)
                .ok()
        );
        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp384r1Sha384)
                .ok()
        );
        unwrap!(config.signature_schemes.push(SignatureScheme::Ed25519).ok());

        unwrap!(config.named_groups.push(NamedGroup::Secp256r1));

        config
    }

    /// Enable RSA ciphers even if they might not be supported.
    pub fn enable_rsa_signatures(mut self) -> Self {
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha512)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha512)
                .ok()
        );
        self
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Configure ALPN protocol names to send in the ClientHello.
    ///
    /// The server will select one of the offered protocols and echo it back
    /// in EncryptedExtensions. This is required for endpoints that multiplex
    /// protocols on a single port (e.g. AWS IoT Core MQTT over port 443).
    pub fn with_alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn_protocols = Some(protocols);
        self
    }

    /// Configures the maximum plaintext fragment size.
    ///
    /// This option may help reduce memory size, as smaller fragment lengths require smaller
    /// read/write buffers. Note that embedded-tls does not currently use this option to fragment
    /// writes. Note that the buffers need to include some overhead over the configured fragment
    /// length.
    ///
    /// From [RFC 6066, Section 4.  Maximum Fragment Length Negotiation](https://www.rfc-editor.org/rfc/rfc6066#page-8):
    ///
    /// > Without this extension, TLS specifies a fixed maximum plaintext
    /// > fragment length of 2^14 bytes.  It may be desirable for constrained
    /// > clients to negotiate a smaller maximum fragment length due to memory
    /// > limitations or bandwidth limitations.
    ///
    /// > For example, if the negotiated length is 2^9=512, then, when using currently defined
    /// > cipher suites ([...]) and null compression, the record-layer output can be at most
    /// > 805 bytes: 5 bytes of headers, 512 bytes of application data, 256 bytes of padding,
    /// > and 32 bytes of MAC.
    pub fn with_max_fragment_length(mut self, max_fragment_length: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(max_fragment_length);
        self
    }

    /// Resets the max fragment length to 14 bits (16384).
    pub fn reset_max_fragment_length(mut self) -> Self {
        self.max_fragment_length = None;
        self
    }

    pub fn with_psk(mut self, psk: &'a [u8], identities: &[&'a [u8]]) -> Self {
        // TODO: Remove potential panic
        self.psk = Some((psk, unwrap!(Vec::from_slice(identities).ok())));
        self
    }
}

impl Default for TlsConfig<'_> {
    fn default() -> Self {
        TlsConfig::new()
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certificate<D> {
    X509(D),
    RawPublicKey(D),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signer standing in for an HSM: it holds no key material, and produces a
    /// signature the test can recognise.
    struct ExternalEd25519;

    impl SigningKey for ExternalEd25519 {
        fn signature_scheme(&self) -> SignatureScheme {
            SignatureScheme::Ed25519
        }

        fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
            if out.len() < 64 {
                return Err(TlsError::EncodeError);
            }
            out[..64].fill(0xAB);
            out[0] = message.len() as u8;
            Ok(64)
        }
    }

    struct TooBig;

    impl SigningKey for TooBig {
        fn signature_scheme(&self) -> SignatureScheme {
            SignatureScheme::Ed25519
        }

        fn sign(&self, _message: &[u8], _out: &mut [u8]) -> Result<usize, TlsError> {
            Err(TlsError::EncodeError)
        }
    }

    #[test]
    fn external_key_reports_its_own_scheme() {
        let key = PrivateKey::External(&ExternalEd25519);
        assert_eq!(key.signature_scheme(), SignatureScheme::Ed25519);
    }

    #[test]
    fn external_key_signature_is_truncated_to_the_length_written() {
        let key = PrivateKey::External(&ExternalEd25519);
        let mut out = Vec::<u8, 128>::new();
        key.sign(b"hello", &mut out).unwrap();

        assert_eq!(out.len(), 64);
        assert_eq!(out[0], 5);
        assert_eq!(out[1], 0xAB);
    }

    #[test]
    fn external_key_signing_twice_does_not_accumulate() {
        let key = PrivateKey::External(&ExternalEd25519);
        let mut out = Vec::<u8, 128>::new();
        key.sign(b"hello", &mut out).unwrap();
        key.sign(b"hi", &mut out).unwrap();

        assert_eq!(out.len(), 64);
        assert_eq!(out[0], 2);
    }

    #[test]
    fn external_key_propagates_signing_errors() {
        let key = PrivateKey::External(&TooBig);
        let mut out = Vec::<u8, 128>::new();
        assert!(key.sign(b"hello", &mut out).is_err());
    }
}
