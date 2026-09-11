use core::marker::PhantomData;

use crate::TlsError;
use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::extensions::extension_data::supported_groups::NamedGroup;
pub use crate::handshake::certificate::{CertificateEntryRef, CertificateRef};
pub use crate::handshake::certificate_verify::CertificateVerifyRef;
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit};
use digest::array::ArraySize;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset, block_api::BlockSizeUser};
use heapless::Vec;
use p256::SecretKey;
use p256::ecdsa::SigningKey;
use rand_core::CryptoRng;
pub use sha2::{Sha256, Sha384};
use typenum::{Sum, U10, U12, U16, U32};

pub use crate::extensions::extension_data::max_fragment_length::MaxFragmentLength;

pub const TLS_RECORD_OVERHEAD: usize = 128;

// longest label is 12b -> buf <= 2 + 1 + 6 + longest + 1 + hash_out = hash_out + 22
type LongestLabel = U12;
type LabelOverhead = U10;
type LabelBuffer<CipherSuite> = Sum<
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize,
    Sum<LongestLabel, LabelOverhead>,
>;

/// Represents a TLS 1.3 cipher suite
pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: KeyInit<KeySize = Self::KeyLen> + AeadInOut<NonceSize = Self::IvLen>;
    type KeyLen: ArraySize;
    type IvLen: ArraySize;

    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
    type LabelBufferSize: ArraySize;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = Aes128Gcm;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = Sha256;
    type LabelBufferSize = LabelBuffer<Self>;
}

pub struct Aes256GcmSha384;
impl TlsCipherSuite for Aes256GcmSha384 {
    const CODE_POINT: u16 = CipherSuite::TlsAes256GcmSha384 as u16;
    type Cipher = Aes256Gcm;
    type KeyLen = U32;
    type IvLen = U12;

    type Hash = Sha384;
    type LabelBufferSize = LabelBuffer<Self>;
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

pub trait CryptoProvider {
    type CipherSuite: TlsCipherSuite;
    type Signature: AsRef<[u8]>;

    fn rng(&mut self) -> impl CryptoRng;

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, crate::TlsError> {
        Err::<&mut NoVerify, _>(crate::TlsError::Unimplemented)
    }

    /// Provide a signing key for client certificate authentication.
    ///
    /// The provider resolves the private key internally (e.g. from memory, flash, or a hardware
    /// crypto module such as an HSM/TPM/secure element).
    fn signer(
        &mut self,
    ) -> Result<(impl signature::Signer<Self::Signature>, SignatureScheme), crate::TlsError> {
        Err::<(NoSign, _), crate::TlsError>(crate::TlsError::Unimplemented)
    }

    /// Resolve the client certificate for mutual TLS authentication.
    ///
    /// Return `None` if no client certificate is available (an empty certificate message will
    /// be sent to the server). The data type `D` can be borrowed (`&[u8]`) or owned
    /// (e.g. `heapless::Vec<u8, N>`) — the certificate is only needed long enough to encode
    /// into the TLS message.
    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        None::<Certificate<&[u8]>>
    }
}

impl<T: CryptoProvider> CryptoProvider for &mut T {
    type CipherSuite = T::CipherSuite;

    type Signature = T::Signature;

    fn rng(&mut self) -> impl CryptoRng {
        T::rng(self)
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, crate::TlsError> {
        T::verifier(self)
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::Signer<Self::Signature>, SignatureScheme), crate::TlsError> {
        T::signer(self)
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        T::client_cert(self)
    }
}

pub struct NoSign;

impl<S> signature::Signer<S> for NoSign {
    fn try_sign(&self, _msg: &[u8]) -> Result<S, signature::Error> {
        unimplemented!()
    }
}

pub struct UnsecureProvider<'a, CipherSuite, RNG> {
    rng: RNG,
    priv_key: Option<&'a [u8]>,
    client_cert: Option<Certificate<&'a [u8]>>,
    _marker: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRng> UnsecureProvider<'_, (), RNG> {
    pub fn new<CipherSuite: TlsCipherSuite>(
        rng: RNG,
    ) -> UnsecureProvider<'static, CipherSuite, RNG> {
        UnsecureProvider {
            rng,
            priv_key: None,
            client_cert: None,
            _marker: PhantomData,
        }
    }
}

impl<'a, CipherSuite: TlsCipherSuite, RNG: CryptoRng> UnsecureProvider<'a, CipherSuite, RNG> {
    pub fn with_priv_key(mut self, priv_key: &'a [u8]) -> Self {
        self.priv_key = Some(priv_key);
        self
    }

    pub fn with_cert(mut self, cert: Certificate<&'a [u8]>) -> Self {
        self.client_cert = Some(cert);
        self
    }
}

impl<CipherSuite: TlsCipherSuite, RNG: CryptoRng> CryptoProvider
    for UnsecureProvider<'_, CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRng {
        &mut self.rng
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::Signer<Self::Signature>, SignatureScheme), crate::TlsError> {
        let key_der = self.priv_key.ok_or(TlsError::InvalidPrivateKey)?;
        let secret_key =
            SecretKey::from_sec1_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;

        Ok((
            SigningKey::from(&secret_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        self.client_cert.clone()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) config: &'a TlsConfig<'a>,
    pub(crate) crypto_provider: Provider,
}

impl<'a, Provider> TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    /// Create a new context with a given config and a crypto provider.
    pub fn new(config: &'a TlsConfig<'a>, crypto_provider: Provider) -> Self {
        Self {
            config,
            crypto_provider,
        }
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

        #[cfg(feature = "p384")]
        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp384r1Sha384)
                .ok()
        );

        #[cfg(feature = "ed25519")]
        unwrap!(config.signature_schemes.push(SignatureScheme::Ed25519).ok());

        #[cfg(not(feature = "x25519"))]
        unwrap!(config.named_groups.push(NamedGroup::Secp256r1));

        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        unwrap!(config.named_groups.push(NamedGroup::SecP256r1MLKEM768));

        #[cfg(feature = "x25519")]
        unwrap!(config.named_groups.push(NamedGroup::X25519));

        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        unwrap!(config.named_groups.push(NamedGroup::X25519MLKEM768));

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
