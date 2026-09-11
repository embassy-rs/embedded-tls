//! Cryptographic primitives, served by [`embassy_crypto`].
//!
//! This module adapts the concrete `embassy-crypto` types to the small set of
//! traits the TLS state machine is generic over ([`TlsHash`], [`TlsHmac`] and
//! [`TlsAead`]), and hosts the few constructions TLS needs on top of them:
//! HKDF, ECDSA signature DER (de)serialization and the `CertificateVerify`
//! signing/verification helpers.

use core::fmt::Debug;

#[cfg(any(feature = "p256", feature = "p384", test))]
use der::Encode;
#[cfg(any(feature = "p256", feature = "p384", test))]
use der::asn1::UintRef;
use der::asn1::{AnyRef, BitStringRef, OctetStringRef};
use der::{Decode, Sequence};
use heapless::Vec;

use crate::TlsError;

/// Size of an AEAD nonce, in bytes. TLS 1.3 uses 96-bit nonces for every cipher suite.
pub const NONCE_LEN: usize = 12;

/// Size of an AEAD tag, in bytes. TLS 1.3 uses 128-bit tags for every cipher suite.
pub const TAG_LEN: usize = 16;

/// A fixed-size byte array, as produced by a hash or used as an AEAD key.
pub trait ByteArray: Copy + AsRef<[u8]> + AsMut<[u8]> + Debug {
    /// Length in bytes.
    const LEN: usize;

    /// An all-zero array.
    fn zeroed() -> Self;
}

impl<const N: usize> ByteArray for [u8; N] {
    const LEN: usize = N;

    fn zeroed() -> Self {
        [0; N]
    }
}

/// A hash function usable as a TLS 1.3 transcript and HKDF hash.
pub trait TlsHash: Clone {
    /// The digest.
    type Output: ByteArray;

    /// HMAC over this hash.
    type Hmac: TlsHmac<Output = Self::Output>;

    /// Start a new hash computation.
    fn new() -> Self;

    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);

    /// Finish the computation and return the digest.
    fn finalize(self) -> Self::Output;

    /// Compute the digest of `data` in one call.
    #[must_use]
    fn digest(data: &[u8]) -> Self::Output {
        let mut hash = Self::new();
        hash.update(data);
        hash.finalize()
    }
}

/// A message authentication code usable for HKDF and the `Finished` messages.
pub trait TlsHmac {
    /// The tag.
    type Output: ByteArray;

    /// Start a new MAC computation with `key`.
    fn new(key: &[u8]) -> Self;

    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);

    /// Finish the computation and return the tag.
    fn finalize(self) -> Self::Output;

    /// Finish the computation and compare the tag with `tag` in constant time.
    fn verify(self, tag: &[u8]) -> bool;
}

/// An authenticated cipher usable as a TLS 1.3 record protection algorithm.
pub trait TlsAead {
    /// The key.
    type Key: ByteArray;

    /// Initialize with `key`.
    fn new(key: &Self::Key) -> Self;

    /// Encrypt `buf` in place, authenticating it and `aad`, and return the tag.
    fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], TlsError>;

    /// Verify `tag` over `buf` and `aad`, then decrypt `buf` in place.
    fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), TlsError>;
}

macro_rules! impl_hash {
    ($hash:ty, $hmac:ty, $size:literal) => {
        impl TlsHash for $hash {
            type Output = [u8; $size];
            type Hmac = $hmac;

            fn new() -> Self {
                <$hash>::new()
            }

            fn update(&mut self, data: &[u8]) {
                <$hash>::update(self, data);
            }

            fn finalize(self) -> Self::Output {
                <$hash>::finalize(self)
            }
        }

        impl TlsHmac for $hmac {
            type Output = [u8; $size];

            fn new(key: &[u8]) -> Self {
                <$hmac>::new(key)
            }

            fn update(&mut self, data: &[u8]) {
                <$hmac>::update(self, data);
            }

            fn finalize(self) -> Self::Output {
                <$hmac>::finalize(self)
            }

            fn verify(self, tag: &[u8]) -> bool {
                <$hmac>::verify(self, tag).is_ok()
            }
        }
    };
}

impl_hash!(embassy_crypto::Sha256, embassy_crypto::HmacSha256, 32);
impl_hash!(embassy_crypto::Sha384, embassy_crypto::HmacSha384, 48);

macro_rules! impl_aead {
    ($aead:ty, $key_size:literal) => {
        impl TlsAead for $aead {
            type Key = [u8; $key_size];

            fn new(key: &Self::Key) -> Self {
                <$aead>::new(key)
            }

            fn encrypt(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<[u8; TAG_LEN], TlsError> {
                <$aead>::encrypt(self, nonce, aad, buf).map_err(|_| TlsError::CryptoError)
            }

            fn decrypt(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                buf: &mut [u8],
                tag: &[u8; TAG_LEN],
            ) -> Result<(), TlsError> {
                <$aead>::decrypt(self, nonce, aad, buf, tag).map_err(|_| TlsError::CryptoError)
            }
        }
    };
}

impl_aead!(embassy_crypto::Aes128Gcm, 16);
impl_aead!(embassy_crypto::Aes256Gcm, 32);

/// HKDF (RFC 5869) over a [`TlsHash`].
pub struct Hkdf<H: TlsHash> {
    prk: H::Output,
}

impl<H: TlsHash> Hkdf<H> {
    /// `HKDF-Extract(salt, ikm)`.
    #[must_use]
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        let mut mac = H::Hmac::new(salt);
        mac.update(ikm);
        Self {
            prk: mac.finalize(),
        }
    }

    /// Wrap an existing pseudorandom key.
    pub fn from_prk(prk: &[u8]) -> Result<Self, TlsError> {
        if prk.len() != H::Output::LEN {
            return Err(TlsError::InternalError);
        }
        let mut out = H::Output::zeroed();
        out.as_mut().copy_from_slice(prk);
        Ok(Self { prk: out })
    }

    /// The pseudorandom key.
    pub fn prk(&self) -> &H::Output {
        &self.prk
    }

    /// `HKDF-Expand(prk, info, okm.len())`, written to `okm`.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), TlsError> {
        if okm.len().div_ceil(H::Output::LEN) > 255 {
            return Err(TlsError::CryptoError);
        }

        let mut previous: Option<H::Output> = None;
        for (i, chunk) in okm.chunks_mut(H::Output::LEN).enumerate() {
            let mut mac = H::Hmac::new(self.prk.as_ref());
            if let Some(previous) = &previous {
                mac.update(previous.as_ref());
            }
            mac.update(info);
            mac.update(&[i as u8 + 1]);
            let block = mac.finalize();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            previous = Some(block);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DER structures
// ---------------------------------------------------------------------------

/// `ECDSA-Sig-Value` (RFC 3279 section 2.2.3): the encoding of ECDSA signatures in
/// both TLS `CertificateVerify` messages and X.509 certificates.
#[cfg(any(feature = "p256", feature = "p384", test))]
#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// `ECPrivateKey` (RFC 5915 section 3).
#[derive(Sequence)]
struct EcPrivateKey<'a> {
    version: u8,
    private_key: &'a OctetStringRef,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}

/// Left-pad an unsigned integer into a fixed-size, big-endian array.
#[cfg(any(
    all(feature = "rustpki", any(feature = "p256", feature = "p384")),
    test
))]
fn uint_to_array<const N: usize>(value: UintRef<'_>) -> Result<[u8; N], TlsError> {
    let bytes = value.as_bytes();
    if bytes.len() > N {
        return Err(TlsError::DecodeError);
    }
    let mut out = [0; N];
    out[N - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

/// Parse a DER `ECDSA-Sig-Value` into its `(r, s)` components.
#[cfg(any(
    all(feature = "rustpki", any(feature = "p256", feature = "p384")),
    test
))]
pub(crate) fn ecdsa_signature_from_der<const N: usize>(
    der: &[u8],
) -> Result<([u8; N], [u8; N]), TlsError> {
    let signature = EcdsaSigValue::from_der(der).map_err(|_| TlsError::DecodeError)?;
    Ok((uint_to_array(signature.r)?, uint_to_array(signature.s)?))
}

/// Encode an ECDSA signature `(r, s)` as a DER `ECDSA-Sig-Value`.
#[cfg(any(feature = "p256", feature = "p384", test))]
pub(crate) fn ecdsa_signature_to_der<const N: usize>(
    r: &[u8],
    s: &[u8],
    out: &mut Vec<u8, N>,
) -> Result<(), TlsError> {
    let signature = EcdsaSigValue {
        r: UintRef::new(r).map_err(|_| TlsError::EncodeError)?,
        s: UintRef::new(s).map_err(|_| TlsError::EncodeError)?,
    };
    // Two 48-byte integers, each with a possible leading zero, plus headers.
    let mut buf = [0u8; 104];
    let encoded = signature
        .encode_to_slice(&mut buf)
        .map_err(|_| TlsError::EncodeError)?;
    out.clear();
    out.extend_from_slice(encoded)
        .map_err(|_| TlsError::EncodeError)
}

/// Parse a SEC1 `ECPrivateKey` and return the raw private scalar.
pub(crate) fn sec1_private_key(der: &[u8]) -> Result<&[u8], TlsError> {
    let key = EcPrivateKey::from_der(der).map_err(|_| TlsError::DecodeError)?;
    if key.version != 1 {
        return Err(TlsError::DecodeError);
    }
    Ok(key.private_key.as_bytes())
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

/// Verify a DER-encoded ECDSA/P-256 signature over `message`, hashed with SHA-256.
///
/// `public_key` is the uncompressed SEC1 encoding of the public key.
#[cfg(all(feature = "rustpki", feature = "p256"))]
pub(crate) fn verify_ecdsa_p256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use embassy_crypto::p256::{Signature, VerifyingKey};

    let public_key = public_key.try_into().map_err(|_| TlsError::DecodeError)?;
    let verifying_key = VerifyingKey::from_sec1(public_key).map_err(|_| TlsError::DecodeError)?;
    let (r, s) = ecdsa_signature_from_der::<32>(signature)?;
    let signature = Signature::from_scalars(&r, &s).map_err(|_| TlsError::DecodeError)?;
    let digest = embassy_crypto::Sha256::digest(message);
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| TlsError::InvalidSignature)
}

/// Verify a DER-encoded ECDSA/P-384 signature over `message`, hashed with SHA-384.
///
/// `public_key` is the uncompressed SEC1 encoding of the public key.
#[cfg(all(feature = "rustpki", feature = "p384"))]
pub(crate) fn verify_ecdsa_p384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use embassy_crypto::p384::{Signature, VerifyingKey};

    let public_key = public_key.try_into().map_err(|_| TlsError::DecodeError)?;
    let verifying_key = VerifyingKey::from_sec1(public_key).map_err(|_| TlsError::DecodeError)?;
    let (r, s) = ecdsa_signature_from_der::<48>(signature)?;
    let signature = Signature::from_scalars(&r, &s).map_err(|_| TlsError::DecodeError)?;
    let digest = embassy_crypto::Sha384::digest(message);
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| TlsError::InvalidSignature)
}

/// Sign `message` with ECDSA/P-256 over SHA-256, writing the DER-encoded signature to `out`.
#[cfg(feature = "p256")]
pub(crate) fn sign_ecdsa_p256<const N: usize>(
    key: &embassy_crypto::p256::SigningKey,
    message: &[u8],
    out: &mut Vec<u8, N>,
) -> Result<(), TlsError> {
    let digest = embassy_crypto::Sha256::digest(message);
    let signature = key
        .sign_prehash(&digest)
        .map_err(|_| TlsError::CryptoError)?;
    ecdsa_signature_to_der(signature.r(), signature.s(), out)
}

/// Sign `message` with ECDSA/P-384 over SHA-384, writing the DER-encoded signature to `out`.
#[cfg(feature = "p384")]
pub(crate) fn sign_ecdsa_p384<const N: usize>(
    key: &embassy_crypto::p384::SigningKey,
    message: &[u8],
    out: &mut Vec<u8, N>,
) -> Result<(), TlsError> {
    let digest = embassy_crypto::Sha384::digest(message);
    let signature = key
        .sign_prehash(&digest)
        .map_err(|_| TlsError::CryptoError)?;
    ecdsa_signature_to_der(signature.r(), signature.s(), out)
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature over `message`.
///
/// `public_key` is the 32-byte compressed point and `signature` the 64-byte `R || S`.
#[cfg(all(feature = "ed25519", feature = "rustpki"))]
pub(crate) fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use embassy_crypto::ed25519::{Signature, VerifyingKey};

    let public_key = public_key.try_into().map_err(|_| TlsError::DecodeError)?;
    let signature = signature.try_into().map_err(|_| TlsError::DecodeError)?;
    VerifyingKey::from_bytes(public_key)
        .verify(message, &Signature::from_bytes(signature))
        .map_err(|_| TlsError::InvalidSignature)
}

/// Sign `message` with Ed25519, writing the 64-byte signature to `out`.
#[cfg(feature = "ed25519")]
pub(crate) fn sign_ed25519<const N: usize>(
    key: &embassy_crypto::ed25519::SigningKey,
    message: &[u8],
    out: &mut Vec<u8, N>,
) -> Result<(), TlsError> {
    let signature = key.sign(message).map_err(|_| TlsError::CryptoError)?;
    out.clear();
    out.extend_from_slice(signature.as_bytes())
        .map_err(|_| TlsError::EncodeError)
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// Adapter exposing the registered [`embassy_crypto::driver::Rng`] to the `rsa` crate.
#[cfg(feature = "rsa")]
pub(crate) struct RsaRng;

#[cfg(feature = "rsa")]
use embassy_crypto::rng_fill_bytes;

#[cfg(feature = "rsa")]
impl rsa::rand_core::RngCore for RsaRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rng_fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        rng_fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "rsa")]
impl rsa::rand_core::CryptoRng for RsaRng {}

// ---------------------------------------------------------------------------
// CertificateVerify
// ---------------------------------------------------------------------------

/// Size of the largest `CertificateVerify` signed content: 64 bytes of padding,
/// the 34-byte context string and a SHA-384 transcript hash.
pub(crate) const CERTIFICATE_VERIFY_MESSAGE_LEN: usize = 64 + 34 + 48;

/// Build the content signed in a `CertificateVerify` message (RFC 8446 section 4.4.3).
pub(crate) fn certificate_verify_message(
    context: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8, CERTIFICATE_VERIFY_MESSAGE_LEN>, TlsError> {
    let mut msg = Vec::new();
    msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(context)
        .map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(transcript_hash)
        .map_err(|_| TlsError::EncodeError)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_der_roundtrip() {
        let mut r = [0xffu8; 32];
        let mut s = [0x01u8; 32];
        r[0] = 0x80;
        s[0] = 0x00;
        s[1] = 0x00;

        let mut der = Vec::<u8, 104>::new();
        ecdsa_signature_to_der(&r, &s, &mut der).unwrap();
        // 0x30 len 0x02 0x21 0x00 r[32] 0x02 0x1e s[2..]
        assert_eq!(der.len(), 2 + 2 + 33 + 2 + 30);
        assert_eq!(&der[..5], &[0x30, 67, 0x02, 33, 0x00]);

        let (r2, s2) = ecdsa_signature_from_der::<32>(&der).unwrap();
        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    #[test]
    fn ecdsa_der_rejects_trailing_data() {
        let mut der = Vec::<u8, 104>::new();
        ecdsa_signature_to_der(&[1u8; 32], &[2u8; 32], &mut der).unwrap();
        der.push(0).unwrap();
        assert!(ecdsa_signature_from_der::<32>(&der).is_err());
    }

    #[test]
    fn sec1_private_key_parses() {
        // SEQUENCE { INTEGER 1, OCTET STRING (4 bytes), [0] { OID } }
        let der = [
            0x30, 0x10, 0x02, 0x01, 0x01, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xa0, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70,
        ];
        assert_eq!(sec1_private_key(&der).unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[cfg(all(feature = "ed25519", feature = "rustpki"))]
    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let key = embassy_crypto::ed25519::SigningKey::from_bytes(&[7u8; 32]);
        let public_key = key.verifying_key().unwrap().to_bytes();

        let mut signature = Vec::<u8, 64>::new();
        sign_ed25519(&key, b"hello", &mut signature).unwrap();
        assert_eq!(signature.len(), 64);
        verify_ed25519(&public_key, b"hello", &signature).unwrap();
        assert!(verify_ed25519(&public_key, b"hellp", &signature).is_err());
        assert!(verify_ed25519(&public_key[..31], b"hello", &signature).is_err());
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = core::array::from_fn(|i| i as u8);
        let info: [u8; 10] = core::array::from_fn(|i| 0xf0 + i as u8);

        let hkdf = Hkdf::<embassy_crypto::Sha256>::extract(&salt, &ikm);
        assert_eq!(
            hkdf.prk(),
            &[
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );

        let mut okm = [0; 42];
        hkdf.expand(&info, &mut okm).unwrap();
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }
}
