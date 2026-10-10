//! rustls-webpki signature algorithms over embassy-crypto, and over the `rsa` crate for RSA.
//!
//! Each algorithm uses only embassy-crypto, `rsa` and `rustls-pki-types`, so that it can move
//! to a crate of its own.

use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};

/// Verifies `signature` over `message` with the public key from a certificate's
/// `subjectPublicKey`.
type Verify = fn(&[u8], &[u8], &[u8]) -> Result<(), InvalidSignature>;

#[derive(Debug)]
pub(super) struct Algorithm {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    verify: Verify,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        (self.verify)(public_key, message, signature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

// Only the pairings TLS 1.3 names, ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384, which
// are the ones the client advertises. P-256 with SHA-384 would make every firmware with
// `p256` link a SHA-384 driver.
#[cfg(feature = "p256")]
pub(super) static ECDSA_P256_SHA256: Algorithm = Algorithm {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA256,
    verify: |key, message, signature| {
        crate::crypto::verify_ecdsa_p256(key, message, signature).map_err(|_| InvalidSignature)
    },
};

#[cfg(feature = "p384")]
pub(super) static ECDSA_P384_SHA384: Algorithm = Algorithm {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA384,
    verify: |key, message, signature| {
        crate::crypto::verify_ecdsa_p384(key, message, signature).map_err(|_| InvalidSignature)
    },
};

#[cfg(feature = "ed25519")]
pub(super) static ED25519: Algorithm = Algorithm {
    public_key: alg_id::ED25519,
    signature: alg_id::ED25519,
    verify: |key, message, signature| {
        crate::crypto::verify_ed25519(key, message, signature).map_err(|_| InvalidSignature)
    },
};

#[cfg(feature = "rsa")]
pub(super) static RSA_PKCS1_SHA256: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA256,
    verify: rsa_pkcs1::<rsa::sha2::Sha256>,
};

#[cfg(feature = "rsa")]
pub(super) static RSA_PKCS1_SHA384: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA384,
    verify: rsa_pkcs1::<rsa::sha2::Sha384>,
};

#[cfg(feature = "rsa")]
pub(super) static RSA_PKCS1_SHA512: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA512,
    verify: rsa_pkcs1::<rsa::sha2::Sha512>,
};

// TLS 1.3's rsa_pss_rsae schemes sign with an rsaEncryption key, so the public key
// identifier is RSA_ENCRYPTION, not the RSASSA-PSS one.
#[cfg(feature = "rsa")]
pub(super) static RSA_PSS_SHA256: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA256,
    verify: rsa_pss::<rsa::sha2::Sha256>,
};

#[cfg(feature = "rsa")]
pub(super) static RSA_PSS_SHA384: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA384,
    verify: rsa_pss::<rsa::sha2::Sha384>,
};

#[cfg(feature = "rsa")]
pub(super) static RSA_PSS_SHA512: Algorithm = Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA512,
    verify: rsa_pss::<rsa::sha2::Sha512>,
};

/// Every algorithm the enabled features provide, for certificate signatures.
pub(super) static ALL: &[&dyn SignatureVerificationAlgorithm] = &[
    #[cfg(feature = "p256")]
    &ECDSA_P256_SHA256,
    #[cfg(feature = "p384")]
    &ECDSA_P384_SHA384,
    #[cfg(feature = "ed25519")]
    &ED25519,
    #[cfg(feature = "rsa")]
    &RSA_PKCS1_SHA256,
    #[cfg(feature = "rsa")]
    &RSA_PKCS1_SHA384,
    #[cfg(feature = "rsa")]
    &RSA_PKCS1_SHA512,
    #[cfg(feature = "rsa")]
    &RSA_PSS_SHA256,
    #[cfg(feature = "rsa")]
    &RSA_PSS_SHA384,
    #[cfg(feature = "rsa")]
    &RSA_PSS_SHA512,
];

/// Decodes an RSA public key of 2048 to 8192 bits, the sizes rustls-webpki's own RSA
/// algorithms accept.
#[cfg(feature = "rsa")]
fn rsa_key(key: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_pkcs1_der(key).map_err(|_| InvalidSignature)?;
    if !(2048..=8192).contains(&key.n().bits()) {
        return Err(InvalidSignature);
    }
    Ok(key)
}

#[cfg(feature = "rsa")]
fn rsa_pkcs1<D>(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature>
where
    D: rsa::sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    use rsa::signature::Verifier;

    let key = rsa::pkcs1v15::VerifyingKey::<D>::new(rsa_key(key)?);
    let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| InvalidSignature)
}

#[cfg(feature = "rsa")]
fn rsa_pss<D>(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature>
where
    D: rsa::sha2::Digest + rsa::sha2::digest::FixedOutputReset,
{
    use rsa::signature::Verifier;

    let key = rsa::pss::VerifyingKey::<D>::new(rsa_key(key)?);
    let signature = rsa::pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| InvalidSignature)
}

#[cfg(all(test, feature = "rsa"))]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_that_does_not_parse_is_rejected() {
        let result =
            (RSA_PSS_SHA256.verify)(&[0x30, 0x03, 0x02, 0x01, 0x01], b"message", &[0; 256]);
        assert!(result.is_err());
    }
}
