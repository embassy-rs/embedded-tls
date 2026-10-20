use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

use heapless::Vec;

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,

    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,

    /* EdDSA algorithms */
    Ed25519,
    Ed448,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,

    Sha224Ecdsa,
    Sha224Rsa,
    Sha224Dsa,

    /* Legacy algorithms */
    RsaPkcs1Sha1,
    EcdsaSha1,

    /* Brainpool */
    Sha256BrainpoolP256r1,
    Sha384BrainpoolP384r1,
    Sha512BrainpoolP512r1,

    /* ML-DSA */
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /* Reserved Code Points */
    //private_use(0xFE00..0xFFFF),
    //(0xFFFF)
}

impl SignatureScheme {
    #[must_use]
    pub fn of(raw: u16) -> Option<Self> {
        match raw {
            0x0401 => Some(Self::RsaPkcs1Sha256),
            0x0501 => Some(Self::RsaPkcs1Sha384),
            0x0601 => Some(Self::RsaPkcs1Sha512),

            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0603 => Some(Self::EcdsaSecp521r1Sha512),

            0x0804 => Some(Self::RsaPssRsaeSha256),
            0x0805 => Some(Self::RsaPssRsaeSha384),
            0x0806 => Some(Self::RsaPssRsaeSha512),

            0x0807 => Some(Self::Ed25519),
            0x0808 => Some(Self::Ed448),

            0x0809 => Some(Self::RsaPssPssSha256),
            0x080a => Some(Self::RsaPssPssSha384),
            0x080b => Some(Self::RsaPssPssSha512),

            0x0303 => Some(Self::Sha224Ecdsa),
            0x0301 => Some(Self::Sha224Rsa),
            0x0302 => Some(Self::Sha224Dsa),

            0x0201 => Some(Self::RsaPkcs1Sha1),
            0x0203 => Some(Self::EcdsaSha1),

            0x081A => Some(Self::Sha256BrainpoolP256r1),
            0x081B => Some(Self::Sha384BrainpoolP384r1),
            0x081C => Some(Self::Sha512BrainpoolP512r1),

            0x0904 => Some(Self::MlDsa44),
            0x0905 => Some(Self::MlDsa65),
            0x0906 => Some(Self::MlDsa87),

            _ => None,
        }
    }

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Self::of(buf.read_u16()?).ok_or(ParseError::InvalidData)
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::RsaPkcs1Sha256 => 0x0401,
            Self::RsaPkcs1Sha384 => 0x0501,
            Self::RsaPkcs1Sha512 => 0x0601,

            Self::EcdsaSecp256r1Sha256 => 0x0403,
            Self::EcdsaSecp384r1Sha384 => 0x0503,
            Self::EcdsaSecp521r1Sha512 => 0x0603,

            Self::RsaPssRsaeSha256 => 0x0804,
            Self::RsaPssRsaeSha384 => 0x0805,
            Self::RsaPssRsaeSha512 => 0x0806,

            Self::Ed25519 => 0x0807,
            Self::Ed448 => 0x0808,

            Self::RsaPssPssSha256 => 0x0809,
            Self::RsaPssPssSha384 => 0x080a,
            Self::RsaPssPssSha512 => 0x080b,

            Self::Sha224Ecdsa => 0x0303,
            Self::Sha224Rsa => 0x0301,
            Self::Sha224Dsa => 0x0302,

            Self::RsaPkcs1Sha1 => 0x0201,
            Self::EcdsaSha1 => 0x0203,

            Self::Sha256BrainpoolP256r1 => 0x081A,
            Self::Sha384BrainpoolP384r1 => 0x081B,
            Self::Sha512BrainpoolP512r1 => 0x081C,

            Self::MlDsa44 => 0x0904,
            Self::MlDsa65 => 0x0905,
            Self::MlDsa87 => 0x0906,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SignatureAlgorithms<const N: usize> {
    pub supported_signature_algorithms: Vec<SignatureScheme, N>,
}

impl<const N: usize> SignatureAlgorithms<N> {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;
        let mut data = buf.slice(data_length)?;
        let mut supported_signature_algorithms = Vec::new();
        while !data.is_empty() {
            let raw = data.read_u16()?;
            if let Some(scheme) = SignatureScheme::of(raw) {
                supported_signature_algorithms
                    .push(scheme)
                    .map_err(|_| ParseError::InsufficientSpace)?;
            }
        }
        Ok(Self {
            supported_signature_algorithms,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for &a in &self.supported_signature_algorithms {
                buf.push_u16(a.as_u16())
                    .map_err(|_| TlsError::EncodeError)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod skip_unknown_tests {
    use super::*;
    use crate::parse_buffer::ParseBuffer;

    #[test]
    fn then_unknown_code_points_are_skipped() {
        // length: 3 u16s = 6 bytes
        let bytes = [0x00, 0x06, 0xFA, 0xFA, 0x04, 0x01, 0xAB, 0xCD];
        let mut buf = ParseBuffer::new(&bytes);
        let parsed = SignatureAlgorithms::<8>::parse(&mut buf).expect("parses");
        const EXPECTED: usize = 1;
        assert_eq!(parsed.supported_signature_algorithms.len(), EXPECTED);
        assert_eq!(
            parsed.supported_signature_algorithms[0],
            SignatureScheme::RsaPkcs1Sha256
        );
    }

    #[test]
    fn then_malformed_length_is_rejected() {
        // length says 3 bytes (odd), trailing partial u16
        let bytes = [0x00, 0x03, 0x04, 0x01, 0xFF];
        let mut buf = ParseBuffer::new(&bytes);
        let result = SignatureAlgorithms::<8>::parse(&mut buf);
        assert!(result.is_err());
    }
}
