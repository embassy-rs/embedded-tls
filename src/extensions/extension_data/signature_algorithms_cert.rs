use crate::buffer::CryptoBuffer;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};

use heapless::Vec;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SignatureAlgorithmsCert<const N: usize> {
    pub supported_signature_algorithms: Vec<SignatureScheme, N>,
}

impl<const N: usize> SignatureAlgorithmsCert<N> {
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
    fn then_unknown_code_points_are_skipped_cert() {
        let bytes = [0x00, 0x06, 0xFA, 0xFA, 0x04, 0x01, 0xAB, 0xCD];
        let mut buf = ParseBuffer::new(&bytes);
        let parsed = SignatureAlgorithmsCert::<8>::parse(&mut buf).expect("parses");
        const EXPECTED: usize = 1;
        assert_eq!(parsed.supported_signature_algorithms.len(), EXPECTED);
        assert_eq!(
            parsed.supported_signature_algorithms[0],
            SignatureScheme::RsaPkcs1Sha256
        );
    }

    #[test]
    fn then_malformed_length_is_rejected_cert() {
        let bytes = [0x00, 0x03, 0x04, 0x01, 0xFF];
        let mut buf = ParseBuffer::new(&bytes);
        let result = SignatureAlgorithmsCert::<8>::parse(&mut buf);
        assert!(result.is_err());
    }
}
