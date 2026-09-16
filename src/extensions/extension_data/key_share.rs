use heapless::Vec;

use crate::buffer::CryptoBuffer;
use crate::extensions::extension_data::supported_groups::NamedGroup;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareServerHello<'a>(pub KeyShareEntry<'a>);

impl<'a> KeyShareServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        Ok(KeyShareServerHello(KeyShareEntry::parse(buf)?))
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.0.encode(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareClientHello<'a, const N: usize> {
    pub client_shares: Vec<KeyShareEntry<'a>, N>,
}

impl<'a, const N: usize> KeyShareClientHello<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let mut data = buf.slice(len)?;
        let mut client_shares = Vec::new();
        // Skip key shares with unknown groups (e.g. GREASE, unrecognised PQ hybrids)
        // per RFC 8446 §4.2.8: "the server MUST check ... that it is willing to
        // negotiate ... and ignore all others."
        while !data.is_empty() {
            let group_raw = data.read_u16()?;
            let opaque_len = data.read_u16()? as usize;
            let opaque = data.slice(opaque_len)?;
            match NamedGroup::of(group_raw) {
                Some(group) => {
                    let _ = client_shares.push(KeyShareEntry {
                        group,
                        opaque: opaque.as_slice(),
                    });
                }
                None => {} // unknown group, skip
            }
        }
        Ok(KeyShareClientHello { client_shares })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for client_share in &self.client_shares {
                client_share.encode(buf)?;
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

#[allow(dead_code)]
impl KeyShareHelloRetryRequest {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_group: NamedGroup::parse(buf)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.selected_group.encode(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareEntry<'a> {
    pub(crate) group: NamedGroup,
    pub(crate) opaque: &'a [u8],
}

impl<'a> KeyShareEntry<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let group = NamedGroup::parse(buf)?;

        let opaque_len = buf.read_u16()?;
        let opaque = buf.slice(opaque_len as usize)?;

        Ok(Self {
            group,
            opaque: opaque.as_slice(),
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.group.encode(buf)?;

        buf.with_u16_length(|buf| buf.extend_from_slice(self.opaque))
            .map_err(|_| TlsError::EncodeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[test]
    fn test_parse_empty() {
        setup();
        let buffer = [
            0x00, 0x17, // Secp256r1
            0x00, 0x00, // key_exchange length = 0 bytes
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(0, result.opaque.len());
    }

    #[test]
    fn test_parse() {
        setup();
        let buffer = [
            0x00, 0x17, // Secp256r1
            0x00, 0x02, // key_exchange length = 2 bytes
            0xAA, 0xBB,
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(2, result.opaque.len());
        assert_eq!([0xAA, 0xBB], result.opaque);
    }
}
