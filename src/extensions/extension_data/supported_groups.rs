use heapless::Vec;

use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1,
    Secp384r1,
    Secp521r1,
    X25519,
    X448,

    /* Finite Field Groups (DHE) */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,

    /* Post-quantum hybrid groups */
    X25519MLKEM768,
    SecP256r1MLKEM768,
    SecP384r1MLKEM1024,
}

impl NamedGroup {
    /// Try to convert a raw u16 to a known NamedGroup.
    pub fn of(raw: u16) -> Option<Self> {
        match raw {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x0019 => Some(Self::Secp521r1),
            0x001D => Some(Self::X25519),
            0x001E => Some(Self::X448),

            0x0100 => Some(Self::Ffdhe2048),
            0x0101 => Some(Self::Ffdhe3072),
            0x0102 => Some(Self::Ffdhe4096),
            0x0103 => Some(Self::Ffdhe6144),
            0x0104 => Some(Self::Ffdhe8192),

            0x11EB => Some(Self::SecP256r1MLKEM768),
            0x11EC => Some(Self::X25519MLKEM768),
            0x11ED => Some(Self::SecP384r1MLKEM1024),

            _ => None,
        }
    }

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Self::of(buf.read_u16()?).ok_or(ParseError::InvalidData)
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Secp256r1 => 0x0017,
            Self::Secp384r1 => 0x0018,
            Self::Secp521r1 => 0x0019,
            Self::X25519 => 0x001D,
            Self::X448 => 0x001E,

            Self::Ffdhe2048 => 0x0100,
            Self::Ffdhe3072 => 0x0101,
            Self::Ffdhe4096 => 0x0102,
            Self::Ffdhe6144 => 0x0103,
            Self::Ffdhe8192 => 0x0104,

            Self::SecP256r1MLKEM768 => 0x11EB,
            Self::X25519MLKEM768 => 0x11EC,
            Self::SecP384r1MLKEM1024 => 0x11ED,
        }
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.as_u16())
            .map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedGroups<const N: usize> {
    pub supported_groups: Vec<NamedGroup, N>,
}

impl<const N: usize> SupportedGroups<N> {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;
        let mut data = buf.slice(data_length)?;
        let mut supported_groups = Vec::new();
        // Skip unknown named groups per RFC 8446 Section 9.3
        while !data.is_empty() {
            match NamedGroup::parse(&mut data) {
                Ok(group) => {
                    let _ = supported_groups.push(group);
                }
                Err(ParseError::InvalidData) => {} // unknown group, skip
                Err(e) => return Err(e),
            }
        }
        Ok(Self { supported_groups })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for g in &self.supported_groups {
                g.encode(buf)?;
            }
            Ok(())
        })
    }
}
