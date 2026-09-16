use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

/// ALPN protocol name list per RFC 7301, Section 3.1.
///
/// Wire format:
/// ```text
/// opaque ProtocolName<1..2^8-1>;
///
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
/// ```
/// Maximum number of ALPN protocol names carried in one list.
///
/// Offering more than this returns an error rather than silently dropping the
/// extras, which would leave the peer negotiating against a list the caller
/// never intended.
pub const MAX_ALPN_PROTOCOLS: usize = 8;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AlpnProtocolNameList<'a> {
    pub protocols: heapless::Vec<&'a [u8], MAX_ALPN_PROTOCOLS>,
}

impl<'a> AlpnProtocolNameList<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let list_len = buf.read_u16()? as usize;
        let mut list_buf = buf.slice(list_len)?;

        let mut protocols = heapless::Vec::new();
        while !list_buf.is_empty() {
            let name_len = list_buf.read_u8()? as usize;
            if name_len == 0 {
                return Err(ParseError::InvalidData);
            }
            let name = list_buf.slice(name_len)?;
            protocols
                .push(name.as_slice())
                .map_err(|_| ParseError::InsufficientSpace)?;
        }

        Ok(Self { protocols })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        // Outer u16 length prefix for the ProtocolNameList
        buf.with_u16_length(|buf| {
            for protocol in &self.protocols {
                buf.push(protocol.len() as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(protocol)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn then_all_offered_protocols_are_retained() {
        let protocols: [&[u8]; 5] = [b"h2", b"http/1.1", b"spdy/3", b"acme-tls/1", b"mqtt"];

        let mut list = AlpnProtocolNameList {
            protocols: heapless::Vec::new(),
        };
        for protocol in &protocols {
            list.protocols.push(*protocol).expect("capacity holds 5");
        }

        const EXPECTED_COUNT: usize = 5;
        assert_eq!(list.protocols.len(), EXPECTED_COUNT);
    }

    #[test]
    fn then_offering_past_capacity_is_an_error() {
        let mut list = AlpnProtocolNameList {
            protocols: heapless::Vec::new(),
        };
        for _ in 0..MAX_ALPN_PROTOCOLS {
            list.protocols.push(b"x").expect("fits");
        }

        let result = list.protocols.push(b"overflow");

        assert!(result.is_err());
    }
}
