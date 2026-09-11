use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::crypto::{ByteArray, TlsHash};
use crate::parse_buffer::ParseBuffer;
use core::fmt::{Debug, Formatter};

pub struct Finished<H: TlsHash> {
    pub verify: H::Output,
    pub hash: Option<H::Output>,
}

#[cfg(feature = "defmt")]
impl<H: TlsHash> defmt::Format for Finished<H> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", H::Output::LEN);
    }
}

impl<H: TlsHash> Debug for Finished<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Finished")
            .field("verify", &self.hash)
            .finish()
    }
}

impl<H: TlsHash> Finished<H> {
    pub fn parse(buf: &mut ParseBuffer, _len: u32) -> Result<Self, TlsError> {
        let mut verify = H::Output::zeroed();
        buf.fill(verify.as_mut())?;
        Ok(Self { verify, hash: None })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.extend_from_slice(self.verify.as_ref())
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}
