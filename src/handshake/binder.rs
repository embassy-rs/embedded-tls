use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::crypto::{ByteArray, TlsHash};
use core::fmt::{Debug, Formatter};

pub struct PskBinder<H: TlsHash> {
    pub verify: H::Output,
}

#[cfg(feature = "defmt")]
impl<H: TlsHash> defmt::Format for PskBinder<H> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", H::Output::LEN);
    }
}

impl<H: TlsHash> Debug for PskBinder<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskBinder").finish()
    }
}

impl<H: TlsHash> PskBinder<H> {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(H::Output::LEN as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(self.verify.as_ref())
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn len() -> usize {
        H::Output::LEN
    }
}
