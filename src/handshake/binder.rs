use crate::TlsError;
use crate::buffer::CryptoBuffer;
use core::fmt::{Debug, Formatter};
use digest::array::{Array, ArraySize};

pub struct PskBinder<N: ArraySize> {
    pub verify: Array<u8, N>,
}

#[cfg(feature = "defmt")]
impl<N: ArraySize> defmt::Format for PskBinder<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl<N: ArraySize> Debug for PskBinder<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskBinder").finish()
    }
}

impl<N: ArraySize> PskBinder<N> {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        let len = self.verify.len() as u8;
        //buf.extend_from_slice(&[len[1], len[2], len[3]]);
        buf.push(len).map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.verify[..self.verify.len()])
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn len() -> usize {
        N::to_usize()
    }
}
