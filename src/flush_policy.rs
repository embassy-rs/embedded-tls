//! Flush policy for TLS sockets.
//!
//! Two strategies are provided:
//! - `Relaxed`: close the TLS encryption buffer and hand the data to the transport
//!   delegate without forcing a transport-level flush.
//! - `Strict`: in addition to handing the data to the transport delegate, also
//!   request a flush of the transport. For TCP transports this typically means
//!   waiting for an ACK (e.g. on embassy TCP sockets) before considering the
//!   data fully flushed.

/// Policy controlling how TLS layer flushes encrypted data to the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushPolicy {
    /// Close the TLS encryption buffer and pass bytes to the transport delegate.
    /// Do not force a transport-level flush or wait for an ACK.
    Relaxed,

    /// In addition to passing bytes to the transport delegate, request a
    /// transport-level flush and wait for confirmation (ACK) before returning.
    Strict,
}

impl FlushPolicy {
    /// Returns true when the transport delegate should be explicitly flushed.
    ///
    /// Relaxed -> false, Strict -> true.
    #[must_use]
    pub fn flush_transport(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

impl Default for FlushPolicy {
    /// Default to `Strict` for compatibility with embedded-tls 0.17.0.
    fn default() -> Self {
        FlushPolicy::Strict
    }
}
