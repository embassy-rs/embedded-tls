#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc // TODO
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/*!
# Example

```
use embedded_tls::*;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::net::TcpStream;

// All cryptography is served by `embassy-crypto` drivers, resolved at link time.
// Link a crate providing the primitives (here the software implementations in
// `embassy-crypto-rustcrypto`) and one registering a random number generator (here
// the operating system's, from `embassy-crypto-rand`; embedded HALs provide their own).
use embassy_crypto_rand as _;
use embassy_crypto_rustcrypto as _;

#[tokio::main]
async fn main() {
    let stream = TcpStream::connect("google.com:443")
        .await
        .expect("error creating TCP connection");

    println!("TCP connection opened");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("google.com").enable_rsa_signatures();
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    // By default the server certificate is not verified, which is fine when using PSK or
    // when just testing. Otherwise, pass a verifier such as `embedded_tls::webpki::CertVerifier`
    // (std only) or `embedded_tls::pki::CertVerifier` with `TlsContext::with_verifier`.
    tls.open(TlsContext::new(&config))
        .await
        .expect("error establishing TLS connection");

    println!("TLS session opened");
}
```
*/

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

use parse_buffer::ParseError;
pub mod alert;
mod application_data;
pub mod blocking;
mod buffer;
mod change_cipher_spec;
mod cipher_suites;
mod common;
mod config;
mod connection;
mod content_types;
pub mod crypto;
mod extensions;
pub mod flush_policy;
mod handshake;
mod key_schedule;
mod parse_buffer;
pub mod read_buffer;
mod record;
mod record_reader;
mod write_buffer;

pub use embassy_crypto;
pub use extensions::extension_data::signature_algorithms::SignatureScheme;
pub use handshake::certificate_verify::CertificateVerify;

#[cfg(feature = "webpki")]
pub mod webpki;

#[cfg(feature = "rustpki")]
mod der_certificate;
#[cfg(feature = "rustpki")]
pub mod pki;

mod asynch;
pub use asynch::*;

pub use flush_policy::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsError {
    ConnectionClosed,
    Unimplemented,
    MissingHandshake,
    HandshakeAborted(alert::AlertLevel, alert::AlertDescription),
    AbortHandshake(alert::AlertLevel, alert::AlertDescription),
    IoError,
    InternalError,
    InvalidRecord,
    UnknownContentType,
    InvalidNonceLength,
    InvalidTicketLength,
    UnknownExtensionType,
    InsufficientSpace,
    InvalidHandshake,
    InvalidCipherSuite,
    InvalidSignatureScheme,
    InvalidSignature,
    InvalidExtensionsLength,
    InvalidSessionIdLength,
    InvalidSupportedVersions,
    InvalidApplicationData,
    InvalidKeyShare,
    InvalidCertificate,
    InvalidCertificateEntry,
    InvalidCertificateRequest,
    InvalidPrivateKey,
    UnableToInitializeCryptoEngine,
    ParseError(ParseError),
    OutOfMemory,
    CryptoError,
    EncodeError,
    DecodeError,
    Io(embedded_io::ErrorKind),
}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        if let Self::Io(k) = self {
            *k
        } else {
            error!("TLS error: {:?}", self);
            embedded_io::ErrorKind::Other
        }
    }
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for TlsError {}

#[cfg(feature = "std")]
mod stdlib {
    use crate::config::TlsClock;

    use std::time::SystemTime;
    impl TlsClock for SystemTime {
        fn now() -> Option<u64> {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        }
    }
}

/// An internal function to mark an unused value.
///
/// All calls to this should be removed before 1.x.
fn unused<T>(_: T) {}

/// Drivers for the crate's own unit tests: the software `embassy-crypto` drivers and the
/// operating system random number generator.
#[cfg(test)]
mod test_drivers {
    use embassy_crypto_rand as _;
    use embassy_crypto_rustcrypto as _;
}
