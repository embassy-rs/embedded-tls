# Embedded-TLS

[![CI](https://github.com/embassy-rs/embedded-tls/actions/workflows/ci.yaml/badge.svg)](https://github.com/embassy-rs/embedded-tls/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/embedded-tls.svg)](https://crates.io/crates/embedded-tls)
[![docs.rs](https://docs.rs/embedded-tls/badge.svg)](https://docs.rs/embedded-tls)
[![Matrix](https://img.shields.io/matrix/embassy-rs:matrix.org)](https://matrix.to/#/#embassy-rs:matrix.org)

This project was originally developed under the `drogue-iot` organization. It has since been
transferred to [embassy-rs](https://github.com/embassy-rs), which now maintains it.

Embedded-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The Rust crate was formerly known as `drogue-tls`.

The client supports both async and blocking modes. By default, the `std` feature is enabled, but can be disabled for bare metal usage.

To use the async mode, import `embedded_tls::*`. To use the blocking mode, import `embedded_tls::blocking::*`.

Embedded-TLS uses `embassy-crypto` for all cryptography and RNG (except RSA). You must add dependencies providing implementations. See the [`embassy-crypto` README](https://docs.embassy.dev/embassy-crypto) for details.

Some features and extensions are not yet implemented, have a look at [open issues](https://github.com/embassy-rs/embedded-tls/issues).

Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.

## Verifying the server

Pass a certificate verifier to `TlsContext::new`. `webpki::CertVerifier`, with the `webpki` feature, checks the server's chain against one trusted root with rustls-webpki. It works without `std`. The `p256`, `p384`, `ed25519` and `rsa` features choose the signatures it can check, and the client offers only those. `pki::CertVerifier`, with the `rustpki` feature, is a verifier written for this crate on `RustCrypto`. It accepts only a server certificate the trusted root signed directly. `InsecureNoVerify` skips verification, and is safe only when a pre-shared key authenticates the server.

```rust,ignore
use embedded_tls::webpki::CertVerifier;

// ROOT is the trusted root certificate, DER encoded.
let config = TlsConfig::new().with_server_name("example.com");
let verifier: CertVerifier<Aes128GcmSha256, SystemTime, 2048> =
    CertVerifier::new(Certificate::X509(ROOT));
tls.open(TlsContext::new(&config, verifier)).await?;
```

`with_server_name` sets the name the certificate must match, a DNS name or an IP address. Without one, `webpki::CertVerifier` refuses the certificate with `TlsError::MissingServerName`. For an IP address, the client sends no SNI, as RFC 6066 requires. `pki::CertVerifier` matches DNS names only.

`CERT_SIZE`, the verifier's last parameter, must hold the server's own certificate. A larger one fails with `TlsError::OutOfMemory`. Measure it with `openssl s_client -connect example.com:443 </dev/null | openssl x509 -outform DER | wc -c`, and leave room for a renewed certificate.

Each signature feature needs an `embassy-crypto` driver linked for its algorithm, such as `embassy-crypto-rustcrypto` with its `embassy-crypto-p256-ecdsa` feature for `p256`. Without one, the link fails with an undefined symbol. The `rsa` feature uses the `rsa` crate, which needs a global allocator.

The verifier's `TlsClock` gives the time for the certificate dates. `std::time::SystemTime` implements it with the `std` feature. On a device, implement it for a type that reads the device's clock. On a device that does not know the time, use `InsecureIgnoreDates`. The verifier then skips the dates, and every other check still runs.

To move from `pki::CertVerifier`, change the import and the feature. The generics and the constructor are the same, and `CERT_SIZE` can shrink to the server's certificate. To move from the old `webpki` verifier, drop the `alloc` feature, enable a signature feature if `default-features` is off, and enable `rsa` for RSA chains.

## Community

* [Embassy Matrix Chat Room](https://matrix.to/#/#embassy-rs:matrix.org)
* [Embassy website](https://embassy.dev/)
