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

## Community

* [Embassy Matrix Chat Room](https://matrix.to/#/#embassy-rs:matrix.org)
* [Embassy website](https://embassy.dev/)
