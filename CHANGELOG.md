# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Fix a record-stream desync when an async record read is cancelled and resumed (e.g. under a read/write `select`): persist the partial record header on the reader, and read only the still-missing body bytes in `advance` instead of a fixed `amount`.
- All crypto (except RSA) and RNG is now done through `embassy-crypto`. You must add dependencies providing implementations yourself. See the [`embassy-crypto` README](https://docs.embassy.dev/embassy-crypto) for details.
- Removed the `CryptoProvider` trait and `UnsecureProvider`. `TlsContext::new` now takes the config and the certificate verifier. The client certificate and key are set with `TlsContext::with_client_cert`. The cipher suite is selected by the `TlsConnection` generic param.
- Added `PrivateKey` for client certificate authentication.
- Added the `p256` feature, for consistency with `p384` and `ed25519`.

## 0.19.0 - 2026-06-01

- Added post-quantum hybrid named groups.
- Add missing implementation to support Client Certificate Authorization (#135)
- Changed edition from 2021 to 2024.
- Add ALPN extension support.
- Move certificate resolution from TlsConfig into CryptoProvider
- Upgrade defmt, embedded-io
- Support RSA signatures
- Add brainpool and ml-dsa signature algorithms
- Add CompressCertificate extension
- Add server chain validation with rust native pki using RustCrypto (rustpki feature)
- Added EcdsaSecp384r1Sha384 and ability to exdend signature schemes
- Introduce a configurable FlushPolicy to control when the TLS layer flushes its underlying transport.

## 0.17.0 - 2024-01-06

- Update to stable rust

## 0.16.3 - 2023-11-04

- Don't block when reading into an empty buffer

## 0.16.2 - 2023-11-02

- Re-add `impl_trait_projections` to support older nightly rustc versions

## 0.16.1 - 2023-10-30

- Corrected recommended read buffer size (16640 bytes instead of 16384)
- Use unwrap macro where possible
- Update to embedded-io 0.6
- Update dependencies

## 0.15.0 - 2023-08-26

- Updated p256 dependency from 0.11 to 0.13.2 (#124)
- Fix reading buffered data in multiple steps (#121, #122)
- Fix error in NewSessionTicket message handling (#120)

## 0.14.1 - 2023-04-29

- Correctly handle transcript of coalesced records, attempt 2.

## 0.14.0 - 2023-04-29

- Refactoring and improving API.
- Support splitting read and write of a connection.
- Properly flush write buffer after handshake.
- Implement BufRead traits for connections.
- Better handling of protocol violations and unsupported features.
- Correctly handle transcript of coalesced records.
