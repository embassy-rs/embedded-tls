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
- The `webpki` verifier now uses rustls-webpki 0.103 and checks signatures through `embassy-crypto`. It verifies RSA chains with the `rsa` feature, without `std`, and uses the intermediates the server sends.
- Removed the `alloc` feature. The `rsa` feature no longer turns on `rustpki`. The `webpki` and `rustpki` features each need at least one of `p256`, `p384`, `ed25519` and `rsa`.
- `p256` is now a default feature, and the client offers only the signature schemes of the enabled signature features. `TlsConfig::enable_rsa_signatures` needs `rsa`.
- A build with no signature feature can only use a pre-shared key. `open` without one fails with the new `TlsError::MissingPsk`.
- An RSA `CertificateVerify` from the server must use RSASSA-PSS. RFC 9846 section 4.3.3 defines the `rsa_pkcs1` schemes for signatures in certificates only.
- Certificates signed with P-256 and SHA-384, or P-384 and SHA-256, no longer verify. TLS 1.3 has no scheme for these pairs.
- The `webpki` verifier refuses the server's certificate when no server name is set, with the new `TlsError::MissingServerName`.
- A server name that is an IP address is not sent as SNI. The `webpki` verifier checks it against the certificate's IP addresses.
- `webpki`'s `set_hostname_verification` refuses unparseable host names.
- The `webpki` verifier keeps only the server's own certificate after verifying the chain, so `CERT_SIZE` needs to hold that certificate, not the whole chain.
- The `rustpki` verifier accepts only a server certificate the trusted root signed directly, and ignores the rest of the chain. A chain through an intermediate needs the `webpki` verifier.
- The `rustpki` verifier returns `TlsError::DecodeError` for a `CertificateVerify` that claims `rsa_pss_rsae_sha256` for a non-RSA key, rather than panicking.
- `TlsClock::now()` returning `None` means the device does not know the time. Both verifiers then skip the certificate dates, and the `webpki` verifier logs a warning.
- Renamed `NoClock` to `InsecureIgnoreDates`. `NoClock` remains as a deprecated alias.

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
