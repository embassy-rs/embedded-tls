//! Shared test setup: links the software `embassy-crypto` drivers and the operating system
//! random number generator driver.
#![allow(dead_code)]

// A crate that is never named is not linked, so the drivers must be pulled in explicitly.
use embassy_crypto_rand as _;
use embassy_crypto_rustcrypto as _;
