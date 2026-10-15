//! limbo's test cases: the pinned `limbo.json` and the fields the report reads.

use crate::{Result, fetch};
use jiff::Timestamp;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The x509-limbo commit whose `limbo.json` is run, and that file's SHA-256.
pub const LIMBO_COMMIT: &str = "554528a9b0c0d95e071f55de018326f0b65a8364";
const LIMBO_SHA256: &str = "611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de";

#[derive(Deserialize)]
pub struct Limbo {
    pub testcases: Vec<Case>,
}

#[derive(Deserialize)]
pub struct Case {
    pub id: String,
    pub validation_kind: String,
    pub features: Vec<String>,
    pub expected_result: Expected,
    pub expected_peer_name: Option<PeerName>,
    pub validation_time: Option<Timestamp>,
    pub peer_certificate: String,
    pub untrusted_intermediates: Vec<String>,
    pub trusted_certs: Vec<String>,
}

#[derive(Deserialize)]
pub struct PeerName {
    pub value: String,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Expected {
    Success,
    Failure,
}

impl Expected {
    /// The result limbo records for a verifier that gets this case right.
    pub fn result(self) -> &'static str {
        match self {
            Expected::Success => "SUCCESS",
            Expected::Failure => "FAILURE",
        }
    }
}

/// The folder for limbo's files, and the cases from `limbo.json`, which is downloaded once.
pub fn load() -> Result<(PathBuf, Limbo)> {
    let dir = fetch::target_dir()?.join("limbo");
    let json = dir.join(format!("limbo-{LIMBO_COMMIT}.json"));
    if !json.exists() {
        let url =
            format!("https://raw.githubusercontent.com/C2SP/x509-limbo/{LIMBO_COMMIT}/limbo.json");
        let (body, _) = fetch::get(&url)?;
        check_sha256(&body, LIMBO_SHA256)?;
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&json, body)?;
    }
    Ok((dir, serde_json::from_slice(&std::fs::read(&json)?)?))
}

/// Refuses `body` unless its SHA-256 is `expected`.
fn check_sha256(body: &[u8], expected: &str) -> Result<()> {
    let sha256 = format!("{:x}", Sha256::digest(body));
    if sha256 != expected {
        return Err(format!("limbo.json has SHA-256 {sha256}, not {expected}").into());
    }
    Ok(())
}

/// A case with `id`, as limbo writes it, for the tests. It has no certificates.
#[cfg(test)]
pub fn case(id: &str, kind: &str, features: &[&str], expected: Expected) -> Case {
    Case {
        id: id.to_string(),
        validation_kind: kind.to_string(),
        features: features.iter().map(|feature| feature.to_string()).collect(),
        expected_result: expected,
        expected_peer_name: None,
        validation_time: None,
        peer_certificate: String::new(),
        untrusted_intermediates: Vec::new(),
        trusted_certs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SHA-256 of "limbo", from `printf limbo | shasum -a 256`.
    const LIMBO: &str = "355a61ea1af2c7c19ff24a11722777d74122ac0fafa27d8a954b209be00f55cd";

    #[test]
    fn a_download_with_another_sha256_is_refused() {
        assert!(check_sha256(b"limbo", LIMBO).is_ok());
        assert!(check_sha256(b"limbO", LIMBO).is_err());
    }
}
