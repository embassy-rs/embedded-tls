//! Downloads for the tasks.

use crate::Result;
use std::path::{Path, PathBuf};

/// The repository's `target` folder, or `CARGO_TARGET_DIR` when it is set.
pub fn target_dir() -> Result<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask is not in the repository")?;
    Ok(std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from))
}

/// The body at `url`, and its `Last-Modified` header.
pub fn get(url: &str) -> Result<(Vec<u8>, Option<String>)> {
    println!("Downloading {url}");
    let mut response = ureq::get(url).call()?;
    let modified = response.headers().get("last-modified");
    let modified = modified.and_then(|v| v.to_str().ok()).map(str::to_string);
    // ureq reads at most 10 MB by default, and limbo's files are larger.
    let body = response
        .body_mut()
        .with_config()
        .limit(1 << 30)
        .read_to_vec()?;
    Ok((body, modified))
}
