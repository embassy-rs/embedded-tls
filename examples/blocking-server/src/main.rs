//! TLS 1.3 server example using blocking I/O.
//!
//! Listens on 127.0.0.1:12345, accepts one connection, performs a TLS handshake,
//! reads a message, echoes it back, and shuts down.
//!
//! Generate test certs first:  bash tests/data/gen_test_certs.sh
//!
//! Run:    cargo run --manifest-path examples/blocking-server/Cargo.toml
//! Test:   echo "hello" | openssl s_client -connect 127.0.0.1:12345 \
//!             -CAfile tests/data/ca-cert.pem -tls1_3 -quiet

use embedded_io::Write as _;
use embedded_io_adapters::std::FromStd;
use embedded_tls::blocking::TlsConnection;
use embedded_tls::*;
use std::error::Error;

// A crate that is never named is not linked, so the software crypto and RNG
// drivers must be pulled in explicitly.
use embassy_crypto_rand as _;
use embassy_crypto_rustcrypto as _;
use std::net::TcpListener;

/// Resolve a test data file relative to this example's manifest, so the
/// example runs from any working directory.
fn data_file(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data")
        .join(name)
}

fn load_certs(path: &std::path::Path) -> Vec<Vec<u8>> {
    let f = std::fs::File::open(path).expect("cannot open cert file");
    rustls_pemfile::certs(&mut std::io::BufReader::new(f)).expect("cannot parse certs")
}

fn load_key(path: &std::path::Path) -> Vec<u8> {
    let f = std::fs::File::open(path).expect("cannot open key file");
    let mut r = std::io::BufReader::new(f);
    loop {
        match rustls_pemfile::read_one(&mut r).expect("cannot parse key") {
            Some(rustls_pemfile::Item::ECKey(k)) => return k,
            Some(rustls_pemfile::Item::PKCS8Key(k)) => return k,
            None => panic!("no private key found"),
            _ => {}
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let certs = load_certs(&data_file("chain-cert.pem"));
    let key = load_key(&data_file("im-server-key.pem"));

    let listener = TcpListener::bind("127.0.0.1:12345")?;
    log::info!("Listening on 127.0.0.1:12345");

    let (stream, peer) = listener.accept()?;
    log::info!("Accepted connection from {peer}");

    let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
    let config = TlsServerConfig::new(&cert_refs);
    let signing_key = PrivateKey::from_sec1_der(&key).expect("cannot parse private key");
    let context = TlsServerContext::new(&config, NoVerify, &signing_key);

    let mut read_buf = [0; 16384];
    let mut write_buf = [0; 16384];
    let mut tls: TlsConnection<FromStd<std::net::TcpStream>, Aes128GcmSha256> =
        TlsConnection::new(FromStd::new(stream), &mut read_buf, &mut write_buf);

    tls.open_server(context).expect("TLS handshake failed");
    log::info!("TLS handshake complete");

    let mut rx = [0; 4096];
    let n = tls.read(&mut rx).expect("read failed");
    log::info!("Received: {:?}", core::str::from_utf8(&rx[..n]));

    tls.write_all(&rx[..n]).expect("write failed");
    tls.flush().expect("flush failed");
    log::info!("Echoed {} bytes", n);

    tls.close().ok();
    Ok(())
}
