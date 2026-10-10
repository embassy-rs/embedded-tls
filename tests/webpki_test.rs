#![cfg(all(feature = "webpki", feature = "p256"))]

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::webpki::CertVerifier;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

mod common;
mod tlsserver;

static LOG_INIT: OnceLock<()> = OnceLock::new();

fn init_log() {
    LOG_INIT.get_or_init(|| {
        env_logger::init();
    });
}

async fn setup() -> SocketAddr {
    init_log();

    use mio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("cannot listen on port");

    let addr = listener
        .local_addr()
        .expect("error retrieving socket address");

    std::thread::spawn(move || {
        tlsserver::run(listener);
    });

    log::info!("Server at {:?}", addr);
    addr
}

/// Starts a server that sends its certificate and the intermediate that signed it.
fn setup_chain() -> SocketAddr {
    init_log();

    use mio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("cannot listen on port");
    let addr = listener
        .local_addr()
        .expect("error retrieving socket address");

    let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let certs = tlsserver::load_certs(&data.join("chain-cert.pem"));
    let key = tlsserver::load_private_key(&data.join("im-server-key.pem"));
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    std::thread::spawn(move || {
        tlsserver::run_with_config(listener, config);
    });
    addr
}

#[tokio::test]
async fn test_server_certificate_validation() {
    use embedded_tls::*;

    let addr = setup().await;
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    // Hostname verification is not enabled
    let config = TlsConfig::new();

    let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096> =
        CertVerifier::new(Certificate::X509(&der[..]));
    let open_fut = tls.open(TlsContext::new(&config, verifier));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}

#[tokio::test]
async fn test_server_chain_with_an_intermediate() {
    use embedded_tls::*;

    let addr = setup_chain();
    let der = pem_parser::pem_to_der(include_str!("data/ca-cert.pem"));

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    let config = TlsConfig::new().with_server_name("localhost");

    let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096> =
        CertVerifier::new(Certificate::X509(&der[..]));
    tls.open(TlsContext::new(&config, verifier))
        .await
        .expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
