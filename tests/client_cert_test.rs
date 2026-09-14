#![cfg(feature = "p256")]

use embedded_io_adapters::tokio_1::FromTokio;
use rustls::server::AllowAnyAuthenticatedClient;
use std::net::SocketAddr;
use std::sync::Once;

mod common;
mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    init_log();
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            use tlsserver::*;

            let versions = &[&rustls::version::TLS13];

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let ca = load_certs(&test_dir.join("data").join("ca-cert.pem"));
            let certs = load_certs(&test_dir.join("data").join("server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("server-key.pem"));

            let mut client_auth_roots = rustls::RootCertStore::empty();
            for root in ca.iter() {
                client_auth_roots.add(root).unwrap()
            }

            let client_cert_verifier = AllowAnyAuthenticatedClient::new(client_auth_roots);

            let config = rustls::ServerConfig::builder()
                .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
                .with_kx_groups(&rustls::ALL_KX_GROUPS)
                .with_protocol_versions(versions)
                .unwrap()
                .with_client_cert_verifier(client_cert_verifier.boxed())
                .with_single_cert(certs, privkey)
                .unwrap();

            run_with_config(listener, config);
        });
        #[allow(static_mut_refs)]
        unsafe {
            ADDR.replace(addr)
        };
    });
    unsafe { ADDR.unwrap() }
}

#[tokio::test]
async fn test_client_certificate_auth() {
    use embedded_tls::*;
    use tokio::net::TcpStream;
    let addr = setup();

    let client_cert_pem = include_str!("data/client-cert.pem");
    let client_cert_der = pem_parser::pem_to_der(client_cert_pem);

    let private_key_pem = include_str!("data/client-key.pem");
    let private_key_der = pem_parser::pem_to_der(private_key_pem);

    let stream = TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    log::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("factbird.com");

    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    log::info!("SIZE of connection is {}", core::mem::size_of_val(&tls));

    let private_key = PrivateKey::from_sec1_der(&private_key_der).expect("invalid private key");
    let open_fut = tls.open(
        TlsContext::new(&config, NoVerify)
            .with_client_cert(Certificate::X509(&client_cert_der), &private_key),
    );
    log::info!("SIZE of open fut is {}", core::mem::size_of_val(&open_fut));
    open_fut.await.expect("error establishing TLS connection");
    log::info!("Established");

    let write_fut = tls.write(b"ping");
    log::info!(
        "SIZE of write fut is {}",
        core::mem::size_of_val(&write_fut)
    );
    write_fut.await.expect("error writing data");
    tls.flush().await.expect("error flushing data");

    // Make sure reading into a 0 length buffer doesn't loop
    let mut rx_buf = [0; 0];
    let read_fut = tls.read(&mut rx_buf);
    log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
    let sz = read_fut.await.expect("error reading data");
    assert_eq!(sz, 0);

    let mut rx_buf = [0; 4096];
    let read_fut = tls.read(&mut rx_buf);
    log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
    let sz = read_fut.await.expect("error reading data");
    assert_eq!(4, sz);
    assert_eq!(b"ping", &rx_buf[..sz]);
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    // Test that embedded-tls doesn't block if the buffer is empty.
    let mut rx_buf = [0; 0];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    assert_eq!(sz, 0);

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
