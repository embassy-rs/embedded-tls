#![cfg(feature = "rustpki")]

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use p256::SecretKey;
use p256::ecdsa::{DerSignature, SigningKey};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use rustls::server::WebPkiClientVerifier;
use signature::Signer;
use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

struct RustPkiProvider<'a> {
    rng: UnwrapErr<SysRng>,
    verifier: CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>,
    priv_key: Option<&'a [u8]>,
    client_cert: Option<embedded_tls::Certificate<&'a [u8]>>,
}

impl CryptoProvider for RustPkiProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = DerSignature;

    fn rng(&mut self) -> impl embedded_tls::CryptoRng {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(&mut self) -> Result<(impl Signer<Self::Signature>, SignatureScheme), TlsError> {
        let key_der = self.priv_key.ok_or(TlsError::InvalidPrivateKey)?;

        let secret_key =
            SecretKey::from_sec1_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;

        Ok((
            SigningKey::from(&secret_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
    }

    fn client_cert(&mut self) -> Option<embedded_tls::Certificate<impl AsRef<[u8]>>> {
        self.client_cert.clone()
    }
}

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

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let ca = load_certs(&test_dir.join("data").join("ca-cert.pem"));
            let certs = load_certs(&test_dir.join("data").join("chain-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("im-server-key.pem"));

            let mut client_auth_roots = rustls::RootCertStore::empty();
            for root in ca.into_iter() {
                client_auth_roots.add(root).unwrap()
            }

            let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                .allow_unauthenticated()
                .build()
                .unwrap();

            let config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
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
async fn test_server_certificate_validation() {
    use embedded_tls::*;

    let rng = UnwrapErr(SysRng);

    let addr = setup();
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    let config = TlsConfig::new().with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        RustPkiProvider {
            rng: rng,
            verifier: CertVerifier::new(Certificate::X509(&der[..])),
            priv_key: None,
            client_cert: None,
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}

/*
#[tokio::test]
async fn test_mutual_certificate_validation() {
    use embedded_tls::*;

    let rng = UnwrapErr(SysRng);

    let addr = setup();
    let ca_pem = include_str!("data/ca-cert.pem");
    let ca_der = pem_parser::pem_to_der(ca_pem);

    let cli_pem = include_str!("data/client-cert.pem");
    let cli_der = pem_parser::pem_to_der(cli_pem);

    let key_pem = include_str!("data/client-key.pem");
    let key_der = pem_parser::pem_to_der(key_pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    let config = TlsConfig::new().with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        RustPkiProvider {
            rng: rng,
            verifier: CertVerifier::new(Certificate::X509(&ca_der[..])),
            priv_key: Some(&key_der),
            client_cert: Some(Certificate::X509(&cli_der[..])),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
*/
