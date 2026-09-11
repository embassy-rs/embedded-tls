use embedded_io::Write as _;
use embedded_io_adapters::std::FromStd;
use embedded_tls::blocking::*;
use embedded_tls::webpki::CertVerifier;
use std::net::TcpStream;
use std::time::SystemTime;

struct Provider<'a> {
    rng: rand::rngs::ThreadRng,
    verifier: CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for Provider<'_> {
    type CipherSuite = Aes128GcmSha256;

    type Signature = &'static [u8];

    fn rng(&mut self) -> impl embedded_tls::CryptoRng {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <cert.pem>", args[0]);
        std::process::exit(1);
    }

    let cert_path = &args[1];
    let pem_content = std::fs::read_to_string(cert_path)
        .expect(&format!("Failed to read certificate file: {}", cert_path));

    let stream = TcpStream::connect("127.0.0.1:12345").expect("error connecting to server");

    log::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    let der = pem_parser::pem_to_der(&pem_content);
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls = TlsConnection::new(
        FromStd::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    tls.open(TlsContext::new(
        &config,
        Provider {
            rng: rand::rng(),
            verifier: CertVerifier::new(Certificate::X509(&der)),
        },
    ))
    .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("error writing data");
    tls.flush().expect("error flushing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}
