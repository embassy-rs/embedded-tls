// The TLS 1.3 exporter must produce the same keying material as rustls on the other end of the same handshake.
#![cfg(feature = "p256")]

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

mod common;
mod tlsserver;

const CASES: &[(&[u8], &[u8])] = &[
    (b"EXPORTER-test", b""),
    (b"EXPORTER-test", b"\x00\x00\x00\x0f\x00"),
    (b"EXPORTER-other", b""),
    // longer than the 30-byte label of RFC 8915 (NTS), to exercise the label buffer
    (b"EXPORTER-network-time-security", b"\x00\x00\x00\x0f\x00"),
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// A rustls server that completes the handshake, exports `CASES` (32 bytes each) and sends them as hex lines.
fn spawn_server(suite: rustls::SupportedCipherSuite) -> u16 {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data");
    let config = rustls::ServerConfig::builder()
        .with_cipher_suites(&[suite])
        .with_kx_groups(&rustls::ALL_KX_GROUPS)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            tlsserver::load_certs(&dir.join("server-cert.pem")),
            tlsserver::load_private_key(&dir.join("server-key.pem")),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).unwrap();
        }
        let mut lines = String::new();
        for (label, context) in CASES {
            let mut out = [0u8; 32];
            conn.export_keying_material(&mut out, label, Some(context))
                .unwrap();
            lines.push_str(&hex(&out));
            lines.push('\n');
        }
        conn.writer().write_all(lines.as_bytes()).unwrap();
        while conn.wants_write() {
            conn.complete_io(&mut sock).unwrap();
        }
        // wait for the client to finish reading before the socket goes away
        let mut sink = [0u8; 1];
        let _ = sock.read(&mut sink);
    });
    port
}

async fn check<C: TlsCipherSuite + 'static>(suite: rustls::SupportedCipherSuite) {
    let port = spawn_server(suite);
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut read_buf = [0; 16384];
    let mut write_buf = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, C> =
        TlsConnection::new(FromTokio::new(stream), &mut read_buf, &mut write_buf);

    // not available before the handshake
    let mut out = [0u8; 32];
    assert!(
        tls.export_keying_material(b"EXPORTER-test", b"", &mut out)
            .is_err()
    );

    tls.open(TlsContext::new(&config, InsecureNoVerify))
        .await
        .expect("handshake");

    let mut ours = String::new();
    for (label, context) in CASES {
        tls.export_keying_material(label, context, &mut out)
            .expect("export");
        ours.push_str(&hex(&out));
        ours.push('\n');
    }
    let mut theirs = vec![0u8; ours.len()];
    let mut filled = 0;
    while filled < theirs.len() {
        let n = tls.read(&mut theirs[filled..]).await.expect("read");
        assert!(n > 0, "server closed early");
        filled += n;
    }
    assert_eq!(ours, String::from_utf8(theirs).unwrap());
    // label and context are part of the derivation
    let lines: Vec<&str> = ours.lines().collect();
    for i in 0..lines.len() {
        for j in i + 1..lines.len() {
            assert_ne!(lines[i], lines[j]);
        }
    }
}

#[tokio::test]
async fn exporter_matches_rustls_aes128_sha256() {
    check::<Aes128GcmSha256>(rustls::cipher_suite::TLS13_AES_128_GCM_SHA256).await;
}

#[tokio::test]
async fn exporter_matches_rustls_aes256_sha384() {
    check::<Aes256GcmSha384>(rustls::cipher_suite::TLS13_AES_256_GCM_SHA384).await;
}
