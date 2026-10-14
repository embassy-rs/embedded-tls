//! A write or flush future dropped while the transport is blocked must not lose, repeat or corrupt
//! data. A full-duplex client drives the writer inside a `select`, which drops it when the other
//! branch is ready first.

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::{ErrorType, Read, Write};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Once;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

mod common;
mod tlsserver;

static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");
        std::thread::spawn(move || {
            tlsserver::run(listener);
        });
        #[allow(static_mut_refs)]
        unsafe {
            ADDR.replace(addr)
        };
    });
    unsafe { ADDR.unwrap() }
}

/// A transport whose writes stop after a byte budget, as a socket with a full send buffer does.
/// A write that finds the budget spent returns `Pending`.
struct Stalling<T> {
    inner: T,
    budget: Rc<Cell<Option<usize>>>,
}

impl<T: ErrorType> ErrorType for Stalling<T> {
    type Error = T::Error;
}

impl<T: Read> Read for Stalling<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.read(buf).await
    }
}

impl<T: Write> Write for Stalling<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let allowed = match self.budget.get() {
            None => buf.len(),
            Some(0) => return std::future::pending().await,
            Some(budget) => budget.min(buf.len()),
        };
        let written = self.inner.write(&buf[..allowed]).await?;
        if let Some(budget) = self.budget.get() {
            self.budget.set(Some(budget - written));
        }
        Ok(written)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush().await
    }
}

/// One transport that both halves of a split connection use.
struct Shared<T>(Rc<RefCell<T>>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ErrorType> ErrorType for Shared<T> {
    type Error = T::Error;
}

// The tests use one half at a time, so a borrow held across an await never meets another.
#[allow(clippy::await_holding_refcell_ref)]
impl<T: Read> Read for Shared<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.borrow_mut().read(buf).await
    }
}

#[allow(clippy::await_holding_refcell_ref)]
impl<T: Write> Write for Shared<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.borrow_mut().write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.borrow_mut().flush().await
    }
}

/// A transport whose flush stays pending while `stalled` is set, as an embassy TCP socket's
/// flush does until the peer acknowledges the data. `flushes` counts the flushes that complete.
struct SlowFlush<T> {
    inner: T,
    stalled: Rc<Cell<bool>>,
    flushes: Rc<Cell<usize>>,
}

impl<T: ErrorType> ErrorType for SlowFlush<T> {
    type Error = T::Error;
}

impl<T: Read> Read for SlowFlush<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.read(buf).await
    }
}

impl<T: Write> Write for SlowFlush<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        if self.stalled.get() {
            return std::future::pending().await;
        }
        self.inner.flush().await?;
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }
}

/// The bytes a TLS 1.3 record adds to its data with AES-128-GCM: the 5-byte header, the 1-byte
/// inner content type and the 16-byte tag. The flush sweep fails if this is wrong.
const RECORD_OVERHEAD: usize = 22;

/// A write buffer that holds the largest ClientHello the crate sends, and is smaller than the
/// data a test writes, so a write fills a record.
const SMALL_WRITE_BUFFER: usize = 1536;

/// Polls `future` once and drops it, as a `select` does when another branch wins. Returns
/// whether it completed.
fn poll_once_then_drop<F: Future>(future: F) -> bool {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    future.as_mut().poll(&mut context).is_ready()
}

/// Reads until `expected.len()` bytes have arrived, and returns them.
async fn read_exactly<R: Read>(reader: &mut R, expected: &[u8]) -> Vec<u8>
where
    R::Error: std::fmt::Debug,
{
    let mut received = Vec::new();
    let mut buf = [0; 4096];
    while received.len() < expected.len() {
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf))
            .await
            .expect("the echo did not arrive")
            .expect("error reading data");
        assert_ne!(read, 0, "the server closed the connection");
        received.extend_from_slice(&buf[..read]);
    }
    received
}

#[tokio::test]
async fn flush_dropped_mid_record_resumes_on_the_next_flush() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let budget = Rc::new(Cell::new(None));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Stalling {
            inner: FromTokio::new(stream),
            budget: budget.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    tls.write_all(b"first").await.expect("error writing data");
    budget.set(Some(10));
    assert!(!poll_once_then_drop(tls.flush()));
    budget.set(None);
    tls.write_all(b" second").await.expect("error writing data");
    tls.flush().await.expect("error flushing data");

    assert_eq!(
        read_exactly(&mut tls, b"first second").await,
        b"first second"
    );
}

#[tokio::test]
async fn write_dropped_while_flushing_a_full_record_does_not_repeat_data() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let budget = Rc::new(Cell::new(None));
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so one write fills the record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Stalling {
            inner: FromTokio::new(stream),
            budget: budget.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut sent = 0;
    while sent < data.len() {
        // Each first attempt is dropped while the transport is blocked. A write that did not
        // complete took nothing, so the caller offers the same bytes again.
        budget.set(Some(7));
        let mut written = None;
        {
            let mut future = pin!(tls.write(&data[sent..]));
            let mut context = Context::from_waker(Waker::noop());
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                written = Some(result.expect("error writing data"));
            }
        }
        budget.set(None);
        let written = match written {
            Some(written) => written,
            None => tls.write(&data[sent..]).await.expect("error writing data"),
        };
        sent += written;
    }
    tls.flush().await.expect("error flushing data");

    assert_eq!(read_exactly(&mut tls, &data).await, data);
}

#[tokio::test]
async fn flush_dropped_at_every_byte_of_a_record_resumes_on_the_next_flush() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let budget = Rc::new(Cell::new(None));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Stalling {
            inner: FromTokio::new(stream),
            budget: budget.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    let chunk = b"0123456789";
    let record_len = chunk.len() + RECORD_OVERHEAD;
    let mut expected = Vec::new();
    for cut in 0..=record_len {
        tls.write_all(chunk).await.expect("error writing data");
        expected.extend_from_slice(chunk);
        budget.set(Some(cut));
        // The flush completes only when the budget covers the whole record.
        assert_eq!(
            poll_once_then_drop(tls.flush()),
            cut == record_len,
            "cut at {cut}"
        );
        // The transport took the whole budget, so the record was cut at `cut`.
        assert_eq!(budget.get(), Some(0), "cut at {cut}");
        budget.set(None);
        tls.flush().await.expect("error flushing data");
    }

    assert_eq!(read_exactly(&mut tls, &expected).await, expected);
}

#[tokio::test]
async fn write_dropped_at_every_byte_of_a_full_record_does_not_repeat_data() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let budget = Rc::new(Cell::new(None));
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so each write fills a record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Stalling {
            inner: FromTokio::new(stream),
            budget: budget.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    // More records than a record has bytes, so the cuts reach every byte of one.
    let data: Vec<u8> = (0..2_400_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    // The first write fills a record without touching the transport. Its count is the data that
    // one record holds.
    let mut sent = tls.write(&data).await.expect("error writing data");
    let record_len = sent + RECORD_OVERHEAD;
    // Each later write sends the full record first, cut one byte further on each time, from 0 to
    // the whole record.
    let mut attempts = 0;
    let mut received = Vec::new();
    while sent < data.len() {
        let cut = attempts % (record_len + 1);
        attempts += 1;
        budget.set(Some(cut));
        let mut written = None;
        {
            let mut future = pin!(tls.write(&data[sent..]));
            let mut context = Context::from_waker(Waker::noop());
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                written = Some(result.expect("error writing data"));
            }
        }
        // The write completes only when the budget covers the whole record.
        assert_eq!(written.is_some(), cut == record_len, "cut at {cut}");
        // The transport took the whole budget, so the record was cut at `cut`.
        assert_eq!(budget.get(), Some(0), "cut at {cut}");
        budget.set(None);
        let written = match written {
            Some(written) => written,
            None => tls.write(&data[sent..]).await.expect("error writing data"),
        };
        sent += written;
        // Reading the echo of each full record keeps the socket buffers from filling. A full
        // buffer would stall the transport before the cut. The open record holds `written`.
        let echoed = sent - written;
        received.extend(read_exactly(&mut tls, &data[received.len()..echoed]).await);
    }
    assert!(attempts > record_len, "only {attempts} attempts");
    tls.flush().await.expect("error flushing data");
    received.extend(read_exactly(&mut tls, &data[received.len()..]).await);

    assert_eq!(received, data);
}

#[tokio::test]
async fn split_writer_flush_dropped_mid_record_resumes_on_the_next_flush() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let budget = Rc::new(Cell::new(None));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(Stalling {
            inner: FromTokio::new(stream),
            budget: budget.clone(),
        }))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer
        .write_all(b"first")
        .await
        .expect("error writing data");
    budget.set(Some(10));
    assert!(!poll_once_then_drop(writer.flush()));
    assert_eq!(budget.get(), Some(0));
    budget.set(None);
    writer
        .write_all(b" second")
        .await
        .expect("error writing data");
    writer.flush().await.expect("error flushing data");

    assert_eq!(
        read_exactly(&mut reader, b"first second").await,
        b"first second"
    );
}

#[tokio::test]
async fn flush_dropped_while_flushing_the_transport_flushes_it_on_the_next_flush() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let stalled = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: FromTokio::new(stream),
            stalled: stalled.clone(),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    tls.write_all(b"first").await.expect("error writing data");
    let before = flushes.get();
    stalled.set(true);
    assert!(!poll_once_then_drop(tls.flush()));
    stalled.set(false);
    tls.flush().await.expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut tls, b"first").await, b"first");
}

#[tokio::test]
async fn split_writer_flush_dropped_while_flushing_the_transport_flushes_it_on_the_next_flush() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let stalled = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(SlowFlush {
            inner: FromTokio::new(stream),
            stalled: stalled.clone(),
            flushes: flushes.clone(),
        }))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer
        .write_all(b"first")
        .await
        .expect("error writing data");
    let before = flushes.get();
    stalled.set(true);
    assert!(!poll_once_then_drop(writer.flush()));
    stalled.set(false);
    writer.flush().await.expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut reader, b"first").await, b"first");
}

#[tokio::test]
async fn write_dropped_while_flushing_the_transport_flushes_it_on_the_next_write() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let stalled = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so one write fills the record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: FromTokio::new(stream),
            stalled: stalled.clone(),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let first = tls.write(&data).await.expect("error writing data");
    assert!(first < data.len(), "the first write should fill the record");
    let before = flushes.get();
    // The next write sends the full record, then waits on the transport's flush.
    stalled.set(true);
    assert!(!poll_once_then_drop(tls.write(&data[first..])));
    stalled.set(false);
    let second = tls.write(&data[first..]).await.expect("error writing data");

    assert_eq!(flushes.get(), before + 1);
    tls.write_all(&data[first + second..])
        .await
        .expect("error writing data");
    tls.flush().await.expect("error flushing data");
    assert_eq!(read_exactly(&mut tls, &data).await, data);
}

#[tokio::test]
async fn a_flush_with_nothing_sent_since_the_last_transport_flush_does_not_flush_it_again() {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: FromTokio::new(stream),
            stalled: Rc::new(Cell::new(false)),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");

    tls.write_all(b"first").await.expect("error writing data");
    let before = flushes.get();
    tls.flush().await.expect("error flushing data");
    tls.flush().await.expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut tls, b"first").await, b"first");
}

#[tokio::test]
async fn a_split_writer_flush_with_nothing_sent_since_the_last_transport_flush_does_not_flush_it_again()
 {
    use embedded_tls::*;
    let stream = tokio::net::TcpStream::connect(setup())
        .await
        .expect("error connecting to server");
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(SlowFlush {
            inner: FromTokio::new(stream),
            stalled: Rc::new(Cell::new(false)),
            flushes: flushes.clone(),
        }))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .await
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer
        .write_all(b"first")
        .await
        .expect("error writing data");
    let before = flushes.get();
    writer.flush().await.expect("error flushing data");
    writer.flush().await.expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut reader, b"first").await, b"first");
}
