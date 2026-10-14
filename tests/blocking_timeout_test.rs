//! A blocking read or write that returns a timeout part way through a record must not lose,
//! repeat or corrupt data. A caller that sets a timeout on its socket, so it can run timers
//! while the peer is quiet, retries the call after the timeout.

use embedded_io::{ErrorType, Read, Write};
use embedded_io_adapters::std::FromStd;
use std::cell::{Cell, RefCell};
use std::net::{SocketAddr, TcpStream};
use std::rc::Rc;
use std::sync::Once;

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

/// A transport that times out after a byte budget, as a socket with a timeout does when the peer
/// stops for a while. The budget stays at `Some(0)` until the test clears it, so a test can check
/// that a timeout came from the spent budget. A budget of `None` lets every call through.
struct TimingOut<T> {
    inner: T,
    read_budget: Rc<Cell<Option<usize>>>,
    write_budget: Rc<Cell<Option<usize>>>,
}

fn timed_out() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::TimedOut)
}

impl<T: ErrorType<Error = std::io::Error>> ErrorType for TimingOut<T> {
    type Error = std::io::Error;
}

impl<T: Read + ErrorType<Error = std::io::Error>> Read for TimingOut<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.read_budget.get() {
            None => self.inner.read(buf),
            Some(0) => Err(timed_out()),
            Some(budget) => {
                let allowed = budget.min(buf.len());
                let read = self.inner.read(&mut buf[..allowed])?;
                self.read_budget.set(Some(budget - read));
                Ok(read)
            }
        }
    }
}

impl<T: Write + ErrorType<Error = std::io::Error>> Write for TimingOut<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self.write_budget.get() {
            None => self.inner.write(buf),
            Some(0) => Err(timed_out()),
            Some(budget) => {
                let written = self.inner.write(&buf[..budget.min(buf.len())])?;
                self.write_budget.set(Some(budget - written));
                Ok(written)
            }
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
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

impl<T: Read> Read for Shared<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.borrow_mut().read(buf)
    }
}

impl<T: Write> Write for Shared<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.borrow_mut().flush()
    }
}

/// A transport whose flush times out while `time_out` is set, as a socket with a timeout
/// does when the peer is slow to acknowledge the data. `flushes` counts the flushes that
/// complete.
struct SlowFlush<T> {
    inner: T,
    time_out: Rc<Cell<bool>>,
    flushes: Rc<Cell<usize>>,
}

impl<T: ErrorType<Error = std::io::Error>> ErrorType for SlowFlush<T> {
    type Error = std::io::Error;
}

impl<T: Read + ErrorType<Error = std::io::Error>> Read for SlowFlush<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.read(buf)
    }
}

impl<T: Write + ErrorType<Error = std::io::Error>> Write for SlowFlush<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if self.time_out.get() {
            return Err(timed_out());
        }
        self.inner.flush()?;
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

type Budgets = (Rc<Cell<Option<usize>>>, Rc<Cell<Option<usize>>>);

fn transport() -> (TimingOut<FromStd<TcpStream>>, Budgets) {
    let stream = TcpStream::connect(setup()).expect("error connecting to server");
    // A lost record would otherwise leave a read waiting for ever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("error setting the read timeout");
    let read_budget = Rc::new(Cell::new(None));
    let write_budget = Rc::new(Cell::new(None));
    let transport = TimingOut {
        inner: FromStd::new(stream),
        read_budget: read_budget.clone(),
        write_budget: write_budget.clone(),
    };
    (transport, (read_budget, write_budget))
}

/// Reads until `expected.len()` bytes have arrived, and returns them.
fn read_exactly<R: Read>(reader: &mut R, expected: &[u8]) -> Vec<u8>
where
    R::Error: std::fmt::Debug,
{
    let mut received = Vec::new();
    let mut buf = [0; 4096];
    while received.len() < expected.len() {
        let read = reader.read(&mut buf).expect("error reading data");
        assert_ne!(read, 0, "the server closed the connection");
        received.extend_from_slice(&buf[..read]);
    }
    received
}

fn is_timeout(error: &embedded_tls::TlsError) -> bool {
    matches!(
        error,
        embedded_tls::TlsError::Io(embedded_io::ErrorKind::TimedOut)
    )
}

#[test]
fn read_timed_out_mid_header_resumes_on_the_next_read() {
    use embedded_tls::blocking::*;
    let (transport, (read_budget, _)) = transport();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("error writing data");
    tls.flush().expect("error flushing data");
    read_budget.set(Some(2));
    let mut buf = [0; 64];
    let error = tls.read(&mut buf).expect_err("the read should time out");
    assert!(is_timeout(&error), "{error:?}");
    assert_eq!(read_budget.get(), Some(0));
    read_budget.set(None);

    assert_eq!(read_exactly(&mut tls, b"ping"), b"ping");
}

#[test]
fn read_timed_out_mid_body_resumes_on_the_next_read() {
    use embedded_tls::blocking::*;
    let (transport, (read_budget, _)) = transport();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("error writing data");
    tls.flush().expect("error flushing data");
    // The 5-byte header and 3 bytes of the body.
    read_budget.set(Some(8));
    let mut buf = [0; 64];
    let error = tls.read(&mut buf).expect_err("the read should time out");
    assert!(is_timeout(&error), "{error:?}");
    assert_eq!(read_budget.get(), Some(0));
    read_budget.set(None);

    assert_eq!(read_exactly(&mut tls, b"ping"), b"ping");
}

#[test]
fn flush_timed_out_mid_record_resumes_on_the_next_flush() {
    use embedded_tls::blocking::*;
    let (transport, (_, write_budget)) = transport();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    tls.write_all(b"first").expect("error writing data");
    write_budget.set(Some(10));
    let error = tls.flush().expect_err("the flush should time out");
    assert!(is_timeout(&error), "{error:?}");
    assert_eq!(write_budget.get(), Some(0));
    write_budget.set(None);
    tls.write_all(b" second").expect("error writing data");
    tls.flush().expect("error flushing data");

    assert_eq!(read_exactly(&mut tls, b"first second"), b"first second");
}

#[test]
fn write_timed_out_while_flushing_a_full_record_does_not_repeat_data() {
    use embedded_tls::blocking::*;
    let (transport, (_, write_budget)) = transport();
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so one write fills the record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut sent = 0;
    while sent < data.len() {
        // Each first attempt times out once the transport has taken 7 bytes. A write that
        // returned an error took nothing, so the caller offers the same bytes again.
        write_budget.set(Some(7));
        let written = match tls.write(&data[sent..]) {
            Ok(written) => written,
            Err(error) => {
                assert!(is_timeout(&error), "{error:?}");
                write_budget.set(None);
                tls.write(&data[sent..]).expect("error writing data")
            }
        };
        sent += written;
    }
    write_budget.set(None);
    tls.flush().expect("error flushing data");

    assert_eq!(read_exactly(&mut tls, &data), data);
}

#[test]
fn flush_timed_out_at_every_byte_of_a_record_resumes_on_the_next_flush() {
    use embedded_tls::blocking::*;
    let (transport, (_, write_budget)) = transport();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    let chunk = b"0123456789";
    let record_len = chunk.len() + RECORD_OVERHEAD;
    let mut expected = Vec::new();
    for cut in 0..=record_len {
        tls.write_all(chunk).expect("error writing data");
        expected.extend_from_slice(chunk);
        write_budget.set(Some(cut));
        // The flush succeeds only when the budget covers the whole record.
        match tls.flush() {
            Ok(()) => assert_eq!(
                cut, record_len,
                "a flush cut at {cut} should have timed out"
            ),
            Err(error) => assert!(
                cut < record_len && is_timeout(&error),
                "cut at {cut}: {error:?}"
            ),
        }
        // The transport took the whole budget, so the record was cut at `cut`.
        assert_eq!(write_budget.get(), Some(0), "cut at {cut}");
        write_budget.set(None);
        tls.flush().expect("error flushing data");
    }

    assert_eq!(read_exactly(&mut tls, &expected), expected);
}

#[test]
fn write_timed_out_at_every_byte_of_a_full_record_does_not_repeat_data() {
    use embedded_tls::blocking::*;
    let (transport, (_, write_budget)) = transport();
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so each write fills a record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(transport, &mut read_record_buffer, &mut write_record_buffer);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    // More records than a record has bytes, so the cuts reach every byte of one.
    let data: Vec<u8> = (0..2_400_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    // The first write fills a record without touching the transport. Its count is the data that
    // one record holds.
    let mut sent = tls.write(&data).expect("error writing data");
    let record_len = sent + RECORD_OVERHEAD;
    // Each later write sends the full record first, cut one byte further on each time, from 0 to
    // the whole record.
    let mut attempts = 0;
    let mut received = Vec::new();
    while sent < data.len() {
        let cut = attempts % (record_len + 1);
        attempts += 1;
        write_budget.set(Some(cut));
        let result = tls.write(&data[sent..]);
        // The transport took the whole budget, so the record was cut at `cut`.
        assert_eq!(write_budget.get(), Some(0), "cut at {cut}");
        write_budget.set(None);
        let written = match result {
            Ok(written) => {
                assert_eq!(
                    cut, record_len,
                    "a write cut at {cut} should have timed out"
                );
                written
            }
            Err(error) => {
                assert!(is_timeout(&error), "cut at {cut}: {error:?}");
                tls.write(&data[sent..]).expect("error writing data")
            }
        };
        sent += written;
        // Reading the echo of each full record keeps the socket buffers from filling. A full
        // buffer would block the transport before the cut. The open record holds `written`.
        let echoed = sent - written;
        received.extend(read_exactly(&mut tls, &data[received.len()..echoed]));
    }
    assert!(attempts > record_len, "only {attempts} attempts");
    tls.flush().expect("error flushing data");
    received.extend(read_exactly(&mut tls, &data[received.len()..]));

    assert_eq!(received, data);
}

#[test]
fn split_writer_flush_timed_out_mid_record_resumes_on_the_next_flush() {
    use embedded_tls::blocking::*;
    let (transport, (_, write_budget)) = transport();
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(transport))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer.write_all(b"first").expect("error writing data");
    write_budget.set(Some(10));
    let error = writer.flush().expect_err("the flush should time out");
    assert!(is_timeout(&error), "{error:?}");
    assert_eq!(write_budget.get(), Some(0));
    write_budget.set(None);
    writer.write_all(b" second").expect("error writing data");
    writer.flush().expect("error flushing data");

    assert_eq!(read_exactly(&mut reader, b"first second"), b"first second");
}

#[test]
fn flush_timed_out_while_flushing_the_transport_flushes_it_on_the_next_flush() {
    use embedded_tls::blocking::*;
    let (transport, _) = transport();
    let time_out = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: transport,
            time_out: time_out.clone(),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(embedded_tls::flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    tls.write_all(b"first").expect("error writing data");
    let before = flushes.get();
    time_out.set(true);
    let error = tls.flush().expect_err("the flush should time out");
    assert!(is_timeout(&error), "{error:?}");
    time_out.set(false);
    tls.flush().expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut tls, b"first"), b"first");
}

#[test]
fn split_writer_flush_timed_out_while_flushing_the_transport_flushes_it_on_the_next_flush() {
    use embedded_tls::blocking::*;
    let (transport, _) = transport();
    let time_out = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(SlowFlush {
            inner: transport,
            time_out: time_out.clone(),
            flushes: flushes.clone(),
        }))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(embedded_tls::flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer.write_all(b"first").expect("error writing data");
    let before = flushes.get();
    time_out.set(true);
    let error = writer.flush().expect_err("the flush should time out");
    assert!(is_timeout(&error), "{error:?}");
    time_out.set(false);
    writer.flush().expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut reader, b"first"), b"first");
}

#[test]
fn write_timed_out_while_flushing_the_transport_flushes_it_on_the_next_write() {
    use embedded_tls::blocking::*;
    let (transport, _) = transport();
    let time_out = Rc::new(Cell::new(false));
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    // A small write buffer, so one write fills the record.
    let mut write_record_buffer = [0; SMALL_WRITE_BUFFER];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: transport,
            time_out: time_out.clone(),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(embedded_tls::flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let first = tls.write(&data).expect("error writing data");
    assert!(first < data.len(), "the first write should fill the record");
    let before = flushes.get();
    // The next write sends the full record, then times out on the transport's flush.
    time_out.set(true);
    let error = tls
        .write(&data[first..])
        .expect_err("the write should time out");
    assert!(is_timeout(&error), "{error:?}");
    time_out.set(false);
    let second = tls.write(&data[first..]).expect("error writing data");

    assert_eq!(flushes.get(), before + 1);
    tls.write_all(&data[first + second..])
        .expect("error writing data");
    tls.flush().expect("error flushing data");
    assert_eq!(read_exactly(&mut tls, &data), data);
}

#[test]
fn a_flush_with_nothing_sent_since_the_last_transport_flush_does_not_flush_it_again() {
    use embedded_tls::blocking::*;
    let (transport, _) = transport();
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        SlowFlush {
            inner: transport,
            time_out: Rc::new(Cell::new(false)),
            flushes: flushes.clone(),
        },
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(embedded_tls::flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");

    tls.write_all(b"first").expect("error writing data");
    let before = flushes.get();
    tls.flush().expect("error flushing data");
    tls.flush().expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut tls, b"first"), b"first");
}

#[test]
fn a_split_writer_flush_with_nothing_sent_since_the_last_transport_flush_does_not_flush_it_again() {
    use embedded_tls::blocking::*;
    let (transport, _) = transport();
    let flushes = Rc::new(Cell::new(0));
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls: TlsConnection<_, Aes128GcmSha256> = TlsConnection::new(
        Shared(Rc::new(RefCell::new(SlowFlush {
            inner: transport,
            time_out: Rc::new(Cell::new(false)),
            flushes: flushes.clone(),
        }))),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );
    tls.set_flush_policy(embedded_tls::flush_policy::FlushPolicy::Strict);
    tls.open(TlsContext::new(&config, NoVerify))
        .expect("error establishing TLS connection");
    let (mut reader, mut writer) = tls.split();

    writer.write_all(b"first").expect("error writing data");
    let before = flushes.get();
    writer.flush().expect("error flushing data");
    writer.flush().expect("error flushing data");

    assert_eq!(flushes.get(), before + 1);
    assert_eq!(read_exactly(&mut reader, b"first"), b"first");
}
