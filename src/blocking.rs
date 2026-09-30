use core::sync::atomic::Ordering;

use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::{Handshake, State, decrypt_record};
use crate::flush_policy::FlushPolicy;
use crate::key_schedule::KeySchedule;
use crate::key_schedule::{ReadKeySchedule, WriteKeySchedule};
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::{RecordReader, RecordReaderBorrowMut};
use crate::write_buffer::{WriteBuffer, WriteBufferBorrowMut};
use embedded_io::Error as _;
use embedded_io::{BufRead, ErrorType, Read, Write};
use portable_atomic::AtomicBool;

pub use crate::TlsError;
pub use crate::config::*;

/// Type representing a TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: AtomicBool,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn is_opened(&mut self) -> bool {
        *self.opened.get_mut()
    }

    /// Create a new TLS connection with the provided context and a blocking I/O implementation
    ///
    /// NOTE: The record read buffer should be sized to fit an encrypted TLS record. The size of this record
    /// depends on the server configuration, but the maximum allowed value for a TLS record is 16640 bytes,
    /// which should be a safe value to use.
    ///
    /// The write record buffer can be smaller than the read buffer. During writes [`TLS_RECORD_OVERHEAD`] bytes of
    /// overhead is added per record, so the buffer must at least be this large. Large writes are split into multiple
    /// records if depending on the size of the write buffer.
    /// The largest of the two buffers will be used to encode the TLS handshake record, hence either of the
    /// buffers must at least be large enough to encode a handshake.
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        Self {
            delegate,
            opened: AtomicBool::new(false),
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
            flush_policy: FlushPolicy::default(),
        }
    }

    /// Returns a reference to the current flush policy.
    ///
    /// The flush policy controls whether the underlying transport is flushed
    /// (via its `flush()` method) after writing a TLS record.
    #[inline]
    pub fn flush_policy(&self) -> FlushPolicy {
        self.flush_policy
    }

    /// Replace the current flush policy with the provided one.
    ///
    /// This sets how and when the connection will call `flush()` on the
    /// underlying transport after writing records.
    #[inline]
    pub fn set_flush_policy(&mut self, policy: FlushPolicy) {
        self.flush_policy = policy;
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when
    /// creating the connection instance.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection
    /// instance must be recreated.
    pub fn open<Verifier>(&mut self, mut context: TlsContext<Verifier>) -> Result<(), TlsError>
    where
        Verifier: TlsVerifier<CipherSuite>,
    {
        let mut handshake: Handshake<CipherSuite> = Handshake::new();
        if let Some(server_name) = context.config.server_name {
            context.verifier.set_hostname_verification(server_name)?;
        }
        let mut state = State::ClientHello;

        while state != State::ApplicationData {
            let next_state = state.process_blocking(
                &mut self.delegate,
                &mut handshake,
                &mut self.record_reader,
                &mut self.record_write_buf,
                &mut self.key_schedule,
                &mut context,
            )?;
            trace!("State {:?} -> {:?}", state, next_state);
            state = next_state;
        }
        *self.opened.get_mut() = true;

        Ok(())
    }

    /// The handshake logic lives in [`crate::server_handshake`]; this method is
    /// the blocking I/O driver over it.
    ///
    /// On failure the peer is told why with a TLS alert before the error is
    /// returned, so interop problems are diagnosable from the client side.
    #[cfg(feature = "server")]
    pub fn open_server<Verifier>(
        &mut self,
        context: crate::server_config::TlsServerContext<'_, Verifier>,
    ) -> Result<(), TlsError>
    where
        Verifier: TlsVerifier<CipherSuite>,
    {
        let result = self.open_server_handshake(context);

        if let Err(error) = &result
            && let Some((level, description)) = crate::server_handshake::alert_for(error)
        {
            // Best effort: the peer may already have gone away.
            let _ = self.send_handshake_alert(level, description);
        }

        result
    }

    /// Encode and send a fatal alert. Failures here are not reported: the
    /// handshake error that triggered the alert is what the caller needs.
    #[cfg(feature = "server")]
    fn send_handshake_alert(
        &mut self,
        level: crate::alert::AlertLevel,
        description: crate::alert::AlertDescription,
    ) -> Result<(), TlsError> {
        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let tx = self.record_write_buf.write_record(
            &ClientRecord::Alert(crate::alert::Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;
        self.delegate
            .write_all(tx)
            .map_err(|e| TlsError::Io(e.kind()))?;
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
        Ok(())
    }

    #[cfg(feature = "server")]
    fn open_server_handshake<Verifier>(
        &mut self,
        context: crate::server_config::TlsServerContext<'_, Verifier>,
    ) -> Result<(), TlsError>
    where
        Verifier: TlsVerifier<CipherSuite>,
    {
        use crate::server_handshake::{CHANGE_CIPHER_SPEC, ServerHandshake};

        let crate::server_config::TlsServerContext {
            config,
            verifier: _verifier,
            private_key,
        } = context;
        let mut handshake: ServerHandshake<'_, CipherSuite> = ServerHandshake::new(config);

        macro_rules! send {
            ($outgoing:expr) => {{
                let out = $outgoing;
                self.delegate
                    .write_all(out.bytes)
                    .map_err(|e| TlsError::Io(e.kind()))?;
                if out.encrypted {
                    self.key_schedule.write_state().increment_counter();
                }
                self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
            }};
        }

        // Scoped so the record's borrow of the reader ends before the next read.
        {
            let record = self
                .record_reader
                .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;
            handshake.absorb_client_hello(&record)?;
        }

        if handshake.needs_hello_retry() {
            send!(
                handshake.encode_hello_retry_request(
                    &mut self.key_schedule,
                    &mut self.record_write_buf
                )?
            );
            self.delegate
                .write_all(&CHANGE_CIPHER_SPEC)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;

            loop {
                let record = self
                    .record_reader
                    .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;
                if handshake.absorb_hello_retry_response(&record)? {
                    break;
                }
            }
        }

        handshake.compute_keys(&mut self.key_schedule)?;
        send!(handshake.encode_server_hello(&mut self.key_schedule, &mut self.record_write_buf)?);
        handshake.init_handshake_secret(&mut self.key_schedule)?;

        if !handshake.did_hrr() {
            self.delegate
                .write_all(&CHANGE_CIPHER_SPEC)
                .map_err(|e| TlsError::Io(e.kind()))?;
        }

        handshake.negotiate_alpn();

        for flight_record in handshake.flight() {
            send!(handshake.encode_flight_record(
                *flight_record,
                private_key,
                &mut self.key_schedule,
                &mut self.record_write_buf
            )?);
        }

        handshake.capture_traffic_hash(&mut self.key_schedule);

        loop {
            let record = self
                .record_reader
                .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;
            if handshake.process_client_record(&mut self.key_schedule, record)? {
                break;
            }
        }

        handshake.finalize(&mut self.key_schedule)?;
        *self.opened.get_mut() = true;
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;

        Ok(())
    }

    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// The slice may be buffered internally and not written to the connection immediately.
    /// In this case [`Self::flush()`] should be called to force the currently buffered writes
    /// to be written to the connection.
    ///
    /// Returns the number of bytes buffered/written.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.is_opened() {
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush()?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush()?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written
    /// to the connection.
    pub fn flush(&mut self) -> Result<(), TlsError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;

            key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport()?;
            }
        }

        Ok(())
    }

    #[inline]
    fn flush_transport(&mut self) -> Result<(), TlsError> {
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))
    }

    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered()?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.is_opened() {
            while self.decrypted.is_empty() {
                self.read_application_data()?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let key_schedule = self.key_schedule.read_state();
        let record = self
            .record_reader
            .read_blocking(&mut self.delegate, key_schedule)?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: self.opened.get_mut(),
        };
        decrypt_record(key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        })?;

        Ok(())
    }

    fn close_internal(&mut self) -> Result<(), TlsError> {
        self.flush()?;

        let is_opened = self.is_opened();
        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let slice = self.record_write_buf.write_record(
            &ClientRecord::close_notify(is_opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.delegate
            .write_all(slice)
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.write_state().increment_counter();

        self.flush_transport()?;

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the I/O provider.
    pub fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal() {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    pub fn split(
        &mut self,
    ) -> (
        TlsReader<'_, Socket, CipherSuite>,
        TlsWriter<'_, Socket, CipherSuite>,
    )
    where
        Socket: Clone,
    {
        let (wks, rks) = self.key_schedule.as_split();

        let reader = TlsReader {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: rks,
            record_reader: self.record_reader.reborrow_mut(),
            decrypted: &mut self.decrypted,
        };
        let writer = TlsWriter {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: wks,
            record_write_buf: self.record_write_buf.reborrow_mut(),
            flush_policy: self.flush_policy,
        };

        (reader, writer)
    }
}

impl<'a, Socket, CipherSuite> ErrorType for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> Read for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsConnection::read(self, buf)
    }
}

impl<'a, Socket, CipherSuite> BufRead for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> Write for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsConnection::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        TlsConnection::flush(self)
    }
}

pub struct TlsReader<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut ReadKeySchedule<CipherSuite>,
    record_reader: RecordReaderBorrowMut<'a>,
    decrypted: &'a mut DecryptedBufferInfo,
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<'a, Socket, CipherSuite> TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.opened.load(Ordering::Acquire) {
            while self.decrypted.is_empty() {
                self.read_application_data()?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read_blocking(&mut self.delegate, self.key_schedule)?;

        let mut opened = self.opened.load(Ordering::Acquire);
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: self.decrypted,
            is_open: &mut opened,
        };
        let result = decrypt_record(self.key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !opened {
            self.opened.store(false, Ordering::Release);
        }
        result
    }
}

pub struct TlsWriter<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut WriteKeySchedule<CipherSuite>,
    record_write_buf: WriteBufferBorrowMut<'a>,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn flush_transport(&mut self) -> Result<(), TlsError> {
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))
    }
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<Socket, CipherSuite> ErrorType for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<Socket, CipherSuite> ErrorType for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> Read for TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered()?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }
}

impl<'a, Socket, CipherSuite> BufRead for TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> Write for TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if self.opened.load(Ordering::Acquire) {
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush()?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush()?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if !self.record_write_buf.is_empty() {
            let slice = self.record_write_buf.close_record(self.key_schedule)?;

            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;

            self.key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport()?;
            }
        }

        Ok(())
    }
}
