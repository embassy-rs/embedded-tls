use crate::{
    TlsError,
    buffer::CryptoBuffer,
    config::{TLS_RECORD_OVERHEAD, TlsCipherSuite},
    connection::encrypt,
    key_schedule::{ReadKeySchedule, WriteKeySchedule},
    record::{ClientRecord, ClientRecordHeader},
};

/// Holds one record. While a record is open, plaintext is appended to it. Once sealed, the
/// buffer keeps the encrypted record until the transport has consumed all of it, so a `flush`
/// that is cancelled or fails part way through resumes where it stopped.
pub struct WriteBuffer<'a> {
    buffer: &'a mut [u8],
    pos: usize,
    /// The bytes of a sealed record that the transport has already consumed.
    sent: usize,
    current_header: Option<ClientRecordHeader>,
}

pub(crate) struct WriteBufferBorrow<'a> {
    buffer: &'a [u8],
    pos: &'a usize,
    sent: &'a usize,
    current_header: &'a Option<ClientRecordHeader>,
}

pub(crate) struct WriteBufferBorrowMut<'a> {
    buffer: &'a mut [u8],
    pos: &'a mut usize,
    sent: &'a mut usize,
    current_header: &'a mut Option<ClientRecordHeader>,
}

impl<'a> WriteBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        debug_assert!(
            buffer.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            buffer,
            pos: 0,
            sent: 0,
            current_header: None,
        }
    }

    pub(crate) fn reborrow_mut(&mut self) -> WriteBufferBorrowMut<'_> {
        WriteBufferBorrowMut {
            buffer: self.buffer,
            pos: &mut self.pos,
            sent: &mut self.sent,
            current_header: &mut self.current_header,
        }
    }

    pub(crate) fn reborrow(&self) -> WriteBufferBorrow<'_> {
        WriteBufferBorrow {
            buffer: self.buffer,
            pos: &self.pos,
            sent: &self.sent,
            current_header: &self.current_header,
        }
    }

    pub fn is_full(&self) -> bool {
        self.reborrow().is_full()
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        self.reborrow_mut().append(buf)
    }

    pub fn is_empty(&self) -> bool {
        self.reborrow().is_empty()
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.reborrow().contains(header)
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        self.reborrow_mut().start_record(header)
    }

    pub fn write_record<CipherSuite>(
        &mut self,
        record: &ClientRecord<CipherSuite>,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
        read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        write_record(
            self.buffer,
            &mut self.pos,
            &mut self.current_header,
            record,
            write_key_schedule,
            read_key_schedule,
        )
    }
}

impl<'a> WriteBufferBorrow<'a> {
    fn max_block_size(&self) -> usize {
        self.buffer.len() - TLS_RECORD_OVERHEAD
    }

    pub fn is_full(&self) -> bool {
        *self.pos == self.max_block_size()
    }

    pub fn len(&self) -> usize {
        *self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn space(&self) -> usize {
        self.max_block_size() - *self.pos
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.current_header.as_ref() == Some(&header)
    }

    pub(crate) fn is_open(&self) -> bool {
        self.current_header.is_some()
    }

    /// The bytes of the sealed record that the transport has not yet consumed. Empty while a
    /// record is open.
    pub(crate) fn unsent(&self) -> &'a [u8] {
        if self.is_open() {
            &[]
        } else {
            &self.buffer[*self.sent..*self.pos]
        }
    }
}

impl WriteBufferBorrowMut<'_> {
    fn reborrow(&self) -> WriteBufferBorrow<'_> {
        WriteBufferBorrow {
            buffer: self.buffer,
            pos: self.pos,
            sent: self.sent,
            current_header: self.current_header,
        }
    }

    pub fn is_full(&self) -> bool {
        self.reborrow().is_full()
    }

    pub fn is_empty(&self) -> bool {
        self.reborrow().is_empty()
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.reborrow().contains(header)
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        let buffered = usize::min(buf.len(), self.reborrow().space());
        if buffered > 0 {
            self.buffer[*self.pos..*self.pos + buffered].copy_from_slice(&buf[..buffered]);
            *self.pos += buffered;
        }
        buffered
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        start_record(self.buffer, self.pos, self.current_header, header)
    }

    pub(crate) fn seal_record<CipherSuite>(
        &mut self,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        seal_record(
            self.buffer,
            self.pos,
            self.current_header,
            write_key_schedule,
        )
    }

    pub(crate) fn is_open(&self) -> bool {
        self.reborrow().is_open()
    }

    pub(crate) fn unsent(&self) -> &[u8] {
        self.reborrow().unsent()
    }

    /// Records that the transport consumed `count` bytes of the sealed record. The buffer is
    /// empty again once it has consumed all of them.
    pub(crate) fn mark_sent(&mut self, count: usize) {
        *self.sent += count;
        if *self.sent >= *self.pos {
            *self.pos = 0;
            *self.sent = 0;
        }
    }
}

fn start_record(
    buffer: &mut [u8],
    pos: &mut usize,
    current_header: &mut Option<ClientRecordHeader>,
    header: ClientRecordHeader,
) -> Result<(), TlsError> {
    debug_assert!(current_header.is_none());

    debug!("start_record({:?})", header);
    *current_header = Some(header);

    with_buffer(buffer, pos, |mut buf| {
        header.encode(&mut buf)?;
        buf.push_u16(0)?;
        Ok(buf.rewind())
    })
}

fn with_buffer(
    buffer: &mut [u8],
    pos: &mut usize,
    op: impl FnOnce(CryptoBuffer) -> Result<CryptoBuffer, TlsError>,
) -> Result<(), TlsError> {
    let buf = CryptoBuffer::wrap_with_pos(buffer, *pos);

    match op(buf) {
        Ok(buf) => {
            *pos = buf.len();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Encrypts the open record in place and leaves it in the buffer, `*pos` bytes long.
fn seal_record<CipherSuite>(
    buffer: &mut [u8],
    pos: &mut usize,
    current_header: &mut Option<ClientRecordHeader>,
    write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    const HEADER_SIZE: usize = 5;

    let header = current_header.take().unwrap();
    with_buffer(buffer, pos, |mut buf| {
        if !header.is_encrypted() {
            return Ok(buf);
        }

        buf.push(header.trailer_content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;

        let mut buf = buf.offset(HEADER_SIZE);
        encrypt(write_key_schedule, &mut buf)?;
        Ok(buf.rewind())
    })?;
    let [upper, lower] = ((*pos - HEADER_SIZE) as u16).to_be_bytes();

    buffer[3] = upper;
    buffer[4] = lower;

    Ok(())
}

fn close_record<'a, CipherSuite>(
    buffer: &'a mut [u8],
    pos: &mut usize,
    current_header: &mut Option<ClientRecordHeader>,
    write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
) -> Result<&'a [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    seal_record(buffer, pos, current_header, write_key_schedule)?;
    let len = core::mem::take(pos);
    Ok(&buffer[..len])
}

fn write_record<'a, CipherSuite>(
    buffer: &'a mut [u8],
    pos: &mut usize,
    current_header: &mut Option<ClientRecordHeader>,
    record: &ClientRecord<CipherSuite>,
    write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
) -> Result<&'a [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if current_header.is_some() {
        return Err(TlsError::InternalError);
    }

    start_record(buffer, pos, current_header, record.header())?;
    with_buffer(buffer, pos, |buf| {
        let mut buf = buf.forward();
        record.encode_payload(&mut buf)?;

        let transcript = read_key_schedule
            .ok_or(TlsError::InternalError)?
            .transcript_hash();

        record.finish_record(&mut buf, transcript, write_key_schedule)?;
        Ok(buf.rewind())
    })?;
    close_record(buffer, pos, current_header, write_key_schedule)
}
