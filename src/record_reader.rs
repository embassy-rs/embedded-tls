use crate::key_schedule::ReadKeySchedule;
use embedded_io::{Error, Read as BlockingRead};
use embedded_io_async::Read as AsyncRead;

use crate::{
    TlsError,
    config::TlsCipherSuite,
    record::{RecordHeader, ServerRecord},
};

pub struct RecordReader<'a> {
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: usize,
    /// Partial record header bytes read so far. Persisted here (not on the
    /// read future's stack) so a cancelled async read resumes the header
    /// instead of dropping consumed bytes and desyncing the record stream.
    header_buf: [u8; RecordHeader::LEN],
    header_read: usize,
}

pub struct RecordReaderBorrowMut<'a> {
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: &'a mut usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: &'a mut usize,
    header_buf: &'a mut [u8; RecordHeader::LEN],
    header_read: &'a mut usize,
}

impl<'a> RecordReader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        if buf.len() < 16640 {
            warn!("Read buffer is smaller than 16640 bytes, which may cause problems!");
        }
        Self {
            buf,
            decoded: 0,
            pending: 0,
            header_buf: [0; RecordHeader::LEN],
            header_read: 0,
        }
    }

    pub fn reborrow_mut(&mut self) -> RecordReaderBorrowMut<'_> {
        RecordReaderBorrowMut {
            buf: self.buf,
            decoded: &mut self.decoded,
            pending: &mut self.pending,
            header_buf: &mut self.header_buf,
            header_read: &mut self.header_read,
        }
    }

    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            &mut self.header_buf,
            &mut self.header_read,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read_blocking(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            &mut self.header_buf,
            &mut self.header_read,
            transport,
            key_schedule,
        )
    }
}

impl RecordReaderBorrowMut<'_> {
    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read(
            self.buf,
            self.decoded,
            self.pending,
            self.header_buf,
            self.header_read,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read_blocking(
            self.buf,
            self.decoded,
            self.pending,
            self.header_buf,
            self.header_read,
            transport,
            key_schedule,
        )
    }
}

pub async fn read<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    header_buf: &mut [u8; RecordHeader::LEN],
    header_read: &mut usize,
    transport: &mut impl AsyncRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    // Resumable header read: `header_buf`/`header_read` live in the caller's
    // RecordReader, so if this future is dropped (e.g. a concurrent TX wins a
    // `select`) mid-header, the bytes already pulled from the transport are
    // kept and the next call continues instead of restarting mid-record.
    while *header_read < RecordHeader::LEN {
        let read = transport
            .read(&mut header_buf[*header_read..])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *header_read += read;
    }
    let header = RecordHeader::decode(*header_buf)?;

    // `advance` is already resumable via `pending`; if it is cancelled,
    // `header_read` stays full so the header is re-decoded on resume.
    advance(buf, decoded, pending, transport, header.content_length()).await?;
    let result = consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    );
    // Whole record (header + body) is in the buffer now; arm for the next one.
    *header_read = 0;
    result
}

pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    header_buf: &mut [u8; RecordHeader::LEN],
    header_read: &mut usize,
    transport: &mut impl BlockingRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    // A `read` that fails part way through the header keeps what it has, so the next `read`
    // completes it. The async `read` does the same for a cancelled future.
    while *header_read < RecordHeader::LEN {
        let read = transport
            .read(&mut header_buf[*header_read..])
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *header_read += read;
    }
    let header = RecordHeader::decode(*header_buf)?;

    advance_blocking(buf, decoded, pending, transport, header.content_length())?;
    let result = consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    );
    *header_read = 0;
    result
}

async fn advance(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl AsyncRead,
    amount: usize,
) -> Result<(), TlsError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    // Read only the bytes still missing for this record. On a resumed call
    // `*pending` already holds part of the record, so capping the read at
    // `amount - *pending` (rather than a fixed `amount`) avoids over-reading
    // into the next record and stranding those bytes — which desynced the
    // record stream on the next header read.
    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..][..amount - *pending])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *pending += read;
    }

    Ok(())
}

fn advance_blocking(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl BlockingRead,
    amount: usize,
) -> Result<(), TlsError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..][..amount - *pending])
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *pending += read;
    }

    Ok(())
}

fn consume<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    header: RecordHeader,
    digest: &mut CipherSuite::Hash,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    let content_len = header.content_length();

    let slice = &mut buf[*decoded..][..content_len];

    *decoded += content_len;
    *pending -= content_len;

    ServerRecord::decode(header, slice, digest)
}

fn ensure_contiguous(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    len: usize,
) -> Result<(), TlsError> {
    if *decoded + len > buf.len() {
        if len > buf.len() {
            error!(
                "Record too large for buffer. Size: {} Buffer size: {}",
                len,
                buf.len()
            );
            return Err(TlsError::InsufficientSpace);
        }
        buf.copy_within(*decoded..*decoded + *pending, 0);
        *decoded = 0;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::{Aes128GcmSha256, content_types::ContentType, key_schedule::KeySchedule};

    struct ChunkRead<'a>(&'a [u8], usize);

    impl embedded_io::ErrorType for ChunkRead<'_> {
        type Error = Infallible;
    }

    impl BlockingRead for ChunkRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = usize::min(self.1, buf.len());
            let len = usize::min(len, self.0.len());
            buf[..len].copy_from_slice(&self.0[..len]);
            self.0 = &self.0[len..];
            Ok(len)
        }
    }

    #[test]
    fn can_read_blocking() {
        can_read_blocking_case(1);
        can_read_blocking_case(2);
        can_read_blocking_case(3);
        can_read_blocking_case(4);
        can_read_blocking_case(5);
        can_read_blocking_case(6);
        can_read_blocking_case(7);
        can_read_blocking_case(8);
        can_read_blocking_case(9);
        can_read_blocking_case(10);
        can_read_blocking_case(11);
        can_read_blocking_case(12);
        can_read_blocking_case(13);
        can_read_blocking_case(14);
        can_read_blocking_case(15);
        can_read_blocking_case(16);
    }

    fn can_read_blocking_case(chunk_size: usize) {
        let mut transport = ChunkRead(
            &[
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x04,
                // Data
                0xde,
                0xad,
                0xbe,
                0xef,
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x02,
                // Data
                0xaa,
                0xbb,
            ],
            chunk_size,
        );

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(6, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_blocking_must_rotate_buffer() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x04,
            // Data
            0xde,
            0xad,
            0xbe,
            0xef,
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x02,
            // Data
            0xaa,
            0xbb,
        ]
        .as_slice();

        let mut buf = [0; 4]; // cannot contain both data portions
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(2, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_empty_record() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
        ]
        .as_slice();

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    // Regression: a resumed body read (entered with `pending` already holding
    // part of the record, e.g. after the read future was cancelled by a
    // `select` and polled again) must read only `amount - pending` more bytes.
    // Reading a fixed `amount` over-reads into the next record and desyncs the
    // stream. `advance` and `advance_blocking` share this logic.
    fn advance_resume_case(chunk_size: usize) {
        // 8 bytes available; the record wants 5 and already has 2 pending, so
        // exactly 3 more should be consumed — leaving 5 for the next record.
        let mut transport = ChunkRead(
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            chunk_size,
        );

        let mut buf = [0u8; 32];
        buf[0] = 0xaa; // 2 bytes of this record already buffered
        buf[1] = 0xbb;
        let mut decoded = 0usize;
        let mut pending = 2usize;

        advance_blocking(&mut buf, &mut decoded, &mut pending, &mut transport, 5).unwrap();

        assert_eq!(
            5, pending,
            "chunk_size={chunk_size}: record should be full, not over-read"
        );
        assert_eq!(0, decoded);
        assert_eq!(
            5,
            transport.0.len(),
            "chunk_size={chunk_size}: over-read into the next record"
        );
        assert_eq!(&[0xaa, 0xbb, 0x11, 0x22, 0x33], &buf[..5]);
    }

    #[test]
    fn advance_only_reads_missing_bytes_on_resume() {
        for chunk_size in 1..=8 {
            advance_resume_case(chunk_size);
        }
    }
}
