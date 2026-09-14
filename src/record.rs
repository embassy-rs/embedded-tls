use crate::TlsError;
use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::WriteKeySchedule;
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    parse_buffer::ParseBuffer,
};
use core::fmt::Debug;

pub type Encrypted = bool;

#[allow(clippy::large_enum_variant)]
pub enum ClientRecord<'config, 'a, CipherSuite>
where
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(ClientHandshake<'config, 'a, CipherSuite>, Encrypted),
    Alert(Alert, Encrypted),
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecordHeader {
    Handshake(Encrypted),
    Alert(Encrypted),
    ApplicationData,
}

impl ClientRecordHeader {
    pub fn is_encrypted(self) -> bool {
        match self {
            ClientRecordHeader::Handshake(encrypted) | ClientRecordHeader::Alert(encrypted) => {
                encrypted
            }
            ClientRecordHeader::ApplicationData => true,
        }
    }

    pub fn header_content_type(self) -> ContentType {
        match self {
            Self::Handshake(false) => ContentType::Handshake,
            Self::Alert(false) => ContentType::ChangeCipherSpec,
            Self::Handshake(true) | Self::Alert(true) | Self::ApplicationData => {
                ContentType::ApplicationData
            }
        }
    }

    pub fn trailer_content_type(self) -> ContentType {
        match self {
            Self::Handshake(_) => ContentType::Handshake,
            Self::Alert(_) => ContentType::Alert,
            Self::ApplicationData => ContentType::ApplicationData,
        }
    }

    pub fn version(self) -> [u8; 2] {
        match self {
            Self::Handshake(true) | Self::Alert(true) | Self::ApplicationData => [0x03, 0x03],
            Self::Handshake(false) | Self::Alert(false) => [0x03, 0x01],
        }
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.header_content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.version())
            .map_err(|_| TlsError::EncodeError)?;

        Ok(())
    }
}

impl<'config, CipherSuite> ClientRecord<'config, '_, CipherSuite>
where
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn header(&self) -> ClientRecordHeader {
        match self {
            ClientRecord::Handshake(_, encrypted) => ClientRecordHeader::Handshake(*encrypted),
            ClientRecord::Alert(_, encrypted) => ClientRecordHeader::Alert(*encrypted),
        }
    }

    pub fn client_hello(config: &'config TlsConfig<'config>) -> Result<Self, TlsError> {
        Ok(ClientRecord::Handshake(
            ClientHandshake::ClientHello(ClientHello::new(config)?),
            false,
        ))
    }

    pub fn close_notify(opened: bool) -> Self {
        ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            opened,
        )
    }

    pub(crate) fn encode_payload(&self, buf: &mut CryptoBuffer) -> Result<usize, TlsError> {
        let record_length_marker = buf.len();

        match self {
            ClientRecord::Handshake(handshake, _) => handshake.encode(buf)?,
            ClientRecord::Alert(alert, _) => alert.encode(buf)?,
        };

        Ok(buf.len() - record_length_marker)
    }

    pub fn finish_record(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        match self {
            ClientRecord::Handshake(handshake, false) => {
                handshake.finalize(buf, transcript, write_key_schedule)
            }
            ClientRecord::Handshake(_, true) => {
                ClientHandshake::<CipherSuite>::finalize_encrypted(buf, transcript);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub enum ServerRecord<'a, CipherSuite: TlsCipherSuite> {
    Handshake(ServerHandshake<'a, CipherSuite>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    ApplicationData(ApplicationData<'a>),
}

pub struct RecordHeader {
    header: [u8; 5],
}

impl RecordHeader {
    pub const LEN: usize = 5;

    pub fn content_type(&self) -> ContentType {
        // Content type already validated in read
        unwrap!(ContentType::of(self.header[0]))
    }

    pub fn content_length(&self) -> usize {
        // Content length already validated in read
        u16::from_be_bytes([self.header[3], self.header[4]]) as usize
    }

    pub fn data(&self) -> &[u8; 5] {
        &self.header
    }

    pub fn decode(header: [u8; 5]) -> Result<RecordHeader, TlsError> {
        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(_) => Ok(RecordHeader { header }),
        }
    }
}

impl<'a, CipherSuite: TlsCipherSuite> ServerRecord<'a, CipherSuite> {
    pub fn content_type(&self) -> ContentType {
        match self {
            ServerRecord::Handshake(_) => ContentType::Handshake,
            ServerRecord::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            ServerRecord::Alert(_) => ContentType::Alert,
            ServerRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn decode(
        header: RecordHeader,
        data: &'a mut [u8],
        digest: &mut CipherSuite::Hash,
    ) -> Result<ServerRecord<'a, CipherSuite>, TlsError> {
        assert_eq!(header.content_length(), data.len());
        match header.content_type() {
            ContentType::Invalid => Err(TlsError::Unimplemented),
            ContentType::ChangeCipherSpec => Ok(ServerRecord::ChangeCipherSpec(
                ChangeCipherSpec::read(data)?,
            )),
            ContentType::Alert => {
                let mut parse = ParseBuffer::new(data);
                let alert = Alert::parse(&mut parse)?;
                Ok(ServerRecord::Alert(alert))
            }
            ContentType::Handshake => {
                let mut parse = ParseBuffer::new(data);
                Ok(ServerRecord::Handshake(ServerHandshake::read(
                    &mut parse, digest,
                )?))
            }
            ContentType::ApplicationData => {
                let buf = CryptoBuffer::wrap_with_pos(data, data.len());
                Ok(ServerRecord::ApplicationData(ApplicationData::new(
                    buf, header,
                )))
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}
