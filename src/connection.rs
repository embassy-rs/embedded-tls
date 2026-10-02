use crate::config::{Certificate, PrivateKey, TlsCipherSuite, TlsContext};
use crate::crypto::{TAG_LEN, TlsAead, TlsHash, certificate_verify_message};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::{CertificateVerify, TlsError, TlsVerifier};
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use core::fmt::Debug;
use embedded_io::Error as _;
use embedded_io::{Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
#[cfg(not(feature = "x25519"))]
use embassy_crypto::p256::SecretKey;
#[cfg(feature = "x25519")]
use embassy_crypto::x25519::SecretKey;
#[cfg(feature = "mlkem")]
use ml_kem::{DecapsulationKey, MlKem768};

use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;

pub(crate) fn decrypt_record<CipherSuite>(
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
    mut cb: impl FnMut(
        &mut ReadKeySchedule<CipherSuite>,
        ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let ServerRecord::ApplicationData(ApplicationData {
        header,
        data: mut app_data,
    }) = record
    {
        let server_key = key_schedule.get_key()?;
        let nonce = key_schedule.get_nonce()?;

        let crypto = <CipherSuite::Cipher as TlsAead>::new(server_key);
        let data = app_data.as_mut_slice();
        let ciphertext_len = data
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(TlsError::CryptoError)?;
        let (ciphertext, tag) = data.split_at_mut(ciphertext_len);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().map_err(|_| TlsError::CryptoError)?;
        crypto.decrypt(&nonce, header.data(), ciphertext, tag)?;
        app_data.truncate(ciphertext_len);

        let padding = app_data
            .as_slice()
            .iter()
            .enumerate()
            .rfind(|(_, b)| **b != 0);
        if let Some((index, _)) = padding {
            app_data.truncate(index + 1);
        };

        let content_type =
            ContentType::of(*app_data.as_slice().last().unwrap()).ok_or(TlsError::InvalidRecord)?;

        trace!("Decrypting: content type = {:?}", content_type);

        // Remove the content type
        app_data.truncate(app_data.len() - 1);

        let mut buf = ParseBuffer::new(app_data.as_slice());
        match content_type {
            ContentType::Handshake => {
                // Decode potentially coalesced handshake messages
                while buf.remaining() > 0 {
                    let inner = ServerHandshake::read(&mut buf, key_schedule.transcript_hash())?;
                    cb(key_schedule, ServerRecord::Handshake(inner))?;
                }
            }
            ContentType::ApplicationData => {
                let inner = ApplicationData::new(app_data, header);
                cb(key_schedule, ServerRecord::ApplicationData(inner))?;
            }
            ContentType::Alert => {
                let alert = Alert::parse(&mut buf)?;
                cb(key_schedule, ServerRecord::Alert(alert))?;
            }
            _ => return Err(TlsError::Unimplemented),
        }
        key_schedule.increment_counter();
    } else {
        trace!("Not decrypting: content_type = {:?}", record.content_type());
        cb(key_schedule, record)?;
    }
    Ok(())
}

pub(crate) fn encrypt<CipherSuite>(
    key_schedule: &WriteKeySchedule<CipherSuite>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_key = key_schedule.get_key()?;
    let nonce = key_schedule.get_nonce()?;
    let crypto = <CipherSuite::Cipher as TlsAead>::new(client_key);
    let len = buf.len() + TAG_LEN;

    if len > buf.capacity() {
        return Err(TlsError::InsufficientSpace);
    }

    trace!("output size {}", len);
    let len_bytes = (len as u16).to_be_bytes();
    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    let tag = crypto
        .encrypt(&nonce, &additional_data, buf.as_mut_slice())
        .map_err(|_| TlsError::InvalidApplicationData)?;
    buf.extend_from_slice(&tag)
        .map_err(|_| TlsError::InvalidApplicationData)
}

pub struct Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<SecretKey>,
    certificate_request: Option<CertificateRequest>,
    #[cfg(feature = "mlkem")]
    kem: Option<DecapsulationKey<MlKem768>>,
    /// The number of pre-shared key identities the `ClientHello` offered.
    psk_identities: usize,
    server_auth: ServerAuth,
}

impl<CipherSuite> Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Handshake<CipherSuite> {
        Handshake {
            traffic_hash: None,
            secret: None,
            certificate_request: None,
            #[cfg(feature = "mlkem")]
            kem: None,
            psk_identities: 0,
            server_auth: ServerAuth::None,
        }
    }
}

/// How far the server has proven its identity. A valid `Finished` only proves that the peer
/// knows the handshake secret. A peer that chose its own key share always knows it
/// (RFC 8446, Section 4.4).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerAuth {
    /// The server has proven nothing yet.
    None,
    /// The verifier accepted the `Certificate`, and its `CertificateVerify` has not arrived.
    Certificate,
    /// The verifier accepted the `CertificateVerify` signature.
    Signed,
    /// The server selected the pre-shared key the client offered.
    Psk,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientCertVerify,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    pub async fn process<'v, Transport, CipherSuite, Verifier>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer<'_>,
        key_schedule: &mut KeySchedule<CipherSuite>,
        context: &mut TlsContext<'_, Verifier>,
    ) -> Result<State, TlsError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        CipherSuite: TlsCipherSuite,
        Verifier: TlsVerifier<CipherSuite>,
    {
        match self {
            State::ClientHello => {
                let (state, tx) = client_hello(key_schedule, context.config, tx_buf, handshake)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ServerVerify => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result =
                    process_server_verify(handshake, key_schedule, &mut context.verifier, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ClientCert => {
                let (state, tx) =
                    client_cert(handshake, key_schedule, context.client_cert, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, context.private_key, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    pub fn process_blocking<'v, Transport, CipherSuite, Verifier>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer,
        key_schedule: &mut KeySchedule<CipherSuite>,
        context: &mut TlsContext<'_, Verifier>,
    ) -> Result<State, TlsError>
    where
        Transport: BlockingRead + BlockingWrite + 'a,
        CipherSuite: TlsCipherSuite,
        Verifier: TlsVerifier<CipherSuite>,
    {
        match self {
            State::ClientHello => {
                let (state, tx) = client_hello(key_schedule, context.config, tx_buf, handshake)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ServerVerify => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result =
                    process_server_verify(handshake, key_schedule, &mut context.verifier, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ClientCert => {
                let (state, tx) =
                    client_cert(handshake, key_schedule, context.client_cert, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, context.private_key, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}

fn handle_processing_error_blocking<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond_blocking(tx, transport, key_schedule)?;
    }

    result
}

fn respond_blocking<CipherSuite>(
    tx: &[u8],
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport.flush().map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

async fn handle_processing_error<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer<'_>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond(tx, transport, key_schedule).await?;
    }

    result
}

async fn respond<CipherSuite>(
    tx: &[u8],
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport
        .flush()
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

fn client_hello<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    config: &crate::config::TlsConfig,
    tx_buf: &'r mut WriteBuffer,
    handshake: &mut Handshake<CipherSuite>,
) -> Result<(State, &'r [u8]), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
    handshake.psk_identities = config.psk.as_ref().map_or(0, |p| p.1.len());
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
    let client_hello = ClientRecord::client_hello(config)?;
    let slice = tx_buf.write_record(&client_hello, write_key_schedule, Some(read_key_schedule))?;

    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) = client_hello {
        handshake.secret.replace(client_hello.secret);
        #[cfg(feature = "mlkem")]
        handshake.kem.replace(client_hello.kem);
        Ok((State::ServerHello, slice))
    } else {
        Err(TlsError::EncodeError)
    }
}

fn process_server_hello<CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    match record {
        ServerRecord::Handshake(server_handshake) => match server_handshake {
            ServerHandshake::ServerHello(server_hello) => {
                trace!("********* ServerHello");
                let secret = handshake.secret.take().ok_or(TlsError::InvalidHandshake)?;
                #[cfg(feature = "mlkem")]
                let kem = handshake.kem.take().ok_or(TlsError::InvalidHandshake)?;
                let shared = server_hello
                    .calculate_shared_secret(
                        &secret,
                        #[cfg(feature = "mlkem")]
                        &kem,
                    )
                    .ok_or(TlsError::InvalidKeyShare)?;
                if let Some(selected) = server_hello.selected_psk_identity() {
                    // (RFC 8446, Section 4.2.11)
                    //
                    // The selected identity must be one the client offered.
                    if usize::from(selected) >= handshake.psk_identities {
                        return Err(TlsError::InvalidHandshake);
                    }
                    handshake.server_auth = ServerAuth::Psk;
                }
                key_schedule.initialize_handshake_secret(&shared)?;
                Ok(State::ServerVerify)
            }
            _ => Err(TlsError::InvalidHandshake),
        },
        ServerRecord::Alert(alert) => {
            Err(TlsError::HandshakeAborted(alert.level, alert.description))
        }
        _ => Err(TlsError::InvalidRecord),
    }
}

fn process_server_verify<CipherSuite, Verifier>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    verifier: &mut Verifier,
    record: ServerRecord<'_, CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
    Verifier: TlsVerifier<CipherSuite>,
{
    let mut state = State::ServerVerify;
    decrypt_record(key_schedule.read_state(), record, |key_schedule, record| {
        match record {
            ServerRecord::Handshake(server_handshake) => {
                match server_handshake {
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(certificate) => {
                        if handshake.server_auth != ServerAuth::None {
                            return Err(TlsError::InvalidHandshake);
                        }
                        let transcript = key_schedule.transcript_hash();
                        verifier.verify_certificate(transcript, certificate)?;
                        handshake.server_auth = ServerAuth::Certificate;
                        debug!("Certificate verified!");
                    }
                    ServerHandshake::CertificateVerify(verify) => {
                        if handshake.server_auth != ServerAuth::Certificate {
                            return Err(TlsError::InvalidHandshake);
                        }
                        verifier.verify_signature(verify)?;
                        handshake.server_auth = ServerAuth::Signed;
                        debug!("Signature verified!");
                    }
                    ServerHandshake::CertificateRequest(request) => {
                        handshake.certificate_request.replace(request.try_into()?);
                    }
                    ServerHandshake::Finished(finished) => {
                        if !matches!(handshake.server_auth, ServerAuth::Signed | ServerAuth::Psk) {
                            warn!("Finished before the server authenticated");
                            return Err(TlsError::InvalidHandshake);
                        }
                        if !key_schedule.verify_server_finished(&finished)? {
                            warn!("Server signature verification failed");
                            return Err(TlsError::InvalidSignature);
                        }

                        // trace!("server verified {}", verified);
                        state = if handshake.certificate_request.is_some() {
                            State::ClientCert
                        } else {
                            handshake
                                .traffic_hash
                                .replace(key_schedule.transcript_hash().clone());
                            State::ClientFinished
                        };
                    }
                    _ => return Err(TlsError::InvalidHandshake),
                }
            }
            ServerRecord::ChangeCipherSpec(_) => {}
            _ => return Err(TlsError::InvalidRecord),
        }

        Ok(())
    })?;
    Ok(state)
}

fn client_cert<'r, CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    client_cert: Option<Certificate<&[u8]>>,
    buffer: &'r mut WriteBuffer,
) -> Result<(State, &'r [u8]), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    handshake
        .traffic_hash
        .replace(key_schedule.transcript_hash().clone());

    let request_context = &handshake
        .certificate_request
        .as_ref()
        .ok_or(TlsError::InvalidHandshake)?
        .request_context;

    let mut certificate = CertificateRef::with_context(request_context);
    let next_state = if let Some(ref cert) = client_cert {
        certificate.add(cert.into())?;
        State::ClientCertVerify
    } else {
        State::ClientFinished
    };
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(
            &ClientRecord::Handshake(ClientHandshake::ClientCert(certificate), true),
            write_key_schedule,
            Some(read_key_schedule),
        )
        .map(|slice| (next_state, slice))
}

fn client_cert_verify<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    private_key: Option<&PrivateKey>,
    buffer: &'r mut WriteBuffer,
) -> Result<(Result<State, TlsError>, &'r [u8]), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let signed = private_key
        .ok_or(TlsError::InvalidPrivateKey)
        .and_then(|key| {
            let msg = certificate_verify_message(
                b"TLS 1.3, client CertificateVerify\x00",
                key_schedule.transcript_hash().clone().finalize().as_ref(),
            )?;

            let mut signature = heapless::Vec::new();
            key.sign(&msg, &mut signature)?;

            trace!("Signature: {:?} ({})", signature, signature.len());

            Ok(CertificateVerify {
                signature_scheme: key.signature_scheme(),
                signature,
            })
        });

    let (result, record) = match signed {
        Ok(certificate_verify) => (
            Ok(State::ClientFinished),
            ClientRecord::Handshake(ClientHandshake::ClientCertVerify(certificate_verify), true),
        ),
        Err(e) => {
            error!("Failed to sign CertificateVerify: {:?}", e);
            (
                Err(e),
                ClientRecord::Alert(
                    Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                    true,
                ),
            )
        }
    };

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(&record, write_key_schedule, Some(read_key_schedule))
        .map(|slice| (result, slice))
}

fn client_finished<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    buffer: &'r mut WriteBuffer,
) -> Result<&'r [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_finished = key_schedule
        .create_client_finished()
        .map_err(|_| TlsError::InvalidHandshake)?;

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer.write_record(
        &ClientRecord::Handshake(ClientHandshake::Finished(client_finished), true),
        write_key_schedule,
        Some(read_key_schedule),
    )
}

fn client_finished_finalize<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    handshake: &mut Handshake<CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.replace_transcript_hash(
        handshake
            .traffic_hash
            .take()
            .ok_or(TlsError::InvalidHandshake)?,
    );
    key_schedule.initialize_master_secret()?;

    Ok(State::ApplicationData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignatureScheme;
    use crate::config::{Aes128GcmSha256, CertificateVerifyRef, NoVerify};
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    use crate::handshake::server_hello::ServerHello;

    type Suite = Aes128GcmSha256;

    /// The client's state after a `ServerHello` from a peer that chose its own key share, so the
    /// peer knows the handshake secret.
    fn after_server_hello() -> (Handshake<Suite>, KeySchedule<Suite>) {
        let mut key_schedule = KeySchedule::new();
        key_schedule.initialize_early_secret(None).unwrap();
        key_schedule.initialize_handshake_secret(&[7; 32]).unwrap();
        (Handshake::new(), key_schedule)
    }

    fn finished(key_schedule: &mut KeySchedule<Suite>) -> ServerRecord<'static, Suite> {
        let finished = key_schedule.read_state().server_finished().unwrap();
        assert!(
            key_schedule
                .read_state()
                .verify_server_finished(&finished)
                .unwrap()
        );
        ServerRecord::Handshake(ServerHandshake::Finished(finished))
    }

    fn certificate() -> ServerRecord<'static, Suite> {
        ServerRecord::Handshake(ServerHandshake::Certificate(CertificateRef::with_context(
            &[],
        )))
    }

    /// A `CertificateVerify` with a made-up signature. `NoVerify` accepts any signature, so the
    /// tests that use it check only the order of the messages.
    fn certificate_verify() -> ServerRecord<'static, Suite> {
        ServerRecord::Handshake(ServerHandshake::CertificateVerify(CertificateVerifyRef {
            signature_scheme: SignatureScheme::EcdsaSecp256r1Sha256,
            signature: &[1; 64],
        }))
    }

    #[test]
    fn finished_without_a_certificate_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let record = finished(&mut key_schedule);
        let result =
            process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn certificate_then_certificate_verify_then_finished_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        for record in [certificate(), certificate_verify()] {
            let result =
                process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
            assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        }
        let record = finished(&mut key_schedule);
        let result =
            process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn a_certificate_after_a_selected_psk_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Psk;
        let result = process_server_verify(
            &mut handshake,
            &mut key_schedule,
            &mut NoVerify,
            certificate(),
        );
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn finished_after_a_verified_signature_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Signed;
        let record = finished(&mut key_schedule);
        let result =
            process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn finished_after_a_selected_psk_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Psk;
        let record = finished(&mut key_schedule);
        let result =
            process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn finished_after_a_certificate_without_its_signature_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Certificate;
        let record = finished(&mut key_schedule);
        let result =
            process_server_verify(&mut handshake, &mut key_schedule, &mut NoVerify, record);
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn certificate_verify_after_a_certificate_authenticates_the_server() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Certificate;
        let result = process_server_verify(
            &mut handshake,
            &mut key_schedule,
            &mut NoVerify,
            certificate_verify(),
        );
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::Signed);
    }

    /// A `ServerHello` with a P-256 key share from a fresh key, and with a `pre_shared_key`
    /// extension that selects the identity `psk` when it is set.
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn server_hello(psk: Option<u16>) -> std::vec::Vec<u8> {
        let key = SecretKey::generate()
            .unwrap()
            .public_key()
            .unwrap()
            .to_sec1();
        let mut extensions = std::vec::Vec::new();
        extensions.extend_from_slice(&[0x00, 0x33]);
        extensions.extend_from_slice(&(4 + key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x17]);
        extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key);
        if let Some(identity) = psk {
            extensions.extend_from_slice(&[0x00, 0x29, 0x00, 0x02]);
            extensions.extend_from_slice(&identity.to_be_bytes());
        }
        let mut hello = std::vec![0x03, 0x03];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        hello
    }

    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn process_hello(handshake: &mut Handshake<Suite>, bytes: &[u8]) -> Result<State, TlsError> {
        handshake.secret = Some(SecretKey::generate().unwrap());
        let hello = ServerHello::parse(&mut ParseBuffer::new(bytes)).unwrap();
        let mut key_schedule = KeySchedule::new();
        key_schedule.initialize_early_secret(None).unwrap();
        process_server_hello(
            handshake,
            &mut key_schedule,
            ServerRecord::Handshake(ServerHandshake::ServerHello(hello)),
        )
    }

    #[test]
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn a_selected_psk_that_was_not_offered_is_refused() {
        let mut handshake = Handshake::new();
        let result = process_hello(&mut handshake, &server_hello(Some(0)));
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn a_selected_psk_identity_past_the_offered_ones_is_refused() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 1;
        let result = process_hello(&mut handshake, &server_hello(Some(1)));
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn a_selected_psk_that_was_offered_authenticates_the_server() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 2;
        let result = process_hello(&mut handshake, &server_hello(Some(1)));
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::Psk);
    }

    #[test]
    #[cfg(not(any(feature = "x25519", feature = "mlkem")))]
    fn a_hello_without_a_psk_leaves_the_server_unauthenticated() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 1;
        let result = process_hello(&mut handshake, &server_hello(None));
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    #[test]
    fn certificate_verify_without_a_certificate_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = process_server_verify(
            &mut handshake,
            &mut key_schedule,
            &mut NoVerify,
            certificate_verify(),
        );
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }
}
