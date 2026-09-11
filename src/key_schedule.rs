use crate::crypto::{ByteArray, Hkdf, NONCE_LEN, TlsAead, TlsHash, TlsHmac};
use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{TlsError, config::TlsCipherSuite};

pub type HashOutput<CipherSuite> = <<CipherSuite as TlsCipherSuite>::Hash as TlsHash>::Output;
pub type KeyArray<CipherSuite> = <<CipherSuite as TlsCipherSuite>::Cipher as TlsAead>::Key;
pub type IvArray = [u8; NONCE_LEN];

// longest label is 12b -> buf <= 2 + 1 + 6 + longest + 1 + hash_out = hash_out + 22
const LABEL_BUFFER_LEN: usize = 48 + 22;

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    Initialized(Hkdf<CipherSuite::Hash>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, secret: Hkdf<CipherSuite::Hash>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> Result<&Hkdf<CipherSuite::Hash>, TlsError> {
        match self {
            Secret::Initialized(secret) => Ok(secret),
            Secret::Uninitialized => Err(TlsError::InternalError),
        }
    }

    /// `HKDF-Expand-Label(secret, label, context, okm.len())`, as defined in RFC 8446 section 7.1.
    fn expand_label(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
        okm: &mut [u8],
    ) -> Result<(), TlsError> {
        let mut hkdf_label = heapless::Vec::<u8, LABEL_BUFFER_LEN>::new();
        hkdf_label
            .extend_from_slice(&(okm.len() as u16).to_be_bytes())
            .map_err(|_| TlsError::InternalError)?;

        let label_len = 6 + label.len() as u8;
        hkdf_label
            .push(label_len)
            .map_err(|_| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(b"tls13 ")
            .map_err(|_| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(label)
            .map_err(|_| TlsError::InternalError)?;

        match context_type {
            ContextType::None => {
                hkdf_label.push(0).map_err(|_| TlsError::InternalError)?;
            }
            ContextType::Hash(context) => {
                let context = context.as_ref();
                hkdf_label
                    .push(context.len() as u8)
                    .map_err(|_| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(context)
                    .map_err(|_| TlsError::InternalError)?;
            }
        }

        self.as_ref()?
            .expand(&hkdf_label, okm)
            .map_err(|_| TlsError::CryptoError)
    }

    fn expand_label_hash(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashOutput<CipherSuite>, TlsError> {
        let mut out = HashOutput::<CipherSuite>::zeroed();
        self.expand_label(label, context_type, out.as_mut())?;
        Ok(out)
    }
}

pub struct SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashOutput<CipherSuite>,
    hkdf: Secret<CipherSuite>,
}

impl<CipherSuite> SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            secret: HashOutput::<CipherSuite>::zeroed(),
            hkdf: Secret::Uninitialized,
        }
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let hkdf = Hkdf::<CipherSuite::Hash>::extract(self.secret.as_ref(), ikm);
        self.secret = *hkdf.prk();
        self.hkdf.replace(hkdf);
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashOutput<CipherSuite>, TlsError> {
        self.hkdf.expand_label_hash(label, context_type)
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::empty_hash())?;
        Ok(())
    }
}

pub(crate) struct KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_secret: Secret<CipherSuite>,
    counter: u64,
    key: KeyArray<CipherSuite>,
    iv: IvArray,
}

impl<CipherSuite> KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
            key: KeyArray::<CipherSuite>::zeroed(),
            iv: [0; NONCE_LEN],
        }
    }

    #[inline]
    pub fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        Ok(&self.key)
    }

    #[inline]
    pub fn get_iv(&self) -> Result<&IvArray, TlsError> {
        Ok(&self.iv)
    }

    pub fn get_nonce(&self) -> Result<IvArray, TlsError> {
        let iv = self.get_iv()?;
        Ok(KeySchedule::<CipherSuite>::get_nonce(self.counter, iv))
    }

    fn calculate_traffic_secret(
        &mut self,
        label: &[u8],
        shared: &mut SharedState<CipherSuite>,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<(), TlsError> {
        let secret = shared.derive_secret(label, ContextType::transcript_hash(transcript_hash))?;
        let traffic_secret = Hkdf::<CipherSuite::Hash>::from_prk(secret.as_ref())?;

        self.traffic_secret.replace(traffic_secret);
        self.traffic_secret
            .expand_label(b"key", ContextType::None, self.key.as_mut())?;
        self.traffic_secret
            .expand_label(b"iv", ContextType::None, &mut self.iv)?;
        self.counter = 0;
        Ok(())
    }

    pub fn increment_counter(&mut self) {
        self.counter = unwrap!(self.counter.checked_add(1));
    }
}

enum ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    None,
    Hash(HashOutput<CipherSuite>),
}

impl<CipherSuite> ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn transcript_hash(hash: &CipherSuite::Hash) -> Self {
        Self::Hash(hash.clone().finalize())
    }

    fn empty_hash() -> Self {
        Self::Hash(CipherSuite::Hash::new().finalize())
    }
}

pub struct KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    shared: SharedState<CipherSuite>,
    client_state: WriteKeySchedule<CipherSuite>,
    server_state: ReadKeySchedule<CipherSuite>,
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            shared: SharedState::new(),
            client_state: WriteKeySchedule {
                state: KeyScheduleState::new(),
                binder_key: Secret::Uninitialized,
            },
            server_state: ReadKeySchedule {
                state: KeyScheduleState::new(),
                transcript_hash: CipherSuite::Hash::new(),
            },
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.server_state.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: CipherSuite::Hash) {
        self.server_state.transcript_hash = hash;
    }

    pub fn as_split(
        &mut self,
    ) -> (
        &mut WriteKeySchedule<CipherSuite>,
        &mut ReadKeySchedule<CipherSuite>,
    ) {
        (&mut self.client_state, &mut self.server_state)
    }

    pub(crate) fn write_state(&mut self) -> &mut WriteKeySchedule<CipherSuite> {
        &mut self.client_state
    }

    pub(crate) fn read_state(&mut self) -> &mut ReadKeySchedule<CipherSuite> {
        &mut self.server_state
    }

    pub fn create_client_finished(&self) -> Result<Finished<CipherSuite::Hash>, TlsError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .expand_label_hash(b"finished", ContextType::None)?;

        let mut hmac = <CipherSuite::Hash as TlsHash>::Hmac::new(key.as_ref());
        hmac.update(
            self.server_state
                .transcript_hash
                .clone()
                .finalize()
                .as_ref(),
        );
        let verify = hmac.finalize();

        Ok(Finished { verify, hash: None })
    }

    /// The per-record nonce: the IV `XOR`ed with the big-endian record sequence number
    /// (RFC 8446 section 5.3).
    fn get_nonce(counter: u64, iv: &IvArray) -> IvArray {
        let mut nonce = *iv;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter.to_be_bytes()) {
            *n ^= c;
        }
        nonce
    }

    // Initializes the early secrets with a callback for any PSK binders
    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        let zero = HashOutput::<CipherSuite>::zeroed();
        self.shared.initialize(psk.unwrap_or(zero.as_ref()));

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state
            .binder_key
            .replace(Hkdf::<CipherSuite::Hash>::from_prk(binder_key.as_ref())?);
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        self.shared.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        let zero = HashOutput::<CipherSuite>::zeroed();
        self.shared.initialize(zero.as_ref());

        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
        self.shared.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
    ) -> Result<(), TlsError> {
        self.client_state.state.calculate_traffic_secret(
            client_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        self.server_state.state.calculate_traffic_secret(
            server_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        Ok(())
    }
}

impl<CipherSuite> Default for KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn default() -> Self {
        KeySchedule::new()
    }
}

pub struct WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    binder_key: Secret<CipherSuite>,
}
impl<CipherSuite> WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray, TlsError> {
        self.state.get_nonce()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<PskBinder<CipherSuite::Hash>, TlsError> {
        let key = self
            .binder_key
            .expand_label_hash(b"finished", ContextType::None)?;

        let mut hmac = <CipherSuite::Hash as TlsHash>::Hmac::new(key.as_ref());
        hmac.update(transcript_hash.clone().finalize().as_ref());
        let verify = hmac.finalize();
        Ok(PskBinder { verify })
    }
}

pub struct ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    transcript_hash: CipherSuite::Hash,
}

impl<CipherSuite> ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.transcript_hash
    }

    pub(crate) fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray, TlsError> {
        self.state.get_nonce()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<CipherSuite::Hash>,
    ) -> Result<bool, TlsError> {
        let key = self
            .state
            .traffic_secret
            .expand_label_hash(b"finished", ContextType::None)?;

        let mut hmac = <CipherSuite::Hash as TlsHash>::Hmac::new(key.as_ref());
        hmac.update(
            finished
                .hash
                .as_ref()
                .ok_or_else(|| {
                    warn!("No hash in Finished");
                    TlsError::InternalError
                })?
                .as_ref(),
        );
        Ok(hmac.verify(finished.verify.as_ref()))
    }
}
