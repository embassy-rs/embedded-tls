use digest::OutputSizeUser;
use digest::array::{Array, ArraySize};
use digest::typenum::Unsigned;
use hmac::{KeyInit, Mac, SimpleHmac};
use sha2::Digest;

use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{TlsError, config::TlsCipherSuite};

pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;
pub type LabelBufferSize<CipherSuite> = <CipherSuite as TlsCipherSuite>::LabelBufferSize;

pub type IvArray<CipherSuite> = Array<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = Array<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
pub type HashArray<CipherSuite> = Array<u8, HashOutputSize<CipherSuite>>;

type Hkdf<CipherSuite> = hkdf::GenericHkdf<SimpleHmac<<CipherSuite as TlsCipherSuite>::Hash>>;

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    Initialized(Hkdf<CipherSuite>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, secret: Hkdf<CipherSuite>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> Result<&Hkdf<CipherSuite>, TlsError> {
        match self {
            Secret::Initialized(secret) => Ok(secret),
            Secret::Uninitialized => Err(TlsError::InternalError),
        }
    }

    fn make_expanded_hkdf_label<N: ArraySize>(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<Array<u8, N>, TlsError> {
        fn copy_slice(dest: &mut [u8], src: &[u8]) -> usize {
            let len = src.len();
            dest[..len].copy_from_slice(src);
            len
        }

        //info!("make label {:?} {}", label, len);

        let mut hkdf_label = Array::<u8, LabelBufferSize<CipherSuite>>::from_fn(|_| 0);
        let mut i = 0;

        i += copy_slice(&mut hkdf_label[i..], &N::to_u16().to_be_bytes());

        let label_len = 6 + label.len() as u8;
        i += copy_slice(&mut hkdf_label[i..], &label_len.to_be_bytes());
        i += copy_slice(&mut hkdf_label[i..], b"tls13 ");
        i += copy_slice(&mut hkdf_label[i..], label);

        match context_type {
            ContextType::None => {
                i += copy_slice(&mut hkdf_label[i..], &[0]);
            }
            ContextType::Hash(context) => {
                i += copy_slice(&mut hkdf_label[i..], &[context.len() as u8]);
                i += copy_slice(&mut hkdf_label[i..], &context);
            }
        }

        let mut okm = Array::default();
        //info!("label {:x?}", label);
        self.as_ref()?
            .expand(&hkdf_label[..i], &mut okm)
            .map_err(|_| TlsError::CryptoError)?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }
}

pub struct SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashArray<CipherSuite>,
    hkdf: Secret<CipherSuite>,
}

impl<CipherSuite> SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            secret: Array::default(),
            hkdf: Secret::Uninitialized,
        }
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(self.secret.as_ref()), ikm);
        self.hkdf.replace(hkdf);
        self.secret = secret;
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashArray<CipherSuite>, TlsError> {
        self.hkdf
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(label, context_type)
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
    iv: IvArray<CipherSuite>,
}

impl<CipherSuite> KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
            key: KeyArray::<CipherSuite>::default(),
            iv: IvArray::<CipherSuite>::default(),
        }
    }

    #[inline]
    pub fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        Ok(&self.key)
    }

    #[inline]
    pub fn get_iv(&self) -> Result<&IvArray<CipherSuite>, TlsError> {
        Ok(&self.iv)
    }

    pub fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
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
        let traffic_secret =
            Hkdf::<CipherSuite>::from_prk(&secret).map_err(|_| TlsError::InternalError)?;

        self.traffic_secret.replace(traffic_secret);
        self.key = self
            .traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None)?;
        self.iv = self
            .traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None)?;
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
    Hash(HashArray<CipherSuite>),
}

impl<CipherSuite> ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn transcript_hash(hash: &CipherSuite::Hash) -> Self {
        Self::Hash(hash.clone().finalize())
    }

    fn empty_hash() -> Self {
        Self::Hash(
            <CipherSuite::Hash as Digest>::new()
                .chain_update([])
                .finalize(),
        )
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
                transcript_hash: <CipherSuite::Hash as Digest>::new(),
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

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(
            &mut hmac,
            &self.server_state.transcript_hash.clone().finalize(),
        );
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    fn get_nonce(counter: u64, iv: &IvArray<CipherSuite>) -> IvArray<CipherSuite> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter = Self::pad::<CipherSuite::IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        // info!("iv = {:x?}", iv);

        let mut nonce = Array::default();

        for (index, (l, r)) in iv[0..CipherSuite::IvLen::to_usize()]
            .iter()
            .zip(counter.iter())
            .enumerate()
        {
            nonce[index] = l ^ r;
        }

        //debug!("nonce {:x?}", nonce);

        nonce
    }

    fn pad<N: ArraySize>(input: &[u8]) -> Array<u8, N> {
        // info!("padding input = {:x?}", input);
        let mut padded = Array::default();
        for (index, byte) in input.iter().rev().enumerate() {
            /*info!(
                "{} pad {}={:x?}",
                index,
                ((N::to_usize() - index) - 1),
                *byte
            );*/
            padded[(N::to_usize() - index) - 1] = *byte;
        }
        padded
    }

    fn zero() -> HashArray<CipherSuite> {
        Array::default()
    }

    // Initializes the early secrets with a callback for any PSK binders
    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        self.shared.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        );

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state.binder_key.replace(
            Hkdf::<CipherSuite>::from_prk(&binder_key).map_err(|_| TlsError::InternalError)?,
        );
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        self.shared.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        self.shared.initialize(Self::zero().as_slice());

        //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        //info!("Derive keys, hash: {:x?}", context);

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

    pub(crate) fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<PskBinder<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .binder_key
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();
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

    pub(crate) fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<HashOutputSize<CipherSuite>>,
    ) -> Result<bool, TlsError> {
        //info!("verify server finished: {:x?}", finished.verify);
        //self.client_traffic_secret.as_ref().unwrap().expand()
        //info!("size ===> {}", D::OutputSize::to_u16());
        let key = self
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;
        // info!("hmac sign key {:x?}", key);
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::InternalError)?;
        Mac::update(
            &mut hmac,
            finished.hash.as_ref().ok_or_else(|| {
                warn!("No hash in Finished");
                TlsError::InternalError
            })?,
        );
        //let code = hmac.clone().finalize().into_bytes();
        Ok(hmac.verify(&finished.verify).is_ok())
        //info!("verified {:?}", verified);
        //unimplemented!()
    }
}
