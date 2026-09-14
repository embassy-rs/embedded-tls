use core::cmp::Ordering;
use der::asn1::{
    BitStringRef, GeneralizedTime, IntRef, ObjectIdentifier, SequenceOf, SetOf, UtcTime,
};
use der::{
    AnyRef, Choice, Decode, Enumerated, Header, Reader, Sequence, SliceReader, Tag, Tagged,
    ValueOrd,
};
use heapless::Vec;

pub const MAX_SAN_DNS_NAMES: usize = 3;
pub const HOSTNAME_MAXLEN: usize = 64;

const DNS_NAME_TAG: u8 = 0x82;
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const SUBJECT_ALT_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for AlgorithmIdentifier<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "AlgorithmIdentifier:{}", &self.oid.as_bytes())
    }
}

#[cfg(feature = "p256")]
pub const ECDSA_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
    parameters: None,
};
#[cfg(feature = "p384")]
pub const ECDSA_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
    parameters: None,
};
#[cfg(feature = "ed25519")]
pub const ED25519: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
    parameters: None,
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
    parameters: Some(AnyRef::NULL),
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
    parameters: Some(AnyRef::NULL),
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
    parameters: Some(AnyRef::NULL),
};

#[derive(Debug, Clone, PartialEq, Eq, Copy, Enumerated)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,
    /// Version 2
    V2 = 1,
    /// Version 3
    V3 = 2,
}

impl ValueOrd for Version {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

#[derive(Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DecodedCertificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitStringRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    pub oid: ObjectIdentifier,
    pub value: AnyRef<'a>,
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for AttributeTypeAndValue<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Attribute:{} Value:{}",
            &self.oid.as_bytes(),
            &self.value.value()
        )
    }
}

#[derive(Debug, Sequence, ValueOrd)]
pub struct ExtensionIdAndValue<'a> {
    pub extn_id: ObjectIdentifier,
    pub critical: Option<bool>,
    pub extn_value: AnyRef<'a>, // always type OCTET STRING
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for ExtensionIdAndValue<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "extnID:{} extnValue:{} critical:{}",
            &self.extn_id.as_bytes(),
            &self.extn_value.value(),
            &self.critical,
        )
    }
}

#[derive(Debug, Choice, ValueOrd)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Time {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Time::UtcTime(utc_time) => {
                defmt::write!(fmt, "UtcTime:{}", utc_time.to_unix_duration())
            }
            Time::GeneralTime(generalized_time) => {
                defmt::write!(fmt, "GeneralTime:{}", generalized_time.to_unix_duration())
            }
        }
    }
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubjectPublicKeyInfoRef<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub public_key: BitStringRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: IntRef<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,

    pub validity: Validity,
    pub subject: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<SequenceOf<ExtensionIdAndValue<'a>, 12>>,
}

/// Extract CommonName (CN) from the subject.
///
/// Parses the rdnSequence field of a TBS certificate, locates the
/// Common Name (OID 2.5.4.3), and returns it.
///
/// Returns `None` if no common name is present or does not fit into
/// `heapless::String<64>`.
pub fn extract_common_name<'a>(
    tbs: &TbsCertificate<'a>,
) -> Result<Option<heapless::String<64>>, der::Error> {
    let mut common_name = None;

    for elems in tbs.subject.iter() {
        let attrs = elems
            .get(0)
            .ok_or(der::ErrorKind::Value { tag: Tag::Set })?;

        if attrs.oid == COMMON_NAME_OID {
            let mut v: Vec<u8, HOSTNAME_MAXLEN> = Vec::new();
            v.extend_from_slice(attrs.value.value())
                .map_err(|_| der::ErrorKind::Value {
                    tag: Tag::Utf8String,
                })?;

            common_name = heapless::String::from_utf8(v).ok();
        }
    }
    Ok(common_name)
}

/// Extract DNS names from the Subject Alternative Name (SAN) extension.
///
/// Parses the extensions field of a TBS certificate, locates the SAN
/// extension (OID 2.5.29.17), and returns all GeneralName entries of
/// type dNSName (tag [2] IMPLICIT IA5String).
///
/// Returns an empty vector if no SAN extension is present.
pub fn extract_san_dns_names<'a>(
    tbs: &TbsCertificate<'a>,
) -> Result<heapless::Vec<heapless::String<HOSTNAME_MAXLEN>, MAX_SAN_DNS_NAMES>, der::Error> {
    let mut dns_names = heapless::Vec::new();

    let extensions_any = match &tbs.extensions {
        Some(ext) => ext,
        None => return Ok(dns_names),
    };

    for elems in extensions_any.iter() {
        if elems.extn_id != SUBJECT_ALT_NAME_OID {
            continue;
        }

        elems.extn_value.tag().assert_eq(Tag::OctetString)?;
        let mut san_reader = SliceReader::new(elems.extn_value.value())?;
        let san_header = Header::decode(&mut san_reader)?;
        san_header.tag().assert_eq(Tag::Sequence)?;
        let san_content = san_reader.read_slice(san_header.length())?;
        let mut gn_reader = SliceReader::new(san_content)?;
        while !gn_reader.is_finished() {
            let tag_byte = gn_reader.peek_byte().ok_or(der::ErrorKind::Incomplete {
                expected_len: 1u8.into(),
                actual_len: 0u8.into(),
            })?;

            let gn_header = Header::decode(&mut gn_reader)?;
            let gn_value = gn_reader.read_slice(gn_header.length())?;

            if tag_byte == DNS_NAME_TAG {
                // dNSName [2] IMPLICIT IA5String
                let gn_value_str =
                    core::str::from_utf8(gn_value).map_err(|_| der::ErrorKind::Value {
                        tag: Tag::Ia5String,
                    })?;

                let dns_name = heapless::String::try_from(gn_value_str).map_err(|_| {
                    der::ErrorKind::Value {
                        tag: Tag::Ia5String,
                    }
                })?;

                let _ = dns_names.push(dns_name);
                if dns_names.is_full() {
                    break;
                }
            }
        }
    }
    Ok(dns_names)
}
