use core::marker::PhantomData;

use embassy_crypto::rng_fill_bytes;
use heapless::Vec;

#[cfg(not(feature = "x25519"))]
use embassy_crypto::p256::SecretKey;
#[cfg(feature = "x25519")]
use embassy_crypto::x25519::SecretKey;
#[cfg(all(feature = "mlkem"))]
use ml_kem::{DecapsulationKey, FromSeed, KeyExport, MlKem768};

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::crypto::{ByteArray, TlsHash};
use crate::extensions::extension_data::alpn::AlpnProtocolNameList;
use crate::extensions::extension_data::key_share::{KeyShareClientHello, KeyShareEntry};
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyClientHello;
use crate::extensions::extension_data::psk_key_exchange_modes::{
    PskKeyExchangeMode, PskKeyExchangeModes,
};
use crate::extensions::extension_data::server_name::ServerNameList;
use crate::extensions::extension_data::signature_algorithms::SignatureAlgorithms;
use crate::extensions::extension_data::supported_groups::{NamedGroup, SupportedGroups};
use crate::extensions::extension_data::supported_versions::{SupportedVersionsClientHello, TLS13};
use crate::extensions::messages::ClientHelloExtension;
use crate::handshake::{LEGACY_VERSION, Random};
use crate::key_schedule::{HashOutput, WriteKeySchedule};

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: SecretKey,
    #[cfg(feature = "mlkem")]
    pub(crate) kem: DecapsulationKey<MlKem768>,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'config TlsConfig<'config>) -> Result<Self, TlsError> {
        // RFC 9846, section 9.2: a ClientHello without a pre-shared key must offer signature
        // schemes, and a server that receives one without either aborts the handshake.
        if config.signature_schemes.is_empty() && config.psk.is_none() {
            return Err(TlsError::MissingPsk);
        }

        let mut random = [0; 32];
        rng_fill_bytes(&mut random);

        let secret = SecretKey::generate().map_err(|_| TlsError::CryptoError)?;

        #[cfg(feature = "mlkem")]
        let mut kem_seed = [0; 64];
        #[cfg(feature = "mlkem")]
        rng_fill_bytes(&mut kem_seed);
        #[cfg(feature = "mlkem")]
        let kem = MlKem768::from_seed(&kem_seed.into()).0;

        Ok(Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret,
            #[cfg(feature = "mlkem")]
            kem,
        })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.random)
            .map_err(|_| TlsError::EncodeError)?;

        // session id (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // cipher suites (2+)
        buf.push_u16(2).map_err(|_| TlsError::EncodeError)?;
        buf.push_u16(CipherSuite::CODE_POINT)
            .map_err(|_| TlsError::EncodeError)?;

        // compression methods, 1 byte of 0
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions (1+)
        buf.with_u16_length(|buf| {
            // Section 4.2.1.  Supported Versions
            // Implementations of this specification MUST send this extension in the
            // ClientHello containing all versions of TLS which they are prepared to
            // negotiate
            ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            })
            .encode(buf)?;

            // RFC 9846, section 4.3.3: only a client that wants a certificate sends this, and an
            // empty list is malformed. A build without signature features is PSK-only.
            if !self.config.signature_schemes.is_empty() {
                ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                    supported_signature_algorithms: self.config.signature_schemes.clone(),
                })
                .encode(buf)?;
            }

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientHelloExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientHelloExtension::SupportedGroups(SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            })
            .encode(buf)?;

            ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            })
            .encode(buf)?;

            self.encode_key_share(buf)?;

            // The verifier still checks an IP address against the certificate.
            let host_name = self.config.server_name.filter(|name| !is_ip_address(name));
            if let Some(server_name) = host_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                let mut protos = Vec::new();
                for p in alpn_protocols {
                    // Surfacing the overflow matters: silently dropping the
                    // extras would negotiate against a list the caller never
                    // asked for.
                    protos.push(*p).map_err(|_| TlsError::OutOfMemory)?;
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: protos,
                })
                .encode(buf)?;
            }

            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            if let Some((_, identities)) = &self.config.psk {
                ClientHelloExtension::PreSharedKey(PreSharedKeyClientHello {
                    identities: identities.clone(),
                    hash_size: HashOutput::<CipherSuite>::LEN,
                })
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }

    fn encode_key_share(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        #[cfg(not(feature = "x25519"))]
        let public_key = self
            .secret
            .public_key()
            .map_err(|_| TlsError::CryptoError)?
            .to_sec1();
        #[cfg(feature = "x25519")]
        let public_key = self
            .secret
            .public_key()
            .map_err(|_| TlsError::CryptoError)?
            .to_bytes();

        // concat(pubkey + ek) for SecP256r1MlKem768 (65+1184 = 1249 bytes)
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        let mut hybrid: Vec<u8, 1249> = Vec::new();
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        hybrid.extend_from_slice(&public_key).unwrap();
        #[cfg(all(not(feature = "x25519"), feature = "mlkem"))]
        hybrid.extend(self.kem.encapsulation_key().to_bytes());

        // concat(ek + pubkey) for x25519MlKem768 (1184+32 = 1216 bytes)
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        let mut hybrid: Vec<u8, 1216> = Vec::new();
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        hybrid.extend(self.kem.encapsulation_key().to_bytes());
        #[cfg(all(feature = "x25519", feature = "mlkem"))]
        hybrid.extend_from_slice(&public_key).unwrap();

        ClientHelloExtension::KeyShare(KeyShareClientHello {
            client_shares: Vec::from_slice(&[
                #[cfg(not(feature = "x25519"))]
                KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: &public_key,
                },
                #[cfg(all(feature = "mlkem", not(feature = "x25519")))]
                KeyShareEntry {
                    group: NamedGroup::SecP256r1MLKEM768,
                    opaque: &hybrid,
                },
                #[cfg(feature = "x25519")]
                KeyShareEntry {
                    group: NamedGroup::X25519,
                    opaque: &public_key,
                },
                #[cfg(all(feature = "mlkem", feature = "x25519"))]
                KeyShareEntry {
                    group: NamedGroup::X25519MLKEM768,
                    opaque: &hybrid,
                },
            ])
            .unwrap(),
        })
        .encode(buf)
    }

    pub fn finalize(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        // Special case for PSK which needs to:
        //
        // 1. Add the client hello without the binders to the transcript
        // 2. Create the binders for each identity using the transcript
        // 3. Add the rest of the client hello.
        //
        // This causes a few issues since lengths must be correctly inside the payload,
        // but won't actually be added to the record buffer until the end.
        if let Some((_, identities)) = &self.config.psk {
            let binders_len = identities.len() * (1 + HashOutput::<CipherSuite>::LEN);

            let binders_pos = enc_buf.len() - binders_len;

            // NOTE: Exclude the binders_len itself from the digest
            transcript.update(&enc_buf[0..binders_pos - 2]);

            // Append after the client hello data. Sizes have already been set.
            let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
            // Create a binder and encode for each identity
            for _id in identities {
                let binder = write_key_schedule.create_psk_binder(transcript)?;
                binder.encode(&mut buf)?;
            }

            transcript.update(&enc_buf[binders_pos - 2..]);
        } else {
            transcript.update(enc_buf);
        }

        Ok(())
    }
}

/// Whether `name` is an IP address, which RFC 6066 section 3 keeps out of SNI. A DNS name has
/// no `:`, and its last label is never all digits (RFC 3696, section 2), so this does not link
/// an address parser. The verifier parses the name in full.
fn is_ip_address(name: &str) -> bool {
    name.contains(':') || name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use crate::extensions::ExtensionType;
    use crate::extensions::extension_data::signature_algorithms::SignatureScheme;

    /// The extension types in the `ClientHello` that `config` produces, in order.
    fn extension_types(config: &TlsConfig) -> std::vec::Vec<u16> {
        let hello = ClientHello::<Aes128GcmSha256>::new(config).unwrap();
        let mut bytes = [0; 4096];
        let mut buf = CryptoBuffer::wrap(&mut bytes);
        hello.encode(&mut buf).unwrap();
        // The version, random, empty session ID, one cipher suite, one compression method and
        // the extensions' length come first.
        let mut extensions = &buf.as_slice()[2 + 32 + 1 + 4 + 2 + 2..];
        let mut types = std::vec::Vec::new();
        while let [high, low, len_high, len_low, rest @ ..] = extensions {
            types.push(u16::from_be_bytes([*high, *low]));
            extensions = &rest[usize::from(u16::from_be_bytes([*len_high, *len_low]))..];
        }
        types
    }

    #[test]
    fn signature_algorithms_is_left_out_when_no_scheme_is_enabled() {
        let mut config = TlsConfig::new().with_psk(&[0; 32], &[b"client"]);
        config.signature_schemes.clear();
        assert!(!extension_types(&config).contains(&(ExtensionType::SignatureAlgorithms as u16)));
    }

    // RFC 9846, section 9.2: a ClientHello without a pre-shared key must offer signature schemes.
    #[test]
    fn client_hello_without_a_scheme_or_a_pre_shared_key_is_refused() {
        let mut config = TlsConfig::new();
        config.signature_schemes.clear();
        assert!(matches!(
            ClientHello::<Aes128GcmSha256>::new(&config),
            Err(TlsError::MissingPsk)
        ));
    }

    #[test]
    fn signature_algorithms_is_sent_when_a_scheme_is_enabled() {
        let mut config = TlsConfig::new();
        config.signature_schemes.clear();
        config
            .signature_schemes
            .push(SignatureScheme::Ed25519)
            .unwrap();
        assert!(extension_types(&config).contains(&(ExtensionType::SignatureAlgorithms as u16)));
    }

    #[test]
    fn a_dns_server_name_is_sent_as_sni() {
        for name in ["example.com", "123.example.com", "1e100.net"] {
            let config = TlsConfig::new().with_server_name(name);
            assert!(
                extension_types(&config).contains(&(ExtensionType::ServerName as u16)),
                "{name}"
            );
        }
    }

    // RFC 6066, section 3: "Literal IPv4 and IPv6 addresses are not permitted in "HostName"."
    #[test]
    fn an_ip_address_server_name_is_not_sent_as_sni() {
        for name in ["192.0.2.1", "2001:db8::1"] {
            let config = TlsConfig::new().with_server_name(name);
            assert!(
                !extension_types(&config).contains(&(ExtensionType::ServerName as u16)),
                "{name}"
            );
        }
    }

    /// How the verifier reads `name`: `Some(true)` for an IP address, `Some(false)` for a DNS
    /// name, and `None` when it refuses the name.
    #[cfg(feature = "webpki")]
    fn verifier_reads_ip(name: &str) -> Option<bool> {
        match pki_types::ServerName::try_from(name) {
            Ok(pki_types::ServerName::IpAddress(_)) => Some(true),
            Ok(_) => Some(false),
            Err(_) => None,
        }
    }

    #[test]
    fn ip_addresses_and_dns_names_are_told_apart() {
        let cases = [
            ("0.0.0.0", true),
            ("127.0.0.1", true),
            ("192.0.2.1", true),
            ("255.255.255.255", true),
            ("::", true),
            ("::1", true),
            ("fe80::1", true),
            ("2001:db8::1", true),
            ("2001:DB8::1", true),
            ("2001:db8:0:0:0:0:0:1", true),
            ("0000:0000:0000:0000:0000:0000:0000:0001", true),
            ("::ffff:192.0.2.1", true),
            ("64:ff9b::192.0.2.1", true),
            ("::192.0.2.1", true),
            ("::FFFF:192.0.2.1", true),
            ("a", false),
            ("broker", false),
            ("localhost", false),
            ("example.com", false),
            ("EXAMPLE.COM", false),
            ("example.com.", false),
            ("_sip._tcp.example.com", false),
            ("my-host.example", false),
            ("xn--bcher-kva.example", false),
            ("3com.com", false),
            ("1e100.net", false),
            ("123.example.com", false),
            ("192.0.2.1.example.com", false),
            ("1.2.3.4.in-addr.arpa", false),
            ("0x7f.example", false),
        ];
        for (name, ip) in cases {
            assert_eq!(is_ip_address(name), ip, "{name}");
            // Pins how pki-types reads these names, which the sweep below relies on as its oracle.
            #[cfg(feature = "webpki")]
            assert_eq!(verifier_reads_ip(name), Some(ip), "{name}");
        }
    }

    /// Thousands of generated addresses and DNS names, from a fixed seed so a failure repeats.
    /// For every name the verifier accepts, the SNI decision must match how the verifier reads it.
    #[cfg(feature = "webpki")]
    #[test]
    fn the_sni_check_agrees_with_the_verifier_on_generated_names() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::string::{String, ToString};

        /// A xorshift generator.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            /// A DNS label of 1 to 12 characters, digits only when `digits_only` is set.
            fn label(&mut self, digits_only: bool) -> String {
                let alphabet: &[u8] = if digits_only {
                    b"0123456789"
                } else {
                    b"abcdefghijklmnopqrstuvwxyz0123456789-"
                };
                let len = 1 + self.next() % 12;
                let label: String = (0..len)
                    .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize] as char)
                    .collect();
                if label.starts_with('-') || label.ends_with('-') {
                    label.replace('-', "x")
                } else {
                    label
                }
            }
        }

        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        // The names the verifier accepted, per kind, so a kind it refuses entirely is noticed.
        let mut accepted = [0_u32; 6];
        for round in 0..20_000_u32 {
            let bits = (u128::from(rng.next()) << 64) | u128::from(rng.next());
            let kind = (round % 6) as usize;
            let name = match kind {
                0 => Ipv4Addr::from(bits as u32).to_string(),
                1 => Ipv6Addr::from(bits).to_string(),
                2 => {
                    let groups = Ipv6Addr::from(bits).segments();
                    groups.map(|g| std::format!("{g:x}")).join(":")
                }
                3 => {
                    let groups = Ipv6Addr::from(bits).segments();
                    groups.map(|g| std::format!("{g:04X}")).join(":")
                }
                4 => Ipv4Addr::from(bits as u32).to_ipv6_mapped().to_string(),
                _ => {
                    let labels = 1 + bits % 4;
                    let mut name = String::new();
                    for i in 0..labels {
                        let last = i == labels - 1;
                        let digits_only = !last && rng.next().is_multiple_of(2);
                        name += &rng.label(digits_only);
                        if !last {
                            name.push('.');
                        }
                    }
                    name
                }
            };
            let Some(ip) = verifier_reads_ip(&name) else {
                continue;
            };
            assert_eq!(is_ip_address(&name), ip, "{name}");
            accepted[kind] += 1;
        }
        assert!(
            accepted.iter().all(|&n| n > 0),
            "accepted per kind: {accepted:?}"
        );
    }
}
