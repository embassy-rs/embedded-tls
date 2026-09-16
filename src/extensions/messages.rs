use crate::extensions::{
    extension_data::{
        alpn::AlpnProtocolNameList,
        key_share::{KeyShareClientHello, KeyShareServerHello},
        max_fragment_length::MaxFragmentLength,
        pre_shared_key::{PreSharedKeyClientHello, PreSharedKeyServerHello},
        psk_key_exchange_modes::PskKeyExchangeModes,
        server_name::{ServerNameList, ServerNameResponse},
        signature_algorithms::SignatureAlgorithms,
        signature_algorithms_cert::SignatureAlgorithmsCert,
        supported_groups::SupportedGroups,
        supported_versions::{SupportedVersionsClientHello, SupportedVersionsServerHello},
        unimplemented::Unimplemented,
    },
    extension_group_macro::extension_group,
};

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CH
extension_group! {
    pub enum ClientHelloExtension<'a> {
        ServerName(ServerNameList<'a, 1>),
        SupportedVersions(SupportedVersionsClientHello<4>),
        SignatureAlgorithms(SignatureAlgorithms<25>),
        SupportedGroups(SupportedGroups<13>),
        KeyShare(KeyShareClientHello<'a, 4>),
        PreSharedKey(PreSharedKeyClientHello<'a, 4>),
        PskKeyExchangeModes(PskKeyExchangeModes<4>),
        SignatureAlgorithmsCert(SignatureAlgorithmsCert<25>),
        MaxFragmentLength(MaxFragmentLength),
        StatusRequest(Unimplemented<'a>),
        UseSrtp(Unimplemented<'a>),
        Heartbeat(Unimplemented<'a>),
        ApplicationLayerProtocolNegotiation(AlpnProtocolNameList<'a>),
        SignedCertificateTimestamp(Unimplemented<'a>),
        ClientCertificateType(Unimplemented<'a>),
        ServerCertificateType(Unimplemented<'a>),
        Padding(Unimplemented<'a>),
        EarlyData(Unimplemented<'a>),
        Cookie(Unimplemented<'a>),
        CertificateAuthorities(Unimplemented<'a>),
        OidFilters(Unimplemented<'a>),
        PostHandshakeAuth(Unimplemented<'a>),
        CompressCertificate(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with SH
extension_group! {
    pub enum ServerHelloExtension<'a> {
        KeyShare(KeyShareServerHello<'a>),
        PreSharedKey(PreSharedKeyServerHello),
        Cookie(Unimplemented<'a>), // temporary so we don't trip up on HelloRetryRequests
        SupportedVersions(SupportedVersionsServerHello)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with EE
extension_group! {
    pub enum EncryptedExtensionsExtension<'a> {
        ServerName(ServerNameResponse),
        MaxFragmentLength(MaxFragmentLength),
        SupportedGroups(SupportedGroups<13>),
        UseSrtp(Unimplemented<'a>),
        Heartbeat(Unimplemented<'a>),
        ApplicationLayerProtocolNegotiation(AlpnProtocolNameList<'a>),
        ClientCertificateType(Unimplemented<'a>),
        ServerCertificateType(Unimplemented<'a>),
        EarlyData(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CR
extension_group! {
    pub enum CertificateRequestExtension<'a> {
        StatusRequest(Unimplemented<'a>),
        SignatureAlgorithms(SignatureAlgorithms<25>),
        SignedCertificateTimestamp(Unimplemented<'a>),
        CertificateAuthorities(Unimplemented<'a>),
        OidFilters(Unimplemented<'a>),
        SignatureAlgorithmsCert(Unimplemented<'a>),
        CompressCertificate(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CT
extension_group! {
    pub enum CertificateExtension<'a> {
        StatusRequest(Unimplemented<'a>),
        SignedCertificateTimestamp(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with NST
extension_group! {
    pub enum NewSessionTicketExtension<'a> {
        EarlyData(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with HRR
extension_group! {
    pub enum HelloRetryRequestExtension<'a> {
        KeyShare(Unimplemented<'a>),
        Cookie(Unimplemented<'a>),
        SupportedVersions(Unimplemented<'a>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::AlertDescription;
    use crate::parse_buffer::ParseBuffer;

    #[test]
    fn then_illegal_extension_in_server_hello_aborts() {
        // Vector length 0x0004, extension type 0x0000 (server_name), data
        // length 0x0000. RFC 8446 4.2 forbids server_name in a ServerHello.
        let bytes = [0x00u8, 0x04, 0x00, 0x00, 0x00, 0x00];
        let mut buf = ParseBuffer::new(&bytes);

        let result = ServerHelloExtension::parse_vector::<8>(&mut buf);

        assert!(matches!(
            result,
            Err(crate::TlsError::AbortHandshake(
                _,
                AlertDescription::IllegalParameter
            ))
        ));
    }

    #[test]
    fn then_compress_certificate_in_client_hello_is_accepted() {
        // Extension type 27 (compress_certificate), as sent by curl and Chrome.
        let bytes = [0x00u8, 0x06, 0x00, 0x1b, 0x00, 0x02, 0x00, 0x02];
        let mut buf = ParseBuffer::new(&bytes);

        let result = ClientHelloExtension::parse_vector::<8>(&mut buf);

        assert!(result.is_ok());
    }
}
