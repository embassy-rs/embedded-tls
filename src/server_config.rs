//! Server-specific TLS configuration

use crate::config::PrivateKey;

/// Server TLS configuration
pub struct TlsServerConfig<'a> {
    /// Server certificate chain (DER-encoded X.509), leaf first
    pub(crate) cert_chain: &'a [&'a [u8]],
    /// Server name (optional)
    pub(crate) server_name: Option<&'a str>,
    /// ALPN protocols supported by the server, in preference order
    pub(crate) alpn_protocols: Option<&'a [&'a [u8]]>,
}

impl<'a> TlsServerConfig<'a> {
    /// Create a new server configuration with the given certificate chain.
    ///
    /// The cert chain should be DER-encoded X.509 certificates, leaf first.
    #[must_use]
    pub fn new(cert_chain: &'a [&'a [u8]]) -> Self {
        Self {
            cert_chain,
            server_name: None,
            alpn_protocols: None,
        }
    }

    /// Set server name.
    #[must_use]
    pub fn with_server_name(mut self, name: &'a str) -> Self {
        self.server_name = Some(name);
        self
    }

    /// Set ALPN protocols supported by the server, in preference order.
    #[must_use]
    pub fn with_alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn_protocols = Some(protocols);
        self
    }
}

/// Everything needed to accept a connection: the configuration, the key the
/// server signs `CertificateVerify` with, and an optional client-certificate
/// verifier.
///
/// Client certificates are requested only when a verifier is supplied. With no
/// verifier the server does not send `CertificateRequest` and accepts a client
/// that sends no certificate.
pub struct TlsServerContext<'a, Verifier = crate::config::InsecureNoVerify> {
    pub(crate) config: &'a TlsServerConfig<'a>,
    pub(crate) private_key: &'a PrivateKey,
    pub(crate) client_verifier: Option<Verifier>,
}

impl<'a> TlsServerContext<'a, crate::config::InsecureNoVerify> {
    /// Create a server context with no client-certificate authentication.
    #[must_use]
    pub fn new(config: &'a TlsServerConfig<'a>, private_key: &'a PrivateKey) -> Self {
        Self {
            config,
            private_key,
            client_verifier: None,
        }
    }

    /// Attach a client-certificate verifier to this context.
    ///
    /// Client certificates are requested and required during the handshake when
    /// a verifier is attached: a client that sends no certificate is rejected.
    ///
    /// An implementation must validate the chain and its
    /// policy in `verify_certificate` (the transcript passed there is the one
    /// `CertificateVerify` signs), and in `verify_signature` check the
    /// signature over the RFC 8446 section 4.4.3 content with the CLIENT
    /// context string `"TLS 1.3, client CertificateVerify"`.
    /// `set_hostname_verification` is never called by the server. The library
    /// performs no hostname or revocation checking.
    pub fn with_client_verifier<V>(self, verifier: V) -> TlsServerContext<'a, V> {
        TlsServerContext {
            config: self.config,
            private_key: self.private_key,
            client_verifier: Some(verifier),
        }
    }
}
