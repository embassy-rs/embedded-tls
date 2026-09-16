//! Server-specific TLS configuration

use crate::config::PrivateKey;

/// Server TLS configuration
pub struct TlsServerConfig<'a> {
    /// Server certificate chain (DER-encoded X.509), leaf first
    pub(crate) cert_chain: &'a [&'a [u8]],
    /// Server name (optional)
    pub(crate) server_name: Option<&'a str>,
    /// Trust anchor that client certificates must chain to, when mutual TLS
    /// is required. `None` disables client certificate authentication.
    pub(crate) client_auth_ca: Option<&'a [u8]>,
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
            client_auth_ca: None,
            alpn_protocols: None,
        }
    }

    /// Set server name.
    #[must_use]
    pub fn with_server_name(mut self, name: &'a str) -> Self {
        self.server_name = Some(name);
        self
    }

    /// Require client certificate authentication (mTLS).
    ///
    /// `trust_anchor` is the DER-encoded CA certificate that a presented client
    /// certificate must chain to. The handshake is aborted if the client sends
    /// no certificate, sends one that does not chain to `trust_anchor`, or
    /// fails to prove possession of the corresponding private key.
    ///
    /// The trust anchor is required rather than optional so that mutual TLS
    /// cannot be requested without saying who is trusted.
    ///
    /// No hostname matching or revocation checking is performed: a client
    /// certificate carries no hostname the server can meaningfully check, and
    /// revocation needs infrastructure an embedded server does not have.
    #[cfg(feature = "rustpki")]
    #[must_use]
    pub fn with_client_auth(mut self, trust_anchor: &'a [u8]) -> Self {
        self.client_auth_ca = Some(trust_anchor);
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
/// server signs `CertificateVerify` with, and the verifier used to check a
/// client certificate when mutual TLS is configured.
///
/// Pass [`NoVerify`](crate::NoVerify) as the verifier when client certificate
/// authentication is not in use — it is never consulted in that case.
pub struct TlsServerContext<'a, Verifier> {
    pub(crate) config: &'a TlsServerConfig<'a>,
    pub(crate) verifier: Verifier,
    pub(crate) private_key: &'a PrivateKey,
}

impl<'a, Verifier> TlsServerContext<'a, Verifier> {
    /// Create a new server context.
    ///
    /// `private_key` must correspond to the leaf certificate in the
    /// configuration's chain; the server proves possession of it on every
    /// handshake.
    #[must_use]
    pub fn new(
        config: &'a TlsServerConfig<'a>,
        verifier: Verifier,
        private_key: &'a PrivateKey,
    ) -> Self {
        Self {
            config,
            verifier,
            private_key,
        }
    }
}
