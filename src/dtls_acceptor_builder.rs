use crate::{DtlsAcceptor, AcceptorIdentity, Protocol, Result, SrtpProfile};

/// A builder for `DtlsAcceptor`s.
/// With this builder you can configure the following DTLS properties:
/// - The identity to be used for authentication (certificate or PSK)
/// - Adding and enabling the the DTLS extension 'use_srtp'
/// - Configuring min/max supported DTLS versions
/// - Adding custom cipher suites
pub struct DtlsAcceptorBuilder {
    pub(crate) identity: AcceptorIdentity,
    pub(crate) srtp_profiles: Vec<SrtpProfile>,
    pub(crate) min_protocol: Option<Protocol>,
    pub(crate) max_protocol: Option<Protocol>,
    pub(crate) cipher_list: Vec<String>,
    pub(crate) psk_identity_hint: Option<String>,
}

impl DtlsAcceptorBuilder {
    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Dtlsv10)`.
    ///
    /// # Underlying SSL
    /// This will be used for setting the ssl options witch corresponds to [`SSL_CTX_set_options`].
    ///
    /// [`SSL_CTX_set_options`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut DtlsAcceptorBuilder {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    ///
    /// # Underlying SSL
    /// This will be used for setting the ssl options witch corresponds to [`SSL_CTX_set_options`].
    ///
    /// [`SSL_CTX_set_options`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut DtlsAcceptorBuilder {
        self.max_protocol = protocol;
        self
    }

    /// Enables the DTLS extension "use_srtp" as defined in RFC5764.
    ///
    /// This corresponds to [`SSL_CTX_set_tlsext_use_srtp`].
    ///
    /// [`SSL_CTX_set_tlsext_use_srtp`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn add_srtp_profile(&mut self, profile: SrtpProfile) -> &mut DtlsAcceptorBuilder {
        self.srtp_profiles.push(profile);
        self
    }

    /// Adds a cipher name to the list of allowed ciphers.
    ///
    /// This is required for PSK cipher suites (e.g. "PSK-AES128-CBC-SHA", "PSK-AES256-CBC-SHA").
    pub fn add_cipher<C: Into<String>>(&mut self, cipher: C) -> &mut DtlsAcceptorBuilder {
        self.cipher_list.push(cipher.into());
        self
    }

    /// Sets the PSK identity hint to be sent to the client during the handshake.
    ///
    /// When set, OpenSSL will send a `ServerKeyExchange` message containing this hint,
    /// which helps the client select the correct PSK.
    ///
    /// This corresponds to [`SSL_CTX_use_psk_identity_hint`].
    ///
    /// [`SSL_CTX_use_psk_identity_hint`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_use_psk_identity_hint.html
    pub fn psk_identity_hint<S: Into<String>>(&mut self, hint: S) -> &mut DtlsAcceptorBuilder {
        self.psk_identity_hint = Some(hint.into());
        self
    }

    /// Creates a new `DtlsAcceptor` with the settings from this builder.
    pub fn build(&self) -> Result<DtlsAcceptor> {
        Ok(DtlsAcceptor::new(self)?)
    }
}
