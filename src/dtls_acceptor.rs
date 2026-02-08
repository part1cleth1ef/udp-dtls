use crate::openssl::try_set_supported_protocols;
use crate::{DtlsAcceptorBuilder, DtlsStream, HandshakeError, AcceptorIdentity, Protocol, Result};
use log::debug;
use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslMethod};
use std::ffi::CString;
use std::{fmt, io, io::Write, result};

unsafe extern "C" {
    fn SSL_CTX_use_psk_identity_hint(
        ctx: *mut openssl_sys::SSL_CTX,
        identity_hint: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

/// Acceptor for incoming UDP sessions secured with DTLS.
#[derive(Clone)]
pub struct DtlsAcceptor(SslAcceptor);

impl DtlsAcceptor {
    /// Creates a `DtlsAcceptor` with default settings.
    ///
    /// The identity acts as the server's authentication credential.
    pub fn default<I: Into<AcceptorIdentity>>(identity: I) -> Result<DtlsAcceptor> {
        DtlsAcceptor::builder(identity).build()
    }

    /// Creates a acceptor with the settings from the given builder.
    ///
    /// The `DtlsAcceptor` will use the settings from the given builder.
    ///
    /// The following properties will be applied from the builder:
    /// - Sets minimal/maximal protocol version
    /// - Sets srtp profile by enabling the DTLS extension 'use_srtp'
    /// - Sets the certificate and private key (for certificate identity)
    /// - Sets the PSK server callback (for PSK identity)
    /// - Adds the certificates from the identity chain to the certificate chain.
    pub fn new(builder: &DtlsAcceptorBuilder) -> Result<DtlsAcceptor> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;

        if builder.srtp_profiles.len() > 0 {
            let srtp_line = builder
                .srtp_profiles
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");

            acceptor.set_tlsext_use_srtp(&srtp_line)?;
        }

        match &builder.identity {
            AcceptorIdentity::Certificate(identity) => {
                let identity = identity.as_ref();

                if let Some(ref pkey) = identity.pkey {
                    acceptor.set_private_key(pkey)?;
                }
                if let Some(ref cert) = identity.cert {
                    acceptor.set_certificate(cert)?;
                }

                if let Some(ref chain) = identity.ca {
                    for cert in chain.iter().rev() {
                        acceptor.add_extra_chain_cert(cert.to_owned())?;
                    }
                }
            }
            AcceptorIdentity::Psk(psk_identity) => {
                let psk_identity = psk_identity.clone();

                acceptor.set_psk_server_callback(move |_, identity, mut psk| {
                    // Verify client identity matches if provided
                    if let Some(client_identity) = identity {
                        if client_identity != psk_identity.0.as_ref() {
                            debug!("psk_server_callback: client identity mismatch");
                            return Err(ErrorStack::get());
                        }
                    }

                    if let Err(err) = psk.write_all(&psk_identity.1) {
                        debug!("psk_server_callback error (psk): {:?}", err);
                        return Err(ErrorStack::get());
                    }

                    Ok(psk_identity.1.len())
                });

                if let Some(ref hint) = builder.psk_identity_hint {
                    let c_hint = CString::new(hint.as_bytes()).map_err(|e| {
                        debug!("psk_identity_hint contains interior null byte: {:?}", e);
                        ErrorStack::get()
                    })?;
                    unsafe {
                        let ret = SSL_CTX_use_psk_identity_hint(
                            acceptor.as_ptr(),
                            c_hint.as_ptr(),
                        );
                        if ret != 1 {
                            return Err(ErrorStack::get().into());
                        }
                    }
                }
            }
        }

        if !builder.cipher_list.is_empty() {
            acceptor.set_cipher_list(&builder.cipher_list.join(":"))?;
        }

        try_set_supported_protocols(builder.min_protocol, builder.max_protocol, &mut acceptor)?;

        Ok(DtlsAcceptor(acceptor.build()))
    }

    /// Returns a new builder for a `DtlsAcceptor`.
    ///
    /// The identity acts as the server's authentication credential
    /// (certificate + private key, or PSK).
    pub fn builder<I: Into<AcceptorIdentity>>(identity: I) -> DtlsAcceptorBuilder {
        DtlsAcceptorBuilder {
            identity: identity.into(),
            srtp_profiles: vec![],
            min_protocol: Some(Protocol::Dtlsv10),
            max_protocol: None,
            cipher_list: vec![],
            psk_identity_hint: None,
        }
    }

    /// Accepts a new client connection with the provided stream.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn accept<S: fmt::Debug>(
        &self,
        stream: S,
    ) -> result::Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let stream = self.0.accept(stream)?;
        Ok(DtlsStream::from(stream))
    }
}

impl From<SslAcceptor> for DtlsAcceptor {
    fn from(acceptor: SslAcceptor) -> Self {
        DtlsAcceptor(acceptor)
    }
}

impl AsRef<SslAcceptor> for DtlsAcceptor {
    fn as_ref(&self) -> &SslAcceptor {
        &self.0
    }
}
