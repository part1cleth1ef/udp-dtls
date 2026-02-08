use crate::{Certificate, Error};
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};

use bytes::Bytes;

/// A cryptographic identity.
///
/// An identity is an X509 certificate along with its corresponding private key and chain of certificates to a trusted
/// root.
pub struct CertificateIdentity(ParsedPkcs12_2);

impl CertificateIdentity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that should be sent to clients to allow them to build a chain to a trusted
    /// root. The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<CertificateIdentity, Error> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse2(pass)?;
        Ok(CertificateIdentity(parsed))
    }

    /// Returns the X509 certificate from this identity, if present.
    ///
    /// Note: Since `ParsedPkcs12_2` uses `Option<X509>`, this now returns `Option<Certificate>`.
    /// PKCS12 identities used for DTLS will typically always contain a certificate.
    pub fn certificate(&self) -> Option<Certificate> {
        self.0.cert.as_ref().map(|c| Certificate::from(c.clone()))
    }
}

impl From<ParsedPkcs12_2> for CertificateIdentity {
    fn from(pkcs_12: ParsedPkcs12_2) -> Self {
        CertificateIdentity(pkcs_12)
    }
}

impl AsRef<ParsedPkcs12_2> for CertificateIdentity {
    fn as_ref(&self) -> &ParsedPkcs12_2 {
        &self.0
    }
}

/// Identity/key for PSK authentication.
///
/// Used for both client and server PSK-based DTLS connections.
///
/// # Hint
/// You should specify one of the PSK_* ciphers, e.g. PSK-AES128-CBC-SHA or PSK-AES256-CBC-SHA
#[derive(Clone)]
pub struct PskIdentity(pub(crate) Bytes, pub(crate) Bytes);

impl PskIdentity {
    pub fn new(identity: &[u8], key: &[u8]) -> PskIdentity {
        PskIdentity(Bytes::copy_from_slice(identity), Bytes::copy_from_slice(key))
    }
}

/// Possible identities for DTLS connector (client)
pub enum ConnectorIdentity {
    Certificate(CertificateIdentity),
    Psk(PskIdentity),
}

/// Possible identities for DTLS acceptor (server)
pub enum AcceptorIdentity {
    Certificate(CertificateIdentity),
    Psk(PskIdentity),
}

impl From<CertificateIdentity> for AcceptorIdentity {
    fn from(identity: CertificateIdentity) -> Self {
        AcceptorIdentity::Certificate(identity)
    }
}

impl From<PskIdentity> for AcceptorIdentity {
    fn from(identity: PskIdentity) -> Self {
        AcceptorIdentity::Psk(identity)
    }
}
