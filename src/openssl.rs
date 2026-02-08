use openssl::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslOptions},
};
use std::sync::Once;

use crate::Protocol;

/// Sets protocol version requirements for the given `SslContextBuilder`
///
/// - Clears the options used by the context
/// - Enables the min/max protocol options
pub fn try_set_supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    let no_ssl_mask = SslOptions::NO_SSL_MASK;

    ctx.clear_options(no_ssl_mask);
    let mut options = SslOptions::empty();
    options |= match min {
        None | Some(Protocol::Dtlsv10) => SslOptions::empty(),
        Some(Protocol::Dtlsv12) => SslOptions::NO_DTLSV1,
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };
    options |= match max {
        None | Some(Protocol::Dtlsv12) => SslOptions::empty(),
        Some(Protocol::Dtlsv10) => SslOptions::NO_DTLSV1_2,
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };

    ctx.set_options(options);

    Ok(())
}

pub fn init_trust() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let result = openssl_probe::probe();
        if let Some(path) = result.cert_file {
            if std::env::var("SSL_CERT_FILE").is_err() {
                // SAFETY: This is called once during initialization via `Once`,
                // before any other threads read these variables.
                unsafe { std::env::set_var("SSL_CERT_FILE", &path); }
            }
        }
        if let Some(path) = result.cert_dir.first() {
            // SSL_CERT_DIR env var takes a single directory path
            if std::env::var("SSL_CERT_DIR").is_err() {
                // SAFETY: This is called once during initialization via `Once`,
                // before any other threads read these variables.
                unsafe { std::env::set_var("SSL_CERT_DIR", path); }
            }
        }
    });
}
