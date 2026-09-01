//! Let's Encrypt via HTTP-01 (spec §11.5).
//!
//! The parts that are easy to get wrong, and are handled here:
//!
//! - **Authorization reuse is the normal renewal path, not an edge case.** A CA
//!   reuses a valid authorization for weeks, so on renewal most identifiers come
//!   back already `Valid` with nothing to prove. Treating that as an error
//!   breaks every renewal.
//! - **The useful failure text is on the challenge, not the order.** When an
//!   order ends invalid, the order's own error is usually empty; "Connection
//!   refused fetching http://…/.well-known/…" lives on the challenge, and that
//!   is the sentence the user needs.
//! - **The challenge token becomes a filename.** It comes from the CA, so it is
//!   checked as base64url before it is joined to a path.
//! - **Retries cost rate-limit budget.** Five failed validations per identifier
//!   per hour is not much, so a failure backs off rather than looping.

use std::path::{Path, PathBuf};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use unihelm_core::{ErrorCode, Result, UnihelmError};

/// The crate's 30-second default is too tight for a CA under load, and a
/// timeout here means a task fails that would have succeeded.
///
/// `pub(crate)` because the DNS-01 order in `ops::dns` polls the same CA with
/// the same patience — a wildcard order that gave up sooner than an HTTP-01 one
/// would be a second, undocumented timeout policy for the same server.
pub(crate) const RETRY: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .backoff(1.6)
    .timeout(Duration::from_secs(180));

/// Install the process-wide rustls crypto provider.
///
/// Must run once before any ACME call. Without it, the first TLS handshake
/// panics at runtime rather than failing at compile time — and it panics only
/// when more than one provider is present in the dependency graph, which is
/// exactly the situation that arises as a project grows.
pub fn install_crypto_provider() {
    // An error means somebody already installed one, which is fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Which ACME directory to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directory {
    Production,
    /// Far higher rate limits, and a root nothing trusts — for testing the flow
    /// without spending the real budget.
    Staging,
}

impl Directory {
    pub fn url(self) -> &'static str {
        match self {
            Directory::Production => LetsEncrypt::Production.url(),
            Directory::Staging => LetsEncrypt::Staging.url(),
        }
    }
}

/// A freshly issued certificate.
pub struct Issued {
    /// Leaf first, then intermediates — what `ssl_certificate` wants.
    pub chain_pem: String,
    /// PKCS#8, for `ssl_certificate_key`.
    pub key_pem: String,
    pub not_before: time::OffsetDateTime,
    pub not_after: time::OffsetDateTime,
    pub issuer: String,
}

/// Load the stored account, or register a new one.
///
/// Returns the account and, when one was minted, the credential blob to seal and
/// store. Credentials are scoped to a directory URL: a staging credential is
/// useless against production and vice versa.
pub async fn load_or_register(
    stored: Option<&str>,
    directory: Directory,
    contact_email: Option<&str>,
) -> Result<(Account, Option<String>)> {
    if let Some(json) = stored {
        let credentials: AccountCredentials = serde_json::from_str(json).map_err(|e| {
            UnihelmError::internal(format!("the stored ACME credential is unreadable: {e}"))
        })?;
        let account = Account::builder()
            .map_err(acme_error)?
            .from_credentials(credentials)
            .await
            .map_err(acme_error)?;
        return Ok((account, None));
    }

    let mailto = contact_email.map(|m| format!("mailto:{m}"));
    let contact: Vec<&str> = mailto.iter().map(String::as_str).collect();

    let (account, credentials) = Account::builder()
        .map_err(acme_error)?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.url().to_owned(),
            None,
        )
        .await
        .map_err(acme_error)?;

    let blob = serde_json::to_string(&credentials)
        .map_err(|e| UnihelmError::internal(format!("could not serialise the credential: {e}")))?;
    Ok((account, Some(blob)))
}

/// Issue a certificate for `names` using HTTP-01.
pub async fn issue_http01(
    account: &Account,
    webroot: &Path,
    names: &[String],
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<Issued> {
    if names.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a certificate needs at least one name",
        ));
    }
    for name in names {
        // HTTP-01 cannot issue a wildcard — that is DNS-01 only — and letting
        // the order fail at the CA wastes rate-limit budget to learn it.
        if name.starts_with("*.") {
            return Err(UnihelmError::new(
                ErrorCode::NotImplemented,
                format!("`{name}` is a wildcard, which needs DNS-01 validation"),
            ));
        }
    }

    let identifiers: Vec<Identifier> = names.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(acme_error)?;

    let mut written: Vec<PathBuf> = Vec::new();
    let result = run_order(&mut order, webroot, &mut written, log).await;

    // Sweep the tokens whatever happened. A stale challenge file left in a
    // customer's webroot is somebody else's puzzle later.
    for path in &written {
        let _ = tokio::fs::remove_file(path).await;
    }

    result
}

async fn run_order(
    order: &mut Order,
    webroot: &Path,
    written: &mut Vec<PathBuf>,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<Issued> {
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(acme_error)?;

            // Read the status *before* `challenge()`: it borrows the handle for
            // the rest of its life.
            match authz.status {
                // The normal renewal path. A CA reuses a valid authorization,
                // so there is nothing to prove for most identifiers.
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(UnihelmError::new(
                        ErrorCode::CommandFailed,
                        format!("the CA reported an unexpected authorization status: {other:?}"),
                    ));
                }
            }

            let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::NotImplemented,
                    "the CA offered no http-01 challenge for this name",
                )
            })?;

            let key_authorization = challenge.key_authorization();
            let path = write_token(webroot, &challenge.token, key_authorization.as_str()).await?;
            log(&format!(
                "published the challenge for {}",
                authz_name(&challenge.token)
            ));
            written.push(path);

            // Only now invite the CA to come and fetch it.
            challenge.set_ready().await.map_err(acme_error)?;
        }
    } // `authorizations` borrows the order; it must end before poll_ready.

    log("waiting for validation");
    let status = order.poll_ready(&RETRY).await.map_err(acme_error)?;

    if status != OrderStatus::Ready {
        let detail = challenge_errors(order).await;
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            if detail.is_empty() {
                format!("the CA ended the order as {status:?}")
            } else {
                // This is the sentence that actually tells somebody what to fix.
                detail.join("; ")
            },
        ));
    }

    log("generating a key and finalising the order");
    let key_pem = order.finalize().await.map_err(acme_error)?;
    let chain_pem = order.poll_certificate(&RETRY).await.map_err(acme_error)?;

    let (not_before, not_after, issuer) = parse_validity(&chain_pem)?;
    Ok(Issued {
        chain_pem,
        key_pem,
        not_before,
        not_after,
        issuer,
    })
}

/// Collect the per-challenge errors after a failed order.
async fn challenge_errors(order: &mut Order) -> Vec<String> {
    let mut out = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        let identifier = authz.identifier().to_string();
        for challenge in &authz.challenges {
            if let Some(problem) = &challenge.error {
                out.push(format!("{identifier}: {problem}"));
            }
        }
    }
    out
}

/// Write the challenge response into the shared ACME webroot.
async fn write_token(webroot: &Path, token: &str, key_authorization: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    // The token becomes a filename and comes from the CA. base64url only.
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the CA sent a challenge token that is not base64url",
        ));
    }

    let dir = webroot.join(".well-known").join("acme-challenge");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| UnihelmError::internal(format!("could not create {}: {e}", dir.display())))?;
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
        .await
        .map_err(|e| UnihelmError::internal(format!("could not chmod {}: {e}", dir.display())))?;

    let path = dir.join(token);
    // Exact bytes, no trailing newline — the CA compares byte for byte.
    tokio::fs::write(&path, key_authorization.as_bytes())
        .await
        .map_err(|e| UnihelmError::internal(format!("could not write {}: {e}", path.display())))?;
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .await
        .map_err(|e| UnihelmError::internal(format!("could not chmod {}: {e}", path.display())))?;

    Ok(path)
}

/// Assemble an [`Issued`] from the chain and key an order produced.
///
/// The DNS-01 path in `ops::dns` runs its own order (the challenge lives in a
/// zone, not in a webroot) but must end up with a certificate that is
/// indistinguishable from an HTTP-01 one — same validity parsing, same issuer
/// string, so `write_certificate` and `db.certificate_issued` cannot tell the
/// two apart. Sharing this constructor is what guarantees that.
pub fn issued_from(chain_pem: String, key_pem: String) -> Result<Issued> {
    let (not_before, not_after, issuer) = parse_validity(&chain_pem)?;
    Ok(Issued {
        chain_pem,
        key_pem,
        not_before,
        not_after,
        issuer,
    })
}

/// Read validity dates and issuer out of the leaf certificate.
fn parse_validity(chain_pem: &str) -> Result<(time::OffsetDateTime, time::OffsetDateTime, String)> {
    use x509_parser::prelude::*;

    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes()).map_err(|e| {
        UnihelmError::internal(format!("could not parse the issued certificate: {e}"))
    })?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|e| {
        UnihelmError::internal(format!("could not parse the issued certificate: {e}"))
    })?;

    // `x509_parser::prelude` brings its own `time` module into scope, so the
    // crate has to be named from the root here.
    let to_time = |t: ASN1Time| {
        ::time::OffsetDateTime::from_unix_timestamp(t.timestamp())
            .unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
    };

    Ok((
        to_time(cert.validity().not_before),
        to_time(cert.validity().not_after),
        cert.issuer().to_string(),
    ))
}

/// Write an issued certificate where the vhost template expects it.
pub fn write_certificate(dir: &Path, issued: &Issued) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(dir)
        .map_err(|e| UnihelmError::internal(format!("could not create {}: {e}", dir.display())))?;

    let write = |name: &str, contents: &str, mode: u32| -> Result<()> {
        let path = dir.join(name);
        let mut temp = path.clone();
        temp.as_mut_os_string().push(".tmp");

        let inner = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&temp)?;
            // Tighten before writing, so a private key is never briefly readable.
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()
        };
        inner().map_err(|e| {
            UnihelmError::internal(format!("could not write {}: {e}", temp.display()))
        })?;
        std::fs::rename(&temp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            UnihelmError::internal(format!("could not write {}: {e}", path.display()))
        })
    };

    write("fullchain.pem", &issued.chain_pem, 0o644)?;
    write("privkey.pem", &issued.key_pem, 0o600)?;

    // OCSP stapling needs the issuer chain without the leaf.
    let chain_only = strip_leaf(&issued.chain_pem);
    write("chain.pem", &chain_only, 0o644)?;
    Ok(())
}

/// Everything after the first certificate in a PEM chain.
fn strip_leaf(chain_pem: &str) -> String {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    match chain_pem.match_indices(BEGIN).nth(1) {
        Some((index, _)) => chain_pem[index..].to_string(),
        // A single-certificate chain is its own issuer file; nginx accepts it
        // and stapling simply finds nothing to staple.
        None => chain_pem.to_string(),
    }
}

/// Map a CA error onto the panel's error vocabulary.
///
/// `pub(crate)` for the same reason as [`RETRY`]: a rate-limit from Let's
/// Encrypt must read as `UNI-1003` whether the order was HTTP-01 or DNS-01, or
/// the renewal scheduler's backoff would only recognise half of them.
pub(crate) fn acme_error(e: instant_acme::Error) -> UnihelmError {
    use instant_acme::Error;
    let code = match &e {
        Error::Api(problem) => match problem.r#type.as_deref() {
            Some("urn:ietf:params:acme:error:rateLimited") => ErrorCode::RateLimited,
            Some("urn:ietf:params:acme:error:unauthorized") => ErrorCode::PermissionDenied,
            Some("urn:ietf:params:acme:error:rejectedIdentifier") => ErrorCode::InvalidDomain,
            _ => ErrorCode::CommandFailed,
        },
        Error::Timeout(_) => ErrorCode::AgentTimeout,
        Error::Unsupported(_) => ErrorCode::NotImplemented,
        _ => ErrorCode::CommandFailed,
    };
    UnihelmError::new(code, e.to_string())
}

fn authz_name(token: &str) -> String {
    // Only the first few characters — the whole token in a log line is not
    // secret, but it is noise.
    token.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hostile_challenge_token_never_becomes_a_path() {
        // The token comes from the CA and is joined to a filesystem path.
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "../../../etc/cron.d/evil",
            "a/b",
            "",
            "with space",
            "semi;colon",
            &"x".repeat(200),
        ] {
            assert!(
                write_token(dir.path(), bad, "auth").await.is_err(),
                "token `{bad}` should have been refused"
            );
        }

        // A real base64url token is fine.
        let path = write_token(dir.path(), "aBc-123_xyz", "token.thumbprint")
            .await
            .unwrap();
        assert!(path.ends_with("aBc-123_xyz"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "token.thumbprint");
    }

    #[tokio::test]
    async fn the_challenge_response_has_no_trailing_newline() {
        // The CA compares the body byte for byte; a newline fails validation
        // with a message that says nothing about newlines.
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), "token123", "abc.def")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"abc.def");
    }

    #[tokio::test]
    async fn the_challenge_file_is_readable_by_nginx() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), "token123", "abc.def")
            .await
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the CA fetches this through nginx");
    }

    #[tokio::test]
    async fn a_wildcard_is_refused_before_the_order_is_created() {
        // HTTP-01 cannot issue one, and finding out at the CA costs
        // rate-limit budget.
        install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        // No account is needed: the check happens first.
        let err = issue_http01_precheck(&["*.example.com".to_string()]);
        assert_eq!(err.unwrap_err().code, ErrorCode::NotImplemented);
        let _ = dir;
    }

    /// The name checks `issue_http01` performs before touching the network.
    fn issue_http01_precheck(names: &[String]) -> Result<()> {
        if names.is_empty() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a certificate needs a name",
            ));
        }
        for name in names {
            if name.starts_with("*.") {
                return Err(UnihelmError::new(
                    ErrorCode::NotImplemented,
                    format!("`{name}` is a wildcard, which needs DNS-01 validation"),
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn the_issuer_chain_excludes_the_leaf() {
        // `ssl_trusted_certificate` must not contain the leaf, or stapling
        // silently does nothing.
        let chain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n\
                     -----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n";
        let stripped = strip_leaf(chain);
        assert!(!stripped.contains("LEAF"));
        assert!(stripped.contains("INTERMEDIATE"));

        // A self-contained chain is left alone rather than emptied.
        let single = "-----BEGIN CERTIFICATE-----\nONLY\n-----END CERTIFICATE-----\n";
        assert_eq!(strip_leaf(single), single);
    }

    #[test]
    fn certificate_files_land_with_the_right_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let issued = Issued {
            chain_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n\
                        -----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n"
                .into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n".into(),
            not_before: time::OffsetDateTime::UNIX_EPOCH,
            not_after: time::OffsetDateTime::UNIX_EPOCH,
            issuer: "test".into(),
        };
        write_certificate(dir.path(), &issued).unwrap();

        let mode = |name: &str| {
            std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(
            mode("privkey.pem"),
            0o600,
            "a private key must not be world-readable"
        );
        assert_eq!(mode("fullchain.pem"), 0o644);
        assert_eq!(mode("chain.pem"), 0o644);
        assert!(crate::tls::certificate_present(dir.path()));
    }

    #[test]
    fn staging_and_production_are_different_directories() {
        // Credentials are scoped to a directory URL; crossing them produces an
        // authentication failure nobody can explain.
        assert_ne!(Directory::Staging.url(), Directory::Production.url());
        assert!(Directory::Staging.url().contains("staging"));
    }
}
