//! The panel's own certificate.
//!
//! A fresh install has no domain. Requiring one — or an ssh tunnel — before the
//! operator can even see the panel is not a decision to make on their behalf, so
//! the panel terminates TLS itself with a certificate it generates on first
//! start. It is reachable at `https://<the server's address>:8088` the moment
//! the installer finishes.
//!
//! Self-signed means the browser warns once and the operator clicks through.
//! That is the same trade every panel in this category makes, and it is a far
//! better one than the alternative it replaces: plain HTTP, where the password
//! crosses the network in the clear and — because the session cookie is marked
//! `Secure` off loopback — the login silently fails anyway.
//!
//! `unihelm cert panel <domain>` replaces this with a real certificate.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where the generated certificate lives, under the panel's state directory.
pub fn cert_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("panel-tls")
}

/// Load the panel's certificate, generating one if it is not there yet.
///
/// Returns the PEM-encoded chain and key.
pub fn load_or_generate(state_dir: &Path, addresses: &[IpAddr]) -> Result<(Vec<u8>, Vec<u8>)> {
    let dir = cert_dir(state_dir);
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key =
            std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
        return Ok((cert, key));
    }

    let (cert, key) = generate(addresses)?;

    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(&cert_path, &cert)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    std::fs::write(&key_path, &key).with_context(|| format!("writing {}", key_path.display()))?;

    // The key is the panel's identity on the wire; nothing but this process has
    // any business reading it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("locking down {}", key_path.display()))?;
    }

    tracing::info!(path = %cert_path.display(), "generated a self-signed certificate for the panel");
    Ok((cert, key))
}

/// A certificate covering localhost and every address this machine answers on,
/// so it is valid however the operator reaches the panel.
fn generate(addresses: &[IpAddr]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    let mut names = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .context("localhost is a valid name")?,
        ),
        SanType::IpAddress(IpAddr::from([127, 0, 0, 1])),
        SanType::IpAddress("::1".parse().expect("::1 parses")),
    ];
    for addr in addresses {
        if !addr.is_loopback() && !addr.is_unspecified() {
            names.push(SanType::IpAddress(*addr));
        }
    }

    let mut params = CertificateParams::default();
    params.subject_alt_names = names;

    // rcgen defaults to 1975..4096, which is not a validity period so much as
    // the absence of one, and TLS stacks treat it that way: a browser that would
    // have offered "proceed anyway" for an untrusted issuer refuses outright for
    // a certificate valid for twenty-one centuries. Ten years, starting an hour
    // ago so a server whose clock is still settling does not reject its own
    // certificate on first boot.
    let now = std::time::SystemTime::now();
    let hour = std::time::Duration::from_secs(3600);
    let decade = std::time::Duration::from_secs(3600 * 24 * 365 * 10);
    params.not_before = (now - hour).into();
    params.not_after = (now + decade).into();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Unihelm panel");
    dn.push(DnType::OrganizationName, "Unihelm");
    params.distinguished_name = dn;

    let key = KeyPair::generate().context("generating the panel's key")?;
    let cert = params
        .self_signed(&key)
        .context("signing the panel's certificate")?;

    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

/// The address this machine would use to reach the outside world, so the
/// certificate names the address the operator is most likely to type.
///
/// Asking a UDP socket rather than the shell: connecting a datagram socket sends
/// nothing, it only makes the kernel pick a route and bind a source address, so
/// this works with no network and no `hostname` process — and the panel is not
/// allowed to spawn one anyway (`tests/gates/no-shell.sh`; only the exec module
/// may).
///
/// Best effort. A certificate missing an address is one more line in a warning
/// the operator is already clicking through, and never a reason not to start.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut found = Vec::new();
    for probe in ["1.1.1.1:80", "[2606:4700:4700::1111]:80"] {
        let Ok(target) = probe.parse::<std::net::SocketAddr>() else {
            continue;
        };
        let bind: std::net::SocketAddr = if target.is_ipv6() {
            "[::]:0".parse().expect("valid")
        } else {
            "0.0.0.0:0".parse().expect("valid")
        };
        if let Ok(socket) = std::net::UdpSocket::bind(bind)
            && socket.connect(target).is_ok()
            && let Ok(addr) = socket.local_addr()
            && !addr.ip().is_loopback()
            && !addr.ip().is_unspecified()
        {
            found.push(addr.ip());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_certificate_covers_loopback_and_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let (cert, key) = load_or_generate(dir.path(), &[addr]).unwrap();

        assert!(String::from_utf8_lossy(&cert).contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key).contains("PRIVATE KEY"));
    }

    /// Regenerating on every start would log the operator out and re-warn the
    /// browser each time the panel restarts.
    #[test]
    fn an_existing_certificate_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_generate(dir.path(), &[]).unwrap();
        let second = load_or_generate(dir.path(), &[]).unwrap();
        assert_eq!(first.0, second.0, "the certificate was regenerated");
    }

    /// rcgen's default validity is 1975..4096, and a TLS stack reads that as a
    /// broken certificate rather than a long-lived one: browsers that would
    /// offer "proceed anyway" for an untrusted issuer refuse it outright, which
    /// makes the panel unreachable in exactly the browser it is meant to be
    /// opened in.
    #[test]
    fn the_certificate_has_a_believable_validity_period() {
        use std::time::{Duration, SystemTime};

        let dir = tempfile::tempdir().unwrap();
        let (pem, _) = load_or_generate(dir.path(), &[]).unwrap();
        let text = String::from_utf8_lossy(&pem);

        let (_, der) = x509_parser::pem::parse_x509_pem(text.as_bytes()).expect("valid PEM");
        let cert = der.parse_x509().expect("valid certificate");

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert!(not_before <= now, "not_before is in the future");
        assert!(
            now - not_before < Duration::from_secs(3600 * 25).as_secs() as i64,
            "not_before is a day or more in the past: the 1975 default is back"
        );
        assert!(not_after > now, "the certificate is already expired");
        let years = (not_after - now) / (3600 * 24 * 365);
        assert!(
            (1..=20).contains(&years),
            "validity is {years} years; a browser will refuse it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_key_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_generate(dir.path(), &[]).unwrap();
        let mode = std::fs::metadata(cert_dir(dir.path()).join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key.pem is mode {mode:o}");
    }
}
