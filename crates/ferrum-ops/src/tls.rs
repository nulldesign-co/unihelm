//! Self-signed certificates for the places TLS has to be *something*.
//!
//! Two of them: the catch-all server, which must present a certificate to a
//! request for a host it does not know, and a freshly installed panel that has
//! no domain pointed at it yet. Neither is a certificate anybody should trust —
//! they exist so that "no certificate configured" is not a reason for nginx to
//! refuse to start.

use std::path::Path;

use ferrum_core::{FerrumError, Result};

/// Generate a self-signed certificate and write it as `fullchain.pem` and
/// `privkey.pem`, matching the layout an issued certificate uses.
///
/// Using the same filenames means the vhost template does not need to know
/// which kind of certificate it is pointing at.
pub fn write_self_signed(dir: &Path, names: &[String]) -> Result<()> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let names = if names.is_empty() {
        vec!["localhost".to_string()]
    } else {
        names.to_vec()
    };

    let key = KeyPair::generate()
        .map_err(|e| FerrumError::internal(format!("could not generate a key: {e}")))?;

    let mut params = CertificateParams::new(names.clone())
        .map_err(|e| FerrumError::internal(format!("invalid certificate names: {e}")))?;

    // A subject that says what this is, so an operator who inspects it in a
    // browser sees "Ferrum default" rather than a blank certificate they have to
    // guess about.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, names[0].clone());
    dn.push(DnType::OrganizationName, "Ferrum (self-signed)");
    params.distinguished_name = dn;

    // rcgen's default validity is 1975 to 4096, which works but looks like a
    // bug in every certificate viewer and confuses expiry monitoring. An hour of
    // backdating absorbs clock skew between the panel and whatever inspects it.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(3650);

    let cert = params
        .self_signed(&key)
        .map_err(|e| FerrumError::internal(format!("could not self-sign: {e}")))?;

    std::fs::create_dir_all(dir)
        .map_err(|e| FerrumError::internal(format!("could not create {}: {e}", dir.display())))?;

    write_secret(&dir.join("privkey.pem"), key.serialize_pem().as_bytes())?;
    let chain = cert.pem();
    write_public(&dir.join("fullchain.pem"), chain.as_bytes())?;
    // nginx wants a trusted-certificate file for stapling; a self-signed
    // certificate is its own chain.
    write_public(&dir.join("chain.pem"), chain.as_bytes())?;
    Ok(())
}

/// Is there already a usable certificate here?
pub fn certificate_present(dir: &Path) -> bool {
    dir.join("fullchain.pem").is_file() && dir.join("privkey.pem").is_file()
}

/// Private keys are 0600 and root-owned. nginx reads them as root before it
/// drops privileges, so there is no reason for anybody else to.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    write_with_mode(path, bytes, 0o600)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    write_with_mode(path, bytes, 0o644)
}

fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let mut temp = path.to_path_buf();
    temp.as_mut_os_string().push(".tmp");

    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temp)?;
        // Tighten before writing, so the key is never briefly world-readable.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()
    };

    write()
        .map_err(|e| FerrumError::internal(format!("could not write {}: {e}", temp.display())))?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        FerrumError::internal(format!("could not write {}: {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use x509_parser::prelude::FromDer;

    #[test]
    fn a_self_signed_pair_is_written_with_the_issued_layout() {
        // The vhost template points at fullchain.pem/privkey.pem and must not
        // need to know whether the certificate is real.
        let dir = tempfile::tempdir().unwrap();
        write_self_signed(dir.path(), &["example.com".into()]).unwrap();

        assert!(certificate_present(dir.path()));
        let chain = std::fs::read_to_string(dir.path().join("fullchain.pem")).unwrap();
        let key = std::fs::read_to_string(dir.path().join("privkey.pem")).unwrap();
        assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("PRIVATE KEY"));
        assert!(
            dir.path().join("chain.pem").is_file(),
            "stapling needs a trusted-cert file"
        );
    }

    #[test]
    fn the_certificate_has_a_plausible_validity_window() {
        // rcgen defaults to 1975..4096, which is valid but reads as a bug and
        // breaks expiry monitoring.
        let dir = tempfile::tempdir().unwrap();
        write_self_signed(dir.path(), &["example.com".into()]).unwrap();

        let pem = std::fs::read_to_string(dir.path().join("fullchain.pem")).unwrap();
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&parsed.contents).unwrap();

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        assert!(not_before <= now, "the certificate must already be valid");
        assert!(
            now - not_before < 7200,
            "backdated by an hour, not by fifty years"
        );
        let years = (not_after - now) / (365 * 24 * 3600);
        assert!(
            (9..=11).contains(&years),
            "expected roughly ten years, got {years}"
        );
    }

    #[test]
    fn the_private_key_is_not_readable_by_anybody_else() {
        let dir = tempfile::tempdir().unwrap();
        write_self_signed(dir.path(), &["example.com".into()]).unwrap();

        let key_mode = std::fs::metadata(dir.path().join("privkey.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            key_mode, 0o600,
            "a private key must never be group- or world-readable"
        );

        let chain_mode = std::fs::metadata(dir.path().join("fullchain.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(chain_mode, 0o644);
    }

    #[test]
    fn an_empty_name_list_still_produces_a_usable_certificate() {
        // The catch-all server answers for hosts we have never heard of.
        let dir = tempfile::tempdir().unwrap();
        write_self_signed(dir.path(), &[]).unwrap();
        assert!(certificate_present(dir.path()));
    }

    #[test]
    fn regenerating_replaces_the_pair_atomically() {
        let dir = tempfile::tempdir().unwrap();
        write_self_signed(dir.path(), &["a.example".into()]).unwrap();
        let first = std::fs::read_to_string(dir.path().join("fullchain.pem")).unwrap();

        write_self_signed(dir.path(), &["b.example".into()]).unwrap();
        let second = std::fs::read_to_string(dir.path().join("fullchain.pem")).unwrap();

        assert_ne!(first, second);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn certificate_present_is_false_for_an_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!certificate_present(dir.path()));
    }
}
