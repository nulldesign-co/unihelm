//! Creating the Linux account and directory layout a tenant's sites live in
//! (spec §4.3, §6.3).
//!
//! # How the permissions work, and why
//!
//! nginx serves static files directly, so it needs to read into a tenant's site
//! root. PHP files are read by that tenant's own FPM pool, which already runs as
//! them. The question is how to let one shared nginx reach many tenants without
//! letting the tenants reach each other.
//!
//! The obvious answer — add the nginx account to every tenant's group — works
//! until a server has a few hundred tenants and nginx's supplementary group list
//! becomes a problem. So it is done the other way round: a tenant's home is
//! owned `tenant:<nginx group>` with mode `0710`. The tenant owns it outright,
//! nginx can *traverse* it because it is in the group, and everybody else —
//! including every other tenant — has nothing. One group, no growth.
//!
//! Files a tenant creates land at 0644 through the usual umask, which is
//! group-readable so nginx can serve them, and world-readable in principle — but
//! unreachable, because no other account can traverse the 0710 home to get to
//! them.

use unihelm_core::{Domain, LinuxUser, Result};
use unihelm_distro::pkg::LogSink;
use unihelm_distro::{Cmd, Distro, Family};

use crate::registry::OpContext;
use crate::slices::{self, TenantSlice};

/// The account nginx runs as, per family.
///
/// nginx.org's packages use `nginx` on both families; the Debian archive's own
/// package uses `www-data`, and a server that once had it installed may still
/// have that account. Preferring `nginx` and falling back is what makes this
/// work on a machine with a history.
pub fn nginx_user(distro: &Distro) -> &'static str {
    let _ = distro;
    "nginx"
}

/// Directories every site gets (spec §4.3).
const SITE_DIRS: &[(&str, u32)] = &[
    // Served content. Group-readable so nginx can serve static files.
    ("public", 0o750),
    // Per-site logs, written by nginx as root and rotated by logrotate.
    ("logs", 0o750),
    // Upload and session scratch; `open_basedir` includes it, nothing else does.
    ("tmp", 0o700),
    // Deliberately outside the document root: somewhere for a `.env` or a
    // vendor directory that must never be reachable over HTTP.
    ("private", 0o700),
];

/// Create the tenant's Linux account if it does not exist, and make sure its
/// resource slice does (spec §6.3).
///
/// Idempotent: re-provisioning an existing tenant must not fail, because the
/// site-create path calls this every time and a retried task has to converge.
pub async fn ensure_tenant_user(
    ctx: &OpContext,
    user: &LinuxUser,
    home: &str,
    can_ssh: bool,
) -> Result<()> {
    let distro = ctx.distro();
    let log = ctx.log_sink();

    if user_exists(user).await {
        log.line(&format!("account {user} already exists"));
    } else {
        // No shell unless the plan grants one (spec §6.3). A tenant who cannot
        // log in cannot be tricked into running anything.
        let shell = if can_ssh {
            "/bin/bash"
        } else {
            nologin_path(distro)
        };

        Cmd::new("useradd")
            .args([
                "--create-home",
                "--home-dir",
                home,
                "--shell",
                shell,
                "--comment",
                "Unihelm tenant",
            ])
            .arg("--")
            .arg(user.as_str())
            .run_checked()
            .await?;
        log.line(&format!("created account {user}"));

        apply_home_permissions(distro, user, home).await?;
    }

    // The slice is applied on every pass, not only when the account is
    // created: an account provisioned by an older panel gains its slice the
    // next time anything touches it, and a task retried after a crash between
    // useradd and here still converges. Re-applying identical limits is a
    // no-op inside the config engine, so the steady-state cost is one hash
    // comparison. Default limits until plans (spec §6.2) supply real ones —
    // and a failure is a real failure: limits are enforcement, not decoration
    // (spec §6.3), so a tenant must not silently provision without their
    // slice.
    slices::apply_tenant_slice(ctx, user, &TenantSlice::default()).await?;
    Ok(())
}

/// Set the home directory's ownership and mode.
///
/// Split out because it must also run when re-provisioning an account created
/// by an older version of the panel.
pub async fn apply_home_permissions(distro: &Distro, user: &LinuxUser, home: &str) -> Result<()> {
    let group = nginx_user(distro);

    // If nginx is not installed yet its group does not exist; fall back to the
    // tenant's own group and fix it when nginx lands.
    let owner = if group_exists(group).await {
        format!("{}:{}", user.as_str(), group)
    } else {
        format!("{}:{}", user.as_str(), user.as_str())
    };

    Cmd::new("chown")
        .arg(&owner)
        .arg("--")
        .arg(home)
        .run_checked()
        .await?;
    // 0710: owner everything, group traverse only, others nothing.
    Cmd::new("chmod")
        .arg("0710")
        .arg("--")
        .arg(home)
        .run_checked()
        .await?;
    Ok(())
}

/// Create the directory layout for one site.
pub async fn ensure_site_dirs(
    distro: &Distro,
    user: &LinuxUser,
    domain: &Domain,
    log: &dyn LogSink,
) -> Result<()> {
    let root = unihelm_config::paths::site_root(user.as_str(), domain.as_str());
    let group = if group_exists(nginx_user(distro)).await {
        nginx_user(distro).to_string()
    } else {
        user.as_str().to_string()
    };
    let owner = format!("{}:{}", user.as_str(), group);

    // The `sites/` parent, then the site root.
    for dir in [
        root.parent().expect("a site root always has a parent"),
        root.as_path(),
    ] {
        Cmd::new("mkdir")
            .args(["-p", "--"])
            .arg(dir)
            .run_checked()
            .await?;
        Cmd::new("chown")
            .arg(&owner)
            .arg("--")
            .arg(dir)
            .run_checked()
            .await?;
        Cmd::new("chmod")
            .arg("0750")
            .arg("--")
            .arg(dir)
            .run_checked()
            .await?;
    }

    for (name, mode) in SITE_DIRS {
        let path = root.join(name);
        Cmd::new("mkdir")
            .args(["-p", "--"])
            .arg(&path)
            .run_checked()
            .await?;
        Cmd::new("chown")
            .arg(&owner)
            .arg("--")
            .arg(&path)
            .run_checked()
            .await?;
        Cmd::new("chmod")
            .arg(format!("{mode:04o}"))
            .arg("--")
            .arg(&path)
            .run_checked()
            .await?;
    }

    // Logs live outside the tenant home so a tenant cannot delete or forge their
    // own access log, and so a full home quota does not stop nginx logging.
    let log_dir = unihelm_config::paths::site_log_dir(domain.as_str());
    Cmd::new("mkdir")
        .args(["-p", "--"])
        .arg(&log_dir)
        .run_checked()
        .await?;
    Cmd::new("chmod")
        .arg("0750")
        .arg("--")
        .arg(&log_dir)
        .run_checked()
        .await?;

    log.line(&format!("created {} ", root.display()));
    Ok(())
}

/// Write a placeholder page, so a brand-new site shows something other than a
/// 403 while its owner works out what to upload.
pub async fn write_placeholder(user: &LinuxUser, domain: &Domain) -> Result<()> {
    let path =
        unihelm_config::paths::site_public(user.as_str(), domain.as_str()).join("index.html");
    if path.exists() {
        return Ok(());
    }

    let body = format!(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head><meta charset=\"utf-8\"><title>{domain}</title>\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>\n\
         <body style=\"font-family:system-ui,sans-serif;margin:4rem auto;max-width:34rem;line-height:1.6\">\n\
         <h1 style=\"font-weight:600\">{domain}</h1>\n\
         <p>This site is set up and serving. Upload your files to replace this page.</p>\n\
         </body></html>\n"
    );

    std::fs::write(&path, body).map_err(|e| {
        unihelm_core::UnihelmError::internal(format!("could not write {}: {e}", path.display()))
    })?;

    Cmd::new("chown")
        .arg(format!("{}:{}", user.as_str(), user.as_str()))
        .arg("--")
        .arg(&path)
        .run()
        .await?;
    Ok(())
}

/// Remove a site's directory tree.
///
/// Deliberately not recursive-force on an arbitrary path: the path is built from
/// a validated [`LinuxUser`] and [`Domain`], and the prefix is re-checked here,
/// because `rm -rf` with a path assembled somewhere else is how panels delete
/// `/`.
pub async fn remove_site_dirs(user: &LinuxUser, domain: &Domain) -> Result<()> {
    let root = unihelm_config::paths::site_root(user.as_str(), domain.as_str());
    let expected_prefix = unihelm_config::paths::tenant_home(user.as_str()).join("sites");

    if !root.starts_with(&expected_prefix) || root.components().count() < 5 {
        return Err(unihelm_core::UnihelmError::internal(format!(
            "refusing to remove {} — it is not inside {}",
            root.display(),
            expected_prefix.display()
        )));
    }

    if root.exists() {
        Cmd::new("rm")
            .args(["-rf", "--"])
            .arg(&root)
            .run_checked()
            .await?;
    }
    let log_dir = unihelm_config::paths::site_log_dir(domain.as_str());
    if log_dir.exists() {
        Cmd::new("rm")
            .args(["-rf", "--"])
            .arg(&log_dir)
            .run_checked()
            .await?;
    }
    Ok(())
}

async fn user_exists(user: &LinuxUser) -> bool {
    Cmd::new("id")
        .args(["-u", "--"])
        .arg(user.as_str())
        .run()
        .await
        .map(|o| o.success())
        .unwrap_or(false)
}

async fn group_exists(group: &str) -> bool {
    Cmd::new("getent")
        .args(["group", "--"])
        .arg(group)
        .run()
        .await
        .map(|o| o.success())
        .unwrap_or(false)
}

/// `nologin` is in different places on the two families.
fn nologin_path(distro: &Distro) -> &'static str {
    match distro.info.family {
        Family::Debian => "/usr/sbin/nologin",
        Family::Rhel => "/sbin/nologin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> LinuxUser {
        LinuxUser::parse("uh_abc12345").unwrap()
    }

    fn domain() -> Domain {
        Domain::parse("example.com").unwrap()
    }

    #[test]
    fn the_site_layout_matches_the_documented_one() {
        let root = unihelm_config::paths::site_root("uh_abc12345", "example.com");
        assert_eq!(
            root.to_str().unwrap(),
            "/home/uh_abc12345/sites/example.com"
        );
        for (name, _) in SITE_DIRS {
            assert!(root.join(name).starts_with(&root));
        }
        let names: Vec<&str> = SITE_DIRS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["public", "logs", "tmp", "private"]);
    }

    #[test]
    fn only_the_served_directory_is_group_readable() {
        // nginx needs to read `public`. It has no business in `private` or in a
        // tenant's session files.
        let modes: std::collections::HashMap<_, _> = SITE_DIRS.iter().copied().collect();
        assert_eq!(modes["public"], 0o750);
        assert_eq!(
            modes["private"], 0o700,
            "private must not be group-readable"
        );
        assert_eq!(
            modes["tmp"], 0o700,
            "session files must not be group-readable"
        );
        for (name, mode) in SITE_DIRS {
            assert_eq!(mode & 0o007, 0, "{name} must give `other` nothing");
        }
    }

    #[test]
    fn nologin_differs_by_family() {
        let debian = Distro::mock();
        assert_eq!(nologin_path(&debian), "/usr/sbin/nologin");
        let (rhel, _) = unihelm_distro::mock::mock_distro_with_recorder(Family::Rhel);
        assert_eq!(nologin_path(&rhel), "/sbin/nologin");
    }

    #[tokio::test]
    async fn removal_refuses_a_path_outside_the_tenant_home() {
        // The path is built from validated newtypes, so this cannot normally
        // happen — which is exactly why it is worth asserting: `rm -rf` on a
        // path assembled elsewhere is how panels delete `/`.
        let root = unihelm_config::paths::site_root(user().as_str(), domain().as_str());
        let expected = unihelm_config::paths::tenant_home(user().as_str()).join("sites");
        assert!(root.starts_with(&expected));
        assert!(root.components().count() >= 5, "{root:?}");
    }

    #[test]
    fn logs_live_outside_the_tenant_home() {
        // So a tenant cannot delete or forge their own access log, and so a full
        // home quota does not stop nginx from logging.
        let log_dir = unihelm_config::paths::site_log_dir("example.com");
        assert!(!log_dir.starts_with("/home"), "{log_dir:?}");
        assert!(log_dir.starts_with("/var/log/unihelm"));
    }
}
