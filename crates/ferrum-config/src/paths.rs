//! Where the panel's managed files live (spec §10.4 rule 1, §4.3).
//!
//! Everything Ferrum writes sits under a `ferrum.d` directory of its own. We
//! never edit `nginx.conf`, a distro's `sites-enabled`, or a stock pool file —
//! the single line we add to the distribution's configuration is an `include`,
//! and that line is the entire footprint of the panel on files we do not own.
//!
//! # The development root
//!
//! Every path here is resolved under a root that defaults to `/`. A development
//! instance sets it to a scratch directory with [`set_root`], which makes the
//! whole chain — rendering a vhost, validating it, recording a revision, rolling
//! it back — exercisable on a laptop without root and without touching `/etc`.
//! In production the root is never set and these are the absolute paths above.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ferrum_core::PhpVersion;
use ferrum_distro::Family;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Root every managed path under `dir` instead of `/`.
///
/// Callable once, before anything resolves a path. Returns `false` if a root was
/// already set, which is a programming error rather than something to recover
/// from — half the panel writing to one prefix and half to another would be
/// worse than either.
pub fn set_root(dir: impl Into<PathBuf>) -> bool {
    ROOT.set(dir.into()).is_ok()
}

/// The configured root, or `/`.
pub fn root() -> &'static Path {
    ROOT.get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new("/"))
}

/// Resolve an absolute path under the configured root.
fn under(absolute: &str) -> PathBuf {
    let trimmed = absolute.trim_start_matches('/');
    root().join(trimmed)
}

/// Directory holding our nginx includes.
pub fn nginx_dir() -> PathBuf {
    under("/etc/nginx/ferrum.d")
}

/// The one line we add to the distribution's `nginx.conf`, via its own `conf.d`
/// drop-in directory so even that is not an edit to a stock file.
pub fn nginx_hook() -> PathBuf {
    under("/etc/nginx/conf.d/ferrum.conf")
}

/// Where nginx writes per-site logs.
///
/// Outside the tenant home, so a tenant cannot delete or forge their own access
/// log and a full home quota does not stop nginx logging.
pub fn site_log_root() -> PathBuf {
    under("/var/log/ferrum/sites")
}

/// The panel's data directory.
pub fn data_dir() -> PathBuf {
    under("/var/lib/ferrum")
}

/// Rendered configs, ACME account keys, certificates.
pub fn state_dir() -> PathBuf {
    under("/var/lib/ferrum/state")
}

/// Webroot for ACME http-01 challenges, shared by every site.
pub fn acme_webroot() -> PathBuf {
    state_dir().join("acme")
}

/// Issued certificates.
pub fn cert_root() -> PathBuf {
    under("/var/lib/ferrum/state/certs")
}

/// The self-signed certificate the catch-all server and a fresh panel use.
pub fn default_cert_dir() -> PathBuf {
    cert_root().join("_default")
}

/// The page shown while a site is in maintenance mode.
pub fn maintenance_root() -> PathBuf {
    under("/var/lib/ferrum/state/maintenance")
}

/// Per-site FPM sockets. Under `/run`, so they are recreated on boot and never
/// leave a stale socket behind.
pub fn fpm_socket_dir() -> PathBuf {
    under("/run/ferrum/fpm")
}

pub fn nginx_site(domain: &str) -> PathBuf {
    nginx_dir().join(format!("site-{domain}.conf"))
}

pub fn nginx_catchall() -> PathBuf {
    // `00-` so it sorts first and really is the default server.
    nginx_dir().join("00-catchall.conf")
}

pub fn nginx_panel() -> PathBuf {
    nginx_dir().join("01-panel.conf")
}

pub fn site_log_dir(domain: &str) -> PathBuf {
    site_log_root().join(domain)
}

pub fn logrotate_site(domain: &str) -> PathBuf {
    under("/etc/logrotate.d").join(format!("ferrum-{domain}"))
}

pub fn cert_dir(domain: &str) -> PathBuf {
    cert_root().join(domain)
}

/// Directory the distribution's PHP-FPM reads pool files from.
///
/// The layouts genuinely differ, which is exactly the kind of thing that must
/// not leak into a feature module (spec §7.2).
pub fn fpm_pool_dir(family: Family, version: PhpVersion) -> PathBuf {
    match family {
        // Sury/Debian: /etc/php/8.3/fpm/pool.d/
        Family::Debian => under(&format!("/etc/php/{}/fpm/pool.d", version.as_str())),
        // Remi/RHEL: /etc/opt/remi/php83/php-fpm.d/
        Family::Rhel => under(&format!("/etc/opt/remi/php{}/php-fpm.d", version.compact())),
    }
}

/// Where MariaDB reads drop-in configuration from.
///
/// Both families include a directory rather than expecting edits to the main
/// file, which is what lets the panel own one file completely and never touch
/// the distribution's (spec §10.4).
pub fn mysql_conf_d(family: Family) -> PathBuf {
    match family {
        Family::Debian => under("/etc/mysql/mariadb.conf.d"),
        Family::Rhel => under("/etc/my.cnf.d"),
    }
}

pub fn fpm_pool_file(family: Family, version: PhpVersion, site: &str) -> PathBuf {
    fpm_pool_dir(family, version).join(format!("ferrum-{site}.conf"))
}

/// The `php-fpm` binary for a version, for `-t` config tests.
///
/// Not rooted: this is a program to execute, resolved from the trusted binary
/// directories, not a file we write.
pub fn fpm_binary(family: Family, version: PhpVersion) -> String {
    match family {
        Family::Debian => format!("php-fpm{}", version.as_str()),
        Family::Rhel => format!("/opt/remi/php{}/root/usr/sbin/php-fpm", version.compact()),
    }
}

pub fn fpm_socket(site: &str, version: PhpVersion) -> PathBuf {
    fpm_socket_dir().join(format!("{site}-php{}.sock", version.compact()))
}

/// Where administrator-installed systemd units live — and therefore ours: the
/// panel acts as the administrator's hands, so its units go where an operator
/// would look for them, not into `/usr/lib/systemd` where packages install
/// theirs (and where a package upgrade could clobber them).
pub fn systemd_system_dir() -> PathBuf {
    under("/etc/systemd/system")
}

/// A unit file the panel owns, by its full file name (`ferrum-ft_ab.slice`).
pub fn systemd_unit(unit_file_name: &str) -> PathBuf {
    systemd_system_dir().join(unit_file_name)
}

/// A drop-in decorating `unit_file_name` without editing it: systemd merges
/// every `<unit>.d/*.conf` over the unit file itself. This is how the panel
/// places a unit into a tenant slice (spec §6.3) while the unit file stays
/// whole for whoever else manages it.
pub fn systemd_dropin(unit_file_name: &str, dropin_file_name: &str) -> PathBuf {
    systemd_system_dir()
        .join(format!("{unit_file_name}.d"))
        .join(dropin_file_name)
}

/// Where the panel-managed Adminer single-file app lives (spec §11.4).
///
/// Under the panel's own data directory, not under any tenant's home and not
/// under a webroot nginx already serves: the file is reachable only through
/// the dedicated loopback server block that points at it explicitly.
pub fn adminer_dir() -> PathBuf {
    under("/var/lib/ferrum/adminer")
}

/// The Adminer script itself. Root-owned 0644: the FPM pool that executes it
/// must never be able to replace it.
pub fn adminer_php() -> PathBuf {
    adminer_dir().join("adminer.php")
}

/// Scratch space for the Adminer pool (uploads, sessions). Owned by the pool's
/// runtime user, and inside `adminer_dir` so `open_basedir` covers it.
pub fn adminer_tmp_dir() -> PathBuf {
    adminer_dir().join("tmp")
}

/// Logs for the Adminer pool and vhost, beside the per-site logs.
pub fn adminer_log_dir() -> PathBuf {
    under("/var/log/ferrum/adminer")
}

/// The nginx server block that serves Adminer on loopback.
///
/// `02-` so it sorts with the panel's own infrastructure files, after the
/// catch-all and panel vhosts and before any `site-*.conf`.
pub fn nginx_adminer() -> PathBuf {
    nginx_dir().join("02-adminer.conf")
}

/// The loopback port Adminer is served on (spec §11.4).
///
/// Not a filesystem path, but it lives with them for the same reason they are
/// centralised: the agent (which renders the vhost) and the web process (which
/// reports the URL) must agree on one value. 8806 collides with neither the
/// panel's own 127.0.0.1:8088 nor anything a hosted app plausibly binds
/// (3000/8080-class ports).
pub const ADMINER_LOOPBACK_PORT: u16 = 8806;

/// The parent of every tenant home — the directory whose filesystem disk
/// quotas are detected on and enforced against (spec §6.3).
pub fn home_root() -> PathBuf {
    under("/home")
}

/// The sshd drop-in carrying the chrooted-SFTP `Match Group` block (spec §6).
///
/// `sshd_config.d` rather than an edit to `sshd_config` itself, for the same
/// reason as the nginx hook: the panel's entire footprint on a stock file is
/// zero — both families ship an `Include /etc/ssh/sshd_config.d/*.conf` in
/// their stock `sshd_config`.
pub fn sshd_dropin() -> PathBuf {
    under("/etc/ssh/sshd_config.d/50-ferrum.conf")
}

/// A tenant's home, and the standard layout inside it (spec §4.3).
pub fn tenant_home(linux_user: &str) -> PathBuf {
    home_root().join(linux_user)
}

pub fn site_root(linux_user: &str, domain: &str) -> PathBuf {
    tenant_home(linux_user).join("sites").join(domain)
}

pub fn site_public(linux_user: &str, domain: &str) -> PathBuf {
    site_root(linux_user, domain).join("public")
}

/// A tenant Node application's working directory: `<home>/apps/<name>`
/// (spec §11.6).
///
/// Beside `sites/` rather than inside it: an app is not a vhost — it may be
/// published behind one, behind several, or behind none at all — and putting
/// it under a domain's directory would make renaming the domain move the
/// running application.
pub fn app_dir(linux_user: &str, app: &str) -> PathBuf {
    tenant_home(linux_user).join("apps").join(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests run in the same process, so the root is whatever it defaults
    // to — `/`. `set_root` is exercised by the dev-mode integration path, where
    // it is called before anything else.

    #[test]
    fn fpm_layouts_differ_by_family() {
        assert_eq!(
            fpm_pool_dir(Family::Debian, PhpVersion::V83)
                .to_str()
                .unwrap(),
            "/etc/php/8.3/fpm/pool.d"
        );
        assert_eq!(
            fpm_pool_dir(Family::Rhel, PhpVersion::V83)
                .to_str()
                .unwrap(),
            "/etc/opt/remi/php83/php-fpm.d"
        );
        assert_eq!(fpm_binary(Family::Debian, PhpVersion::V84), "php-fpm8.4");
        assert!(fpm_binary(Family::Rhel, PhpVersion::V84).contains("php84"));
    }

    #[test]
    fn the_catchall_sorts_before_every_site() {
        let catchall = nginx_catchall();
        let site = nginx_site("aaa.example.com");
        assert!(
            catchall.file_name().unwrap() < site.file_name().unwrap(),
            "the default server must be included first"
        );
    }

    #[test]
    fn site_paths_follow_the_documented_layout() {
        assert_eq!(
            site_public("ft_abc123", "example.com").to_str().unwrap(),
            "/home/ft_abc123/sites/example.com/public"
        );
    }

    #[test]
    fn managed_paths_never_touch_a_stock_file() {
        // The panel's entire footprint on files it does not own is one include.
        for path in [nginx_site("a.com"), nginx_catchall(), nginx_panel()] {
            assert!(
                path.starts_with(nginx_dir()),
                "{path:?} escaped the managed directory"
            );
        }
        assert_eq!(
            nginx_hook().to_str().unwrap(),
            "/etc/nginx/conf.d/ferrum.conf"
        );
    }

    #[test]
    fn logs_live_outside_the_tenant_home() {
        let log_dir = site_log_dir("example.com");
        assert!(!log_dir.starts_with("/home"), "{log_dir:?}");
        assert!(log_dir.starts_with("/var/log/ferrum"));
    }

    #[test]
    fn under_joins_relative_to_the_root_without_swallowing_it() {
        assert_eq!(under("/etc/nginx"), PathBuf::from("/etc/nginx"));

        // The hazard `under` exists to avoid: `Path::join` with an absolute
        // argument *replaces* the base rather than nesting under it. Built from
        // a binding so this demonstrates the behaviour rather than tripping the
        // lint that warns about writing it literally.
        let absolute: &Path = Path::new("/etc/nginx");
        assert_eq!(
            Path::new("/tmp/x").join(absolute),
            PathBuf::from("/etc/nginx"),
            "a naive join silently discards the root"
        );

        // Trimming the leading separator first is what makes it nest, which is
        // exactly what `under` does.
        let trimmed = absolute
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        assert_eq!(
            Path::new("/tmp/x").join(trimmed),
            PathBuf::from("/tmp/x/etc/nginx")
        );
    }
}
