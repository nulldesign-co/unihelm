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

/// `/etc/ferrum` — `config.toml` and the master key (spec §4.3).
///
/// Rooted like everything else here, so a development instance's "system"
/// configuration lives in its scratch tree. The one thing that reads it as a
/// hard-coded absolute string is the packaged installer, which by definition is
/// not running under a development root.
///
/// A backup of the panel has to include this directory: without `secret.key`
/// every sealed secret in the restored database — ACME account keys, DNS
/// credentials, backup repository passwords — is ciphertext nobody can open
/// (spec §11.10, §12 rule 6).
pub fn config_dir() -> PathBuf {
    under("/etc/ferrum")
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

/// Where the panel-managed WP-CLI phar lives (spec §11.12).
///
/// Under the panel's data directory, root-owned and mode 0755, for the same
/// reason Adminer lives there: a tenant runs it (as themselves, through the
/// privilege-dropping helper) but must never be able to *replace* it. A phar
/// inside a tenant home would be a file the tenant could swap for their own
/// code moments before the panel invoked it — and the panel invokes it while
/// holding a database password.
pub fn wp_cli_dir() -> PathBuf {
    under("/var/lib/ferrum/wp-cli")
}

/// The WP-CLI phar itself. Not `wp` on `$PATH`: the panel runs the version it
/// pinned and verified, never whatever a distribution package happens to have
/// put in `/usr/local/bin`.
pub fn wp_cli_phar() -> PathBuf {
    wp_cli_dir().join("wp-cli.phar")
    // ---------------------------------------------------------------------------
    // ModSecurity WAF (spec §11.9)
    // ---------------------------------------------------------------------------
}

/// The stock `sshd_config`, read by the security posture scan when `sshd -T`
/// cannot be run. Its `Include` line is what makes [`sshd_dropin`] work.
pub fn sshd_config() -> PathBuf {
    under("/etc/ssh/sshd_config")
}

/// The drop-in directory sshd includes. Read — never written — by the posture
/// scan, which reports what the *effective* configuration says.
pub fn sshd_config_dir() -> PathBuf {
    under("/etc/ssh/sshd_config.d")
}

/// nginx's own top-level configuration. Ferrum never writes it; the WAF
/// preflight *reads* it to find out whether it offers a main-context `include`
/// that a `load_module` line could live in (see `ferrum_ops::waf`).
pub fn nginx_conf() -> PathBuf {
    under("/etc/nginx/nginx.conf")
}

/// Where nginx looks for dynamic modules on both families. The nginx.org
/// packages ship `/etc/nginx/modules` as a symlink to their real module
/// directory (`/usr/lib/nginx/modules` on deb, `/usr/lib64/nginx/modules` on
/// rpm), so this one path resolves correctly on both.
pub fn nginx_modules_dir() -> PathBuf {
    under("/etc/nginx/modules")
}

/// The WAF's configuration directory: everything ModSecurity reads that Ferrum
/// generates.
pub fn waf_dir() -> PathBuf {
    config_dir().join("waf")
}

/// The single rules file nginx points ModSecurity at. It `Include`s the Core
/// Rule Set and carries the per-site policy Ferrum renders from the database.
pub fn waf_main_conf() -> PathBuf {
    waf_dir().join("main.conf")
}

/// The unpacked OWASP Core Rule Set, under the panel's data directory rather
/// than `/etc`: it is a downloaded artefact with a pinned checksum, not
/// configuration an operator edits.
pub fn waf_crs_dir() -> PathBuf {
    data_dir().join("waf/crs")
}

/// Where one CRS release unpacks to. Version-suffixed so an upgrade lands
/// beside the running set rather than half-overwriting it.
pub fn waf_crs_release_dir(version: &str) -> PathBuf {
    waf_crs_dir().join(format!("coreruleset-{version}"))
}

/// ModSecurity's persistence directory (`SecDataDir`). Under the panel's data
/// directory and 0700: it holds request fragments from live traffic.
pub fn waf_data_dir() -> PathBuf {
    data_dir().join("waf/data")
}

/// The WAF audit log, beside the per-site logs rather than in the tenant home:
/// it records what attackers sent, which is not a tenant's file to edit.
pub fn waf_audit_log() -> PathBuf {
    under("/var/log/ferrum/waf/audit.log")
}

/// Where the per-site mail relay configuration lives (spec §11.18).
///
/// Under `/etc/ferrum` rather than in the tenant home: the file holds the
/// relay credential, and a tenant who could edit it could point their site's
/// mail at a server they control while still sending as the operator's domain.
/// The tenant only ever needs to *read* it.
pub fn mail_dir() -> PathBuf {
    config_dir().join("mail")
}

/// One site's relay configuration, read by the sendmail shim PHP's
/// `sendmail_path` points at.
///
/// Per site rather than one shared file so the mode can be `0640` owned
/// `root:<tenant group>`: the relay credential is readable by the tenant whose
/// PHP sends the mail — that is inherent to `mail()` running as the tenant —
/// and no wider.
pub fn mail_site_config(domain: &str) -> PathBuf {
    mail_dir().join(format!("{domain}.msmtprc"))
}

/// The http-context nginx include that turns ModSecurity on.
///
/// `03-` so it sorts after the catch-all, panel and Adminer server blocks and
/// before any `site-*.conf` — the directives are inherited by every server
/// block that follows, and nginx inheritance does not depend on order, but a
/// human reading the directory should meet the global switch before the sites
/// it governs.
pub fn nginx_waf() -> PathBuf {
    nginx_dir().join("03-waf.conf")
}

// ---------------------------------------------------------------------------
// Plugins (spec §6 plugin note, §14 Phase 6)
// ---------------------------------------------------------------------------

/// Where installed plugin payloads live.
///
/// Under the panel's data directory, root-owned, and **never** inside a tenant
/// home or a webroot — the same reasoning as Adminer and the WP-CLI phar. A
/// plugin's own unprivileged account may read and execute what is here; it must
/// never be able to replace it, because the agent starts that code as a service.
pub fn plugin_root() -> PathBuf {
    data_dir().join("plugins")
}

/// One plugin's installed tree: `/var/lib/ferrum/plugins/<slug>`.
pub fn plugin_dir(slug: &str) -> PathBuf {
    plugin_root().join(slug)
}

/// The manifest inside an installed (or staged) plugin tree.
pub fn plugin_manifest(dir: &Path) -> PathBuf {
    dir.join("plugin.toml")
}

/// The detached minisign signature over the manifest.
pub fn plugin_signature(dir: &Path) -> PathBuf {
    dir.join("plugin.toml.minisig")
}

/// The runtime directory systemd creates for one plugin, owned by the plugin's
/// own account so the sidecar can bind its socket inside it.
///
/// Under `/run` so it is recreated on boot and never leaves a stale socket
/// behind, exactly like the FPM socket directory.
pub fn plugin_runtime_dir(slug: &str) -> PathBuf {
    under("/run/ferrum/plugins").join(slug)
}

/// The UDS the agent dials to reach one plugin.
pub fn plugin_socket(slug: &str) -> PathBuf {
    plugin_runtime_dir(slug).join("plugin.sock")
}

/// The `RuntimeDirectory=` value for a plugin unit — a path *relative to*
/// `/run`, which is what systemd expects, and never rooted for development.
pub fn plugin_runtime_dir_relative(slug: &str) -> String {
    format!("ferrum/plugins/{slug}")
}

/// The unit file name for one plugin's sidecar.
pub fn plugin_unit_file_name(slug: &str) -> String {
    format!("ferrum-plugin-{slug}.service")
}

/// `/etc/systemd/system/ferrum-plugin-<slug>.service`.
pub fn plugin_unit(slug: &str) -> PathBuf {
    systemd_unit(&plugin_unit_file_name(slug))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests run in the same process, so the root is whatever it defaults
    // to — `/`. `set_root` is exercised by the dev-mode integration path, where
    // it is called before anything else.

    #[test]
    fn every_waf_file_the_panel_writes_is_inside_a_directory_it_owns() {
        // The WAF is the one feature that would be tempting to wire up by
        // editing nginx.conf. Nothing here may land outside `ferrum.d`,
        // `/etc/ferrum` or `/var/lib/ferrum` (spec §10.4 rule 1).
        assert!(nginx_waf().starts_with(nginx_dir()));
        assert!(waf_main_conf().starts_with(config_dir()));
        assert!(waf_crs_release_dir("4.29.0").starts_with(data_dir()));
        assert!(waf_data_dir().starts_with(data_dir()));
    }

    #[test]
    fn the_paths_the_posture_scan_reads_are_never_written_by_the_panel() {
        // Read-only inputs. Listed here so a later refactor that starts
        // *writing* one of them has to delete this assertion first.
        assert_eq!(nginx_conf().to_str().unwrap(), "/etc/nginx/nginx.conf");
        assert_eq!(sshd_config().to_str().unwrap(), "/etc/ssh/sshd_config");
        assert_eq!(
            sshd_config_dir().to_str().unwrap(),
            "/etc/ssh/sshd_config.d"
        );
        // The panel's own sshd drop-in lives in that directory, so the scan
        // reads Ferrum's chrooted-SFTP block too — as it should, since that
        // block is part of the effective configuration.
        assert!(sshd_dropin().starts_with(sshd_config_dir()));
    }

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
