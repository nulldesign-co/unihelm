//! Where the panel's managed files live (spec §10.4 rule 1, §4.3).
//!
//! Everything Ferrum writes sits under a `ferrum.d` directory of its own. We
//! never edit `nginx.conf`, a distro's `sites-enabled`, or a stock pool file —
//! the single line we add to the distribution's configuration is an `include`,
//! and that line is the entire footprint of the panel on files we do not own.

use std::path::PathBuf;

use ferrum_core::PhpVersion;
use ferrum_distro::Family;

/// Directory holding our nginx includes.
pub const NGINX_DIR: &str = "/etc/nginx/ferrum.d";

/// The one line we add to the distribution's `nginx.conf`, via its own
/// `conf.d` drop-in directory so even that is not an edit to a stock file.
pub const NGINX_HOOK: &str = "/etc/nginx/conf.d/ferrum.conf";

/// Where nginx writes per-site logs.
pub const SITE_LOG_DIR: &str = "/var/log/ferrum/sites";

/// Webroot for ACME http-01 challenges, shared by every site.
pub const ACME_WEBROOT: &str = "/var/lib/ferrum/state/acme";

/// Issued certificates.
pub const CERT_DIR: &str = "/var/lib/ferrum/state/certs";

/// The self-signed certificate the catch-all server and a fresh panel use.
pub const DEFAULT_CERT_DIR: &str = "/var/lib/ferrum/state/certs/_default";

pub fn nginx_site(domain: &str) -> PathBuf {
    PathBuf::from(NGINX_DIR).join(format!("site-{domain}.conf"))
}

pub fn nginx_catchall() -> PathBuf {
    // `00-` so it sorts first and really is the default server.
    PathBuf::from(NGINX_DIR).join("00-catchall.conf")
}

pub fn nginx_panel() -> PathBuf {
    PathBuf::from(NGINX_DIR).join("01-panel.conf")
}

pub fn site_log_dir(domain: &str) -> PathBuf {
    PathBuf::from(SITE_LOG_DIR).join(domain)
}

pub fn logrotate_site(domain: &str) -> PathBuf {
    PathBuf::from("/etc/logrotate.d").join(format!("ferrum-{domain}"))
}

pub fn cert_dir(domain: &str) -> PathBuf {
    PathBuf::from(CERT_DIR).join(domain)
}

/// Directory the distribution's PHP-FPM reads pool files from.
///
/// The layouts genuinely differ, which is exactly the kind of thing that must
/// not leak into a feature module (spec §7.2).
pub fn fpm_pool_dir(family: Family, version: PhpVersion) -> PathBuf {
    match family {
        // Sury/Debian: /etc/php/8.3/fpm/pool.d/
        Family::Debian => PathBuf::from(format!("/etc/php/{}/fpm/pool.d", version.as_str())),
        // Remi/RHEL: /etc/opt/remi/php83/php-fpm.d/
        Family::Rhel => PathBuf::from(format!("/etc/opt/remi/php{}/php-fpm.d", version.compact())),
    }
}

pub fn fpm_pool_file(family: Family, version: PhpVersion, site: &str) -> PathBuf {
    fpm_pool_dir(family, version).join(format!("ferrum-{site}.conf"))
}

/// The `php-fpm` binary for a version, for `-t` config tests.
pub fn fpm_binary(family: Family, version: PhpVersion) -> String {
    match family {
        Family::Debian => format!("php-fpm{}", version.as_str()),
        Family::Rhel => format!("/opt/remi/php{}/root/usr/sbin/php-fpm", version.compact()),
    }
}

/// Per-site FPM socket. Under `/run`, so it is recreated on boot and never
/// leaves a stale socket behind.
pub fn fpm_socket(site: &str, version: PhpVersion) -> PathBuf {
    PathBuf::from(format!(
        "/run/ferrum/fpm/{site}-php{}.sock",
        version.compact()
    ))
}

/// A tenant's home, and the standard layout inside it (spec §4.3).
pub fn tenant_home(linux_user: &str) -> PathBuf {
    PathBuf::from("/home").join(linux_user)
}

pub fn site_root(linux_user: &str, domain: &str) -> PathBuf {
    tenant_home(linux_user).join("sites").join(domain)
}

pub fn site_public(linux_user: &str, domain: &str) -> PathBuf {
    site_root(linux_user, domain).join("public")
}

#[cfg(test)]
mod tests {
    use super::*;

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
                path.starts_with(NGINX_DIR),
                "{path:?} escaped the managed directory"
            );
        }
        assert_eq!(NGINX_HOOK, "/etc/nginx/conf.d/ferrum.conf");
    }
}
