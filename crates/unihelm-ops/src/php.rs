//! PHP package naming, which is where the two families differ most (spec §11.3).
//!
//! Two traps live here, both found the hard way and both worth a test:
//!
//! - **There is no `php8X-php-curl` on Remi.** `curl.so` ships inside
//!   `php8X-php-common`, so asking for a curl package fails the whole
//!   transaction. Debian *does* have `php8.3-curl`.
//! - **There is no `php8.3-mysqli` on Debian.** The package is `php8.3-mysql`,
//!   which ships `mysqli.so`, `mysqlnd.so` and `pdo_mysql.so`. Remi calls the
//!   same thing `php8X-php-mysqlnd`.
//!
//! Getting either wrong produces a failed install that reads like a broken
//! repository.

use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, PhpVersion, Result, UnihelmError};
use unihelm_distro::{Family, PackageName};

/// The extensions the panel will install.
///
/// An enum, not a free string: this value becomes a package name, and a package
/// name is an argument to a program running as root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PhpExt {
    /// MySQL/MariaDB, including PDO. `mysqli` lives here too.
    Mysql,
    Pgsql,
    Sqlite3,
    Gd,
    Imagick,
    Mbstring,
    Curl,
    Xml,
    Xsl,
    Zip,
    Intl,
    Opcache,
    Bcmath,
    Soap,
    Redis,
    Ldap,
    Gmp,
    Sodium,
}

impl PhpExt {
    /// Installed on every PHP version by default: the set a mainstream PHP
    /// application assumes exists.
    pub const DEFAULT: &'static [PhpExt] = &[
        PhpExt::Mysql,
        PhpExt::Gd,
        PhpExt::Mbstring,
        PhpExt::Curl,
        PhpExt::Xml,
        PhpExt::Zip,
        PhpExt::Intl,
        PhpExt::Opcache,
        PhpExt::Bcmath,
    ];

    pub const ALL: &'static [PhpExt] = &[
        PhpExt::Mysql,
        PhpExt::Pgsql,
        PhpExt::Sqlite3,
        PhpExt::Gd,
        PhpExt::Imagick,
        PhpExt::Mbstring,
        PhpExt::Curl,
        PhpExt::Xml,
        PhpExt::Xsl,
        PhpExt::Zip,
        PhpExt::Intl,
        PhpExt::Opcache,
        PhpExt::Bcmath,
        PhpExt::Soap,
        PhpExt::Redis,
        PhpExt::Ldap,
        PhpExt::Gmp,
        PhpExt::Sodium,
    ];

    pub const fn as_str(self) -> &'static str {
        use PhpExt::*;
        match self {
            Mysql => "mysql",
            Pgsql => "pgsql",
            Sqlite3 => "sqlite3",
            Gd => "gd",
            Imagick => "imagick",
            Mbstring => "mbstring",
            Curl => "curl",
            Xml => "xml",
            Xsl => "xsl",
            Zip => "zip",
            Intl => "intl",
            Opcache => "opcache",
            Bcmath => "bcmath",
            Soap => "soap",
            Redis => "redis",
            Ldap => "ldap",
            Gmp => "gmp",
            Sodium => "sodium",
        }
    }

    /// The package that provides this extension, or `None` when the family
    /// ships it inside another package.
    ///
    /// `None` is not "unsupported": it means the extension is already there once
    /// the core packages are installed, and asking for it by name would fail.
    pub fn package(self, family: Family, version: PhpVersion) -> Option<String> {
        use PhpExt::*;
        match family {
            Family::Debian => {
                let v = version.as_str();
                Some(match self {
                    // `php8.3-mysqli` does not exist; this package provides it.
                    Mysql => format!("php{v}-mysql"),
                    Pgsql => format!("php{v}-pgsql"),
                    Sqlite3 => format!("php{v}-sqlite3"),
                    Gd => format!("php{v}-gd"),
                    Imagick => format!("php{v}-imagick"),
                    Mbstring => format!("php{v}-mbstring"),
                    Curl => format!("php{v}-curl"),
                    Xml => format!("php{v}-xml"),
                    // Debian splits XSL out of the xml package; Remi does not.
                    Xsl => format!("php{v}-xsl"),
                    Zip => format!("php{v}-zip"),
                    Intl => format!("php{v}-intl"),
                    Opcache => format!("php{v}-opcache"),
                    Bcmath => format!("php{v}-bcmath"),
                    Soap => format!("php{v}-soap"),
                    Redis => format!("php{v}-redis"),
                    Ldap => format!("php{v}-ldap"),
                    Gmp => format!("php{v}-gmp"),
                    Sodium => format!("php{v}-sodium"),
                })
            }
            Family::Rhel => {
                let v = version.compact();
                Some(match self {
                    Mysql => format!("php{v}-php-mysqlnd"),
                    Pgsql => format!("php{v}-php-pgsql"),
                    Sqlite3 => format!("php{v}-php-pdo"),
                    Gd => format!("php{v}-php-gd"),
                    Imagick => format!("php{v}-php-pecl-imagick-im7"),
                    Mbstring => format!("php{v}-php-mbstring"),
                    // curl.so is inside php8X-php-common. Asking for a curl
                    // package here fails the whole dnf transaction.
                    Curl => return None,
                    // Remi's xml package already contains xsl.so.
                    Xml => format!("php{v}-php-xml"),
                    Xsl => return None,
                    Zip => format!("php{v}-php-pecl-zip"),
                    Intl => format!("php{v}-php-intl"),
                    Opcache => format!("php{v}-php-opcache"),
                    Bcmath => format!("php{v}-php-bcmath"),
                    Soap => format!("php{v}-php-soap"),
                    Redis => format!("php{v}-php-pecl-redis6"),
                    Ldap => format!("php{v}-php-ldap"),
                    Gmp => format!("php{v}-php-gmp"),
                    Sodium => format!("php{v}-php-sodium"),
                })
            }
        }
    }
}

/// The packages that make a PHP version usable: FPM, the CLI, and the
/// extensions asked for.
pub fn packages_for(
    family: Family,
    version: PhpVersion,
    extensions: &[PhpExt],
) -> Result<Vec<PackageName>> {
    let core = match family {
        Family::Debian => {
            vec![
                format!("php{}-fpm", version.as_str()),
                format!("php{}-cli", version.as_str()),
            ]
        }
        Family::Rhel => vec![
            format!("php{}-php-fpm", version.compact()),
            format!("php{}-php-cli", version.compact()),
        ],
    };

    let mut names = core;
    for ext in extensions {
        if let Some(pkg) = ext.package(family, version) {
            names.push(pkg);
        }
    }

    // Deduplicate: two extensions can resolve to one package.
    names.sort();
    names.dedup();

    names
        .iter()
        .map(|n| {
            PackageName::parse(n).map_err(|e| {
                UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!("`{n}` is not a valid package name: {e}"),
                )
            })
        })
        .collect()
}

/// The FPM package alone, for a version that is already installed and only
/// needs an extension added.
pub fn fpm_package(family: Family, version: PhpVersion) -> Result<PackageName> {
    let name = match family {
        Family::Debian => format!("php{}-fpm", version.as_str()),
        Family::Rhel => format!("php{}-php-fpm", version.compact()),
    };
    PackageName::parse(&name)
        .map_err(|e| UnihelmError::new(ErrorCode::InvalidInput, format!("{name}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(family: Family, version: PhpVersion, exts: &[PhpExt]) -> Vec<String> {
        packages_for(family, version, exts)
            .unwrap()
            .into_iter()
            .map(|p| p.as_str().to_string())
            .collect()
    }

    #[test]
    fn there_is_no_curl_package_on_remi() {
        // curl.so ships in php8X-php-common. Asking for php83-php-curl fails the
        // whole transaction, and the error reads like a broken repository.
        assert_eq!(PhpExt::Curl.package(Family::Rhel, PhpVersion::V83), None);
        let rhel = names(Family::Rhel, PhpVersion::V83, &[PhpExt::Curl]);
        assert!(!rhel.iter().any(|n| n.contains("curl")), "{rhel:?}");

        // Debian does have one.
        assert_eq!(
            PhpExt::Curl
                .package(Family::Debian, PhpVersion::V83)
                .as_deref(),
            Some("php8.3-curl")
        );
    }

    #[test]
    fn mysqli_comes_from_a_package_that_is_not_called_mysqli() {
        assert_eq!(
            PhpExt::Mysql
                .package(Family::Debian, PhpVersion::V83)
                .as_deref(),
            Some("php8.3-mysql"),
            "there is no php8.3-mysqli package"
        );
        assert_eq!(
            PhpExt::Mysql
                .package(Family::Rhel, PhpVersion::V83)
                .as_deref(),
            Some("php83-php-mysqlnd")
        );
    }

    #[test]
    fn xsl_is_split_out_on_debian_and_bundled_on_remi() {
        assert_eq!(
            PhpExt::Xsl
                .package(Family::Debian, PhpVersion::V84)
                .as_deref(),
            Some("php8.4-xsl")
        );
        assert_eq!(PhpExt::Xsl.package(Family::Rhel, PhpVersion::V84), None);
    }

    #[test]
    fn the_core_packages_differ_by_family() {
        let debian = names(Family::Debian, PhpVersion::V83, &[]);
        assert_eq!(debian, vec!["php8.3-cli", "php8.3-fpm"]);

        let rhel = names(Family::Rhel, PhpVersion::V83, &[]);
        assert_eq!(rhel, vec!["php83-php-cli", "php83-php-fpm"]);
    }

    #[test]
    fn the_default_extension_set_installs_on_both_families() {
        for family in [Family::Debian, Family::Rhel] {
            for &version in PhpVersion::ALL {
                let packages = packages_for(family, version, PhpExt::DEFAULT).unwrap();
                assert!(
                    packages.len() >= 2,
                    "{family:?} {version} produced {packages:?}"
                );
                // Every generated name must survive the panel's own validation:
                // these become arguments to a program running as root.
                for p in &packages {
                    assert!(PackageName::parse(p.as_str()).is_ok(), "{p}");
                }
            }
        }
    }

    #[test]
    fn every_known_extension_resolves_or_is_deliberately_bundled() {
        for family in [Family::Debian, Family::Rhel] {
            for &ext in PhpExt::ALL {
                match ext.package(family, PhpVersion::V83) {
                    Some(name) => assert!(
                        PackageName::parse(&name).is_ok(),
                        "{ext:?} on {family:?} produced an invalid package name `{name}`"
                    ),
                    // Only the two we know are bundled elsewhere.
                    None => assert!(
                        matches!(ext, PhpExt::Curl | PhpExt::Xsl) && family == Family::Rhel,
                        "{ext:?} on {family:?} resolves to nothing and is not a documented case"
                    ),
                }
            }
        }
    }

    #[test]
    fn duplicate_extensions_collapse_to_one_package() {
        let list = names(
            Family::Rhel,
            PhpVersion::V83,
            &[PhpExt::Curl, PhpExt::Curl, PhpExt::Gd, PhpExt::Gd],
        );
        assert_eq!(list.iter().filter(|n| n.contains("gd")).count(), 1);
    }

    #[test]
    fn the_fpm_unit_and_package_names_agree() {
        use unihelm_distro::svc::ManagedUnit;
        for family in [Family::Debian, Family::Rhel] {
            for &version in PhpVersion::ALL {
                let package = fpm_package(family, version).unwrap();
                let unit = ManagedUnit::PhpFpm { version }.unit_name(family);
                // The unit is the package name plus `.service` on both families.
                assert_eq!(
                    unit.as_str(),
                    format!("{}.service", package.as_str()),
                    "{family:?} {version}: package `{package}` does not match unit `{unit}`"
                );
            }
        }
    }
}
