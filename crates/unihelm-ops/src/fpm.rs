//! Retiring the distribution's stock PHP-FPM pool.
//!
//! Both families ship a `www.conf` pool that runs as the web server's own user
//! (`apache` on Remi, `www-data` on Sury) with no `open_basedir`. On a live
//! AlmaLinux box the panel installed PHP 8.3, created a properly isolated pool
//! for the tenant — and left five `pool www` workers running as `apache`
//! alongside it.
//!
//! Two reasons that has to go, in increasing order of seriousness:
//!
//! 1. Five idle workers is 150 MB on a machine where the whole panel is
//!    budgeted 50 MB (spec §13).
//! 2. It is a tenant-isolation hole one config mistake wide. Remi's pool socket
//!    is reachable by nginx by design, so a vhost pointed at the wrong socket —
//!    by a bug, by a hand edit, by an imported config — runs that tenant's PHP
//!    as `apache`, outside their `open_basedir`, with read access to every
//!    other tenant's files. The panel's isolation story is only as good as the
//!    absence of a second, unisolated way in.
//!
//! The stock file is moved aside rather than edited: `paths` is explicit that
//! Unihelm never edits a distro's own config, and a rename is something an
//! operator can undo with one `mv`. An operator who wants the pool back can say
//! so in the file itself — see [`KEEP_MARKER`].

use std::path::{Path, PathBuf};

use unihelm_config::paths;
use unihelm_core::{PhpVersion, Result, UnihelmError};
use unihelm_distro::Family;

use crate::registry::OpContext;
use unihelm_config::apply::Reloader;

/// The suffix we move the stock pool to. PHP-FPM only reads `*.conf`, so a file
/// ending in anything else is inert while staying exactly where the operator
/// would look for it.
const DISABLED_SUFFIX: &str = ".unihelm-disabled";

/// An operator who genuinely wants the stock pool puts this anywhere in
/// `www.conf` and Unihelm leaves it alone from then on.
///
/// It lives in the file rather than in the panel's settings because that is
/// where the next person to wonder "why is there a pool running as apache" will
/// be looking.
pub const KEEP_MARKER: &str = "unihelm: keep";

/// What we did, so the caller can log something true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockPool {
    /// There was no stock pool to begin with.
    Absent,
    /// Moved aside just now.
    Retired,
    /// A package upgrade put it back; removed, because the copy we took the
    /// first time is still there.
    RemovedDuplicate,
    /// The operator asked us to leave it.
    KeptOnRequest,
    /// Left in place because it is the only pool there is.
    ///
    /// FPM refuses to start with no pool at all, so retiring the last one does
    /// not harden a server — it takes every PHP site on it offline. On a machine
    /// where PHP was serving sites before the panel arrived, that is exactly what
    /// happened: `www.conf` moved aside, `php-fpm` failed with "No pool defined",
    /// and the sites answered 502.
    KeptAsOnlyPool,
}

/// Where the distribution's stock pool lives for a PHP version.
pub fn stock_pool_path(family: Family, version: PhpVersion) -> PathBuf {
    paths::fpm_pool_dir(family, version).join("www.conf")
}

/// Move the stock pool out of the way, if it is there and wanted gone.
///
/// Idempotent, and safe to call on every install and every site creation: a
/// package upgrade restores `www.conf`, so "we did this once at install time"
/// is not a state that stays true.
pub fn retire_stock_pool(family: Family, version: PhpVersion) -> Result<StockPool> {
    retire_stock_pool_in(&paths::fpm_pool_dir(family, version))
}

/// The same, against an explicit pool directory.
///
/// Split out so the tests can work in a temporary directory: `paths::set_root`
/// is a process-wide `OnceLock`, which a parallel test binary cannot use to give
/// each test its own tree.
pub fn retire_stock_pool_in(pool_dir: &Path) -> Result<StockPool> {
    let stock = pool_dir.join("www.conf");
    let disabled = pool_dir.join(format!("www.conf{DISABLED_SUFFIX}"));

    if !stock.exists() {
        return Ok(StockPool::Absent);
    }

    if pool_is_marked_keep(&stock) {
        return Ok(StockPool::KeptOnRequest);
    }

    // Never leave FPM with nothing to run.
    //
    // The point of retiring the stock pool is that it runs as the web server
    // user with no open_basedir, and every site Unihelm creates gets its own
    // pool instead. Until at least one of those exists, moving this one aside
    // stops FPM dead — and a stopped FPM is not a hardened server, it is a
    // server whose PHP sites all return 502. It is retired on the next site
    // creation, which is when there is something to take over from it.
    if !another_pool_exists(pool_dir) {
        return Ok(StockPool::KeptAsOnlyPool);
    }

    if disabled.exists() {
        // A copy is already preserved. The file that just reappeared is the
        // package's pristine default — rpm and dpkg leave a `.rpmnew`/`.dpkg-dist`
        // instead of overwriting anything an admin edited, so nothing of theirs
        // is in this one.
        std::fs::remove_file(&stock).map_err(|e| {
            UnihelmError::internal(format!(
                "could not remove the restored stock pool {}: {e}",
                stock.display()
            ))
        })?;
        return Ok(StockPool::RemovedDuplicate);
    }

    std::fs::rename(&stock, &disabled).map_err(|e| {
        UnihelmError::internal(format!(
            "could not move the stock pool {} aside: {e}",
            stock.display()
        ))
    })?;
    Ok(StockPool::Retired)
}

/// Whether any pool other than the stock `www.conf` is configured.
///
/// FPM includes `*.conf` from the pool directory, so that glob is the question:
/// a `.unihelm-disabled` file is not matched by it and does not count.
fn another_pool_exists(pool_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(pool_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let path = e.path();
        path.extension().is_some_and(|x| x == "conf")
            && path.file_name().is_some_and(|n| n != "www.conf")
    })
}

fn pool_is_marked_keep(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains(KEEP_MARKER))
        .unwrap_or(false)
}

impl StockPool {
    /// Did this change the config on disk?
    ///
    /// The answer decides whether FPM has to be told. Removing a pool file
    /// changes nothing until the master process re-reads its config: on the live
    /// box the file went away and five workers kept running as `apache`, because
    /// the site's own pool was unchanged and so the config engine — correctly —
    /// skipped the reload. Same shape as the nginx certificate bug: the thing
    /// that changed was not the thing being watched.
    pub const fn changed_disk(self) -> bool {
        matches!(self, StockPool::Retired | StockPool::RemovedDuplicate)
    }
}

/// Retire the stock pool, say what happened in the task log, and reload FPM if
/// anything actually moved.
///
/// Never fatal: a stock pool we could not move is a wasted 150 MB and a latent
/// isolation risk, both of which are worth a loud line in the log and neither of
/// which is worth failing an otherwise-good PHP install over.
pub async fn retire_and_log(ctx: &OpContext, version: PhpVersion) {
    let distro = ctx.distro();
    let family = distro.info.family;
    let php = version.as_str();

    let outcome = retire_stock_pool(family, version);
    match &outcome {
        Ok(StockPool::Absent) => return,
        Ok(StockPool::Retired) => ctx.log(format!(
            "disabled the stock PHP {php} `www` pool (it runs as the web server \
             user with no open_basedir); moved to www.conf{DISABLED_SUFFIX}"
        )),
        Ok(StockPool::RemovedDuplicate) => ctx.log(format!(
            "a package upgrade restored the stock PHP {php} `www` pool; removed \
             it again (the original is still at www.conf{DISABLED_SUFFIX})"
        )),
        Ok(StockPool::KeptAsOnlyPool) => {
            ctx.log(format!(
                "leaving the stock PHP {php} `www` pool in place — it is the only \
                 pool configured, and FPM will not start without one. It runs as \
                 the web server user without open_basedir, so anything served \
                 through it is not isolated; it is retired automatically once a \
                 site of your own has a pool to take over from it."
            ));
            return;
        }
        Ok(StockPool::KeptOnRequest) => {
            ctx.log(format!(
                "leaving the stock PHP {php} `www` pool alone — it is marked \
                 `{KEEP_MARKER}`. It runs as the web server user without \
                 open_basedir, so nothing served through it is isolated."
            ));
            return;
        }
        Err(e) => {
            ctx.log(format!(
                "could not disable the stock PHP {php} `www` pool: {e}. It runs \
                 as the web server user without open_basedir; disable it by hand."
            ));
            return;
        }
    }

    if !outcome.map(StockPool::changed_disk).unwrap_or(false) {
        return;
    }

    match crate::services::UnitReloader::fpm(distro, version)
        .reload()
        .await
    {
        Ok(()) => ctx.log(format!(
            "reloaded PHP {php} FPM; the `www` workers are gone"
        )),
        Err(e) => ctx.log(format!(
            "moved the stock PHP {php} pool aside but could not reload FPM ({e}); \
             its workers keep running until the next restart"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pool {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Pool {
        /// A pool directory that already holds a site's own pool.
        ///
        /// Which is the state every one of these tests means: the stock pool is
        /// only retired when something else can serve, because FPM will not
        /// start with no pool at all. `bare()` is for the tests about *that*.
        fn new() -> Self {
            let pool = Self::bare();
            std::fs::write(pool.path.join("uh_tenant.conf"), "[uh_tenant]\n").unwrap();
            pool
        }

        /// Nothing but whatever the test writes itself.
        fn bare() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().to_path_buf();
            Self { _dir: dir, path }
        }

        fn stock(&self) -> PathBuf {
            self.path.join("www.conf")
        }

        fn disabled(&self) -> PathBuf {
            self.path.join(format!("www.conf{DISABLED_SUFFIX}"))
        }

        fn write_stock(&self, body: &str) {
            std::fs::write(self.stock(), body).unwrap();
        }

        fn retire(&self) -> StockPool {
            retire_stock_pool_in(&self.path).unwrap()
        }
    }

    #[test]
    fn a_stock_pool_is_moved_aside_and_the_move_is_reversible() {
        let pool = Pool::new();
        pool.write_stock("[www]\nuser = apache\n");

        assert_eq!(pool.retire(), StockPool::Retired);
        assert!(!pool.stock().exists());

        // Still there, still readable, still exactly what it was — one `mv` from
        // being back.
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "[www]\nuser = apache\n"
        );
    }

    #[test]
    fn running_twice_is_not_an_error_and_does_not_lose_the_backup() {
        let pool = Pool::new();
        pool.write_stock("original\n");
        pool.retire();

        assert_eq!(pool.retire(), StockPool::Absent);
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn a_pool_restored_by_a_package_upgrade_is_retired_again() {
        // The reason this runs on every site creation and not once at install:
        // `dnf upgrade php83-php-fpm` puts www.conf back, and five workers as
        // `apache` reappear with it.
        let pool = Pool::new();
        pool.write_stock("original\n");
        pool.retire();

        pool.write_stock("pristine default from the package\n");
        assert_eq!(pool.retire(), StockPool::RemovedDuplicate);
        assert!(!pool.stock().exists());
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "original\n",
            "the first copy is the one that might carry an operator's edits"
        );
    }

    #[test]
    fn an_operator_can_ask_for_the_stock_pool_to_be_left_alone() {
        let pool = Pool::new();
        pool.write_stock("[www]\n; unihelm: keep - I need this\n");

        assert_eq!(pool.retire(), StockPool::KeptOnRequest);
        assert!(pool.stock().exists(), "an explicit opt-out must survive");
        // And it stays opted out, however many times we look at it.
        assert_eq!(pool.retire(), StockPool::KeptOnRequest);
    }

    #[test]
    fn a_system_that_never_had_one_is_not_a_failure() {
        let pool = Pool::new();
        assert_eq!(pool.retire(), StockPool::Absent);
    }

    #[test]
    fn the_real_path_is_the_one_php_fpm_reads() {
        // A typo here would move nothing and report success.
        assert!(
            stock_pool_path(Family::Rhel, PhpVersion::V83)
                .ends_with("etc/opt/remi/php83/php-fpm.d/www.conf"),
            "{:?}",
            stock_pool_path(Family::Rhel, PhpVersion::V83)
        );
        assert!(
            stock_pool_path(Family::Debian, PhpVersion::V83)
                .ends_with("etc/php/8.3/fpm/pool.d/www.conf"),
            "{:?}",
            stock_pool_path(Family::Debian, PhpVersion::V83)
        );
    }
}
#[cfg(test)]
mod only_pool_tests {
    use super::*;

    fn pool_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// The stock pool is the only one: leave it.
    ///
    /// This is a live server that had PHP before the panel arrived. Retiring
    /// `www.conf` left FPM with no pool at all, so it failed to start with "No
    /// pool defined" and every PHP site on the machine answered 502. A stopped
    /// FPM is not a hardened server.
    #[test]
    fn the_last_pool_is_never_retired() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::KeptAsOnlyPool
        );
        assert!(
            dir.path().join("www.conf").exists(),
            "the only pool was moved aside; FPM cannot start"
        );
    }

    /// Once a site has a pool of its own, the stock one goes as designed.
    #[test]
    fn the_stock_pool_retires_once_something_can_take_over() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();
        std::fs::write(dir.path().join("uh_abc123.conf"), "[uh_abc123]\n").unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::Retired
        );
        assert!(!dir.path().join("www.conf").exists());
        assert!(
            dir.path()
                .join(format!("www.conf{DISABLED_SUFFIX}"))
                .exists()
        );
    }

    /// An already-disabled copy is not a pool FPM can run, so it does not count
    /// as "something else is configured".
    #[test]
    fn a_disabled_copy_does_not_count_as_another_pool() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();
        std::fs::write(
            dir.path().join(format!("old.conf{DISABLED_SUFFIX}")),
            "[old]\n",
        )
        .unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::KeptAsOnlyPool,
            "FPM does not include .unihelm-disabled files"
        );
    }
}
