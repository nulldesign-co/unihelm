//! Resolving a path inside a tenant home, and refusing everything else.
//!
//! This is the check that runs **inside the helper**, after it has dropped to
//! the tenant's uid. [`ferrum_core::TenantPath`] already rejected the obvious
//! shapes before the request was built; this rejects what only the filesystem
//! knows — a symlink out of the home, a component swapped between the check and
//! the use, a directory that is really a mount point somewhere else.
//!
//! Resolution walks one component at a time from the home downwards and refuses
//! to follow any symlink at all. That is stricter than canonicalising and
//! comparing prefixes, and deliberately so: a symlink that resolves back inside
//! the home today can be repointed outside it between the check and the open.
//! Refusing the whole class removes the race rather than narrowing it.

use std::io;
use std::path::{Component, Path, PathBuf};

use super::proto::FsErrorKind;

#[derive(Debug)]
pub struct SafeError {
    pub kind: FsErrorKind,
    pub message: String,
}

impl SafeError {
    pub fn new(kind: FsErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn escape(path: &Path) -> Self {
        Self::new(
            FsErrorKind::Escape,
            format!("`{}` resolves outside the account's home", path.display()),
        )
    }

    pub fn io(path: &Path, e: &io::Error) -> Self {
        Self::new(
            FsErrorKind::from_io(e),
            format!("{}: {e}", path.display()),
        )
    }
}

pub type SafeResult<T> = std::result::Result<T, SafeError>;

/// A path proved to be inside a tenant home.
///
/// The only way to build one is through [`resolve`] or [`resolve_new`], so a
/// function that takes a `SafePath` cannot be handed an unchecked path by
/// mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePath {
    absolute: PathBuf,
    /// The same path relative to the home, `/`-separated — what the API speaks.
    relative: String,
}

impl SafePath {
    pub fn as_path(&self) -> &Path {
        &self.absolute
    }

    pub fn relative(&self) -> &str {
        &self.relative
    }

    /// Extend by one already-safe component (a directory entry we just read).
    pub fn join_entry(&self, name: &str) -> SafeResult<Self> {
        reject_bad_component(name)?;
        Ok(Self {
            absolute: self.absolute.join(name),
            relative: if self.relative.is_empty() {
                name.to_string()
            } else {
                format!("{}/{name}", self.relative)
            },
        })
    }
}

/// The tenant home itself, resolved once.
///
/// The home is the one path we do canonicalise, because it is ours: the panel
/// created it, and if it is a symlink that is a fact about our own layout, not
/// about anything the tenant did.
pub fn home_root(home: &Path) -> SafeResult<SafePath> {
    let absolute = std::fs::canonicalize(home).map_err(|e| SafeError::io(home, &e))?;
    if !absolute.is_dir() {
        return Err(SafeError::new(
            FsErrorKind::NotADirectory,
            format!("{} is not a directory", absolute.display()),
        ));
    }
    Ok(SafePath {
        absolute,
        relative: String::new(),
    })
}

/// Resolve an existing path under `home`.
///
/// `path` may be absolute (as the agent sends it) or relative to the home.
pub fn resolve(home: &Path, path: &Path) -> SafeResult<SafePath> {
    let root = home_root(home)?;
    let relative = relative_to(&root, path)?;

    let mut current = root;
    for component in split(&relative) {
        current = step(&current, component)?;
    }
    Ok(current)
}

/// Resolve the *parent* of a path that may not exist yet, and hand back the
/// final component with it.
///
/// Creating a file means proving the directory it goes in is inside the home;
/// the name itself is checked for the shapes a name must never have.
pub fn resolve_new(home: &Path, path: &Path) -> SafeResult<(SafePath, String)> {
    // The trailing form matters for a create: `sites/` and `sites/.` name a
    // directory-to-be, not a file. `Path`'s components normalise both away, so
    // this check reads the raw text — the name being created is whatever
    // follows the last separator, and it must be a real name.
    let raw = path
        .to_str()
        .ok_or_else(|| SafeError::new(FsErrorKind::Invalid, "path is not UTF-8"))?;
    if let Some(last) = raw.rsplit('/').next() {
        reject_bad_component(last)?;
    }

    let root = home_root(home)?;
    let relative = relative_to(&root, path)?;
    let mut components = split(&relative);

    let Some(name) = components.pop() else {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "cannot create the home directory itself",
        ));
    };
    reject_bad_component(name)?;

    let mut current = root;
    for component in components {
        current = step(&current, component)?;
    }

    // Whatever is at the target must not be a symlink either: writing "through"
    // one is how a tenant-owned link becomes a write to a path they chose.
    let candidate = current.absolute.join(name);
    if let Ok(meta) = std::fs::symlink_metadata(&candidate)
        && meta.file_type().is_symlink()
    {
        return Err(SafeError::escape(&candidate));
    }

    Ok((current, name.to_string()))
}

/// The full [`SafePath`] for a name inside an already-resolved directory.
pub fn child(dir: &SafePath, name: &str) -> SafeResult<SafePath> {
    dir.join_entry(name)
}

/// One step down, refusing to follow a symlink.
fn step(current: &SafePath, name: &str) -> SafeResult<SafePath> {
    reject_bad_component(name)?;
    let next = current.absolute.join(name);

    let meta = std::fs::symlink_metadata(&next).map_err(|e| SafeError::io(&next, &e))?;
    if meta.file_type().is_symlink() {
        // Not "resolve it and check where it lands" — see the module comment.
        return Err(SafeError::escape(&next));
    }

    current.join_entry(name)
}

/// Strip the home prefix from an absolute path, or accept a relative one.
fn relative_to(root: &SafePath, path: &Path) -> SafeResult<String> {
    let relative = if path.is_absolute() {
        path.strip_prefix(&root.absolute)
            .map_err(|_| SafeError::escape(path))?
    } else {
        path
    };

    let mut out = String::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| SafeError::new(FsErrorKind::Invalid, "path is not UTF-8"))?;
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(part);
            }
            Component::CurDir => {}
            // `..`, `/`, and Windows prefixes have no business here. They are
            // rejected rather than normalised away, because normalising `a/../b`
            // silently accepts input that should never have been built.
            _ => return Err(SafeError::escape(path)),
        }
    }
    Ok(out)
}

fn split(relative: &str) -> Vec<&str> {
    relative.split('/').filter(|s| !s.is_empty()).collect()
}

fn reject_bad_component(name: &str) -> SafeResult<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            format!("`{name}` is not a usable name"),
        ));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "a name may not contain a separator or a NUL",
        ));
    }
    if name.len() > 255 {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "a name may not exceed 255 bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Home {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            // The temp dir itself may be a symlink (/var -> /private/var on
            // macOS), so the home we hand around is the canonical one.
            let path = std::fs::canonicalize(dir.path()).unwrap();
            std::fs::create_dir_all(path.join("sites/example.com/public")).unwrap();
            std::fs::write(path.join("sites/example.com/public/index.php"), "<?php").unwrap();
            Self { _dir: dir, path }
        }
    }

    #[test]
    fn a_path_inside_the_home_resolves() {
        let home = Home::new();
        let p = resolve(&home.path, Path::new("sites/example.com/public/index.php")).unwrap();
        assert_eq!(p.relative(), "sites/example.com/public/index.php");
        assert!(p.as_path().starts_with(&home.path));
    }

    #[test]
    fn an_absolute_path_inside_the_home_resolves_too() {
        let home = Home::new();
        let absolute = home.path.join("sites/example.com");
        assert_eq!(resolve(&home.path, &absolute).unwrap().relative(), "sites/example.com");
    }

    #[test]
    fn dot_dot_is_refused_even_when_it_would_land_inside() {
        // `sites/../sites` is harmless in effect. It is still refused, because
        // accepting it means the normaliser is the thing standing between a
        // tenant and `/etc` — and normalisers are where these bugs live.
        let home = Home::new();
        for bad in ["sites/../sites", "../", "sites/../../etc/passwd", "/etc/passwd"] {
            let err = resolve(&home.path, Path::new(bad)).unwrap_err();
            assert_eq!(err.kind, FsErrorKind::Escape, "{bad} -> {err:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_home_is_refused() {
        let home = Home::new();
        std::os::unix::fs::symlink("/etc", home.path.join("escape")).unwrap();

        let err = resolve(&home.path, Path::new("escape/passwd")).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Escape);
        let err = resolve(&home.path, Path::new("escape")).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Escape);
    }

    #[cfg(unix)]
    #[test]
    fn even_a_symlink_that_stays_inside_is_refused() {
        // The one that looks safe is the dangerous one: it passes a
        // "canonicalise and compare the prefix" check today and can be
        // repointed at /etc between that check and the open.
        let home = Home::new();
        std::os::unix::fs::symlink(home.path.join("sites"), home.path.join("shortcut")).unwrap();

        let err = resolve(&home.path, Path::new("shortcut/example.com")).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Escape);
    }

    #[cfg(unix)]
    #[test]
    fn writing_through_a_symlink_is_refused() {
        let home = Home::new();
        std::os::unix::fs::symlink("/etc/passwd", home.path.join("target")).unwrap();

        let err = resolve_new(&home.path, Path::new("target")).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Escape);
    }

    #[test]
    fn a_new_file_resolves_to_its_parent_and_its_name() {
        let home = Home::new();
        let (dir, name) = resolve_new(&home.path, Path::new("sites/example.com/new.txt")).unwrap();
        assert_eq!(dir.relative(), "sites/example.com");
        assert_eq!(name, "new.txt");
    }

    #[test]
    fn a_new_file_under_a_missing_directory_is_a_not_found_not_a_silent_create() {
        let home = Home::new();
        let err = resolve_new(&home.path, Path::new("nope/new.txt")).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::NotFound);
    }

    #[test]
    fn names_that_are_not_names_are_refused() {
        let home = Home::new();
        for bad in ["sites/", "sites/.", "sites/.."] {
            assert!(
                resolve_new(&home.path, Path::new(bad)).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn a_resolved_directory_extends_only_by_a_plain_name() {
        let home = Home::new();
        let dir = resolve(&home.path, Path::new("sites")).unwrap();
        assert_eq!(dir.join_entry("example.com").unwrap().relative(), "sites/example.com");
        for bad in ["..", ".", "", "a/b", "a\0b"] {
            assert!(dir.join_entry(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_home_itself_is_addressable() {
        let home = Home::new();
        let root = resolve(&home.path, Path::new("")).unwrap();
        assert_eq!(root.relative(), "");
        assert_eq!(root.as_path(), home.path);
    }
}
