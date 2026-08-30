//! The child side of a web terminal — everything here runs *after* the
//! privilege drop, or as root for an admin session (spec §11.16, §5.2 rule 3).
//!
//! `unihelm-agentd --pty-helper` re-execs the agent binary, and `main.rs` calls
//! the same `drop_privileges` the file-manager and WordPress helpers use —
//! including its `setuid(0)`-must-fail proof — before anything in this module
//! runs. Then [`run`] replaces the process with the login shell.
//!
//! # Why the shell path is checked twice
//!
//! [`super::vet_shell`] already refused anything outside the allowlist on the
//! agent side. It is checked again here because *this* is the process boundary
//! where privilege changed: a bug on the agent side that let an arbitrary path
//! through would otherwise be arbitrary code execution as root. Two copies of a
//! check that must never fail is the correct number when one of them sits on a
//! trust boundary — the same reasoning `wordpress::helper::check_argv` gives.
//!
//! # The environment is built, not inherited
//!
//! The parent re-execs with a cleared environment, and this module hands
//! `execve` an explicit `envp`. Nothing the agent happens to have in its own
//! environment — a proxy variable, a `LD_*` left by an operator's shell —
//! reaches a tenant's terminal, and nothing a tenant sets can reach back.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Exit code for a helper that could not start a shell at all, chosen to sit
/// outside the range a shell itself uses (0-127 for exits, 128+n for signals).
pub const HELPER_FAILED: i32 = 121;

/// A terminal type every curses application understands, and colour.
const TERM: &str = "xterm-256color";

/// The `PATH` a session starts with.
///
/// Fixed rather than inherited: the agent's own `PATH` is not a tenant's
/// business, and an empty `PATH` produces a shell where nothing works.
const PATH_ENV: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Replace this process with the login shell. Only returns on failure.
///
/// `home` and `shell` come from the agent's argv, already validated there;
/// `shell` is validated again here.
pub fn run(home: &Path, shell: &Path) -> i32 {
    if let Err(e) = super::vet_shell(shell) {
        eprintln!("pty-helper: {}", e.detail);
        return HELPER_FAILED;
    }

    // A home that has gone missing must not cost the operator their shell: land
    // in `/` and say so, rather than refusing to start.
    if std::env::set_current_dir(home).is_err() {
        eprintln!(
            "pty-helper: {} is not reachable; starting in /",
            home.display()
        );
        let _ = std::env::set_current_dir("/");
    }

    let account = current_account();
    let envp = environment(&account, home, shell);

    // argv[0] with a leading `-` is the POSIX convention for "this is a login
    // shell": it makes bash read the profile files, which is what gives a
    // tenant their own aliases and prompt.
    let argv0 = format!("-{}", basename(shell));

    let c_shell = match CString::new(shell.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("pty-helper: the shell path contains a NUL byte");
            return HELPER_FAILED;
        }
    };
    let c_argv0 = match CString::new(argv0) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("pty-helper: the shell name contains a NUL byte");
            return HELPER_FAILED;
        }
    };

    let argv: [*const libc::c_char; 2] = [c_argv0.as_ptr(), std::ptr::null()];
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    // SAFETY: `execve` replaces the process image. Both arrays are
    // NULL-terminated and every pointer in them borrows a `CString` that is
    // still alive at the call. If it returns, it failed.
    unsafe {
        libc::execve(c_shell.as_ptr(), argv.as_ptr(), envp_ptrs.as_ptr());
    }

    eprintln!(
        "pty-helper: could not start {}: {}",
        shell.display(),
        std::io::Error::last_os_error()
    );
    HELPER_FAILED
}

/// The account this process actually runs as, read back from the system rather
/// than taken from the command line.
///
/// Reading it back is the point: after the drop, `geteuid` is the truth about
/// what this shell can do, and the `USER` a tenant sees should be that and not
/// what the agent believed it was passing.
fn current_account() -> String {
    // SAFETY: `geteuid` reads process state and cannot fail.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: `getpwuid` returns a pointer into a libc-owned static buffer; the
    // name is copied out immediately and a NULL return is handled.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

/// The explicit environment the shell starts with.
pub fn environment(account: &str, home: &Path, shell: &Path) -> Vec<CString> {
    let entries = [
        format!("HOME={}", home.display()),
        format!("USER={account}"),
        format!("LOGNAME={account}"),
        format!("SHELL={}", shell.display()),
        format!("TERM={TERM}"),
        format!("PATH={PATH_ENV}"),
        // UTF-8 by default: a terminal that mangles a tenant's Persian file
        // names is a bug report, and the panel ships with fa_IR anyway.
        "LANG=C.UTF-8".to_string(),
        // A breadcrumb in `env` output and in process listings, so somebody
        // looking at a live shell can tell where it came from.
        "UNIHELM_TERMINAL=1".to_string(),
    ];
    entries
        .into_iter()
        .filter_map(|e| CString::new(e).ok())
        .collect()
}

/// The last path component, for the login-shell `argv[0]`.
fn basename(path: &Path) -> String {
    path.file_name()
        .unwrap_or_else(|| OsStr::new("shell"))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_is_built_from_scratch_and_carries_no_inherited_variables() {
        // Whatever the agent's own environment holds must not appear here.
        let env = environment(
            "uh_demo",
            Path::new("/home/uh_demo"),
            Path::new("/bin/bash"),
        );
        let text: Vec<String> = env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();

        assert!(text.contains(&"USER=uh_demo".to_string()));
        assert!(text.contains(&"HOME=/home/uh_demo".to_string()));
        assert!(text.contains(&"SHELL=/bin/bash".to_string()));
        assert!(text.iter().any(|v| v.starts_with("TERM=")));
        assert!(text.iter().any(|v| v.starts_with("PATH=/usr/local/sbin")));
        assert!(
            !text.iter().any(|v| v.starts_with("LD_")),
            "no LD_* may reach a tenant's shell: {text:?}"
        );
        assert_eq!(
            text.len(),
            8,
            "the environment is a fixed list; a new entry needs a reason: {text:?}"
        );
    }

    #[test]
    fn the_shell_starts_as_a_login_shell() {
        // `-bash`, not `bash`: the leading dash is what makes bash read the
        // profile files, and a terminal without a tenant's own prompt and
        // aliases is not the shell they expect.
        assert_eq!(format!("-{}", basename(Path::new("/bin/bash"))), "-bash");
        assert_eq!(format!("-{}", basename(Path::new("/usr/bin/zsh"))), "-zsh");
    }

    #[test]
    fn a_shell_outside_the_allowlist_is_refused_after_the_drop_as_well() {
        // The agent already refused this. The helper refuses it again because
        // this is the side of the trust boundary where privilege changed.
        assert!(super::super::vet_shell(Path::new("/tmp/payload")).is_err());
        assert!(super::super::vet_shell(Path::new("/usr/sbin/nologin")).is_err());
    }
}
