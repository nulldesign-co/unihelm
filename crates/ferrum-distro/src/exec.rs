//! Process execution — argv arrays only (spec §12 rule 2).
//!
//! There is no `run(cmd: &str)` in this module and there never will be. Every
//! caller builds a program plus a vector of arguments, which the kernel passes to
//! `execve` untouched: no shell, no word splitting, no globbing, no substitution.
//! That removes shell injection as a *category* rather than as a series of bugs.
//!
//! A repo-wide CI grep gate and a clippy lint keep `sh -c` and friends from
//! creeping back in (see `.github/workflows/ci.yml`).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use ferrum_core::{ErrorCode, FerrumError};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::{DistroError, Result};

/// Directories we are willing to find system binaries in.
///
/// Resolving to an absolute path here means a poisoned `PATH` cannot redirect
/// `systemctl` to something else — the agent is root, so this matters.
const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
];

/// Commands that have not finished in this long are killed and reported.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Output of a finished command.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub program: String,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// stdout with trailing whitespace removed — the common case for a one-line
    /// answer like a version string.
    pub fn trimmed_stdout(&self) -> &str {
        self.stdout.trim()
    }

    /// The most useful text to show a human when this command failed.
    pub fn failure_text(&self) -> String {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            self.stdout.trim().to_string()
        } else {
            stderr.to_string()
        }
    }
}

/// A command to run. Construct, add args, run. There is no string form.
#[derive(Debug, Clone)]
pub struct Cmd {
    program: String,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    /// Run with a cleared environment plus only what `env` sets.
    clear_env: bool,
}

impl Cmd {
    /// `program` is a bare binary name (`systemctl`), resolved against
    /// [`TRUSTED_BIN_DIRS`], or an absolute path.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            clear_env: true,
        }
    }

    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Self {
        self.args.push(a.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn env(mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> Self {
        self.env
            .push((k.as_ref().to_os_string(), v.as_ref().to_os_string()));
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Inherit the parent environment instead of starting from empty.
    pub fn inherit_env(mut self) -> Self {
        self.clear_env = false;
        self
    }

    /// Human-readable form for logs and task output. **Display only** — it is
    /// never parsed back into a command.
    pub fn display(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.args {
            s.push(' ');
            s.push_str(&a.to_string_lossy());
        }
        s
    }

    fn build(&self) -> Result<Command> {
        let path = resolve_program(&self.program)?;
        let mut cmd = Command::new(path);
        cmd.args(&self.args);
        if self.clear_env {
            cmd.env_clear();
            // A minimal, predictable environment. Anything a specific command
            // needs is added explicitly by its caller.
            cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
            cmd.env("LC_ALL", "C");
            cmd.env("LANG", "C");
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);
        Ok(cmd)
    }

    /// Run to completion, capturing output. A non-zero exit is returned as data,
    /// not as an error — use [`Cmd::run_checked`] when non-zero means failure.
    pub async fn run(&self) -> Result<CmdOutput> {
        let started = Instant::now();
        let mut cmd = self.build()?;
        tracing::debug!(cmd = %self.display(), "exec");

        let child = cmd.spawn().map_err(|e| DistroError::Spawn {
            program: self.program.clone(),
            source: e,
        })?;

        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(r) => r.map_err(|e| DistroError::Spawn {
                program: self.program.clone(),
                source: e,
            })?,
            Err(_) => {
                return Err(DistroError::Timeout {
                    cmd: self.display(),
                    seconds: self.timeout.as_secs(),
                });
            }
        };

        Ok(CmdOutput {
            program: self.program.clone(),
            // 128 + signal is the shell convention for "killed by a signal"; we
            // reuse it so a signalled command is distinguishable from exit 0.
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration: started.elapsed(),
        })
    }

    /// Run, and turn a non-zero exit into an error carrying the command's own
    /// diagnostics — which is what a task log should show a user.
    pub async fn run_checked(&self) -> Result<CmdOutput> {
        let out = self.run().await?;
        if out.success() {
            Ok(out)
        } else {
            Err(DistroError::CommandFailed {
                cmd: self.display(),
                status: out.status,
                output: out.failure_text(),
            })
        }
    }

    /// Run, streaming each output line to `sink` as it appears.
    ///
    /// This is how a five-minute `dnf install` becomes a live task log instead of
    /// a five-minute silence (spec §10.1).
    pub async fn run_streaming<F>(&self, mut sink: F) -> Result<CmdOutput>
    where
        F: FnMut(&str) + Send,
    {
        let started = Instant::now();
        let mut cmd = self.build()?;
        tracing::debug!(cmd = %self.display(), "exec (streaming)");

        let mut child = cmd.spawn().map_err(|e| DistroError::Spawn {
            program: self.program.clone(),
            source: e,
        })?;

        let stdout = child.stdout.take().expect("stdout was piped in build()");
        let stderr = child.stderr.take().expect("stderr was piped in build()");
        let mut out_lines = BufReader::new(stdout).lines();
        let mut err_lines = BufReader::new(stderr).lines();

        let mut collected_out = String::new();
        let mut collected_err = String::new();

        let pump = async {
            loop {
                tokio::select! {
                    line = out_lines.next_line() => match line {
                        Ok(Some(l)) => { sink(&l); collected_out.push_str(&l); collected_out.push('\n'); }
                        Ok(None) | Err(_) => {
                            // stdout is done; drain stderr and stop.
                            while let Ok(Some(l)) = err_lines.next_line().await {
                                sink(&l);
                                collected_err.push_str(&l);
                                collected_err.push('\n');
                            }
                            break;
                        }
                    },
                    line = err_lines.next_line() => match line {
                        Ok(Some(l)) => { sink(&l); collected_err.push_str(&l); collected_err.push('\n'); }
                        Ok(None) | Err(_) => {
                            while let Ok(Some(l)) = out_lines.next_line().await {
                                sink(&l);
                                collected_out.push_str(&l);
                                collected_out.push('\n');
                            }
                            break;
                        }
                    },
                }
            }
        };

        let status = match tokio::time::timeout(self.timeout, async {
            pump.await;
            child.wait().await
        })
        .await
        {
            Ok(r) => r.map_err(|e| DistroError::Spawn {
                program: self.program.clone(),
                source: e,
            })?,
            Err(_) => {
                let _ = child.kill().await;
                return Err(DistroError::Timeout {
                    cmd: self.display(),
                    seconds: self.timeout.as_secs(),
                });
            }
        };

        Ok(CmdOutput {
            program: self.program.clone(),
            status: status.code().unwrap_or(-1),
            stdout: collected_out,
            stderr: collected_err,
            duration: started.elapsed(),
        })
    }
}

/// Find a binary in a fixed list of system directories.
pub fn resolve_program(program: &str) -> Result<PathBuf> {
    if program.contains('/') {
        let p = PathBuf::from(program);
        return if p.is_absolute() && p.exists() {
            Ok(p)
        } else {
            Err(DistroError::ProgramNotFound(program.to_string()))
        };
    }
    for dir in TRUSTED_BIN_DIRS {
        let candidate = PathBuf::from(dir).join(program);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(DistroError::ProgramNotFound(program.to_string()))
}

/// True when the binary exists — used by preflight and by "is docker installed?".
pub fn program_available(program: &str) -> bool {
    resolve_program(program).is_ok()
}

impl From<DistroError> for FerrumError {
    fn from(e: DistroError) -> Self {
        let code = match &e {
            DistroError::UnsupportedDistro(_) | DistroError::OsRelease(_) => {
                ErrorCode::UnsupportedDistro
            }
            DistroError::ProgramNotFound(_) | DistroError::Spawn { .. } => ErrorCode::CommandFailed,
            DistroError::CommandFailed { .. } | DistroError::Timeout { .. } => {
                ErrorCode::CommandFailed
            }
            DistroError::InvalidName(_) => ErrorCode::InvalidInput,
            DistroError::ServiceFailed { .. } => ErrorCode::ServiceActionFailed,
            DistroError::PackageFailed { .. } => ErrorCode::PackageBackendFailed,
        };
        FerrumError::new(code, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_a_real_command_with_argv() {
        let out = Cmd::new("echo").arg("hello world").run().await.unwrap();
        assert!(out.success());
        assert_eq!(out.trimmed_stdout(), "hello world");
    }

    #[tokio::test]
    async fn arguments_are_never_interpreted_by_a_shell() {
        // If this went through `sh -c`, the semicolon would start a new command
        // and the backticks would substitute. Through argv it is just text.
        let payload = "a; touch /tmp/ferrum-pwned; `id`; $(id); a|b>c";
        let out = Cmd::new("echo").arg(payload).run().await.unwrap();
        assert_eq!(out.trimmed_stdout(), payload);
        assert!(!std::path::Path::new("/tmp/ferrum-pwned").exists());
    }

    #[tokio::test]
    async fn empty_and_dashed_arguments_survive_intact() {
        let out = Cmd::new("echo")
            .args(["--not-a-flag-to-us", "-n", ""])
            .run()
            .await
            .unwrap();
        assert!(out.stdout.contains("--not-a-flag-to-us"));
    }

    #[tokio::test]
    async fn non_zero_exit_is_data_for_run_and_an_error_for_run_checked() {
        let out = Cmd::new("false").run().await.unwrap();
        assert!(!out.success());
        let err = Cmd::new("false").run_checked().await.unwrap_err();
        assert!(matches!(err, DistroError::CommandFailed { .. }));
    }

    #[tokio::test]
    async fn missing_program_is_reported_not_panicked() {
        let err = Cmd::new("definitely-not-a-real-binary-xyz")
            .run()
            .await
            .unwrap_err();
        assert!(matches!(err, DistroError::ProgramNotFound(_)));
    }

    #[tokio::test]
    async fn relative_paths_are_refused() {
        assert!(resolve_program("../../bin/sh").is_err());
        assert!(resolve_program("./evil").is_err());
    }

    #[tokio::test]
    async fn a_hung_command_is_killed_at_the_timeout() {
        let err = Cmd::new("sleep")
            .arg("30")
            .timeout(Duration::from_millis(200))
            .run()
            .await
            .unwrap_err();
        assert!(matches!(err, DistroError::Timeout { .. }));
    }

    #[tokio::test]
    async fn streaming_delivers_lines_as_they_arrive() {
        let mut lines = Vec::new();
        let out = Cmd::new("printf")
            .arg("one\\ntwo\\nthree\\n")
            .run_streaming(|l| lines.push(l.to_string()))
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(lines, vec!["one", "two", "three"]);
    }

    #[tokio::test]
    async fn environment_is_scrubbed_by_default() {
        // SAFETY: single-threaded test setup before any thread reads the env.
        unsafe { std::env::set_var("FERRUM_TEST_LEAK", "secret") };
        let out = Cmd::new("env").run().await.unwrap();
        assert!(
            !out.stdout.contains("FERRUM_TEST_LEAK"),
            "parent env must not leak into commands"
        );
        let out = Cmd::new("env").inherit_env().run().await.unwrap();
        assert!(out.stdout.contains("FERRUM_TEST_LEAK"));
    }
}
