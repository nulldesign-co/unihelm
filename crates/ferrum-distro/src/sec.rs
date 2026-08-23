//! SELinux / AppArmor (spec §7.4).
//!
//! The rule is short: **we never turn it off.** Panels that run `setenforce 0`
//! to make a feature work are trading their users' security for their own
//! convenience. The `SecModule` sets the minimal contexts, booleans and port
//! labels each feature actually needs, and a feature that cannot be made to work
//! under an enforcing policy is a bug to fix, not a policy to disable.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::detect::Family;
use crate::exec::{Cmd, program_available};
use crate::{DistroError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecModuleKind {
    Selinux,
    AppArmor,
    /// No LSM active — reported in the UI so an operator knows what they have.
    None,
}

/// The kinds of content the panel labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileContext {
    /// Files nginx serves: `httpd_sys_content_t`.
    WebContent,
    /// Directories a web app writes to: `httpd_sys_rw_content_t`.
    WebWritable,
    /// Panel state under `/var/lib/ferrum`.
    PanelState,
}

/// Ports the panel asks the LSM to allow a service to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortContext {
    /// `http_port_t` — nginx vhosts on a non-standard port.
    Http,
    /// The panel's own listener.
    Panel,
    /// A tenant Node.js app port.
    NodeApp,
}

#[async_trait]
pub trait SecModule: Send + Sync {
    fn kind(&self) -> SecModuleKind;

    /// Is the policy currently enforcing? Reported, never changed.
    async fn is_enforcing(&self) -> Result<bool>;

    /// Label a path so the relevant service may use it.
    async fn set_file_context(&self, path: &Path, context: FileContext) -> Result<()>;

    /// Allow a service to bind a port it would otherwise be denied.
    async fn allow_port(
        &self,
        port: u16,
        proto: crate::fw::Proto,
        context: PortContext,
    ) -> Result<()>;

    /// Flip a named policy boolean.
    async fn set_boolean(&self, name: &str, value: bool) -> Result<()>;
}

/// Pick the module that is actually present on this machine.
pub fn detect_sec_module(family: Family) -> Arc<dyn SecModule> {
    match family {
        Family::Rhel if program_available("getenforce") => Arc::new(SelinuxModule),
        Family::Debian if Path::new("/sys/kernel/security/apparmor").exists() => {
            Arc::new(AppArmorModule)
        }
        _ => Arc::new(NoopSecModule),
    }
}

pub struct SelinuxModule;

impl SelinuxModule {
    /// SELinux type for a content class.
    const fn file_type(context: FileContext) -> &'static str {
        match context {
            FileContext::WebContent => "httpd_sys_content_t",
            FileContext::WebWritable => "httpd_sys_rw_content_t",
            FileContext::PanelState => "var_lib_t",
        }
    }
}

#[async_trait]
impl SecModule for SelinuxModule {
    fn kind(&self) -> SecModuleKind {
        SecModuleKind::Selinux
    }

    async fn is_enforcing(&self) -> Result<bool> {
        let out = Cmd::new("getenforce").run().await?;
        Ok(out.trimmed_stdout().eq_ignore_ascii_case("enforcing"))
    }

    async fn set_file_context(&self, path: &Path, context: FileContext) -> Result<()> {
        let path_str = path.to_str().ok_or_else(|| {
            DistroError::InvalidName("path is not valid UTF-8 and cannot be labelled".into())
        })?;
        if !path.is_absolute() {
            return Err(DistroError::InvalidName(
                "file context paths must be absolute".into(),
            ));
        }

        // `semanage fcontext` records the rule; `restorecon` applies it. Doing
        // only the second is the classic mistake — the label then disappears on
        // the next relabel.
        let ty = Self::file_type(context);
        let pattern = format!("{}(/.*)?", path_str.trim_end_matches('/'));

        let add = Cmd::new("semanage")
            .args(["fcontext", "-a", "-t", ty, "--"])
            .arg(&pattern)
            .run()
            .await?;
        if !add.success() && !add.failure_text().contains("already defined") {
            return Err(DistroError::CommandFailed {
                cmd: "semanage fcontext -a".into(),
                status: add.status,
                output: add.failure_text(),
            });
        }

        Cmd::new("restorecon")
            .args(["-R", "-F", "--"])
            .arg(path_str)
            .run_checked()
            .await?;
        Ok(())
    }

    async fn allow_port(
        &self,
        port: u16,
        proto: crate::fw::Proto,
        context: PortContext,
    ) -> Result<()> {
        let ty = match context {
            PortContext::Http | PortContext::Panel => "http_port_t",
            PortContext::NodeApp => "http_port_t",
        };
        let out = Cmd::new("semanage")
            .args(["port", "-a", "-t", ty, "-p", proto.as_str()])
            .arg(port.to_string())
            .run()
            .await?;
        if out.success() || out.failure_text().contains("already defined") {
            return Ok(());
        }
        Err(DistroError::CommandFailed {
            cmd: "semanage port -a".into(),
            status: out.status,
            output: out.failure_text(),
        })
    }

    async fn set_boolean(&self, name: &str, value: bool) -> Result<()> {
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(DistroError::InvalidName(format!(
                "`{name}` is not a policy boolean name"
            )));
        }
        Cmd::new("setsebool")
            .arg("-P")
            .arg(name)
            .arg(if value { "on" } else { "off" })
            .run_checked()
            .await?;
        Ok(())
    }
}

pub struct AppArmorModule;

#[async_trait]
impl SecModule for AppArmorModule {
    fn kind(&self) -> SecModuleKind {
        SecModuleKind::AppArmor
    }

    async fn is_enforcing(&self) -> Result<bool> {
        // aa-status exits 0 when the module is loaded; the count of enforced
        // profiles is in its output.
        let out = Cmd::new("aa-status").arg("--enabled").run().await;
        Ok(out.map(|o| o.success()).unwrap_or(false))
    }

    async fn set_file_context(&self, _path: &Path, _context: FileContext) -> Result<()> {
        // AppArmor is path-based: there are no labels to set. Paths we hand to
        // nginx and php-fpm already sit under the prefixes the distro profiles
        // permit, so there is nothing to do rather than something to skip.
        Ok(())
    }

    async fn allow_port(
        &self,
        _port: u16,
        _proto: crate::fw::Proto,
        _context: PortContext,
    ) -> Result<()> {
        Ok(())
    }

    async fn set_boolean(&self, _name: &str, _value: bool) -> Result<()> {
        Ok(())
    }
}

/// Used when no LSM is active. Every method succeeds, and [`SecModuleKind::None`]
/// tells the security dashboard to say so out loud.
pub struct NoopSecModule;

#[async_trait]
impl SecModule for NoopSecModule {
    fn kind(&self) -> SecModuleKind {
        SecModuleKind::None
    }
    async fn is_enforcing(&self) -> Result<bool> {
        Ok(false)
    }
    async fn set_file_context(&self, _path: &Path, _context: FileContext) -> Result<()> {
        Ok(())
    }
    async fn allow_port(
        &self,
        _port: u16,
        _proto: crate::fw::Proto,
        _context: PortContext,
    ) -> Result<()> {
        Ok(())
    }
    async fn set_boolean(&self, _name: &str, _value: bool) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relative_paths_are_never_labelled() {
        let m = SelinuxModule;
        let err = m
            .set_file_context(Path::new("relative/path"), FileContext::WebContent)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn boolean_names_are_validated_before_reaching_setsebool() {
        let m = SelinuxModule;
        assert!(
            m.set_boolean("httpd unified; rm -rf /", true)
                .await
                .is_err()
        );
        assert!(m.set_boolean("../../x", true).await.is_err());
    }

    #[test]
    fn content_types_map_to_the_expected_selinux_labels() {
        assert_eq!(
            SelinuxModule::file_type(FileContext::WebContent),
            "httpd_sys_content_t"
        );
        assert_eq!(
            SelinuxModule::file_type(FileContext::WebWritable),
            "httpd_sys_rw_content_t"
        );
    }

    #[tokio::test]
    async fn noop_module_reports_that_nothing_is_enforcing() {
        let m = NoopSecModule;
        assert_eq!(m.kind(), SecModuleKind::None);
        assert!(!m.is_enforcing().await.unwrap());
    }
}
