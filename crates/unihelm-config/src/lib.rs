//! `unihelm-config` — rendering, validating and activating the files the panel
//! owns (spec §10.4).
//!
//! The contract this crate implements is the one that decides whether a
//! sysadmin can trust the panel:
//!
//! 1. Files Unihelm fully owns live in dedicated include directories and carry a
//!    hash header.
//! 2. If a human edited one, the panel says so and offers a diff — it does not
//!    overwrite.
//! 3. Escape hatches (a custom nginx snippet, php.ini overrides) are first-class
//!    fields injected at safe include points, so people rarely need to edit
//!    anything by hand in the first place.
//! 4. Every activation validates before it reloads, and rolls back on any
//!    failure.
//! 5. Every activation is a revision that can be restored in one click.

pub mod apply;
pub mod context;
pub mod managed;
pub mod paths;
pub mod templates;

pub use apply::{
    ApplyOutcome, ApplyRequest, ConfigEngine, DriftReport, NewRevision, PostCheck, Reloader,
    RevisionStore, StoredRevision, Validator, managed_for,
};
pub use context::{PoolContext, SiteContext, SiteType};
pub use managed::{CommentStyle, DiffKind, DiffLine, FileState, ManagedFile};
pub use templates::TemplateSet;

use std::path::PathBuf;

use unihelm_core::{ErrorCode, UnihelmError};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("template `{template}`: {detail}")]
    Template { template: String, detail: String },

    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {reason}")]
    BadPath { path: PathBuf, reason: String },

    #[error("{path} was edited outside the panel")]
    Drift { path: PathBuf, diff: Vec<DiffLine> },

    #[error("{path} exists but was not written by the panel")]
    Foreign { path: PathBuf },

    #[error("{validator} rejected the configuration:\n{output}")]
    ValidationFailed { validator: String, output: String },

    #[error("{service} failed to reload:\n{output}")]
    ReloadFailed { service: String, output: String },

    #[error("the change was reverted because a check failed ({check}):\n{output}")]
    PostCheckFailed { check: String, output: String },

    #[error("could not record a configuration revision: {0}")]
    RevisionStore(String),
}

pub type Result<T, E = ConfigError> = std::result::Result<T, E>;

impl From<ConfigError> for UnihelmError {
    fn from(e: ConfigError) -> Self {
        let code = match &e {
            ConfigError::Drift { .. } | ConfigError::Foreign { .. } => ErrorCode::ConfigDrift,
            ConfigError::ValidationFailed { .. } | ConfigError::Template { .. } => {
                ErrorCode::ConfigValidationFailed
            }
            ConfigError::ReloadFailed { .. } | ConfigError::PostCheckFailed { .. } => {
                ErrorCode::ConfigRollback
            }
            ConfigError::Io { .. }
            | ConfigError::BadPath { .. }
            | ConfigError::RevisionStore(_) => ErrorCode::Internal,
        };
        UnihelmError::new(code, e.to_string())
    }
}
