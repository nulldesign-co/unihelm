//! Render → validate → activate → roll back (spec §10.4 rules 4 and 5).
//!
//! ## Why validation happens after the write, not before
//!
//! The spec's sequence reads "render to temp → validate → atomic move →
//! reload". For nginx and PHP-FPM that ordering is not achievable as written:
//! `nginx -t` tests the *installed* configuration tree, so a file that is not
//! yet included cannot be tested. What matters is the property the sequence
//! exists to guarantee — **never reload a broken configuration** — and that is
//! preserved by writing first and validating before the reload. Writing a file
//! to disk changes nothing about the running server; only the reload does.
//!
//! So the real sequence is:
//!
//! 1. snapshot what is there now (content, or the fact that nothing was),
//! 2. write the new content atomically,
//! 3. validate the whole configuration with the service's own tool,
//! 4. on failure, restore the snapshot atomically and hand back the validator's
//!    own words — the server is still running the configuration it always was,
//! 5. on success, reload, then post-check, restoring and reloading again if the
//!    post-check fails,
//! 6. record a revision so the UI can offer one-click rollback.
//!
//! Rendering is serialised per service, so two concurrent site creations cannot
//! interleave writes and reloads into a broken tree (spec §11.2 AC).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::managed::{
    CommentStyle, DiffLine, FileState, ManagedFile, body_hash, read_body, simple_diff, with_header,
    write_atomic,
};
use crate::templates::TemplateSet;
use crate::{ConfigError, Result};

/// A service's own configuration checker: `nginx -t`, `php-fpm8.3 -t`.
#[async_trait]
pub trait Validator: Send + Sync {
    fn name(&self) -> &'static str;
    /// `Err` carries the tool's output verbatim — that text is what a user needs
    /// to see, and paraphrasing it helps nobody.
    async fn validate(&self) -> std::result::Result<(), String>;
}

/// Applies a validated configuration to a running service.
#[async_trait]
pub trait Reloader: Send + Sync {
    fn name(&self) -> &'static str;
    async fn reload(&self) -> std::result::Result<(), String>;
}

/// An optional proof that the change actually works — a real request to the
/// site, a health probe against a new FPM pool.
#[async_trait]
pub trait PostCheck: Send + Sync {
    fn describe(&self) -> String;
    async fn check(&self) -> std::result::Result<(), String>;
}

/// Persisted history, so any activation can be undone (spec §10.4 rule 5).
#[async_trait]
pub trait RevisionStore: Send + Sync {
    async fn record(&self, revision: NewRevision) -> std::result::Result<i64, String>;
    async fn active(&self, path: &str) -> std::result::Result<Option<StoredRevision>, String>;
}

#[derive(Debug, Clone)]
pub struct NewRevision {
    pub path: String,
    pub sha256: String,
    pub content: String,
    pub rendered_by_task: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredRevision {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub content: String,
}

/// What to write, how to check it, and how to put it live.
pub struct ApplyRequest<'a> {
    pub file: ManagedFile,
    /// Name of a template registered in the [`TemplateSet`].
    pub template: &'a str,
    pub context: serde_json::Value,
    /// Serialisation key — every file belonging to one service shares it.
    pub service: &'a str,
    pub validator: &'a dyn Validator,
    pub reloader: &'a dyn Reloader,
    pub post_check: Option<&'a dyn PostCheck>,
    /// Overwrite a file a human has edited. Only ever set from an explicit
    /// "yes, discard my changes" in the UI.
    pub force: bool,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutcome {
    pub path: PathBuf,
    /// False when the rendered content was byte-identical to what was already
    /// there — no write, no reload, no revision.
    pub changed: bool,
    pub revision_id: Option<i64>,
    pub reloaded: bool,
}

pub struct ConfigEngine {
    templates: TemplateSet,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    revisions: Option<Arc<dyn RevisionStore>>,
}

impl ConfigEngine {
    pub fn new(templates: TemplateSet) -> Self {
        Self {
            templates,
            locks: Mutex::new(HashMap::new()),
            revisions: None,
        }
    }

    pub fn with_revisions(mut self, store: Arc<dyn RevisionStore>) -> Self {
        self.revisions = Some(store);
        self
    }

    pub fn templates(&self) -> &TemplateSet {
        &self.templates
    }

    /// Render a template without touching the filesystem — used by the UI's
    /// "preview this vhost" and by tests.
    pub fn preview(&self, template: &str, context: &serde_json::Value) -> Result<String> {
        self.templates.render(template, context)
    }

    /// The full apply sequence.
    pub async fn apply(&self, request: ApplyRequest<'_>) -> Result<ApplyOutcome> {
        let body = self.templates.render(request.template, &request.context)?;
        let contents = with_header(&body, request.file.comment_style);
        let path = request.file.path.clone();

        let lock = self.lock_for(request.service).await;
        let _guard = lock.lock().await;

        // 1. What is there now?
        match request.file.state() {
            FileState::Foreign => return Err(ConfigError::Foreign { path }),
            FileState::Unreadable { reason } => return Err(ConfigError::BadPath { path, reason }),
            FileState::Drifted { .. } if !request.force => {
                let current = read_body(&path)?.unwrap_or_default();
                return Err(ConfigError::Drift {
                    path,
                    diff: simple_diff(&current, &body),
                });
            }
            FileState::Managed { hash } if hash == body_hash(&body) && !request.force => {
                // Nothing to do. Reloading nginx because a page was refreshed is
                // exactly the kind of pointless churn that makes panels feel
                // unsafe to click around in.
                return Ok(ApplyOutcome {
                    path,
                    changed: false,
                    revision_id: None,
                    reloaded: false,
                });
            }
            _ => {}
        }

        let snapshot = snapshot_of(&path)?;

        // 2. Write.
        write_atomic(&path, &contents, request.file.mode)?;

        // 3. Validate, and undo completely if the service disagrees.
        if let Err(output) = request.validator.validate().await {
            restore(&path, &snapshot, request.file.mode)?;
            return Err(ConfigError::ValidationFailed {
                validator: request.validator.name().to_string(),
                output,
            });
        }

        // 4. Reload.
        if let Err(output) = request.reloader.reload().await {
            restore(&path, &snapshot, request.file.mode)?;
            // The running configuration is already the old one, but the service
            // may be in a half-reloaded state; put it back deliberately.
            let _ = request.reloader.reload().await;
            return Err(ConfigError::ReloadFailed {
                service: request.reloader.name().to_string(),
                output,
            });
        }

        // 5. Prove it works, where we can.
        if let Some(check) = request.post_check
            && let Err(output) = check.check().await
        {
            restore(&path, &snapshot, request.file.mode)?;
            let _ = request.reloader.reload().await;
            return Err(ConfigError::PostCheckFailed {
                check: check.describe(),
                output,
            });
        }

        // 6. Record, so this can be undone from the UI.
        let revision_id = match &self.revisions {
            Some(store) => store
                .record(NewRevision {
                    path: path.to_string_lossy().into_owned(),
                    sha256: body_hash(&body),
                    content: contents,
                    rendered_by_task: request.task_id,
                })
                .await
                .map_err(ConfigError::RevisionStore)
                .map(Some)?,
            None => None,
        };

        tracing::info!(path = %path.display(), service = request.service, "configuration applied");
        Ok(ApplyOutcome {
            path,
            changed: true,
            revision_id,
            reloaded: true,
        })
    }

    /// Remove a managed file and reload, restoring it if the service objects.
    pub async fn remove(
        &self,
        file: &ManagedFile,
        service: &str,
        validator: &dyn Validator,
        reloader: &dyn Reloader,
    ) -> Result<bool> {
        let lock = self.lock_for(service).await;
        let _guard = lock.lock().await;

        let snapshot = snapshot_of(&file.path)?;
        if snapshot.is_none() {
            return Ok(false);
        }

        crate::managed::remove_managed(&file.path)?;

        if let Err(output) = validator.validate().await {
            restore(&file.path, &snapshot, file.mode)?;
            return Err(ConfigError::ValidationFailed {
                validator: validator.name().to_string(),
                output,
            });
        }
        if let Err(output) = reloader.reload().await {
            restore(&file.path, &snapshot, file.mode)?;
            let _ = reloader.reload().await;
            return Err(ConfigError::ReloadFailed {
                service: reloader.name().to_string(),
                output,
            });
        }
        Ok(true)
    }

    /// Put a stored revision back on disk (spec §10.4 rule 5).
    pub async fn rollback(
        &self,
        path: &Path,
        revision: &StoredRevision,
        service: &str,
        mode: u32,
        validator: &dyn Validator,
        reloader: &dyn Reloader,
    ) -> Result<()> {
        let lock = self.lock_for(service).await;
        let _guard = lock.lock().await;

        let snapshot = snapshot_of(path)?;
        write_atomic(path, &revision.content, mode)?;

        if let Err(output) = validator.validate().await {
            restore(path, &snapshot, mode)?;
            return Err(ConfigError::ValidationFailed {
                validator: validator.name().to_string(),
                output,
            });
        }
        if let Err(output) = reloader.reload().await {
            restore(path, &snapshot, mode)?;
            let _ = reloader.reload().await;
            return Err(ConfigError::ReloadFailed {
                service: reloader.name().to_string(),
                output,
            });
        }

        tracing::warn!(path = %path.display(), revision = revision.id, "configuration rolled back");
        Ok(())
    }

    /// Compare what is on disk against what we would render now.
    pub fn drift_report(
        &self,
        file: &ManagedFile,
        template: &str,
        context: &serde_json::Value,
    ) -> Result<DriftReport> {
        let expected = self.templates.render(template, context)?;
        let state = file.state();
        let current = read_body(&file.path)?;

        let diff = match (&state, &current) {
            (FileState::Drifted { .. }, Some(body)) => simple_diff(body, &expected),
            _ => Vec::new(),
        };

        Ok(DriftReport {
            path: file.path.clone(),
            state,
            diff,
        })
    }

    async fn lock_for(&self, service: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks
            .entry(service.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub path: PathBuf,
    pub state: FileState,
    pub diff: Vec<DiffLine>,
}

/// Full current contents, or `None` when the file does not exist.
fn snapshot_of(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// Put things back exactly as they were.
///
/// A failure here is genuinely serious — the server is left with a config we
/// could not undo — so it is logged loudly and returned rather than swallowed.
fn restore(path: &Path, snapshot: &Option<String>, mode: u32) -> Result<()> {
    match snapshot {
        Some(contents) => write_atomic(path, contents, mode),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ConfigError::Io { path: path.to_path_buf(), source: e }),
        },
    }
    .inspect_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "could not restore the previous configuration");
    })
}

/// A managed file whose comment style follows its extension.
pub fn managed_for(path: impl Into<PathBuf>) -> ManagedFile {
    let path: PathBuf = path.into();
    let style = match path.extension().and_then(|e| e.to_str()) {
        // FPM pool files and php.ini fragments comment with `;`.
        Some("ini") => CommentStyle::Semicolon,
        _ if path.to_string_lossy().contains("fpm") => CommentStyle::Semicolon,
        _ => CommentStyle::Hash,
    };
    ManagedFile {
        path,
        mode: 0o644,
        comment_style: style,
    }
}
