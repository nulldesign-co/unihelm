//! The safety property this crate exists for: a failed change leaves the server
//! exactly as it was (spec §10.4 rule 4).
//!
//! Every test here is a way the apply sequence can go wrong in production —
//! a syntax error in a template, a service that refuses to reload, a sysadmin
//! who edited the file at 3am — and what the panel must do about it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::sync::Mutex;
use unihelm_config::apply::{
    NewRevision, PostCheck, Reloader, RevisionStore, StoredRevision, Validator,
};
use unihelm_config::managed::{CommentStyle, with_header};
use unihelm_config::{
    ApplyRequest, ConfigEngine, ConfigError, FileState, ManagedFile, TemplateSet,
};

// --- doubles ---------------------------------------------------------------

struct FakeValidator {
    ok: AtomicBool,
    calls: AtomicUsize,
    message: String,
}

impl FakeValidator {
    fn passing() -> Self {
        Self {
            ok: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            message: String::new(),
        }
    }
    fn failing(message: &str) -> Self {
        Self {
            ok: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            message: message.to_string(),
        }
    }
}

#[async_trait]
impl Validator for FakeValidator {
    fn name(&self) -> &'static str {
        "nginx -t"
    }
    async fn validate(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.ok.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(self.message.clone())
        }
    }
}

struct FakeReloader {
    ok: AtomicBool,
    calls: AtomicUsize,
}

impl FakeReloader {
    fn passing() -> Self {
        Self {
            ok: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        }
    }
    fn failing() -> Self {
        Self {
            ok: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Reloader for FakeReloader {
    fn name(&self) -> &'static str {
        "nginx"
    }
    async fn reload(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.ok.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("job for nginx.service failed".into())
        }
    }
}

struct FailingCheck;

#[async_trait]
impl PostCheck for FailingCheck {
    fn describe(&self) -> String {
        "GET https://example.com/".into()
    }
    async fn check(&self) -> Result<(), String> {
        Err("502 Bad Gateway".into())
    }
}

#[derive(Default)]
struct MemoryRevisions {
    rows: Mutex<Vec<StoredRevision>>,
}

#[async_trait]
impl RevisionStore for MemoryRevisions {
    async fn record(&self, revision: NewRevision) -> Result<i64, String> {
        let mut rows = self.rows.lock().await;
        let id = rows.len() as i64 + 1;
        rows.push(StoredRevision {
            id,
            path: revision.path,
            sha256: revision.sha256,
            content: revision.content,
        });
        Ok(id)
    }

    async fn active(&self, path: &str) -> Result<Option<StoredRevision>, String> {
        Ok(self
            .rows
            .lock()
            .await
            .iter()
            .rev()
            .find(|r| r.path == path)
            .cloned())
    }
}

// --- fixtures --------------------------------------------------------------

/// A tiny template, so these tests are about the apply sequence and not about
/// nginx syntax.
fn engine() -> (ConfigEngine, Arc<MemoryRevisions>) {
    let mut set = TemplateSet::load().unwrap();
    inject_test_template(&mut set);
    let store = Arc::new(MemoryRevisions::default());
    (ConfigEngine::new(set).with_revisions(store.clone()), store)
}

fn inject_test_template(set: &mut TemplateSet) {
    set.add_template("test/simple", "value = {{ value }}\n")
        .unwrap();
}

fn request<'a>(
    file: ManagedFile,
    value: &str,
    validator: &'a FakeValidator,
    reloader: &'a FakeReloader,
) -> ApplyRequest<'a> {
    ApplyRequest {
        file,
        template: "test/simple",
        context: serde_json::json!({ "value": value }),
        service: "nginx",
        validator,
        reloader,
        post_check: None,
        force: false,
        task_id: None,
    }
}

// --- tests -----------------------------------------------------------------

#[tokio::test]
async fn a_successful_apply_writes_validates_reloads_and_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, store) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    let outcome = engine
        .apply(request(
            ManagedFile::nginx(&path),
            "one",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();

    assert!(outcome.changed);
    assert!(outcome.reloaded);
    assert_eq!(outcome.revision_id, Some(1));
    assert_eq!(reloader.count(), 1);
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("value = one")
    );
    assert!(matches!(
        ManagedFile::nginx(&path).state(),
        FileState::Managed { .. }
    ));
    assert!(
        store
            .active(path.to_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_validation_failure_restores_the_previous_file_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();

    // A good configuration is live.
    let good = FakeValidator::passing();
    let reloader = FakeReloader::passing();
    engine
        .apply(request(ManagedFile::nginx(&path), "good", &good, &reloader))
        .await
        .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // A bad one is attempted.
    let bad = FakeValidator::failing(
        "nginx: [emerg] invalid parameter \"quic\" in /etc/nginx/unihelm.d/site.conf:12",
    );
    let err = engine
        .apply(request(ManagedFile::nginx(&path), "bad", &bad, &reloader))
        .await
        .unwrap_err();

    match err {
        ConfigError::ValidationFailed { validator, output } => {
            assert_eq!(validator, "nginx -t");
            // The user must see nginx's own words, including the line number.
            assert!(output.contains("[emerg]"), "got: {output}");
            assert!(output.contains(":12"));
        }
        other => panic!("expected ValidationFailed, got {other:?}"),
    }

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "the file must be byte-identical"
    );
    assert_eq!(
        reloader.count(),
        1,
        "a rejected configuration must never be reloaded"
    );
}

#[tokio::test]
async fn a_validation_failure_on_a_new_file_leaves_no_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("brand-new.conf");
    let (engine, _) = engine();
    let bad = FakeValidator::failing("nginx: [emerg] unknown directive");
    let reloader = FakeReloader::passing();

    assert!(
        engine
            .apply(request(ManagedFile::nginx(&path), "x", &bad, &reloader))
            .await
            .is_err()
    );
    assert!(
        !path.exists(),
        "a rejected new vhost must not be left on disk"
    );
    assert_eq!(reloader.count(), 0);
}

#[tokio::test]
async fn a_reload_failure_restores_and_reloads_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let validator = FakeValidator::passing();

    let ok_reloader = FakeReloader::passing();
    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "good",
            &validator,
            &ok_reloader,
        ))
        .await
        .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // The config validates, but systemd cannot reload the service.
    let broken = FakeReloader::failing();
    let err = engine
        .apply(request(
            ManagedFile::nginx(&path),
            "next",
            &validator,
            &broken,
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, ConfigError::ReloadFailed { .. }));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(
        broken.count(),
        2,
        "after restoring the old file the service must be reloaded back onto it"
    );
}

#[tokio::test]
async fn a_failed_post_check_undoes_a_change_that_validated_and_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let validator = FakeValidator::passing();
    let reloader = FakeReloader::passing();

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "good",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    let check = FailingCheck;
    let mut req = request(ManagedFile::nginx(&path), "next", &validator, &reloader);
    req.post_check = Some(&check);
    let err = engine.apply(req).await.unwrap_err();

    match err {
        ConfigError::PostCheckFailed { check, output } => {
            assert!(check.contains("example.com"));
            assert!(output.contains("502"));
        }
        other => panic!("expected PostCheckFailed, got {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(
        reloader.count(),
        3,
        "reload, then reload again after restoring"
    );
}

#[tokio::test]
async fn a_human_edit_stops_the_render_and_produces_a_diff() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "one",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();

    // The sysadmin adds a line by hand.
    let edited = std::fs::read_to_string(&path).unwrap() + "# my hand-tuned cache rules\n";
    std::fs::write(&path, &edited).unwrap();

    let err = engine
        .apply(request(
            ManagedFile::nginx(&path),
            "two",
            &validator,
            &reloader,
        ))
        .await
        .unwrap_err();

    match err {
        ConfigError::Drift { path: p, diff } => {
            assert_eq!(p, path);
            assert!(!diff.is_empty(), "the user needs to see what would change");
        }
        other => panic!("expected Drift, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        edited,
        "the sysadmin's edit must survive untouched"
    );
    assert_eq!(reloader.count(), 1);
}

#[tokio::test]
async fn force_overwrites_a_drifted_file_when_the_user_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "one",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();
    std::fs::write(
        &path,
        std::fs::read_to_string(&path).unwrap() + "# edited\n",
    )
    .unwrap();

    let mut req = request(ManagedFile::nginx(&path), "two", &validator, &reloader);
    req.force = true;
    let outcome = engine.apply(req).await.unwrap();

    assert!(outcome.changed);
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains("value = two"));
    assert!(!after.contains("# edited"));
}

#[tokio::test]
async fn a_file_the_panel_never_wrote_is_never_touched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let original = "server {\n    # hand-written, years old\n}\n";
    std::fs::write(&path, original).unwrap();

    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());
    let err = engine
        .apply(request(
            ManagedFile::nginx(&path),
            "x",
            &validator,
            &reloader,
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, ConfigError::Foreign { .. }));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert_eq!(reloader.count(), 0);
}

#[tokio::test]
async fn re_rendering_identical_content_does_not_reload_anything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "same",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();
    let outcome = engine
        .apply(request(
            ManagedFile::nginx(&path),
            "same",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();

    assert!(!outcome.changed);
    assert!(!outcome.reloaded);
    assert_eq!(
        reloader.count(),
        1,
        "nothing changed, so nothing should have been reloaded"
    );
}

#[tokio::test]
async fn concurrent_applies_to_one_service_do_not_interleave() {
    // Spec §11.2 AC: concurrent site creations must not corrupt the config.
    // Each apply validates and reloads; if two overlapped, a validation could
    // run against a half-written tree.
    struct Tracking {
        inside: AtomicUsize,
        overlapped: AtomicBool,
    }

    #[async_trait]
    impl Validator for Tracking {
        fn name(&self) -> &'static str {
            "tracking"
        }
        async fn validate(&self) -> Result<(), String> {
            if self.inside.fetch_add(1, Ordering::SeqCst) != 0 {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.inside.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (engine, _) = engine();
    let engine = Arc::new(engine);
    let tracking = Arc::new(Tracking {
        inside: AtomicUsize::new(0),
        overlapped: AtomicBool::new(false),
    });
    let reloader = Arc::new(FakeReloader::passing());

    let mut handles = Vec::new();
    for i in 0..8 {
        let engine = engine.clone();
        let tracking = tracking.clone();
        let reloader = reloader.clone();
        let path = dir.path().join(format!("site-{i}.conf"));
        handles.push(tokio::spawn(async move {
            engine
                .apply(ApplyRequest {
                    file: ManagedFile::nginx(&path),
                    template: "test/simple",
                    context: serde_json::json!({ "value": format!("site{i}") }),
                    service: "nginx",
                    validator: tracking.as_ref(),
                    reloader: reloader.as_ref(),
                    post_check: None,
                    force: false,
                    task_id: None,
                })
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    assert!(
        !tracking.overlapped.load(Ordering::SeqCst),
        "two applies to the same service ran at once"
    );
    for i in 0..8 {
        let content = std::fs::read_to_string(dir.path().join(format!("site-{i}.conf"))).unwrap();
        assert!(
            content.contains(&format!("value = site{i}")),
            "site {i} got the wrong content"
        );
    }
}

#[tokio::test]
async fn removing_a_vhost_that_breaks_nginx_puts_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let good = FakeValidator::passing();
    let reloader = FakeReloader::passing();

    engine
        .apply(request(ManagedFile::nginx(&path), "one", &good, &reloader))
        .await
        .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // Removing this vhost turns out to break the configuration — another file
    // referenced its upstream, say.
    let bad = FakeValidator::failing("nginx: [emerg] host not found in upstream");
    let err = engine
        .remove(&ManagedFile::nginx(&path), "nginx", &bad, &reloader)
        .await
        .unwrap_err();

    assert!(matches!(err, ConfigError::ValidationFailed { .. }));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "the vhost must come back"
    );
}

#[tokio::test]
async fn removing_an_absent_file_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    let removed = engine
        .remove(
            &ManagedFile::nginx(dir.path().join("nope.conf")),
            "nginx",
            &validator,
            &reloader,
        )
        .await
        .unwrap();
    assert!(!removed);
    assert_eq!(reloader.count(), 0, "nothing changed, nothing to reload");
}

#[tokio::test]
async fn a_revision_can_be_rolled_back_in_one_step() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, store) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "first",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();
    let first = store.active(path.to_str().unwrap()).await.unwrap().unwrap();

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "second",
            &validator,
            &reloader,
        ))
        .await
        .unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("value = second")
    );

    engine
        .rollback(&path, &first, "nginx", 0o644, &validator, &reloader)
        .await
        .unwrap();

    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains("value = first"));
    assert!(matches!(
        ManagedFile::nginx(&path).state(),
        FileState::Managed { .. }
    ));
}

#[tokio::test]
async fn a_rollback_that_will_not_validate_is_itself_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let good = FakeValidator::passing();
    let reloader = FakeReloader::passing();

    engine
        .apply(request(
            ManagedFile::nginx(&path),
            "current",
            &good,
            &reloader,
        ))
        .await
        .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // An old revision that references something that no longer exists.
    let stale = StoredRevision {
        id: 99,
        path: path.to_string_lossy().into_owned(),
        sha256: "0".repeat(64),
        content: with_header("value = ancient\n", CommentStyle::Hash),
    };
    let bad = FakeValidator::failing("nginx: [emerg] cannot load certificate");
    assert!(
        engine
            .rollback(&path, &stale, "nginx", 0o644, &bad, &reloader)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

#[tokio::test]
async fn a_template_that_is_missing_a_value_fails_before_anything_is_written() {
    // Strict undefined is what stops `server_name ;` from ever reaching disk.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("site.conf");
    let (engine, _) = engine();
    let (validator, reloader) = (FakeValidator::passing(), FakeReloader::passing());

    let err = engine
        .apply(ApplyRequest {
            file: ManagedFile::nginx(&path),
            template: "test/simple",
            context: serde_json::json!({}),
            service: "nginx",
            validator: &validator,
            reloader: &reloader,
            post_check: None,
            force: false,
            task_id: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, ConfigError::Template { .. }), "got {err:?}");
    assert!(
        !path.exists(),
        "nothing should be written when the render fails"
    );
    assert_eq!(reloader.count(), 0);
}
