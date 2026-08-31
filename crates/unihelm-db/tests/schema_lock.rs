//! Regression tests for the concurrent-migration bug.
//!
//! Reported as `table users already exists` / `table subscriptions already
//! exists` / `duplicate column name: quota_soft_mb` when `unihelm-agentd` and
//! `unihelm-web` were started together against one fresh directory. Both read an
//! empty `_sqlx_migrations`, both decided migration 1 was pending, and the loser
//! died. sqlx cannot prevent it: its `Migrate::lock`/`unlock` for SQLite are
//! no-ops, unlike Postgres.
//!
//! `flock` locks belong to the open file description, so separate `File::open`
//! calls contend even inside one process — one test process is enough to prove
//! the exclusion, and these tests fail against the old `Db::open`-migrates
//! behaviour.

use std::time::Duration;

use unihelm_db::{Db, DbError, SchemaState, migrate_lock};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_migrations_of_one_file_all_succeed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.db");

    let opens: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            tokio::spawn(async move { Db::open_and_migrate(&path).await })
        })
        .collect();

    for (i, task) in opens.into_iter().enumerate() {
        let db = task
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("open {i} failed: {e}"));
        assert!(
            matches!(db.schema_state().await.unwrap(), SchemaState::Ready { .. }),
            "open {i} left the schema unready"
        );
        db.close().await;
    }

    // Every migration applied exactly once. A double-apply would have failed
    // above, but assert the bookkeeping too: this is the table both processes
    // were racing to write.
    let db = Db::open(&path).await.unwrap();
    let dupes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT version FROM _sqlx_migrations \
         GROUP BY version HAVING count(*) > 1)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(dupes, 0, "a migration was recorded twice");
    db.close().await;

    // Never unlinked: unlink-then-recreate is how two processes end up flocking
    // two different inodes and both winning.
    assert!(migrate_lock::lock_path(&path).exists());
}

#[tokio::test]
async fn open_does_not_create_a_database() {
    // `unihelm doctor` used to conjure a fully migrated database on a machine
    // where the agent had never run, then report it healthy.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.db");

    let err = Db::open(&path).await.unwrap_err();
    assert!(matches!(err, DbError::NotInitialised { .. }), "{err}");
    assert!(!path.exists(), "the read-only door created a database");
    assert!(Db::open_unchecked(&path).await.is_err());
    assert!(!path.exists());
}

#[tokio::test]
async fn open_refuses_a_schema_the_owner_has_not_applied() {
    // An empty file is a valid empty SQLite database — which is exactly what a
    // half-finished install leaves behind.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.db");
    std::fs::write(&path, b"").unwrap();

    match Db::open(&path).await {
        Err(DbError::SchemaNotReady { state, .. }) => {
            assert_eq!(state, SchemaState::Empty);
            // The message has to name the fix, because this is what an operator
            // reads instead of "table users already exists".
            assert!(state.to_string().contains("unihelm-agentd"), "{state}");
        }
        other => panic!("expected SchemaNotReady, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_waiting_returns_once_the_owner_has_migrated() {
    // unihelm-web's posture: the agent is starting, so wait for it rather than
    // burn systemd's restart budget.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.db");

    let owner_path = path.clone();
    let owner = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Db::open_and_migrate(&owner_path).await.unwrap()
    });

    let db = Db::open_waiting(&path, Duration::from_secs(10))
        .await
        .expect("web should have waited for the agent");
    assert!(matches!(
        db.schema_state().await.unwrap(),
        SchemaState::Ready { .. }
    ));
    owner.await.unwrap().close().await;
    db.close().await;
}

#[tokio::test]
async fn open_waiting_gives_up_with_a_message_that_names_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.db");
    let err = Db::open_waiting(&path, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unihelm-agentd"), "{err}");
}
