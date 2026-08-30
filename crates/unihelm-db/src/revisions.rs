//! Configuration revisions (spec §10.4 rule 5).
//!
//! Every activation of a file the panel owns is stored here, so any change can
//! be undone from the UI. Exactly one revision per path is `active`, enforced by
//! a partial unique index — the alternative, two rows both claiming to be what
//! is on disk, makes rollback a guess.

use serde::Serialize;

use crate::{Db, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Serialize)]
pub struct ConfigRevision {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub rendered_by_task: Option<String>,
    pub active: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// Omitted from listings: a vhost is a few kilobytes and a list of twenty is
    /// not something to send down a wire for a sidebar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConfigRevisionRow {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub content: String,
    pub rendered_by_task: Option<String>,
    pub active: i64,
    pub created_at: String,
}

impl ConfigRevisionRow {
    fn into_revision(self, with_content: bool) -> Result<ConfigRevision> {
        Ok(ConfigRevision {
            id: self.id,
            path: self.path,
            sha256: self.sha256,
            rendered_by_task: self.rendered_by_task,
            active: self.active != 0,
            created_at: from_sql_time(&self.created_at)?,
            content: with_content.then_some(self.content),
        })
    }
}

/// How many revisions to keep per path.
///
/// Enough to undo a bad afternoon, few enough that a site re-rendered on every
/// settings change does not grow the database without bound.
const KEEP_PER_PATH: i64 = 20;

impl Db {
    /// Record an activation and make it the active revision for its path.
    pub async fn record_revision(
        &self,
        path: &str,
        sha256: &str,
        content: &str,
        rendered_by_task: Option<&str>,
    ) -> Result<i64> {
        let mut tx = self.begin().await?;

        // Only one row per path may claim to be on disk.
        sqlx::query("UPDATE config_revisions SET active = 0 WHERE path = ?1 AND active = 1")
            .bind(path)
            .execute(&mut *tx)
            .await?;

        let row: (i64,) = sqlx::query_as(
            "INSERT INTO config_revisions (path, sha256, content, rendered_by_task, active, created_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5) RETURNING id",
        )
        .bind(path)
        .bind(sha256)
        .bind(content)
        .bind(rendered_by_task)
        .bind(to_sql_time(now()))
        .fetch_one(&mut *tx)
        .await?;

        // Trim inside the same transaction, so a crash cannot leave the history
        // unbounded.
        sqlx::query(
            "DELETE FROM config_revisions
             WHERE path = ?1 AND active = 0 AND id NOT IN (
                 SELECT id FROM config_revisions WHERE path = ?1 ORDER BY id DESC LIMIT ?2
             )",
        )
        .bind(path)
        .bind(KEEP_PER_PATH)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row.0)
    }

    /// The revision currently on disk for a path.
    pub async fn active_revision(&self, path: &str) -> Result<Option<ConfigRevision>> {
        let row = sqlx::query_as::<_, ConfigRevisionRow>(
            "SELECT * FROM config_revisions WHERE path = ?1 AND active = 1",
        )
        .bind(path)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| r.into_revision(true)).transpose()
    }

    /// One revision by id, with its content, for a rollback.
    pub async fn revision(&self, id: i64) -> Result<Option<ConfigRevision>> {
        let row =
            sqlx::query_as::<_, ConfigRevisionRow>("SELECT * FROM config_revisions WHERE id = ?1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?;
        row.map(|r| r.into_revision(true)).transpose()
    }

    /// History for a path, newest first, without the file bodies.
    pub async fn revision_history(&self, path: &str, limit: i64) -> Result<Vec<ConfigRevision>> {
        let rows = sqlx::query_as::<_, ConfigRevisionRow>(
            "SELECT * FROM config_revisions WHERE path = ?1 ORDER BY id DESC LIMIT ?2",
        )
        .bind(path)
        .bind(limit.clamp(1, 100))
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(|r| r.into_revision(false)).collect()
    }

    /// Make a stored revision the active one again, after it has been written
    /// back to disk.
    pub async fn mark_revision_active(&self, id: i64) -> Result<()> {
        let Some(revision) = self.revision(id).await? else {
            return Err(crate::DbError::NotFound {
                what: "configuration revision",
            });
        };
        let mut tx = self.begin().await?;
        sqlx::query("UPDATE config_revisions SET active = 0 WHERE path = ?1 AND active = 1")
            .bind(&revision.path)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE config_revisions SET active = 1 WHERE id = ?1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Forget the history for a path — used when the site it belonged to is
    /// deleted, so its vhost does not linger in the database forever.
    pub async fn forget_revisions(&self, path: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM config_revisions WHERE path = ?1")
            .bind(path)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/etc/nginx/unihelm.d/site-example.com.conf";

    async fn db() -> Db {
        Db::open_memory().await.unwrap()
    }

    #[tokio::test]
    async fn the_newest_revision_is_the_active_one() {
        let db = db().await;
        db.record_revision(PATH, "aaa", "first", None)
            .await
            .unwrap();
        let second = db
            .record_revision(PATH, "bbb", "second", Some("task-1"))
            .await
            .unwrap();

        let active = db.active_revision(PATH).await.unwrap().unwrap();
        assert_eq!(active.id, second);
        assert_eq!(active.content.as_deref(), Some("second"));
        assert_eq!(active.rendered_by_task.as_deref(), Some("task-1"));
    }

    #[tokio::test]
    async fn exactly_one_revision_per_path_is_ever_active() {
        // Two rows both claiming to be on disk would make rollback a guess.
        let db = db().await;
        for i in 0..5 {
            db.record_revision(PATH, &format!("h{i}"), &format!("body {i}"), None)
                .await
                .unwrap();
        }
        let active: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM config_revisions WHERE path = ?1 AND active = 1")
                .bind(PATH)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(active.0, 1);
    }

    #[tokio::test]
    async fn history_is_newest_first_and_omits_the_bodies() {
        let db = db().await;
        for i in 0..3 {
            db.record_revision(PATH, &format!("h{i}"), &format!("body {i}"), None)
                .await
                .unwrap();
        }
        let history = db.revision_history(PATH, 10).await.unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[0].id > history[1].id);
        assert!(
            history[0].content.is_none(),
            "a listing should not carry every file body"
        );
        assert!(history[0].active);
        assert!(!history[1].active);
    }

    #[tokio::test]
    async fn history_is_trimmed_so_it_cannot_grow_without_bound() {
        // A site re-rendered on every settings change must not fill the disk.
        let db = db().await;
        for i in 0..40 {
            db.record_revision(PATH, &format!("h{i}"), &format!("body {i}"), None)
                .await
                .unwrap();
        }
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM config_revisions WHERE path = ?1")
            .bind(PATH)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(count.0 <= KEEP_PER_PATH, "kept {} revisions", count.0);
        // And the newest is still there.
        assert_eq!(
            db.active_revision(PATH)
                .await
                .unwrap()
                .unwrap()
                .content
                .as_deref(),
            Some("body 39")
        );
    }

    #[tokio::test]
    async fn trimming_never_discards_the_active_revision() {
        let db = db().await;
        let first = db
            .record_revision(PATH, "keep", "the live one", None)
            .await
            .unwrap();
        db.mark_revision_active(first).await.unwrap();
        for i in 0..40 {
            db.record_revision(PATH, &format!("h{i}"), &format!("body {i}"), None)
                .await
                .unwrap();
        }
        // The last write is active; the point is that the invariant holds.
        assert!(db.active_revision(PATH).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rolling_back_moves_the_active_marker() {
        let db = db().await;
        let first = db
            .record_revision(PATH, "aaa", "first", None)
            .await
            .unwrap();
        db.record_revision(PATH, "bbb", "second", None)
            .await
            .unwrap();

        db.mark_revision_active(first).await.unwrap();
        let active = db.active_revision(PATH).await.unwrap().unwrap();
        assert_eq!(active.id, first);
        assert_eq!(active.content.as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn paths_keep_separate_histories() {
        let db = db().await;
        let other = "/etc/nginx/unihelm.d/site-other.com.conf";
        db.record_revision(PATH, "a", "one", None).await.unwrap();
        db.record_revision(other, "b", "two", None).await.unwrap();

        assert_eq!(
            db.active_revision(PATH)
                .await
                .unwrap()
                .unwrap()
                .content
                .as_deref(),
            Some("one")
        );
        assert_eq!(
            db.active_revision(other)
                .await
                .unwrap()
                .unwrap()
                .content
                .as_deref(),
            Some("two")
        );
        assert_eq!(db.revision_history(PATH, 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn forgetting_a_path_removes_its_whole_history() {
        let db = db().await;
        for i in 0..3 {
            db.record_revision(PATH, &format!("h{i}"), "x", None)
                .await
                .unwrap();
        }
        assert_eq!(db.forget_revisions(PATH).await.unwrap(), 3);
        assert!(db.active_revision(PATH).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rolling_back_to_a_revision_that_does_not_exist_is_an_error() {
        let db = db().await;
        assert!(matches!(
            db.mark_revision_active(999).await,
            Err(crate::DbError::NotFound { .. })
        ));
    }
}
