//! What the Stack Manager has installed (spec §11.1).
//!
//! One row per component, so the dashboard can answer "is nginx installed, at
//! what version, and did the last attempt fail" without shelling out to the
//! package manager on every page load.

use serde::Serialize;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Absent,
    Installing,
    Installed,
    Failed,
    Removing,
}

impl ComponentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ComponentStatus::Absent => "absent",
            ComponentStatus::Installing => "installing",
            ComponentStatus::Installed => "installed",
            ComponentStatus::Failed => "failed",
            ComponentStatus::Removing => "removing",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "absent" => ComponentStatus::Absent,
            "installing" => ComponentStatus::Installing,
            "installed" => ComponentStatus::Installed,
            "failed" => ComponentStatus::Failed,
            "removing" => ComponentStatus::Removing,
            other => {
                return Err(DbError::Corrupt {
                    field: "stack_components.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }

    /// Is something already happening to this component?
    ///
    /// Two concurrent installs of the same component would fight over the
    /// package manager's lock and produce a confusing failure.
    pub const fn is_busy(self) -> bool {
        matches!(
            self,
            ComponentStatus::Installing | ComponentStatus::Removing
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StackComponent {
    pub slug: String,
    pub installed_version: Option<String>,
    pub status: ComponentStatus,
    pub last_error: Option<String>,
    pub last_task_id: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub installed_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StackComponentRow {
    pub slug: String,
    pub installed_version: Option<String>,
    pub status: String,
    pub last_error: Option<String>,
    pub last_task_id: Option<String>,
    pub installed_at: Option<String>,
    pub updated_at: String,
}

impl TryFrom<StackComponentRow> for StackComponent {
    type Error = DbError;

    fn try_from(r: StackComponentRow) -> Result<Self> {
        Ok(StackComponent {
            slug: r.slug,
            installed_version: r.installed_version,
            status: ComponentStatus::parse(&r.status)?,
            last_error: r.last_error,
            last_task_id: r.last_task_id,
            installed_at: r.installed_at.as_deref().map(from_sql_time).transpose()?,
        })
    }
}

impl Db {
    /// Claim a component for an install or removal.
    ///
    /// Returns `false` when something is already in flight, which is how two
    /// clicks on "install nginx" become one install instead of two package
    /// managers fighting over a lock.
    pub async fn claim_component(
        &self,
        slug: &str,
        status: ComponentStatus,
        task_id: &str,
    ) -> Result<bool> {
        let ts = to_sql_time(now());
        let affected = sqlx::query(
            "INSERT INTO stack_components (slug, status, last_task_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (slug) DO UPDATE SET
                 status = ?2, last_task_id = ?3, updated_at = ?4
             WHERE stack_components.status NOT IN ('installing', 'removing')",
        )
        .bind(slug)
        .bind(status.as_str())
        .bind(task_id)
        .bind(&ts)
        .execute(self.pool())
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    pub async fn component_installed(&self, slug: &str, version: Option<&str>) -> Result<()> {
        let ts = to_sql_time(now());
        sqlx::query(
            "UPDATE stack_components
             SET status = 'installed', installed_version = ?2, installed_at = ?3,
                 last_error = NULL, updated_at = ?3
             WHERE slug = ?1",
        )
        .bind(slug)
        .bind(version)
        .bind(&ts)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn component_removed(&self, slug: &str) -> Result<()> {
        sqlx::query(
            "UPDATE stack_components
             SET status = 'absent', installed_version = NULL, installed_at = NULL,
                 last_error = NULL, updated_at = ?2
             WHERE slug = ?1",
        )
        .bind(slug)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn component_failed(&self, slug: &str, error: &str) -> Result<()> {
        sqlx::query(
            "UPDATE stack_components SET status = 'failed', last_error = ?2, updated_at = ?3
             WHERE slug = ?1",
        )
        .bind(slug)
        .bind(error)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn component(&self, slug: &str) -> Result<Option<StackComponent>> {
        let row = sqlx::query_as::<_, StackComponentRow>(
            "SELECT * FROM stack_components WHERE slug = ?1",
        )
        .bind(slug)
        .fetch_optional(self.pool())
        .await?;
        row.map(StackComponent::try_from).transpose()
    }

    pub async fn components(&self) -> Result<Vec<StackComponent>> {
        let rows = sqlx::query_as::<_, StackComponentRow>(
            "SELECT * FROM stack_components ORDER BY slug ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(StackComponent::try_from).collect()
    }

    /// Release components left mid-install by an agent restart.
    ///
    /// Without this a crash during `apt install` leaves a component permanently
    /// "installing" and the button permanently disabled.
    pub async fn reconcile_components(&self) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE stack_components
             SET status = 'failed',
                 last_error = 'the agent restarted while this was in progress',
                 updated_at = ?1
             WHERE status IN ('installing', 'removing')",
        )
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Db {
        Db::open_memory().await.unwrap()
    }

    #[tokio::test]
    async fn an_unknown_component_is_simply_absent() {
        let db = db().await;
        assert!(db.component("nginx").await.unwrap().is_none());
        assert!(db.components().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_component_moves_from_claimed_to_installed() {
        let db = db().await;
        assert!(
            db.claim_component("nginx", ComponentStatus::Installing, "task-1")
                .await
                .unwrap()
        );
        assert_eq!(
            db.component("nginx").await.unwrap().unwrap().status,
            ComponentStatus::Installing
        );

        db.component_installed("nginx", Some("1.30.4"))
            .await
            .unwrap();
        let c = db.component("nginx").await.unwrap().unwrap();
        assert_eq!(c.status, ComponentStatus::Installed);
        assert_eq!(c.installed_version.as_deref(), Some("1.30.4"));
        assert!(c.installed_at.is_some());
    }

    #[tokio::test]
    async fn a_second_click_does_not_start_a_second_install() {
        // Two package managers fighting over dpkg's lock produces a failure
        // nobody can read.
        let db = db().await;
        assert!(
            db.claim_component("nginx", ComponentStatus::Installing, "task-1")
                .await
                .unwrap()
        );
        assert!(
            !db.claim_component("nginx", ComponentStatus::Installing, "task-2")
                .await
                .unwrap(),
            "a component already in flight must not be claimed again"
        );
        assert_eq!(
            db.component("nginx")
                .await
                .unwrap()
                .unwrap()
                .last_task_id
                .as_deref(),
            Some("task-1"),
            "the first claim keeps the component"
        );
    }

    #[tokio::test]
    async fn a_finished_component_can_be_claimed_again() {
        let db = db().await;
        db.claim_component("nginx", ComponentStatus::Installing, "task-1")
            .await
            .unwrap();
        db.component_installed("nginx", Some("1.30.4"))
            .await
            .unwrap();

        assert!(
            db.claim_component("nginx", ComponentStatus::Removing, "task-2")
                .await
                .unwrap()
        );
        db.component_removed("nginx").await.unwrap();
        let c = db.component("nginx").await.unwrap().unwrap();
        assert_eq!(c.status, ComponentStatus::Absent);
        assert!(c.installed_version.is_none());
    }

    #[tokio::test]
    async fn a_failure_is_recorded_and_does_not_block_a_retry() {
        let db = db().await;
        db.claim_component("nginx", ComponentStatus::Installing, "task-1")
            .await
            .unwrap();
        db.component_failed("nginx", "E: Unable to locate package nginx")
            .await
            .unwrap();

        let c = db.component("nginx").await.unwrap().unwrap();
        assert_eq!(c.status, ComponentStatus::Failed);
        assert!(c.last_error.unwrap().contains("Unable to locate"));
        assert!(
            db.claim_component("nginx", ComponentStatus::Installing, "task-2")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_successful_install_clears_a_previous_failure() {
        let db = db().await;
        db.claim_component("nginx", ComponentStatus::Installing, "t1")
            .await
            .unwrap();
        db.component_failed("nginx", "mirror unreachable")
            .await
            .unwrap();
        db.claim_component("nginx", ComponentStatus::Installing, "t2")
            .await
            .unwrap();
        db.component_installed("nginx", Some("1.30.4"))
            .await
            .unwrap();

        assert!(
            db.component("nginx")
                .await
                .unwrap()
                .unwrap()
                .last_error
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_agent_restart_releases_components_left_in_flight() {
        // Otherwise the install button stays disabled forever.
        let db = db().await;
        db.claim_component("nginx", ComponentStatus::Installing, "t1")
            .await
            .unwrap();
        db.claim_component("php8.3", ComponentStatus::Removing, "t2")
            .await
            .unwrap();
        db.claim_component("mariadb", ComponentStatus::Installing, "t3")
            .await
            .unwrap();
        db.component_installed("mariadb", Some("11.4"))
            .await
            .unwrap();

        assert_eq!(db.reconcile_components().await.unwrap(), 2);
        assert!(
            !db.component("nginx")
                .await
                .unwrap()
                .unwrap()
                .status
                .is_busy()
        );
        assert_eq!(
            db.component("mariadb").await.unwrap().unwrap().status,
            ComponentStatus::Installed
        );
    }

    #[tokio::test]
    async fn several_components_coexist() {
        let db = db().await;
        for slug in ["nginx", "php8.3", "php8.4", "mariadb"] {
            db.claim_component(slug, ComponentStatus::Installing, "t")
                .await
                .unwrap();
            db.component_installed(slug, Some("1.0")).await.unwrap();
        }
        let all = db.components().await.unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].slug, "mariadb", "listing is sorted");
    }
}
