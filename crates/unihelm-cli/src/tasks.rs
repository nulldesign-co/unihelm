//! `unihelm task` (spec §11.17, §11.20).
//!
//! Tasks are the one area with no operation behind it: the task table is the
//! panel's own bookkeeping, and the agent exposes it as rows and a control
//! frame rather than as a registry entry. So this reads the same database
//! `unihelm-web` reads for `/api/tasks`, through the same tenant-scoped
//! repository — a CLI-shaped copy of that endpoint, not a second source of
//! truth.
//!
//! `--follow` streams from the database rather than from the event bus. That is
//! not a shortcut: events only exist from the moment you subscribe, so a
//! follower that attached a millisecond late would silently drop the first
//! lines of the log — usually the ones that say what went wrong.

use anyhow::{Context, Result};
use serde_json::json;
use unihelm_core::TaskId;

use crate::cli::TaskCommand;
use crate::session::Session;

pub async fn run(session: &Session, cmd: &TaskCommand) -> Result<i32> {
    match cmd {
        TaskCommand::List(page) => {
            let repo = session.db().tasks(&session.auth().tenant_scope);
            let tasks = repo
                .list(page.limit.unwrap_or(50), page.offset.unwrap_or(0).max(0))
                .await?;
            let active = repo.count_active().await?;
            session.print("task.list", &json!({ "tasks": tasks, "active": active }));
            Ok(0)
        }
        TaskCommand::Show { task_id } => {
            let id = parse_task_id(task_id)?;
            let task = session
                .db()
                .tasks(&session.auth().tenant_scope)
                .by_id(id)
                .await?
                .with_context(|| format!("no task {id}"))?;
            session.print("task.show", &serde_json::to_value(&task)?);
            Ok(0)
        }
        TaskCommand::Logs { task_id, after_seq } => {
            let id = parse_task_id(task_id)?;
            if session.follow() {
                return session.follow_task(id).await;
            }
            let lines = session
                .db()
                .tasks(&session.auth().tenant_scope)
                .logs(id, (*after_seq).max(0), 10_000)
                .await?;
            if session.json() {
                session.print_json(&json!({ "lines": lines }));
            } else {
                for line in &lines {
                    println!("{}", line.line);
                }
            }
            Ok(0)
        }
        TaskCommand::Cancel { task_id } => session.cancel_task(parse_task_id(task_id)?).await,
    }
}

/// A task id is a UUID. Saying so beats the parser's own message, which talks
/// about groups and hyphens.
fn parse_task_id(raw: &str) -> Result<TaskId> {
    raw.parse::<TaskId>()
        .map_err(|_| anyhow::anyhow!("`{raw}` is not a task id; task ids are UUIDs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_id_that_is_not_a_uuid_is_refused_before_the_database_is_touched() {
        let err = parse_task_id("not-a-uuid").unwrap_err();
        assert!(err.to_string().contains("UUID"), "{err}");
        assert!(parse_task_id("").is_err());
        assert!(parse_task_id("11111111-2222-3333-4444-555555555555").is_ok());
    }
}
