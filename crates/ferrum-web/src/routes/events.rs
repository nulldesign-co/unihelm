//! Server-sent events: the live half of the task drawer (spec §10.1, §11.17).
//!
//! SSE rather than websockets because the traffic is one-directional and SSE
//! reconnects on its own — one less thing to get right in the client, and one
//! less protocol on the panel's attack surface.

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use ferrum_core::TaskId;
use ferrum_ipc::frame::{EventFrame, EventKind};
use futures::stream::Stream;
use tokio::sync::broadcast;

use crate::auth::CurrentUser;
use crate::state::SharedState;

/// Comment frames keep proxies from closing an idle stream.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// Stream task events this caller is allowed to see.
///
/// Visibility is decided per task and then remembered for the life of the
/// stream, so a chatty install costs one authorisation check rather than one per
/// log line.
pub async fn stream(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.agent.events();
    let stream = async_stream::stream! {
        let mut rx = rx;
        let mut visible: HashMap<TaskId, bool> = HashMap::new();

        loop {
            match rx.recv().await {
                Ok(frame) => {
                    let Some(task_id) = task_id_of(&frame) else { continue };

                    let allowed = match visible.get(&task_id) {
                        Some(known) => *known,
                        None => {
                            let ok = state
                                .db
                                .tasks(&current.auth.tenant_scope)
                                .by_id(task_id)
                                .await
                                .map(|t| t.is_some())
                                .unwrap_or(false);
                            visible.insert(task_id, ok);
                            ok
                        }
                    };
                    if !allowed {
                        continue;
                    }

                    if let Some(event) = to_sse(&frame) {
                        yield Ok(event);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // Tell the client rather than silently dropping: it can
                    // re-fetch the log from `/api/tasks/{id}/logs`.
                    tracing::warn!(skipped, "sse consumer lagged");
                    if let Ok(event) = Event::default()
                        .event("lagged")
                        .json_data(serde_json::json!({ "skipped": skipped }))
                    {
                        yield Ok(event);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEPALIVE).text("keep-alive"))
}

fn task_id_of(frame: &EventFrame) -> Option<TaskId> {
    match &frame.kind {
        EventKind::TaskLog { task_id, .. } | EventKind::TaskState { task_id, .. } => Some(*task_id),
        EventKind::Pong { .. } => None,
    }
}

fn to_sse(frame: &EventFrame) -> Option<Event> {
    let (name, payload) = match &frame.kind {
        EventKind::TaskLog { task_id, seq, line } => (
            "task.log",
            serde_json::json!({ "task_id": task_id, "seq": seq, "line": line }),
        ),
        EventKind::TaskState {
            task_id,
            status,
            progress,
            detail,
        } => (
            "task.state",
            serde_json::json!({
                "task_id": task_id,
                "status": status,
                "progress": progress,
                "detail": detail,
            }),
        ),
        EventKind::Pong { .. } => return None,
    };
    Event::default().event(name).json_data(payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pong_frames_are_not_forwarded_to_browsers() {
        let frame = EventFrame::new(EventKind::Pong {
            agent_version: "0.1.0".into(),
        });
        assert!(task_id_of(&frame).is_none());
        assert!(to_sse(&frame).is_none());
    }

    #[test]
    fn task_frames_carry_their_id() {
        let id = TaskId::new();
        let log = EventFrame::new(EventKind::TaskLog {
            task_id: id,
            seq: 1,
            line: "x".into(),
        });
        assert_eq!(task_id_of(&log), Some(id));
        assert!(to_sse(&log).is_some());

        let state = EventFrame::new(EventKind::TaskState {
            task_id: id,
            status: "ok".into(),
            progress: Some(100),
            detail: None,
        });
        assert_eq!(task_id_of(&state), Some(id));
    }
}
