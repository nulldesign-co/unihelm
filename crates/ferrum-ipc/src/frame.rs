//! The envelopes that travel over the socket (spec §5.3).

use ferrum_core::{AuthContext, FerrumError, TaskId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped only for an incompatible change. Receivers reject frames whose `v`
/// they do not understand rather than guessing.
pub const PROTOCOL_VERSION: u16 = 1;

const fn default_version() -> u16 {
    PROTOCOL_VERSION
}

/// `{ "v": 1, "id": "...", "op": "site.create", "auth": {…}, "input": {…} }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFrame {
    #[serde(default = "default_version")]
    pub v: u16,
    pub id: Uuid,
    /// The registry key, e.g. `svc.status`. Validated against the whitelist by
    /// the agent — never used to build a path or a command.
    pub op: String,
    pub auth: AuthContext,
    #[serde(default)]
    pub input: serde_json::Value,
}

impl RequestFrame {
    pub fn new(op: impl Into<String>, auth: AuthContext, input: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: Uuid::new_v4(),
            op: op.into(),
            auth,
            input,
        }
    }
}

/// What the agent decided about a request.
///
/// `task` is the interesting one: anything slower than ~300 ms returns
/// immediately with a task id and streams its progress as events (spec §10.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum ResponseBody {
    Ok {
        #[serde(default)]
        data: serde_json::Value,
    },
    Err {
        error: FerrumError,
    },
    Task {
        task_id: TaskId,
    },
}

/// `{ "v": 1, "id": "...", "result": "ok", "data": {…} }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFrame {
    #[serde(default = "default_version")]
    pub v: u16,
    pub id: Uuid,
    #[serde(flatten)]
    pub body: ResponseBody,
}

impl ResponseFrame {
    pub fn ok(id: Uuid, data: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            body: ResponseBody::Ok { data },
        }
    }
    pub fn err(id: Uuid, error: FerrumError) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            body: ResponseBody::Err { error },
        }
    }
    pub fn task(id: Uuid, task_id: TaskId) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            body: ResponseBody::Task { task_id },
        }
    }
}

/// Out-of-band client requests that are not operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case")]
pub enum ControlKind {
    /// Start receiving [`EventKind::TaskLog`] / [`EventKind::TaskState`] for a task.
    Subscribe {
        task_id: TaskId,
    },
    Unsubscribe {
        task_id: TaskId,
    },
    /// Ask the agent to cancel a task; only honoured where cancellation is safe.
    CancelTask {
        task_id: TaskId,
    },
    /// Liveness probe used by the mutual watchdog (spec §5.5).
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFrame {
    #[serde(default = "default_version")]
    pub v: u16,
    pub id: Uuid,
    #[serde(flatten)]
    pub kind: ControlKind,
}

impl ControlFrame {
    pub fn new(kind: ControlKind) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: Uuid::new_v4(),
            kind,
        }
    }
}

/// Server-pushed messages that are not a reply to a specific request id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventKind {
    /// One line of task output. `seq` lets the UI reorder and de-duplicate after
    /// a reconnect; the same line is persisted to `task_logs`.
    TaskLog {
        task_id: TaskId,
        seq: i64,
        line: String,
    },
    /// A task changed state, including its terminal state and failure reason.
    TaskState {
        task_id: TaskId,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Reply to [`ControlKind::Ping`].
    Pong { agent_version: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFrame {
    #[serde(default = "default_version")]
    pub v: u16,
    /// Correlates with the control frame that created the subscription, when
    /// there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl EventFrame {
    pub fn new(kind: EventKind) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: None,
            kind,
        }
    }
    pub fn for_request(id: Uuid, kind: EventKind) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: Some(id),
            kind,
        }
    }
}

/// Anything the client may send. Distinguished by the presence of `op` vs
/// `control`, so the JSON on the wire stays exactly as documented in §5.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientFrame {
    Request(RequestFrame),
    Control(ControlFrame),
}

impl ClientFrame {
    pub fn version(&self) -> u16 {
        match self {
            ClientFrame::Request(f) => f.v,
            ClientFrame::Control(f) => f.v,
        }
    }
    pub fn id(&self) -> Uuid {
        match self {
            ClientFrame::Request(f) => f.id,
            ClientFrame::Control(f) => f.id,
        }
    }
}

/// Anything the agent may send: a reply (`result`) or a push (`event`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerFrame {
    Response(ResponseFrame),
    Event(EventFrame),
}

impl ServerFrame {
    pub fn version(&self) -> u16 {
        match self {
            ServerFrame::Response(f) => f.v,
            ServerFrame::Event(f) => f.v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::{Role, TenantScope, UserId};

    fn auth() -> AuthContext {
        AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-1")
    }

    fn roundtrip_client(f: &ClientFrame) -> ClientFrame {
        serde_json::from_str(&serde_json::to_string(f).unwrap()).unwrap()
    }

    #[test]
    fn request_and_control_are_unambiguous() {
        let req = ClientFrame::Request(RequestFrame::new(
            "svc.status",
            auth(),
            serde_json::json!({}),
        ));
        assert!(matches!(roundtrip_client(&req), ClientFrame::Request(_)));

        let ctl = ClientFrame::Control(ControlFrame::new(ControlKind::Ping));
        assert!(matches!(roundtrip_client(&ctl), ClientFrame::Control(_)));

        let sub = ClientFrame::Control(ControlFrame::new(ControlKind::Subscribe {
            task_id: TaskId::new(),
        }));
        assert!(matches!(roundtrip_client(&sub), ClientFrame::Control(_)));
    }

    #[test]
    fn response_and_event_are_unambiguous() {
        let id = Uuid::new_v4();
        for f in [
            ServerFrame::Response(ResponseFrame::ok(id, serde_json::json!({"a":1}))),
            ServerFrame::Response(ResponseFrame::task(id, TaskId::new())),
            ServerFrame::Response(ResponseFrame::err(id, FerrumError::invalid("nope"))),
            ServerFrame::Event(EventFrame::new(EventKind::Pong {
                agent_version: "0.1.0".into(),
            })),
            ServerFrame::Event(EventFrame::new(EventKind::TaskLog {
                task_id: TaskId::new(),
                seq: 1,
                line: "hello".into(),
            })),
        ] {
            let json = serde_json::to_string(&f).unwrap();
            let back: ServerFrame = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&f),
                std::mem::discriminant(&back),
                "variant changed across roundtrip: {json}"
            );
        }
    }

    #[test]
    fn wire_shape_matches_the_spec() {
        let id = Uuid::nil();
        let v = serde_json::to_value(ResponseFrame::ok(id, serde_json::json!({"x":1}))).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["result"], "ok");
        assert_eq!(v["data"]["x"], 1);

        let v = serde_json::to_value(ResponseFrame::task(id, TaskId::new())).unwrap();
        assert_eq!(v["result"], "task");
        assert!(v["task_id"].is_string());

        let req = RequestFrame::new("site.create", auth(), serde_json::json!({"domain":"a.com"}));
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["op"], "site.create");
        assert!(v["auth"].is_object());
        assert_eq!(v["input"]["domain"], "a.com");
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compat() {
        let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","result":"ok","data":{},
                       "future_field":"from a newer agent"}"#;
        let f: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(f, ServerFrame::Response(_)));
    }

    #[test]
    fn missing_version_defaults_to_current() {
        let json = r#"{"id":"00000000-0000-0000-0000-000000000000","result":"ok","data":{}}"#;
        let f: ServerFrame = serde_json::from_str(json).unwrap();
        assert_eq!(f.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn invalid_typed_input_is_rejected_at_the_protocol_edge() {
        // The auth context is a typed struct: a frame carrying a bogus role never
        // becomes a usable value.
        let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","op":"svc.status",
                       "auth":{"actor_user_id":1,"acting_role":"superadmin",
                               "tenant_scope":{"kind":"global"},"permissions":[],"request_id":"x"},
                       "input":{}}"#;
        assert!(serde_json::from_str::<ClientFrame>(json).is_err());
    }
}
