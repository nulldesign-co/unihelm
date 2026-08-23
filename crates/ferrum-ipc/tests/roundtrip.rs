//! End-to-end: a real Unix socket, a real client, a real handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use ferrum_core::{AuthContext, ErrorCode, FerrumError, Role, TaskId, TenantScope, UserId};
use ferrum_ipc::frame::{
    ControlFrame, ControlKind, EventFrame, EventKind, RequestFrame, ResponseBody,
};
use ferrum_ipc::peercred::{PeerCred, PeerPolicy};
use ferrum_ipc::server::{EventSink, IpcServer, RequestHandler, SharedHandler};
use ferrum_ipc::{IpcClient, IpcError};

struct TestHandler {
    calls: AtomicUsize,
}

#[async_trait]
impl RequestHandler for TestHandler {
    async fn handle_request(
        &self,
        req: RequestFrame,
        peer: PeerCred,
        events: EventSink,
    ) -> ResponseBody {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match req.op.as_str() {
            "sys.ping" => ResponseBody::Ok {
                data: serde_json::json!({ "pong": true, "peer_uid": peer.uid }),
            },
            "sys.echo" => ResponseBody::Ok { data: req.input },
            "sys.slow" => {
                let task_id = TaskId::new();
                for seq in 0..3 {
                    events
                        .emit(EventFrame::new(EventKind::TaskLog {
                            task_id,
                            seq,
                            line: format!("step {seq}"),
                        }))
                        .await;
                }
                ResponseBody::Task { task_id }
            }
            other => ResponseBody::Err {
                error: FerrumError::new(
                    ErrorCode::UnknownOperation,
                    format!("no such op `{other}`"),
                ),
            },
        }
    }

    async fn handle_control(&self, ctl: ControlFrame, _peer: PeerCred, events: EventSink) {
        if matches!(ctl.kind, ControlKind::Ping) {
            events
                .emit(EventFrame::for_request(
                    ctl.id,
                    EventKind::Pong {
                        agent_version: "test".into(),
                    },
                ))
                .await;
        }
    }
}

fn auth() -> AuthContext {
    AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-e2e")
}

async fn start() -> (tempfile::TempDir, IpcClient, Arc<TestHandler>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let handler = Arc::new(TestHandler {
        calls: AtomicUsize::new(0),
    });

    let server = IpcServer::bind(&path, None, PeerPolicy::same_user_only()).unwrap();
    {
        let factory = Arc::new(SharedHandler(handler.clone()));
        tokio::spawn(async move {
            server.serve(factory, std::future::pending::<()>()).await;
        });
    }

    let client = IpcClient::connect(&path).await.unwrap();
    (dir, client, handler)
}

#[tokio::test]
async fn request_response_roundtrip() {
    let (_dir, client, handler) = start().await;

    let body = client
        .call("sys.ping", &auth(), serde_json::json!({}))
        .await
        .unwrap();
    match body {
        ResponseBody::Ok { data } => assert_eq!(data["pong"], true),
        other => panic!("unexpected body: {other:?}"),
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unknown_operation_returns_a_stable_error_code() {
    let (_dir, client, _) = start().await;
    let body = client
        .call("does.not.exist", &auth(), serde_json::json!({}))
        .await
        .unwrap();
    match body {
        ResponseBody::Err { error } => {
            assert_eq!(error.code, ErrorCode::UnknownOperation);
            assert_eq!(error.code.code(), "FER-1504");
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[tokio::test]
async fn concurrent_calls_are_correlated_by_id() {
    let (_dir, client, _) = start().await;
    let client = Arc::new(client);

    let mut handles = Vec::new();
    for i in 0..32 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let body = client
                .call("sys.echo", &auth(), serde_json::json!({ "i": i }))
                .await
                .unwrap();
            match body {
                ResponseBody::Ok { data } => {
                    assert_eq!(data["i"], i, "reply landed on the wrong caller")
                }
                other => panic!("unexpected body: {other:?}"),
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn long_operations_return_a_task_id_and_stream_logs() {
    let (_dir, client, _) = start().await;

    let mut events = client.events();
    let body = client
        .call("sys.slow", &auth(), serde_json::json!({}))
        .await
        .unwrap();
    let task_id = match body {
        ResponseBody::Task { task_id } => task_id,
        other => panic!("expected a task, got {other:?}"),
    };

    let mut lines = Vec::new();
    while lines.len() < 3 {
        let ev = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
            .await
            .expect("timed out waiting for task logs")
            .expect("event channel closed");
        if let EventKind::TaskLog {
            task_id: t, line, ..
        } = ev.kind
        {
            assert_eq!(t, task_id);
            lines.push(line);
        }
    }
    assert_eq!(lines, vec!["step 0", "step 1", "step 2"]);
}

#[tokio::test]
async fn ping_gets_a_pong() {
    let (_dir, client, _) = start().await;
    client.ping().await.unwrap();
}

#[tokio::test]
async fn socket_is_not_world_accessible() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let _server = IpcServer::bind(&path, None, PeerPolicy::same_user_only()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the socket must never be readable by other accounts"
    );
}

#[tokio::test]
async fn bind_replaces_a_stale_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    std::fs::write(&path, b"leftover from a crash").unwrap();
    let server = IpcServer::bind(&path, None, PeerPolicy::same_user_only());
    assert!(
        server.is_ok(),
        "a stale socket must not stop the agent from starting"
    );
}

#[tokio::test]
async fn calls_fail_fast_once_the_agent_goes_away() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let handler = Arc::new(TestHandler {
        calls: AtomicUsize::new(0),
    });
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    let server = IpcServer::bind(&path, None, PeerPolicy::same_user_only()).unwrap();
    tokio::spawn(async move {
        server
            .serve(Arc::new(SharedHandler(handler)), async {
                let _ = stop_rx.await;
            })
            .await;
    });

    let client = IpcClient::connect(&path).await.unwrap();
    client
        .call("sys.ping", &auth(), serde_json::json!({}))
        .await
        .unwrap();

    // Drop the listener and let the connection close.
    let _ = stop_tx.send(());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Existing connections may survive the accept loop shutting down, so the
    // assertion is about *not hanging*: either it errors, or it still answers.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.call("sys.ping", &auth(), serde_json::json!({})),
    )
    .await;
    assert!(
        result.is_ok(),
        "a call must not hang past its timeout when the agent is gone"
    );
    if let Ok(Err(e)) = result {
        assert!(
            matches!(e, IpcError::Closed | IpcError::Timeout),
            "unexpected error: {e}"
        );
    }
}
