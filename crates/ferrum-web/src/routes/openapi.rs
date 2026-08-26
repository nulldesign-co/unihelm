//! The machine-readable face of the API (spec §13).
//!
//! The OpenAPI 3.1 document is generated from the same handler annotations the
//! router serves, so it cannot describe an API this binary does not have. The
//! reverse — a route the document forgot — is exactly the drift this module's
//! tests exist to catch: the document lives next to the code, but nothing in
//! the type system forces a new `.route(...)` line to come with a
//! `#[utoipa::path]`, so a source-level completeness check does it instead.
//!
//! JSON only, on purpose: bundling swagger-ui would spend the UI budget (spec
//! §3) on a viewer any client can run locally against this document.

use std::sync::OnceLock;

use axum::http::header;
use axum::response::IntoResponse;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::auth::CurrentUser;

/// The whole documented surface. Handlers are listed here and annotated where
/// they live; referenced request/response schemas are collected automatically.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ferrum Panel API",
        description = "Everything the UI can do goes through these endpoints \
            (spec §2.6) — there is no private channel, so this document is the \
            product surface. Errors always carry the `FER-xxxx` envelope \
            (`ApiErrorBody`); clients should branch on the `slug`.",
    ),
    paths(
        super::auth::login,
        super::auth::logout,
        super::auth::me,
        super::server::overview,
        super::server::services,
        super::stack::status,
        super::stack::install,
        super::stack::remove,
        super::sites::list,
        super::sites::create,
        super::sites::update,
        super::sites::delete,
        super::sites::drift,
        super::panel_tls::issue,
        super::panel_tls::status,
        super::quota::backend,
        super::plans::list,
        super::plans::create,
        super::plans::update,
        super::plans::delete,
        super::plans::assign,
        super::plans::suspend,
        super::plans::unsuspend,
        super::certs::issue,
        super::certs::list,
        super::tasks::list,
        super::tasks::detail,
        super::tasks::logs,
        document,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Sessions and the current account"),
        (name = "server", description = "Host metrics and managed services"),
        (name = "stack", description = "Installing and removing stack components"),
        (name = "sites", description = "Site CRUD and config drift"),
        (name = "plans", description = "Plan limits, feature flags and assignment"),
        (name = "subscriptions", description = "Suspension lifecycle"),
        (name = "certificates", description = "TLS issuance and inventory"),
        (name = "tasks", description = "Long-running work: polling and logs"),
        (name = "meta", description = "The API describing itself"),
    ),
)]
pub struct ApiDoc;

/// Declares how a caller authenticates (spec §12.7): a session cookie on every
/// request, plus the CSRF header on anything state-changing. Written as
/// `securitySchemes` so generated clients know to send both.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                crate::auth::SESSION_COOKIE,
                "Session cookie set by POST /api/auth/login.",
            ))),
        );
        components.add_security_scheme(
            "csrf_header",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                crate::auth::CSRF_HEADER,
                "CSRF token from the login (or /api/auth/me) response; required \
                 on every state-changing request.",
            ))),
        );
    }
}

/// Serialized once, on first request: the document is a static property of
/// this binary, so re-deriving it per request would be pure waste.
static RENDERED: OnceLock<String> = OnceLock::new();

fn rendered() -> &'static str {
    RENDERED.get_or_init(|| {
        ApiDoc::openapi()
            .to_json()
            .expect("the OpenAPI document is built from static annotations; serializing cannot fail")
    })
}

/// This API, as OpenAPI 3.1.
///
/// Behind the session like every other read: the document enumerates the
/// panel's attack surface, which is not an anonymous caller's business.
#[utoipa::path(
    get,
    path = "/api/openapi.json",
    tag = "meta",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "This document", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = crate::error::ApiErrorBody),
    ),
)]
pub async fn document(_current: CurrentUser) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], rendered())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The router source, captured at compile time. `include_str!` is the
    /// tolerance mechanism as much as the drift detector: this test only ever
    /// sees the `mod.rs` it was compiled with, so a parallel branch adding
    /// routes cannot fail *this* build — but the moment their routes merge into
    /// this file, they must be documented or allowlisted below.
    const ROUTER_SRC: &str = include_str!("mod.rs");

    /// Routes that are registered but deliberately absent from the document.
    const UNDOCUMENTED: &[&str] = &[
        // SSE: OpenAPI 3.1 has no first-class way to describe an event stream,
        // and a half-true schema is worse than a named omission.
        "/api/events",
        // Liveness for systemd and load balancers, not part of the product API.
        "/healthz",
    ];

    /// Wave-1 route areas being built on parallel branches (the allocations in
    /// docs/wave1-contracts.md). Their documentation lands with their code;
    /// remove each prefix as its area gets annotated so drift detection covers
    /// it again.
    const PARALLEL_AREA_PREFIXES: &[&str] = &[
        "/api/files",
        "/api/databases",
        "/api/cron",
        "/api/dns",
        "/api/backups",
        "/api/apps",
        // `/api/plans` is deliberately absent: the plans area is annotated and
        // documented, so drift detection covers it again.
        "/api/firewall",
    ];

    /// Every string literal handed to `.route(...)` in the router source.
    ///
    /// Parsed textually rather than by walking the axum `Router`, because the
    /// built router does not expose its paths — and a textual scan of the same
    /// file the compiler saw is exactly as current as the binary itself.
    fn registered_paths() -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = ROUTER_SRC;
        while let Some(pos) = rest.find(".route(") {
            rest = &rest[pos + ".route(".len()..];
            // `.route(` may be split from its path literal by a line break
            // (rustfmt does this for long lines), so skip any whitespace.
            let after = rest.trim_start();
            if let Some(quoted) = after.strip_prefix('"') {
                if let Some(end) = quoted.find('"') {
                    out.push(quoted[..end].to_string());
                }
            }
        }
        assert!(
            !out.is_empty(),
            "found no .route(\"...\") calls in routes/mod.rs — the scanner is broken, \
             which would make the completeness test pass vacuously"
        );
        out
    }

    fn document() -> serde_json::Value {
        serde_json::from_str(rendered()).expect("the served document must be valid JSON")
    }

    #[test]
    fn the_document_builds_serializes_and_is_openapi_3_1() {
        let doc = document();
        let version = doc["openapi"].as_str().unwrap_or_default();
        assert!(
            version.starts_with("3.1"),
            "spec §13 says OpenAPI 3.1, got {version:?}"
        );
        assert!(doc["paths"].is_object());
    }

    #[test]
    fn the_session_cookie_and_csrf_header_are_declared_as_security_schemes() {
        let doc = document();
        let schemes = &doc["components"]["securitySchemes"];
        assert_eq!(schemes["session_cookie"]["type"], "apiKey");
        assert_eq!(schemes["session_cookie"]["in"], "cookie");
        assert_eq!(schemes["session_cookie"]["name"], crate::auth::SESSION_COOKIE);
        assert_eq!(schemes["csrf_header"]["type"], "apiKey");
        assert_eq!(schemes["csrf_header"]["in"], "header");
        assert_eq!(schemes["csrf_header"]["name"], crate::auth::CSRF_HEADER);
    }

    #[test]
    fn the_error_envelope_is_modelled_once_with_code_slug_and_message() {
        let doc = document();
        let envelope = &doc["components"]["schemas"]["ApiErrorBody"];
        assert!(
            envelope.is_object(),
            "the FER-xxxx envelope must be a shared schema, not restated per route"
        );
        for field in ["code", "slug", "message"] {
            assert!(
                envelope["properties"][field].is_object(),
                "ApiErrorBody must document `{field}`"
            );
        }
    }

    #[test]
    fn every_registered_route_is_documented_or_deliberately_allowlisted() {
        let doc = document();
        let documented = doc["paths"].as_object().expect("paths object");
        let mut missing = Vec::new();
        for path in registered_paths() {
            let allowlisted = UNDOCUMENTED.contains(&path.as_str())
                || PARALLEL_AREA_PREFIXES
                    .iter()
                    .any(|prefix| path.starts_with(prefix));
            if !allowlisted && !documented.contains_key(&path) {
                missing.push(path);
            }
        }
        assert!(
            missing.is_empty(),
            "routes registered in routes/mod.rs but absent from the OpenAPI document \
             (annotate the handler with #[utoipa::path] and list it in ApiDoc, or \
             allowlist it here with a reason): {missing:?}"
        );
    }

    #[test]
    fn documented_paths_do_not_outlive_their_routes() {
        // Drift in the other direction: describing an endpoint the router no
        // longer serves is a lie to every generated client.
        let doc = document();
        let registered = registered_paths();
        let stale: Vec<&String> = doc["paths"]
            .as_object()
            .expect("paths object")
            .keys()
            .filter(|path| !registered.contains(path))
            .collect();
        assert!(
            stale.is_empty(),
            "documented but not registered in routes/mod.rs: {stale:?}"
        );
    }

    #[test]
    fn every_mutation_requires_the_csrf_header_except_login() {
        // The CSRF contract (spec §12.7): a cookie alone must never authorize
        // a state change. If this fails, either the annotation forgot the
        // csrf_header scheme or a mutation genuinely skips CSRF — and the
        // second one is a bug in the API, not in this test.
        let doc = document();
        for (path, item) in doc["paths"].as_object().expect("paths object") {
            for method in ["post", "put", "patch", "delete"] {
                let Some(op) = item.get(method) else { continue };
                if path == "/api/auth/login" {
                    // The one mutation that cannot present a CSRF token yet:
                    // it is where the token comes from.
                    continue;
                }
                let requires_csrf = op["security"]
                    .as_array()
                    .is_some_and(|reqs| reqs.iter().any(|req| req.get("csrf_header").is_some()));
                assert!(
                    requires_csrf,
                    "{} {path} is a mutation but its documented security does not \
                     include csrf_header",
                    method.to_uppercase(),
                );
            }
        }
    }

    #[test]
    fn login_is_documented_as_reachable_without_a_session() {
        let doc = document();
        let security = doc["paths"]["/api/auth/login"]["post"]["security"]
            .as_array()
            .expect("login must declare its security explicitly")
            .clone();
        // `security(())` renders as one empty requirement: "no auth needed".
        assert!(
            security
                .iter()
                .any(|req| req.as_object().is_some_and(|o| o.is_empty())),
            "login must be marked public; it is where sessions come from"
        );
    }
}
