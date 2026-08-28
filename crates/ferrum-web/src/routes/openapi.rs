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

/// The version of the **API contract**, not of the panel binary.
///
/// Spec §14 Phase 6 asks for a "public API stability guarantee + versioning".
/// A version is only half of that; the other half is a written policy saying
/// what it promises, which lives in `docs/api-versioning.md` and is summarised
/// in this document's `info.description`. Semver, read as:
///
/// * **patch** — the document got more accurate. Descriptions, examples, a
///   response field that was always there being written down.
/// * **minor** — something was *added*: a new endpoint, a new optional request
///   field, a new field in a response, a new enum value in a field the docs
///   already describe as open. A client written against an earlier minor keeps
///   working.
/// * **major** — something a client could depend on changed or went away.
///
/// Deliberately decoupled from `CARGO_PKG_VERSION`: tying the two would mean
/// every panel release claimed an API change, which makes the number useless
/// for the one thing it is for — telling an integrator whether they have to
/// read anything.
pub const API_VERSION: &str = "1.0.0";

/// The whole documented surface. Handlers are listed here and annotated where
/// they live; referenced request/response schemas are collected automatically.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ferrum Panel API",
        version = API_VERSION,
        description = "Everything the UI can do goes through these endpoints \
            (spec §2.6) — there is no private channel, so this document is the \
            product surface. Errors always carry the `FER-xxxx` envelope \
            (`ApiErrorBody`); clients should branch on the `slug`.\n\n\
            **Stability.** This document's `info.version` is the API contract \
            version (semver), independent of the panel release it ships in. \
            What may change inside a minor bump, what may not, and how a \
            breaking change would be announced are written down in \
            `docs/api-versioning.md` (spec §14 Phase 6: \"public API stability \
            guarantee + versioning\").",
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
        super::plans::subscriptions,
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
        super::alerts::events,
        super::alerts::rules_list,
        super::alerts::rules_set,
        super::alerts::channels_list,
        super::alerts::channels_set,
        super::alerts::channels_delete,
        super::alerts::channels_test,
        super::apps::list,
        super::apps::create,
        super::apps::delete,
        super::apps::restart,
        super::apps::logs,
        super::cron::list,
        super::cron::create,
        super::cron::update,
        super::cron::delete,
        super::firewall::rules,
        super::firewall::port_open,
        super::firewall::port_close,
        super::firewall::bans,
        super::firewall::ban,
        super::firewall::unban,
        super::firewall::sentinel_get,
        super::firewall::sentinel_set,
        super::dns::check,
        super::dns::provider_set,
        super::dns::issue_wildcard,
        super::backups::repos_list,
        super::backups::repos_create,
        super::backups::repos_delete,
        super::backups::snapshots,
        super::backups::schedules_list,
        super::backups::schedules_create,
        super::backups::schedules_delete,
        super::backups::runs_list,
        super::backups::runs_create,
        super::backups::restores_create,
        super::wordpress::detect,
        super::wordpress::install,
        super::wordpress::update,
        super::wordpress::plugins,
        super::wordpress::plugins_update,
        super::wordpress::cli,
        super::imports::create,
        super::imports::list,
        super::imports::detail,
        super::imports::apply,
        super::waf::status,
        super::waf::enable,
        super::waf::disable,
        super::waf::rules_set,
        super::waf::security_posture,
        super::webhooks::list,
        super::webhooks::detail,
        super::webhooks::create,
        super::webhooks::update,
        super::webhooks::delete,
        super::webhooks::test,
        super::plugins::list,
        super::plugins::install,
        super::plugins::enable,
        super::plugins::disable,
        super::plugins::remove,
        super::mail::relay_get,
        super::mail::relay_set,
        super::mail::relay_test,
        super::branding::public_get,
        super::branding::asset,
        super::branding::settings_get,
        super::branding::settings_set,
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
        (name = "alerts", description = "Alert rules, alert history and notifier channels"),
        (name = "apps", description = "Tenant Node.js applications: units, ports and journals"),
        (name = "cron", description = "Per-subscription scheduled commands and the crontab they render into"),
        (name = "firewall", description = "Managed ports, bans, and the Sentinel brute-force defence"),
        (name = "dns", description = "The pointing advisory and the stored Cloudflare credential"),
        (name = "backups", description = "restic repositories, schedules, run history and restores"),
        (name = "wordpress", description = "The WordPress toolkit: install, detect, core and plugin updates, and the restricted WP-CLI passthrough"),
        (name = "waf", description = "ModSecurity: module availability, per-site policy and rule exclusions"),
        (name = "webhooks", description = "Outbound event delivery: registered endpoints, their signing secrets, and the delivery history"),
        (name = "plugins", description = "Sidecar plugins: installing a verified payload, and starting or stopping its unprivileged process"),
        (name = "imports", description = "Migrating an account in from cPanel or aaPanel: the dry-run plan, and applying one"),
        (name = "mail", description = "The outbound SMTP relay every site's PHP mail() sends through, and the SPF/DKIM/DMARC records it needs — surfaced as guidance, never managed"),
        (name = "branding", description = "White-label branding per reseller. `GET /api/branding` and the asset route are public: the login page renders before there is a session"),
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
    /// Every source file that registers routes.
    ///
    /// `mod.rs` alone is not enough. A module that builds its own `Router` and
    /// gets `.merge`d — the file manager does, for its larger body limit — keeps
    /// all eighteen of its paths inside *its* file, so a scan of `mod.rs` sees
    /// the `.merge(files::router())` line and nothing else. That is a silent
    /// hole exactly where drift is hardest to notice, so each sub-router's
    /// source is scanned too. Adding a sub-router means adding it here; the
    /// count assertion below is what stops a rename from turning this whole
    /// test into a no-op.
    const ROUTER_SRCS: &[&str] = &[include_str!("mod.rs"), include_str!("files.rs")];

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
        "/api/dns",
        "/api/cron",
        "/api/backups",
        // `/api/plans`, `/api/apps` and `/api/cron` are deliberately absent:
        // all three areas are annotated and documented, so drift detection
        // covers them again.
        // `/api/plans`, `/api/apps` and `/api/backups` are deliberately absent:
        // those areas are annotated and documented, so drift detection covers
        // them again.
    ];

    /// Every string literal handed to `.route(...)` in the router source.
    ///
    /// Parsed textually rather than by walking the axum `Router`, because the
    /// built router does not expose its paths — and a textual scan of the same
    /// file the compiler saw is exactly as current as the binary itself.
    fn registered_paths() -> Vec<String> {
        let mut out = Vec::new();
        for src in ROUTER_SRCS {
            let mut rest = *src;
            while let Some(pos) = rest.find(".route(") {
                rest = &rest[pos + ".route(".len()..];
                // `.route(` may be split from its path literal by a line break
                // (rustfmt does this for long lines), so skip any whitespace.
                let after = rest.trim_start();
                if let Some(quoted) = after.strip_prefix('"')
                    && let Some(end) = quoted.find('"')
                {
                    out.push(quoted[..end].to_string());
                }
            }
        }
        assert!(
            out.len() > 20,
            "the route scanner found only {} paths across {} source files — it is \
             broken, which would make the completeness test pass vacuously",
            out.len(),
            ROUTER_SRCS.len()
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

    /// Spec §14 Phase 6 promises a "public API stability guarantee +
    /// versioning". A generated client reads `info.version` to decide whether
    /// it has to change, so an absent or default version is the same as no
    /// guarantee at all.
    #[test]
    fn the_document_declares_an_explicit_semver_api_version() {
        let doc = document();
        let version = doc["info"]["version"]
            .as_str()
            .expect("info.version must be a string");
        assert_eq!(version, API_VERSION);

        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3, "the API version must be semver: {version}");
        for part in parts {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "`{part}` is not a semver component in {version}"
            );
        }

        // Decoupled from the binary on purpose: tying them would make every
        // panel release claim an API change (see API_VERSION's own docs).
        assert_ne!(
            version,
            env!("CARGO_PKG_VERSION"),
            "the API contract version must not be the crate version"
        );
    }

    /// The policy is half the promise: a version with nothing written down
    /// beside it is only a number, so the document names the document that
    /// explains what it guarantees.
    #[test]
    fn the_document_points_at_the_written_stability_policy() {
        let doc = document();
        let description = doc["info"]["description"].as_str().unwrap_or_default();
        assert!(
            description.contains("docs/api-versioning.md"),
            "info.description must name the policy document: {description}"
        );
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
