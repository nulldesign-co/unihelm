//! Serving the embedded React application (spec §3, §4.3).
//!
//! The whole UI is compiled into the binary with `rust-embed`, so deploying the
//! panel is copying one file — no Node.js on the server, no static directory to
//! keep in sync, nothing to serve out of `/var/www` by accident.

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui-dist"]
struct Assets;

/// CSP hashes for the inline scripts in the served `index.html`.
///
/// index.html carries one inline script, and it has to be inline: it sets the
/// dark class from localStorage before the first paint, and an external file
/// would arrive too late to stop the page flashing the wrong theme. Under
/// `script-src 'self'` the browser refused to run it, so the panel shipped a
/// theme flash and an error in everybody's console — its own policy blocking
/// its own script.
///
/// The hashes are computed from the bytes actually being served rather than
/// written down next to the policy, because a hardcoded hash is wrong the moment
/// somebody edits the script, and wrong in a way that only shows up as a flicker
/// nobody connects to a CSP.
pub fn inline_script_hashes() -> Vec<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let Some(index) = Assets::get("index.html") else {
        return Vec::new();
    };
    let Ok(html) = std::str::from_utf8(index.data.as_ref()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut rest = html;
    // Only bare `<script>` blocks: a `<script src=...>` has no body to hash, and
    // its opening tag does not end in `>` immediately.
    while let Some(start) = rest.find("<script>") {
        let after = &rest[start + "<script>".len()..];
        let Some(end) = after.find("</script>") else {
            break;
        };
        let body = &after[..end];
        let digest = Sha256::digest(body.as_bytes());
        out.push(format!(
            "'sha256-{}'",
            base64::engine::general_purpose::STANDARD.encode(digest)
        ));
        rest = &after[end..];
    }
    out
}

/// Serve a built asset, falling back to `index.html` so client-side routes work
/// on a hard refresh.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // An API path that reaches here is a genuine 404, not a route for the SPA to
    // handle — returning index.html would turn every typo into a 200.
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => asset_response(path, content.data.into_owned(), false),
        None => match Assets::get("index.html") {
            Some(index) => asset_response("index.html", index.data.into_owned(), true),
            None => (
                StatusCode::NOT_FOUND,
                "the web interface is not built into this binary",
            )
                .into_response(),
        },
    }
}

fn asset_response(path: &str, bytes: Vec<u8>, is_fallback: bool) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        .body(Body::from(bytes))
        .expect("a static asset response is always well-formed");

    let headers = response.headers_mut();

    // Vite fingerprints its assets, so everything except the entry document can
    // be cached hard. `index.html` must never be, or a panel update leaves users
    // on the old bundle.
    let cache = if is_fallback || path == "index.html" {
        "no-cache, no-store, must-revalidate"
    } else if is_fingerprinted(path) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));

    response
}

/// Vite emits `name-A1b2C3d4.js`; that hash is what makes immutable caching safe.
///
/// The hash is base64url, so it can contain `_` as well as letters and digits —
/// missing that is how an "immutable" cache rule silently degrades to one hour.
fn is_fingerprinted(path: &str) -> bool {
    let Some(stem) = std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
    else {
        return false;
    };
    stem.rsplit_once('-').is_some_and(|(name, hash)| {
        !name.is_empty()
            && hash.len() >= 8
            && hash.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[cfg(test)]
mod tests {
    /// The policy has to name every inline script index.html actually carries.
    ///
    /// Under a bare `script-src 'self'` the browser refused to run the theme
    /// script, so the panel shipped a flash of the wrong theme and a CSP error
    /// in every console — its own policy blocking its own script, on every page
    /// load, for anybody who looked.
    #[test]
    fn every_inline_script_is_named_by_the_policy() {
        let index = Assets::get("index.html").expect("the UI bundle is embedded");
        let html = std::str::from_utf8(index.data.as_ref()).expect("index.html is utf-8");

        let inline = html.matches("<script>").count();
        let hashes = inline_script_hashes();
        assert_eq!(
            hashes.len(),
            inline,
            "index.html has {inline} inline script(s) but the policy names {}",
            hashes.len()
        );
        for h in &hashes {
            assert!(
                h.starts_with("'sha256-") && h.ends_with('\''),
                "malformed: {h}"
            );
        }
    }

    /// A `<script src=…>` has no body, so hashing it would be meaningless.
    #[test]
    fn external_scripts_are_not_hashed() {
        let index = Assets::get("index.html").expect("the UI bundle is embedded");
        let html = std::str::from_utf8(index.data.as_ref()).expect("index.html is utf-8");
        assert_eq!(
            inline_script_hashes().len(),
            html.matches("<script>").count()
        );
    }

    use super::*;

    #[test]
    fn fingerprinted_assets_are_recognised() {
        assert!(is_fingerprinted("assets/index-A1b2C3d4.js"));
        assert!(is_fingerprinted("assets/vendor-0123456789ab.css"));
        // Vite's hashes are base64url and routinely contain underscores.
        assert!(is_fingerprinted("assets/index-D_IY9T5L.js"));
        assert!(is_fingerprinted("assets/index-4v0K5kQn.css"));
        assert!(!is_fingerprinted("index.html"));
        assert!(!is_fingerprinted("assets/logo.svg"));
        assert!(
            !is_fingerprinted("assets/a-b.js"),
            "a short suffix is not a content hash"
        );
        assert!(
            !is_fingerprinted("assets/-A1b2C3d4.js"),
            "a hash with no name is not an asset"
        );
    }

    #[tokio::test]
    async fn unknown_api_paths_are_404_not_the_spa_shell() {
        let response = serve("/api/does-not-exist".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn client_routes_fall_back_to_the_shell() {
        let response = serve("/sites/example.com/settings".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache, no-store, must-revalidate",
            "the shell must never be cached, or updates never reach anyone"
        );
    }

    #[tokio::test]
    async fn the_root_serves_the_shell() {
        let response = serve("/".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html"
        );
    }
}
