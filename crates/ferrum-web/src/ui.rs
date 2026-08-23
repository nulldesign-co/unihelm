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
