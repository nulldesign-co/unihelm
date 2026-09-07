//! Plain HTTP arriving on the panel's TLS port.
//!
//! The panel terminates its own TLS (see `tls`) on port 8088, and 8088 is not
//! 443, so a browser handed `51.195.99.122:8088` fills in `http://` and sends a
//! request line where rustls expects a ClientHello. rustls answers the only way
//! the protocol allows — an alert — and the browser reports
//! `ERR_INVALID_HTTP_RESPONSE`. Every operator reads that as "the panel is
//! broken", not "add https://", and the panel was serving the whole time. A
//! working panel that presents itself as a dead one is the same defect class as
//! a success message for work that never happened.
//!
//! So the first byte of every accepted connection is inspected before rustls is
//! given it. A TLS record of type `handshake` starts with 0x16 and every TLS
//! connection opens with one; that byte is *peeked*, never read, so a real TLS
//! client is handed on with its ClientHello still intact at byte zero. Anything
//! else is plain HTTP: read the request line and `Host`, answer `308` pointing
//! at the https form of the same URL, close, and never involve rustls at all.
//!
//! 308 rather than 301, for two independent reasons. 301 permits a client to
//! rewrite POST as GET, so a form post would arrive stripped of its body; 308
//! preserves method and body. And browsers cache a 301 for the life of the
//! profile, which would strand an operator who later sets `tls = "off"` behind
//! a redirect their own browser applies before it ever reaches this server.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use axum_server::accept::Accept;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A TLS record-layer frame of type `handshake` (RFC 8446 §5.1). Every TLS
/// version the panel will ever speak opens with one, and it is not a byte any
/// HTTP method name can start with, so one byte separates the two protocols.
const TLS_HANDSHAKE: u8 = 0x16;

/// Cap on the request head read while looking for `Host`. A browser's request
/// line plus headers is a couple of kilobytes. Past this it is not a browser
/// that mistyped a scheme, and reading unbounded from an unauthenticated
/// listener is how a redirect helper turns into a memory exhaustion primitive.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// How long a connection has to reveal which protocol it speaks, and then to
/// accept the answer. Matches axum-server's own rustls handshake timeout, so a
/// stalled connection costs the same whichever branch it takes. Without a
/// deadline a client that connects and sends nothing pins a spawned task for
/// the lifetime of the process.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// An acceptor that answers plain HTTP itself and passes TLS through untouched.
///
/// Wrap it *inside* `RustlsAcceptor` (`rustls.acceptor(HttpsRedirect::new())`),
/// so it sees the raw stream first and rustls only ever receives connections
/// that actually opened with a handshake record.
#[derive(Clone, Copy, Debug)]
pub struct HttpsRedirect {
    timeout: Duration,
}

impl HttpsRedirect {
    pub fn new() -> Self {
        Self {
            timeout: PROBE_TIMEOUT,
        }
    }
}

impl Default for HttpsRedirect {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Accept<TcpStream, S> for HttpsRedirect
where
    S: Send + 'static,
{
    type Stream = TcpStream;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(TcpStream, S)>> + Send>>;

    fn accept(&self, mut stream: TcpStream, service: S) -> Self::Future {
        let timeout = self.timeout;

        Box::pin(async move {
            let first = match tokio::time::timeout(timeout, peek_first_byte(&stream)).await {
                Ok(Ok(byte)) => byte,
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection sent no bytes within the probe window; \
                         could not tell TLS from plain HTTP, so it was closed",
                    ));
                }
            };

            if first != TLS_HANDSHAKE {
                return redirect_and_close(&mut stream, timeout).await;
            }

            // `peek` above left the byte in the socket receive buffer, so rustls
            // reads the ClientHello from its true first byte. Consuming it here
            // would break every TLS connection, which is the one outcome worse
            // than the bug being fixed.
            Ok((stream, service))
        })
    }
}

/// Answer one plaintext request with a 308 and close.
///
/// Always returns `Err`, even when the redirect was written successfully:
/// axum-server drops a connection whose `Accept` future errored, which is
/// exactly what should happen to a connection this function has already
/// finished with. The error text is what a future reader of a log sees, so it
/// says what the connection was and what was done about it.
async fn redirect_and_close<S>(
    stream: &mut TcpStream,
    timeout: Duration,
) -> io::Result<(TcpStream, S)> {
    // Read before the head, because the answer depends on it when the client
    // sent no `Host`. On a listener bound to 0.0.0.0 this is the concrete
    // address the connection actually landed on, which is the address the
    // operator typed — the bind address is not.
    let local = stream.local_addr().ok();

    let head = match tokio::time::timeout(timeout, read_head(stream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            // A client that cannot finish a request head in ten seconds is not
            // the mistyped-scheme case this exists for, and the bytes so far
            // may not name a target. Guessing one would be inventing a URL.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "plain HTTP on the TLS port, but the request head never arrived; closed",
            ));
        }
    };

    let Some(location) = redirect_target(&head, local) else {
        return Err(io::Error::other(
            "connection was neither a TLS handshake nor an HTTP request; closed without a reply",
        ));
    };

    tracing::debug!(
        %location,
        "plain HTTP on the TLS port; redirecting rather than letting rustls fail the connection"
    );

    // Best effort from here: the client may already be gone, and there is
    // nothing left to salvage if it is.
    let _ = stream
        .write_all(redirect_response(&location).as_bytes())
        .await;
    let _ = stream.shutdown().await;

    Err(io::Error::other(
        "plain HTTP on the TLS port: answered 308 to the https form and closed",
    ))
}

/// The first byte, without consuming it.
async fn peek_first_byte(stream: &TcpStream) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    match stream.peek(&mut byte).await? {
        0 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the client closed the connection before sending anything",
        )),
        _ => Ok(byte[0]),
    }
}

/// Read up to the blank line that ends the headers, `MAX_HEAD_BYTES`, or EOF —
/// whichever comes first.
async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    while head.len() < MAX_HEAD_BYTES {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
        if head_is_complete(&head) {
            break;
        }
    }
    head.truncate(MAX_HEAD_BYTES);
    Ok(head)
}

fn head_is_complete(head: &[u8]) -> bool {
    head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n")
}

/// The https URL a plaintext request head should be redirected to, or `None`
/// when the bytes are not an HTTP request at all — a port scanner or a client
/// speaking some other protocol gets closed rather than a fabricated target.
fn redirect_target(head: &[u8], local: Option<SocketAddr>) -> Option<String> {
    let mut lines = head.split(|b| *b == b'\n');
    let target = request_target(lines.next()?)?;
    let host = lines
        .find_map(host_header)
        .or_else(|| local.map(|addr| addr.to_string()))?;
    Some(format!("https://{host}{target}"))
}

fn redirect_response(location: &str) -> String {
    // Only a client that does not follow redirects ever reads this body — but
    // that client is `curl` in an operator's terminal during exactly the
    // confusion this module exists to end, so it names what happened and what
    // to do instead of being empty.
    let body = format!(
        "This is the Unihelm panel, and it speaks HTTPS on this port.\n\
         Your client sent a plain HTTP request, so nothing was served.\n\
         Retry at: {location}\n"
    );
    format!(
        "HTTP/1.1 308 Permanent Redirect\r\n\
         Location: {location}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len()
    )
}

/// The origin-form target out of a request line such as `GET /x?y=1 HTTP/1.1`.
///
/// `None` means this was not a request line. An absolute-form target (`GET
/// http://host/x`, which only proxies send) or `*` becomes `/`: the scheme is
/// the thing being corrected here, and rewriting someone else's absolute URL is
/// not this acceptor's job.
fn request_target(line: &[u8]) -> Option<&str> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|b| *b == b' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty() || !version.starts_with(b"HTTP/") {
        return None;
    }

    let target = std::str::from_utf8(target).ok()?;
    // The target is pasted into a `Location:` header. Bytes outside printable
    // ASCII are rejected rather than escaped: one that could end the header
    // line is a response-splitting bug, and no browser needs to send one.
    if !target.starts_with('/') || !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Some("/");
    }
    Some(target)
}

/// The `Host` header value, when it is one this server may safely echo back.
///
/// The value goes straight into a `Location:` header, so it is checked against
/// the character set a host can actually contain rather than trusted — a client
/// that could smuggle a CR or LF through here would be writing its own headers
/// into the panel's response. Anything else returns `None` and the caller falls
/// back to the address the connection landed on.
fn host_header(line: &[u8]) -> Option<String> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let colon = line.iter().position(|b| *b == b':')?;
    let (name, value) = line.split_at(colon);
    if !name.eq_ignore_ascii_case(b"host") {
        return None;
    }

    let value = std::str::from_utf8(&value[1..]).ok()?.trim();
    // 253 bytes of DNS name plus `:65535`.
    if value.is_empty() || value.len() > 260 {
        return None;
    }
    let printable = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'));
    printable.then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Drive one connection through the acceptor. Returns what the acceptor
    /// decided and the client end, so a test can read whatever was written back.
    async fn probe(request: &[u8]) -> (io::Result<TcpStream>, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let accepted = HttpsRedirect::new()
            .accept(server, ())
            .await
            .map(|(stream, ())| stream);
        (accepted, client, addr)
    }

    /// The whole design rests on the handshake byte still being there when
    /// rustls looks: reading it instead of peeking would break every real TLS
    /// connection, which is worse than the bug this module fixes.
    #[tokio::test]
    async fn a_tls_handshake_first_byte_is_passed_through_with_the_record_still_unread() {
        let hello = [TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x2c];
        let (accepted, _client, _) = probe(&hello).await;

        let mut server = accepted.expect("a TLS connection must be handed to rustls");
        let mut seen = [0u8; 5];
        server.read_exact(&mut seen).await.unwrap();
        assert_eq!(
            seen, hello,
            "the record was consumed before rustls could read it"
        );
    }

    /// The reported defect: a browser given `host:8088` sends plain HTTP into
    /// the TLS listener and shows ERR_INVALID_HTTP_RESPONSE, which reads as a
    /// dead panel rather than a missing scheme.
    #[tokio::test]
    async fn a_plaintext_request_is_answered_with_a_308_to_the_https_form_of_the_same_url() {
        let (accepted, mut client, _) =
            probe(b"GET /x?y=1 HTTP/1.1\r\nHost: panel.example:8088\r\n\r\n").await;
        assert!(
            accepted.is_err(),
            "a plaintext connection must not reach rustls"
        );

        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(
            reply.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"),
            "reply was: {reply}"
        );
        assert!(
            reply.contains("Location: https://panel.example:8088/x?y=1\r\n"),
            "reply was: {reply}"
        );
        // 301 lets a client turn POST into GET and is cached for the life of
        // the browser profile, so it would outlive `tls = "off"`.
        assert!(
            !reply.contains("301"),
            "the redirect must be 308, not 301: {reply}"
        );
    }

    #[tokio::test]
    async fn a_request_without_a_host_header_still_gets_a_usable_redirect() {
        let (accepted, mut client, addr) = probe(b"GET /sites HTTP/1.1\r\n\r\n").await;
        assert!(accepted.is_err());

        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(
            reply.contains(&format!("Location: https://{addr}/sites\r\n")),
            "reply was: {reply}"
        );
    }

    /// The redirect line is written from client-supplied bytes, so a `Host`
    /// that is not a host must not reach it.
    #[test]
    fn a_host_that_is_not_a_host_falls_back_to_the_address_the_connection_landed_on() {
        let local: SocketAddr = "203.0.113.7:8088".parse().unwrap();
        let head = b"GET / HTTP/1.1\r\nHost: not a host\r\n\r\n";
        assert_eq!(
            redirect_target(head, Some(local)).as_deref(),
            Some("https://203.0.113.7:8088/")
        );
    }

    #[test]
    fn bytes_that_are_not_an_http_request_produce_no_redirect_rather_than_a_guessed_one() {
        let local: SocketAddr = "203.0.113.7:8088".parse().unwrap();
        assert_eq!(
            redirect_target(b"SSH-2.0-OpenSSH_9.6\r\n", Some(local)),
            None
        );
    }

    /// A connection that opens and says nothing must not hold its task: with no
    /// deadline, one such connection per accept is a free way to leak tasks.
    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_closed_instead_of_held_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let acceptor = HttpsRedirect {
            timeout: Duration::from_millis(50),
        };
        let result: io::Result<(TcpStream, ())> = acceptor.accept(server, ()).await;
        assert!(
            result.is_err(),
            "a silent connection was held open rather than closed"
        );
    }
}
