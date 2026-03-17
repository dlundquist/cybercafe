//! Legacy TLS interception handler.
//!
//! For each TPROXY'd connection:
//! 1. Read the initial TLS ClientHello bytes from the TCP stream
//! 2. Look up hostname from DNS snoop map
//! 3. Fetch the real server's certificate (via modern TLS)
//! 4. Mint a fake certificate matching the server's CN/SANs
//! 5. Accept TLS handshake with the client using the fake cert
//! 6. Serve an HTML error page explaining the TLS version issue

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::certmint::{self, CaKeyPair, CertCache};
use crate::clienthello;
use crate::dns_snoop::DnsSnoopMap;
use crate::portmap::PortAction;

/// Handle a single intercepted legacy TLS connection.
///
/// Guard mode: serve an error page after TLS handshake.
/// Proxy mode: connect upstream via modern TLS, bidirectional copy.
pub async fn handle(
    mut stream: TcpStream,
    orig_dest: SocketAddr,
    peer_addr: SocketAddr,
    ca: Arc<CaKeyPair>,
    dns_map: Arc<DnsSnoopMap>,
    cert_cache: Arc<CertCache>,
    action: &PortAction,
) -> io::Result<()> {
    // Read the first bytes to determine TLS version and peek at ClientHello
    let mut initial_buf = vec![0u8; 4096];
    let n = stream.read(&mut initial_buf).await?;
    if n == 0 {
        return Ok(());
    }
    initial_buf.truncate(n);

    let tls_version = clienthello::parse_tls_version(&initial_buf);
    log::info!(
        "intercept: {} → {} using {}",
        peer_addr,
        orig_dest,
        tls_version.display_name()
    );

    // Look up hostname from DNS snoop
    let dest_ip: IpAddr = orig_dest.ip();
    let hostname = dns_map
        .lookup(&dest_ip)
        .unwrap_or_else(|| orig_dest.ip().to_string());

    let dest_port = orig_dest.port();

    // Check the cert cache first; fetch + mint only on miss.
    let (cert, key) = if let Some(cached) = cert_cache.get(&hostname, dest_port) {
        log::debug!("intercept: cert cache hit for {}:{}", hostname, dest_port);
        cached
    } else {
        log::debug!("intercept: cert cache miss for {}:{}", hostname, dest_port);

        // Fetch real server cert info (blocking I/O in spawn_blocking)
        let host_for_fetch = hostname.clone();
        let cert_info = tokio::task::spawn_blocking(move || {
            certmint::fetch_server_cert_info(&host_for_fetch, dest_port)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let (cn, sans) = match cert_info {
            Ok(info) => info,
            Err(e) => {
                log::warn!(
                    "intercept: failed to fetch cert from {}:{} — {}, using hostname",
                    hostname,
                    dest_port,
                    e
                );
                (hostname.clone(), vec![hostname.clone()])
            }
        };

        // Mint a fake certificate
        let (cert, key) = certmint::mint_cert(&ca, &cn, &sans)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        cert_cache.put(hostname.clone(), dest_port, cert.clone(), key.clone());
        (cert, key)
    };

    // Build SSL acceptor configured for legacy TLS
    let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Allow old TLS versions — SSLv3 may fail if compiled out
    let _ = acceptor_builder.set_min_proto_version(Some(SslVersion::SSL3));

    acceptor_builder
        .set_private_key(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    acceptor_builder
        .set_certificate(&cert)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let acceptor = acceptor_builder.build();

    // Wrap the stream so the already-read bytes are replayed first
    let prefixed = PrefixedStream::new(initial_buf, stream);

    // Perform TLS handshake
    let ssl = openssl::ssl::Ssl::new(acceptor.context())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut tls_stream = tokio_openssl::SslStream::new(ssl, prefixed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Pin::new(&mut tls_stream)
        .accept()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS accept: {}", e)))?;

    match action {
        PortAction::Guard => {
            // Serve the error page
            let page =
                build_error_page(&hostname, tls_version.display_name(), &orig_dest.to_string());
            let response = format!(
                "HTTP/1.0 200 OK\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                page.len(),
                page
            );

            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.shutdown().await?;

            log::info!("intercept: served error page to {}", peer_addr);
        }
        PortAction::Proxy => {
            // Connect upstream via modern TLS, bidirectional copy
            let upstream = TcpStream::connect((orig_dest.ip(), orig_dest.port())).await?;

            let mut connector = SslConnector::builder(SslMethod::tls())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            connector.set_verify(SslVerifyMode::NONE);
            let connector = connector.build();

            let ssl = connector
                .configure()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                .into_ssl(&hostname)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let mut upstream_tls = tokio_openssl::SslStream::new(ssl, upstream)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Pin::new(&mut upstream_tls)
                .connect()
                .await
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("upstream TLS: {}", e))
                })?;

            let (c2s, s2c) = copy_bidirectional(&mut tls_stream, &mut upstream_tls).await?;

            log::info!(
                "intercept: proxy {} done ({}→upstream, {}→client)",
                peer_addr,
                c2s,
                s2c
            );

            upstream_tls.shutdown().await?;
            tls_stream.shutdown().await?;
        }
        _ => unreachable!("intercept::handle called with non-guard/proxy action"),
    }

    Ok(())
}

fn build_error_page(hostname: &str, tls_version: &str, dest: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<title>TLS Version Not Supported</title>
<style>
body {{
    font-family: "Courier New", monospace;
    background: #000080;
    color: #ffffff;
    margin: 40px;
    line-height: 1.6;
}}
.box {{
    border: 2px solid #ffffff;
    padding: 20px;
    max-width: 600px;
    margin: 0 auto;
}}
h1 {{
    color: #ffff00;
    text-align: center;
    border-bottom: 1px solid #ffffff;
    padding-bottom: 10px;
}}
.warn {{
    color: #ff6600;
    font-weight: bold;
}}
code {{
    background: #000000;
    padding: 2px 6px;
}}
</style>
</head>
<body>
<div class="box">
<h1>&#9888; Secure Connection Failed</h1>
<p>Your browser attempted to connect to <code>{hostname}</code>
using <span class="warn">{tls_version}</span>, which is no longer
supported by modern servers.</p>

<p>This connection was intercepted by the dial-up gateway's
TLS upgrader to prevent a silent connection failure.</p>

<h2>What to do:</h2>
<p>Configure your browser to use this gateway as an HTTP proxy
(port 8080). The <b>lo-fi-web</b> proxy running there will fetch
pages using modern TLS on your behalf, strip JavaScript, downgrade
HTML5, and dither images so your browser can render them.</p>

<p>In your browser's proxy settings, set the HTTP proxy to this
gateway's IP address, port <code>8080</code>. Then browse
<code>http://</code> URLs normally &mdash; the proxy handles the
rest.</p>

<p><small>
Destination: {dest}<br>
Detected protocol: {tls_version}<br>
Minimum required: TLS 1.2
</small></p>
</div>
</body>
</html>"#,
        hostname = hostname,
        tls_version = tls_version,
        dest = dest,
    )
}

// ---------------------------------------------------------------------------
// PrefixedStream: replay buffered bytes before delegating to inner stream
// ---------------------------------------------------------------------------

/// A stream that yields pre-buffered bytes first, then reads from the inner stream.
struct PrefixedStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If we still have prefix bytes to deliver
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Delegate to inner stream
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
