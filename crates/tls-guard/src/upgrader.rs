//! Plaintext-to-TLS upgrader handler.
//!
//! For each connection on an `upgrade` port:
//! 1. Look up hostname via DNS snoop
//! 2. Connect to the same server on the TLS port
//! 3. Establish modern TLS to upstream
//! 4. Bidirectionally copy data between plaintext client and TLS upstream

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns_snoop::DnsSnoopMap;

/// Handle a single plaintext connection by upgrading it to TLS upstream.
pub async fn handle(
    mut stream: TcpStream,
    orig_dest: SocketAddr,
    peer_addr: SocketAddr,
    tls_port: u16,
    dns_map: Arc<DnsSnoopMap>,
) -> io::Result<()> {
    let dest_ip: IpAddr = orig_dest.ip();
    let hostname = dns_map
        .lookup(&dest_ip)
        .unwrap_or_else(|| orig_dest.ip().to_string());

    log::info!(
        "upgrade: {} → {}:{} (plaintext → TLS :{})",
        peer_addr,
        hostname,
        orig_dest.port(),
        tls_port
    );

    // Connect to upstream on the TLS port
    let upstream = TcpStream::connect((orig_dest.ip(), tls_port)).await?;

    // Establish TLS to upstream
    let mut connector = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();

    let ssl = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .into_ssl(&hostname)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut tls_stream = tokio_openssl::SslStream::new(ssl, upstream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    std::pin::Pin::new(&mut tls_stream)
        .connect()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS connect: {}", e)))?;

    // Bidirectional copy
    let (c2s, s2c) = copy_bidirectional(&mut stream, &mut tls_stream).await?;

    log::info!(
        "upgrade: {} done ({}→upstream, {}→client)",
        peer_addr,
        c2s,
        s2c
    );

    tls_stream.shutdown().await?;
    Ok(())
}
