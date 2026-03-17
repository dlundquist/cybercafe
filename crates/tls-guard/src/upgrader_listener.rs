//! TPROXY listener for upgrade (plaintext → TLS) ports.
//!
//! Similar to listener.rs but dispatches to upgrader::handle instead
//! of intercept::handle. Looks up the TLS port from the port rules.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

use crate::dns_snoop::DnsSnoopMap;
use crate::listener::set_ip_transparent;
use crate::portmap::{self, PortAction, PortRule};
use crate::upgrader;

/// Create and bind the upgrader TPROXY socket (requires CAP_NET_ADMIN).
///
/// Call this during privileged startup, then pass the result to
/// [`run_upgrader_listener`] after dropping privileges.
pub fn bind_upgrader_listener(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    set_ip_transparent(&socket)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let listener = TcpListener::from_std(socket.into())?;
    log::info!("Upgrader listener: bound on 0.0.0.0:{}", port);
    Ok(listener)
}

/// Run the upgrader accept loop (no privileges required).
pub async fn run_upgrader_listener(
    listener: TcpListener,
    rules: Arc<Vec<PortRule>>,
    dns_map: Arc<DnsSnoopMap>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let orig_dest = stream.local_addr()?;

        let tls_port = match portmap::action_for_port(&rules, orig_dest.port()) {
            Some(PortAction::Upgrade { tls_port }) => *tls_port,
            _ => {
                log::warn!(
                    "upgrader: no upgrade rule for port {}, dropping {}",
                    orig_dest.port(),
                    peer_addr
                );
                continue;
            }
        };

        let dns_map = Arc::clone(&dns_map);

        tokio::spawn(async move {
            if let Err(e) =
                upgrader::handle(stream, orig_dest, peer_addr, tls_port, dns_map).await
            {
                log::warn!("upgrader error for {}: {}", peer_addr, e);
            }
        });
    }
}
