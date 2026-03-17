//! TPROXY listener: accepts connections redirected by nftables TPROXY rule.
//!
//! Uses IP_TRANSPARENT to bind the socket, then spawns interception handlers
//! for each accepted connection.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

use crate::certmint::{CaKeyPair, CertCache};
use crate::dns_snoop::DnsSnoopMap;
use crate::intercept;
use crate::portmap::{self, PortAction, PortRule};

/// Set IP_TRANSPARENT on a socket (requires CAP_NET_ADMIN).
pub(crate) fn set_ip_transparent(socket: &Socket) -> io::Result<()> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(socket),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as u32,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create and bind the TPROXY listener socket (requires CAP_NET_ADMIN).
///
/// Call this during privileged startup, then pass the result to [`run_listener`]
/// after dropping privileges.
pub fn bind_listener(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

    // IP_TRANSPARENT allows us to bind to non-local addresses (TPROXY)
    set_ip_transparent(&socket)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let listener = TcpListener::from_std(socket.into())?;
    log::info!("TPROXY listener: bound on 0.0.0.0:{}", port);
    Ok(listener)
}

/// Run the TPROXY accept loop (no privileges required).
///
/// Dispatches by original destination port to the appropriate handler
/// based on the port rules (Guard → error page, Proxy → MITM proxy).
pub async fn run_listener(
    listener: TcpListener,
    ca: Arc<CaKeyPair>,
    dns_map: Arc<DnsSnoopMap>,
    cert_cache: Arc<CertCache>,
    rules: Arc<Vec<PortRule>>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;

        // With TPROXY, local_addr() is the original destination
        let orig_dest = stream.local_addr()?;

        let action = match portmap::action_for_port(&rules, orig_dest.port()) {
            Some(a @ (PortAction::Guard | PortAction::Proxy)) => a.clone(),
            _ => {
                log::warn!(
                    "TPROXY: no guard/proxy rule for port {}, dropping {}",
                    orig_dest.port(),
                    peer_addr
                );
                continue;
            }
        };

        log::info!(
            "TPROXY: connection from {} → {} (intercepted)",
            peer_addr,
            orig_dest
        );

        let ca = Arc::clone(&ca);
        let dns_map = Arc::clone(&dns_map);
        let cert_cache = Arc::clone(&cert_cache);

        tokio::spawn(async move {
            if let Err(e) =
                intercept::handle(stream, orig_dest, peer_addr, ca, dns_map, cert_cache, &action).await
            {
                log::warn!("intercept error for {}: {}", peer_addr, e);
            }
        });
    }
}
