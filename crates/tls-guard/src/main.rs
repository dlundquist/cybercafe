mod certmint;
mod clienthello;
mod dns_snoop;
mod intercept;
mod listener;
mod nfqueue;
mod nft_setup;
mod portmap;
mod route_setup;
mod upgrader;
mod upgrader_listener;

use std::sync::Arc;

use clap::Parser;

/// TLS interceptor and plaintext upgrader for the PPP dial-up gateway.
///
/// Three modes per port (configured via --port-rules):
///   guard   — NFQUEUE classifies TLS; legacy gets error page, modern passes through
///   proxy   — NFQUEUE classifies TLS; legacy is MITM-proxied, modern passes through
///   upgrade — all plaintext traffic is wrapped in TLS to upstream
#[derive(Parser, Debug)]
#[command(name = "tls-guard")]
struct Args {
    /// Network interface to guard
    #[arg(long, default_value = "ppp0")]
    interface: String,

    /// TPROXY listen port for legacy TLS interception (guard/proxy)
    #[arg(long, default_value_t = 8443)]
    listen_port: u16,

    /// TPROXY listen port for plaintext upgrade rules
    #[arg(long, default_value_t = 8110)]
    upgrader_port: u16,

    /// NFQUEUE number for packet classification
    #[arg(long, default_value_t = 0)]
    queue_num: u16,

    /// Port rules config file
    #[arg(long, default_value = "port-rules.conf")]
    port_rules: String,

    /// CA private key PEM file (optional; ephemeral if omitted)
    #[arg(long)]
    ca_key: Option<String>,

    /// CA certificate PEM file (optional)
    #[arg(long)]
    ca_cert: Option<String>,

    /// Print equivalent nftables rules and exit
    #[arg(long)]
    print_nftables: bool,

    /// Skip nftables and policy routing setup/cleanup (caller manages rules)
    #[arg(long)]
    no_setup: bool,

    /// Maximum number of cached minted certificates (0 = no cache)
    #[arg(long, default_value_t = 256)]
    cert_cache_size: usize,

    /// Drop privileges to this user after setup (default: nobody)
    #[arg(long, default_value = "nobody")]
    user: String,
}

// Policy routing constants
const FWMARK_LEGACY: u32 = 0x2;
const ROUTING_TABLE: u32 = 100;

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    // 1. Load port rules
    let rules = portmap::load_port_rules(&args.port_rules).expect("failed to load port rules");

    let n_guard = portmap::guard_proxy_ports(&rules)
        .iter()
        .filter(|p| portmap::action_for_port(&rules, **p) == Some(&portmap::PortAction::Guard))
        .count();
    let n_proxy = portmap::guard_proxy_ports(&rules)
        .iter()
        .filter(|p| portmap::action_for_port(&rules, **p) == Some(&portmap::PortAction::Proxy))
        .count();
    let n_upgrade = portmap::upgrade_rules(&rules).len();
    log::info!(
        "Loaded {} port rules ({} guard, {} proxy, {} upgrade)",
        rules.len(),
        n_guard,
        n_proxy,
        n_upgrade
    );

    if args.print_nftables {
        nft_setup::print_nft_rules(
            &args.interface,
            args.listen_port,
            args.queue_num,
            args.upgrader_port,
            &rules,
        );
        return;
    }

    let rules = Arc::new(rules);
    let has_guard_proxy = !portmap::guard_proxy_ports(&rules).is_empty();
    let has_upgrade = !portmap::upgrade_rules(&rules).is_empty();

    // 2. Generate or load CA (needed for guard/proxy)
    let ca = if has_guard_proxy {
        let ca = match (&args.ca_key, &args.ca_cert) {
            (Some(key_path), Some(cert_path)) => {
                log::info!("Loading CA from {} / {}", key_path, cert_path);
                certmint::load_ca(key_path, cert_path).expect("failed to load CA keypair")
            }
            _ => {
                log::info!("Generating ephemeral CA keypair");
                certmint::generate_ephemeral_ca().expect("failed to generate CA")
            }
        };
        Some(Arc::new(ca))
    } else {
        None
    };

    // ---- Privileged setup phase ----
    // All operations below require CAP_NET_ADMIN / CAP_NET_RAW.
    // We bind sockets and create nftables rules before dropping privileges.

    // 3. Create nftables rules and policy routing
    let managed_setup = !args.no_setup;
    if managed_setup {
        log::info!("Setting up nftables rules on {}", args.interface);
        nft_setup::create_nft_rules(
            &args.interface,
            args.listen_port,
            args.queue_num,
            args.upgrader_port,
            &rules,
        )
        .expect("failed to create nftables rules");

        log::info!(
            "Setting up policy routing (fwmark 0x{:x} -> table {})",
            FWMARK_LEGACY,
            ROUTING_TABLE
        );
        route_setup::add_policy_routing(FWMARK_LEGACY, ROUTING_TABLE)
            .expect("failed to set up policy routing");
    } else {
        log::info!("Skipping nftables/routing setup (--no-setup)");
    }

    // 4. Bind DNS snooper socket (CAP_NET_RAW: AF_PACKET)
    let dns_fd = dns_snoop::bind_dns_socket(&args.interface)
        .expect("failed to bind DNS snooper socket");

    // 5. Bind NFQUEUE handle (CAP_NET_ADMIN)
    let nfq_handle = if has_guard_proxy {
        Some(nfqueue::bind_nfqueue(args.queue_num)
            .expect("failed to bind NFQUEUE"))
    } else {
        None
    };

    // 6. Bind TPROXY listener for guard/proxy (CAP_NET_ADMIN: IP_TRANSPARENT)
    let tproxy_listener = if has_guard_proxy {
        Some(listener::bind_listener(args.listen_port)
            .expect("failed to bind TPROXY listener"))
    } else {
        None
    };

    // 7. Bind upgrader listener (CAP_NET_ADMIN: IP_TRANSPARENT)
    let upgrader_listener = if has_upgrade {
        Some(upgrader_listener::bind_upgrader_listener(args.upgrader_port)
            .expect("failed to bind upgrader listener"))
    } else {
        None
    };

    // ---- Privilege drop ----
    // All privileged sockets are bound. Drop to unprivileged user.
    let (uid, gid) = privsep::lookup_user(&args.user).expect("lookup user for privilege drop");
    if unsafe { libc::getuid() } == uid {
        log::info!("Already running as uid={}, skipping setuid/setgid", uid);
    } else {
        privsep::drop_privileges(uid, gid).expect("drop privileges");
        log::info!("Dropped privileges to uid={} gid={}", uid, gid);
    }
    privsep::drop_capabilities(&[privsep::CAP_NET_ADMIN, privsep::CAP_NET_RAW])
        .expect("drop capabilities");
    log::info!("Dropped all capabilities");

    // ---- Unprivileged runtime ----
    // From here on, the process has no capabilities. All sockets are pre-bound.

    // 8. Start DNS snooper
    let dns_map = Arc::new(dns_snoop::DnsSnoopMap::new());
    let dns_map_clone = Arc::clone(&dns_map);
    tokio::spawn(async move {
        if let Err(e) = dns_snoop::run_dns_snooper(dns_fd, dns_map_clone).await {
            log::error!("DNS snooper error: {}", e);
        }
    });

    // 9. Start NFQUEUE classifier (only if guard/proxy rules exist)
    if let Some(handle) = nfq_handle {
        tokio::spawn(async move {
            if let Err(e) = nfqueue::run_nfqueue(handle).await {
                log::error!("NFQUEUE error: {}", e);
            }
        });
    }

    // 10. Start TPROXY listener for guard/proxy (only if needed)
    let mut handles = Vec::new();

    if let Some(tcp_listener) = tproxy_listener {
        let listener_ca = ca.unwrap();
        let listener_dns = Arc::clone(&dns_map);
        let cache_cap = args.cert_cache_size.max(1);
        let listener_cache = Arc::new(certmint::CertCache::new(cache_cap));
        log::info!("Certificate cache: {} entries max", cache_cap);
        let listener_rules = Arc::clone(&rules);
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                listener::run_listener(tcp_listener, listener_ca, listener_dns, listener_cache, listener_rules)
                    .await
            {
                log::error!("Listener error: {}", e);
            }
        }));
    }

    // 11. Start upgrader listener (only if upgrade rules exist)
    if let Some(upg_listener) = upgrader_listener {
        let upgrader_dns = Arc::clone(&dns_map);
        let upgrader_rules = Arc::clone(&rules);
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                upgrader_listener::run_upgrader_listener(upg_listener, upgrader_rules, upgrader_dns)
                    .await
            {
                log::error!("Upgrader listener error: {}", e);
            }
        }));
    }

    // 12. Wait for shutdown signal
    log::info!("tls-guard running. Press Ctrl-C to stop.");
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl-C");

    log::info!("Shutting down...");

    // Cleanup nftables (requires no privileges — netlink socket opened fresh,
    // but delete_nft_table may fail without CAP_NET_ADMIN. That's expected
    // when running as nobody — the service file handles cleanup via ExecStopPost
    // or the rules are cleaned by the test harness.)
    if managed_setup {
        if let Err(e) = nft_setup::delete_nft_table() {
            log::warn!("Failed to delete nft table: {} (expected without CAP_NET_ADMIN)", e);
        }
        if let Err(e) = route_setup::del_policy_routing(FWMARK_LEGACY, ROUTING_TABLE) {
            log::warn!("Failed to delete policy routing: {} (expected without CAP_NET_ADMIN)", e);
        }
    }

    for h in handles {
        h.abort();
    }
    log::info!("Cleanup complete.");
}
