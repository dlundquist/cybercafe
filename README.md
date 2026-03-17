# cybercafe

A Raspberry Pi that answers the phone and gets your vintage PC online.

Plug a USR Sportster into a SIP ATA, point the ATA at a Pi running
cybercafe, and your Windows 98 box has a real dial-up connection — PPP
over V.22bis/V.34, with the handshake screech and everything. No
emulation: the modem training, symbol timing, and error correction are
the real thing, running in software.

For vintage machines with Ethernet (Power Mac G3, SGI O2, Sun Ultra 5),
skip the modem — the same Pi serves as a TLS bridge and HTTP proxy over
the LAN.

See [VISION.md](VISION.md) for the full architecture, component
descriptions, diagrams, and future possibilities.

## Components

| Crate | What it does |
|-------|-------------|
| `sip-modem-server` | SIP UA + RTP + audio thread; answers calls, runs modem training, bridges data to ppp-server |
| `ppp-server` | LCP/IPCP state machine, HDLC framing, TUN device; speaks PPP over a Unix socket |
| `modem-engine` | Rust wrapper around spandsp for V.22bis, V.34, and V.90 modulation |
| `modem-ctl` | AT command helper; resets/configures/dials a physical serial modem, then execs pppd |
| `sip-modem-dial` | Outbound SIP UA; places calls to a remote SIP endpoint |
| `tls-guard` | Transparent TLS interceptor + plaintext-to-TLS upgrader for legacy machines |
| `spandsp-sys` | FFI bindings to libspandsp (V.34-capable fork) |

Companion project: [lo-fi-web](https://github.com/dlundquist/lo-fi-web) — an HTTP degrading proxy
(Go) that strips JavaScript, downgrades HTML5, and dithers images so
vintage browsers can render modern websites.

## Requirements

### Build

- **Rust** (stable toolchain)
- **libspandsp** with V.34 support — the
  [v90modem fork](https://github.com/dlundquist/v90modem) of spandsp
  carries ~40 V.34 Phase 3/4 patches not in the freeswitch upstream.
  Build and install it as a shared library:
  ```sh
  cd v90modem/spandsp-master
  autoreconf -fi
  ./configure --enable-v34 --enable-shared --disable-static \
      --prefix=$HOME/.local \
      CFLAGS="-Wno-incompatible-pointer-types -Wno-int-conversion"
  touch src/*.h          # skip macOS-only header generators
  make -j$(nproc) && make install
  ```
  The `spandsp-sys` crate links against the installed `libspandsp.so`
  via rpath configured in `.cargo/config.toml`.
- **C compiler** and **pkg-config** (for spandsp build)

### Runtime

- **Linux** — required for TUN devices, nftables, NFQUEUE, and
  `IP_TRANSPARENT`
- **nftables** with kernel modules: `nf_tables`, `nft_tproxy`,
  `nf_tproxy_ipv4`, `nft_queue`, `nf_conntrack` — used by tls-guard
  for transparent interception
- **CAP_NET_ADMIN** — needed by ppp-server (TUN device creation) and
  tls-guard (nftables rules, policy routing, `IP_TRANSPARENT` sockets)
- **CAP_NET_RAW** — needed by tls-guard (AF_PACKET socket for DNS
  snooping)
- **SIP ATA with FXS port** — for dial-up mode (Cisco SPA112,
  Grandstream HT80x, Cisco VG202XM, or similar)

The systemd unit files (`ppp-server.service`, `tls-guard.service`) grant
the minimum capabilities via `AmbientCapabilities` and run as `nobody` —
no need to run as root.

## Building

```sh
cargo build
cargo test     # no hardware or root needed
```

## Security

cybercafe sits between untrusted vintage machines and the public
internet. The components that handle untrusted input are hardened
accordingly:

### tls-guard

- **Runs unprivileged** — the systemd unit runs as `nobody` with only
  `CAP_NET_ADMIN` and `CAP_NET_RAW`. `NoNewPrivileges=yes` prevents
  escalation.
- **Ephemeral CA** — the certificate authority used for MITM proxying is
  generated fresh at startup and never written to disk. It exists only
  in memory for the lifetime of the process.
- **No trust-store modification** — tls-guard never installs its CA
  into the system or any browser's trust store. The CA is only useful
  for legacy clients that don't validate certificate chains (which is
  why they need tls-guard in the first place).
- **Classification before interception** — NFQUEUE inspects only the
  first packet (TLS ClientHello) of each connection. Modern TLS (1.2+)
  is immediately accepted back into the kernel fast path with a
  conntrack mark and is never proxied or decrypted.
- **nftables cleanup** — `ExecStopPost` in the systemd unit removes the
  nftables table and policy routing rules on shutdown, ensuring no
  stale interception rules survive a crash.

tls-guard is **not** a firewall, deep packet inspection engine, or
content filter. It classifies TLS versions to help legacy clients reach
modern servers, but does not inspect, scan, or block traffic based on
content. Modern TLS connections are passed through to the kernel
uninspected.

### ppp-server

- **Runs unprivileged** — `nobody` with only `CAP_NET_ADMIN` for TUN
  device creation.
- **Single-client TUN** — each PPP session creates an isolated
  point-to-point TUN device. There is no bridging to the host's
  network interfaces; routing and NAT are configured separately by the
  administrator using standard Linux tools.
- **Protocol validation** — the LCP/IPCP state machine validates all
  PPP frames (CRC, HDLC framing, option lengths) before processing.

### sip-modem-server

- **Minimal SIP parser** — handles only INVITE, ACK, BYE, and 200 OK.
  Unknown methods and malformed requests are dropped, not processed.
- **Optional SIP Basic auth** — `--auth-file` enables HTTP Basic
  authentication on INVITE requests (same `username password` file
  format as ppp-server). Without `--auth-file`, any INVITE is accepted.
  The server is intended to run on a private LAN behind an ATA;
  firewall SIP (UDP 5060) and RTP ports to the local network regardless.

### General

- **Low-value credentials only** — the optional auth files (SIP Basic,
  PPP PAP/CHAP) contain passwords for the ATA and dial-up clients, not
  for upstream services or infrastructure. These credentials exist
  because vintage hardware expects to provide them, not because they
  protect anything sensitive. No API keys or persistent cryptographic
  material.
- **Privilege separation** — the `privsep` crate handles capability
  dropping. Services start with ambient capabilities and immediately
  drop everything not needed.

## Not for Public Deployment

cybercafe is designed for a single-user Pi on a home LAN, not a
multi-tenant server. It must not be exposed on a public IP.

- **Open proxy by design** — sip-modem-server hands callers a PPP link
  via ppp-server with a routable IP and NAT. Anyone who can complete a
  SIP call effectively gets an open proxy through your network.
- **sip-modem-server** listens on UDP 5060 with optional Basic auth (not
  Digest) — Basic auth over UDP is plaintext-equivalent.
- **ppp-server's Unix socket** is world-readable/writable (0o666) — any
  local user on a shared host can connect and exhaust the IP pool.
- **tls-guard** requires being the default gateway (nftables TPROXY) —
  meaningless on a VPS with no vintage machines behind it.
- **No connection limits, rate limiting, or resource caps** on any
  component.
- **To share with friends** — put the server behind Tailscale or
  WireGuard instead of exposing it to the public internet.
