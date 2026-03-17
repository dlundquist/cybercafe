# cybercafe: Dial-Up Internet Over SIP

A collection of Rust tools that recreate a functional dial-up Internet
experience using modern SIP telephony infrastructure. Plug a vintage PC with
a serial modem into an off-the-shelf SIP ATA, point the ATA at a Raspberry Pi,
and the old machine is online — complete with the handshake screech, a real
33.6 kbps CONNECT banner, and PPP over a TUN device that routes to the modern
Internet. No emulation, no fakery: the modem training, symbol timing, and
error correction are the real thing, running in software on the Pi.

## The Setup

```
                       phone cable             SIP/RTP
┌──────────────────┐   (RJ-11)    ┌─────────┐  (UDP)   ┌──────────────────┐
│ Vintage PC       ├──────────────┤ SIP ATA ├────┐     │ Raspberry Pi     │
│ + serial modem   │              │ (FXS)   │    │     │ running          │
│ (USR 56k, etc.)  │              └─────────┘    │     │ cybercafe +      │
└──────────────────┘                    Ethernet │     │ tls-guard +      ├)))  WiFi
                                        (RJ-45)  │     │ lo-fi-web        │  ── Internet
┌──────────────────┐  10BASE-T / 100BASE-TX  ┌───┴─┐   │                  │
│ Vintage machine  ├─────────────────────────┤ hub ├───┤                  │
│ (Mac OS 8, IRIX, │                         └───┬─┘   └──────────────────┘
│  Solaris, Win98) │  ┌──────────────────┐       │
└──────────────────┘  │ More vintage     ├───────┘
                      │ machines...      │
                      └──────────────────┘
```

### Bill of materials

| Part | Examples | Role |
|------|----------|------|
| Vintage machine with serial modem | Any PC + USR Sportster 56k, Hayes-compatible | The "client" — runs a dialer, pppd, and vintage software |
| SIP ATA with FXS port | Cisco SPA112, Grandstream HT80x, Cisco VG202XM | Converts analog phone signals to SIP/RTP and back |
| Linux SBC or server | Raspberry Pi 4/5, any x86 box | Runs cybercafe; answers calls, terminates PPP, routes packets |

### What you do

1. Configure the ATA's FXS port to send SIP INVITEs to the Pi's IP.
2. Start `ppp-server` (creates a TUN device and listens on a Unix socket).
3. Start `sip-modem-server` (listens for SIP calls on UDP 5060).
4. On the vintage machine, dial out (`ATDT`). The ATA places the call, the Pi
   answers, modems train, PPP negotiates, and the old machine gets an IP.
5. Set up NAT on the Pi with `nft` or `iptables` masquerade so the vintage
   machine can reach the Internet.

## How It Works

A call walks through the entire stack:

1. **ATDT** — The vintage modem dials. The ATA's FXS port detects the DTMF
   digits and places a SIP INVITE to the Pi.

2. **SIP answer** — `sip-modem-server` receives the INVITE, responds 200 OK,
   and begins exchanging RTP audio.

3. **Modem training** — `modem-engine` (wrapping spandsp) runs V.22bis or V.34
   modulation inside the RTP audio stream. The modem and the software negotiate
   symbol rates, equalizer taps, and error correction — the same handshake you
   heard in the '90s.

4. **CONNECT** — Training completes. The modem enters data mode. Bytes flow
   between the vintage serial port and `sip-modem-server` as modulated audio.

5. **PPP** — `sip-modem-server` bridges the byte stream to `ppp-server` over a
   Unix socket. `ppp-server` runs LCP and IPCP negotiation, assigns an IP
   address, and creates a `ppp0` TUN device.

6. **Online** — The vintage machine has a routable IP. Packets flow:
   vintage app → modem → ATA → RTP → Pi → TUN → Internet.

### The key insight

An ATA's FXS port contains a real D/A converter. When `sip-modem-server`
places µ-law or A-law PCM codewords into RTP packets, the ATA faithfully
reconstructs the corresponding analog waveform on its phone port. This means
V.90-style downstream PCM encoding — where codewords directly represent
quantization levels rather than sampled analog audio — actually works. The
modem on the other end of the phone cable receives a signal that is
bit-accurate to what the software intended, limited only by the ATA's DAC
quality and line impedance.

## The Components

Each tool does one thing. They communicate through Unix primitives — sockets,
stdio, TUN devices — and can be composed, replaced, or used independently.

| Crate | What it does |
|-------|-------------|
| `sip-modem-server` | SIP user agent + RTP media engine + audio thread; answers calls, runs modem training, bridges data to ppp-server |
| `ppp-server` | LCP/IPCP state machine, HDLC framing, TUN device creation; speaks PPP over a Unix socket |
| `modem-engine` | Rust wrapper around spandsp for V.22bis, V.34, and V.90 modulation/demodulation |
| `modem-ctl` | AT command helper; resets, configures, and dials a physical serial modem, then execs pppd |
| `sip-modem-dial` | Outbound SIP UA; places calls to a remote SIP endpoint (the client-side complement to sip-modem-server) |
| `tls-guard` | Transparent TLS interceptor and plaintext-to-TLS upgrader; makes HTTPS and modern mail work from vintage machines |
| `spandsp-sys` | Unsafe FFI bindings to libspandsp (V.34-capable fork) |

### Recomposability

Because the pieces are independent, you can rearrange them:

- **ppp-server** works for any "serial-over-socket" PPP scenario, not just
  modem calls. Pipe any byte stream into its Unix socket and get a TUN device.
- **modem-engine** is a library. Use it to build other modem-over-VoIP
  applications — fax gateways, BBS servers, retro game bridges.
- **sip-modem-dial** is the client-side counterpart. Run it on a second Pi to
  place outbound modem calls through a SIP trunk.
- Swap `ppp-server` for a BBS door, a SLIP implementation, or raw serial
  passthrough. `sip-modem-server` doesn't care what's on the other end of the
  Unix socket.

## Non-Goals

- **Not a general SIP stack.** The SIP implementation is a minimal UA — no
  registration, no proxy, no codec negotiation beyond G.711. Use Opal or SRTP
  if you need a real onesip stack.
- **Not a replacement for real ISP infrastructure.** There is no RADIUS, no
  modem pool management, no billing.
- **Not trying to be fast.** The entire point is the experience. 33.6 kbps is
  a feature, not a bug.
- **NAT/routing is the OS's job.** The stack creates a TUN device and assigns
  IPs. Masquerading, firewalling, and DNS are handled by standard Linux
  networking tools (`nft`, `iptables`, `systemd-networkd`, etc.).

## tls-guard

Makes the modern encrypted Internet accessible from machines that only speak
SSLv3 or plaintext. Runs on the Pi as a transparent network-level service —
no client configuration beyond setting the Pi as the default gateway.

### Three modes per port

Configured via a simple rules file (`port-rules.conf`):

| Mode | What happens | Example |
|------|-------------|---------|
| **guard** | Modern TLS (1.2+) passes through the kernel untouched. Legacy TLS (SSLv3, TLS 1.0/1.1) is intercepted and served a styled error page explaining the problem and how to configure the HTTP proxy. | `443 guard` |
| **proxy** | Same classification as guard, but legacy TLS connections are MITM-proxied: tls-guard accepts the legacy handshake, connects to the real server with modern TLS, and copies data bidirectionally. | `443 proxy` |
| **upgrade** | All plaintext traffic is transparently wrapped in TLS to a specified upstream port. Vintage email clients speak plaintext SMTP/POP3/IMAP to the Pi; tls-guard connects to the real mail server over TLS. | `110 upgrade 995` |

### How it works

tls-guard operates entirely at the network layer using Linux nftables and
NFQUEUE — no SOCKS proxy, no iptables REDIRECT, no application-level config:

1. **nftables rules** intercept traffic on configured ports in the PREROUTING
   chain.

2. **NFQUEUE classification** (guard/proxy modes) — the first data packet of
   each TCP connection is diverted to userspace, where tls-guard parses the
   TLS ClientHello record header to determine the protocol version. Modern
   connections get a conntrack mark (`0x1`) and are accepted back into the
   kernel fast path. Legacy connections get mark `0x2` and are re-queued
   into a TPROXY rule.

3. **TPROXY interception** — marked packets are transparently proxied to a
   local listener bound with `IP_TRANSPARENT`. The listener sees the
   original destination IP via `local_addr()`, preserving the illusion of
   a direct connection.

4. **DNS snooping** — a passive BPF-filtered `AF_PACKET` socket captures DNS
   responses on the guarded interface, maintaining an IP → hostname cache.
   When tls-guard intercepts a connection to `93.184.216.34`, it already
   knows the client was trying to reach `example.com` — no extra DNS lookup
   needed.

5. **Certificate minting** — for guard and proxy modes, tls-guard fetches
   the real server's certificate to extract its CN and SANs, then mints a
   matching certificate signed by an ephemeral CA generated at startup.
   The legacy client sees a certificate that matches the hostname it
   expects.

6. **Policy routing** — a custom routing table with `ip rule fwmark 0x2`
   ensures TPROXY return traffic is delivered back to the transparent
   socket.

### Default port rules

```
443  guard              # HTTPS: legacy → error page, modern → passthrough
110  upgrade  995       # POP3 → POP3S
143  upgrade  993       # IMAP → IMAPS
25   upgrade  465       # SMTP → SMTPS
587  upgrade  465       # SMTP submission → SMTPS
```

With these defaults, a vintage PC behind the Pi can:
- Browse HTTP sites normally (no interception)
- Get a clear error page when attempting HTTPS with old TLS, directing
  them to configure the HTTP proxy
- Use Outlook Express, Eudora, or any plaintext mail client against
  modern mail providers that require TLS

## Deployment Without a Modem

The modem stack (sip-modem-server, modem-engine, ppp-server) exists to get
vintage machines online over a phone line. But many vintage machines already
have Ethernet — a Power Mac G3 with 10BASE-T, an SGI O2, a Sun Ultra 5, a
Compaq Deskpro running NT 4.0. These machines are on the LAN at 10 or
100 Mbps, yet they still can't use the modern Internet:

1. **TLS 1.2+ is mandatory everywhere** — SSLv3 and TLS 1.0 are rejected by
   virtually all servers. Mail providers require TLS for SMTP, POP3, and IMAP.
2. **HTML5 + JavaScript frameworks** — sites are unusable without JS execution
   and modern DOM APIs.
3. **Modern image formats** — WebP and AVIF won't decode; even supported PNGs
   are multi-megabyte.

For these machines, the solution is the same Raspberry Pi running **tls-guard**
and **lo-fi-web** — just reached over Ethernet instead of a phone line. No
ATA, no phone cable, no modem training.

```
┌──────────────────┐             ┌──────────────────┐
│ Vintage machine  │  10BASE-T   │ Raspberry Pi     │
│ (Mac OS 8, IRIX, ├─────────────┤ running          │
│  Solaris, Win98) │  Ethernet   │ tls-guard +      ├)))  WiFi
└──────────────────┘   (RJ-45)   │ lo-fi-web        │  ── Internet
                                 └──────────────────┘
           Token Ring left as an exercise for the reader.
```

Setup is simpler than dial-up — the vintage machine sets the Pi as its default
gateway (for tls-guard's transparent interception) and configures the Pi as its
HTTP proxy (for lo-fi-web). That's it.

For Ethernet clients, image transcoding is optional since bandwidth isn't the
bottleneck — the `16bit` profile with higher JPEG quality is a sensible default.
The constraints are TLS compatibility, HTML5/JS complexity, and display
capabilities, not link speed.

This is the simpler deployment: no ATA, no phone cable, no modem training, no
PPP negotiation. Just two services on a Pi bridging the gap between vintage
networking stacks and the modern Internet.

## Companion Components

### HTTP Degrading Proxy (Go) — `lo-fi-web`

Lives in a separate repository: [`lo-fi-web`](https://github.com/dlundquist/lo-fi-web)

A standalone Go service, separate from the Rust workspace. The vintage browser
configures it as a plain HTTP proxy; the proxy fetches the modern site, strips
JavaScript and CSS, downgrades HTML5, dithers images, and returns something a
1990s browser can render. See the [lo-fi-web README](https://github.com/dlundquist/lo-fi-web#readme)
for the full transformation pipeline, image profiles, and configuration.

Go is a natural fit — `net/http` has built-in forward-proxy primitives and
`golang.org/x/net/html` provides a proper HTML5 tree walker — whereas the Rust
ecosystem would require pulling in hyper, reqwest, and html5ever for a service
that has no shared-memory coupling to the modem stack.

The proxy serves both dial-up and Ethernet clients. For dial-up, the vintage
machine dials in through the full modem stack and reaches the proxy over PPP.
For Ethernet, the vintage machine connects to the proxy directly over the LAN —
no modem stack involved.

## Future Possibilities

- **BBS hosting over SIP** — Run a BBS door behind `sip-modem-server`;
  callers dial in with real modems.
- **Fax gateway** — spandsp already supports T.38; wire it to
  `sip-modem-server` for inbound/outbound fax.
- **Retro gaming** — Modem-to-modem games (DOOM, Duke Nukem) over SIP
  trunking, with `sip-modem-dial` on each end.
- **Museum / exhibit installations** — A self-contained kiosk where visitors
  experience dial-up firsthand.
- **Ethernet LAN gateway** — A single Pi serves multiple vintage machines on
  a hub or switch — Power Macs, SGI workstations, Sun boxes — all sharing
  tls-guard and lo-fi-web without any modem hardware. Ideal for museum
  workshops, vintage computing meetups, or a home collection.
