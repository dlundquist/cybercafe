# Testing

Checkboxes track what has been verified; unchecked items are known gaps.

---

## Unit Tests (no hardware, no root)

Run: `cargo test`

### ppp-server (34 tests)
- [x] CRC-16/CCITT FCS — determinism, mutation detection, residual
- [x] HDLC framing — round-trip, byte escaping, FCS rejection
- [x] PPP frame round-trip and short-frame handling
- [x] LCP state machine — ConfReq/Ack, echo, termination, auth option,
      full negotiation to Opened
- [x] IPCP state machine — IP assignment, NAK on wrong IP, zero-IP
      suggestion
- [x] PAP authentication — success and wrong-password rejection
- [x] CHAP MD5 authentication — success and wrong-hash rejection
- [x] IP pool — /24 range, acquire/release, /30 prefix, first/second
      host
- [x] CIDR parsing — valid and invalid
- [x] Auth file whitespace handling

### sip-modem-server (21 tests)
- [x] Base64 decode — standard and padded
- [x] SIP Basic auth parsing — valid, missing prefix, malformed
- [x] Auth DB credential lookup
- [x] SIP response building — status line, 100 Trying, BYE From/To swap
- [x] SIP header extraction — value, missing, case-insensitive
- [x] SIP call flow — INVITE→ACK→BYE, auth enforcement, auth acceptance
- [x] SDP RTP port extraction — found and missing
- [x] µ-law codec — encode/decode round-trip, negative samples, silence,
      sign symmetry

### modem-engine (4 tests)
- [x] V.90 scrambler/descrambler round-trip (x^23 + x^5 + 1)
- [x] V.90 downstream encoder/decoder round-trip — µ-law
- [x] V.90 downstream encoder/decoder round-trip — A-law
- [x] V.90 multi-frame round-trip

### tls-guard (29 tests)
- [x] Ephemeral CA generation
- [x] Certificate minting with SANs (DNS and IP)
- [x] TLS ClientHello parsing — empty, too short, non-TLS, SSLv2,
      SSLv3, TLS 1.0–1.2, display names
- [x] DNS response parsing — name parsing, compression, A record,
      non-response rejection, TTL expiry
- [x] nfqueue TCP payload extraction — too short, non-TCP, valid
- [x] Port map parsing — empty, comments, all three modes, helpers,
      error cases (unknown mode, missing TLS port, invalid port,
      duplicate)

### mnl (4 tests)
- [x] Netlink batch construction
- [x] Message construction and attributes
- [x] Nested attributes

### Crates with no unit tests
- [ ] sip-modem-dial
- [ ] modem-ctl
- [ ] privsep
- [ ] spandsp-sys (FFI bindings; exercised indirectly via modem-engine)

---

## Integration Tests (root required, no hardware)

### ppp-server netns test

Run: `sudo test/ppp-server-test.sh [--auth {none|pap|chap}]`

Connects real pppd to ppp-server via socat PTY bridge in isolated
network namespaces. Requires: `pppd`, `socat`, `ip` (iproute2).

- [x] No-auth: LCP negotiation, IPCP, bidirectional ping through PPP
- [x] PAP auth: success path
- [x] PAP auth: wrong password rejected
- [x] CHAP MD5 auth: success path
- [x] CHAP MD5 auth: wrong password rejected
- [ ] Multiple concurrent PPP sessions
- [ ] IP pool exhaustion and release
- [ ] LCP echo keepalive timeout
- [ ] Framing errors / corrupt frames

### tls-guard netns test

Full nftables integration in network namespaces — real TPROXY, real TLS
handshakes, real DNS snooping. Requires: `nftables`, `ip` (iproute2).

- [x] Guard mode — TLS ClientHello parsing, block page
- [x] Proxy mode — MITM with ephemeral CA, content inspection
- [x] Upgrade mode — plaintext → TLS upgrade (e.g. SMTP STARTTLS)
- [ ] SNI extraction for multi-domain routing
- [ ] Certificate chain with intermediate CAs
- [ ] Client certificate passthrough (legacy clients)
- [ ] Long-running connections / idle timeout

---

## Hardware Interop Tests

These require a SIP-capable voice gateway (e.g. Cisco with FXS ports or
a SIP ATA) and a Raspberry Pi (or similar) running sip-modem-server +
ppp-server.

### SIP modem server — inbound call

Gateway places SIP INVITE to sip-modem-server, which answers, trains
the modem, and bridges to ppp-server.

- [x] V.22bis training — inbound INVITE, 200 OK, training to 2400 bps
- [x] PPP over V.22bis — LCP/IPCP negotiation through modem link
- [x] Async UART framing — digital modem start/stop bit
      stripping/insertion in `v22bis_put_bit_cb` / `v22bis_get_bit_cb`
- [x] Bridge failure reset — second call after first disconnects
- [ ] V.34 training — inbound call with `ME_MODULATION=v34`
- [ ] V.8 negotiation — `ME_MODULATION=v8`, auto-selects V.34/V.22bis
- [ ] V.8 with V.90 — `ME_MODULATION=v8 ME_ADVERTISE_V90=1`
- [ ] V.90 downstream — PCM path through digital trunk
- [ ] Training timeout — no answer / failed training → hangup after 30s
- [ ] RTP carrier loss — RTP stops mid-call → hangup after 10s
- [ ] Concurrent inbound calls (multiple FXS ports)
- [ ] Call duration stability (>10 min sustained PPP session)

### SIP modem dial — outbound call

Run: `test/sip-dial-netns.sh <peer_ip> <number>`

sip-modem-dial places a SIP INVITE to a voice gateway, trains the
modem, and runs pppd in an isolated network namespace.

- [x] V.22bis outbound dial — SIP INVITE, modem training, PPP in netns
- [x] PAP auth through MICA — CHAP rejected, falls back to PAP, auth
      succeeds, IPCP assigns IP from pool
- [ ] V.34 outbound dial — `ME_MODULATION=v34`
- [ ] V.8 outbound — `ME_MODULATION=v8`
- [ ] BYE on local hangup — clean SIP teardown
- [ ] BYE on remote hangup — remote side disconnects first

### Digital modem pool — multi-session

Run: `sudo test/ppp-server-serial.sh --host <gateway_ip>
[--ports 2001-2024] [--auth pap|chap|none]`

Bridges digital modem pool reverse telnet ports to ppp-server via socat.
Each modem session gets its own PPP IP from the pool.

- [x] Single modem connection — TCP→socket bridge, PPP negotiation
- [x] PAP/CHAP auth through serial bridge
- [ ] Multiple simultaneous modem connections (one IP per modem)
- [ ] IP pool exhaustion with full modem pool
- [ ] Modem disconnect / reconnect cycling
- [ ] Graceful shutdown with active sessions

### Physical modem — USB dial

Run: `test/pppd-netns.sh /dev/ttyUSB0 <number>`

- [x] modem-ctl reset — `+++`, ATH, ATZ, ATV1, ATE1
- [x] modem-ctl dial — AT command, CONNECT, pppd exec
- [x] Baud rate 115200 DTE
- [ ] Dial failure — busy, no answer, no carrier
- [ ] Modem hangup recovery — redial after disconnect

---

## End-to-End Scenarios

### Vintage machine dials up and browses the web

Full path: vintage machine → analog modem → FXS gateway → SIP →
sip-modem-server → ppp-server → TUN → NAT → HTTP proxy → internet.

- [x] PPP link established with IP assignment
- [x] DNS resolution through PPP link
- [ ] HTTP browsing through proxy — HTML downgraded, images transcoded,
      scripts stripped
- [ ] File download through proxy — .zip passed through, .exe allowed
- [ ] Image-heavy page — grayscale dithering at modem speeds
- [ ] Call duration stability (>10 min sustained browsing session)

### Vintage machine on Ethernet through tls-guard

Full path: vintage machine → Ethernet → Pi (default gateway) →
tls-guard (TPROXY) → HTTP proxy → internet.

- [ ] HTTP traffic passes through unmodified (guard mode)
- [ ] HTTPS site → tls-guard block page with explanation
- [ ] HTTPS site → tls-guard proxy mode with MITM and content downgrade
- [ ] SMTP plaintext → tls-guard upgrade to STARTTLS

---

## Manual Hardware Test Walkthrough

Step-by-step verification of the full modem stack on hardware.

### Prerequisites

- USB analog modem (e.g. USR 56k) on a serial/USB port
- SIP-capable FXS gateway configured to route calls to sip-modem-server
- Build: `cargo build`

### Steps

**1. Start ppp-server**
```
sudo RUST_LOG=debug ./target/debug/ppp-server
```
Expected: `Listening on /run/ppp_server.sock`

**2. Verify socket**
```
ls -l /run/ppp_server.sock
```
Expected: `srwxrwxrwx`

**3. Start sip-modem-server**
```
RUST_LOG=debug ./target/debug/sip-modem-server
```
Expected: `SIP listening on 0.0.0.0:5060` / `RTP listening on 0.0.0.0:5004`

**4. Reset modem**
```
./target/debug/modem-ctl /dev/ttyUSB0 reset
```
Expected: `[OK] modem ready`

**5. Place a call**

Either configure the gateway to dial the SIP server, or dial outbound:
```
./target/debug/modem-ctl /dev/ttyUSB0 dial <extension>
```

Expected sip-modem-server log:
```
INVITE from ... -> 200 OK
V.22bis training complete (2400 bps)
Connected to PPP bridge: /run/ppp_server.sock
```

Expected ppp-server log:
```
LCP opened
IPCP opened: server=10.0.0.1 client=10.0.0.2
```

**6. Verify PPP link**
```
ip addr show ppp0
```

**7. Ping**
```
ping -I ppp0 10.0.0.2
```

**8. Hangup**

Kill ppp-server or send SIP BYE. Expected: call drops, modem prints
`NO CARRIER`.
