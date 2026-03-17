#!/usr/bin/env bash
# Run pppd in an isolated network namespace so that ppp0, routes, and any
# default-gateway change are confined there.  /etc/resolv.conf is never
# modified (usepeerdns is intentionally omitted; DNS servers pushed by the
# peer appear in pppd debug output as IPCP options 0x81/0x83).
#
# Architecture:
#   pppd            runs in the isolated namespace  → ppp0 created there
#   sip-modem-dial  runs in the host namespace      → can reach the Cisco
#
# pppd's 'pty' option creates a bidirectional pty device for the serial link.
# The pty child command uses 'nsenter --net=/proc/1/ns/net' to re-enter the
# host (PID 1) network namespace before exec-ing sip-modem-dial, so SIP and
# RTP traffic reaches the Cisco while ppp0 stays isolated.
#
# Usage:
#   ./test/sip-dial-netns.sh [--user USER] [--pass PASS] <peer_ip> <number> [extra pppd args...]
#
# Example:
#   ./test/sip-dial-netns.sh 192.168.3.250 5552221

set -euo pipefail

PPP_USER="dialup"
PPP_PASS="dialup"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) PPP_USER="$2"; shift 2 ;;
        --pass) PPP_PASS="$2"; shift 2 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

PEER_IP="${1:?Usage: $0 [--user USER] [--pass PASS] <peer_ip> <number> [pppd-args...]}"
NUMBER="${2:?Usage: $0 [--user USER] [--pass PASS] <peer_ip> <number> [pppd-args...]}"
shift 2

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIP_DIAL="${SCRIPT_DIR}/../target/debug/sip-modem-dial"

if [[ ! -x "$SIP_DIAL" ]]; then
    echo "[netns] ERROR: sip-modem-dial not found at $SIP_DIAL — run 'cargo build' first" >&2
    exit 1
fi

NS="ppp-test-$$"

cleanup() {
    echo "[netns] tearing down namespace $NS" >&2
    sudo ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[netns] creating namespace $NS" >&2
sudo ip netns add "$NS"
sudo ip netns exec "$NS" ip link set lo up

echo "[netns] pppd (${NS}) ←pty→ sip-modem-dial (host netns via nsenter)" >&2

# The pty child inherits root from pppd (which runs under sudo).
# nsenter --net=/proc/1/ns/net re-enters PID 1's network namespace (= host),
# so sip-modem-dial can open SIP/RTP sockets to the Cisco.
# Only the network namespace changes; pppd itself (and ppp0) remain in $NS.
#
# pppd option notes:
#   refuse-chap refuse-mschap refuse-mschap-v2
#                 Cisco has 'ppp authentication chap pap'; refusing all CHAP
#                 variants causes pppd to ConfNak with PAP directly instead
#                 of wasting round trips suggesting MS-CHAPv2 (which the
#                 Cisco doesn't support).  Credentials work on the command
#                 line without /etc/ppp/chap-secrets.
#   noauth        we do not challenge the peer.
#   nodetach      stay in foreground; debug output goes to stderr (this terminal).
#   debug         full LCP/IPCP/auth log.  DNS servers appear as IPCP options.
#   defaultroute  adds default route inside the namespace only.
#   lcp-restart 10
#                 at 1200 bps, each LCP frame takes ~250 ms.  Increasing
#                 the retransmission timer from 3 s to 10 s reduces clutter
#                 on the slow link and prevents queued retransmissions from
#                 tearing down LCP after it opens.
#   lcp-max-configure 30
#                 pppd starts sending LCP before modem training completes;
#                 30 × 10 s = 300 s covers the full handshake delay.

# Forward ME_* env vars through sudo/nsenter for modem engine tuning
ME_ENVS=""
for v in $(env | grep '^ME_' | cut -d= -f1); do
    ME_ENVS="$ME_ENVS $v=${!v}"
done

PTY_CMD="nsenter --net=/proc/1/ns/net env RUST_LOG=info${ME_ENVS:+ $ME_ENVS} ${SIP_DIAL} ${PEER_IP} ${NUMBER}"

sudo ip netns exec "$NS" \
    pppd \
    pty "$PTY_CMD" \
    user "$PPP_USER" \
    password "$PPP_PASS" \
    refuse-chap refuse-mschap refuse-mschap-v2 \
    noauth nodetach debug \
    defaultroute \
    lcp-restart 3 \
    lcp-max-configure 30 \
    "$@"
