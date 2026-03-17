#!/usr/bin/env bash
# Hardware interop test: connect ppp-server to Cisco MICA digital modems via
# reverse telnet, then dial from a Windows machine through the MICA pool.
#
# Signal path:
#   Win98 DUN → analog modem → POTS → Cisco FXS → ISDN PRI → MICA modem
#     → async tty line → reverse telnet (TCP) → socat → ppp-server
#
# Usage:
#   sudo test/ppp-server-serial.sh --host <cisco_ip> [--ports 2001-2024] [--auth pap|chap|none]
#
# Each socat instance bridges one TCP reverse-telnet port to ppp-server's Unix
# socket.  ppp-server accepts multiple connections, each gets its own IP from
# the pool and its own LCP/IPCP state machine.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PPP_SERVER="${SCRIPT_DIR}/../target/debug/ppp-server"

# --- Defaults -----------------------------------------------------------------

HOST=""
PORT_RANGE="2001-2024"
AUTH_MODE="none"
CIDR="10.99.0.0/24"
SERVER_IP="10.99.0.1"

# --- Parse args ---------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  HOST="$2";       shift 2 ;;
        --ports) PORT_RANGE="$2"; shift 2 ;;
        --auth)  AUTH_MODE="$2";  shift 2 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

if [[ -z "$HOST" ]]; then
    echo "Usage: $0 --host <cisco_ip> [--ports 2001-2024] [--auth pap|chap|none]" >&2
    exit 1
fi

# --- Prerequisites ------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: must be root" >&2
    exit 1
fi

for cmd in socat ip; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found on PATH" >&2
        exit 1
    fi
done

if [[ ! -x "$PPP_SERVER" ]]; then
    echo "ERROR: ppp-server not found at $PPP_SERVER — run 'cargo build' first" >&2
    exit 1
fi

# --- Constants ----------------------------------------------------------------

PORT_START="${PORT_RANGE%-*}"
PORT_END="${PORT_RANGE#*-}"
SUFFIX="$$"
TUN="tun-hw-${SUFFIX}"
SOCK="/tmp/ppp-hw-${SUFFIX}.sock"
NS_SRV="ppp-hw-${SUFFIX}"
LOG_SRV="/tmp/ppp-hw-${SUFFIX}-srv.log"
AUTH_FILE="/tmp/ppp-hw-${SUFFIX}-auth"

SOCAT_PIDS=()
SRV_PID=""

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    echo ""
    echo "[cleanup] stopping socat instances..."
    for pid in "${SOCAT_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true

    echo "[cleanup] stopping ppp-server..."
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null || true

    echo "[cleanup] removing namespace ${NS_SRV}..."
    ip netns del "$NS_SRV" 2>/dev/null || true
    rm -f "$SOCK" "$LOG_SRV" "$AUTH_FILE"
    echo "[cleanup] done."
}
trap cleanup EXIT INT TERM

# --- Create namespace ---------------------------------------------------------

echo "[setup] creating namespace ${NS_SRV}"
ip netns add "$NS_SRV"
ip netns exec "$NS_SRV" ip link set lo up

# --- Auth file ----------------------------------------------------------------

srv_auth_args=()
case "$AUTH_MODE" in
    none) ;;
    pap|chap)
        echo "# ppp-server auth file for hardware interop test" > "$AUTH_FILE"
        echo "# Add username/password pairs, one per line:" >> "$AUTH_FILE"
        echo "dialup dialup" >> "$AUTH_FILE"
        srv_auth_args=(--auth-file "$AUTH_FILE")
        echo "[setup] auth mode: ${AUTH_MODE} (credentials: dialup/dialup)"
        ;;
    *)
        echo "ERROR: unknown auth mode: $AUTH_MODE" >&2
        exit 1
        ;;
esac

# --- Start ppp-server ---------------------------------------------------------

echo "[setup] starting ppp-server (tun=${TUN}, cidr=${CIDR})"
ip netns exec "$NS_SRV" \
    env RUST_LOG=info \
    "$PPP_SERVER" \
        --listen "$SOCK" \
        --cidr "$CIDR" \
        --tun-name "$TUN" \
        --user root \
        ${srv_auth_args[@]+"${srv_auth_args[@]}"} \
    >"$LOG_SRV" 2>&1 &
SRV_PID=$!

# Poll for socket
waited=0
while [[ ! -S "$SOCK" ]] && (( waited < 5 )); do
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        echo "ERROR: ppp-server exited early:" >&2
        cat "$LOG_SRV" >&2
        exit 1
    fi
    sleep 1
    ((waited++))
done

if [[ ! -S "$SOCK" ]]; then
    echo "ERROR: ppp-server socket not ready after 5s" >&2
    cat "$LOG_SRV" >&2
    exit 1
fi
echo "[setup] ppp-server socket ready: ${SOCK}"

# --- Open reverse telnet to all MICA lines ------------------------------------

echo "[setup] opening reverse telnet to ${HOST} ports ${PORT_START}-${PORT_END}"
for port in $(seq "$PORT_START" "$PORT_END"); do
    socat "TCP:${HOST}:${port}" "UNIX-CONNECT:${SOCK}" &
    SOCAT_PIDS+=($!)
done
echo "[setup] ${#SOCAT_PIDS[@]} socat instances started"

# --- Ready --------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  ppp-server ready — waiting for incoming modem calls"
echo ""
echo "  Server IP:  ${SERVER_IP}"
echo "  Client pool: ${CIDR}"
echo "  Auth mode:   ${AUTH_MODE}"
echo "  TUN device:  ${TUN} (in namespace ${NS_SRV})"
echo ""
echo "  Dial from Windows DUN to reach any of the ${#SOCAT_PIDS[@]} MICA lines."
echo "  Watch ppp-server log:  tail -f ${LOG_SRV}"
echo ""
echo "  Press Ctrl-C to stop."
echo "============================================================"
echo ""

# Tail the log so the operator can watch negotiation in real time
tail -f "$LOG_SRV" &
TAIL_PID=$!

# Wait for ppp-server to exit (or Ctrl-C)
wait "$SRV_PID" || true
kill "$TAIL_PID" 2>/dev/null || true
