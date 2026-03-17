#!/usr/bin/env bash
# Automated SIP dial integration test.
#
# Dials the Cisco via sip-modem-dial at each modulation speed, waits for PPP
# to come up inside an isolated network namespace, pings through the modem
# link, then tears everything down and moves to the next speed.
#
# Defaults come from ../../lab-config.sh (CISCO_IP, DIAL_NUMBER, PPP_USER,
# PPP_PASS).  Override with flags or positional args.
#
# Usage:
#   sudo test/sip-dial-test.sh [--mod MODE] [--ping-target IP] [--timeout SECS]
#                               [peer_ip] [number]
#
# With no --mod flag, runs all three modes in sequence: v22bis, v34, v8.
#
# Example:
#   sudo test/sip-dial-test.sh
#   sudo test/sip-dial-test.sh --mod v34
#   sudo test/sip-dial-test.sh --ping-target 192.168.3.1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="${SCRIPT_DIR}/../.."
SIP_DIAL="${SCRIPT_DIR}/../target/debug/sip-modem-dial"

# Source lab defaults (CISCO_IP, DIAL_NUMBER, PPP_USER, PPP_PASS, etc.)
if [[ -f "${BASE_DIR}/lab-config.sh" ]]; then
    # shellcheck source=../../lab-config.sh
    source "${BASE_DIR}/lab-config.sh"
fi

# --- Prerequisites -----------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: must be root" >&2
    exit 1
fi

for cmd in pppd ip ping; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found on PATH" >&2
        exit 1
    fi
done

if [[ ! -x "$SIP_DIAL" ]]; then
    echo "ERROR: sip-modem-dial not found at $SIP_DIAL — run 'cargo build' first" >&2
    exit 1
fi

# --- Parse args --------------------------------------------------------------

PPP_USER="${PPP_USER:-dialup}"
PPP_PASS="${PPP_PASS:-dialup}"
PING_TARGET=""
TIMEOUT=120
MOD_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) PPP_USER="$2"; shift 2 ;;
        --pass) PPP_PASS="$2"; shift 2 ;;
        --ping-target) PING_TARGET="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --mod) MOD_MODE="$2"; shift 2 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

PEER_IP="${1:-${CISCO_IP:?No peer IP: set CISCO_IP in lab-config.sh or pass as argument}}"
NUMBER="${2:-${DIAL_NUMBER:?No number: set DIAL_NUMBER in lab-config.sh or pass as argument}}"

if [[ -n "$MOD_MODE" ]]; then
    MOD_MODES=("$MOD_MODE")
else
    MOD_MODES=(v22bis v34 v8 v90)
fi

# --- Helpers -----------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; ((PASS_COUNT++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL_COUNT++)) || true; }

check() {
    local desc="$1"; shift
    if "$@"; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

# Current test resources (globals so cleanup works)
CUR_PPP_PID=""
CUR_NS=""
CUR_LOG=""

cleanup_test() {
    [[ -n "$CUR_PPP_PID" ]] && kill "$CUR_PPP_PID" 2>/dev/null && wait "$CUR_PPP_PID" 2>/dev/null || true
    [[ -n "$CUR_NS" ]] && ip netns del "$CUR_NS" 2>/dev/null || true
    [[ -n "$CUR_LOG" ]] && rm -f "$CUR_LOG"
    CUR_PPP_PID="" CUR_NS="" CUR_LOG=""
}
trap cleanup_test EXIT INT TERM

# Map modulation mode to expected training log pattern
training_pattern() {
    case "$1" in
        v22bis) echo "V.22bis.*training complete\|V22BIS.*training complete\|entering TRAINING: mod=V22BIS" ;;
        v34)    echo "V.8.*result\|V.34.*training complete\|V34.*training complete\|entering TRAINING: mod=V34" ;;
        v8)     echo "V.8.*result\|training complete" ;;
        v90)    echo "V.8.*result\|V.90\|V90\|training complete" ;;
    esac
}

# Human-readable description for each mode
mod_description() {
    case "$1" in
        v22bis) echo "V.22bis (2400 bps)" ;;
        v34)    echo "V.8 → V.34 (33.6 kbps)" ;;
        v8)     echo "V.8 auto-negotiation (V.34/V.90)" ;;
        v90)    echo "V.90 (56k downstream / V.34 upstream)" ;;
    esac
}

# --- Run one modulation mode -------------------------------------------------

run_test() {
    local mod="$1"
    local suffix="$$-${mod}"

    CUR_NS="ppp-sip-test-${suffix}"
    CUR_LOG="/tmp/sip-dial-test-${suffix}.log"
    CUR_PPP_PID=""

    echo ""
    echo "=== SIP dial test ($(mod_description "$mod")) ==="
    echo "[test] peer=$PEER_IP number=$NUMBER user=$PPP_USER timeout=${TIMEOUT}s"

    ip netns add "$CUR_NS"
    ip netns exec "$CUR_NS" ip link set lo up

    # Build env vars for modem engine
    local me_envs="ME_MODULATION=${mod}"
    # v34 and v90 both use V.8 negotiation — direct V.34 doesn't work
    # against the MICA (it expects V.8 first).  v90 additionally
    # advertises V.90 in the V.8 capability exchange.
    if [[ "$mod" == "v34" ]]; then
        me_envs="ME_MODULATION=v8"
    elif [[ "$mod" == "v90" ]]; then
        me_envs="ME_MODULATION=v8 ME_ADVERTISE_V90=1"
    fi
    for v in $(env | grep '^ME_' | cut -d= -f1); do
        [[ "$v" == "ME_MODULATION" || "$v" == "ME_ADVERTISE_V90" ]] && continue
        me_envs="$me_envs $v=${!v}"
    done

    local pty_cmd="nsenter --net=/proc/1/ns/net env RUST_LOG=info ${me_envs} ${SIP_DIAL} ${PEER_IP} ${NUMBER}"

    ip netns exec "$CUR_NS" \
        pppd \
        pty "$pty_cmd" \
        user "$PPP_USER" \
        password "$PPP_PASS" \
        refuse-chap refuse-mschap refuse-mschap-v2 \
        noauth nodetach debug \
        defaultroute \
        lcp-restart 3 \
        lcp-max-configure 30 \
        >"$CUR_LOG" 2>&1 &
    CUR_PPP_PID=$!

    # Wait for IPCP
    echo "[test] waiting for PPP link (${mod})..."
    local elapsed=0
    local ipcp_ok=false
    while (( elapsed < TIMEOUT )); do
        if ! kill -0 "$CUR_PPP_PID" 2>/dev/null; then
            echo "[test] pppd exited early (${mod}):" >&2
            cat "$CUR_LOG" >&2
            break
        fi
        if grep -q "local  IP address" "$CUR_LOG" 2>/dev/null; then
            ipcp_ok=true
            break
        fi
        sleep 1
        ((elapsed++))
    done

    # Assertions
    check "[${mod}] modem training started" grep -q "entering TRAINING" "$CUR_LOG"
    check "[${mod}] modem reached DATA state" grep -q "DATA state" "$CUR_LOG"
    check "[${mod}] LCP negotiation completed" grep -q "LCP opened\|ConfAck" "$CUR_LOG"
    check "[${mod}] PAP authentication succeeded" grep -q "PAP authentication succeeded" "$CUR_LOG"

    if $ipcp_ok; then
        pass "[${mod}] IPCP opened — PPP link up"

        local peer_ppp_ip
        peer_ppp_ip=$(grep "remote IP address" "$CUR_LOG" | tail -1 | awk '{print $NF}')

        local ping_dest
        if [[ -n "$PING_TARGET" ]]; then
            ping_dest="$PING_TARGET"
        elif [[ -n "$peer_ppp_ip" ]]; then
            ping_dest="$peer_ppp_ip"
        else
            ping_dest="$PEER_IP"
        fi

        echo "[test] pinging $ping_dest through modem link (${mod})..."
        check "[${mod}] ping through PPP/modem link" \
            ip netns exec "$CUR_NS" ping -c 3 -W 5 "$ping_dest"
    else
        fail "[${mod}] IPCP opened — PPP link up"
        echo "--- ${mod} log ---" >&2
        cat "$CUR_LOG" >&2
    fi

    echo "=== ALL CHECKS DONE (${mod}) ==="
    cleanup_test
}

# --- Main loop ---------------------------------------------------------------

TOTAL_PASS=0
TOTAL_FAIL=0

FIRST_TEST=true
for mode in "${MOD_MODES[@]}"; do
    if $FIRST_TEST; then
        FIRST_TEST=false
    else
        # Wait for the Cisco to release the T1 PRI B-channel from the
        # previous call.  Without this, the next INVITE can arrive before
        # the ISDN layer frees the channel, causing Q.931 cause 38
        # "network out of order" and a silent SIP hang.
        echo "[test] waiting 5s for T1 B-channel release..."
        sleep 5
    fi
    PASS_COUNT=0
    FAIL_COUNT=0
    run_test "$mode" || true
    ((TOTAL_PASS += PASS_COUNT)) || true
    ((TOTAL_FAIL += FAIL_COUNT)) || true
done

echo ""
if (( TOTAL_FAIL == 0 )); then
    echo "=== ALL TESTS PASSED (${TOTAL_PASS} checks across ${#MOD_MODES[@]} modulation modes) ==="
    exit 0
else
    echo "=== ${TOTAL_FAIL} FAILED, ${TOTAL_PASS} passed (${#MOD_MODES[@]} modulation modes) ==="
    exit 1
fi
