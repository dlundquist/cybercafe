#!/usr/bin/env bash
# End-to-end integration test for ppp-server.
#
# Connects real pppd to ppp-server via socat bridging a pty to a Unix socket.
# Both run in isolated network namespaces.  After IPCP completes, verifies
# bidirectional IP by pinging through the PPP tunnel.
#
# Usage:
#   sudo test/ppp-server-test.sh [--auth {none|pap|chap}]
#
# With no flag, runs all three auth modes in sequence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PPP_SERVER="${SCRIPT_DIR}/../target/debug/ppp-server"

# --- Prerequisites -----------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: must be root" >&2
    exit 1
fi

for cmd in pppd socat ip ping; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found on PATH" >&2
        exit 1
    fi
done

if [[ ! -x "$PPP_SERVER" ]]; then
    echo "ERROR: ppp-server not found at $PPP_SERVER — run 'cargo build' first" >&2
    exit 1
fi

# --- Parse args ---------------------------------------------------------------

AUTH_MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth) AUTH_MODE="$2"; shift 2 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

if [[ -n "$AUTH_MODE" ]]; then
    AUTH_MODES=("$AUTH_MODE")
else
    AUTH_MODES=(none pap chap)
fi

# --- Constants ----------------------------------------------------------------

SERVER_IP=10.99.0.1
CIDR=10.99.0.0/24
TIMEOUT=30

# --- Helpers ------------------------------------------------------------------

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
CUR_SRV_PID=""
CUR_CLI_PID=""
CUR_NS_SRV=""
CUR_NS_CLI=""
CUR_SOCK=""
CUR_LOG_SRV=""
CUR_LOG_CLI=""
CUR_AUTH_FILE=""

cleanup_test() {
    [[ -n "$CUR_SRV_PID" ]] && kill "$CUR_SRV_PID" 2>/dev/null && wait "$CUR_SRV_PID" 2>/dev/null || true
    [[ -n "$CUR_CLI_PID" ]] && kill "$CUR_CLI_PID" 2>/dev/null && wait "$CUR_CLI_PID" 2>/dev/null || true
    [[ -n "$CUR_NS_SRV" ]]  && ip netns del "$CUR_NS_SRV" 2>/dev/null || true
    [[ -n "$CUR_NS_CLI" ]]  && ip netns del "$CUR_NS_CLI" 2>/dev/null || true
    rm -f "$CUR_SOCK" "$CUR_LOG_SRV" "$CUR_LOG_CLI" "$CUR_AUTH_FILE"
    CUR_SRV_PID="" CUR_CLI_PID=""
    CUR_NS_SRV="" CUR_NS_CLI=""
    CUR_SOCK="" CUR_LOG_SRV="" CUR_LOG_CLI="" CUR_AUTH_FILE=""
}
trap cleanup_test EXIT INT TERM

# --- Run one auth mode --------------------------------------------------------

run_test() {
    local auth="$1"
    local suffix="$$-${auth}"

    # Set globals for cleanup
    CUR_NS_SRV="ppp-srv-${suffix}"
    CUR_NS_CLI="ppp-cli-${suffix}"
    CUR_SOCK="/tmp/ppp-test-${suffix}.sock"
    CUR_LOG_SRV="/tmp/ppp-test-${suffix}-srv.log"
    CUR_LOG_CLI="/tmp/ppp-test-${suffix}-cli.log"
    CUR_AUTH_FILE="/tmp/ppp-test-${suffix}-auth"
    CUR_SRV_PID=""
    CUR_CLI_PID=""

    local TUN="tun-t-${suffix}"

    echo ""
    echo "=== ppp-server integration test (auth=${auth}) ==="

    # -- Create namespaces -----------------------------------------------------

    ip netns add "$CUR_NS_SRV"
    ip netns add "$CUR_NS_CLI"
    ip netns exec "$CUR_NS_SRV" ip link set lo up
    ip netns exec "$CUR_NS_CLI" ip link set lo up

    # -- Auth file -------------------------------------------------------------

    local srv_auth_args=()
    local cli_auth_args=()

    case "$auth" in
        none)
            cli_auth_args=(noauth)
            ;;
        pap)
            echo "testuser testpass" > "$CUR_AUTH_FILE"
            srv_auth_args=(--auth-file "$CUR_AUTH_FILE")
            cli_auth_args=(user testuser password testpass refuse-chap refuse-mschap refuse-mschap-v2)
            ;;
        chap)
            echo "testuser testpass" > "$CUR_AUTH_FILE"
            srv_auth_args=(--auth-file "$CUR_AUTH_FILE")
            cli_auth_args=(user testuser password testpass refuse-pap refuse-eap refuse-mschap refuse-mschap-v2)
            ;;
        *)
            echo "ERROR: unknown auth mode: $auth" >&2
            return 1
            ;;
    esac

    # -- Start ppp-server ------------------------------------------------------

    ip netns exec "$CUR_NS_SRV" \
        env RUST_LOG=debug \
        "$PPP_SERVER" \
            --listen "$CUR_SOCK" \
            --cidr "$CIDR" \
            --tun-name "$TUN" \
            --user root \
            ${srv_auth_args[@]+"${srv_auth_args[@]}"} \
        >"$CUR_LOG_SRV" 2>&1 &
    CUR_SRV_PID=$!

    # Poll for socket
    local waited=0
    while [[ ! -S "$CUR_SOCK" ]] && (( waited < 5 )); do
        if ! kill -0 "$CUR_SRV_PID" 2>/dev/null; then
            echo "ppp-server exited early:" >&2
            cat "$CUR_LOG_SRV" >&2
            fail "ppp-server socket ready"
            cleanup_test
            return 1
        fi
        sleep 1
        ((waited++))
    done

    if [[ -S "$CUR_SOCK" ]]; then
        pass "ppp-server socket ready"
    else
        echo "ppp-server log:" >&2
        cat "$CUR_LOG_SRV" >&2
        fail "ppp-server socket ready"
        cleanup_test
        return 1
    fi

    # -- Start pppd via socat --------------------------------------------------

    ip netns exec "$CUR_NS_CLI" \
        pppd \
            pty "socat - UNIX-CONNECT:${CUR_SOCK}" \
            nodetach noauth debug \
            lcp-echo-interval 0 \
            "${cli_auth_args[@]}" \
        >"$CUR_LOG_CLI" 2>&1 &
    CUR_CLI_PID=$!

    # -- Wait for IPCP ---------------------------------------------------------

    local elapsed=0
    local ipcp_ok=false
    while (( elapsed < TIMEOUT )); do
        if ! kill -0 "$CUR_SRV_PID" 2>/dev/null; then
            echo "ppp-server died during negotiation:" >&2
            cat "$CUR_LOG_SRV" >&2
            break
        fi
        if ! kill -0 "$CUR_CLI_PID" 2>/dev/null; then
            echo "pppd died during negotiation:" >&2
            cat "$CUR_LOG_CLI" >&2
            break
        fi
        if grep -q "local  IP address" "$CUR_LOG_CLI" 2>/dev/null; then
            ipcp_ok=true
            break
        fi
        sleep 1
        ((elapsed++))
    done

    # -- Assertions ------------------------------------------------------------

    check "LCP negotiation completed" grep -q "LCP opened" "$CUR_LOG_SRV"

    case "$auth" in
        pap)  check "PAP auth succeeded" grep -q "PAP auth succeeded" "$CUR_LOG_SRV" ;;
        chap) check "CHAP auth succeeded" grep -q "CHAP auth succeeded" "$CUR_LOG_SRV" ;;
    esac

    if $ipcp_ok; then
        pass "IPCP opened"
    else
        fail "IPCP opened"
        echo "--- ppp-server log ---" >&2
        cat "$CUR_LOG_SRV" >&2
        echo "--- pppd log ---" >&2
        cat "$CUR_LOG_CLI" >&2
        cleanup_test
        return 1
    fi

    check "ping through PPP tunnel succeeded" \
        ip netns exec "$CUR_NS_CLI" ping -c 3 -W 2 "$SERVER_IP"

    echo "=== ALL CHECKS DONE (auth=${auth}) ==="

    # Clean up this test's resources before the next one
    cleanup_test
}

# --- Main loop ----------------------------------------------------------------

TOTAL_PASS=0
TOTAL_FAIL=0

for mode in "${AUTH_MODES[@]}"; do
    PASS_COUNT=0
    FAIL_COUNT=0
    run_test "$mode" || true
    ((TOTAL_PASS += PASS_COUNT)) || true
    ((TOTAL_FAIL += FAIL_COUNT)) || true
done

echo ""
if (( TOTAL_FAIL == 0 )); then
    echo "=== ALL TESTS PASSED (${TOTAL_PASS} checks) ==="
    exit 0
else
    echo "=== ${TOTAL_FAIL} FAILED, ${TOTAL_PASS} passed ==="
    exit 1
fi
