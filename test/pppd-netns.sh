#!/usr/bin/env bash
# Run modem-ctl (which execs pppd) in a throwaway network namespace so that
# the ppp client interface and its routes don't collide with ppp0 on the host
# (where ppp-server is already running).
#
# Usage:
#   ./test/pppd-netns.sh <device> <number> [extra pppd args...]
#
# Example:
#   ./test/pppd-netns.sh /dev/ttyUSB0 5001
#
# The namespace is named ppp-test-<PID> and is torn down on exit (normal,
# Ctrl-C, or error).

set -euo pipefail

DEVICE="${1:?Usage: $0 <device> <number> [pppd-args...]}"
NUMBER="${2:?Usage: $0 <device> <number> [pppd-args...]}"
shift 2
EXTRA_PPPD_ARGS="${*:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODEM_CTL="${SCRIPT_DIR}/../target/debug/modem-ctl"

if [[ ! -x "$MODEM_CTL" ]]; then
    echo "[netns] ERROR: modem-ctl not found at $MODEM_CTL — run 'cargo build' first" >&2
    exit 1
fi

NS="ppp-test-$$"

cleanup() {
    echo "[netns] tearing down namespace $NS"
    sudo ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[netns] creating namespace $NS"
sudo ip netns add "$NS"

echo "[netns] starting modem-ctl $DEVICE dial $NUMBER (pppd runs inside $NS)"
# ip netns exec keeps the current uid; sudo inside modem-ctl is not needed
# because the serial device and Unix socket are accessible from any netns.
# pppd needs root to create a ppp interface — run as root in the namespace.
sudo ip netns exec "$NS" \
    "$MODEM_CTL" "$DEVICE" dial "$NUMBER" \
    ${EXTRA_PPPD_ARGS:+--pppd-args "$EXTRA_PPPD_ARGS"}
