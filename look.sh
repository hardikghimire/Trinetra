#!/usr/bin/env bash
#
# nic_overload_monitor.sh — watch NIC drop/error counters and per-core softirq
# load while a command (e.g. a Shiv scan) runs, then save a before/after
# summary once it finishes.
#
# Usage:
#   ./nic_overload_monitor.sh <iface> -- <command to run> [args...]
#
# Example:
#   ./nic_overload_monitor.sh eth0 -- sudo ./shiv -p 1-65535 192.168.1.50
#
# Requires: iproute2 (ip), sysstat (mpstat), iproute2-tc (tc). ethtool optional.

set -uo pipefail

IFACE="${1:-}"
shift || true
if [[ "${1:-}" != "--" ]]; then
    echo "Usage: $0 <iface> -- <command to run> [args...]" >&2
    exit 1
fi
shift
CMD=("$@")

if [[ -z "$IFACE" || ${#CMD[@]} -eq 0 ]]; then
    echo "Usage: $0 <iface> -- <command to run> [args...]" >&2
    exit 1
fi

for bin in ip mpstat; do
    command -v "$bin" >/dev/null 2>&1 || { echo "Missing required tool: $bin" >&2; exit 1; }
done
HAVE_ETHTOOL=0
command -v ethtool >/dev/null 2>&1 && HAVE_ETHTOOL=1
HAVE_TC=0
command -v tc >/dev/null 2>&1 && HAVE_TC=1

TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="./nic_monitor_${TS}"
mkdir -p "$OUTDIR"
CPU_LOG="$OUTDIR/cpu_samples.log"
COUNTER_LOG="$OUTDIR/counter_samples.log"
REPORT="$OUTDIR/report.txt"

# ── Parse `ip -s link show <iface>` into 8 numbers:
# rx_bytes rx_packets rx_errors rx_dropped tx_bytes tx_packets tx_errors tx_dropped
get_counters() {
    ip -s link show "$IFACE" | awk '
        /^ *RX:/ { getline; rxb=$1; rxp=$2; rxe=$3; rxd=$4; next }
        /^ *TX:/ { getline; txb=$1; txp=$2; txe=$3; txd=$4; next }
        END { print rxb, rxp, rxe, rxd, txb, txp, txe, txd }'
}

echo "[*] Interface: $IFACE"
echo "[*] Output dir: $OUTDIR"
echo "[*] Command: ${CMD[*]}"

# ── Baseline snapshot ────────────────────────────────────────────────────
BASELINE="$(get_counters)"
read -r B_RXB B_RXP B_RXE B_RXD B_TXB B_TXP B_TXE B_TXD <<< "$BASELINE"

{
    echo "=== baseline $(date -Iseconds) ==="
    ip -s link show "$IFACE"
    if [[ $HAVE_TC -eq 1 ]]; then
        echo "--- tc qdisc ---"
        tc -s qdisc show dev "$IFACE"
    fi
    if [[ $HAVE_ETHTOOL -eq 1 ]]; then
        echo "--- ethtool -S ---"
        ethtool -S "$IFACE" 2>/dev/null | grep -iE 'drop|error|fifo|overrun|discard'
    fi
} > "$OUTDIR/baseline.txt"

# ── Background sampling loop ────────────────────────────────────────────
# mpstat -P ALL 1 1 doubles as our ~1s tick.
SAMPLE_PID=""
sampling_loop() {
    while true; do
        {
            echo "=== $(date -Iseconds) ==="
            get_counters
        } >> "$COUNTER_LOG"

        {
            echo "=== $(date -Iseconds) ==="
            mpstat -P ALL 1 1
        } >> "$CPU_LOG"

        if [[ $HAVE_TC -eq 1 ]]; then
            {
                echo "=== $(date -Iseconds) ==="
                tc -s qdisc show dev "$IFACE" | grep -i dropped
            } >> "$OUTDIR/qdisc_samples.log"
        fi
    done
}
sampling_loop &
SAMPLE_PID=$!

cleanup() {
    kill "$SAMPLE_PID" 2>/dev/null
    wait "$SAMPLE_PID" 2>/dev/null
}
trap cleanup EXIT

# ── Run the target command in the foreground ────────────────────────────
START_EPOCH=$(date +%s)
"${CMD[@]}"
CMD_STATUS=$?
END_EPOCH=$(date +%s)
DURATION=$((END_EPOCH - START_EPOCH))

cleanup
trap - EXIT

# ── Final snapshot ───────────────────────────────────────────────────────
FINAL="$(get_counters)"
read -r F_RXB F_RXP F_RXE F_RXD F_TXB F_TXP F_TXE F_TXD <<< "$FINAL"

{
    echo "=== final $(date -Iseconds) ==="
    ip -s link show "$IFACE"
    if [[ $HAVE_TC -eq 1 ]]; then
        echo "--- tc qdisc ---"
        tc -s qdisc show dev "$IFACE"
    fi
    if [[ $HAVE_ETHTOOL -eq 1 ]]; then
        echo "--- ethtool -S ---"
        ethtool -S "$IFACE" 2>/dev/null | grep -iE 'drop|error|fifo|overrun|discard'
    fi
} > "$OUTDIR/final.txt"

# ── Deltas ────────────────────────────────────────────────────────────────
D_RXP=$((F_RXP - B_RXP)); D_RXE=$((F_RXE - B_RXE)); D_RXD=$((F_RXD - B_RXD))
D_TXP=$((F_TXP - B_TXP)); D_TXE=$((F_TXE - B_TXE)); D_TXD=$((F_TXD - B_TXD))

if [[ $DURATION -gt 0 ]]; then
    TX_PPS=$((D_TXP / DURATION))
    RX_PPS=$((D_RXP / DURATION))
else
    TX_PPS=$D_TXP
    RX_PPS=$D_RXP
fi

# Max %soft seen on any core across all samples
MAX_SOFT="n/a"
if [[ -s "$CPU_LOG" ]]; then
    MAX_SOFT=$(awk '
        /%usr/ { for (i=1;i<=NF;i++) if ($i=="%soft") col=i; next }
        col && NF>=col && $1 !~ /^(CPU|Average|Linux|===)/ {
            v=$col+0; if (v>max) max=v
        }
        END { print (max=="" ? "n/a" : max) }
    ' "$CPU_LOG")
fi

TC_DROPS="n/a"
if [[ $HAVE_TC -eq 1 && -f "$OUTDIR/qdisc_samples.log" ]]; then
    TC_DROPS=$(grep -o 'dropped [0-9]*' "$OUTDIR/qdisc_samples.log" | awk '{print $2}' | sort -n | tail -1)
fi

{
    echo "NIC Overload Report"
    echo "===================="
    echo "Interface     : $IFACE"
    echo "Command       : ${CMD[*]}"
    echo "Exit status   : $CMD_STATUS"
    echo "Duration      : ${DURATION}s"
    echo
    echo "-- Packet counts (delta over run) --"
    echo "TX packets    : $D_TXP  (${TX_PPS} pps avg)"
    echo "RX packets    : $D_RXP  (${RX_PPS} pps avg)"
    echo
    echo "-- Overload indicators --"
    echo "TX errors     : $D_TXE"
    echo "TX dropped    : $D_TXD"
    echo "RX errors     : $D_RXE"
    echo "RX dropped    : $D_RXD"
    echo "Max %soft(any core): $MAX_SOFT"
    echo "Max tc qdisc dropped seen: $TC_DROPS"
    echo
    echo "-- Verdict --"
    if [[ "$D_TXD" -gt 0 || "$D_TXE" -gt 0 || "$D_RXD" -gt 0 || "$D_RXE" -gt 0 ]]; then
        echo "NIC/driver counters show drops or errors during the run -> likely NIC overload."
    elif [[ "$TC_DROPS" != "n/a" && "$TC_DROPS" -gt 0 ]]; then
        echo "tc qdisc dropped packets during the run -> queueing bottleneck before the NIC."
    elif [[ "$MAX_SOFT" != "n/a" ]] && awk -v v="$MAX_SOFT" 'BEGIN{exit !(v>85)}'; then
        echo "No drop counters incremented, but a core spent >85% time in softirq -> single-core"
        echo "packet-processing bottleneck (looks like a hang even with low overall CPU%)."
    else
        echo "No clear NIC overload signal in these counters. If it still hung, check RAM/swap"
        echo "and Shiv's internal queues (buffer pool, retry queue) instead of the NIC."
    fi
    echo
    echo "Raw logs: $OUTDIR/baseline.txt, final.txt, counter_samples.log, cpu_samples.log"
    [[ $HAVE_TC -eq 1 ]] && echo "          $OUTDIR/qdisc_samples.log"
} | tee "$REPORT"

echo
echo "[*] Full report saved to: $REPORT"
