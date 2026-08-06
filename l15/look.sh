#!/usr/bin/env bash
# Samples `tc -s qdisc show dev eth0` every 0.5s for 16s so you can line the
# output up against a scan run and see if backlog/drops build up mid-burst.
#
# Usage:
#   ./watch_qdisc.sh &          # start it in the background
#   ./shiv -sS -Pn 192.168.1.254 --debug rtt   # then kick off your scan
#   wait                        # or just let the 16s finish on its own
#
# Output goes to qdisc_watch_<timestamp>.log in the current directory.

IFACE="eth0"
DURATION=16
INTERVAL=0.5
OUTFILE="qdisc_watch_$(date +%Y%m%d_%H%M%S).log"

if ! command -v tc >/dev/null 2>&1; then
    echo "tc not found (install iproute2)" >&2
    exit 1
fi

echo "Sampling 'tc -s qdisc show dev $IFACE' every ${INTERVAL}s for ${DURATION}s -> $OUTFILE"

end=$(( $(date +%s%0N) + DURATION * 1000000000 ))

while [ "$(date +%s%0N)" -lt "$end" ]; do
    {
        echo "===== $(date '+%Y-%m-%d %H:%M:%S.%3N') ====="
        tc -s qdisc show dev "$IFACE"
        echo
    } >> "$OUTFILE"
    sleep "$INTERVAL"
done

echo "Done. Saved to $OUTFILE"
