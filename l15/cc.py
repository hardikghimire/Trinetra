#!/usr/bin/env python3
"""
Extract real wire-to-wire RTT per destination port from a tcpdump capture,
so it can be compared against shiv's own --debug rtt output.

Requires: pip install dpkt

Usage:
    sudo tcpdump -i eth0 -w scan.pcap 'host 192.168.1.254 and tcp'
    # (run your shiv scan while that's capturing, then ctrl-c the tcpdump)
    python3 pcap_rtt.py scan.pcap --target 192.168.1.254

What it does:
    - Finds every outbound SYN (SYN set, ACK clear) to <target>, keyed by
      destination port. Uses the FIRST SYN seen per port as t0 (ignores
      retries so it lines up with how shiv reports the initial probe).
    - Finds the first inbound reply from <target> on that same port
      (SYN+ACK, or RST) after t0.
    - rtt_ms = reply_time - t0, in milliseconds, from the pcap's own
      capture timestamps (kernel-level, same-ish precision as shiv's
      SO_TIMESTAMPING path, but captured independently by tcpdump/libpcap).
    - Prints a per-port table plus min/avg/max, in the same shape as
      shiv's "RTT Debug" block so you can eyeball the two side by side.
"""

import argparse
import sys
import statistics

try:
    import dpkt
except ImportError:
    sys.exit("Missing dependency. Install it with: pip install dpkt --break-system-packages")


def ip_to_str(b):
    return ".".join(str(x) for x in b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="path to the .pcap/.pcapng file")
    ap.add_argument("--target", required=True, help="target IP that was scanned")
    args = ap.parse_args()

    syn_time = {}   # port -> first SYN timestamp (float, seconds)
    reply_time = {}  # port -> first reply timestamp

    with open(args.pcap, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
            except Exception:
                continue

            src = ip_to_str(ip.src) if isinstance(ip.src, (bytes, bytearray)) else ip.src
            dst = ip_to_str(ip.dst) if isinstance(ip.dst, (bytes, bytearray)) else ip.dst
            syn = bool(tcp.flags & dpkt.tcp.TH_SYN)
            ack = bool(tcp.flags & dpkt.tcp.TH_ACK)
            rst = bool(tcp.flags & dpkt.tcp.TH_RST)

            # Outbound SYN (probe): us -> target, SYN set, ACK clear
            if dst == args.target and syn and not ack:
                port = tcp.dport
                if port not in syn_time:
                    syn_time[port] = ts

            # Inbound reply: target -> us, on that port, SYN+ACK or RST
            elif src == args.target and (rst or (syn and ack)):
                port = tcp.sport
                if port in syn_time and port not in reply_time:
                    reply_time[port] = ts

    rows = []
    for port, t0 in syn_time.items():
        t1 = reply_time.get(port)
        if t1 is None:
            continue
        rtt_ms = (t1 - t0) * 1000.0
        rows.append((port, rtt_ms))

    rows.sort(key=lambda r: r[0])

    if not rows:
        print("No matched SYN -> reply pairs found. Check --target and that the "
              "capture covers the scan window.")
        return

    print(f"{'PORT':>7}  {'RTT (ms)':>10}")
    for port, rtt_ms in rows:
        print(f"{port:>7}  {rtt_ms:>10.3f}")

    values = [r[1] for r in rows]
    print()
    print(f"Matched     : {len(rows)} / {len(syn_time)} probes")
    print(f"Min RTT     : {min(values):.3f} ms")
    print(f"Avg RTT     : {statistics.mean(values):.3f} ms")
    print(f"Max RTT     : {max(values):.3f} ms")
    if len(values) > 1:
        print(f"Stdev       : {statistics.pstdev(values):.3f} ms")


if __name__ == "__main__":
    main()
