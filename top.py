#!/usr/bin/env python3
"""
shiv_to_topology.py

Converts the raw scan output written by save_scan_results() (Shiv scanner,
see anomaly_analysis.cpp / control.cpp) into the structured topology format
that index.html's parsePortScanTXT() understands:

    SUBNET: <cidr>
    HOST: <ip> | <name> | <status>
    PORT: <port> | <service> | <status>
    CONNECT: <ip> -> <ip>

DESIGN GOAL: no hardcoded IPs / domains / ports / service names anywhere.
Every field is pulled out by matching the *shape* of the data (an IPv4
octet pattern, a "<number>/tcp" pattern, a domain-label pattern, etc.),
not by comparing against a fixed list of known values. That means it
keeps working no matter what hosts, ports, or services a future scan
happens to report.

Usage:
    python3 shiv_to_topology.py out.txt topology.txt
    cat out.txt | python3 shiv_to_topology.py - topology.txt
"""

import re
import sys
from collections import OrderedDict

# ---------------------------------------------------------------------------
# 1. STRUCTURAL PATTERNS (shape-based, not value-based)
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Any dotted-quad, valid or not (0-255 not strictly enforced -- doesn't
# matter for extraction purposes, we just need "looks like an IPv4").
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Any domain-shaped token: label.label.tld  (used for reverse-DNS hostnames
# that aren't IPs, e.g. "web01.internal.corp"). Deliberately generic --
# matches ANY domain, not a specific one.
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

# "Shiv scan report for <maybe hostname> (<ip>)" or just "<ip>"
# Host/ip are captured generically -- whatever text is actually there.
HOST_HEADER_RE = re.compile(
    r'Shiv scan report for\s+'
    r'(?:(?P<host>\S+)\s*\(\s*(?P<ip1>' + IPV4_RE.pattern + r')\s*\)'
    r'|(?P<ip2>' + IPV4_RE.pattern + r'))'
)

# Optional "[Provider Label]" that may follow a host header
PROVIDER_RE = re.compile(r'\[\s*(?P<provider>[^\]]+?)\s*\]')

# Port table row: "<port>/tcp   <state>   <service>   [extra...]"
# port/state/service are all captured dynamically -- any number, any
# state word, any service string. Nothing here is a fixed enum.
PORT_LINE_RE = re.compile(
    r'^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+'
    r'(?P<state>\S+)\s+'
    r'(?P<service>\S+)'
)

# "Not shown: N closed tcp ports (reset) | ..." style summary line
NOT_SHOWN_RE = re.compile(r'^Not shown:', re.IGNORECASE)

PORT_TABLE_HEADER_RE = re.compile(r'^PORT\s+STATE\s+SERVICE', re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text)


def normalize_state(state: str) -> str:
    """
    Map whatever state word Shiv printed to one of the three states
    index.html's UI understands for styling (open/filtered/closed),
    WITHOUT hardcoding the full list of possible Shiv states -- anything
    unrecognized just passes through unchanged so it still displays.
    """
    s = state.lower()
    if s in ('open', 'unfiltered'):
        return 'open'
    if s in ('filtered', 'confused'):
        return 'filtered'
    if s == 'closed':
        return 'closed'
    return s  # unknown state word -> keep as-is, don't drop the data


def guess_subnet(ips):
    """
    Derive a /24 subnet label purely from the IPs actually seen in this
    scan -- never a hardcoded network. If hosts span multiple /24s, fall
    back to the most common one.
    """
    if not ips:
        return None
    prefixes = ['.'.join(ip.split('.')[:3]) + '.0/24' for ip in ips]
    counts = OrderedDict()
    for p in prefixes:
        counts[p] = counts.get(p, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


def parse_shiv_output(raw_text: str):
    """
    Walk the raw Shiv console/log output line by line and pull out hosts +
    ports using only the structural patterns above.
    """
    text = strip_ansi(raw_text)
    lines = text.split('\n')

    hosts = OrderedDict()   # ip -> {"name": ..., "ports": [...]}
    current_ip = None

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        # Skip the column header row, it's not data
        if PORT_TABLE_HEADER_RE.match(line):
            continue

        # --- Host header ---
        m = HOST_HEADER_RE.search(line)
        if m:
            ip = m.group('ip1') or m.group('ip2')
            host_token = m.group('host')  # may be None, or a hostname, or repeat of ip
            name = ip
            if host_token and host_token != ip and not IPV4_RE.fullmatch(host_token):
                name = host_token
            pm = PROVIDER_RE.search(line)
            if pm and name == ip:
                # No distinct hostname was found, but we do have a
                # provider label -- still useful as a display name.
                name = f"{ip} [{pm.group('provider')}]"

            current_ip = ip
            if ip not in hosts:
                hosts[ip] = {"name": name, "ports": []}
            continue

        # --- Port row ---
        pm = PORT_LINE_RE.match(line)
        if pm and current_ip:
            port = pm.group('port')
            service = pm.group('service')
            state = normalize_state(pm.group('state'))
            hosts[current_ip]["ports"].append((port, service, state))
            continue

        # "Not shown: ..." and other summary lines are intentionally
        # ignored here -- they describe aggregate counts, not individual
        # ports/hosts/services, so there's nothing structured to extract.

    return hosts


def to_topology_txt(hosts: "OrderedDict"):
    ips = list(hosts.keys())
    subnet = guess_subnet(ips)

    out_lines = ["# Auto-generated from Shiv scan output"]
    if subnet:
        out_lines.append(f"SUBNET: {subnet}")
    out_lines.append("")

    for ip, info in hosts.items():
        status = "alive"  # a host we got any output for is reachable
        out_lines.append(f"HOST: {ip} | {info['name']} | {status}")
        for port, service, state in info["ports"]:
            out_lines.append(f"PORT: {port} | {service} | {state}")
        out_lines.append("")

    return "\n".join(out_lines).rstrip() + "\n"


def main():
    if len(sys.argv) < 2:
        print("Usage: shiv_to_topology.py <input:out.txt|-> [output:topology.txt]",
              file=sys.stderr)
        sys.exit(1)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else None

    raw = sys.stdin.read() if src == '-' else open(src, 'r', encoding='utf-8', errors='replace').read()

    hosts = parse_shiv_output(raw)
    topology_txt = to_topology_txt(hosts)

    if dst:
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(topology_txt)
        print(f"Wrote {dst} ({len(hosts)} host(s) detected)", file=sys.stderr)
    else:
        sys.stdout.write(topology_txt)


if __name__ == '__main__':
    main()
