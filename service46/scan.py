#!/usr/bin/env python3
"""
scan.py - Capture raw service responses for service-probe detection.
Usage: python3 scan.py <ip> <port> [output_file] [--timeout seconds]

Smart protocol selection: reads nmap-service-probes first to decide whether to
use raw TCP, SSL, or UDP — eliminating unnecessary connection attempts.
--force-raw / --force-http / --force-https / --udp override the auto-detection.

Special handling: port 1883 (MQTT) uses a proper MQTT CONNECT handshake to
retrieve broker version info via the $SYS/broker/version topic.
"""

import socket
import sys
import ssl
import re
import struct
import argparse
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------------------------
# Probe-file parser
# ---------------------------------------------------------------------------

def parse_probe_file(probe_path: str) -> dict:
    """
    Parse nmap-service-probes and return two mappings:

      ssl_ports  : set[int]  – ports that should be contacted over SSL/TLS
      tcp_ports  : dict[int, bytes | None]
                              – port → probe payload (None = NULL / banner-only)
      udp_ports  : dict[int, bytes | None]
                              – port → probe payload
      excluded   : set[int]  – ports listed on the Exclude line

    Only the *first* match per port is stored (nmap tries probes in order and
    stops at the first match, so we replicate that priority here).
    """
    ssl_ports: set[int] = set()
    tcp_ports: dict[int, bytes | None] = {}
    udp_ports: dict[int, bytes | None] = {}
    excluded:  set[int] = set()

    def expand_port_list(token: str) -> list[int]:
        """Turn '80,443,8080-8090' into a flat list of ints."""
        ports = []
        for part in token.split(','):
            part = part.strip()
            if '-' in part:
                lo, hi = part.split('-', 1)
                ports.extend(range(int(lo), int(hi) + 1))
            elif part:
                ports.append(int(part))
        return ports

    def unescape_probe_string(raw: str) -> bytes:
        """
        Convert the printable probe string (between q|…|) into real bytes,
        handling \\r \\n \\t \\xHH octal and literal chars.
        """
        result = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == '\\' and i + 1 < len(raw):
                c = raw[i + 1]
                if c == 'r':
                    result.append(0x0d); i += 2
                elif c == 'n':
                    result.append(0x0a); i += 2
                elif c == 't':
                    result.append(0x09); i += 2
                elif c == '0':
                    result.append(0x00); i += 2
                elif c == 'x' and i + 3 < len(raw):
                    result.append(int(raw[i+2:i+4], 16)); i += 4
                elif c.isdigit():          # octal \NNN
                    octal_str = ''
                    j = i + 1
                    while j < len(raw) and raw[j].isdigit() and len(octal_str) < 3:
                        octal_str += raw[j]; j += 1
                    result.append(int(octal_str, 8)); i = j
                elif c == '\\':
                    result.append(ord('\\')); i += 2
                else:
                    result.append(ord(c)); i += 2
            else:
                result.append(ord(raw[i])); i += 1
        return bytes(result)

    current_proto   = None   # 'TCP' | 'UDP'
    current_payload = None   # bytes | None
    current_name    = None   # probe name string

    try:
        with open(probe_path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')

                # --- Exclude line ---
                if line.startswith('Exclude '):
                    # Format: "Exclude T:9100-9107,T:..."
                    for segment in line[8:].split(','):
                        segment = segment.strip()
                        if ':' in segment:
                            segment = segment.split(':', 1)[1]
                        for p in expand_port_list(segment):
                            excluded.add(p)

                # --- Probe line ---
                elif line.startswith('Probe '):
                    # Format: Probe TCP|UDP <name> q|<payload>|
                    m = re.match(r'^Probe\s+(TCP|UDP)\s+(\S+)\s+q\|([^|]*)\|', line)
                    if m:
                        current_proto   = m.group(1)
                        current_name    = m.group(2)
                        raw_payload     = m.group(3)
                        current_payload = None if current_name == 'NULL' else unescape_probe_string(raw_payload)

                # --- ports line (TCP) ---
                elif line.startswith('ports ') and current_proto == 'TCP':
                    for p in expand_port_list(line[6:]):
                        if p not in tcp_ports:          # first probe wins
                            tcp_ports[p] = current_payload

                # --- sslports line ---
                elif line.startswith('sslports '):
                    for p in expand_port_list(line[9:]):
                        ssl_ports.add(p)
                        # Also register in tcp_ports if not already there,
                        # using the current probe's payload.
                        if p not in tcp_ports:
                            tcp_ports[p] = current_payload

                # --- ports line (UDP) ---
                elif line.startswith('ports ') and current_proto == 'UDP':
                    for p in expand_port_list(line[6:]):
                        if p not in udp_ports:
                            udp_ports[p] = current_payload

    except FileNotFoundError:
        print(f"[!] Probe file not found: {probe_path}", file=sys.stderr)

    return {
        'ssl_ports': ssl_ports,
        'tcp_ports': tcp_ports,
        'udp_ports': udp_ports,
        'excluded':  excluded,
    }


def decide_method(port: int, probe_data: dict, force_udp: bool = False) -> tuple:
    """
    Return (method, payload) where method is one of:
      'mqtt'     – MQTT CONNECT handshake (port 1883 or other known MQTT ports)
      'ssl'      – wrap in TLS, send payload (may be None)
      'tcp'      – plain TCP, send payload (may be None = banner grab only)
      'udp'      – UDP, send payload
      'fallback' – no probe-file info; caller should try multiple methods
    """
    if force_udp:
        payload = probe_data['udp_ports'].get(port, None)
        return ('udp', payload)

    # MQTT special handling: port 1883 (standard) and 8883 (MQTT over SSL)
    if port == 1883:
        return ('mqtt', None)

    if port in probe_data['ssl_ports']:
        payload = probe_data['tcp_ports'].get(port, None)
        return ('ssl', payload)

    if port in probe_data['tcp_ports']:
        return ('tcp', probe_data['tcp_ports'][port])

    if port in probe_data['udp_ports']:
        return ('udp', probe_data['udp_ports'][port])

    return ('fallback', None)


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------

MAX_RESPONSE = 65536
CHUNK        = 4096


def _recv_all(sock, timeout) -> bytes:
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(CHUNK)
            if not chunk:
                break
            data += chunk
            if len(data) >= MAX_RESPONSE:
                break
        except socket.timeout:
            break
    return data


def capture_tcp(host: str, port: int, timeout: float, payload: bytes | None) -> bytes | None:
    """Plain TCP: optionally send a probe, then read the response."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if payload:
                s.sendall(payload)
            return _recv_all(s, timeout) or None
    except Exception as e:
        print(f"  [tcp] {e}", file=sys.stderr)
        return None


def capture_ssl(host: str, port: int, timeout: float, payload: bytes | None) -> bytes | None:
    """TLS-wrapped TCP: optionally send a probe, then read the response."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            data = b''
            while True:
                try:
                    chunk = s.recv(CHUNK)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= MAX_RESPONSE:
                        break
                except socket.timeout:
                    break
                except ssl.SSLWantReadError:
                    continue
                except ssl.SSLError as e:
                    if 'ZERO_RETURN' in str(e):
                        break
                    raise
            return data or None
    except Exception as e:
        print(f"  [ssl] {e}", file=sys.stderr)
        return None


def capture_udp(host: str, port: int, timeout: float, payload: bytes | None) -> bytes | None:
    """UDP: send probe (or empty datagram) and read a response."""
    if payload is None:
        payload = b'\n'    # generic wake-up byte
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            data, _ = s.recvfrom(CHUNK)
            return data or None
    except Exception as e:
        print(f"  [udp] {e}", file=sys.stderr)
        return None


def capture_mqtt(host: str, port: int, timeout: float) -> bytes | None:
    """
    MQTT-specific probe: perform a proper MQTT CONNECT handshake, then
    subscribe to $SYS/broker/version to pull the broker version banner.

    Returns a synthesised response buffer containing the CONNACK + any
    PUBLISH packets received (including the version string), so the caller
    can write it to a file and pass it to the probe tool exactly like any
    other raw capture.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    collected = bytearray()

    try:
        sock.connect((host, port))

        # --- Build CONNECT packet ---
        client_id = b"scan_probe"
        connect = bytearray()
        connect.append(0x10)                                    # CONNECT fixed header
        connect.append(12 + len(client_id))                    # Remaining length
        connect.extend(b"\x00\x04MQTT\x04\x02\x00\x3c")       # Protocol name/level, flags, keepalive
        connect.extend(struct.pack(">H", len(client_id)))
        connect.extend(client_id)
        sock.sendall(bytes(connect))

        # --- Read CONNACK (4 bytes expected) ---
        connack = b''
        try:
            connack = sock.recv(4)
        except socket.timeout:
            pass

        if len(connack) < 4:
            print(f"  [mqtt] Incomplete CONNACK ({len(connack)} bytes)", file=sys.stderr)
            collected.extend(connack)
            return bytes(collected) or None

        collected.extend(connack)
        return_code = connack[3]

        if return_code != 0:
            print(f"  [mqtt] Broker requires auth (CONNACK return code: {return_code})", file=sys.stderr)
            # Still return what we got — it's enough for the probe tool to ID the service
            return bytes(collected)

        print(f"  [mqtt] Connected (CONNACK OK)", file=sys.stderr)

        # --- Build SUBSCRIBE packet for $SYS/broker/version ---
        topic = b"$SYS/broker/version"
        subscribe = bytearray()
        subscribe.append(0x82)                                  # SUBSCRIBE, QoS1
        subscribe.append(2 + 2 + len(topic) + 1)              # Remaining length
        subscribe.extend(b"\x00\x01")                          # Packet ID = 1
        subscribe.extend(struct.pack(">H", len(topic)))
        subscribe.extend(topic)
        subscribe.append(0x00)                                  # Requested QoS 0
        sock.sendall(bytes(subscribe))

        # --- Read SUBACK + any PUBLISH messages ---
        sock.settimeout(timeout)
        while True:
            try:
                data = sock.recv(CHUNK)
                if not data:
                    break
                collected.extend(data)

                # Try to print version string for operator convenience
                for i in range(len(data)):
                    if 32 <= data[i] <= 126:
                        segment = data[i:].split(b'\x00')[0]
                        try:
                            text = segment.decode('ascii', errors='replace')
                            if 'mosquitto' in text.lower() or 'version' in text.lower():
                                print(f"  [mqtt] Broker version: {text}", file=sys.stderr)
                                break
                        except Exception:
                            pass
                if len(collected) >= MAX_RESPONSE:
                    break
            except socket.timeout:
                break

    except Exception as e:
        print(f"  [mqtt] {e}", file=sys.stderr)
    finally:
        sock.close()

    return bytes(collected) or None


def capture_fallback(host: str, port: int, timeout: float) -> tuple[bytes | None, str | None]:
    """
    Original 3-step fallback used when the probe file has no info for this port.
    Returns (response, method_label).
    """
    http_probe = (
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    ).encode()

    print(f"[*] Trying raw TCP banner...", file=sys.stderr)
    r = capture_tcp(host, port, timeout, payload=None)
    if r:
        print(f"[+] Got raw TCP response: {len(r)} bytes", file=sys.stderr)
        return r, 'raw_tcp'
    print(f"[-] No raw TCP response", file=sys.stderr)

    print(f"[*] Trying HTTP probe...", file=sys.stderr)
    r = capture_tcp(host, port, timeout, payload=http_probe)
    if r:
        print(f"[+] Got HTTP response: {len(r)} bytes", file=sys.stderr)
        return r, 'http'
    print(f"[-] No HTTP response", file=sys.stderr)

    print(f"[*] Trying HTTPS/SSL probe...", file=sys.stderr)
    r = capture_ssl(host, port, timeout, payload=http_probe)
    if r:
        print(f"[+] Got HTTPS/SSL response: {len(r)} bytes", file=sys.stderr)
        return r, 'https'
    print(f"[-] No HTTPS/SSL response", file=sys.stderr)

    return None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEFAULT_PROBE_PATHS = [
    '/home/ghostfreak/service/nmap-service-probes.txt',
    '/home/ghostfreak/service/nmap-service-probes.txt',
    '/home/ghostfreak/service/nmap-service-probes.txt',
    '/home/ghostfreak/service/nmap-service-probes.txt',
]


def find_probe_file(explicit: str | None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else None
    for p in DEFAULT_PROBE_PATHS:
        if Path(p).exists():
            return p
    return None


def main():
    parser = argparse.ArgumentParser(description='Capture raw service responses for service-probe detection')
    parser.add_argument('ip',          help='Target IP address')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('output', nargs='?', default=None, help='Output file (default: auto-generated)')
    parser.add_argument('--probes',    default=None,  help='Path to nmap-service-probes file (auto-detected if omitted)')
    parser.add_argument('--udp',       action='store_true', help='Use UDP protocol')
    parser.add_argument('--timeout',   type=int, default=5, help='Timeout in seconds (default: 5)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    parser.add_argument('--force-raw',   action='store_true', help='Force raw TCP only (no fallback)')
    parser.add_argument('--force-http',  action='store_true', help='Force HTTP probe only')
    parser.add_argument('--force-https', action='store_true', help='Force HTTPS probe only')
    args = parser.parse_args()

    # Generate default output filename if not specified
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"{args.ip}_{args.port}_{timestamp}.raw"

    response = None
    method = None

    if args.udp:
        # UDP capture — load probes to get correct payload, fallback to generic
        if args.verbose:
            print(f"[*] Capturing UDP response from {args.ip}:{args.port}")
        probe_path = find_probe_file(args.probes)
        probe_data = parse_probe_file(probe_path) if probe_path else {'ssl_ports': set(), 'tcp_ports': {}, 'udp_ports': {}, 'excluded': set()}
        _, payload = decide_method(args.port, probe_data, force_udp=True)
        response = capture_udp(args.ip, args.port, args.timeout, payload)
        method = "udp"

    elif args.force_raw:
        # Force raw TCP only
        if args.verbose:
            print(f"[*] Capturing raw TCP banner from {args.ip}:{args.port}")
        response = capture_tcp(args.ip, args.port, args.timeout, payload=None)
        method = "raw_tcp"

    elif args.force_http:
        # Force HTTP only
        if args.verbose:
            print(f"[*] Capturing HTTP response from {args.ip}:{args.port}")
        http_probe = f"GET / HTTP/1.1\r\nHost: {args.ip}:{args.port}\r\nConnection: close\r\n\r\n".encode()
        response = capture_tcp(args.ip, args.port, args.timeout, payload=http_probe)
        method = "http"

    elif args.force_https:
        # Force HTTPS only
        if args.verbose:
            print(f"[*] Capturing HTTPS response from {args.ip}:{args.port}")
        https_probe = f"GET / HTTP/1.1\r\nHost: {args.ip}:{args.port}\r\nConnection: close\r\n\r\n".encode()
        response = capture_ssl(args.ip, args.port, args.timeout, payload=https_probe)
        method = "https"

    else:
        # Smart auto-detection using probe file
        probe_path = find_probe_file(args.probes)
        if probe_path:
            if args.verbose:
                print(f"[*] Loading probe file: {probe_path}", file=sys.stderr)
            probe_data = parse_probe_file(probe_path)
        else:
            print(f"[!] nmap-service-probes not found – using fallback detection.", file=sys.stderr)
            probe_data = {'ssl_ports': set(), 'tcp_ports': {}, 'udp_ports': {}, 'excluded': set()}

        detected_method, payload = decide_method(args.port, probe_data)

        if detected_method == 'mqtt':
            # Special MQTT handshake — performs CONNECT + $SYS/broker/version subscribe
            print(f"[*] Probe file: port {args.port} → MQTT handshake", file=sys.stderr)
            response = capture_mqtt(args.ip, args.port, args.timeout)
            method = "mqtt"

        elif detected_method == 'ssl':
            print(f"[*] Probe file: port {args.port} → SSL/TLS", file=sys.stderr)
            response = capture_ssl(args.ip, args.port, args.timeout, payload)
            method = "https"

        elif detected_method == 'tcp' and payload is None:
            # NULL probe: banner grab only
            print(f"[*] Probe file: port {args.port} → raw TCP banner", file=sys.stderr)
            response = capture_tcp(args.ip, args.port, args.timeout, payload=None)
            method = "raw_tcp"

        elif detected_method == 'tcp':
            print(f"[*] Probe file: port {args.port} → TCP probe ({len(payload)} bytes)", file=sys.stderr)
            response = capture_tcp(args.ip, args.port, args.timeout, payload=payload)
            method = "tcp_probe"

        else:
            # No probe-file match: original 3-step fallback
            if args.verbose:
                print(f"[*] No probe-file match for port {args.port} – using automatic fallback detection", file=sys.stderr)
            response, method = capture_fallback(args.ip, args.port, args.timeout)

    if response is None or len(response) == 0:
        print(f"[-] No response received from {args.ip}:{args.port} using any method", file=sys.stderr)
        sys.exit(1)

    # Save to file
    with open(args.output, 'wb') as f:
        f.write(response)

    print(f"[+] Saved {len(response)} bytes to {args.output} (method: {method})")

    if args.verbose:
        print(f"\nFirst 200 bytes (hexdump):")
        hex_str = ' '.join(f'{b:02x}' for b in response[:50])
        print(f"  {hex_str}...")
        print(f"\nFirst 200 bytes (ascii preview):")
        ascii_preview = response[:200].decode('ascii', errors='replace')
        print(f"  {ascii_preview[:200]}")

    # Optional: automatically run probe tool
    probe_tool = input("\nRun probe tool? (y/n): ").lower().strip()
    if probe_tool == 'y':
        import subprocess
        probe_cmd = ['./probe', '/home/ghostfreak/service/nmap-service-probes.txt', args.output, str(args.port), 'tcp']
        if args.udp:
            probe_cmd[-1] = 'udp'
        print(f"\n[*] Running: {' '.join(probe_cmd)}")
        subprocess.run(probe_cmd)


if __name__ == '__main__':
    main()
