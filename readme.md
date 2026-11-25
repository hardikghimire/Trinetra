<div align="center">

# Trinetra

**A low-level, high-performance TCP and UDP scanner and service fingerprinter built on Linux `io_uring`.**

[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)]()
[![Kernel](https://img.shields.io/badge/Kernel-6.12%2B-critical.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)]()
[![License](https://img.shields.io/badge/License-NPSL%200.95-orange.svg)](LICENSE)

</div>

---

## Table of contents

- [Overview](#overview)
- [License and provenance](#license-and-provenance)
- [Version detection: inherited, modified, added](#version-detection-inherited-modified-added)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Architecture (for contributors)](#architecture-for-contributors)
- [A note on naming](#a-note-on-naming)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)

---

## Overview

Trinetra is a from-scratch, raw-packet scanner for TCP and UDP that leverages
Linux `io_uring` for batched asynchronous I/O. It is designed as a
**learning-first** tool: the implementation comes first, and the theory
follows by observing real packet behavior. Trinetra provides deep,
low-level control over every header and option it sends, making it a
practical lab for understanding networking internals, protocol
behavior, and kernel I/O subsystems.

---

> [!WARNING]
> **Trinetra performs raw packet manipulation and may crash or destabilize
> target TCP/IP stacks.** It is intended **strictly** for educational
> purposes, home labs, and authorized penetration testing / red-team
> engagements.
>
> **Do not use Trinetra against systems you do not own or have explicit
> written permission to test.** You are responsible for complying with all
> applicable laws.

---

## License and provenance

Trinetra is an original project. The only Nmap-derived part is the
**probe-file matching component of service/version detection** (the
`nmap-service-probes` database format and its match semantics). That component
is distributed under the **Nmap Public Source License Version 0.95 (NPSL)**.
The complete license, including GPL-2.0 Exhibit A, is in [`LICENSE`](LICENSE).

That component has been substantially modified and extended, and the
modifications are covered by the applicable NPSL/GPL terms as part of the
derivative work. The rest of Trinetra, including the scanner core (TCP and
UDP), the I/O engine, the web/TLS fingerprinting stage, and all other modules,
is independently authored and may be governed by its own notices.

A copyright or license notice in another file does not replace the NPSL where
that file contains or derives from Nmap code or data.

See the NPSL and GPL-2.0 terms in that file for the applicable obligations.
Version detection is itemized in
[Version detection: inherited, modified, added](#version-detection-inherited-modified-added).

---

## Version detection: inherited, modified, added

Trinetra's `-sV` is a two-stage pipeline. Stage 1 uses an Nmap-compatible probe
database; Stage 2 is Trinetra's own web/TLS fingerprinting. Everything outside
version detection (raw TCP and UDP scanning, `io_uring` engine, namespace
isolation, discovery, enumeration, server mode, DNS) is original and is not
covered here.

### 1. Inherited from Nmap (the only borrowed part)

Probe-file matching, kept compatible so existing probe data keeps working:

| Inherited | Detail |
|---|---|
| `nmap-service-probes` file format | `Probe`, `ports`, `sslports`, `rarity`, `fallback`, `totalwaitms`, `tcpwrappedms`, `Exclude`, `match`, `softmatch` |
| Match semantics | Hard vs soft matches, NULL probe first, fallback chains, rarity vs `--version-intensity` |
| Template substitution grammar | `$1`..`$9`, `$P()`, `$SUBST()`, `$I()`, and `p/ v/ i/ h/ o/ d/ cpe:/` fields |

### 2. Modified: the probe-matching layer, re-engineered

`probe.cpp` re-implements the inherited layer for multithreaded scanning:

| Area | What Trinetra does |
|---|---|
| **Thread-safe lazy regex compile** | Patterns compile on first use behind atomics and a mutex (double-checked), so thousands of unused signatures cost nothing at startup. |
| **Hit-count-driven JIT** | A pattern is PCRE2-JIT-compiled only after it matches more than twice, with automatic fallback to the interpreter on JIT stack exhaustion. |
| **ReDoS containment** | Per-thread match contexts enforce match and depth limits, so a catastrophic-backtracking signature is logged and skipped instead of stalling a worker. |
| **Bad signature isolation** | An invalid regex disables only that template, with a line-numbered error, rather than aborting the scan. |
| **Literal-prefix prefilter** | For anchored patterns (`^...`), a safe literal prefix is extracted (alternation, quantifiers and escapes handled) and compared before PCRE2 runs. |
| **Arena allocator** | A 64 MiB bump allocator keeps compiled regexes contiguous; out-of-arena frees fall through safely. |
| **Port index** | A hash index from `(protocol, tunnel, port)` to the probes that list it, replacing repeated linear scans. |
| **`mmap` probe loading** | The probe file is memory-mapped and parsed in place; an unterminated last line is handled safely. |
| **Hardened parser** | Exceptions with line numbers instead of `exit()`; bounds-checked escapes and delimiters; validated `rarity`, `totalwaitms`, `tcpwrappedms`; unknown and **circular fallback** detection at load time. |
| **`Exclude` grammar** | `T:` / `U:` / `S:` prefixed ports and ranges, where the protocol prefix persists across items. |
| **RAII** | Smart pointers and scoped guards replace manual lifetime management in the parse and match paths. |
| **Decoupled matching** | `ProbeEngine::matchResponse()` takes bytes plus a context and performs no I/O, so one engine serves TCP, TLS and UDP. The probe that produced a response is tried first. |

### 3. Added: new in Trinetra

#### A. Asynchronous I/O reactor

`async_io.cpp` / `async_io.hpp` is Trinetra's own network layer for version detection:

| Area | What Trinetra does |
|---|---|
| **Sharded `epoll` reactor** | N worker threads, each owning one `epoll` instance and one `eventfd` wake-up. Every operation belongs to exactly one worker, so no operation is touched from two threads. `submit()` and `cancel()` only enqueue and wake. |
| **Exactly-once completion** | An atomic flag makes `finish()` idempotent. A timeout, an event and a cancel can race and exactly one wins; the fd is closed once and every op gets exactly one `on_complete`, even on shutdown. |
| **Adaptive connect budget** | Connect timeout comes from the **median of the last 32 RTT samples x 4**, clamped between a configurable floor (`min_connect_ms`) and the caller's ceiling. |
| **Per-stage deadlines** | Separate deadlines for connect, TLS handshake, send, first byte and idle, kept in an ordered map with a stale-fd guard. |
| **Cooperative cancellation** | `run_blocking()` honors the global terminate flag and gives the reactor a bounded window to cancel. |
| **Fixed source-port mode** | Optional bind to a fixed source port with `SO_REUSEADDR`/`SO_REUSEPORT` and bounded retry on `EADDRINUSE`. |
| **Bounded responses** | Configurable per-operation response cap. |
| **Shared reactor** | One process-wide reactor with a configurable thread count that reports late reconfiguration instead of silently ignoring it. |

#### B. Web fingerprinting (Stage 2, entirely Trinetra's own)

Implemented in `control.cpp`, after probe matching:

- **Platform signature layer** driven by `signatures.conf` (`[platform.*]`
  blocks and `[terms]`), covering firewalls/IDS, WAFs, proxies and gateways,
  routers and embedded devices, admin UIs, frameworks, servers/PBX, IoT /
  cameras / printers / ICS, and CMS / e-commerce / forums.
- **HTTP response analysis**: status line and code, HTML `<title>` extraction
  with entity decoding, asset-path and web-manifest discovery (`href`/`src`,
  `rel="manifest"`), SPA redirect discovery, and header-derived fingerprints
  (server, framework, proxy/CDN, cache, reporting endpoints).
- **Robust body handling**: header parsing with duplicate-header tracking,
  chunked decoding, and compressed-body decoding (including zstd) under hard
  size caps.
- **Redirect following with SSRF guards**: loopback, link-local, private and
  LAN targets are refused as redirect destinations.
- **Smart `Host` header**: reverse DNS for public targets, direct IP for LAN
  targets, `--host` override, optional custom DNS resolvers.
- **Probe fix-ups**: missing `Host:` / `User-Agent:` injected into HTTP probes;
  an HTTP/1.0 probe that draws a 5xx is retried as 1.1.
- **400-over-plaintext "SSL twin" fingerprinting** when a plain-HTTP request
  to a TLS port is answered with an HTTP error.
- **Special-case handlers**: MQTT handshake, UDP-first auto-detect with TCP
  fallback, and HP-PJL vs HTTP disambiguation on port 9100.

#### C. TLS handling and diagnostics

- **Handshake tracing**: an OpenSSL message callback records every handshake
  message type sent and received, alerts in both directions, the negotiated
  cipher from the ServerHello, bytes in/out, and the OpenSSL error queue.
- **Failure forensics**: on failure the tracer also captures the peer
  certificate (subject, issuer, self-signed, key type and size, signature
  algorithm). Peer-controlled text has control characters stripped and length
  capped, to prevent **terminal escape injection** into the operator's console.
- **Human-readable diagnosis**: alert names, hints, and a one-line reason for
  why a handshake died.
- **Strict then permissive**: a strict-profile attempt is followed by a
  permissive profile when needed, so older or odd devices are still fingerprinted.
- **Certificate intelligence**: SANs, issuer, validity, serial, SHA-1 and
  SHA-256 fingerprints and verification result, with optional peer
  verification, CA file/path and mTLS.
- **Correct SNI**: SNI never carries an IP literal (RFC 6066); IP targets are
  verified against the certificate's IP SANs instead.
- **TLS context cache** keyed by options, shared safely across workers.
- **Mid-stream TLS discovery**: if a plaintext probe receives a TLS record, the
  scan switches to TLS and retries that probe instead of accepting alert bytes
  as a banner.

#### D. Binary protocol decoder

When regex matching fails or gives a thin result, `binproto` identifies binary
protocols structurally and fills product, version and extra info.

#### E. Scan-time optimizations

| Optimization | Effect |
|---|---|
| **Reachability pre-check** (connect, then one HTTP GET) classifies a port as reachable, closed or filtered before any probe is sent | Filtered ports no longer burn a connect timeout on every probe |
| **Consecutive-timeout abort** (two in a row) | Stops probing a port that went dark mid-scan |
| **TLS dead-port short-circuit** | If the handshake fails in every profile, the TLS probe queue is skipped, since probe payload cannot change a failed handshake |
| **Probe-derived read timeouts** | Wait time comes from the probes' own `totalwaitms` |
| **NULL-probe sanity rule** | A NULL probe that draws a non-200 HTTP reply marks a web port and is skipped past |
| **Per-thread scan context** | Target, Host, SNI, path and TLS state are thread-local, so concurrent targets never mix state |

#### F. Operator experience

- Structured, color-aware **verbose logging** with phases and sanitized output.
- **Version notes** that explain *why* a result is missing or partial (server
  side blocking, TLS fault, repeated timeouts).
- Tunable reactor knobs: threads, response cap, cipher lists (TLS 1.2 and 1.3),
  minimum connect budget.

---

## Features

<details open>
<summary><strong>Scanning</strong></summary>

<br>

- **Multiple TCP scan types**
  - SYN (default), FIN, ACK, NULL, Xmas, Window, Maimon
  - Per-flag scans: CWR, ECE, URG, PSH
  - Custom named combinations: HANUMAN, KAKABHUSUNDI, GANESH, RAM, GARUD, JATAYU

- **UDP scanning (`-sU`)**
  - Built on raw UDP sockets rather than kernel UDP sockets
  - Works with the same options as TCP scans (for example `-Pn`)
  - Default port list: loads 1001 common UDP ports from `udp_1001_ports.txt`,
    the same way TCP loads its default list
  - Combine with `-sV` for UDP service detection

- **Ports file (`-p`)**
  - `-p` accepts a file with one port per line (for example `-p ports.txt`),
    for both TCP and UDP scans

- **State-machine handshake scan (`-G`)**
  - Completes a real 4-way TCP handshake with graceful teardown
  - Runs inside an isolated network namespace

- **Host discovery**
  - `-sn` for ICMP
  - `-sn6` for ICMPv6
  - Optional `-Pn` to skip discovery

- **IPv4 / IPv6 traceroute**
  - `--traceroute`, add `-6` for IPv6

- **Passive discovery (`--netradar`)**
  - Observe existing traffic on the wire: SYN, ACK, FIN, QUIC, DNS
  - Sends no packets of its own

</details>

<details open>
<summary><strong>Fingerprinting & Enumeration</strong></summary>

<br>

- **Service/version detection (`-sV`)**
  - Dual-stage pipeline
  - Stage 1: Nmap-compatible probe-file matching, on Trinetra's own reactor and
    re-engineered matching engine
  - Stage 2: Trinetra's dynamic response-body signature layer (titles, asset
    paths, platform/CDN fingerprints)
  - Details: [Version detection: inherited, modified, added](#version-detection-inherited-modified-added)

- **UDP service probing**
  - Enabled via `-sU -sV`, or `-sV --udp`

- **TLS / HTTP fingerprinting**
  - Certificate extraction: SANs, issuer, validity
  - HTTP title and asset fingerprinting
  - Handshake tracing and failure diagnosis
  - Optional mTLS

- **OS fingerprinting (`--os-detect`)**
  - Passive, from replies received

- **Enumeration modules (`--enum`)**
  - `shodan`
  - `ssl`
  - `dns`
  - `trail:<api-key>` (SecurityTrails)
  - Comma-separated, any order

- **Discovery module**
  - ASN/org lookup: `--cn`, `--org`
  - Country IP-range fetch: `--country`, `--owner`, `--ipv4`/`--ipv6`
  - Reverse IP/ASN to domains: `--ip`, `--range`, `--asn`

</details>

<details open>
<summary><strong>Performance & I/O</strong></summary>

<br>

- **`io_uring`-based async I/O**
  - Per-thread rings

- **SQPOLL mode**
  - Kernel-thread submission
  - Auto-enabled by probe volume (adaptive pacing)
  - Auto-enabled by estimated duration (fixed pacing)
  - Force with `--sqpoll`

- **Congestion-aware batching**
  - Adaptive rate/delay tuning
  - Flags: `--cong-curve`, `--cong-alpha-*`, `--rate-dyn-*`, `--batch-delay-dyn-*`

- **EWMA RTT estimation**
  - Retry logic
  - Flags: `--set-rtt`, `--rto-mult`, `--rto-pad1/2`

- **Version-detection reactor**
  - Sharded `epoll` workers, adaptive connect budget, per-stage deadlines

</details>

<details open>
<summary><strong>Networking & Isolation</strong></summary>

<br>

- **Network namespace isolation**
  - Flags: `--split`, `--split-ip`, `--split-gw`, `--split-ip6`, `--split-gw6`, `--split-mac`, `--split-iface`
  - Backed by macvlan

- **MAC spoofing and ARP-based on-link resolution**
  - `--src-mac` for spoofing
  - `--dst-mac` to skip ARP

- **TCP option crafting**
  - MSS, window scale, SACK, timestamps, NOPs
  - MPTCP, TCP-AO, TFO cookie injection
  - Custom sequence numbers

- **IP-layer control**
  - TTL, DSCP/TOS
  - IP ID generation modes
  - Fragmentation: `-f`, `--frag ofo|zof|lap`
  - Router Alert, IPSO

- **IPv6 extension headers**
  - Hop-by-Hop, Destination, Routing
  - AH, ESP, Flow Label
  - Extension-header chain manipulation
  - Early chain termination

- **Checksum manipulation**
  - Invalid checksums: `--badsum`
  - Partial invalid checksum patterns: `--prsum`

- **Ethernet / VLAN**
  - Single and double 802.1Q (QinQ) tagging
  - Custom EtherType
  - Multicast destination MAC
  - Padding

</details>

<details open>
<summary><strong>Robustness</strong></summary>

<br>

- **Signal handling**
  - SIGINT handling with safe shutdown

- **Resource safety**
  - RAII-based resource management

- **Output**
  - Structured output
  - Per-host packet-sent counters

- **Drop detection**
  - Three checkpoints
  - Buffer-pool exhaustion
  - SQ backpressure
  - `sendmsg()` rejection

- **Hostile-input hardening**
  - Regex backtracking limits, bounded response sizes, sanitized peer text,
    SSRF-guarded redirects

- **Target export**
  - `--grep` for a plain, copy-friendly target list

</details>

<details open>
<summary><strong>Server Mode</strong></summary>

<br>

- **`--server`**
  - Start Trinetra as a web console
  - Accessible over HTTPS
  - Multi device access
  - TLS handled automatically via `stunnel`
  - Configurable port: `--server-port`, default 8443
  - Generate number of server consoles: `--count 5`
  - Configurable auth token: `--server-token`

</details>

<details open>
<summary><strong>DNS</strong></summary>

<br>

- **Custom DNS servers**
  - IPv4/IPv6 via `--dns-servers`

- **DNS-over-TLS**
  - Via `--dns-servers-tls`
  - Port 853, certificate-verified

- **Reverse DNS**
  - PTR lookups

- **DNS enumeration**
  - Full enumeration via `--enum dns`

</details>

---

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| **Linux kernel** | **6.12** | Enforced by `setup.sh`; required for the `io_uring` feature set Trinetra uses |
| Architecture | x86_64 / aarch64 | Others may work but are untested |
| OS | Debian, Ubuntu, or Arch Linux | Auto-detected by `setup.sh` |
| Compiler | GCC or Clang with **C++20** | `build-essential` / `base-devel` |
| Build tools | `make`, `cmake`, `pkg-config`, `git` | |
| Privileges | `root` (sudo) | Raw sockets + namespace isolation |
| Capabilities (if not root) | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` | For raw sockets and `unshare(CLONE_NEWNET)` |

**Runtime libraries installed by the setup script:**

| Library | Source |
|---|---|
| [`liburing`](https://github.com/axboe/liburing) | Built from source |
| [`concurrentqueue`](https://github.com/cameron314/concurrentqueue) | Headers |
| `libcurl4-openssl-dev`, `libssl-dev` / `openssl` | Package manager |
| `nlohmann-json3-dev` | Package manager |
| `libpugixml-dev` | Package manager |
| `libpcre2-dev` | Package manager |
| `zlib1g-dev` | Package manager |
| `stunnel4` (Debian/Ubuntu) or `stunnel` (Arch) | Package manager |

> [!IMPORTANT]
> **Kernel 6.12 or newer is mandatory.** The installer will refuse to
> continue on older kernels.

---

## Quick Start

### Automated install (recommended)

The included `setup.sh` handles OS detection, kernel check, dependency
installation, `liburing` build, header installation, data-file
placement, and the final build + install.

```bash
git clone https://github.com/gh1m1reh4rd1k/trinetra.git
cd trinetra
sudo ./setup.sh
```

The script will:

1. Detect your distribution (Debian/Ubuntu or Arch).
2. Verify your kernel is **>= 6.12**.
3. Install system build dependencies.
4. Build and install `liburing` from source.
5. Install `concurrentqueue` headers.
6. Copy data files (MAC vendors, ports, signatures, cloud ranges) to
   the install prefix.
7. Build and `make install` the project.
8. Run a final verification pass.

### Manual build

If you already have all dependencies installed:

```bash
make -j"$(nproc)"
sudo make install
```

---

## Usage

> The examples below use the installed binary name. See
> [A note on naming](#a-note-on-naming) if your install uses a
> different name.

### Basic TCP scans

```bash
# Default SYN scan over a /24
sudo shiv 192.168.1.0/24 -p 1-1024

# Xmas scan on selected ports
sudo shiv 10.0.0.5 -p 80,443,8080 -sX

# Full 4-way handshake scan inside an isolated namespace
sudo shiv 10.0.0.5 -p 80,443 -G

# Scan inside an isolated namespace
sudo shiv --split 192.168.1.254 -p 443,22
```

### UDP scans

```bash
# UDP scan of selected ports, skipping host discovery
sudo shiv 10.0.0.1 -sU -Pn -p 53,123,161

# UDP scan using the default list of 1001 common UDP ports
sudo shiv 10.0.0.1 -sU -Pn

# Read ports from a file, one port per line
sudo shiv 10.0.0.1 -sU -Pn -p ports.txt

# UDP scan followed by service/version detection
sudo shiv 10.0.0.1 -sU -sV -p 53,123,161
```

### Service / version detection

```bash
# HTTP/TLS-aware version detection
sudo shiv example.com -p 1-10000 -sV

# Force HTTPS probe with strict TLS verification
sudo shiv example.com -p 443 -sV --force-https --tls-verify

# UDP service probing
sudo shiv 10.0.0.1 -p 53,123,161 -sV --udp
```

### Host discovery

```bash
# ICMP host discovery
sudo shiv -sn 192.168.1.0/24

# Discover, then only scan hosts that responded
sudo shiv -sn -sS -Pn 192.168.1.0/24
```

### Enumeration

```bash
# Shodan InternetDB + DNS enumeration on a domain
sudo shiv example.com --enum shodan,dns

# SecurityTrails subdomain lookup
sudo shiv example.com --enum trail:<api-key>
```

### Discovery (ASN / country / reverse IP)

```bash
# List ASNs and orgs for a country
sudo shiv --cn nepal

# Fetch all public IPv4 ranges for a country
sudo shiv --country nepal --ipv4 -o np.txt

# Reverse-lookup domains on an IP
sudo shiv --ip 103.48.88.33

# Routes announced by an ASN
sudo shiv --asn AS45353 --ipv6
```

### Passive discovery

```bash
# Watch the wire until Ctrl-C
sudo shiv --netradar

# Capture for 30 seconds on a specific interface
sudo shiv --netradar --time 30s --interface eth0
```

### Traceroute

```bash
sudo shiv 8.8.8.8 --traceroute

sudo shiv scanme.nmap.org --traceroute
```

### Server mode

```bash
# Start LAN control panel (prints a ready-to-use HTTPS link)
sudo shiv --server

# Custom port and fixed token
sudo shiv --server --server-port 9443 --server-token <token>
```

> For the full flag reference: pacing, IP/TCP header crafting, IPv6
> extension-header control, buffer management, debug modes, and more,
> see the [standard documentation](https://github.com/gh1m1reh4rd1k/trinetra/wiki/standard_documentation)
> or run `shiv --help`.

---

## Architecture (for contributors)

### Sending Packets
- TCP: `io_uring_prep_sendmsg()`
- ARP: `io_uring_prep_sendto()` for batched ARP requests
- Raw sockets: `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` for custom
  IP/TCP header crafting
- UDP: raw UDP sockets (not kernel UDP sockets), implemented mainly in a
  dedicated UDP scan module

### Receiving Packets
- Primary: `io_uring_prep_recvmsg()` for async reception
- Raw TCP socket: `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`
- ARP: `io_uring_prep_recvmsg()`
- Non-blocking sockets via `fcntl()` + `O_NONBLOCK`

### `io_uring` Configuration
- Separate send and receive rings (`io_uring_queue_init()`)
- `io_uring_wait_cqe_timeout()` for response timeouts
- Configurable queue depths (`--send-uring`, `--rcv-uring`)
- `IORING_SETUP_SQPOLL` with a non-SQPOLL fallback if kernel init
  fails

### Namespace Isolation
- `unshare(CLONE_NEWNET)` + macvlan device bridged off a physical
  interface (`--split*` family of flags)
- Keeps scanner traffic separate from host routing/stack
- `-G` (state-machine handshake) auto-enters the namespace

### Concurrency
- `moodycamel::ConcurrentQueue` for task queuing
- Per-thread `io_uring` rings for batch transmission
- `std::atomic` for coordination; `std::mutex` for output sync

### Buffer Management
- Custom `PacketBufferPool`
- Thread-local pools to reduce contention
- Concurrent queue for buffer reuse

### Version-detection pipeline

```
 ports (open)
     |
     v
 reachability pre-check ---- closed / filtered --> note + skip
     |
     v
 probe planning (NULL -> port-listed -> rarity-limited)
     |
     v
 sharded epoll reactor (TCP / TLS, adaptive deadlines)
     |
     v
 Stage 1: probe-file match (lazy regex, JIT, prefix filter, binproto)
     |
     v
 Stage 2: HTTP / TLS body signatures (titles, assets, platform, CDN)
     |
     v
 result + notes explaining any gaps
```

| File | Role |
|---|---|
| `async_io.cpp/.hpp` | Sharded `epoll` reactor: TCP/TLS operations, deadlines, cancellation, TLS tracing |
| `probe.cpp/.hpp` | Probe database parser, regex/template matching, `ProbeEngine` |
| `control.cpp` | Version-scan orchestration, reachability, TLS/HTTP capture, Stage 2 signatures |

---

## A note on naming

The CLI reference and `setup.sh` currently refer to the binary as
**`shiv`**, and the installer writes data files under
`/usr/share/shiv/`. The repository is named **Trinetra**. Until the
two are unified, use whichever name your build actually produces:
`shiv` in most builds today.

---

## Troubleshooting

| Symptom | Cause & Fix |
|---|---|
| **"Shiv's minimum requirement kernel version is 6.12"** | Your kernel is too old. Upgrade to 6.12+ and reboot. On Debian/Ubuntu, consider HWE or mainline kernels; on Arch, `linux` or `linux-lts` (current LTS is fine). |
| **"Missing source files: ..."** | `setup.sh` expects `mac-vendors.txt`, `ports.txt`, `signatures.conf`, `shiv_split.conf`, and the `ranges/*.txt` files in the repo root. Clone the full repository and run the script from the project root. |
| **"This script requires sudo privileges"** | Run with `sudo ./setup.sh`. For manual runs, either be root or grant the binary `CAP_NET_RAW` / `CAP_NET_ADMIN` / `CAP_SYS_ADMIN`. |
| **`--handshake` / `--isolate` / `--version` are unknown flags** | Those aren't real flags. Use `-G` for state-machine handshake, `--split` for namespace isolation, and `-sV` for version detection. |
| **A TLS port shows no version info** | Run with verbose output: the handshake trace names the alert, cipher and certificate seen, which usually explains the failure. |

---

## Contributing

Issues and pull requests are welcome. Please open an issue before
starting work on significant changes.

## Acknowledgments

- The `io_uring` and `liburing` teams
- The Nmap project (probe-file format and match semantics used in Stage 1)
- [`moodycamel::ConcurrentQueue`](https://github.com/cameron314/concurrentqueue)
- SecurityTrails and Shodan InternetDB APIs
