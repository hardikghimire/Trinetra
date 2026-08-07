# Project-shiva <img src="https://github.com/GhimireHardik/project-shiva/blob/main/images/shiv.gif" width="130" height="130" align="center" />


<img src="https://github.com/HardikGhimire1/shiva/blob/main/images/uring.jpg" />


**Warning**: This scanner uses raw packet manipulation and may crash or destabilize target TCP/IP stacks. Use with caution.

- **Usage Scope**: Strictly for educational purposes, home labs, or authorized testing environments only.
- **Reverse Approach**: Focuses on implementation first, then learning concepts by analyzing real packet behavior.
- **Low-Level Control**: Provides advanced raw packet access and customization.
- **Goal**: Help users understand networking internals, protocols, and system behavior through hands-on experiments.

## Sending Packets

- **Method**: TCP sending goes through `io_uring_prep_sendmsg()`.
- **For ARP**: uses `io_uring_prep_sendto()` for batch ARP requests.
- **Raw Sockets**: Created with `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` to craft custom IP/TCP headers.

## Receiving Packets

- **Primary Method**: uses `io_uring_prep_recvmsg()` for async reception.
- **Raw Socket**: Created with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` to receive TCP responses.
- **For ARP**: `io_uring_prep_recvmsg()` for ARP response reception.
- **Non-blocking I/O**: Sockets are set to non-blocking mode using `fcntl()` with `O_NONBLOCK`.

## Processing & Architecture

- **Async I/O via io_uring**:
  - Send rings: `io_uring_queue_init()` for batch sending
  - Receive rings: `io_uring_queue_init()` for batch receiving
  - Timeouts: `io_uring_wait_cqe_timeout()` for response timeout handling
  - Queue depths configurable via CLI flags
- **SQPOLL mode**: `IORING_SETUP_SQPOLL` can be force-enabled, or is auto-enabled via a hybrid check — with adaptive/dynamic pacing (the default), once probe volume (hosts × ports) crosses a configurable threshold (default 300000); with fixed/non-dynamic pacing, once the estimated scan duration reaches 8s. A single host's max volume (65535, full port range) never crosses the default threshold on its own. Runs submission on a dedicated kernel thread to cut down on `io_uring_enter` syscalls, with a fallback to non-SQPOLL rings if kernel init fails.

## Namespace Isolation

- **Isolation mode**: Runs the scan entirely inside an isolated network namespace (`unshare(CLONE_NEWNET)`) bridged off a physical interface via a macvlan device — keeps the scanner's traffic separated from the host's normal network stack/routing.
  - Configurable via command-line or a config file, and needs root / `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`.
- **State machine scan (handshake mode)**: Performs a real 4-way TCP handshake with graceful connection teardown, and automatically runs inside the same isolated namespace as the isolation mode — selecting handshake-mode alone is enough to trigger namespace entry.

## Version Detection

Dual-staged: nmap's probe-signature database (`ServiceProbe`/`AllProbes`, `ServiceProbeMatch` regex engine) drives probe selection/matching as stage one, then a dynamic response-body signature layer (`HttpFingerprint`, `PlatformSignatureSet` — title, asset paths, platform/CDN signature rules) fingerprints the actual response content as stage two. Results from both stages are merged for the final service/version output, with fallback probes and CPE/version-string extraction throughout.

## Concurrent Processing

- `moodycamel::ConcurrentQueue` for packet task queuing
- Per-thread async I/O rings (io_uring) for batch packet transmission
- `std::atomic` flags for thread coordination (`terminate_flag`)
- `std::mutex` for output synchronization (`cout_mutex`)

## Buffer Management

- Custom `PacketBufferPool` for memory pooling
- Thread-local buffer pools to reduce contention
- Concurrent queue for buffer reuse

# Features

## Core Scanning
- Smart EWMA RTT: adaptive RTT estimation with retry logic for accurate timing.
- State machine scan: full 4-way TCP handshake with graceful teardown; namespace-isolated when requested.
- Multiple scan types: SYN (default), NULL, ACK, FIN, Xmas, Maimon, Window, and other custom TCP-flag combinations; dedicated UDP and host-discovery modes.

## Probing & Fingerprinting
- Version detection: dual-stage approach — Nmap-style probe DB for selection/matching, plus dynamic response-body signatures (titles/assets/platform fingerprints).
- TLS / HTTP fingerprinting: certificate extraction (SANs, issuer, validity) and HTTP response/title/asset fingerprinting for platform identification.

## Performance & I/O
- SQPOLL: kernel-thread io_uring submission — auto-enabled based on probe volume (adaptive pacing) or estimated duration (fixed pacing), or can be forced; multi-host scans typically needed to trigger it by default.
- Congestion-aware batching: adaptive rate and batch-delay tuning for dynamic pacing.

## Networking & Isolation
- Namespace isolation: run scans inside an isolated network namespace/macvlan.
- Traceroute: traceroute support for IPv4 and IPv6 (`run_traceroute` / `run_traceroute6`).

## DNS
- Custom DNS servers: support for multiple custom DNS servers (IPv4 or IPv6).
- DNS-over-TLS: DoT lookups on port 853 with certificate verification.
- Reverse DNS / PTR lookups using either system resolver or configured custom DoT servers.

## Packet & Link-layer Control
- MAC / ARP control: ability to spoof MAC addresses and perform ARP-based on-link resolution.
- TCP option crafting: MSS, window scale, SACK, timestamps, TCP Fast Open cookie injection, and other TCP option manipulations.
- Checksum manipulation: advanced invalid-checksum patterns and bit-level manipulation for stack testing.
- Raw access: full raw packet crafting and experimentation support for educational/testing use.

## Robustness & Usability
- SIGINT handling: emergency protocol activation and safe shutdown to prevent crashes on interrupt.
- RAII: resource management via RAII for exception-safe cleanup.
- Output: modern, structured scan output formatting.

## Misc / Integrations
- TCP flags: explicit handling for ECE and CWR flags.
- Public databases: enrichment via SecurityTrails and Shodan InternetDB.
