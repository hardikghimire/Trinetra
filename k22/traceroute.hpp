#ifndef TRACEROUTE_HPP
#define TRACEROUTE_HPP

// ─────────────────────────────────────────────────────────────────────────
// Shiv --traceroute
//
// Deliberately reuses, rather than reimplements, the project's existing
// raw-ICMP primitives:
//   - icmp_detail::RawSocket   (icmp_ping.hpp) — same RAII raw ICMP socket
//   - icmp_detail::icmp_checksum (icmp_ping.hpp) — same RFC 792 checksum
//   - reverse_dns_lookup / ptr_cache_lookup / ptr_cache_store (utils.hpp)
//     — same shared PTR cache already used by control.cpp
//   - WriteCallback (utils.hpp) — same libcurl sink already declared for
//     the project's other HTTP calls
//
// What's genuinely new is the per-hop send/wait control loop itself:
// icmp_ping_sweep()/tcp_syn_probe_sweep() are built to fire at MANY hosts
// concurrently via io_uring and collect whichever answers land in a shared
// window. Traceroute is the opposite access pattern — one target, TTL
// incremented one hop at a time, each hop's probes waited on before moving
// to the next — so it cannot reuse their io_uring batch/CQE machinery
// without fighting its design. It reuses everything below that layer
// instead (socket, checksum, DNS cache, HTTP sink).
// ─────────────────────────────────────────────────────────────────────────

#include <string>
#include <vector>
#include <cstdint>

// One MPLS label-stack entry, decoded from an RFC 4950 ICMP extension
// object when the responding hop includes one (MPLS-aware routers only —
// most hops will simply have an empty mpls_labels vector).
struct MplsLabelEntry {
    uint32_t label = 0;   // 20-bit MPLS label value
    uint8_t  exp    = 0;  // 3-bit Traffic Class / EXP (CoS)
    uint8_t  bos    = 0;  // bottom-of-stack flag
    uint8_t  ttl    = 0;  // MPLS shim TTL
};

// AS / ISP / geolocation info for one hop's IP, resolved via an HTTP
// geo-IP lookup (best effort — private/reserved hops will simply come
// back with resolved == false).
struct GeoIspInfo {
    bool        resolved = false;
    std::string asn;       // e.g. "AS15169 Google LLC"
    std::string isp;
    std::string org;
    std::string country;
    std::string region;
    std::string city;
    double      lat = 0.0;
    double      lon = 0.0;
};

struct TracerouteProbe {
    bool   responded = false;
    double rtt_ms     = 0.0;
};

struct TracerouteHop {
    int                          ttl = 0;
    std::string                  ip;         // empty = every probe at this ttl timed out
    std::string                  hostname;   // reverse-DNS name, empty if unresolved/disabled
    std::vector<TracerouteProbe> probes;      // one entry per probe sent at this ttl
    std::vector<MplsLabelEntry>  mpls_labels; // empty if hop didn't include RFC 4950 extensions
    GeoIspInfo                   geo;
    bool                         is_destination = false;
    bool                         unreachable    = false; // hop answered with Dest Unreachable
};

struct TracerouteOptions {
    int  max_hops       = 30;
    int  probes_per_hop = 3;
    int  timeout_ms      = 1000;   // per-probe wait
    bool resolve_dns     = true;   // reverse DNS per hop (uses utils.hpp's shared PTR cache)
    bool resolve_geoip    = true;  // AS / ISP / geolocation lookup per hop
    std::string interface;         // reserved: source-interface binding, unused for now
};

// Runs a classic UDP/ICMP-style TTL-incrementing traceroute over ICMPv4
// echo probes. Blocks until the destination replies, every hop up to
// max_hops has been probed, or a Destination-Unreachable is received.
std::vector<TracerouteHop> run_traceroute(const std::string& target_ip,
                                           const TracerouteOptions& opts);

// IPv6 counterpart — ICMPv6 echo probes + IPV6_UNICAST_HOPS instead of
// IP_TTL, ICMPV6 Time Exceeded instead of ICMP Time Exceeded. Same
// per-hop control flow and the same MPLS/geo/DNS enrichment.
std::vector<TracerouteHop> run_traceroute6(const std::string& target_ip6,
                                            const TracerouteOptions& opts);

// Pretty-prints a completed traceroute (RTTs, resolved name + IP, MPLS
// label/EXP if present, AS/ISP/geo if present), styled to match the rest
// of Shiv's CLI output.
void print_traceroute_results(const std::string& target_display,
                               const std::vector<TracerouteHop>& hops,
                               int max_hops_requested);

#endif // TRACEROUTE_HPP
