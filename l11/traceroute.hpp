#ifndef TRACEROUTE_HPP
#define TRACEROUTE_HPP


#include <string>
#include <vector>
#include <cstdint>

struct MplsLabelEntry {
    uint32_t label = 0;   // 20-bit MPLS label value
    uint8_t  exp    = 0;  // 3-bit Traffic Class / EXP (CoS)
    uint8_t  bos    = 0;  // bottom-of-stack flag
    uint8_t  ttl    = 0;  // MPLS shim TTL
};

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

std::vector<TracerouteHop> run_traceroute(const std::string& target_ip,
                                           const TracerouteOptions& opts);
std::vector<TracerouteHop> run_traceroute6(const std::string& target_ip6,
                                            const TracerouteOptions& opts);
void print_traceroute_results(const std::string& target_display,
                               const std::vector<TracerouteHop>& hops,
                               int max_hops_requested);

#endif
