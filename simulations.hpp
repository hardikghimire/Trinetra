#pragma once

#include <string>
#include <vector>
#include <cstddef>

// simulations.hpp / simulations.cpp
//
// Home for "target-spec simulations" -- features that are triggered by the
// *shape of the target argument itself* rather than by an explicit flag
// like --enum. The first one here: "*.domain.tld" as a target means
// "auto-discover every subdomain, resolve each to IP(s), collapse to the
// unique IP set, and scan that." More simulations can be added to this
// file/namespace later without touching handler.cpp's core parse loop
// again -- handler.cpp just needs to route new patterns here.

namespace simulations {

// One discovered hostname and whatever it resolved to.
struct SimHostResolution {
    std::string hostname;
    std::vector<std::string> ips;   // empty if discovered but unresolved
};

struct SimulationResult {
    bool ok = false;
    std::string error;              // populated when ok == false

    std::string base_domain;        // "nmap.org" extracted from "*.nmap.org"

    // Every subdomain discovered by the underlying DNS-enum engine.
    std::vector<SimHostResolution> resolved_hosts;

    // Discovered but never resolved to any A/AAAA (passive-only hit,
    // NXDOMAIN, timeout, etc) -- kept for reporting, not scanned.
    std::vector<std::string> unresolved_hosts;

    // The actual point of the feature: dedup(all resolved IPs), in
    // first-seen order. This is what gets handed to the scan engine.
    std::vector<std::string> unique_ips;

    size_t total_hosts_discovered = 0;
};

// Recognizes a wildcard target spec such as "*.nmap.org". On success,
// writes the bare domain ("nmap.org") to out_domain and returns true.
// Deliberately narrow -- exactly one leading "*.", a real-looking domain
// after it, no embedded '*' -- this is a trigger pattern, not a glob
// matcher, so it never misfires on a literal hostname.
bool is_wildcard_target_spec(const std::string& token, std::string& out_domain);

// Runs the "auto enum + smart simulation": discover subdomains of
// base_domain, resolve every one to IP(s), and collapse the result down
// to the unique IP set that should actually be scanned.
//
// Reuses the existing dns_enum.cpp engine (active brute force + AXFR +
// passive sources + stage2) instead of reimplementing discovery -- this
// is purely an orchestration/aggregation layer on top of it.
SimulationResult run_wildcard_enum_simulation(const std::string& base_domain,
                                               int timeout_ms = 3000,
                                               int retries = 2,
                                               int resolve_concurrency = 300,
                                               bool use_edns0 = true,
                                               bool verbose = false);

} // namespace simulations
