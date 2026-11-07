#include "simulations.hpp"
#include "dns_enum.hpp"

#include <unordered_set>
#include <cctype>

namespace simulations {

bool is_wildcard_target_spec(const std::string& token, std::string& out_domain) {
    // Must start with exactly "*."
    if (token.size() < 4) return false;           // "*.a.b" minimum-ish
    if (token[0] != '*' || token[1] != '.') return false;

    std::string domain = token.substr(2);
    if (domain.empty()) return false;

    // Not a general glob -- only the single leading "*." is recognized.
    if (domain.find('*') != std::string::npos) return false;

    // Must look like an actual domain: at least one further '.', and
    // only sane hostname characters.
    if (domain.find('.') == std::string::npos) return false;

    for (unsigned char c : domain) {
        bool ok = std::isalnum(c) || c == '-' || c == '.';
        if (!ok) return false;
    }
    if (domain.front() == '.' || domain.back() == '.' || domain.back() == '-')
        return false;

    out_domain = std::move(domain);
    return true;
}

SimulationResult run_wildcard_enum_simulation(const std::string& base_domain,
                                               int timeout_ms,
                                               int retries,
                                               int resolve_concurrency,
                                               bool use_edns0,
                                               bool verbose) {
    SimulationResult sim;
    sim.base_domain = base_domain;

    if (base_domain.empty()) {
        sim.error = "empty base domain";
        return sim;
    }

    // Configure the shared dns_enum engine to focus purely on discovery +
    // resolution -- the posture/security-finding features it also does
    // (DNSSEC, SRV, TLSA, takeovers, dorking, ASN lookups...) aren't what
    // this simulation is for, so skip them to keep the run fast.
    DnsEnumOptions opts;
    opts.enabled            = true;
    opts.do_active          = true;
    opts.do_passive         = true;
    opts.timeout_ms         = timeout_ms;
    opts.retries            = retries;
    opts.active_concurrency = resolve_concurrency;
    opts.brute_concurrency  = resolve_concurrency;
    opts.use_edns0          = use_edns0;
    opts.verbose            = verbose;

    opts.query_srv          = false;
    opts.query_tlsa         = false;
    opts.query_sshfp        = false;
    opts.query_email_crypto = false;
    opts.check_takeovers    = false;
    opts.nsec_walk          = false;
    opts.query_asn          = false;
    opts.query_bgp_siblings = false;
    opts.query_ripestat     = false;
    opts.google_dork        = false;
    opts.ptr_sweep_self     = false;
    opts.ptr_sweep_prefix   = false;

    opts.run_stage2         = true;
    opts.stage2_timeout_ms  = timeout_ms * 3;

    DnsEnumResult result;
    try {
        result = run_dns_enum_two_stage(base_domain, opts);
    } catch (const std::exception& e) {
        sim.error = std::string("dns enum failed: ") + e.what();
        return sim;
    }

    std::unordered_set<std::string> ip_seen;
    sim.unique_ips.reserve(result.hosts.size() * 2);
    sim.resolved_hosts.reserve(result.hosts.size());

    for (const auto& [hostname, host] : result.hosts) {
        if (host.wildcard_suspect) continue;   // skip catch-all DNS noise

        SimHostResolution entry;
        entry.hostname = hostname;

        if (host.ips.empty()) {
            sim.unresolved_hosts.push_back(hostname);
        } else {
            entry.ips.assign(host.ips.begin(), host.ips.end());
            for (const auto& ip : host.ips) {
                if (ip_seen.insert(ip).second) {
                    sim.unique_ips.push_back(ip);
                }
            }
        }

        sim.resolved_hosts.push_back(std::move(entry));
    }

    // Belt-and-suspenders: pick up any stage2 hostname that for some
    // reason wasn't folded into result.hosts, so nothing discovered gets
    // silently dropped from the simulation.
    for (const auto& hostname : result.stage2.hostnames) {
        if (result.hosts.find(hostname) != result.hosts.end()) continue;

        SimHostResolution entry;
        entry.hostname = hostname;

        auto it = result.stage2.host_ips.find(hostname);
        if (it != result.stage2.host_ips.end() && !it->second.empty()) {
            entry.ips.assign(it->second.begin(), it->second.end());
            for (const auto& ip : it->second) {
                if (ip_seen.insert(ip).second) {
                    sim.unique_ips.push_back(ip);
                }
            }
        } else {
            sim.unresolved_hosts.push_back(hostname);
        }

        sim.resolved_hosts.push_back(std::move(entry));
    }

    sim.total_hosts_discovered = sim.resolved_hosts.size();

    if (sim.unique_ips.empty()) {
        sim.error = "no resolvable hosts found under *." + base_domain;
        return sim;   // ok stays false
    }

    sim.ok = true;
    return sim;
}

} // namespace simulations
