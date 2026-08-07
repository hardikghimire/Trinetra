#pragma once
//
// dns_enum.hpp — Project Shiva DNS enumeration subsystem (--dns-enum)
//
// Combines:
//   ACTIVE  : direct queries against authoritative/recursive resolvers —
//             full record-type sweep, zone transfer (AXFR) attempts,
//             wildcard-aware subdomain brute force, DNSSEC presence,
//             email-security record collection (SPF/DKIM/DMARC/BIMI/
//             MTA-STS/TLS-RPT), reverse PTR sweep.
//   PASSIVE : no packets sent to the target's nameservers at all — pulls
//             from third-party datasets (crt.sh CT logs, Wayback Machine
//             CDX index, RDAP for WHOIS, Team Cymru for ASN/BGP) to widen
//             the subdomain/infra picture beyond what active probing can
//             safely or legally reach (historical data, offline assets).
//
// Reuses shiv's existing primitives: raw UDP/TCP sockets + io_uring
// (see handler.cpp / scan.cpp), libcurl + nlohmann::json (already linked
// in scan.cpp) for passive HTTP(S) lookups, and the g_dns_servers /
// g_dns_tls_servers globals from handler.hpp so --dns-servers /
// --dns-servers-tls transparently apply to --dns-enum as well.
//
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <optional>
#include <chrono>

// ---------------------------------------------------------------------
// Record model
// ---------------------------------------------------------------------

enum class DnsRRType : uint16_t {
    A      = 1,
    NS     = 2,
    CNAME  = 5,
    SOA    = 6,
    PTR    = 12,
    MX     = 15,
    TXT    = 16,
    AAAA   = 28,
    SRV    = 33,
    NAPTR  = 35,
    DS     = 43,
    RRSIG  = 46,
    NSEC   = 47,
    DNSKEY = 48,
    CAA    = 257,
    AXFR   = 252,
    ANY    = 255,
};

const char* dns_rrtype_name(DnsRRType t);

struct DnsRecord {
    DnsRRType   type{};
    std::string name;     // owner name as returned by the server
    std::string value;    // decoded/rendered RDATA (human readable)
    uint32_t    ttl = 0;
    std::string source;   // "active:<server>", "axfr:<ns>", "passive:crt.sh", ...
};

// Where a discovered hostname came from — lets the report explain *why*
// something is in scope without re-deriving it.
enum class DiscoverySource {
    ActiveBruteForce,
    ActiveZoneTransfer,
    ActiveRecordChain,   // found while resolving MX/NS/SRV/CNAME targets etc.
    PassiveCertLog,
    PassiveWayback,
    PassiveRdap,
};

struct DiscoveredHost {
    std::string hostname;
    std::unordered_set<std::string> ips;   // resolved A/AAAA, may be empty (passive-only hit)
    std::unordered_set<DiscoverySource> sources;
    bool wildcard_suspect = false;         // resolves identically to the wildcard probe
};

struct EmailSecurityPosture {
    bool has_spf = false;              std::string spf_record;
    bool has_dmarc = false;            std::string dmarc_record;
    bool has_bimi = false;             std::string bimi_record;
    bool has_mta_sts_dns = false;      std::string mta_sts_dns_record;
    bool has_mta_sts_policy = false;   std::string mta_sts_policy_body;   // fetched over HTTPS
    bool has_tls_rpt = false;          std::string tls_rpt_record;
    std::vector<std::pair<std::string,std::string>> dkim_selectors_found; // selector -> record
    std::vector<std::string> mx_hosts;
};

struct DnssecPosture {
    bool dnskey_present = false;
    bool ds_present_at_parent = false;   // best-effort; requires parent-zone query
    bool rrsig_seen = false;             // any RRSIG observed while walking apex records
    int  dnskey_count = 0;
};

struct WhoisRdapInfo {
    bool found = false;
    std::string registrar;
    std::string created;
    std::string updated;
    std::string expires;
    std::vector<std::string> statuses;
    std::vector<std::string> nameservers;
    std::string raw_source_url;
};

struct AsnInfo {
    std::string ip;
    std::string asn;
    std::string as_name;
    std::string prefix;
    std::string country;
    std::string registry;
    std::string allocated;
};

struct ZoneTransferAttempt {
    std::string ns_host;
    std::string ns_ip;
    bool succeeded = false;
    size_t records_pulled = 0;
    std::string error; // populated when !succeeded
};

struct DnsEnumResult {
    std::string domain;

    // Raw records collected from apex + well-known lookups.
    std::vector<DnsRecord> records;

    // Merged subdomain view (brute force + AXFR + passive), deduplicated.
    std::unordered_map<std::string, DiscoveredHost> hosts;

    std::vector<ZoneTransferAttempt> axfr_attempts;
    EmailSecurityPosture mail_security;
    DnssecPosture dnssec;

    // Passive-only enrichment.
    WhoisRdapInfo domain_whois;
    std::vector<AsnInfo> asn_lookups;               // one per unique resolved IP
    std::vector<std::string> wayback_urls_sample;    // capped sample, not the full dump

    bool wildcard_dns = false;
    std::string wildcard_ip_sample;

    std::chrono::milliseconds active_duration{0};
    std::chrono::milliseconds passive_duration{0};
};

// ---------------------------------------------------------------------
// Options — mirrors the sv_* (version-detection) option block style
// already used in main.cpp's Config struct.
// ---------------------------------------------------------------------

struct DnsEnumOptions {
    bool enabled       = false;
    bool do_active      = true;
    bool do_passive     = true;

    // Active tuning
    int  timeout_ms          = 2000;
    int  retries              = 2;
    int  brute_concurrency    = 200;   // in-flight UDP queries during brute force
    bool attempt_axfr         = true;
    bool skip_wildcard_filter = false; // if true, report wildcard-matching hits anyway
    std::string wordlist_file;         // optional; falls back to built-in list

    // Email-security / DKIM selector tuning
    std::vector<std::string> extra_dkim_selectors;

    // Passive tuning
    int  passive_timeout_ms   = 6000;
    bool query_crtsh          = true;
    bool query_wayback        = true;
    bool query_rdap           = true;
    bool query_asn            = true;
    size_t wayback_sample_cap = 50;

    // Output
    bool verbose      = false;
    std::string save_json_file; // empty = don't save
};

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

// Runs whichever of active/passive is enabled in `opts` and returns the
// merged result. Honors g_dns_servers / g_dns_tls_servers (handler.hpp)
// for the active phase when the user supplied --dns-servers[-tls].
DnsEnumResult run_dns_enum(const std::string& domain, const DnsEnumOptions& opts);

// Pretty, colorized console report (uses the same color:: palette as the
// rest of shiv's output).
void print_dns_enum_result(const DnsEnumResult& result, const DnsEnumOptions& opts);

// Writes the full result (including the uncapped host map) as JSON.
bool save_dns_enum_result(const DnsEnumResult& result, const std::string& path);

// Exposed individually so other subsystems (e.g. version-detection) can
// reuse a single generic query instead of the old A/AAAA/PTR-only helpers
// in handler.cpp.
bool dns_query_generic(const std::string& qname, DnsRRType qtype,
                        const std::vector<std::string>& servers,
                        int timeout_ms, int retries,
                        std::vector<DnsRecord>& out_records,
                        std::string* used_server = nullptr);
