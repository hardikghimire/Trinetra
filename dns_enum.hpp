#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <optional>
#include <chrono>
#include <openssl/evp.h>


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
    TLSA   = 52,
    NSEC3  = 50,
    OPT    = 41,
    HINFO      = 13,
    DNAME      = 39,
    SSHFP      = 44,
    NSEC3PARAM = 51,
    SMIMEA     = 53,
    CDS        = 59,
    CDNSKEY    = 60,
    OPENPGPKEY = 61,
    SVCB       = 64,
    HTTPS      = 65,
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
    ActiveMutatedBruteForce,   // hit came from a generated permutation, not the raw wordlist
    ActiveZoneTransfer,
    ActiveRecordChain,   // found while resolving MX/NS/SRV/CNAME targets etc.
    ActiveSrv,
    ActivePtrSweep,
    ActiveNsecWalk,
    PassiveCertLog,       // crt.sh
    PassiveCertspotter,
    PassiveWayback,
    PassiveRdap,
    PassiveHackertarget,
    PassiveRapidDns,
    PassiveOtx,            // AlienVault OTX passive DNS
    PassiveUrlscan,
    PassiveDork,           // Google Custom Search JSON API — hit URL/snippet parsed for hosts
    PassiveRipestat,       // RIPEstat network-info — secondary ASN/prefix source, fills Cymru gaps

    // ---- Stage 2 sources (see Stage2SubdomainResult below) ----
    PassiveThcIp,           // ip.thc.org/sb/<domain>
    PassiveSubdomainCenter, // api.subdomain.center
    PassiveDomainee,        // api.domainee.dev
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
    bool nsec3param_present = false;     // zone uses NSEC3 (hash params visible)
    bool cds_present = false;            // child publishing rollover DS
    bool cdnskey_present = false;        // child publishing rollover DNSKEY
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
    std::string source = "cymru";   // "cymru" | "ripestat" (which source resolved this IP)
};

struct ZoneTransferAttempt {
    std::string ns_host;
    std::string ns_ip;
    bool succeeded = false;
    size_t records_pulled = 0;
    std::string error; // populated when !succeeded
};

struct TakeoverFinding {
    std::string hostname;
    std::vector<std::string> cname_chain;   // hostname -> ... -> final target
    std::string matched_service;            // "AWS S3", "GitHub Pages", ...
    bool http_confirmed = false;            // fingerprint string seen in response body
    std::string fingerprint_snippet;        // the matched signature text
};

struct SrvFinding {
    std::string service;    // "_ldap._tcp", "_sip._tcp", ...
    std::string target;
    uint16_t port = 0;
    uint16_t priority = 0;
    uint16_t weight = 0;
};

struct TlsaFinding {
    std::string service;    // "_443._tcp", "_25._tcp", ...
    uint8_t cert_usage = 0;
    uint8_t selector = 0;
    uint8_t matching_type = 0;
    std::string data_hex;
};

struct SshfpFinding {
    uint8_t algorithm = 0;      // 1=RSA 2=DSA 3=ECDSA 4=Ed25519
    uint8_t fp_type = 0;        // 1=SHA-1 2=SHA-256
    std::string fingerprint_hex;
};

struct NsecWalkResult {
    bool attempted = false;
    bool zone_signed = false;      // NSEC actually observed
    bool wrapped = false;          // walk completed a full loop of the zone
    std::vector<std::string> names_from_bitmap_gaps; // owner names discovered via chain
    std::string note;
};

struct PtrSweepResult {
    bool attempted = false;
    std::string prefix_swept;      // e.g. "203.0.113.0/24"
    size_t hosts_checked = 0;
    std::vector<std::pair<std::string,std::string>> ptrs; // ip -> ptr name
};

struct DorkHit {
    std::string query;
    std::string title;
    std::string url;
    std::string snippet;
};

struct DorkQueryStatus {
    std::string query;
    long http_status = 0;
    bool blocked = false;          // 429 / 403 / quota-exceeded / CAPTCHA-shaped body
    std::string block_reason;
    size_t result_count = 0;
};

struct PassiveSourceStatus {
    std::string source_name;
    bool ok = false;
    bool rate_limited = false;
    std::string detail;
    size_t items_found = 0;
};

struct BgpSiblingPrefix {
    std::string asn;
    std::string prefix;
    std::string description;
};

struct Stage2SourceStatus {
    std::string source_name;   // "thc.org" | "subdomain.center" | "domainee.dev"
    bool ok = false;
    std::string detail;        // "ok", or error/http-status text on failure
    size_t items_found = 0;    // new in-scope hostnames contributed by this source
};

struct Stage2SubdomainResult {
    bool attempted = false;
    std::vector<std::string> hostnames;              // unique, in-scope, normalized, sorted
    std::unordered_map<std::string, std::unordered_set<std::string>> host_ips; // hostname -> resolved A/AAAA
    std::vector<std::string> unresolved;              // no authoritative answer at all (timeout/unreachable)
    std::vector<Stage2SourceStatus> source_status;
    std::chrono::milliseconds duration{0};            // source-fetch phase
    std::chrono::milliseconds resolve_duration{0};    // A/AAAA resolution phase (vectorized, like stage 1)
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
    NsecWalkResult nsec_walk;

    std::vector<SrvFinding> srv_findings;
    std::vector<TlsaFinding> tlsa_findings;
    std::vector<SshfpFinding> sshfp_findings;  
    std::vector<TakeoverFinding> takeover_findings;
    PtrSweepResult ptr_sweep;

    // Passive-only enrichment.
    WhoisRdapInfo domain_whois;
    std::vector<AsnInfo> asn_lookups;                // one per unique resolved IP
    std::vector<BgpSiblingPrefix> sibling_prefixes;   // same-ASN prefixes, for wider PTR sweeps
    std::vector<std::string> wayback_urls_sample;     // capped sample, not the full dump
    std::vector<DorkHit> dork_hits;
    std::vector<DorkQueryStatus> dork_query_status;
    std::vector<PassiveSourceStatus> passive_source_status;

    bool wildcard_dns = false;
    std::string wildcard_ip_sample;

    std::chrono::milliseconds active_duration{0};
    std::chrono::milliseconds passive_duration{0};

    // Populated only when the stage-2 pass (see below) was run.
    Stage2SubdomainResult stage2;
};

struct DnsEnumOptions {
    bool enabled       = false;
    bool do_active      = true;
    bool do_passive     = true;

    // Active tuning
    int  timeout_ms          = 2000;
    int  retries              = 2;
    int  brute_concurrency    = 200;   // in-flight UDP queries during brute force
    int  active_concurrency   = 300;   // in-flight UDP queries for the shared async
                                        // engine (apex sweep / DNSSEC / DKIM / SRV / TLSA
                                        // / AXFR-NS resolution / PTR sweep all share this)
    bool attempt_axfr         = true;
    bool skip_wildcard_filter = false; // if true, report wildcard-matching hits anyway
    std::string wordlist_file;         // optional; falls back to built-in list
    bool use_edns0            = true;  // advertise a 4096B UDP payload to cut TCP fallbacks

    bool   mutate_wordlist       = true;
    size_t mutation_max_candidates = 2000; // hard cap so this can't blow up on a big result set
    bool   prefer_dork_for_subdomains = false;

    // Email-security / DKIM selector tuning
    std::vector<std::string> extra_dkim_selectors;

    // SRV / TLSA / takeover / DNSSEC-walk tuning
    bool query_srv   = true;
    bool query_tlsa  = true;
    bool query_sshfp = true;
    bool query_email_crypto = true;               // OPENPGPKEY + SMIMEA lookups
    std::vector<std::string> extra_email_locals; 
    std::vector<int> tlsa_ports = {443, 25};
    bool check_takeovers = true;
    bool nsec_walk = true;
    int  nsec_walk_max_steps = 200;

    // Reverse PTR
    bool   ptr_sweep_self  = true;   // PTR every IP already discovered
    bool   ptr_sweep_prefix = false; // opt-in: also sweep the whole /24 (v4) each discovered
                                      // IP sits in, and any sibling ASN prefixes found
    size_t ptr_sweep_max_hosts = 256;

    // Passive tuning
    int    passive_timeout_ms = 6000;
    int    passive_concurrency = 8;  // concurrent curl handles for the HTTP-based sources
    bool   query_crtsh        = true;
    bool   query_certspotter  = true;
    bool   query_wayback      = true;
    bool   query_rdap         = true;
    bool   query_asn          = true;
    bool   query_ripestat     = true;   // secondary ASN/prefix source (stat.ripe.net); no key needed —
                                          // fills IPs Cymru bulk whois missed and enriches AS holder names
    bool   query_bgp_siblings = true;
    bool   query_hackertarget = true;
    bool   query_rapiddns     = true;
    bool   query_otx          = true;
    bool   query_urlscan      = true;
    size_t wayback_sample_cap = 50;
    bool        google_dork = false;
    std::string google_api_key;
    std::string google_cx;
    std::vector<std::string> extra_dork_templates; // "{domain}" gets substituted
    int         dork_results_per_query = 10;
    int         dork_max_queries_per_run = 12;      // safety cap on API quota burn

    bool        dork_discover_subdomains = true;

    bool run_stage2          = true;
    int  stage2_timeout_ms   = 10000;

    // Output
    bool verbose      = false;
    std::string save_json_file; // empty = don't save
};

DnsEnumResult run_dns_enum(const std::string& domain, const DnsEnumOptions& opts);
void print_dns_enum_result(const DnsEnumResult& result, const DnsEnumOptions& opts);
bool save_dns_enum_result(const DnsEnumResult& result, const std::string& path);

Stage2SubdomainResult run_stage2_subdomain_enum(const std::string& domain, int timeout_ms,
                                                 std::unordered_map<std::string, DiscoveredHost>* merge_into = nullptr,
                                                 int resolve_concurrency = 300,
                                                 bool use_edns0 = true,
                                                 int retries = 2);


void print_stage2_subdomain_result(const Stage2SubdomainResult& result, bool show_subdomain_list = true);

DnsEnumResult run_dns_enum_two_stage(const std::string& domain, const DnsEnumOptions& opts);

bool dns_query_generic(const std::string& qname, DnsRRType qtype,
                        const std::vector<std::string>& servers,
                        int timeout_ms, int retries,
                        std::vector<DnsRecord>& out_records,
                        std::string* used_server = nullptr);

struct AsyncDnsJob {
    std::string qname;
    DnsRRType   qtype;
    std::string tag;   // caller-defined, echoed back so results can be routed
};
struct AsyncDnsResult {
    std::string tag;
    std::string qname;
    DnsRRType   qtype;
    std::vector<DnsRecord> records;
    bool answered = false; // true even for definitive NXDOMAIN
};
std::vector<AsyncDnsResult> dns_query_batch(const std::vector<AsyncDnsJob>& jobs,
                                             const std::vector<std::string>& servers,
                                             int timeout_ms, int concurrency,
                                             bool use_edns0 = true);
