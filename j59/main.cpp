#include "utils.hpp"
#include "public_db.hpp"
#include <fstream>
#include "scan.hpp"
#include "icmp_ping.hpp"
#include "probe.h"
#include <stdexcept>
#include <future>
#include <ctime>
#include <map>
#include <algorithm>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sstream>
#include <set>
#include <iomanip>
#include <cstdio>
#include <queue>
#include <unordered_set>
#include <csignal>
#include <charconv>
#include <array>

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string green   = "\033[32m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string white   = "\033[97m";
    const std::string red     = "\033[91m";
    const std::string dim     = "\033[2m";    
    const std::string cyan    = "\033[36m";    
    const std::string bright_cyan = "\033[96m";
    
}

namespace {
// NEW:
constexpr size_t MAX_EXPANDED_IPS_PER_CIDR = 1000000;      // 1M IPs per CIDR (e.g., /12)
constexpr size_t MAX_TOTAL_IPS             = 50000000;     // 50M total IPs (reasonable max)
constexpr size_t MAX_INPUT_TOKEN_LEN       = 2048;
constexpr size_t TARGETS_PER_QUEUE = 1000;   // max targets per recv/send queue pair


std::unordered_map<std::string, std::string> mac_vendor_map;
std::vector<int> global_raw_sockets;
std::vector<io_uring*> global_uring_rings;
std::vector<std::thread*> global_worker_threads;
std::mutex global_resources_mutex;
std::atomic<int> crash_signal{0};


inline void trim_in_place(std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    if (b == 0 && e == s.size()) return;
    s = (b < e) ? s.substr(b, e - b) : std::string{};
}

inline bool has_bad_control_char(const std::string& s) {
    for (unsigned char c : s) {
        if ((c < 0x20 && c != '\t') || c == 0x7F) return true;
    }
    return false;
}
} // close anonymous namespace early — normalize_ip_string needs external linkage

bool normalize_ip_string(const std::string& in, std::string& out) {
    in_addr a4{};
    if (inet_pton(AF_INET, in.c_str(), &a4) == 1) {
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a4, buf, sizeof(buf))) return false;
        out.assign(buf);
        return true;
    }
    in6_addr a6{};
    if (inet_pton(AF_INET6, in.c_str(), &a6) == 1) {
        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &a6, buf, sizeof(buf))) return false;
        out.assign(buf);
        return true;
    }
    return false;
}

bool get_local_ip6(const char* remote_ip6, uint8_t out_ip6[16]) {
    struct in6_addr addr{};
    if (inet_pton(AF_INET6, remote_ip6, &addr) != 1) return false;

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    struct SocketGuard {
        int fd;
        ~SocketGuard() { if (fd >= 0) close(fd); }
    } guard{sock};

    sockaddr_in6 remote{};
    remote.sin6_family = AF_INET6;
    remote.sin6_port   = htons(9);
    remote.sin6_addr   = addr;
    if (connect(sock, (sockaddr*)&remote, sizeof(remote)) < 0) return false;

    sockaddr_in6 local{};
    socklen_t len = sizeof(local);
    if (getsockname(sock, (sockaddr*)&local, &len) != 0) return false;

    memcpy(out_ip6, &local.sin6_addr, 16);
    return true;
}

namespace { // reopen for the remaining TU-local helpers
inline bool add_unique_ip(std::vector<std::string>& dst,
                          std::unordered_set<std::string>& seen,
                          std::string ip) {
    if (!seen.insert(ip).second) return false;
    dst.emplace_back(std::move(ip));
    return true;
}
}

struct ParseContext {
    std::string source_label; 
    bool is_file;             

    // Formats a position string for error messages
    std::string pos(size_t idx) const {
        if (is_file)
            return source_label + ":" + std::to_string(idx);
        return "position " + std::to_string(idx) + " of " + source_label;
    }
};

void expand_cidr(const std::string& cidr, std::vector<std::string>& ips);
bool resolve_domain_to_ip(const std::string& domain, std::string& resolved_ip);

static bool parse_targets(
    std::vector<std::string>& tokens_in,   // caller pre-splits into tokens
    std::vector<std::string>& ips,         // output accumulator
    const ParseContext& ctx)
{
    // Reserve sizes scaled to expected input volume
    const size_t bulk_reserve  = ctx.is_file ? 4096  : 512;
    const size_t seen_reserve  = ctx.is_file ? 8192  : 1024;
    const size_t dns_reserve   = ctx.is_file ? 512   : 128;

    std::vector<std::string> bulk_ips;
    bulk_ips.reserve(bulk_reserve);

    std::unordered_set<std::string> seen;
    seen.reserve(seen_reserve);

    std::unordered_map<std::string, std::string> dns_cache;
    dns_cache.reserve(dns_reserve);

    size_t idx = 0;
    for (std::string& token : tokens_in) {
        ++idx;

        // ── Step A: length guard ────────────────────────────────────────
        if (token.size() > MAX_INPUT_TOKEN_LEN) {
            std::cerr << "Token too long at " << ctx.pos(idx) << "\n";
            return false;
        }

        // ── Step B: comment strip + trim ────────────────────────────────
        if (size_t hash = token.find('#'); hash != std::string::npos)
            token.erase(hash);
        trim_in_place(token);
        if (token.empty()) continue;

        // ── Step C: control-character guard ─────────────────────────────
        if (has_bad_control_char(token)) {
            std::cerr << "Invalid characters at " << ctx.pos(idx) << "\n";
            return false;
        }

        // ── Step D: CIDR branch ─────────────────────────────────────────
        if (token.find('/') != std::string::npos) {
            // IPv6 CIDR ranges (e.g. 2001:db8::/64) are not expanded — a
            // /64 alone is 2^64 addresses, so blind enumeration the way
            // expand_cidr() does for IPv4 isn't viable here. Give a clear,
            // specific error instead of letting it fall through to
            // expand_cidr()'s generic "Invalid CIDR" (which would be
            // misleading — the syntax is valid, it's just unsupported).
            if (token.find(':') != std::string::npos) {
                std::cerr << "IPv6 CIDR ranges are not supported at " << ctx.pos(idx)
                          << " -> " << token
                          << " (specify individual IPv6 addresses instead)\n";
                return false;
            }

            const size_t before = bulk_ips.size();
            
            // Expand the CIDR into bulk_ips
            expand_cidr(token, bulk_ips);
            
            if (bulk_ips.size() == before) {
                std::cerr << "Invalid CIDR at " << ctx.pos(idx)
                          << " -> " << token << "\n";
                return false;
            }
            
            // ── FIXED: Deduplicate newly expanded entries using temporary vector ──
            std::vector<std::string> unique_new_ips;
            unique_new_ips.reserve(bulk_ips.size() - before);
            
            for (size_t i = before; i < bulk_ips.size(); ++i) {
                // Skip empty strings and check for duplicates
                if (!bulk_ips[i].empty()) {
                    if (seen.insert(bulk_ips[i]).second) {
                        unique_new_ips.push_back(std::move(bulk_ips[i]));
                    }
                }
            }
            
            // Resize bulk_ips back to before expansion and insert deduplicated IPs
            bulk_ips.resize(before);
            bulk_ips.insert(bulk_ips.end(),
                           std::make_move_iterator(unique_new_ips.begin()),
                           std::make_move_iterator(unique_new_ips.end()));

        // ── Step E: single IP / domain branch ───────────────────────────
        } else {
            std::string out_ip;

            // Guard: reject bare integers — they look like forgotten port numbers.
            // A valid hostname must contain at least one letter or a dot.
            bool looks_like_bare_number = !token.empty() &&
                std::all_of(token.begin(), token.end(), ::isdigit);
            if (looks_like_bare_number) {
                long v = 0;
                try {
                    v = std::stol(token);
                } catch (const std::exception&) {
                    std::cerr << "Error: '" << token << "' is not a valid IP address or hostname.\n";
                    return false;
                }
                if (v >= 1 && v <= 65535) {
                    std::cerr << "Error: '" << token << "' looks like a port number, not an IP address.\n"
                              << "  Did you forget -p? Use: -p " << token << "\n";
                } else {
                    std::cerr << "Error: '" << token << "' is not a valid IP address or hostname.\n";
                }
                return false;
            }

            // Numeric IP literal (v4 or v6)? Otherwise DNS — one call now
            // checks both A and AAAA records.
            if (!normalize_ip_string(token, out_ip)) {
                // Not an IP, try DNS resolution
                auto it = dns_cache.find(token);
                if (it != dns_cache.end()) {
                    out_ip = it->second;
                } else {
                    if (!resolve_domain_to_ip(token, out_ip)) {
                        std::cerr << "Cannot resolve '" << token
                                  << "' at " << ctx.pos(idx) << "\n";
                        return false;
                    }
                    dns_cache.emplace(token, out_ip);
                }
            }
            
            // Add unique IP using the helper function
            add_unique_ip(bulk_ips, seen, std::move(out_ip));
        }

        // ── Step F: global limit check ──────────────────────────────────
        if (ips.size() + bulk_ips.size() > MAX_TOTAL_IPS) {
            std::cerr << "Too many IPs after expansion (limit "
                      << MAX_TOTAL_IPS << ")\n";
            return false;
        }
    }

    // Move all collected IPs to the output
    ips.insert(ips.end(),
               std::make_move_iterator(bulk_ips.begin()),
               std::make_move_iterator(bulk_ips.end()));
    
    return true;
}

void load_mac_vendors(const std::string &filename) {
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) { std::cerr << "Warning: Could not open MAC vendor file: " << filename << "\n"; return; }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return; }
    size_t file_size = st.st_size;

    char* data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0));
    close(fd);
    if (data == MAP_FAILED) return;

    mac_vendor_map.reserve(35000);

    const char* end = data + file_size;
    const char* p = data;
    while (p < end) {
        const char* line_end = static_cast<const char*>(memchr(p, '\n', end - p));
        if (!line_end) line_end = end;
        if (p == line_end || *p == '#') { p = line_end + 1; continue; }
        const char* delim = p;
        while (delim < line_end && *delim != ' ' && *delim != '\t') ++delim;
        if (delim == line_end) { p = line_end + 1; continue; }
        char key[7]; int k = 0;
        for (const char* c = p; c < delim && k < 6; ++c)
            if (*c != ':') key[k++] = toupper((unsigned char)*c);
        if (k != 6) { p = line_end + 1; continue; }

        const char* v = delim;
        while (v < line_end && (*v == ' ' || *v == '\t')) ++v;

        mac_vendor_map.emplace(std::string(key, 6), std::string(v, line_end - v));
        p = line_end + 1;
    }
    munmap(data, file_size);
}

std::string get_mac_vendor(const std::string &mac_address) {
    if (mac_address.size() < 8) return "unknown"; 
    char key[7];
    int k = 0;
    for (char c : mac_address) {
        if (c != ':') {
            key[k++] = toupper((unsigned char)c);
            if (k == 6) break;
        }
    }
    key[6] = '\0';
    std::string oui(key, 6);

    auto it = mac_vendor_map.find(oui);
    if (it != mac_vendor_map.end()) return it->second;

    auto hex_nibble = [](char c) -> int {
        return (c <= '9') ? (c - '0') : (c - 'A' + 10);
    };
    uint8_t first_byte = static_cast<uint8_t>((hex_nibble(key[0]) << 4) | hex_nibble(key[1]));
    if (first_byte & 0x02) return "Locally Administered";

    return "unknown";
}

std::vector<std::string> perform_sn_discovery(const std::vector<std::string>& ips,
                                               std::string& interface,
                                               size_t& down_hosts_out,
                                               std::unordered_map<uint32_t, std::string>& mac_cache_out)
{
    std::vector<std::string> alive_ips;
    alive_ips.reserve(ips.size());
    down_hosts_out = 0;
    if (ips.empty()) return alive_ips;
    // ---- overall timing, for the "Overall arp ping completed" summary ----
    auto fn_start = std::chrono::steady_clock::now();
    struct rusage ru_fn_start{}; getrusage(RUSAGE_SELF, &ru_fn_start);

    // ---- figure out local subnet (same pattern as the -Pn block) ----
    uint32_t local_ip_int = get_local_ip(ips[0].c_str());
    uint8_t  src_ip_bytes[4] = {0};
    uint8_t  netmask[4]      = {0};
    uint32_t netmask_int     = 0;
    bool     subnet_ok       = false;
    uint8_t  src_mac[6]      = {0};

    if (local_ip_int != 0) {
        if (interface.empty()) interface = autodetect_interface(local_ip_int);
        int tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (tmp_sock >= 0) {
            if (get_interface_ip_and_netmask(tmp_sock, interface.c_str(), src_ip_bytes, netmask)) {
                memcpy(&netmask_int, netmask, 4);
                subnet_ok = get_interface_mac(tmp_sock, interface.c_str(), src_mac);
            }
            close(tmp_sock);
        }
    }

    // ---- split targets: same-subnet -> ARP, everything else -> ICMP ----
    struct HostSlot { std::string ip; bool alive=false; std::string mac; double dur_s=0.0; double cpu_s=0.0; uint32_t ip_int=0; bool icmp_only_no_mac=false; };
    std::vector<HostSlot> slots(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) slots[i].ip = ips[i];

    std::vector<uint8_t*> arp_target_ptrs;
    std::vector<std::unique_ptr<uint8_t[]>> arp_target_bufs;
    std::vector<size_t> arp_indices;
    std::vector<std::string> icmp_ips;
    std::vector<size_t> icmp_indices;

    // Per-host results from each probe, tracked independently so neither
    // pass blindly overwrites the other's finding. is_lan_host marks the
    // same-subnet hosts that get BOTH probes (vs. off-subnet hosts that
    // only ever get ICMP and have no ARP opinion to reconcile).
    std::vector<bool> arp_alive(ips.size(), false);
    std::vector<bool> icmp_alive(ips.size(), false);
    std::vector<bool> is_lan_host(ips.size(), false);

    for (size_t i = 0; i < ips.size(); ++i) {
        uint8_t ip_bytes[4] = {0};
        if (inet_pton(AF_INET, ips[i].c_str(), ip_bytes) <= 0) {
            // Not a v4 literal — if it's a valid IPv6 target, there's no
            // ARP or ICMPv4 path for it (NDP-based discovery isn't
            // implemented here), so treat it as alive by default rather
            // than silently dropping it from the scan the way falling
            // through to "down" below would.
            if (get_ip_version(ips[i].c_str()) == 6) {
                slots[i].alive = true;
            }
            continue;
        }
        uint32_t ip_int; memcpy(&ip_int, ip_bytes, 4);
        slots[i].ip_int = ip_int;  
        if (subnet_ok && is_same_subnet(ip_int, local_ip_int, netmask_int)) {
            auto buf = std::make_unique<uint8_t[]>(4);
            memcpy(buf.get(), ip_bytes, 4);
            arp_target_ptrs.push_back(buf.get());
            arp_target_bufs.push_back(std::move(buf));
            arp_indices.push_back(i);
            is_lan_host[i] = true;
            // LAN host: probe with ICMP too, so a missed/blocked ARP
            // reply doesn't get treated as "down" without a second signal.
            icmp_ips.push_back(ips[i]);
            icmp_indices.push_back(i);
        } else {
            icmp_ips.push_back(ips[i]);
            icmp_indices.push_back(i);
        }
    }

    // ---- ARP pass: batched sends of ARP_BATCH_SIZE hosts, each batch gets
    // up to 2 retries with an adaptive (RTT-based) per-round timeout instead
    // of one fixed-timeout blast across the whole subnet ----
    constexpr size_t ARP_BATCH_SIZE = 63;
    if (!arp_target_ptrs.empty() && subnet_ok) {
        int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sock >= 0) {
            struct io_uring arp_ring;
            if (io_uring_queue_init(512, &arp_ring, IORING_SETUP_COOP_TASKRUN) == 0) {
                auto arp_start = std::chrono::steady_clock::now();
                struct rusage ru_start{}; getrusage(RUSAGE_SELF, &ru_start);

                const size_t total_arp_targets = arp_target_ptrs.size();
                for (size_t batch_start = 0; batch_start < total_arp_targets; batch_start += ARP_BATCH_SIZE) {
                    const size_t batch_end = std::min(batch_start + ARP_BATCH_SIZE, total_arp_targets);
                    const size_t this_batch_size = batch_end - batch_start;   // last batch can be < 63

                    std::vector<uint8_t*> batch_target_ptrs(
                        arp_target_ptrs.begin() + batch_start, arp_target_ptrs.begin() + batch_end);

                    std::vector<std::unique_ptr<uint8_t[]>> mac_bufs;
                    std::vector<uint8_t*> mac_ptrs;
                    mac_bufs.reserve(this_batch_size);
                    mac_ptrs.reserve(this_batch_size);
                    for (size_t j = 0; j < this_batch_size; ++j) {
                        auto mb = std::make_unique<uint8_t[]>(6);
                        memset(mb.get(), 0, 6);
                        mac_ptrs.push_back(mb.get());
                        mac_bufs.push_back(std::move(mb));
                    }

                    if (send_arp_request(arp_sock, &arp_ring, interface.c_str(), src_mac,
                                          src_ip_bytes, batch_target_ptrs)) {
                        // initial_rtt_ms seeds the adaptive timeout; it's refined
                        // from real replies as they arrive. max_retries=2 means
                        // up to 3 total attempts per host in this batch.
                        receive_arp_reply(arp_sock, &arp_ring, batch_target_ptrs, mac_ptrs,
                                           EthArpOptions{}, /*initial_rtt_ms=*/100,
                                           interface.c_str(), src_mac, src_ip_bytes,
                                           /*max_retries=*/2,
                                           /*min_round_timeout_ms=*/20,
                                           /*max_round_timeout_ms=*/1000);
                    }

                    for (size_t j = 0; j < this_batch_size; ++j) {
                        size_t idx = arp_indices[batch_start + j];
                        uint8_t* m = mac_ptrs[j];
                        bool resolved = (m[0]|m[1]|m[2]|m[3]|m[4]|m[5]) != 0;
                        arp_alive[idx] = resolved;
                        if (resolved) slots[idx].mac = format_mac(m);
                    }
                }

                auto arp_end = std::chrono::steady_clock::now();
                struct rusage ru_end{}; getrusage(RUSAGE_SELF, &ru_end);
                double dur_s = std::chrono::duration<double>(arp_end - arp_start).count();
                double cpu_s = (ru_end.ru_utime.tv_sec - ru_start.ru_utime.tv_sec) +
                               (ru_end.ru_utime.tv_usec - ru_start.ru_utime.tv_usec) / 1e6 +
                               (ru_end.ru_stime.tv_sec - ru_start.ru_stime.tv_sec) +
                               (ru_end.ru_stime.tv_usec - ru_start.ru_stime.tv_usec) / 1e6;
                for (size_t j = 0; j < arp_target_ptrs.size(); ++j) {
                    slots[arp_indices[j]].dur_s = dur_s;
                    slots[arp_indices[j]].cpu_s = cpu_s;
                }

                io_uring_queue_exit(&arp_ring);
            }
            close(arp_sock);
        }
    }

    // ---- ICMP pass for non-local targets, reusing your existing sweep ----
    if (!icmp_ips.empty()) {
        auto icmp_start = std::chrono::steady_clock::now();
        struct rusage ru_start{}; getrusage(RUSAGE_SELF, &ru_start);
        auto results = icmp_ping_sweep(icmp_ips, 1200);
        auto icmp_end = std::chrono::steady_clock::now();
        struct rusage ru_end{}; getrusage(RUSAGE_SELF, &ru_end);
        double dur_s = std::chrono::duration<double>(icmp_end - icmp_start).count();
        double cpu_s = (ru_end.ru_utime.tv_sec - ru_start.ru_utime.tv_sec) +
                       (ru_end.ru_utime.tv_usec - ru_start.ru_utime.tv_usec) / 1e6 +
                       (ru_end.ru_stime.tv_sec - ru_start.ru_stime.tv_sec) +
                       (ru_end.ru_stime.tv_usec - ru_start.ru_stime.tv_usec) / 1e6;
        for (size_t k = 0; k < results.size(); ++k) {
            size_t idx = icmp_indices[k];
            bool alive_icmp = (results[k].state == IcmpHostState::Alive
                              || results[k].state == IcmpHostState::NetAdminProhibited
                              || results[k].state == IcmpHostState::HostAdminProhibited
                              || results[k].state == IcmpHostState::CommAdminProhibited);
            icmp_alive[idx] = alive_icmp;
            slots[idx].dur_s = dur_s;
            slots[idx].cpu_s = cpu_s;
            if (!is_lan_host[idx]) {
                // Off-subnet host: no ARP opinion was ever formed for it,
                // ICMP is the only signal, decide right here.
                slots[idx].alive = alive_icmp;
            }
        }

        // ---- SYN fallback for off-subnet hosts ICMP never answered ----
        // Only retry true timeouts — explicit ICMP errors (Dead,
        // NetUnreachable, etc.) already got a definitive answer from a
        // router and aren't worth a SYN probe.
        std::vector<std::string> syn_ips;
        std::vector<size_t>      syn_indices;
        for (size_t k = 0; k < results.size(); ++k) {
            size_t idx = icmp_indices[k];
            if (is_lan_host[idx]) continue;
            if (results[k].state != IcmpHostState::NoResponse) continue;
            syn_ips.push_back(icmp_ips[k]);
            syn_indices.push_back(idx);
        }
        if (!syn_ips.empty()) {
            auto syn_start = std::chrono::steady_clock::now();
            struct rusage ru_syn_start{}; getrusage(RUSAGE_SELF, &ru_syn_start);
            auto syn_results = tcp_syn_probe_sweep(syn_ips, local_ip_int, 1000);
            auto syn_end = std::chrono::steady_clock::now();
            struct rusage ru_syn_end{}; getrusage(RUSAGE_SELF, &ru_syn_end);
            double syn_dur_s = std::chrono::duration<double>(syn_end - syn_start).count();
            double syn_cpu_s = (ru_syn_end.ru_utime.tv_sec - ru_syn_start.ru_utime.tv_sec) +
                                (ru_syn_end.ru_utime.tv_usec - ru_syn_start.ru_utime.tv_usec) / 1e6 +
                                (ru_syn_end.ru_stime.tv_sec - ru_syn_start.ru_stime.tv_sec) +
                                (ru_syn_end.ru_stime.tv_usec - ru_syn_start.ru_stime.tv_usec) / 1e6;
            for (size_t j = 0; j < syn_results.size(); ++j) {
                size_t idx = syn_indices[j];
                if (syn_results[j].alive) {
                    slots[idx].alive = true;
                    // Same print columns as the ICMP pass — just roll this
                    // pass's cost in, no new print type needed.
                    slots[idx].dur_s += syn_dur_s;
                    slots[idx].cpu_s += syn_cpu_s;
                }
            }
        }
    }

    std::vector<uint8_t*> recheck_ptrs;
    std::vector<std::unique_ptr<uint8_t[]>> recheck_bufs;
    std::vector<size_t> recheck_slot_idx;

    for (size_t k = 0; k < arp_indices.size(); ++k) {
        size_t idx = arp_indices[k];
        if (arp_alive[idx]) {
            slots[idx].alive = true;
        } else if (icmp_alive[idx]) {
            recheck_slot_idx.push_back(idx);
            auto buf = std::make_unique<uint8_t[]>(4);
            memcpy(buf.get(), arp_target_bufs[k].get(), 4);
            recheck_ptrs.push_back(buf.get());
            recheck_bufs.push_back(std::move(buf));
        } else {
            slots[idx].alive = false;
        }
    }

    // ---- one extra ARP resend, only for the ARP-missed/ICMP-alive set ----
    if (!recheck_ptrs.empty()) {
        int arp_sock2 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sock2 >= 0) {
            struct io_uring arp_ring2;
            if (io_uring_queue_init(256, &arp_ring2, IORING_SETUP_COOP_TASKRUN) == 0) {
                std::vector<std::unique_ptr<uint8_t[]>> mac_bufs2;
                std::vector<uint8_t*> mac_ptrs2;
                mac_bufs2.reserve(recheck_ptrs.size());
                mac_ptrs2.reserve(recheck_ptrs.size());
                for (size_t j = 0; j < recheck_ptrs.size(); ++j) {
                    auto mb = std::make_unique<uint8_t[]>(6);
                    memset(mb.get(), 0, 6);
                    mac_ptrs2.push_back(mb.get());
                    mac_bufs2.push_back(std::move(mb));
                }

                if (send_arp_request(arp_sock2, &arp_ring2, interface.c_str(), src_mac,
                                      src_ip_bytes, recheck_ptrs)) {
                    receive_arp_reply(arp_sock2, &arp_ring2, recheck_ptrs, mac_ptrs2,
                                       EthArpOptions{}, /*initial_rtt_ms=*/100,
                                       interface.c_str(), src_mac, src_ip_bytes,
                                       /*max_retries=*/1,
                                       /*min_round_timeout_ms=*/20,
                                       /*max_round_timeout_ms=*/1000);
                }

                for (size_t j = 0; j < recheck_slot_idx.size(); ++j) {
                    size_t idx = recheck_slot_idx[j];
                    uint8_t* m = mac_ptrs2[j];
                    bool resolved = (m[0]|m[1]|m[2]|m[3]|m[4]|m[5]) != 0;
                    // ICMP already proved this host is up; ARP only
                    // decides whether we also get a MAC out of it.
                    slots[idx].alive = true;
                    if (resolved) {
                        slots[idx].mac = format_mac(m);
                    } else {
                        slots[idx].icmp_only_no_mac = true;
                    }
                }

                io_uring_queue_exit(&arp_ring2);
            }
            close(arp_sock2);
        } else {
            // Couldn't even open the second raw socket - fall back to
            // "alive, no MAC" rather than silently dropping these hosts.
            for (size_t idx : recheck_slot_idx) {
                slots[idx].alive = true;
                slots[idx].icmp_only_no_mac = true;
            }
        }
    }

    // ---- print report, one block per host, in original order ----
    std::cout << "\nStarting " << color::bold << "Shiv" << color::reset
              << " (" << color::yellow << "ARP Ping" << color::reset
              << ") scan at " << get_current_time() << "\n";

    for (size_t i = 0; i < slots.size(); ++i) {
        auto& s = slots[i];

        if (s.alive) {
            print_output(PrintOutputType::HOST_HEADER, s.ip, 0, "", "", "", 0,0,0,0,0,0, "", "", 0.0, "", false, false);
            std::cout << "\n";
            std::cout << std::left << std::setw(15) << "Status" << ": "
                      << color::green << "alive" << color::reset << "\n";
            std::string vendor = s.mac.empty() ? "" : get_mac_vendor(s.mac);
            print_output(PrintOutputType::MAC_ADDRESS, "", 0, "", "", "", 0,0,0,0,0,0,
                         s.mac, vendor, 0.0, "", false, false);
            if (s.icmp_only_no_mac) {
                std::cout << std::left << std::setw(15) << "Note" << ": "
                          << color::yellow
                          << "alive (confirmed via ICMP)"
                          << color::reset << "\n";
            }
            print_output(PrintOutputType::SCAN_TIMING, "", 0, "", "", "", 0,0,0,0,0,0, "", "", s.dur_s, "", false, false);
            print_output(PrintOutputType::CPU_TIME,    "", 0, "", "", "", 0,0,0,0,0,0, "", "", s.cpu_s, "", false, false);
            std::cout << color::green << std::string(73, '_') << color::reset << "\n";
            alive_ips.push_back(s.ip);
            if (!s.mac.empty()) mac_cache_out[s.ip_int] = s.mac;
        } else {
            down_hosts_out++;
            // down hosts intentionally not printed, per spec
        }
    }

    auto fn_end = std::chrono::steady_clock::now();
    struct rusage ru_fn_end{}; getrusage(RUSAGE_SELF, &ru_fn_end);
    double total_dur_s = std::chrono::duration<double>(fn_end - fn_start).count();
    double total_cpu_s = (ru_fn_end.ru_utime.tv_sec - ru_fn_start.ru_utime.tv_sec) +
                          (ru_fn_end.ru_utime.tv_usec - ru_fn_start.ru_utime.tv_usec) / 1e6 +
                          (ru_fn_end.ru_stime.tv_sec - ru_fn_start.ru_stime.tv_sec) +
                          (ru_fn_end.ru_stime.tv_usec - ru_fn_start.ru_stime.tv_usec) / 1e6;

    std::cout << "Shiv: " << slots.size() << " IP addresses (" << color::green
              << alive_ips.size() << color::reset << " hosts up) scanned in "
              << std::fixed << std::setprecision(2) << total_dur_s << "s\n";
    print_output(PrintOutputType::DOWN_HOSTS_SUMMARY, "", 0, "", "", "", 0,
                 static_cast<size_t>(down_hosts_out), 0,0,0, slots.size(), "", "", 0.0, "", false, false);

    return alive_ips;
}

void expand_cidr(const std::string& cidr, std::vector<std::string>& ips) {
    std::string input = cidr;
    trim_in_place(input);

    if (input.empty() || input.size() > MAX_INPUT_TOKEN_LEN || has_bad_control_char(input)) {
        std::cerr << "Invalid CIDR input\n";
        return;
    }

    const size_t slash = input.find('/');
    if (slash == std::string::npos) {
        std::string norm;
        if (get_ip_version(input.c_str()) == 4 && normalize_ip_string(input, norm)) {
            ips.push_back(std::move(norm));
        } else {
            std::cerr << "Invalid IPv4/CIDR: " << input << "\n";
        }
        return;
    }

    if (input.find('/', slash + 1) != std::string::npos) {
        std::cerr << "Invalid CIDR format: " << input << "\n";
        return;
    }

    std::string ip_part = input.substr(0, slash);
    std::string pfx_part = input.substr(slash + 1);
    trim_in_place(ip_part);
    trim_in_place(pfx_part);

    if (ip_part.empty() || pfx_part.empty()) {
        std::cerr << "Invalid CIDR format: " << input << "\n";
        return;
    }

    in_addr base{};
    if (inet_pton(AF_INET, ip_part.c_str(), &base) != 1) {
        std::cerr << "Invalid IPv4 in CIDR: " << ip_part << "\n";
        return;
    }

    int prefix = -1;
    auto p = std::from_chars(pfx_part.data(), pfx_part.data() + pfx_part.size(), prefix);
    if (p.ec != std::errc() || p.ptr != pfx_part.data() + pfx_part.size() || prefix < 0 || prefix > 32) {
        std::cerr << "Invalid CIDR prefix: " << pfx_part << "\n";
        return;
    }

    const uint32_t ip = ntohl(base.s_addr);
    const uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    const uint32_t network = ip & mask;
    const uint32_t broadcast = network | ~mask;

    // /31,/32 include all addresses. Others exclude network+broadcast.
    const uint32_t start = (prefix >= 31) ? network : (network + 1u);
    const uint32_t end   = (prefix >= 31) ? broadcast : (broadcast - 1u);

    if (start > end) return;

    const uint64_t count = static_cast<uint64_t>(end) - static_cast<uint64_t>(start) + 1ULL;
    if (count > MAX_EXPANDED_IPS_PER_CIDR) {
        std::cerr << "CIDR range too large (" << count << " IPs): " << input << "\n";
        return;
    }

    ips.reserve(ips.size() + static_cast<size_t>(count));

    char buf[INET_ADDRSTRLEN];
    for (uint32_t cur = start;; ++cur) {
        in_addr a{};
        a.s_addr = htonl(cur);
        if (inet_ntop(AF_INET, &a, buf, sizeof(buf))) {
            ips.emplace_back(buf);
        }
        if (cur == end) break;
    }
}

bool resolve_domain_to_ip(const std::string& domain, std::string& resolved_ip) {
    resolved_ip.clear();
    if (domain.empty() || domain.size() > 253) return false;

    std::string host = domain;
    trim_in_place(host);
    if (host.empty() || has_bad_control_char(host)) return false;
    if (normalize_ip_string(host, resolved_ip)) return true;

    auto attempt_once = [&host]() -> std::pair<int, std::string> {
        struct AddrState {
            std::mutex m;
            std::condition_variable cv;
            bool done = false;
            int rc = -1;
            std::string ip;
        };
        auto state = std::make_shared<AddrState>();

        std::thread([state, host]() {
            addrinfo hints{};
            hints.ai_family   = AF_UNSPEC;   // fetch both A and AAAA in one query
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags    = AI_ADDRCONFIG;

            addrinfo* result = nullptr;
            int rc = getaddrinfo(host.c_str(), nullptr, &hints, &result);
            std::string ip_out;
            if (rc == 0 && result) {
                struct Guard { addrinfo* p; ~Guard(){ if(p) freeaddrinfo(p); } } g{result};
                rc = EAI_NONAME; // default if no usable record found

                // Prefer an IPv4 (A) record first — same precedence the old
                // two-function version had.
                for (addrinfo* rp = result; rp; rp = rp->ai_next) {
                    if (rp->ai_family != AF_INET || !rp->ai_addr) continue;
                    if (rp->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) continue;
                    const auto* sa = reinterpret_cast<const sockaddr_in*>(rp->ai_addr);
                    char buf[INET_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) continue;
                    ip_out = buf;
                    rc = 0;
                    break;
                }
                // No A record — fall back to the first AAAA record.
                if (rc != 0) {
                    for (addrinfo* rp = result; rp; rp = rp->ai_next) {
                        if (rp->ai_family != AF_INET6 || !rp->ai_addr) continue;
                        if (rp->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in6))) continue;
                        const auto* sa = reinterpret_cast<const sockaddr_in6*>(rp->ai_addr);
                        char buf[INET6_ADDRSTRLEN];
                        if (!inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf))) continue;
                        ip_out = buf;
                        rc = 0;
                        break;
                    }
                }
            }
            {
                std::lock_guard<std::mutex> lock(state->m);
                state->rc   = rc;
                state->ip   = ip_out;
                state->done = true;
            }
            state->cv.notify_all();
        }).detach();

        std::unique_lock<std::mutex> lock(state->m);
        bool finished = state->cv.wait_for(lock, std::chrono::milliseconds(2000),
                                            [&] { return state->done; });
        if (!finished) return {-1, std::string{}};   // timeout -> transient
        return {state->rc, state->ip};
    };

    int rc = 0;
    for (int attempt = 1; attempt <= 2; ++attempt) {
        auto [code, ip] = attempt_once();
        rc = code;

        if (rc == 0 && !ip.empty()) {
            resolved_ip = ip;
            return true;
        }

        if (rc == EAI_FAIL || rc == EAI_NONAME) break;
        if (attempt < 2) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cerr << "domain to ip resolution failed, can't perform without ip.\n";
    return false;
}

bool read_ips_from_file(const std::string& filename,
                        std::vector<std::string>& ips)
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open IP file: " << filename << "\n";
        return false;
    }

    std::vector<std::string> tokens;
    tokens.reserve(4096);
    std::string line;
    while (std::getline(file, line)) {
        tokens.emplace_back(std::move(line));
    }

    ParseContext ctx{ filename, /*is_file=*/true };
    return parse_targets(tokens, ips, ctx);
}

// line 339 — thinned to a splitter + adapter
bool process_ip_string(const std::string& ip_str,
                       std::vector<std::string>& ips)
{
    std::vector<std::string> tokens;
    tokens.reserve(64);

    std::stringstream ss(ip_str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        tokens.emplace_back(std::move(token));
    }

    ParseContext ctx{ "CLI argument", /*is_file=*/false };
    return parse_targets(tokens, ips, ctx);
}

// Duplicates everything written to a stream (cout/cerr) into an in-memory
// buffer while still passing it through to the real terminal live.
// Lets us capture the *entire* session (debug prints, version-detection
// output, etc.) for saving, without touching any individual print call-site.
class TeeBuf : public std::streambuf {
    std::streambuf* real;
    std::ostringstream capture;
protected:
    int overflow(int c) override {
        if (c != EOF) {
            capture.put(static_cast<char>(c));
            real->sputc(static_cast<char>(c));
        }
        return c;
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        capture.write(s, n);
        return real->sputn(s, n);
    }
public:
    explicit TeeBuf(std::streambuf* r) : real(r) {}
    std::string str() const { return capture.str(); }
};

void save_scan_results(const std::vector<RecPross>& results, const std::string& output_file,
                        const std::string& raw_log = "") {
    if (output_file.empty()) {
        return;
    }

    std::ofstream out_file(output_file);

    if (!out_file.is_open()) {
        std::cerr << "Failed to create output file: " << output_file << "\n";
        return;
    }

    RecPross combined_result{};
    for (const auto& result : results) {
        combined_result.closed_ports += result.closed_ports;
        combined_result.open_ports.insert(
            combined_result.open_ports.end(),
            result.open_ports.begin(),
            result.open_ports.end()
        );
        combined_result.filtered_ports.insert(
            combined_result.filtered_ports.end(),
            result.filtered_ports.begin(),
            result.filtered_ports.end()
        );

        if (!result.mac_address.empty()) {
            combined_result.mac_address = result.mac_address;
        }
    }

    std::sort(combined_result.open_ports.begin(), combined_result.open_ports.end());
    std::sort(combined_result.filtered_ports.begin(), combined_result.filtered_ports.end());

    const auto& service_map = read_services_from_file("services");

    const std::string safe_mac = combined_result.mac_address;
    const std::string safe_vendor = combined_result.mac_address.empty()
        ? ""
        : get_mac_vendor(combined_result.mac_address);

    if (!raw_log.empty()) {
        out_file << raw_log;
    } else {
        out_file << "shiv scan results\n";

        if (!safe_mac.empty()) {
            out_file << "MAC Address: " << safe_mac << " (" << safe_vendor << ")\n\n";
        }

        out_file << "Open Ports:\n";
        for (uint16_t port : combined_result.open_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << port << "/tcp (" << service << ")\n";
        }

        out_file << "\nFiltered Ports:\n";
        for (uint16_t port : combined_result.filtered_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << port << "/tcp (" << service << ")\n";
        }

        out_file << "\nClosed Ports: " << combined_result.closed_ports << "\n";
    }

    out_file.close();
    std::cout << "Scan results saved to: " << output_file << "\n";
}


void emergency_cleanup();
extern std::atomic<bool> terminate_flag;
static std::atomic_flag terminate_flag_signal = ATOMIC_FLAG_INIT;


#define SIGNAL_WRITE(fd, msg, len) \
    do { ssize_t _wr = write((fd), (msg), (len)); (void)_wr; } while(0)

void signal_handler(int sig) {
    static const char msg_int[]  = "\n⏹️  Scan interrupted by user.\n";
    static const char msg_segv[] = "\n❌ Segmentation fault (invalid memory access)\n";
    static const char msg_abrt[] = "\n❌ Aborted (internal error)\n";
    static const char msg_fpe[]  = "\n❌ Floating point exception\n";
    static const char msg_ill[]  = "\n❌ Illegal instruction\n";
    static const char msg_def[]  = "\n❌ Unknown error occurred\n";

    switch (sig) {
        case SIGINT:
        case SIGTERM:
            SIGNAL_WRITE(STDERR_FILENO, msg_int, sizeof(msg_int) - 1);
            terminate_flag_signal.test_and_set(std::memory_order_relaxed);
            terminate_flag.store(true, std::memory_order_relaxed);
            break;

        case SIGSEGV:
            SIGNAL_WRITE(STDERR_FILENO, msg_segv, sizeof(msg_segv) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(139);
            break;

        case SIGABRT:
            SIGNAL_WRITE(STDERR_FILENO, msg_abrt, sizeof(msg_abrt) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(134);
            break;

        case SIGFPE:
            SIGNAL_WRITE(STDERR_FILENO, msg_fpe, sizeof(msg_fpe) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(136);
            break;

        case SIGILL:
            SIGNAL_WRITE(STDERR_FILENO, msg_ill, sizeof(msg_ill) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(132);
            break;

        default:
            SIGNAL_WRITE(STDERR_FILENO, msg_def, sizeof(msg_def) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(1);
            break;
    }
}

template<typename T>
void track_global_resource(T resource) {
    std::lock_guard<std::mutex> lock(global_resources_mutex);
    
    if constexpr (std::is_same_v<T, int>) {
        if (resource >= 0) {
            global_raw_sockets.push_back(resource);
        }
    } else if constexpr (std::is_same_v<T, io_uring*>) {
        if (resource != nullptr) {
            global_uring_rings.push_back(resource);
        }
    } else if constexpr (std::is_same_v<T, std::thread*>) {
        if (resource != nullptr) {
            global_worker_threads.push_back(resource);
        }
    }
}

void emergency_cleanup() {
    std::cerr << "Performing emergency cleanup...\n";
    terminate_flag.store(true, std::memory_order_relaxed);
 
    std::vector<int>         sockets_to_close;
    std::vector<io_uring*>   rings_to_exit;
    std::vector<std::thread*> threads_to_join;
 
    {
        std::lock_guard<std::mutex> lock(global_resources_mutex);
        sockets_to_close  = std::move(global_raw_sockets);
        rings_to_exit     = std::move(global_uring_rings);
        threads_to_join   = std::move(global_worker_threads);
        global_raw_sockets.clear();
        global_uring_rings.clear();
        global_worker_threads.clear();
    }
 
    for (int s : sockets_to_close) {
        if (s >= 0) {                          
            int flags = fcntl(s, F_GETFL, 0);
            if (flags != -1) fcntl(s, F_SETFL, flags | O_NONBLOCK);
            shutdown(s, SHUT_RDWR);
            if (close(s) == -1)
                std::cerr << "Failed to close socket " << s << ": "
                          << strerror(errno) << "\n";
            else
                std::cerr << "Closed raw socket: " << s << "\n";
        }
    }
    for (io_uring* ring : rings_to_exit) {
        if (!ring) continue;
        try {
            struct io_uring_cqe* cqe;
            while (io_uring_peek_cqe(ring, &cqe) == 0)
                io_uring_cqe_seen(ring, cqe);
            io_uring_queue_exit(ring);
            delete ring;
            std::cerr << "Exited io_uring ring\n";
        } catch (const std::exception& e) {
            std::cerr << "Error exiting io_uring ring: " << e.what() << "\n";
        }
    }
    // NEW (REPLACE WITH THIS):
for (std::thread* t : threads_to_join) {
    if (!t) continue;
    try {
        if (t->joinable()) {
            std::cerr << "Joining worker thread (timeout: 2s)...\n";
            auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(2);
            bool joined = false;

            // pthread_tryjoin_np actually checks whether the underlying OS
            // thread has finished. joinable() only tracks whether *this*
            // std::thread object still owns an un-joined handle — it says
            // nothing about whether the thread function has returned, which
            // is why the old loop always slept out the full 2s regardless.
            while (!joined && std::chrono::steady_clock::now() < deadline) {
                int rc = pthread_tryjoin_np(t->native_handle(), nullptr);
                if (rc == 0) { joined = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            if (joined) {
                // pthread_tryjoin_np already reaped the thread via the raw
                // pthread API; tell std::thread to forget its handle
                // without calling its own join() on an already-joined
                // native handle (that would be undefined behavior).
                t->detach();
                std::cerr << "Worker thread joined successfully\n";
            } else {
                // Still running after 2s: do NOT call a blocking join()
                // here — that reintroduces the exact hang this cleanup
                // path exists to avoid. Detach and let the OS reclaim it
                // on process exit instead.
                t->detach();
                std::cerr << "Worker thread did not finish within 2s — detached\n";
            }
        } else {
            std::cerr << "Thread not joinable, skipping\n";
        }
        delete t;
    } catch (const std::exception& e) {
        std::cerr << "Error cleaning up thread: " << e.what() << "\n";
        delete t;
    }
}
 
    std::cerr << "Emergency cleanup completed\n";
}
 

void thread_worker(const std::vector<std::string>& thread_ips, const std::vector<int>& ports, 
                   PacketBufferPool& pool, int send_sock, std::vector<RecPross>& results, size_t main_batch_size, 
                   uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered, 
                   bool print_filtered_if_few, bool fast_scan, std::atomic<int>& down_hosts_count, ScanType scan_type, 
                   uint8_t custom_ttl,uint8_t custom_dscp, uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id, 
                   const TcpBuildOptions& opts,
                   int user_rcvbuf_size, const std::string& source_ip, size_t send_uring_depth, size_t rcv_uring_depth,
                   uint16_t base_source_port, uint16_t retry_source_port, bool debug_packet, bool debug_rtt,bool debug_wsn,bool debug_ttl,bool debug_demux,bool debug_strack,bool debug_send,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,const SportRangeConfig& sport_range_cfg,const GsportConfig& gsport_cfg,int initial_rtt_ms,int port_timeout_min_ms, int
                   port_timeout_max_ms,RateConfig rate_config,JitterConfig jitter_config,BatchDelayConfig batch_delay_config,
                   BandwidthConfig bandwidth_config, bool is_threaded,
                   GlobalRecvCtx* g_recv, GlobalSendCtx* g_send, const std::string& user_interface,
                   const EthArpOptions& eth_opts,const std::unordered_map<uint32_t, std::string>& pre_resolved_arp_cache,
                   bool enable_version_detection = false, AllProbes* vprobes = nullptr,
                   const VersionDetectOptions& sv_opts = VersionDetectOptions{}) {
                   
    
    // Local aliases: same names the body below has always used, now backed
    // by the shared opts struct instead of ~29 individual parameters.
    const uint8_t&     window_scale            = opts.window_scale;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;

    // NEW:
    std::random_device rd;
    thread_local std::mt19937 rng(rd() + std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::uniform_int_distribution<uint16_t> port_dist(1, 65535); 
    if (!g_recv || !g_recv->valid) {
        std::cerr << "[thread_worker] g_recv not initialised — aborting\n";
        return;
    }
    if (!g_send || !g_send->valid) {
        std::cerr << "[thread_worker] g_send not initialised — aborting\n";
        return;
    }
    struct io_uring* send_ring_ptr = &g_send->ring;
    int send_sock6 = g_send->sock6;   // -1 if this batch has no IPv6 targets
    std::string interface = user_interface;   // honor --interface if user gave one
    uint8_t src_ip_bytes[4] = {0}, netmask[4] = {0};
    bool arp_initialized = false;
    uint32_t src_ip_int = 0, netmask_int = 0;
    
    if (!thread_ips.empty()) {
        if (get_ip_version(thread_ips[0].c_str()) == 6) {
            // IPv6 has no ARP layer — there's no same-subnet L2 fast path
            // to set up here (that's ARP-only, see below), just interface
            // autodetection so --interface isn't required for v6 scans.
            if (interface.empty()) {
                uint8_t local_ip6[16];
                if (get_local_ip6(thread_ips[0].c_str(), local_ip6)) {
                    struct in6_addr addr6{};
                    memcpy(&addr6, local_ip6, 16);
                    interface = autodetect_interface(addr6);
                }
            }
        } else {
            int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (temp_sock >= 0) {
                uint32_t local_ip = get_local_ip(thread_ips[0].c_str());
                if (local_ip != 0) {
                    if (interface.empty()) interface = autodetect_interface(local_ip);
                    memcpy(src_ip_bytes, &local_ip, 4);
                    int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
                    if (arp_sock >= 0) {
                        if (get_interface_ip_and_netmask(arp_sock, interface.c_str(), src_ip_bytes, netmask)) {
                            arp_initialized = true;
                            memcpy(&src_ip_int, src_ip_bytes, 4);
                            memcpy(&netmask_int, netmask, 4);
                        }
                        close(arp_sock);
                    }
                }
                close(temp_sock);
            }
        }
    }
    
    std::unordered_map<uint32_t, std::string> thread_arp_cache;
    // IPs for which this thread installed a static kernel ARP entry (via
    // --dst-mac / --ether-dst-multicast) — removed again before the thread
    // exits so the scan doesn't leave stale entries in the host's ARP table.
    std::vector<std::array<uint8_t, 4>> statically_arped_ips;
    bool multi_ip = (thread_ips.size() > 1);
    std::unordered_set<uint32_t> counted_down_ips;
    // NEW:
    std::vector<std::unique_ptr<uint8_t[]>> same_subnet_target_ips;
    std::vector<uint32_t> same_subnet_ip_ints;
    std::vector<size_t> same_subnet_indices;
    for (size_t i = 0; i < thread_ips.size(); ++i) {
        const auto& ip_str = thread_ips[i];
        uint8_t target_ip_bytes[4] = {0};
        if (inet_pton(AF_INET, ip_str.c_str(), target_ip_bytes) > 0) {
            uint32_t target_ip_int;
            memcpy(&target_ip_int, target_ip_bytes, 4);

            auto cached = pre_resolved_arp_cache.find(target_ip_int);
            if (cached != pre_resolved_arp_cache.end()) {
                // -sn already resolved this host — trust it, don't re-ARP.
                thread_arp_cache[target_ip_int] = cached->second;
                results[i].mac_address = cached->second;
                continue;
            }

            if (arp_initialized && is_same_subnet(target_ip_int, src_ip_int, netmask_int)) {
                auto ip_buf = std::make_unique<uint8_t[]>(4);
                memcpy(ip_buf.get(), target_ip_bytes, 4);
                same_subnet_target_ips.push_back(std::move(ip_buf));
                same_subnet_ip_ints.push_back(target_ip_int);
                same_subnet_indices.push_back(i);
            }
        }
    }
    if (eth_opts.use_custom_dst_mac) {
        // Item 3: user supplied a fixed destination MAC — skip ARP resolution
        // entirely for same-subnet targets and use it directly.
        //
        // "Use it directly" has to mean something the kernel's own L2 code
        // will honor, since actual TCP packets go out through the
        // IPPROTO_RAW/IP_HDRINCL socket in main.cpp, where the kernel (not
        // this program) builds the Ethernet header from its neighbour
        // table. So instead of only recording the MAC for display, pin a
        // permanent, completed neighbour entry for each target IP: the
        // kernel then addresses every frame to that IP straight at
        // custom_dst_mac and never issues a real ARP request for it.
        std::string mac_str = format_mac(eth_opts.custom_dst_mac);
        for (size_t j = 0; j < same_subnet_target_ips.size(); ++j) {
            uint32_t ip_val;
            memcpy(&ip_val, same_subnet_target_ips[j].get(), 4);
            thread_arp_cache[ip_val] = mac_str;
            results[same_subnet_indices[j]].mac_address = mac_str;

            std::array<uint8_t, 4> ip_arr{};
            memcpy(ip_arr.data(), same_subnet_target_ips[j].get(), 4);

            if (set_static_arp_entry(interface.c_str(), ip_arr.data(), eth_opts.custom_dst_mac)) {
                statically_arped_ips.push_back(ip_arr);
            } else {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << color::yellow << "[--dst-mac] " << color::reset
                          << "Could not pin a static ARP entry for this target "
                             "(needs root/CAP_NET_ADMIN); traffic may still use "
                             "the kernel's real ARP resolution instead of the "
                             "requested MAC.\n";
            }
        }
        same_subnet_target_ips.clear();   // prevents the ARP block below from re-running
    }
    
    if (!same_subnet_target_ips.empty()) {
        int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sock >= 0) {
            struct io_uring arp_ring;
            if (io_uring_queue_init(512, &arp_ring, IORING_SETUP_COOP_TASKRUN) == 0) {
                uint8_t src_mac[6] = {0};
                if (get_interface_mac(arp_sock, interface.c_str(), src_mac)) {
                    // Same batching strategy as -sn: ARP_BATCH_SIZE hosts per
                    // send+receive cycle, each batch gets its own adaptive
                    // timeout/retry budget instead of one shared deadline
                    // across the whole subnet.
                    constexpr size_t ARP_BATCH_SIZE = 63;
                    const size_t total_arp_targets = same_subnet_target_ips.size();

                    for (size_t batch_start = 0; batch_start < total_arp_targets; batch_start += ARP_BATCH_SIZE) {
                        const size_t batch_end = std::min(batch_start + ARP_BATCH_SIZE, total_arp_targets);
                        const size_t this_batch_size = batch_end - batch_start;   // last batch can be < 63

                        std::vector<std::unique_ptr<uint8_t[]>> mac_buffers;
                        mac_buffers.reserve(this_batch_size);
                        for (size_t j = 0; j < this_batch_size; ++j) {
                            auto mac_buf = std::make_unique<uint8_t[]>(6);
                            memset(mac_buf.get(), 0, 6);
                            mac_buffers.push_back(std::move(mac_buf));
                        }

                        bool has_localhost = false;
                        for (size_t j = batch_start; j < batch_end; ++j) {
                            uint32_t ip_val;
                            memcpy(&ip_val, same_subnet_target_ips[j].get(), 4);
                            if (ip_val == htonl(0x7F000001)) {
                                has_localhost = true;
                                break;
                            }
                        }

                        std::vector<uint8_t*> raw_target_ips;
                        raw_target_ips.reserve(this_batch_size);
                        for (size_t j = batch_start; j < batch_end; ++j) {
                            raw_target_ips.push_back(same_subnet_target_ips[j].get());
                        }

                        if (send_arp_request(arp_sock, &arp_ring, interface.c_str(), src_mac,
                                             src_ip_bytes, raw_target_ips, eth_opts)) {

                            std::vector<uint8_t*> raw_mac_buffers;
                            raw_mac_buffers.reserve(mac_buffers.size());
                            for (const auto& buf : mac_buffers) {
                                raw_mac_buffers.push_back(buf.get());
                            }

                            if (!has_localhost) {
                                receive_arp_reply(arp_sock, &arp_ring, raw_target_ips,
                                                  raw_mac_buffers, eth_opts, /*initial_rtt_ms=*/150,
                                                  interface.c_str(), src_mac, src_ip_bytes,
                                                  /*max_retries=*/2);
                            } else {
                                for (size_t j = 0; j < this_batch_size; ++j) {
                                    uint32_t ip_val;
                                    memcpy(&ip_val, same_subnet_target_ips[batch_start + j].get(), 4);
                                    if (ip_val == htonl(0x7F000001)) {
                                        uint8_t fake_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
                                        memcpy(mac_buffers[j].get(), fake_mac, 6);
                                    }
                                }
                                // Drain any ARP replies that arrived for real IPs
                                // in this batch, waking immediately on the first
                                // reply rather than after a fixed 10 ms sleep.
                                struct io_uring_cqe* arp_cqe = nullptr;
                                struct __kernel_timespec arp_ts = {
                                    .tv_sec  = 0,
                                    .tv_nsec = 10 * 1000 * 1000   // 10 ms max
                                };
                                if (io_uring_wait_cqe_timeout(&arp_ring, &arp_cqe, &arp_ts) == 0
                                    && arp_cqe) {
                                    io_uring_cqe_seen(&arp_ring, arp_cqe);
                                }
                            }

                            for (size_t j = 0; j < this_batch_size; ++j) {
                                size_t global_j = batch_start + j;
                                uint32_t target_ip_int = same_subnet_ip_ints[global_j];
                                size_t original_index = same_subnet_indices[global_j];
                                bool mac_resolved = (mac_buffers[j][0] != 0 || mac_buffers[j][1] != 0 ||
                                                    mac_buffers[j][2] != 0 || mac_buffers[j][3] != 0 ||
                                                    mac_buffers[j][4] != 0 || mac_buffers[j][5] != 0);

                                if (mac_resolved) {
                                    std::string mac_address = format_mac(mac_buffers[j].get());
                                    thread_arp_cache[target_ip_int] = mac_address;
                                    results[original_index].mac_address = mac_address;
                                } else {
                                    counted_down_ips.insert(target_ip_int);
                                    down_hosts_count++;
                                }
                            }
                        }
                    }
                }
                io_uring_queue_exit(&arp_ring);
            }
            close(arp_sock);
        }
    }
    
    static const std::unordered_map<ScanType, std::string> scan_names = {
        {ScanType::SYN, "SYN"}, {ScanType::FIN, "FIN"}, {ScanType::ACK, "ACK"},
        {ScanType::NULL_SCAN, "NULL"}, {ScanType::XMAS, "XMAS"}, {ScanType::WINDOW, "WINDOW"},
        {ScanType::MAIMON, "MAIMON"}, {ScanType::CWR, "CWR"}, {ScanType::ECE, "ECE"},
        {ScanType::URG, "URG"}, {ScanType::PSH, "PSH"}, {ScanType::HANUMAN, "HANUMAN"},
        {ScanType::KAKABHUSUNDI, "KAKABHUSUNDI"}, {ScanType::GANESH, "GANESH"},
        {ScanType::RAM, "RAM"}, {ScanType::GARUD, "GARUD"}, {ScanType::JATAYU, "JATAYU"}
    };
    std::string scan_name = scan_names.count(scan_type) ? scan_names.at(scan_type) : "UNKNOWN";
    
    if (multi_ip && !thread_ips.empty()) {
        print_output(PrintOutputType::OVERALL_HEADER, "", thread_ips.size(), 
                     fast_scan ? "fast" : "graceful", "", scan_name,
                     0, ports.size(), 0, 0, 0, thread_ips.size(), "", "", 0.0, "", true, true);
       
        if (use_tfo_cookie) {
            std::string tfo_info = "TFO cookie: ";
            if (tfo_cookie_random) {
                tfo_info += "random(" + std::to_string(tfo_cookie_length) + " bytes)";
            } else if (tfo_cookie_as_hex) {
                tfo_info += "hex(" + tfo_cookie_str + ")";
            } else if (!tfo_cookie_str.empty()) {
                tfo_info += "str(" + tfo_cookie_str + ")";
            } else if (tfo_cookie_num > 0) {
                tfo_info += "num(" + std::to_string(tfo_cookie_num) + ")";
            } else {
                tfo_info += "default(8 bytes)";
            }
            std::cout << tfo_info << std::endl;
        }
    }
    
    std::uniform_int_distribution<uint16_t> ephemeral_dist(32768, 60999);
    
    for (size_t i = 0; i < thread_ips.size() && !terminate_flag; ++i) {
        const auto& ip_str = thread_ips[i];
        uint16_t source_port = (base_source_port > 0) ? base_source_port : 0;
        int ip_version = get_ip_version(ip_str.c_str());
        if (ip_version != 4 && ip_version != 6) {
            std::cerr << "Invalid target IP address: " << ip_str << std::endl;
            continue;
        }
        reset_network_disconnect_flag();

        // local_ip (v4, 0.0.0.0-typed) is only meaningful on the v4 path —
        // worker_thread/receive_response take it as a plain uint32_t and
        // it's unused for IPv6 tasks (those source from the destination
        // socket's own routing, same as every other v6 raw-socket path in
        // this codebase). same_subnet/ARP is IPv4-only for the same reason
        // stated in the preamble above: IPv6 has no ARP layer.
        uint32_t local_ip = 0;

        uint8_t local_ip6[16] = {0};
        const uint8_t* local_ip6_ptr = nullptr;
        if (ip_version == 6) {
            if (!get_local_ip6(ip_str.c_str(), local_ip6)) {
                std::cerr << "Failed to determine local IPv6 address for " << ip_str << ".\n";
                continue;
            }
            local_ip6_ptr = local_ip6;
            if (interface.empty()) {
                struct in6_addr addr6{};
                memcpy(&addr6, local_ip6, 16);
                interface = autodetect_interface(addr6);
            }
        } else {
            local_ip = get_local_ip(ip_str.c_str());
            if (local_ip == 0) {
                std::cerr << "Failed to determine local IP address for " << ip_str << ".\n";
                continue;
            }

            if (interface.empty()) {
                interface = autodetect_interface(local_ip);
            }

            uint8_t target_ip_bytes[4] = {0};
            if (inet_pton(AF_INET, ip_str.c_str(), target_ip_bytes) <= 0) {
                std::cerr << "Invalid target IP address: " << ip_str << std::endl;
                continue;
            }

            uint32_t target_ip_int;
            memcpy(&target_ip_int, target_ip_bytes, 4);

            if (counted_down_ips.find(target_ip_int) != counted_down_ips.end()) {
                continue;
            }

            bool is_same_subnet_ip = arp_initialized && is_same_subnet(target_ip_int, src_ip_int, netmask_int);
            if (is_same_subnet_ip) {
                auto it = std::find(same_subnet_ip_ints.begin(), same_subnet_ip_ints.end(), target_ip_int);
                if (it != same_subnet_ip_ints.end()) {
                    size_t arp_index = std::distance(same_subnet_ip_ints.begin(), it);
                    size_t original_index = same_subnet_indices[arp_index];
                    if (results[original_index].mac_address.empty()) {
                        continue;
                    }
                }
            }
        }

        
        if (!multi_ip) {
            print_output(PrintOutputType::SCAN_HEADER, ip_str, 0, "", "", scan_name,
                         0, 0, 0, 0, 0, 0, "", "", 0.0, "", true, true);
           
            if (use_tfo_cookie) {
                std::string tfo_info = "TFO cookie: " + 
                   (tfo_cookie_random   ? "random(" + std::to_string(tfo_cookie_length) + " bytes)" :
                    tfo_cookie_as_hex   ? "hex(" + tfo_cookie_str + ")" :
                    !tfo_cookie_str.empty() ? "str(" + tfo_cookie_str + ")" :
                    tfo_cookie_num > 0  ? "num(" + std::to_string(tfo_cookie_num) + ")" :
                               "default(8 bytes)");
                std::cout << tfo_info << std::endl;
             }
        }  
        
            print_output(PrintOutputType::HOST_HEADER, ip_str);
            print_output(PrintOutputType::PORT_TABLE_HEADER);
        
        auto scan_start_time = std::chrono::steady_clock::now();
        // CPU-time snapshot alongside the wall-clock one: Duration (below)
        // answers "how long did the user wait", CPU Time answers "how much
        // processor work did this cost" — they're independent axes and can
        // move in opposite directions (e.g. SQPOLL can hold Duration flat
        // while inflating CPU Time via a spinning poller thread).
        // RUSAGE_SELF aggregates all threads in the process on Linux, so
        // this correctly captures the worker threads spawned below, not
        // just the calling thread.
        struct rusage ru_scan_start{};
        getrusage(RUSAGE_SELF, &ru_scan_start);

        worker_thread(ip_str.c_str(), local_ip, source_ip.c_str(), ports, rng, pool, send_sock,
	     results[i], main_batch_size, seq_num, win_size, ip_version, print_individual_closed_filtered, print_filtered_if_few, send_ring_ptr, fast_scan,
	     scan_type, custom_ttl, custom_dscp,custom_ip_flags, ip_id_mode, fixed_ip_id,
	     opts,
	     user_rcvbuf_size, send_uring_depth, rcv_uring_depth, 
	     source_port, retry_source_port, debug_packet, debug_rtt,debug_wsn,debug_ttl,debug_demux,debug_strack,debug_send,frag_out_of_order,frag_overlap,frag_overlap_bytes,frag_zof,sport_range_cfg,gsport_cfg,initial_rtt_ms, port_timeout_min_ms, port_timeout_max_ms,rate_config,jitter_config,batch_delay_config,bandwidth_config,
	     is_threaded,g_recv, send_sock6, local_ip6_ptr);
	// Adaptive inter-target sync: drain any leftover in-flight send-ring
        // CQEs from this target before the next target's probes begin, so
        // residual NIC/queue backlog doesn't bleed into the next target's
        // window. Costs ~0ms if the ring is already drained; bounded so a
        // stuck ring can't stall the whole scan.
        if (send_ring_ptr) {
            io_uring_submit(send_ring_ptr);
            constexpr int DRAIN_CAP_MS = 100;
            auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(DRAIN_CAP_MS);
            while (std::chrono::steady_clock::now() < drain_deadline) {
                struct io_uring_cqe* cqe = nullptr;
                struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
                int ret = io_uring_wait_cqe_timeout(send_ring_ptr, &cqe, &ts);
                if (ret == -ETIME) break;       // ring is quiet
                if (ret < 0) break;
                if (cqe) io_uring_cqe_seen(send_ring_ptr, cqe);
            }
        }

        RecPross& result = results[i];
        const auto& service_map = read_services_from_file("services");
        std::string not_shown_message;
        if (result.closed_ports > 0 && !print_individual_closed_filtered) {
            not_shown_message += std::to_string(result.closed_ports) + " closed tcp ports (reset)";
        }
        if (result.filtered_ports.size() > 4) {
            if (!not_shown_message.empty()) {
                not_shown_message += " | ";
            }
            std::string state_desc = "filtered";
            if (PacketTask::expects_rst_response(scan_type)) {
                state_desc = "confused";
            }
            not_shown_message += std::to_string(result.filtered_ports.size()) + " tcp ports " + state_desc + " (no response)";
        }

        // A host with zero open ports prints nothing under PORT/STATE/SERVICE,
        // which reads as broken output rather than "nothing open here". Show
        // a small, real sample instead, then shrink Not-shown by whatever we
        // displayed so the counts underneath still add up.
        //   - filtered AND closed both present -> 3 filtered + 2 closed
        //   - filtered only                    -> 5 filtered
        //   - closed only                      -> 5 closed
        if (result.open_ports.empty() && !print_individual_closed_filtered) {
            bool has_filtered = !result.filtered_ports.empty();
            bool has_closed   = result.closed_ports > 0;

            int want_filtered = has_filtered && has_closed ? 3 : (has_filtered ? 5 : 0);
            int want_closed   = has_filtered && has_closed ? 2 : (has_closed ? 5 : 0);

            // Preference order for which sample ports to show: known service
            // name first (and within those, the well-known 21-1023 range
            // first), THEN whatever's left with an unknown service — so a
            // host with 15 known + 5 unknown out of 20 shows the 15 known
            // ones before ever falling back to "unknown".
            auto rank = [&](uint16_t p) -> int {
                bool known    = service_map.count(p) && service_map.at(p) != "unknown";
                bool wellknown = p >= 21 && p <= 1023;
                if (known && wellknown) return 0;
                if (known)              return 1;
                return 2;   // unknown service, last resort
            };

            std::vector<uint16_t> filtered_sorted = result.filtered_ports;
            std::stable_sort(filtered_sorted.begin(), filtered_sorted.end(),
                [&](uint16_t a, uint16_t b) { return rank(a) < rank(b); });

            int shown_filtered = 0;
            for (size_t idx = 0; idx < filtered_sorted.size() && shown_filtered < want_filtered; ++idx, ++shown_filtered) {
                uint16_t p = filtered_sorted[idx];
                std::string svc = service_map.count(p) ? service_map.at(p) : "unknown";
                print_output(PrintOutputType::PORT_RESULT, "", p, "filtered", svc, scan_name,
                             0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
            }

            // closed_ports is only ever a count — no port list is kept for it —
            // but every port that got an RST is still sitting in packet_details
            // keyed by port number, so pull real port numbers back out of there.
            int shown_closed = 0;
            if (want_closed > 0) {
                std::vector<uint16_t> closed_candidates;
                for (const auto& [p, details] : result.packet_details) {
                    bool is_open = std::find(result.open_ports.begin(), result.open_ports.end(), p) != result.open_ports.end();
                    bool is_filt = std::find(result.filtered_ports.begin(), result.filtered_ports.end(), p) != result.filtered_ports.end();
                    if (is_open || is_filt) continue;
                    if (!(details.tcp_flags & TH_RST)) continue;
                    closed_candidates.push_back(p);
                }
                std::stable_sort(closed_candidates.begin(), closed_candidates.end(),
                    [&](uint16_t a, uint16_t b) { return rank(a) < rank(b); });

                for (size_t idx = 0; idx < closed_candidates.size() && shown_closed < want_closed; ++idx, ++shown_closed) {
                    uint16_t p = closed_candidates[idx];
                    std::string svc = service_map.count(p) ? service_map.at(p) : "unknown";
                    print_output(PrintOutputType::PORT_RESULT, "", p, "closed", svc, scan_name,
                                 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                }
            }

            }

        // "Packets sent" moved here from worker_thread() (scan.cpp) so it
        // prints after the sample port lines above, not before them.
        {
            std::string layer3_reason;
            for (uint16_t fport : result.filtered_ports) {
                auto rit = result.icmp_filter_reasons.find(fport);
                if (rit != result.icmp_filter_reasons.end()) {
                    std::string icmp_note;
                    switch (rit->second) {
                        case IcmpFilterReason::NetAdminProhibited:
                            icmp_note = "Net-admin-prohibited"
                                        " (" + color::red + "ACL/router policy blocks subnet" + color::reset + ")";
                            break;
                        case IcmpFilterReason::HostAdminProhibited:
                            icmp_note = "Host-admin-prohibited"
                                        " (" + color::red + "host firewall/ACL denies this IP" + color::reset + ")";
                            break;
                        case IcmpFilterReason::CommAdminProhibited:
                            icmp_note = "Comm-admin-prohibited"
                                        " (" + color::red + "iptables REJECT / firewall policy" + color::reset + ")";
                            break;
                        default:
                            break;
                    }
                    if (!icmp_note.empty()) {
                        layer3_reason = "Reason         : " + icmp_note
                                      + " (port " + std::to_string(fport) + ")\n";
                    }
                    break;
                }
            }
            if (!result.icmp_warnings.empty()) {
                std::unordered_set<int> seen_w;
                for (auto& [wr, wmsg] : result.icmp_warnings) {
                    if (seen_w.insert(static_cast<int>(wr)).second) {
                        layer3_reason += "Warning        : "
                                       + color::yellow + wmsg + color::reset + "\n";
                    }
                }
            }
            std::cout << "\n" << layer3_reason
                      << "Packets sent   : " << result.packets_sent << "\n";
        }

        if (!result.mac_address.empty()) {
            std::string vendor = get_mac_vendor(result.mac_address);
            
                print_output(PrintOutputType::MAC_ADDRESS, "", 0, "", "", "",
                             0, 0, 0, 0, 0, 0, result.mac_address, vendor, 0.0, "", false, true);
            
        }
        if (!not_shown_message.empty()) {
            
                print_output(PrintOutputType::NOT_SHOWN_MESSAGE, "", 0, "", "", "",
                             0, 0, 0, 0, 0, 0, "", "", 0.0, not_shown_message, false, true);
            
        }
        if (!terminate_flag) {
	    auto scan_end_time = std::chrono::steady_clock::now();
	    double elapsed_seconds = std::chrono::duration_cast<std::chrono::milliseconds>(
		scan_end_time - scan_start_time).count() / 1000.0;

	    bool has_rtt = (result.learned_rtt_ms > 0);
           
                print_output(PrintOutputType::SCAN_TIMING, "", has_rtt ? 1 : 0, "", "", "",
                             0, ports.size(), 0, 0, 0, 0, "", "", elapsed_seconds, "", false, true);

            struct rusage ru_scan_end{};
            getrusage(RUSAGE_SELF, &ru_scan_end);
            double cpu_seconds =
                (ru_scan_end.ru_utime.tv_sec  - ru_scan_start.ru_utime.tv_sec)  +
                (ru_scan_end.ru_utime.tv_usec - ru_scan_start.ru_utime.tv_usec) / 1e6 +
                (ru_scan_end.ru_stime.tv_sec  - ru_scan_start.ru_stime.tv_sec)  +
                (ru_scan_end.ru_stime.tv_usec - ru_scan_start.ru_stime.tv_usec) / 1e6;
            print_output(PrintOutputType::CPU_TIME, "", 0, "", "", "",
                         0, 0, 0, 0, 0, 0, "", "", cpu_seconds, "", false, true);
           

	    if (has_rtt) {
                   
                    print_output(PrintOutputType::RTT_INFO, "", 0, "", "", "",
                                 0, 0, 0, 0, 0, 0, "", "",
                                 static_cast<double>(result.learned_rtt_ms), "", false, true);
                
            } else {
                
                    print_output(PrintOutputType::RTT_INFO, "", 0, "", "", "",
                                 0, 0, 0, 0, 0, 0, "", "",
                                 0.0, "", false, true);
                
            }
	    if (!multi_ip) {
	        if (debug_rtt && !result.rtt_debug_entries.empty()) {
		    std::lock_guard<std::mutex> lock(cout_mutex);
		    std::cout << "\nRTT Debug      : \n";

		    const auto& entries = result.rtt_debug_entries;
		    const size_t INLINE_THRESHOLD = 10;

		    // Build a set of open ports for quick lookup
		    std::unordered_set<int> open_set;
		    for (const auto& op : result.open_ports) {
		        open_set.insert(static_cast<int>(op));
		    }

		// Separate open and non-open entries
		    std::vector<std::pair<int,double>> open_entries, other_entries;
		    for (const auto& e : entries) {
		        if (open_set.count(e.first)) {
		            open_entries.push_back(e);
		        } else {
		            other_entries.push_back(e);
		        }
		    }

		    // Always print open ports individually with [open] state
		    for (size_t i = 0; i < open_entries.size(); ++i) {
		        bool last_open = (i == open_entries.size() - 1) && other_entries.empty();
		        int rtt_int = static_cast<int>(open_entries[i].second);
		        if (open_entries[i].second > 0 && rtt_int == 0) rtt_int = 1;
		    
		        std::cout << "    " << color::green << std::left << std::setw(7) << "open" << color::reset
		                  << " " << std::setw(10) << (std::to_string(open_entries[i].first) + "/tcp")
		                  << ": ewma=" << std::fixed << std::setprecision(3)
		                  << open_entries[i].second << "ms → int=" << rtt_int << "ms\n";
		    }

		    // Now handle the remaining (closed/filtered) entries
		    if (!other_entries.empty()) {
		        if (other_entries.size() <= INLINE_THRESHOLD) {
		            // Few enough — print individually
		            for (size_t i = 0; i < other_entries.size(); ++i) {
		                bool last = (i == other_entries.size() - 1);
		                int rtt_int = static_cast<int>(other_entries[i].second);
		                if (other_entries[i].second > 0 && rtt_int == 0) rtt_int = 1;
		            
		                std::cout << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
		                          << " " << std::setw(10) << (std::to_string(other_entries[i].first) + "/tcp")
		                          << ": ewma=" << std::fixed << std::setprecision(3)
		                          << other_entries[i].second << "ms → int=" << rtt_int << "ms\n";
		            }
		        } else {
		            // Too many — summarize closed ports
		            double min_rtt = other_entries[0].second, 
		                   max_rtt = other_entries[0].second, 
		                   sum_rtt = 0.0;
		            int min_port = other_entries[0].first, 
		                max_port = other_entries[0].first;

		            for (const auto& e : other_entries) {
		                if (e.second < min_rtt) { 
		                    min_rtt = e.second; 
		                    min_port = e.first; 
		                }
		                if (e.second > max_rtt) { 
		                    max_rtt = e.second; 
		                    max_port = e.first; 
		                }
		                sum_rtt += e.second;
		            }
		            double avg_rtt = sum_rtt / static_cast<double>(other_entries.size());

		            int avg_port = other_entries[0].first;
		            double avg_closest = other_entries[0].second;
		            double best_delta = std::abs(other_entries[0].second - avg_rtt);
		            for (const auto& e : other_entries) {
		                double delta = std::abs(e.second - avg_rtt);
		                if (delta < best_delta) { 
		                    best_delta = delta; 
		                    avg_port = e.first; 
		                    avg_closest = e.second; 
		                }
		            }

		            int min_int = static_cast<int>(min_rtt); 
		            if (min_rtt > 0 && min_int == 0) min_int = 1;
		            int max_int = static_cast<int>(max_rtt); 
		            if (max_rtt > 0 && max_int == 0) max_int = 1;
		            int avg_int = static_cast<int>(avg_closest); 
		            if (avg_closest > 0 && avg_int == 0) avg_int = 1;

		            std::cout << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
		                      << " " << other_entries.size() << " ports sampled\n";
		            std::cout << "    Min ewma       "
		                      << " " << std::setw(10) << (std::to_string(min_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << min_rtt << "ms"
		                      << " → int=" << min_int << "ms\n";
		            std::cout << "    Avg ewma       "
		                      << " " << std::setw(10) << (std::to_string(avg_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << avg_closest << "ms"
		                      << " → int=" << avg_int << "ms\n";
		            std::cout << "    Max ewma       "
		                      << " " << std::setw(10) << (std::to_string(max_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << max_rtt << "ms"
		                      << " → int=" << max_int << "ms\n";
		        }
		    }
	        }
	    }
	    if (debug_send && !sent_debug_log.empty()) {
                flush_sent_packet_debug();
            }

            // --debug demux: printed once here, after RTT info and before

            // --debug demux: printed once here, after RTT info and before
            // TTL/packet/WSN debug output, using the WHOLE-SCAN totals
            // thread_worker() already merged into `result` batch-by-batch.
            // Unlike the debug_rtt block above, this is NOT gated by
            // `!multi_ip` — it belongs to this specific target's block in
            // the per-target loop, so it prints correctly (once, in the
            // right place, never interleaved with another target's lines)
            // whether the scan has one target or many.
            if (debug_demux && !result.demux_debug_entries.empty()) {
                print_demux_debug(ip_str, result.demux_debug_entries, result.demux_counts, result.open_ports);
            }
            if (debug_strack && (!result.strack_entries.empty() || result.strack_counts.unresolved > 0)) {
                print_strack_debug(ip_str, result.strack_entries, result.strack_counts);
            }

            if (debug_ttl && result.received_ttl > 0) {
                display_ttl_analysis(
                  result.rtt_debug_entries,
                  custom_ttl,
                  result.received_ttl,
                  ip_str.c_str(),
                  !result.open_ports.empty() || result.closed_ports > 0
                );
            }
                         
            if (!result.packet_details.empty() && !terminate_flag && debug_packet) {
                for (const auto& pair : result.packet_details) {
                    display_packet_details(pair.second, debug_packet);
                }
            }

            if (!result.packet_details.empty() && !terminate_flag && debug_wsn) {
                display_wsn_analysis(result.packet_details, window_scale);
            }

            // ── -sV: version-probe this host's open ports right here, so the
            // output lands inside this host's own report block, before the
            // multi-host separator — not as a separate pass at the very end.
            if (enable_version_detection && vprobes && !terminate_flag
	        && !result.open_ports.empty()) {
	        std::cout << std::left << std::setw(9) << "\nPORT" << "VERSION\n";

	    // Bounded-concurrency dispatch: cap in-flight version probes per host
	    // so we don't spawn one OS thread per open port on hosts with hundreds
	    // open. The actual socket I/O for each probe is already handled by
	    // async_io's shared reactor, so this cap just limits how many
	    // run_version_probe() calls (staging/matching logic) run at once.
	        constexpr size_t kMaxConcurrentProbes = 16;
	        std::vector<std::future<void>> inflight;

	        for (uint16_t port : result.open_ports) {
		    if (terminate_flag) break;

		    inflight.push_back(std::async(std::launch::async,
		        [vprobes, ip_str, port, sv_opts]() {
		            if (terminate_flag) return;
		            run_version_probe(*vprobes, ip_str, port, sv_opts);
		        }));
 
		    if (inflight.size() >= kMaxConcurrentProbes) {
		        for (auto &f : inflight) f.get();
		        inflight.clear();
		    }
	        }
	        for (auto &f : inflight) f.get();   // drain stragglers
	    }
        }
        
        if (multi_ip && i < thread_ips.size() - 1) {
                print_output(PrintOutputType::MULTI_IP_SEPARATOR);
            
        }
    }
    
    if (multi_ip && !thread_ips.empty() && !terminate_flag) {
        int total_open = 0;
        int total_closed = 0;
        int total_filtered = 0;
        uint64_t total_packets_sent = 0;
        for (const auto& result : results) {
            total_open += result.open_ports.size();
            total_closed += result.closed_ports;
            total_filtered += result.filtered_ports.size();
        }
        
        print_output(PrintOutputType::THREAD_SUMMARY, "", 0, "", "", scan_name,
                     0, 0, total_open, total_closed, total_filtered, thread_ips.size(), 
                     "", "", 0.0, "", false, true);
    }
    if (!counted_down_ips.empty() && multi_ip) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << counted_down_ips.size();
    }

    for (const auto& ip_arr : statically_arped_ips) {
        delete_static_arp_entry(interface.c_str(), ip_arr.data());
    }
}

static void print_full_help() {

	        std::cerr << "                                                   \n";
		std::cerr << color::yellow << "            ॐ त्र्यम्बकं यजामहे सुगन्धिं पुष्टिवर्धनम्।\n" << color::reset;
		std::cerr << color::yellow << "            उर्वारुकमिव बन्धनान्मृत्योर्मुक्षीय मामृतात्।।\n\n" << color::reset;
		
		std::cerr << color::green << "TCP Scan Modes:\n" << color::reset;
		std::cerr << color::green << "---------------\n\n" << color::reset;

		std::cerr << color::green << "Standard Scans:\n" << color::reset;
		std::cerr << color::yellow << " -sS" << color::reset << " SYN Scan (default) " << color::white << "[SYN]" << color::reset << "\n";
		std::cerr << color::yellow << " -sF" << color::reset << " FIN Scan " << color::white << "[FIN]" << color::reset << "\n";
		std::cerr << color::yellow << " -sA" << color::reset << " ACK Scan " << color::white << "[ACK]" << color::reset << "\n";
		std::cerr << color::yellow << " -sN" << color::reset << " NULL Scan (no flags) " << color::white << "[NONE]" << color::reset << "\n";
		std::cerr << color::yellow << " -sX" << color::reset << " XMAS Scan " << color::white << "[FIN, PSH, URG]" << color::reset << "\n";
		std::cerr << color::yellow << " -sW" << color::reset << " Window Scan " << color::white << "[ACK]" << color::reset << "\n";
		std::cerr << color::yellow << " -sM" << color::reset << " Maimon Scan " << color::white << "[FIN, ACK]" << color::reset << "\n";
		std::cerr << color::yellow << " -sCW" << color::reset << " CWR Flag Scan " << color::white << "[CWR]" << color::reset << "\n";
		std::cerr << color::yellow << " -sE" << color::reset << " ECE Flag Scan " << color::white << "[ECE]" << color::reset << "\n";
		std::cerr << color::yellow << " -sUG" << color::reset << " URG Flag Scan " << color::white << "[URG]" << color::reset << "\n";
		std::cerr << color::yellow << " -sPH" << color::reset << " PSH Flag Scan " << color::white << "[PSH]" << color::reset << "\n\n";

		std::cerr << color::green << "Custom / Advanced Scans:\n" << color::reset;
		std::cerr << color::yellow << " -sH" << color::reset << " HANUMAN Scan " << color::white << "[CWR, PSH, URG]" << color::reset << "\n";
		std::cerr << color::yellow << " -sK" << color::reset << " KAKABHUSUNDI Scan " << color::white << "[ECE, SYN, CWR]" << color::reset << "\n";
		std::cerr << color::yellow << " -sG" << color::reset << " GANESH Scan " << color::white << "[SYN, ECE]" << color::reset << "\n";
		std::cerr << color::yellow << " -sR" << color::reset << " RAM Scan " << color::white << "[SYN, CWR, PSH]" << color::reset << "\n";
		std::cerr << color::yellow << " -sD" << color::reset << " GARUD Scan " << color::white << "[SYN, URG, CWR]" << color::reset << "\n";
		std::cerr << color::yellow << " -sJ" << color::reset << " JATAYU Scan " << color::white << "[SYN, CWR]" << color::reset << "\n\n";
		
		std::cerr << color::green << "TCP Headers:\n" << color::reset;
		std::cerr << color::green << "-------------\n\n" << color::reset;

		std::cerr << color::yellow << " --ttl" << color::reset << " <value> Set IP TTL (0-255, default: 64)\n";
		std::cerr << color::yellow << " --ip-flags" << color::reset << " <hex> Set IP fragment flags (fake claim) | (hex, default: 0x4000=DF, 0x2000=MF , 0x0000=no flags)\n";
		std::cerr << color::yellow << " -g" << color::reset << " <port> | N:<port>[,N:<port>...]\n";
		std::cerr << color::yellow << "                             " << color::reset << "<port>       -> fixed source port for the INITIAL send only (default: 443)\n";
		std::cerr << color::yellow << "                             " << color::reset << "N:<port>     -> fixed source port for just attempt N (N=0 initial, 1=1st retry, 2=2nd retry), port must be a single number, not a range\n";
		std::cerr << color::yellow << "                             " << color::reset << "e.g. -g 0:443,1:22,2:8080\n";
		std::cerr << color::yellow << " --sport-range" << color::reset << " <min>-<max> | N:<min>-<max>[,N:<min>-<max>...]\n";
		std::cerr << color::yellow << "                             " << color::reset << "<min>-<max>  -> use this range for ALL 3 send attempts (min must be < max)\n";
		std::cerr << color::yellow << "                             " << color::reset << "N:<min>-<max> -> override just attempt N (N=0 initial, 1=1st retry, 2=2nd retry)\n";
		std::cerr << color::yellow << "                             " << color::reset << "e.g. --sport-range 0:5555-6666,1:7000-8000,2:3333-5555  (leaves attempt 0 at its default 443)\n";
		std::cerr << color::yellow << "                             " << color::reset << "a --sport-range entry for a given attempt overrides that attempt's fixed default port\n";
		std::cerr << color::yellow << " -S" << color::reset << " <ip> Specify source IP address\n";
		std::cerr << color::yellow << " -p" << color::reset << " <port> | <port,port> | port-port\n";
		std::cerr << color::yellow << " --badsum" << color::reset << " | <hex> Send invalid checksum default: auto | --badsum 0xffff\n";
		std::cerr << color::yellow << " --prsum" << color::reset << " Send partial invalid checksum (lower,upper,bitflip,middle,swap,incremental,pattern,rfc1141,seq-tied,port-tied,carry-break,valid-ish,\n";
		std::cerr << "                                                                               null,msb,lsb3,rfc1141,seq-tied,goodbye,timestamp-lie,ones-complement,walking-bit,entropy)\n\n";
		
		std::cerr << color::green << "IP Headers:\n" << color::reset;
		
		std::cerr << color::yellow << "  --dscp" << color::reset << " <value|name> Set IP DSCP/TOS field\n\n";

		std::cerr << color::white << "   Standard/Default:\n" << color::reset;
		std::cerr << "     " << color::yellow << " BE" << color::reset << " or " << color::yellow << "0" << color::reset   << "  # Best Effort (default)\n";
		std::cerr << "     " << color::yellow << " CS1" << color::reset << " or " << color::yellow << "8" << color::reset  << "  # Class Selector 1 (Scavenger)\n";
		std::cerr << "     " << color::yellow << " CS2" << color::reset << " or " << color::yellow << "16" << color::reset << "  # Class Selector 2\n";
		std::cerr << "     " << color::yellow << " CS3" << color::reset << " or " << color::yellow << "24" << color::reset << "  # Class Selector 3\n";
		std::cerr << "     " << color::yellow << " CS4" << color::reset << " or " << color::yellow << "32" << color::reset << "  # Class Selector 4\n";
		std::cerr << "     " << color::yellow << " CS5" << color::reset << " or " << color::yellow << "40" << color::reset << "  # Class Selector 5 (Signaling)\n";
		std::cerr << "     " << color::yellow << " CS6" << color::reset << " or " << color::yellow << "48" << color::reset << "  # Class Selector 6 (Network Control)\n";
		std::cerr << "     " << color::yellow << " CS7" << color::reset << " or " << color::yellow << "56" << color::reset << "  # Class Selector 7\n\n";

		std::cerr << color::white << "   Assured Forwarding (AF):\n" << color::reset;
		std::cerr << "     " << color::yellow << "AF11" << color::reset << " or " << color::yellow << "10" << color::reset << "  # Assured Forwarding 1, Low Drop\n";
		std::cerr << "     " << color::yellow << "AF12" << color::reset << " or " << color::yellow << "12" << color::reset << "  # Assured Forwarding 1, Medium Drop\n";
		std::cerr << "     " << color::yellow << "AF13" << color::reset << " or " << color::yellow << "14" << color::reset << "  # Assured Forwarding 1, High Drop\n";
		std::cerr << "     " << color::yellow << "AF21" << color::reset << " or " << color::yellow << "18" << color::reset << "  # Assured Forwarding 2, Low Drop\n";
		std::cerr << "     " << color::yellow << "AF22" << color::reset << " or " << color::yellow << "20" << color::reset << "  # Assured Forwarding 2, Medium Drop\n";
		std::cerr << "     " << color::yellow << "AF23" << color::reset << " or " << color::yellow << "22" << color::reset << "  # Assured Forwarding 2, High Drop\n";
		std::cerr << "     " << color::yellow << "AF31" << color::reset << " or " << color::yellow << "26" << color::reset << "  # Assured Forwarding 3, Low Drop\n";
		std::cerr << "     " << color::yellow << "AF32" << color::reset << " or " << color::yellow << "28" << color::reset << "  # Assured Forwarding 3, Medium Drop\n";
		std::cerr << "     " << color::yellow << "AF33" << color::reset << " or " << color::yellow << "30" << color::reset << "  # Assured Forwarding 3, High Drop\n";
		std::cerr << "     " << color::yellow << "AF41" << color::reset << " or " << color::yellow << "34" << color::reset << "  # Assured Forwarding 4, Low Drop\n";
		std::cerr << "     " << color::yellow << "AF42" << color::reset << " or " << color::yellow << "36" << color::reset << "  # Assured Forwarding 4, Medium Drop\n";
		std::cerr << "     " << color::yellow << "AF43" << color::reset << " or " << color::yellow << "38" << color::reset << "  # Assured Forwarding 4, High Drop\n\n";

		std::cerr << color::white << "   Expedited Forwarding:\n" << color::reset;
		std::cerr << "     " << color::yellow << "EF" << color::reset << "  or " << color::yellow << "46" << color::reset << "  # Expedited Forwarding (Voice/Video)\n";
		std::cerr << "     " << color::yellow << "VA" << color::reset << "  or " << color::yellow << "44" << color::reset << "  # Voice Admit\n\n";

		std::cerr << color::white << "   Examples:\n" << color::reset;
		std::cerr << "     " << color::yellow << "shiv 192.168.1.1 -p 80 --dscp EF" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv 10.0.0.0/24 -p 1-1000 --dscp AF41" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv example.com -p 443 --dscp 46" << color::reset << "\n\n";

		std::cerr << color::yellow << " --ip-tos" << color::reset << " <hex> Set raw IP TOS byte (DSCP + ECN)\n\n";

		std::cerr << color::white << "   ECN (Explicit Congestion Notification) Values:\n" << color::reset;
		std::cerr << "     " << color::yellow << "0x00" << color::reset << "  DSCP=0 (BE), ECN=00 (Non-ECT)          # Best Effort, No ECN\n";
		std::cerr << "     " << color::yellow << "0x01" << color::reset << "  DSCP=0 (BE), ECN=01 (ECT(1))           # Best Effort, ECN Capable (1)\n";
		std::cerr << "     " << color::yellow << "0x02" << color::reset << "  DSCP=0 (BE), ECN=10 (ECT(0))           # Best Effort, ECN Capable (0)\n";
		std::cerr << "     " << color::yellow << "0x03" << color::reset << "  DSCP=0 (BE), ECN=11 (CE)               # Best Effort, Congestion Experienced\n\n";

		std::cerr << color::white << "   Expedited Forwarding (EF) with ECN:\n" << color::reset;
		std::cerr << "     " << color::yellow << "0xB8" << color::reset << "  DSCP=46 (EF), ECN=00 (Non-ECT)        # Voice/Video, No ECN\n";
		std::cerr << "     " << color::yellow << "0xB9" << color::reset << "  DSCP=46 (EF), ECN=01 (ECT(1))         # Voice/Video, ECN Capable (1)\n";
		std::cerr << "     " << color::yellow << "0xBA" << color::reset << "  DSCP=46 (EF), ECN=10 (ECT(0))         # Voice/Video, ECN Capable (0)\n";
		std::cerr << "     " << color::yellow << "0xBB" << color::reset << "  DSCP=46 (EF), ECN=11 (CE)             # Voice/Video, Congestion Experienced\n\n";

		std::cerr << color::white << "   Assured Forwarding (AF41) with ECN:\n" << color::reset;
		std::cerr << "     " << color::yellow << "0x88" << color::reset << "  DSCP=34 (AF41), ECN=00 (Non-ECT)      # AF4 Low Drop, No ECN\n";
		std::cerr << "     " << color::yellow << "0x8A" << color::reset << "  DSCP=34 (AF41), ECN=10 (ECT(0))       # AF4 Low Drop, ECN Capable (0)\n\n";

		std::cerr << color::white << "   Assured Forwarding (AF31) with ECN:\n" << color::reset;
		std::cerr << "     " << color::yellow << "0x68" << color::reset << "  DSCP=26 (AF31), ECN=00 (Non-ECT)      # AF3 Low Drop, No ECN\n\n";

		std::cerr << color::white << "   Class Selector (CS) Values:\n" << color::reset;
		std::cerr << "     " << color::yellow << "0xA0" << color::reset << "  DSCP=40 (CS5), ECN=00 (Non-ECT)       # Signaling (Voice Call Setup)\n";
		std::cerr << "     " << color::yellow << "0xC0" << color::reset << "  DSCP=48 (CS6), ECN=00 (Non-ECT)       # Network Control (Routing)\n";
		std::cerr << "     " << color::yellow << "0xE0" << color::reset << "  DSCP=56 (CS7), ECN=00 (Non-ECT)       # Network Control (Maintenance)\n\n";

		std::cerr << color::white << "   Common Examples:\n" << color::reset;
		std::cerr << "     " << color::yellow << "shiv 192.168.1.1 -p 80 --ip-tos 0xB8" << color::reset << "     # EF (Voice) without ECN\n";
		std::cerr << "     " << color::yellow << "shiv 10.0.0.1 -p 443 --ip-tos 0x01" << color::reset << "       # Best Effort with ECT(1)\n";
		std::cerr << "     " << color::yellow << "shiv 8.8.8.8 -p 53 --ip-tos 0x88" << color::reset << "         # AF41 (Assured Forwarding)\n";
		std::cerr << "     " << color::yellow << "shiv 1.1.1.1 -p 22 --ip-tos 0x03" << color::reset << "         # CE (Congestion Experienced)\n\n";

		std::cerr << color::white << "   ECN Field Values:\n" << color::reset;
		std::cerr << "     " << color::yellow << "00" << color::reset << " = Non-ECT (Not ECN-Capable Transport)\n";
		std::cerr << "     " << color::yellow << "01" << color::reset << " = ECT(1) (ECN-Capable Transport, value 1)\n";
		std::cerr << "     " << color::yellow << "10" << color::reset << " = ECT(0) (ECN-Capable Transport, value 0)\n";
		std::cerr << "     " << color::yellow << "11" << color::reset << " = CE (Congestion Experienced)\n\n";

		std::cerr << color::white << "   Examples:\n" << color::reset;
		std::cerr << "     " << color::yellow << "shiv 192.168.1.1 -p 80 --dscp EF" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv 10.0.0.0/24 -p 1-1000 --dscp AF41" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv example.com -p 443 --dscp 46" << color::reset << "\n\n";

		std::cerr << color::yellow << " --ip-id " << color::reset << " <mode> Set IP ID generation strategy\n\n";

		std::cerr << color::white << "   Available Modes:\n" << color::reset;
		std::cerr << "     " << color::yellow << "random" << color::reset << "      # Random ID (default) - Randomized per packet\n";
		std::cerr << "     " << color::yellow << "sequential" << color::reset << "  # Incremental (1,2,3...) - Increases by 1 each packet\n";
		std::cerr << "     " << color::yellow << "zero" << color::reset << "        # Always 0 - Fixed zero value\n";
		std::cerr << "     " << color::yellow << "constant" << color::reset << "    # User specified fixed ID (use with --ip-id <value>)\n";
		std::cerr << "     " << color::yellow << "iprofile" << color::reset << "    # Based on destination IP - OS fingerprinting friendly\n";
		std::cerr << "     " << color::yellow << "time" << color::reset << "        # Timestamp based - microsecond precision\n\n";

		std::cerr << color::white << "   Examples:\n" << color::reset;
		std::cerr << "     " << color::yellow << "shiv 192.168.1.1 -p 80 --ip-id random" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv 10.0.0.1 -p 443 --ip-id sequential" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv 8.8.8.8 -p 53 --ip-id zero" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv 1.1.1.1 -p 22 --ip-id constant --ip-id 0x1234" << color::reset << "\n";
		std::cerr << "     " << color::yellow << "shiv example.com -p 80 --ip-id time" << color::reset << "\n\n";

		std::cerr << color::white << "   Mode Details:\n" << color::reset;
		std::cerr << "     " << color::yellow << "random" << color::reset << "     - Best for stealth scanning\n";
		std::cerr << "               - Random values between 1-65535\n";
		std::cerr << "     " << color::yellow << "sequential" << color::reset << " - Mimics normal TCP stack behavior\n";
		std::cerr << "               - Wraps around after 65535\n";
		std::cerr << "     " << color::yellow << "zero" << color::reset << "       - Some OS/firewalls use zero ID\n";
		std::cerr << "               - Can bypass certain IDS rules\n";
		std::cerr << "     " << color::yellow << "constant" << color::reset << "  - Testing fixed ID scenarios\n";
		std::cerr << "               - Use with --ip-id <hex|dec>\n";
		std::cerr << "     " << color::yellow << "forged" << color::reset << "     - Advanced evasion technique\n";
		std::cerr << "               - Copies ID pattern from legitimate traffic\n";
		std::cerr << "     " << color::yellow << "iprofile" << color::reset << "  - Matches OS behavior per destination\n";
		std::cerr << "               - Different ID per target IP\n";
		std::cerr << "     " << color::yellow << "time" << color::reset << "       - High precision for analysis\n";
		std::cerr << "               - ID = timestamp microseconds >> 16\n";
		
		std::cerr << color::yellow << " --ip-rsa"       << color::reset << "  Add IP Router Alert option (RFC 2113)\n";
        	std::cerr << color::yellow << " --ip-security"  << color::reset << " <0xNN>  Add IP Security Option/IPSO (RFC 1108), default 0x01\n\n";
        	
        	std::cerr << color::green << "Version Detection (-sV) Options:\n" << color::reset;
		std::cerr << color::yellow << " -sV" << color::reset << " enable service/version detection on open ports\n";
		std::cerr << color::yellow << " --sv-timeout" << color::reset << " <sec> response/read timeout once connected (default 3)\n";
		std::cerr << color::yellow << " --connect-timeout" << color::reset << " <sec> TCP connect timeout (default: same as --sv-timeout)\n";
		std::cerr << color::yellow << " --udp" << color::reset << " probe UDP instead of TCP\n";
		std::cerr << color::yellow << " --force-raw" << color::reset << " banner-grab only, skip HTTP/TLS probes\n";
		std::cerr << color::yellow << " --force-http" << color::reset << " force an HTTP GET probe\n";
		std::cerr << color::yellow << " --force-https" << color::reset << " force an HTTPS GET probe (TLS)\n";
		std::cerr << color::yellow << " --tls-verify" << color::reset << " enforce TLS certificate validation\n";
		std::cerr << color::yellow << " --tls-ca" << color::reset << " <file> CA bundle (PEM) for verification\n";
		std::cerr << color::yellow << " --tls-ca-path" << color::reset << " <dir> directory of hashed CA certs\n";
		std::cerr << color::yellow << " --tls-cert" << color::reset << " <file> client cert (mTLS)\n";
		std::cerr << color::yellow << " --tls-key" << color::reset << " <file> client key (mTLS)\n";
		std::cerr << color::yellow << " --tls-sni" << color::reset << " <name> override TLS SNI hostname\n";
		std::cerr << color::yellow << " --host" << color::reset << " <value> override the HTTP Host: header value\n";
		std::cerr << color::yellow << " --save" << color::reset << " <file> save raw probe response to file\n";
		std::cerr << color::yellow << " --verbose" << color::reset << " verbose version-detection diagnostics\n";
		std::cerr << color::dim << " (all of the above are ignored unless -sV is also given)\n\n" << color::reset;

		std::cerr << color::green << "Miscellaneous Options:\n" << color::reset;

		std::cerr << color::green << "TCP Options Control:\n" << color::reset;
		std::cerr << color::yellow << " --ws" << color::reset << " <value> Set Window Scale (0-500, default: 7)\n";
		std::cerr << color::yellow << " --mss" << color::reset << " <value> Set MSS value (0-66666, default: 1460)\n";
		std::cerr << color::yellow << " --t" << color::reset << " <value> Set TCP timestamp (0-100000000, default: 1234567)\n";
		std::cerr << color::yellow << " --tsecr" << color::reset << " <value> Set TCP TSecr value (hex: 0x123 or decimal, default: 0)\n";
		std::cerr << color::yellow << " --nops" << color::reset << " <count> Add NOPs to TCP options (default: 1)\n";
		std::cerr << color::yellow << " --sack" << color::reset << " <on|off> Enable/disable SACK option (default: on)\n";
		std::cerr << color::yellow << " --tcp-mtcp"    << color::reset << "  Add MPTCP MP_CAPABLE option (kind 30)\n";
        	std::cerr << color::yellow << " --tcp-ao"       << color::reset << " <kid:rnext:maclen>  Add TCP-AO option (kind 29), default 1:1:12\n";
		std::cerr << color::yellow << " --win-size" << color::reset << " <value> Set TCP window size (0-10000, default: 65535)\n";
		std::cerr << color::yellow << " --seq-num" << color::reset << " <value> Set TCP sequence number (0-4294967295U, default: random)\n\n";

		std::cerr << color::yellow << " --inj-tfo-cookie" << color::reset << " <val> Inject TFO cookie (length, string=direct, 0x=hex)\n";
		std::cerr << "                                                      Length must be ODD number for valid TFO\n";
		std::cerr << "                                                      Use EVEN number for TCP stack confusion attack\n";
		std::cerr << "                                                      Handler:\n";
		std::cerr << "                                                      len:N Random cookie of N bytes (N must be ODD, >=5)\n";
		std::cerr << "                                                      str:S String cookie S\n";
		std::cerr << "                                                      hex:H Hex cookie 0xH\n";
		std::cerr << "                                                      Examples:\n";
		std::cerr << color::yellow << "                                     --inj-tfo-cookie" << color::reset << " len:5 (random 5 bytes [auto added garbage cookie])\n";
		std::cerr << color::yellow << "                                     --inj-tfo-cookie" << color::reset << " str:abc (string \"abc\")\n";
		std::cerr << color::yellow << "                                     --inj-tfo-cookie" << color::reset << " hex:DEAD (hex 0xDEAD)\n\n";

		std::cerr << color::green << "Packet Segments / Fragmentation:\n" << color::reset;
		std::cerr << color::green << "---------------------------------\n\n" << color::reset;

		std::cerr << color::green << "IP Fragmentation:\n" << color::reset;
		std::cerr << "  " << color::yellow << "-f <size>" << color::reset << "                 Fragment size (8-65528, must be multiple of 8)\n";
		std::cerr << "\n";
		std::cerr << "  " << color::green << "       Reassembly Variations:\n" << color::reset;
		std::cerr << "    " << color::yellow << "         --frag ofo" << color::reset << "              Send Out-Of-Order fragments\n";
		std::cerr << "    " << color::yellow << "         --frag zof" << color::reset << "              Send zero-offset fragment at last\n";
		std::cerr << "    " << color::yellow << "         --frag lap" << color::reset << "              Send overlap fragments\n\n";

		std::cerr << color::green << "MTU(Maximum Transmission Unit):\n" << color::reset;
		std::cerr << color::yellow << " --mtu <value>" << color::reset << " | valid range: 22 to 65535\n\n";

		std::cerr << color::green << "IP Length Manipulation (Evasion/Fingerprinting):\n" << color::reset;
	        std::cerr << color::yellow << " --packet-length" << color::reset << " <N> |  Set the real on-wire packet size to exactly N bytes (40-65535)\n\n";
 
	        std::cerr << color::green << "  Behavior:\n" << color::reset;
	        std::cerr << "    " << color::yellow << "N > natural size" << color::reset << "   Pads with null bytes as TCP payload (honest length)\n";
	        std::cerr << "    " << color::yellow << "N < natural size" << color::reset << "   Truncates from the tail: payload first, then TCP options\n";
	        std::cerr << "    " << color::yellow << "N == natural size" << color::reset << "  No-op\n\n";

	        std::cerr << color::white << "  Notes:\n" << color::reset;
	        std::cerr << "    • This only changes real bytes sent — there is no 'fake length' mode.\n";
	        std::cerr << "      Linux always rewrites the IP header's Total Length field to match\n";
	        std::cerr << "      the real packet size on IP_HDRINCL sockets, so lying about it is\n";
	        std::cerr << "      not possible; only the actual size can be changed.\n";
	        std::cerr << "    • Floor is 40 bytes (bare IP + TCP header, no options/payload).\n";
	        std::cerr << "      Below that, the fixed header fields would be corrupted, so N < 40\n";
	        std::cerr << "      is rejected at parse time.\n";
	        std::cerr << "    • If N lands inside the TCP options region, the TCP data-offset\n";
	        std::cerr << "      field is recalculated automatically so the packet stays well-formed.\n\n";

	        std::cerr << color::green << "  Examples:\n" << color::reset;
	        std::cerr << "    " << color::cyan << "# Shrink packet (trims options/payload, header offset auto-fixed)" << color::reset << "\n";
	        std::cerr << "    shiv 10.0.0.1 -p 80 " << color::yellow << "--packet-length 44" << color::reset << "\n";
	        std::cerr << "        → Sends 44 bytes total (20 ip + 20 tcp + 4 bytes options)\n\n";

	        std::cerr << "    " << color::cyan << "# Pad packet with null bytes" << color::reset << "\n";
	        std::cerr << "    shiv 192.168.1.1 -p 22 " << color::yellow << "--packet-length 1500" << color::reset << "\n";
	        std::cerr << "        → Pads to 1500 bytes with nulls, honest length\n\n";

	        std::cerr << color::white << "  Technical Details:\n" << color::reset;
	        std::cerr << "    • Normal SYN packet: 74 bytes on wire (14 eth + 20 ip + 40 tcp)\n";
	        std::cerr << "    • TCP options: MSS, WScale, SACK, Timestamp, NOP = up to 20 extra bytes\n";
	        std::cerr << "    • Minimum valid TCP header (no options): 40 bytes total (ip+tcp)\n\n";

		std::cerr << color::green << "Payload Options:\n" << color::reset;
		std::cerr << color::yellow << " --data" << color::reset << " <string> Custom payload data (string/hex/number)\n";
		std::cerr << color::yellow << " --data-length" << color::reset << " <size> Generate random payload of specified length\n\n";
		
		std::cerr << color::green << "Ethernet / ARP Options:\n" << color::reset;
		std::cerr << color::yellow << " --src-mac" << color::reset << " <mac> Use this MAC as source instead of the interface's real one\n";
		std::cerr << color::yellow << " --dst-mac" << color::reset << " <mac> Skip ARP entirely, use this MAC as destination\n";
		std::cerr << color::yellow << " --ether-type" << color::reset << " <val> Custom EtherType for the ARP frame (hex or decimal, default: 0x0806)\n";
		std::cerr << color::yellow << " --vlan" << color::reset << " <id> Add a single 802.1Q VLAN tag (1-4094)\n";
		std::cerr << color::yellow << " --vlan-stack" << color::reset << " <id1,id2> Add double 802.1Q tagging (QinQ)\n";
		std::cerr << color::yellow << " --ether-dst-multicast" << color::reset << " <type> Send to a well-known multicast MAC\n";
		std::cerr << "                                                      Types: ipv4-all, stp, lldp, all-nodes\n";
		std::cerr << color::yellow << " --ether-padding" << color::reset << " <size|random> Pad the ARP frame with extra bytes\n";
		
		std::cerr << color::green << "Host Discovery:\n" << color::reset;
		std::cerr << color::yellow << " -Pn" << color::reset << " skip target ping probe\n\n";

		std::cerr << color::green << "Miscellaneous Options:\n" << color::reset;
		std::cerr << color::green << "----------------------------\n\n" << color::reset;

		std::cerr << color::green << "Multi Host Specification:\n" << color::reset;
		std::cerr << " <IP> can be a single IP, comma-separated IPs, CIDR notation (e.g., 192.168.1.0/24), or any combination\n";
		std::cerr << color::yellow << " -iL" << color::reset << " <ips.txt> Scan saved hosts\n";
		std::cerr << color::yellow << " --exclude-ports" << color::reset << " <PORT_SPEC> Ports to exclude from scanning (format same as -p)\n\n";

		std::cerr << color::green << "State Machine Scan:\n" << color::reset;
		std::cerr << color::yellow << " -G" << color::reset << " State Machine Scan (perform 4 way handshake, must use iptables to block outbound rst)\n\n";

		std::cerr << color::green << "Public Access DB:\n" << color::reset;
		std::cerr << color::yellow << " --trial" << color::reset << " <api-key> Use security trials api to fetch subdomains and perform scan\n";
		std::cerr << "                                                For eg: shiv abc.com -p 22 --trial <api-key>\n";
		std::cerr << color::yellow << " --enum" << color::reset << " Use internetdb to fetch target information\n\n";
		
		std::cerr << color::yellow << " --port-timeout" << color::reset << " <min>-<max> Set port giveup timeout(default: min:5ms-max:700ms). e.g. --port-timeout 10ms-500ms\n";
		std::cerr << color::yellow << " --interface" << color::reset << " Set desired interface\n";
		std::cerr << color::yellow << " -o" << color::reset << " <File_Name>.txt Save results to file (plain text)\n\n";

		std::cerr << color::green << "Pace Control:\n" << color::reset;
		std::cerr << color::yellow << " --rate TIME:MIN-MAX" << color::reset << " Control packet rate.TIME units: ms, s, m  (e.g. 500ms:300-500, 2s:1000-1500)\n";
		std::cerr << color::yellow << " --jitter [TIME]" << color::reset << "\n"
			  << "     Add delay between each packet\n"
			  << "     TIME formats : 50ms | 2s | 1m\n"
			  << "     Default      : random (0.9ms – 7ms per packet)\n";

		std::cerr << color::yellow << " --batch-delay [TIME | MIN-MAX]" << color::reset << "\n"
			  << "     Add delay between batch executions (default batches: 14)\n"
			  << "     No argument  : random (10ms – 60ms)\n"
			  << "     Exact value  : 50ms | 2s | 1m\n"
			  << "     Range        : 20ms – 100ms (random within range)\n"
			  << "     For eg:      : --batch-delay   |  --batch_delay 10ms   |   --batch-delay 20ms-30ms\n\n";

		std::cerr << color::yellow << " --bandwidth TIME:BYTES" << color::reset << "\n"
			  << "     Cap total on-wire bytes dispatched per time window\n"
			  << "     TIME formats : 500ms | 1s | 2m\n"
			  << "     BYTES suffix : K = x1024 | M = x1024x1024 | G = x1024x1024x1024 (optional, case-insensitive)\n"
			  << "     For eg:      : --bandwidth 1s:500000   (500000 bytes/sec, raw number)\n"
			  << "                    --bandwidth 1s:500K     (500x1024 = 512000 bytes/sec)\n"
			  << "                    --bandwidth 500ms:2M    (2x1024x1024 bytes per 500ms window)\n"
			  << "                    --bandwidth 1s:1G       (1x1024^3 bytes/sec)\n\n";

		std::cerr << color::green << "Buffer Management:\n" << color::reset;
		std::cerr << color::yellow << " --rcv-uring" << color::reset << " <depth> Set io_uring receive queue depth (Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, default: auto=dynamic)\n";
		std::cerr << color::yellow << " --rcvbuf" << color::reset << " <size> Set receive buffer size in bytes(128k, 2m, 1g, or bytes), (default: auto)\n";
		std::cerr << color::yellow << " --send-uring" << color::reset << " <depth> Set io_uring send queue depth (Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, default: auto=1024)\n";
		std::cerr << color::yellow << " -b <size>" << color::reset << " Set port batch size (default: 250, range: 1-1000)\n"
			  << "     Ports are split into chunks of this size and scanned together.\n"
			  << "     Example: -b 250  (scan 250 ports per batch)\n";
		
		std::cerr << color::yellow << " --set-rtt" << color::reset << " <ms|s> Set initial RTT seed (default: 290ms). e.g. --set-rtt 150ms or --set-rtt 0.5s\n\n";

		std::cerr << color::green << "Debug Options:\n" << color::reset;
		
		std::cerr << color::yellow << " --debug <mode>" << color::reset
		          << " Enable debug features\n";

		std::cerr << "         "
		          << color::yellow << "recv" << color::reset
		          << "  Display detailed received packet information\n";
		          
		std::cerr << "         "
		          << color::yellow << "send" << color::reset
		          << "  Display detailed send packet information\n";

		std::cerr << "         "
		          << color::yellow << "rtt" << color::reset
		          << "     Display RTT (Round Trip Time) calculations\n";
		          
		std::cerr << "         "
		          << color::yellow << "wsn" << color::reset
		          << "     Detect WSN (Window Size Negotiation) inconsistent anomalies\n";
		          
		std::cerr << "         "
		          << color::yellow << "tll" << color::reset
		          << "     Display TTL (Time To Live) and target hop distance\n";

		std::cerr << "         "
		          << color::yellow << "demux" << color::reset
		          << "   Show live receive-side demux decisions (matched/dropped/replies, why a reply was rejected, and a per-batch summary)\n";
		          
		std::cerr << "         "
		          << color::yellow << "strack" << color::reset
		          << "   Show State-transition output, Ports marked as filtered by initial syn may be get discover when retry\n\n";
}

int main(int argc, char *argv[]) {
    // Capture everything printed for the rest of the run (debug lines,
    // version-detection output, per-flag prints, etc.) so it can be
    // written out by save_scan_results() once the scan is fully done.
    std::streambuf* teeOut_orig = std::cout.rdbuf();
    std::streambuf* teeErr_orig = std::cerr.rdbuf();
    TeeBuf teeOut(teeOut_orig);
    TeeBuf teeErr(teeErr_orig);
    std::cout.rdbuf(&teeOut);
    std::cerr.rdbuf(&teeErr);

    load_mac_vendors("/usr/share/shiv/mac-vendor.txt");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    
    struct SignalRegistrar {
        static bool register_signals(struct sigaction* sa) {
            const std::pair<int, const char*> signals[] = {
                {SIGINT,  "SIGINT"},   {SIGSEGV, "SIGSEGV"}, {SIGABRT, "SIGABRT"},
                {SIGTERM, "SIGTERM"},  {SIGFPE,  "SIGFPE"},  {SIGBUS,  "SIGBUS"},
                {SIGILL,  "SIGILL"},   {SIGSYS,  "SIGSYS"},  {SIGPIPE, "SIGPIPE"},
                {SIGXCPU, "SIGXCPU"},  {SIGXFSZ, "SIGXFSZ"}
            };
            
            for (const auto& [sig, name] : signals) {
                if (sigaction(sig, sa, nullptr) == -1) {
                    std::cerr << "Failed to register " << name << ": " 
                              << strerror(errno) << std::endl;
                    return false;
                }
            }
            return true;
        }
    };

    if (!SignalRegistrar::register_signals(&sa)) {
        return 1;
    }

    {
        struct rlimit memlock_limit{};
        if (getrlimit(RLIMIT_MEMLOCK, &memlock_limit) == 0) {
            constexpr rlim_t DESIRED_MEMLOCK = 64ULL * 1024 * 1024; // 64 MiB
            if (memlock_limit.rlim_cur != RLIM_INFINITY &&
                memlock_limit.rlim_cur < DESIRED_MEMLOCK) {
                rlim_t new_soft = (memlock_limit.rlim_max == RLIM_INFINITY)
                                       ? DESIRED_MEMLOCK
                                       : std::min(DESIRED_MEMLOCK, memlock_limit.rlim_max);
                struct rlimit updated = memlock_limit;
                updated.rlim_cur = new_soft;
                if (setrlimit(RLIMIT_MEMLOCK, &updated) != 0) {
                    std::cerr << "[main] warning: could not raise RLIMIT_MEMLOCK ("
                              << strerror(errno)
                              << "); idle-ring creation may fail under concurrent load\n";
                }
            }
        }
    }

    struct Config {
       bool use_badsum = false,badsum_value_set = false,use_partial_badsum = false, fast_scan = true,use_file = true, print_individual_closed_filtered = false,
            print_filtered_if_few = false, graceful_scan = false,use_manual_tcp_checksum = false,
            sack_permitted = true, use_custom_data = false, generate_random_data = false,debug_packet = false,use_trial_api = false,expect_domain_for_trial = false,use_shodan_enum = false;
       uint16_t custom_badsum_value = 0, manual_tcp_checksum = 0,base_source_port = 443, retry_source_port = 8443, win_size = 0, custom_ip_flags = 0x4000,
                fixed_ip_id = 0, data_length = 0, nops_count = 0, mss_value = 1460,frag_offset_size  = 8,mtu_size = 0;
       int user_rcvbuf_size = -1,port_timeout_min_ms = 5,port_timeout_max_ms = 700;
       uint8_t custom_ttl = 64, window_scale = 7,custom_dscp = 0,custom_ip_tos = 0;SportRangeConfig sport_range_cfg;GsportConfig gsport_cfg;
       uint32_t seq_num = 0, timestamp_val = 1234567, timestamp_ecr_custom = 0;
       size_t send_uring_depth = 1024, rcv_uring_depth = 0, main_batch_size = 250;
       bool batch_specified = false;
       bool debug_rtt = false;
       int initial_rtt_ms = 290;
       bool debug_wsn = false;
       bool debug_ttl = false;
       bool debug_demux = false;
       bool debug_strack = false;
       bool debug_send = false;
       bool use_ip_tos = false;
       bool use_fragmentation = false;
       bool frag_out_of_order = false;
       uint16_t frag_overlap_bytes = 8;
       bool frag_overlap = false;
       bool frag_zof = false; 
       ScanType scan_type = ScanType::SYN;
       bool scan_type_specified = false;
       std::string partial_badsum_type, source_ip, ip_file, port_spec, interface,
                   output_file, exclude_ports_spec, custom_data, tfo_cookie_str,trial_api_key;
       std::vector<int> excluded_ports,parsed_ports;
       bool use_tfo_cookie = false, tfo_cookie_as_hex = false, tfo_cookie_random = false;
       uint64_t tfo_cookie_num = 0;
       size_t tfo_cookie_length = 0;
       bool    use_tcp_mptcp = false;
       bool    use_tcp_ao = false;
       uint8_t tcp_ao_keyid = 1, tcp_ao_rnextkeyid = 1, tcp_ao_mac_len = 12;
       bool    use_ip_router_alert = false;
       bool    use_ip_security = false;
       uint8_t ip_security_classification = 0x01;
       RateConfig rate_config;
       JitterConfig  jitter_config;
       BatchDelayConfig batch_delay_config;
       BandwidthConfig   bandwidth_config;
       PacketLengthConfig packet_length_config;
       IpIdMode ip_id_mode  = IpIdMode::RANDOM;
       bool skip_ping       = false;
       bool sn_scan         = false;
       bool enable_version_detection = false;
       int  sv_timeout_sec         = 3;
       int  sv_connect_timeout_sec = 0;
       int  sv_intensity           = 7;
       bool sv_udp                 = false;
       bool sv_force_raw           = false;
       bool sv_force_http          = false;
       bool sv_force_https         = false;
       bool sv_tls_verify          = false;
       bool sv_verbose             = false;
       std::string sv_save_file, sv_tls_ca_file, sv_tls_ca_path,
                   sv_tls_cert, sv_tls_key, sv_tls_sni, sv_host_override;
       EthArpOptions eth_opts;
   } config;
   
    std::vector<std::string> ips;
    int arg_idx = 1;

    auto get_next_arg = [&](int& idx, const std::string& option_name) -> std::string {
        if (idx + 1 >= argc) {
            std::cerr << "Option " << option_name << " requires an argument\n";
            exit(1);
        }
        return argv[++idx];
    };

    auto parse_uint16 = [](const std::string& str, const std::string& option_name) -> uint16_t {
        try {
            unsigned long value = std::stoul(str);
            if (value > std::numeric_limits<uint16_t>::max()) {
                throw std::out_of_range("value exceeds uint16_t maximum");
            }
            return static_cast<uint16_t>(value);
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str
                      << " (" << e.what() << ")\n";
            exit(1);
        }
    };

    auto parse_uint32 = [](const std::string& str, const std::string& option_name) -> uint32_t {
        try {
            return static_cast<uint32_t>(std::stoul(str));
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str << " (" << e.what() << ")\n";
            exit(1);
        }
    };
    auto parse_size_t = [](const std::string& str, const std::string& option_name) -> size_t {
        try {
            return std::stoul(str);
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str << " (" << e.what() << ")\n";
            exit(1);
        }
    };
    auto validate_uring_depth = [](size_t depth) -> bool {
        const std::vector<size_t> allowed_depths = {2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
        return std::find(allowed_depths.begin(), allowed_depths.end(), depth) != allowed_depths.end();
    };
    std::unordered_map<std::string, std::function<void(int&)>> option_handlers = {
        {"-iL", [&](int& idx) {
            config.ip_file = get_next_arg(idx, "-iL");
        }},
        
        {"--enum", [&](int& idx) {
            config.use_shodan_enum = true;
        }},
        
        {"--trial", [&](int& idx) {
            std::string api_key = get_next_arg(idx, "--trial");
            config.use_trial_api = true;
            config.trial_api_key = api_key;
            config.expect_domain_for_trial = true;
        }},
        
        {"--sport-range", [&](int& idx) {
	    std::string range_str = get_next_arg(idx, "--sport-range");
	    if (!parse_sport_range_config(range_str, config.sport_range_cfg)) {
		exit(1);
	    }
	}},
        
        {"--send-uring", [&](int& idx) {
            size_t depth = parse_size_t(get_next_arg(idx, "--send-uring"), "--send-uring");
            if (!validate_uring_depth(depth)) {
                std::cerr << "Invalid send uring depth. Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096\n";
                exit(1);
            }
            config.send_uring_depth = depth;
        }},
        
        {"--rate", [&](int& idx) {
	    std::string rate_str = get_next_arg(idx, "--rate");
	    if (!parse_rate_config(rate_str, config.rate_config)) {
		exit(1);
	    }
	}},
	
	
	{"--batch-delay", [&](int& idx) {
	    std::string delay_arg;
	    if (idx + 1 < argc && argv[idx + 1][0] != '-') {
		delay_arg = argv[++idx];
	    }
	    if (!parse_batch_delay_config(delay_arg, config.batch_delay_config)) {
		exit(1);
	    }
	}},
	
	{"--bandwidth", [&](int& idx) {
            std::string bw_str = get_next_arg(idx, "--bandwidth");
            if (!parse_bandwidth_config(bw_str, config.bandwidth_config)) {
                exit(1);
            }
        }},
        
        {"--rcv-uring", [&](int& idx) {
            size_t depth = parse_size_t(get_next_arg(idx, "--rcv-uring"), "--rcv-uring");
            if (!validate_uring_depth(depth)) {
                std::cerr << "Invalid receive uring depth. Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096\n";
                exit(1);
            }
            config.rcv_uring_depth = depth;
        }},
        
        {"--packet-length", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--packet-length");
	    if (!parse_packet_length(val, config.packet_length_config)) {
		exit(1);
	    }
	}},
        
        {"-p", [&](int& idx) {
	    config.port_spec = get_next_arg(idx, "-p");
	    config.use_file = false;
	    config.parsed_ports = parse_ports(config.port_spec);
	    if (config.parsed_ports.size() <= 9) {
		config.print_individual_closed_filtered = true;
	    }
	}},
        
        {"--jitter", [&](int& idx) {
	    std::string jitter_arg;
	    if (idx + 1 < argc && argv[idx + 1][0] != '-') {
		jitter_arg = argv[++idx];
	    }
	    if (!parse_jitter_config(jitter_arg, config.jitter_config)) {
		exit(1);
	    }
	}},
	
	{"-h", [&](int& idx) {
            print_full_help();
            exit(0);
        }},
        
        {"--help", [&](int& idx) {
            print_full_help();
            exit(0);
        }},
        
        {"--port-timeout", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--port-timeout");

	    auto parse_ms = [](const std::string& s) -> int {
		try {
		    if (s.size() >= 2 && s.substr(s.size() - 2) == "ms")
			return static_cast<int>(std::stod(s.substr(0, s.size() - 2)));
		    if (!s.empty() && s.back() == 's')
			return static_cast<int>(std::stod(s.substr(0, s.size() - 1)) * 1000.0);
		    return static_cast<int>(std::stod(s));  // plain number = ms
		} catch (const std::exception&) {
		    std::cerr << "--port-timeout: invalid numeric value '" << s << "'\n";
		    exit(1);
		}
	    };

	    size_t dash = val.find('-');
	    // Handle negative or ambiguous: only split on dash after first char
	    for (size_t i = 1; i < val.size(); ++i) {
		if (val[i] == '-') { dash = i; break; }
	    }

	    if (dash == std::string::npos || dash == 0 || dash == val.size() - 1) {
		std::cerr << "--port-timeout: use format min-max e.g. 5ms-700ms or 5-700\n";
		exit(1);
	    }

	    int tmin = parse_ms(val.substr(0, dash));
	    int tmax = parse_ms(val.substr(dash + 1));

	    if (tmin < 1 || tmax < 1 || tmin > tmax) {
		std::cerr << "--port-timeout: min must be >= 1 and min <= max\n";
		exit(1);
	    }
	    if (tmax > 30000) {
		std::cerr << "--port-timeout: max cannot exceed 30000ms\n";
		exit(1);
	    }
	    config.port_timeout_min_ms = tmin;
	    config.port_timeout_max_ms = tmax;
	}},
        
        {"--inj-tfo-cookie", [&](int& idx) {
            std::string tfo_arg = get_next_arg(idx, "--inj-tfo-cookie");
            config.use_tfo_cookie = true;
            
            if (tfo_arg.find("len:") == 0) {
                std::string len_str = tfo_arg.substr(4);
                try {
                    config.tfo_cookie_length = std::stoul(len_str);
                    if (config.tfo_cookie_length < 1 || config.tfo_cookie_length > 253) {
                        std::cerr << "TFO random length must be 1-253 bytes\n";
                        exit(1);
                    }
                    config.tfo_cookie_random = true;
                    
                    if (config.tfo_cookie_length % 2 == 0) {
                        std::cout << "[INFO] TFO cookie length " << config.tfo_cookie_length 
                                  << " is EVEN. Auto-correcting to " 
                                  << (config.tfo_cookie_length + 1) << " (ODD)\n";
                        config.tfo_cookie_length++;
                    }
                    if (config.tfo_cookie_length < 5) {
                        config.tfo_cookie_length = 5;
                        std::cout << "[INFO] Minimum TFO cookie is 5 bytes\n";
                    }
                    std::cout << "TFO: Random cookie length: " << config.tfo_cookie_length << " bytes\n";
                } catch (const std::exception& e) {
                    std::cerr << "Invalid TFO length: " << len_str << "\n";
                    exit(1);
                }
            }
            else if (tfo_arg.find("str:") == 0) {
                config.tfo_cookie_str = tfo_arg.substr(4);
                size_t byte_count = config.tfo_cookie_str.length();
                if (byte_count % 2 == 0) {
                    std::cout << "[WARNING] String cookie will be " << byte_count 
                              << " bytes (EVEN). Auto-padding to make ODD.\n";
                }
                std::cout << "TFO: String cookie: \"" << config.tfo_cookie_str 
                          << "\" (" << byte_count << " bytes)\n";
            }
            else if (tfo_arg.find("hex:") == 0) {
                std::string hex_str = tfo_arg.substr(4);
                config.tfo_cookie_as_hex = true;
                config.tfo_cookie_str = "0x" + hex_str;
                size_t byte_count = hex_str.length() / 2;
                if (hex_str.length() % 2 != 0) byte_count++;
                if (byte_count % 2 == 0) {
                    std::cout << "[WARNING] Hex cookie will be " << byte_count 
                              << " bytes (EVEN). Auto-padding to make ODD.\n";
                }
                std::cout << "TFO: Hex cookie: 0x" << hex_str 
                          << " (" << byte_count << " bytes)\n";
            }
            else {
                std::cout << "[INFO] Auto-detecting TFO cookie type...\n";
                if ((tfo_arg.find("0x") == 0 || tfo_arg.find("0X") == 0) && tfo_arg.length() > 2) {
                    config.tfo_cookie_as_hex = true;
                    config.tfo_cookie_str = tfo_arg;
                    std::cout << "TFO: Hex cookie (legacy): " << tfo_arg << "\n";
                }
                else if (std::all_of(tfo_arg.begin(), tfo_arg.end(), ::isdigit)) {
                    try {
                        size_t num_val = std::stoul(tfo_arg);
                        if (num_val <= 253) {
                            config.tfo_cookie_random = true;
                            config.tfo_cookie_length = num_val;
                            std::cout << "TFO: Random length (legacy): " << num_val << " bytes\n";
                        } else {
                            config.tfo_cookie_num = num_val;
                            std::cout << "TFO: Numeric value (legacy): " << num_val << "\n";
                        }
                    } catch (...) {
                        config.tfo_cookie_str = tfo_arg;
                        std::cout << "TFO: String cookie (legacy): \"" << tfo_arg << "\"\n";
                    }
                }
                else {
                    config.tfo_cookie_str = tfo_arg;
                    std::cout << "TFO: String cookie (legacy): \"" << tfo_arg << "\"\n";
                }
            }
        }},

        {"--debug", [&](int& idx) {
	    std::string debug_arg = get_next_arg(idx, "--debug");
	    std::stringstream ss(debug_arg);
	    std::string token;
	    while (std::getline(ss, token, ',')) {
		if (token == "recv") {
		    config.debug_packet = true;
		} else if (token == "rtt") {
		    config.debug_rtt = true;
		} else if (token == "wsn") {
		    config.debug_wsn = true;
		} else if (token == "ttl") {
		    config.debug_ttl = true;
		} else if (token == "demux") {
		    config.debug_demux = true;
		} else if (token == "strack") {
		    config.debug_strack = true;
		} else if (token == "send") {
		    config.debug_send = true;
		} else {
		    std::cerr << "Invalid --debug token '" << token 
		              << "'. Valid: recv,rtt,wsn,ttl,demux,strack,send\n";
		    exit(1);
		}
	    }
	}},
        
        {"-b", [&](int& idx) {
            std::string batch_spec = get_next_arg(idx, "-b");
            try {
                size_t val = std::stoul(batch_spec);
                if (val < 1 || val > 10000) {
                    std::cerr << "Batch size must be between 1 and 10000\n";
                    exit(1);
                }
                config.main_batch_size = val;
            } catch (const std::exception& e) {
                std::cerr << "Invalid batch size: " << batch_spec << " (" << e.what() << ")\n";
                exit(1);
            }
            config.batch_specified = true;
        }},
        
         {"-g", [&](int& idx) {
            std::string gsport_str = get_next_arg(idx, "-g");
            if (!parse_gsport_config(gsport_str, config.gsport_cfg)) {
                exit(1);
            }
        }},
        
        {"--seq-num", [&](int& idx) {
            long temp_seq = 0;
            try {
                temp_seq = std::stol(get_next_arg(idx, "--seq-num"));
            } catch (const std::exception&) {
                std::cerr << "--seq-num: invalid numeric value\n";
                exit(1);
            }
            if (temp_seq < 0 || temp_seq > 4294967295U) {
                std::cerr << "Sequence number must be between 0 and 4294967295\n";
                exit(1);
            }
            config.seq_num = static_cast<uint32_t>(temp_seq);
        }},
        
        {"--win-size", [&](int& idx) {
           uint16_t value = parse_uint16(get_next_arg(idx, "--win-size"), "--win-size");
           if (value > 100000) {
                std::cerr << "Error: --win-size must be between 0 and 100000\n";
                exit(1);
           }
           config.win_size = value;
        }},
        
        {"--interface", [&](int& idx) {
            config.interface = get_next_arg(idx, "--interface");
        }},
        
        {"-S", [&](int& idx) {
            config.source_ip = get_next_arg(idx, "-S");
        }},
        
        {"-G", [&](int& idx) {
            config.graceful_scan = true;
            config.fast_scan = false;
        }},
        
        {"--rcvbuf", [&](int& idx) {
            std::string buf_str = get_next_arg(idx, "--rcvbuf");
            try {
                size_t multiplier = 1;
                if (!buf_str.empty()) {
                    char last_char = std::tolower(buf_str.back());
                    if (last_char == 'k') {
                        multiplier = 1024;
                        buf_str.pop_back();
                    } else if (last_char == 'm') {
                        multiplier = 1024 * 1024;
                        buf_str.pop_back();
                    } else if (last_char == 'g') {
                        multiplier = 1024 * 1024 * 1024;
                        buf_str.pop_back();
                    }
                }
                long long computed_rcvbuf = static_cast<long long>(std::stoi(buf_str)) * static_cast<long long>(multiplier);
                if (computed_rcvbuf < 1024 || computed_rcvbuf > 100LL * 1024 * 1024) {
                    std::cerr << "Receive buffer size must be between 1KB and 100MB\n";
                    exit(1);
                }
                config.user_rcvbuf_size = static_cast<int>(computed_rcvbuf);
            } catch (const std::exception& e) {
                std::cerr << "Invalid receive buffer size: " << buf_str 
                          << " (use format: 128k, 2m, 1g, or plain bytes)\n";
                exit(1);
            }
        }},
        
        {"-o", [&](int& idx) {
            config.output_file = get_next_arg(idx, "-o");
        }},
        
        {"--exclude-ports", [&](int& idx) {
            config.exclude_ports_spec = get_next_arg(idx, "--exclude-ports");
            config.excluded_ports = parse_ports(config.exclude_ports_spec);
        }},
        
        {"-f", [&](int& idx) {
	    config.use_fragmentation = true;
	    std::string size_str = get_next_arg(idx, "-f");

	    if (size_str.empty()) {
		std::cerr << "-f: no size specified.\n"
		          << "    Usage: -f <size>  (default: 8)\n"
		          << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		          << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		exit(1);
	    }

	    // reject clearly non-numeric input early with a clean message
	    bool has_only_digits = !size_str.empty() &&
		                   std::all_of(size_str.begin(), size_str.end(), ::isdigit);
	    if (!has_only_digits) {
		std::cerr << "-f: invalid fragment size '" << size_str << "' (must be a number)\n";
		exit(1);
	    }

	    try {
		int val = std::stoi(size_str);
		if (val < 2 || val > 65528) {
		    std::cerr << "-f: size " << val << " is out of range.\n"
		              << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		              << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		    exit(1);
		}
		if (val % 2 != 0) {
		    std::cerr << "-f: size " << val << " is not a multiple of 2.\n"
		              << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		              << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		    exit(1);
		}
		// warn (don't exit) when using experimental sub-8 sizes
		if (val < 8) {
		    std::cerr << "[WARN] -f " << val << ": experimental fragment size — produces intentionally\n"
		              << "       malformed fragments that violate RFC 791. Use only for evasion testing.\n";
		}
		config.frag_offset_size = static_cast<uint16_t>(val);
	    } catch (const std::exception&) {
		std::cerr << "-f: invalid fragment size '" << size_str << "' (value out of integer range)\n";
		exit(1);
	    }
	}},
	
	{"--frag", [&](int& idx) {
	    config.use_fragmentation = true;
	    std::string frag_arg = get_next_arg(idx, "--frag");

	    if (frag_arg.empty()) {
		std::cerr << "--frag: no option specified. Available: ofo, lap, zof\n"
		          << "        Example: --frag ofo  or  --frag lap  or  --frag zof\n";
		exit(1);
	    }

	    std::string lap_peek_num = "";
	    bool has_lap = (frag_arg.find("lap") != std::string::npos);
	    if (has_lap && idx + 1 < argc) {
		std::string peek = argv[idx + 1];
		bool looks_like_number = !peek.empty() && peek[0] != '-' &&
		                         std::all_of(peek.begin(), peek.end(), ::isdigit);
		if (looks_like_number) {
		    lap_peek_num = peek;
		    ++idx;
		}
	    }

	    bool seen_ofo = false;
	    bool seen_zof = false;
	    bool seen_lap = false;

	    std::stringstream ss(frag_arg);
	    std::string token;
	    while (std::getline(ss, token, ',')) {
		if (token.empty()) continue;

		if (token == "ofo") {
		    if (seen_ofo) {
		        std::cerr << "--frag: duplicate token 'ofo'\n";
		        exit(1);
		    }
		    seen_ofo = true;
		    config.frag_out_of_order = true;

		} else if (token == "lap") {
		    if (seen_lap) {
		        std::cerr << "--frag: duplicate token 'lap'\n";
		        exit(1);
		    }
		    seen_lap = true;
		    config.frag_overlap_bytes = 8;
		    config.frag_overlap = true;
		    if (!lap_peek_num.empty()) {
		        try {
		            int oval = std::stoi(lap_peek_num);
		            if (oval < 8 || oval > 65520 || (oval % 8 != 0)) {
		                std::cerr << "--frag lap: overlap size must be a multiple of 8 "
		                          << "between 8 and 65520 (got " << oval << ").\n"
		                          << "        Note: sizes 2 and 6 are only for -f experimental mode, "
		                          << "not for --frag lap.\n";
		                exit(1);
		            }
		            config.frag_overlap_bytes = static_cast<uint16_t>(oval);
		        } catch (...) {
		            std::cerr << "--frag lap: invalid overlap size '" << lap_peek_num << "'\n";
		            exit(1);
		        }
		    }
		    std::cout << "[INFO] --frag lap: overlapping fragmentation enabled, "
		              << "overlap=" << config.frag_overlap_bytes << " bytes\n";

		} else if (token == "zof") {
		    if (seen_zof) {
		        std::cerr << "--frag: duplicate token 'zof'\n";
		        exit(1);
		    }
		    seen_zof = true;
		    config.frag_zof = true;
		    std::cout << "[INFO] --frag zof: zero-offset fragment will be sent last\n";

		} else {
		    std::cerr << "--frag: unknown token '" << token
		              << "'. Available: ofo, lap, zof\n";
		    exit(1);
		}
	    }

	    // zof and ofo are mutually exclusive
	    if (seen_zof && seen_ofo) {
		std::cerr << "--frag: 'zof' and 'ofo' cannot be used together.\n"
		          << "        zof sends the zero-offset fragment last;\n"
		          << "        ofo shuffles all fragments randomly, which destroys that guarantee.\n"
		          << "        Use one or the other.\n";
		exit(1);
	    }
	}},

	{"--mtu", [&](int& idx) {
	    std::string mtu_str = get_next_arg(idx, "--mtu");
	    int val = 0;
	    try {
		val = std::stoi(mtu_str);
	    } catch (...) {
		std::cerr << "--mtu: invalid value '" << mtu_str << "'\n";
		exit(1);
	    }
	    if (val < 22 || val > 65535) {
		std::cerr << "--mtu: value must be between 22 and 65535\n";
		exit(1);
	    }
	    int payload = val - 20;
	    if (payload % 2 != 0) {
		int adjusted = (payload / 2) * 2;
		if (adjusted < 2) adjusted = 2;
		std::cout << "[INFO] --mtu " << val << ": payload " << payload
		          << " bytes is not even "
		          << "Adjusting to MTU " << (adjusted + 20) << " (payload " << adjusted << " bytes)\n";
		val = adjusted + 20;
	    }
	    config.mtu_size          = static_cast<uint16_t>(val);
	    config.use_fragmentation = true;  // --mtu implies fragmentation
	}},
        
        {"--ws", [&](int& idx) {
            float ws_val = 0.0f;
            try {
                ws_val = std::stof(get_next_arg(idx, "--ws"));
            } catch (const std::exception&) {
                std::cerr << "--ws: invalid numeric value\n";
                exit(1);
            }
            if (ws_val < 0.0f || ws_val > 500.0f) {
                std::cerr << "Window scale must be between 0.5 and 30.0\n";
                exit(1);
            }
            config.window_scale = static_cast<uint8_t>(ws_val);
        }},
        
        {"--mss", [&](int& idx) {
            uint16_t mss = parse_uint16(get_next_arg(idx, "--mss"), "--mss");
            if (mss > 66666) {
                std::cerr << "Invalid value\n";
            }
            config.mss_value = mss;
        }},
        
        {"--t", [&](int& idx) {
            config.timestamp_val = parse_uint32(get_next_arg(idx, "--t"), "--t");
        }},
        
        {"--tsecr", [&](int& idx) {
            std::string tsecr_str = get_next_arg(idx, "--tsecr");
            try {
                if (tsecr_str.find("0x") == 0 || tsecr_str.find("0X") == 0) {
                    config.timestamp_ecr_custom = std::stoul(tsecr_str.substr(2), nullptr, 16);
                } else {
                    config.timestamp_ecr_custom = std::stoul(tsecr_str);
                }
            } catch (const std::exception& e) {
                std::cerr << "Invalid TSecr value: " << tsecr_str << " (" << e.what() << ")\n";
                exit(1);
            }
        }},
        
        {"--nops", [&](int& idx) {
            int temp_nops = 0;
            try {
                temp_nops = std::stoi(get_next_arg(idx, "--nops"));
            } catch (const std::exception&) {
                std::cerr << "--nops: invalid numeric value\n";
                exit(1);
            }
            if (temp_nops < 0 || temp_nops > 300) {
                std::cerr << "NOPs count must be between 0 and 300\n";
                exit(1);
            }
            config.nops_count = static_cast<uint16_t>(temp_nops);
        }},
        
        {"--set-rtt", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--set-rtt");
	    // Accept plain number (ms) or suffix: 290ms, 1s, 500ms
	    double ms_val = 0.0;
	    try {
		if (val.size() >= 2 && val.substr(val.size() - 2) == "ms") {
		    ms_val = std::stod(val.substr(0, val.size() - 2));
		} else if (!val.empty() && val.back() == 's') {
		    ms_val = std::stod(val.substr(0, val.size() - 1)) * 1000.0;
		} else {
		    ms_val = std::stod(val);  // plain number = ms
		}
	    } catch (const std::exception&) {
		std::cerr << "--set-rtt: invalid numeric value '" << val << "'\n";
		exit(1);
	    }
	    int rtt = static_cast<int>(ms_val);
	    if (rtt < 1 || rtt > 10000) {
		std::cerr << "--set-rtt: value must be between 1ms and 10000ms\n";
		exit(1);
	    }
	    config.initial_rtt_ms = rtt;
	}},
        
        {"--data", [&](int& idx) {
            config.custom_data = get_next_arg(idx, "--data");
            config.use_custom_data = true;
            config.generate_random_data = false;
        }},
        
        {"--data-length", [&](int& idx) {
            config.data_length = parse_uint16(get_next_arg(idx, "--data-length"), "--data-length");
            if (config.data_length > 1000) {
                std::cerr << "Data length too large (max 1000)\n";
                exit(1);
            }
            config.generate_random_data = true;
            config.use_custom_data = false;
        }},
        
        {"--sack", [&](int& idx) {
            std::string sack_str = get_next_arg(idx, "--sack");
            if (sack_str == "on" || sack_str == "1" || sack_str == "yes" || sack_str == "true") {
                config.sack_permitted = true;
            } else if (sack_str == "off" || sack_str == "0" || sack_str == "no" || sack_str == "false") {
                config.sack_permitted = false;
            } else {
                std::cerr << "Invalid SACK value. Use 'on' or 'off'\n";
                exit(1);
            }
        }},
        
        {"--src-mac", [&](int& idx) {
            std::string s = get_next_arg(idx, "--src-mac");
            if (!parse_mac(s, config.eth_opts.custom_src_mac)) {
                std::cerr << "Invalid --src-mac format, expected aa:bb:cc:dd:ee:ff\n";
                exit(1);
            }
            config.eth_opts.use_custom_src_mac = true;
        }},

        {"--dst-mac", [&](int& idx) {
            std::string s = get_next_arg(idx, "--dst-mac");
            if (!parse_mac(s, config.eth_opts.custom_dst_mac)) {
                std::cerr << "Invalid --dst-mac format, expected aa:bb:cc:dd:ee:ff\n";
                exit(1);
            }
            config.eth_opts.use_custom_dst_mac = true;
        }},

        {"--ether-type", [&](int& idx) {
            std::string s = get_next_arg(idx, "--ether-type");
            try {
                config.eth_opts.custom_ethertype = static_cast<uint16_t>(std::stoul(s, nullptr, 0));
            } catch (const std::exception&) {
                std::cerr << "--ether-type: invalid numeric value '" << s << "'\n";
                exit(1);
            }
            config.eth_opts.use_custom_ethertype = true;
        }},

        {"--vlan", [&](int& idx) {
            uint16_t vid = parse_uint16(get_next_arg(idx, "--vlan"), "--vlan");
            config.eth_opts.vlan_ids = { vid };
        }},

        {"--vlan-stack", [&](int& idx) {
            std::string v = get_next_arg(idx, "--vlan-stack");
            size_t comma = v.find(',');
            if (comma == std::string::npos) {
                std::cerr << "--vlan-stack requires format ID1,ID2\n";
                exit(1);
            }
            uint16_t id1 = parse_uint16(v.substr(0, comma), "--vlan-stack");
            uint16_t id2 = parse_uint16(v.substr(comma + 1), "--vlan-stack");
            config.eth_opts.vlan_ids = { id1, id2 };
        }},

        {"--ether-dst-multicast", [&](int& idx) {
            static const std::unordered_map<std::string, std::string> multicast_table = {
                {"ipv4-all", "01:00:5e:00:00:01"},
                {"stp",      "01:80:c2:00:00:00"},
                {"lldp",     "01:80:c2:00:00:0e"},
                {"all-nodes","33:33:00:00:00:01"}
            };
            std::string key = get_next_arg(idx, "--ether-dst-multicast");
            auto it = multicast_table.find(key);
            if (it == multicast_table.end()) {
                std::cerr << "Unknown multicast type: " << key << "\n";
                exit(1);
            }
            parse_mac(it->second, config.eth_opts.custom_dst_mac);
            config.eth_opts.use_custom_dst_mac = true;
        }},

        {"--ether-padding", [&](int& idx) {
            std::string v = get_next_arg(idx, "--ether-padding");
            if (v == "random") {
                config.eth_opts.random_padding = true;
                config.eth_opts.padding_size = 16;   // sensible default length for random padding
            } else {
                config.eth_opts.padding_size = parse_uint16(v, "--ether-padding");
            }
        }},
        
        {"--ttl", [&](int& idx) {
            int ttl_val = 0;
            try {
                ttl_val = std::stoi(get_next_arg(idx, "--ttl"));
            } catch (const std::exception&) {
                std::cerr << "--ttl: invalid numeric value\n";
                exit(1);
            }
            if (ttl_val < 0 || ttl_val > 259) {
                std::cerr << "TTL must be between 0 and 259\n";
                exit(1);
            }
            config.custom_ttl = static_cast<uint8_t>(ttl_val);
        }},
        
        {"--tcp-mtcp", [&](int& idx) {
            config.use_tcp_mptcp = true;
        }},

        {"--tcp-ao", [&](int& idx) {
            config.use_tcp_ao = true;
            // optional "keyid:rnextkeyid:maclen" e.g. --tcp-ao 1:1:16
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                std::string val = get_next_arg(idx, "--tcp-ao");
                size_t p1 = val.find(':');
                size_t p2 = (p1 == std::string::npos) ? std::string::npos
                                                        : val.find(':', p1 + 1);
                try {
                    if (p1 != std::string::npos) {
                        config.tcp_ao_keyid = static_cast<uint8_t>(std::stoi(val.substr(0, p1)));
                        if (p2 != std::string::npos) {
                            config.tcp_ao_rnextkeyid =
                                static_cast<uint8_t>(std::stoi(val.substr(p1 + 1, p2 - p1 - 1)));
                            config.tcp_ao_mac_len =
                                static_cast<uint8_t>(std::stoi(val.substr(p2 + 1)));
                        } else {
                            config.tcp_ao_rnextkeyid =
                                static_cast<uint8_t>(std::stoi(val.substr(p1 + 1)));
                        }
                    } else {
                        config.tcp_ao_keyid = static_cast<uint8_t>(std::stoi(val));
                    }
                } catch (...) {
                    std::cerr << "Invalid --tcp-ao value: " << val << "\n";
                    exit(1);
                }
            }
        }},

        {"--ip-rsa", [&](int& idx) {
            config.use_ip_router_alert = true;
        }},

        {"--ip-security", [&](int& idx) {
            config.use_ip_security = true;
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                std::string val = get_next_arg(idx, "--ip-security");
                try {
                    config.ip_security_classification =
                        static_cast<uint8_t>(std::stoul(val, nullptr, 0));
                } catch (...) {
                    std::cerr << "Invalid --ip-security classification: " << val << "\n";
                    exit(1);
                }
            }
        }},
        
        {"--dscp", [&](int& idx) {
            std::string dscp_arg = get_next_arg(idx, "--dscp");
            if (!parse_dscp_value(dscp_arg, config.custom_dscp)) {
                exit(1);
            }
        }},
        
         {"-Pn", [&](int& idx) {
            config.skip_ping = true;
        }},
        {"-sn", [&](int& idx) {
            config.sn_scan = true;
        }},
        
         {"-sV", [&](int& idx) {
            config.enable_version_detection = true;
        }},
        
         {"--sv-timeout", [&](int& idx) {
            try {
                config.sv_timeout_sec = std::stoi(get_next_arg(idx, "--sv-timeout"));
            } catch (const std::exception&) {
                std::cerr << "--sv-timeout: invalid numeric value\n";
                exit(1);
            }
        }},
        
         {"--connect-timeout", [&](int& idx) {
            try {
                config.sv_connect_timeout_sec = std::stoi(get_next_arg(idx, "--connect-timeout"));
            } catch (const std::exception&) {
                std::cerr << "--connect-timeout: invalid numeric value\n";
                exit(1);
            }
        }},
        
         {"--intensity", [&](int& idx) {
            try {
                config.sv_intensity = std::stoi(get_next_arg(idx, "--intensity"));
            } catch (const std::exception&) {
                std::cerr << "--intensity: invalid numeric value\n";
                exit(1);
            }
        }},
        
         {"--udp",         [&](int& idx) { config.sv_udp = true; }},
         {"--force-raw",   [&](int& idx) { config.sv_force_raw = true; }},
         {"--force-http",  [&](int& idx) { config.sv_force_http = true;  config.sv_force_https = false; }},
         {"--force-https", [&](int& idx) { config.sv_force_https = true; config.sv_force_http  = false; }},
         {"--tls-verify",  [&](int& idx) { config.sv_tls_verify = true; }},
         {"--verbose",     [&](int& idx) { config.sv_verbose = true; }},
         {"--save", [&](int& idx) {
            config.sv_save_file = get_next_arg(idx, "--save");
        }},
        
         {"--tls-ca", [&](int& idx) {
            config.sv_tls_ca_file = get_next_arg(idx, "--tls-ca");
        }},
        
         {"--tls-ca-path", [&](int& idx) {
            config.sv_tls_ca_path = get_next_arg(idx, "--tls-ca-path");
        }},
        
         {"--tls-cert", [&](int& idx) {
            config.sv_tls_cert = get_next_arg(idx, "--tls-cert");
        }},
        
         {"--tls-key", [&](int& idx) {
            config.sv_tls_key = get_next_arg(idx, "--tls-key");
        }},
        
         {"--tls-sni", [&](int& idx) {
            config.sv_tls_sni = get_next_arg(idx, "--tls-sni");
        }},
        
         {"--host", [&](int& idx) {
            config.sv_host_override = get_next_arg(idx, "--host");
        }},
        
        {"--ip-tos", [&](int& idx) {
            std::string tos_arg = get_next_arg(idx, "--ip-tos");
            if (!parse_ip_tos_value(tos_arg, config.custom_ip_tos)) {
                exit(1);
            }
            config.use_ip_tos = true;
            // Report what was set so the user can verify
            uint8_t dscp_val = (config.custom_ip_tos >> 2) & 0x3F;
            uint8_t ecn_val  =  config.custom_ip_tos & 0x03;
            std::cout << "[ip-tos] TOS=0x" << std::hex << std::uppercase
                      << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(config.custom_ip_tos)
                      << std::dec << std::setfill(' ')
                      << "  DSCP=" << static_cast<unsigned>(dscp_val)
                      << "  ECN="  << static_cast<unsigned>(ecn_val)  << "\n";
        }},
        
        {"--ip-flags", [&](int& idx) {
            try {
                config.custom_ip_flags = static_cast<uint16_t>(std::stoi(get_next_arg(idx, "--ip-flags"), nullptr, 0));
            } catch (const std::exception&) {
                std::cerr << "--ip-flags: invalid numeric value\n";
                exit(1);
            }
        }},
        
        {"--ip-id", [&](int& idx) {
	    std::string mode_arg = get_next_arg(idx, "--ip-id");
	    if (!parse_ip_id_mode(mode_arg, config.ip_id_mode, config.fixed_ip_id)) {
		exit(1);
	    }
	}},
	{"--fixed-ip-id", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--fixed-ip-id");
	    std::cerr << "[deprecated] --fixed-ip-id; use --ip-id " << val << " instead\n";
	    if (!parse_ip_id_mode(val, config.ip_id_mode, config.fixed_ip_id)) {
		exit(1);
	    }
	}},
        {"--badsum", [&](int& idx) {
            config.use_badsum = true;
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                const char* arg = argv[++idx];
                try {
                    size_t pos;
                    long val = std::stol(arg, &pos, 0);
                    if (pos != std::strlen(arg) || val < 0 || val > 0xFFFF) {
                        std::cerr << "error: --badsum '" << arg
                                  << "' is not a valid 16-bit value (0x0000–0xFFFF)\n";
                        exit(1);
                    }
                    config.custom_badsum_value = static_cast<uint16_t>(val);
                    config.badsum_value_set = true;
                } catch (const std::exception&) {
                    std::cerr << "error: --badsum '" << arg
                              << "' is not a valid hex or decimal number\n";
                    exit(1);
                }
            }
        }},
        
        {"--prsum", [&](int& idx) {
            config.use_partial_badsum = true;
            config.partial_badsum_type = get_next_arg(idx, "--prsum");
        }},
        
        
        {"--inject-tfo-cookie", [&](int& idx) {
            option_handlers["--inj-tfo-cookie"](idx);
        }},

        {"--retry-sport", [&](int& idx) {
            config.retry_source_port = parse_uint16(get_next_arg(idx, "--retry-sport"), "--retry-sport");
            if (config.retry_source_port == 0) {
                std::cerr << "--retry-sport: port must be 1-65535\n";
                exit(1);
            }
        }}
    };
    std::unordered_map<std::string, ScanType> scan_type_map = {
        {"--syn-scan", ScanType::SYN}, {"-sS", ScanType::SYN},
        {"--fin-scan", ScanType::FIN}, {"-sF", ScanType::FIN},
        {"--ack-scan", ScanType::ACK}, {"-sA", ScanType::ACK},
        {"--null-scan", ScanType::NULL_SCAN}, {"-sN", ScanType::NULL_SCAN},
        {"--xmas-scan", ScanType::XMAS}, {"-sX", ScanType::XMAS},
        {"--window-scan", ScanType::WINDOW}, {"-sW", ScanType::WINDOW},
        {"--maimon-scan", ScanType::MAIMON}, {"-sM", ScanType::MAIMON},
        {"--cwr-scan", ScanType::CWR}, {"-sCW", ScanType::CWR},
        {"--ece-scan", ScanType::ECE}, {"-sE", ScanType::ECE},
        {"--urg-scan", ScanType::URG}, {"-sUG", ScanType::URG},
        {"--psh-scan", ScanType::PSH}, {"-sPH", ScanType::PSH},
        {"--hanuman-scan", ScanType::HANUMAN}, {"-sH", ScanType::HANUMAN},
        {"--kakabhusundi-scan", ScanType::KAKABHUSUNDI}, {"-sK", ScanType::KAKABHUSUNDI},
        {"--ganesh-scan", ScanType::GANESH}, {"-sG", ScanType::GANESH},
        {"--ram-scan", ScanType::RAM}, {"-sR", ScanType::RAM},
        {"--garud-scan", ScanType::GARUD}, {"-sD", ScanType::GARUD},
        {"--jatayu-scan", ScanType::JATAYU}, {"-sJ", ScanType::JATAYU}
    };

    while (arg_idx < argc) {
        std::string arg = argv[arg_idx];
        auto scan_it = scan_type_map.find(arg);
        if (scan_it != scan_type_map.end()) {
            config.scan_type = scan_it->second;
            config.scan_type_specified = true;
            arg_idx++;
            continue;
        }
        
        auto it = option_handlers.find(arg);
        if (it != option_handlers.end()) {
            it->second(arg_idx);
            arg_idx++;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        } else {
	   if (!process_ip_string(arg, ips)) {
	       return 1;          // parse_targets already printed the error
	   }
	   arg_idx++;
	}
    }
    
    if (!config.ip_file.empty()) {
        if (!read_ips_from_file(config.ip_file, ips)) {
            return 1;
        }
    }
    
    if (config.use_trial_api) {
        std::string target_domain;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg[0] == '-') {
                if (arg == "--trial") {
                    i++; 
                }
                continue;
            }
            target_domain = arg;
            break;
        }
    
        if (target_domain.empty()) {
            std::cerr << "Error: --trial option requires a domain (e.g., example.com)\n";
            return 1;
        }

        std::cout << "\nSubdomain Enum for \"" << color::bold << target_domain << color::reset << "\"\n";

        ips.clear();
        std::vector<std::string> subdomains = fetch_subdomains_from_api(target_domain, config.trial_api_key);
        if (subdomains.empty()) {
            std::cout << std::left << std::setw(20) << "API Lookup"
                      << ": " << color::yellow << "trying jq-less method..." << color::reset << "\n";
            subdomains = fetch_subdomains_from_api_no_jq(target_domain, config.trial_api_key);
        }

        if (subdomains.empty()) {
            std::cerr << std::left << std::setw(20) << "API Lookup"
                      << ": " << color::red << "no subdomains found or API request failed" << color::reset << "\n";
            return 1;
        }

        std::cout << "Subdomain Found : " << subdomains.size() << "\n";

        std::vector<std::string> unique_subdomains;
        std::unordered_set<std::string> seen;

        for (const auto& sub : subdomains) {
            if (seen.find(sub) == seen.end()) {
                seen.insert(sub);
                unique_subdomains.push_back(sub);
            }
        }
        subdomains = std::move(unique_subdomains);

        std::vector<std::string> resolved_ips;
        std::unordered_map<std::string, std::vector<std::string>> ip_to_domains;
        std::vector<std::string> unresolved_subdomains;

        for (const auto& subdomain : subdomains) {
            struct hostent *host_entry = gethostbyname(subdomain.c_str());
            if (host_entry == nullptr || host_entry->h_addrtype != AF_INET) {
                unresolved_subdomains.push_back(subdomain);
                continue;
            }
    
            char ip_buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, host_entry->h_addr_list[0], ip_buffer, INET_ADDRSTRLEN);
            std::string resolved_ip = std::string(ip_buffer);
    
            ip_to_domains[resolved_ip].push_back(subdomain);
        }

        if (!unresolved_subdomains.empty()) {
            std::cout << "Unresolved : " << color::yellow << unresolved_subdomains.size()
                      << color::reset << " | ";
            for (size_t i = 0; i < unresolved_subdomains.size(); ++i) {
                std::cout << color::yellow << unresolved_subdomains[i] << color::reset;
                if (i + 1 < unresolved_subdomains.size()) std::cout << " , ";
            }
            std::cout << "\n";
        }

        std::cout << "Resolved IPs : " << ip_to_domains.size() << " unique ip addresses\n";

        std::vector<std::pair<std::string, std::vector<std::string>>> ip_domain_pairs(
            ip_to_domains.begin(), ip_to_domains.end());

        std::sort(ip_domain_pairs.begin(), ip_domain_pairs.end(),
            [](const auto& a, const auto& b) {
                return a.second.size() > b.second.size();
            });

        const int MAX_PER_ROW = 5;
        const std::string separator(70, '_');

        for (const auto& [ip, domains] : ip_domain_pairs) {
            std::cout << color::green << separator << color::reset << "\n";
            std::cout << "\nResolved Hosts for \"" << color::green << ip << color::reset << "\"\n";
            for (size_t i = 0; i < domains.size(); ++i) {
                std::cout << domains[i];
                if ((i + 1) % MAX_PER_ROW == 0 || i + 1 == domains.size())
                    std::cout << "\n";
                else
                    std::cout << "  ";
            }
        }

        for (const auto& [ip, domains] : ip_domain_pairs) {
            resolved_ips.push_back(ip);
        }
        ips = resolved_ips;

        if (resolved_ips.empty()) { 
            std::cerr << color::red << "Error: No subdomains could be resolved." 
                      << color::reset << "\n";
            return 1;
        }
        std::cout << color::bold << "\nSummary" << color::reset << "\n";
        std::cout << std::left << std::setw(20) << "Total Subdomains" << ": " << subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Resolved to IPv4" << ": " << subdomains.size() - unresolved_subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Unresolved"       << ": " << unresolved_subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Unique IPs"       << ": " << ip_to_domains.size() << "\n\n";

        std::cout << color::bold << "Ready to scan " << ip_to_domains.size() 
                  << " unique IP addresses" << color::reset << "\n\n";
                  
    }

    if (ips.size() > 5000000000) {
        std::cerr << color::red << "❌ Error: Maximum 5000000000 IPs supported" 
                  << color::reset << "\n";
        return 1;
    }
    if (ips.empty()) {
        std::cerr
            << color::yellow << "Damn!!:" << color::reset
            << " no target specified\n\n"

            << color::yellow << "Usage:" << color::reset << "\n"
            << "  " << color::green
            << "shiv <target> -p <ports> [options]"
            << color::reset << "\n\n"

            << color::yellow << "Examples:" << color::reset << "\n"
            << "  " << color::green
            << "shiv 192.168.1.1 -p 22,80,443"
            << color::reset << "\n"
            << "  " << color::green
            << "shiv example.com -p 1-1000 -sS"
            << color::reset << "\n\n"

            << color::yellow << "Help:" << color::reset << "\n"
            << "  Run "
            << color::green << "shiv --help" << color::reset
            << " for more information and unleash the power.\n";

        return 1;
    }
    if (ips.size() > 5000000000000) {
        std::cerr << "Maximum 5000000000000 IPs supported\n";
        return 1;
    }
    std::vector<int> ports;
    if (config.use_file) {
        ports = read_ports_from_file("/usr/share/shiv/ports.txt");
    } else {
        ports = std::move(config.parsed_ports);
    }
    
    if (!config.excluded_ports.empty()) {
        std::vector<int> filtered_ports;
        std::sort(ports.begin(), ports.end());
        std::sort(config.excluded_ports.begin(), config.excluded_ports.end());
        
        std::set_difference(ports.begin(), ports.end(), 
                           config.excluded_ports.begin(), config.excluded_ports.end(),
                           std::back_inserter(filtered_ports));
        
        ports = filtered_ports;
        
        if (ports.empty()) {
            std::cerr << "No valid ports to scan after exclusion.\n";
            return 1;
        }
    }
    
    if (ports.size() <= 9) {
        config.print_individual_closed_filtered = true;
    }
    if (ports.size() <= 4) {
        config.print_filtered_if_few = true;
    }
    
    if (ports.empty() || terminate_flag) {
        std::cerr << "No valid ports to scan.\n";
        return 1;
    }
    
    if (config.batch_specified && config.main_batch_size > ports.size()) {
         std::cerr << "Batch size (-b " << config.main_batch_size
                   << ") must be equal to or less than the number of ports scanned ("
                   << ports.size() << ")\n";
        return 1;
    }
    static const std::unordered_map<ScanType, std::string> scan_names = {
        {ScanType::SYN, "SYN"}, {ScanType::FIN, "FIN"}, {ScanType::ACK, "ACK"},
        {ScanType::NULL_SCAN, "NULL"}, {ScanType::XMAS, "XMAS"}, {ScanType::WINDOW, "WINDOW"},
        {ScanType::MAIMON, "MAIMON"}, {ScanType::CWR, "CWR"}, {ScanType::ECE, "ECE"},
        {ScanType::URG, "URG"}, {ScanType::PSH, "PSH"}, {ScanType::HANUMAN, "HANUMAN"},
        {ScanType::KAKABHUSUNDI, "KAKABHUSUNDI"}, {ScanType::GANESH, "GANESH"},
        {ScanType::RAM, "RAM"}, {ScanType::GARUD, "GARUD"}, {ScanType::JATAYU, "JATAYU"}
    };

    std::string scan_name = scan_names.count(config.scan_type) 
                            ? scan_names.at(config.scan_type) 
                            : "UNKNOWN";
    auto total_scan_start = std::chrono::steady_clock::now();
    struct rusage ru_total_start{};
    getrusage(RUSAGE_SELF, &ru_total_start);
    PacketBufferPool pool(ports.size(), 1, config.main_batch_size);
    std::atomic<int> total_down_hosts{0};
    // ── -sV: load probe database once, up front, not per-batch/per-host ────
    AllProbes vprobes;
    bool version_probes_loaded = false;
    if (config.enable_version_detection) {
        try {
            vprobes.loadFromFile("nmap-service-probes.txt");
            version_probes_loaded = true;
        } catch (const std::exception& e) {
            std::cerr << "[-sV] Failed to load nmap-service-probes.txt: "
                      << e.what() << "\n";
        }
    }

    // Create a single socket
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }
    int reuseport = 1;
    if (setsockopt(send_sock, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseport)) < 0) {
        std::cerr << "Failed to set SO_REUSEPORT: " << strerror(errno) << std::endl;
        close(send_sock);
        return 1;
    }
    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Setsockopt IP_HDRINCL failed: " << strerror(errno) << std::endl;
        close(send_sock);
        return 1;
    }

    ips.erase(std::remove_if(ips.begin(), ips.end(),
        [](const std::string& s) { return s.empty(); }), ips.end());

    if (ips.empty()) {
        std::cerr << "No valid IPs to scan after expansion.\n";
        close(send_sock);
        return 1;
    }

    bool have_ipv6_target = std::any_of(ips.begin(), ips.end(),
        [](const std::string& s) { return get_ip_version(s.c_str()) == 6; });
    int send_sock6 = -1;
    if (have_ipv6_target) {
        // IPPROTO_RAW (not IPPROTO_TCP) — matches the v4 socket above and is
        // required so IPV6_HDRINCL below is accepted for a non-ICMPv6 raw
        // socket. build_packet() writes a complete, hand-built ip6_hdr into
        // the buffer (see its is_ipv6 branch), so the kernel must be told
        // not to generate its own IPv6 header on top of it.
        send_sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (send_sock6 < 0) {
            std::cerr << "IPv6 socket creation failed: " << strerror(errno)
                      << " — IPv6 targets in this run will fail to send.\n";
        } else if (setsockopt(send_sock6, SOL_SOCKET, SO_REUSEPORT,
                               &reuseport, sizeof(reuseport)) < 0) {
            std::cerr << "Failed to set SO_REUSEPORT on IPv6 socket: "
                      << strerror(errno) << " — closing it; IPv6 targets "
                         "in this run will fail to send.\n";
            close(send_sock6);
            send_sock6 = -1;
        } else if (setsockopt(send_sock6, IPPROTO_IPV6, IPV6_HDRINCL,
                               &one, sizeof(one)) < 0) {
            std::cerr << "Failed to set IPV6_HDRINCL on IPv6 socket: "
                      << strerror(errno) << " — closing it; IPv6 targets "
                         "in this run will fail to send.\n";
            close(send_sock6);
            send_sock6 = -1;
        }
    }
    auto close_send_sockets = [&]() {
        close(send_sock);
        if (send_sock6 >= 0) close(send_sock6);
    };
    std::unordered_map<uint32_t, std::string> sn_mac_cache; 
    if (!config.skip_ping) {
        // Determine local subnet once for the first IP (representative)
        uint32_t ping_local_ip  = 0;
        uint32_t ping_netmask   = 0;
        bool     ping_subnet_ok = false;
        if (!ips.empty()) {
            ping_local_ip = get_local_ip(ips[0].c_str());
            if (ping_local_ip != 0) {
                std::string iface = autodetect_interface(ping_local_ip);
                int tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
                if (tmp_sock >= 0) {
                    uint8_t lip[4], mask[4];
                    memcpy(lip, &ping_local_ip, 4);
                    if (get_interface_ip_and_netmask(tmp_sock, iface.c_str(), lip, mask)) {
                        memcpy(&ping_netmask, mask, 4);
                        ping_subnet_ok = true;
                    }
                    close(tmp_sock);
                }
            }
        }
        if (config.sn_scan) {
            size_t down_hosts = 0;
	    std::vector<std::string> alive = perform_sn_discovery(ips, config.interface, down_hosts, sn_mac_cache);

            if (!config.scan_type_specified) {
                // -sn used alone: discovery only, no port scan
                close_send_sockets();
                return 0;
            }
            // -sn combined with -sS/-sF/etc: scan only the hosts that answered
            ips = std::move(alive);
            if (ips.empty()) {
                close_send_sockets();
                return 1;
            }
        }

        constexpr size_t TARGETS_PER_QUEUE = 1000;   // <-- the 1k limit

        // Collect only external IPs for pinging
        std::vector<std::string> external_ips;
        std::vector<size_t>      external_indices;
        for (size_t i = 0; i < ips.size(); ++i) {
            in_addr a{};
            if (inet_pton(AF_INET, ips[i].c_str(), &a) != 1) continue;
            uint32_t tip = a.s_addr;
            bool internal = ping_subnet_ok &&
                            is_same_subnet(tip, ping_local_ip, ping_netmask);
            if (!internal) {
                external_ips.push_back(ips[i]);
                external_indices.push_back(i);
            }
        }

        if (!external_ips.empty()) {
            auto ping_results = icmp_ping_sweep(external_ips, 1200);

            std::vector<std::string> surviving_ips;
            surviving_ips.reserve(ips.size());

            // Keep all internal IPs unchanged
            std::unordered_set<size_t> external_set(
                external_indices.begin(), external_indices.end());

            std::vector<bool> keep(ips.size(), true);
            

            for (size_t pi = 0; pi < ping_results.size(); ++pi) {
                const auto& pr  = ping_results[pi];
                size_t      idx = external_indices[pi];
                switch (pr.state) {
                    case IcmpHostState::Alive:
                        // fine — keep
                        break;
                    case IcmpHostState::Dead:
		        std::cout << "[ping] " << pr.ip
			          << " appears down (ICMP type 3 code 1: host unreachable) — skipping\n";
		        keep[idx] = false;
		        total_down_hosts++;
		        break;

		    case IcmpHostState::NoResponse:
		        std::cout << "[ping] " << pr.ip
			          << " no response (timeout — ICMP blocked or host down use -Pn) — skipping\n";
		        keep[idx] = false;
		        total_down_hosts++;
		        break;
                    case IcmpHostState::NetUnreachable:
                        std::cout << "[ping] " << pr.ip
                                  << " network unreachable"
                                     " (ICMP type 3 code 0: net unreachable)"
                                     " — skipping\n";
                        keep[idx] = false;
                        total_down_hosts++;
                        break;
                    case IcmpHostState::NetAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " network admin prohibited"
                                     " (ICMP type 3 code 9:"
                                     " ACL/router policy blocks subnet)"
                                     " — scanning anyway\n";
                        // keep = true: an active policy device replied,
                        // so the host exists — TCP ports may still be open.
                        break;
                    case IcmpHostState::HostAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " host admin prohibited"
                                     " (ICMP type 3 code 10:"
                                     " host firewall/ACL denies this IP)"
                                     " — scanning anyway\n";
                        // keep = true: host is reachable at network layer.
                        break;
                    case IcmpHostState::CommAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " communication admin prohibited"
                                     " (ICMP type 3 code 13:"
                                     " iptables REJECT / firewall policy)"
                                     " — scanning anyway\n";
                        // keep = true: active REJECT means host is definitely up.
                        break;
                }
            }

            // Rebuild ips and single_results in-place, preserving order
            std::vector<std::string> new_ips;
            new_ips.reserve(ips.size());
            for (size_t i = 0; i < ips.size(); ++i) {
                if (keep[i]) new_ips.push_back(ips[i]);
            }
            ips = std::move(new_ips);

            if (ips.empty()) {
                close_send_sockets();
                return 1;
            }
        }
    }

    constexpr size_t TARGETS_PER_QUEUE = 1000;   // <-- the 1k limit

    std::vector<RecPross> all_results(ips.size());

    const size_t total_targets = ips.size();
    size_t batch_start = 0;

    while (batch_start < total_targets && !terminate_flag) {
        size_t batch_end = std::min(batch_start + TARGETS_PER_QUEUE, total_targets);

        // Slice of IPs for this batch
        std::vector<std::string> batch_ips(
            ips.begin() + batch_start, ips.begin() + batch_end);

        // Results sub-vector for this batch
        std::vector<RecPross> batch_results(batch_ips.size());

        // SQPOLL's kernel poller thread busy-spins on its own dedicated
        // core for essentially the whole time it has work — sq_thread_idle
        // only trims the idle tail after the last submission, not the
        // spinning while packets are actively flowing. That's a good trade
        // only when the io_uring_enter syscalls it eliminates would have
        // cost more than the core-time spent keeping the poller hot.
        // Measured: a ~1300-probe single-host scan paid ~1.3 cores of sys
        // time for SQPOLL on both rings with no wall-clock win over the
        // plain ring. SQPOLL_PROBE_THRESHOLD is the total-probe count
        // (targets * ports) above which that trade starts paying off —
        // below it, both rings use the plain COOP_TASKRUN ring instead.
        constexpr size_t SQPOLL_PROBE_THRESHOLD = 50000;
        const size_t batch_probe_volume = batch_ips.size() * ports.size();
        const bool enable_sqpoll = batch_probe_volume >= SQPOLL_PROBE_THRESHOLD;

        {
            std::unique_ptr<GlobalRecvCtx> g_recv_ctx = init_global_recv_ctx(
                batch_ips, config.rcv_uring_depth, config.user_rcvbuf_size,
                enable_sqpoll);
            GlobalRecvCtx* g_recv = g_recv_ctx.get();
            if (!g_recv || !g_recv->valid) {
                std::cerr << "[main] Failed to init global recv context for batch "
                          << batch_start << "–" << batch_end << " — skipping\n";
                batch_start = batch_end;
                continue;
            }

            std::unique_ptr<GlobalSendCtx> g_send_ctx = init_global_send_ctx(
                send_sock, config.send_uring_depth, ports.size(), enable_sqpoll, send_sock6);
            GlobalSendCtx* g_send = g_send_ctx.get();
            if (!g_send || !g_send->valid) {
                std::cerr << "[main] Failed to init global send context for batch "
                          << batch_start << "–" << batch_end << " — skipping\n";
                batch_start = batch_end;
                continue;
            }
            if (config.debug_packet) {
                std::cerr << "[main] SQPOLL: TX ring " << (g_send->sqpoll_active ? "active" : "inactive")
                          << ", RX ring " << (g_recv->sqpoll_active ? "active" : "inactive") << "\n";
            }

            if (total_targets > TARGETS_PER_QUEUE) {
                std::cout << "[batch] Scanning targets "
                          << (batch_start + 1) << "–" << batch_end
                          << " of " << total_targets << "\n";
            }

            // Bundle the packet-crafting knobs into one TcpBuildOptions
            // struct instead of forwarding ~29 individual config.* fields —
            // see TcpBuildOptions in scan.hpp for why.
            TcpBuildOptions opts;
            opts.use_ip_tos              = config.use_ip_tos;
            opts.custom_ip_tos_byte      = config.custom_ip_tos;
            opts.use_manual_tcp_checksum = config.use_manual_tcp_checksum;
            opts.manual_tcp_checksum     = config.manual_tcp_checksum;
            opts.window_scale            = config.window_scale;
            opts.mss_value               = config.mss_value;
            opts.timestamp_val           = config.timestamp_val;
            opts.timestamp_ecr_custom    = config.timestamp_ecr_custom;
            opts.nops_count              = config.nops_count;
            opts.sack_permitted          = config.sack_permitted;
            opts.custom_data             = config.custom_data;
            opts.data_length             = config.data_length;
            opts.use_custom_data         = config.use_custom_data;
            opts.generate_random_data    = config.generate_random_data;
            opts.use_badsum              = config.use_badsum;
            opts.custom_badsum_value     = config.custom_badsum_value;
            opts.badsum_value_set        = config.badsum_value_set;
            opts.use_partial_badsum      = config.use_partial_badsum;
            opts.partial_badsum_type     = config.partial_badsum_type;
            opts.use_tfo_cookie          = config.use_tfo_cookie;
            opts.tfo_cookie_as_hex       = config.tfo_cookie_as_hex;
            opts.tfo_cookie_random       = config.tfo_cookie_random;
            opts.tfo_cookie_str          = config.tfo_cookie_str;
            opts.tfo_cookie_num          = config.tfo_cookie_num;
            opts.tfo_cookie_length       = config.tfo_cookie_length;
            opts.use_fragmentation       = config.use_fragmentation;
            opts.frag_size               = config.frag_offset_size;
            opts.mtu_size                = config.mtu_size;
            opts.packet_length_config    = config.packet_length_config;
            opts.use_tcp_mptcp              = config.use_tcp_mptcp;
            opts.use_tcp_ao                 = config.use_tcp_ao;
            opts.tcp_ao_keyid               = config.tcp_ao_keyid;
            opts.tcp_ao_rnextkeyid          = config.tcp_ao_rnextkeyid;
            opts.tcp_ao_mac_len             = config.tcp_ao_mac_len;
            opts.use_ip_router_alert        = config.use_ip_router_alert;
            opts.use_ip_security            = config.use_ip_security;
            opts.ip_security_classification = config.ip_security_classification;
            VersionDetectOptions sv_opts_from_config;
            sv_opts_from_config.timeout_sec         = config.sv_timeout_sec;
            sv_opts_from_config.connect_timeout_sec = config.sv_connect_timeout_sec;
            sv_opts_from_config.intensity           = config.sv_intensity;
            sv_opts_from_config.udp                 = config.sv_udp;
            sv_opts_from_config.force_raw           = config.sv_force_raw;
            sv_opts_from_config.force_http          = config.sv_force_http;
            sv_opts_from_config.force_https         = config.sv_force_https;
            sv_opts_from_config.tls_verify          = config.sv_tls_verify;
            sv_opts_from_config.verbose             = config.sv_verbose;
            sv_opts_from_config.save_file           = config.sv_save_file;
            sv_opts_from_config.tls_ca_file         = config.sv_tls_ca_file;
            sv_opts_from_config.tls_ca_path         = config.sv_tls_ca_path;
            sv_opts_from_config.tls_cert            = config.sv_tls_cert;
            sv_opts_from_config.tls_key             = config.sv_tls_key;
            sv_opts_from_config.tls_sni             = config.sv_tls_sni;
            sv_opts_from_config.host_override       = config.sv_host_override;

            thread_worker(batch_ips, ports, pool, send_sock,
                 batch_results, config.main_batch_size, config.seq_num, config.win_size,
                 config.print_individual_closed_filtered, config.print_filtered_if_few, config.fast_scan,
                 total_down_hosts, config.scan_type, config.custom_ttl, config.custom_dscp, config.custom_ip_flags,
                 config.ip_id_mode, config.fixed_ip_id,
                 opts,
                 config.user_rcvbuf_size, config.source_ip,
                 config.send_uring_depth, config.rcv_uring_depth,
                 config.base_source_port, config.retry_source_port, config.debug_packet,
                 config.debug_rtt, config.debug_wsn, config.debug_ttl, config.debug_demux, config.debug_strack, config.debug_send,
                 config.frag_out_of_order, config.frag_overlap, config.frag_overlap_bytes, config.frag_zof,
                 config.sport_range_cfg, config.gsport_cfg, config.initial_rtt_ms,
                 config.port_timeout_min_ms, config.port_timeout_max_ms,
                 config.rate_config, config.jitter_config, config.batch_delay_config,
                 config.bandwidth_config,
                 false, g_recv, g_send, config.interface, config.eth_opts,sn_mac_cache,config.enable_version_detection && version_probes_loaded, &vprobes,sv_opts_from_config);
        }  // g_recv_ctx and g_send_ctx destroyed here — reader thread stops cleanly

        // Copy batch results into the correct global slot
        for (size_t j = 0; j < batch_results.size(); ++j) {
            all_results[batch_start + j] = std::move(batch_results[j]);
        }

        batch_start = batch_end;

        // Sleep 5 seconds between batches (not after the last one)
        if (batch_start < total_targets && !terminate_flag) {
            std::cout << "[batch] Waiting 5 seconds before next batch...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    close_send_sockets();
    // all_results is already populated — no std::move needed here
    auto total_scan_end = std::chrono::steady_clock::now();
    auto total_duration = total_scan_end - total_scan_start;

    double total_elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        total_duration).count() / 1000.0;

    struct rusage ru_total_end{};
    getrusage(RUSAGE_SELF, &ru_total_end);
    double total_cpu_seconds =
        (ru_total_end.ru_utime.tv_sec  - ru_total_start.ru_utime.tv_sec)  +
        (ru_total_end.ru_utime.tv_usec - ru_total_start.ru_utime.tv_usec) / 1e6 +
        (ru_total_end.ru_stime.tv_sec  - ru_total_start.ru_stime.tv_sec)  +
        (ru_total_end.ru_stime.tv_usec - ru_total_start.ru_stime.tv_usec) / 1e6;

    std::cout << "\n";
    if (ips.size() > 1) {
    
        if (total_elapsed_ms < 1.0) {
            double total_elapsed_us = total_elapsed_ms * 1000;
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(1) 
                      << total_elapsed_us << " microseconds\n";
        } else if (total_elapsed_ms < 1000.0) {
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2) 
                      << total_elapsed_ms << " milliseconds\n";
        } else {
            double total_elapsed_seconds = total_elapsed_ms / 1000.0;
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2) 
                      << total_elapsed_seconds << " seconds\n";
        }
        // CPU Time here is process-wide (RUSAGE_SELF sums all threads on
        // Linux) — this is the efficiency number to watch when tuning
        // SQPOLL/spin/thread-count knobs; Duration above is the
        // user-facing speed number and the two are independent axes.
        std::cout << "CPU time used: " << std::fixed << std::setprecision(3)
                  << total_cpu_seconds << " seconds (user+sys)\n";
    
    }
    if (!config.output_file.empty()) {
        save_scan_results(all_results, config.output_file, teeOut.str() + teeErr.str());
    }

    // Restore the real streambufs (not strictly required before process exit,
    // but keeps cout/cerr well-behaved if anything runs after this point).
    std::cout.rdbuf(teeOut_orig);
    std::cerr.rdbuf(teeErr_orig);

    if (terminate_flag) {
        std::cout << "\nScan interrupted by user.\n";
    }

    if (config.use_shodan_enum && !ips.empty()) {
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "SHODAN INTERNETDB ENUMERATION" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        std::set<std::string> unique_ips(ips.begin(), ips.end());
        int ip_count = 1;
        int total_ips = unique_ips.size();
        for (const auto& ip : unique_ips) {
            std::cout << "\n[" << ip_count << "/" << total_ips << "] ";
            std::cout.flush();
        
            std::string shodan_data = fetch_shodan_info(ip);
        
            if (!shodan_data.empty()) {
                display_shodan_info(shodan_data, ip);
            } else {
                std::cout << "No data for " << ip << std::endl;
            }
        
            ip_count++;
            if (ip_count <= total_ips) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }
    int total_down_hosts_count = total_down_hosts.load();
    if (total_down_hosts_count > 0) {
        print_output(PrintOutputType::DOWN_HOSTS_SUMMARY, "", 0, "", "", "",
                     0, 0, total_down_hosts_count, 0, 0, ips.size(), 
                     "", "", 0.0, "", false, true);
    }
    
    return 0;
}

