#include "utils.hpp"
#include "public_db.hpp"
#include <fstream>
#include <termios.h>
#include <cstdlib>
#include "scan.hpp"
#include "icmp_ping.hpp"
#include "traceroute.hpp"
#include "probe.hpp"
#include "async_io.hpp"
#include "netns_split.hpp"
#include "os_detect.hpp"
#include <stdexcept>
#include <future>
#include <thread>
#include <ctime>
#include <map>
#include <algorithm>
#include <pthread.h>
#include <malloc.h>
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
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <atomic>
#include "debug.hpp"
#include "handler.hpp"
#include "dns_enum.hpp"
#include "simulations.hpp"

static int init_arp_ring(struct io_uring* ring, unsigned entries) {
    struct io_uring_params p{};
    p.flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    if (io_uring_queue_init_params(entries, ring, &p) == 0) return 0;
    return io_uring_queue_init(entries, ring, IORING_SETUP_COOP_TASKRUN);
}

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

void print_typewriter(std::ostream& os, const std::string& text,
                              std::chrono::milliseconds delay) {
    size_t i = 0;
    const size_t n = text.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        size_t len = 1;
        if      ((c & 0x80) == 0x00) len = 1;   
        else if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;   
        else if ((c & 0xF8) == 0xF0) len = 4;
        len = std::min(len, n - i);
        os.write(text.data() + i, (std::streamsize)len);
        os.flush();
        i += len;
        if (c != '\n')
            std::this_thread::sleep_for(delay);
    }
}

const char* kMantra =
    "ॐ त्र्यम्बकं यजामहे सुगन्धिं पुष्टिवर्धनम् |\n"
    "उर्वारुकमिव बन्धनान्मृत्योर्मुक्षीय माऽमृतात् ||\n";

std::vector<int> global_raw_sockets;
std::vector<io_uring*> global_uring_rings;
std::vector<std::thread*> global_worker_threads;
std::mutex global_resources_mutex;

constexpr size_t MAX_EXPANDED_IPS_PER_CIDR = 1000000;   
constexpr size_t MAX_TOTAL_IPS             = 50000000;    
constexpr size_t MAX_INPUT_TOKEN_LEN       = 2048;
constexpr size_t TARGETS_PER_QUEUE = 1000;
constexpr size_t MAX_IL_FILE_LINES         = 2000000;
constexpr size_t MAX_IL_FILE_BYTES         = 256ull * 1024 * 1024;

std::unordered_map<std::string, std::string> mac_vendor_map;
std::unordered_map<std::string, std::string> ip_to_domain_map;
std::vector<std::string> g_dns_bypassed_targets;
std::unordered_map<std::string, std::vector<std::string>> g_not_scanned_map;
std::vector<std::string> g_dns_servers;
std::vector<std::string> g_dns_tls_servers;
std::unordered_set<std::string> g_seen_target_ips;
std::vector<std::pair<std::string, std::string>> g_eliminated_targets;
std::atomic<int> crash_signal{0};
int g_target_ip_pref = 0;
bool g_saw_literal_target = false;

struct termios g_orig_termios;
bool g_termios_saved = false;

void restore_terminal_echo() {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    }
}


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
bool custom_dns_configured();

// Vectorized forward resolution (hostname -> IP). Resolves the whole batch
// concurrently instead of one blocking getaddrinfo()/thread per name --
// suitable for 1000+ hostnames in a single call. See definition below for
// the exact server-selection and fallback rules.
bool resolve_domain_to_ip_batch(const std::vector<std::string>& domains,
                                 std::unordered_map<std::string, std::string>& out_ip,
                                 std::unordered_map<std::string, std::vector<std::string>>& out_all_ips,
                                 std::vector<std::string>& out_unresolved,
                                 int timeout_ms = 2000,
                                 int retries = 2,
                                 int concurrency = 500);

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

    std::unordered_set<std::string>& seen = g_seen_target_ips;
    seen.reserve(seen.size() + seen_reserve);

    std::vector<std::string> pending_hostnames;      // domains seen this call, in order
    std::unordered_set<std::string> pending_seen;    // de-dupe before the batch resolve
    pending_hostnames.reserve(dns_reserve);
    pending_seen.reserve(dns_reserve);

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

        {
            std::string base_domain;
            if (simulations::is_wildcard_target_spec(token, base_domain)) {
                g_saw_literal_target = true;

                simulations::SimulationResult sim =
                    simulations::run_wildcard_enum_simulation(base_domain);

                if (!sim.ok) {
                    std::cerr << "Simulation failed for *." << base_domain
                              << ": " << sim.error << "\n";
                    return false;
                }

                for (const auto& host : sim.resolved_hosts)
                    for (const auto& ip : host.ips)
                        ip_to_domain_map[ip] = host.hostname;

                if (!sim.unresolved_hosts.empty())
                    g_not_scanned_map[base_domain] = sim.unresolved_hosts;

                for (const auto& ip : sim.unique_ips)
                    add_unique_ip(bulk_ips, seen, ip);

                if (ips.size() + bulk_ips.size() > MAX_TOTAL_IPS) {
                    std::cerr << "Too many IPs after expansion (limit "
                              << MAX_TOTAL_IPS << ")\n";
                    return false;
                }
                continue;
            }
        }

        if (token.find('/') != std::string::npos) {
            g_saw_literal_target = true;
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

            if (!normalize_ip_string(token, out_ip)) {
                // Not a literal IP — defer to the single batch DNS pass
                // after this loop instead of resolving one name at a time.
                if (pending_seen.insert(token).second) pending_hostnames.push_back(token);
                continue; // Step F's limit check runs after the batch resolve instead
            } else {
                g_saw_literal_target = true;
                if (custom_dns_configured()) {
                    g_dns_bypassed_targets.push_back(token);
                }
            }
           
            const std::string literal_ip = out_ip;
            if (!add_unique_ip(bulk_ips, seen, std::move(out_ip))) {
                g_eliminated_targets.emplace_back(token, literal_ip);
            }
        }

        // ── Step F: global limit check ──────────────────────────────────
        if (ips.size() + bulk_ips.size() > MAX_TOTAL_IPS) {
            std::cerr << "Too many IPs after expansion (limit "
                      << MAX_TOTAL_IPS << ")\n";
            return false;
        }
    }
    if (!pending_hostnames.empty()) {
        std::unordered_map<std::string, std::string> resolved_ip;
        std::unordered_map<std::string, std::vector<std::string>> resolved_all_ips;
        std::vector<std::string> unresolved;
        resolve_domain_to_ip_batch(pending_hostnames, resolved_ip, resolved_all_ips, unresolved);

        if (!unresolved.empty()) {
            std::cerr << "Cannot resolve '" << unresolved.front() << "'\n";
            return false;
        }

        for (const auto& token : pending_hostnames) {
            const std::string& out_ip = resolved_ip.at(token);
            if (add_unique_ip(bulk_ips, seen, out_ip)) {
                ip_to_domain_map[out_ip] = token;
            } else {
                g_eliminated_targets.emplace_back(token, out_ip);
            }

            if (ips.size() + bulk_ips.size() > MAX_TOTAL_IPS) {
                std::cerr << "Too many IPs after expansion (limit "
                          << MAX_TOTAL_IPS << ")\n";
                return false;
            }
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

    void* raw = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    close(fd);
    if (raw == MAP_FAILED) return;
    struct MmapCloser {
        void*  addr;
        size_t len;
        ~MmapCloser() { if (addr && addr != MAP_FAILED) munmap(addr, len); }
    } mmap_guard{raw, file_size};

    char* data = static_cast<char*>(raw);
    mac_vendor_map.reserve(35000);

    const char* end = data + file_size;
    const char* p = data;
    while (p < end) {
        const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
        const char* line_end = nl ? nl : end;
        const char* next_line = nl ? nl + 1 : end;
        if (line_end > p && line_end[-1] == '\r') --line_end;
        if (p == line_end || *p == '#') { p = next_line; continue; }
        const char* delim = p;
        while (delim < line_end && *delim != ' ' && *delim != '\t') ++delim;
        if (delim == line_end) { p = next_line; continue; }
        char key[7]; int k = 0;
        for (const char* c = p; c < delim && k < 6; ++c)
            if (*c != ':') key[k++] = toupper((unsigned char)*c);
        if (k != 6) { p = next_line; continue; }

        const char* v = delim;
        while (v < line_end && (*v == ' ' || *v == '\t')) ++v;

        mac_vendor_map.emplace(std::string(key, 6), std::string(v, line_end - v));
        p = next_line;
    }
}

std::string get_mac_vendor(const std::string &mac_address) {
    if (mac_address.size() < 8) return "unknown"; 
    char key[7] = {};
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

struct IfaceSubnetInfo { bool ok = false; uint32_t netmask_int = 0; };

static std::mutex g_iface_subnet_mutex;
static std::unordered_map<std::string, IfaceSubnetInfo> g_iface_subnet_cache;

static IfaceSubnetInfo get_iface_subnet_info_cached(const std::string& interface) {
    {
        std::lock_guard<std::mutex> lk(g_iface_subnet_mutex);
        auto it = g_iface_subnet_cache.find(interface);
        if (it != g_iface_subnet_cache.end()) return it->second;
    }
    IfaceSubnetInfo info;
    uint8_t src_ip_bytes[4] = {0}, netmask[4] = {0};
    int tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (tmp_sock >= 0) {
        if (get_interface_ip_and_netmask(tmp_sock, interface.c_str(), src_ip_bytes, netmask)) {
            memcpy(&info.netmask_int, netmask, 4);
            info.ok = true;
        }
        close(tmp_sock);
    }
    if (!info.ok) return info;
    std::lock_guard<std::mutex> lk(g_iface_subnet_mutex);
    return g_iface_subnet_cache[interface] = info;
}

static bool classify_v4_onlink(const std::string& target_ip, uint32_t ip_int,
                                uint32_t local_ip_int, uint32_t netmask_int, bool subnet_ok,
                                const std::string& interface) {
    bool topologically_onlink = subnet_ok && is_same_subnet(ip_int, local_ip_int, netmask_int);

    bool route_onlink = false;
    std::string route_iface;
    if (!topologically_onlink) {
        bool is_onlink_route = false;
        if (route_lookup(target_ip, AF_INET, route_iface, is_onlink_route) && is_onlink_route)
            route_onlink = true;
    }

    bool cache_onlink = !topologically_onlink && !route_onlink
                         && (neighbor_cache_has_entry_v4(target_ip) || conntrack_has_entry(target_ip));

    std::string check_iface = topologically_onlink ? interface : route_iface;
    bool is_ptp = !check_iface.empty() && is_point_to_point_interface(check_iface);

    return (topologically_onlink || route_onlink || cache_onlink) && !is_ptp;
}

bool is_target_onlink(const std::string& target_ip, std::string interface = "") {
    int ip_version = get_ip_version(target_ip.c_str());
    if (ip_version == 4) {
        uint32_t local_ip_int = get_local_ip(target_ip.c_str());
        if (local_ip_int == 0) return false;
        if (interface.empty()) interface = autodetect_interface(local_ip_int);

        IfaceSubnetInfo iface_info = get_iface_subnet_info_cached(interface);
        uint32_t netmask_int = iface_info.netmask_int;
        bool     subnet_ok   = iface_info.ok;

        uint8_t ip_bytes[4] = {0};
        if (inet_pton(AF_INET, target_ip.c_str(), ip_bytes) <= 0) return false;
        uint32_t ip_int; memcpy(&ip_int, ip_bytes, 4);

        return classify_v4_onlink(target_ip, ip_int, local_ip_int, netmask_int, subnet_ok, interface);
    } else if (ip_version == 6) {
        struct in6_addr target6{};
        bool topologically_onlink = false;
        if (inet_pton(AF_INET6, target_ip.c_str(), &target6) == 1) {
            std::string check_if = interface;
            if (check_if.empty()) {
                bool route_onlink_v6 = false;
                std::string route_iface_v6;
                if (route_lookup(target_ip, AF_INET6, route_iface_v6, route_onlink_v6) &&
                    !route_iface_v6.empty()) {
                    check_if = route_iface_v6;
                } else {
                    uint8_t local_ip6_bytes[16] = {0};
                    if (get_local_ip6(target_ip.c_str(), local_ip6_bytes)) {
                        struct in6_addr local_addr6{};
                        memcpy(&local_addr6, local_ip6_bytes, 16);
                        check_if = autodetect_interface(local_addr6);
                    } else {
                        std::string default_iface, default_gw;
                        check_if = (get_default_route(AF_INET6, default_iface, default_gw) && !default_iface.empty())
                                       ? default_iface : "eth0";
                    }
                }
            }
            for (const auto& local : get_all_interface_ip6(check_if)) {
                if (local.scope == Ipv6Scope::LinkLocal) continue; 
                int full_bytes = local.prefix_len / 8;
                int rem_bits   = local.prefix_len % 8;
                bool match = (full_bytes == 0) || memcmp(target6.s6_addr, local.addr, full_bytes) == 0;
                if (match && rem_bits && full_bytes < 16) {
                    uint8_t m = static_cast<uint8_t>(0xFF << (8 - rem_bits));
                    match = (target6.s6_addr[full_bytes] & m) == (local.addr[full_bytes] & m);
                }
                if (match) { topologically_onlink = true; break; }
            }
        }
        if (topologically_onlink) {
            bool is_ptp6 = !interface.empty() && is_point_to_point_interface(interface);
            return !is_ptp6;
        }

        std::string route_iface;
        bool is_onlink_route = false;
        if (route_lookup(target_ip, AF_INET6, route_iface, is_onlink_route) && is_onlink_route) {
            return !is_point_to_point_interface(route_iface);
        }
        bool cache_onlink = neighbor_cache_has_entry(AF_INET6, target_ip) || conntrack_has_entry(target_ip);
        return cache_onlink && !(!route_iface.empty() && is_point_to_point_interface(route_iface));
    }
    return false;
}

bool is_target_same_network_internal(const std::string& target_ip, std::string* out_iface = nullptr) {
    int ip_version = get_ip_version(target_ip.c_str());
    int family = (ip_version == 6) ? AF_INET6 : AF_INET;

    std::string target_iface, target_gw;
    bool target_onlink = false;
    if (!route_lookup(target_ip, family, target_iface, target_onlink, &target_gw)) return false;
    if (out_iface) *out_iface = target_iface;

    std::string default_iface, default_gw;
    bool have_default = get_default_route(family, default_iface, default_gw);

    if (!have_default) {
        return target_onlink;
    }
    bool same_as_default_path = (target_iface == default_iface) && (target_gw == default_gw);
    return !same_as_default_path;
}

bool is_target_onlink_cached(const std::string& target_ip, const std::string& interface = "") {
    return is_target_onlink(target_ip, interface);
}

TargetLocality assess_target_locality(const std::string& target_ip, std::string interface) {
    TargetLocality result;
    result.onlink = is_target_onlink_cached(target_ip, interface);

    if (!result.onlink) {
        result.same_network_internal = is_target_same_network_internal(target_ip, &result.routed_iface);
        return result;
    }
    int ip_version = get_ip_version(target_ip.c_str());
    int family = (ip_version == 6) ? AF_INET6 : AF_INET;
    std::string check_iface = interface;
    if (check_iface.empty()) {
        std::string route_iface; bool tmp_onlink = false;
        if (route_lookup(target_ip, family, route_iface, tmp_onlink)) check_iface = route_iface;
    }
    if (!check_iface.empty() && classify_interface_kind(check_iface) == "virtual") {
        result.via_virtual_interface = true;

        constexpr uint64_t kConntrackGraceMs = 3000; // conntrack table needs a beat to populate post-split
        uint64_t entered_at = g_split_ns_entered_at_ms.load(std::memory_order_acquire);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        bool in_post_split_grace = entered_at != 0 &&
            static_cast<uint64_t>(now_ms) - entered_at < kConntrackGraceMs;
        result.corroborated = in_post_split_grace ? true : conntrack_has_entry(target_ip);
    }
    return result;
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

    {
        bool has_v4 = false, has_v6 = false;
        for (const auto& ip_str : ips) {
            uint8_t tmp4[4];
            struct in6_addr tmp6;
            if (inet_pton(AF_INET, ip_str.c_str(), tmp4) == 1) has_v4 = true;
            else if (inet_pton(AF_INET6, ip_str.c_str(), &tmp6) == 1) has_v6 = true;
            if (has_v4 && has_v6) break;
        }
        std::vector<std::string> parts;
        if (has_v4) parts.push_back("ARP");
        if (has_v6) parts.push_back("NDP");
        parts.push_back("ICMP");

        std::string method_label;
        for (size_t p = 0; p < parts.size(); ++p) {
            if (p > 0) method_label += " + ";
            method_label += parts[p];
        }
        method_label += " Ping";

        std::cout << "\nStarting " << color::bold << "Shiv" << color::reset
                  << " (" << color::yellow << method_label << color::reset
                  << ") scan at " << get_current_time() << "\n";
        std::cout.flush();
    }

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
    // Our own interface IP, for the self-scan special case below.
    uint32_t own_ip_int = 0;
    if (subnet_ok) memcpy(&own_ip_int, src_ip_bytes, 4);

    int      ifindex6           = 0;
    bool     have_v6_iface      = false;
    struct in6_addr local_ip6_prefix {};
    int      local_ip6_prefixlen = 0;

    if (!interface.empty()) {
        ifindex6 = static_cast<int>(if_nametoindex(interface.c_str()));

        struct ifaddrs* ifa_list = nullptr;
        if (getifaddrs(&ifa_list) == 0) {
            for (struct ifaddrs* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6) continue;
                if (interface != ifa->ifa_name) continue;
                auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
                local_ip6_prefix = sa6->sin6_addr;
                have_v6_iface    = true;
                if (ifa->ifa_netmask) {
                    auto* mask6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_netmask);
                    local_ip6_prefixlen = 0;
                    for (int b = 0; b < 16; ++b) {
                        uint8_t byte = mask6->sin6_addr.s6_addr[b];
                        while (byte & 0x80) { local_ip6_prefixlen++; byte = static_cast<uint8_t>(byte << 1); }
                    }
                }
                if (!IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) break;
            }
            freeifaddrs(ifa_list);
        }
    }

    auto is_on_link6 = [&](const struct in6_addr& target) -> bool {
        if (!have_v6_iface || local_ip6_prefixlen <= 0) return false;
        int full_bytes = local_ip6_prefixlen / 8;
        int rem_bits   = local_ip6_prefixlen % 8;
        if (full_bytes > 0 && memcmp(target.s6_addr, local_ip6_prefix.s6_addr, full_bytes) != 0) return false;
        if (rem_bits == 0) return true;
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem_bits));
        return (target.s6_addr[full_bytes] & mask) == (local_ip6_prefix.s6_addr[full_bytes] & mask);
    };

    struct HostSlot { std::string ip; bool alive=false; std::string mac; double dur_s=0.0; double cpu_s=0.0; uint32_t ip_int=0; bool icmp_only_no_mac=false; bool is_self_host=false; IcmpHostState icmp_state=IcmpHostState::NoResponse; };
    std::vector<HostSlot> slots(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) slots[i].ip = ips[i];

    std::vector<uint8_t*> arp_target_ptrs;
    std::vector<std::unique_ptr<uint8_t[]>> arp_target_bufs;
    std::vector<size_t> arp_indices;
    std::vector<std::string> icmp_ips;
    std::vector<size_t> icmp_indices;
    std::vector<std::string> ndp_ips;
    std::vector<size_t>      ndp_indices;
    std::vector<std::string> icmp6_ips;
    std::vector<size_t>      icmp6_indices;
    std::vector<bool> arp_alive(ips.size(), false);
    std::vector<bool> icmp_alive(ips.size(), false);
    std::vector<bool> is_lan_host(ips.size(), false);
    std::vector<bool> ndp_alive(ips.size(), false);
    std::vector<bool> icmp6_alive(ips.size(), false);
    std::vector<bool> is_lan_host6(ips.size(), false);

    for (size_t i = 0; i < ips.size(); ++i) {
        uint8_t ip_bytes[4] = {0};
        if (inet_pton(AF_INET, ips[i].c_str(), ip_bytes) <= 0) {
            struct in6_addr a6 {};
            if (::inet_pton(AF_INET6, ips[i].c_str(), &a6) == 1) {
                if (ifindex6 > 0 && is_on_link6(a6)) {
                    ndp_ips.push_back(ips[i]);
                    ndp_indices.push_back(i);
                    is_lan_host6[i] = true;
                    icmp6_ips.push_back(ips[i]);
                    icmp6_indices.push_back(i);
                } else {
                    icmp6_ips.push_back(ips[i]);
                    icmp6_indices.push_back(i);
                }
            }
            continue;
        }
        uint32_t ip_int; memcpy(&ip_int, ip_bytes, 4);
        slots[i].ip_int = ip_int;
        if (subnet_ok && ip_int == own_ip_int) {
            slots[i].alive        = true;
            slots[i].mac          = format_mac(src_mac);
            slots[i].is_self_host = true;
            continue;
        }
        bool is_onlink = classify_v4_onlink(ips[i], ip_int, local_ip_int, netmask_int, subnet_ok, interface);

        if (is_onlink) {
            auto buf = std::make_unique<uint8_t[]>(4);
            memcpy(buf.get(), ip_bytes, 4);
            arp_target_ptrs.push_back(buf.get());
            arp_target_bufs.push_back(std::move(buf));
            arp_indices.push_back(i);
            is_lan_host[i] = true;
            icmp_ips.push_back(ips[i]);
            icmp_indices.push_back(i);
        } else {
            icmp_ips.push_back(ips[i]);
            icmp_indices.push_back(i);
        }
    }

    constexpr size_t ARP_BATCH_SIZE = 63;
    if (!arp_target_ptrs.empty() && subnet_ok) {
        int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (arp_sock >= 0) {
            struct io_uring arp_ring;
            if (init_arp_ring(&arp_ring, 512) == 0) {
                auto arp_start = std::chrono::steady_clock::now();
                struct rusage ru_start{}; getrusage(RUSAGE_SELF, &ru_start);

                const size_t total_arp_targets = arp_target_ptrs.size();
                std::vector<double> arp_rtt_ms_all(total_arp_targets, 0.0);
                for (size_t batch_start = 0; batch_start < total_arp_targets; batch_start += ARP_BATCH_SIZE) {
                    const size_t batch_end = std::min(batch_start + ARP_BATCH_SIZE, total_arp_targets);
                    const size_t this_batch_size = batch_end - batch_start;

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

                    std::vector<double> arp_rtt_ms(this_batch_size, 0.0);
                    if (send_arp_request(arp_sock, &arp_ring, interface.c_str(), src_mac,
                                          src_ip_bytes, batch_target_ptrs)) {
                        receive_arp_reply(arp_sock, &arp_ring, batch_target_ptrs, mac_ptrs,
                                           EthArpOptions{}, /*initial_rtt_ms=*/100,
                                           interface.c_str(), src_mac, src_ip_bytes,
                                           /*max_retries=*/2,
                                           /*min_round_timeout_ms=*/20,
                                           /*max_round_timeout_ms=*/1000,
                                           &arp_rtt_ms);
                    }

                    for (size_t j = 0; j < this_batch_size; ++j) {
                        size_t idx = arp_indices[batch_start + j];
                        uint8_t* m = mac_ptrs[j];
                        bool resolved = (m[0]|m[1]|m[2]|m[3]|m[4]|m[5]) != 0;
                        arp_alive[idx] = resolved;
                        if (resolved) slots[idx].mac = format_mac(m);
                        arp_rtt_ms_all[batch_start + j] = arp_rtt_ms[j];
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
                    slots[arp_indices[j]].dur_s = (arp_rtt_ms_all[j] > 0.0) ? arp_rtt_ms_all[j] / 1000.0 : dur_s;
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
            slots[idx].icmp_state = results[k].state;
            slots[idx].dur_s = (results[k].rtt_s > 0.0) ? results[k].rtt_s : dur_s;
            slots[idx].cpu_s = cpu_s;
            if (!is_lan_host[idx]) {
                // Off-subnet host: no ARP opinion was ever formed for it,
                // ICMP is the only signal, decide right here.
                slots[idx].alive = alive_icmp;
            }
        }
        std::vector<std::string> syn_ips;
        std::vector<size_t>      syn_indices;
        for (size_t k = 0; k < results.size(); ++k) {
            size_t idx = icmp_indices[k];
            if (is_lan_host[idx]) continue;
            bool retryable = results[k].state == IcmpHostState::NoResponse
                            || results[k].state == IcmpHostState::FragNeeded
                            || results[k].state == IcmpHostState::TtlExceeded
                            || results[k].state == IcmpHostState::FragTimeout
                            || results[k].state == IcmpHostState::BadSpi;
            if (!retryable) continue;
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

    // ---- NDP pass: on-link IPv6 targets, mirrors the ARP pass above ----
    struct rusage ru_v6_start{}; getrusage(RUSAGE_SELF, &ru_v6_start);
    if (!ndp_ips.empty() && ifindex6 > 0) {
        auto ndp_results = ndp_neighbor_sweep(ndp_ips, src_mac, ifindex6, 1200);
        for (size_t k = 0; k < ndp_results.size(); ++k) {
            size_t idx = ndp_indices[k];
            ndp_alive[idx] = (ndp_results[k].state == IcmpHostState::Alive);
            if (ndp_alive[idx]) slots[idx].dur_s = ndp_results[k].rtt_s;
        }
    }

    // ---- ICMPv6 pass: off-link IPv6 targets + LAN v6 hosts (second signal)
    if (!icmp6_ips.empty()) {
        auto icmp6_results = icmp6_ping_sweep(icmp6_ips, 1200);
        for (size_t k = 0; k < icmp6_results.size(); ++k) {
            size_t idx = icmp6_indices[k];
            bool alive6 = (icmp6_results[k].state == IcmpHostState::Alive
                         || icmp6_results[k].state == IcmpHostState::NetAdminProhibited
                         || icmp6_results[k].state == IcmpHostState::HostAdminProhibited
                         || icmp6_results[k].state == IcmpHostState::CommAdminProhibited);
            icmp6_alive[idx] = alive6;
            slots[idx].icmp_state = icmp6_results[k].state;
            if (alive6 && slots[idx].dur_s == 0.0) slots[idx].dur_s = icmp6_results[k].rtt_s;
            if (!is_lan_host6[idx]) {
                slots[idx].alive = alive6;
            }
        }
    }
    struct rusage ru_v6_end{}; getrusage(RUSAGE_SELF, &ru_v6_end);
    double v6_cpu_s = (ru_v6_end.ru_utime.tv_sec - ru_v6_start.ru_utime.tv_sec) +
                      (ru_v6_end.ru_utime.tv_usec - ru_v6_start.ru_utime.tv_usec) / 1e6 +
                      (ru_v6_end.ru_stime.tv_sec - ru_v6_start.ru_stime.tv_sec) +
                      (ru_v6_end.ru_stime.tv_usec - ru_v6_start.ru_stime.tv_usec) / 1e6;
    for (size_t idx : ndp_indices)   if (slots[idx].alive) slots[idx].cpu_s = v6_cpu_s;
    for (size_t idx : icmp6_indices) if (slots[idx].alive) slots[idx].cpu_s = v6_cpu_s;

    // ---- reconcile on-link v6 hosts: alive if EITHER NDP or ICMPv6 said so
    for (size_t k = 0; k < ndp_indices.size(); ++k) {
        size_t idx = ndp_indices[k];
        slots[idx].alive = ndp_alive[idx] || icmp6_alive[idx];
        if (slots[idx].alive && !ndp_alive[idx]) {
            slots[idx].icmp_only_no_mac = true;
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
            if (init_arp_ring(&arp_ring2, 256) == 0) {
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
            for (size_t idx : recheck_slot_idx) {
                slots[idx].alive = true;
                slots[idx].icmp_only_no_mac = true;
            }
        }
    }
    auto icmp_down_reason = [](IcmpHostState st) -> std::pair<std::string, bool> {
        switch (st) {
            case IcmpHostState::Dead:
                return {"unreachable (ICMP type 3 code 1: host unreachable)", true};
            case IcmpHostState::NetUnreachable:
                return {"unreachable (ICMP type 3 code 0: network unreachable)", true};
            case IcmpHostState::HostUnknown:
                return {"unreachable (ICMP type 3 code 7: destination host unknown)", true};
            case IcmpHostState::NetUnknown:
                return {"unreachable (ICMP type 3 code 6: destination network unknown)", true};
            case IcmpHostState::NoRoute:
                return {"unreachable (ICMP type 1 code 0: no route to destination)", true};
            case IcmpHostState::SrcRouteFailed:
                return {"unreachable (ICMP type 3 code 5: source route failed)", true};
            case IcmpHostState::SrcHostIsolated:
                return {"unreachable (ICMP type 3 code 8: source host isolated)", true};
            case IcmpHostState::ProtoUnreachable:
                return {"unreachable (ICMP type 3 code 2: protocol unreachable)", true};
            case IcmpHostState::HostPrecViolation:
                return {"unreachable (ICMP type 3 code 14: host precedence violation)", true};
            case IcmpHostState::FragNeeded:
                return {"path issue (fragmentation needed) — host may still be up", false};
            case IcmpHostState::TtlExceeded:
                return {"path issue (TTL exceeded in transit) — host may still be up", false};
            case IcmpHostState::FragTimeout:
                return {"path issue (fragment reassembly timeout) — host may still be up", false};
            case IcmpHostState::BadSpi:
                return {"path issue (bad SPI) — host may still be up", false};
            default:
                return {"no response — host down, or silently filtering all probes", false};
        }
    };
    std::vector<std::string> down_host_lines;
    std::map<std::string, std::pair<size_t, bool>> down_reason_counts; // reason -> {count, definitive}
    size_t external_down_count = 0;

    for (size_t i = 0; i < slots.size(); ++i) {
        auto& s = slots[i];

        if (s.alive) {
            print_output(PrintOutputType::HOST_HEADER, s.ip, 0, "", "", "", 0,0,0,0,0,0, "", "", 0.0, "", false, false);
            std::cout << "\n";
            std::cout << std::left << std::setw(15) << "Status" << ": "
                      << color::green << "alive" << color::reset << "\n";
            std::string vendor = s.is_self_host ? "ME" : (s.mac.empty() ? "" : get_mac_vendor(s.mac));
            print_output(PrintOutputType::MAC_ADDRESS, "", 0, "", "", "", 0,0,0,0,0,0,
                         s.mac, vendor, 0.0, "", false, false);
            if (s.icmp_only_no_mac) {
                std::cout << std::left << std::setw(15) << "Note" << ": "
                          << color::yellow
                          << "alive (confirmed via ICMP)"
                          << color::reset << "\n";
            }
            if (s.icmp_state == IcmpHostState::NetAdminProhibited ||
                s.icmp_state == IcmpHostState::HostAdminProhibited ||
                s.icmp_state == IcmpHostState::CommAdminProhibited) {
                std::cout << std::left << std::setw(15) << "Note" << ": "
                          << color::yellow
                          << "host blocked — ICMP filtered by firewall/ACL, but host is up"
                          << color::reset << "\n";
            }
            print_output(PrintOutputType::SCAN_TIMING, "", 0, "", "", "", 0,0,0,0,0,0, "", "", s.dur_s, "", false, false);
            print_output(PrintOutputType::CPU_TIME,    "", 0, "", "", "", 0,0,0,0,0,0, "", "", s.cpu_s, "", false, false);
            std::cout << color::green << std::string(73, '_') << color::reset << "\n";
            alive_ips.push_back(s.ip);
            if (!s.mac.empty()) mac_cache_out[s.ip_int] = s.mac;
        } else {
            down_hosts_out++;
            bool is_external = !is_lan_host[i] && !is_lan_host6[i];
            if (is_external) {
                external_down_count++;
                auto [reason, definitive] = icmp_down_reason(s.icmp_state);
                std::ostringstream line;
                line << color::red << s.ip << color::reset << " — "
                     << (definitive ? "really dead, " : "")
                     << reason;
                down_host_lines.push_back(line.str());
                auto& entry = down_reason_counts[reason];
                entry.first++;
                entry.second = definitive;
            }
        }
    }
    auto fn_end = std::chrono::steady_clock::now();
    struct rusage ru_fn_end{}; getrusage(RUSAGE_SELF, &ru_fn_end);
    double total_dur_s = std::chrono::duration<double>(fn_end - fn_start).count();
    double total_cpu_s = (ru_fn_end.ru_utime.tv_sec - ru_fn_start.ru_utime.tv_sec) +
                          (ru_fn_end.ru_utime.tv_usec - ru_fn_start.ru_utime.tv_usec) / 1e6 +
                          (ru_fn_end.ru_stime.tv_sec - ru_fn_start.ru_stime.tv_sec) +
                          (ru_fn_end.ru_stime.tv_usec - ru_fn_start.ru_stime.tv_usec) / 1e6;

    constexpr size_t kDownDetailThreshold = 20;
    if (external_down_count > kDownDetailThreshold) {
        std::cout << "\n";   // gap above "Hosts"
        std::cout << "Hosts       : " << slots.size() << "\n";
        std::cout << "Status      : ";
        bool first = true;
        for (const auto& [reason, info] : down_reason_counts) {
            if (!first) std::cout << ", ";
            first = false;
            std::cout << color::yellow << reason << color::reset
                      << " (" << info.first << ")";
        }
        std::cout << "\n";
        std::cout << "Duration    : " << std::fixed << std::setprecision(2) << total_dur_s << "s\n";
        std::cout << "CPU Time    : " << std::fixed << std::setprecision(2) << total_cpu_s << "s\n";
    } else {
        for (const auto& line : down_host_lines) {
            std::cout << line << "\n";
        }
    }

    std::cout << "\n";   // gap above "Shiv: ... scanned in ..."
    std::cout << "Shiv: " << slots.size() << " IP addresses (" << color::green
              << alive_ips.size() << color::reset << " hosts up) scanned in "
              << std::fixed << std::setprecision(2) << total_dur_s << "s\n";
    print_output(PrintOutputType::DOWN_HOSTS_SUMMARY, "", 0, "", "", "", 0,
                 static_cast<size_t>(down_hosts_out), 0,0,0, slots.size(), "", "", 0.0, "", false, false);

    return alive_ips;
}

void print_grepable_output(const std::string& target_spec,
                            const std::vector<std::string>& host_list,
                            bool ip_only)
{
    std::cout << "\nGrepable output for (" << target_spec << ")\n";
    for (const auto& ip : host_list) {
        if (!ip_only) {
            auto it = ip_to_domain_map.find(ip);
            if (it != ip_to_domain_map.end()) {
                std::cout << color::green << it->second << color::reset
                          << " (" << color::yellow << ip << color::reset << ")\n";
                continue;
            }
        }
        std::cout << color::yellow << ip << color::reset << "\n";
    }
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

namespace {

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// Encodes "www.example.com" as length-prefixed labels: 3www7example3com0
void dns_encode_name(const std::string& host, std::vector<uint8_t>& out) {
    size_t start = 0;
    while (start < host.size()) {
        size_t dot = host.find('.', start);
        size_t len = (dot == std::string::npos) ? host.size() - start : dot - start;
        if (len > 63) len = 63; // guard against malformed input, not a valid label but keeps us safe
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) out.push_back(static_cast<uint8_t>(host[start + i]));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
}

// Builds a single-question query packet. qtype: 1 = A, 28 = AAAA.
std::vector<uint8_t> dns_build_query(uint16_t txn_id, const std::string& host, uint16_t qtype) {
    std::vector<uint8_t> pkt;
    pkt.reserve(host.size() + 32);
    DnsHeader hdr{};
    hdr.id      = htons(txn_id);
    hdr.flags   = htons(0x0100); // standard query, recursion desired
    hdr.qdcount = htons(1);
    const uint8_t* hp = reinterpret_cast<const uint8_t*>(&hdr);
    pkt.insert(pkt.end(), hp, hp + sizeof(hdr));
    dns_encode_name(host, pkt);
    uint16_t qtype_n  = htons(qtype);
    uint16_t qclass_n = htons(1); // IN
    const uint8_t* qtp = reinterpret_cast<const uint8_t*>(&qtype_n);
    const uint8_t* qcp = reinterpret_cast<const uint8_t*>(&qclass_n);
    pkt.insert(pkt.end(), qtp, qtp + 2);
    pkt.insert(pkt.end(), qcp, qcp + 2);
    return pkt;
}

size_t dns_skip_name(const uint8_t* buf, size_t len, size_t pos) {
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) return pos + 1;
        if ((b & 0xC0) == 0xC0) return pos + 2; // compression pointer: 2 bytes total
        pos += 1 + b;
    }
    return pos;
}

// Scans the answer section for the first record of `want_type` (1=A, 28=AAAA).
bool dns_parse_answer(const uint8_t* buf, size_t len, uint16_t want_type, std::string& resolved_ip) {
    if (len < sizeof(DnsHeader)) return false;
    DnsHeader hdr{};
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t qdcount = ntohs(hdr.qdcount);
    uint16_t ancount = ntohs(hdr.ancount);
    if (ancount == 0) return false;

    size_t pos = sizeof(DnsHeader);
    for (uint16_t i = 0; i < qdcount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        pos += 4; // qtype + qclass
        if (pos > len) return false;
    }

    for (uint16_t i = 0; i < ancount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        if (pos + 10 > len) return false;
        uint16_t rtype, rclass, rdlen;
        memcpy(&rtype,  buf + pos, 2); rtype  = ntohs(rtype);  pos += 2;
        memcpy(&rclass, buf + pos, 2); rclass = ntohs(rclass); pos += 2;
        pos += 4; // TTL, unused
        memcpy(&rdlen,  buf + pos, 2); rdlen  = ntohs(rdlen);  pos += 2;
        if (pos + rdlen > len) return false;

        if (rtype == want_type && rclass == 1) {
            if (want_type == 1 && rdlen == 4) {
                char out[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, buf + pos, out, sizeof(out))) { resolved_ip = out; return true; }
            } else if (want_type == 28 && rdlen == 16) {
                char out[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, buf + pos, out, sizeof(out))) { resolved_ip = out; return true; }
            }
        }
        pos += rdlen;
    }
    return false;
}

void dns_parse_answer_all(const uint8_t* buf, size_t len, uint16_t want_type,
                           std::vector<std::string>& out_ips) {
    if (len < sizeof(DnsHeader)) return;
    DnsHeader hdr{};
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t qdcount = ntohs(hdr.qdcount);
    uint16_t ancount = ntohs(hdr.ancount);
    if (ancount == 0) return;

    size_t pos = sizeof(DnsHeader);
    for (uint16_t i = 0; i < qdcount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        pos += 4;
        if (pos > len) return;
    }
    for (uint16_t i = 0; i < ancount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        if (pos + 10 > len) return;
        uint16_t rtype, rclass, rdlen;
        memcpy(&rtype,  buf + pos, 2); rtype  = ntohs(rtype);  pos += 2;
        memcpy(&rclass, buf + pos, 2); rclass = ntohs(rclass); pos += 2;
        pos += 4;
        memcpy(&rdlen,  buf + pos, 2); rdlen  = ntohs(rdlen);  pos += 2;
        if (pos + rdlen > len) return;

        if (rtype == want_type && rclass == 1) {
            if (want_type == 1 && rdlen == 4) {
                char ipbuf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, buf + pos, ipbuf, sizeof(ipbuf))) out_ips.emplace_back(ipbuf);
            } else if (want_type == 28 && rdlen == 16) {
                char ipbuf[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, buf + pos, ipbuf, sizeof(ipbuf))) out_ips.emplace_back(ipbuf);
            }
        }
        pos += rdlen;
    }
}

size_t dns_decode_name(const uint8_t* buf, size_t len, size_t pos, std::string& out) {
    out.clear();
    size_t original_pos = pos;
    bool jumped = false;
    size_t hops = 0;
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) { pos += 1; break; }
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return original_pos;
            size_t target = static_cast<size_t>((b & 0x3F) << 8) | buf[pos + 1];
            if (!jumped) { original_pos = pos + 2; jumped = true; }
            pos = target;
            if (++hops > 128) return original_pos; // guard against pointer loops
            continue;
        }
        size_t label_len = b;
        pos += 1;
        if (pos + label_len > len) return original_pos;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(buf + pos), label_len);
        pos += label_len;
    }
    return jumped ? original_pos : pos;
}

std::string build_ptr_qname(const std::string& ip) {
    int fam = get_ip_version(ip.c_str());
    if (fam == 4) {
        struct in_addr addr{};
        inet_pton(AF_INET, ip.c_str(), &addr);
        const uint8_t* b = reinterpret_cast<const uint8_t*>(&addr.s_addr);
        char buf[64];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
        return buf;
    } else if (fam == 6) {
        struct in6_addr addr{};
        inet_pton(AF_INET6, ip.c_str(), &addr);
        std::string out;
        out.reserve(72);
        static const char hex[] = "0123456789abcdef";
        for (int i = 15; i >= 0; --i) {
            uint8_t byte = addr.s6_addr[i];
            out.push_back(hex[byte & 0xF]);
            out.push_back('.');
            out.push_back(hex[(byte >> 4) & 0xF]);
            out.push_back('.');
        }
        out += "ip6.arpa";
        return out;
    }
    return "";
}

bool dns_parse_ptr_answer(const uint8_t* buf, size_t len, std::string& out_domain) {
    if (len < sizeof(DnsHeader)) return false;
    DnsHeader hdr{};
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t qdcount = ntohs(hdr.qdcount);
    uint16_t ancount = ntohs(hdr.ancount);
    if (ancount == 0) return false;

    size_t pos = sizeof(DnsHeader);
    for (uint16_t i = 0; i < qdcount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        pos += 4;
        if (pos > len) return false;
    }

    for (uint16_t i = 0; i < ancount; ++i) {
        pos = dns_skip_name(buf, len, pos);
        if (pos + 10 > len) return false;
        uint16_t rtype, rclass, rdlen;
        memcpy(&rtype,  buf + pos, 2); rtype  = ntohs(rtype);  pos += 2;
        memcpy(&rclass, buf + pos, 2); rclass = ntohs(rclass); pos += 2;
        pos += 4; // TTL
        memcpy(&rdlen,  buf + pos, 2); rdlen  = ntohs(rdlen);  pos += 2;
        if (pos + rdlen > len) return false;

        if (rtype == 12 && rclass == 1) { // PTR, IN
            std::string name;
            dns_decode_name(buf, len, pos, name);
            if (!name.empty()) { out_domain = name; return true; }
        }
        pos += rdlen;
    }
    return false;
}

}


bool resolve_via_custom_dns(const std::string& host, std::string& resolved_ip,
                             const std::vector<std::string>& servers) {
    if (servers.empty()) return false;

    for (int attempt = 1; attempt <= 2; ++attempt) {
        uint16_t txn_id = static_cast<uint16_t>(
            (getpid() * 2654435761u) ^ (attempt * 7919u) ^ static_cast<uint32_t>(time(nullptr)));
        auto pkt_a    = dns_build_query(txn_id,     host, 1);
        auto pkt_aaaa = dns_build_query(static_cast<uint16_t>(txn_id + 1), host, 28);

        struct Sock { int fd; uint16_t want_type; };
        std::vector<Sock> socks;
        socks.reserve(servers.size() * 2);

        for (const auto& srv : servers) {
            int fam = get_ip_version(srv.c_str());
            if (fam != 4 && fam != 6) continue; // already validated at parse time, but stay defensive

            for (uint16_t qtype : {static_cast<uint16_t>(1), static_cast<uint16_t>(28)}) {
                int fd = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (fd < 0) continue;

                sockaddr_storage ss{};
                socklen_t slen;
                if (fam == 4) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
                    sa->sin_family = AF_INET;
                    sa->sin_port   = htons(53);
                    inet_pton(AF_INET, srv.c_str(), &sa->sin_addr);
                    slen = sizeof(*sa);
                } else {
                    auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
                    sa->sin6_family = AF_INET6;
                    sa->sin6_port   = htons(53);
                    inet_pton(AF_INET6, srv.c_str(), &sa->sin6_addr);
                    slen = sizeof(*sa);
                }

                const auto& pkt = (qtype == 1) ? pkt_a : pkt_aaaa;
                if (sendto(fd, pkt.data(), pkt.size(), 0,
                           reinterpret_cast<sockaddr*>(&ss), slen) < 0) {
                    close(fd);
                    continue;
                }
                socks.push_back({fd, qtype});
            }
        }

        if (socks.empty()) continue;

        std::string a_result, aaaa_result;
        std::vector<std::string> all_a, all_aaaa;
        bool got_a = false, got_aaaa = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1200);
        uint8_t buf[512];

        while (!(got_a && got_aaaa) && !socks.empty()) {
            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining.count() <= 0) break;

            fd_set rfds; FD_ZERO(&rfds);
            int maxfd = -1;
            for (auto& s : socks) { FD_SET(s.fd, &rfds); maxfd = std::max(maxfd, s.fd); }

            auto us = std::chrono::duration_cast<std::chrono::microseconds>(remaining).count();
            timeval tv{ static_cast<time_t>(us / 1000000), static_cast<suseconds_t>(us % 1000000) };

            int rv = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
            if (rv <= 0) break; // timeout or error — nothing more will arrive

            for (auto it = socks.begin(); it != socks.end();) {
                if (FD_ISSET(it->fd, &rfds)) {
                    ssize_t n = recv(it->fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        std::string ip_out;
                        if (dns_parse_answer(buf, static_cast<size_t>(n), it->want_type, ip_out)) {
                            if (it->want_type == 1 && !got_a)        { a_result = ip_out;    got_a = true; }
                            else if (it->want_type == 28 && !got_aaaa) { aaaa_result = ip_out; got_aaaa = true; }
                        }
                        if (it->want_type == 1)  dns_parse_answer_all(buf, static_cast<size_t>(n), 1,  all_a);
                        else                     dns_parse_answer_all(buf, static_cast<size_t>(n), 28, all_aaaa);
                    }
                    close(it->fd);
                    it = socks.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& s : socks) close(s.fd);

        if (got_a || got_aaaa) {
            if (g_target_ip_pref == 4 && !got_a) {
                return false;   // -4: IPv4-only, and no A record — do not fall back to v6
            }
            if (g_target_ip_pref == 6 && !got_aaaa) {
                return false;   // -6: IPv6-only, and no AAAA record — do not fall back to v4
            }
            resolved_ip = (g_target_ip_pref == 6) ? aaaa_result : a_result;
            for (const auto& other : all_a)    if (other != resolved_ip) g_not_scanned_map[resolved_ip].push_back(other);
            for (const auto& other : all_aaaa) if (other != resolved_ip) g_not_scanned_map[resolved_ip].push_back(other);
            return true;
        }
    }
    return false;
}

namespace {

bool dot_send_query(SSL* ssl, const std::vector<uint8_t>& query) {
    uint16_t len_n = htons(static_cast<uint16_t>(query.size()));
    if (SSL_write(ssl, &len_n, 2) != 2) return false;
    size_t sent = 0;
    while (sent < query.size()) {
        int n = SSL_write(ssl, query.data() + sent, static_cast<int>(query.size() - sent));
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool dot_recv_message(SSL* ssl, std::vector<uint8_t>& out) {
    uint8_t len_buf[2];
    size_t got = 0;
    while (got < 2) {
        int n = SSL_read(ssl, len_buf + got, static_cast<int>(2 - got));
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    uint16_t msg_len = static_cast<uint16_t>((len_buf[0] << 8) | len_buf[1]);
    out.resize(msg_len);
    got = 0;
    while (got < msg_len) {
        int n = SSL_read(ssl, out.data() + got, static_cast<int>(msg_len - got));
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

struct DotConn { SSL* ssl = nullptr; SSL_CTX* ctx = nullptr; int fd = -1; };

DotConn dot_connect(const std::string& server, int timeout_ms) {
    DotConn conn;
    int fam = get_ip_version(server.c_str());
    if (fam != 4 && fam != 6) return conn;

    int fd = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return conn;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    sockaddr_storage ss{};
    socklen_t slen;
    if (fam == 4) {
        auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
        sa->sin_family = AF_INET;
        sa->sin_port   = htons(853);
        inet_pton(AF_INET, server.c_str(), &sa->sin_addr);
        slen = sizeof(*sa);
    } else {
        auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
        sa->sin6_family = AF_INET6;
        sa->sin6_port   = htons(853);
        inet_pton(AF_INET6, server.c_str(), &sa->sin6_addr);
        slen = sizeof(*sa);
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&ss), slen);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return conn; }
    if (rc < 0) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        rc = select(fd + 1, nullptr, &wfds, nullptr, &tv);
        if (rc <= 0) { close(fd); return conn; }
        int so_err = 0; socklen_t so_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err != 0) { close(fd); return conn; }
    }
    fcntl(fd, F_SETFL, flags);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return conn; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return conn; }
    SSL_set_fd(ssl, fd);
    SSL_set1_host(ssl, server.c_str());
    SSL_set_tlsext_host_name(ssl, server.c_str());

    if (SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return conn;
    }
    conn.ssl = ssl; conn.ctx = ctx; conn.fd = fd;
    return conn;
}

void dot_close(DotConn& conn) {
    if (conn.ssl) { SSL_shutdown(conn.ssl); SSL_free(conn.ssl); conn.ssl = nullptr; }
    if (conn.ctx) { SSL_CTX_free(conn.ctx); conn.ctx = nullptr; }
    if (conn.fd >= 0) { close(conn.fd); conn.fd = -1; }
}

// Forward (A/AAAA) query over DoT.
bool dot_query_server(const std::string& server, const std::string& host,
                       uint16_t qtype, std::string& resolved_ip, int timeout_ms) {
    DotConn conn = dot_connect(server, timeout_ms);
    if (!conn.ssl) return false;
    bool ok = false;
    auto query = dns_build_query(
        static_cast<uint16_t>((getpid() * 2654435761u) ^ static_cast<uint32_t>(time(nullptr))),
        host, qtype);
    if (dot_send_query(conn.ssl, query)) {
        std::vector<uint8_t> resp;
        if (dot_recv_message(conn.ssl, resp))
            ok = dns_parse_answer(resp.data(), resp.size(), qtype, resolved_ip);
    }
    dot_close(conn);
    return ok;
}

bool dot_query_server_all(const std::string& server, const std::string& host,
                           uint16_t qtype, std::vector<std::string>& out_ips,
                           int timeout_ms) {
    DotConn conn = dot_connect(server, timeout_ms);
    if (!conn.ssl) return false;
    bool ok = false;
    auto query = dns_build_query(
        static_cast<uint16_t>((getpid() * 2654435761u) ^ static_cast<uint32_t>(time(nullptr))),
        host, qtype);
    if (dot_send_query(conn.ssl, query)) {
        std::vector<uint8_t> resp;
        if (dot_recv_message(conn.ssl, resp)) {
            dns_parse_answer_all(resp.data(), resp.size(), qtype, out_ips);
            ok = !out_ips.empty();
        }
    }
    dot_close(conn);
    return ok;
}

// Reverse (PTR) query over DoT.
bool dot_ptr_query_server(const std::string& server, const std::string& qname,
                           std::string& out_domain, int timeout_ms) {
    DotConn conn = dot_connect(server, timeout_ms);
    if (!conn.ssl) return false;
    bool ok = false;
    auto query = dns_build_query(
        static_cast<uint16_t>((getpid() * 2654435761u) ^ static_cast<uint32_t>(time(nullptr))),
        qname, 12); // PTR
    if (dot_send_query(conn.ssl, query)) {
        std::vector<uint8_t> resp;
        if (dot_recv_message(conn.ssl, resp))
            ok = dns_parse_ptr_answer(resp.data(), resp.size(), out_domain);
    }
    dot_close(conn);
    return ok;
}

} 

bool resolve_via_custom_dns_tls(const std::string& host, std::string& resolved_ip,
                                 const std::vector<std::string>& servers) {
    if (servers.empty()) return false;

    for (const auto& srv : servers) {
        std::vector<std::string> all_a, all_aaaa;
        bool got_a    = dot_query_server_all(srv, host, 1,  all_a,    2000);
        bool got_aaaa = dot_query_server_all(srv, host, 28, all_aaaa, 2000);
        if (!got_a && !got_aaaa) continue; // this server gave nothing; try the next one

        if (g_target_ip_pref == 4 && !got_a) {
            continue;   // -4: no A record from this server — don't fall back to v6, try next server
        }
        if (g_target_ip_pref == 6 && !got_aaaa) {
            continue;   // -6: no AAAA record from this server — don't fall back to v4, try next server
        }
        resolved_ip = (g_target_ip_pref == 6) ? all_aaaa.front() : all_a.front();
        for (const auto& other : all_a)    if (other != resolved_ip) g_not_scanned_map[resolved_ip].push_back(other);
        for (const auto& other : all_aaaa) if (other != resolved_ip) g_not_scanned_map[resolved_ip].push_back(other);
        return true;
    }
    return false;
}

bool resolve_ptr_via_custom_dns_tls(const std::string& ip, std::string& out_domain,
                                     const std::vector<std::string>& servers) {
    if (servers.empty()) return false;
    std::string qname = build_ptr_qname(ip);
    if (qname.empty()) return false;
    for (const auto& srv : servers) {
        if (dot_ptr_query_server(srv, qname, out_domain, 2000)) return true;
    }
    return false;
}

bool resolve_ptr_via_custom_dns(const std::string& ip, std::string& out_domain,
                                 const std::vector<std::string>& servers) {
    if (servers.empty()) return false;
    std::string qname = build_ptr_qname(ip);
    if (qname.empty()) return false;

    for (int attempt = 1; attempt <= 2; ++attempt) {
        uint16_t txn_id = static_cast<uint16_t>(
            (getpid() * 2654435761u) ^ (attempt * 7919u) ^ static_cast<uint32_t>(time(nullptr)));
        auto pkt = dns_build_query(txn_id, qname, 12); // PTR

        struct Sock { int fd; };
        std::vector<Sock> socks;
        socks.reserve(servers.size());

        for (const auto& srv : servers) {
            int fam = get_ip_version(srv.c_str());
            if (fam != 4 && fam != 6) continue;
            int fd = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            if (fd < 0) continue;

            sockaddr_storage ss{};
            socklen_t slen;
            if (fam == 4) {
                auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
                sa->sin_family = AF_INET;
                sa->sin_port   = htons(53);
                inet_pton(AF_INET, srv.c_str(), &sa->sin_addr);
                slen = sizeof(*sa);
            } else {
                auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
                sa->sin6_family = AF_INET6;
                sa->sin6_port   = htons(53);
                inet_pton(AF_INET6, srv.c_str(), &sa->sin6_addr);
                slen = sizeof(*sa);
            }
            if (sendto(fd, pkt.data(), pkt.size(), 0,
                       reinterpret_cast<sockaddr*>(&ss), slen) < 0) { close(fd); continue; }
            socks.push_back({fd});
        }
        if (socks.empty()) continue;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1200);
        uint8_t buf[512];
        bool got = false;

        while (!got && !socks.empty()) {
            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining.count() <= 0) break;

            fd_set rfds; FD_ZERO(&rfds);
            int maxfd = -1;
            for (auto& s : socks) { FD_SET(s.fd, &rfds); maxfd = std::max(maxfd, s.fd); }

            auto us = std::chrono::duration_cast<std::chrono::microseconds>(remaining).count();
            timeval tv{ static_cast<time_t>(us / 1000000), static_cast<suseconds_t>(us % 1000000) };

            int rv = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
            if (rv <= 0) break;

            for (auto it = socks.begin(); it != socks.end();) {
                if (FD_ISSET(it->fd, &rfds)) {
                    ssize_t n = recv(it->fd, buf, sizeof(buf), 0);
                    if (n > 0 && dns_parse_ptr_answer(buf, static_cast<size_t>(n), out_domain)) got = true;
                    close(it->fd);
                    it = socks.erase(it);
                    if (got) break;
                } else {
                    ++it;
                }
            }
        }
        for (auto& s : socks) close(s.fd);
        if (got) return true;
    }
    return false;
}

// Returns the plain-UDP --dns-servers list, or empty if only
// --dns-servers-tls (DoT) was configured, or empty if nothing was set.
// dns_query_batch() speaks plain UDP only, so an empty return here with
// custom_dns_configured()==true means "DoT-only, can't be batched" and
// callers should fall back to a thread pool over the single-target TLS path.
std::vector<std::string> get_configured_plain_dns_servers() {
    return g_dns_servers;
}

// Vectorized forward resolution (hostname -> IP). Resolves the whole
// `domains` batch concurrently instead of one blocking call per name:
//
//   - Literal IP strings pass straight through, no DNS involved.
//   - DoT-only (--dns-servers-tls): raw UDP can't pipeline TLS, so this
//     falls back to a bounded thread pool over the existing single-target
//     resolve_via_custom_dns_tls(), capped at 64 concurrent handshakes.
//   - Plain --dns-servers, or (when nothing is configured) the system
//     resolvers read from /etc/resolv.conf: both speak ordinary UDP, so
//     the whole batch is fired through dns_query_batch() — the same
//     vectorized engine dns_enum.cpp uses for subdomain brute force —
//     two jobs per host (A + AAAA), `concurrency` in flight at once.
//     A short retry pass re-issues anything that never got a definitive
//     answer, since some UDP loss is normal at this volume.
//
// out_ip: hostname -> chosen address (honors g_target_ip_pref).
// out_all_ips: hostname -> every address the response(s) contained (used
//   to populate g_not_scanned_map exactly as the old single-target
//   function did).
// out_unresolved: hostnames that could not be resolved at all.
// Returns true iff at least one hostname resolved.
bool resolve_domain_to_ip_batch(const std::vector<std::string>& domains,
                                 std::unordered_map<std::string, std::string>& out_ip,
                                 std::unordered_map<std::string, std::vector<std::string>>& out_all_ips,
                                 std::vector<std::string>& out_unresolved,
                                 int timeout_ms,
                                 int retries,
                                 int concurrency) {
    out_ip.clear();
    out_all_ips.clear();
    out_unresolved.clear();
    if (domains.empty()) return false;

    // 1) Validate, de-dupe, and let literal IPs pass straight through.
    std::vector<std::string> to_query;
    to_query.reserve(domains.size());
    std::unordered_set<std::string> seen;
    for (const auto& d : domains) {
        std::string host = d;
        trim_in_place(host);
        if (host.empty() || host.size() > 253 || has_bad_control_char(host)) {
            out_unresolved.push_back(d);
            continue;
        }
        if (!seen.insert(host).second) continue;
        std::string literal_ip;
        if (normalize_ip_string(host, literal_ip)) { out_ip[host] = literal_ip; continue; }
        to_query.push_back(host);
    }
    if (to_query.empty()) return !out_ip.empty();

    // 2) DoT-only custom servers -- bounded thread pool over the existing
    //    single-target TLS resolver (see comment above).
    if (!g_dns_tls_servers.empty()) {
        const int pool_size = std::max(1, std::min(concurrency, 64));
        std::mutex out_mutex;
        std::atomic<size_t> next{0};
        auto worker = [&]() {
            for (;;) {
                size_t idx = next.fetch_add(1);
                if (idx >= to_query.size()) return;
                const std::string& host = to_query[idx];
                std::string ip;
                bool ok = resolve_via_custom_dns_tls(host, ip, g_dns_tls_servers);
                std::lock_guard<std::mutex> lock(out_mutex);
                if (ok) out_ip[host] = ip;
                else    out_unresolved.push_back(host);
            }
        };
        std::vector<std::thread> pool;
        pool.reserve(pool_size);
        for (int i = 0; i < pool_size; ++i) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
        return !out_ip.empty();
    }

    // 3) Plain custom servers, or the system resolver -- the real
    //    vectorized path. Both speak ordinary UDP, so route the whole
    //    batch through dns_query_batch(), two jobs per host (A + AAAA).
    std::vector<std::string> servers = !g_dns_servers.empty() ? g_dns_servers : get_system_resolvers();
    if (servers.empty()) {
        std::cerr << "resolve_domain_to_ip_batch: no DNS servers available "
                     "(resolv.conf unreadable and no --dns-servers set)\n";
        for (auto& h : to_query) out_unresolved.push_back(h);
        return !out_ip.empty();
    }

    std::unordered_map<std::string, std::vector<std::string>> v4, v6;
    std::unordered_set<std::string> answered_hosts;

    auto run_pass = [&](std::vector<AsyncDnsJob>& job_list) {
        auto results = dns_query_batch(job_list, servers, timeout_ms, concurrency, /*use_edns0=*/true);
        for (auto& r : results) {
            if (r.answered) answered_hosts.insert(r.tag);
            for (auto& rec : r.records) {
                if (rec.type == DnsRRType::A)    v4[r.tag].push_back(rec.value);
                if (rec.type == DnsRRType::AAAA) v6[r.tag].push_back(rec.value);
            }
        }
    };

    std::vector<AsyncDnsJob> jobs;
    jobs.reserve(to_query.size() * 2);
    for (auto& host : to_query) {
        jobs.push_back({host, DnsRRType::A,    host});
        jobs.push_back({host, DnsRRType::AAAA, host});
    }
    run_pass(jobs);

    // Retry pass: re-issue only for hosts that never got a definitive
    // answer at all (packet loss is expected at hundreds of in-flight
    // UDP queries) -- a host that got a real NXDOMAIN is not retried.
    for (int attempt = 1; attempt < retries; ++attempt) {
        std::vector<AsyncDnsJob> leftover;
        leftover.reserve(to_query.size() * 2);
        for (auto& host : to_query) {
            if (answered_hosts.count(host)) continue;
            leftover.push_back({host, DnsRRType::A,    host});
            leftover.push_back({host, DnsRRType::AAAA, host});
        }
        if (leftover.empty()) break;
        run_pass(leftover);
    }

    // 4) Apply g_target_ip_pref and populate outputs, exactly matching
    //    the old single-target function's selection rules.
    for (auto& host : to_query) {
        auto& all4 = v4[host];
        auto& all6 = v6[host];

        if (g_target_ip_pref == 6 && all6.empty()) { out_unresolved.push_back(host); continue; }
        if (g_target_ip_pref == 4 && all4.empty()) { out_unresolved.push_back(host); continue; }

        std::string chosen;
        if (g_target_ip_pref == 6)      chosen = all6.front();
        else if (g_target_ip_pref == 4) chosen = all4.front();
        else if (!all4.empty())         chosen = all4.front();
        else if (!all6.empty())         chosen = all6.front();

        if (chosen.empty()) { out_unresolved.push_back(host); continue; }

        std::vector<std::string> all;
        all.reserve(all4.size() + all6.size());
        all.insert(all.end(), all4.begin(), all4.end());
        all.insert(all.end(), all6.begin(), all6.end());

        out_ip[host] = chosen;
        out_all_ips[host] = all;
        for (auto& other : all) if (other != chosen) g_not_scanned_map[chosen].push_back(other);
    }

    return !out_ip.empty();
}

// Single-target convenience wrapper — kept for every existing call site
// (the target-token parser above, etc.) that only has one hostname in
// hand. Internally just runs the vectorized engine with a batch of 1, so
// selection/caching semantics stay identical to calling the batch entry
// point directly. For resolving many hostnames at once, call
// resolve_domain_to_ip_batch() directly instead of looping this — looping
// this still serializes one DNS round trip per call.
bool resolve_domain_to_ip(const std::string& domain, std::string& resolved_ip) {
    resolved_ip.clear();
    std::unordered_map<std::string, std::string> out_ip;
    std::unordered_map<std::string, std::vector<std::string>> out_all_ips;
    std::vector<std::string> unresolved;
    resolve_domain_to_ip_batch({domain}, out_ip, out_all_ips, unresolved,
                                /*timeout_ms=*/2000, /*retries=*/2, /*concurrency=*/2);
    if (out_ip.empty()) return false;
    resolved_ip = out_ip.begin()->second; // batch of 1 -- only one possible entry
    return true;
}

bool custom_dns_configured() {
    return !g_dns_tls_servers.empty() || !g_dns_servers.empty();
}

bool resolve_ptr_via_configured_dns(const std::string& ip, std::string& out_domain) {
    if (!g_dns_tls_servers.empty()) return resolve_ptr_via_custom_dns_tls(ip, out_domain, g_dns_tls_servers);
    if (!g_dns_servers.empty())     return resolve_ptr_via_custom_dns(ip, out_domain, g_dns_servers);
    return false;
}

bool read_ips_from_file(const std::string& filename,
                        std::vector<std::string>& ips)
{
    struct stat st{};
    if (stat(filename.c_str(), &st) != 0) {
        std::cerr << "Failed to open IP file: " << filename << "\n";
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        std::cerr << "Error: '" << filename << "' is not a regular file "
                   << "(-iL requires a plain text file of targets, not a "
                   << "device, pipe, or socket).\n";
        return false;
    }

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open IP file: " << filename << "\n";
        return false;
    }

    std::vector<std::string> tokens;
    tokens.reserve(4096);
    std::string line;
    size_t bytes_read = 0;
    while (std::getline(file, line)) {
        bytes_read += line.size() + 1;
        if (bytes_read > MAX_IL_FILE_BYTES) {
            std::cerr << "Error: '" << filename << "' exceeds the "
                      << (MAX_IL_FILE_BYTES / (1024 * 1024))
                      << "MB limit for -iL target files.\n";
            return false;
        }
        if (tokens.size() >= MAX_IL_FILE_LINES) {
            std::cerr << "Error: '" << filename << "' exceeds the "
                      << MAX_IL_FILE_LINES << "-line limit for -iL target files.\n";
            return false;
        }
        tokens.emplace_back(std::move(line));
    }

    ParseContext ctx{ filename, true };
    return parse_targets(tokens, ips, ctx);
}

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

    ParseContext ctx{ "CLI argument", false };
    return parse_targets(tokens, ips, ctx);
}

static std::string strip_ansi_codes(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\033' && i + 1 < input.size() && input[i + 1] == '[') {
            size_t j = i + 2;
            while (j < input.size() && input[j] != 'm') {
                ++j;
            }
            i = j;
        } else {
            result += input[i];
        }
    }

    return result;
}

void save_scan_results(const std::vector<RecPross>& results, const std::string& output_file,
                        const std::string& raw_log) {
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

    const auto& service_map = read_services_from_file("/usr/share/nmap/nmap-services");

    const std::string safe_mac = combined_result.mac_address;
    const std::string safe_vendor = combined_result.mac_address.empty()
        ? ""
        : get_mac_vendor(combined_result.mac_address);

    if (!raw_log.empty()) {
        out_file << strip_ansi_codes(raw_log);
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
            restore_terminal_echo();
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

        case SIGPIPE:
            break;

        default:
            SIGNAL_WRITE(STDERR_FILENO, msg_def, sizeof(msg_def) - 1);
            crash_signal.store(sig, std::memory_order_relaxed);
            _exit(1);
            break;
    }
}


void track_raw_socket(int fd) {
    if (fd < 0) return;
    std::lock_guard<std::mutex> lock(global_resources_mutex);
    global_raw_sockets.push_back(fd);
}
void untrack_raw_socket(int fd) {
    if (fd < 0) return;
    std::lock_guard<std::mutex> lock(global_resources_mutex);
    auto& v = global_raw_sockets;
    v.erase(std::remove(v.begin(), v.end(), fd), v.end());
}

void track_uring_ring(io_uring* ring) {
    if (!ring) return;
    std::lock_guard<std::mutex> lock(global_resources_mutex);
    global_uring_rings.push_back(ring);
}
void track_worker_thread(std::thread* t) {
    if (!t) return;
    std::lock_guard<std::mutex> lock(global_resources_mutex);
    global_worker_threads.push_back(t);
}

void emergency_cleanup() {
    const bool was_interrupted = terminate_flag.load(std::memory_order_relaxed);
    if (was_interrupted) std::cerr << "Performing emergency cleanup...\n";
 
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
            else if (was_interrupted)
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

for (std::thread* t : threads_to_join) {
    if (!t) continue;
    try {
        if (t->joinable()) {
            std::cerr << "Joining worker thread (timeout: 2s)...\n";
            auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(2);
            bool joined = false;
            while (!joined && std::chrono::steady_clock::now() < deadline) {
                int rc = pthread_tryjoin_np(t->native_handle(), nullptr);
                if (rc == 0) { joined = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            if (joined) {
                t->detach();
                std::cerr << "Worker thread joined successfully\n";
            } else {
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
 
    if (was_interrupted) std::cerr << "Emergency cleanup completed\n";
}
 

void thread_worker(const std::vector<std::string>& thread_ips,
                   const std::vector<std::string>& thread_hostnames,
                   const std::vector<int>& ports,
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
                   bool enable_version_detection, AllProbes* vprobes,
                   const VersionDetectOptions& sv_opts) {
                   
    
    const uint8_t&     window_scale            = opts.window_scale;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;

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
    std::vector<std::array<uint8_t, 4>> statically_arped_ips;
    bool multi_ip = (thread_ips.size() > 1);
    std::unordered_set<uint32_t> counted_down_ips;
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
            if (init_arp_ring(&arp_ring, 512) == 0) {
                uint8_t src_mac[6] = {0};
                if (get_interface_mac(arp_sock, interface.c_str(), src_mac)) {
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
                        bool has_special_case = false;
                        for (size_t j = batch_start; j < batch_end; ++j) {
                            uint32_t ip_val;
                            memcpy(&ip_val, same_subnet_target_ips[j].get(), 4);
                            if (ip_val == htonl(0x7F000001) || ip_val == src_ip_int) {
                                has_special_case = true;
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

                            if (!has_special_case) {
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
                                    } else if (ip_val == src_ip_int) {
                                        // Our own interface IP — we already
                                        // know our own MAC, fill it in
                                        // directly instead of waiting.
                                        memcpy(mac_buffers[j].get(), src_mac, 6);
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
        VersionDetectOptions sv_opts_effective = sv_opts;
        if (i < thread_hostnames.size() && !thread_hostnames[i].empty()) {
            sv_opts_effective.host_override = thread_hostnames[i];
        }
        uint16_t source_port = (base_source_port > 0) ? base_source_port : 0;
        int ip_version = get_ip_version(ip_str.c_str());
        if (ip_version != 4 && ip_version != 6) {
            std::cerr << "Invalid target IP address: " << ip_str << std::endl;
            continue;
        }
        reset_network_disconnect_flag();
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
        struct rusage ru_scan_start{};
        getrusage(RUSAGE_SELF, &ru_scan_start);

        worker_thread(ip_str.c_str(), local_ip, source_ip.c_str(), ports, rng, pool, send_sock,
	     results[i], main_batch_size, seq_num, win_size, ip_version, print_individual_closed_filtered, print_filtered_if_few, send_ring_ptr, fast_scan,
	     scan_type, custom_ttl, custom_dscp,custom_ip_flags, ip_id_mode, fixed_ip_id,
	     opts,
	     user_rcvbuf_size, send_uring_depth, rcv_uring_depth, 
	     source_port, retry_source_port, debug_packet, debug_rtt,debug_wsn,debug_ttl,debug_demux,debug_strack,debug_send,frag_out_of_order,frag_overlap,frag_overlap_bytes,frag_zof,sport_range_cfg,gsport_cfg,initial_rtt_ms, port_timeout_min_ms, port_timeout_max_ms,rate_config,jitter_config,batch_delay_config,bandwidth_config,
	     is_threaded,g_recv, g_send, send_sock6, local_ip6_ptr);

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
        const auto& service_map = read_services_from_file("/usr/share/nmap/nmap-services");
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
        if (result.open_ports.empty() && !print_individual_closed_filtered) {
            bool has_filtered = !result.filtered_ports.empty();
            bool has_closed   = result.closed_ports > 0;

            int want_filtered = has_filtered && has_closed ? 3 : (has_filtered ? 5 : 0);
            int want_closed   = has_filtered && has_closed ? 2 : (has_closed ? 5 : 0);
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
            std::string sorted_filtered_state = PacketTask::expects_rst_response(scan_type) ? "confused" : "filtered";
            for (size_t idx = 0; idx < filtered_sorted.size() && shown_filtered < want_filtered; ++idx, ++shown_filtered) {
                uint16_t p = filtered_sorted[idx];
                std::string svc = service_map.count(p) ? service_map.at(p) : "unknown";
                print_output(PrintOutputType::PORT_RESULT, "", p, sorted_filtered_state, svc, scan_name,
                             0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
            }
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

        {
            std::string layer3_reason;
            for (uint16_t fport : result.filtered_ports) {
                auto rit = result.icmp_filter_reasons.find(fport);
                if (rit != result.icmp_filter_reasons.end()) {
                    std::string icmp_note;
                    switch (rit->second.reason) {
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
                for (auto& [wr, wmsg, wreplier] : result.icmp_warnings) {
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
            {
                const uint64_t tx_loss = result.loss_buffer_pool
                                       + result.loss_build_fail
                                       + result.loss_kernel_reject
                                       + result.loss_drain_timeout
                                       + result.loss_no_socket
                                       + result.loss_aborted;
                const uint64_t rx_loss = result.rx_kernel_ovfl
                                       + result.rx_cq_overflow
                                       + result.rx_truncated;

                if (tx_loss || rx_loss || result.rx_slot_starved) {
                    const uint64_t attempted =
                        static_cast<uint64_t>(result.packets_sent) + tx_loss;
                    const double pct = attempted
                        ? (100.0 * static_cast<double>(tx_loss)
                                 / static_cast<double>(attempted))
                        : 0.0;

                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\nIncident\n";

                    auto checkpoint = [](const char* name, const char* reason, uint64_t n,
                                          const char* label = "Drops") {
                        if (!n) return;
                        std::cout << "  -> CheckPoint  : " << std::left << std::setw(13) << name
                                  << "| Reason : " << std::setw(31) << reason
                                  << "| " << label << " : " << n << "\n";
                    };

                    checkpoint("BufferPool",   "pool exhausted",                result.loss_buffer_pool);
                    checkpoint("Build",        "packet build rejected",         result.loss_build_fail);
                    checkpoint("KernelReject", "sendmsg returned error",        result.loss_kernel_reject);
                    checkpoint("DrainTimeout", "CQE unreaped, buffer stranded", result.loss_drain_timeout);
                    checkpoint("NoSocket",     "IPv6 task, no v6 socket",       result.loss_no_socket);
                    checkpoint("Abandoned",    "batch aborted / submit error",  result.loss_aborted);
                    checkpoint("RxKernelDrop", "SO_RXQ_OVFL, recv buffer full", result.rx_kernel_ovfl);
                    checkpoint("RxCqOverflow", "io_uring CQ overflow",          result.rx_cq_overflow);
                    checkpoint("RxTruncated",  "frame exceeded MAX_LEN",        result.rx_truncated, "Truncated");
                    checkpoint("RxSlotStarve", "no free slot, re-arm deferred", result.rx_slot_starved);

                    std::cout << std::right;

                    if (tx_loss) {
                        std::cout << "  -> TX total    : " << tx_loss << " of " << attempted
                                  << " attempted (" << std::fixed << std::setprecision(2)
                                  << pct << "%)\n";
                        std::cout << "     note        : transmit attempts, not probe failures —\n"
                                     "                   retries may still have resolved the port.\n";
                    }
                    if (rx_loss || result.rx_slot_starved) {
                        std::cout << "     note        : RX counters are socket-wide; concurrent\n"
                                     "                   targets will show overlapping figures.\n";
                    }
                }
            }
	    if (!multi_ip) {
	        if (debug_rtt && !result.rtt_debug_entries.empty()) {
		    std::ostringstream rtt_oss;
		    rtt_oss << "\nRTT Debug      : \n";

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
		    
		        rtt_oss << "    " << color::green << std::left << std::setw(7) << "open" << color::reset
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
		            
		                rtt_oss << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
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

		            rtt_oss << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
		                      << " " << other_entries.size() << " ports sampled\n";
		            rtt_oss << "    Min ewma       "
		                      << " " << std::setw(10) << (std::to_string(min_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << min_rtt << "ms"
		                      << " → int=" << min_int << "ms\n";
		            rtt_oss << "    Avg ewma       "
		                      << " " << std::setw(10) << (std::to_string(avg_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << avg_closest << "ms"
		                      << " → int=" << avg_int << "ms\n";
		            rtt_oss << "    Max ewma       "
		                      << " " << std::setw(10) << (std::to_string(max_port) + "/tcp")
		                      << ": ewma=" << std::fixed << std::setprecision(3) << max_rtt << "ms"
		                      << " → int=" << max_int << "ms\n";
		        }
		    }
		    {
		        std::lock_guard<std::mutex> lock(cout_mutex);
		        std::cout << rtt_oss.str();
		    }
	        }
	    }
	    if (debug_send && !sent_debug_log.empty()) {
                flush_sent_packet_debug();
            }
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
                display_wsn_analysis(result.packet_details, window_scale, ip_str.c_str());
            }
            
            if (g_os_detect && !terminate_flag) {
                const osdetect::Context os_ctx =
                    osdetect::make_context(scan_type, opts, custom_ttl, win_size);
                const osdetect::Result os_res =
                    osdetect::analyze(result.packet_details, os_ctx);
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << osdetect::render(os_res, ip_str, sv_opts.verbose);
            }
            const bool udp_probe_all_ports = sv_opts.udp && !ports.empty();
            if (enable_version_detection && vprobes && !terminate_flag
	        && (!result.open_ports.empty() || udp_probe_all_ports)) {
	        std::cout << std::left << std::setw(9) << "\nPORT" << "VERSION\n";

	        constexpr size_t kMaxConcurrentProbes = 16;
	        std::vector<std::future<void>> inflight;
	        std::vector<uint16_t> udp_probe_ports;
	        if (udp_probe_all_ports) {
	            udp_probe_ports.reserve(ports.size());
	            for (int p : ports) udp_probe_ports.push_back(static_cast<uint16_t>(p));
	        }
	        const std::vector<uint16_t>& ports_to_probe =
	            udp_probe_all_ports ? udp_probe_ports : result.open_ports;

	        for (uint16_t port : ports_to_probe) {
		    if (terminate_flag) break;

		    inflight.push_back(std::async(std::launch::async,
		        [vprobes, ip_str, port, sv_opts_effective]() {
		            if (terminate_flag) return;
		            try {
		                run_version_probe(*vprobes, ip_str, port, sv_opts_effective);
		            } catch (const std::exception &e) {
		                std::cerr << "[version-probe] " << ip_str << ":" << port
		                          << " threw: " << e.what() << " -- skipping\n";
		            } catch (...) {
		                std::cerr << "[version-probe] " << ip_str << ":" << port
		                          << " threw an unknown exception -- skipping\n";
		            }
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

void print_full_help() {

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
		std::cerr << color::yellow << "                             " << color::reset << "N:<port>     -> fixed source port for just attempt N (N=0 initial, 1-5=retries), port must be a single number, not a range\n";
		std::cerr << color::yellow << "                             " << color::reset << "e.g. -g 0:443,1:22,2:8080,3:53,4:21,5:110\n";
		std::cerr << color::yellow << " --sport-range" << color::reset << " <min>-<max> | N:<min>-<max>[,N:<min>-<max>...]\n";
		std::cerr << color::yellow << "                             " << color::reset << "<min>-<max>  -> use this range for ALL 6 send attempts (min must be < max)\n";
		std::cerr << color::yellow << "                             " << color::reset << "N:<min>-<max> -> override just attempt N (N=0 initial, 1-5=retries)\n";
		std::cerr << color::yellow << "                             " << color::reset << "e.g. --sport-range 0:5555-6666,1:7000-8000,2:3333-5555  (leaves attempts 3-5 at their default web ports)\n";
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
        	
        	std::cerr << color::green << "IPV6 Options:\n" << color::reset;
        	std::cerr << color::yellow << " --hop"   << color::reset << " <opt>[:<val>]  IPv6-only Hop-by-Hop Options header (alert:0|1, jumbo:N, pad:N, unknown:N)\n";
        	std::cerr << color::yellow << " --dest"  << color::reset << " <opt>[:<val>]  IPv6-only Destination Options header (home[:<addr>], tunnel:N, pad:N, malformed, unknown:N)\n";
        	std::cerr << color::yellow << " --route" << color::reset << " <spec>  IPv6-only Routing header: 0:N (Type0, N segs), 2 (Type2/MIPv6), srh:N (Segment Routing), or bare N (invalid type)\n";
        	std::cerr << color::yellow << " --ah"    << color::reset << " <mode>  IPv6-only Authentication Header: yes|badspi|noicv|badlen|seq0\n";
        	std::cerr << color::yellow << " --esp"   << color::reset << " <mode>  IPv6-only ESP header: yes|badpad|badspi|noiv|bad\n";
        	std::cerr << color::yellow << " --flow"  << color::reset << " <value> IPv6-only Flow Label (0-1048575, 'rand', or 'inc' per packet)\n";
        	std::cerr << color::yellow << " --chain" << color::reset << " <opt>[:<val>]  IPv6-only extension-header chain order: rand, reverse, custom:AH,ESP,HBH, dup:hop|dest|route|ah[:N], unknown:N\n";
        	std::cerr << color::yellow << " --stop"  << color::reset << " <position>[:<val>]  IPv6-only early chain termination (next-header=59): first, hop, dest[:N], route, all\n\n";
        	
        	std::cerr << color::green << "Linux Namespace Options:\n" << color::reset;
        	std::cerr << color::yellow << " --split" << color::reset << "        Run entirely inside an isolated netns/macvlan\n";
        	std::cerr << color::yellow << " --split-ip"    << color::reset << " <ip/prefix>   IPv4 address for the namespace, e.g. 192.168.1.114\n";
        	std::cerr << color::yellow << " --split-gw"    << color::reset << " <ip>          IPv4 gateway for the namespace, e.g. 192.168.1.254\n";
        	std::cerr << color::yellow << " --split-ip6"   << color::reset << " <ip/prefix>   IPv6 address for the namespace, e.g. 2001:db8::114/64\n";
        	std::cerr << color::yellow << " --split-gw6"   << color::reset << " <ip>          IPv6 gateway for the namespace, e.g. 2001:db8::1\n";
        	std::cerr << color::yellow << " --split-mac"   << color::reset << " <mac>         MAC address for the namespace's macvlan device\n";
        	std::cerr << color::yellow << " --split-iface" << color::reset << " <iface>       Physical interface to bridge off (default: --interface or auto-detect)\n";
        	std::cerr << "                              At least one of --split-ip/--split-ip6 (+matching gateway) is required; set both for dual-stack.\n\n";
        	
        	std::cerr << color::green << "Version Detection (-sV) Options:\n" << color::reset;
		std::cerr << color::yellow << " -sV" << color::reset << " enable service/version detection on open ports\n";
		std::cerr << color::yellow << " --sv-timeout" << color::reset << " <sec> response/read timeout once connected (default 3)\n";
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
		std::cerr << color::yellow << " --verbose" << color::reset << " verbose version-detection diagnostics\n";
		std::cerr << color::dim << " (all of the above are ignored unless -sV is also given)\n\n" << color::reset;

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
		std::cerr << color::yellow << " -sn" << color::reset << " discover alive hosts\n";
		std::cerr << "                                            For eg: shiv -sn 192.168.1.0/24 (discover alive hosts)\n";
		std::cerr << "                                            For eg: shiv -sn -sS -Pn 192.168.1.0/24 (discover alive hosts and only scan discovered targets\n";
		std::cerr << color::yellow << " -sn6" << color::reset << " discover alive hosts using icmp6\n";
		
		std::cerr << color::yellow << " -Pn" << color::reset << " skip target ping probe\n\n";
		
		std::cerr << color::green << "Miscellaneous Options:\n" << color::reset;
		
		std::cerr << color::yellow << " --port-timeout" << color::reset << " <min>-<max> Set port giveup timeout(default: min:5ms-max:700ms). e.g. --port-timeout 10ms-500ms\n";
		std::cerr << color::yellow << " --interface" << color::reset << " Set desired interface\n";
		std::cerr << color::yellow << " --grep" << color::reset << " Print a plain, copy-friendly grepable target list at the end of the scan\n";
		std::cerr << color::yellow << " --traceroute" << color::reset << " Print traced routes informations with Geo locations,ASN etc\n";
	        std::cerr << color::yellow << " --os-detect" << color::reset << " Passively fingerprint the target OS from the replies received\n";
		std::cerr << color::yellow << " -o" << color::reset << " <File_Name>.txt Save results to file (plain text)\n\n";

		std::cerr << color::green << "Multi Host Specification:\n" << color::reset;
		std::cerr << " <IP> can be a single IP, comma-separated IPs, CIDR notation (e.g., 192.168.1.0/24), or any combination\n";
		std::cerr << color::yellow << " -iL" << color::reset << " <ips.txt> Scan saved hosts\n";
		std::cerr << color::yellow << " --dns-servers" << color::reset << " <server,server,...> Use these DNS servers (1-10, IPv4 or IPv6) instead of the system resolver\n";
		std::cerr << color::yellow << " --dns-servers-tls" << color::reset << " <server,server,...> Use these DNS servers over DNS-over-TLS, port 853, cert-verified (1-10, IPv4 or IPv6)\n";
		std::cerr << color::yellow << " -4" << color::reset << " Force IPv4-only when resolving domain targets (fails instead of falling back to IPv6)\n";
		std::cerr << color::yellow << " -6" << color::reset << " Force IPv6-only when resolving domain targets (fails instead of falling back to IPv4)\n";
		std::cerr << color::yellow << " --exclude-ports" << color::reset << " <PORT_SPEC> Ports to exclude from scanning (format same as -p)\n\n";
		std::cerr << color::green << "State Machine Scan:\n" << color::reset;
		std::cerr << color::yellow << " -G" << color::reset << " State Machine Scan (perform 4 way handshake , it run inside namespace )\n\n";

		std::cerr << color::green << "Enumeration Options\n" << color::reset;
		std::cerr << color::yellow << " --enum" << color::reset << " <module,module,...> Run one or more OSINT/enumeration modules, comma-separated, any order\n";
		std::cerr << "                                      shodan        : Query Shodan InternetDB for target info\n";
		std::cerr << "                                      ssl           : SSL/TLS enumeration (chain, SANs, key strength, expiry, OCSP/CT, SNI variance)\n";
		std::cerr << "                                      dns           : Passive+active DNS/OSINT enumeration (records,AXFR,DNSSEC,Wayback/RDAP/ASN)\n";
		std::cerr << "                                      trail:<key>   : Use security trials API to fetch subdomains\n\n";
		std::cerr << "                                      For eg: shiv  abc.com --enum trail:<api-key> (only perform trail)\n";
		std::cerr << "                                      For eg: shiv  abc.com -sS -Pn --enum shodan,dns (scan, then shodan + dns enum)\n";
		std::cerr << "                                      For eg: shiv  abc.com --enum shodan,trail:<api-key>,dns (multiple modules, any order)\n\n";
		
		std::cerr << color::green << "Passive Discovery (--netradar) Options:\n" << color::reset;
		std::cerr << color::yellow << " --netradar" << color::reset << " Passively watch the wire instead of sending probes: puts the interface in promiscuous mode\n";
		std::cerr << "             and correlates TCP SYN/SYN-ACK/ACK/PSH/PSH-ACK/FIN-ACK traffic plus QUIC and DNS\n";
		std::cerr << "             query/response exchanges to report which hosts have which ports open. No packets\n";
		std::cerr << "             of shiv's own are ever sent -- only what already crosses the capture NIC is seen\n";
		std::cerr << "             (same LAN segment, a switch mirror/SPAN port, or an on-path gateway).\n";
		std::cerr << color::yellow << " --time" << color::reset << " <N>[s|m|h] Only valid together with --netradar. Capture for this long, then stop\n";
		std::cerr << "             automatically and print one aggregated report (grouped by host, every open port\n";
		std::cerr << "             folded into a single comma-separated cell). Omit --time to run until Ctrl-C instead\n";
		std::cerr << "             -- the report still prints once, at that point.\n\n";
		std::cerr << "                                      For eg: shiv --netradar (run until Ctrl-C, then print the report)\n";
		std::cerr << "                                      For eg: shiv --netradar --time 30s (capture for 30 seconds)\n";
		std::cerr << "                                      For eg: shiv --netradar --time 5m --interface eth0 (5 minutes on a specific interface)\n\n";
		
	        std::cerr << color::green << "Discovery Options:\n" << color::reset;
		std::cerr << "  category 1 - ASN / organisation lookup:\n";
		std::cerr << color::yellow << "   --cn" << color::reset << " <country>         List every ASN and org name for a country\n";
		std::cerr << "            Accepts a name (nepal, \"south korea\"), ISO-2 (np) or ISO-3 (npl); typos are corrected.\n";
		std::cerr << "                                      For eg: shiv --cn nepal\n";
		std::cerr << color::yellow << "   --org" << color::reset << " <name>           Filter the ASN list to one organisation (typo-tolerant)\n";
		std::cerr << "            With --cn, filters that country's list; used alone, it scans every country's list for a match.\n";
		std::cerr << "                                      For eg: shiv --cn nepal --org \"sky broadband\"\n";
		std::cerr << "                                      For eg: shiv --org worldlink\n\n";

		std::cerr << "  category 2 - IP-range discovery:\n";
		std::cerr << color::yellow << "   --country" << color::reset << " <country>     Fetch a country's public IPv4/IPv6 ranges from RIR/NetworksDB\n";
		std::cerr << "            Accepts a name (nepal, \"south korea\"), ISO-2 (np) or ISO-3 (npl); typos are corrected.\n";
		std::cerr << "                                      For eg: shiv --country nepal --ipv4 -o np.txt\n";
		std::cerr << color::yellow << "   --owner" << color::reset << " [name]          Annotate ranges with their owner, or filter to one owner/ASN\n";
		std::cerr << "            Looks up one sample address per range (Team Cymru ASN DNS lookup).\n";
		std::cerr << "                                      For eg: shiv --country nepal --owner\n";
		std::cerr << "                                      For eg: shiv --country nepal --owner worldlink\n";
		std::cerr << color::yellow << "   --ipv4" << color::reset << " / " << color::yellow << "--ipv6" << color::reset << "         Restrict output to one family (default: both)\n\n";

		std::cerr << "  category 3 - IP/ASN to domains:\n";
		std::cerr << color::yellow << "   --ip" << color::reset << " <ip>               Reverse-lookup domains hosted on an IPv4 address\n";
		std::cerr << color::yellow << "   --range" << color::reset << " <cidr/24>       Reverse-lookup domains in an IPv4 /24 (host bits are cleared automatically)\n";
		std::cerr << "                                      For eg: shiv --ip 103.48.88.33\n";
		std::cerr << "                                      For eg: shiv --range 103.48.88.0/24\n";
		std::cerr << color::yellow << "   --asn" << color::reset << " <ASN>             Print the IPv4/IPv6 routes announced by an ASN (no domain lookups)\n";
		std::cerr << color::yellow << "   --ipv4" << color::reset << " / " << color::yellow << "--ipv6" << color::reset << "         With --asn, restrict routes to one family (default: both)\n";
		std::cerr << "                                      For eg: shiv --asn AS45353 --ipv6\n\n";
		
		std::cerr << color::green << "Filtered State Tackle Controller / Performance Options \n" << color::reset;
		std::cerr << color::yellow << "  --retry-delay-min" << color::reset << " <dur>       Floor for congestion-scaled retry delay (default: 3ms)\n";
		std::cerr << color::yellow << "  --retry-delay-max" << color::reset << " <dur>       Ceiling for congestion-scaled retry delay (default: 700ms)\n";
		std::cerr << color::yellow << "  --retry-delay-floor-div" << color::reset << " <n>   Divisor applied to learned RTT timeout for the delay floor (default: 4)\n";
		std::cerr << color::yellow << "  --cong-curve" << color::reset << " <float>          Exponent shaping how fast retry delay, dynamic rate limit, batch delay and retry cap ramp up with congestion (default: 2.0, higher = stays gentle longer, then ramps harder near full congestion)\n";
		std::cerr << color::yellow << "  --cong-alpha-up" << color::reset << " <0-1>         EMA smoothing weight when congestion is rising (default: 0.5, higher = reacts faster)\n";
		std::cerr << color::yellow << "  --cong-alpha-down" << color::reset << " <0-1>       EMA smoothing weight when congestion is falling (default: 0.1, lower = recovers slower/more cautiously)\n\n";

		std::cerr << color::yellow << "  --rto-mult" << color::reset << " <n>                RTT-variance multiplier in the RTO formula base_rtt + n*rttvar (default: 4, Jacobson/Karels)\n";
		std::cerr << color::yellow << "  --rto-pad1" << color::reset << " <ms>               Extra timeout padding added on 1st retry (default: 40ms)\n";
		std::cerr << color::yellow << "  --rto-pad2" << color::reset << " <ms>               Extra timeout padding added on the 2nd retry, escalating by +50% of this value per retry stage beyond that (default: 100ms)\n";

		std::cerr << color::yellow << "  --rate-dyn-window" << color::reset << " <dur>       Window size for the adaptive rate limiter (default: 200ms)\n";
		std::cerr << color::yellow << "  --rate-dyn-min" << color::reset << " <n>            Min packets/window under heavy congestion (default: 20)\n";
		std::cerr << color::yellow << "  --rate-dyn-max" << color::reset << " <n>            Max packets/window once congestion is detected (default: 150); rate is unlimited until the first retry congestion appears\n\n";

		std::cerr << color::yellow << "  --batch-delay-dyn-min" << color::reset << " <dur>   Min inter-batch sleep under adaptive batch delay (default: 0)\n";
		std::cerr << color::yellow << "  --batch-delay-dyn-max" << color::reset << " <dur>   Max inter-batch sleep under adaptive batch delay (default: 800ms)\n\n";

		std::cerr << color::yellow << "  --buf-peak" << color::reset << " <float>            Peak buffer-pool over-allocation factor, 1.0-20.0 (default: 1.3; hard limit 65536 buffers)\n";
		std::cerr << color::yellow << "  --batch-settle" << color::reset << " <us>           Min wait (us) for receive-ring completions to coalesce before processing (default: 500)\n";
		std::cerr << color::yellow << "  --sqpoll-threshold" << color::reset << " <n>        Probe volume (hosts*ports) per host batch that auto-enables SQPOLL when pacing is adaptive/dynamic (default: 300000, triggers at >=). When rate/batch-delay use fixed, non-dynamic pacing, an estimated-duration check is used instead.\n";
		std::cerr << "\n  " << color::yellow << "Note: --rate-dyn-* requires the rate limiter to stay in its default adaptive mode —\n"
                     				     << "  combining it with an explicit --rate is rejected at startup.\n"
                                                     << "  Same rule for --batch-delay-dyn-* and an explicit --batch-delay." << color::reset << "\n\n";
	

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
			  << "     For eg:      : --bandwidth 1s:500000   (500000 bytes/sec, raw number)\n"
			  << "                    --bandwidth 1s:500K     (500x1024 = 512000 bytes/sec)\n"
			  << "                    --bandwidth 500ms:2M    (2x1024x1024 bytes per 500ms window)\n"
			  << "                    --bandwidth 1s:1G       (1x1024^3 bytes/sec)\n"
			  << "                    --bandwidth 1s:9000-10000 (randomized 9000-10000 bytes/sec per window)\n\n";
		  
		std::cerr << color::green << "Buffer Management:\n" << color::reset;
		std::cerr << color::yellow << " --rcv-uring" << color::reset << " <depth> Set io_uring receive queue depth (Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, default: auto=dynamic)\n";
		std::cerr << color::yellow << " --rcvbuf" << color::reset << " <size> Set receive buffer size in bytes(128k, 2m, 1g, or bytes), (default: auto)\n";
		std::cerr << color::yellow << " --send-uring" << color::reset << " <depth> Set io_uring send queue depth (Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, default: auto=2048)\n";
		std::cerr << color::yellow << " --sqpoll" << color::reset << " Force-enable io_uring SQPOLL mode (kernel-thread submission, fewer io_uring_enter syscalls). Auto-enabled when adaptive pacing sees >= --sqpoll-threshold probes (default 300000, counted per host batch), or when fixed pacing predicts a scan >=8s\n";
		std::cerr << color::yellow << " -b <size>" << color::reset << " Set max port batch size (default: 500, support: 1 to 65535)\n"
			  		   << "     Ports are split into batches of at most this size, evenly\n"
			                   << "     distributed across chunk — actual batch sizes may be smaller(auto handles uneven).\n"
			                   << "     Example: -b 500  (batches of ~500 ports or fewer)\n";
		
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
		          
		std::cerr << color::green << "Server Options:\n" << color::reset;
		std::cerr << color::yellow << " --server" << color::reset << " Start shiv as a LAN control-panel server (open a browser to run scans remotely)\n";
		std::cerr << color::yellow << " --server-port" << color::reset << " <port> Public HTTPS port clients connect to (default: 8443). TLS is handled automatically via stunnel\n";
		std::cerr << color::yellow << " --server-token" << color::reset << " <token> Use a fixed auth token instead of a randomly generated one (not allowed with --count)\n";
		std::cerr << color::yellow << " --count" << color::reset << " <2-15> Generate this many independent links, each with its own port (consecutive from --server-port) and its own random token.\n";
		std::cerr << "                                            For eg: shiv --server (starts on the default port, prints a ready-to-use https link)\n";
		std::cerr << "                                            For eg: shiv --server --server-port 9443\n";
		std::cerr << "                                            For eg: shiv --server --count 5 (5 links on ports 8443-8447)\n\n";
}

void load_signature_config(const std::string &path) {
    g_signature_conf_path = path;
}
