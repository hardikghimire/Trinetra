#include <future>
#include <chrono>
#include <mutex>
#include "utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/neighbour.h>
#include <cctype>
#include <chrono>
#include <ctime>
#include <net/if.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <functional>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <vector>
#include <string>
#include <cerrno>
#include "dns_enum.hpp"

bool custom_dns_configured();
bool resolve_ptr_via_configured_dns(const std::string& ip, std::string& out_domain);

std::vector<std::string> get_configured_plain_dns_servers();

static inline uint64_t process_scalar_remainder(const uint8_t* data, int len) {
    uint64_t sum = 0;
    while (len >= 2) {
        uint16_t word;
        std::memcpy(&word, data, sizeof(word));
        sum += word;
        data += 2;
        len -= 2;
    }
    if (len > 0) {
        sum += static_cast<uint16_t>(*data) << 8;
    }
    return sum;
}

unsigned short checksum(void *b, int len) {
    const uint8_t* data = static_cast<const uint8_t*>(b);
    uint64_t sum = 0;

#ifdef __AVX2__

    if (len >= 32) {
        __m256i zero = _mm256_setzero_si256();
        __m256i sum_vec = _mm256_setzero_si256();
        int avx2_len = len - (len % 32);

        for (int i = 0; i < avx2_len; i += 32) {
            __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
            __m256i sum_part = _mm256_sad_epu8(v, zero);
            sum_vec = _mm256_add_epi64(sum_vec, sum_part);
        }

        sum += _mm256_extract_epi64(sum_vec, 0);
        sum += _mm256_extract_epi64(sum_vec, 1);
        sum += _mm256_extract_epi64(sum_vec, 2);
        sum += _mm256_extract_epi64(sum_vec, 3);

        data += avx2_len;
        len -= avx2_len;
    }
#elif defined(__SSE2__)

    if (len >= 16) {
        __m128i zero = _mm_setzero_si128();
        __m128i sum_vec = _mm_setzero_si128();
        int sse2_len = len - (len % 16);

        for (int i = 0; i < sse2_len; i += 16) {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i));
            __m128i sum_part = _mm_sad_epu8(v, zero);
            sum_vec = _mm_add_epi64(sum_vec, sum_part);
        }

        sum += _mm_extract_epi64(sum_vec, 0);
        sum += _mm_extract_epi64(sum_vec, 1);

        data += sse2_len;
        len -= sse2_len;
    }
#endif

    sum += process_scalar_remainder(data, len);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

std::vector<int> parse_ports(const std::string &port_spec) {
    std::vector<int> ports;
    std::stringstream ss(port_spec);
    std::string token;

    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (token.empty()) {
            std::cerr << "Empty port specification ignored\n";
            continue;
        }

        size_t dash_pos = token.find('-');
        if (dash_pos != std::string::npos) {
            try {
                int start_port = std::stoi(token.substr(0, dash_pos));
                int end_port = std::stoi(token.substr(dash_pos + 1));

                if (start_port > 0 && start_port <= 65535 && end_port > 0 && end_port <= 65535 && start_port <= end_port) {
                    ports.reserve(ports.size() + (end_port - start_port + 1));
                    for (int port = start_port; port <= end_port; ++port) {
                        ports.push_back(port);
                    }
                } else {
                    if (start_port <= 0 || start_port > 65535)
                        std::cerr << "Start port out of range (1-65535): " << start_port << std::endl;
                    else if (end_port <= 0 || end_port > 65535)
                        std::cerr << "End port out of range (1-65535): " << end_port << std::endl;
                    else
                        std::cerr << "Invalid range (start > end): " << token << std::endl;
                }
            } catch (const std::exception &e) {
                std::cerr << "Invalid port range format: " << token << " (" << e.what() << ")\n";
            }
        } else {
            try {
                int port = std::stoi(token);
                if (port > 0 && port <= 65535) {
                    ports.push_back(port);
                } else {
                    std::cerr << "Port out of range (1-65535): " << port << std::endl;
                }
            } catch (const std::exception &e) {
                std::cerr << "Invalid port number: " << token << " (" << e.what() << ")\n";
            }
        }
    }

    if (ports.empty()) {
        std::cerr << "No valid ports parsed from: " << port_spec << std::endl;
        return ports;
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

std::vector<int> read_ports_from_file(const std::string& filename) {
    std::vector<int> ports;

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open " << filename << ": " << strerror(errno) << std::endl;
        return ports;
    }
    struct FDGuard {
        int fd;
        ~FDGuard() { if (fd >= 0) close(fd); }
    } guard{fd};

    struct stat st;
    if (fstat(fd, &st) < 0) {
        std::cerr << "Failed to get file size for " << filename
                  << ": " << strerror(errno) << std::endl;
        return ports;
    }
    if (st.st_size == 0) {
        std::cerr << filename << " is empty" << std::endl;
        return ports;
    }

    size_t file_size = static_cast<size_t>(st.st_size);
    void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (mapped == MAP_FAILED) {
        std::cerr << "mmap failed: " << strerror(errno) << std::endl;
        return ports;
    }
    struct MapGuard {
        void* ptr; size_t size;
        ~MapGuard() { if (ptr != MAP_FAILED) munmap(ptr, size); }
    } map_guard{mapped, file_size};

    ports.reserve((file_size / 7) + 100);
    const char* data    = static_cast<const char*>(mapped);
    const char* end     = data + file_size;
    const char* current = data;

    while (current < end) {
        while (current < end &&
               (*current == ' ' || *current == '\t' || *current == '\r')) ++current;
        if (current >= end) break;

        const char* num_start = current;
        while (current < end && *current >= '0' && *current <= '9') ++current;

        if (current > num_start) {
            int port  = 0;
            bool valid = true;
            for (const char* p = num_start; p < current && valid; ++p) {
                if (port > 65535 / 10) { valid = false; break; }
                port = port * 10 + (*p - '0');
                if (port > 65535) { valid = false; break; }
            }
            if (valid && port > 0) {
                ports.push_back(port);
            } else if (current - num_start > 0) {
                std::cerr << "Port out of range in " << filename << ": "
                          << std::string(num_start, current - num_start) << std::endl;
            }
        }
        while (current < end && *current != '\n') ++current;
        if (current < end) ++current;
    }

    if (ports.empty()) {
        std::cerr << "No valid ports found in " << filename << std::endl;
        return ports;
    }
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

int get_ip_version(const char* ip) {
    struct sockaddr_in sa4;
    if (inet_pton(AF_INET, ip, &sa4.sin_addr) == 1) {
        return 4;
    }
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1) {
        return 6;
    }
    return 0;
}

bool parse_cidr_generic(const std::string& cidr, int family,
                         std::string& ip_out, uint8_t& prefix_out) {
    if (family != AF_INET && family != AF_INET6) return false;

    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;

    std::string ip = cidr.substr(0, slash);
    std::string prefix_str = cidr.substr(slash + 1);
    if (prefix_str.empty()) return false;

    for (char c : prefix_str) {
        if (!isdigit(static_cast<unsigned char>(c))) return false;
    }

    int max_prefix = (family == AF_INET) ? 32 : 128;
    int p;
    try {
        p = std::stoi(prefix_str);
    } catch (...) {
        return false;
    }
    if (p < 0 || p > max_prefix) return false;

    unsigned char buf[16];
    if (inet_pton(family, ip.c_str(), buf) != 1) return false;

    ip_out = ip;
    prefix_out = static_cast<uint8_t>(p);
    return true;
}

int make_sockaddr_from_ip(const std::string& ip, uint16_t port,
                           struct sockaddr_storage& out, socklen_t& out_len) {
    out = {};
    out_len = 0;
    auto* a4 = reinterpret_cast<struct sockaddr_in*>(&out);
    if (inet_pton(AF_INET, ip.c_str(), &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(port);
        out_len = sizeof(struct sockaddr_in);
        return AF_INET;
    }
    auto* a6 = reinterpret_cast<struct sockaddr_in6*>(&out);
    if (inet_pton(AF_INET6, ip.c_str(), &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(port);
        out_len = sizeof(struct sockaddr_in6);
        return AF_INET6;
    }
    return 0;
}

namespace {

struct V6AddrRecord {
    std::string ifname;
    struct in6_addr addr;
    uint8_t prefix;
};

struct LocalIfaceSnapshot {
    std::chrono::steady_clock::time_point taken;
    std::unordered_map<std::string, unsigned int> iface_flags;
    std::unordered_map<std::string, std::string> addr_owner;
    std::vector<V6AddrRecord> v6;
};

std::string make_addr_key(int family, const void* addr, size_t len) {
    std::string key;
    key.reserve(len + 1);
    key.push_back(static_cast<char>(family));
    key.append(static_cast<const char*>(addr), len);
    return key;
}

uint8_t netmask6_prefix(const struct sockaddr* mask) {
    if (!mask || mask->sa_family != AF_INET6) return 64;
    const auto* m6 = reinterpret_cast<const struct sockaddr_in6*>(mask);
    uint8_t prefix = 0;
    for (int i = 0; i < 16; ++i) {
        prefix = static_cast<uint8_t>(prefix + __builtin_popcount(m6->sin6_addr.s6_addr[i]));
    }
    return prefix;
}

std::shared_ptr<const LocalIfaceSnapshot> get_local_iface_snapshot(int& err_out) {
    static std::mutex snapshot_mutex;
    static std::shared_ptr<const LocalIfaceSnapshot> cached;
    static const std::chrono::milliseconds max_age(250);

    std::lock_guard<std::mutex> lock(snapshot_mutex);
    const auto now = std::chrono::steady_clock::now();
    if (cached && (now - cached->taken) < max_age) return cached;

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        err_out = errno;
        return nullptr;
    }

    auto snap = std::make_shared<LocalIfaceSnapshot>();
    snap->taken = now;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        const std::string name = ifa->ifa_name ? ifa->ifa_name : "";
        snap->iface_flags[name] |= ifa->ifa_flags;
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
            snap->addr_owner.emplace(make_addr_key(AF_INET, &sin->sin_addr, 4), name);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(ifa->ifa_addr);
            snap->addr_owner.emplace(make_addr_key(AF_INET6, &sin6->sin6_addr, 16), name);
            V6AddrRecord rec;
            rec.ifname = name;
            rec.addr = sin6->sin6_addr;
            rec.prefix = netmask6_prefix(ifa->ifa_netmask);
            snap->v6.push_back(std::move(rec));
        }
    }
    freeifaddrs(ifaddr);

    cached = snap;
    return cached;
}

}

static std::string autodetect_interface_impl(int family, const void* addr, size_t addr_len) {
    static std::unordered_map<std::string, std::string> iface_cache;
    static std::mutex cache_mutex;

    char keybuf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(family, addr, keybuf, sizeof(keybuf));
    std::string key(keybuf);

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = iface_cache.find(key);
        if (it != iface_cache.end()) return it->second;
    }

    int snap_err = 0;
    auto snap = get_local_iface_snapshot(snap_err);
    if (!snap) {
        std::cerr << "getifaddrs failed: " << strerror(snap_err) << std::endl;
        std::string default_iface, default_gw;
        if (get_default_route(family, default_iface, default_gw) && !default_iface.empty()) {
            return default_iface;
        }
        return "eth0";
    }
    auto owner = snap->addr_owner.find(make_addr_key(family, addr, addr_len));
    if (owner != snap->addr_owner.end()) {
        std::string found_iface = owner->second;
        std::lock_guard<std::mutex> lock(cache_mutex);
        iface_cache[key] = found_iface;
        return found_iface;
    }

    std::string default_iface, default_gw;
    if (get_default_route(family, default_iface, default_gw) && !default_iface.empty())
        return default_iface;
    return "eth0";
}

std::string autodetect_interface(uint32_t local_ip) {
    return autodetect_interface_impl(AF_INET, &local_ip, sizeof(local_ip));
}

std::string autodetect_interface(const struct in6_addr& local_ip6) {
    return autodetect_interface_impl(AF_INET6, &local_ip6, sizeof(local_ip6));
}

bool get_interface_ip6(const char* ifname, uint8_t* ip6, uint8_t* prefix_len) {
    if (!ip6 || !ifname) return false;

    int snap_err = 0;
    auto snap = get_local_iface_snapshot(snap_err);
    if (!snap) {
        std::cerr << "get_interface_ip6: getifaddrs failed: " << strerror(snap_err) << "\n";
        return false;
    }

    bool found_global = false, found_any = false;
    uint8_t best_ip[16] = {0};
    uint8_t best_prefix = 64;

    for (const auto& rec : snap->v6) {
        if (rec.ifname != ifname) continue;
        if (IN6_IS_ADDR_LOOPBACK(&rec.addr)) continue;
        const bool is_link_local = IN6_IS_ADDR_LINKLOCAL(&rec.addr);

        if (!is_link_local) {
            memcpy(best_ip, &rec.addr, 16);
            best_prefix = rec.prefix;
            found_global = true;
            break;
        } else if (!found_any) {
            memcpy(best_ip, &rec.addr, 16);
            best_prefix = rec.prefix;
        }
        found_any = true;
    }

    if (!found_global && !found_any) return false;
    memcpy(ip6, best_ip, 16);
    if (prefix_len) *prefix_len = best_prefix;
    return true;
}

Ipv6Scope classify_ipv6_scope(const struct in6_addr& a) {
    if (IN6_IS_ADDR_LINKLOCAL(&a)) return Ipv6Scope::LinkLocal;
    if ((a.s6_addr[0] & 0xFE) == 0xFC) return Ipv6Scope::UniqueLocal;
    return Ipv6Scope::Global;
}

std::vector<Ipv6AddrInfo> get_all_interface_ip6(const std::string& ifname) {
    std::vector<Ipv6AddrInfo> out;
    int snap_err = 0;
    auto snap = get_local_iface_snapshot(snap_err);
    if (!snap) return out;

    for (const auto& rec : snap->v6) {
        if (ifname != rec.ifname) continue;
        if (IN6_IS_ADDR_LOOPBACK(&rec.addr)) continue;

        Ipv6AddrInfo info{};
        memcpy(info.addr, &rec.addr, 16);
        info.scope = classify_ipv6_scope(rec.addr);
        info.prefix_len = rec.prefix;
        out.push_back(info);
    }
    return out;
}

std::string format_ipv6(const uint8_t* ip6) {
    if (!ip6) return "::";
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET6, ip6, buf, sizeof(buf))) return "::";
    return std::string(buf);
}

static bool load_services_file(const std::string& filename,
                               std::unordered_map<uint16_t, std::string>& service_map) {

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open services file: " << filename << ": " << strerror(errno) << std::endl;
        return false;
    }
    struct FDGuard {
        int fd;
        ~FDGuard() { if (fd >= 0) close(fd); }
    } fd_guard{fd};

    struct stat st;
    if (fstat(fd, &st) < 0) {
        std::cerr << "Failed to get services file size: " << strerror(errno) << std::endl;
        return false;
    }
    if (st.st_size == 0) {
        std::cerr << "services file is empty\n";
        return false;
    }
    size_t file_size = static_cast<size_t>(st.st_size);
    void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (mapped == MAP_FAILED) {
        std::cerr << "mmap failed for services file: " << strerror(errno) << std::endl;
        return false;
    }
    struct MapGuard {
        void* ptr; size_t size;
        ~MapGuard() { munmap(ptr, size); }
    } map_guard{mapped, file_size};

    service_map.reserve(20000);
    const char *data = static_cast<const char*>(mapped);
    const char *end = data + file_size;
    const char *line_start = data;
    while (line_start < end) {
        const char *nl = static_cast<const char*>(memchr(line_start, '\n', end - line_start));
        const char *line_end = nl ? nl : end;
        const char *next_line = nl ? nl + 1 : end;
        if (line_end > line_start && line_end[-1] == '\r') --line_end;

        if (line_start == line_end || *line_start == '#') {
            line_start = next_line;
            continue;
        }
        const char *ptr = line_start;
        const char *service_start = ptr;
        while (ptr < line_end && *ptr != '\t' && *ptr != ' ') {
            ptr++;
        }
        if (ptr == service_start) {
            line_start = next_line;
            continue;
        }
        std::string_view service_name(service_start, ptr - service_start);
        while (ptr < line_end && (*ptr == '\t' || *ptr == ' ')) {
            ptr++;
        }
        uint32_t port = 0;
        bool valid_port = false;
        bool overflow = false;
        while (ptr < line_end && *ptr >= '0' && *ptr <= '9') {
            if (!overflow) {
                port = port * 10 + static_cast<uint32_t>(*ptr - '0');
                if (port > 65535) overflow = true;
            }
            ptr++;
            valid_port = true;
        }
        if (!valid_port || overflow || port == 0) {
            line_start = next_line;
            continue;
        }
        bool is_tcp = false;
        if (ptr < line_end && *ptr == '/') {
            ptr++;
            const char *proto_start = ptr;
            while (ptr < line_end && *ptr != '\t' && *ptr != ' ') {
                ptr++;
            }
            std::string_view protocol(proto_start, ptr - proto_start);
            if (protocol == "tcp") is_tcp = true;
        }
        if (is_tcp) {
            service_map[static_cast<uint16_t>(port)] = std::string(service_name);
        }
        line_start = next_line;
    }
    return true;
}

const std::unordered_map<uint16_t, std::string>& read_services_from_file(const std::string &filename) {
    static std::mutex cache_mutex;
    static std::unordered_map<std::string, std::unordered_map<uint16_t, std::string>> cache;
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_fail;
    static const std::unordered_map<uint16_t, std::string> empty_map;
    constexpr std::chrono::seconds kRetryAfter{5};

    std::lock_guard<std::mutex> lk(cache_mutex);
    auto found = cache.find(filename);
    if (found != cache.end()) return found->second;

    const auto now = std::chrono::steady_clock::now();
    auto failed = last_fail.find(filename);
    if (failed != last_fail.end() && (now - failed->second) < kRetryAfter) return empty_map;

    std::unordered_map<uint16_t, std::string> parsed;
    if (!load_services_file(filename, parsed)) {
        last_fail[filename] = now;
        return empty_map;
    }
    last_fail.erase(filename);
    auto& slot = cache[filename];
    slot = std::move(parsed);
    return slot;
}

namespace {
std::unordered_map<std::string, std::string> g_ptr_cache;
std::mutex g_ptr_cache_mutex;
}

bool ptr_cache_lookup(const std::string& ip, std::string& out_domain) {
    std::lock_guard<std::mutex> lock(g_ptr_cache_mutex);
    auto it = g_ptr_cache.find(ip);
    if (it == g_ptr_cache.end()) return false;
    out_domain = it->second;
    return true;
}

void ptr_cache_store(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lock(g_ptr_cache_mutex);
    g_ptr_cache[ip] = domain;
}

namespace {

std::string reverse_arpa_v4(const std::string& ip) {
    struct in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return "";
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&a.s_addr);
    std::ostringstream ss;
    ss << (int)b[3] << "." << (int)b[2] << "." << (int)b[1] << "." << (int)b[0] << ".in-addr.arpa";
    return ss.str();
}

std::string reverse_arpa_v6(const std::string& ip) {
    struct in6_addr a{};
    if (inet_pton(AF_INET6, ip.c_str(), &a) != 1) return "";
    std::ostringstream ss;
    for (int i = 15; i >= 0; --i) {
        uint8_t byte = a.s6_addr[i];
        ss << std::hex << (byte & 0xF) << "." << ((byte >> 4) & 0xF) << ".";
    }
    ss << "ip6.arpa";
    return ss.str();
}

std::string reverse_arpa(const std::string& ip) {
    return (get_ip_version(ip.c_str()) == 4) ? reverse_arpa_v4(ip) : reverse_arpa_v6(ip);
}

}

std::vector<std::string> get_system_resolvers() {
    std::vector<std::string> servers;
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("nameserver", 0) != 0) continue;
        std::istringstream iss(line);
        std::string tag, ip;
        iss >> tag >> ip;
        if (!ip.empty() && get_ip_version(ip.c_str()) > 0) servers.push_back(ip);
    }
    return servers;
}

void reverse_dns_lookup_batch(const std::vector<std::string>& ips,
                               std::unordered_map<std::string, std::string>& out_hostnames,
                               int timeout_ms,
                               int retries,
                               int concurrency) {
    out_hostnames.clear();
    if (ips.empty()) return;

    std::vector<std::string> to_query;
    to_query.reserve(ips.size());
    std::unordered_set<std::string> seen;
    for (const auto& ip : ips) {
        if (!seen.insert(ip).second) continue;
        std::string cached;
        if (ptr_cache_lookup(ip, cached)) {
            if (!cached.empty()) out_hostnames[ip] = cached;
            continue;
        }
        to_query.push_back(ip);
    }
    if (to_query.empty()) return;

    std::vector<std::string> servers = get_configured_plain_dns_servers();
    bool dot_only = servers.empty() && custom_dns_configured();
    if (servers.empty() && !dot_only) servers = get_system_resolvers();

    if (!dot_only && !servers.empty()) {

        std::vector<AsyncDnsJob> jobs;
        jobs.reserve(to_query.size());
        for (auto& ip : to_query) {
            std::string arpa = reverse_arpa(ip);
            if (!arpa.empty()) jobs.push_back({arpa, DnsRRType::PTR, ip});
        }

        std::unordered_set<std::string> still_missing;
        for (auto& ip : to_query) still_missing.insert(ip);

        auto run_pass = [&](std::vector<AsyncDnsJob>& job_list) {
            auto results = dns_query_batch(job_list, servers, timeout_ms, concurrency,  true);
            for (auto& r : results) {
                std::string name;
                for (auto& rec : r.records) {
                    if (rec.type == DnsRRType::PTR && !rec.value.empty()) { name = rec.value; break; }
                }
                if (!name.empty()) {
                    out_hostnames[r.tag] = name;
                    ptr_cache_store(r.tag, name);
                    still_missing.erase(r.tag);
                } else if (r.answered) {

                    ptr_cache_store(r.tag, "");
                    still_missing.erase(r.tag);
                }

            }
        };
        run_pass(jobs);

        for (int attempt = 1; attempt < retries && !still_missing.empty(); ++attempt) {
            std::vector<AsyncDnsJob> retry_jobs;
            retry_jobs.reserve(still_missing.size());
            for (auto& ip : still_missing) {
                std::string arpa = reverse_arpa(ip);
                if (!arpa.empty()) retry_jobs.push_back({arpa, DnsRRType::PTR, ip});
            }
            if (retry_jobs.empty()) break;
            run_pass(retry_jobs);
        }
        return;
    }

    const int pool_size = std::max(1, std::min(concurrency, 64));
    std::mutex out_mutex;
    std::atomic<size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            size_t idx = next.fetch_add(1);
            if (idx >= to_query.size()) return;
            const std::string& ip = to_query[idx];
            std::string domain;
            bool ok = resolve_ptr_via_configured_dns(ip, domain);
            std::lock_guard<std::mutex> lock(out_mutex);
            ptr_cache_store(ip, ok ? domain : "");
            if (ok && !domain.empty()) out_hostnames[ip] = domain;
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(pool_size);
    for (int i = 0; i < pool_size; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
}

std::string reverse_dns_lookup(const std::string& ip_address) {
    std::unordered_map<std::string, std::string> out;
    reverse_dns_lookup_batch({ip_address}, out,  2000,  2,  1);
    auto it = out.find(ip_address);
    return it != out.end() ? it->second : "";
}

bool get_interface_mac(int sock, const char* ifname, uint8_t* mac) {
    if (!mac || !ifname) return false;

    if (strcmp(ifname, "lo") == 0) {
        static const uint8_t loopback_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        memcpy(mac, loopback_mac, 6);
        return true;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        return true;
    }

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        std::cerr << "get_interface_mac: getifaddrs failed: " << strerror(errno) << "\n";
        return false;
    }

    bool found = false;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_PACKET) continue;

        struct sockaddr_ll* sll =
            reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen != 6) continue;

        memcpy(mac, sll->sll_addr, 6);
        found = true;
        if (strcmp(ifa->ifa_name, ifname) == 0) break;
    }
    freeifaddrs(ifaddr);

    if (!found) {
        std::cerr << "get_interface_mac: no hardware address found for '"
                  << ifname << "'\n";
    }
    return found;
}

bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask) {
    if (!ip || !netmask || !ifname) return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        return false;
    }
    memcpy(ip, &(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 4);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        return false;
    }
    memcpy(netmask, &(((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr), 4);
    return true;
}

bool parse_mac(const std::string& mac_str, uint8_t* out_mac) {
    if (!out_mac) return false;
    unsigned int b[6];
    int n = sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    if (n != 6) return false;
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xFF) return false;
        out_mac[i] = static_cast<uint8_t>(b[i]);
    }
    return true;
}

static const size_t MAX_RESPONSE_SIZE = 10 * 1024 * 1024;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;

    if (size == 0 || nmemb == 0 || newLength / size != nmemb) {
        return 0;
    }

    if (s->size() + newLength > MAX_RESPONSE_SIZE) {
        return 0;
    }

    try {
        s->append((char*)contents, newLength);
    } catch(const std::bad_alloc& e) {
        return 0;
    } catch(const std::exception& e) {
        return 0;
    }

    return newLength;
}

std::string format_mac(const uint8_t* mac) {
    if (!mac) {
        return "00:00:00:00:00:00";
    }
    static const char hex_chars[] = "0123456789abcdef";
    char buf[18];
    for (int i = 0; i < 6; ++i) {
        int pos = i * 3;
        buf[pos]     = hex_chars[(mac[i] >> 4) & 0x0F];
        buf[pos + 1] = hex_chars[ mac[i]       & 0x0F];
        if (i < 5) buf[pos + 2] = ':';
    }
    buf[17] = '\0';
    return std::string(buf, 17);
}

bool is_same_subnet(uint32_t ip1, uint32_t ip2, uint32_t netmask) {
    return (ip1 & netmask) == (ip2 & netmask);
}

bool route_lookup(const std::string& target_ip, int family,
                   std::string& out_iface, bool& out_is_onlink,
                   std::string* out_gateway) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return false;

    struct { struct nlmsghdr nh; struct rtmsg rt; char attrbuf[512]; } req{};
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type  = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_seq   = 1;
    req.rt.rtm_family  = static_cast<unsigned char>(family);
    req.rt.rtm_dst_len = (family == AF_INET) ? 32 : 128;

    size_t addr_len = (family == AF_INET) ? 4 : 16;
    auto* rta = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(addr_len);

    if (family == AF_INET) {
        struct in_addr a{};
        if (inet_pton(AF_INET, target_ip.c_str(), &a) != 1) { close(sock); return false; }
        memcpy(RTA_DATA(rta), &a, addr_len);
    } else {
        struct in6_addr a6{};
        if (inet_pton(AF_INET6, target_ip.c_str(), &a6) != 1) { close(sock); return false; }
        memcpy(RTA_DATA(rta), &a6, addr_len);
    }
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(addr_len);

    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) { close(sock); return false; }

    char buf[8192];
    ssize_t len = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (len <= 0) return false;

    bool found = false;
    for (auto* nh = reinterpret_cast<struct nlmsghdr*>(buf);
         NLMSG_OK(nh, static_cast<size_t>(len)); nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_ERROR) return false;
        if (nh->nlmsg_type != RTM_NEWROUTE) continue;

        auto* rtm = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(nh));
        auto* attr = RTM_RTA(rtm);
        int attr_len = static_cast<int>(RTM_PAYLOAD(nh));
        bool has_gateway = false;
        int  oif = -1;
        std::string gw_text;
        struct rtattr* multipath_attr = nullptr;

        for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
            if (attr->rta_type == RTA_GATEWAY) {
                has_gateway = true;
                char gwbuf[INET6_ADDRSTRLEN] = {0};
                inet_ntop(family, RTA_DATA(attr), gwbuf, sizeof(gwbuf));
                gw_text = gwbuf;
            }
            if (attr->rta_type == RTA_OIF)       oif = *reinterpret_cast<int*>(RTA_DATA(attr));
            if (attr->rta_type == RTA_MULTIPATH) multipath_attr = attr;
        }

        if (multipath_attr && oif < 0) {
            auto* rtnh = reinterpret_cast<struct rtnexthop*>(RTA_DATA(multipath_attr));
            int rtnh_len = static_cast<int>(RTA_PAYLOAD(multipath_attr));
            if (RTNH_OK(rtnh, rtnh_len)) {
                oif = rtnh->rtnh_ifindex;
                auto* nh_attr = RTNH_DATA(rtnh);
                int nh_attr_len = rtnh->rtnh_len - sizeof(struct rtnexthop);
                for (; RTA_OK(nh_attr, nh_attr_len); nh_attr = RTA_NEXT(nh_attr, nh_attr_len)) {
                    if (nh_attr->rta_type == RTA_GATEWAY) {
                        has_gateway = true;
                        char gwbuf[INET6_ADDRSTRLEN] = {0};
                        inet_ntop(family, RTA_DATA(nh_attr), gwbuf, sizeof(gwbuf));
                        gw_text = gwbuf;
                    }
                }
            }
        }

        if (oif >= 0) {
            char ifname_buf[IF_NAMESIZE] = {0};
            if (if_indextoname(static_cast<unsigned>(oif), ifname_buf)) {
                out_iface     = ifname_buf;
                out_is_onlink = !has_gateway;
                if (out_gateway) *out_gateway = gw_text;
                found = true;
            }
        }
    }
    return found;
}

namespace {

struct DefaultRouteEntry {
    std::chrono::steady_clock::time_point taken{};
    bool        found = false;
    std::string iface;
    std::string gateway;
};

std::mutex g_default_route_mutex;
std::unordered_map<int, DefaultRouteEntry> g_default_route_cache;
constexpr std::chrono::milliseconds kDefaultRouteTtl{2000};

bool get_default_route_uncached(int family, std::string& out_iface, std::string& out_gateway) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return false;

    struct { struct nlmsghdr nh; struct rtgenmsg rtg; } req{};
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.nh.nlmsg_type  = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq   = 1;
    req.rtg.rtgen_family = static_cast<unsigned char>(family);

    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) { close(sock); return false; }

    bool found = false;
    uint32_t best_metric = UINT32_MAX;
    char buf[16384];
    bool done = false;

    while (!done) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) break;

        for (auto* nh = reinterpret_cast<struct nlmsghdr*>(buf);
             NLMSG_OK(nh, static_cast<size_t>(len)); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            if (nh->nlmsg_type != RTM_NEWROUTE) continue;

            auto* rtm = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(nh));
            if (rtm->rtm_dst_len != 0) continue;
            if (rtm->rtm_table != RT_TABLE_MAIN) continue;

            auto* attr = RTM_RTA(rtm);
            int attr_len = static_cast<int>(RTM_PAYLOAD(nh));
            bool has_gateway = false;
            int  oif = -1;
            uint32_t metric = 0;
            std::string gw_text;

            for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                if (attr->rta_type == RTA_GATEWAY) {
                    has_gateway = true;
                    char gwbuf[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(family, RTA_DATA(attr), gwbuf, sizeof(gwbuf));
                    gw_text = gwbuf;
                }
                if (attr->rta_type == RTA_OIF)      oif = *reinterpret_cast<int*>(RTA_DATA(attr));
                if (attr->rta_type == RTA_PRIORITY) metric = *reinterpret_cast<uint32_t*>(RTA_DATA(attr));
            }

            if (oif >= 0 && has_gateway && metric < best_metric) {
                char ifname_buf[IF_NAMESIZE] = {0};
                if (if_indextoname(static_cast<unsigned>(oif), ifname_buf)) {
                    out_iface   = ifname_buf;
                    out_gateway = gw_text;
                    best_metric = metric;
                    found = true;
                }
            }
        }
    }
    close(sock);
    return found;
}

}

bool get_default_route(int family, std::string& out_iface, std::string& out_gateway) {
    if (family != AF_INET && family != AF_INET6) return false;

    {
        std::lock_guard<std::mutex> lk(g_default_route_mutex);
        auto it = g_default_route_cache.find(family);
        if (it != g_default_route_cache.end() &&
            (std::chrono::steady_clock::now() - it->second.taken) < kDefaultRouteTtl) {
            if (!it->second.found) return false;
            out_iface   = it->second.iface;
            out_gateway = it->second.gateway;
            return true;
        }
    }

    DefaultRouteEntry entry;
    entry.found = get_default_route_uncached(family, entry.iface, entry.gateway);
    entry.taken = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(g_default_route_mutex);
        g_default_route_cache[family] = entry;
    }

    if (!entry.found) return false;
    out_iface   = entry.iface;
    out_gateway = entry.gateway;
    return true;
}

namespace {

struct NeighborSnapshot {
    std::chrono::steady_clock::time_point taken{};
    std::unordered_set<std::string> reachable;   
};

std::mutex g_neighbor_mutex;
std::unordered_map<int, std::shared_ptr<const NeighborSnapshot>> g_neighbor_cache;
constexpr std::chrono::milliseconds kNeighborTtl{500};

std::string make_neigh_key(int family, const void* addr, size_t len) {
    std::string key;
    key.reserve(len + 1);
    key.push_back(static_cast<char>(family));
    key.append(static_cast<const char*>(addr), len);
    return key;
}

std::shared_ptr<const NeighborSnapshot> fetch_neighbor_snapshot(int family) {
    auto snap = std::make_shared<NeighborSnapshot>();
    snap->taken = std::chrono::steady_clock::now();

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return snap;                     
    struct FDGuard { int fd; ~FDGuard() { if (fd >= 0) close(fd); } } guard{sock};

    struct { struct nlmsghdr nh; struct ndmsg nd; } req{};
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nh.nlmsg_type  = RTM_GETNEIGH;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq   = 1;
    req.nd.ndm_family  = static_cast<unsigned char>(family);

    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) return snap;

    bool done = false;
    char buf[8192];
    while (!done) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) break;
        for (auto* nh = reinterpret_cast<struct nlmsghdr*>(buf);
             NLMSG_OK(nh, static_cast<size_t>(len)); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            if (nh->nlmsg_type != RTM_NEWNEIGH) continue;

            auto* ndm = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(nh));
            if (!(ndm->ndm_state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT)))
                continue;

            auto* attr = RTM_RTA(ndm);
            int attr_len = static_cast<int>(RTM_PAYLOAD(nh));
            for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                if (attr->rta_type != NDA_DST) continue;
                size_t addr_len = (family == AF_INET) ? 4 : 16;
                if (RTA_PAYLOAD(attr) < addr_len) continue;   
                snap->reachable.insert(make_neigh_key(family, RTA_DATA(attr), addr_len));
            }
        }
    }
    return snap;
}

std::shared_ptr<const NeighborSnapshot> get_neighbor_snapshot_cached(int family) {
    std::lock_guard<std::mutex> lk(g_neighbor_mutex);
    auto it = g_neighbor_cache.find(family);
    if (it != g_neighbor_cache.end() &&
        (std::chrono::steady_clock::now() - it->second->taken) < kNeighborTtl) {
        return it->second;
    }
    auto fresh = fetch_neighbor_snapshot(family);
    g_neighbor_cache[family] = fresh;
    return fresh;
}

struct ConntrackSnapshot {
    std::chrono::steady_clock::time_point taken{};
    std::unordered_set<std::string> addrs;
};

std::mutex g_conntrack_mutex;
std::shared_ptr<const ConntrackSnapshot> g_conntrack_cache;
constexpr std::chrono::milliseconds kConntrackTtl{500};

std::shared_ptr<const ConntrackSnapshot> fetch_conntrack_snapshot() {
    auto snap = std::make_shared<ConntrackSnapshot>();
    snap->taken = std::chrono::steady_clock::now();

    std::ifstream f("/proc/net/nf_conntrack");
    if (!f.is_open()) return snap;

    std::string line, token;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        while (iss >> token) {
            for (const char* prefix : {"src=", "dst="}) {
                size_t plen = std::strlen(prefix);
                if (token.size() > plen && token.compare(0, plen, prefix) == 0) {
                    const char* val = token.c_str() + plen;
                    unsigned char raw[16];
                    if (inet_pton(AF_INET6, val, raw) == 1)
                        snap->addrs.insert(make_neigh_key(AF_INET6, raw, 16));
                    else if (inet_pton(AF_INET, val, raw) == 1)
                        snap->addrs.insert(make_neigh_key(AF_INET, raw, 4));
                }
            }
        }
    }
    return snap;
}

std::shared_ptr<const ConntrackSnapshot> get_conntrack_snapshot_cached() {
    std::lock_guard<std::mutex> lk(g_conntrack_mutex);
    if (g_conntrack_cache &&
        (std::chrono::steady_clock::now() - g_conntrack_cache->taken) < kConntrackTtl) {
        return g_conntrack_cache;
    }
    auto fresh = fetch_conntrack_snapshot();
    g_conntrack_cache = fresh;
    return fresh;
}

} 

bool neighbor_cache_has_entry(int family, const std::string& target_ip) {
    if (family != AF_INET && family != AF_INET6) return false;

    struct in_addr  want4{};
    struct in6_addr want6{};
    const void* addr_ptr; size_t addr_len;
    if (family == AF_INET) {
        if (inet_pton(AF_INET, target_ip.c_str(), &want4) != 1) return false;
        addr_ptr = &want4; addr_len = 4;
    } else {
        if (inet_pton(AF_INET6, target_ip.c_str(), &want6) != 1) return false;
        addr_ptr = &want6; addr_len = 16;
    }

    auto snap = get_neighbor_snapshot_cached(family);
    return snap->reachable.count(make_neigh_key(family, addr_ptr, addr_len)) != 0;
}

bool conntrack_has_entry(const std::string& target_ip) {
    if (target_ip.empty()) return false;
    unsigned char raw[16];
    std::string key;
    if (inet_pton(AF_INET6, target_ip.c_str(), raw) == 1)     key = make_neigh_key(AF_INET6, raw, 16);
    else if (inet_pton(AF_INET, target_ip.c_str(), raw) == 1) key = make_neigh_key(AF_INET, raw, 4);
    else return false;
    auto snap = get_conntrack_snapshot_cached();
    return snap->addrs.count(key) != 0;
}

bool neighbor_cache_has_entry_v4(const std::string& target_ip) {
    return neighbor_cache_has_entry(AF_INET, target_ip);
}

bool is_point_to_point_interface(const std::string& ifname) {
    int snap_err = 0;
    auto snap = get_local_iface_snapshot(snap_err);
    if (!snap) return false;
    auto it = snap->iface_flags.find(ifname);
    return it != snap->iface_flags.end() && (it->second & IFF_POINTOPOINT) != 0;
}

bool is_vlan_interface(const std::string& ifname) {
    std::ifstream f("/proc/net/vlan/config");
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        auto pipe_pos = line.find('|');
        if (pipe_pos == std::string::npos) continue;
        std::string name = line.substr(0, pipe_pos);

        size_t start = name.find_first_not_of(" \t");
        size_t end   = name.find_last_not_of(" \t");
        if (start == std::string::npos) continue;
        name = name.substr(start, end - start + 1);
        if (name == ifname) return true;
    }
    return false;
}

std::string classify_interface_kind(const std::string& ifname) {
    struct stat st{};
    std::string dev_path = "/sys/class/net/" + ifname + "/device";
    if (lstat(dev_path.c_str(), &st) == 0) return "physical";
    return "virtual";
}

std::string get_current_time() {
    time_t now = time(nullptr);
    if (now == (time_t)-1) {
        return "[unknown time]";
    }
    std::string result = ctime(&now);
    if (!result.empty() && result[result.length()-1] == '\n') {
        result.resize(result.length()-1);
    }
    return result;
}

namespace {

struct IpRangeV4 { uint32_t start, end; std::string label; };
struct IpRangeV6 { unsigned __int128 start, end; std::string label; };

std::vector<IpRangeV4> g_v4_ranges;
std::vector<IpRangeV6> g_v6_ranges;

unsigned __int128 ipv6_to_u128(const unsigned char* b16) {
    unsigned __int128 v = 0;
    for (int i = 0; i < 16; ++i) v = (v << 8) | b16[i];
    return v;
}

void add_cidr_range(const std::string& cidr, const std::string& label) {
    size_t slash = cidr.find('/');
    std::string addr = (slash == std::string::npos) ? cidr : cidr.substr(0, slash);
    int prefix = -1;
    if (slash != std::string::npos) {
        char *endp = nullptr;
        long v = std::strtol(cidr.c_str() + slash + 1, &endp, 10);
        prefix = (endp != cidr.c_str() + slash + 1 && *endp == '\0') ? static_cast<int>(v) : -1;
    }

    in_addr a4{};
    if (inet_pton(AF_INET, addr.c_str(), &a4) == 1) {
        if (prefix == -1) prefix = 32;
        if (prefix < 0 || prefix > 32) return;
        uint32_t base = ntohl(a4.s_addr);
        uint32_t mask = (prefix == 0) ? 0u : (~uint32_t(0) << (32 - prefix));
        uint32_t start = base & mask;
        uint32_t end   = start | ~mask;
        g_v4_ranges.push_back({start, end, label});
        return;
    }
    in6_addr a6{};
    if (inet_pton(AF_INET6, addr.c_str(), &a6) == 1) {
        if (prefix == -1) prefix = 128;
        if (prefix < 0 || prefix > 128) return;
        unsigned __int128 base = ipv6_to_u128(a6.s6_addr);
        unsigned __int128 mask = (prefix == 0) ? 0
            : (prefix == 128 ? ~(unsigned __int128)0 : (~(unsigned __int128)0 << (128 - prefix)));
        unsigned __int128 start = base & mask;
        unsigned __int128 end   = start | ~mask;
        g_v6_ranges.push_back({start, end, label});
    }
}

void for_each_line(const std::string& path,
                    const std::function<void(const char*, size_t)>& handle_line) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) { std::cerr << "Warning: Could not open IP range file: " << path << "\n"; return; }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return; }
    size_t file_size = st.st_size;
    void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return;
    struct MapGuard {
        void* ptr; size_t size;
        ~MapGuard() { munmap(ptr, size); }
    } map_guard{mapped, file_size};

    const char* data = static_cast<const char*>(mapped);
    const char* end = data + file_size;
    const char* p = data;
    while (p < end) {
        const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
        const char* line_end = nl ? nl : end;
        const char* next_line = nl ? nl + 1 : end;
        size_t len = line_end - p;
        if (len > 0 && p[len - 1] == '\r') --len;
        if (len > 0) handle_line(p, len);
        p = next_line;
    }
}

void load_plain_range_file(const std::string& path, const std::string& label) {
    for_each_line(path, [&](const char* line, size_t len) {
        add_cidr_range(std::string(line, len), label);
    });
}

void load_aws_range_file(const std::string& path) {
    for_each_line(path, [&](const char* line, size_t len) {
        const char* p = line;
        const char* end = line + len;
        auto next_token = [&]() -> std::string {
            while (p < end && isspace((unsigned char)*p)) ++p;
            const char* start = p;
            while (p < end && !isspace((unsigned char)*p)) ++p;
            return std::string(start, p - start);
        };
        std::string service = next_token();
        if (service.empty() || service == "SERVICE" || service[0] == '=') return;
        std::string region = next_token();
        std::string cidr   = next_token();
        if (region.empty() || cidr.empty()) return;
        add_cidr_range(cidr, service + " " + region);
    });
}

void finalize_ip_range_tables() {
    std::sort(g_v4_ranges.begin(), g_v4_ranges.end(),
              [](const IpRangeV4& a, const IpRangeV4& b) { return a.start < b.start; });
    std::sort(g_v6_ranges.begin(), g_v6_ranges.end(),
              [](const IpRangeV6& a, const IpRangeV6& b) { return a.start < b.start; });
}

}

void load_ip_range_databases(const std::string& aws_path,
                              const std::string& cloudflare_path,
                              const std::string& akamai_path,
                              const std::string& azure_path,
                              const std::string& digitalocean_path,
                              const std::string& google_path,
                              const std::string& alibaba_path,
                              const std::string& fastly_path,
                              const std::string& hetzner_path,
                              const std::string& vultr_path,
                              const std::string& zscaler_path,
                              const std::string& googlebot_path,
                              const std::string& linode_path,
                              const std::string& tor_path) {
    load_aws_range_file(aws_path);
    load_plain_range_file(cloudflare_path,   "Cloudflare Inc");
    load_plain_range_file(akamai_path,       "Akamai Technologies");
    load_plain_range_file(azure_path,        "Microsoft Azure");
    load_plain_range_file(digitalocean_path, "DigitalOcean LLC");
    load_plain_range_file(google_path,       "Google LLC");
    load_plain_range_file(alibaba_path,      "Alibaba Cloud");
    load_plain_range_file(fastly_path,       "Fastly Inc");
    load_plain_range_file(hetzner_path,      "Hetzner Online GmbH");
    load_plain_range_file(vultr_path,        "The Constant Company (Vultr)");
    load_plain_range_file(zscaler_path,      "Zscaler Inc");
    load_plain_range_file(googlebot_path,    "Googlebot Crawler");
    load_plain_range_file(linode_path,       "Linode/Akamai Connected Cloud");
    load_plain_range_file(tor_path,          "Tor Exit Node");
    finalize_ip_range_tables();
}

bool lookup_ip_provider(const std::string& ip, std::string& out_label) {
    in_addr a4{};
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) {
        uint32_t target = ntohl(a4.s_addr);
        auto it = std::upper_bound(g_v4_ranges.begin(), g_v4_ranges.end(), target,
            [](uint32_t val, const IpRangeV4& r) { return val < r.start; });
        if (it == g_v4_ranges.begin()) return false;
        --it;
        if (target >= it->start && target <= it->end) { out_label = it->label; return true; }
        return false;
    }
    in6_addr a6{};
    if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) {
        unsigned __int128 target = ipv6_to_u128(a6.s6_addr);
        auto it = std::upper_bound(g_v6_ranges.begin(), g_v6_ranges.end(), target,
            [](unsigned __int128 val, const IpRangeV6& r) { return val < r.start; });
        if (it == g_v6_ranges.begin()) return false;
        --it;
        if (target >= it->start && target <= it->end) { out_label = it->label; return true; }
        return false;
    }
    return false;
}

bool assess_interface_health(const std::string& ifname, InterfaceHealth& out) {
    if (ifname.empty()) return false;
    std::string base = "/sys/class/net/" + ifname;

    std::ifstream speed_f(base + "/speed");
    if (speed_f) speed_f >> out.speed_mbps;

    std::ifstream duplex_f(base + "/duplex");
    std::string duplex_str;
    if (duplex_f) {
        duplex_f >> duplex_str;
        out.full_duplex = (duplex_str == "full");
        out.duplex_readable = true;
    }

    std::ifstream carrier_f(base + "/carrier");
    int carrier_val = 0;
    if (carrier_f) {
        carrier_f >> carrier_val;
        out.carrier_up = (carrier_val == 1);
        out.carrier_readable = true;
    }
    return true;
}

bool detect_local_firewall_active(bool& has_iptables_rules, bool& has_nft_rules) {
    has_iptables_rules = false;
    has_nft_rules = false;

    std::ifstream ipt("/proc/net/ip_tables_names");
    if (ipt && ipt.peek() != std::ifstream::traits_type::eof()) has_iptables_rules = true;

    std::ifstream nft("/proc/net/nf_tables");
    std::string line;
    while (nft && std::getline(nft, line)) {
        if (!line.empty()) { has_nft_rules = true; break; }
    }
    return true;
}

bool get_icmp_ratelimit(int& ratelimit_ms, int& ratemask) {
    std::ifstream f1("/proc/sys/net/ipv4/icmp_ratelimit");
    std::ifstream f2("/proc/sys/net/ipv4/icmp_ratemask");
    if (!f1 || !f2) return false;
    f1 >> ratelimit_ms;
    f2 >> ratemask;
    return true;
}

bool is_target_local_to_host(const std::string& target_ip) {
    struct in_addr a4{};
    struct in6_addr a6{};
    int family = 0;
    if (inet_pton(AF_INET, target_ip.c_str(), &a4) == 1) {
        family = AF_INET;
        if ((ntohl(a4.s_addr) >> 24) == 0x7Fu) return true;
    } else if (inet_pton(AF_INET6, target_ip.c_str(), &a6) == 1) {
        family = AF_INET6;
        if (IN6_IS_ADDR_LOOPBACK(&a6)) return true;
    } else {
        return false;
    }

    int snap_err = 0;
    auto snap = get_local_iface_snapshot(snap_err);
    if (!snap) return false;

    const void* raw = (family == AF_INET) ? static_cast<const void*>(&a4.s_addr)
                                          : static_cast<const void*>(&a6);
    const size_t len = (family == AF_INET) ? 4 : 16;
    return snap->addr_owner.find(make_addr_key(family, raw, len)) != snap->addr_owner.end();
}
