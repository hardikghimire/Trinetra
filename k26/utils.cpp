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

// Custom-DNS bridge — defined in main.cpp, internal-linkage globals guard
// these so this is the only way to reach them from another translation unit.
bool custom_dns_configured();
bool resolve_ptr_via_configured_dns(const std::string& ip, std::string& out_domain);

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
    // AVX2 implementation
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
    // SSE2 implementation
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

    // Process remaining bytes
    sum += process_scalar_remainder(data, len);

    // Fold 64-bit sum to 16-bit checksum
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

    // Reject anything but plain digits up front -- std::stoi alone would
    // silently accept "24abc" and stop at the first non-digit.
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

    unsigned char buf[16]; // big enough for either family
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

    struct ifaddrs *ifaddr;
    std::string interface;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "getifaddrs failed: " << strerror(errno) << std::endl;
        return "eth0";
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != family) continue;
        const void* candidate = (family == AF_INET)
            ? static_cast<const void*>(&reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr)
            : static_cast<const void*>(&reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr)->sin6_addr);
        if (memcmp(candidate, addr, addr_len) == 0) {
            interface = ifa->ifa_name;
            break;
        }
    }
    freeifaddrs(ifaddr);
    if (interface.empty()) {
        std::cerr << "No interface found for local IP; using default 'eth0'\n";
        interface = "eth0";
    }

    std::lock_guard<std::mutex> lock(cache_mutex);
    iface_cache[key] = interface;
    return interface;
}

std::string autodetect_interface(uint32_t local_ip) {
    return autodetect_interface_impl(AF_INET, &local_ip, sizeof(local_ip));
}

std::string autodetect_interface(const struct in6_addr& local_ip6) {
    return autodetect_interface_impl(AF_INET6, &local_ip6, sizeof(local_ip6));
}


bool get_interface_ip6(const char* ifname, uint8_t* ip6, uint8_t* prefix_len) {
    if (!ip6 || !ifname) return false;

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        std::cerr << "get_interface_ip6: getifaddrs failed: " << strerror(errno) << "\n";
        return false;
    }

    bool found_global = false, found_any = false;
    uint8_t best_ip[16] = {0};
    uint8_t best_prefix = 64;

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;

        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) continue;
        bool is_link_local = IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr);

        uint8_t prefix = 64;
        if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET6) {
            struct sockaddr_in6* mask6 = (struct sockaddr_in6*)ifa->ifa_netmask;
            prefix = 0;
            for (int i = 0; i < 16; ++i) {
                uint8_t byte = mask6->sin6_addr.s6_addr[i];
                while (byte) { prefix += (byte & 1); byte >>= 1; }
            }
        }

        if (!is_link_local) {
            memcpy(best_ip, &sin6->sin6_addr, 16);
            best_prefix = prefix;
            found_global = true;
            break;
        } else if (!found_any) {
            memcpy(best_ip, &sin6->sin6_addr, 16);
            best_prefix = prefix;
        }
        found_any = true;
    }
    freeifaddrs(ifaddr);

    if (!found_global && !found_any) return false;
    memcpy(ip6, best_ip, 16);
    if (prefix_len) *prefix_len = best_prefix;
    return true;
}

std::string format_ipv6(const uint8_t* ip6) {
    if (!ip6) return "::";
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET6, ip6, buf, sizeof(buf))) return "::";
    return std::string(buf);
}

const std::unordered_map<uint16_t, std::string>& read_services_from_file(const std::string &filename) {
    static std::unordered_map<uint16_t, std::string> service_map;
    static std::once_flag once_flag;
    
    std::call_once(once_flag, [&]() {
        int fd = open(filename.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "Failed to open services file: " << strerror(errno) << std::endl;
            return;
        }
        struct stat st;
        if (fstat(fd, &st) < 0) {
            std::cerr << "Failed to get services file size: " << strerror(errno) << std::endl;
            close(fd);
            return;
        }
        off_t file_size = st.st_size;
        if (file_size == 0) {
            std::cerr << "services file is empty\n";
            close(fd);
            return;
        }
        char *mapped_data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (mapped_data == MAP_FAILED) {
            std::cerr << "mmap failed for services file: " << strerror(errno) << std::endl;
            close(fd);
            return;
        }
        service_map.reserve(20000);
        const char *data = mapped_data;
        const char *end = data + file_size;
        const char *line_start = data;
        while (line_start < end) {
            const char *line_end = static_cast<const char*>(memchr(line_start, '\n', end - line_start));
            if (!line_end) line_end = end;
            if (line_start == line_end || *line_start == '#') {
                line_start = line_end + 1;
                continue;
            }
            const char *ptr = line_start;
            const char *service_start = ptr;
            while (ptr < line_end && *ptr != '\t' && *ptr != ' ') {
                ptr++;
            }
            if (ptr == service_start) {
                line_start = line_end + 1;
                continue; 
            }
            std::string_view service_name(service_start, ptr - service_start);
            while (ptr < line_end && (*ptr == '\t' || *ptr == ' ')) {
                ptr++;
            }
            uint16_t port = 0;
            bool valid_port = false;
            while (ptr < line_end && *ptr >= '0' && *ptr <= '9') {
                port = port * 10 + (*ptr - '0');
                ptr++;
                valid_port = true;
            }
            if (!valid_port || port == 0 || port > 65535) {
                line_start = line_end + 1;
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
                if (protocol.length() == 3 && 
                    protocol[0] == 't' && 
                    protocol[1] == 'c' && 
                    protocol[2] == 'p') {
                    is_tcp = true;
                }
            }
            if (is_tcp) {
                service_map[port] = std::string(service_name);
            }
            line_start = line_end + 1;
        }
        munmap(mapped_data, file_size);
        close(fd);
    });
    
    return service_map;
}

namespace {
std::unordered_map<std::string, std::string> g_ptr_cache;
std::mutex g_ptr_cache_mutex;
} // namespace

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

std::string reverse_dns_lookup(const std::string& ip_address) {
    std::string cached;
    if (ptr_cache_lookup(ip_address, cached)) return cached;

    // Honor --dns-servers / --dns-servers-tls here too — this is the PTR
    // lookup behind the "Shiv scan report for <hostname>" banner, and it
    // was leaking to the system resolver in plaintext even when the target
    // itself was resolved over DoT.
    if (custom_dns_configured()) {
        std::string domain;
        bool ok = resolve_ptr_via_configured_dns(ip_address, domain);
        ptr_cache_store(ip_address, ok ? domain : "");
        return ok ? domain : "";
    }

    // Build address — support both IPv4 and IPv6 targets.
    struct sockaddr_storage ss{};
    socklen_t ss_len = 0;
    make_sockaddr_from_ip(ip_address, 0, ss, ss_len);

    if (ss_len == 0) {
        // Not a valid IPv4 or IPv6 literal.
        ptr_cache_store(ip_address, "");
        return "";
    }

    struct sockaddr_storage ss_copy = ss;
    socklen_t ss_len_copy = ss_len;

    // Shared state outlives this function if getnameinfo() runs past our
    // timeout — the detached thread writes into it safely whenever it
    // finishes, and nobody blocks waiting for that to happen.
    struct DnsState {
        std::mutex m;
        std::condition_variable cv;
        bool done = false;
        int rc = -1;
        std::string name;
    };
    auto state = std::make_shared<DnsState>();

    std::thread([state, ss_copy, ss_len_copy]() {
        char hostname[NI_MAXHOST];
        int rc = getnameinfo(
            reinterpret_cast<const struct sockaddr*>(&ss_copy), ss_len_copy,
            hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        {
            std::lock_guard<std::mutex> lock(state->m);
            state->rc   = rc;
            state->name = (rc == 0) ? std::string(hostname) : std::string{};
            state->done = true;
        }
        state->cv.notify_all();
    }).detach();

    std::string ret;
    {
        std::unique_lock<std::mutex> lock(state->m);
        bool finished = state->cv.wait_for(lock, std::chrono::milliseconds(1500),
                                            [&] { return state->done; });
        // rc here is EAI_AGAIN / EAI_FAIL / EAI_NONAME / 0 on success.
        // All non-zero and the timeout case fall through to ret staying empty -> skip.
        if (finished && state->rc == 0) ret = state->name;
    }
    // Timeout case: we move on immediately. The detached thread keeps running
    // in the background and will simply be discarded/abandoned when it
    // eventually finishes — it does NOT block us here.

    ptr_cache_store(ip_address, ret);
    return ret;
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

// ---- on-link ground-truth helpers ----
// See utils.hpp for the rationale: address-range checks (the old
// is_private_lan_ip) can't tell a VPS bridged public subnet or a colo
// /29 from a genuinely off-link public IP. These ask the kernel directly.

bool route_lookup(const std::string& target_ip, int family,
                   std::string& out_iface, bool& out_is_onlink) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return false;

    struct {
        struct nlmsghdr nh;
        struct rtmsg    rt;
        char            attrbuf[512];
    } req{};

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

        for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
            if (attr->rta_type == RTA_GATEWAY) has_gateway = true;
            if (attr->rta_type == RTA_OIF)     oif = *reinterpret_cast<int*>(RTA_DATA(attr));
        }
        if (oif >= 0) {
            char ifname_buf[IF_NAMESIZE] = {0};
            if (if_indextoname(static_cast<unsigned>(oif), ifname_buf)) {
                out_iface     = ifname_buf;
                out_is_onlink = !has_gateway;  // no gateway hop = direct/on-link
                found = true;
            }
        }
    }
    return found;
}

bool neighbor_cache_has_entry_v4(const std::string& target_ip) {
    std::ifstream f("/proc/net/arp");
    if (!f.is_open()) return false;
    std::string line;
    std::getline(f, line);  // skip header
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string addr, hwtype, flags, mac;
        iss >> addr >> hwtype >> flags >> mac;
        if (addr == target_ip) {
            return flags == "0x2" && mac != "00:00:00:00:00:00";  // ATF_COMPLETE
        }
    }
    return false;
}

bool is_point_to_point_interface(const std::string& ifname) {
    struct ifaddrs* ifa_list = nullptr;
    if (getifaddrs(&ifa_list) != 0) return false;
    bool result = false;
    for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || ifname != ifa->ifa_name) continue;
        if (ifa->ifa_flags & IFF_POINTOPOINT) { result = true; break; }
    }
    freeifaddrs(ifa_list);
    return result;
}

std::string get_current_time() {
    time_t now = time(nullptr);
    if (now == (time_t)-1) {
        return "[unknown time]";
    }
    std::string result = ctime(&now);
    if (!result.empty() && result[result.length()-1] == '\n') {
        result.resize(result.length()-1);
    // AFTER (unchanged existing code, then new block appended):
    }
    return result;
}

namespace {

struct IpRangeV4 { uint32_t start, end; std::string label; };
struct IpRangeV6 { unsigned __int128 start, end; std::string label; }; // GCC/Clang extension, fine on this Linux-only target

std::vector<IpRangeV4> g_v4_ranges;
std::vector<IpRangeV6> g_v6_ranges;

unsigned __int128 ipv6_to_u128(const unsigned char* b16) {
    unsigned __int128 v = 0;
    for (int i = 0; i < 16; ++i) v = (v << 8) | b16[i];
    return v;
}

// Parses one "addr/prefix" CIDR literal (v4 or v6) and pushes [start,end]
// into the matching table under `label`. Silently skips malformed lines
// (e.g. the stray "network" line in cloudflare_range.txt) instead of
// aborting the whole file load.
void add_cidr_range(const std::string& cidr, const std::string& label) {
    size_t slash = cidr.find('/');
    // Some provider lists (fastly.txt, hetzner.txt, zscaler.txt, googlebot.txt,
    // linode.txt, tor.txt) ship bare addresses with no "/prefix" at all. A
    // trailing "::" on an IPv6 literal (e.g. "2a04:4e40::") is just standard
    // zero-compression, NOT a missing-prefix marker — inet_pton resolves it
    // to a full 128-bit address on its own. Without an explicit prefix we
    // can't know the provider's real block size, so we fall back to a
    // single-host match (/32 or /128) rather than dropping the line.
    std::string addr = (slash == std::string::npos) ? cidr : cidr.substr(0, slash);
    int prefix = (slash == std::string::npos) ? -1 : std::atoi(cidr.c_str() + slash + 1);

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

// mmap's `path` once and calls handle_line(ptr, len) per non-empty line
// (CRLF-safe). Shared by every loader below — one mmap/munmap to get right.
void for_each_line(const std::string& path,
                    const std::function<void(const char*, size_t)>& handle_line) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) { std::cerr << "Warning: Could not open IP range file: " << path << "\n"; return; }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return; }
    size_t file_size = st.st_size;
    char* data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0));
    close(fd);
    if (data == MAP_FAILED) return;

    const char* end = data + file_size;
    const char* p = data;
    while (p < end) {
        const char* line_end = static_cast<const char*>(memchr(p, '\n', end - p));
        if (!line_end) line_end = end;
        size_t len = line_end - p;
        if (len > 0 && p[len - 1] == '\r') --len;   // CRLF files
        if (len > 0) handle_line(p, len);
        p = line_end + 1;
    }
    munmap(data, file_size);
}

void load_plain_range_file(const std::string& path, const std::string& label) {
    for_each_line(path, [&](const char* line, size_t len) {
        add_cidr_range(std::string(line, len), label);
    });
}

// aws.txt is 3 whitespace-delimited columns: SERVICE  REGION  IP_RANGE,
// with a header row and a "====" separator row to skip.
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

} // namespace

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
