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
    ports.reserve(256);

    const char* p   = port_spec.data();
    const char* end = p + port_spec.size();

    while (p < end) {
        // skip leading whitespace
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        if (p >= end) break;

        // find comma boundary for this token
        const char* tok_end = p;
        while (tok_end < end && *tok_end != ',') ++tok_end;

        // trim trailing whitespace
        const char* te = tok_end;
        while (te > p && (*(te-1) == ' ' || *(te-1) == '\t')) --te;

        if (p == te) {
            std::cerr << "Empty port specification ignored\n";
            p = tok_end + 1;
            continue;
        }

        // find '-' after leading digit run to detect range vs single
        const char* dash = p;
        while (dash < te && *dash >= '0' && *dash <= '9') ++dash;
        bool is_range = (dash < te && *dash == '-');

        if (is_range) {
            int s_port = 0, e_port = 0;
            auto [p1, ec1] = std::from_chars(p, te, s_port);
            if (ec1 != std::errc() || p1 >= te || *p1 != '-') {
                std::cerr << "Invalid port range format: "
                          << std::string(p, te) << "\n";
                p = tok_end + 1; continue;
            }
            auto [p2, ec2] = std::from_chars(p1 + 1, te, e_port);
            if (ec2 != std::errc() || p2 != te) {
                std::cerr << "Invalid port range format: "
                          << std::string(p, te) << "\n";
                p = tok_end + 1; continue;
            }
            if (s_port < 1 || s_port > 65535)
                std::cerr << "Start port out of range (1-65535): " << s_port << "\n";
            else if (e_port < 1 || e_port > 65535)
                std::cerr << "End port out of range (1-65535): " << e_port << "\n";
            else if (s_port > e_port)
                std::cerr << "Invalid range (start > end): "
                          << std::string(p, te) << "\n";
            else {
                const size_t range_sz = static_cast<size_t>(e_port - s_port + 1);
                const size_t old_sz   = ports.size();
                ports.resize(old_sz + range_sz);
                // compiler auto-vectorizes this loop
                for (size_t i = 0; i < range_sz; ++i)
                    ports[old_sz + i] = s_port + static_cast<int>(i);
            }
        } else {
            int port = 0;
            auto [ptr, ec] = std::from_chars(p, te, port);
            if (ec != std::errc() || ptr != te)
                std::cerr << "Invalid port number: " << std::string(p, te) << "\n";
            else if (port < 1 || port > 65535)
                std::cerr << "Port out of range (1-65535): " << port << "\n";
            else
                ports.push_back(port);
        }
        p = tok_end + 1;
    }

    if (ports.empty()) {
        std::cerr << "No valid ports parsed from: " << port_spec << "\n";
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
 
    const char* data = static_cast<const char*>(mapped);

    // helper lambda: parse one memory region into a port vector
    auto parse_region = [&filename](const char* rdata, size_t rlen,
                                     std::vector<int>& out) {
        const char* p   = rdata;
        const char* end = rdata + rlen;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\r')) ++p;
            if (p >= end) break;
            if (*p == '#') { while (p < end && *p != '\n') ++p; if (p < end) ++p; continue; }
            if (*p < '0' || *p > '9') { while (p < end && *p != '\n') ++p; if (p < end) ++p; continue; }
            int port = 0;
            auto [ptr, ec] = std::from_chars(p, end, port);
            if (ec == std::errc() && port >= 1 && port <= 65535)
                out.push_back(port);
            else if (ec != std::errc())
                std::cerr << "Port out of range in " << filename << ": " << port << "\n";
            p = ptr;
            while (p < end && *p != '\n') ++p;
            if (p < end) ++p;
        }
    };

    // small file: single-threaded
    if (file_size < 256 * 1024) {
        ports.reserve((file_size / 5) + 64);
        parse_region(data, file_size, ports);
    }
    // large file: split on newline boundaries, parse in parallel
    else {
        const size_t n_threads = std::min<size_t>(
            4u, std::max<size_t>(2u, (size_t)std::thread::hardware_concurrency()));

        std::vector<std::pair<const char*, size_t>> regions;
        const char* seg = data;
        for (size_t t = 0; t < n_threads; ++t) {
            if (seg >= data + file_size) break;
            const char* nom = (t == n_threads - 1)
                ? data + file_size
                : data + (t + 1) * (file_size / n_threads);
            while (nom < data + file_size && *nom != '\n') ++nom;
            if (nom < data + file_size) ++nom;
            regions.emplace_back(seg, static_cast<size_t>(nom - seg));
            seg = nom;
        }

        std::vector<std::vector<int>> chunks(regions.size());
        std::vector<std::future<void>> futures;
        futures.reserve(regions.size());
        for (size_t t = 0; t < regions.size(); ++t) {
            auto [rd, rl] = regions[t];
            futures.push_back(std::async(std::launch::async,
                [rd, rl, &chunks, t, &parse_region, &filename]() {
                    chunks[t].reserve(rl / 5 + 16);
                    parse_region(rd, rl, chunks[t]);
                }));
        }
        size_t total = 0;
        for (size_t t = 0; t < regions.size(); ++t) { futures[t].get(); total += chunks[t].size(); }
        ports.reserve(total);
        for (auto& c : chunks)
            ports.insert(ports.end(), std::make_move_iterator(c.begin()),
                                      std::make_move_iterator(c.end()));
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
    return 0;
}

std::string autodetect_interface(uint32_t local_ip) {
    static std::unordered_map<uint32_t, std::string> iface_cache;
    static std::mutex cache_mutex;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = iface_cache.find(local_ip);
        if (it != iface_cache.end()) return it->second;
    }

    struct ifaddrs *ifaddr;
    std::string interface;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "getifaddrs failed: " << strerror(errno) << std::endl;
        return "eth0";
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (sin->sin_addr.s_addr == local_ip) {
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
    iface_cache[local_ip] = interface;
    return interface;
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
        service_map.reserve(24000);
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
             int tmp_port = 0;
            auto [p_end, ec] = std::from_chars(ptr, line_end, tmp_port);
            if (ec != std::errc() || tmp_port <= 0 || tmp_port > 65535) {
                line_start = line_end + 1;
                continue;
            }
            uint16_t port = static_cast<uint16_t>(tmp_port);
            ptr = p_end;
            bool is_tcp = false;
            if (ptr + 4 <= line_end && ptr[0] == '/') {
                // compare 3 bytes as one uint32 — single branch
                uint32_t proto32 = 0;
                memcpy(&proto32, ptr + 1, 3);
                constexpr uint32_t TCP32 =
                    uint32_t('t') | (uint32_t('c') << 8) | (uint32_t('p') << 16);
                is_tcp = ((proto32 & 0x00FFFFFFu) == TCP32);
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

std::string reverse_dns_lookup(const std::string& ip_address) {
    static std::unordered_map<std::string, std::string> dns_cache;
    static std::mutex dns_mutex;

    {
        std::lock_guard<std::mutex> lock(dns_mutex);
        auto it = dns_cache.find(ip_address);
        if (it != dns_cache.end()) return it->second;
    }

    struct sockaddr_in sa{};
    if (inet_pton(AF_INET, ip_address.c_str(), &sa.sin_addr) != 1) {
        std::lock_guard<std::mutex> lock(dns_mutex);
        dns_cache[ip_address] = "";
        return "";
    }
    sa.sin_family = AF_INET;
    sa.sin_port   = 0;
    struct sockaddr_in sa_copy = sa;
    auto task = std::async(std::launch::async, [sa_copy]() -> std::string {
        char hostname[NI_MAXHOST];
        int rc = getnameinfo(
            reinterpret_cast<const struct sockaddr*>(&sa_copy), sizeof(sa_copy),
            hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        return (rc == 0) ? std::string(hostname) : std::string{};
    });

    std::string ret;
    if (task.wait_for(std::chrono::milliseconds(1500)) == std::future_status::ready)
        ret = task.get();

    {
        std::lock_guard<std::mutex> lock(dns_mutex);
        dns_cache[ip_address] = ret;
    }
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

