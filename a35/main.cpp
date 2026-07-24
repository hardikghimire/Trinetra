#include "utils.hpp"
#include "public_db.hpp"
#include <fstream>
#include <shared_mutex>
#include "scan.hpp"
#include "icmp_ping.hpp"
#include <stdexcept>
#include <future>
#include <ctime>
#include <map>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sstream>
#include <set>
#include <iomanip>
#include <cstdio>
#include <queue>
#include <unordered_set>
#include <csignal>
#include <charconv>
#include <immintrin.h>   // __m256i, _mm256_* AVX2 intrinsics
#include <emmintrin.h>   // __m128i, _mm_*  SSE2 intrinsics

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
constexpr size_t MAX_EXPANDED_IPS_PER_CIDR = 100000000000000000ULL; // safety cap per CIDR
constexpr size_t MAX_TOTAL_IPS             = 100000000000000000ULL; // global safety cap
constexpr size_t MAX_INPUT_TOKEN_LEN       = 2048;


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

inline bool normalize_ipv4_string(const std::string& in, std::string& out) {
    in_addr a{};
    if (inet_pton(AF_INET, in.c_str(), &a) != 1) return false;
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return false;
    out.assign(buf);
    return true;
}

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
bool resolve_domain_to_ipv4(const std::string& domain, std::string& resolved_ip);

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
                long v = std::stol(token);
                if (v >= 1 && v <= 65535) {
                    std::cerr << "Error: '" << token << "' looks like a port number, not an IP address.\n"
                              << "  Did you forget -p? Use: -p " << token << "\n";
                } else {
                    std::cerr << "Error: '" << token << "' is not a valid IP address or hostname.\n";
                }
                return false;
            }

            // Check if it's a valid IPv4 address
            if (!normalize_ipv4_string(token, out_ip)) {
                // Not an IP, try DNS resolution
                auto it = dns_cache.find(token);
                if (it != dns_cache.end()) {
                    out_ip = it->second;
                } else {
                    if (!resolve_domain_to_ipv4(token, out_ip)) {
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

void load_mac_vendors(const std::string& filename) {
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Warning: Could not open MAC vendor file: " << filename << "\n";
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return; }
    const size_t file_size = static_cast<size_t>(st.st_size);

    char* data = static_cast<char*>(
        mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0));
    // Security fix: close fd immediately — mapping is independent of the descriptor
    close(fd);
    if (data == MAP_FAILED) return;

    // Security fix: RAII munmap — fires after merge regardless of early returns
    struct MmapGuard {
        char* ptr; size_t sz;
        ~MmapGuard() { if (ptr != MAP_FAILED) munmap(ptr, sz); }
    } guard{ data, file_size };

    mac_vendor_map.reserve(35000);

    // Parse lambda — identical logic to the original while-loop, extracted
    // so it can run per-region in async tasks without any shared state.
    auto parse_region = [](const char* rdata, size_t rlen,
                            std::unordered_map<std::string, std::string>& out)
    {
        const char* p   = rdata;
        const char* end = rdata + rlen;
        while (p < end) {
            const char* line_end =
                static_cast<const char*>(memchr(p, '\n', static_cast<size_t>(end - p)));
            if (!line_end) line_end = end;

            if (p == line_end || *p == '#') { p = line_end + 1; continue; }

            const char* delim = p;
            while (delim < line_end && *delim != ' ' && *delim != '\t') ++delim;
            if (delim == line_end) { p = line_end + 1; continue; }

            char key[7]; int k = 0;
            for (const char* c = p; c < delim && k < 6; ++c)
                if (*c != ':') key[k++] = static_cast<char>(toupper(static_cast<unsigned char>(*c)));
            if (k != 6) { p = line_end + 1; continue; }

            const char* v = delim;
            while (v < line_end && (*v == ' ' || *v == '\t')) ++v;

            out.emplace(std::string(key, 6), std::string(v, static_cast<size_t>(line_end - v)));
            p = line_end + 1;
        }
    };

    // Small files: single-threaded
    constexpr size_t PARALLEL_THRESHOLD = 256 * 1024;
    if (file_size < PARALLEL_THRESHOLD) {
        parse_region(data, file_size, mac_vendor_map);
        return; // MmapGuard fires here
    }

    // Large files: split on newline boundaries, parse in parallel
    const size_t n_threads = std::min<size_t>(
        4u, std::max<size_t>(2u, static_cast<size_t>(std::thread::hardware_concurrency())));

    std::vector<std::pair<const char*, size_t>> regions;
    regions.reserve(n_threads);
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

    const size_t nreg = regions.size();
    std::vector<std::unordered_map<std::string, std::string>> shards(nreg);
    for (auto& shard : shards) shard.reserve(35000 / nreg + 64);

    std::vector<std::future<void>> futures;
    futures.reserve(nreg);
    for (size_t t = 0; t < nreg; ++t) {
        auto [rd, rl] = regions[t];
        futures.push_back(std::async(std::launch::async,
            [rd, rl, &shards, t, &parse_region]() {
                parse_region(rd, rl, shards[t]);
            }));
    }

    for (size_t t = 0; t < nreg; ++t) {
        futures[t].get();
        for (auto& [k, v] : shards[t])
            mac_vendor_map.emplace(std::move(k), std::move(v));
    }
    // MmapGuard fires here
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
    return (it != mac_vendor_map.end()) ? it->second : "unknown";
}

namespace {
inline char* u32_to_dotted(uint32_t ip, char* dst) {
    auto write_octet = [](char* p, uint32_t v) -> char* {
        if      (v >= 100) { *p++ = '0' + v/100; v%=100; *p++ = '0' + v/10; v%=10; }
        else if (v >= 10)  { *p++ = '0' + v/10;  v%=10; }
        *p++ = '0' + v;
        return p;
    };
    dst = write_octet(dst, (ip >> 24) & 0xFF); *dst++ = '.';
    dst = write_octet(dst, (ip >> 16) & 0xFF); *dst++ = '.';
    dst = write_octet(dst, (ip >>  8) & 0xFF); *dst++ = '.';
    dst = write_octet(dst,  ip        & 0xFF);
    *dst = '\0';
    return dst;
}

// fills [start, end] inclusive (host-byte-order) into out
inline void fill_ip_range(uint32_t start, uint32_t end,
                           std::vector<std::string>& out) {
    out.reserve(out.size() + (static_cast<size_t>(end - start) + 1));
    char buf[16];
    for (uint32_t cur = start; ; ++cur) {
        u32_to_dotted(cur, buf);
        out.emplace_back(buf);
        if (cur == end) break;
    }
}

inline void fill_ip_range_reverse(uint32_t start, uint32_t end,
                                   std::vector<std::string>& out) {
    if (start > end) return;                          
    out.reserve(out.size() + (static_cast<size_t>(end - start) + 1));
    char buf[16];
    for (uint32_t cur = end; ; --cur) {
        u32_to_dotted(cur, buf);
        out.emplace_back(buf);
        if (cur == start) break;                       
    }
}

constexpr size_t CIDR_PARALLEL_THRESHOLD = 4096;
constexpr size_t CIDR_MAX_THREADS        = 8;
constexpr size_t MAX_DNS_CONCURRENCY     = 32;
} 

static std::vector<std::string>
batch_resolve_domains(const std::vector<std::string>& domains) {
    const size_t n = domains.size();
    std::vector<std::string> results(n);
    if (n == 0) return results;
    if (n == 1) { resolve_domain_to_ipv4(domains[0], results[0]); return results; }

    std::counting_semaphore<MAX_DNS_CONCURRENCY> sem(MAX_DNS_CONCURRENCY);
    std::vector<std::future<std::string>> futures;
    futures.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        sem.acquire();
        futures.push_back(std::async(std::launch::async,
            [&domains, i, &sem]() -> std::string {
                std::string ip;
                resolve_domain_to_ipv4(domains[i], ip);
                sem.release();
                return ip;
            }));
    }
    for (size_t i = 0; i < n; ++i)
        results[i] = futures[i].get();
    return results;
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
        if (normalize_ipv4_string(input, norm)) {
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

    // small range: sequential, no threading overhead
    if (count < CIDR_PARALLEL_THRESHOLD) {
        fill_ip_range_reverse(start, end, ips);
        return;
    }

    // large range: parallel chunk fill — each task owns its vector, no sharing
    const size_t n_threads = std::min<size_t>(
        CIDR_MAX_THREADS,
        std::max<size_t>(2, std::thread::hardware_concurrency()));
    const size_t chunk = static_cast<size_t>(count) / n_threads;

    std::vector<std::vector<std::string>> chunks(n_threads);
    for (auto& c : chunks) c.reserve(chunk + 1);

    std::vector<std::future<void>> futures;
    futures.reserve(n_threads);

    for (size_t t = 0; t < n_threads; ++t) {
        uint32_t cs = start + static_cast<uint32_t>(t * chunk);
        uint32_t ce = (t == n_threads - 1)
                    ? end
                    : (cs + static_cast<uint32_t>(chunk) - 1u);
        futures.push_back(std::async(std::launch::async,
            // Each chunk itself is filled in reverse (high→low within the chunk)
            [cs, ce, &chunks, t]() { fill_ip_range_reverse(cs, ce, chunks[t]); }));
    }

    ips.reserve(ips.size() + static_cast<size_t>(count));
    // Merge chunks in REVERSE thread order so overall order is end→start
    for (size_t t = n_threads; t-- > 0; ) {
        futures[t].get();
        ips.insert(ips.end(),
                   std::make_move_iterator(chunks[t].begin()),
                   std::make_move_iterator(chunks[t].end()));
    }
}

bool resolve_domain_to_ipv4(const std::string& domain, std::string& resolved_ip) {
    resolved_ip.clear();
    if (domain.empty() || domain.size() > 253) return false;

    std::string host = domain;
    trim_in_place(host);
    if (host.empty() || has_bad_control_char(host)) return false;
    if (normalize_ipv4_string(host, resolved_ip)) return true;
    // thread-safe DNS cache — shared_lock allows concurrent reads, no serialization
    static std::unordered_map<std::string, std::string> dns_cache;
    static std::shared_mutex cache_rw;
    {
        std::shared_lock<std::shared_mutex> rl(cache_rw);
        auto it = dns_cache.find(host);
        if (it != dns_cache.end()) {
            resolved_ip = it->second;
            return !resolved_ip.empty();
        }
    }
    auto task = std::async(std::launch::async, [host_copy = host]() -> std::string {
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags    = AI_ADDRCONFIG;

        addrinfo* result = nullptr;
        int rc = getaddrinfo(host_copy.c_str(), nullptr, &hints, &result);
        if (rc != 0 || !result) return {};

        struct Guard { addrinfo* p; ~Guard(){ if(p) freeaddrinfo(p); } } g{result};

        for (addrinfo* rp = result; rp; rp = rp->ai_next) {
            if (rp->ai_family != AF_INET || !rp->ai_addr) continue;
            if (rp->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) continue;
            const auto* sa = reinterpret_cast<const sockaddr_in*>(rp->ai_addr);
            char buf[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) continue;
            return std::string(buf);
        }
        return {};
    });
    if (task.wait_for(std::chrono::milliseconds(2000)) != std::future_status::ready)
        return false;

    resolved_ip = task.get();
    {
        std::unique_lock<std::shared_mutex> wl(cache_rw);
        dns_cache.emplace(host, resolved_ip);
    }
    return !resolved_ip.empty();
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

std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);

    const char* p  = s.data();
    const size_t n = s.size();
    size_t i       = 0;

#ifdef __SSE2__
    const __m128i v_dquote = _mm_set1_epi8('"');
    const __m128i v_bslash = _mm_set1_epi8('\\');
    const __m128i v_nl     = _mm_set1_epi8('\n');
    const __m128i v_cr     = _mm_set1_epi8('\r');
    const __m128i v_tab    = _mm_set1_epi8('\t');
    const __m128i v_bias   = _mm_set1_epi8('\x80');
    const __m128i v_sp_b   = _mm_set1_epi8('\x80' ^ 0x20); // 0xA0

    for (; i + 16 <= n; i += 16) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));

        __m128i ctrl  = _mm_cmplt_epi8(                   // bytes < 0x20
            _mm_xor_si128(chunk, v_bias), v_sp_b);

        __m128i special = _mm_or_si128(
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_dquote),
                         _mm_cmpeq_epi8(chunk, v_bslash)),
            _mm_or_si128(
                _mm_or_si128(_mm_cmpeq_epi8(chunk, v_nl),
                             _mm_cmpeq_epi8(chunk, v_cr)),
                _mm_or_si128(_mm_cmpeq_epi8(chunk, v_tab), ctrl)));

        int mask = _mm_movemask_epi8(special);
        if (mask == 0) {
            out.append(p + i, 16);
        } else {
            int first = __builtin_ctz(static_cast<unsigned>(mask));
            if (first > 0) out.append(p + i, static_cast<size_t>(first));
            // Handle the chunk byte-by-byte from `first` onward
            for (int k = first; k < 16; ++k) {
                unsigned char c = static_cast<unsigned char>(p[i + k]);
                switch (c) {
                    case '"':  out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\n': out += "\\n";  break;
                    case '\r': out += "\\r";  break;
                    case '\t': out += "\\t";  break;
                    case '\b': out += "\\b";  break;
                    case '\f': out += "\\f";  break;
                    default:
                        if (c < 0x20) {
                            char esc[7];
                            snprintf(esc, sizeof(esc), "\\u%04x",
                                     static_cast<unsigned>(c));
                            out += esc;
                        } else {
                            out += static_cast<char>(c);
                        }
                        break;
                }
            }
        }
    }
#endif

    // Scalar tail — handles remaining bytes (< 16) or full string without SSE2
    for (; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(p[i]);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char esc[7];
                    snprintf(esc, sizeof(esc), "\\u%04x",
                             static_cast<unsigned>(c));
                    out += esc;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

std::string escape_xml(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);

    const char* p  = s.data();
    const size_t n = s.size();
    size_t i       = 0;

#ifdef __SSE2__
    const __m128i v_amp    = _mm_set1_epi8('&');
    const __m128i v_lt     = _mm_set1_epi8('<');
    const __m128i v_gt     = _mm_set1_epi8('>');
    const __m128i v_dquote = _mm_set1_epi8('"');
    const __m128i v_squote = _mm_set1_epi8('\'');

    for (; i + 16 <= n; i += 16) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));
        __m128i special = _mm_or_si128(
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_amp),
                         _mm_cmpeq_epi8(chunk, v_lt)),
            _mm_or_si128(
                _mm_or_si128(_mm_cmpeq_epi8(chunk, v_gt),
                             _mm_cmpeq_epi8(chunk, v_dquote)),
                _mm_cmpeq_epi8(chunk, v_squote)));

        int mask = _mm_movemask_epi8(special);
        if (mask == 0) {
            out.append(p + i, 16);
        } else {
            int first = __builtin_ctz(static_cast<unsigned>(mask));
            if (first > 0) out.append(p + i, static_cast<size_t>(first));
            for (int k = first; k < 16; ++k) {
                switch (p[i + k]) {
                    case '&':  out += "&amp;";  break;
                    case '<':  out += "&lt;";   break;
                    case '>':  out += "&gt;";   break;
                    case '"':  out += "&quot;"; break;
                    case '\'': out += "&apos;"; break;
                    default:   out += p[i + k]; break;
                }
            }
        }
    }
#endif

    for (; i < n; ++i) {
        switch (p[i]) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += p[i];    break;
        }
    }
    return out;
}

void save_scan_results(const std::vector<RecPross>& results, const std::string& output_file) {
    if (output_file.empty()) {
        return;
    }

    size_t dot_pos = output_file.find_last_of('.');
    if (dot_pos == std::string::npos) {
        std::cerr << "Output file must have an extension (.txt, .xml, .json, .csv)\n";
        return;
    }

    std::string extension = output_file.substr(dot_pos);
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

    auto csv_escape = [](const std::string& s) -> std::string {
        bool needs_quotes = false;
        for (char c : s) {
            if (c == '"' || c == ',' || c == '\n' || c == '\r') {
                needs_quotes = true;
                break;
            }
        }

        if (!needs_quotes) {
            return s;
        }

        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        for (char c : s) {
            if (c == '"') {
                out += "\"\"";
            } else {
                out.push_back(c);
            }
        }
        out.push_back('"');
        return out;
    };

    if (extension == ".txt") {
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
    else if (extension == ".xml") {
        out_file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out_file << "<shiv_scan>\n";

        if (!safe_mac.empty()) {
            out_file << "  <mac_address>" << escape_xml(safe_mac) << "</mac_address>\n";
            out_file << "  <mac_vendor>" << escape_xml(safe_vendor) << "</mac_vendor>\n";
        }

        out_file << "  <open_ports>\n";
        for (uint16_t port : combined_result.open_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << "    <port number=\"" << port
                     << "\" protocol=\"tcp\" service=\"" << escape_xml(service) << "\"/>\n";
        }
        out_file << "  </open_ports>\n";

        out_file << "  <filtered_ports>\n";
        for (uint16_t port : combined_result.filtered_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << "    <port number=\"" << port
                     << "\" protocol=\"tcp\" service=\"" << escape_xml(service) << "\"/>\n";
        }
        out_file << "  </filtered_ports>\n";

        out_file << "  <closed_ports count=\"" << combined_result.closed_ports << "\"/>\n";
        out_file << "</shiv_scan>\n";
    }
    else if (extension == ".json") {
        out_file << "{\n";
        out_file << "  \"shiv_scan\": {\n";

        if (!safe_mac.empty()) {
            out_file << "    \"mac_address\": \"" << escape_json(safe_mac) << "\",\n";
            out_file << "    \"mac_vendor\": \"" << escape_json(safe_vendor) << "\",\n";
        }

        out_file << "    \"open_ports\": [\n";
        for (size_t i = 0; i < combined_result.open_ports.size(); ++i) {
            uint16_t port = combined_result.open_ports[i];
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";

            out_file << "      {\"port\": " << port
                     << ", \"protocol\": \"tcp\", \"service\": \"" << escape_json(service) << "\"}";
            if (i + 1 < combined_result.open_ports.size()) {
                out_file << ",";
            }
            out_file << "\n";
        }
        out_file << "    ],\n";

        out_file << "    \"filtered_ports\": [\n";
        for (size_t i = 0; i < combined_result.filtered_ports.size(); ++i) {
            uint16_t port = combined_result.filtered_ports[i];
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";

            out_file << "      {\"port\": " << port
                     << ", \"protocol\": \"tcp\", \"service\": \"" << escape_json(service) << "\"}";
            if (i + 1 < combined_result.filtered_ports.size()) {
                out_file << ",";
            }
            out_file << "\n";
        }
        out_file << "    ],\n";

        out_file << "    \"closed_ports\": " << combined_result.closed_ports << "\n";
        out_file << "  }\n";
        out_file << "}\n";
    }
    else if (extension == ".csv") {
        out_file << "Port,Protocol,Service,Status\n";

        for (uint16_t port : combined_result.open_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << port << ",tcp," << csv_escape(service) << ",open\n";
        }

        for (uint16_t port : combined_result.filtered_ports) {
            std::string service = service_map.count(port) ? service_map.at(port) : "unknown";
            out_file << port << ",tcp," << csv_escape(service) << ",filtered\n";
        }

        out_file << ",,," << csv_escape("closed (count: " + std::to_string(combined_result.closed_ports) + ")") << "\n";
    }
    else {
        std::cerr << "Unsupported output format: " << extension << "\n";
        return;
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
    for (std::thread* t : threads_to_join) {
        if (!t) continue;
        try {
            if (t->joinable()) {
                std::cerr << "Joining worker thread (timeout: 2s)...\n";
                auto deadline = std::chrono::steady_clock::now()
                                + std::chrono::seconds(2);
                bool joined = false;
 
                while (std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    if (!t->joinable()) {
                        joined = true;   
                        break;
                    }
                }
 
                if (t->joinable()) {
                    if (joined) {
                        t->join();
                        std::cerr << "Worker thread joined successfully\n";
                    } else {
                        std::cerr << "Thread did not finish within 2s — detaching\n";
                        t->detach();
                    }
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
                   int timeout_ms, PacketBufferPool& pool, int send_sock, std::vector<RecPross>& results, size_t main_batch_size, 
                   uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered, 
                   bool print_filtered_if_few, bool fast_scan, std::atomic<int>& down_hosts_count, ScanType scan_type, 
                   uint8_t custom_ttl,uint8_t custom_dscp, uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id, 
                   bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum, uint8_t window_scale, uint16_t mss_value, 
                   uint32_t timestamp_val, uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted, 
                   const std::string& custom_data, uint16_t data_length, bool use_custom_data, bool generate_random_data, 
                   int user_rcvbuf_size, const std::string& source_ip, size_t send_uring_depth, size_t rcv_uring_depth,
                   bool use_badsum, uint16_t custom_badsum_value, bool use_partial_badsum, const std::string& partial_badsum_type,
                   bool use_tfo_cookie, bool tfo_cookie_as_hex, bool tfo_cookie_random, const std::string& tfo_cookie_str, 
                   uint64_t tfo_cookie_num, size_t tfo_cookie_length, uint16_t base_source_port, bool debug_packet, bool debug_rtt,bool debug_wsn,bool debug_ttl,bool use_fragmentation, uint16_t frag_size, uint16_t mtu_size,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,uint16_t sport_range_min, uint16_t sport_range_max,int initial_rtt_ms,int port_timeout_min_ms, int port_timeout_max_ms,RateConfig rate_config,JitterConfig jitter_config,BatchDelayConfig batch_delay_config,
                   bool use_ip_tos, uint8_t custom_ip_tos_byte,PacketLengthConfig packet_length_config, bool is_threaded) {
                   
    
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint16_t> port_dist(1, 65535); 
    struct io_uring send_ring; 
    size_t actual_send_depth;
    if (send_uring_depth > 0) {
        actual_send_depth = send_uring_depth;
    } else {
        actual_send_depth = std::min<size_t>(256, std::max<size_t>(64, ports.size() / 2));
    }
    
    if (io_uring_queue_init(actual_send_depth, &send_ring, IORING_SETUP_COOP_TASKRUN) < 0) {
        std::cerr << "Failed to initialize send ring: " << strerror(errno) << std::endl;
        return;
    }
    std::string interface;
    uint8_t src_ip_bytes[4] = {0}, netmask[4] = {0};
    bool arp_initialized = false;
    uint32_t src_ip_int = 0, netmask_int = 0;
    
    if (!thread_ips.empty()) {
        int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (temp_sock >= 0) {
            uint32_t local_ip = get_local_ip(thread_ips[0].c_str());
            if (local_ip != 0) {
                interface = autodetect_interface(local_ip);
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
    
    std::unordered_map<uint32_t, std::string> thread_arp_cache;
    bool multi_ip = (thread_ips.size() > 1);
    std::unordered_set<uint32_t> counted_down_ips;
    std::vector<uint8_t*> same_subnet_target_ips;
    std::vector<uint32_t> same_subnet_ip_ints;
    std::vector<size_t>   same_subnet_indices;

    // Step A: convert all IP strings to uint32_t once, validate with inet_pton
    const size_t n_ips = thread_ips.size();
    std::vector<uint32_t> ip_ints(n_ips, 0);
    std::vector<bool>     ip_valid(n_ips, false);

    for (size_t i = 0; i < n_ips; ++i) {
        uint8_t tmp[4] = {0};
        if (inet_pton(AF_INET, thread_ips[i].c_str(), tmp) > 0) {
            memcpy(&ip_ints[i], tmp, 4);
            ip_valid[i] = true;
        }
    }

    // Step B: SIMD subnet test — (ip & netmask) == (src_ip & netmask)
    if (arp_initialized && n_ips > 0) {
        const uint32_t network_masked = src_ip_int & netmask_int;
        size_t i = 0;

#ifdef __AVX2__
        const __m256i vmask    = _mm256_set1_epi32(static_cast<int>(netmask_int));
        const __m256i vnetwork = _mm256_set1_epi32(static_cast<int>(network_masked));
        for (; i + 8 <= n_ips; i += 8) {
            __m256i vips   = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(ip_ints.data() + i));
            __m256i masked = _mm256_and_si256(vips, vmask);
            __m256i cmp    = _mm256_cmpeq_epi32(masked, vnetwork);
            int bitmask    = _mm256_movemask_epi8(cmp);
            if (bitmask == 0) continue; // fast path: none of 8 IPs match
            for (int k = 0; k < 8; ++k) {
                if (!ip_valid[i + k]) continue;
                if (((bitmask >> (k * 4)) & 0xF) != 0xF) continue;
                uint32_t ip_int = ip_ints[i + k];
                same_subnet_target_ips.push_back(new uint8_t[4]);
                memcpy(same_subnet_target_ips.back(), &ip_int, 4);
                same_subnet_ip_ints.push_back(ip_int);
                same_subnet_indices.push_back(i + k);
            }
        }
#endif

#if defined(__SSE2__) && !defined(__AVX2__)
        const __m128i vmask128    = _mm_set1_epi32(static_cast<int>(netmask_int));
        const __m128i vnetwork128 = _mm_set1_epi32(static_cast<int>(network_masked));
        for (; i + 4 <= n_ips; i += 4) {
            __m128i vips   = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ip_ints.data() + i));
            __m128i masked = _mm_and_si128(vips, vmask128);
            __m128i cmp    = _mm_cmpeq_epi32(masked, vnetwork128);
            int bitmask    = _mm_movemask_epi8(cmp);
            if (bitmask == 0) continue;
            for (int k = 0; k < 4; ++k) {
                if (!ip_valid[i + k]) continue;
                if (((bitmask >> (k * 4)) & 0xF) != 0xF) continue;
                uint32_t ip_int = ip_ints[i + k];
                same_subnet_target_ips.push_back(new uint8_t[4]);
                memcpy(same_subnet_target_ips.back(), &ip_int, 4);
                same_subnet_ip_ints.push_back(ip_int);
                same_subnet_indices.push_back(i + k);
            }
        }
#endif

        // Scalar tail — handles remainder and is the full path without SIMD
        for (; i < n_ips; ++i) {
            if (!ip_valid[i]) continue;
            if ((ip_ints[i] & netmask_int) != network_masked) continue;
            uint32_t ip_int = ip_ints[i];
            same_subnet_target_ips.push_back(new uint8_t[4]);
            memcpy(same_subnet_target_ips.back(), &ip_int, 4);
            same_subnet_ip_ints.push_back(ip_int);
            same_subnet_indices.push_back(i);
        }
    }
    
    if (!same_subnet_target_ips.empty()) {
    	int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    	if (arp_sock >= 0) {
        	struct io_uring arp_ring;
        	if (io_uring_queue_init(512, &arp_ring, IORING_SETUP_COOP_TASKRUN) == 0) {
            	uint8_t src_mac[6] = {0};
            	if (get_interface_mac(arp_sock, interface.c_str(), src_mac)) {
                	// Prepare MAC buffers
                	std::vector<uint8_t*> mac_buffers(same_subnet_target_ips.size());
                	for (size_t j = 0; j < mac_buffers.size(); ++j) {
                    	mac_buffers[j] = new uint8_t[6];
                    	memset(mac_buffers[j], 0, 6);
                	}
                
                	// Check for localhost before sending ARP
                	bool has_localhost = false;
                	for (size_t j = 0; j < same_subnet_target_ips.size(); ++j) {
                    	uint32_t ip_val;
                    	memcpy(&ip_val, same_subnet_target_ips[j], 4);
                    	if (ip_val == htonl(0x7F000001)) { // 127.0.0.1 in network byte order
                        	has_localhost = true;
                        	break;
                    	}
                	}
                
                	if (send_arp_request(arp_sock, &arp_ring, interface.c_str(), src_mac, 
                                    	src_ip_bytes, same_subnet_target_ips)) {
                    
                    	// ONLY wait for replies if there are non-localhost targets
                    	if (!has_localhost) {
                        	receive_arp_reply(arp_sock, &arp_ring, same_subnet_target_ips, 
                                         	mac_buffers, 1500);
                    	} else {
                        	// For localhost, immediately mark as resolved with fake MAC
                        	for (size_t j = 0; j < same_subnet_target_ips.size(); ++j) {
                            	uint32_t ip_val;
                            	memcpy(&ip_val, same_subnet_target_ips[j], 4);
                            	if (ip_val == htonl(0x7F000001)) {
                                	// Set fake MAC for localhost
                                	uint8_t fake_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
                                	memcpy(mac_buffers[j], fake_mac, 6);
                            	}
                        	}
                        	// Small delay to let ARP requests be sent
                        	std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    	}
                    
                    	{
                        const size_t n_arp = same_subnet_target_ips.size();
                        // SWAR zero-check: load 6 MAC bytes into a uint64_t in one instruction.
                        auto mac_is_resolved = [](const uint8_t* buf) -> bool {
                            uint64_t word = 0;
                            memcpy(&word, buf, 6);
                            return word != 0;
                        };
                        constexpr size_t FORMAT_MAC_ASYNC_THRESHOLD = 64;
                        if (n_arp <= FORMAT_MAC_ASYNC_THRESHOLD) {
                            // Serial path — small subnets
                            for (size_t j = 0; j < n_arp; ++j) {
                                const uint32_t ip_int  = same_subnet_ip_ints[j];
                                const size_t   orig    = same_subnet_indices[j];
                                if (mac_is_resolved(mac_buffers[j])) {
                                    std::string mac = format_mac(mac_buffers[j]);
                                    thread_arp_cache[ip_int]    = mac;
                                    results[orig].mac_address   = mac;
                                } else {
                                    counted_down_ips.insert(ip_int);
                                    down_hosts_count++;
                                }
                            }
                        } else {
                            constexpr size_t MAX_FMT_THREADS = 4;
                            const size_t n_tasks = std::min(MAX_FMT_THREADS, n_arp);
                            const size_t chunk   = n_arp / n_tasks;
                            struct TaskResult {
                                std::vector<uint32_t> down_ips;
                                int                   down_count = 0;
                            };
                            std::vector<TaskResult> task_results(n_tasks);
                            std::vector<std::future<void>> fmt_futures;
                            fmt_futures.reserve(n_tasks);
                            for (size_t t = 0; t < n_tasks; ++t) {
                                const size_t jstart = t * chunk;
                                const size_t jend   = (t == n_tasks - 1) ? n_arp : jstart + chunk;
                                fmt_futures.push_back(std::async(std::launch::async,
                                    [&, t, jstart, jend]() {
                                        TaskResult& tr = task_results[t];
                                        for (size_t j = jstart; j < jend; ++j) {
                                            const uint32_t ip_int = same_subnet_ip_ints[j];
                                            const size_t   orig   = same_subnet_indices[j];
                                            if (mac_is_resolved(mac_buffers[j])) {
                                                std::string mac = format_mac(mac_buffers[j]);
                                                thread_arp_cache[ip_int]  = mac;
                                                results[orig].mac_address = mac;
                                            } else {
                                                tr.down_ips.push_back(ip_int);
                                                ++tr.down_count;
                                            }
                                        }
                                    }));
                            }
                            int total_new_down = 0;
                            for (size_t t = 0; t < n_tasks; ++t) {
                                fmt_futures[t].get();
                                for (uint32_t ip : task_results[t].down_ips)
                                    counted_down_ips.insert(ip);
                                total_new_down += task_results[t].down_count;
                            }
                            if (total_new_down > 0)
                                down_hosts_count.fetch_add(total_new_down, std::memory_order_relaxed);
                        }
                    }
                }

                for (auto mac_buf : mac_buffers) {
                    delete[] mac_buf;
                }
            }
            io_uring_queue_exit(&arp_ring);
        }
        close(arp_sock);
    }
    for (auto ip_buf : same_subnet_target_ips) {
        delete[] ip_buf;
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
        //if (is_threaded) std::cout << "\n";
       
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
    
    // ── Parallel path: when -I mode is active, scan all IPs concurrently ───────
    if (is_threaded && thread_ips.size() > 1) {
        std::vector<std::future<void>> ip_futures;
        ip_futures.reserve(thread_ips.size());

        for (size_t i = 0; i < thread_ips.size() && !terminate_flag; ++i) {
            const auto& ip_str = thread_ips[i];

            uint16_t source_port = (base_source_port > 0) ? base_source_port : 0;

            int ip_version = get_ip_version(ip_str.c_str());
            if (ip_version != 4) {
                std::cerr << "Only IPv4 addresses are supported. Invalid IP: " << ip_str << std::endl;
                continue;
            }
            uint32_t local_ip = get_local_ip(ip_str.c_str());
            if (local_ip == 0) {
                std::cerr << "Failed to determine local IP address for " << ip_str << ".\n";
                continue;
            }

            uint8_t target_ip_bytes[4] = {0};
            if (inet_pton(AF_INET, ip_str.c_str(), target_ip_bytes) <= 0) {
                std::cerr << "Invalid target IP address: " << ip_str << std::endl;
                continue;
            }
            uint32_t target_ip_int;
            memcpy(&target_ip_int, target_ip_bytes, 4);
            if (counted_down_ips.find(target_ip_int) != counted_down_ips.end())
                continue;

            bool is_same_subnet_ip = arp_initialized && is_same_subnet(target_ip_int, src_ip_int, netmask_int);
            if (is_same_subnet_ip) {
                auto it = std::find(same_subnet_ip_ints.begin(), same_subnet_ip_ints.end(), target_ip_int);
                if (it != same_subnet_ip_ints.end()) {
                    size_t arp_index = std::distance(same_subnet_ip_ints.begin(), it);
                    size_t original_index = same_subnet_indices[arp_index];
                    if (results[original_index].mac_address.empty())
                        continue;
                }
            }

            // Capture everything by value that worker_thread needs; results[i] by ref via index
            ip_futures.push_back(std::async(std::launch::async,
                [&, i, ip_str, local_ip, source_port]() {
                    worker_thread(
                        ip_str.c_str(), local_ip, source_ip.c_str(), timeout_ms, ports, rng, pool,
                        send_sock, results[i], main_batch_size, seq_num, win_size, 4,
                        print_individual_closed_filtered, print_filtered_if_few,
                        &send_ring, fast_scan, scan_type,
                        custom_ttl, custom_dscp, custom_ip_flags, ip_id_mode, fixed_ip_id,
                        use_manual_tcp_checksum, manual_tcp_checksum,
                        window_scale, mss_value, timestamp_val, timestamp_ecr_custom,
                        nops_count, sack_permitted, custom_data, data_length,
                        use_custom_data, generate_random_data, user_rcvbuf_size,
                        send_uring_depth, rcv_uring_depth,
                        use_badsum, custom_badsum_value, use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
                        tfo_cookie_str, tfo_cookie_num, tfo_cookie_length,
                        source_port, debug_packet, debug_rtt, debug_wsn, debug_ttl,
                        use_fragmentation, frag_size, mtu_size, frag_out_of_order,
                        frag_overlap, frag_overlap_bytes, frag_zof,
                        sport_range_min, sport_range_max, initial_rtt_ms,
                        port_timeout_min_ms, port_timeout_max_ms,
                        rate_config, jitter_config, batch_delay_config,
                        use_ip_tos, custom_ip_tos_byte, packet_length_config,
                        true /* is_threaded */);
                }));
        }

        // Wait for all IPs to finish scanning before printing any output
        for (auto& f : ip_futures)
            if (f.valid()) f.get();

    } else {
        // ── Sequential path: used when -I mode is off, or single IP ─────────────
        for (size_t i = 0; i < thread_ips.size() && !terminate_flag; ++i) {
            const auto& ip_str = thread_ips[i];
            uint16_t source_port;
            if (base_source_port > 0) {
                source_port = base_source_port;
            } else {
                source_port = 0;
            }
            int ip_version = get_ip_version(ip_str.c_str());
            if (ip_version != 4) {
                std::cerr << "Only IPv4 addresses are supported. Invalid IP: " << ip_str << std::endl;
                continue;
            }
            uint32_t local_ip = get_local_ip(ip_str.c_str());
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

            if (counted_down_ips.find(target_ip_int) != counted_down_ips.end())
                continue;

            bool is_same_subnet_ip = arp_initialized && is_same_subnet(target_ip_int, src_ip_int, netmask_int);
            if (is_same_subnet_ip) {
                auto it = std::find(same_subnet_ip_ints.begin(), same_subnet_ip_ints.end(), target_ip_int);
                if (it != same_subnet_ip_ints.end()) {
                    size_t arp_index = std::distance(same_subnet_ip_ints.begin(), it);
                    size_t original_index = same_subnet_indices[arp_index];
                    if (results[original_index].mac_address.empty())
                        continue;
                }
            }

            if (!is_threaded) {
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
            }

            auto scan_start_time = std::chrono::steady_clock::now();
            worker_thread(ip_str.c_str(), local_ip, source_ip.c_str(), timeout_ms, ports, rng, pool, send_sock,
                 results[i], main_batch_size, seq_num, win_size, 4, print_individual_closed_filtered, print_filtered_if_few, &send_ring, fast_scan,
                 scan_type, custom_ttl, custom_dscp, custom_ip_flags, ip_id_mode, fixed_ip_id, use_manual_tcp_checksum, manual_tcp_checksum,
                 window_scale, mss_value, timestamp_val, timestamp_ecr_custom, nops_count, sack_permitted,
                 custom_data, data_length, use_custom_data, generate_random_data, user_rcvbuf_size, send_uring_depth, rcv_uring_depth,
                 use_badsum, custom_badsum_value, use_partial_badsum, partial_badsum_type, use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
                 tfo_cookie_str, tfo_cookie_num, tfo_cookie_length, source_port, debug_packet, debug_rtt, debug_wsn, debug_ttl,
                 use_fragmentation, frag_size, mtu_size, frag_out_of_order, frag_overlap, frag_overlap_bytes, frag_zof,
                 sport_range_min, sport_range_max, initial_rtt_ms, port_timeout_min_ms, port_timeout_max_ms,
                 rate_config, jitter_config, batch_delay_config, use_ip_tos, custom_ip_tos_byte, packet_length_config, is_threaded);

            RecPross& result = results[i];
            const auto& service_map = read_services_from_file("services");
            std::string not_shown_message;
            int remaining_closed = result.closed_ports - (int)result.closed_port_list.size();
            if (remaining_closed > 0 && !print_individual_closed_filtered)
                not_shown_message += std::to_string(remaining_closed) + " closed tcp ports (reset)";
            if (result.filtered_ports.size() > 3) {
                if (!not_shown_message.empty()) not_shown_message += " | ";
                std::string state_desc = "filtered";
                if (PacketTask::expects_rst_response(scan_type)) state_desc = "confused";
                not_shown_message += std::to_string(result.filtered_ports.size() - 3) + " tcp ports " + state_desc + " (no response)";
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
                if (has_rtt) {
                    print_output(PrintOutputType::RTT_INFO, "", 0, "", "", "",
                                 0, 0, 0, 0, 0, 0, "", "",
                                 static_cast<double>(result.learned_rtt_ms), "", false, true);
                } else {
                    print_output(PrintOutputType::RTT_INFO, "", 0, "", "", "",
                                 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                }
                if (debug_ttl && result.received_ttl > 0) {
                    display_ttl_analysis(result.rtt_debug_entries, custom_ttl, result.received_ttl,
                                         ip_str.c_str(), !result.open_ports.empty() || result.closed_ports > 0);
                }
                if (!result.packet_details.empty() && !terminate_flag && debug_packet)
                    for (const auto& pair : result.packet_details)
                        display_packet_details(pair.second, debug_packet);
                if (!result.packet_details.empty() && !terminate_flag && debug_wsn)
                    display_wsn_analysis(result.packet_details, window_scale);
            }

            if (multi_ip && i < thread_ips.size() - 1 && !is_threaded)
                print_output(PrintOutputType::MULTI_IP_SEPARATOR);
        }
    }
    
    if (multi_ip && !thread_ips.empty() && !terminate_flag && !is_threaded) {
        int total_open = 0, total_closed = 0, total_filtered = 0;
        for (const auto& result : results) {
            total_open    += result.open_ports.size();
            total_closed  += result.closed_ports;
            total_filtered += result.filtered_ports.size();
        }
        print_output(PrintOutputType::THREAD_SUMMARY, "", 0, "", "", scan_name,
                     0, 0, total_open, total_closed, total_filtered, thread_ips.size(),
                     "", "", 0.0, "", false, true);
    }

    // -I mode flush: all scans are done, now render everything in order
    if (is_threaded && !thread_ips.empty()) {
        // Single-IP: emit the banner that was suppressed before the scan
        if (!multi_ip) {
            print_output(PrintOutputType::SCAN_HEADER, thread_ips[0], 0, "", "", scan_name,
                         0, 0, 0, 0, 0, 0, "", "", 0.0, "", true, true);
        }

        // Pre-compute which indices are alive so separators don't fire after the last alive host
        std::vector<size_t> alive_indices;
        for (size_t i = 0; i < thread_ips.size(); ++i) {
            uint8_t tip[4] = {0};
            uint32_t tip_int = 0;
            if (inet_pton(AF_INET, thread_ips[i].c_str(), tip) == 1)
                memcpy(&tip_int, tip, 4);
            bool is_down = (tip_int != 0 && counted_down_ips.count(tip_int));
            bool has_output = !results[i].output_buffer.empty()
                              || !results[i].open_ports.empty()
                              || results[i].closed_ports > 0
                              || !results[i].filtered_ports.empty();
            if (!is_down && has_output)
                alive_indices.push_back(i);
        }

        for (size_t ai = 0; ai < alive_indices.size(); ++ai) {
            size_t i = alive_indices[ai];
            const RecPross& res = results[i];

            print_output(PrintOutputType::HOST_HEADER, thread_ips[i]);
            print_output(PrintOutputType::PORT_TABLE_HEADER);

            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << res.output_buffer;
            }

            if (multi_ip && ai < alive_indices.size() - 1) {
                print_output(PrintOutputType::MULTI_IP_SEPARATOR);
            }
        }

        if (multi_ip && !terminate_flag) {
            int total_open = 0, total_closed = 0, total_filtered = 0;
            for (size_t i : alive_indices) {
                total_open    += results[i].open_ports.size();
                total_closed  += results[i].closed_ports;
                total_filtered += results[i].filtered_ports.size();
            }
            print_output(PrintOutputType::THREAD_SUMMARY, "", 0, "", "", scan_name,
                         0, 0, total_open, total_closed, total_filtered, alive_indices.size(),
                         "", "", 0.0, "", false, true);
        }
    } else {
        // Normal (non -I) multi-IP path: THREAD_SUMMARY only
        if (multi_ip && !thread_ips.empty() && !terminate_flag) {
            int total_open = 0, total_closed = 0, total_filtered = 0;
            for (const auto& result : results) {
                total_open    += result.open_ports.size();
                total_closed  += result.closed_ports;
                total_filtered += result.filtered_ports.size();
            }
            print_output(PrintOutputType::THREAD_SUMMARY, "", 0, "", "", scan_name,
                         0, 0, total_open, total_closed, total_filtered, thread_ips.size(),
                         "", "", 0.0, "", false, true);
        }
    }

    io_uring_queue_exit(&send_ring);
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
		
		std::cerr << color::green << "DSCP (Differentiated Services Code Point) Options:\n" << color::reset;
		std::cerr << color::yellow << " --dscp" << color::reset << " <value|name> Set IP DSCP/TOS field\n\n";

		std::cerr << color::white << "   Standard/Default:\n" << color::reset;
		std::cerr << "     " << color::yellow << "BE" << color::reset << " or " << color::yellow << "0" << color::reset   << "  # Best Effort (default)\n";
		std::cerr << "     " << color::yellow << "CS1" << color::reset << " or " << color::yellow << "8" << color::reset  << "  # Class Selector 1 (Scavenger)\n";
		std::cerr << "     " << color::yellow << "CS2" << color::reset << " or " << color::yellow << "16" << color::reset << "  # Class Selector 2\n";
		std::cerr << "     " << color::yellow << "CS3" << color::reset << " or " << color::yellow << "24" << color::reset << "  # Class Selector 3\n";
		std::cerr << "     " << color::yellow << "CS4" << color::reset << " or " << color::yellow << "32" << color::reset << "  # Class Selector 4\n";
		std::cerr << "     " << color::yellow << "CS5" << color::reset << " or " << color::yellow << "40" << color::reset << "  # Class Selector 5 (Signaling)\n";
		std::cerr << "     " << color::yellow << "CS6" << color::reset << " or " << color::yellow << "48" << color::reset << "  # Class Selector 6 (Network Control)\n";
		std::cerr << "     " << color::yellow << "CS7" << color::reset << " or " << color::yellow << "56" << color::reset << "  # Class Selector 7\n\n";

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
		
		std::cerr << color::green << "IP TOS (Type of Service) / DSCP-ECN Options:\n" << color::reset;
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
		
		std::cerr << color::green << "IP Fragmentation:\n" << color::reset;
		std::cerr << "  " << color::yellow << "-f <size>" << color::reset << "                 Fragment size (8-65528, must be multiple of 8)\n";
		std::cerr << "\n";
		std::cerr << "  " << color::green << "       Reassembly Variations:\n" << color::reset;
		std::cerr << "    " << color::yellow << "         --frag ofo" << color::reset << "              Send Out-Of-Order fragments\n";
		std::cerr << "    " << color::yellow << "         --frag zof" << color::reset << "              Send zero-offset fragment at last\n";
		std::cerr << "    " << color::yellow << "         --frag lap" << color::reset << "              Send overlap fragments\n\n";

		std::cerr << color::green << "MTU(Maximum Transmission Unit):\n" << color::reset;
		std::cerr << color::yellow << " --mtu <value>" << color::reset << " | valid range: 22 to 65535\n\n";
		
		std::cerr << color::green << " IP ID (Identification) Modes:\n" << color::reset;
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
		std::cerr << "               - ID = timestamp microseconds >> 16\n\n";

		std::cerr << color::green << "TCP/IP Header Control Options:\n" << color::reset;
		std::cerr << color::yellow << " --ttl" << color::reset << " <value> Set IP TTL (0-255, default: 64)\n";
		std::cerr << color::yellow << " --ip-flags" << color::reset << " <hex> Set IP fragment flags (hex, default: 0x4000=DF)\n";
		std::cerr << color::yellow << " -g" << color::reset << " <value> Specify source port 1-65535 (default: random)\n";
		std::cerr << color::yellow << " --sport-range <min>-<max>" << color::reset << " min must be less than max (default: choosen from 32768-60999)\n";
		std::cerr << color::yellow << " -S" << color::reset << " <ip> Specify source IP address\n";
		std::cerr << color::yellow << " -p" << color::reset << " <port> | <port,port> | port-port\n";
		std::cerr << color::yellow << " --badsum" << color::reset << " | <hex> Send invalid checksum default: auto | --badsum 0xffff\n";
		std::cerr << color::yellow << " --prsum" << color::reset << " Send partial invalid checksum (lower,upper,bitflip,middle,swap,incremental,pattern,rfc1141,seq-tied,port-tied,carry-break,valid-ish,\n";
		std::cerr << "                                                                               null,msb,lsb3,rfc1141,seq-tied,goodbye,timestamp-lie,ones-complement,walking-bit,entropy)\n\n";

		std::cerr << color::green << "Payload Options:\n" << color::reset;
		std::cerr << color::yellow << " --data" << color::reset << " <string> Custom payload data (string/hex/number)\n";
		std::cerr << color::yellow << " --data-length" << color::reset << " <size> Generate random payload of specified length\n\n";
		
		std::cerr << color::yellow << "Host Discovery:\n" << color::reset;
		std::cerr << color::yellow << " -Pn" << color::reset << " skip target ping probe\n\n";
		std::cerr << color::yellow << " -I" << color::reset << " Batch print mode: suppress live output, render results after full scan completes (safe for parallel/vector scanning)\n\n";
		
		std::cerr << color::green << "IP Length Manipulation (Evasion/Fingerprinting):\n" << color::reset;
		std::cerr << color::yellow << " --packet-length" << color::reset << " <mode> |  Manipulate IP length field for evasion or OS fingerprinting\n";

		std::cerr << color::green << "  Modes:\n" << color::reset;
		std::cerr << "    " << color::yellow << "small" << color::reset << "            Lie: IP.len=40, actual=74 (20 byte lie)\n";
		std::cerr << "    " << color::yellow << "small:N" << color::reset << "          Truncate: Send exactly N bytes (N must be >= 60)\n";
		std::cerr << "    " << color::yellow << "big" << color::reset << "              Lie: IP.len=134, actual=74 (60 byte lie)\n";
		std::cerr << "    " << color::yellow << "big:N" << color::reset << "            Pad: Send N bytes (adds null padding)\n";
		std::cerr << "    " << color::yellow << "exact:N" << color::reset << "          Send exactly N bytes (honest length)\n";
		std::cerr << "    " << color::yellow << "claimed:N" << color::reset << "        Lie only: IP.len=N, actual unchanged\n\n";

		std::cerr << color::white << "  ⚠️  CRITICAL NOTES:\n" << color::reset;
		std::cerr << "    • " << color::yellow << "small" << color::reset << " (no number) = LIE mode (IP.len=40, actual=74)\n";
		std::cerr << "    • " << color::yellow << "small:N" << color::reset << " (with number) = TRUNCATE mode\n";
		std::cerr << "    • Truncation below 60 bytes will MALFORM the TCP header\n";
		std::cerr << "    • Malformed packets are silently dropped by most targets\n";
		std::cerr << "    • The '14 byte difference' is normal Ethernet overhead, not a feature\n";
		std::cerr << "    • Minimum valid TCP packet with options is 60 bytes\n\n";

		std::cerr << color::green << "  Examples:\n" << color::reset;
		std::cerr << "    " << color::cyan << "# IP length lying (evasion - tests strict firewalls)" << color::reset << "\n";
		std::cerr << "    shiv 10.0.0.1 -p 80 " << color::yellow << "--packet-length small" << color::reset << "\n";
		std::cerr << "        → Claim 40 bytes, send 74 bytes (20 byte lie)\n\n";

		std::cerr << "    " << color::cyan << "# Test packet truncation (only works if N >= 60)" << color::reset << "\n";
		std::cerr << "    shiv 10.0.0.1 -p 80 " << color::yellow << "--packet-length small:60" << color::reset << "\n";
		std::cerr << "        → Send exactly 60 bytes (no lie, just trim TCP options)\n\n";

		std::cerr << "    " << color::cyan << "# Test strict firewalls (will fail if N < 60)" << color::reset << "\n";
		std::cerr << "    shiv target.com -p 443 " << color::yellow << "--packet-length small:42" << color::reset << "\n";
		std::cerr << "        → Truncated to 42 bytes (malformed TCP → filtered)\n\n";

		std::cerr << "    " << color::cyan << "# Pad packet with null bytes" << color::reset << "\n";
		std::cerr << "    shiv 192.168.1.1 -p 22 " << color::yellow << "--packet-length big:1500" << color::reset << "\n";
		std::cerr << "        → Pad to 1500 bytes with nulls, honest length\n\n";

		std::cerr << "    " << color::cyan << "# Lie about huge packet (tests max length filters)" << color::reset << "\n";
		std::cerr << "    shiv target.com -p 80 " << color::yellow << "--packet-length claimed:65535" << color::reset << "\n";
		std::cerr << "        → Claim 65535 bytes, send 74 bytes (extreme lie)\n\n";

		std::cerr << color::green << "  Detection Guide (What results reveal):\n" << color::reset;
		std::cerr << "    • " << color::yellow << "--packet-length small" << color::reset << " (LIE) works\n";
		std::cerr << "        → Target has lenient IP stack (ignores IP.len mismatch)\n\n";
		std::cerr << "    • " << color::yellow << "--packet-length small:60" << color::reset << " works, but " 
			  << color::yellow << "small:42" << color::reset << " fails\n";
		std::cerr << "        → Target validates TCP header integrity\n";
		std::cerr << "        → Minimum packet size is 60 bytes (normal TCP with options)\n\n";
		std::cerr << "    • " << color::yellow << "exact:N" << color::reset << " works for all N >= 60\n";
		std::cerr << "        → Normal TCP stack, no special filtering\n\n";
		std::cerr << "    • " << color::yellow << "big" << color::reset << " (LIE) fails but " << color::yellow << "big:1500" << color::reset << " works\n";
		std::cerr << "        → Firewall checks maximum packet length\n";
		std::cerr << "        → Drops packets claiming > MTU\n\n";
		std::cerr << "    • " << color::yellow << "claimed:N" << color::reset << " with N > 1500 fails\n";
		std::cerr << "        → Stateful firewall validating IP.len against MTU\n\n";

		std::cerr << color::white << "  Technical Details:\n" << color::reset;
		std::cerr << "    • Normal SYN packet: 74 bytes on wire (14 eth + 20 ip + 40 tcp)\n";
		std::cerr << "    • TCP options: MSS, WScale, SACK, Timestamp, NOP = 20 extra bytes\n";
		std::cerr << "    • Minimum valid TCP header with options: 40 bytes\n";
		std::cerr << "    • Truncating below 60 bytes cuts into TCP option data\n";
		std::cerr << "    • Most stacks drop packets with incomplete TCP headers\n\n";

		std::cerr << color::dim << "  Note: The original documentation claiming 'Claim 60, send 74'\n";
		std::cerr << "        is INCORRECT. That describes normal packet behavior,\n";
		std::cerr << "        not the --packet-length feature. Use 'small' for lying,\n";
		std::cerr << "        'small:N' for truncation." << color::reset << "\n\n";
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

		std::cerr << color::green << "TCP Options Control:\n" << color::reset;
		std::cerr << color::yellow << " --ws" << color::reset << " <value> Set Window Scale (0-500, default: 7)\n";
		std::cerr << color::yellow << " --mss" << color::reset << " <value> Set MSS value (0-66666, default: 1460)\n";
		std::cerr << color::yellow << " --t" << color::reset << " <value> Set TCP timestamp (0-100000000, default: 1234567)\n";
		std::cerr << color::yellow << " --tsecr" << color::reset << " <value> Set TCP TSecr value (hex: 0x123 or decimal, default: 0)\n";
		std::cerr << color::yellow << " --nops" << color::reset << " <count> Add NOPs to TCP options (default: 1)\n";
		std::cerr << color::yellow << " --sack" << color::reset << " <on|off> Enable/disable SACK option (default: on)\n";
		std::cerr << color::yellow << " --win-size" << color::reset << " <value> Set TCP window size (0-10000, default: 65535)\n";
		std::cerr << color::yellow << " --seq-num" << color::reset << " <value> Set TCP sequence number (0-4294967295U, default: random)\n\n";

		std::cerr << color::green << "Debug Options:\n" << color::reset;
		
		std::cerr << color::yellow << " --debug <mode>" << color::reset
		          << " Enable debug features\n";

		std::cerr << "         "
		          << color::yellow << "packet" << color::reset
		          << "  Display detailed packet information\n";

		std::cerr << "         "
		          << color::yellow << "rtt" << color::reset
		          << "     Display RTT (Round Trip Time) calculations\n";
		          
		std::cerr << "         "
		          << color::yellow << "wsn" << color::reset
		          << "     Detect WSN (Window Size Negotiation) inconsistent anomalies\n";
		          
		std::cerr << "         "
		          << color::yellow << "tll" << color::reset
		          << "     Display TTL (Time To Live) and target hop distance\n\n";

		std::cerr << color::green << "System Control:\n" << color::reset;
		std::cerr << color::yellow << " --rcvbuf" << color::reset << " <size> Set receive buffer size in bytes(128k, 2m, 1g, or bytes), (default: auto)\n";
		std::cerr << color::yellow << " --send-uring" << color::reset << " <depth> Set io_uring send queue depth (16-4096, default: auto=128)\n";
		std::cerr << color::yellow << " --rcv-uring" << color::reset << " <depth> Set io_uring receive queue depth (16-4096, default: auto=dynamic)\n";
		std::cerr << color::yellow << " -b batch_size/send_size" << color::reset << " <num> Set batch size to scan number of ports at once with grouping, [default 70/70] optimal\n\n"
		
			  << color::yellow << "     Meanings and Values\n" << color::reset
			  << "     batch_size    : 70 (max ports allowed to scan in one batch group)\n"
			  << "     send_size     : 30 (packets to send in one go)\n"
			  << "     total_chunks  : 15 (15 chunks needed, each chunk handles 70 ports, total 1001 ports)\n\n"

			  << color::yellow << "     Formula\n" << color::reset
			  << "     total_ports / batch_size = total_chunks\n"
			  << "     1001 / 70 = 14.3 + 1 = 15 total_chunks (code automatically handles uneven cases by creating needed chunks)\n\n"

			  << color::yellow << "     Breakdown and Calculation\n" << color::reset
			  << "     14 chunks * 70 ports = 980 ports\n"
			  << "     1 chunk  * 21 ports = 21 ports (scanner handles remaining ports by creating a new chunk)\n"
			  << "     total = 1001 ports\n\n"

			  << color::yellow << "     Batch Breaking\n" << color::reset
			  << "     sends per 70-port chunk = (70 / 30) = 3 sends (30 + 30 + 10 = total 70)\n"
			  << "     sends for 21-port chunk = (21 / 30) = 1 send (21) (code handles uneven cases properly)\n\n";
		
		std::cerr << color::yellow << " --set-rtt" << color::reset << " <ms|s> Set initial RTT seed (default: 290ms). e.g. --set-rtt 150ms or --set-rtt 0.5s\n";
		std::cerr << color::yellow << " --rate TIME:MIN-MAX" << color::reset << " Control packet rate.TIME units: ms, s, m  (e.g. 500ms:300-500, 2s:1000-1500)\n";
		std::cerr << color::yellow << " --jitter [TIME]" << color::reset << "\n"
			  << "     Add delay between each packet\n"
			  << "     TIME formats : 50ms | 2s | 1m\n"
		          << "     Default      : random (0.9ms – 7ms per packet)\n"
		          << "     Behavior     : Uses sendmsg() → disables io_uring batching\n";
		          
		std::cerr << color::yellow << " --batch-delay [TIME | MIN-MAX]" << color::reset << "\n"
		          << "     Add delay between batch executions (default batches: 14)\n"
		          << "     No argument  : random (10ms – 60ms)\n"
		          << "     Exact value  : 50ms | 2s | 1m\n"
		          << "     Range        : 20ms – 100ms (random within range)\n"
		          << "     For eg:      : --batch-delay   |  --batch_delay 10ms   |   --batch-delay 20ms-30ms\n\n";
		std::cerr << color::yellow << " --port-timeout" << color::reset << " <min>-<max> Set port giveup timeout(default: min:5ms-max:700ms). e.g. --port-timeout 10ms-500ms\n";
		std::cerr << color::yellow << " --interface" << color::reset << " Set desired interface\n";
		std::cerr << color::yellow << " --timeout" << color::reset << " <ms> Set response timeout (default: 500ms)\n";
		std::cerr << color::yellow << " -o" << color::reset << " <OUTPUT_FILE> Save results to file (supported formats: .txt, .xml, .json, .csv)\n\n";
}

int main(int argc, char *argv[]) {
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

    struct Config {
       bool use_badsum = false,use_partial_badsum = false, fast_scan = true,use_file = true, print_individual_closed_filtered = false,
            print_filtered_if_few = false, graceful_scan = false,use_manual_tcp_checksum = false,
            sack_permitted = true, use_custom_data = false, generate_random_data = false,debug_packet = false,use_trial_api = false,expect_domain_for_trial = false,use_shodan_enum = false;
       uint16_t custom_badsum_value = 0, manual_tcp_checksum = 0,base_source_port = 0, win_size = 0, custom_ip_flags = 0x4000,
                fixed_ip_id = 0, data_length = 0, nops_count = 0, mss_value = 1460,frag_offset_size  = 8,mtu_size = 0;
       int timeout_ms = 370, user_rcvbuf_size = -1,port_timeout_min_ms = 5,port_timeout_max_ms = 700;
       uint8_t custom_ttl = 64, window_scale = 7,custom_dscp = 0,custom_ip_tos = 0;uint16_t sport_range_min = 32768, sport_range_max = 60999;
       uint32_t seq_num = 0, timestamp_val = 1234567, timestamp_ecr_custom = 0;
       size_t send_uring_depth = 0, rcv_uring_depth = 0,
              scan_batch_size = 70, main_batch_size = 70;
       bool batch_specified = false;
       bool debug_rtt = false;
       int initial_rtt_ms = 290;
       bool debug_wsn = false;
       bool debug_ttl = false;
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
       RateConfig rate_config;
       JitterConfig  jitter_config;
       BatchDelayConfig batch_delay_config;
       PacketLengthConfig packet_length_config;
       IpIdMode ip_id_mode  = IpIdMode::RANDOM;
       bool skip_ping       = false;
       bool batch_print = false;
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
	    size_t dash = range_str.find('-');
	    if (dash == std::string::npos || dash == 0 || dash == range_str.size() - 1) {
		std::cerr << "--sport-range: use format min-max (e.g. 1024-65535)\n";
		exit(1);
	    }
	    config.sport_range_min = parse_uint16(range_str.substr(0, dash), "--sport-range");
	    config.sport_range_max = parse_uint16(range_str.substr(dash + 1), "--sport-range");
	    if (config.sport_range_min == 0 || config.sport_range_max == 0) {
		std::cerr << "--sport-range: ports must be 1-65535\n"; exit(1);
	    }
	    if (config.sport_range_min >= config.sport_range_max) {
		std::cerr << "--sport-range: min must be less than max\n"; exit(1);
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

	    // Parse a single value "ms" or "s" into milliseconds
	    auto parse_ms = [](const std::string& s) -> int {
		if (s.size() >= 2 && s.substr(s.size() - 2) == "ms")
		    return static_cast<int>(std::stod(s.substr(0, s.size() - 2)));
		if (!s.empty() && s.back() == 's')
		    return static_cast<int>(std::stod(s.substr(0, s.size() - 1)) * 1000.0);
		return static_cast<int>(std::stod(s));  // plain number = ms
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
		if (token == "packet") {
		    config.debug_packet = true;
		} else if (token == "rtt") {
		    config.debug_rtt = true;
		} else if (token == "wsn") {
		    config.debug_wsn = true;
		} else if (token == "ttl") {
		    config.debug_ttl = true;
		} else {
		    std::cerr << "Invalid --debug token '" << token 
		              << "'. Valid: packet,rtt,wsn,ttl\n";
		    exit(1);
		}
	    }
	}},
        
        {"-b", [&](int& idx) {
            std::string batch_spec = get_next_arg(idx, "-b");
            size_t slash_pos = batch_spec.find('/');
            
            if (slash_pos != std::string::npos) {
                try {
                    config.scan_batch_size = std::stoul(batch_spec.substr(0, slash_pos));
                    config.main_batch_size = std::stoul(batch_spec.substr(slash_pos + 1));
                    
                    if (config.scan_batch_size < 1 || config.scan_batch_size > 10000) {
                        std::cerr << "Scan batch size must be between 1 and 10000\n";
                        exit(1);
                    }
                    
                    if (config.main_batch_size < 1 || config.main_batch_size > 10000) {
                        std::cerr << "Main batch size must be between 1 and 10000\n";
                        exit(1);
                    }
                    
                    if (config.scan_batch_size < config.main_batch_size) {
                        std::cerr << "Scan batch size cannot be smaller than main batch size\n";
                        exit(1);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Invalid batch specification format: " << batch_spec 
                              << " (use format: scan_batch/main_batch)\n";
                    exit(1);
                }
            } else {
                try {
                    size_t single_batch = std::stoul(batch_spec);
                    if (single_batch < 1 || single_batch > 10000) {
                        std::cerr << "Batch size must be between 1 and 10000\n";
                        exit(1);
                    }
                    config.scan_batch_size = single_batch;
                    config.main_batch_size = single_batch;
                } catch (const std::exception& e) {
                    std::cerr << "Invalid batch size: " << batch_spec << " (" << e.what() << ")\n";
                    exit(1);
                }
            }
            config.batch_specified = true;
        }},
        
        {"-g", [&](int& idx) {
            config.base_source_port = parse_uint16(get_next_arg(idx, "-g"), "-g");
        }},
        
        {"--seq-num", [&](int& idx) {
            long temp_seq = std::stol(get_next_arg(idx, "--seq-num"));
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
                config.user_rcvbuf_size = std::stoi(buf_str) * multiplier;
                if (config.user_rcvbuf_size < 1024 || config.user_rcvbuf_size > 100 * 1024 * 1024) {
                    std::cerr << "Receive buffer size must be between 1KB and 100MB\n";
                    exit(1);
                }
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
	    try {
		int val = std::stoi(size_str);
		if (val < 8 || val > 65528 || (val % 8 != 0)) {
		    std::cerr << "-f: size must be a multiple of 8, between 8 and 65528\n";
		    exit(1);
		}
		config.frag_offset_size = static_cast<uint16_t>(val);
	    } catch (const std::exception& e) {
		std::cerr << "-f: invalid fragment size: " << size_str << "\n";
		exit(1);
	    }
	}},
	
	{"--frag", [&](int& idx) {
	    config.use_fragmentation = true;
	    std::string frag_arg = get_next_arg(idx, "--frag");
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

	    std::stringstream ss(frag_arg);
	    std::string token;
	    while (std::getline(ss, token, ',')) {
		if (token == "ofo") {
		    config.frag_out_of_order = true;
		} else if (token == "lap") {
		    config.frag_overlap_bytes = 8;
		    config.frag_overlap = true;
		    if (!lap_peek_num.empty()) {
		        try {
		            int oval = std::stoi(lap_peek_num);
		            if (oval < 8 || oval > 65520 || (oval % 8 != 0)) {
		                std::cerr << "--frag lap: overlap size must be a multiple of 8 "
		                          << "between 8 and 65520 (got " << oval << ").\n"
		                          << "Note: sizes 2 and 6 are only for -f experimental mode, "
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
		    config.frag_zof = true;
		    std::cout << "[INFO] --frag zof: zero-offset fragment will be sent last\n";
		} else {
		    std::cerr << "--frag: unknown token '" << token
		              << "'. Available: ofo, lap, zof\n";
		    exit(1);
		}
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
		std::cerr << "--mtu: value must be between 28 and 65535\n";
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
            float ws_val = std::stof(get_next_arg(idx, "--ws"));
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
            int temp_nops = std::stoi(get_next_arg(idx, "--nops"));
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
	    if (val.size() >= 2 && val.substr(val.size() - 2) == "ms") {
		ms_val = std::stod(val.substr(0, val.size() - 2));
	    } else if (!val.empty() && val.back() == 's') {
		ms_val = std::stod(val.substr(0, val.size() - 1)) * 1000.0;
	    } else {
		ms_val = std::stod(val);  // plain number = ms
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
        
        {"--ttl", [&](int& idx) {
            int ttl_val = std::stoi(get_next_arg(idx, "--ttl"));
            if (ttl_val < 0 || ttl_val > 259) {
                std::cerr << "TTL must be between 0 and 259\n";
                exit(1);
            }
            config.custom_ttl = static_cast<uint8_t>(ttl_val);
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
        
        {"-I", [&](int& idx) {
	    config.batch_print = true;
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
                      << std::dec
                      << "  DSCP=" << static_cast<unsigned>(dscp_val)
                      << "  ECN="  << static_cast<unsigned>(ecn_val)  << "\n";
        }},
        
        {"--ip-flags", [&](int& idx) {
            config.custom_ip_flags = static_cast<uint16_t>(std::stoi(get_next_arg(idx, "--ip-flags"), nullptr, 0));
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
                config.custom_badsum_value = static_cast<uint16_t>(std::stoi(argv[++idx], nullptr, 0));
            }
        }},
        
        {"--prsum", [&](int& idx) {
            config.use_partial_badsum = true;
            config.partial_badsum_type = get_next_arg(idx, "--prsum");
        }},
        
        {"--timeout", [&](int& idx) {
            config.timeout_ms = std::stoi(get_next_arg(idx, "--timeout"));
            if (config.timeout_ms < 1 || config.timeout_ms > 10000) {
                std::cerr << "Timeout must be between 10 and 10000 ms\n";
                exit(1);
            }
        }},
        
        {"--inject-tfo-cookie", [&](int& idx) {
            option_handlers["--inj-tfo-cookie"](idx);
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

        std::cout << color::green << "🌐 " << color::bold << "Subdomain Enumeration: " 
                  << target_domain << color::reset << "\n";
        std::cout << "├─ 🔍 " << color::bold << "API Lookup" << color::reset << "\n";

        ips.clear();
        std::vector<std::string> subdomains = fetch_subdomains_from_api(target_domain, config.trial_api_key);
        if (subdomains.empty()) {
            std::cout << "│   ├─ " << color::yellow << "Trying jq-less method..." 
                      << color::reset << std::endl;
            subdomains = fetch_subdomains_from_api_no_jq(target_domain, config.trial_api_key);
        }

        if (subdomains.empty()) {
            std::cerr << "│   └─ " << color::red << "❌ No subdomains found or API request failed." 
                      << color::reset << "\n";
            return 1;
        }

        std::cout << "│   └─ " << color::green << "✅ Found " << subdomains.size() 
                  << " subdomains" << color::reset << "\n";

        std::vector<std::string> unique_subdomains;
        std::unordered_set<std::string> seen;

        for (const auto& sub : subdomains) {
            if (seen.find(sub) == seen.end()) {
                seen.insert(sub);
                unique_subdomains.push_back(sub);
            }
        }
        subdomains = std::move(unique_subdomains);

        std::cout << "├─ 📡 " << color::bold << "DNS Resolution" << color::reset << "\n";

        std::vector<std::string> resolved_ips;
        std::unordered_map<std::string, std::vector<std::string>> ip_to_domains;
        std::vector<std::string> unresolved_subdomains;

        // parallel resolution — gethostbyname is not thread-safe, replaced
        // with batch_resolve_domains which uses getaddrinfo (reentrant)
        {
            std::vector<std::string> resolved = batch_resolve_domains(subdomains);
            for (size_t si = 0; si < subdomains.size(); ++si) {
                if (resolved[si].empty()) {
                    unresolved_subdomains.push_back(subdomains[si]);
                } else {
                    ip_to_domains[resolved[si]].push_back(subdomains[si]);
                }
            }
        }

        if (!unresolved_subdomains.empty()) {
            std::cout << "│   ├─ " << color::yellow << "⚠️  " << unresolved_subdomains.size() 
                      << " subdomains could not be resolved to IPv4" << color::reset << "\n";
            for (const auto& unresolved : unresolved_subdomains) {
                std::cout << "│   │   └─ " << color::yellow << unresolved << color::reset << "\n";
            }
        }

        std::cout << "│   └─ " << color::green << "✅ " << ip_to_domains.size() 
                  << " unique IP addresses resolved" << color::reset << "\n";

        std::cout << "└─ 🗺️  " << color::bold << "Resolved Hosts" << color::reset << "\n\n";

        std::vector<std::pair<std::string, std::vector<std::string>>> ip_domain_pairs(
            ip_to_domains.begin(), ip_to_domains.end());

        std::sort(ip_domain_pairs.begin(), ip_domain_pairs.end(),
            [](const auto& a, const auto& b) {
                return a.second.size() > b.second.size();
            });

        const size_t MAX_IPS_PER_ROW = 3;
        const size_t COLUMN_WIDTH = 40; 

        for (size_t row_start = 0; row_start < ip_domain_pairs.size(); row_start += MAX_IPS_PER_ROW) {
            size_t row_end = std::min(row_start + MAX_IPS_PER_ROW, ip_domain_pairs.size());
            size_t ips_in_row = row_end - row_start;
    
            for (size_t i = 0; i < ips_in_row; ++i) {
                const auto& [ip, domains] = ip_domain_pairs[row_start + i];
                std::cout << color::green << "📍 " << color::bold << ip << color::reset;
        
                if (i < ips_in_row - 1) {
                    size_t current_length = ip.length() + 3;
                    size_t padding_needed = COLUMN_WIDTH - current_length;
                    if (padding_needed > 0) {
                        std::cout << std::string(padding_needed, ' ');
                    }
                }
            }
            std::cout << "\n";
            for (size_t i = 0; i < ips_in_row; ++i) {
                const auto& [ip, domains] = ip_domain_pairs[row_start + i];
                std::cout << "└─ 🌐 " << color::bold << "Domains (" << domains.size() << ")" << color::reset;
        
                if (i < ips_in_row - 1) {
                    size_t current_length = 8 + std::to_string(domains.size()).length() + 2; 
                    size_t padding_needed = COLUMN_WIDTH - current_length;
                    if (padding_needed > 0) {
                        std::cout << std::string(padding_needed, ' ');
                    }
                }
            }
            std::cout << "\n";
            size_t max_domains_in_row = 0;
            for (size_t i = 0; i < ips_in_row; ++i) {
                max_domains_in_row = std::max(max_domains_in_row, 
                                             ip_domain_pairs[row_start + i].second.size());
            }

            for (size_t line = 0; line < max_domains_in_row; ++line) {
                for (size_t i = 0; i < ips_in_row; ++i) {
                    const auto& [ip, domains] = ip_domain_pairs[row_start + i];
            
                    if (line < domains.size()) {
                        std::string prefix;
                        if (line == domains.size() - 1) {
                            prefix = "      └─ ";
                        } else {
                            prefix = "      ├─ ";
                        }
                
                        std::cout << prefix << color::green << domains[line] << color::reset;
                        if (i < ips_in_row - 1) {
                            size_t current_length = prefix.length() + domains[line].length();
                            size_t padding_needed = COLUMN_WIDTH - current_length;
                            if (padding_needed > 0) {
                                std::cout << std::string(padding_needed, ' ');
                            }
                        }
                    } else {
                        if (i < ips_in_row - 1) {
                            std::cout << std::string(COLUMN_WIDTH, ' ');
                        }
                    }
                }
                std::cout << "\n";
            }
            if (row_end < ip_domain_pairs.size()) {
                std::cout << "\n";
            }
        }

        for (const auto& [ip, domains] : ip_domain_pairs) {
            resolved_ips.push_back(ip);
        }
        ips = resolved_ips;

        if (resolved_ips.empty()) { 
            std::cerr << color::red << "❌ Error: No subdomains could be resolved." 
                      << color::reset << "\n";
            return 1;
        }
        std::cout << "\n" << color::green << "📊 " << color::bold << "Summary" << color::reset << "\n";
        std::cout << "├─ Total Subdomains: " << subdomains.size() << "\n";
        std::cout << "├─ Resolved to IPv4: " << subdomains.size() - unresolved_subdomains.size() << "\n";
        std::cout << "├─ Unresolved: " << unresolved_subdomains.size() << "\n";
        std::cout << "└─ Unique IPs: " << ip_to_domains.size() << "\n\n";

        std::cout << color::bold << "🎯 Ready to scan " << ip_to_domains.size() 
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
    PacketBufferPool pool(ports.size(), 1);
    std::atomic<int> total_down_hosts{0};

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

    // Auto-enable batch print mode when scanning more than 5 targets
    if (ips.size() > 5 && !config.batch_print) {
        config.batch_print = true;
    }

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
            if (config.batch_print) {
                // ── Async path: fire probes, scan runs in parallel, join before flush ──
                auto ping_future = icmp_ping_sweep_async(external_ips, 1200);

                // TCP scan runs here while ICMP probes are in-flight
                std::vector<RecPross> single_results(ips.size());
                thread_worker(ips, ports, config.timeout_ms, pool, send_sock,
                     single_results, config.main_batch_size, config.seq_num, config.win_size,
                     config.print_individual_closed_filtered, config.print_filtered_if_few, config.fast_scan,
                     total_down_hosts, config.scan_type, config.custom_ttl, config.custom_dscp, config.custom_ip_flags,
                     config.ip_id_mode, config.fixed_ip_id,
                     config.use_manual_tcp_checksum, config.manual_tcp_checksum, config.window_scale,
                     config.mss_value, config.timestamp_val, config.timestamp_ecr_custom, config.nops_count,
                     config.sack_permitted, config.custom_data, config.data_length, config.use_custom_data,
                     config.generate_random_data, config.user_rcvbuf_size, config.source_ip,
                     config.send_uring_depth, config.rcv_uring_depth, config.use_badsum,
                     config.custom_badsum_value, config.use_partial_badsum, config.partial_badsum_type,
                     config.use_tfo_cookie, config.tfo_cookie_as_hex, config.tfo_cookie_random,
                     config.tfo_cookie_str, config.tfo_cookie_num, config.tfo_cookie_length,
                     config.base_source_port, config.debug_packet, config.debug_rtt, config.debug_wsn, config.debug_ttl,
                     config.use_fragmentation, config.frag_offset_size, config.mtu_size,
                     config.frag_out_of_order, config.frag_overlap, config.frag_overlap_bytes, config.frag_zof,
                     config.sport_range_min, config.sport_range_max, config.initial_rtt_ms,
                     config.port_timeout_min_ms, config.port_timeout_max_ms,
                     config.rate_config, config.jitter_config, config.batch_delay_config,
                     config.use_ip_tos, config.custom_ip_tos, config.packet_length_config,
                     config.batch_print);

                // Now join: ping results are ready (scan already waited longer than 1200ms)
                auto ping_results = ping_future.get();

                // Filter: zero out results for dead external hosts
                std::vector<bool> keep(ips.size(), true);
                for (size_t pi = 0; pi < ping_results.size(); ++pi) {
                    const auto& pr  = ping_results[pi];
                    size_t      idx = external_indices[pi];
                    switch (pr.state) {
                        case IcmpHostState::Alive:
                        case IcmpHostState::NetAdminProhibited:
                        case IcmpHostState::HostAdminProhibited:
                        case IcmpHostState::CommAdminProhibited:
                            break;
                        case IcmpHostState::Dead:
                        case IcmpHostState::NetUnreachable:
                        case IcmpHostState::NoResponse:
                            keep[idx] = false;
                            total_down_hosts++;
                            break;
                    }
                }

                // Remove dead hosts from single_results before flush
                std::vector<RecPross> filtered_results;
                std::vector<std::string> filtered_ips;
                filtered_results.reserve(ips.size());
                filtered_ips.reserve(ips.size());
                for (size_t i = 0; i < ips.size(); ++i) {
                    if (keep[i]) {
                        filtered_results.push_back(std::move(single_results[i]));
                        filtered_ips.push_back(ips[i]);
                    }
                }

                close(send_sock);

                // Flush output (reuse existing post-scan block)
                auto total_scan_end = std::chrono::steady_clock::now();
                auto total_duration = total_scan_end - total_scan_start;
                double total_elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                    total_duration).count() / 1000.0;

                std::cout << "\n";
                if (filtered_ips.size() > 1) {
                    if (total_elapsed_ms < 1.0) {
                        std::cout << "Overall scan completed in " << std::fixed << std::setprecision(1)
                                  << (total_elapsed_ms * 1000) << " microseconds\n";
                    } else if (total_elapsed_ms < 1000.0) {
                        std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2)
                                  << total_elapsed_ms << " milliseconds\n";
                    } else {
                        std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2)
                                  << (total_elapsed_ms / 1000.0) << " seconds\n";
                    }
                }

                if (!config.output_file.empty()) {
                    save_scan_results(filtered_results, config.output_file);
                }
                if (terminate_flag) std::cout << "\nScan interrupted by user.\n";

                int total_down_hosts_count = total_down_hosts.load();
                if (total_down_hosts_count > 0) {
                    print_output(PrintOutputType::DOWN_HOSTS_SUMMARY, "", 0, "", "", "",
                                 0, 0, total_down_hosts_count, 0, 0, ips.size(),
                                 "", "", 0.0, "", false, true);
                }
                return 0;

            } else {
                // ── Blocking path (unchanged): used when batch_print is false ──
                auto ping_results = icmp_ping_sweep(external_ips, 1200);

                std::vector<bool> keep(ips.size(), true);

                for (size_t pi = 0; pi < ping_results.size(); ++pi) {
                    const auto& pr  = ping_results[pi];
                    size_t      idx = external_indices[pi];
                    switch (pr.state) {
                        case IcmpHostState::Alive: break;
                        case IcmpHostState::Dead:
                            std::cout << "[ping] " << pr.ip
                                      << " appears down (ICMP type 3 code 1: host unreachable) — skipping\n";
                            keep[idx] = false; total_down_hosts++; break;
                        case IcmpHostState::NoResponse:
                            std::cout << "[ping] " << pr.ip
                                      << " no response (timeout — ICMP blocked or host down use -Pn) — skipping\n";
                            keep[idx] = false; total_down_hosts++; break;
                        case IcmpHostState::NetUnreachable:
                            std::cout << "[ping] " << pr.ip
                                      << " network unreachable (ICMP type 3 code 0: net unreachable) — skipping\n";
                            keep[idx] = false; total_down_hosts++; break;
                        case IcmpHostState::NetAdminProhibited:
                            std::cout << "[ping] " << pr.ip
                                      << " network admin prohibited (ICMP type 3 code 9: ACL/router policy) — scanning anyway\n";
                            break;
                        case IcmpHostState::HostAdminProhibited:
                            std::cout << "[ping] " << pr.ip
                                      << " host admin prohibited (ICMP type 3 code 10: host firewall) — scanning anyway\n";
                            break;
                        case IcmpHostState::CommAdminProhibited:
                            std::cout << "[ping] " << pr.ip
                                      << " communication admin prohibited (ICMP type 3 code 13: iptables REJECT) — scanning anyway\n";
                            break;
                    }
                }

                std::vector<std::string> new_ips;
                new_ips.reserve(ips.size());
                for (size_t i = 0; i < ips.size(); ++i)
                    if (keep[i]) new_ips.push_back(ips[i]);
                ips = std::move(new_ips);

                if (ips.empty()) {
                    close(send_sock);
                    return 1;
                }
            }
        }
    }

    std::vector<RecPross> single_results(ips.size());

    thread_worker(ips, ports, config.timeout_ms, pool, send_sock,
         single_results, config.main_batch_size, config.seq_num, config.win_size,
         config.print_individual_closed_filtered, config.print_filtered_if_few, config.fast_scan,
         total_down_hosts, config.scan_type, config.custom_ttl, config.custom_dscp, config.custom_ip_flags,
         config.ip_id_mode, config.fixed_ip_id,
         config.use_manual_tcp_checksum, config.manual_tcp_checksum, config.window_scale,
         config.mss_value, config.timestamp_val, config.timestamp_ecr_custom, config.nops_count,
         config.sack_permitted, config.custom_data, config.data_length, config.use_custom_data,
         config.generate_random_data, config.user_rcvbuf_size, config.source_ip,
         config.send_uring_depth, config.rcv_uring_depth, config.use_badsum,
         config.custom_badsum_value, config.use_partial_badsum, config.partial_badsum_type,
         config.use_tfo_cookie, config.tfo_cookie_as_hex, config.tfo_cookie_random,
         config.tfo_cookie_str, config.tfo_cookie_num, config.tfo_cookie_length,
         config.base_source_port, config.debug_packet, config.debug_rtt, config.debug_wsn, config.debug_ttl,
         config.use_fragmentation, config.frag_offset_size, config.mtu_size,
         config.frag_out_of_order, config.frag_overlap, config.frag_overlap_bytes, config.frag_zof,
         config.sport_range_min, config.sport_range_max, config.initial_rtt_ms,
         config.port_timeout_min_ms, config.port_timeout_max_ms,
         config.rate_config, config.jitter_config, config.batch_delay_config,
         config.use_ip_tos, config.custom_ip_tos, config.packet_length_config,
         config.batch_print);

    close(send_sock);
    std::vector<RecPross> all_results = std::move(single_results);
    auto total_scan_end = std::chrono::steady_clock::now();
    auto total_duration = total_scan_end - total_scan_start;

    double total_elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        total_duration).count() / 1000.0;

    std::cout << "\n";
    if (ips.size() > 1) {
        //std::cout << scan_name << " scan completed at " << get_current_time() << "\n";
    
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
    
    	uint64_t total_packets_sent = 0;
        int total_open = 0;
        int total_closed = 0;
        int total_filtered = 0;
        for (const auto& result : all_results) {
            total_open += result.open_ports.size();
            total_closed += result.closed_ports;
            total_filtered += result.filtered_ports.size();
            total_packets_sent += result.packets_sent;
        }

    }
    if (!config.output_file.empty()) {
        save_scan_results(all_results, config.output_file);
    }
    
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

