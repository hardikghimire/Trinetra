#ifndef SCAN_HPP
#define SCAN_HPP

#include <sys/ioctl.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unordered_set>
#include <errno.h>
#include <vector>
#include <sstream>
#include <span>
#include <poll.h>
#include <algorithm>
#include <thread>
#include <mutex>
#include <fcntl.h>
#include <liburing.h>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <random>
#include <sys/mman.h>
#include <sys/stat.h>
#include <iomanip>
#include <cmath>
#include <ctime>
#include <csignal>
#include <atomic>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <ifaddrs.h>
#undef BLOCK_SIZE 
#include <concurrentqueue.h> 

#ifndef TH_CWR
#define TH_CWR   0x80  
#endif
#ifndef TH_ECE  
#define TH_ECE   0x40  
#endif
#ifndef TH_URG
#define TH_URG   0x20  
#endif  
#ifndef TH_PUSH
#define TH_PUSH  0x08 
#endif

extern std::atomic<bool> terminate_flag;
extern std::atomic<int> filtered_ports_printed_count;
extern std::atomic<bool> network_disconnect_flag; 
void signal_handler(int signal);

struct RateConfig {
    bool     enabled       = false;
    uint64_t window_us     = 0;  
    uint32_t min_packets   = 0;   
    uint32_t max_packets   = 0;   
};

inline bool parse_duration_to_us(std::string_view s,
                                  uint64_t& out,
                                  const char* flag_name)
{
    // ── unit detection ───────────────────────────────────────────────────
    double   multiplier = 0.0;
    size_t   num_len    = 0;        // how many chars belong to the number

    if (s.size() >= 2 && s.substr(s.size() - 2) == "ms") {
        multiplier = 1'000.0;
        num_len    = s.size() - 2;
    } else if (!s.empty() && s.back() == 's' &&
               (s.size() < 2 || s[s.size() - 2] != 'm')) {
        multiplier = 1'000'000.0;
        num_len    = s.size() - 1;
    } else if (!s.empty() && s.back() == 'm') {
        multiplier = 60'000'000.0;
        num_len    = s.size() - 1;
    } else {
        std::cerr << flag_name
                  << ": unknown time unit (use ms, s, or m)"
                     " e.g. 500ms, 2s, 1m\n";
        return false;
    }

    // ── numeric parse ────────────────────────────────────────────────────
    if (num_len == 0) {
        std::cerr << flag_name << ": missing numeric value before unit\n";
        return false;
    }

    double val = 0.0;
    try {
        val = std::stod(std::string(s.substr(0, num_len)));
    } catch (const std::exception&) {
        std::cerr << flag_name << ": invalid numeric value '"
                  << s << "'\n";
        return false;
    }

    // ── positivity check ─────────────────────────────────────────────────
    if (val <= 0.0) {
        std::cerr << flag_name << ": time must be > 0\n";
        return false;
    }

    out = static_cast<uint64_t>(val * multiplier);
    return true;
}

inline bool parse_rate_config(const std::string& arg, RateConfig& out) {
    // Find the colon separating time from packet range
    size_t colon = arg.find(':');
    if (colon == std::string::npos || colon == 0 || colon == arg.size() - 1) {
        std::cerr << "--rate: use format TIME:MIN-MAX e.g. 500ms:300-500\n";
        return false;
    }

    std::string time_part  = arg.substr(0, colon);
    std::string range_part = arg.substr(colon + 1);

    // Parse time into microseconds
     uint64_t window_us = 0;
     if (!parse_duration_to_us(time_part, window_us, "--rate")) return false;

    // Parse min-max packet range
    size_t dash = range_part.find('-');
    if (dash == std::string::npos || dash == 0 || dash == range_part.size() - 1) {
        std::cerr << "--rate: packet range must be MIN-MAX e.g. 300-500\n";
        return false;
    }
    uint32_t pmin = static_cast<uint32_t>(std::stoul(range_part.substr(0, dash)));
    uint32_t pmax = static_cast<uint32_t>(std::stoul(range_part.substr(dash + 1)));
    if (pmin == 0 || pmax == 0) {
        std::cerr << "--rate: min and max packets must be > 0\n";
        return false;
    }
    if (pmin > pmax) {
        std::cerr << "--rate: min must be <= max\n";
        return false;
    }

    out.enabled      = true;
    out.window_us    = window_us;
    out.min_packets  = pmin;
    out.max_packets  = pmax;
    return true;
}

struct JitterConfig {
    bool     enabled      = false;
    bool     random_mode  = false;  
    uint64_t delay_us     = 0;      
};


inline bool parse_jitter_config(const std::string& arg, JitterConfig& out) {
    if (arg.empty()) {
        out.enabled     = true;
        out.random_mode = true;
        out.delay_us    = 0;
        return true;
    }

    if (!parse_duration_to_us(arg, out.delay_us, "--jitter")) return false;

    out.enabled     = true;
    out.random_mode = false;
    return true;
}

struct BatchDelayConfig {
    bool     enabled      = false;
    bool     random_mode  = false;  
    bool     range_mode   = false;  
    uint64_t delay_us     = 0;      
    uint64_t min_us       = 0;      
    uint64_t max_us       = 0;       
};

inline bool parse_batch_delay_config(const std::string& arg, BatchDelayConfig& out) {
    // Helper: parse a time string with suffix ms/s/m → microseconds
    auto parse_us = [](const std::string& s, uint64_t& us) -> bool {
        if (s.size() >= 2 && s.substr(s.size() - 2) == "ms") {
            double ms = std::stod(s.substr(0, s.size() - 2));
            if (ms <= 0) { std::cerr << "--batch-delay: time must be > 0\n"; return false; }
            us = static_cast<uint64_t>(ms * 1000.0);
        } else if (!s.empty() && s.back() == 's' &&
                   (s.size() < 2 || s[s.size()-2] != 'm')) {
            double sv = std::stod(s.substr(0, s.size() - 1));
            if (sv <= 0) { std::cerr << "--batch-delay: time must be > 0\n"; return false; }
            us = static_cast<uint64_t>(sv * 1'000'000.0);
        } else if (!s.empty() && s.back() == 'm') {
            double mv = std::stod(s.substr(0, s.size() - 1));
            if (mv <= 0) { std::cerr << "--batch-delay: time must be > 0\n"; return false; }
            us = static_cast<uint64_t>(mv * 60'000'000.0);
        } else {
            std::cerr << "--batch-delay: unknown time unit (use ms, s, or m)\n";
            return false;
        }
        return true;
    };

    if (arg.empty()) {
        out.enabled     = true;
        out.random_mode = true;
        out.min_us      = 10'000;   
        out.max_us      = 60'000;  
        return true;
    }
    size_t dash = std::string::npos;
    for (size_t i = 1; i < arg.size(); ++i) {
        if (arg[i] == '-') { dash = i; break; }
    }

    if (dash != std::string::npos && dash != arg.size() - 1) {
        // range mode: min-max
        std::string min_str = arg.substr(0, dash);
        std::string max_str = arg.substr(dash + 1);
        uint64_t min_us = 0, max_us = 0;
        if (!parse_duration_to_us(min_str, min_us, "--batch-delay")) return false;
        if (!parse_duration_to_us(max_str, max_us, "--batch-delay")) return false;
        if (min_us >= max_us) {
            std::cerr << "--batch-delay: min must be less than max\n";
            return false;
        }
        out.enabled    = true;
        out.range_mode = true;
        out.min_us     = min_us;
        out.max_us     = max_us;
        return true;
    }
    uint64_t us = 0;
    if (!parse_duration_to_us(arg, us, "--batch-delay")) return false;
    out.enabled    = true;
    out.random_mode = false;
    out.range_mode  = false;
    out.delay_us    = us;
    return true;
}

// ─── PacketLengthConfig ───────────────────────────────────────────────────────

enum class PacketLengthMode {
    NONE,          // feature disabled (default)
    BIG,           // claim bigger than actual (no <N>)
    SMALL,         // claim smaller than actual (no <N>)
    BIG_EXACT,     // pad real bytes to N, claim N
    SMALL_EXACT,   // shrink real bytes to N, claim N
    EXACT,         // pad/shrink real bytes to N, claim N (honest)
    CLAIMED        // only lie ip_len = N, leave real bytes alone
};

struct PacketLengthConfig {
    bool              enabled     = false;
    PacketLengthMode  mode        = PacketLengthMode::NONE;
    uint16_t          target_len  = 0;   // N from big:<N> / small:<N> / exact:<N> / claimed:<N>
    int               big_delta   = 64;  // how many bytes to over-claim when no N given
    int               small_delta = 20;  // how many bytes to under-claim when no N given
};

inline bool parse_packet_length(const std::string& arg, PacketLengthConfig& out) {
    // Helper: parse optional ":<num>" suffix
    auto parse_n = [&](const std::string& s, uint16_t& n, size_t prefix_len) -> bool {
        if (s.size() <= prefix_len) { n = 0; return true; }  // no N given
        if (s[prefix_len] != ':') {
            std::cerr << "--packet-length: expected ':' after keyword, got '" << s << "'\n";
            return false;
        }
        try {
            unsigned long v = std::stoul(s.substr(prefix_len + 1));
            if (v < 40 || v > 65535) {
                std::cerr << "--packet-length: length must be 40–65535\n";
                return false;
            }
            n = static_cast<uint16_t>(v);
            return true;
        } catch (...) {
            std::cerr << "--packet-length: invalid number in '" << s << "'\n";
            return false;
        }
    };

    out.enabled = true;

    if (arg == "big") {
        out.mode = PacketLengthMode::BIG;
        return true;
    }
    if (arg == "small") {
        out.mode = PacketLengthMode::SMALL;
        return true;
    }
    if (arg.find("big:") == 0) {
        out.mode = PacketLengthMode::BIG_EXACT;
        return parse_n(arg, out.target_len, 3);
    }
    if (arg.find("small:") == 0) {
        out.mode = PacketLengthMode::SMALL_EXACT;
        return parse_n(arg, out.target_len, 5);
    }
    if (arg.find("exact:") == 0) {
        out.mode = PacketLengthMode::EXACT;
        return parse_n(arg, out.target_len, 5);
    }
    if (arg.find("claimed:") == 0) {
        out.mode = PacketLengthMode::CLAIMED;
        return parse_n(arg, out.target_len, 7);
    }

    std::cerr << "--packet-length: unrecognised value '" << arg
              << "'. Use: big, small, big:<N>, small:<N>, exact:<N>, claimed:<N>\n";
    return false;
}

inline bool parse_dscp_value(const std::string& arg, uint8_t& out_dscp) {
    static const std::unordered_map<std::string, uint8_t> dscp_map = {
        {"BE",   0},  {"CS0",  0},
        {"CS1",  8},  {"CS2", 16},  {"CS3", 24},  {"CS4", 32},
        {"CS5", 40},  {"CS6", 48},  {"CS7", 56},
        {"AF11",10},  {"AF12",12},  {"AF13",14},
        {"AF21",18},  {"AF22",20},  {"AF23",22},
        {"AF31",26},  {"AF32",28},  {"AF33",30},
        {"AF41",34},  {"AF42",36},  {"AF43",38},
        {"EF",  46},  {"VA",  44},
    };

    // Try symbolic name first (case-insensitive by uppercasing input)
    std::string upper = arg;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto it = dscp_map.find(upper);
    if (it != dscp_map.end()) {
        out_dscp = it->second;
        return true;
    }

    // Try numeric (decimal or 0x hex)
    try {
        unsigned long val;
        if (arg.size() > 2 && (arg[0] == '0') && (arg[1] == 'x' || arg[1] == 'X'))
            val = std::stoul(arg.substr(2), nullptr, 16);
        else
            val = std::stoul(arg);

        if (val > 63) {
            std::cerr << "--dscp: value " << val
                      << " out of range (0-63, or use a name like EF, AF41, CS3)\n";
            return false;
        }
        out_dscp = static_cast<uint8_t>(val);
        return true;
    } catch (...) {
        std::cerr << "--dscp: unrecognized value '" << arg
                  << "'. Use a name (e.g. EF, AF41, CS3, BE) or a number 0-63.\n";
        return false;
    }
}


inline bool parse_ip_tos_value(const std::string& arg, uint8_t& out_tos) {
    // Accept decimal (0–255) or hex (0x00–0xFF)
    try {
        unsigned long val;
        if (arg.size() > 2 && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X'))
            val = std::stoul(arg.substr(2), nullptr, 16);
        else
            val = std::stoul(arg);

        if (val > 255) {
            std::cerr << "--ip-tos: value " << val
                      << " out of range (0x00–0xFF / 0–255)\n";
            return false;
        }
        out_tos = static_cast<uint8_t>(val);
        return true;
    } catch (...) {
        std::cerr << "--ip-tos: invalid value '" << arg
                  << "'. Use hex (e.g. 0xB8) or decimal (e.g. 184).\n";
        return false;
    }
}

enum class IpIdMode {
    RANDOM,       
    SEQUENTIAL,   
    ZERO,         
    FIXED,        
    IPROFILE,     
    TIME          
};

inline bool parse_ip_id_mode(const std::string& arg,
                              IpIdMode& out_mode,
                              uint16_t& out_value)
{
    if (arg == "random")     { out_mode = IpIdMode::RANDOM;     return true; }
    if (arg == "sequential") { out_mode = IpIdMode::SEQUENTIAL; return true; }
    if (arg == "zero")       { out_mode = IpIdMode::ZERO;       return true; }
    if (arg == "iprofile")   { out_mode = IpIdMode::IPROFILE;   return true; }
    if (arg == "time")       { out_mode = IpIdMode::TIME;       return true; }

    // Try numeric — user-specified fixed value
    try {
        unsigned long v;
        if (arg.size() > 2 && arg[0] == '0' && (arg[1]=='x'||arg[1]=='X'))
            v = std::stoul(arg.substr(2), nullptr, 16);
        else
            v = std::stoul(arg);
        if (v > 65535) {
            std::cerr << "--ip-id: value " << v << " out of range (0–65535)\n";
            return false;
        }
        out_mode  = IpIdMode::FIXED;
        out_value = static_cast<uint16_t>(v);
        return true;
    } catch (...) {
        std::cerr << "--ip-id: unrecognized mode '" << arg
                  << "'. Use: random, sequential, zero, iprofile, time, or a 0–65535 number.\n";
        return false;
    }
}


enum class ScanType { SYN, FIN, ACK, NULL_SCAN, XMAS, WINDOW, MAIMON, CWR, ECE, URG, PSH, HANUMAN, KAKABHUSUNDI, GANESH, RAM, GARUD, JATAYU };

class RAIIManager {
private:
    std::vector<std::function<void()>> cleanup_actions;
    std::atomic<bool> resources_released{false};
    mutable std::mutex mutex;

public:
    RAIIManager() = default;

    template<typename Resource, typename CleanupFunc>
    Resource* track_resource(Resource* resource, CleanupFunc cleanup) {
        if (!resource) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(mutex);
        if (resources_released.load(std::memory_order_acquire)) {
            cleanup(resource);
            return nullptr;
        }

        cleanup_actions.emplace_back([resource, cleanup]() mutable {
            cleanup(resource);
        });

        return resource;
    }

    template<typename T, typename Deleter>
    T* track_unique_ptr(std::unique_ptr<T, Deleter>&& ptr) {
        if (!ptr) {
            return nullptr;
        }

        T* raw_ptr = ptr.get();
        Deleter deleter = ptr.get_deleter();

        std::lock_guard<std::mutex> lock(mutex);
        if (resources_released.load(std::memory_order_acquire)) {
            deleter(raw_ptr);
            ptr.release();
            return nullptr;
        }

        ptr.release();
        cleanup_actions.emplace_back([raw_ptr, deleter]() mutable {
            if (raw_ptr) {
                deleter(raw_ptr);
            }
        });

        return raw_ptr;
    }

    template<typename T, typename Deleter>
    T* track_unique_ptr(std::unique_ptr<T, Deleter>&) = delete;

    template<typename T, typename Deleter>
    T* track_array(T* array, size_t count, Deleter deleter) {
        (void)count;

        if (!array) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(mutex);
        if (resources_released.load(std::memory_order_acquire)) {
            deleter(array);
            return nullptr;
        }

        cleanup_actions.emplace_back([array, deleter]() mutable {
            deleter(array);
        });

        return array;
    }

    template<typename T>
    T* track_array(T* array, size_t count) {
        return track_array(array, count, [](T* p) { delete[] p; });
    }

    void add_cleanup_action(std::function<void()> action) {
        if (!action) {
            return;
        }

        std::lock_guard<std::mutex> lock(mutex);
        if (resources_released.load(std::memory_order_acquire)) {
            action();
            return;
        }

        cleanup_actions.emplace_back(std::move(action));
    }

    void release_all() {
        std::vector<std::function<void()>> actions_to_run;

        {
            std::lock_guard<std::mutex> lock(mutex);

            if (resources_released.exchange(true, std::memory_order_acq_rel)) {
                return;
            }

            actions_to_run.swap(cleanup_actions);
        }

        for (auto it = actions_to_run.rbegin(); it != actions_to_run.rend(); ++it) {
            try {
                (*it)();
            } catch (...) {
               
            }
        }
    }

    bool is_released() const {
        return resources_released.load(std::memory_order_acquire);
    }

    size_t tracked_count() const {
        std::lock_guard<std::mutex> lock(mutex);
        return cleanup_actions.size();
    }

    ~RAIIManager() noexcept {
        release_all();
    }

    RAIIManager(const RAIIManager&) = delete;
    RAIIManager& operator=(const RAIIManager&) = delete;

    RAIIManager(RAIIManager&& other) noexcept {
        std::lock_guard<std::mutex> lock(other.mutex);
        cleanup_actions = std::move(other.cleanup_actions);
        resources_released.store(
            other.resources_released.load(std::memory_order_acquire),
            std::memory_order_release
        );
        other.cleanup_actions.clear();
        other.resources_released.store(true, std::memory_order_release);
    }

    RAIIManager& operator=(RAIIManager&& other) noexcept {
        if (this == &other) {
            return *this;
        }

        release_all();

        std::scoped_lock lock(mutex, other.mutex);
        cleanup_actions = std::move(other.cleanup_actions);
        resources_released.store(
            other.resources_released.load(std::memory_order_acquire),
            std::memory_order_release
        );
        other.cleanup_actions.clear();
        other.resources_released.store(true, std::memory_order_release);

        return *this;
    }
};


class ScopedRAII {
private:
    RAIIManager& manager;
    
public:
    explicit ScopedRAII(RAIIManager& mgr) : manager(mgr) {}
    ~ScopedRAII() { manager.release_all(); }
    RAIIManager& get_manager() { return manager; }
    ScopedRAII(const ScopedRAII&) = delete;
    ScopedRAII& operator=(const ScopedRAII&) = delete;
};

struct arp_header {
    uint16_t htype;uint16_t ptype;uint8_t hlen;uint8_t plen;uint16_t opcode;uint8_t src_mac[6];uint8_t src_ip[4];uint8_t dst_mac[6];uint8_t dst_ip[4];  
};

struct eth_frame {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct PacketDetails {
    // ── original fields ──────────────────────────────────────────────────────
    uint16_t port           = 0;
    uint8_t  tcp_flags      = 0;
    uint32_t seq_num        = 0;
    uint32_t ack_num        = 0;
    uint16_t window_size    = 0;
    uint16_t length         = 0;       // payload byte count
    uint8_t  window_scale   = 0;
    bool     sack_permitted = false;
    uint32_t tsval          = 0;
    uint32_t tsecr          = 0;
    std::string tfo_data;
    std::string payload;
    bool     df_flag        = false;
    uint16_t checksum       = 0;
    uint16_t nop_count      = 0;
    uint16_t ip_id          = 0;
    uint8_t  ttl            = 0;
    bool has_window_scale   = false;
    bool has_sack           = false;
    bool has_timestamp      = false;
    bool has_tfo            = false;
    bool has_payload        = false;
    bool has_df             = false;
    bool has_nops           = false;

    // ── new: raw capture ─────────────────────────────────────────────────────
    std::vector<uint8_t> raw_packet;         // full IP+TCP+payload bytes
    uint16_t ip_total_length    = 0;
    uint8_t  ip_header_len      = 0;         // in bytes (ip_hl * 4)
    uint8_t  tcp_header_len     = 0;         // in bytes (th_off * 4)
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port           = 0;
    uint16_t dst_port           = 0;
    uint64_t capture_epoch_us   = 0;         // from SO_TIMESTAMP

    // ── new: probe context ───────────────────────────────────────────────────
    int      retry_index        = 0;
    double   rtt_ms             = 0.0;
    uint8_t  sent_ttl           = 0;
    uint8_t  sent_ws            = 0;
    uint32_t sent_tsval         = 0;
    uint8_t  sent_flags         = 0;

    // ── new: IP header extras ─────────────────────────────────────────────────
    uint8_t  ip_tos             = 0;
    uint16_t ip_frag_off_raw    = 0;
    bool     ip_mf_flag         = false;
    uint8_t  ip_protocol        = 0;
    uint16_t ip_checksum        = 0;
    bool     ip_checksum_valid  = false;

    // ── new: TCP header extras ────────────────────────────────────────────────
    uint8_t  tcp_data_offset    = 0;
    uint8_t  tcp_reserved_bits  = 0;
    uint16_t tcp_urg_ptr        = 0;
    bool     tcp_checksum_valid = false;

    // ── new: TCP options raw & parsed ─────────────────────────────────────────
    std::vector<uint8_t> tcp_options_raw;
    std::vector<uint8_t> tcp_payload_raw;
    uint16_t    payload_len         = 0;
    std::string tcp_option_layout;           // e.g. "MSS NOP WS SACK TS"
    bool     has_mss                = false;
    uint16_t mss_value              = 0;
    bool     has_eol                = false;
    uint8_t  eol_offset             = 0;
    bool     has_unknown_options    = false;
    std::vector<uint8_t> unknown_option_kinds;
    bool     has_sack_blocks        = false;
    std::vector<std::pair<uint32_t,uint32_t>> sack_blocks;

    // ── new: timing ───────────────────────────────────────────────────────────
    int64_t  kernel_rx_ts_us    = 0;
    int64_t  user_rx_ts_us      = 0;
    int64_t  tx_ts_us           = 0;
    double   rtt_ewma_ms        = 0.0;
    double   rtt_jitter_ms      = 0.0;
    bool     rtt_outlier        = false;
    bool     ttl_outlier        = false;
    int      hop_distance_est   = 0;

    // ── new: probe identity & classification ──────────────────────────────────
    uint32_t flow_hash              = 0;
    uint32_t probe_id               = 0;
    uint32_t response_index         = 0;
    bool     duplicate_response     = false;
    bool     retransmission_suspect = false;
    std::string classification_reason;
    std::vector<std::string> signature_tags;
    int      anomaly_score          = 0;
    double   anomaly_confidence     = 0.0;

    // ── new: sent probe parameters ────────────────────────────────────────────
    uint16_t sent_window_size   = 0;
    uint16_t sent_mss           = 0;
    uint32_t sent_seq           = 0;
    uint32_t sent_ack           = 0;
    uint8_t  sent_dscp          = 0;
    uint8_t  sent_ip_tos        = 0;
    uint16_t sent_ip_id         = 0;
    bool     sent_df            = false;
    bool     sent_sack_permitted= false;
};

enum class IcmpFilterReason {
    None,
    NetAdminProhibited,  // code 9  — ACL/router policy blocks the subnet
    HostAdminProhibited, // code 10 — host firewall / per-IP ACL
    CommAdminProhibited, // code 13 — iptables REJECT or router/firewall policy
};

struct RecPross {
    int closed_ports = 0;
    std::vector<uint16_t> open_ports;      
    std::vector<uint16_t> filtered_ports; 
    // Port → ICMP admin-prohibited reason. Only set when reason is known.
    std::unordered_map<uint16_t, IcmpFilterReason> icmp_filter_reasons;
    std::string mac_address;             
    int learned_rtt_ms = 0;
    std::unordered_map<uint16_t, PacketDetails> packet_details;  
    int packets_sent = 0;
    uint8_t received_ttl = 0;
    std::vector<std::pair<int, double>> rtt_debug_entries;
    std::string output_buffer;
    

    RecPross() = default;
};

struct pseudo_hdr {
    uint32_t src;uint32_t dst;uint8_t placeholder;uint8_t protocol;uint16_t tcp_len;
};

struct PacketTemplate {
    uint8_t ip_hl = 5;uint8_t ip_v = 4;uint8_t ip_tos = 0;uint16_t ip_off = 0;uint8_t ip_p = IPPROTO_TCP;uint16_t th_off = 5;uint16_t th_urp = 0;
};

struct PortState {
    uint16_t src_port;uint32_t seq;uint32_t ack_seq;bool connection_established;bool fin_sent;bool fin_ack_received; std::chrono::steady_clock::time_point start_time;int retry_count;int timeout_ms;
    bool rtt_measured;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;double ewma_rtt; bool final_state_determined;enum class PortReportedState { None, Open, Closed, Filtered };
    PortReportedState reported_state;
};

struct PacketTask {
    sockaddr_in dest; uint16_t src_port;uint32_t seq;uint32_t ack;uint8_t flags;std::string data;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;ScanType scan_type;uint16_t dest_port;
    uint32_t timestamp_val;uint32_t timestamp_ecr;bool include_timestamp;uint8_t window_scale;uint16_t mss_value;uint32_t custom_timestamp;uint32_t timestamp_ecr_custom;uint16_t nops_count;bool sack_permitted;
    std::string custom_data;uint16_t data_length;bool use_custom_data;bool generate_random_data;bool use_badsum;uint16_t custom_badsum_value;bool use_partial_badsum;std::string partial_badsum_type;
    bool use_tfo_cookie;bool tfo_cookie_as_hex;bool tfo_cookie_random;std::string tfo_cookie_str;uint64_t tfo_cookie_num;size_t tfo_cookie_length;
    struct ScanInfo {
        struct ScanTypeData {
            std::string name;
            uint8_t flags;
            bool expects_rst;
            bool analyzes_window;
        };
        static const std::unordered_map<ScanType, ScanTypeData>& get_scan_map() {
            static const std::unordered_map<ScanType, ScanTypeData> scan_map = {
            {ScanType::SYN, {"SYN", TH_SYN, false, false}},
            {ScanType::FIN, {"FIN", TH_FIN, true, false}},
            {ScanType::ACK, {"ACK", TH_ACK, false, false}},
            {ScanType::NULL_SCAN, {"NULL", 0, true, false}},
            {ScanType::XMAS, {"XMAS", TH_FIN | TH_URG | TH_PUSH, true, false}},
            {ScanType::WINDOW, {"WINDOW", TH_ACK, false, true}},
            {ScanType::MAIMON, {"MAIMON", TH_FIN | TH_ACK, true, false}},
            {ScanType::CWR, {"CWR", TH_CWR, true, false}},
            {ScanType::ECE, {"ECE", TH_ECE, true, false}},
            {ScanType::URG, {"URG", TH_URG, true, false}},
            {ScanType::PSH, {"PSH", TH_PUSH, true, false}},
            {ScanType::HANUMAN, {"HANUMAN", TH_CWR | TH_PUSH | TH_URG, true, false}},
            {ScanType::KAKABHUSUNDI, {"KAKABHUSUNDI", TH_ECE | TH_SYN | TH_CWR, false, false}},
            {ScanType::GANESH, {"GANESH", TH_SYN | TH_ECE, false, false}},
            {ScanType::RAM, {"RAM", TH_SYN | TH_CWR | TH_PUSH, false, false}},
            {ScanType::GARUD, {"GARUD", TH_SYN | TH_URG | TH_CWR, false, false}},
            {ScanType::JATAYU, {"JATAYU", TH_SYN | TH_CWR, false, false}}
        };
        return scan_map;
    }
        static const std::unordered_set<ScanType>& get_rst_expecting_scans() {
            static const std::unordered_set<ScanType> rst_scans = {
                ScanType::FIN,ScanType::NULL_SCAN,ScanType::XMAS,ScanType::MAIMON,
                ScanType::CWR,ScanType::ECE,ScanType::URG,ScanType::PSH,ScanType::HANUMAN,ScanType::KAKABHUSUNDI
            };
            return rst_scans;
        }
    };
    PacketTask()noexcept:dest{},src_port(0),seq(0),ack(0),flags(0),data{},syn_sent_time{},sent_tsval(0),scan_type(ScanType::SYN),dest_port(0),timestamp_val(0),timestamp_ecr(0),include_timestamp(false),window_scale(7),mss_value(1460),
                     custom_timestamp(1234567),timestamp_ecr_custom(0),nops_count(0),sack_permitted(true),custom_data(""),data_length(0),use_custom_data(false),generate_random_data(false),use_badsum(false),custom_badsum_value(0),
                     use_partial_badsum(false),partial_badsum_type(""),use_tfo_cookie(false),tfo_cookie_as_hex(false),tfo_cookie_random(false),tfo_cookie_str(""),tfo_cookie_num(0),tfo_cookie_length(0){}
    
    PacketTask(const sockaddr_in& d, uint16_t sp, uint32_t s, uint32_t a, uint8_t f,
               std::string&& dat, std::chrono::steady_clock::time_point sst,uint32_t stv, ScanType type, uint32_t tsval = 0, uint32_t tsecr = 0,
               bool inc_ts = false, uint8_t ws = 7, uint16_t mss = 1460,uint32_t custom_ts = 1234567, uint32_t tsecr_custom = 0,
               uint16_t nops = 0, bool sack = true, const std::string& cdata = "",uint16_t dlen = 0, bool use_cdata = false, bool gen_random = false,
               bool use_bad = false, uint16_t custom_badsum_val = 0,bool use_partial_bad = false, const std::string& partial_bad_type = "",
               bool use_tfo = false, bool tfo_as_hex = false, bool tfo_random = false,const std::string& tfo_str = "", uint64_t tfo_num = 0, size_t tfo_len = 0) noexcept
        : dest(d),src_port(sp),seq(s),ack(a),flags(f),data(std::move(dat)),syn_sent_time(sst),sent_tsval(stv),
          scan_type(type),dest_port(ntohs(d.sin_port)),timestamp_val(tsval),timestamp_ecr(tsecr),include_timestamp(inc_ts),window_scale(ws),
          mss_value(mss),custom_timestamp(custom_ts),timestamp_ecr_custom(tsecr_custom),nops_count(nops),sack_permitted(sack),custom_data(cdata),data_length(dlen),
          use_custom_data(use_cdata),generate_random_data(gen_random),use_badsum(use_bad),custom_badsum_value(custom_badsum_val),use_partial_badsum(use_partial_bad),partial_badsum_type(partial_bad_type),
          use_tfo_cookie(use_tfo),tfo_cookie_as_hex(tfo_as_hex),tfo_cookie_random(tfo_random),tfo_cookie_str(tfo_str),tfo_cookie_num(tfo_num),tfo_cookie_length(tfo_len) {}
    
    PacketTask(PacketTask&& other) noexcept
        : dest(other.dest),src_port(other.src_port),seq(other.seq),ack(other.ack),flags(other.flags),data(std::move(other.data)),syn_sent_time(other.syn_sent_time),sent_tsval(other.sent_tsval),scan_type(other.scan_type),
          dest_port(other.dest_port),timestamp_val(other.timestamp_val),timestamp_ecr(other.timestamp_ecr),include_timestamp(other.include_timestamp),window_scale(other.window_scale),mss_value(other.mss_value),
          custom_timestamp(other.custom_timestamp),timestamp_ecr_custom(other.timestamp_ecr_custom),nops_count(other.nops_count),sack_permitted(other.sack_permitted),custom_data(std::move(other.custom_data)),
          data_length(other.data_length),use_custom_data(other.use_custom_data),generate_random_data(other.generate_random_data),use_badsum(other.use_badsum),custom_badsum_value(other.custom_badsum_value),
          use_partial_badsum(other.use_partial_badsum),partial_badsum_type(std::move(other.partial_badsum_type)),use_tfo_cookie(other.use_tfo_cookie),tfo_cookie_as_hex(other.tfo_cookie_as_hex),
          tfo_cookie_random(other.tfo_cookie_random),tfo_cookie_str(std::move(other.tfo_cookie_str)),tfo_cookie_num(other.tfo_cookie_num),tfo_cookie_length(other.tfo_cookie_length) {}
    
    PacketTask& operator=(PacketTask&& other) noexcept {
        if (this != &other) {
            dest = other.dest;src_port = other.src_port;seq = other.seq;ack = other.ack;flags = other.flags;data = std::move(other.data);syn_sent_time = other.syn_sent_time;sent_tsval = other.sent_tsval;
            scan_type = other.scan_type;dest_port = other.dest_port;timestamp_val = other.timestamp_val;timestamp_ecr = other.timestamp_ecr;include_timestamp = other.include_timestamp;window_scale = other.window_scale;
            mss_value = other.mss_value;custom_timestamp = other.custom_timestamp;timestamp_ecr_custom = other.timestamp_ecr_custom;nops_count = other.nops_count;sack_permitted = other.sack_permitted;
            custom_data = std::move(other.custom_data);data_length = other.data_length;use_custom_data = other.use_custom_data;generate_random_data = other.generate_random_data;use_badsum = other.use_badsum;
            custom_badsum_value = other.custom_badsum_value;use_partial_badsum = other.use_partial_badsum;partial_badsum_type = std::move(other.partial_badsum_type);use_tfo_cookie = other.use_tfo_cookie;
            tfo_cookie_as_hex = other.tfo_cookie_as_hex;tfo_cookie_random = other.tfo_cookie_random;tfo_cookie_str = std::move(other.tfo_cookie_str);tfo_cookie_num = other.tfo_cookie_num;tfo_cookie_length = other.tfo_cookie_length;
        }
        return *this;
    }
    PacketTask(const PacketTask&) = delete;
    PacketTask& operator=(const PacketTask&) = delete;
    ~PacketTask() = default;
    [[nodiscard]] bool has_data() const noexcept { 
        return !data.empty(); 
    }
    [[nodiscard]] std::string get_scan_type_name() const {
        const auto& scan_map = ScanInfo::get_scan_map();
        auto it = scan_map.find(scan_type);
        return (it != scan_map.end()) ? it->second.name : "UNKNOWN";
    }
    [[nodiscard]] static uint8_t get_flags_for_scan_type(ScanType type) noexcept {
        const auto& scan_map = ScanInfo::get_scan_map();
        auto it = scan_map.find(type);
        return (it != scan_map.end()) ? it->second.flags : TH_SYN;
    }
    [[nodiscard]] static bool expects_rst_response(ScanType type) noexcept {
        const auto& rst_scans = ScanInfo::get_rst_expecting_scans();
        return rst_scans.find(type) != rst_scans.end();
    }
    [[nodiscard]] static bool analyzes_window_size(ScanType type) noexcept {
        const auto& scan_map = ScanInfo::get_scan_map();
        auto it = scan_map.find(type);
        return (it != scan_map.end()) ? it->second.analyzes_window : false;
    }
    void set_scan_type(ScanType type) noexcept {
        scan_type = type;
        flags = get_flags_for_scan_type(type);
    }
    [[nodiscard]] float get_window_scale_float() const noexcept {
        return static_cast<float>(window_scale);
    }
    [[nodiscard]] bool set_window_scale(float scale) noexcept {
        if (scale < 0.5f || scale > 30.0f) return false;
        window_scale = static_cast<uint8_t>(std::clamp(scale, 0.5f, 30.0f));
        return true;
    }
    [[nodiscard]] bool set_mss_value(uint16_t mss) noexcept {
        if (mss < 1 || mss > 65535) return false;
        mss_value = mss;
        return true;
    }
    [[nodiscard]] bool set_custom_timestamp(uint32_t ts) noexcept {
        if (ts > 100000000) return false;
        custom_timestamp = ts;
        return true;
    }
    [[nodiscard]] bool set_nops_count(uint16_t nops) noexcept {
        if (nops > 300) return false;
        nops_count = nops;
        return true;
    }
    [[nodiscard]] bool set_tsecr_from_string(const std::string& tsecr_str) noexcept {
        try {
            if (tsecr_str.empty()) {
                timestamp_ecr_custom = 0;
                return true;
            }
            if (tsecr_str.length() > 2 && 
                (tsecr_str.substr(0, 2) == "0x" || tsecr_str.substr(0, 2) == "0X")) {
                timestamp_ecr_custom = std::stoul(tsecr_str.substr(2), nullptr, 16);
            } else {
                timestamp_ecr_custom = std::stoul(tsecr_str);
            }
            return true;
        } catch (...) {
            return false;
        }
    }
    
    [[nodiscard]] std::string get_tsecr_string() const {
        std::stringstream ss;
        ss << "0x" << std::hex << timestamp_ecr_custom << std::dec;
        return ss.str();
    }
    [[nodiscard]] bool set_badsum(bool enable, uint16_t value = 0) noexcept {
        use_badsum = enable;
        if (enable && value != 0) {
            custom_badsum_value = value;
        }
        return true;
    }
    [[nodiscard]] bool set_partial_badsum(bool enable, const std::string& type = "") noexcept {
        use_partial_badsum = enable;
        if (enable && !type.empty()) {
            partial_badsum_type = type;
        }
        return true;
    }
    [[nodiscard]] std::string get_checksum_config_string() const {
        if (use_badsum) {
            return "badsum(" + std::to_string(custom_badsum_value) + ")";
        } 
        if (use_partial_badsum) {
            return "partial_badsum(" + partial_badsum_type + ")";
        }
        return "normal";
    }
    void set_tfo_cookie(const std::string& cookie_str) noexcept {
        use_tfo_cookie = true;tfo_cookie_as_hex = false;tfo_cookie_random = false;tfo_cookie_str = cookie_str;tfo_cookie_num = 0;tfo_cookie_length = 0;
    }
    void set_tfo_cookie_hex(const std::string& hex_str) noexcept {
        use_tfo_cookie = true;tfo_cookie_as_hex = true;tfo_cookie_random = false;tfo_cookie_str = hex_str;tfo_cookie_num = 0;tfo_cookie_length = 0;
    }
    void set_tfo_cookie_random(size_t length) noexcept {
        use_tfo_cookie = true;tfo_cookie_random = true;tfo_cookie_length = std::max<size_t>(length, 4);tfo_cookie_str.clear();tfo_cookie_num = 0;tfo_cookie_as_hex = false;
    }
    void set_tfo_cookie_number(uint64_t num) noexcept {
        use_tfo_cookie = true;tfo_cookie_num = num;tfo_cookie_str.clear();tfo_cookie_random = false;tfo_cookie_as_hex = false;tfo_cookie_length = 0;
    }
    [[nodiscard]] bool get_tfo_cookie_data(std::vector<uint8_t>& cookie_data, 
                                          std::mt19937& rng) const {
        if (!use_tfo_cookie) return false;
        cookie_data.clear();
        if (tfo_cookie_random) {
            size_t cookie_len = tfo_cookie_length;
            if (cookie_len % 2 == 0) {
                cookie_len++;
            }
            cookie_len = std::max<size_t>(cookie_len, 5);
            cookie_data.resize(cookie_len);
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            std::generate(cookie_data.begin(), cookie_data.end(), 
                         [&]() { return byte_dist(rng); });
            
        } else if (tfo_cookie_as_hex) {
            std::string hex_str = tfo_cookie_str;
            if (hex_str.find("0x") == 0 || hex_str.find("0X") == 0) {
                hex_str = hex_str.substr(2);
            }
            if (hex_str.length() % 2 != 0) {
                hex_str = "0" + hex_str;
            }
            cookie_data.reserve(hex_str.length() / 2);
            for (size_t i = 0; i < hex_str.length(); i += 2) {
                std::string byte_str = hex_str.substr(i, 2);
                try {
                    cookie_data.push_back(static_cast<uint8_t>(
                        std::stoul(byte_str, nullptr, 16)));
                } catch (...) {
                    cookie_data.push_back(0);
                }
            }
            if (cookie_data.size() % 2 == 0) {
                cookie_data.push_back(0x01); 
            }
            
        } else if (!tfo_cookie_str.empty()) {
            cookie_data.assign(tfo_cookie_str.begin(), tfo_cookie_str.end());
            
            if (cookie_data.size() % 2 == 0) {
                cookie_data.push_back(0x01);
            }
            
        } else {
            uint64_t num = tfo_cookie_num;
            size_t bytes_needed = 0;
            if (num == 0) {
                bytes_needed = 1;
            } else {
                uint64_t temp = num;
                while (temp > 0) {
                    bytes_needed++;
                    temp >>= 8;
                }
            }
            if (bytes_needed % 2 == 0) bytes_needed++;
            bytes_needed = std::max<size_t>(bytes_needed, 5);
            cookie_data.resize(bytes_needed);
            for (int i = bytes_needed - 1; i >= 0; --i) {
                if (num > 0) {
                    cookie_data[i] = static_cast<uint8_t>(num & 0xFF);
                    num >>= 8;
                } else {
                    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
                    cookie_data[i] = byte_dist(rng);
                }
            }
        }
        
        return !cookie_data.empty();
    }
    
    [[nodiscard]] std::string get_tfo_cookie_info() const {
        if (!use_tfo_cookie) return "none";
        
        if (tfo_cookie_random) {
            return "random(" + std::to_string(tfo_cookie_length) + " bytes)";
        } 
        if (tfo_cookie_as_hex) {
            return "hex(" + tfo_cookie_str + ")";
        } 
        if (!tfo_cookie_str.empty()) {
            return "str(" + tfo_cookie_str + ")";
        }
        
        size_t bytes_needed = 0;
        uint64_t temp = tfo_cookie_num;
        if (temp == 0) bytes_needed = 1;
        else while (temp > 0) { bytes_needed++; temp >>= 8; }
        if (bytes_needed % 2 == 0) bytes_needed++;
        bytes_needed = std::max<size_t>(bytes_needed, 5);
        
        return "num(" + std::to_string(tfo_cookie_num) + " → " + 
               std::to_string(bytes_needed) + " bytes)";
    }
};

class PacketBufferPool {
private:
    thread_local static moodycamel::ConcurrentQueue<char*> buffer_queue;
    thread_local static std::vector<char> slab;
    thread_local static char* slab_start;
    thread_local static char* slab_end;

public:
    static const size_t buffer_size = 4096;

private:
    size_t pool_size;
    size_t max_buffers;
    size_t num_ports;

    size_t get_hardware_concurrency_or_default(size_t default_threads = 2);
    size_t get_buffer_count(size_t ports, size_t num_threads);
    size_t get_max_buffer_count(size_t ports, size_t num_threads);
    void initialize_thread_local_buffers();

public:
    PacketBufferPool(size_t ports, size_t num_threads = 2);
    void initialize_for_worker_thread();
    char* acquire();
    void release(char* buffer);
};


enum class PrintOutputType {
    PORT_RESULT,PORT_RESULT_CUSTOM,SCAN_HEADER,SCAN_SUMMARY,HOST_HEADER,PORT_TABLE_HEADER,HOST_STATUS,NOT_SHOWN_MESSAGE,MAC_ADDRESS,           
    SCAN_TIMING,MULTI_IP_SEPARATOR,THREAD_SUMMARY,OVERALL_HEADER,DOWN_HOSTS_SUMMARY,OVERALL_COMPLETION,INTERRUPTION_MESSAGE, RTT_INFO  
};

void print_output(PrintOutputType type, 
                 const std::string& ip = "",uint16_t port = 0,const std::string& state = "",const std::string& service = "unknown",const std::string& scan_name = "",uint16_t window_size = 0,
                 size_t port_count = 0,size_t open_count = 0,size_t closed_count = 0,size_t filtered_count = 0,size_t host_count = 0,const std::string& mac_address = "",
                 const std::string& vendor = "",double elapsed_seconds = 0.0,const std::string& not_shown_message = "",bool print_timestamp = false,bool show_service = true);
                 
std::string capture_output(PrintOutputType type,
                           const std::string& ip = "",
                           uint16_t port = 0,
                           const std::string& state = "",
                           const std::string& service = "unknown",
                           const std::string& scan_name = "",
                           uint16_t window_size = 0,
                           size_t port_count = 0,
                           size_t open_count = 0,
                           size_t closed_count = 0,
                           size_t filtered_count = 0,
                           size_t host_count = 0,
                           const std::string& mac_address = "",
                           const std::string& vendor = "",
                           double elapsed_seconds = 0.0,
                           const std::string& not_shown_message = "",
                           bool print_timestamp = false,
                           bool show_service = true);

extern std::mutex cout_mutex;
int get_ip_version(const char* ip);
std::string autodetect_interface(uint32_t local_ip);
bool get_interface_mac(int sock, const char* ifname, uint8_t* mac);
bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask);
bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, uint8_t* src_mac, uint8_t* src_ip, uint8_t* target_IP);
bool receive_arp_reply(int sock, struct io_uring* ring, uint8_t* target_ip, uint8_t* mac, int timeout_ms = 1000);
std::string format_mac(const uint8_t* mac);
bool is_same_subnet(uint32_t ip1, uint32_t ip2, uint32_t netmask);
uint32_t get_local_ip(const char *remote_ip);

int send_tcp_packets(int sock, const std::span<PacketTask> tasks, uint32_t src_ip, 
                     std::mt19937 &rng, PacketBufferPool &pool, uint16_t win_size,
                     struct io_uring *send_ring, size_t batch_size, uint8_t custom_ttl,
                     uint8_t custom_dscp, uint16_t custom_ip_flags,
                     IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                     bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum,
                     uint8_t window_scale = 7, uint16_t mss_value = 1460, 
                     uint32_t timestamp_val = 1234567,
                     uint32_t timestamp_ecr_custom = 0, uint16_t nops_count = 0, 
                     bool sack_permitted = true, const std::string& custom_data = "", 
                     uint16_t data_length = 0, bool use_custom_data = false, 
                     bool generate_random_data = false, bool use_badsum = false, 
                     uint16_t custom_badsum_value = 0, bool use_partial_badsum = false, 
                     const std::string& partial_badsum_type = "",
                     bool use_tfo_cookie = false, bool tfo_cookie_as_hex = false, 
                     bool tfo_cookie_random = false, const std::string& tfo_cookie_str = "", 
                     uint64_t tfo_cookie_num = 0, size_t tfo_cookie_length = 0,
                     bool use_fragmentation = false, uint16_t frag_size = 8, 
                     uint16_t mtu_size = 0, bool frag_out_of_order = false,
                     bool frag_overlap = false, uint16_t frag_overlap_bytes = 0, 
                     bool frag_zof = false, bool use_ip_tos = false, 
                     uint8_t custom_ip_tos_byte = 0,PacketLengthConfig packet_length_config = {},std::function<void(const std::vector<uint16_t>&,const std::vector<uint16_t>&)> on_pre_submit = nullptr);
                     

struct SlotMeta {
    struct sockaddr_in src_addr;
    socklen_t          src_len;
    struct iovec       iov;
    struct msghdr      msg;
    // cmsg buffer for SO_TIMESTAMP ancillary data (timeval = 16 bytes + cmsg header = 32 bytes)
    alignas(struct cmsghdr) char cmsg_buf[64];
};

RecPross receive_response(const char *dest_ip, std::span<const int> ports, uint32_t local_ip, 
                      int timeout_ms, std::mt19937 &rng, PacketBufferPool &pool, int send_sock, 
                      uint16_t source_port, uint32_t seq_num, uint16_t win_size, 
                      bool print_individual_closed_filtered, bool print_filtered_if_few, 
                      struct io_uring *send_ring, bool fast_scan, size_t batch_size,
                      ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp, 
                      uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                      bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum,
                      uint8_t window_scale = 7, uint16_t mss_value = 1460, 
                      uint32_t timestamp_val = 1234567,
                      uint32_t timestamp_ecr_custom = 0, uint16_t nops_count = 0, 
                      bool sack_permitted = true, const std::string& custom_data = "", 
                      uint16_t data_length = 0, bool use_custom_data = false, 
                      bool generate_random_data = false,
                      bool use_badsum = false, uint16_t custom_badsum_value = 0,
                      bool use_partial_badsum = false, const std::string& partial_badsum_type = "",
                      bool use_tfo_cookie = false, bool tfo_cookie_as_hex = false, 
                      bool tfo_cookie_random = false, const std::string& tfo_cookie_str = "", 
                      uint64_t tfo_cookie_num = 0, size_t tfo_cookie_length = 0,
                      bool debug_rtt = false, bool debug_ttl = false,
                      bool use_fragmentation = false, uint16_t frag_size = 8, 
                      uint16_t mtu_size = 0, bool frag_out_of_order = false,
                      bool frag_overlap = false, uint16_t frag_overlap_bytes = 0, 
                      bool frag_zof = false, uint16_t sport_range_min = 32768, 
                      uint16_t sport_range_max = 60999, int initial_rtt_ms = 290,
                      int port_timeout_min_ms = 5, int port_timeout_max_ms = 700,
                      RateConfig rate_config = {}, JitterConfig jitter_config = {},
                      BatchDelayConfig batch_delay_config = {}, bool use_ip_tos = false, 
                      uint8_t custom_ip_tos_byte = 0,PacketLengthConfig packet_length_config = {},int recv_sock_in = -1,struct io_uring* recv_ring_in = nullptr,std::vector<SlotMeta>* slots_in = nullptr,uint8_t* recv_bufs_in = nullptr);

void thread_worker(const std::vector<std::string>& thread_ips, const std::vector<int>& ports, 
                   int timeout_ms, PacketBufferPool& pool, int send_sock, std::vector<RecPross>& results, size_t main_batch_size, 
                   uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered, 
                   bool print_filtered_if_few, bool fast_scan, std::atomic<int>& down_hosts_count, ScanType scan_type,
                   uint8_t custom_ttl, uint8_t custom_dscp, uint16_t custom_ip_flags, 
                   IpIdMode ip_id_mode, uint16_t fixed_ip_id, bool use_manual_tcp_checksum, 
                   uint16_t manual_tcp_checksum, uint8_t window_scale = 7, 
                   uint16_t mss_value = 1460, uint32_t timestamp_val = 1234567, 
                   uint32_t timestamp_ecr_custom = 0, uint16_t nops_count = 0, 
                   bool sack_permitted = true, const std::string& custom_data = "", 
                   uint16_t data_length = 0, bool use_custom_data = false, 
                   bool generate_random_data = false, int user_rcvbuf_size = -1, 
                   const std::string& source_ip = "", size_t send_uring_depth = 0, 
                   size_t rcv_uring_depth = 0, bool use_badsum = false, 
                   uint16_t custom_badsum_value = 0, bool use_partial_badsum = false, 
                   const std::string& partial_badsum_type = "", bool use_tfo_cookie = false,
                   bool tfo_cookie_as_hex = false, bool tfo_cookie_random = false,
                   const std::string& tfo_cookie_str = "", uint64_t tfo_cookie_num = 0,
                   size_t tfo_cookie_length = 0, uint16_t base_source_port = 0, 
                   bool debug_packet = false, bool debug_rtt = false, bool debug_wsn = false,
                   bool debug_ttl = false, bool use_fragmentation = false, 
                   uint16_t frag_size = 8, uint16_t mtu_size = 0, bool frag_out_of_order = false,
                   bool frag_overlap = false, uint16_t frag_overlap_bytes = 0, 
                   bool frag_zof = false, uint16_t sport_range_min = 32768, 
                   uint16_t sport_range_max = 60999, int initial_rtt_ms = 290,
                   int port_timeout_min_ms = 5, int port_timeout_max_ms = 700,
                   RateConfig rate_config = {}, JitterConfig jitter_config = {},
                   BatchDelayConfig batch_delay_config = {}, bool use_ip_tos = false, 
                   uint8_t custom_ip_tos_byte = 0,PacketLengthConfig packet_length_config = {}, bool is_threaded = false);

                     
void worker_thread(const char *ip, uint32_t local_ip, const char* source_ip, int timeout_ms, 
                   const std::vector<int>& ports, std::mt19937 &rng, PacketBufferPool &pool, 
                   int send_sock, RecPross &result, size_t main_batch_size, uint32_t seq_num,
                   uint16_t win_size, int ip_version, bool print_individual_closed_filtered, 
                   bool print_filtered_if_few, struct io_uring *send_ring, bool fast_scan,
                   ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp, 
                   uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                   bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum,
                   uint8_t window_scale = 7, uint16_t mss_value = 1460, 
                   uint32_t timestamp_val = 1234567,
                   uint32_t timestamp_ecr_custom = 0, uint16_t nops_count = 0, 
                   bool sack_permitted = true, const std::string& custom_data = "", 
                   uint16_t data_length = 0, bool use_custom_data = false, 
                   bool generate_random_data = false, int user_rcvbuf_size = -1,
                   size_t send_uring_depth = 0, size_t rcv_uring_depth = 0,
                   bool use_badsum = false, uint16_t custom_badsum_value = 0,
                   bool use_partial_badsum = false, const std::string& partial_badsum_type = "",
                   bool use_tfo_cookie = false, bool tfo_cookie_as_hex = false, 
                   bool tfo_cookie_random = false, const std::string& tfo_cookie_str = "", 
                   uint64_t tfo_cookie_num = 0, size_t tfo_cookie_length = 0,
                   uint16_t base_source_port = 0, bool debug_packet = false, 
                   bool debug_rtt = false, bool debug_wsn = false, bool debug_ttl = false,
                   bool use_fragmentation = false, uint16_t frag_size = 8, 
                   uint16_t mtu_size = 0, bool frag_out_of_order = false,
                   bool frag_overlap = false, uint16_t frag_overlap_bytes = 0, 
                   bool frag_zof = false, uint16_t sport_range_min = 32768, 
                   uint16_t sport_range_max = 60999, int initial_rtt_ms = 290,
                   int port_timeout_min_ms = 5, int port_timeout_max_ms = 700,
                   RateConfig rate_config = {}, JitterConfig jitter_config = {},
                   BatchDelayConfig batch_delay_config = {}, bool use_ip_tos = false, 
                   uint8_t custom_ip_tos_byte = 0,PacketLengthConfig packet_length_config = {}, bool is_threaded = false);
                   
bool process_response(PortState& state, uint16_t dest_port, 
                                   struct tcphdr* tcph, int bytes, struct ip* iph,sockaddr_in& dest, moodycamel::ConcurrentQueue<PacketTask>& packet_queue,std::counting_semaphore<65536>& queue_sem,ScanType scan_type, bool fast_scan, RecPross& result,
                                   const std::unordered_map<uint16_t, std::string>& service_map,std::chrono::steady_clock::time_point current_time,uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,
                                   uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,const std::string& custom_data, uint16_t data_length,
                                   bool use_custom_data, bool generate_random_data, bool print_individual_closed_filtered,bool use_badsum, uint16_t custom_badsum_value,
                                   bool use_partial_badsum, const std::string& partial_badsum_type,bool use_tfo_cookie = false, bool tfo_cookie_as_hex = false, bool tfo_cookie_random = false,
                                   const std::string& tfo_cookie_str = "", uint64_t tfo_cookie_num = 0, size_t tfo_cookie_length = 0,std::string* output_buf = nullptr);
                                   
void display_packet_details(const PacketDetails& details, bool debug_enabled);

void print_rtt_debug(const std::vector<std::pair<int, double>>& entries);

void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,uint8_t sent_ws);

void display_ttl_analysis(const std::vector<std::pair<int, double>>& rtt_entries,uint8_t sent_ttl, uint8_t received_ttl,const char* ip, bool host_responded);
                   
bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                     uint8_t* src_mac, uint8_t* src_ip, 
                     const std::vector<uint8_t*>& target_IPs);

bool receive_arp_reply(int sock, struct io_uring* ring, 
                      const std::vector<uint8_t*>& target_IPs,
                      std::vector<uint8_t*>& macs, 
                      int timeout_ms);
                   
#endif
