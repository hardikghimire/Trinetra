#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <shared_mutex>
#include <unordered_set>
#include <array>
#include <errno.h>
#include <vector>
#include <sstream>
#include <span>
#include <poll.h>
#include <algorithm>
#include <thread>
#include <mutex>
#include <shared_mutex>
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
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <ifaddrs.h>
#undef BLOCK_SIZE 
#include <concurrentqueue.h>
#include <blockingconcurrentqueue.h> 

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
extern std::vector<int>          global_raw_sockets;
extern std::vector<io_uring*>    global_uring_rings;
extern std::vector<std::thread*> global_worker_threads;
extern std::mutex                global_resources_mutex;
extern std::atomic<double> g_congestion_ratio;   
extern std::atomic<size_t> g_ports_in_retry_global;
extern std::atomic<size_t> g_active_ports_global;
extern std::atomic<int>    g_dynamic_max_retries; 

// NEW — centralized dynamic-slowdown tuning, all CLI-overridable
struct CongestionTuneConfig {
    uint64_t retry_delay_min_us = 3000;      // --retry-delay-min
    uint64_t retry_delay_max_us = 700000;    // --retry-delay-max
    uint32_t rtt_floor_div      = 4;         // --retry-delay-floor-div
    double   curve_exp          = 2.0;       // --cong-curve
    double   alpha_up           = 0.5;       // --cong-alpha-up
    double   alpha_down         = 0.1;       // --cong-alpha-down
    int      rto_mult           = 4;         // --rto-mult
    int      rto_pad1_ms        = 40;        // --rto-pad1
    int      rto_pad2_ms        = 100;       // --rto-pad2
    double   buf_peak_factor    = 1.3;       // --buf-peak
    unsigned batch_settle_us    = 500;       // --batch-settle
    size_t   sqpoll_threshold   = 300000;    // --sqpoll-threshold
    int      min_retries        = 2;         // NEW — floor, no CLI yet
    int      max_retries        = 5;         // NEW — ceiling, no CLI yet
};

extern CongestionTuneConfig g_cong_tune;
void track_raw_socket(int fd);
void untrack_raw_socket(int fd);
void track_uring_ring(io_uring* ring);
void track_worker_thread(std::thread* t);
void emergency_cleanup();
extern std::atomic<bool> g_send_fixed_file_active;
inline constexpr int SEND_SOCK_FIXED_IDX  = 0;
inline constexpr int SEND6_SOCK_FIXED_IDX = 1;
void signal_handler(int signal);

struct RateConfig {
    bool     enabled       = false;
    uint64_t window_us     = 0;  
    uint32_t min_packets   = 0;   
    uint32_t max_packets   = 0;
    bool     dynamic_mode  = false;
    bool     gate_by_retry = false;
};

struct RateLimiterState {
    uint32_t rate_window_sent    = 0;
    uint32_t rate_window_target  = 0;
    std::chrono::steady_clock::time_point rate_window_start =
        std::chrono::steady_clock::now();
    std::uniform_int_distribution<uint32_t> rate_pkt_dist;
    bool     initialized = false;
};

struct SportRangeConfig {
    bool     stage_is_range[6] = {false, false, false, false, false, false};
    uint16_t stage_min[6]      = {0, 0, 0, 0, 0, 0};
    uint16_t stage_max[6]      = {0, 0, 0, 0, 0, 0};
};

struct GsportConfig {
    bool     stage_is_set[6] = {false, false, false, false, false, false};
    uint16_t stage_port[6]   = {0, 0, 0, 0, 0, 0};
};

inline constexpr uint16_t DEFAULT_RETRY2_SPORT = 8080;

inline constexpr uint16_t RETRY_WEB_SPORTS[6] = {
    0,     // 0 — unused
    80,    // retry 1
    8080,  // retry 2
    8000,  // retry 3
    8443,  // retry 4
    9443   // retry 5
};

inline uint16_t fast_uniform_port(std::mt19937& rng, uint16_t lo, uint16_t hi) {
    uint32_t range  = static_cast<uint32_t>(hi) - static_cast<uint32_t>(lo) + 1u;
    uint64_t rnd    = static_cast<uint64_t>(rng());
    uint64_t mult   = rnd * range;
    uint32_t low32  = static_cast<uint32_t>(mult);
    if (low32 < range) {
        uint32_t threshold = (0xFFFFFFFFu - range + 1u) % range;
        while (low32 < threshold) {
            rnd   = static_cast<uint64_t>(rng());
            mult  = rnd * range;
            low32 = static_cast<uint32_t>(mult);
        }
    }
    return static_cast<uint16_t>(lo + static_cast<uint32_t>(mult >> 32));
}

struct JitterConfig {
    bool     enabled      = false;
    bool     random_mode  = false;  
    uint64_t delay_us     = 0;      
};

struct BatchDelayConfig {
    bool     enabled      = false;
    bool     random_mode  = false;  
    bool     range_mode   = false;  
    uint64_t delay_us     = 0;      
    uint64_t min_us       = 0;      
    uint64_t max_us       = 0;
    bool     dynamic_mode = false;       
};


double estimate_scan_duration_ms(size_t batch_probe_volume,
                                  const RateConfig&       rate_cfg,
                                  const JitterConfig&     jitter_cfg,
                                  const BatchDelayConfig& batch_delay_cfg,
                                  int initial_rtt_ms);
                                  
struct BandwidthConfig {
    bool     enabled         = false;
    uint64_t window_us       = 0;
    uint64_t total_bytes_min = 0;
    uint64_t total_bytes_max = 0;
};

struct BandwidthLimiterState {
    std::chrono::steady_clock::time_point window_start =
        std::chrono::steady_clock::now();
    uint64_t              reserved_bytes       = 0;
    std::atomic<uint64_t> actual_bytes_sent{0};
    uint64_t              window_target_bytes  = 0;  
    bool                  initialized = false;
};

struct PacketLengthConfig {
    bool     enabled    = false;
    uint16_t target_len = 0;   // N from --packet-length <N>
};

enum class IpIdMode {
    RANDOM,       
    SEQUENTIAL,   
    ZERO,         
    FIXED,        
    IPROFILE,     
    TIME          
};

enum class HopOptKind  { NONE, ALERT, JUMBO, PAD, UNKNOWN };
enum class DestOptKind { NONE, HOME, TUNNEL, PAD, MALFORMED, UNKNOWN };
enum class RouteHdrType  { NONE, TYPE0, TYPE2, SRH, INVALID };
enum class AhMode        { NONE, VALID, BADSPI, NOICV, BADLEN, SEQ0 };
enum class EspMode       { NONE, VALID, BADPAD, BADSPI, NOIV, MALFORMED };
enum class FlowLabelMode { NONE, FIXED, RANDOM, INCREMENT };
enum class ChainMode { NONE, RAND, REVERSE, CUSTOM, DUP, UNKNOWN, SPLIT };
enum class StopMode  { NONE, FIRST, HOP, DEST, ROUTE, ALL };

// RFC 8200 §4.2 / IANA "Destination Options and Hop-by-Hop Options" registry.
inline constexpr uint8_t IP6OPT_PAD1_T         = 0x00;
inline constexpr uint8_t IP6OPT_PADN_T         = 0x01;
inline constexpr uint8_t IP6OPT_ROUTER_ALERT_T = 0x05;  // HBH only  (RFC 2711)
inline constexpr uint8_t IP6OPT_JUMBO_T        = 0xC2;  // HBH only  (RFC 2675)
inline constexpr uint8_t IP6OPT_TUNNEL_LIMIT_T = 0x04;  // Dest only (RFC 2473)
inline constexpr uint8_t IP6OPT_HOME_ADDRESS_T = 0xC9;  // Dest only (RFC 6275)
// Routing Header types (IANA "IPv6 Routing Types" registry).
inline constexpr uint8_t IP6_ROUTE_TYPE0 = 0;   // RFC 5095 — deprecated
inline constexpr uint8_t IP6_ROUTE_TYPE2 = 2;   // RFC 6275 — Mobile IPv6
inline constexpr uint8_t IP6_ROUTE_SRH   = 4;   // RFC 8754 — Segment Routing
inline constexpr uint32_t IP6_ROUTE_SEG_MAX  = 16;      // cap so header <= IP6_EXT_HDR_CAP
inline constexpr uint32_t IP6_FLOW_LABEL_MAX = 0xFFFFF; // 20-bit field, RFC 8200 §3
inline constexpr uint8_t  IP6_NO_NEXT_HEADER = 59;       // RFC 8200 §4.7 "No Next Header", for --stop
inline constexpr uint32_t IP6_CHAIN_DUP_MAX  = 8;  
inline constexpr uint32_t IP6_HOP_PAD_MAX  = 256;
inline constexpr uint32_t IP6_DEST_PAD_MAX = 256;
inline constexpr uint32_t IP6_JUMBO_MIN    = 65536;  // RFC 2675 floor
inline constexpr uint32_t IP6_TUNNEL_MAX   = 255;    // 1-byte field
inline constexpr size_t   IP6_EXT_HDR_CAP  = 320;    // per-header buffer size

struct Ipv6ExtHeaderOptions {
    bool        use_hop_opts      = false;
    HopOptKind  hop_kind          = HopOptKind::NONE;
    uint32_t    hop_value         = 0;      // alert flag / jumbo length / pad length
    uint8_t     hop_unknown_type  = 0x3E;   // raw option-type byte, --hop unknown:N

    bool        use_dest_opts     = false;
    DestOptKind dest_kind         = DestOptKind::NONE;
    uint32_t    dest_value        = 0;      // tunnel limit / pad length
    uint8_t     dest_unknown_type = 0x3E;   // raw option-type byte, --dest unknown:N
    struct in6_addr dest_home_addr = {};    // optional value, --dest home:<addr>
    bool        dest_home_addr_set = false;

    // --route
    bool          use_route_hdr  = false;
    RouteHdrType  route_kind     = RouteHdrType::NONE;
    uint32_t      route_segments = 0;   // Type0/SRH segment count (0 allowed)
    uint8_t       route_raw_type = 0;   // --route <N> with N not in {0,2,srh} → INVALID, raw type byte

    // --ah
    bool    use_ah  = false;
    AhMode  ah_mode = AhMode::NONE;

    // --esp
    bool    use_esp  = false;
    EspMode esp_mode = EspMode::NONE;

    // --flow
    bool          use_flow_label = false;
    FlowLabelMode flow_mode      = FlowLabelMode::NONE;
    uint32_t      flow_value     = 0;   // fixed value for FIXED mode

    // --chain
    ChainMode             chain_mode          = ChainMode::NONE;
    std::vector<uint8_t>  chain_custom_order;        // --chain custom:AH,ESP,HBH -> IPPROTO_* values in order
    uint8_t               chain_dup_target    = 0;   // --chain dup:<hop|dest|route|ah> -> IPPROTO_* value
    uint32_t              chain_dup_count     = 2;   // --chain dup:route:2 -> total occurrences (default 2)
    uint8_t               chain_unknown_value = 0;   // --chain unknown:N -> raw next-header value to inject

    // --stop
    StopMode  stop_mode   = StopMode::NONE;
    uint32_t  stop_dest_n = 1;   // --stop dest:2 -> Nth Destination Options occurrence (1-indexed)
};

// Parses --dest's <option>[:<value>]. Same contract as parse_hop_option().

// Parses --ah's <mode>: yes|badspi|noicv|badlen|seq0

// Parses --esp's <mode>: yes|badpad|badspi|noiv|bad

// Parses --flow's <value>: a 0-1048575 number, "0", "rand", or "inc".

// Maps a --chain custom:... token to its IPPROTO_* value.

// Parses --chain's <option>[:<value>]. Returns false (message on stderr,
// `out` left untouched) on anything malformed or out of range.

// Parses --stop's <position>[:<value>]. Returns false (message on stderr,
// `out` left untouched) on anything malformed or out of range.

struct TcpBuildOptions {
    bool        use_ip_tos              = false;
    uint8_t     custom_ip_tos_byte      = 0;

    bool        use_manual_tcp_checksum = false;
    uint16_t    manual_tcp_checksum     = 0;

    uint8_t     window_scale            = 7;
    uint16_t    mss_value               = 1460;
    uint32_t    timestamp_val           = 1234567;
    uint32_t    timestamp_ecr_custom    = 0;
    uint16_t    nops_count              = 0;
    bool        sack_permitted          = true;

    std::string custom_data;
    uint16_t    data_length             = 0;
    bool        use_custom_data         = false;
    bool        generate_random_data    = false;

    bool        use_badsum              = false;
    uint16_t    custom_badsum_value     = 0;
    bool        badsum_value_set        = false;
    bool        use_partial_badsum      = false;
    std::string partial_badsum_type;

    bool        use_tfo_cookie          = false;
    bool        tfo_cookie_as_hex       = false;
    bool        tfo_cookie_random       = false;
    std::string tfo_cookie_str;
    uint64_t    tfo_cookie_num          = 0;
    size_t      tfo_cookie_length       = 0;

    bool        use_fragmentation       = false;
    uint16_t    frag_size               = 8;
    uint16_t    mtu_size                = 0;
    bool        use_tcp_mptcp          = false;

    bool        use_tcp_ao             = false;
    uint8_t     tcp_ao_keyid           = 1;
    uint8_t     tcp_ao_rnextkeyid      = 1;
    uint8_t     tcp_ao_mac_len         = 12;

    bool        use_ip_router_alert    = false;

    bool        use_ip_security        = false;
    uint8_t     ip_security_classification = 0x01;   // RFC1108: 0x01 = Unclassified

    PacketLengthConfig packet_length_config{};
    Ipv6ExtHeaderOptions ipv6_ext_opts{};
};

enum class ArpOpMode { REQUEST, REPLY, GRATUITOUS };

struct EthArpOptions {
    bool     use_custom_src_mac    = false;              // item 2
    uint8_t  custom_src_mac[6]     = {0,0,0,0,0,0};

    bool     use_custom_dst_mac    = false;              // item 3
    uint8_t  custom_dst_mac[6]     = {0,0,0,0,0,0};

    bool     use_custom_ethertype  = false;              // item 1
    uint16_t custom_ethertype      = ETH_P_ARP;

    std::vector<uint16_t> vlan_ids;                      // item 4 (1 entry) / item 5 (2 entries)

    uint16_t padding_size          = 0;                  // item 7
    bool     random_padding        = false;

    ArpOpMode arp_mode              = ArpOpMode::REQUEST; // item 9 (named arp_mode, NOT arp_op — see note above)
};

enum class ScanType { SYN, FIN, ACK, NULL_SCAN, XMAS, WINDOW, MAIMON, CWR, ECE, URG, PSH, HANUMAN, KAKABHUSUNDI, GANESH, RAM, GARUD, JATAYU };

inline size_t estimate_packet_wire_bytes(const TcpBuildOptions& opts, ScanType scan_type) {
    constexpr size_t IP_HDR_LEN  = 20;
    constexpr size_t TCP_HDR_LEN = 20;
    constexpr size_t MAX_OPTS    = 40;

    size_t opt_len = 0;
    if (!(scan_type == ScanType::NULL_SCAN || scan_type == ScanType::XMAS))
        opt_len += 4;                                   // MSS
    if (opts.window_scale > 0)      opt_len += 3;        // window scale
    if (opts.sack_permitted)        opt_len += 2;        // SACK-permitted
    if (opts.timestamp_val != 0)    opt_len += 10;       // timestamp
    if (opts.use_tcp_mptcp) opt_len += std::min(size_t(12), MAX_OPTS - opt_len);
    if (opts.use_tcp_ao)    opt_len += std::min(size_t(4 + opts.tcp_ao_mac_len), MAX_OPTS - opt_len);
    if (opts.use_tfo_cookie) {
        size_t cookie_len = opts.tfo_cookie_length ? opts.tfo_cookie_length : 8;
        opt_len += std::min(cookie_len + 2, MAX_OPTS - opt_len);
    }
    opt_len = std::min(opt_len, MAX_OPTS);
    opt_len = (opt_len + 3) & ~size_t(3);                // word-align, like build_packet's NOP pad

    size_t data_len = 0;
    if (opts.use_custom_data)                          data_len = opts.custom_data.size();
    else if (opts.generate_random_data || opts.data_length > 0) data_len = opts.data_length;
    size_t ip_opt_len = 0;
    if (opts.use_ip_router_alert) ip_opt_len += 4;
    if (opts.use_ip_security)     ip_opt_len += 11;
    ip_opt_len = (ip_opt_len + 3) & ~size_t(3);

    return IP_HDR_LEN + TCP_HDR_LEN + opt_len + data_len;
}

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
            // NEW:
	    } catch (const std::exception& e) {
	        std::cerr << "RAIIManager cleanup threw: " << e.what() << std::endl;
	    } catch (...) {
	        std::cerr << "RAIIManager cleanup threw unknown exception" << std::endl;
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

// ── TX-side debug: mirrors PacketDetails, but for what was actually built
// and queued to send, not what came back. Populated in build_packet().
struct SentPacketDetails {
    std::string dst_ip;
    uint16_t    dst_port          = 0;
    uint16_t    src_port          = 0;

    // IP header
    uint16_t    ip_id             = 0;
    uint16_t    ip_total_length   = 0;
    uint8_t     ip_header_len     = 0;
    uint8_t     ttl               = 0;
    uint8_t     ip_tos            = 0;
    bool        df_flag           = false;
    bool        mf_flag           = false;
    uint16_t    ip_frag_off_raw   = 0;
    uint16_t    ip_checksum       = 0;
    // IPv6-only fields (populated when is_ipv6 == true; meaningless otherwise)
    bool        is_ipv6           = false;
    uint8_t     traffic_class     = 0;
    uint32_t    flow_label        = 0;
    uint8_t     next_header       = 0;

    // TCP header
    uint8_t     tcp_flags         = 0;
    uint32_t    seq_num           = 0;
    uint32_t    ack_num           = 0;
    uint16_t    window_size       = 0;
    uint8_t     tcp_header_len    = 0;
    uint8_t     tcp_data_offset   = 0;
    uint16_t    tcp_urg_ptr       = 0;
    uint16_t    checksum          = 0;
    std::string checksum_mode;      // "normal" / "manual" / "badsum" / "partial-badsum:<type>"

    // TCP options
    std::string tcp_option_layout;
    size_t      options_len        = 0;
    bool        has_mss            = false;  uint16_t mss_value       = 0;
    bool        has_window_scale   = false;  uint8_t  window_scale    = 0;
    bool        sack_permitted     = false;
    bool        has_timestamp      = false;  uint32_t tsval = 0, tsecr = 0;
    bool        has_tfo            = false;  size_t   tfo_cookie_len  = 0;
    bool        has_mptcp          = false;
    bool        has_tcp_ao         = false;

    // Payload / sizing
    uint16_t    payload_len         = 0;
    std::vector<uint8_t> payload_preview;   // first N bytes only
    size_t      total_packet_len    = 0;

    // Fragmentation
    bool        fragmented          = false;
    uint16_t    frag_step           = 0;     // 0 = not fragmented

    // Misc / provenance
    bool        intentional_malformed = false;
    bool        packet_length_adjusted = false;
    uint16_t    packet_length_target   = 0;   // --packet-length N, if it fired
    int         retry_index         = 0;
};

enum class IcmpFilterReason {
    None,
    // ── existing: admin-prohibited (filtered ports) ───────────────────────────
    NetAdminProhibited,      // type 3 code 9  — ACL/router policy blocks subnet
    HostAdminProhibited,     // type 3 code 10 — host firewall / per-IP ACL
    CommAdminProhibited,     // type 3 code 13 — iptables REJECT / firewall policy
    // ── fatal: scan aborted on detection ─────────────────────────────────────
    ProtoUnreachable,        // type 3 code 2  — protocol not supported by host
    SrcRouteFailed,          // type 3 code 5  — source route failed
    NetUnknown,              // type 3 code 6  — destination network unknown
    HostUnknown,             // type 3 code 7  — destination host unknown
    SrcHostIsolated,         // type 3 code 8  — source host isolated
    HostPrecViolation,       // type 3 code 14 — host precedence violation
    NoRoute,                 // type 1 code 0  — no route to destination
    // ── warnings: non-fatal, printed after scan in reason section ─────────────
    FragNeeded,              // type 3 code 4  — fragmentation needed, DF set
    TtlExpired,              // type 11 code 0 — TTL expired in transit
    FragReassemblyTimeout,   // type 11 code 1 — fragment reassembly time exceeded
    BadSpi,                  // type 40 code 0 — bad security parameters index
};

struct DemuxDebugEntry {
    std::string target;         // dest IP this event belongs to — needed
                                 // once entries from several targets are
                                 // merged for a multi-IP scan's report
    uint16_t    port     = 0;   // scanned port the event concerns
    std::string tag;            // "MATCH", "DROP unknown-port", ...
    std::string detail;         // free-form extra context (ack/seq mismatch, etc.)
    uint16_t    src_port = 0;   // our source port on the triggering packet
    uint8_t     flags    = 0;   // raw TCP flags (0 for pure-ICMP events)
    int         attempt  = -1;  // probe attempt this reply matches:
                                 // 0 = initial SYN, 1 = 1st retry, 2 = 2nd
                                 // retry, -1 = unknown (port isn't ours)
    uint8_t     ttl      = 0;   // IP TTL on the triggering packet (0 = n/a)
    bool        is_icmp  = false; // came from the ICMP-filtered path, not raw TCP
};

// Aggregate counters for a target's --debug demux session, accumulated
// across every batch of receive_response() calls for that target.
struct DemuxDebugCounters {
    uint64_t matched      = 0;  // passed every demux check, handed to process_response
    uint64_t unknown_port = 0;  // dest/blocked port isn't part of this scan
    uint64_t bad_src_port = 0;  // right port, but src port we never sent from
    uint64_t bad_token    = 0;  // ACK/seq didn't match our SYN token — spoofed/stale
    uint64_t stale_rst    = 0;  // RST for a port with no outstanding probe

    DemuxDebugCounters& operator+=(const DemuxDebugCounters& o) {
        matched      += o.matched;
        unknown_port += o.unknown_port;
        bad_src_port += o.bad_src_port;
        bad_token    += o.bad_token;
        stale_rst    += o.stale_rst;
        return *this;
    }
};

enum class StrackFinalState : uint8_t { None, Open, Closed, Filtered };

struct StrackEntry {
    uint16_t          port             = 0;
    StrackFinalState  final_state      = StrackFinalState::None;
    int               resolved_attempt = -1;   // 0-5 = answered on that attempt, -1 = never answered
    uint16_t          src_port         = 0;    // src port the resolving packet used (0 if never answered)
    double            rtt_ms           = -1.0; // -1 = not measured
    bool              is_icmp          = false;
    int                     attempts_sent          = 0;   // total probes sent (1 = initial only)
    std::array<uint16_t, 6> attempt_src_ports{};          // src port used per attempt
    std::array<uint8_t, 6>  attempt_src_port_nums{};      // which attempt number each entry belongs to
    uint8_t                 attempt_src_port_count = 0;
};

struct StrackCounters {
    uint64_t resolved_attempt[6] = {0, 0, 0, 0, 0, 0};
    uint64_t unresolved          = 0;
    uint64_t total_ports_tracked = 0;
    uint64_t total_packets_sent  = 0;

    StrackCounters& operator+=(const StrackCounters& o) {
        for (int i = 0; i < 6; ++i) resolved_attempt[i] += o.resolved_attempt[i];
        unresolved          += o.unresolved;
        total_ports_tracked += o.total_ports_tracked;
        total_packets_sent  += o.total_packets_sent;
        return *this;
    }
};

struct RecPross {
    int closed_ports = 0;
    std::vector<uint16_t> open_ports;
    std::vector<uint16_t> filtered_ports;
    // Port → ICMP admin-prohibited reason. Only set when reason is known.
    std::unordered_map<uint16_t, IcmpFilterReason> icmp_filter_reasons;
    std::vector<std::pair<IcmpFilterReason, std::string>> icmp_warnings;
    std::string mac_address;
    int learned_rtt_ms = 0;
    std::unordered_map<uint16_t, PacketDetails> packet_details;
    int packets_sent = 0;
    uint8_t received_ttl = 0;
    std::vector<std::pair<int, double>> rtt_debug_entries;
    std::vector<DemuxDebugEntry> demux_debug_entries;
    DemuxDebugCounters           demux_counts;
    std::vector<StrackEntry>     strack_entries;
    StrackCounters               strack_counts;
    std::string output_buffer;

    RecPross() = default;
};

struct pseudo_hdr {
    uint32_t src;uint32_t dst;uint8_t placeholder;uint8_t protocol;uint16_t tcp_len;
};

struct pseudo_hdr6 {
    uint8_t  src[16];
    uint8_t  dst[16];
    uint32_t tcp_len;   // network byte order
    uint8_t  zeros[3];
    uint8_t  next_header;
};

struct PacketTemplate {
    uint8_t ip_hl = 5;uint8_t ip_v = 4;uint8_t ip_tos = 0;uint16_t ip_off = 0;uint8_t ip_p = IPPROTO_TCP;uint16_t th_off = 5;uint16_t th_urp = 0;
};

struct PortState {
    uint16_t src_port;uint32_t seq;uint32_t ack_seq;bool connection_established;bool fin_sent;bool fin_ack_received; std::chrono::steady_clock::time_point start_time;int retry_count;int timeout_ms;int retries_cap = 2;
    bool rtt_measured;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;double ewma_rtt; bool final_state_determined;enum class PortReportedState { None, Open, Closed, Filtered };
    PortReportedState reported_state;
    std::array<uint16_t, 6> used_src_ports{};
    std::array<uint8_t, 6>  used_src_port_attempt{}; 
    uint8_t                 used_src_port_count = 0;
    bool                    retry_send_deferred = false;
    bool                    initial_send_deferred = false;
    bool                    counted_in_retry    = false;

    void record_src_port(uint16_t p, int attempt) {
        for (uint8_t i = 0; i < used_src_port_count; ++i)
            if (used_src_ports[i] == p) return;
        if (used_src_port_count < used_src_ports.size()) {
            used_src_ports[used_src_port_count]         = p;
            used_src_port_attempt[used_src_port_count]  = static_cast<uint8_t>(attempt);
            used_src_port_count++;
        }
    }
    int attempt_for_src_port(uint16_t p) const {
        if (p == src_port) return retry_count;
        for (uint8_t i = 0; i < used_src_port_count; ++i)
            if (used_src_ports[i] == p) return used_src_port_attempt[i];
        return retry_count;
    }
    bool accepts_src_port(uint16_t p) const {
        if (p == src_port) return true;
        for (uint8_t i = 0; i < used_src_port_count; ++i)
            if (used_src_ports[i] == p) return true;
        return false;
    }
};

struct PacketTask {
    sockaddr_in dest; sockaddr_in6 dest6{}; bool is_ipv6 = false; uint16_t src_port;uint32_t seq;uint32_t ack;uint8_t flags;std::string data;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;ScanType scan_type;uint16_t dest_port;
    uint32_t timestamp_val;uint32_t timestamp_ecr;bool include_timestamp;uint8_t window_scale;uint16_t mss_value;uint32_t custom_timestamp;uint32_t timestamp_ecr_custom;uint16_t nops_count;bool sack_permitted;
    std::string custom_data;uint16_t data_length;bool use_custom_data;bool generate_random_data;bool use_badsum;uint16_t custom_badsum_value;bool use_partial_badsum;std::string partial_badsum_type;
    bool use_tfo_cookie;bool tfo_cookie_as_hex;bool tfo_cookie_random;std::string tfo_cookie_str;uint64_t tfo_cookie_num;size_t tfo_cookie_length;bool is_poison = false;
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
    PacketTask()noexcept:dest{},dest6{},is_ipv6(false),src_port(0),seq(0),ack(0),flags(0),data{},syn_sent_time{},sent_tsval(0),scan_type(ScanType::SYN),dest_port(0),timestamp_val(0),timestamp_ecr(0),include_timestamp(false),window_scale(7),mss_value(1460),
                     custom_timestamp(1234567),timestamp_ecr_custom(0),nops_count(0),sack_permitted(true),custom_data(""),data_length(0),use_custom_data(false),generate_random_data(false),use_badsum(false),custom_badsum_value(0),
                     use_partial_badsum(false),partial_badsum_type(""),use_tfo_cookie(false),tfo_cookie_as_hex(false),tfo_cookie_random(false),tfo_cookie_str(""),tfo_cookie_num(0),tfo_cookie_length(0){}
    
    PacketTask(const sockaddr_in& d, uint16_t sp, uint32_t s, uint32_t a, uint8_t f,
               std::string&& dat, std::chrono::steady_clock::time_point sst,uint32_t stv, ScanType type, uint32_t tsval = 0, uint32_t tsecr = 0,
               bool inc_ts = false, uint8_t ws = 7, uint16_t mss = 1460,uint32_t custom_ts = 1234567, uint32_t tsecr_custom = 0,
               uint16_t nops = 0, bool sack = true, const std::string& cdata = "",uint16_t dlen = 0, bool use_cdata = false, bool gen_random = false,
               bool use_bad = false, uint16_t custom_badsum_val = 0,bool use_partial_bad = false, const std::string& partial_bad_type = "",
               bool use_tfo = false, bool tfo_as_hex = false, bool tfo_random = false,const std::string& tfo_str = "", uint64_t tfo_num = 0, size_t tfo_len = 0) noexcept
        : dest(d),dest6{},is_ipv6(false),src_port(sp),seq(s),ack(a),flags(f),data(std::move(dat)),syn_sent_time(sst),sent_tsval(stv),
          scan_type(type),dest_port(ntohs(d.sin_port)),timestamp_val(tsval),timestamp_ecr(tsecr),include_timestamp(inc_ts),window_scale(ws),
          mss_value(mss),custom_timestamp(custom_ts),timestamp_ecr_custom(tsecr_custom),nops_count(nops),sack_permitted(sack),custom_data(cdata),data_length(dlen),
          use_custom_data(use_cdata),generate_random_data(gen_random),use_badsum(use_bad),custom_badsum_value(custom_badsum_val),use_partial_badsum(use_partial_bad),partial_badsum_type(partial_bad_type),
          use_tfo_cookie(use_tfo),tfo_cookie_as_hex(tfo_as_hex),tfo_cookie_random(tfo_random),tfo_cookie_str(tfo_str),tfo_cookie_num(tfo_num),tfo_cookie_length(tfo_len) {}
    PacketTask(const sockaddr_in6& d6, uint16_t sp, uint32_t s, uint32_t a, uint8_t f,
               std::string&& dat, std::chrono::steady_clock::time_point sst,uint32_t stv, ScanType type, uint32_t tsval = 0, uint32_t tsecr = 0,
               bool inc_ts = false, uint8_t ws = 7, uint16_t mss = 1460,uint32_t custom_ts = 1234567, uint32_t tsecr_custom = 0,
               uint16_t nops = 0, bool sack = true, const std::string& cdata = "",uint16_t dlen = 0, bool use_cdata = false, bool gen_random = false,
               bool use_bad = false, uint16_t custom_badsum_val = 0,bool use_partial_bad = false, const std::string& partial_bad_type = "",
               bool use_tfo = false, bool tfo_as_hex = false, bool tfo_random = false,const std::string& tfo_str = "", uint64_t tfo_num = 0, size_t tfo_len = 0) noexcept
        : dest{},dest6(d6),is_ipv6(true),src_port(sp),seq(s),ack(a),flags(f),data(std::move(dat)),syn_sent_time(sst),sent_tsval(stv),
          scan_type(type),dest_port(ntohs(d6.sin6_port)),timestamp_val(tsval),timestamp_ecr(tsecr),include_timestamp(inc_ts),window_scale(ws),
          mss_value(mss),custom_timestamp(custom_ts),timestamp_ecr_custom(tsecr_custom),nops_count(nops),sack_permitted(sack),custom_data(cdata),data_length(dlen),
          use_custom_data(use_cdata),generate_random_data(gen_random),use_badsum(use_bad),custom_badsum_value(custom_badsum_val),use_partial_badsum(use_partial_bad),partial_badsum_type(partial_bad_type),
          use_tfo_cookie(use_tfo),tfo_cookie_as_hex(tfo_as_hex),tfo_cookie_random(tfo_random),tfo_cookie_str(tfo_str),tfo_cookie_num(tfo_num),tfo_cookie_length(tfo_len) {}
    
    PacketTask(PacketTask&& other) noexcept
        : dest(other.dest),dest6(other.dest6),is_ipv6(other.is_ipv6),src_port(other.src_port),seq(other.seq),ack(other.ack),flags(other.flags),data(std::move(other.data)),syn_sent_time(other.syn_sent_time),sent_tsval(other.sent_tsval),scan_type(other.scan_type),
          dest_port(other.dest_port),timestamp_val(other.timestamp_val),timestamp_ecr(other.timestamp_ecr),include_timestamp(other.include_timestamp),window_scale(other.window_scale),mss_value(other.mss_value),
          custom_timestamp(other.custom_timestamp),timestamp_ecr_custom(other.timestamp_ecr_custom),nops_count(other.nops_count),sack_permitted(other.sack_permitted),custom_data(std::move(other.custom_data)),
          data_length(other.data_length),use_custom_data(other.use_custom_data),generate_random_data(other.generate_random_data),use_badsum(other.use_badsum),custom_badsum_value(other.custom_badsum_value),
          use_partial_badsum(other.use_partial_badsum),partial_badsum_type(std::move(other.partial_badsum_type)),use_tfo_cookie(other.use_tfo_cookie),tfo_cookie_as_hex(other.tfo_cookie_as_hex),
          tfo_cookie_random(other.tfo_cookie_random),tfo_cookie_str(std::move(other.tfo_cookie_str)),tfo_cookie_num(other.tfo_cookie_num),tfo_cookie_length(other.tfo_cookie_length),is_poison(other.is_poison) {}
    
    PacketTask& operator=(PacketTask&& other) noexcept {
        if (this != &other) {
            dest = other.dest;dest6 = other.dest6;is_ipv6 = other.is_ipv6;src_port = other.src_port;seq = other.seq;ack = other.ack;flags = other.flags;data = std::move(other.data);syn_sent_time = other.syn_sent_time;sent_tsval = other.sent_tsval;
            scan_type = other.scan_type;dest_port = other.dest_port;timestamp_val = other.timestamp_val;timestamp_ecr = other.timestamp_ecr;include_timestamp = other.include_timestamp;window_scale = other.window_scale;
            mss_value = other.mss_value;custom_timestamp = other.custom_timestamp;timestamp_ecr_custom = other.timestamp_ecr_custom;nops_count = other.nops_count;sack_permitted = other.sack_permitted;
            custom_data = std::move(other.custom_data);data_length = other.data_length;use_custom_data = other.use_custom_data;generate_random_data = other.generate_random_data;use_badsum = other.use_badsum;
            custom_badsum_value = other.custom_badsum_value;use_partial_badsum = other.use_partial_badsum;partial_badsum_type = std::move(other.partial_badsum_type);use_tfo_cookie = other.use_tfo_cookie;
            tfo_cookie_as_hex = other.tfo_cookie_as_hex;tfo_cookie_random = other.tfo_cookie_random;tfo_cookie_str = std::move(other.tfo_cookie_str);tfo_cookie_num = other.tfo_cookie_num;tfo_cookie_length = 
            other.tfo_cookie_length;is_poison = other.is_poison;
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
            std::generate(cookie_data.begin(), cookie_data.end(), 
                         [&]() { return static_cast<uint8_t>(rng()); });
            
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
                    cookie_data[i] = static_cast<uint8_t>(rng());
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
    size_t get_buffer_count(size_t ports, size_t num_threads, size_t batch_size);
    size_t get_max_buffer_count(size_t ports, size_t num_threads, size_t batch_size);
    void initialize_thread_local_buffers();

public:
    PacketBufferPool(size_t ports, size_t num_threads = 2, size_t batch_size = 0);
    void initialize_for_worker_thread();
    char* acquire();
    void release(char* buffer);
};

enum class PrintOutputType {
    PORT_RESULT,PORT_RESULT_CUSTOM,SCAN_HEADER,SCAN_SUMMARY,HOST_HEADER,PORT_TABLE_HEADER,HOST_STATUS,NOT_SHOWN_MESSAGE,MAC_ADDRESS,           
    SCAN_TIMING,MULTI_IP_SEPARATOR,THREAD_SUMMARY,OVERALL_HEADER,DOWN_HOSTS_SUMMARY,OVERALL_COMPLETION,INTERRUPTION_MESSAGE, RTT_INFO, CPU_TIME  
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
extern std::mutex sent_debug_mutex;
extern std::vector<SentPacketDetails> sent_debug_log;
int get_ip_version(const char* ip);
std::string autodetect_interface(uint32_t local_ip);
bool get_interface_mac(int sock, const char* ifname, uint8_t* mac);
bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask);
bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                     uint8_t* src_mac, uint8_t* src_ip, 
                     const std::vector<uint8_t*>& target_IPs,
                     const EthArpOptions& eth_opts = EthArpOptions{});
                     
                     
                      
                      
std::string format_mac(const uint8_t* mac);
bool is_same_subnet(uint32_t ip1, uint32_t ip2, uint32_t netmask);
bool is_private_lan_ip(const uint8_t ip[4]);
uint32_t get_local_ip(const char *remote_ip);
bool set_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4], const uint8_t mac[6]);
void delete_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4]);

int send_tcp_packets(int sock, const std::span<PacketTask> tasks, uint32_t src_ip, 
                     std::mt19937 &rng, PacketBufferPool &pool, uint16_t win_size,
                     struct io_uring *send_ring, size_t batch_size, uint8_t custom_ttl,
                     uint8_t custom_dscp, uint16_t custom_ip_flags,
                     IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                     const TcpBuildOptions& opts,
                     bool frag_out_of_order = false, bool frag_overlap = false,
                     uint16_t frag_overlap_bytes = 0, bool frag_zof = false,
                     std::function<void(const std::vector<uint16_t>&,const std::vector<uint16_t>&)> on_pre_submit = nullptr,
                     uint64_t* out_bytes_sent = nullptr, bool debug_send = false,
                     int sock6 = -1, const uint8_t* src_ip6 = nullptr);
                     

struct SlotMeta {
    struct sockaddr_in src_addr;
    socklen_t          src_len;
    struct iovec       iov;
    struct msghdr      msg;
    alignas(struct cmsghdr) char cmsg_buf[128];
};

struct SlotMeta6 {
    struct sockaddr_in6 src_addr;
    socklen_t           src_len;
    struct iovec        iov;
    struct msghdr       msg;
    alignas(struct cmsghdr) char cmsg_buf[128];
};

struct IPv6Key {
    uint8_t bytes[16];
    bool operator==(const IPv6Key& o) const noexcept {
        return memcmp(bytes, o.bytes, 16) == 0;
    }
};
struct IPv6KeyHash {
    size_t operator()(const IPv6Key& a) const noexcept {
        uint64_t h1, h2;
        memcpy(&h1, a.bytes,     8);
        memcpy(&h2, a.bytes + 8, 8);
        return std::hash<uint64_t>{}(h1) ^ (std::hash<uint64_t>{}(h2) << 1);
    }
};
inline IPv6Key make_ipv6_key(const struct in6_addr& a) {
    IPv6Key k; memcpy(k.bytes, &a, 16); return k;
}

struct RawPacket {
    static constexpr size_t MAX_LEN = 2048;
    enum class PktType : uint8_t { TCP = 0, ICMP = 1, TCP6 = 2, ICMPV6 = 3 } pkt_type = PktType::TCP;

    uint8_t  data[MAX_LEN];
    int      len = 0;
    int64_t  kernel_rx_us = 0;   // from SO_TIMESTAMP cmsg, 0 if absent
};

struct GlobalRecvCtx {
    int                      tcp_sock    = -1;
    int                      icmp_sock   = -1;   // NEW: ICMP recv merged into ring
    int                      tcp6_sock   = -1;   // IPv6 TCP raw recv, -1 if v6 unused
    int                      icmpv6_sock = -1;   // IPv6 ICMP raw recv, -1 if v6 unused
    struct io_uring          ring{};
    std::unique_ptr<uint8_t[]> buf_storage;
    std::vector<SlotMeta>    slots;
    std::unique_ptr<uint8_t[]> buf6_storage;
    std::vector<SlotMeta6>   slots6;
    uint8_t*                 bufs      = nullptr;
    uint8_t*                 bufs6     = nullptr;
    bool                     valid     = false;
    bool                     sqpoll_active = false;
    bool  fixed_files_active = false;
    int   tcp_fixed_idx      = -1;
    int   icmp_fixed_idx     = -1;   // -1 if icmp_sock creation failed
    int   tcp6_fixed_idx     = -1;   // -1 if tcp6_sock unused/creation failed
    int   icmpv6_fixed_idx   = -1;   // -1 if icmpv6_sock unused/creation failed
    static constexpr uint64_t ICMP_SLOT_FLAG  = (1ULL << 32);
    static constexpr size_t   N_ICMP_SLOTS    = 4;   // ICMP bursts are rare
    static constexpr uint64_t WAKE_ACK_FLAG   = (1ULL << 33);
    static constexpr uint64_t TCP6_SLOT_FLAG    = (1ULL << 34);
    static constexpr uint64_t ICMPV6_SLOT_FLAG  = (1ULL << 35);
    static constexpr size_t   N_ICMPV6_SLOTS    = 4;   // mirrors N_ICMP_SLOTS
    std::array<std::array<uint8_t, 1500>, N_ICMP_SLOTS> icmp_bufs{};
    std::array<struct iovec,      N_ICMP_SLOTS>          icmp_iovs{};
    std::array<struct msghdr,     N_ICMP_SLOTS>          icmp_msgs{};
    std::array<struct sockaddr_in,N_ICMP_SLOTS>          icmp_src_addrs{};
    std::array<socklen_t,         N_ICMP_SLOTS>          icmp_src_lens{};
    std::array<std::array<uint8_t, 1500>, N_ICMPV6_SLOTS> icmpv6_bufs{};
    std::array<struct iovec,       N_ICMPV6_SLOTS>         icmpv6_iovs{};
    std::array<struct msghdr,      N_ICMPV6_SLOTS>         icmpv6_msgs{};
    std::array<struct sockaddr_in6,N_ICMPV6_SLOTS>         icmpv6_src_addrs{};
    std::array<socklen_t,          N_ICMPV6_SLOTS>         icmpv6_src_lens{};

    // ip (network byte order) → index into results vector
    std::unordered_map<uint32_t, size_t> ip_to_idx;
    // IPv6 counterpart — can't share ip_to_idx, a 128-bit address doesn't
    // fit a uint32_t key.
    std::unordered_map<IPv6Key, size_t, IPv6KeyHash> ip_to_idx6;

    // ── single-reader-thread + per-target queue infrastructure ───────────
    std::unordered_map<uint32_t,
        std::unique_ptr<moodycamel::ConcurrentQueue<RawPacket>>> target_queues;
    // IPv6 counterpart — same reasoning as ip_to_idx6 above.
    std::unordered_map<IPv6Key,
        std::unique_ptr<moodycamel::ConcurrentQueue<RawPacket>>, IPv6KeyHash> target_queues6;
    std::thread       reader_thread;
    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_stop{false};

    moodycamel::ConcurrentQueue<RawPacket>* queue_for(uint32_t src_addr) {
        auto it = target_queues.find(src_addr);
        return it == target_queues.end() ? nullptr : it->second.get();
    }
    moodycamel::ConcurrentQueue<RawPacket>* queue_for6(const IPv6Key& src_addr) {
        auto it = target_queues6.find(src_addr);
        return it == target_queues6.end() ? nullptr : it->second.get();
    }
    std::shared_mutex        idle_ring_mu;
    std::unordered_map<uint32_t, int> idle_ring_fds;
    std::unordered_map<IPv6Key, int, IPv6KeyHash> idle_ring_fds6;

    void register_idle_ring(uint32_t ip, int fd) {
        std::unique_lock lock(idle_ring_mu);
        idle_ring_fds[ip] = fd;
    }
    void unregister_idle_ring(uint32_t ip) {
        std::unique_lock lock(idle_ring_mu);
        idle_ring_fds.erase(ip);
    }
    void register_idle_ring6(const IPv6Key& ip, int fd) {
        std::unique_lock lock(idle_ring_mu);
        idle_ring_fds6[ip] = fd;
    }
    void unregister_idle_ring6(const IPv6Key& ip) {
        std::unique_lock lock(idle_ring_mu);
        idle_ring_fds6.erase(ip);
    }

    GlobalRecvCtx() = default;
    ~GlobalRecvCtx() {
        if (reader_started) {
            reader_stop.store(true, std::memory_order_release);
            if (reader_thread.joinable()) reader_thread.join();
        }
        if (valid) io_uring_queue_exit(&ring);
        tcp_sock = icmp_sock = tcp6_sock = icmpv6_sock = -1;
    }
    GlobalRecvCtx(const GlobalRecvCtx&)            = delete;
    GlobalRecvCtx& operator=(const GlobalRecvCtx&) = delete;
};

struct GlobalSendCtx {
    int             sock  = -1;
    int             sock6 = -1;
    struct io_uring ring{};
    bool            valid = false;
    bool            sqpoll_active = false;
    struct io_uring errq_ring_v4{};
    struct io_uring errq_ring_v6{};
    bool            errq_ring_v4_valid = false;
    bool            errq_ring_v6_valid = false;

    GlobalSendCtx() = default;
    ~GlobalSendCtx() {
        if (valid) io_uring_queue_exit(&ring);
        if (errq_ring_v4_valid) io_uring_queue_exit(&errq_ring_v4);
        if (errq_ring_v6_valid) io_uring_queue_exit(&errq_ring_v6);
    }
    GlobalSendCtx(const GlobalSendCtx&)            = delete;
    GlobalSendCtx& operator=(const GlobalSendCtx&) = delete;
};

std::unique_ptr<GlobalSendCtx> init_global_send_ctx(
    int    sock,
    size_t send_uring_depth,
    size_t num_ports,
    bool   enable_sqpoll,
    int    sock6 = -1,
    int    attach_wq_fd = -1);
    
struct RTTTracker {
    std::atomic<int>  current_rtt_ms;
    std::atomic<int>  rtt_var_ms;
    std::atomic<bool> has_measurement;
    RTTTracker(int seed_rtt)
        : current_rtt_ms(seed_rtt), rtt_var_ms(seed_rtt / 2), has_measurement(false) {}
    void update(int new_rtt_ms) {
        bool expected = false;
        if (has_measurement.compare_exchange_strong(expected, true)) {
            current_rtt_ms.store(new_rtt_ms);
            rtt_var_ms.store(new_rtt_ms / 2);
        } else {
            int current = current_rtt_ms.load();
            int diff = (current > new_rtt_ms) ? (current - new_rtt_ms) : (new_rtt_ms - current);

            int var_current  = rtt_var_ms.load();
            int var_smoothed = (3 * var_current + diff) / 4;   // beta = 1/4
            rtt_var_ms.compare_exchange_weak(var_current, var_smoothed);

            int smoothed = (7 * current + new_rtt_ms) / 8;     // alpha = 1/8 (unchanged)
            current_rtt_ms.compare_exchange_weak(current, smoothed);
        }
    }
    int get_timeout_for_retry(int retry_count) const {
        if (!has_measurement.load()) return current_rtt_ms.load();
        int base_rtt = current_rtt_ms.load();
        int rttvar   = rtt_var_ms.load();
        int rto      = base_rtt + g_cong_tune.rto_mult * rttvar;      // Jacobson/Karels RTO
        if (retry_count <= 0) return rto;
        if (retry_count == 1) return rto + g_cong_tune.rto_pad1_ms;
        int extra_stages = retry_count - 2;
        return rto + g_cong_tune.rto_pad2_ms + (extra_stages * g_cong_tune.rto_pad2_ms) / 2;
    }
    bool should_mark_filtered(int retry_count, int retries_cap) const {
        return retry_count >= retries_cap;
    }
};

RecPross receive_response(const char *dest_ip, std::span<const int> ports, uint32_t local_ip, 
                      std::mt19937 &rng, PacketBufferPool &pool, int send_sock, 
                      uint16_t source_port, uint16_t retry_source_port, uint32_t seq_num, uint16_t win_size,
                      bool print_individual_closed_filtered, bool print_filtered_if_few, 
                      struct io_uring *send_ring, bool fast_scan, size_t batch_size,
                      ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp, 
                      uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                      const TcpBuildOptions& opts,
                      RTTTracker& shared_rtt_tracker,
                      bool debug_rtt = false, bool debug_ttl = false, bool debug_demux = false, bool debug_strack = false,
                      bool frag_out_of_order = false, bool frag_overlap = false,
                      uint16_t frag_overlap_bytes = 0, bool frag_zof = false,
                      const SportRangeConfig& sport_range_cfg = {},const GsportConfig& gsport_cfg = {},
                      int initial_rtt_ms = 290, int port_timeout_min_ms = 5, int port_timeout_max_ms = 700,
                      RateConfig rate_config = {}, JitterConfig jitter_config = {},
                      BatchDelayConfig batch_delay_config = {},
                      GlobalRecvCtx* g_recv = nullptr, struct io_uring* idle_ring_ptr = nullptr,
                      RateLimiterState* rate_state = nullptr,
                      BandwidthConfig bandwidth_config = {},
                      BandwidthLimiterState* bandwidth_state = nullptr,
                      uint64_t initial_dispatch_delay_us = 0, bool debug_send = false,
                      int sock6 = -1, const uint8_t* src_ip6 = nullptr);

class AllProbes;   // defined in probe.h — forward decl so scan.hpp doesn't need to include it
// Creates and initialises a GlobalRecvCtx for a set of target IPs.
// Returns nullptr on failure.
std::unique_ptr<GlobalRecvCtx> init_global_recv_ctx(
    const std::vector<std::string>& target_ips,
    size_t                          rcv_uring_depth,
    int                             user_rcvbuf_size,
    bool                            enable_sqpoll);
    
void recv_reader_thread_func(GlobalRecvCtx* ctx);
                     
void worker_thread(const char *ip, uint32_t local_ip, const char* source_ip, 
                   const std::vector<int>& ports, std::mt19937 &rng, PacketBufferPool &pool, 
                   int send_sock, RecPross &result, size_t main_batch_size, uint32_t seq_num,
                   uint16_t win_size, int ip_version, bool print_individual_closed_filtered, 
                   bool print_filtered_if_few, struct io_uring *send_ring, bool fast_scan,
                   ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp, 
                   uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                   const TcpBuildOptions& opts,
                   int user_rcvbuf_size = -1,
                   size_t send_uring_depth = 0, size_t rcv_uring_depth = 0,
                   uint16_t source_port = 0, uint16_t retry_source_port = 0, bool debug_packet = false,
                   bool debug_rtt = false, bool debug_wsn = false, bool debug_ttl = false,
                   bool debug_demux = false, bool debug_strack = false,
                   bool debug_send = false,
                   bool frag_out_of_order = false,
                   bool frag_overlap = false, uint16_t frag_overlap_bytes = 0, 
                   bool frag_zof = false, const SportRangeConfig& sport_range_cfg = {},const GsportConfig& gsport_cfg = {},
                   int initial_rtt_ms = 290,
                   int port_timeout_min_ms = 5, int port_timeout_max_ms = 700,
                   RateConfig rate_config = {}, JitterConfig jitter_config = {},
                   BatchDelayConfig batch_delay_config = {},
                   BandwidthConfig bandwidth_config = {}, bool is_threaded = false,GlobalRecvCtx* g_recv = nullptr,
                   int sock6 = -1, const uint8_t* src_ip6 = nullptr);
                   
bool process_response(PortState& state, uint16_t dest_port, 
                                   struct tcphdr* tcph, int bytes, struct ip* iph,sockaddr_in& dest, moodycamel::BlockingConcurrentQueue<PacketTask>& packet_queue,ScanType scan_type, bool fast_scan, RecPross& result,
                                   const std::unordered_map<uint16_t, std::string>& service_map,std::chrono::steady_clock::time_point current_time,uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,
                                   uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,const std::string& custom_data, uint16_t data_length,
                                   bool use_custom_data, bool generate_random_data, bool print_individual_closed_filtered,bool use_badsum, uint16_t custom_badsum_value,
                                   bool badsum_value_set, bool use_partial_badsum, const std::string& partial_badsum_type,bool use_tfo_cookie = false, bool tfo_cookie_as_hex = false, bool tfo_cookie_random = false,
                                   const std::string& tfo_cookie_str = "", uint64_t tfo_cookie_num = 0, size_t tfo_cookie_length = 0,std::string* output_buf = nullptr,
                                   sockaddr_in6* dest6_ptr = nullptr);
                                   
void display_packet_details(const PacketDetails& details, bool debug_enabled);
void display_sent_packet_details(const SentPacketDetails& d, bool debug_enabled);
void flush_sent_packet_debug();

void print_rtt_debug(const std::vector<std::pair<int, double>>& entries);
void print_demux_debug(const std::string& target_ip,
                        const std::vector<DemuxDebugEntry>& entries,
                        const DemuxDebugCounters& counts,
                        const std::vector<uint16_t>& open_ports);
                        
void print_strack_debug(const std::string& target_ip,
                         const std::vector<StrackEntry>& entries,
                         const StrackCounters& counts);

void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,uint8_t sent_ws,const char* dest_ip);

void display_ttl_analysis(const std::vector<std::pair<int, double>>& rtt_entries,uint8_t sent_ttl, uint8_t received_ttl,const char* ip, bool host_responded);
void reset_network_disconnect_flag();
bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                     uint8_t* src_mac, uint8_t* src_ip, 
                     const std::vector<uint8_t*>& target_IPs,
                     const EthArpOptions& eth_opts);

bool receive_arp_reply(int sock, struct io_uring* ring, 
                      const std::vector<uint8_t*>& target_IPs,
                      std::vector<uint8_t*>& macs, 
                      const EthArpOptions& eth_opts,
                      int initial_rtt_ms,
                      const char* ifname,
                      uint8_t* src_mac,
                      uint8_t* src_ip,
                      int max_retries = 2,
                      int min_round_timeout_ms = 20,
                      int max_round_timeout_ms = 1000,
                      std::vector<double>* out_rtt_ms = nullptr);
                   
#endif
