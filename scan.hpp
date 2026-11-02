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
    int      min_retries        = 2;         // — floor, no CLI yet
    int      max_retries        = 5;         // — ceiling, no CLI yet
    int      dispatch_jitter_floor_ms = 60;  // — RTO floor so internal batch/coalesce
                                              // scheduling delay isn't mistaken for a dropped packet
};

extern CongestionTuneConfig g_cong_tune;

struct RetryBudgetState {
    std::atomic<double> congestion_ratio{0.0};
    std::atomic<int>    dynamic_max_retries{2};
    std::atomic<size_t> ports_in_retry{0};
    std::atomic<size_t> active_ports{0};

    RetryBudgetState() { dynamic_max_retries.store(g_cong_tune.min_retries); }
    double update_congestion(double sample) {
        if (!std::isfinite(sample)) sample = 0.0;
        sample = std::clamp(sample, 0.0, 1.0);
        double prev  = congestion_ratio.load(std::memory_order_relaxed);
        double alpha = (sample > prev) ? g_cong_tune.alpha_up : g_cong_tune.alpha_down;
        double next  = std::clamp(alpha * sample + (1.0 - alpha) * prev, 0.0, 1.0);
        if (next < 0.01) next = 0.0;              
        congestion_ratio.store(next, std::memory_order_relaxed);
        int span = g_cong_tune.max_retries - g_cong_tune.min_retries;
        int dyn  = g_cong_tune.min_retries +
                   static_cast<int>(std::lround(std::pow(next, g_cong_tune.curve_exp) * span));
        dyn = std::clamp(dyn, g_cong_tune.min_retries, g_cong_tune.max_retries);
        dynamic_max_retries.store(dyn, std::memory_order_relaxed);
        return next;
    }
};
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

// Thread-safe byte-budget scheduler.  ONE instance is shared by every target and
// thread in the process (see global_bandwidth_limiter()).
//
//   reserve(bytes, earliest)  -> earliest instant >= `earliest` at which `bytes`
//                                may be sent without exceeding the budget of the
//                                window that instant falls in.  Windows end when
//                                their TIME is up *or* their budget is spent.
//   debit(bytes)              -> charge bytes that cannot be delayed (handshake
//                                follow-ups) against the current window.
//   settle(delta)             -> correct the window by (actual - estimated) bytes
//                                once a send has completed.
class BandwidthLimiterState {
public:
    using Clock = std::chrono::steady_clock;

    BandwidthLimiterState() = default;
    BandwidthLimiterState(const BandwidthLimiterState&)            = delete;
    BandwidthLimiterState& operator=(const BandwidthLimiterState&) = delete;

    // First caller wins; the per-target calls that follow are no-ops.
    void configure(const BandwidthConfig& c) {
        std::lock_guard<std::mutex> lk(mu_);
        if (configured_) return;
        cfg_        = c;
        configured_ = true;
        std::random_device rd;
        rng_.seed(rd());
    }

    Clock::time_point reserve(uint64_t bytes, Clock::time_point earliest) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!active_locked()) return earliest;
        Clock::time_point t = std::max(earliest, window_start_);   // never before the window opens
        for (;;) {
            if (t >= window_end_) roll_locked(t);                  // time-based expiry
            if (used_ == 0 || used_ + bytes <= budget_) {          // used_==0: an oversized packet still goes out alone
                used_ += bytes;
                return t;
            }
            t = window_end_;                                       // budget spent -> next window
        }
    }

    void debit(uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!active_locked()) return;
        const auto now = Clock::now();
        if (now >= window_end_) roll_locked(now);
        used_ += bytes;
    }

    void settle(int64_t delta) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!active_locked() || delta == 0) return;
        const auto now = Clock::now();
        if (now >= window_end_) roll_locked(now);
        if (delta > 0) used_ += static_cast<uint64_t>(delta);
        else {
            const uint64_t d = static_cast<uint64_t>(-delta);
            used_ = used_ > d ? used_ - d : 0;
        }
    }

private:
    bool active_locked() const { return cfg_.enabled && cfg_.window_us > 0; }

    void roll_locked(Clock::time_point start) {
        window_start_ = start;
        window_end_   = start + std::chrono::microseconds(cfg_.window_us);
        used_         = 0;
        budget_       = (cfg_.total_bytes_min < cfg_.total_bytes_max)
            ? std::uniform_int_distribution<uint64_t>(cfg_.total_bytes_min, cfg_.total_bytes_max)(rng_)
            : cfg_.total_bytes_max;
    }

    std::mutex        mu_;
    BandwidthConfig   cfg_{};
    bool              configured_ = false;
    std::mt19937_64   rng_;
    Clock::time_point window_start_{};
    Clock::time_point window_end_{};
    uint64_t          used_   = 0;
    uint64_t          budget_ = 0;
};

inline BandwidthLimiterState& global_bandwidth_limiter() {
    static BandwidthLimiterState g;
    return g;
}

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

inline uint32_t generate_tcp_tsval() {
    static const uint32_t base_offset = [] {
        std::random_device rd;
        std::mt19937 gen(rd());
        return std::uniform_int_distribution<uint32_t>()(gen);
    }();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now().time_since_epoch())
                  .count();
    return base_offset + static_cast<uint32_t>(ms);
}

struct TcpBuildOptions {
    bool        use_ip_tos              = false;
    uint8_t     custom_ip_tos_byte      = 0;

    bool        use_manual_tcp_checksum = false;
    uint16_t    manual_tcp_checksum     = 0;

    uint8_t     window_scale            = 7;
    uint16_t    mss_value               = 1460;
    uint32_t    timestamp_val           = generate_tcp_tsval();
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

// Exact size of the IPv6 extension-header chain build_packet() emits for these
// options.  Defined in scan.cpp, next to the header builders it reuses.
size_t estimate_ipv6_ext_bytes(const TcpBuildOptions& opts);

inline constexpr size_t PKT_BUF_CAP = 4096;   // == PacketBufferPool::buffer_size (static_assert'ed below the class)

// Number of L3 bytes (IP header onward) one probe puts on the wire, i.e. what the
// io_uring sendmsg CQE reports as `res`.  It mirrors build_packet() rule for rule:
//   * TCP options in build_packet's order, each added only if it still fits in 40 B
//   * NULL/XMAS drop all options unless a TFO cookie is requested
//   * payload only when custom data is set, or random data is requested WITH a length
//   * IPv4 options (Router Alert / Security), --packet-length (IPv4 only)
//   * IPv6: 40 B header + exact extension-header chain
//   * --frag*/--mtu: every fragment repeats the IP header (+8 B fragment header on IPv6)
// Ethernet framing (14 B + FCS/preamble/IFG) is NOT included - add it on top if the
// cap is meant to be a wire-rate figure.
inline size_t estimate_packet_wire_bytes(const TcpBuildOptions& opts, ScanType scan_type,
                                          bool is_ipv6 = false) {
    constexpr size_t TCP_HDR_LEN = 20;
    constexpr size_t MAX_OPTS    = 40;
    const bool null_xmas = (scan_type == ScanType::NULL_SCAN || scan_type == ScanType::XMAS);
    const bool malformed = opts.use_tfo_cookie && opts.tfo_cookie_random &&
                           opts.tfo_cookie_length > 100000;     // intentional oversize mode

    // ---- TCP options -------------------------------------------------------
    size_t opt = 0;
    if (malformed) {
        opt = std::min<size_t>(1024, PKT_BUF_CAP - 40);          // best effort; settle() corrects the rest
    } else {
        auto put = [&](size_t n) { if (opt + n <= MAX_OPTS) opt += n; };
        if (!null_xmas)            put(4);                        // MSS
        if (opts.window_scale > 0) put(3);                        // window scale
        if (opts.sack_permitted)   put(2);                        // SACK-permitted
        put(10);                                                  // timestamp: build_packet keys it off task.timestamp_val (= sent_tsval, never 0)
        if (opts.use_tcp_mptcp)    put(12);
        if (opts.use_tcp_ao)       put(4 + opts.tcp_ao_mac_len);
        if (opts.use_tfo_cookie) {
            const size_t space = (MAX_OPTS >= opt + 3) ? MAX_OPTS - opt - 3 : 0;
            size_t cookie = 0;
            const std::string& s = opts.tfo_cookie_str;
            if (opts.tfo_cookie_random) {
                size_t r = opts.tfo_cookie_length ? opts.tfo_cookie_length : 8;
                cookie = std::min({r, size_t(253), space});
            } else if (opts.tfo_cookie_as_hex && !s.empty()) {
                size_t n = s.size();
                if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) n -= 2;
                n += (n & 1);                                     // odd length gets a leading '0'
                cookie = std::min(n / 2, space / 2);              // build_packet caps hex cookies at space/2
            } else if (!s.empty()) {
                cookie = std::min(s.size(), space);
            } else if (opts.tfo_cookie_num > 0) {
                size_t b = 0;
                for (uint64_t t = opts.tfo_cookie_num; t > 0; t >>= 8) ++b;
                cookie = std::min({b, size_t(8), space});
            } else {
                cookie = std::min(size_t(8), space);
            }
            if (cookie > 0) put(3 + cookie);                      // kind + len + 0xF9 + cookie
        }
        if (opts.nops_count > 0) opt += std::min<size_t>(opts.nops_count, MAX_OPTS - opt);
        if (null_xmas && !opts.use_tfo_cookie) opt = 0;
        opt = std::min<size_t>((opt + 3) & ~size_t(3), MAX_OPTS);
    }

    // ---- payload -----------------------------------------------------------
    size_t data_len = 0;
    if (opts.use_custom_data && !opts.custom_data.empty())
        data_len = opts.custom_data.size();
    else if (opts.generate_random_data && opts.data_length > 0)
        data_len = std::min<size_t>(opts.data_length, PKT_BUF_CAP - 40 - opt);

    const size_t tcp_total = TCP_HDR_LEN + opt + data_len;
    const bool   frag      = opts.use_fragmentation || opts.mtu_size > 0;

    // ---- IPv6 --------------------------------------------------------------
    if (is_ipv6) {
        const size_t ext = estimate_ipv6_ext_bytes(opts);
        if (!frag || ext > 0)                  // build_packet() refuses ext headers + fragmentation
            return 40 + ext + tcp_total;
        size_t step = (opts.mtu_size > 0)
            ? (opts.mtu_size >= 48 ? ((size_t(opts.mtu_size) - 48) / 8) * 8 : 65528)
            : (size_t(opts.frag_size) / 8) * 8;
        if (step < 8) step = 8;
        const size_t nfrag = (tcp_total + step - 1) / step;
        return tcp_total + nfrag * (40 + 8);
    }

    // ---- IPv4 --------------------------------------------------------------
    size_t ip_opt = 0;
    if (opts.use_ip_router_alert)                      ip_opt += 4;
    if (opts.use_ip_security && ip_opt + 11 <= 40)     ip_opt += 11;
    ip_opt = (ip_opt + 3) & ~size_t(3);
    const size_t ip_hdr = 20 + ip_opt;
    size_t total = ip_hdr + tcp_total;

    if (opts.packet_length_config.enabled) {           // --packet-length (IPv4 only, applied before fragmentation)
        const size_t target = opts.packet_length_config.target_len;
        if (target > total) {
            total = std::min<size_t>(target, PKT_BUF_CAP);
        } else if (target < total && target >= ip_hdr + 20) {
            const size_t hdr_end = ip_hdr + 20 + opt;
            if (target < hdr_end) {                    // cut lands inside the TCP header+options
                size_t th = ((target - ip_hdr) / 4) * 4;
                total = ip_hdr + std::max<size_t>(th, 20);
            } else {
                total = target;
            }
        }
    }
    if (!frag) return total;

    size_t step = (opts.mtu_size > 0)
        ? (opts.mtu_size >= 20 ? ((size_t(opts.mtu_size) - 20) / 8) * 8 : 65528)
        : (size_t(opts.frag_size) / 2) * 2;
    step = std::max<size_t>(step, opts.mtu_size > 0 ? 8 : 2);
    const size_t body  = total - ip_hdr;
    const size_t nfrag = (body + step - 1) / step;
    return total + (nfrag > 0 ? nfrag - 1 : 0) * ip_hdr;   // each extra fragment repeats the IP header
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
    struct IcmpFilterInfo {
        IcmpFilterReason reason;
        struct in_addr   replier{};
    };
    std::unordered_map<uint16_t, IcmpFilterInfo> icmp_filter_reasons;
    std::vector<std::tuple<IcmpFilterReason, std::string, struct in_addr>> icmp_warnings;
    std::string mac_address;
    int learned_rtt_ms = 0;
    std::unordered_map<uint16_t, PacketDetails> packet_details;
    std::unordered_map<uint16_t, PacketDetails> osdetect_details;
    int packets_sent = 0;
    // ── TX-side drops, one bucket per CAUSE (see TxLossCounters) ─────────
    uint64_t loss_buffer_pool   = 0;   // pool.acquire() returned null
    uint64_t loss_build_fail    = 0;   // build_packet() rejected the task
    uint64_t loss_kernel_reject = 0;   // sendmsg CQE res < 0
    uint64_t loss_drain_timeout = 0;   // CQE never reaped, buffer stranded
    uint64_t loss_no_socket     = 0;   // IPv6 task with no v6 socket
    uint64_t loss_aborted       = 0;   // batch abandoned: abort / submit error
    // ── RX-side drops, deltas over this scan.  Socket-wide: concurrent
    //    targets sharing the reader thread will see overlapping numbers.
    uint64_t rx_kernel_ovfl  = 0;      // SO_RXQ_OVFL — kernel recv buffer full
    uint64_t rx_cq_overflow  = 0;      // io_uring CQ overflow on the recv ring
    uint64_t rx_truncated    = 0; 
    uint64_t rx_slot_starved = 0;      // no free slot, re-arm deferred
    uint64_t rx_queue_drop        = 0;  // per-target queue full (socket-wide delta)
    uint64_t rx_enqueued          = 0;  // packets queued to targets (socket-wide delta)
    uint64_t rx_ignored           = 0;  // frames for no known target (socket-wide delta)
    uint64_t rx_drain_budget_hits = 0;  // consumer hit the 2 ms drain budget (this target)
    uint64_t rx_queue_hwm         = 0;  // highest sampled queue depth (this target)
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
    bool rtt_measured;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;uint32_t tsval_offset;double ewma_rtt; bool final_state_determined;enum class PortReportedState { None, Open, Closed, Filtered };
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

inline uint16_t pick_unique_ephemeral_port(std::mt19937& rng, uint16_t lo, uint16_t hi,
                                            const PortState& state, int max_tries = 16) {
    for (int i = 0; i < max_tries; ++i) {
        uint16_t candidate = fast_uniform_port(rng, lo, hi);
        if (!state.accepts_src_port(candidate)) return candidate;
    }
    for (uint32_t p = lo; p <= hi; ++p)
        if (!state.accepts_src_port(static_cast<uint16_t>(p))) return static_cast<uint16_t>(p);
    return fast_uniform_port(rng, lo, hi);   // range exhausted — statistically unreachable at 5 draws
}

struct PacketTask {
    sockaddr_in dest; sockaddr_in6 dest6{}; bool is_ipv6 = false; uint16_t src_port;uint32_t seq;uint32_t ack;uint8_t flags;std::string data;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;ScanType scan_type;uint16_t dest_port;
    uint32_t timestamp_val;uint32_t timestamp_ecr;bool include_timestamp;uint8_t window_scale;uint16_t mss_value;uint32_t custom_timestamp;uint32_t timestamp_ecr_custom;uint16_t nops_count;bool sack_permitted;
    std::string custom_data;uint16_t data_length;bool use_custom_data;bool generate_random_data;bool use_badsum;uint16_t custom_badsum_value;bool use_partial_badsum;std::string partial_badsum_type;
    bool use_tfo_cookie;bool tfo_cookie_as_hex;bool tfo_cookie_random;std::string tfo_cookie_str;uint64_t tfo_cookie_num;size_t tfo_cookie_length;bool is_poison = false;
    bool bw_prepaid = false;   // true: this packet's bytes were already reserved in the BandwidthLimiterState when it was scheduled
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
                     custom_timestamp(generate_tcp_tsval()),timestamp_ecr_custom(0),nops_count(0),sack_permitted(true),custom_data(""),data_length(0),use_custom_data(false),generate_random_data(false),use_badsum(false),custom_badsum_value(0),
                     use_partial_badsum(false),partial_badsum_type(""),use_tfo_cookie(false),tfo_cookie_as_hex(false),tfo_cookie_random(false),tfo_cookie_str(""),tfo_cookie_num(0),tfo_cookie_length(0){}
    
    PacketTask(const sockaddr_in& d, uint16_t sp, uint32_t s, uint32_t a, uint8_t f,
               std::string&& dat, std::chrono::steady_clock::time_point sst,uint32_t stv, ScanType type, uint32_t tsval = 0, uint32_t tsecr = 0,
               bool inc_ts = false, uint8_t ws = 7, uint16_t mss = 1460,uint32_t custom_ts = generate_tcp_tsval(), uint32_t tsecr_custom = 0,
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
               bool inc_ts = false, uint8_t ws = 7, uint16_t mss = 1460,uint32_t custom_ts = generate_tcp_tsval(), uint32_t tsecr_custom = 0,
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
          tfo_cookie_random(other.tfo_cookie_random),tfo_cookie_str(std::move(other.tfo_cookie_str)),tfo_cookie_num(other.tfo_cookie_num),tfo_cookie_length(other.tfo_cookie_length),is_poison(other.is_poison),bw_prepaid(other.bw_prepaid) {}
    
    PacketTask& operator=(PacketTask&& other) noexcept {
        if (this != &other) {
            dest = other.dest;dest6 = other.dest6;is_ipv6 = other.is_ipv6;src_port = other.src_port;seq = other.seq;ack = other.ack;flags = other.flags;data = std::move(other.data);syn_sent_time = other.syn_sent_time;sent_tsval = other.sent_tsval;
            scan_type = other.scan_type;dest_port = other.dest_port;timestamp_val = other.timestamp_val;timestamp_ecr = other.timestamp_ecr;include_timestamp = other.include_timestamp;window_scale = other.window_scale;
            mss_value = other.mss_value;custom_timestamp = other.custom_timestamp;timestamp_ecr_custom = other.timestamp_ecr_custom;nops_count = other.nops_count;sack_permitted = other.sack_permitted;
            custom_data = std::move(other.custom_data);data_length = other.data_length;use_custom_data = other.use_custom_data;generate_random_data = other.generate_random_data;use_badsum = other.use_badsum;
            custom_badsum_value = other.custom_badsum_value;use_partial_badsum = other.use_partial_badsum;partial_badsum_type = std::move(other.partial_badsum_type);use_tfo_cookie = other.use_tfo_cookie;
            tfo_cookie_as_hex = other.tfo_cookie_as_hex;tfo_cookie_random = other.tfo_cookie_random;tfo_cookie_str = std::move(other.tfo_cookie_str);tfo_cookie_num = other.tfo_cookie_num;tfo_cookie_length =
            other.tfo_cookie_length;is_poison = other.is_poison;bw_prepaid = other.bw_prepaid;
        }
        return *this;
    }
    PacketTask(const PacketTask&) = delete;
    PacketTask& operator=(const PacketTask&) = delete;
    ~PacketTask() = default;

    [[nodiscard]] static uint8_t get_flags_for_scan_type(ScanType type) noexcept {
        const auto& scan_map = ScanInfo::get_scan_map();
        auto it = scan_map.find(type);
        return (it != scan_map.end()) ? it->second.flags : TH_SYN;
    }
    [[nodiscard]] static bool expects_rst_response(ScanType type) noexcept {
        const auto& rst_scans = ScanInfo::get_rst_expecting_scans();
        return rst_scans.find(type) != rst_scans.end();
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
static_assert(PacketBufferPool::buffer_size == PKT_BUF_CAP,
              "estimate_packet_wire_bytes() assumes the same per-packet buffer size as PacketBufferPool");

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

// ── TX-side loss accounting ───────────────────────────────────────────────
// Every path in send_tcp_packets() that destroys a packet increments exactly
// one of these.  Buckets are named for the CAUSE, not the symptom, so the
// incident report points at the thing you actually need to fix.
//
// NOTE ON UNITS: in the fragmented path (--frag*) `kernel_reject`, `aborted`
// and `drain_timeout` count FRAGMENTS, because that is the granularity of a
// sendmsg there.  `buffer_pool`, `build_fail` and `no_socket` always count
// whole packets.  Don't mix them without saying which you mean.
struct TxLossCounters {
    std::atomic<uint64_t> buffer_pool   {0}; // pool.acquire() returned null
    std::atomic<uint64_t> build_fail    {0}; // build_packet() rejected the task
    std::atomic<uint64_t> kernel_reject {0}; // sendmsg CQE res < 0
    std::atomic<uint64_t> drain_timeout {0}; // CQE never reaped, buffer stranded
    std::atomic<uint64_t> no_socket     {0}; // IPv6 task with sock6 < 0
    std::atomic<uint64_t> aborted       {0}; // terminate / submit error / no ring
};

int send_tcp_packets(int sock, const std::span<PacketTask> tasks, uint32_t src_ip, 
                     std::mt19937 &rng, PacketBufferPool &pool, uint16_t win_size,
                     struct io_uring *send_ring, size_t batch_size, uint8_t custom_ttl,
                     uint8_t custom_dscp, uint16_t custom_ip_flags,
                     IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                     const TcpBuildOptions& opts,
                     bool frag_out_of_order = false, bool frag_overlap = false,
                     uint16_t frag_overlap_bytes = 0, bool frag_zof = false,
                     std::function<void(const std::vector<uint16_t>&,
                                        const std::vector<uint16_t>&,
                                        bool, bool)> on_pre_submit = nullptr,
                     uint64_t* out_bytes_sent = nullptr, bool debug_send = false,
                     int sock6 = -1, const uint8_t* src_ip6 = nullptr,
                     TxLossCounters* txloss = nullptr);
                     

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
    int64_t  kernel_rx_us = 0;   
};
static_assert(RawPacket::MAX_LEN >= 1500, "RawPacket must hold a full ICMP slot buffer (1500 B)");

struct GlobalRecvCtx {
    int                      tcp_sock    = -1;
    int                      icmp_sock   = -1;   // ICMP recv merged into ring
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
    // Ancillary-data buffers for SO_RXQ_OVFL on the ICMP sockets.  64 bytes
    // is comfortably more than CMSG_SPACE(sizeof(uint32_t)) needs.
    std::array<std::array<uint8_t, 64>, N_ICMP_SLOTS>   icmp_cmsg_bufs{};
    std::array<std::array<uint8_t, 64>, N_ICMPV6_SLOTS> icmpv6_cmsg_bufs{};
    std::vector<uint8_t>     slot_armed;
    std::vector<uint8_t>     slot6_armed;
    std::array<uint8_t, N_ICMP_SLOTS>   icmp_armed{};
    std::array<uint8_t, N_ICMPV6_SLOTS> icmpv6_armed{};

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
    std::atomic<uint64_t> rx_kernel_ovfl_v4   {0};  // SO_RXQ_OVFL, tcp_sock
    std::atomic<uint64_t> rx_kernel_ovfl_v6   {0};  // SO_RXQ_OVFL, tcp6_sock
    std::atomic<uint64_t> rx_kernel_ovfl_icmp {0};  // SO_RXQ_OVFL, icmp_sock
    std::atomic<uint64_t> rx_kernel_ovfl_icmp6{0};  // SO_RXQ_OVFL, icmpv6_sock
    std::atomic<uint64_t> rx_cq_overflow {0};  // io_uring CQ overflow
    std::atomic<uint64_t> rx_truncated   {0};
    std::atomic<uint64_t> rx_slot_starved{0};  // no free slot on re-arm
    static constexpr size_t TARGET_QUEUE_CAP = 2048;
    std::atomic<uint64_t> rx_enqueued   {0};  // packets handed to a target queue
    std::atomic<uint64_t> rx_queue_drop {0};  // target queue full → packet dropped
    std::atomic<uint64_t> rx_ignored    {0};  // TCP frame with no matching target (noise)

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

    // Number of recvmsg(MSG_ERRQUEUE) requests kept in flight at once.
    // Submitting/harvesting them together instead of one-at-a-time is
    // what turns O(N) io_uring_submit() syscalls into O(N/depth).
    static constexpr size_t kErrqBatchDepth = 8;

    std::mutex   errq_v4_mtx;
    std::mutex   errq_v6_mtx;
    bool         errq_v4_pending[kErrqBatchDepth] = {};
    bool         errq_v6_pending[kErrqBatchDepth] = {};
    char         errq_v4_cmsg_buf[kErrqBatchDepth][512]{};
    char         errq_v6_cmsg_buf[kErrqBatchDepth][512]{};
    char         errq_v4_data_buf[kErrqBatchDepth][256]{};
    char         errq_v6_data_buf[kErrqBatchDepth][256]{};
    struct iovec errq_v4_iov[kErrqBatchDepth]{};
    struct iovec errq_v6_iov[kErrqBatchDepth]{};
    struct msghdr errq_v4_msg[kErrqBatchDepth]{};
    struct msghdr errq_v6_msg[kErrqBatchDepth]{};
    struct sockaddr_storage errq_v4_addr[kErrqBatchDepth]{};
    struct sockaddr_storage errq_v6_addr[kErrqBatchDepth]{};

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
        rto = std::max(rto, g_cong_tune.dispatch_jitter_floor_ms);    // never let the RTO
                                                                       // collapse below our own
                                                                       // batch/coalesce latency
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
                      RTTTracker& shared_rtt_tracker, uint32_t shared_tsval_offset,
                      RetryBudgetState& retry_budget,
                      bool debug_rtt, bool debug_ttl, bool debug_demux, bool debug_strack,
                      bool frag_out_of_order, bool frag_overlap,
                      uint16_t frag_overlap_bytes, bool frag_zof,
                      const SportRangeConfig& sport_range_cfg, const GsportConfig& gsport_cfg,
                      int initial_rtt_ms, int port_timeout_min_ms, int port_timeout_max_ms,
                      RateConfig rate_config, JitterConfig jitter_config,
                      BatchDelayConfig batch_delay_config,
                      GlobalRecvCtx* g_recv, GlobalSendCtx* g_send, struct io_uring* idle_ring_ptr,
                      RateLimiterState* rate_state,
                      BandwidthConfig bandwidth_config, BandwidthLimiterState* bandwidth_state,
                      uint64_t initial_dispatch_delay_us, bool debug_send,
                      int sock6, const uint8_t* src_ip6,
                      bool want_full_details = true);

class AllProbes; 
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
                   GlobalSendCtx* g_send = nullptr,
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
