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
// Set by init_global_send_ctx() once io_uring_register_files() succeeds on
// GlobalSendCtx::ring. When true, sendmsg SQEs must use SEND_SOCK_FIXED_IDX
// + IOSQE_FIXED_FILE instead of the raw send fd.
extern std::atomic<bool> g_send_fixed_file_active;
inline constexpr int SEND_SOCK_FIXED_IDX  = 0;
// Registered alongside SEND_SOCK_FIXED_IDX when init_global_send_ctx() is
// given a valid sock6 — same fixed-file win, second raw socket for AF_INET6.
inline constexpr int SEND6_SOCK_FIXED_IDX = 1;
void signal_handler(int signal);

struct RateConfig {
    bool     enabled       = false;
    uint64_t window_us     = 0;  
    uint32_t min_packets   = 0;   
    uint32_t max_packets   = 0;   
};

// Holds the live state of the --rate token-bucket window (packets sent this
// window, when the window started, how many packets this window's target
// is, and whether the window has been seeded yet). A single instance of
// this struct must be created once per target scan (in worker_thread(),
// before its per-batch loop) and passed by pointer into every
// receive_response() call for that target's batches. receive_response()
// only seeds the window the first time it sees an uninitialized state
// (initialized == false) — every subsequent batch call keeps counting
// against the SAME window instead of starting over, which is what makes
// --rate hold across batch boundaries rather than silently resetting (and
// therefore never triggering) every batch.
struct RateLimiterState {
    uint32_t rate_window_sent    = 0;
    uint32_t rate_window_target  = 0;
    std::chrono::steady_clock::time_point rate_window_start =
        std::chrono::steady_clock::now();
    std::uniform_int_distribution<uint32_t> rate_pkt_dist;
    bool     initialized = false;
};

// Per-attempt source-port range configuration for --sport-range.
// Index 0 = initial send (attempt 1), 1 = 1st retry (attempt 2),
// 2 = 2nd retry (attempt 3).
struct SportRangeConfig {
    bool     stage_is_range[3] = {false, false, false};
    uint16_t stage_min[3]      = {0, 0, 0};
    uint16_t stage_max[3]      = {0, 0, 0};
};

// Per-attempt FIXED source port configuration for -g. Unlike
// SportRangeConfig (random port picked fresh from a range each attempt),
// each stage here pins one exact source port. Same indexing as
// SportRangeConfig: 0 = initial send, 1 = 1st retry, 2 = 2nd retry.
struct GsportConfig {
    bool     stage_is_set[3] = {false, false, false};
    uint16_t stage_port[3]   = {0, 0, 0};
};

// Fixed default source port for the 2nd retry (attempt 3) when no range
// is configured for that stage. Not user-configurable except via
// --sport-range 3:min-max.
inline constexpr uint16_t DEFAULT_RETRY2_SPORT = 8080;

// Lemire's bounded-random algorithm: one 32x32->64 multiply per draw, no
// division/modulo in the common case (only a rare rejection loop near the
// range boundary). Cheaper per call than std::uniform_int_distribution,
// which typically does a division every time it's invoked.
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

// Parses --sport-range. Accepts either:
//   "MIN-MAX"                              -> range applies to all 3 attempts
//   "N:MIN-MAX[,N:MIN-MAX[,N:MIN-MAX]]"    -> N in {1,2,3}, per-attempt
inline bool parse_sport_range_config(const std::string& arg, SportRangeConfig& out) {
    auto parse_one_range = [](const std::string& s, uint16_t& lo, uint16_t& hi) -> bool {
        size_t dash = s.find('-');
        if (dash == std::string::npos || dash == 0 || dash == s.size() - 1) {
            std::cerr << "--sport-range: range must be MIN-MAX (e.g. 2222-3333)\n";
            return false;
        }
        long lo_v, hi_v;
        try {
            lo_v = std::stol(s.substr(0, dash));
            hi_v = std::stol(s.substr(dash + 1));
        } catch (const std::exception&) {
            std::cerr << "--sport-range: invalid numeric value in '" << s << "'\n";
            return false;
        }
        if (lo_v < 1 || lo_v > 65535 || hi_v < 1 || hi_v > 65535) {
            std::cerr << "--sport-range: ports must be 1-65535\n";
            return false;
        }
        if (lo_v >= hi_v) {
            std::cerr << "--sport-range: min must be smaller than max (got "
                       << lo_v << "-" << hi_v << ")\n";
            return false;
        }
        lo = static_cast<uint16_t>(lo_v);
        hi = static_cast<uint16_t>(hi_v);
        return true;
    };

    if (arg.find(':') == std::string::npos) {
        uint16_t lo, hi;
        if (!parse_one_range(arg, lo, hi)) return false;
        for (int i = 0; i < 3; ++i) {
            out.stage_is_range[i] = true;
            out.stage_min[i] = lo;
            out.stage_max[i] = hi;
        }
        return true;
    }

    bool seen[3] = {false, false, false};
    size_t pos = 0;
    while (pos <= arg.size()) {
        size_t comma = arg.find(',', pos);
        std::string token = arg.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = (comma == std::string::npos) ? arg.size() + 1 : comma + 1;

        size_t colon = token.find(':');
        if (colon == std::string::npos || colon == 0 || colon == token.size() - 1) {
            std::cerr << "--sport-range: use format N:MIN-MAX (N=0,1,2), e.g. 0:2222-3333\n";
            return false;
        }
        int stage_num;
        try {
            stage_num = std::stoi(token.substr(0, colon));
        } catch (const std::exception&) {
            std::cerr << "--sport-range: invalid attempt number '" << token.substr(0, colon) << "'\n";
            return false;
        }
        if (stage_num < 0 || stage_num > 2) {
            std::cerr << "--sport-range: attempt number must be 0 (initial), 1 (1st retry), or 2 (2nd retry)\n";
            return false;
        }
        int idx = stage_num;
        if (seen[idx]) {
            std::cerr << "--sport-range: attempt " << stage_num << " specified more than once\n";
            return false;
        }
        seen[idx] = true;

        uint16_t lo, hi;
        if (!parse_one_range(token.substr(colon + 1), lo, hi)) return false;
        out.stage_is_range[idx] = true;
        out.stage_min[idx] = lo;
        out.stage_max[idx] = hi;
    }
    return true;
}

// Parses -g. Accepts either:
//   "PORT"                          -> fixed port for the INITIAL send
//                                       only (stage 0) — unchanged from
//                                       -g's original behavior
//   "N:PORT[,N:PORT[,N:PORT]]"      -> N in {0,1,2}, per-attempt, same
//                                       shape as --sport-range's per-
//                                       attempt form, except PORT must
//                                       be a single number — never a
//                                       MIN-MAX range
inline bool parse_gsport_config(const std::string& arg, GsportConfig& out) {
    auto parse_one_port = [](const std::string& s, uint16_t& port) -> bool {
        if (s.find('-') != std::string::npos) {
            std::cerr << "-g: expected a single port number, not a range (got '"
                       << s << "')\n";
            return false;
        }
        long v;
        try {
            size_t consumed = 0;
            v = std::stol(s, &consumed);
            if (consumed != s.size()) throw std::invalid_argument("trailing characters");
        } catch (const std::exception&) {
            std::cerr << "-g: invalid port number '" << s << "'\n";
            return false;
        }
        if (v < 1 || v > 65535) {
            std::cerr << "-g: port must be 1-65535 (got " << v << ")\n";
            return false;
        }
        port = static_cast<uint16_t>(v);
        return true;
    };

    if (arg.find(':') == std::string::npos) {
        uint16_t port;
        if (!parse_one_port(arg, port)) return false;
        out.stage_is_set[0] = true;
        out.stage_port[0]   = port;
        return true;
    }

    bool seen[3] = {false, false, false};
    size_t pos = 0;
    while (pos <= arg.size()) {
        size_t comma = arg.find(',', pos);
        std::string token = arg.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = (comma == std::string::npos) ? arg.size() + 1 : comma + 1;

        size_t colon = token.find(':');
        if (colon == std::string::npos || colon == 0 || colon == token.size() - 1) {
            std::cerr << "-g: use format N:PORT (N=0,1,2), e.g. 0:443\n";
            return false;
        }
        int stage_num;
        try {
            stage_num = std::stoi(token.substr(0, colon));
        } catch (const std::exception&) {
            std::cerr << "-g: invalid attempt number '" << token.substr(0, colon) << "'\n";
            return false;
        }
        if (stage_num < 0 || stage_num > 2) {
            std::cerr << "-g: attempt number must be 0 (initial), 1 (1st retry), or 2 (2nd retry)\n";
            return false;
        }
        if (seen[stage_num]) {
            std::cerr << "-g: attempt " << stage_num << " specified more than once\n";
            return false;
        }
        seen[stage_num] = true;

        uint16_t port;
        if (!parse_one_port(token.substr(colon + 1), port)) return false;
        out.stage_is_set[stage_num] = true;
        out.stage_port[stage_num]   = port;
    }
    return true;
}

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
    uint32_t pmin = 0, pmax = 0;
    try {
        pmin = static_cast<uint32_t>(std::stoul(range_part.substr(0, dash)));
        pmax = static_cast<uint32_t>(std::stoul(range_part.substr(dash + 1)));
    } catch (const std::exception&) {
        std::cerr << "--rate: packet range must be numeric, e.g. 300-500\n";
        return false;
    }
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

// ─── BandwidthConfig ──────────────────────────────────────────────────────
// --bandwidth TIME:BYTES  e.g. 1s:500000  or  500ms:2MB  (K/M/G suffix optional,
// base-1024). Caps total ON-WIRE bytes dispatched per window, the same way
// RateConfig caps packet COUNT per window.
struct BandwidthConfig {
    bool     enabled     = false;
    uint64_t window_us   = 0;
    uint64_t total_bytes = 0;
};

// Cross-thread state for the --bandwidth window. reserved_bytes is an
// ESTIMATE, touched only by the receive_response producer thread (same
// single-writer guarantee RateLimiterState relies on). actual_bytes_sent is
// written by the SENDER thread (via send_tcp_packets' out_bytes_sent, sourced
// from real io_uring CQE res values) and read by the producer thread — hence
// atomic. Every budget check folds actual into reserved via max(), so any
// drift between the pre-send estimate and the real wire size self-corrects
// on the very next check instead of accumulating across the scan.
struct BandwidthLimiterState {
    std::chrono::steady_clock::time_point window_start =
        std::chrono::steady_clock::now();
    uint64_t              reserved_bytes = 0;
    std::atomic<uint64_t> actual_bytes_sent{0};
    bool                  initialized = false;
};

inline bool parse_bandwidth_config(const std::string& arg, BandwidthConfig& out) {
    size_t colon = arg.find(':');
    if (colon == std::string::npos || colon == 0 || colon == arg.size() - 1) {
        std::cerr << "--bandwidth: use format TIME:BYTES e.g. 1s:500000 or 1s:2MB\n";
        return false;
    }

    std::string time_part  = arg.substr(0, colon);
    std::string bytes_part = arg.substr(colon + 1);

    uint64_t window_us = 0;
    if (!parse_duration_to_us(time_part, window_us, "--bandwidth")) return false;

    uint64_t multiplier = 1;
    std::string num_part = bytes_part;
    if (!bytes_part.empty()) {
        char suf = static_cast<char>(std::toupper(static_cast<unsigned char>(bytes_part.back())));
        if (suf == 'K' || suf == 'M' || suf == 'G') {
            multiplier = (suf == 'K') ? 1024ULL
                       : (suf == 'M') ? 1024ULL * 1024
                                      : 1024ULL * 1024 * 1024;
            num_part = bytes_part.substr(0, bytes_part.size() - 1);
        }
    }
    if (num_part.empty()) {
        std::cerr << "--bandwidth: missing byte value\n";
        return false;
    }

    uint64_t bytes_val = 0;
    try {
        bytes_val = std::stoull(num_part);
    } catch (const std::exception&) {
        std::cerr << "--bandwidth: invalid byte value '" << bytes_part << "'\n";
        return false;
    }
    if (bytes_val == 0) {
        std::cerr << "--bandwidth: byte total must be > 0\n";
        return false;
    }

    out.enabled     = true;
    out.window_us   = window_us;
    out.total_bytes = bytes_val * multiplier;
    return true;
}

// ─── PacketLengthConfig ──────────────────────────────────────────────────────
//
// --packet-length <N> only ever changes the REAL on-wire packet size.
// There used to be "big"/"small"/"claimed" modes that just scribbled a
// fake value into iph->ip_len and left the actual bytes untouched. That
// never worked: this codebase runs with IP_HDRINCL set (see main.cpp),
// and raw(7) documents Total Length as unconditionally rewritten by the
// kernel to match the real number of bytes queued for send -- unlike
// Source Address / Packet ID, which are only "filled in when zero",
// Total Length has no such escape hatch. Those modes were dead on
// arrival, so they've been removed instead of kept as a decoy.
//
// What --packet-length <N> does now depends on how N compares to the
// packet's natural (already-built) size:
//
//   N > natural size  -> PAD: append (N - natural size) zero bytes as
//                        TCP payload. This never touches the TCP header
//                        or options, so ip_len stays honest and th_off
//                        stays correct for any N up to the buffer size --
//                        no alignment restriction needed.
//
//   N < natural size  -> SHRINK: truncate from the tail. Truncating the
//                        tail removes payload bytes first, then TCP
//                        option bytes, and can never reach the fixed
//                        20-byte TCP header or the IP header (the floor
//                        is ip_hdr_len + sizeof(tcphdr)). If the cut only
//                        removes payload, the TCP header/options are
//                        untouched and th_off is left alone. If the cut
//                        reaches into the options region, the new length
//                        is rounded DOWN to the nearest 4-byte boundary
//                        (th_off/"data offset" counts whole 32-bit
//                        words -- a non-aligned cut has no valid th_off
//                        value) and th_off is recalculated to match what
//                        is actually still on the wire. This is the fix
//                        for the previous bug where th_off kept
//                        claiming the pre-truncation header size after
//                        any shrink, corrupting the packet regardless of
//                        which N was picked.
//
//   N == natural size -> no-op.
struct PacketLengthConfig {
    bool     enabled    = false;
    uint16_t target_len = 0;   // N from --packet-length <N>
};

inline bool parse_packet_length(const std::string& arg, PacketLengthConfig& out) {
    try {
        unsigned long v = std::stoul(arg);
        if (v < 40 || v > 65535) {
            std::cerr << "--packet-length: length must be 40–65535\n";
            return false;
        }
        out.enabled    = true;
        out.target_len = static_cast<uint16_t>(v);
        return true;
    } catch (...) {
        std::cerr << "--packet-length: invalid number '" << arg << "'\n";
        return false;
    }
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

// ───────────────────────────────────────────────────────────────────────
// IPv6 extension header injection (--hop / --dest)
//
// RFC 8200 §4 TLV option encoding is shared by Hop-by-Hop Options and
// Destination Options, so both are modeled the same way here.
//
// NOTE: --hop/--dest are rejected together with --fragment/--mtu (see
// build_packet()'s is_ipv6 branch in scan.cpp) — chaining a hand-built
// extension header through the existing per-fragment rebuild path in
// send_tcp_packets() would require that path to become extension-header
// aware, which is unimplemented. Same scoping as use_ip_router_alert /
// use_ip_security being no-ops for v6 (see the note a few lines above
// the is_ipv6 branch in build_packet()).
// ───────────────────────────────────────────────────────────────────────
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

// Hard caps: every parsed value below is clamped to these, so the fixed-
// size stack buffers build_packet() writes into can never overflow
// regardless of user input.
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

// Parses --hop's <option>[:<value>]. Returns false (message on stderr,
// `out` left untouched) on anything malformed or out of range.
inline bool parse_hop_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    size_t colon = arg.find(':');
    std::string name = (colon == std::string::npos) ? arg : arg.substr(0, colon);
    std::string val  = (colon == std::string::npos) ? std::string() : arg.substr(colon + 1);

    auto parse_u32 = [](const std::string& s, uint32_t& v) -> bool {
        if (s.empty()) return false;
        try {
            size_t pos = 0;
            unsigned long parsed = std::stoul(s, &pos, 0);
            if (pos != s.size()) return false;
            v = static_cast<uint32_t>(parsed);
            return true;
        } catch (...) { return false; }
    };

    if (name == "alert") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || (v != 0 && v != 1)) {
            std::cerr << "--hop alert: value must be 0 or 1 (got '" << val << "')\n";
            return false;
        }
        out.use_hop_opts = true; out.hop_kind = HopOptKind::ALERT; out.hop_value = v;
        return true;
    }
    if (name == "jumbo") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v < IP6_JUMBO_MIN) {
            std::cerr << "--hop jumbo: value must be >= " << IP6_JUMBO_MIN
                       << " (jumbograms only apply above 65535 bytes, RFC 2675)\n";
            return false;
        }
        out.use_hop_opts = true; out.hop_kind = HopOptKind::JUMBO; out.hop_value = v;
        return true;
    }
    if (name == "pad") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v > IP6_HOP_PAD_MAX) {
            std::cerr << "--hop pad: length must be 0-" << IP6_HOP_PAD_MAX << "\n";
            return false;
        }
        out.use_hop_opts = true; out.hop_kind = HopOptKind::PAD; out.hop_value = v;
        return true;
    }
    if (name == "unknown") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v > 0xFF) {
            std::cerr << "--hop unknown: option type must be 0-255\n";
            return false;
        }
        out.use_hop_opts = true; out.hop_kind = HopOptKind::UNKNOWN;
        out.hop_unknown_type = static_cast<uint8_t>(v);
        return true;
    }
    std::cerr << "--hop: unrecognized option '" << name << "' (expected alert|jumbo|pad|unknown)\n";
    return false;
}

// Parses --dest's <option>[:<value>]. Same contract as parse_hop_option().
inline bool parse_dest_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    size_t colon = arg.find(':');
    std::string name = (colon == std::string::npos) ? arg : arg.substr(0, colon);
    std::string val  = (colon == std::string::npos) ? std::string() : arg.substr(colon + 1);

    auto parse_u32 = [](const std::string& s, uint32_t& v) -> bool {
        if (s.empty()) return false;
        try {
            size_t pos = 0;
            unsigned long parsed = std::stoul(s, &pos, 0);
            if (pos != s.size()) return false;
            v = static_cast<uint32_t>(parsed);
            return true;
        } catch (...) { return false; }
    };

    if (name == "home") {
        out.use_dest_opts = true; out.dest_kind = DestOptKind::HOME;
        if (!val.empty()) {
            struct in6_addr a{};
            if (inet_pton(AF_INET6, val.c_str(), &a) != 1) {
                std::cerr << "--dest home: invalid IPv6 address '" << val << "'\n";
                return false;
            }
            out.dest_home_addr = a; out.dest_home_addr_set = true;
        }
        return true;
    }
    if (name == "tunnel") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v > IP6_TUNNEL_MAX) {
            std::cerr << "--dest tunnel: limit must be 0-" << IP6_TUNNEL_MAX << "\n";
            return false;
        }
        out.use_dest_opts = true; out.dest_kind = DestOptKind::TUNNEL; out.dest_value = v;
        return true;
    }
    if (name == "pad") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v > IP6_DEST_PAD_MAX) {
            std::cerr << "--dest pad: length must be 0-" << IP6_DEST_PAD_MAX << "\n";
            return false;
        }
        out.use_dest_opts = true; out.dest_kind = DestOptKind::PAD; out.dest_value = v;
        return true;
    }
    if (name == "malformed") {
        out.use_dest_opts = true; out.dest_kind = DestOptKind::MALFORMED;
        return true;
    }
    if (name == "unknown") {
        uint32_t v = 0;
        if (!parse_u32(val, v) || v > 0xFF) {
            std::cerr << "--dest unknown: option type must be 0-255\n";
            return false;
        }
        out.use_dest_opts = true; out.dest_kind = DestOptKind::UNKNOWN;
        out.dest_unknown_type = static_cast<uint8_t>(v);
        return true;
    }
    std::cerr << "--dest: unrecognized option '" << name << "' (expected home|tunnel|pad|malformed|unknown)\n";
    return false;
}

// Parses --route's <spec>. Accepts: "0:N" (Type0, N segments), "2" (Type2 /
// Mobile IPv6, segments fixed at 1 internally), "srh:N" (Segment Routing,
// N segments), or any other bare integer 0-255 (--route 99 etc.) which is
// accepted as-is and flagged INVALID — this tool intentionally builds
// syntactically-bare/unrecognized routing types so you can probe how a
// target's IPv6 stack reacts to them; it is not validating RFC conformance
// of the *target's* behaviour, only of what WE are allowed to construct.
inline bool parse_route_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    auto parse_u32 = [](const std::string& s, uint32_t& v) -> bool {
        if (s.empty()) return false;
        try {
            size_t pos = 0;
            unsigned long parsed = std::stoul(s, &pos, 0);
            if (pos != s.size()) return false;
            v = static_cast<uint32_t>(parsed);
            return true;
        } catch (...) { return false; }
    };

    size_t colon = arg.find(':');
    std::string head = (colon == std::string::npos) ? arg : arg.substr(0, colon);
    std::string tail = (colon == std::string::npos) ? std::string() : arg.substr(colon + 1);

    if (head == "srh") {
        uint32_t n = 0;
        if (!parse_u32(tail, n) || n > IP6_ROUTE_SEG_MAX) {
            std::cerr << "--route srh: segment count must be 0-" << IP6_ROUTE_SEG_MAX << "\n";
            return false;
        }
        out.use_route_hdr = true; out.route_kind = RouteHdrType::SRH; out.route_segments = n;
        return true;
    }
    if (head == "0") {
        uint32_t n = 0;
        // "--route 0:3" and "--route 0:0" both require the colon form;
        // bare "--route 0" is rejected since Type 0 needs an explicit
        // segment count to be unambiguous.
        if (tail.empty() || !parse_u32(tail, n) || n > IP6_ROUTE_SEG_MAX) {
            std::cerr << "--route 0: use 0:N with N = 0-" << IP6_ROUTE_SEG_MAX
                       << " segments (e.g. --route 0:3)\n";
            return false;
        }
        out.use_route_hdr = true; out.route_kind = RouteHdrType::TYPE0; out.route_segments = n;
        return true;
    }
    if (head == "2" && tail.empty()) {
        out.use_route_hdr = true; out.route_kind = RouteHdrType::TYPE2; out.route_segments = 1;
        return true;
    }

    // Fallback: bare numeric routing type not covered above (e.g. "99").
    uint32_t raw = 0;
    if (!parse_u32(head, raw) || !tail.empty() || raw > 0xFF) {
        std::cerr << "--route: unrecognized spec '" << arg
                   << "' (expected 0:N, 2, srh:N, or a bare 0-255 routing type)\n";
        return false;
    }
    out.use_route_hdr = true; out.route_kind = RouteHdrType::INVALID;
    out.route_raw_type = static_cast<uint8_t>(raw); out.route_segments = 0;
    return true;
}

// Parses --ah's <mode>: yes|badspi|noicv|badlen|seq0
inline bool parse_ah_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    if (arg == "yes")     { out.use_ah = true; out.ah_mode = AhMode::VALID;  return true; }
    if (arg == "badspi")  { out.use_ah = true; out.ah_mode = AhMode::BADSPI; return true; }
    if (arg == "noicv")   { out.use_ah = true; out.ah_mode = AhMode::NOICV;  return true; }
    if (arg == "badlen")  { out.use_ah = true; out.ah_mode = AhMode::BADLEN; return true; }
    if (arg == "seq0")    { out.use_ah = true; out.ah_mode = AhMode::SEQ0;   return true; }
    std::cerr << "--ah: unrecognized mode '" << arg
               << "' (expected yes|badspi|noicv|badlen|seq0)\n";
    return false;
}

// Parses --esp's <mode>: yes|badpad|badspi|noiv|bad
inline bool parse_esp_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    if (arg == "yes")     { out.use_esp = true; out.esp_mode = EspMode::VALID;     return true; }
    if (arg == "badpad")  { out.use_esp = true; out.esp_mode = EspMode::BADPAD;    return true; }
    if (arg == "badspi")  { out.use_esp = true; out.esp_mode = EspMode::BADSPI;    return true; }
    if (arg == "noiv")    { out.use_esp = true; out.esp_mode = EspMode::NOIV;      return true; }
    if (arg == "bad")     { out.use_esp = true; out.esp_mode = EspMode::MALFORMED; return true; }
    std::cerr << "--esp: unrecognized mode '" << arg
               << "' (expected yes|badpad|badspi|noiv|bad)\n";
    return false;
}

// Parses --flow's <value>: a 0-1048575 number, "0", "rand", or "inc".
inline bool parse_flow_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    if (arg == "rand") { out.use_flow_label = true; out.flow_mode = FlowLabelMode::RANDOM;    return true; }
    if (arg == "inc")  { out.use_flow_label = true; out.flow_mode = FlowLabelMode::INCREMENT; return true; }
    try {
        size_t pos = 0;
        unsigned long v = std::stoul(arg, &pos, 0);
        if (pos != arg.size() || v > IP6_FLOW_LABEL_MAX) {
            std::cerr << "--flow: value must be 0-" << IP6_FLOW_LABEL_MAX
                       << ", or 'rand'/'inc'\n";
            return false;
        }
        out.use_flow_label = true; out.flow_mode = FlowLabelMode::FIXED;
        out.flow_value = static_cast<uint32_t>(v);
        return true;
    } catch (...) {
        std::cerr << "--flow: unrecognized value '" << arg << "' (expected 0-1048575, 'rand', or 'inc')\n";
        return false;
    }
}

// Maps a --chain custom:... token to its IPPROTO_* value.
inline bool chain_token_to_proto(const std::string& tok, uint8_t& proto) {
    if (tok == "HBH")   { proto = IPPROTO_HOPOPTS; return true; }
    if (tok == "DEST")  { proto = IPPROTO_DSTOPTS; return true; }
    if (tok == "ROUTE") { proto = IPPROTO_ROUTING; return true; }
    if (tok == "AH")    { proto = IPPROTO_AH;      return true; }
    if (tok == "ESP")   { proto = IPPROTO_ESP;     return true; }
    return false;
}

// Parses --chain's <option>[:<value>]. Returns false (message on stderr,
// `out` left untouched) on anything malformed or out of range.
inline bool parse_chain_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    size_t colon = arg.find(':');
    std::string name = (colon == std::string::npos) ? arg : arg.substr(0, colon);
    std::string val  = (colon == std::string::npos) ? std::string() : arg.substr(colon + 1);

    if (name == "rand")    { out.chain_mode = ChainMode::RAND;    return true; }
    if (name == "reverse") { out.chain_mode = ChainMode::REVERSE; return true; }
    if (name == "split")   { out.chain_mode = ChainMode::SPLIT;   return true; }

    if (name == "custom") {
        if (val.empty()) {
            std::cerr << "--chain custom: requires a comma-separated list, e.g. custom:AH,ESP,HBH\n";
            return false;
        }
        std::vector<uint8_t> order;
        size_t start = 0;
        while (start <= val.size()) {
            size_t comma = val.find(',', start);
            std::string tok = val.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            uint8_t proto = 0;
            if (!chain_token_to_proto(tok, proto)) {
                std::cerr << "--chain custom: unrecognized header '" << tok
                           << "' (expected HBH|DEST|ROUTE|AH|ESP)\n";
                return false;
            }
            if (std::find(order.begin(), order.end(), proto) != order.end()) {
                std::cerr << "--chain custom: '" << tok << "' listed more than once "
                             "(use --chain dup:<hop|dest|route|ah> to repeat a header)\n";
                return false;
            }
            order.push_back(proto);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        out.chain_mode = ChainMode::CUSTOM;
        out.chain_custom_order = std::move(order);
        return true;
    }

    if (name == "dup") {
        size_t colon2 = val.find(':');
        std::string target   = (colon2 == std::string::npos) ? val : val.substr(0, colon2);
        std::string countstr = (colon2 == std::string::npos) ? std::string() : val.substr(colon2 + 1);
        uint8_t proto = 0;
        if      (target == "hop")   proto = IPPROTO_HOPOPTS;
        else if (target == "dest")  proto = IPPROTO_DSTOPTS;
        else if (target == "route") proto = IPPROTO_ROUTING;
        else if (target == "ah")    proto = IPPROTO_AH;
        else {
            std::cerr << "--chain dup: unrecognized header '" << target
                       << "' (expected hop|dest|route|ah — esp can't be duplicated, "
                          "it has no next-header field of its own)\n";
            return false;
        }
        uint32_t count = 2;   // default: appears twice total
        if (!countstr.empty()) {
            try {
                size_t pos = 0;
                unsigned long v = std::stoul(countstr, &pos, 0);
                if (pos != countstr.size() || v < 2 || v > IP6_CHAIN_DUP_MAX) {
                    std::cerr << "--chain dup: count must be 2-" << IP6_CHAIN_DUP_MAX
                               << " (got '" << countstr << "')\n";
                    return false;
                }
                count = static_cast<uint32_t>(v);
            } catch (...) {
                std::cerr << "--chain dup: invalid count '" << countstr << "'\n";
                return false;
            }
        }
        out.chain_mode = ChainMode::DUP;
        out.chain_dup_target = proto;
        out.chain_dup_count  = count;
        return true;
    }

    if (name == "unknown") {
        if (val.empty()) {
            std::cerr << "--chain unknown: requires a next-header value, e.g. unknown:253\n";
            return false;
        }
        try {
            size_t pos = 0;
            unsigned long v = std::stoul(val, &pos, 0);
            if (pos != val.size() || v > 0xFF) {
                std::cerr << "--chain unknown: value must be 0-255 (got '" << val << "')\n";
                return false;
            }
            out.chain_mode = ChainMode::UNKNOWN;
            out.chain_unknown_value = static_cast<uint8_t>(v);
            return true;
        } catch (...) {
            std::cerr << "--chain unknown: invalid value '" << val << "'\n";
            return false;
        }
    }

    std::cerr << "--chain: unrecognized option '" << name
               << "' (expected rand|reverse|custom|dup|unknown|split)\n";
    return false;
}

// Parses --stop's <position>[:<value>]. Returns false (message on stderr,
// `out` left untouched) on anything malformed or out of range.
inline bool parse_stop_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    size_t colon = arg.find(':');
    std::string name = (colon == std::string::npos) ? arg : arg.substr(0, colon);
    std::string val  = (colon == std::string::npos) ? std::string() : arg.substr(colon + 1);

    if (name == "first") { out.stop_mode = StopMode::FIRST; return true; }
    if (name == "hop")   { out.stop_mode = StopMode::HOP;   return true; }
    if (name == "route") { out.stop_mode = StopMode::ROUTE; return true; }
    if (name == "all")   { out.stop_mode = StopMode::ALL;   return true; }
    if (name == "dest") {
        uint32_t n = 1;
        if (!val.empty()) {
            try {
                size_t pos = 0;
                unsigned long v = std::stoul(val, &pos, 0);
                if (pos != val.size() || v < 1 || v > IP6_CHAIN_DUP_MAX) {
                    std::cerr << "--stop dest: occurrence must be 1-" << IP6_CHAIN_DUP_MAX
                               << " (got '" << val << "')\n";
                    return false;
                }
                n = static_cast<uint32_t>(v);
            } catch (...) {
                std::cerr << "--stop dest: invalid occurrence '" << val << "'\n";
                return false;
            }
        }
        out.stop_mode = StopMode::DEST;
        out.stop_dest_n = n;
        return true;
    }
    std::cerr << "--stop: unrecognized position '" << name
               << "' (expected first|hop|dest|route|all)\n";
    return false;
}

// ───────────────────────────────────────────────────────────────────────
// TcpBuildOptions
//
// The packet-crafting knobs below (TCP options, TFO cookie, checksum
// tampering, fragmentation, IP TOS, packet-length games) used to be
// copy-pasted as ~29 individual parameters, unchanged, through every
// layer of the call chain:
//
//     thread_worker() -> worker_thread() -> receive_response()
//                      -> send_tcp_packets() -> build_packet()
//
// Bundling them into one struct, passed by const reference, removes that
// duplication and the risk of an argument-order mistake creeping into any
// one of those five signatures. It costs nothing at runtime (no copies —
// every layer just forwards the same const& down the chain), and each
// function keeps using its original field names via local reference
// aliases at the top of its body, so none of the existing logic below the
// signature line had to change.
// ───────────────────────────────────────────────────────────────────────
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

// Cheap pre-send estimate of on-wire bytes, used ONLY to decide WHEN to
// schedule a send (before the real packet exists). Mirrors build_packet()'s
// option-length math (IP 20B + TCP 20B + options) without touching any
// buffers. Deliberately approximate — real accuracy comes from the
// self-correcting actual_bytes_sent feedback in BandwidthLimiterState, so
// small misses here (e.g. TFO cookie exact length) never cause real drift.
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

// A single --debug demux event, captured during receive_response() and
// deferred until the target's whole scan is finished instead of being
// printed live — that's what used to make [demux] lines interleave with
// the port table above them. One entry per matched/dropped packet, with
// enough context (attempt #, ttl, flags, src port) to diagnose *why* a
// demux decision was made without re-running the scan.
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

// --debug strack (state tracking): one entry per port that reached a
// FINAL state (open/closed/filtered), written exactly once — at the same
// port_final choke point that locks that state in, so this can never
// race or double-record. Answers "did this port need a retry to
// resolve, and which one" without reconstructing it from the demux log.
struct StrackEntry {
    uint16_t          port             = 0;
    StrackFinalState  final_state      = StrackFinalState::None;
    int               resolved_attempt = -1;   // 0/1/2 = answered on that attempt,
                                                // -1 = never answered (timeout-filtered)
    uint16_t          src_port         = 0;    // src port the resolving packet used (0 if never answered)
    double            rtt_ms           = -1.0; // -1 = not measured
    bool              is_icmp          = false;
};

// Aggregate counts for a target's --debug strack session.
struct StrackCounters {
    uint64_t resolved_attempt0 = 0;
    uint64_t resolved_attempt1 = 0;
    uint64_t resolved_attempt2 = 0;
    uint64_t unresolved        = 0;   // filtered, no attempt ever answered

    StrackCounters& operator+=(const StrackCounters& o) {
        resolved_attempt0 += o.resolved_attempt0;
        resolved_attempt1 += o.resolved_attempt1;
        resolved_attempt2 += o.resolved_attempt2;
        unresolved        += o.unresolved;
        return *this;
    }
};

struct RecPross {
    int closed_ports = 0;
    std::vector<uint16_t> open_ports;
    std::vector<uint16_t> filtered_ports;
    // Port → ICMP admin-prohibited reason. Only set when reason is known.
    std::unordered_map<uint16_t, IcmpFilterReason> icmp_filter_reasons;
    // Non-fatal path-level ICMP warnings collected during the scan.
    // Each entry is (reason_enum, human-readable description string).
    // Printed in the reason section after the scan completes.
    std::vector<std::pair<IcmpFilterReason, std::string>> icmp_warnings;
    std::string mac_address;
    int learned_rtt_ms = 0;
    std::unordered_map<uint16_t, PacketDetails> packet_details;
    int packets_sent = 0;
    uint8_t received_ttl = 0;
    std::vector<std::pair<int, double>> rtt_debug_entries;
    // --debug demux: buffered events + running counters for this target,
    // merged batch-by-batch in thread_worker() and printed once, after the
    // scan finishes, by print_demux_debug().
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

// IPv6 TCP pseudo-header (RFC 8200 §8.1): 16+16 byte addrs, 32-bit length
// (not 16-bit — IPv6 payloads can exceed 64KB via jumbograms, though Shiv's
// TCP scan payloads never will), 3 zero bytes, 1-byte next-header. Fed to the
// same checksum() in utils.cpp used for IPv4 — that function is already
// buffer-generic, so no new checksum routine is needed, only the right bytes.
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
    uint16_t src_port;uint32_t seq;uint32_t ack_seq;bool connection_established;bool fin_sent;bool fin_ack_received; std::chrono::steady_clock::time_point start_time;int retry_count;int timeout_ms;
    bool rtt_measured;std::chrono::steady_clock::time_point syn_sent_time;uint32_t sent_tsval;double ewma_rtt; bool final_state_determined;enum class PortReportedState { None, Open, Closed, Filtered };
    PortReportedState reported_state;

    // src_port stays "most recent send port" (TX path unaffected).
    // RX validation must accept a reply addressed to ANY local port we've
    // ever probed from for this target port, not just the latest one,
    // because a retry can overwrite src_port before an earlier reply lands.
    std::array<uint16_t, 6> used_src_ports{};
    std::array<uint8_t, 6>  used_src_port_attempt{};   // attempt number recorded alongside each port
    uint8_t                 used_src_port_count = 0;
    bool                    retry_send_deferred = false;
    // Deferred FIRST send: jitter/rate pacing decided this port's initial
    // SYN should go out later than "now". Instead of blocking the dispatch
    // loop with a sleep, we push a deadline_heap entry and let the existing
    // heap-driven wait loop fire the actual send when it's due — same
    // idiom as retry_send_deferred, just for the first send instead of a
    // retry. See receive_response()'s per-port dispatch loop and the
    // "Heap-driven timeout processing" block for the two ends of this.
    bool                    initial_send_deferred = false;
    // Set true the moment this port is counted in the global
    // ports_in_retry tally (first retry). Lets us decrement exactly
    // once when the port reaches a final state, so the live
    // filtered_ratio reflects currently-outstanding retries instead
    // of a cumulative count that can only grow.
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

    // Returns the attempt number that actually sent from src port p.
    // Falls back to the live retry_count only if p was never recorded,
    // which shouldn't happen for anything that passed accepts_src_port().
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
    // IPv4 destination — untouched: same type, same offset-zero layout, same
    // direct-member-access hot path as before. is_ipv6 tells build_packet()
    // which of {dest, dest6} is live; dest4-only code paths never pay for
    // dest6's existence beyond the extra 28 bytes in the struct.
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

    // IPv6 mirror of the constructor above. Same parameter list save for the
    // address type; dest (v4) is left zero-initialized and is_ipv6=true tells
    // build_packet()/send_tcp_packets() to take the IPv6 header path.
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
uint32_t get_local_ip(const char *remote_ip);

// --dst-mac / --ether-dst-multicast support -----------------------------
// These install/remove a permanent, completed entry in the kernel's own
// neighbour (ARP) table for `ifname`. Once installed, the kernel's normal
// L2-resolution code — the same code the IPPROTO_RAW/IP_HDRINCL send
// socket in main.cpp relies on for every outgoing TCP packet — addresses
// frames to `mac` directly and never issues a real ARP request for that
// IP. This is what makes the flag affect actual scan traffic without
// touching the TCP send path (scan.cpp) at all: the TCP packets are built
// and sent exactly as before, only the kernel's idea of "who has this IP"
// is overridden ahead of time.
//
// ip_bytes is 4 raw bytes in network order (as already used throughout
// this codebase for target IPs). Requires CAP_NET_ADMIN (the process
// already needs root for raw sockets, so this is not an extra privilege
// requirement in practice).
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

// IPv6 counterpart of SlotMeta. Can't be reused via a template/union trick
// without touching every existing SlotMeta call site — kept as a parallel
// struct instead, same layout otherwise. IMPORTANT asymmetry vs SlotMeta:
// on Linux, an AF_INET6 SOCK_RAW/IPPROTO_TCP socket does NOT include the
// IPv6 header in received data (unlike AF_INET, which does) — recv() lands
// directly on the TCP header. src_addr here is therefore the *only* source
// of the sender's address; there's no struct ip6_hdr in the payload to read
// it back out of, unlike the v4 dispatch path's iph->ip_src.
struct SlotMeta6 {
    struct sockaddr_in6 src_addr;
    socklen_t           src_len;
    struct iovec        iov;
    struct msghdr       msg;
    alignas(struct cmsghdr) char cmsg_buf[128];
};

// Hashable 128-bit address key for the v6 counterparts of GlobalRecvCtx's
// ip_to_idx/target_queues/idle_ring_fds (all keyed on uint32_t, which simply
// cannot hold a v6 address — this isn't optional, hence a real key type
// rather than e.g. truncating to 32 bits).
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

    // Packet type: set by recv_reader_thread_func before enqueue.
    // ICMP packets contain the raw IP datagram starting at the outer IP header.
    // TCP6/ICMPV6 packets do NOT have an outer IPv6 header in `data` (Linux
    // strips it for AF_INET6 raw sockets) — data starts at the TCP header
    // (TCP6) or the ICMPv6 header (ICMPV6) directly. See SlotMeta6's comment.
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
    // IPv6 TCP recv slots. Separate storage/buffers (not sharing recv_bufs)
    // since SlotMeta6's src_addr type differs and the payload here starts
    // at the TCP header, not an IP header — mixing them into one array
    // would need a per-slot family tag on the hot dispatch path for no
    // benefit, since the flag-bit dispatch below already distinguishes them
    // at zero extra cost.
    std::unique_ptr<uint8_t[]> buf6_storage;
    std::vector<SlotMeta6>   slots6;
    uint8_t*                 bufs      = nullptr;
    uint8_t*                 bufs6     = nullptr;
    bool                     valid     = false;
    // true if this ring is running with a kernel-side SQPOLL thread
    // (io_uring_submit() calls become syscall-free while it stays awake).
    // false means init_global_recv_ctx() fell back to a plain ring —
    // still fully functional, just without the submit-side syscall savings.
    bool                     sqpoll_active = false;

    // Fixed-file registration state for this ring's tcp_sock/icmp_sock.
    // Set once in init_global_recv_ctx(); read (never written) afterward
    // by recv_reader_thread_func on the reader thread only.
    bool  fixed_files_active = false;
    int   tcp_fixed_idx      = -1;
    int   icmp_fixed_idx     = -1;   // -1 if icmp_sock creation failed
    int   tcp6_fixed_idx     = -1;   // -1 if tcp6_sock unused/creation failed
    int   icmpv6_fixed_idx   = -1;   // -1 if icmpv6_sock unused/creation failed

    // ── ICMP slot constants ───────────────────────────────────────────────
    // ICMP recv SQEs use user_data = ICMP_SLOT_FLAG | icmp_slot_index.
    // The flag occupies bit 32, keeping TCP slot indices (0..N_SLOTS-1)
    // distinct even if N_SLOTS somehow reached 2^32 (it never will).
    //
    // SECURITY: the reader dispatches on this flag before any array indexing,
    // so a corrupt/stale user_data value cannot alias a TCP slot index.
    static constexpr uint64_t ICMP_SLOT_FLAG  = (1ULL << 32);
    static constexpr size_t   N_ICMP_SLOTS    = 4;   // ICMP bursts are rare

    // user_data tag for IORING_OP_MSG_RING wake-signal SQEs that this
    // thread's own ring submits (targeting another thread's idle_ring).
    // Occupies bit 33 — disjoint from ICMP_SLOT_FLAG (bit 32) and from any
    // real TCP slot index (0..N_SLOTS-1), so a completion tagged with this
    // flag can never be mistaken for a TCP/ICMP recv completion by the
    // dispatch loop, and vice versa.
    static constexpr uint64_t WAKE_ACK_FLAG   = (1ULL << 33);

    // IPv6 counterparts — bits 34/35, disjoint from every flag above and
    // from plain TCP4 slot indices (which occupy the low bits unflagged).
    // SECURITY: same invariant as ICMP_SLOT_FLAG — dispatch checks these
    // bits before any array indexing, in recv_reader_thread_func.
    static constexpr uint64_t TCP6_SLOT_FLAG    = (1ULL << 34);
    static constexpr uint64_t ICMPV6_SLOT_FLAG  = (1ULL << 35);
    static constexpr size_t   N_ICMPV6_SLOTS    = 4;   // mirrors N_ICMP_SLOTS

    // ICMP recv buffers (one per slot, raw IP datagram including outer IP hdr)
    std::array<std::array<uint8_t, 1500>, N_ICMP_SLOTS> icmp_bufs{};
    std::array<struct iovec,      N_ICMP_SLOTS>          icmp_iovs{};
    std::array<struct msghdr,     N_ICMP_SLOTS>          icmp_msgs{};
    std::array<struct sockaddr_in,N_ICMP_SLOTS>          icmp_src_addrs{};
    std::array<socklen_t,         N_ICMP_SLOTS>          icmp_src_lens{};

    // ICMPv6 recv buffers — mirrors the ICMP arrays above. No outer IPv6
    // header is present here either (see SlotMeta6's comment); an ICMPv6
    // error message's *body* still embeds the original IPv6 header of the
    // packet that triggered it (RFC 4443), which is what inner-packet
    // parsing in the dispatch loop reads to find the original destination.
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
    // ── idle-ring registry for IORING_OP_MSG_RING wakeups ──────────────────
    // Maps target IP -> that target's idle_ring fd, so the single global
    // reader thread can wake the correct per-target consumer the instant a
    // packet is dispatched to it, instead of that consumer polling on a
    // timer (see recv_reader_thread_func's post-dispatch signal step and
    // receive_response's idle-wait loop in scan.cpp).
    //
    // Guarded by a shared_mutex: the signal path (reader thread) takes a
    // shared lock for the lookup + SQE prep + submit; register/unregister
    // take a unique lock. Because the signal path holds its shared lock
    // across the actual io_uring_submit() call (not just the map lookup),
    // unregister_idle_ring() cannot return — and therefore the caller
    // cannot proceed to io_uring_queue_exit()/close the fd — while a
    // MSG_RING submission targeting that fd is still in flight. This is
    // what makes it safe to submit MSG_RING to an fd owned by another
    // thread without a use-after-close race.
    std::shared_mutex        idle_ring_mu;
    std::unordered_map<uint32_t, int> idle_ring_fds;
    // IPv6 counterpart, guarded by the same idle_ring_mu (one mutex for
    // both maps is fine — register/unregister/signal are all cheap map ops,
    // no reason to add lock contention risk with a second mutex).
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
        if (tcp_sock    >= 0) { close(tcp_sock);    tcp_sock    = -1; }
        if (icmp_sock   >= 0) { close(icmp_sock);   icmp_sock   = -1; }  // NEW
        if (tcp6_sock   >= 0) { close(tcp6_sock);   tcp6_sock   = -1; }
        if (icmpv6_sock >= 0) { close(icmpv6_sock); icmpv6_sock = -1; }
    }
    GlobalRecvCtx(const GlobalRecvCtx&)            = delete;
    GlobalRecvCtx& operator=(const GlobalRecvCtx&) = delete;
};
// ── Global shared send resources (1 socket + 1 ring for all targets) ──────
struct GlobalSendCtx {
    int             sock  = -1;   // owned externally (main), do NOT close here — IPv4
    int             sock6 = -1;   // owned externally (main), do NOT close here — IPv6, may stay -1 if v6 isn't in use
    struct io_uring ring{};
    bool            valid = false;
    // true if this ring is running with a kernel-side SQPOLL thread
    // (io_uring_submit() calls become syscall-free while it stays awake).
    // false means init_global_send_ctx() fell back to a plain ring —
    // still fully functional, just without the submit-side syscall savings.
    bool            sqpoll_active = false;

    GlobalSendCtx() = default;
    ~GlobalSendCtx() {
        if (valid) io_uring_queue_exit(&ring);
    }
    GlobalSendCtx(const GlobalSendCtx&)            = delete;
    GlobalSendCtx& operator=(const GlobalSendCtx&) = delete;
};

// Creates and initialises a GlobalSendCtx.
// sock must already be open and configured (IP_HDRINCL etc).
// sock6, if >= 0, must already be open and configured (v6 raw TCP socket)
// and gets registered as a second fixed file alongside sock.
std::unique_ptr<GlobalSendCtx> init_global_send_ctx(
    int    sock,
    size_t send_uring_depth,
    size_t num_ports,
    bool   enable_sqpoll,
    int    sock6 = -1);

RecPross receive_response(const char *dest_ip, std::span<const int> ports, uint32_t local_ip, 
                      std::mt19937 &rng, PacketBufferPool &pool, int send_sock, 
                      uint16_t source_port, uint16_t retry_source_port, uint32_t seq_num, uint16_t win_size,
                      bool print_individual_closed_filtered, bool print_filtered_if_few, 
                      struct io_uring *send_ring, bool fast_scan, size_t batch_size,
                      ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp, 
                      uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                      const TcpBuildOptions& opts,
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

// Prints one target's buffered --debug demux report: aggregate counters
// plus a breakdown of the buffered events. Call once per target, after
// that target's RTT info has been printed, never from inside the receive
// path — entries/counts must already reflect the FULL scan for the target
// (i.e. merged across every batch in thread_worker()).
void print_demux_debug(const std::string& target_ip,
                        const std::vector<DemuxDebugEntry>& entries,
                        const DemuxDebugCounters& counts,
                        const std::vector<uint16_t>& open_ports);
                        
void print_strack_debug(const std::string& target_ip,
                         const std::vector<StrackEntry>& entries,
                         const StrackCounters& counts);

void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,uint8_t sent_ws);

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
                      int max_round_timeout_ms = 1000);
                   
#endif
