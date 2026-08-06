#include "parser.hpp"
#include <cctype>
#include <unordered_map>

bool parse_sport_range_config(const std::string& arg, SportRangeConfig& out) {
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
        for (int i = 0; i < 6; ++i) {
            out.stage_is_range[i] = true;
            out.stage_min[i] = lo;
            out.stage_max[i] = hi;
        }
        return true;
    }

    bool seen[6] = {false, false, false, false, false, false};
    size_t pos = 0;
    while (pos <= arg.size()) {
        size_t comma = arg.find(',', pos);
        std::string token = arg.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = (comma == std::string::npos) ? arg.size() + 1 : comma + 1;

        size_t colon = token.find(':');
        if (colon == std::string::npos || colon == 0 || colon == token.size() - 1) {
            std::cerr << "--sport-range: use format N:MIN-MAX (N=0-5), e.g. 0:2222-3333\n";
            return false;
        }
        int stage_num;
        try {
            stage_num = std::stoi(token.substr(0, colon));
        } catch (const std::exception&) {
            std::cerr << "--sport-range: invalid attempt number '" << token.substr(0, colon) << "'\n";
            return false;
        }
        if (stage_num < 0 || stage_num > 5) {
            std::cerr << "--sport-range: attempt number must be 0-5 (0=initial, 1-5=retries)\n";
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

bool parse_gsport_config(const std::string& arg, GsportConfig& out) {
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

    bool seen[6] = {false, false, false, false, false, false};
    size_t pos = 0;
    while (pos <= arg.size()) {
        size_t comma = arg.find(',', pos);
        std::string token = arg.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = (comma == std::string::npos) ? arg.size() + 1 : comma + 1;

        size_t colon = token.find(':');
        if (colon == std::string::npos || colon == 0 || colon == token.size() - 1) {
            std::cerr << "-g: use format N:PORT (N=0-5), e.g. 0:443\n";
            return false;
        }
        int stage_num;
        try {
            stage_num = std::stoi(token.substr(0, colon));
        } catch (const std::exception&) {
            std::cerr << "-g: invalid attempt number '" << token.substr(0, colon) << "'\n";
            return false;
        }
        if (stage_num < 0 || stage_num > 5) {
            std::cerr << "-g: attempt number must be 0-5 (0=initial, 1-5=retries)\n";
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

bool parse_duration_to_us(std::string_view s,
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

    // ── sanity check ─────────────────────────────────────────────────────
    if (!std::isfinite(val)) {
        std::cerr << flag_name << ": value must be a finite number (not NaN/Inf)\n";
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

bool parse_rate_config(const std::string& arg, RateConfig& out) {
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

bool parse_jitter_config(const std::string& arg, JitterConfig& out) {
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

bool parse_batch_delay_config(const std::string& arg, BatchDelayConfig& out) {
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

bool parse_bandwidth_config(const std::string& arg, BandwidthConfig& out) {
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

    std::string lo_part = num_part, hi_part;
    bool is_range = false;
    size_t dash = num_part.find('-');
    if (dash != std::string::npos && dash > 0 && dash < num_part.size() - 1) {
        lo_part  = num_part.substr(0, dash);
        hi_part  = num_part.substr(dash + 1);
        is_range = true;
    }

    uint64_t bytes_lo = 0, bytes_hi = 0;
    try {
        bytes_lo = std::stoull(lo_part);
        bytes_hi = is_range ? std::stoull(hi_part) : bytes_lo;
    } catch (const std::exception&) {
        std::cerr << "--bandwidth: invalid byte value '" << bytes_part << "'\n";
        return false;
    }
    if (bytes_lo == 0) {
        std::cerr << "--bandwidth: byte total must be > 0\n";
        return false;
    }
    if (is_range && bytes_hi < bytes_lo) {
        std::cerr << "--bandwidth: range min must be <= max (got "
                   << lo_part << "-" << hi_part << ")\n";
        return false;
    }

    out.enabled         = true;
    out.window_us       = window_us;
    out.total_bytes_min = bytes_lo * multiplier;
    out.total_bytes_max = (is_range ? bytes_hi : bytes_lo) * multiplier;
    return true;
}

bool parse_packet_length(const std::string& arg, PacketLengthConfig& out) {
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

bool parse_dscp_value(const std::string& arg, uint8_t& out_dscp) {
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

bool parse_ip_tos_value(const std::string& arg, uint8_t& out_tos) {
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

bool parse_ip_id_mode(const std::string& arg,
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

bool parse_hop_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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

bool parse_dest_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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

bool parse_route_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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

bool parse_ah_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    if (arg == "yes")     { out.use_ah = true; out.ah_mode = AhMode::VALID;  return true; }
    if (arg == "badspi")  { out.use_ah = true; out.ah_mode = AhMode::BADSPI; return true; }
    if (arg == "noicv")   { out.use_ah = true; out.ah_mode = AhMode::NOICV;  return true; }
    if (arg == "badlen")  { out.use_ah = true; out.ah_mode = AhMode::BADLEN; return true; }
    if (arg == "seq0")    { out.use_ah = true; out.ah_mode = AhMode::SEQ0;   return true; }
    std::cerr << "--ah: unrecognized mode '" << arg
               << "' (expected yes|badspi|noicv|badlen|seq0)\n";
    return false;
}

bool parse_esp_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
    if (arg == "yes")     { out.use_esp = true; out.esp_mode = EspMode::VALID;     return true; }
    if (arg == "badpad")  { out.use_esp = true; out.esp_mode = EspMode::BADPAD;    return true; }
    if (arg == "badspi")  { out.use_esp = true; out.esp_mode = EspMode::BADSPI;    return true; }
    if (arg == "noiv")    { out.use_esp = true; out.esp_mode = EspMode::NOIV;      return true; }
    if (arg == "bad")     { out.use_esp = true; out.esp_mode = EspMode::MALFORMED; return true; }
    std::cerr << "--esp: unrecognized mode '" << arg
               << "' (expected yes|badpad|badspi|noiv|bad)\n";
    return false;
}

bool parse_flow_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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

bool chain_token_to_proto(const std::string& tok, uint8_t& proto) {
    if (tok == "HBH")   { proto = IPPROTO_HOPOPTS; return true; }
    if (tok == "DEST")  { proto = IPPROTO_DSTOPTS; return true; }
    if (tok == "ROUTE") { proto = IPPROTO_ROUTING; return true; }
    if (tok == "AH")    { proto = IPPROTO_AH;      return true; }
    if (tok == "ESP")   { proto = IPPROTO_ESP;     return true; }
    return false;
}

bool parse_chain_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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

bool parse_stop_option(const std::string& arg, Ipv6ExtHeaderOptions& out) {
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
