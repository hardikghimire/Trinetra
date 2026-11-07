#include "os_detect.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <numeric>
#include <set>
#include <sstream>

bool g_os_detect = false;

namespace osdetect {
namespace {

constexpr const char* C_RESET = "\033[0m";
constexpr const char* C_BOLD  = "\033[1m";
constexpr const char* C_CYAN  = "\033[96m";
constexpr const char* C_YEL   = "\033[93m";
constexpr const char* C_GREEN = "\033[92m";
constexpr const char* C_RED   = "\033[91m";
constexpr const char* C_WHITE = "\033[97m";

enum class IpIdClass : int { Unknown = -1, Zero = 0, Const, Incr, Swap, Random, Mixed };
enum class IsnClass  : int { Unknown = -1, Random = 0, Time, Incr, Const };
enum class TsClass   : int { Unknown = -1, Low = 0, Hz100, Hz250, Hz1000, Other };
enum class Style     { Linux, Windows, Darwin, FreeBSD, OpenBSD, Solaris, MssOnly };

constexpr unsigned OPT_WS = 1, OPT_SACK = 2, OPT_TS = 4;

constexpr const char* kUnknownName   = "Unrecognised / custom TCP stack";
constexpr const char* kUnknownFamily = "Unknown";

struct Sample {
    uint16_t port = 0;
    uint8_t  ttl = 0;
    int      init_ttl = 0, hops = 0;
    bool     ttl_ok = true;
    bool     df = false;
    uint16_t ipid = 0;
    uint8_t  tos = 0;
    uint8_t  flags = 0;
    uint16_t win = 0;
    uint32_t seq = 0, ack = 0;
    std::string layout, order;
    bool     has_mss = false;  uint16_t mss = 0;
    bool     has_ws = false;   uint8_t  ws = 0;
    bool     sack = false;
    bool     has_ts = false;   uint32_t tsval = 0, tsecr = 0;
    uint16_t urg = 0;
    uint16_t payload = 0;
    uint8_t  rsvd = 0;         // NS + 3 reserved bits of TCP header byte 12
    bool     rsvd_ok = false;  // false when the raw packet could not be located
    bool     unk_opts = false; // unrecognised TCP option kinds present
    uint32_t sent_seq = 0;     // our ISN for this port (0 = unknown)
    int64_t  t_us = 0;
};

using SPtr = const Sample*;

inline double lg(double p) { return std::log(std::max(p, 0.01)); }

int infer_init_ttl(int ttl, int& hops, bool& plausible) {
    static const int cand[] = {32, 64, 128, 255};
    for (int c : cand) {
        if (ttl <= c) { hops = c - ttl; plausible = hops <= 40; return c; }
    }
    hops = 0; plausible = false; return 255;
}

std::string substantive_order(const std::string& layout) {
    std::istringstream is(layout);
    std::string tok, out;
    while (is >> tok) {
        if (tok == "NOP" || tok == "EOL") continue;
        if (!out.empty()) out += ' ';
        out += tok;
    }
    return out;
}

bool is_subsequence(const std::string& small, const std::string& big) {
    std::istringstream a(small), b(big);
    std::string ta, tb;
    bool have_a = static_cast<bool>(a >> ta);
    while (have_a && (b >> tb)) {
        if (ta == tb) have_a = static_cast<bool>(a >> ta);
    }
    return !have_a;
}

template <class K, class Fn>
K mode_of(const std::vector<SPtr>& v, Fn fn, double* frac = nullptr) {
    std::map<K, int> m;
    for (SPtr s : v) ++m[fn(*s)];
    K best{};
    int bc = -1;
    for (const auto& kv : m) if (kv.second > bc) { best = kv.first; bc = kv.second; }
    if (frac) *frac = v.empty() ? 0.0 : static_cast<double>(bc) / static_cast<double>(v.size());
    return best;
}

double median_inplace(std::vector<double>& v) {
    const size_t n = v.size();
    const size_t mid = n / 2;
    std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(mid), v.end());
    double m = v[mid];
    if (n % 2 == 0) {
        const double lo = *std::max_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(mid));
        m = (m + lo) / 2.0;
    }
    return m;
}

std::string join_ports(const std::vector<uint16_t>& p, size_t max_show = 10) {
    std::string out;
    for (size_t i = 0; i < p.size() && i < max_show; ++i) {
        if (i) out += ',';
        out += std::to_string(p[i]);
    }
    if (p.size() > max_show) out += ",+" + std::to_string(p.size() - max_show);
    return out;
}

std::string fmt_pct(double p) {
    char b[16];
    std::snprintf(b, sizeof(b), "%.1f%%", p * 100.0);
    return b;
}

std::string fmt_num(double v, int prec = 1) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.*f", prec, v);
    return b;
}

std::string json_esc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += static_cast<char>(c);
        }
    }
    return o;
}

int ip_offset_in_raw(const std::vector<uint8_t>& raw, size_t ihl) {
    if (raw.size() >= ihl + 20 && (raw[0] >> 4) == 4 &&
        static_cast<size_t>(raw[0] & 0x0F) * 4 == ihl)
        return 0;
    if (raw.size() >= 14 + ihl + 20 && raw[12] == 0x08 && raw[13] == 0x00 &&
        (raw[14] >> 4) == 4 && static_cast<size_t>(raw[14] & 0x0F) * 4 == ihl)
        return 14;
    return -1;
}

bool make_sample(uint16_t port, const PacketDetails& d, Sample& s,
                 std::unordered_map<std::string, std::string>& order_cache) {
    if (d.ttl == 0 || d.src_ip.empty()) return false;         
    if (d.ip_protocol != IPPROTO_TCP) return false;

    s.port   = port;
    s.ttl    = d.ttl;
    s.init_ttl = infer_init_ttl(d.ttl, s.hops, s.ttl_ok);
    s.df     = d.df_flag;
    s.ipid   = d.ip_id;
    s.tos    = d.ip_tos;
    s.flags  = d.tcp_flags;
    s.win    = d.window_size;
    s.seq    = d.seq_num;
    s.ack    = d.ack_num;
    s.layout = d.tcp_option_layout;
    auto it = order_cache.find(s.layout);
    if (it == order_cache.end()) it = order_cache.emplace(s.layout, substantive_order(s.layout)).first;
    s.order  = it->second;
    s.has_mss = d.has_mss;              s.mss = d.mss_value;
    s.has_ws  = d.has_window_scale;     s.ws  = d.window_scale;
    s.sack    = d.sack_permitted || d.has_sack;
    s.has_ts  = d.has_timestamp;        s.tsval = d.tsval;  s.tsecr = d.tsecr;
    s.urg     = d.tcp_urg_ptr;
    s.payload = d.payload_len ? d.payload_len : d.length;
    s.unk_opts = d.has_unknown_options;
    s.sent_seq = d.sent_seq;

    const size_t ihl = d.ip_header_len;
    if (ihl >= 20) {
        const int off = ip_offset_in_raw(d.raw_packet, ihl);
        if (off >= 0) {
            s.rsvd = static_cast<uint8_t>(d.raw_packet[static_cast<size_t>(off) + ihl + 12] & 0x0F);
            s.rsvd_ok = true;
        }
    }
    s.t_us    = d.kernel_rx_ts_us > 0 ? d.kernel_rx_ts_us
              : (d.capture_epoch_us ? static_cast<int64_t>(d.capture_epoch_us) : d.user_rx_ts_us);
    return true;
}

const char* ipid_name(IpIdClass c) {
    switch (c) {
        case IpIdClass::Zero:   return "zero";
        case IpIdClass::Const:  return "constant";
        case IpIdClass::Incr:   return "incrementing";
        case IpIdClass::Swap:   return "incrementing(LE)";
        case IpIdClass::Random: return "random";
        case IpIdClass::Mixed:  return "mixed(zero+non-zero)";
        default:                return "?";
    }
}

const char* isn_name(IsnClass c) {
    switch (c) {
        case IsnClass::Random: return "random";
        case IsnClass::Time:   return "time-dependent";
        case IsnClass::Incr:   return "small-increment";
        case IsnClass::Const:  return "constant";
        default:               return "?";
    }
}

bool ids_incrementing(const std::vector<uint16_t>& ids, bool swap) {
    if (ids.size() < 2) return false;
    const size_t pairs = ids.size() - 1;
    const uint16_t max_step = pairs <= 2 ? 1024 : 4096;
    size_t ok = 0;
    for (size_t i = 1; i < ids.size(); ++i) {
        uint16_t a = ids[i - 1], b = ids[i];
        if (swap) {
            a = static_cast<uint16_t>((a << 8) | (a >> 8));
            b = static_cast<uint16_t>((b << 8) | (b >> 8));
        }
        const uint16_t d = static_cast<uint16_t>(b - a);
        if (d >= 1 && d <= max_step) ++ok;
    }
    if (pairs <= 3) return ok == pairs;
    return ok * 100 >= pairs * 80;
}

IpIdClass classify_ipid(std::vector<std::pair<int64_t, uint16_t>> v) {
    if (v.empty()) return IpIdClass::Unknown;
    std::stable_sort(v.begin(), v.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
    size_t zeros = 0;
    for (const auto& p : v) if (p.second == 0) ++zeros;
    if (zeros == v.size()) return IpIdClass::Zero;
    if (zeros > 0) return v.size() >= 2 ? IpIdClass::Mixed : IpIdClass::Unknown;
    if (v.size() < 2) return IpIdClass::Unknown;

    std::vector<uint16_t> ids;
    ids.reserve(v.size());
    for (const auto& p : v) ids.push_back(p.second);
    if (std::all_of(ids.begin(), ids.end(), [&](uint16_t x) { return x == ids[0]; }))
        return IpIdClass::Const;
    if (ids_incrementing(ids, false)) return IpIdClass::Incr;
    if (ids_incrementing(ids, true))  return IpIdClass::Swap;
    return v.size() >= 3 ? IpIdClass::Random : IpIdClass::Unknown;
}

IsnClass classify_isn(std::vector<std::pair<int64_t, uint32_t>> v) {
    if (v.size() < 2) return IsnClass::Unknown;
    std::stable_sort(v.begin(), v.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<int64_t> d;
    std::vector<double> dt;
    d.reserve(v.size());
    dt.reserve(v.size());
    for (size_t i = 1; i < v.size(); ++i) {
        d.push_back(static_cast<int32_t>(v[i].second - v[i - 1].second));
        dt.push_back(static_cast<double>(v[i].first - v[i - 1].first) / 1e6);
    }
    if (std::all_of(d.begin(), d.end(), [](int64_t x) { return x == 0; })) return IsnClass::Const;
    std::vector<double> rates;
    for (size_t i = 0; i < d.size(); ++i)
        if (d[i] > 0 && dt[i] >= 0.002) rates.push_back(static_cast<double>(d[i]) / dt[i]);
    if (rates.size() >= 3 && rates.size() == d.size()) {
        const double mean = std::accumulate(rates.begin(), rates.end(), 0.0) / static_cast<double>(rates.size());
        double var = 0;
        for (double r : rates) var += (r - mean) * (r - mean);
        var /= static_cast<double>(rates.size());
        if (mean > 500.0 && std::sqrt(var) / mean < 0.30) return IsnClass::Time;
    }
    if (d.size() >= 3) {
        uint64_t g = 0;
        for (int64_t x : d) g = std::gcd(g, static_cast<uint64_t>(std::llabs(x)));
        if (g >= 64) return IsnClass::Time;
    }

    bool all_small = true;
    for (int64_t x : d) if (std::llabs(x) > (1 << 24)) { all_small = false; break; }
    if (all_small) return IsnClass::Incr;
    return IsnClass::Random;
}

struct TsInfo {
    bool     ok = false;          // enough data for a rate estimate
    bool     consistent = true;   // single linear clock fits the samples
    bool     constant = false;    // TSval never changes although time passed
    double   hz = 0.0;
    double   span = 0.0;          // seconds covered
    double   rel_err = 1.0;       // expected relative error of `hz` (jitter model)
    int      n = 0;
    uint32_t last_tsval = 0;
};

TsInfo analyze_ts(const std::vector<SPtr>& src) {
    TsInfo ti;
    std::vector<SPtr> v;
    for (SPtr s : src) if (s->has_ts && s->tsval != 0) v.push_back(s);
    ti.n = static_cast<int>(v.size());
    if (!v.empty()) ti.last_tsval = v.back()->tsval;
    if (v.size() < 2) return ti;
    std::stable_sort(v.begin(), v.end(), [](SPtr a, SPtr b) { return a->t_us < b->t_us; });
    ti.last_tsval = v.back()->tsval;

    std::vector<double> x, y;
    x.reserve(v.size());
    y.reserve(v.size());
    double cum = 0;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) cum += static_cast<double>(static_cast<int32_t>(v[i]->tsval - v[i - 1]->tsval));
        x.push_back(static_cast<double>(v[i]->t_us - v[0]->t_us) / 1e6);
        y.push_back(cum);
    }
    ti.span = x.back();
    if (ti.span < 0.02) return ti;
    if (std::all_of(y.begin(), y.end(), [](double q) { return q == 0.0; })) { ti.constant = true; return ti; }

    std::vector<size_t> idx;
    constexpr size_t kCap = 48;
    if (x.size() <= kCap) { idx.resize(x.size()); std::iota(idx.begin(), idx.end(), size_t{0}); }
    else for (size_t i = 0; i < kCap; ++i) idx.push_back(i * (x.size() - 1) / (kCap - 1));

    std::vector<double> slopes;
    slopes.reserve(idx.size() * (idx.size() - 1) / 2);
    for (size_t a = 0; a < idx.size(); ++a)
        for (size_t b = a + 1; b < idx.size(); ++b) {
            const double dx = x[idx[b]] - x[idx[a]];
            if (dx >= 0.002) slopes.push_back((y[idx[b]] - y[idx[a]]) / dx);
        }
    if (slopes.empty()) return ti;
    const double slope = median_inplace(slopes);
    if (slope <= 0) return ti;

    if (x.size() >= 3) {
        std::vector<double> ic;
        ic.reserve(x.size());
        for (size_t i = 0; i < x.size(); ++i) ic.push_back(y[i] - slope * x[i]);
        const double icpt = median_inplace(ic);
        const double range = std::fabs(y.back() - y.front());
        const double tol = std::max(3.0, slope * 0.006 + 0.03 * range);  
        size_t outliers = 0;
        for (size_t i = 0; i < x.size(); ++i)
            if (std::fabs(y[i] - (icpt + slope * x[i])) > tol) ++outliers;
        ti.consistent = outliers * 10 <= x.size();
    }
    ti.hz = slope;
    ti.rel_err = std::clamp(0.0085 / ti.span / std::sqrt(std::max(1.0, ti.n / 2.0)), 0.02, 1.0);
    ti.ok = ti.consistent;
    return ti;
}

double snap_hz(double hz, double rel_err) {
    static const double std_hz[] = {1, 2, 10, 20, 64, 100, 128, 200, 250, 300, 500, 512, 1000, 1024};
    if (rel_err > 0.35) return 0.0;
    const double tol = std::max(0.12, 2.0 * rel_err);
    double best = 0, bd = 1e9;
    for (double s : std_hz) {
        const double d = std::fabs(std::log(hz / s));
        if (d < bd) { bd = d; best = s; }
    }
    return bd <= tol ? best : 0.0;
}

TsClass ts_class(double hz) {
    if (hz < 50)   return TsClass::Low;
    if (hz < 160)  return TsClass::Hz100;
    if (hz < 400)  return TsClass::Hz250;
    if (hz < 1500) return TsClass::Hz1000;
    return TsClass::Other;
}

std::array<double, 5> ts_soft(double hz, double rel_err) {
    struct Anchor { double hz; int cls; };
    static const Anchor anchors[] = {
        {1, 0}, {2, 0}, {10, 0}, {20, 0},
        {64, 1}, {100, 1}, {128, 1},
        {200, 2}, {250, 2}, {300, 2},
        {500, 3}, {512, 3}, {1000, 3}, {1024, 3},
        {2000, 4}, {4000, 4}, {10000, 4}};
    const double sigma = std::max(0.10, rel_err);
    std::array<double, 5> w{};
    double tot = 0;
    for (const Anchor& a : anchors) {
        const double z = std::log(hz / a.hz) / sigma;
        const double k = std::exp(-0.5 * z * z);
        w[static_cast<size_t>(a.cls)] += k;
        tot += k;
    }
    if (tot < 1e-9) { w = {}; w[static_cast<size_t>(ts_class(hz))] = 1.0; return w; }
    for (double& q : w) q /= tot;
    return w;
}

std::string build_layout(Style st, bool ws, bool sack, bool ts) {
    std::vector<std::string> t;
    auto add = [&](const char* s) { t.emplace_back(s); };
    switch (st) {
        case Style::Linux:     
            add("MSS");
            if (ts) { if (sack) add("SACK-OK"); else { add("NOP"); add("NOP"); } add("TS"); }
            else if (sack) { add("NOP"); add("NOP"); add("SACK-OK"); }
            if (ws) { add("NOP"); add("WS"); }
            break;
        case Style::Windows:
            add("MSS");
            if (ws)   { add("NOP"); add("WS"); }
            if (ts)   { add("NOP"); add("NOP"); add("TS"); }
            if (sack) { add("NOP"); add("NOP"); add("SACK-OK"); }
            break;
        case Style::Darwin: {
            add("MSS");
            int len = 4;
            if (ws)   { add("NOP"); add("WS"); len += 4; }
            if (ts)   { add("NOP"); add("NOP"); add("TS"); len += 12; }
            if (sack) { add("SACK-OK"); len += 2; }
            if (len % 4) add("EOL");
            break;
        }
        case Style::FreeBSD:
            add("MSS");
            if (ws) { add("NOP"); add("WS"); }
            if (sack) { if (ts) add("SACK-OK"); else { add("NOP"); add("NOP"); add("SACK-OK"); } }
            if (ts) add("TS");
            break;
        case Style::OpenBSD:
            add("MSS");
            if (sack) { add("NOP"); add("NOP"); add("SACK-OK"); }
            if (ws)   { add("NOP"); add("WS"); }
            if (ts)   { add("NOP"); add("NOP"); add("TS"); }
            break;
        case Style::Solaris:
            if (ts)   { add("NOP"); add("NOP"); add("TS"); }
            add("MSS");
            if (ws)   { add("NOP"); add("WS"); }
            if (sack) { add("NOP"); add("NOP"); add("SACK-OK"); }
            break;
        case Style::MssOnly:
            add("MSS");
            break;
    }
    std::string out;
    for (size_t i = 0; i < t.size(); ++i) { if (i) out += ' '; out += t[i]; }
    return out;
}

struct Profile {
    const char* name;
    const char* family;
    double prior;
    std::vector<int> ttl;               // plausible initial TTLs
    Style style;
    bool sup_ws, sup_sack, sup_ts;      // options this stack answers with by default
    std::vector<uint16_t> win;          // characteristic SYN-ACK windows
    std::vector<uint16_t> win_soft;     // occasionally seen
    bool win_mss_mult;                  // window is a multiple of MSS (Linux)
    std::vector<int> win_k;             // preferred multipliers
    double win_unknown_p;               // P(any other window)
    int ws_lo, ws_hi;                   // SYN-ACK window-scale range
    double df_p;                        // P(DF set on SYN-ACK)
    std::array<double, 6> ipid;
    std::array<double, 4> isn;
    std::array<double, 5> ts;
    double ecn_p;                       // P(ECE in SYN-ACK | ECN-setup SYN)
    double rst_win0_p;                  // P(RST window == 0)
    bool ts_uptime_ok;                  // TS clock starts at boot (uptime guess valid)
};

const std::vector<Profile>& profiles() {
    static const std::vector<Profile> P = {
        {   // 0
            "Linux 5.x - 6.x (incl. Android, containers, most cloud VMs)", "Linux", 0.26,
            {64}, Style::Linux, true, true, true,
            {}, {65535}, true, {45, 44}, 0.05, 4, 11, 0.97,
            {0.60, 0.02, 0.10, 0.01, 0.07, 0.20},
            {0.95, 0.02, 0.01, 0.02},
            {0.02, 0.02, 0.05, 0.86, 0.05},
            0.88, 0.97, false },
        {   // 1
            "Linux 4.x (incl. RHEL 8, Ubuntu 16.04 / 18.04)", "Linux", 0.08,
            {64}, Style::Linux, true, true, true,
            {}, {65535}, true, {20, 22}, 0.05, 4, 11, 0.97,
            {0.50, 0.02, 0.20, 0.01, 0.07, 0.20},
            {0.95, 0.02, 0.01, 0.02},
            {0.02, 0.04, 0.28, 0.60, 0.06},
            0.88, 0.97, false },
        {   // 2
            "Linux 2.6 - 3.x", "Linux", 0.04,
            {64}, Style::Linux, true, true, true,
            {}, {65535}, true, {4, 10, 20, 22}, 0.05, 3, 9, 0.95,
            {0.25, 0.02, 0.45, 0.02, 0.06, 0.20},
            {0.90, 0.05, 0.02, 0.03},
            {0.02, 0.28, 0.35, 0.30, 0.05},
            0.85, 0.95, true },
        {   // 3
            "Windows 10 / 11 / Server 2016 - 2025", "Windows", 0.16,
            {128}, Style::Windows, true, true, false,
            {65535, 64240}, {8192}, false, {}, 0.04, 8, 8, 0.98,
            {0.01, 0.01, 0.76, 0.02, 0.10, 0.10},
            {0.90, 0.05, 0.02, 0.03},
            {0.20, 0.20, 0.20, 0.20, 0.20},
            0.08, 0.97, false },
        {   // 4
            "Windows Vista / 7 / 8 / Server 2008 - 2012 R2", "Windows", 0.05,
            {128}, Style::Windows, true, true, false,
            {8192}, {65535, 64240}, false, {}, 0.04, 8, 8, 0.98,
            {0.01, 0.01, 0.78, 0.02, 0.08, 0.10},
            {0.88, 0.07, 0.02, 0.03},
            {0.20, 0.20, 0.20, 0.20, 0.20},
            0.06, 0.97, false },
        {   // 5
            "Windows XP / 2003 / 2000", "Windows", 0.005,
            {128}, Style::Windows, false, true, false,
            {64240, 65535, 17520, 16384, 8760}, {}, false, {}, 0.05, 0, 0, 0.98,
            {0.01, 0.01, 0.70, 0.18, 0.05, 0.05},
            {0.45, 0.40, 0.10, 0.05},
            {0.20, 0.20, 0.20, 0.20, 0.20},
            0.02, 0.95, false },
        {   // 6
            "macOS / iOS / iPadOS / tvOS (Darwin)", "Apple", 0.06,
            {64}, Style::Darwin, true, true, true,
            {65535}, {}, false, {}, 0.03, 3, 7, 0.97,
            {0.05, 0.01, 0.05, 0.01, 0.80, 0.08},
            {0.95, 0.02, 0.01, 0.02},
            {0.02, 0.30, 0.05, 0.60, 0.03},
            0.50, 0.98, false },
        {   // 7
            "FreeBSD (incl. pfSense, OPNsense, TrueNAS, NetApp)", "BSD", 0.035,
            {64}, Style::FreeBSD, true, true, true,
            {65535}, {16384}, false, {}, 0.04, 5, 9, 0.96,
            {0.30, 0.02, 0.30, 0.01, 0.30, 0.07},
            {0.93, 0.03, 0.02, 0.02},
            {0.02, 0.25, 0.03, 0.68, 0.02},
            0.12, 0.97, false },
        {   // 8
            "OpenBSD", "BSD", 0.01,
            {64}, Style::OpenBSD, true, true, true,
            {16384}, {65535}, false, {}, 0.04, 3, 7, 0.95,
            {0.02, 0.01, 0.05, 0.01, 0.88, 0.03},
            {0.97, 0.01, 0.01, 0.01},
            {0.05, 0.35, 0.05, 0.50, 0.05},
            0.08, 0.98, false },
        {   // 9
            "Solaris / illumos / OpenIndiana", "Solaris", 0.01,
            {255, 64}, Style::Solaris, true, true, true,
            {}, {}, false, {}, 0.25, 0, 5, 0.90,
            {0.02, 0.02, 0.75, 0.02, 0.09, 0.10},
            {0.40, 0.35, 0.20, 0.05},
            {0.05, 0.45, 0.05, 0.40, 0.05},
            0.60, 0.85, true },
        {   // 10
            "Cisco IOS / IOS-XE / ASA (network device)", "Network device", 0.02,
            {255}, Style::MssOnly, false, false, false,
            {4128, 16384, 8192}, {65535}, false, {}, 0.15, 0, 0, 0.35,
            {0.02, 0.03, 0.85, 0.03, 0.02, 0.05},
            {0.45, 0.25, 0.15, 0.15},
            {0.20, 0.20, 0.20, 0.20, 0.20},
            0.05, 0.60, true },
        {   // 11
            "Embedded / RTOS (lwIP, uIP, VxWorks, printers, IoT firmware)", "Embedded", 0.03,
            {64, 255, 128, 32}, Style::MssOnly, false, false, false,
            {5744, 2144, 4096, 8192, 5840, 2920, 1024, 4380, 8760, 16384}, {}, false, {}, 0.30, 0, 0, 0.40,
            {0.05, 0.10, 0.55, 0.10, 0.10, 0.10},
            {0.30, 0.15, 0.35, 0.20},
            {0.30, 0.25, 0.15, 0.15, 0.15},
            0.03, 0.40, true },
        {   // 12
            "Juniper JunOS / older FreeBSD-based appliance", "BSD", 0.005,
            {64}, Style::FreeBSD, true, true, true,
            {16384}, {}, false, {}, 0.05, 0, 6, 0.90,
            {0.05, 0.03, 0.55, 0.02, 0.30, 0.05},
            {0.60, 0.20, 0.10, 0.10},
            {0.05, 0.30, 0.05, 0.55, 0.05},
            0.10, 0.90, false },
    };
    return P;
}

struct ProfLayout {
    std::array<std::string, 8> layout;
    std::array<std::string, 8> order;
};

const std::vector<ProfLayout>& profile_layouts() {
    static const std::vector<ProfLayout> L = [] {
        std::vector<ProfLayout> v;
        for (const Profile& p : profiles()) {
            ProfLayout pl;
            for (unsigned m = 0; m < 8; ++m) {
                pl.layout[m] = build_layout(p.style, (m & OPT_WS) != 0, (m & OPT_SACK) != 0, (m & OPT_TS) != 0);
                pl.order[m]  = substantive_order(pl.layout[m]);
            }
            v.push_back(std::move(pl));
        }
        return v;
    }();
    return L;
}

struct PortHint { uint16_t lo, hi; const char* fam; double nats; const char* why; };

const PortHint kPortHints[] = {
    {135,   135,   "Windows",        1.2, "MS-RPC"},
    {139,   139,   "Windows",        0.7, "NetBIOS"},
    {445,   445,   "Windows",        0.8, "SMB"},
    {3389,  3389,  "Windows",        1.4, "RDP"},
    {5985,  5986,  "Windows",        1.2, "WinRM"},
    {47001, 47001, "Windows",        1.0, "WinRM listener"},
    {5357,  5357,  "Windows",        0.9, "WSD API"},
    {2179,  2179,  "Windows",        0.8, "Hyper-V console"},
    {1433,  1433,  "Windows",        0.4, "MS SQL"},
    {49152, 49157, "Windows",        0.8, "RPC dynamic range"},
    {49664, 49670, "Windows",        0.9, "RPC dynamic range"},
    {22,    22,    "Unix",           0.3, "SSH"},
    {111,   111,   "Unix",           0.9, "rpcbind"},
    {2049,  2049,  "Unix",           0.8, "NFS"},
    {62078, 62078, "Apple",          2.0, "iOS lockdownd"},
    {548,   548,   "Apple",          1.2, "AFP"},
    {23,    23,    "Network device", 0.4, "telnet"},
    {23,    23,    "Embedded",       0.4, "telnet"},
    {179,   179,   "Network device", 0.7, "BGP"},
    {9100,  9100,  "Embedded",       1.0, "raw printing"},
    {515,   515,   "Embedded",       0.4, "LPD"},
    {8291,  8291,  "Linux",          0.6, "MikroTik Winbox"},
};

struct PortPrior {
    std::map<std::string, double>                nats;    // family -> boost (nats)
    std::map<std::string, std::vector<uint16_t>> ports;   // family -> ports that contributed
};

PortPrior port_prior(const std::vector<SPtr>& sa) {
    PortPrior pp;
    static const char* const kUnix[] = {"Linux", "BSD", "Apple", "Solaris"};
    for (SPtr s : sa) {
        for (const PortHint& h : kPortHints) {
            if (s->port < h.lo || s->port > h.hi) continue;
            auto credit = [&](const char* fam) {
                pp.nats[fam] += h.nats;
                auto& v = pp.ports[fam];
                if (std::find(v.begin(), v.end(), s->port) == v.end()) v.push_back(s->port);
            };
            if (std::string(h.fam) == "Unix") for (const char* u : kUnix) credit(u);
            else credit(h.fam);
        }
    }
    for (auto& kv : pp.nats) kv.second = std::min(kv.second, 2.2);
    return pp;
}

struct Feat {
    bool have_ttl = false;    int init_ttl = 0, ttl_obs = 0, hops = 0;  bool ttl_ok = true;
    bool have_layout = false; std::string layout, order;  double layout_frac = 1.0;
    bool layout_known = true;   // some profile (under some option subset) produces this layout
    bool have_win = false;    uint16_t win = 0;  int win_k = 0;  int mss = 0;  double win_frac = 1.0;
    bool ws_present = false;  int ws = 0;
    bool have_df = false;     bool df = false;
    IpIdClass ipid = IpIdClass::Unknown;  int ipid_n = 0;
    IsnClass  isn = IsnClass::Unknown;    int isn_n = 0;
    TsClass   tsc = TsClass::Unknown;     TsInfo tsi;   double hz_snap = 0;
    std::array<double, 5> tssoft{};
    bool have_ecn = false;    bool ecn_yes = false;
    bool have_rst = false;    double rst_win0 = 0;
};

bool layout_known_to_any(const std::string& layout, const std::string& order, unsigned offered) {
    const auto& P  = profiles();
    const auto& PL = profile_layouts();
    for (size_t i = 0; i < P.size(); ++i) {
        if (P[i].style == Style::MssOnly && layout.empty()) return true;
        for (unsigned m = 0; m < 8; ++m) {
            if (m & ~offered) continue;
            if (layout == PL[i].layout[m] || order == PL[i].order[m]) return true;
        }
    }
    return false;
}

Feat extract_features(const std::vector<SPtr>& sa, const std::vector<SPtr>& rst,
                      const Context& ctx, Fingerprint& fp) {
    Feat f;
    fp.n_synack = static_cast<int>(sa.size());
    fp.n_rst    = static_cast<int>(rst.size());

    // TTL
    const std::vector<SPtr>& base = sa.empty() ? rst : sa;
    if (!base.empty()) {
        f.have_ttl = true;
        f.init_ttl = mode_of<int>(base, [](const Sample& s) { return s.init_ttl; });
        std::vector<SPtr> same;
        for (SPtr s : base) if (s->init_ttl == f.init_ttl) same.push_back(s);
        f.ttl_obs = mode_of<int>(same, [](const Sample& s) { return static_cast<int>(s.ttl); });
        f.hops    = f.init_ttl - f.ttl_obs;
        f.ttl_ok  = f.hops <= 40;
        fp.ttl_observed = f.ttl_obs; fp.ttl_init = f.init_ttl; fp.hops = f.hops; fp.ttl_plausible = f.ttl_ok;
    }

    // SYN-ACK static features
    if (!sa.empty()) {
        f.have_layout = true;
        f.layout = mode_of<std::string>(sa, [](const Sample& s) { return s.layout; }, &f.layout_frac);
        f.order  = substantive_order(f.layout);
        fp.layout = f.layout.empty() ? "(none)" : f.layout;
        fp.layout_consistency = f.layout_frac;
        f.layout_known = layout_known_to_any(f.layout, f.order,
            (ctx.offered_ws ? OPT_WS : 0u) | (ctx.offered_sack ? OPT_SACK : 0u) | (ctx.offered_ts ? OPT_TS : 0u));

        f.have_win = true;
        f.win = mode_of<uint16_t>(sa, [](const Sample& s) { return s.win; }, &f.win_frac);
        fp.window = f.win;
        fp.window_consistency = f.win_frac;

        std::vector<SPtr> with_mss;
        for (SPtr s : sa) if (s->has_mss) with_mss.push_back(s);
        if (!with_mss.empty()) {
            f.mss = mode_of<int>(with_mss, [](const Sample& s) { return static_cast<int>(s.mss); });
            fp.mss = f.mss;
        }
        auto try_unit = [&](int unit) -> int {
            if (unit <= 0 || f.win == 0 || f.win % unit) return 0;
            const int k = f.win / unit;
            return (k >= 2 && k <= 100) ? k : 0;
        };
        f.win_k = try_unit(f.mss);
        if (!f.win_k) f.win_k = try_unit(f.mss - 12);
        fp.window_k = f.win_k;

        std::vector<SPtr> with_ws;
        for (SPtr s : sa) if (s->has_ws) with_ws.push_back(s);
        if (!with_ws.empty()) {
            f.ws_present = true;
            f.ws = mode_of<int>(with_ws, [](const Sample& s) { return static_cast<int>(s.ws); });
            fp.wscale = f.ws;
        }

        f.have_df = true;
        f.df = mode_of<int>(sa, [](const Sample& s) { return s.df ? 1 : 0; }) != 0;
        fp.df = f.df ? 1 : 0;
    }

    {
        std::vector<std::pair<int64_t, uint16_t>> ids;
        ids.reserve(sa.size() + rst.size());
        for (SPtr s : sa) ids.emplace_back(s->t_us, s->ipid);
        if (sa.size() < 2) for (SPtr s : rst) ids.emplace_back(s->t_us, s->ipid);
        f.ipid_n = static_cast<int>(ids.size());
        f.ipid = classify_ipid(std::move(ids));
        fp.ipid = ipid_name(f.ipid);
    }

    {
        std::vector<std::pair<int64_t, uint32_t>> isns;
        isns.reserve(sa.size());
        for (SPtr s : sa) isns.emplace_back(s->t_us, s->seq);
        f.isn_n = static_cast<int>(isns.size());
        f.isn = classify_isn(std::move(isns));
        fp.isn = isn_name(f.isn);
    }
    fp.ts = "n/a";
    if (!sa.empty()) {
        f.tsi = analyze_ts(sa);
        if (f.tsi.ok && f.tsi.hz > 0) {
            f.hz_snap = snap_hz(f.tsi.hz, f.tsi.rel_err);
            f.tsc = ts_class(f.tsi.hz);
            f.tssoft = ts_soft(f.tsi.hz, f.tsi.rel_err);
            fp.ts_hz = f.tsi.hz;
            fp.ts = f.hz_snap > 0 ? fmt_num(f.hz_snap, 0) + " Hz"
                                  : "~" + fmt_num(f.tsi.hz, 0) + " Hz";
        } else if (f.tsi.constant) {
            fp.ts = "constant value";
        } else if (f.tsi.n >= 3 && !f.tsi.consistent) {
            fp.ts = "inconsistent clock";
        } else if (f.tsi.n >= 1) {
            fp.ts = "present (rate unmeasurable)";
        }
    }
    fp.ecn = "not tested";
    if (ctx.sent_ecn_setup && !sa.empty()) {
        f.have_ecn = true;
        const int yes = mode_of<int>(sa, [](const Sample& s) {
            return ((s.flags & TH_ECE) && !(s.flags & TH_CWR)) ? 1 : 0; });
        f.ecn_yes = yes != 0;
        fp.ecn = f.ecn_yes ? "negotiated" : "not negotiated";
    }
    if (!rst.empty()) {
        f.have_rst = true;
        size_t z = 0;
        for (SPtr s : rst) if (s->win == 0) ++z;
        f.rst_win0 = static_cast<double>(z) / static_cast<double>(rst.size());
    }
    {
        std::set<std::string> q;
        auto scan = [&](const std::vector<SPtr>& v, const char* tag) {
            for (SPtr s : v) {
                if (s->rsvd_ok) {
                    if (s->rsvd & 0x0E) q.insert(std::string(tag) + " sets TCP reserved bits");
                    if (s->rsvd & 0x01) q.insert(std::string(tag) + " sets ECN-nonce (NS) bit");
                }
                if (s->urg != 0 && !(s->flags & TH_URG)) q.insert(std::string(tag) + " has non-zero urgent pointer without URG");
                if (s->payload > 0) q.insert(std::string(tag) + " carries payload");
                if (s->unk_opts) q.insert(std::string(tag) + " carries unrecognised TCP option kinds");
                if (s->tos != 0) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "%02X", s->tos);
                    q.insert(std::string(tag) + " has non-zero IP TOS (0x" + b + ")");
                }
            }
        };
        scan(sa, "SYN-ACK");
        scan(rst, "RST");
        if (!sa.empty() && f.win == 0) q.insert("SYN-ACK advertises window 0");
        if (!sa.empty() && f.layout.empty() && (ctx.offered_ws || ctx.offered_sack || ctx.offered_ts))
            q.insert("SYN-ACK carries no options although we offered some");
        if (sa.size() >= 3 && f.win_frac < 0.7)
            q.insert("SYN-ACK window differs between ports (only " + fmt_pct(f.win_frac) + " share the most common value)");
        if (sa.size() >= 3 && f.layout_frac < 0.7)
            q.insert("SYN-ACK option layout differs between ports (only " + fmt_pct(f.layout_frac) + " share the most common one)");
        if (f.mss > 0 && (f.mss < 536 || f.mss > 9000))
            q.insert("unusual SYN-ACK MSS " + std::to_string(f.mss));
        for (SPtr s : sa)
            if ((s->flags & TH_CWR) || ((s->flags & TH_ECE) && !(ctx.sent_flags & TH_ECE))) {
                q.insert("SYN-ACK sets ECE/CWR although no ECN was requested");
                break;
            }
        fp.quirks.assign(q.begin(), q.end());
    }
    return f;
}

enum Slot : size_t { S_TTL, S_LAYOUT, S_WINDOW, S_WSCALE, S_DF, S_IPID, S_ISN, S_TS, S_ECN, S_RST, S_PORTS, S_COUNT };

struct Term { double lp = 0.0; std::string detail; };
using Terms = std::array<Term, S_COUNT>;

template <class C, class T>
bool contains(const C& c, const T& v) { return std::find(c.begin(), c.end(), v) != c.end(); }

std::string describe_mask(unsigned m) {
    std::string s;
    auto add = [&](const char* n) { if (!s.empty()) s += " + "; s += n; };
    if (m & OPT_WS)   add("window-scale");
    if (m & OPT_SACK) add("SACK");
    if (m & OPT_TS)   add("timestamps");
    return s;
}

struct LayoutFit { double prob = 0.03; std::string how; };

LayoutFit layout_fit(const Profile& p, const ProfLayout& pl, const Feat& f, unsigned offered,
                     bool want_detail) {
    LayoutFit best;
    const unsigned def = ((p.sup_ws ? OPT_WS : 0u) | (p.sup_sack ? OPT_SACK : 0u) | (p.sup_ts ? OPT_TS : 0u)) & offered;
    for (unsigned m = 0; m < 8; ++m) {
        if (m & ~offered) continue;
        double fac = 1.0;
        for (unsigned bit : {OPT_WS, OPT_SACK, OPT_TS}) {
            const bool d = (def & bit) != 0, pr = (m & bit) != 0;
            if (d && !pr)      fac *= bit == OPT_WS ? 0.20 : 0.30;   // switched off (sysctl / hardening)
            else if (!d && pr) fac *= 0.08;                          // switched on (non-default)
        }
        double prob = 0.0;
        bool exact = false;
        if (f.layout == pl.layout[m])     { prob = 0.80 * fac; exact = true; }
        else if (f.order == pl.order[m])  { prob = 0.35 * fac; }
        if (prob > best.prob) {
            best.prob = prob;
            if (want_detail) {
                std::string how = exact ? "exact match" : "same option order, different NOP/EOL padding";
                if (m != def) {
                    const unsigned off = def & ~m, on = m & ~def;
                    if (off) how += " with " + describe_mask(off) + " disabled";
                    if (on)  how += std::string(off ? ", " : " with ") + describe_mask(on) + " enabled";
                }
                best.how = how;
            }
        }
    }
    if (best.prob <= 0.03 && p.style == Style::MssOnly && f.layout.empty()) {
        best.prob = 0.45;
        if (want_detail) best.how = "no options (minimal stack)";
    }
    if (best.prob <= 0.03 && want_detail)
        best.how = "expected '" + pl.layout[def] + "'";
    return best;
}

double score_hypothesis(const Profile* p, const ProfLayout* pl, const Feat& f, const Context& ctx,
                        const PortPrior& pp, Terms& T, bool want_detail) {
    const bool nul = (p == nullptr);
    auto D = [&](auto&& fn) { return want_detail ? std::string(fn()) : std::string(); };
    auto put = [&](Slot s, double w, double prob, std::string detail) {
        T[s].lp = w * lg(prob);
        if (want_detail) T[s].detail = std::move(detail);
    };
    const unsigned offered = (ctx.offered_ws ? OPT_WS : 0u) | (ctx.offered_sack ? OPT_SACK : 0u) | (ctx.offered_ts ? OPT_TS : 0u);

    // 1. initial TTL
    if (f.have_ttl) {
        const bool match = !nul && contains(p->ttl, f.init_ttl);
        put(S_TTL, f.ttl_ok ? 1.0 : 0.5, nul ? 0.25 : (match ? 0.90 : 0.04), D([&] {
            return "initial TTL " + std::to_string(f.init_ttl) + " (observed " + std::to_string(f.ttl_obs) +
                   ", ~" + std::to_string(f.hops) + " hops) " + (nul ? "" : (match ? "fits" : "does not fit")); }));
    }

    // 2. option layout (all option subsets we offered)
    if (f.have_layout) {
        if (nul) {
            put(S_LAYOUT, 1.3, f.layout_known ? 0.05 : 0.40, D([&] {
                return "options [" + (f.layout.empty() ? std::string("none") : f.layout) + "]: " +
                       (f.layout_known ? "a known stack would normally be recognised here" : "no known stack uses this layout"); }));
        } else {
            const LayoutFit lf = layout_fit(*p, *pl, f, offered, want_detail);
            put(S_LAYOUT, 1.3, lf.prob, D([&] {
                return "options [" + (f.layout.empty() ? std::string("none") : f.layout) + "]: " + lf.how; }));
        }
    }

    // 3. window
    if (f.have_win) {
        double prob = 0.05; std::string how = "not typical for any known stack";
        if (!nul) {
            if (contains(p->win, f.win)) { prob = 0.70; how = "characteristic value"; }
            else if (p->win_mss_mult && f.win_k && contains(p->win_k, f.win_k)) {
                prob = 0.60; how = std::to_string(f.win_k) + "xMSS, typical multiplier"; }
            else if (p->win_mss_mult && f.win_k) { prob = 0.30; how = std::to_string(f.win_k) + "xMSS"; }
            else if (contains(p->win_soft, f.win)) { prob = 0.30; how = "seen occasionally"; }
            else { prob = p->win_unknown_p; how = "not typical for this stack"; }
        }
        put(S_WINDOW, 1.0, prob, D([&] { return "SYN-ACK window " + std::to_string(f.win) + ": " + how; }));
    }

    // 4. window scale
    if (f.ws_present) {
        double prob; std::string how;
        if (nul)           { prob = 0.15; how = "no known stack fits"; }
        else if (p->sup_ws) {
            const bool in = f.ws >= p->ws_lo && f.ws <= p->ws_hi;
            prob = in ? 0.80 : 0.08; how = in ? " in usual range" : " outside usual range";
        } else             { prob = 0.25; how = " not applicable"; }
        put(S_WSCALE, 0.6, prob, D([&] { return "window scale " + std::to_string(f.ws) + how; }));
    }

    // 5. DF
    if (f.have_df) {
        const double pr = nul ? 0.5 : (f.df ? p->df_p : 1.0 - p->df_p);
        put(S_DF, 0.5, std::clamp(pr, 0.02, 0.98), D([&] { return std::string("DF ") + (f.df ? "set" : "clear"); }));
    }

    // 6. IP-ID class
    if (f.ipid != IpIdClass::Unknown) {
        const double rel = f.ipid == IpIdClass::Zero ? (f.ipid_n >= 2 ? 0.9 : 0.8)
                                                     : std::min(1.0, std::max(0.4, f.ipid_n / 4.0));
        put(S_IPID, 0.8 * rel, nul ? 1.0 / 6.0 : p->ipid[static_cast<size_t>(f.ipid)],
            D([&] { return std::string("IP-ID ") + ipid_name(f.ipid); }));
    }

    // 7. ISN class
    if (f.isn != IsnClass::Unknown) {
        const double rel = f.isn_n >= 3 ? 1.0 : 0.5;
        put(S_ISN, 0.7 * rel, nul ? 0.25 : p->isn[static_cast<size_t>(f.isn)],
            D([&] { return std::string("ISN ") + isn_name(f.isn); }));
    }

    // 8. TCP timestamp clock (soft class membership)
    if (f.tsc != TsClass::Unknown && (nul || p->sup_ts)) {
        double prob = 0.30;
        if (!nul) {
            prob = 0;
            for (size_t c = 0; c < 5; ++c) prob += f.tssoft[c] * p->ts[c];
        }
        const double rel = std::clamp(0.20 / std::max(f.tsi.rel_err, 1e-3), 0.35, 1.0);
        put(S_TS, 0.6 * rel, prob, D([&] {
            return "TS clock " + (f.hz_snap > 0 ? fmt_num(f.hz_snap, 0) : fmt_num(f.tsi.hz, 0)) + " Hz"; }));
    }

    // 9. ECN
    if (f.have_ecn) {
        const double pr = nul ? 0.5 : (f.ecn_yes ? p->ecn_p : 1.0 - p->ecn_p);
        put(S_ECN, 1.0, std::clamp(pr, 0.03, 0.97), D([&] {
            return std::string(f.ecn_yes ? "ECN negotiated" : "ECN not negotiated"); }));
    }

    // 10. RST window
    if (f.have_rst) {
        const double pr = nul ? 0.5 : f.rst_win0 * p->rst_win0_p + (1.0 - f.rst_win0) * (1.0 - p->rst_win0_p);
        put(S_RST, 0.4, std::clamp(pr, 0.05, 0.98), D([&] {
            return std::string(f.rst_win0 >= 0.5 ? "RST window 0" : "RST window non-zero"); }));
    }

    // 11. open-port prior (log-boost applies to the matching family only)
    if (!nul) {
        auto it = pp.nats.find(p->family);
        if (it != pp.nats.end() && it->second > 0) {
            T[S_PORTS].lp = it->second;
            if (want_detail) {
                const auto& v = pp.ports.at(p->family);
                T[S_PORTS].detail = "open ports " + join_ports(v, 6) + " are typical of " + p->family + " hosts";
            }
        }
    }

    {
        std::array<Slot, 4> blk = {S_LAYOUT, S_WINDOW, S_WSCALE, S_DF};
        std::sort(blk.begin(), blk.end(), [&](Slot a, Slot b) { return std::fabs(T[a].lp) > std::fabs(T[b].lp); });
        static const double mult[4] = {1.0, 0.75, 0.55, 0.40};
        for (size_t r = 0; r < blk.size(); ++r) T[blk[r]].lp *= mult[r];
    }

    double total = std::log(nul ? 0.06 : p->prior);   // P(stack is in none of the profiles)
    for (const Term& t : T) total += t.lp;
    return total;
}

Group analyze_group(const std::string& label, const std::vector<SPtr>& sa,
                    const std::vector<SPtr>& rst, const Context& ctx, double anomaly_factor) {
    Group g;
    g.label = label;
    for (SPtr s : sa) g.ports.push_back(s->port);
    if (sa.empty()) for (SPtr s : rst) g.ports.push_back(s->port);
    std::sort(g.ports.begin(), g.ports.end());
    g.ports.erase(std::unique(g.ports.begin(), g.ports.end()), g.ports.end());

    const Feat f = extract_features(sa, rst, ctx, g.fp);
    const PortPrior pp = port_prior(sa);
    const auto& P  = profiles();
    const auto& PL = profile_layouts();
    const size_t N = P.size() + 1;            // last index = "unrecognised stack"
    const size_t UNK = P.size();

    constexpr double kTemp = 1.5;
    std::vector<double> raw(N), pr(N);
    {
        Terms scratch;
        for (size_t i = 0; i < N; ++i) {
            for (Term& t : scratch) t = Term{};
            raw[i] = score_hypothesis(i < UNK ? &P[i] : nullptr, i < UNK ? &PL[i] : nullptr,
                                      f, ctx, pp, scratch, false) / kTemp;
        }
    }
    const double mx = *std::max_element(raw.begin(), raw.end());
    double z = 0;
    for (size_t i = 0; i < N; ++i) { pr[i] = std::exp(raw[i] - mx); z += pr[i]; }
    for (double& x : pr) x /= z;

    auto name_of   = [&](size_t i) { return i < UNK ? std::string(P[i].name)   : std::string(kUnknownName); };
    auto family_of = [&](size_t i) { return i < UNK ? std::string(P[i].family) : std::string(kUnknownFamily); };

    std::vector<size_t> idx(N);
    std::iota(idx.begin(), idx.end(), 0);
    std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return pr[a] > pr[b]; });
    for (size_t i : idx) g.ranked.push_back({name_of(i), family_of(i), raw[i], pr[i]});

    std::map<std::string, double> fam;
    for (size_t i = 0; i < N; ++i) fam[family_of(i)] += pr[i];
    for (const auto& kv : fam) g.families.emplace_back(kv.first, kv.second);
    std::sort(g.families.begin(), g.families.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    g.family_prob  = fam[family_of(idx[0])];
    g.unknown_prob = pr[UNK];
    g.unrecognised = idx[0] == UNK;

    size_t rival = 1;
    for (size_t k = 1; k < idx.size(); ++k)
        if (family_of(idx[k]) != family_of(idx[0])) { rival = k; break; }
    {
        Terms t1, t2;
        const size_t a = idx[0], b = idx[rival];
        score_hypothesis(a < UNK ? &P[a] : nullptr, a < UNK ? &PL[a] : nullptr, f, ctx, pp, t1, true);
        score_hypothesis(b < UNK ? &P[b] : nullptr, b < UNK ? &PL[b] : nullptr, f, ctx, pp, t2, true);
        for (size_t k = 0; k < S_COUNT; ++k) {
            const double delta = t1[k].lp - t2[k].lp;   // weighted nats, unscaled
            if (std::fabs(delta) >= 0.4 && !t1[k].detail.empty()) g.evidence.push_back({t1[k].detail, delta});
        }
        std::sort(g.evidence.begin(), g.evidence.end(),
                  [](const Evidence& x, const Evidence& y) { return std::fabs(x.delta) > std::fabs(y.delta); });
    }
    if (idx.size() >= 2) {
        const size_t a = idx[0], b = idx[1];
        if (family_of(a) != family_of(b) && pr[b] >= 0.25 * pr[a])
            g.ambiguity = "close call between " + name_of(a) + " and " + name_of(b);
        else if (family_of(a) == family_of(b) && pr[a] < 0.60 && !g.unrecognised)
            g.ambiguity = family_of(a) + " family is clear, exact version is ambiguous (" + name_of(b) + " is close)";
    }
    double cov = 0;
    if (f.have_ttl) cov += 1.0;
    if (f.have_layout) cov += 2.0;
    if (f.have_win) cov += 1.0;
    if (f.ws_present) cov += 0.5;
    if (f.have_df) cov += 0.5;
    if (f.ipid != IpIdClass::Unknown) cov += std::min(1.0, f.ipid_n / 4.0);
    if (f.isn != IsnClass::Unknown) cov += f.isn_n >= 3 ? 1.0 : 0.5;
    if (f.tsc != TsClass::Unknown) cov += 1.0;
    if (f.have_ecn) cov += 1.0;
    if (f.have_rst) cov += 0.5;
    const double coverage = std::min(1.0, cov / 7.0);
    double consistency = 1.0;
    if (sa.size() >= 3) consistency = 0.8 + 0.2 * std::min(f.win_frac, f.layout_frac);

    g.confidence = g.family_prob * (0.5 + 0.5 * coverage) * anomaly_factor * consistency;
    g.confidence_label = g.confidence >= 0.75 ? "HIGH" : g.confidence >= 0.50 ? "MEDIUM"
                       : g.confidence >= 0.30 ? "LOW" : "VERY LOW";
    if (g.unrecognised && g.confidence_label != "VERY LOW") g.confidence_label = "LOW";
    if (f.tsi.ok && f.hz_snap > 0 && !g.unrecognised && idx.size() && idx[0] < UNK && P[idx[0]].ts_uptime_ok) {
        const double secs = static_cast<double>(f.tsi.last_tsval) / f.hz_snap;
        if (secs > 60 && secs < 3.0 * 365 * 86400) {
            std::string u = "~" + fmt_num(secs / 86400.0, 1) + " days";
            const double wrap_days = 4294967296.0 / f.hz_snap / 86400.0;
            if (wrap_days < 1000.0)
                u += " (modulo " + fmt_num(wrap_days, 1) + " days: the 32-bit TSval wraps)";
            g.fp.uptime = u + " from TCP timestamp; unreliable if the stack randomises the TS origin";
        }
    }
    return g;
}

} 

Context make_context(ScanType scan_type, const TcpBuildOptions& o, uint8_t sent_ttl, uint16_t sent_window) {
    Context c;
    c.scan_type   = scan_type;
    c.sent_flags  = PacketTask::get_flags_for_scan_type(scan_type);
    c.sent_ttl    = sent_ttl;
    c.sent_window = sent_window;
    c.sent_mss    = o.mss_value;
    c.sent_ws     = o.window_scale;
    c.offered_ws  = o.window_scale > 0;
    c.offered_sack = o.sack_permitted;
    c.offered_ts  = o.timestamp_val != 0;
    c.sent_syn    = (c.sent_flags & TH_SYN) != 0;
    c.sent_ecn_setup = c.sent_syn && (c.sent_flags & TH_ECE) && (c.sent_flags & TH_CWR);
    return c;
}

Result analyze(const std::unordered_map<uint16_t, PacketDetails>& pd, const Context& ctx) {
    Result R;

    std::vector<Sample> samples;
    samples.reserve(pd.size());
    {
        std::unordered_map<std::string, std::string> order_cache;
        for (const auto& kv : pd) {
            Sample s;
            if (make_sample(kv.first, kv.second, s, order_cache)) samples.push_back(std::move(s));
        }
    }
    std::sort(samples.begin(), samples.end(), [](const Sample& a, const Sample& b) { return a.port < b.port; });
    R.samples_total = static_cast<int>(samples.size());

    if (samples.empty()) {
        R.notes.push_back(pd.empty() ? "no TCP replies were captured for this target"
                                     : "no usable IPv4 TCP replies (IPv6 replies carry no IP header details)");
        return R;
    }
    R.have_data = true;

    std::vector<SPtr> sa, rst;
    sa.reserve(samples.size());
    for (const Sample& s : samples) {
        if ((s.flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && !(s.flags & TH_RST)) sa.push_back(&s);
        else if (s.flags & TH_RST) rst.push_back(&s);
    }
    std::map<std::pair<int, std::string>, std::vector<SPtr>> cl;
    for (SPtr s : sa) cl[{s->init_ttl, s->order}].push_back(s);
    std::vector<std::vector<SPtr>> raw_clusters;
    for (auto& kv : cl) raw_clusters.push_back(std::move(kv.second));
    std::sort(raw_clusters.begin(), raw_clusters.end(), [](const auto& a, const auto& b) {
        if (a.size() != b.size()) return a.size() > b.size();
        return a.front()->port < b.front()->port;
    });
    std::vector<std::vector<SPtr>> clusters;
    size_t degraded = 0;
    for (auto& c : raw_clusters) {
        bool merged = false;
        for (auto& m : clusters) {
            if (m.front()->init_ttl == c.front()->init_ttl &&
                c.size() <= std::max<size_t>(3, m.size() / 4) &&
                c.front()->order != m.front()->order &&
                is_subsequence(c.front()->order, m.front()->order)) {
                degraded += c.size();
                m.insert(m.end(), c.begin(), c.end());
                merged = true;
                break;
            }
        }
        if (!merged) clusters.push_back(std::move(c));
    }
    R.n_stacks = static_cast<int>(clusters.size());
    if (degraded)
        R.notes.push_back(std::to_string(degraded) + " SYN-ACK(s) carried fewer options than the main stack's replies: SYN-cookie / backlog "
                          "pressure on the same host, or a second minimal TCP stack behind the same address (folded into the main group)");

    if (!ctx.sent_syn)
        R.notes.push_back("scan type sends no SYN: only RST replies are available, so only TTL / IP-ID / RST features can be used "
                          "(re-run with a SYN scan for full fingerprinting)");

    double anomaly = 1.0;   

    if (clusters.empty()) {
        if (rst.empty()) { R.have_data = false; R.notes.push_back("replies contained neither SYN-ACK nor RST"); return R; }
        R.groups.push_back(analyze_group("closed-port replies (RST only)", {}, rst, ctx, 0.85));
        R.notes.push_back("no open port answered: fingerprint is based on RST replies only (no option layout, window or ISN data)");
    } else {
        const int primary_ttl = clusters[0].front()->init_ttl;
        std::vector<SPtr> rst_same, rst_other;
        for (SPtr s : rst) (s->init_ttl == primary_ttl ? rst_same : rst_other).push_back(s);

        if (clusters.size() > 1) {
            anomaly *= 0.85;
            std::string ports;
            for (size_t i = 0; i < clusters.size(); ++i) {
                if (i) ports += "  |  ";
                std::vector<uint16_t> pp;
                for (SPtr s : clusters[i]) pp.push_back(s->port);
                std::sort(pp.begin(), pp.end());
                ports += join_ports(pp, 6);
            }
            R.notes.push_back("open ports are answered by " + std::to_string(clusters.size()) +
                              " different TCP stacks (" + ports + "): port-forwarding / NAT to several hosts, "
                              "reverse proxy, load balancer or SYN proxy in the path — the primary guess covers the largest group only");
        }
        if (clusters[0].size() >= 150) {
            anomaly *= 0.70;
            R.notes.push_back(std::to_string(clusters[0].size()) + " open ports answered by one stack: likely a tarpit, honeypot or SYN-proxy "
                              "firewall, so the fingerprint may describe that device instead of the real host");
        }
        {
            size_t chk = 0, bad = 0;
            for (SPtr s : clusters[0]) {
                if (!s->sent_seq) continue;
                ++chk;
                if (s->ack != s->sent_seq + 1) ++bad;
            }
            if (chk >= 2 && bad * 2 > chk) {
                anomaly *= 0.85;
                R.notes.push_back("SYN-ACK ack numbers do not match our probe sequence numbers for " + std::to_string(bad) + " of " +
                                  std::to_string(chk) + " replies: forged/injected replies or a SYN proxy are possible");
            }
        }

        const size_t max_groups = std::min<size_t>(clusters.size(), 3);
        for (size_t i = 0; i < max_groups; ++i) {
            std::string label = i == 0 ? "open-port replies (SYN-ACK)"
                                       : "open-port replies (SYN-ACK), second stack";
            if (i >= 2) label = "open-port replies (SYN-ACK), third stack";
            R.groups.push_back(analyze_group(label, clusters[i],
                                             i == 0 ? rst_same : std::vector<SPtr>{}, ctx,
                                             i == 0 ? anomaly : 1.0));
        }
        if (!rst_other.empty()) {
            R.groups.push_back(analyze_group("closed-port replies (RST) from a different TTL", {}, rst_other, ctx, 0.85));
            R.notes.push_back("closed-port RSTs use a different initial TTL than the SYN-ACKs: the RSTs are probably generated "
                              "by a firewall / IPS / gateway rather than the target itself");
            R.groups[0].confidence *= 0.92;
        }
        if (!rst_same.empty()) {
            const int t_sa  = mode_of<int>(clusters[0], [](const Sample& s) { return static_cast<int>(s.ttl); });
            const int t_rst = mode_of<int>(rst_same,    [](const Sample& s) { return static_cast<int>(s.ttl); });
            if (t_sa != t_rst) {
                R.notes.push_back("closed-port RST TTL (" + std::to_string(t_rst) + ") differs from SYN-ACK TTL (" +
                                  std::to_string(t_sa) + "): RSTs may be injected by a device " +
                                  std::to_string(std::abs(t_sa - t_rst)) + " hop(s) away (stateful firewall / IPS), or the paths differ (ECMP)");
                R.groups[0].confidence *= 0.92;
            }
        }
        {
            int lo = 255, hi = 0;
            for (SPtr s : clusters[0]) { lo = std::min<int>(lo, s->ttl); hi = std::max<int>(hi, s->ttl); }
            if (hi - lo >= 2)
                R.notes.push_back("observed TTL of SYN-ACKs varies between " + std::to_string(lo) + " and " + std::to_string(hi) +
                                  ": load-balanced / asymmetric paths or several hosts behind one address");
        }
    }
    for (Group& g : R.groups) {
        g.confidence_label = g.confidence >= 0.75 ? "HIGH" : g.confidence >= 0.50 ? "MEDIUM"
                           : g.confidence >= 0.30 ? "LOW" : "VERY LOW";
        if (g.unrecognised && g.confidence_label != "VERY LOW") g.confidence_label = "LOW";
    }

    if (!R.groups.empty()) {
        const Fingerprint& fp = R.groups[0].fp;
        if (fp.n_synack >= 1 && fp.n_synack < 3)
            R.notes.push_back("only " + std::to_string(fp.n_synack) + " SYN-ACK sample(s): ISN / IP-ID / timestamp-rate analysis is weak "
                              "(scan more open ports for a sharper result)");
        if (!fp.ttl_plausible)
            R.notes.push_back("received TTL implies an implausible hop count for any standard initial TTL (custom TTL or spoofed replies)");
        if (R.groups[0].unrecognised)
            R.notes.push_back("no known stack profile fits these replies: custom or hardened TCP stack, unusual middlebox, or an OS missing from the profile table");
    }
    return R;
}

namespace {

std::string fingerprint_line(const Fingerprint& fp) {
    std::ostringstream o;
    if (fp.ttl_init) o << "TTL " << fp.ttl_observed << " (init " << fp.ttl_init << ", ~" << fp.hops << " hops)";
    if (fp.n_synack) {
        o << " | opts [" << fp.layout << "]";
        o << " | win " << fp.window;
        if (fp.window_k) o << " (" << fp.window_k << "xMSS)";
        if (fp.mss > 0) o << " | mss " << fp.mss;
        if (fp.wscale >= 0) o << " | ws " << fp.wscale;
        if (fp.df >= 0) o << " | DF " << (fp.df ? "1" : "0");
    }
    o << " | IPID " << fp.ipid;
    if (fp.n_synack) {
        o << " | ISN " << fp.isn;
        o << " | TS " << fp.ts;
        if (fp.ecn != "not tested") o << " | ECN " << fp.ecn;
    }
    return o.str();
}

}

std::string render(const Result& r, const std::string& ip, bool verbose) {
    std::ostringstream o;
    o << "\n" << C_BOLD << C_CYAN << "OS detection" << C_RESET << " for " << ip
      << " (passive: analysed " << r.samples_total << " reply packet" << (r.samples_total == 1 ? "" : "s")
      << " already received, nothing extra sent)\n";

    if (!r.have_data || r.groups.empty()) {
        o << "  " << C_YEL << "insufficient data" << C_RESET;
        for (const auto& n : r.notes) o << "\n  - " << n;
        o << "\n";
        return o.str();
    }

    for (size_t gi = 0; gi < r.groups.size(); ++gi) {
        const Group& g = r.groups[gi];
        const Candidate& top = g.ranked.front();
        const char* lc = g.confidence_label == "HIGH" ? C_GREEN
                       : g.confidence_label == "MEDIUM" ? C_YEL : C_RED;

        o << "  " << C_WHITE << (gi == 0 ? "Best match  " : "Also seen   ") << C_RESET << ": "
          << C_BOLD << top.name << C_RESET << "  "
          << lc << "[" << g.confidence_label << " confidence " << fmt_pct(g.confidence)
          << " | exact profile " << fmt_pct(top.prob) << "]" << C_RESET << "\n";
        o << "    group       : " << g.label << "  ports " << join_ports(g.ports) << "\n";

        o << "    family      : ";
        for (size_t i = 0; i < g.families.size() && i < 3; ++i) {
            if (g.families[i].second < 0.005) break;
            if (i) o << " | ";
            o << g.families[i].first << " " << fmt_pct(g.families[i].second);
        }
        o << "\n";
        if (!g.ambiguity.empty()) o << "    ambiguity   : " << C_YEL << g.ambiguity << C_RESET << "\n";

        const size_t show = verbose ? g.ranked.size() : std::min<size_t>(3, g.ranked.size());
        if (show > 1) {
            o << "    candidates  :";
            for (size_t i = 0; i < show; ++i) {
                if (!verbose && g.ranked[i].prob < 0.01) break;
                o << (i ? "\n                  " : " ") << (i + 1) << ". " << g.ranked[i].name
                  << "  " << fmt_pct(g.ranked[i].prob);
            }
            o << "\n";
        }

        o << "    fingerprint : " << fingerprint_line(g.fp) << "\n";
        if (!g.fp.uptime.empty()) o << "    uptime      : " << g.fp.uptime << "\n";
        for (const auto& q : g.fp.quirks) o << "    quirk       : " << q << "\n";

        const size_t ev_show = verbose ? g.evidence.size() : std::min<size_t>(4, g.evidence.size());
        if (ev_show) {
            o << "    evidence    :";
            for (size_t i = 0; i < ev_show; ++i) {
                const Evidence& e = g.evidence[i];
                o << (i ? "\n                  " : " ") << (e.delta > 0 ? C_GREEN : C_RED)
                  << (e.delta > 0 ? "+ " : "- ") << C_RESET << e.text
                  << " (" << (e.delta > 0 ? "+" : "") << fmt_num(e.delta, 1) << ")";
            }
            o << "\n";
        }
    }

    if (!r.notes.empty()) {
        o << "  " << C_YEL << "Notes" << C_RESET << ":\n";
        for (const auto& n : r.notes) o << "    - " << n << "\n";
    }
    o << "  (heuristic result: OS family is usually reliable, exact version is a best guess; "
         "NAT, proxies and tuned/hardened stacks can mislead any passive fingerprint)\n";
    return o.str();
}

std::string render_json(const Result& r, const std::string& ip) {
    auto num = [](double v) { char b[32]; std::snprintf(b, sizeof(b), "%.4f", v); return std::string(b); };
    std::ostringstream o;
    o << "{\"target\":\"" << json_esc(ip) << "\",\"have_data\":" << (r.have_data ? "true" : "false")
      << ",\"samples\":" << r.samples_total << ",\"stacks\":" << r.n_stacks << ",\"groups\":[";
    for (size_t gi = 0; gi < r.groups.size(); ++gi) {
        const Group& g = r.groups[gi];
        if (gi) o << ',';
        o << "{\"label\":\"" << json_esc(g.label) << "\",\"ports\":[";
        for (size_t i = 0; i < g.ports.size(); ++i) o << (i ? "," : "") << g.ports[i];
        o << "]";
        if (!g.ranked.empty()) {
            o << ",\"best\":{\"name\":\"" << json_esc(g.ranked[0].name) << "\",\"family\":\"" << json_esc(g.ranked[0].family)
              << "\",\"prob\":" << num(g.ranked[0].prob) << "}";
        }
        o << ",\"confidence\":" << num(g.confidence) << ",\"confidence_label\":\"" << json_esc(g.confidence_label)
          << "\",\"unrecognised\":" << (g.unrecognised ? "true" : "false")
          << ",\"family_prob\":" << num(g.family_prob) << ",\"ambiguity\":\"" << json_esc(g.ambiguity) << "\"";
        o << ",\"families\":[";
        for (size_t i = 0; i < g.families.size(); ++i)
            o << (i ? "," : "") << "{\"family\":\"" << json_esc(g.families[i].first) << "\",\"prob\":" << num(g.families[i].second) << "}";
        o << "],\"candidates\":[";
        for (size_t i = 0; i < g.ranked.size() && i < 5; ++i)
            o << (i ? "," : "") << "{\"name\":\"" << json_esc(g.ranked[i].name) << "\",\"prob\":" << num(g.ranked[i].prob) << "}";
        o << "],\"evidence\":[";
        for (size_t i = 0; i < g.evidence.size(); ++i)
            o << (i ? "," : "") << "{\"text\":\"" << json_esc(g.evidence[i].text) << "\",\"delta\":" << num(g.evidence[i].delta) << "}";
        const Fingerprint& fp = g.fp;
        o << "],\"fingerprint\":{\"synack\":" << fp.n_synack << ",\"rst\":" << fp.n_rst
          << ",\"ttl_observed\":" << fp.ttl_observed << ",\"ttl_init\":" << fp.ttl_init << ",\"hops\":" << fp.hops
          << ",\"layout\":\"" << json_esc(fp.layout) << "\",\"window\":" << fp.window << ",\"mss\":" << fp.mss
          << ",\"wscale\":" << fp.wscale << ",\"df\":" << fp.df << ",\"ipid\":\"" << json_esc(fp.ipid)
          << "\",\"isn\":\"" << json_esc(fp.isn) << "\",\"ts\":\"" << json_esc(fp.ts) << "\",\"ecn\":\"" << json_esc(fp.ecn)
          << "\",\"uptime\":\"" << json_esc(fp.uptime) << "\",\"quirks\":[";
        for (size_t i = 0; i < fp.quirks.size(); ++i) o << (i ? "," : "") << "\"" << json_esc(fp.quirks[i]) << "\"";
        o << "]}}";
    }
    o << "],\"notes\":[";
    for (size_t i = 0; i < r.notes.size(); ++i) o << (i ? "," : "") << "\"" << json_esc(r.notes[i]) << "\"";
    o << "]}";
    return o.str();
}

}
