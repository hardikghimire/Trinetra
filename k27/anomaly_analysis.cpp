#include "anomaly_analysis.hpp"
#include "scan.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <climits>
#include <string>
#include <cstring>

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string cyan    = "\033[96m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string green   = "\033[92m";
    const std::string white   = "\033[97m";
    const std::string dim     = "\033[90m";
    const std::string red     = "\033[91m";
    const std::string green_yellow = "\033[38;5;154m";
    const std::string orange = "\033[38;5;214m";
}


void display_ttl_analysis(const std::vector<std::pair<int,double>>& rtt_entries,
                          uint8_t sent_ttl,
                          uint8_t received_ttl,
                          const char* dest_ip,
                          bool dest_responded)
{
    struct Hist {
        std::vector<double> hop_hist;
        std::vector<double> rtt_med_hist;
        std::vector<double> score_hist;
        std::vector<double> ttl_conf_hist;
    };
    struct Sig {
        std::string name;
        std::string detail;
        int sev;            // 1..3
        double evidence;    // 0..1
    };

    auto clamp01 = [](double x) { return std::max(0.0, std::min(1.0, x)); };
    auto sigmoid = [](double x) {
        if (x >= 0.0) { double z = std::exp(-x); return 1.0 / (1.0 + z); }
        double z = std::exp(x); return z / (1.0 + z);
    };
    auto safe_ip = [](const char* ip) -> std::string {
        return (ip && *ip) ? std::string(ip) : std::string("unknown");
    };
    // Dual-stack private/local-address check. IPv4-only detection silently
    // treats every IPv6 destination as "public", which routes it through
    // the looser plausibility thresholds (h0=22 vs 8, r0=12 vs 3) below —
    // wrong for link-local/ULA IPv6 targets, which are just as close-hop
    // as private IPv4 ones.
    auto is_private_v4_addr = [](const in_addr& a) -> bool {
        uint32_t x = ntohl(a.s_addr);
        return ((x & 0xFF000000u) == 0x0A000000u) ||      // 10/8
               ((x & 0xFFF00000u) == 0xAC100000u) ||      // 172.16/12
               ((x & 0xFFFF0000u) == 0xC0A80000u) ||      // 192.168/16
               ((x & 0xFF000000u) == 0x7F000000u);        // 127/8
    };
    auto is_private_v6_addr = [](const in6_addr& a) -> bool {
        const uint8_t* b = a.s6_addr;
        // ::1 loopback
        bool is_loopback = true;
        for (int i = 0; i < 15; ++i) if (b[i] != 0) { is_loopback = false; break; }
        if (is_loopback && b[15] == 1) return true;
        // fe80::/10 link-local
        if (b[0] == 0xfe && (b[1] & 0xC0) == 0x80) return true;
        // fc00::/7 unique local
        if ((b[0] & 0xFE) == 0xFC) return true;
        // ::ffff:0:0/96 IPv4-mapped — fall through to the embedded IPv4 rules
        static const uint8_t mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
        if (std::memcmp(b, mapped_prefix, 12) == 0) {
            in_addr embedded{};
            std::memcpy(&embedded.s_addr, b + 12, 4);
            uint32_t x = ntohl(embedded.s_addr);
            return ((x & 0xFF000000u) == 0x0A000000u) ||
                   ((x & 0xFFF00000u) == 0xAC100000u) ||
                   ((x & 0xFFFF0000u) == 0xC0A80000u) ||
                   ((x & 0xFF000000u) == 0x7F000000u);
        }
        return false;
    };
    auto is_private_v4 = [&](const std::string& ip) -> bool {
        in_addr a4{};
        if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) return is_private_v4_addr(a4);
        in6_addr a6{};
        if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) return is_private_v6_addr(a6);
        return false;
    };

    auto median_of = [](const std::vector<double>& v) -> double {
        if (v.empty()) return 0.0;
        std::vector<double> t(v.begin(), v.end());
        std::sort(t.begin(), t.end());
        size_t n = t.size();
        return (n & 1u) ? t[n/2] : 0.5 * (t[n/2 - 1] + t[n/2]);
    };

    auto quantile = [](const std::vector<double>& v, double q) -> double {
        if (v.empty()) return 0.0;
        std::vector<double> t;
        t.reserve(v.size());
        t.insert(t.end(), v.begin(), v.end());
        std::sort(t.begin(), t.end());

        double pos = q * (t.size() - 1);
        size_t lo = static_cast<size_t>(std::floor(pos));
        size_t hi = static_cast<size_t>(std::ceil(pos));
        if (lo == hi) return t[lo];
        double w = pos - lo;
        return t[lo] * (1.0 - w) + t[hi] * w;
    };

    auto mad_of = [&](const std::vector<double>& v, double med) -> double {
        if (v.empty()) return 0.0;
        std::vector<double> d;
        d.reserve(v.size());
        for (double x : v) d.push_back(std::fabs(x - med));
        return median_of(d);
    };

    auto robust_scale = [](double mad) { return 1.4826 * mad + 1e-9; };

    auto stddev_of = [](const std::vector<double>& v) -> double {
        if (v.size() < 2) return 0.0;
        double m = 0.0;
        for (double x : v) m += x;
        m /= static_cast<double>(v.size());
        double a = 0.0;
        for (double x : v) { double d = x - m; a += d * d; }
        return std::sqrt(a / static_cast<double>(v.size()));
    };

    auto robust_z = [&](double x, const std::vector<double>& hist) -> double {
        if (hist.size() < 8) return 0.0;
        double m = median_of(hist);
        double a = mad_of(hist, m);
        return std::fabs(x - m) / robust_scale(a);
    };

    auto infer_initial = [&](uint8_t recv, int& hop, bool& valid, double& conf) -> uint16_t {
        // Real-world initial-TTL defaults in modern use: 64 (Linux/macOS/BSD),
        // 128 (Windows), 255 (Solaris/network gear). Older values like 30/32
        // are rare today and sit only 2 apart from each other, which makes
        // `infer_initial` flag ordinary hop counts as low-confidence/ambiguous
        // purely from prior crowding rather than genuine ambiguity.
        static const uint16_t priors[] = {64, 128, 255};
        valid = false;
        hop = -1;
        conf = 0.0;

        int best = INT_MAX, second = INT_MAX;
        uint16_t init = 0;

        for (uint16_t p : priors) {
            if (recv <= p) {
                int h = static_cast<int>(p) - static_cast<int>(recv);
                if (h < best) { second = best; best = h; init = p; }
                else if (h < second) second = h;
            }
        }

        if (init != 0) {
            valid = true;
            hop = best;
            int gap = (second == INT_MAX) ? 20 : (second - best);
            conf = clamp01(static_cast<double>(gap) / 20.0);
        }
        return init;
    };

    const std::string ip = safe_ip(dest_ip);
    const bool private_target = is_private_v4(ip);

    std::vector<double> rtts;
    rtts.reserve(rtt_entries.size());
    for (const auto& e : rtt_entries) {
        if (e.second > 0.0) rtts.push_back(e.second);
    }

    const double rtt_med = median_of(rtts);
    const double rtt_q10 = quantile(rtts, 0.10);
    const double rtt_q90 = quantile(rtts, 0.90);
    const double rtt_mad = mad_of(rtts, rtt_med);
    const double rtt_std = stddev_of(rtts);

    std::vector<double> rel_jumps;
    rel_jumps.reserve(rtts.size() > 0 ? rtts.size() - 1 : 0);
    for (size_t i = 1; i < rtts.size(); ++i) {
        double den = std::max(1e-9, 0.5 * (rtts[i] + rtts[i - 1]));
        rel_jumps.push_back(std::fabs(rtts[i] - rtts[i - 1]) / den);
    }
    const double jump_med = median_of(rel_jumps);
    const double jump_std = stddev_of(rel_jumps);

    int hop = -1;
    bool hop_valid = false;
    double ttl_conf = 0.0;
    const uint16_t init_ttl = infer_initial(received_ttl, hop, hop_valid, ttl_conf);

    static std::mutex mu;
    static std::unordered_map<std::string, Hist> H;
    static constexpr size_t MAXH = 300;

    double z_hop = 0.0, z_rtt = 0.0, z_ttl_conf = 0.0, z_score = 0.0;
    double score = 0.0;
    double threshold = 0.42;

    // Components
    double c_timeout = dest_responded ? 0.0 : 1.0;
    double c_invalid = hop_valid ? 0.0 : 1.0;
    double c_ambig = hop_valid ? (1.0 - ttl_conf) : 1.0;

    double c_dir = 0.0;
    if (!hop_valid && sent_ttl > 0 && received_ttl > sent_ttl) {
        c_dir = 1.0;
    } else if (hop_valid && hop == 0) {
        // Packet arrived with TTL equal to its initial value — zero hops
        // consumed.  Suspicious (possible TTL spoofing / loopback oddity).
        c_dir = 0.8;
    }
    // else: hop_valid && hop >= 1 → normal, c_dir stays 0.0

    double c_disp = clamp01((rtt_med > 0.0) ? (rtt_mad / (rtt_med + 1e-9)) : 0.0);
    double c_jump = clamp01(0.5 * jump_med + 0.5 * std::tanh(jump_std));

    double c_plaus = 0.0, c_contra = 0.0, c_overlap = 0.0, c_order = 0.0, c_action = 0.0;
    double c_tail = 0.0, c_nonstationary = 0.0, c_sparse = 0.0, c_ttl_conf_drop = 0.0, c_ttl_bucket_edge = 0.0;

    {
        std::lock_guard<std::mutex> g(mu);
        auto& h = H[ip];

        z_hop = (hop_valid ? robust_z(static_cast<double>(hop), h.hop_hist) : 0.0);
        z_rtt = (rtt_med > 0.0 ? robust_z(rtt_med, h.rtt_med_hist) : 0.0);
        z_ttl_conf = robust_z(ttl_conf, h.ttl_conf_hist);

        // Plausibility terms
        const double h0 = private_target ? 8.0 : 22.0;
        const double sh = private_target ? 2.0 : 4.5;
        const double r0 = private_target ? 3.0 : 12.0;
        const double sr = private_target ? 0.9 : 3.0;

        const double hop_high = hop_valid ? sigmoid((static_cast<double>(hop) - h0) / sh) : 1.0;
        const double rtt_low = (rtt_med > 0.0) ? sigmoid((r0 - rtt_med) / sr) : 0.5;
        c_plaus = hop_high * rtt_low;

        c_contra = (hop_valid && rtt_med > 0.0)
            ? sigmoid((static_cast<double>(hop) / (rtt_med + 1e-6)) - (private_target ? 8.0 : 3.0))
            : 0.5;

        // Overlap/order/action against learned manifold
        if (hop_valid && !h.hop_hist.empty() && !h.rtt_med_hist.empty()) {
            double hm = median_of(h.hop_hist), ha = mad_of(h.hop_hist, hm);
            double rm = median_of(h.rtt_med_hist), ra = mad_of(h.rtt_med_hist, rm);

            double h_lo = hm - 2.5 * robust_scale(ha), h_hi = hm + 2.5 * robust_scale(ha);
            double r_lo = std::max(0.0, rm - 2.5 * robust_scale(ra)), r_hi = rm + 2.5 * robust_scale(ra);

            double out_h = (hop < h_lo) ? (h_lo - hop) : ((hop > h_hi) ? (hop - h_hi) : 0.0);
            double out_r = (rtt_med < r_lo) ? (r_lo - rtt_med) : ((rtt_med > r_hi) ? (rtt_med - r_hi) : 0.0);

            c_overlap = clamp01(
                0.5 * sigmoid(out_h / (robust_scale(ha) + 1e-9)) +
                0.5 * sigmoid(out_r / (robust_scale(ra) + 1e-9))
            );

            double dh = static_cast<double>(hop) - hm;
            double dr = rtt_med - rm;
            c_order = clamp01(sigmoid((-dh * dr) / (std::fabs(dh) + std::fabs(dr) + 1e-9)));

            double zh = std::fabs(static_cast<double>(hop) - hm) / robust_scale(ha);
            double zr = std::fabs(rtt_med - rm) / robust_scale(ra);
            double support = std::exp(-0.5 * (zh * zh + zr * zr));
            c_action = clamp01(dest_responded ? (1.0 - support) : support);
        }

        if (rtts.size() >= 4 && rtt_med > 0.0) {
            double tail_excess = rtt_q90 - rtt_med;              // always >= 0
            double scale = robust_scale(rtt_mad) * 6.0 + 1e-9;   // 6 robust-σ → score=1.0
            c_tail = clamp01(tail_excess / scale);
        } else {
            c_tail = 0.0;
        }

        c_nonstationary = clamp01(0.5 * std::tanh(z_hop / 4.0) + 0.5 * std::tanh(z_rtt / 4.0));
        c_sparse = clamp01(1.0 - std::tanh(static_cast<double>(rtts.size()) / 6.0));
        c_ttl_conf_drop = clamp01(std::tanh(z_ttl_conf / 4.0));

        int d1 = std::min({
            std::abs(static_cast<int>(received_ttl) - 32),
            std::abs(static_cast<int>(received_ttl) - 64),
            std::abs(static_cast<int>(received_ttl) - 128)
        });
        c_ttl_bucket_edge = clamp01(sigmoid((3.0 - static_cast<double>(d1)) / 1.5));

        // NOTE ON WEIGHTS: these are hand-picked, not fit against labeled
        // true/false-positive data, so the composite score has no known
        // accuracy in isolation — treat it as one contributing input, not a
        // validated verdict. That's why `anomaly` below never relies on
        // `score > threshold` alone: it also requires a strong single
        // signature or multiple corroborating medium signatures, each with
        // its own independently-reasoned trigger condition. If/when labeled
        // scan data becomes available, refit these weights (e.g. logistic
        // regression against known-benign vs known-malicious traffic)
        // rather than continuing to hand-tune them.
        score =
            0.09 * c_timeout +
            0.05 * c_invalid +
            0.05 * c_ambig +
            0.05 * c_dir +
            0.06 * c_disp +
            0.06 * c_jump +
            0.18 * c_plaus +
            0.12 * c_contra +
            0.08 * c_overlap +
            0.07 * c_order +
            0.06 * c_action +
            0.04 * c_tail +
            0.03 * c_nonstationary +
            0.03 * c_sparse +
            0.02 * c_ttl_conf_drop +
            0.01 * c_ttl_bucket_edge;

        // Adaptive threshold, but bounded around the base threshold. An
        // unbounded median+3*MAD threshold lets a target that gradually
        // ramps up anomalous-looking behavior drag the baseline up with it,
        // so genuinely anomalous traffic of similar magnitude later stops
        // firing. Clamping the drift keeps the adaptation (useful for
        // legitimately noisy-but-benign hosts) without letting it fully
        // absorb sustained attacker-controlled scores.
        const double base_threshold = threshold;
        if (h.score_hist.size() >= 18) {
            double sm = median_of(h.score_hist), sa = mad_of(h.score_hist, sm);
            double adaptive = sm + 3.0 * robust_scale(sa);
            threshold = std::clamp(adaptive, base_threshold * 0.85, base_threshold * 2.2);
        }
        z_score = robust_z(score, h.score_hist);

        if (hop_valid) {
            h.hop_hist.push_back(static_cast<double>(hop));
            if (h.hop_hist.size() > MAXH) h.hop_hist.erase(h.hop_hist.begin());
        }
        if (rtt_med > 0.0) {
            h.rtt_med_hist.push_back(rtt_med);
            if (h.rtt_med_hist.size() > MAXH) h.rtt_med_hist.erase(h.rtt_med_hist.begin());
        }
        h.ttl_conf_hist.push_back(ttl_conf);
        if (h.ttl_conf_hist.size() > MAXH) h.ttl_conf_hist.erase(h.ttl_conf_hist.begin());

        h.score_hist.push_back(score);
        if (h.score_hist.size() > MAXH) h.score_hist.erase(h.score_hist.begin());
    }

    std::vector<Sig> sigs;
    if (c_timeout > 0.5)    sigs.push_back({"TTL_TIMEOUT",              "No response from target.",                               3, c_timeout});
    if (c_invalid > 0.5)    sigs.push_back({"TTL_INVALID_SAMPLE",       "TTL cannot be consistently mapped to initial TTL priors.",3, c_invalid});
    if (c_ambig > 0.65)     sigs.push_back({"TTL_AMBIGUOUS_INFERENCE",  "Initial TTL inference confidence is low.",               2, c_ambig});

    if (c_dir > 0.5)        sigs.push_back({"TTL_DIRECTION_MISMATCH",
                                             (hop_valid && hop == 0)
                                                 ? "Received TTL equals inferred initial — zero hops consumed (possible spoofing)."
                                                 : "Received TTL above sent TTL and cannot be mapped to any standard initial-TTL prior.",
                                             2, c_dir});

    if (c_plaus > 0.65)     sigs.push_back({"TTL_RTT_PLAUSIBILITY_CONFLICT","High hop/low RTT relation is implausible.",           3, c_plaus});
    if (c_contra > 0.65)    sigs.push_back({"TTL_HOP_RTT_RATIO_OUTLIER", "Hop-to-latency ratio is extreme.",                     3, c_contra});
    if (c_overlap > 0.60)   sigs.push_back({"TTL_BASELINE_OVERLAP_CONFLICT","Current behavior lies outside learned envelope.",    2, c_overlap});
    if (c_order > 0.60)     sigs.push_back({"TTL_ORDER_CONSISTENCY_CONFLICT","Hop/RTT direction conflicts with historical trend.", 2, c_order});
    if (c_action > 0.60)    sigs.push_back({"TTL_ACTION_CONSISTENCY_CONFLICT","Observed action inconsistent with historical support.",2, c_action});
    if (c_disp > 0.50)      sigs.push_back({"TTL_RTT_DISPERSION_HIGH",  "RTT robust dispersion is high.",                        1, c_disp});
    if (c_jump > 0.55)      sigs.push_back({"TTL_RTT_JUMP_VOLATILITY",  "Adjacent RTT jump process is volatile.",                1, c_jump});

    if (c_tail > 0.70)      sigs.push_back({"TTL_RTT_HEAVY_TAIL",
                                             "Latency 90th-percentile exceeds median by >4 robust σ.",
                                             1, c_tail});

    if (c_nonstationary > 0.60) sigs.push_back({"TTL_NONSTATIONARY_PATTERN","TTL/RTT pattern shows nonstationary shift.",         2, c_nonstationary});
    if (c_sparse > 0.75)    sigs.push_back({"TTL_SAMPLE_SCARCITY",      "Too few RTT samples for high-confidence inference.",    1, c_sparse});
    if (c_ttl_conf_drop > 0.60) sigs.push_back({"TTL_CONFIDENCE_DROP",  "TTL inference confidence dropped versus baseline.",     2, c_ttl_conf_drop});
    if (c_ttl_bucket_edge > 0.65) sigs.push_back({"TTL_BUCKET_EDGE_AMBIGUITY","Received TTL lies near bucket boundary.",          1, c_ttl_bucket_edge});
    if (z_hop > 4.0)        sigs.push_back({"TTL_HOP_OUTLIER",          "Hop estimate is robust outlier vs history.",            2, clamp01(std::tanh(z_hop/5.0))});
    if (z_rtt > 4.0)        sigs.push_back({"TTL_RTT_OUTLIER",          "RTT median is robust outlier vs history.",              2, clamp01(std::tanh(z_rtt/5.0))});
    if (z_score > 4.0)      sigs.push_back({"TTL_COMPOSITE_OUTLIER",    "Composite score is robust outlier.",                    2, clamp01(std::tanh(z_score/5.0))});
    if (hop_valid && private_target && hop > 20) {
        sigs.push_back({"TTL_PRIVATE_PATH_DEPTH",
                         "Private-address target shows unusually deep hop path.",
                         2, clamp01((hop-20)/20.0)});
    }

    // ---------- false-positive-resistant anomaly gate ----------
    int strong_count = 0;
    int medium_count = 0;
    for (const auto& s : sigs) {
        if (s.sev >= 3 && s.evidence >= 0.60) strong_count++;
        if (s.sev >= 2 && s.evidence >= 0.55) medium_count++;
    }
    bool anomaly =
        (score > threshold) ||
        (strong_count >= 1) ||
        (medium_count >= 2);
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << color::cyan << "\nTTL Analysis (Policy Consistency)" << color::reset << "\n";
    std::cout << "Sent TTL               : " << static_cast<int>(sent_ttl) << "\n";
    std::cout << "Received TTL           : " << static_cast<int>(received_ttl) << "\n";
    if (hop_valid) {
        std::cout << "Inferred Initial TTL   : " << init_ttl
                  << " (confidence: " << std::fixed << std::setprecision(2) << ttl_conf << ")\n";
        std::cout << "Estimated Hop Distance : " << hop << "\n";
    } else {
        std::cout << "Inferred Initial TTL   : unknown\n";
        std::cout << "Estimated Hop Distance : unknown\n";
    }
    if (!rtts.empty()) {
        std::cout << "RTT median/MAD/stddev  : "
                  << std::fixed << std::setprecision(3)
                  << rtt_med << "ms / " << rtt_mad << "ms / " << rtt_std << "ms\n";
    } else {
        std::cout << "RTT median/MAD/stddev  : unavailable\n";
    }
    std::cout << "Composite score        : " << std::fixed << std::setprecision(4) << score
              << " (threshold: " << threshold << ", z_score: " << z_score << ")\n";
    if (!anomaly) {
        std::cout << color::green << "No anomalies detected" << color::reset << "\n";
        return;
    }
    std::sort(sigs.begin(), sigs.end(), [](const Sig& a, const Sig& b) {
        if (a.sev != b.sev) return a.sev > b.sev;
        return a.evidence > b.evidence;
    });
    std::cout << color::yellow << "Detected signatures    : " << sigs.size() << color::reset << "\n";
    for (size_t i = 0; i < sigs.size(); ++i) {
        bool last = (i + 1 == sigs.size());
        std::cout << "  - "
                  << sigs[i].name << " [sev=" << sigs[i].sev
                  << ", ev=" << std::fixed << std::setprecision(2) << sigs[i].evidence << "]"
                  << " -> " << sigs[i].detail << "\n";
    }
    std::cout << color::red << "Anomaly detected" << color::reset << "\n";
}

void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,
                          uint8_t sent_ws,
                          const char* dest_ip)
{
    struct Hist {
        std::vector<double> score_hist;
        std::vector<double> miss_hist;
        std::vector<double> ent_hist;
        std::vector<double> imp_hist;
        std::vector<double> seg_hist;
    };
    struct Sig {
        std::string name;
        std::string detail;
        int sev;
        double evidence;
    };
    struct Obs {
        uint16_t port;
        bool has_ws;
        uint8_t ws;
        bool has_ts;
        bool has_sack;
        uint16_t win;
    };
    struct Segment {
        size_t l = 0, r = 0;
        double p_ws = 0.0, p_ts = 0.0, p_sack = 0.0;
        double med_ws = 0.0, med_win = 0.0;
    };

    auto is_open_synack = [](const PacketDetails& d) -> bool {
        return (d.tcp_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK);
    };
    auto safe_ip = [](const char* ip) -> std::string {
        return (ip && *ip) ? std::string(ip) : std::string("unknown");
    };
    const std::string ip = safe_ip(dest_ip);
    auto clamp01 = [](double x) { return std::max(0.0, std::min(1.0, x)); };
    auto sigmoid = [](double x) {
        if (x >= 0.0) { double z = std::exp(-x); return 1.0 / (1.0 + z); }
        double z = std::exp(x); return z / (1.0 + z);
    };
    auto median_of = [](const std::vector<double>& v) -> double {
        if (v.empty()) return 0.0;
        std::vector<double> t(v.begin(), v.end());
        std::sort(t.begin(), t.end());
        size_t n = t.size();
        return (n & 1u) ? t[n/2] : 0.5 * (t[n/2 - 1] + t[n/2]);
    };
    auto mad_of = [&](const std::vector<double>& v, double med) -> double {
        if (v.empty()) return 0.0;
        std::vector<double> d;
        d.reserve(v.size());
        for (double x : v) d.push_back(std::fabs(x - med));
        return median_of(d);
    };
    auto robust_scale = [](double mad) { return 1.4826 * mad + 1e-9; };
    auto robust_z = [&](double x, const std::vector<double>& hist) {
        if (hist.size() < 12) return 0.0;
        double m = median_of(hist), a = mad_of(hist, m);
        return std::fabs(x - m) / robust_scale(a);
    };
    auto entropy_norm = [](const std::unordered_map<int,int>& counts, int total) -> double {
        if (total <= 0 || counts.empty()) return 0.0;
        if (counts.size() == 1) return 0.0;
        double H = 0.0;
        for (const auto& kv : counts) {
            double p = static_cast<double>(kv.second) / static_cast<double>(total);
            if (p > 0.0) H -= p * std::log2(p);
        }
        return H / std::log2(static_cast<double>(counts.size()));
    };
    auto gini = [](double p) { return 2.0 * p * (1.0 - p); };

    std::vector<Obs> open;
    open.reserve(packet_details.size());
    for (const auto& kv : packet_details) {
        const auto& d = kv.second;
        if (!is_open_synack(d)) continue;
        open.push_back({kv.first, d.has_window_scale, d.window_scale, d.has_timestamp, d.has_sack, d.window_size});
    }
    if (open.empty()) return;
    std::sort(open.begin(), open.end(), [](const Obs& a, const Obs& b){ return a.port < b.port; });

    const size_t n = open.size();

    size_t ws_present = 0, ws_missing = 0, ts_yes = 0, sack_yes = 0;
    std::unordered_map<int,int> ws_counts;
    std::vector<double> ws_vals, win_vals;
    ws_vals.reserve(n); win_vals.reserve(n);

    for (const auto& e : open) {
        if (e.has_ws) { ++ws_present; ws_counts[(int)e.ws]++; ws_vals.push_back((double)e.ws); }
        else ++ws_missing;
        if (e.has_ts) ++ts_yes;
        if (e.has_sack) ++sack_yes;
        win_vals.push_back((double)e.win);
    }

    double p_missing = (double)ws_missing / (double)n;
    double p_present = 1.0 - p_missing;
    double p_ts = (double)ts_yes / (double)n;
    double p_sack = (double)sack_yes / (double)n;

    double ws_entropy_n = entropy_norm(ws_counts, (int)ws_present);
    double imp_profile = (gini(p_present) + gini(p_ts) + gini(p_sack)) / 3.0;

    double ws_disp = 0.0;
    if (!ws_vals.empty()) {
        double m = median_of(ws_vals), a = mad_of(ws_vals, m);
        ws_disp = clamp01(a / (std::fabs(m) + 1e-9));
    }

    double win_disp = 0.0;
    if (!win_vals.empty()) {
        double m = median_of(win_vals), a = mad_of(win_vals, m);
        win_disp = clamp01(a / (std::fabs(m) + 1e-9));
    }

    double expected_ws_presence = (sent_ws > 0) ? 1.0 : 0.0;
    double expect_div = std::fabs(p_present - expected_ws_presence);

    auto obs_dist = [](const Obs& a, const Obs& b) -> double {
        double d_ws_pres = (a.has_ws == b.has_ws) ? 0.0 : 1.0;
        double d_ws_val = 0.0;
        if (a.has_ws && b.has_ws) d_ws_val = std::min(1.0, std::fabs((double)a.ws - (double)b.ws) / 8.0);
        double d_ts = (a.has_ts == b.has_ts) ? 0.0 : 1.0;
        double d_sack = (a.has_sack == b.has_sack) ? 0.0 : 1.0;
        double d_win = std::min(1.0, std::fabs((double)a.win - (double)b.win) / std::max(1.0, 0.5 * (a.win + b.win)));
        return 0.30*d_ws_pres + 0.25*d_ws_val + 0.20*d_ts + 0.15*d_sack + 0.10*d_win;
    };

    std::vector<Segment> segs;
    {
        const double split_thr = 0.35;
        size_t start = 0;
        for (size_t i = 1; i < open.size(); ++i) {
            if (obs_dist(open[i-1], open[i]) > split_thr) {
                segs.push_back(Segment{start, i-1, 0,0,0,0,0});
                start = i;
            }
        }
        segs.push_back(Segment{start, open.size()-1, 0,0,0,0,0});

        for (auto& s : segs) {
            size_t cnt = s.r - s.l + 1;
            size_t c_ws = 0, c_ts = 0, c_sack = 0;
            std::vector<double> sws, swin;
            sws.reserve(cnt); swin.reserve(cnt);

            for (size_t i = s.l; i <= s.r; ++i) {
                const auto& e = open[i];
                if (e.has_ws) { ++c_ws; sws.push_back((double)e.ws); }
                if (e.has_ts) ++c_ts;
                if (e.has_sack) ++c_sack;
                swin.push_back((double)e.win);
            }

            s.p_ws = (double)c_ws / (double)cnt;
            s.p_ts = (double)c_ts / (double)cnt;
            s.p_sack = (double)c_sack / (double)cnt;
            s.med_ws = sws.empty() ? 0.0 : median_of(sws);
            s.med_win = median_of(swin);
        }
    }

    double overlap_conflict = 0.0, order_conflict = 0.0, action_conflict = 0.0;
    double seg_complex = clamp01((segs.size() <= 1) ? 0.0 : std::log2((double)segs.size()) / 4.0);
    double nonstationary = 0.0;
    double transition_vol = 0.0;
    double profile_bimodal = 0.0;
    double ws_absence_cluster = 0.0;

    if (segs.size() >= 2) {
        double ov = 0.0, ord = 0.0, act = 0.0, tv = 0.0;
        int pairs = 0;

        for (size_t i = 1; i < segs.size(); ++i) {
            const auto& A = segs[i-1];
            const auto& B = segs[i];

            double d_ws = std::fabs(A.p_ws - B.p_ws);
            double d_ts = std::fabs(A.p_ts - B.p_ts);
            double d_sack = std::fabs(A.p_sack - B.p_sack);
            double d_mws = std::min(1.0, std::fabs(A.med_ws - B.med_ws) / 8.0);
            double d_win = std::min(1.0, std::fabs(A.med_win - B.med_win) / std::max(1.0, 0.5*(A.med_win + B.med_win)));

            double similarity = 1.0 - clamp01(0.28*d_ws + 0.22*d_ts + 0.18*d_sack + 0.20*d_mws + 0.12*d_win);

            double a_pol = A.p_ws - 0.5, b_pol = B.p_ws - 0.5;
            double flip = sigmoid(-10.0 * (a_pol * b_pol)); // high when sign flips
            ov += similarity * flip;

            double permissive_jump = std::max(0.0, B.p_ws - A.p_ws);
            ord += similarity * permissive_jump;

            double a_dev = std::fabs(A.p_ws - expected_ws_presence);
            double b_dev = std::fabs(B.p_ws - expected_ws_presence);
            act += 0.5 * (a_dev + b_dev) * similarity;

            tv += clamp01(d_ws + d_ts + d_sack);

            pairs++;
        }

        if (pairs > 0) {
            overlap_conflict = clamp01(ov / pairs);
            order_conflict = clamp01(ord / pairs);
            action_conflict = clamp01(act / pairs);
            transition_vol = clamp01(tv / pairs);
        }
    }

    if (open.size() >= 4) {
        std::vector<double> y;
        y.reserve(open.size());
        for (const auto& e : open) y.push_back(e.has_ws ? 1.0 : 0.0);

        double n_d = (double)y.size(), sx=0, sy=0, sxx=0, sxy=0;
        for (size_t i = 0; i < y.size(); ++i) {
            double x = (double)i;
            sx += x; sy += y[i]; sxx += x*x; sxy += x*y[i];
        }
        double den = n_d*sxx - sx*sx;
        double slope = (std::fabs(den) < 1e-9) ? 0.0 : ((n_d*sxy - sx*sy) / den);
        nonstationary = clamp01(std::fabs(slope) * 4.0);
    }

    if (segs.size() >= 2) {
        // bimodality proxy from spread between segment medians
        std::vector<double> meds;
        meds.reserve(segs.size());
        for (const auto& s : segs) meds.push_back(s.med_ws);
        double m = median_of(meds), a = mad_of(meds, m);
        profile_bimodal = clamp01(std::tanh((a) / (std::fabs(m)+1e-9)));
    }

    // WS absence clustering: long contiguous no-WS runs
    {
        size_t best_run = 0, cur = 0;
        for (const auto& e : open) {
            if (!e.has_ws) { cur++; best_run = std::max(best_run, cur); }
            else cur = 0;
        }
        ws_absence_cluster = clamp01((double)best_run / std::max<size_t>(1, open.size()));
    }

    // Keyed per target IP — a single shared static Hist would let a scan of
    // one host shift the adaptive baseline used to judge a completely
    // different host, which is statistically invalid pooling and defeats
    // the purpose of per-target adaptive baselining (mirrors the TTL
    // function's per-IP H[ip] keying above).
    static std::mutex hist_mu;
    static std::unordered_map<std::string, Hist> H;
    static constexpr size_t MAXH = 512;

    double z_missing = 0.0, z_entropy = 0.0, z_imp = 0.0, z_seg = 0.0, z_score = 0.0;
    double score = 0.0, threshold = 0.55;

    {
        std::lock_guard<std::mutex> g(hist_mu);
        auto& hist = H[ip];

        z_missing = robust_z(p_missing, hist.miss_hist);
        z_entropy = robust_z(ws_entropy_n, hist.ent_hist);
        z_imp = robust_z(imp_profile, hist.imp_hist);
        z_seg = robust_z(seg_complex, hist.seg_hist);

        // See the equivalent note in display_ttl_analysis: these weights are
        // heuristic and unvalidated against labeled data, which is exactly
        // why the gate below (strong/medium signature counts) doesn't rely
        // on this score alone.
        score =
            0.10 * p_missing +
            0.08 * ws_entropy_n +
            0.08 * imp_profile +
            0.06 * ws_disp +
            0.06 * win_disp +
            0.06 * expect_div +
            0.10 * overlap_conflict +
            0.08 * order_conflict +
            0.07 * action_conflict +
            0.06 * seg_complex +
            0.05 * nonstationary +
            0.05 * transition_vol +
            0.04 * profile_bimodal +
            0.04 * ws_absence_cluster +
            0.03 * std::tanh(z_missing / 4.0) +
            0.02 * std::tanh(z_entropy / 4.0) +
            0.01 * std::tanh(z_imp / 4.0) +
            0.01 * std::tanh(z_seg / 4.0);

        // Bounded the same way as the TTL threshold: adaptation is useful for
        // benign per-target noise, but left unbounded it lets a target that
        // ramps up anomalous-looking WS behavior gradually raise its own bar
        // until similar future behavior no longer triggers.
        const double base_threshold = threshold;
        if (hist.score_hist.size() >= 20) {
            double sm = median_of(hist.score_hist), sa = mad_of(hist.score_hist, sm);
            double adaptive = sm + 3.0 * robust_scale(sa);
            threshold = std::clamp(adaptive, base_threshold * 0.85, base_threshold * 2.2);
        }
        z_score = robust_z(score, hist.score_hist);

        hist.score_hist.push_back(score);
        hist.miss_hist.push_back(p_missing);
        hist.ent_hist.push_back(ws_entropy_n);
        hist.imp_hist.push_back(imp_profile);
        hist.seg_hist.push_back(seg_complex);

        if (hist.score_hist.size() > MAXH) hist.score_hist.erase(hist.score_hist.begin());
        if (hist.miss_hist.size() > MAXH) hist.miss_hist.erase(hist.miss_hist.begin());
        if (hist.ent_hist.size() > MAXH) hist.ent_hist.erase(hist.ent_hist.begin());
        if (hist.imp_hist.size() > MAXH) hist.imp_hist.erase(hist.imp_hist.begin());
        if (hist.seg_hist.size() > MAXH) hist.seg_hist.erase(hist.seg_hist.begin());
    }

    std::vector<Sig> sigs;
    if (p_missing > 0.60)          sigs.push_back({"WSN_HIGH_MISSING_RATIO",         "Large fraction of open ports missing WS option.",         3, p_missing});
    if (ws_entropy_n > 0.70)       sigs.push_back({"WSN_HIGH_WS_ENTROPY",            "WS values are highly fragmented.",                        2, ws_entropy_n});
    if (imp_profile > 0.55)        sigs.push_back({"WSN_PROFILE_IMPURITY",           "WS/TS/SACK profile is heterogeneous.",                    2, imp_profile});
    if (ws_disp > 0.40)            sigs.push_back({"WSN_WS_DISPERSION",              "WS values have high robust dispersion.",                   2, ws_disp});
    if (win_disp > 0.45)           sigs.push_back({"WSN_WINDOW_DISPERSION",          "Window size varies strongly across open ports.",           2, win_disp});
    if (expect_div > 0.60)         sigs.push_back({"WSN_PROBE_EXPECTATION_MISMATCH", "Observed WS behavior diverges from sent probe intent.",    2, expect_div});
    if (overlap_conflict > 0.60)   sigs.push_back({"WSN_OVERLAP_CONFLICT",           "Similar adjacent regions disagree in action tendency.",    3, overlap_conflict});
    if (order_conflict > 0.55)     sigs.push_back({"WSN_ORDER_CONFLICT",             "Inferred ordering across adjacent regions is inconsistent.",2, order_conflict});
    if (action_conflict > 0.60)    sigs.push_back({"WSN_ACTION_CONSISTENCY_CONFLICT","Observed actions have low manifold support.",              2, action_conflict});
    if (seg_complex > 0.65)        sigs.push_back({"WSN_SEGMENT_COMPLEXITY",         "Behavior splits into many distinct policy-like segments.", 1, seg_complex});
    if (nonstationary > 0.45)      sigs.push_back({"WSN_NONSTATIONARY_PATTERN",      "WS presence trend shifts across ordered ports.",           1, nonstationary});
    if (transition_vol > 0.55)     sigs.push_back({"WSN_TRANSITION_VOLATILITY",      "High volatility between adjacent port profiles.",          1, transition_vol});
    if (profile_bimodal > 0.50)    sigs.push_back({"WSN_BIMODAL_PROFILE",            "Segment medians indicate bimodal behavior.",               2, profile_bimodal});
    if (ws_absence_cluster > 0.55) sigs.push_back({"WSN_WS_ABSENCE_CLUSTER",         "WS absence appears in long contiguous port runs.",         2, ws_absence_cluster});
    if (z_missing > 4.0)           sigs.push_back({"WSN_MISSING_OUTLIER",            "Missing ratio is a robust outlier.",                       2, clamp01(std::tanh(z_missing/5.0))});
    if (z_entropy > 4.0)           sigs.push_back({"WSN_ENTROPY_OUTLIER",            "WS entropy is a robust outlier.",                         2, clamp01(std::tanh(z_entropy/5.0))});
    if (z_imp > 4.0)               sigs.push_back({"WSN_IMPURITY_OUTLIER",           "Profile impurity is a robust outlier.",                    2, clamp01(std::tanh(z_imp/5.0))});
    if (z_seg > 4.0)               sigs.push_back({"WSN_SEGMENT_OUTLIER",            "Segmentation complexity is a robust outlier.",             1, clamp01(std::tanh(z_seg/5.0))});
    if (z_score > 4.0)             sigs.push_back({"WSN_COMPOSITE_OUTLIER",          "Composite score is a robust outlier.",                     2, clamp01(std::tanh(z_score/5.0))});
    if (sent_ws == 0 && ws_present > 0)
        sigs.push_back({"WSN_UNSOLICITED_WS", "Target advertises WS although probe requested none.",          1, clamp01((double)ws_present / (double)std::max<size_t>(1,n))});
    if (sent_ws > 0 && ws_missing == n)
        sigs.push_back({"WSN_TOTAL_WS_STRIP", "All open ports stripped WS.",                                  3, 1.0});

    // ---------- false-positive-resistant anomaly gate ----------
    // Previously `!sigs.empty()` meant a single severity-1 signature (e.g.
    // WSN_SEGMENT_COMPLEXITY) alone flipped the verdict to "Anomaly
    // detected" — far more trigger-happy than the TTL gate below it, and
    // the main source of WSN over-reporting. Mirror TTL's gate instead:
    // require either a high composite score, one strong (sev>=3,
    // evidence>=0.60) signature, or two or more medium (sev>=2,
    // evidence>=0.55) signatures.
    int strong_count = 0;
    int medium_count = 0;
    for (const auto& s : sigs) {
        if (s.sev >= 3 && s.evidence >= 0.60) strong_count++;
        if (s.sev >= 2 && s.evidence >= 0.55) medium_count++;
    }
    bool anomaly =
        (score > threshold) ||
        (strong_count >= 1) ||
        (medium_count >= 2);

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << color::cyan << "\nWSN Analysis (Policy Consistency)" << color::reset << "\n";
    std::cout << "Sent WS             : " << static_cast<int>(sent_ws) << "\n";
    std::cout << "Open ports analyzed : " << n << "\n";
    std::cout << "WS present/missing  : " << ws_present << "/" << ws_missing
              << " (missing_ratio=" << std::fixed << std::setprecision(4) << p_missing << ")\n";
    std::cout << "WS entropy(norm)    : " << ws_entropy_n << "\n";
    std::cout << "Profile impurity    : " << imp_profile << "\n";
    std::cout << "Segment count       : " << segs.size() << " (complexity=" << seg_complex << ")\n";
    std::cout << "Composite score     : " << score
              << " (threshold: " << threshold << ", z_score: " << z_score << ")\n";
    std::cout << "Per-port observations:\n";
    for (size_t i = 0; i < open.size(); ++i) {
        const auto& e = open[i];
        std::cout << "  - "
                  << "Port " << e.port
                  << " -> WS=" << (e.has_ws ? std::to_string((int)e.ws) : std::string("none"))
                  << ", TS=" << (e.has_ts ? "Y" : "N")
                  << ", SACK=" << (e.has_sack ? "Y" : "N")
                  << ", WIN=" << e.win << "\n";
    }
    if (!anomaly) {
        std::cout << color::green << "No anomalies detected" << color::reset << "\n";
        return;
    }
    std::sort(sigs.begin(), sigs.end(), [](const Sig& a, const Sig& b) {
        if (a.sev != b.sev) return a.sev > b.sev;
        return a.evidence > b.evidence;
    });
    std::cout << color::yellow << "Detected signatures : " << sigs.size() << color::reset << "\n";
    for (size_t i = 0; i < sigs.size(); ++i) {
        bool last = (i + 1 == sigs.size());
        std::cout << "  - "
                  << sigs[i].name << " [sev=" << sigs[i].sev
                  << ", ev=" << std::fixed << std::setprecision(2) << sigs[i].evidence << "]"
                  << " -> " << sigs[i].detail << "\n";
    }
    std::cout << color::red << "Anomaly detected" << color::reset << "\n";
}
