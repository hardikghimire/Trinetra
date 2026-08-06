#include "anomaly_analysis.hpp"
#include "scan.hpp"
#include <algorithm>
#include <climits>
#include <cmath>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <arpa/inet.h>

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

namespace {

inline double clamp01(double x) { return std::max(0.0, std::min(1.0, x)); }

inline double sigmoid(double x) {
    if (x >= 0.0) { double z = std::exp(-x); return 1.0 / (1.0 + z); }
    double z = std::exp(x); return z / (1.0 + z);
}

double median_of(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    std::vector<double> t(v.begin(), v.end());
    std::sort(t.begin(), t.end());
    size_t n = t.size();
    return (n & 1u) ? t[n/2] : 0.5 * (t[n/2 - 1] + t[n/2]);
}

double quantile(const std::vector<double>& v, double q) {
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
}

double mad_of(const std::vector<double>& v, double med) {
    if (v.empty()) return 0.0;
    std::vector<double> d;
    d.reserve(v.size());
    for (double x : v) d.push_back(std::fabs(x - med));
    return median_of(d);
}

inline double robust_scale(double mad) { return 1.4826 * mad + 1e-9; }

double stddev_of(const std::vector<double>& v) {
    if (v.size() < 2) return 0.0;
    double m = 0.0;
    for (double x : v) m += x;
    m /= static_cast<double>(v.size());
    double a = 0.0;
    for (double x : v) { double d = x - m; a += d * d; }
    return std::sqrt(a / static_cast<double>(v.size()));
}

double robust_z(double x, const std::vector<double>& hist, size_t min_hist) {
    if (hist.size() < min_hist) return 0.0;
    double m = median_of(hist);
    double a = mad_of(hist, m);
    return std::fabs(x - m) / robust_scale(a);
}

double entropy_norm(const std::unordered_map<int,int>& counts, int total) {
    if (total <= 0 || counts.empty()) return 0.0;
    if (counts.size() == 1) return 0.0;
    double H = 0.0;
    for (const auto& kv : counts) {
        double p = static_cast<double>(kv.second) / static_cast<double>(total);
        if (p > 0.0) H -= p * std::log2(p);
    }
    return H / std::log2(static_cast<double>(counts.size()));
}

inline double gini(double p) { return 2.0 * p * (1.0 - p); }

std::string safe_ip(const char* ip) {
    return (ip && *ip) ? std::string(ip) : std::string("unknown");
}

inline void push_capped(std::vector<double>& v, double x, size_t cap) {
    v.push_back(x);
    if (v.size() > cap) v.erase(v.begin());
}


bool is_private_v4_addr(uint32_t host_order_addr) {
    uint32_t x = host_order_addr;
    return ((x & 0xFF000000u) == 0x0A000000u) ||   // 10/8
           ((x & 0xFFF00000u) == 0xAC100000u) ||   // 172.16/12
           ((x & 0xFFFF0000u) == 0xC0A80000u) ||   // 192.168/16
           ((x & 0xFF000000u) == 0x7F000000u);     // 127/8
}

bool is_private_ip(const std::string& ip) {
    in_addr a4{};
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) {
        return is_private_v4_addr(ntohl(a4.s_addr));
    }

    in6_addr a6{};
    if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) {
        const uint8_t* b = a6.s6_addr;
        bool prefix_zero = true;
        for (int i = 0; i < 10; ++i) if (b[i] != 0) { prefix_zero = false; break; }
        if (prefix_zero && b[10] == 0xFF && b[11] == 0xFF) {
            uint32_t v4 = (static_cast<uint32_t>(b[12]) << 24) |
                          (static_cast<uint32_t>(b[13]) << 16) |
                          (static_cast<uint32_t>(b[14]) << 8)  |
                           static_cast<uint32_t>(b[15]);
            return is_private_v4_addr(v4);
        }

        // ::1 loopback
        bool all_zero_but_last = true;
        for (int i = 0; i < 15; ++i) if (b[i] != 0) { all_zero_but_last = false; break; }
        if (all_zero_but_last && b[15] == 1) return true;

        // fc00::/7 -- unique local addresses
        if ((b[0] & 0xFEu) == 0xFCu) return true;

        // fe80::/10 -- link-local
        if (b[0] == 0xFEu && (b[1] & 0xC0u) == 0x80u) return true;

        return false;
    }
    return false;
}

struct TtlPrior { uint16_t value; double weight; };

constexpr TtlPrior kTtlPriors[] = {
    {64,  1.00},  // Linux, macOS/BSD, Android, most embedded stacks
    {128, 1.00},  // Windows
    {255, 0.90},  // Solaris, Cisco/network gear, many routers and appliances
    {60,  0.55},  // some older macOS/AIX/load-balancer stacks
    {254, 0.40},  // some Cisco/network-gear variants
};

uint16_t infer_initial(uint8_t recv, int& hop, bool& valid, double& conf) {
    valid = false;
    hop = -1;
    conf = 0.0;

    int best = INT_MAX, second = INT_MAX;
    uint16_t init = 0;
    double best_weight = 0.0;

    for (const auto& p : kTtlPriors) {
        if (recv <= p.value) {
            int h = static_cast<int>(p.value) - static_cast<int>(recv);
            if (h < best) { second = best; best = h; init = p.value; best_weight = p.weight; }
            else if (h < second) second = h;
        }
    }

    if (init != 0) {
        valid = true;
        hop = best;
        int gap = (second == INT_MAX) ? 20 : (second - best);
        double gap_conf = clamp01(static_cast<double>(gap) / 20.0);
        conf = clamp01(0.7 * gap_conf + 0.3 * best_weight);
    }
    return init;
}

template <typename Hist>
class TargetHistoryStore {
public:
    explicit TargetHistoryStore(size_t max_targets) : max_targets_(max_targets) {}

    Hist& get(const std::string& key) {
        auto it = map_.find(key);
        if (it != map_.end()) return it->second;
        if (map_.size() >= max_targets_ && !order_.empty()) {
            map_.erase(order_.front());
            order_.pop_front();
        }
        order_.push_back(key);
        return map_[key];
    }

private:
    size_t max_targets_;
    std::unordered_map<std::string, Hist> map_;
    std::deque<std::string> order_;
};

double bounded_adaptive_threshold(double base_threshold,
                                   const std::vector<double>& score_hist,
                                   size_t min_samples) {
    if (score_hist.size() < min_samples) return base_threshold;
    double sm = median_of(score_hist);
    double sa = mad_of(score_hist, sm);
    double raw = sm + 3.0 * robust_scale(sa);

    constexpr double kMinMult = 0.6;
    constexpr double kMaxMult = 2.0;
    return std::max(base_threshold * kMinMult, std::min(raw, base_threshold * kMaxMult));
}

struct Sig {
    std::string name;
    std::string detail;
    int sev;            // 1..3
    double evidence;    // 0..1
};

bool anomaly_gate(double score, double threshold, const std::vector<Sig>& sigs) {
    int strong_count = 0;
    int medium_count = 0;
    for (const auto& s : sigs) {
        if (s.sev >= 3 && s.evidence >= 0.60) strong_count++;
        if (s.sev >= 2 && s.evidence >= 0.55) medium_count++;
    }
    return (score > threshold) || (strong_count >= 1) || (medium_count >= 2);
}

void print_signatures(std::vector<Sig> sigs) {
    std::sort(sigs.begin(), sigs.end(), [](const Sig& a, const Sig& b) {
        if (a.sev != b.sev) return a.sev > b.sev;
        return a.evidence > b.evidence;
    });
    for (const auto& s : sigs) {
        std::cout << "  - "
                  << s.name << " [sev=" << s.sev
                  << ", ev=" << std::fixed << std::setprecision(2) << s.evidence << "]"
                  << " -> " << s.detail << "\n";
    }
}

struct TtlWeights {
    double timeout = 0.09, invalid = 0.05, ambig = 0.05, dir = 0.05;
    double disp = 0.06, jump = 0.06, plaus = 0.18, contra = 0.12;
    double overlap = 0.08, order = 0.07, action = 0.06, tail = 0.04;
    double nonstationary = 0.03, sparse = 0.03, ttl_conf_drop = 0.02, bucket_edge = 0.01;
};
constexpr TtlWeights kTtlWeights{};

struct WsnWeights {
    double missing = 0.10, entropy = 0.08, impurity = 0.08, ws_disp = 0.06;
    double win_disp = 0.06, expect_div = 0.06, overlap = 0.10, order = 0.08;
    double action = 0.07, seg_complex = 0.06, nonstationary = 0.05, transition_vol = 0.05;
    double bimodal = 0.04, absence_cluster = 0.04;
    double z_missing = 0.03, z_entropy = 0.02, z_imp = 0.01, z_seg = 0.01;
};
constexpr WsnWeights kWsnWeights{};

using Vec = std::vector<double>;
using Mat = std::vector<std::vector<double>>;

Vec mean_vector(const std::vector<Vec>& data) {
    const size_t k = data.empty() ? 0 : data.front().size();
    Vec m(k, 0.0);
    if (data.empty()) return m;
    for (const auto& row : data)
        for (size_t j = 0; j < k; ++j) m[j] += row[j];
    for (size_t j = 0; j < k; ++j) m[j] /= static_cast<double>(data.size());
    return m;
}

Mat covariance_matrix(const std::vector<Vec>& data, const Vec& mean, double ridge) {
    const size_t k = mean.size();
    Mat cov(k, Vec(k, 0.0));
    if (data.size() < 2) {
        for (size_t i = 0; i < k; ++i) cov[i][i] = 1.0;
        return cov;
    }
    for (const auto& row : data) {
        for (size_t i = 0; i < k; ++i) {
            const double di = row[i] - mean[i];
            for (size_t j = i; j < k; ++j) {
                cov[i][j] += di * (row[j] - mean[j]);
            }
        }
    }
    const double denom = static_cast<double>(data.size() - 1);
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = i; j < k; ++j) {
            cov[i][j] /= denom;
            cov[j][i] = cov[i][j];
        }
        cov[i][i] += ridge;
    }
    return cov;
}

bool cholesky(const Mat& a, Mat& L) {
    const size_t k = a.size();
    L.assign(k, Vec(k, 0.0));
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j <= i; ++j) {
            double sum = a[i][j];
            for (size_t p = 0; p < j; ++p) sum -= L[i][p] * L[j][p];
            if (i == j) {
                if (sum <= 0.0) return false;
                L[i][j] = std::sqrt(sum);
            } else {
                L[i][j] = sum / L[j][j];
            }
        }
    }
    return true;
}

Vec cholesky_solve(const Mat& L, const Vec& b) {
    const size_t k = L.size();
    Vec y(k, 0.0), x(k, 0.0);
    for (size_t i = 0; i < k; ++i) {
        double sum = b[i];
        for (size_t p = 0; p < i; ++p) sum -= L[i][p] * y[p];
        y[i] = sum / L[i][i];
    }
    for (size_t ii = 0; ii < k; ++ii) {
        const size_t i = k - 1 - ii;
        double sum = y[i];
        for (size_t p = i + 1; p < k; ++p) sum -= L[p][i] * x[p];
        x[i] = sum / L[i][i];
    }
    return x;
}

bool mahalanobis_sq(const Vec& v, const Vec& mean, const Mat& cov, double& out_d2) {
    Mat L;
    if (!cholesky(cov, L)) return false;
    Vec diff(v.size());
    for (size_t i = 0; i < diff.size(); ++i) diff[i] = v[i] - mean[i];
    const Vec x = cholesky_solve(L, diff);
    double d2 = 0.0;
    for (size_t i = 0; i < diff.size(); ++i) d2 += diff[i] * x[i];
    out_d2 = std::max(0.0, d2);
    return true;
}

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

    static constexpr size_t MAXH = 300;
    static constexpr size_t MAX_TRACKED_TARGETS = 4096;
    static constexpr double BASE_THRESHOLD = 0.42;

    const std::string ip = safe_ip(dest_ip);
    const bool private_target = is_private_ip(ip);

    std::vector<double> rtts;
    rtts.reserve(rtt_entries.size());
    for (const auto& e : rtt_entries) {
        if (e.second > 0.0) rtts.push_back(e.second);
    }

    const double rtt_med = median_of(rtts);
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
    static TargetHistoryStore<Hist> store(MAX_TRACKED_TARGETS);

    double z_hop = 0.0, z_rtt = 0.0, z_ttl_conf = 0.0, z_score = 0.0;
    double score = 0.0;
    double threshold = BASE_THRESHOLD;

    double c_timeout = dest_responded ? 0.0 : 1.0;
    double c_invalid = hop_valid ? 0.0 : 1.0;
    double c_ambig = hop_valid ? (1.0 - ttl_conf) : 1.0;

    double c_dir = 0.0;
    if (!hop_valid && sent_ttl > 0 && received_ttl > sent_ttl) {
        c_dir = 1.0;
    } else if (hop_valid && hop == 0) {
        c_dir = 0.8;
    }

    double c_disp = clamp01((rtt_med > 0.0) ? (rtt_mad / (rtt_med + 1e-9)) : 0.0);
    double c_jump = clamp01(0.5 * jump_med + 0.5 * std::tanh(jump_std));

    double c_plaus = 0.0, c_contra = 0.0, c_overlap = 0.0, c_order = 0.0, c_action = 0.0;
    double c_tail = 0.0, c_nonstationary = 0.0, c_sparse = 0.0, c_ttl_conf_drop = 0.0, c_bucket_edge = 0.0;

    {
        std::lock_guard<std::mutex> g(mu);
        auto& h = store.get(ip);

        z_hop = (hop_valid ? robust_z(static_cast<double>(hop), h.hop_hist, 8) : 0.0);
        z_rtt = (rtt_med > 0.0 ? robust_z(rtt_med, h.rtt_med_hist, 8) : 0.0);
        z_ttl_conf = robust_z(ttl_conf, h.ttl_conf_hist, 8);

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
            double scale = robust_scale(rtt_mad) * 6.0 + 1e-9;   // 6 robust-sigma -> score=1.0
            c_tail = clamp01(tail_excess / scale);
        }

        c_nonstationary = clamp01(0.5 * std::tanh(z_hop / 4.0) + 0.5 * std::tanh(z_rtt / 4.0));
        c_sparse = clamp01(1.0 - std::tanh(static_cast<double>(rtts.size()) / 6.0));
        c_ttl_conf_drop = clamp01(std::tanh(z_ttl_conf / 4.0));

        int d1 = std::min({
            std::abs(static_cast<int>(received_ttl) - 64),
            std::abs(static_cast<int>(received_ttl) - 128),
            std::abs(static_cast<int>(received_ttl) - 255)
        });
        c_bucket_edge = clamp01(sigmoid((3.0 - static_cast<double>(d1)) / 1.5));

        score =
            kTtlWeights.timeout * c_timeout +
            kTtlWeights.invalid * c_invalid +
            kTtlWeights.ambig * c_ambig +
            kTtlWeights.dir * c_dir +
            kTtlWeights.disp * c_disp +
            kTtlWeights.jump * c_jump +
            kTtlWeights.plaus * c_plaus +
            kTtlWeights.contra * c_contra +
            kTtlWeights.overlap * c_overlap +
            kTtlWeights.order * c_order +
            kTtlWeights.action * c_action +
            kTtlWeights.tail * c_tail +
            kTtlWeights.nonstationary * c_nonstationary +
            kTtlWeights.sparse * c_sparse +
            kTtlWeights.ttl_conf_drop * c_ttl_conf_drop +
            kTtlWeights.bucket_edge * c_bucket_edge;

        threshold = bounded_adaptive_threshold(BASE_THRESHOLD, h.score_hist, 18);
        z_score = robust_z(score, h.score_hist, 8);

        if (hop_valid) push_capped(h.hop_hist, static_cast<double>(hop), MAXH);
        if (rtt_med > 0.0) push_capped(h.rtt_med_hist, rtt_med, MAXH);
        push_capped(h.ttl_conf_hist, ttl_conf, MAXH);
        push_capped(h.score_hist, score, MAXH);
    }

    std::vector<Sig> sigs;
    if (c_timeout > 0.5)    sigs.push_back({"TTL_TIMEOUT",              "No response from target.",                               3, c_timeout});
    if (c_invalid > 0.5)    sigs.push_back({"TTL_INVALID_SAMPLE",       "TTL cannot be consistently mapped to initial TTL priors.",3, c_invalid});
    if (c_ambig > 0.65)     sigs.push_back({"TTL_AMBIGUOUS_INFERENCE",  "Initial TTL inference confidence is low.",               2, c_ambig});

    if (c_dir > 0.5)        sigs.push_back({"TTL_DIRECTION_MISMATCH",
                                             (hop_valid && hop == 0)
                                                 ? "Received TTL equals inferred initial -- zero hops consumed (possible spoofing)."
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
                                             "Latency 90th-percentile exceeds median by >4 robust sigma.",
                                             1, c_tail});

    if (c_nonstationary > 0.60) sigs.push_back({"TTL_NONSTATIONARY_PATTERN","TTL/RTT pattern shows nonstationary shift.",         2, c_nonstationary});
    if (c_sparse > 0.75)    sigs.push_back({"TTL_SAMPLE_SCARCITY",      "Too few RTT samples for high-confidence inference.",    1, c_sparse});
    if (c_ttl_conf_drop > 0.60) sigs.push_back({"TTL_CONFIDENCE_DROP",  "TTL inference confidence dropped versus baseline.",     2, c_ttl_conf_drop});
    if (c_bucket_edge > 0.65) sigs.push_back({"TTL_BUCKET_EDGE_AMBIGUITY","Received TTL lies near bucket boundary.",             1, c_bucket_edge});
    if (z_hop > 4.0)        sigs.push_back({"TTL_HOP_OUTLIER",          "Hop estimate is robust outlier vs history.",            2, clamp01(std::tanh(z_hop/5.0))});
    if (z_rtt > 4.0)        sigs.push_back({"TTL_RTT_OUTLIER",          "RTT median is robust outlier vs history.",              2, clamp01(std::tanh(z_rtt/5.0))});
    if (z_score > 4.0)      sigs.push_back({"TTL_COMPOSITE_OUTLIER",    "Composite score is robust outlier.",                    2, clamp01(std::tanh(z_score/5.0))});
    if (hop_valid && private_target && hop > 20) {
        sigs.push_back({"TTL_PRIVATE_PATH_DEPTH",
                         "Private-address target shows unusually deep hop path.",
                         2, clamp01((hop-20)/20.0)});
    }

    const bool anomaly = anomaly_gate(score, threshold, sigs);

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
    std::cout << color::yellow << "Detected signatures    : " << sigs.size() << color::reset << "\n";
    print_signatures(sigs);
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
        std::vector<Vec> feat_hist;
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
        std::vector<double> dists;
        dists.reserve(open.size() > 1 ? open.size() - 1 : 0);
        for (size_t i = 1; i < open.size(); ++i) dists.push_back(obs_dist(open[i-1], open[i]));

        const double mu0 = median_of(dists);
        const double sigma0 = robust_scale(mad_of(dists, mu0));
        const double k_slack = 0.5 * sigma0;
        const double h_decision = 4.0 * sigma0 + 1e-9;

        double s_hi = 0.0, s_lo = 0.0;
        size_t start = 0;
        for (size_t i = 1; i < open.size(); ++i) {
            const double d = dists[i - 1];
            s_hi = std::max(0.0, s_hi + (d - mu0 - k_slack));
            s_lo = std::min(0.0, s_lo + (d - mu0 + k_slack));
            if (s_hi > h_decision || s_lo < -h_decision) {
                segs.push_back(Segment{start, i-1, 0,0,0,0,0});
                start = i;
                s_hi = 0.0;
                s_lo = 0.0;
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

    static constexpr size_t MAXH = 512;
    static constexpr size_t MAX_TRACKED_TARGETS = 4096;
    static constexpr double BASE_THRESHOLD = 0.55;

    static std::mutex hist_mu;
    static TargetHistoryStore<Hist> store(MAX_TRACKED_TARGETS);

    const std::string ip = safe_ip(dest_ip);

    double z_missing = 0.0, z_entropy = 0.0, z_imp = 0.0, z_seg = 0.0, z_score = 0.0;
    double score = 0.0, threshold = BASE_THRESHOLD;
    const Vec feat_vec = {
        p_missing, ws_entropy_n, imp_profile, ws_disp, win_disp, expect_div,
        overlap_conflict, order_conflict, action_conflict, seg_complex,
        nonstationary, transition_vol, profile_bimodal, ws_absence_cluster
    };
    constexpr size_t kFeatDim = 14;
    constexpr size_t kMinMahaSamples = 2 * kFeatDim + 2;
    constexpr double kMahaRidge = 1e-3;

    bool maha_used = false;
    double maha_d2 = 0.0;

    {
        std::lock_guard<std::mutex> g(hist_mu);
        auto& hist = store.get(ip);

        z_missing = robust_z(p_missing, hist.miss_hist, 12);
        z_entropy = robust_z(ws_entropy_n, hist.ent_hist, 12);
        z_imp = robust_z(imp_profile, hist.imp_hist, 12);
        z_seg = robust_z(seg_complex, hist.seg_hist, 12);

        const double linear_score =
            kWsnWeights.missing * p_missing +
            kWsnWeights.entropy * ws_entropy_n +
            kWsnWeights.impurity * imp_profile +
            kWsnWeights.ws_disp * ws_disp +
            kWsnWeights.win_disp * win_disp +
            kWsnWeights.expect_div * expect_div +
            kWsnWeights.overlap * overlap_conflict +
            kWsnWeights.order * order_conflict +
            kWsnWeights.action * action_conflict +
            kWsnWeights.seg_complex * seg_complex +
            kWsnWeights.nonstationary * nonstationary +
            kWsnWeights.transition_vol * transition_vol +
            kWsnWeights.bimodal * profile_bimodal +
            kWsnWeights.absence_cluster * ws_absence_cluster +
            kWsnWeights.z_missing * std::tanh(z_missing / 4.0) +
            kWsnWeights.z_entropy * std::tanh(z_entropy / 4.0) +
            kWsnWeights.z_imp * std::tanh(z_imp / 4.0) +
            kWsnWeights.z_seg * std::tanh(z_seg / 4.0);

        if (hist.feat_hist.size() >= kMinMahaSamples) {
            const Vec mean = mean_vector(hist.feat_hist);
            const Mat cov = covariance_matrix(hist.feat_hist, mean, kMahaRidge);
            maha_used = mahalanobis_sq(feat_vec, mean, cov, maha_d2);
        }

        if (maha_used) {
            score = clamp01(std::tanh(maha_d2 / (2.0 * static_cast<double>(kFeatDim))));
        } else {
            score = linear_score;
        }

        threshold = bounded_adaptive_threshold(BASE_THRESHOLD, hist.score_hist, 20);
        z_score = robust_z(score, hist.score_hist, 12);

        push_capped(hist.score_hist, score, MAXH);
        push_capped(hist.miss_hist, p_missing, MAXH);
        push_capped(hist.ent_hist, ws_entropy_n, MAXH);
        push_capped(hist.imp_hist, imp_profile, MAXH);
        push_capped(hist.seg_hist, seg_complex, MAXH);

        hist.feat_hist.push_back(feat_vec);
        if (hist.feat_hist.size() > MAXH) hist.feat_hist.erase(hist.feat_hist.begin());
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

    const bool anomaly = anomaly_gate(score, threshold, sigs);

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
              << " (threshold: " << threshold << ", z_score: " << z_score
              << ", method: " << (maha_used ? "mahalanobis" : "linear-fallback");
    if (maha_used) std::cout << ", D^2=" << std::setprecision(2) << maha_d2;
    std::cout << ")\n";
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
    std::cout << color::yellow << "Detected signatures : " << sigs.size() << color::reset << "\n";
    print_signatures(sigs);
    std::cout << color::red << "Anomaly detected" << color::reset << "\n";
}
