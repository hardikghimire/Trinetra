#include "debug.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <netinet/tcp.h>
#include <unordered_map>
#include <unordered_set>

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

void print_rtt_debug(const std::vector<std::pair<int,double>>& entries) {
    if (entries.empty()) return;

    std::ostringstream oss;
    oss << color::dim << "RTT debug\n" << color::reset;

    const size_t INLINE_THRESHOLD = 10;

    if (entries.size() <= INLINE_THRESHOLD) {
        for (size_t i = 0; i < entries.size(); ++i) {
            int rtt_int = static_cast<int>(entries[i].second);
            if (entries[i].second > 0 && rtt_int == 0) rtt_int = 1;
            oss << "  port " << entries[i].first << "/tcp"
                      << "  ewma=" << std::fixed << std::setprecision(3)
                      << entries[i].second << "ms  int=" << rtt_int << "ms\n";
        }
    } else {
        // stats logic unchanged — only output lines change
        double min_rtt = entries[0].second, max_rtt = entries[0].second, sum_rtt = 0.0;
        int min_port = entries[0].first, max_port = entries[0].first;

        for (const auto& e : entries) {
            if (e.second < min_rtt) { min_rtt = e.second; min_port = e.first; }
            if (e.second > max_rtt) { max_rtt = e.second; max_port = e.first; }
            sum_rtt += e.second;
        }
        double avg_rtt = sum_rtt / static_cast<double>(entries.size());

        int avg_port = entries[0].first;
        double avg_closest = entries[0].second;
        double best_delta = std::abs(entries[0].second - avg_rtt);
        for (const auto& e : entries) {
            double delta = std::abs(e.second - avg_rtt);
            if (delta < best_delta) { best_delta = delta; avg_port = e.first; avg_closest = e.second; }
        }

        int min_int = static_cast<int>(min_rtt); if (min_rtt > 0 && min_int == 0) min_int = 1;
        int max_int = static_cast<int>(max_rtt); if (max_rtt > 0 && max_int == 0) max_int = 1;
        int avg_int = static_cast<int>(avg_closest); if (avg_closest > 0 && avg_int == 0) avg_int = 1;

        oss << std::left
                  << std::setw(12) << "  Sampled"  << ": " << entries.size() << " ports\n"
                  << std::setw(12) << "  Min ewma" << ": port " << min_port << "/tcp  "
                  << std::fixed << std::setprecision(3) << min_rtt << "ms  (int=" << min_int << "ms)\n"
                  << std::setw(12) << "  Avg ewma" << ": port " << avg_port << "/tcp  "
                  << avg_closest << "ms  (int=" << avg_int << "ms)\n"
                  << std::setw(12) << "  Max ewma" << ": port " << max_port << "/tcp  "
                  << max_rtt << "ms  (int=" << max_int << "ms)\n";
    }

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << oss.str();
}

static std::string demux_render_flags(uint8_t flags) {
    std::string s;
    if (flags & TH_SYN) s += "SYN,";
    if (flags & TH_ACK) s += "ACK,";
    if (flags & TH_RST) s += "RST,";
    if (flags & TH_FIN) s += "FIN,";
    if (!s.empty()) s.pop_back();
    return s.empty() ? "none" : s;
}

void print_demux_debug(const std::string& target_ip,
                        const std::vector<DemuxDebugEntry>& entries,
                        const DemuxDebugCounters& counts,
                        const std::vector<uint16_t>& open_ports) {
    if (entries.empty()) return;

    std::ostringstream oss;

    uint64_t total_dropped = counts.unknown_port + counts.bad_src_port +
                              counts.bad_token + counts.stale_rst;

    oss << "\n" << color::dim << "Demux debug" << color::reset << "   : \n";
    oss << "    " << color::bold << "summary" << color::reset
               << " target=" << target_ip
               << color::green << " matched=" << counts.matched << color::reset
               << color::dim  << " dropped=" << total_dropped << color::reset
               << " (unknown_port=" << counts.unknown_port
               << " bad_src_port=" << counts.bad_src_port
               << " bad_token=" << counts.bad_token
               << " stale_rst=" << counts.stale_rst << ")\n";

    std::unordered_set<uint16_t> open_set(open_ports.begin(), open_ports.end());

    std::vector<const DemuxDebugEntry*> match_open, match_other, drops;
    match_open.reserve(open_ports.size());
    for (const auto& e : entries) {
        if (e.tag.rfind("MATCH", 0) == 0) {
            (open_set.count(e.port) ? match_open : match_other).push_back(&e);
        } else {
            drops.push_back(&e);
        }
    }

    for (const auto* ep : match_open) {
        const auto& e = *ep;
        oss << "    " << color::green << std::left << std::setw(7) << "open" << color::reset
                   << " " << std::setw(10) << (std::to_string(e.port) + "/tcp")
                   << ": attempt=" << e.attempt
                   << " src_port=" << e.src_port
                   << " flags=" << demux_render_flags(e.flags)
                   << " ttl=" << static_cast<int>(e.ttl)
                   << (e.is_icmp ? " (icmp)" : "") << "\n";
    }

    const size_t INLINE_THRESHOLD = 10;
    if (!match_other.empty()) {
        if (match_other.size() <= INLINE_THRESHOLD) {
            for (const auto* ep : match_other) {
                const auto& e = *ep;
                oss << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
                           << " " << std::setw(10) << (std::to_string(e.port) + "/tcp")
                           << ": attempt=" << e.attempt
                           << " src_port=" << e.src_port
                           << " flags=" << demux_render_flags(e.flags)
                           << " ttl=" << static_cast<int>(e.ttl)
                           << (e.is_icmp ? " (icmp)" : "") << "\n";
            }
        } else {
            std::unordered_map<uint64_t, std::vector<uint16_t>> groups;
            auto pack_key = [](int attempt, uint8_t flags, uint8_t ttl, bool is_icmp) -> uint64_t {
                return (static_cast<uint64_t>(static_cast<uint8_t>(attempt)) << 24) |
                       (static_cast<uint64_t>(flags) << 16) |
                       (static_cast<uint64_t>(ttl)   << 8)  |
                       (is_icmp ? 1u : 0u);
            };
            for (const auto* ep : match_other) {
                groups[pack_key(ep->attempt, ep->flags, ep->ttl, ep->is_icmp)].push_back(ep->port);
            }
            oss << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
                       << " " << match_other.size() << " ports matched, "
                       << groups.size() << " distinct pattern(s):\n";
            for (auto& [key, ports] : groups) {
                int      attempt = static_cast<int>((key >> 24) & 0xFF);
                uint8_t  flags   = static_cast<uint8_t>((key >> 16) & 0xFF);
                uint8_t  ttl     = static_cast<uint8_t>((key >> 8)  & 0xFF);
                bool     is_icmp = (key & 1u) != 0;
                std::sort(ports.begin(), ports.end());
                oss << "        x" << std::setw(4) << ports.size()
                           << " attempt=" << attempt
                           << " flags=" << demux_render_flags(flags)
                           << " ttl=" << static_cast<int>(ttl)
                           << (is_icmp ? " (icmp)" : "")
                           << "  ports " << ports.front() << "-" << ports.back() << "\n";
            }
        }
    }

    if (!drops.empty()) {
        oss << "    " << color::yellow << "dropped" << color::reset
                   << " " << drops.size() << " packet(s):\n";
        const size_t DROP_LIST_CAP = 30;
        size_t shown = 0;
        std::unordered_map<std::string, uint64_t> overflow_by_tag;
        for (const auto* ep : drops) {
            const auto& e = *ep;
            if (shown < DROP_LIST_CAP) {
                oss << "        " << color::dim << e.tag << color::reset
                           << " port=" << e.port
                           << " attempt=" << e.attempt
                           << " src_port=" << e.src_port
                           << " ttl=" << static_cast<int>(e.ttl)
                           << (e.is_icmp ? " (icmp)" : "")
                           << " — " << e.detail << "\n";
                ++shown;
            } else {
                overflow_by_tag[e.tag]++;
            }
        }
        for (auto& [tag, cnt] : overflow_by_tag) {
            oss << "        ... +" << cnt << " more " << tag << "\n";
        }
    }

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << oss.str();
}

void print_strack_debug(const std::string& target_ip,
                         const std::vector<StrackEntry>& entries,
                         const StrackCounters& counts) {
    if (entries.empty() && counts.unresolved == 0) return;

    std::ostringstream oss;

    auto state_str = [](StrackFinalState s) -> const char* {
        return s == StrackFinalState::Open   ? "open"   :
               s == StrackFinalState::Closed ? "closed" : "filtered";
    };
    auto state_color = [](StrackFinalState s) -> const std::string& {
        return s == StrackFinalState::Open   ? color::green :
               s == StrackFinalState::Closed ? color::red   : color::dim;
    };

    int open0 = 0, closed0 = 0, filtered0 = 0;
    for (const auto& e : entries) {
        if (e.resolved_attempt != 0) continue;
        if      (e.final_state == StrackFinalState::Open)   ++open0;
        else if (e.final_state == StrackFinalState::Closed) ++closed0;
        else                                                ++filtered0;
    }

    oss << "\nState-transition debug : " << color::green << target_ip << color::reset << "\n";

    oss << "    " << std::left << std::setw(20) << "Resolved (probe 1)"
               << ": " << counts.resolved_attempt[0] << " port(s)";
    if (counts.resolved_attempt[0] > 0)
        oss << "  (" << open0 << " open, " << closed0 << " closed, " << filtered0 << " filtered)";
    oss << "\n";

    for (int i = 1; i <= 5; ++i) {
        oss << "    " << std::left << std::setw(20) << ("Resolved (retry " + std::to_string(i) + ")")
                   << ": " << counts.resolved_attempt[i] << " port(s)\n";
    }

    oss << "    " << std::left << std::setw(20) << "Never responded"
               << ": " << counts.unresolved << " port(s) (filtered, all attempts exhausted)\n";

    uint64_t total_retries_sent = counts.total_packets_sent - counts.total_ports_tracked;
    oss << "    " << std::left << std::setw(20) << "Packet breakdown"
               << ": " << counts.total_ports_tracked << " initial, "
               << total_retries_sent << " retries ("
               << counts.total_packets_sent << " total)\n";

    std::vector<const StrackEntry*> needs_detail;
    for (const auto& e : entries)
        if (e.attempts_sent > 1) needs_detail.push_back(&e);

    if (!needs_detail.empty()) {
        std::sort(needs_detail.begin(), needs_detail.end(),
                  [](const StrackEntry* a, const StrackEntry* b) { return a->port < b->port; });
        oss << "\n    Retry detail (" << needs_detail.size() << " port(s)):\n";
        for (const auto* ep : needs_detail) {
            const auto& e = *ep;
            bool no_response = (e.resolved_attempt < 0);
            const std::string& line_color = no_response ? color::yellow : state_color(e.final_state);

            oss << "        " << line_color << std::left << std::setw(9)
                       << state_str(e.final_state) << color::reset
                       << std::setw(10) << (std::to_string(e.port) + "/tcp") << " ";
            for (uint8_t i = 0; i < e.attempt_src_port_count; ++i) {
                oss << e.attempt_src_ports[i];
                if (i + 1 < e.attempt_src_port_count) oss << " -> ";
            }
            if (!no_response) {
                oss << "  (resolved attempt " << e.resolved_attempt;
                if (e.rtt_ms >= 0.0)
                    oss << ", " << std::fixed << std::setprecision(1) << e.rtt_ms << "ms";
                oss << ")";
            } else {
                oss << line_color << "  (no response)" << color::reset;
            }
            oss << (e.is_icmp ? " [icmp]" : "") << "\n";
        }
    }

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << oss.str();
}
