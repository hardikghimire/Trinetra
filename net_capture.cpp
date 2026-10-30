#include "net_capture.hpp"
#include "utils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <iostream>
#include <limits>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <linux/if_packet.h>

extern std::atomic<bool> terminate_flag;

namespace net_capture {

namespace {

constexpr size_t kSnapLen = 65536;

std::string ip4_to_string(uint32_t be_addr) {
    in_addr a{};
    a.s_addr = be_addr;
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

std::string ip6_to_string(const in6_addr& addr) {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string pick_default_iface() {
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe < 0) return "";

    struct if_nameindex* list = if_nameindex();
    std::string chosen;
    if (list) {
        for (struct if_nameindex* it = list; it->if_name != nullptr; ++it) {
            if (std::strcmp(it->if_name, "lo") == 0) continue;

            struct ifreq ifr{};
            std::strncpy(ifr.ifr_name, it->if_name, IFNAMSIZ - 1);
            if (ioctl(probe, SIOCGIFFLAGS, &ifr) < 0) continue;
            if (!(ifr.ifr_flags & IFF_UP)) continue;

            chosen = it->if_name;
            break;
        }
        if_freenameindex(list);
    }
    close(probe);
    return chosen;
}


constexpr int kProtoColW = 7;  
constexpr int kIpColW    = 43;  
constexpr int kDomainColW = 30;
constexpr int kPortColW  = 10; 
constexpr int kStateColW = 8;

std::string pad(const std::string& s, size_t width) {
    constexpr size_t kMinGap = 2;
    if (s.size() + kMinGap >= width) return s + std::string(kMinGap, ' ');
    return s + std::string(width - s.size(), ' ');
}

std::string colorize(const std::string& padded_text, const char* ansi_code, bool enabled) {
    if (!enabled) return padded_text;
    return std::string("\033[") + ansi_code + "m" + padded_text + "\033[0m";
}

bool stdout_is_tty() {
    return isatty(STDOUT_FILENO) != 0;
}

bool color_enabled_for(ColorMode mode) {
    switch (mode) {
        case ColorMode::Always: return true;
        case ColorMode::Never:  return false;
        case ColorMode::Auto:
        default:                return stdout_is_tty();
    }
}

const char* kColorHeader = "1;37";  // bold white
const char* kColorTcp    = "1;36";  // bold cyan
const char* kColorQuic   = "1;35";  // bold magenta
const char* kColorDns    = "1;33";  // bold yellow
const char* kColorOpen   = "1;32";  // bold green
const char* kColorClosed = "1;31";  // bold red

std::string proto_label(Proto proto, IpVersion ver) {
    std::string base;
    switch (proto) {
        case Proto::TCP:  base = "tcp";  break;
        case Proto::QUIC: base = "quic"; break;
        case Proto::DNS:  base = "dns";  break;
    }
    base += (ver == IpVersion::V6) ? "6" : "4";
    return base;
}

const char* proto_color_for(Proto proto) {
    switch (proto) {
        case Proto::TCP:  return kColorTcp;
        case Proto::QUIC: return kColorQuic;
        case Proto::DNS:  return kColorDns;
    }
    return kColorTcp;
}

bool looks_like_responder_port(uint16_t candidate, uint16_t other) {
    bool candidate_wk = candidate < 1024;
    bool other_wk     = other < 1024;
    if (candidate_wk != other_wk) return candidate_wk;
    return candidate < other;
}


struct AggRow {
    Proto                  proto;
    IpVersion              ip_version;
    std::string            responder_ip;
    PortState              state;
    std::vector<uint16_t>  ports;   
};

std::string agg_key(Proto proto, IpVersion ver, const std::string& responder_ip, PortState state) {
    std::string k = proto_label(proto, ver);
    k += '|';
    k += responder_ip;
    k += '|';
    k += (state == PortState::OPEN) ? 'O' : 'C';
    return k;
}

} // namespace

bool parse_duration_ms(const std::string& text, int& out_ms) {
    if (text.empty()) return false;

    char unit = text.back();
    long multiplier = 1000;
    std::string digits = text;

    if (unit == 's' || unit == 'S') {
        multiplier = 1000;
        digits = text.substr(0, text.size() - 1);
    } else if (unit == 'm' || unit == 'M') {
        multiplier = 60L * 1000;
        digits = text.substr(0, text.size() - 1);
    } else if (unit == 'h' || unit == 'H') {
        multiplier = 60L * 60L * 1000;
        digits = text.substr(0, text.size() - 1);
    } else if (!std::isdigit(static_cast<unsigned char>(unit))) {
        return false;
    }

    if (digits.empty()) return false;
    for (char c : digits) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }

    long value = 0;
    try {
        size_t consumed = 0;
        value = std::stol(digits, &consumed);
        if (consumed != digits.size()) return false; 
    } catch (const std::exception&) {
        return false;
    }
    if (value <= 0) return false;

    long long total = static_cast<long long>(value) * static_cast<long long>(multiplier);
    if (total > static_cast<long long>(std::numeric_limits<int>::max())) {
        total = std::numeric_limits<int>::max();
    }

    out_ms = static_cast<int>(total);
    return true;
}


Capture::Capture(Options opts) : opts_(std::move(opts)) {}

Capture::~Capture() {
    close_socket();
}

bool Capture::open_socket() {
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) {
        last_error_ = std::string("socket(AF_PACKET) failed: ") + std::strerror(errno) +
                      " (net_capture needs CAP_NET_RAW / root)";
        return false;
    }

    std::string iface = opts_.iface.empty() ? pick_default_iface() : opts_.iface;
    if (iface.empty()) {
        last_error_ = "no usable interface found -- pass Options::iface explicitly";
        close_socket();
        return false;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        last_error_ = std::string("SIOCGIFINDEX failed for '") + iface + "': " + std::strerror(errno);
        close_socket();
        return false;
    }
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;
    if (bind(fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        last_error_ = std::string("bind() failed on '") + iface + "': " + std::strerror(errno);
        close_socket();
        return false;
    }

    // ---- promiscuous mode ----
    struct packet_mreq mreq{};
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        last_error_ = std::string("failed to enable promiscuous mode on '") + iface +
                      "': " + std::strerror(errno);
        close_socket();
        return false;
    }

    if (opts_.verbose)
        std::cerr << "[netradar] capturing on " << iface << " (promiscuous, IPv4+IPv6"
                   << (opts_.detect_quic ? ", QUIC on udp/" + std::to_string(opts_.quic_port) : "")
                   << (opts_.detect_dns  ? ", DNS on udp/"  + std::to_string(opts_.dns_port)   : "")
                   << (opts_.detect_established_traffic ? ", established-traffic inference on" : "")
                   << ")\n";

    return true;
}

void Capture::close_socket() noexcept {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

void Capture::handle_packet(const uint8_t* buf, size_t len,
                             const std::function<void(const Finding&)>& on_finding) {
    if (len < sizeof(struct ether_header)) return;

    const auto* eth = reinterpret_cast<const struct ether_header*>(buf);
    uint16_t ethertype = ntohs(eth->ether_type);

    const uint8_t* ip_start = buf + sizeof(struct ether_header);
    size_t ip_avail = len - sizeof(struct ether_header);

    if (ethertype == ETHERTYPE_IP) {
        handle_ipv4(ip_start, ip_avail, on_finding);
    } else if (ethertype == ETHERTYPE_IPV6) {
        handle_ipv6(ip_start, ip_avail, on_finding);
    }

}

void Capture::handle_ipv4(const uint8_t* ip_start, size_t ip_avail,
                           const std::function<void(const Finding&)>& on_finding) {
    if (ip_avail < sizeof(struct ip)) return;

    const auto* iph = reinterpret_cast<const struct ip*>(ip_start);
    size_t ip_hlen = static_cast<size_t>(iph->ip_hl) * 4;
    if (ip_hlen < sizeof(struct ip) || ip_avail < ip_hlen) return;

    std::string src_ip = ip4_to_string(iph->ip_src.s_addr);
    std::string dst_ip = ip4_to_string(iph->ip_dst.s_addr);
    const uint8_t* l4_start = ip_start + ip_hlen;
    size_t l4_avail = ip_avail - ip_hlen;

    stats_.packets_seen++;

    if (iph->ip_p == IPPROTO_TCP) {
        handle_tcp(IpVersion::V4, src_ip, dst_ip, l4_start, l4_avail, on_finding);
    } else if ((opts_.detect_quic || opts_.detect_dns) && iph->ip_p == IPPROTO_UDP) {
        handle_udp(IpVersion::V4, src_ip, dst_ip, l4_start, l4_avail, on_finding);
    }
}

void Capture::handle_ipv6(const uint8_t* ip_start, size_t ip_avail,
                           const std::function<void(const Finding&)>& on_finding) {
    if (ip_avail < sizeof(struct ip6_hdr)) return;

    const auto* iph = reinterpret_cast<const struct ip6_hdr*>(ip_start);

    uint8_t next_header = iph->ip6_nxt;
    if (next_header != IPPROTO_TCP && next_header != IPPROTO_UDP) return;

    std::string src_ip = ip6_to_string(iph->ip6_src);
    std::string dst_ip = ip6_to_string(iph->ip6_dst);
    const uint8_t* l4_start = ip_start + sizeof(struct ip6_hdr);
    size_t l4_avail = ip_avail - sizeof(struct ip6_hdr);

    stats_.packets_seen++;

    if (next_header == IPPROTO_TCP) {
        handle_tcp(IpVersion::V6, src_ip, dst_ip, l4_start, l4_avail, on_finding);
    } else if ((opts_.detect_quic || opts_.detect_dns) && next_header == IPPROTO_UDP) {
        handle_udp(IpVersion::V6, src_ip, dst_ip, l4_start, l4_avail, on_finding);
    }
}

void Capture::handle_tcp(IpVersion ver, const std::string& src_ip, const std::string& dst_ip,
                          const uint8_t* tcp_start, size_t tcp_avail,
                          const std::function<void(const Finding&)>& on_finding) {
    if (tcp_avail < sizeof(struct tcphdr)) return;
    const auto* tcph = reinterpret_cast<const struct tcphdr*>(tcp_start);

    const bool syn = tcph->syn;
    const bool ack = tcph->ack;
    const bool rst = tcph->rst;
    const bool fin = tcph->fin;
    const bool psh = tcph->psh;

    uint16_t src_port = ntohs(tcph->source);
    uint16_t dst_port = ntohs(tcph->dest);
    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_num = ntohl(tcph->ack_seq);

    if (syn && !ack) {
        stats_.syn_seen++;
        for (auto& p : pending_) {
            if (p.ip_version     == ver     &&
                p.initiator_ip   == src_ip   && p.initiator_port == src_port &&
                p.responder_ip   == dst_ip   && p.responder_port == dst_port) {
                p.syn_seq = seq;
                p.sent_at = std::chrono::steady_clock::now();
                return;
            }
        }

        PendingSyn p;
        p.ip_version     = ver;
        p.initiator_ip   = src_ip;
        p.initiator_port = src_port;
        p.responder_ip   = dst_ip;
        p.responder_port = dst_port;
        p.syn_seq        = seq;
        p.sent_at        = std::chrono::steady_clock::now();
        pending_.push_back(std::move(p));
        return;
    }

    if (syn && ack) {
        stats_.synack_seen++;
        for (auto it = pending_.begin(); it != pending_.end(); ++it) {
            if (it->ip_version     == ver     &&
                it->initiator_ip   == dst_ip   && it->initiator_port == dst_port &&
                it->responder_ip   == src_ip   && it->responder_port == src_port &&
                ack_num             == it->syn_seq + 1) {

                Finding f;
                f.proto          = Proto::TCP;
                f.ip_version     = ver;
                f.initiator_ip   = it->initiator_ip;
                f.initiator_port = it->initiator_port;
                f.responder_ip   = it->responder_ip;
                f.responder_port = it->responder_port;
                f.state          = PortState::OPEN;
                f.observed_at    = std::chrono::steady_clock::now();

                stats_.matched_open++;
                pending_.erase(it);
                if (!dedupe_and_mark(f)) on_finding(f);
                return;
            }
        }
        return;
    }

    if (rst) {
        stats_.rst_seen++;
        if (!opts_.report_closed) return;
        for (auto it = pending_.begin(); it != pending_.end(); ++it) {
            if (it->ip_version   == ver   &&
                it->initiator_ip == dst_ip && it->initiator_port == dst_port &&
                it->responder_ip == src_ip && it->responder_port == src_port) {

                Finding f;
                f.proto          = Proto::TCP;
                f.ip_version     = ver;
                f.initiator_ip   = it->initiator_ip;
                f.initiator_port = it->initiator_port;
                f.responder_ip   = it->responder_ip;
                f.responder_port = it->responder_port;
                f.state          = PortState::CLOSED;
                f.observed_at    = std::chrono::steady_clock::now();

                stats_.matched_closed++;
                pending_.erase(it);
                if (!dedupe_and_mark(f)) on_finding(f);
                return;
            }
        }
        return;
    }
    if (!opts_.detect_established_traffic) return;

    const bool bare_ack  = ack && !psh && !fin;   // pure ACK: keepalive / acking data
    const bool fin_ack    = fin && ack;            // graceful close of an established session
    const bool psh_ack    = psh && ack;            // the ordinary "here's some data" segment
    const bool bare_psh   = psh && !ack;           // unusual (real stacks set ACK once
                                                    // established) but still mid-session-only

    if (!(bare_ack || fin_ack || psh_ack || bare_psh)) return;

    stats_.ack_seen    += bare_ack  ? 1 : 0;
    stats_.finack_seen += fin_ack   ? 1 : 0;
    stats_.pshack_seen += psh_ack   ? 1 : 0;
    stats_.psh_seen    += bare_psh  ? 1 : 0;

    Finding f;
    f.proto       = Proto::TCP;
    f.ip_version  = ver;
    f.state       = PortState::OPEN;
    f.observed_at = std::chrono::steady_clock::now();

    if (looks_like_responder_port(src_port, dst_port)) {
        f.responder_ip   = src_ip;
        f.responder_port = src_port;
        f.initiator_ip    = dst_ip;
        f.initiator_port  = dst_port;
    } else {
        f.responder_ip   = dst_ip;
        f.responder_port = dst_port;
        f.initiator_ip    = src_ip;
        f.initiator_port  = src_port;
    }

    stats_.matched_open_established++;
    if (!dedupe_and_mark(f)) on_finding(f);
}

void Capture::handle_udp(IpVersion ver, const std::string& src_ip, const std::string& dst_ip,
                          const uint8_t* udp_start, size_t udp_avail,
                          const std::function<void(const Finding&)>& on_finding) {
    if (udp_avail < sizeof(struct udphdr)) return;
    const auto* udph = reinterpret_cast<const struct udphdr*>(udp_start);

    uint16_t src_port = ntohs(udph->source);
    uint16_t dst_port = ntohs(udph->dest);

    const uint8_t* payload = udp_start + sizeof(struct udphdr);
    size_t payload_len = (udp_avail > sizeof(struct udphdr)) ? udp_avail - sizeof(struct udphdr) : 0;
    if (opts_.detect_quic && (src_port == opts_.quic_port || dst_port == opts_.quic_port)) {
        handle_quic(ver, src_ip, src_port, dst_ip, dst_port, payload, payload_len, on_finding);
        return;
    }
    if (opts_.detect_dns && (src_port == opts_.dns_port || dst_port == opts_.dns_port)) {
        handle_dns(ver, src_ip, src_port, dst_ip, dst_port, payload, payload_len, on_finding);
        return;
    }
}

void Capture::handle_quic(IpVersion ver, const std::string& src_ip, uint16_t src_port,
                           const std::string& dst_ip, uint16_t dst_port,
                           const uint8_t* payload, size_t payload_len,
                           const std::function<void(const Finding&)>& on_finding) {
    if (dst_port == opts_.quic_port) {
        if (payload_len < 1 || !(payload[0] & 0x80)) return;

        stats_.quic_initial_seen++;
        for (auto& p : pending_quic_) {
            if (p.ip_version     == ver     &&
                p.initiator_ip   == src_ip   && p.initiator_port == src_port &&
                p.responder_ip   == dst_ip   && p.responder_port == dst_port) {
                p.sent_at = std::chrono::steady_clock::now();
                return;
            }
        }

        PendingQuic p;
        p.ip_version     = ver;
        p.initiator_ip   = src_ip;
        p.initiator_port = src_port;
        p.responder_ip   = dst_ip;
        p.responder_port = dst_port;
        p.sent_at        = std::chrono::steady_clock::now();
        pending_quic_.push_back(std::move(p));
        return;
    }
    for (auto it = pending_quic_.begin(); it != pending_quic_.end(); ++it) {
        if (it->ip_version     == ver     &&
            it->initiator_ip   == dst_ip   && it->initiator_port == dst_port &&
            it->responder_ip   == src_ip   && it->responder_port == src_port) {

            Finding f;
            f.proto          = Proto::QUIC;
            f.ip_version     = ver;
            f.initiator_ip   = it->initiator_ip;
            f.initiator_port = it->initiator_port;
            f.responder_ip   = it->responder_ip;
            f.responder_port = it->responder_port;
            f.state          = PortState::OPEN;
            f.observed_at    = std::chrono::steady_clock::now();

            stats_.quic_matched_open++;
            pending_quic_.erase(it);
            if (!dedupe_and_mark(f)) on_finding(f);
            return;
        }
    }
}

void Capture::handle_dns(IpVersion ver, const std::string& src_ip, uint16_t src_port,
                          const std::string& dst_ip, uint16_t dst_port,
                          const uint8_t* payload, size_t payload_len,
                          const std::function<void(const Finding&)>& on_finding) {
    constexpr size_t kDnsHeaderLen = 12;
    constexpr uint8_t kQrBit = 0x80;

    if (dst_port == opts_.dns_port) {
        if (payload_len < kDnsHeaderLen || (payload[2] & kQrBit)) return;

        stats_.dns_query_seen++;
        for (auto& p : pending_dns_) {
            if (p.ip_version     == ver     &&
                p.initiator_ip   == src_ip   && p.initiator_port == src_port &&
                p.responder_ip   == dst_ip   && p.responder_port == dst_port) {
                p.sent_at = std::chrono::steady_clock::now();
                return;
            }
        }

        PendingDns p;
        p.ip_version     = ver;
        p.initiator_ip   = src_ip;
        p.initiator_port = src_port;
        p.responder_ip   = dst_ip;
        p.responder_port = dst_port;
        p.sent_at        = std::chrono::steady_clock::now();
        pending_dns_.push_back(std::move(p));
        return;
    }
    if (payload_len < kDnsHeaderLen || !(payload[2] & kQrBit)) return;

    for (auto it = pending_dns_.begin(); it != pending_dns_.end(); ++it) {
        if (it->ip_version     == ver     &&
            it->initiator_ip   == dst_ip   && it->initiator_port == dst_port &&
            it->responder_ip   == src_ip   && it->responder_port == src_port) {

            Finding f;
            f.proto          = Proto::DNS;
            f.ip_version     = ver;
            f.initiator_ip   = it->initiator_ip;
            f.initiator_port = it->initiator_port;
            f.responder_ip   = it->responder_ip;
            f.responder_port = it->responder_port;
            f.state          = PortState::OPEN;
            f.observed_at    = std::chrono::steady_clock::now();

            stats_.dns_matched_open++;
            pending_dns_.erase(it);
            if (!dedupe_and_mark(f)) on_finding(f);
            return;
        }
    }
}

bool Capture::dedupe_and_mark(const Finding& f) {
    if (opts_.dedup_window_ms <= 0) return false;

    const auto now    = std::chrono::steady_clock::now();
    const auto window = std::chrono::milliseconds(opts_.dedup_window_ms);

    for (auto& r : reported_) {
        if (r.proto           == f.proto          &&
            r.ip_version      == f.ip_version     &&
            r.initiator_ip    == f.initiator_ip   && r.initiator_port == f.initiator_port &&
            r.responder_ip    == f.responder_ip   && r.responder_port == f.responder_port &&
            r.state           == f.state) {

            const bool within_window = (now - r.last_reported) <= window;
            r.last_reported = now;

            if (within_window) {
                stats_.duplicates_suppressed++;
                return true;
            }
            return false;
        }
    }

    ReportedKey r;
    r.proto          = f.proto;
    r.ip_version     = f.ip_version;
    r.initiator_ip   = f.initiator_ip;
    r.initiator_port = f.initiator_port;
    r.responder_ip   = f.responder_ip;
    r.responder_port = f.responder_port;
    r.state          = f.state;
    r.last_reported  = now;
    reported_.push_back(std::move(r));
    return false;
}

void Capture::sweep_expired() {
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::milliseconds(opts_.pending_timeout_ms);

    size_t before = pending_.size();
    pending_.erase(
        std::remove_if(pending_.begin(), pending_.end(),
                        [&](const PendingSyn& p) { return (now - p.sent_at) > timeout; }),
        pending_.end());
    stats_.pending_expired += (before - pending_.size());

    size_t before_quic = pending_quic_.size();
    pending_quic_.erase(
        std::remove_if(pending_quic_.begin(), pending_quic_.end(),
                        [&](const PendingQuic& p) { return (now - p.sent_at) > timeout; }),
        pending_quic_.end());
    stats_.quic_pending_expired += (before_quic - pending_quic_.size());

    size_t before_dns = pending_dns_.size();
    pending_dns_.erase(
        std::remove_if(pending_dns_.begin(), pending_dns_.end(),
                        [&](const PendingDns& p) { return (now - p.sent_at) > timeout; }),
        pending_dns_.end());
    stats_.dns_pending_expired += (before_dns - pending_dns_.size());
    if (opts_.dedup_window_ms > 0) {
        auto dedup_ttl = std::chrono::milliseconds(opts_.dedup_window_ms) * 2;
        reported_.erase(
            std::remove_if(reported_.begin(), reported_.end(),
                            [&](const ReportedKey& r) { return (now - r.last_reported) > dedup_ttl; }),
            reported_.end());
    }
}

bool Capture::run(const std::function<void(const Finding&)>& on_finding) {
    if (!open_socket()) return false;

    std::vector<uint8_t> buf(kSnapLen);
    auto last_sweep = std::chrono::steady_clock::now();
    const bool has_deadline = opts_.duration_ms > 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(opts_.duration_ms);
    struct timeval tv{};
    tv.tv_sec  = 0;
    tv.tv_usec = 200 * 1000;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!stop_.load(std::memory_order_relaxed) && !terminate_flag.load(std::memory_order_relaxed)) {
        if (has_deadline && std::chrono::steady_clock::now() >= deadline) break;

        ssize_t n = recv(fd_, buf.data(), buf.size(), 0);
        if (n > 0) {
            handle_packet(buf.data(), static_cast<size_t>(n), on_finding);
        }

        auto now = std::chrono::steady_clock::now();
        if (now - last_sweep >= std::chrono::milliseconds(opts_.sweep_interval_ms)) {
            sweep_expired();
            last_sweep = now;
        }
    }

    close_socket();
    return true;
}

void Capture::stop() noexcept {
    stop_.store(true, std::memory_order_relaxed);
}

int run_netradar(const Options& opts) {
    Capture cap(opts);
    const bool color = color_enabled_for(opts.color);

    std::cerr << "Starting netradar (passive TCP SYN/SYN-ACK"
              << (opts.detect_established_traffic ? "/ACK/PSH/PSH-ACK/FIN-ACK" : "")
              << (opts.detect_quic ? " + QUIC Initial/response" : "")
              << (opts.detect_dns  ? " + DNS query/response"    : "")
              << " correlation, IPv4+IPv6)"
              << (opts.iface.empty() ? "" : (" on " + opts.iface));
    if (opts.duration_ms > 0) {
        std::cerr << ", running for " << (opts.duration_ms / 1000.0) << "s";
    } else {
        std::cerr << ", running until interrupted (Ctrl-C)";
    }
    std::cerr << "\n";
    std::vector<AggRow> rows;
    std::unordered_map<std::string, size_t> index;

    bool ok = cap.run([&](const Finding& f) {
        const std::string key = agg_key(f.proto, f.ip_version, f.responder_ip, f.state);
        auto it = index.find(key);
        if (it == index.end()) {
            AggRow row;
            row.proto        = f.proto;
            row.ip_version   = f.ip_version;
            row.responder_ip = f.responder_ip;
            row.state        = f.state;
            row.ports.push_back(f.responder_port);
            index.emplace(key, rows.size());
            rows.push_back(std::move(row));
            return;
        }

        AggRow& row = rows[it->second];
        if (std::find(row.ports.begin(), row.ports.end(), f.responder_port) == row.ports.end()) {
            row.ports.push_back(f.responder_port);
        }
    });

    if (!ok) {
        std::cerr << "netradar: " << cap.last_error() << "\n";
        return 1;
    }
    // One vectorized PTR pass over all unique responder IPs (after capture,
    // so our own PTR queries are never seen as DNS findings).
    std::vector<std::string> ips;
    ips.reserve(rows.size());
    for (const auto& r : rows) ips.push_back(r.responder_ip);

    // Ctrl-C ends the capture by setting the global terminate_flag; clear it
    // for the resolve phase so the batch resolver isn't aborted, then restore.
    const bool was_interrupted = terminate_flag.load(std::memory_order_relaxed);
    terminate_flag.store(false, std::memory_order_relaxed);
    if (!ips.empty()) {
        std::cerr << "[netradar] resolving domains for " << ips.size()
                  << " host(s)... (Ctrl-C again to skip)\n";
    }

    std::unordered_map<std::string, std::string> hostnames;
    reverse_dns_lookup_batch(ips, hostnames);

    terminate_flag.store(was_interrupted, std::memory_order_relaxed);

    std::vector<std::string> domain_cells(rows.size());
    size_t domain_col_w = static_cast<size_t>(kDomainColW);
    for (size_t i = 0; i < rows.size(); ++i) {
        auto it = hostnames.find(rows[i].responder_ip);
        std::string d = (it != hostnames.end()) ? it->second : "";
        if (!d.empty() && d.back() == '.') d.pop_back();
        if (d.empty()) d = "-";
        domain_col_w = std::max(domain_col_w, d.size() + 2);
        domain_cells[i] = std::move(d);
    }

    std::vector<std::string> port_cells(rows.size());
    size_t port_col_w = static_cast<size_t>(kPortColW);
    for (size_t i = 0; i < rows.size(); ++i) {
        std::string cell;
        for (size_t j = 0; j < rows[i].ports.size(); ++j) {
            if (j) cell += ',';
            cell += std::to_string(rows[i].ports[j]);
        }
        port_cells[i] = cell;
        port_col_w = std::max(port_col_w, cell.size() + 2);
    }

    std::cout << colorize(pad("PROTO", kProtoColW), kColorHeader, color)
               << colorize(pad("RESPONDER", kIpColW), kColorHeader, color)
               << colorize(pad("DOMAIN", domain_col_w), kColorHeader, color)
               << colorize(pad("PORT", port_col_w), kColorHeader, color)
               << colorize(pad("STATE", kStateColW), kColorHeader, color)
               << "\n";

    for (size_t i = 0; i < rows.size(); ++i) {
        const AggRow& row = rows[i];
        const char* proto_color = proto_color_for(row.proto);
        const char* state_color = (row.state == PortState::OPEN) ? kColorOpen : kColorClosed;
        const std::string state_text = (row.state == PortState::OPEN) ? "OPEN" : "CLOSED";

        std::cout << colorize(pad(proto_label(row.proto, row.ip_version), kProtoColW), proto_color, color)
                   << pad(row.responder_ip, kIpColW)
                   << pad(domain_cells[i], domain_col_w)
                   << pad(port_cells[i], port_col_w)
                   << colorize(pad(state_text, kStateColW), state_color, color)
                   << "\n";
    }
    std::cout << std::flush;

    const Stats& s = cap.stats();
    std::cerr << "\n[netradar] packets=" << s.packets_seen
              << " syn=" << s.syn_seen
              << " synack=" << s.synack_seen
              << " rst=" << s.rst_seen
              << " open_matched=" << s.matched_open
              << " closed_matched=" << s.matched_closed
              << " expired=" << s.pending_expired;
    if (opts.detect_established_traffic) {
        std::cerr << " | ack=" << s.ack_seen
                   << " finack=" << s.finack_seen
                   << " pshack=" << s.pshack_seen
                   << " psh=" << s.psh_seen
                   << " established_open_matched=" << s.matched_open_established;
    }
    if (opts.detect_quic) {
        std::cerr << " | quic_initial=" << s.quic_initial_seen
                   << " quic_open_matched=" << s.quic_matched_open
                   << " quic_expired=" << s.quic_pending_expired;
    }
    if (opts.detect_dns) {
        std::cerr << " | dns_query=" << s.dns_query_seen
                   << " dns_open_matched=" << s.dns_matched_open
                   << " dns_expired=" << s.dns_pending_expired;
    }
    std::cerr << " | dup_suppressed=" << s.duplicates_suppressed
               << " | hosts_reported=" << rows.size();
    std::cerr << "\n";
    return 0;
}

}
