#include "traceroute.hpp"
// icmp_ping.hpp's tcp_syn_probe_sweep() uses struct tcphdr and TH_* flags
// without including <netinet/tcp.h> itself — it only compiles today because
// main.cpp always includes scan.hpp (which pulls that header in) first.
// Included explicitly here so traceroute.cpp doesn't inherit that ordering
// dependency.
#include <netinet/tcp.h>
#include "icmp_ping.hpp"   // icmp_detail::RawSocket, icmp_detail::icmp_checksum
#include "utils.hpp"       // reverse_dns_lookup, ptr_cache_lookup/store, WriteCallback

#include <curl/curl.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>

namespace {

// ─── Local color codes ──────────────────────────────────────────────────
// main.cpp defines its own `namespace color` with the same palette, but
// that namespace lives in main.cpp itself (not a header), so it isn't
// reachable from this translation unit. Kept intentionally separate to
// avoid a cross-TU dependency for five ANSI strings.
namespace trcolor {
    constexpr const char* reset  = "\033[0m";
    constexpr const char* bold   = "\033[1m";
    constexpr const char* green  = "\033[32m";
    constexpr const char* yellow = "\033[93m";
    constexpr const char* dim    = "\033[2m";
    constexpr const char* cyan   = "\033[36m";
    constexpr const char* red    = "\033[91m";
}

// ─── RFC 4950 ICMP extension parsing (MPLS Label Stack object) ─────────
//
// Time-Exceeded / Dest-Unreachable messages from MPLS-aware routers can
// carry an "ICMP extension structure" (RFC 4884) appended after the
// quoted original datagram. Inside it, a class-1/type-1 object (RFC 4950)
// holds one or more 4-byte MPLS label-stack entries. Most routers never
// send this — an empty result here just means the hop didn't include it,
// not a parse failure.
#pragma pack(push, 1)
struct IcmpExtHdr {
    uint8_t  version_flags; // top nibble = version (2 for RFC 4884)
    uint8_t  reserved;
    uint16_t checksum;
};
struct IcmpExtObjHdr {
    uint16_t length;    // network order, includes this 4-byte header
    uint8_t  class_num;
    uint8_t  c_type;
};
#pragma pack(pop)

constexpr uint8_t ICMP_EXT_CLASS_MPLS       = 1;
constexpr uint8_t ICMP_EXT_CTYPE_MPLS_STACK = 1;

std::vector<MplsLabelEntry> parse_mpls_extensions(const uint8_t* icmp_payload,
                                                    size_t payload_len,
                                                    uint8_t icmp_length_field)
{
    std::vector<MplsLabelEntry> out;

    // RFC 4884's "length" byte counts 32-bit words of the quoted original
    // datagram that precede the extension structure. 0 means either no
    // extensions or a pre-RFC-4884 sender — nothing safe to parse.
    if (icmp_length_field == 0) return out;

    const size_t quoted_len = static_cast<size_t>(icmp_length_field) * 4;
    if (quoted_len == 0 || quoted_len >= payload_len) return out;

    const uint8_t* ext       = icmp_payload + quoted_len;
    const size_t   ext_avail = payload_len - quoted_len;
    if (ext_avail < sizeof(IcmpExtHdr)) return out;

    IcmpExtHdr hdr;
    std::memcpy(&hdr, ext, sizeof(hdr));
    if ((hdr.version_flags >> 4) != 2) return out;   // not RFC 4884 v2

    size_t off = sizeof(IcmpExtHdr);
    while (off + sizeof(IcmpExtObjHdr) <= ext_avail) {
        IcmpExtObjHdr obj;
        std::memcpy(&obj, ext + off, sizeof(obj));
        const uint16_t obj_len = ntohs(obj.length);
        if (obj_len < sizeof(IcmpExtObjHdr) || off + obj_len > ext_avail) break;

        if (obj.class_num == ICMP_EXT_CLASS_MPLS &&
            obj.c_type    == ICMP_EXT_CTYPE_MPLS_STACK) {
            const size_t stack_off = off + sizeof(IcmpExtObjHdr);
            const size_t stack_len = obj_len - sizeof(IcmpExtObjHdr);
            for (size_t s = 0; s + 4 <= stack_len; s += 4) {
                uint32_t word;
                std::memcpy(&word, ext + stack_off + s, 4);
                word = ntohl(word);
                MplsLabelEntry e;
                e.label = (word >> 12) & 0xFFFFFu;  // top 20 bits
                e.exp   = (word >> 9)  & 0x7u;       // 3-bit EXP / CoS
                e.bos   = (word >> 8)  & 0x1u;       // bottom-of-stack
                e.ttl   =  word        & 0xFFu;      // MPLS shim TTL
                out.push_back(e);
            }
        }
        off += obj_len;
    }
    return out;
}

// ─── AS / ISP / geolocation lookup ──────────────────────────────────────
// Uses ip-api.com's free, keyless JSON endpoint. Reuses WriteCallback
// (utils.hpp) — the project's existing libcurl sink — instead of a
// second copy. Results are cached per run: the same transit hop is often
// seen from multiple targets/probes and shouldn't be re-queried each time.
std::mutex                                  g_geo_cache_mu;
std::unordered_map<std::string, GeoIspInfo> g_geo_cache;

std::string json_extract_str(const std::string& body, const std::string& key) {
    const std::string pat = "\"" + key + "\":\"";
    size_t p = body.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = body.find('"', p);
    if (e == std::string::npos) return "";
    return body.substr(p, e - p);
}

double json_extract_num(const std::string& body, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    size_t p = body.find(pat);
    if (p == std::string::npos) return 0.0;
    p += pat.size();
    try { return std::stod(body.substr(p, 32)); } catch (...) { return 0.0; }
}

GeoIspInfo geoip_lookup(const std::string& ip) {
    {
        std::lock_guard<std::mutex> lk(g_geo_cache_mu);
        auto it = g_geo_cache.find(ip);
        if (it != g_geo_cache.end()) return it->second;
    }

    GeoIspInfo info;
    CURL* curl = curl_easy_init();
    if (!curl) return info;

    std::string response;
    const std::string url =
        "http://ip-api.com/json/" + ip +
        "?fields=status,country,regionName,city,lat,lon,isp,org,as,query";

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 800L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || response.empty()) return info;

    if (json_extract_str(response, "status") == "success") {
        info.resolved = true;
        info.country  = json_extract_str(response, "country");
        info.region   = json_extract_str(response, "regionName");
        info.city     = json_extract_str(response, "city");
        info.isp      = json_extract_str(response, "isp");
        info.org      = json_extract_str(response, "org");
        info.asn      = json_extract_str(response, "as");
        info.lat      = json_extract_num(response, "lat");
        info.lon      = json_extract_num(response, "lon");
    }

    std::lock_guard<std::mutex> lk(g_geo_cache_mu);
    g_geo_cache[ip] = info;
    return info;
}

// Skip geo/DNS lookups for RFC 1918 / link-local / loopback hops — they're
// never in ip-api.com's database and reverse DNS on them is almost always
// pointless PTR failures.
bool is_private_v4(const struct in_addr& a) {
    const uint32_t ip = ntohl(a.s_addr);
    return ((ip >> 24) == 10) ||                              // 10.0.0.0/8
           ((ip >> 20) == ((172u << 4) | 1)) ||                // 172.16.0.0/12
           ((ip >> 16) == ((192u << 8) | 168)) ||               // 192.168.0.0/16
           ((ip >> 24) == 127) ||                                // loopback
           ((ip >> 16) == ((169u << 8) | 254));                  // link-local
}

void enrich_hop(TracerouteHop& hop, const TracerouteOptions& opts, bool skip_public_lookups) {
    if (hop.ip.empty() || skip_public_lookups) return;

    if (opts.resolve_dns) {
        std::string cached;
        if (ptr_cache_lookup(hop.ip, cached)) {
            hop.hostname = cached;
        } else {
            hop.hostname = reverse_dns_lookup(hop.ip);
            if (!hop.hostname.empty()) ptr_cache_store(hop.ip, hop.hostname);
        }
    }
    if (opts.resolve_geoip) {
        hop.geo = geoip_lookup(hop.ip);
    }
}

} // namespace

// ─── IPv4 traceroute ─────────────────────────────────────────────────────
std::vector<TracerouteHop> run_traceroute(const std::string& target_ip,
                                           const TracerouteOptions& opts)
{
    using namespace icmp_detail;
    std::vector<TracerouteHop> hops;

    struct in_addr dst{};
    if (::inet_pton(AF_INET, target_ip.c_str(), &dst) != 1) return hops;

    // Same RAII raw ICMP socket type icmp_ping_sweep() uses — CAP_NET_RAW
    // preferred, falls back to an unprivileged ICMP datagram socket.
    RawSocket sock;
    if (!sock.valid()) return hops;

    {
        int fl = ::fcntl(sock.fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(sock.fd, F_SETFL, fl | O_NONBLOCK);
    }
    { int rcvbuf = 1 * 1024 * 1024; ::setsockopt(sock.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }

    struct sockaddr_in dst_addr{};
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr   = dst;

    const uint16_t ident = static_cast<uint16_t>(::getpid() & 0xFFFFu);
    bool done = false;

    for (int ttl = 1; ttl <= opts.max_hops && !done; ++ttl) {
        if (::setsockopt(sock.fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) break;

        TracerouteHop hop;
        hop.ttl = ttl;
        hop.probes.resize(static_cast<size_t>(opts.probes_per_hop));

        for (int p = 0; p < opts.probes_per_hop; ++p) {
            struct { struct icmphdr hdr; uint8_t pad[32]; } pkt{};
            pkt.hdr.type             = ICMP_ECHO;
            pkt.hdr.code             = 0;
            pkt.hdr.un.echo.id       = htons(ident);
            pkt.hdr.un.echo.sequence = htons(static_cast<uint16_t>(ttl * 100 + p));
            pkt.hdr.checksum         = 0;
            pkt.hdr.checksum         = icmp_checksum(&pkt, sizeof(pkt));

            const auto t0 = std::chrono::steady_clock::now();
            if (::sendto(sock.fd, &pkt, sizeof(pkt), 0,
                         reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr)) < 0) {
                continue;
            }

            struct pollfd pfd{ sock.fd, POLLIN, 0 };
            const auto deadline = t0 + std::chrono::milliseconds(opts.timeout_ms);

            while (true) {
                const auto left_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          deadline - std::chrono::steady_clock::now()).count();
                if (left_ms <= 0) break;
                const int pr = ::poll(&pfd, 1, static_cast<int>(left_ms));
                if (pr <= 0) break;

                uint8_t buf[576];
                struct sockaddr_in from{};
                socklen_t fromlen = sizeof(from);
                const ssize_t n = ::recvfrom(sock.fd, buf, sizeof(buf), 0,
                                              reinterpret_cast<sockaddr*>(&from), &fromlen);
                if (n < static_cast<ssize_t>(sizeof(struct ip) + sizeof(struct icmphdr))) continue;

                const auto* iph = reinterpret_cast<const struct ip*>(buf);
                if (iph->ip_v != 4u) continue;
                const int iphlen = iph->ip_hl * 4;
                if (iphlen < 20 || iphlen > 60 || n < iphlen + 8) continue;
                const auto* ih = reinterpret_cast<const struct icmphdr*>(buf + iphlen);

                bool    is_reply_to_us = false;
                bool    unreachable    = false;
                uint8_t icmp_len_field = 0;
                const uint8_t* icmp_payload     = buf + iphlen;
                const size_t   icmp_payload_len = static_cast<size_t>(n) - static_cast<size_t>(iphlen);

                if (ih->type == ICMP_ECHOREPLY && ntohs(ih->un.echo.id) == ident) {
                    is_reply_to_us = true;
                    done           = true;
                } else if ((ih->type == ICMP_TIME_EXCEEDED && ih->code == 0) ||
                           ih->type == ICMP_DEST_UNREACH) {
                    // RFC 4884 length field: byte offset 1 of the 4-byte
                    // "unused" block, i.e. buf+iphlen+5.
                    if (n >= iphlen + 8) icmp_len_field = buf[iphlen + 5];

                    const size_t off_inner = static_cast<size_t>(iphlen) + 8u;
                    if (n >= static_cast<ssize_t>(off_inner + 20)) {
                        const auto* iip = reinterpret_cast<const struct ip*>(buf + off_inner);
                        if (iip->ip_v == 4u) {
                            const int    iiphlen   = iip->ip_hl * 4;
                            const size_t off_iicmp = off_inner + static_cast<size_t>(iiphlen);
                            if (n >= static_cast<ssize_t>(off_iicmp + 8)) {
                                const auto* iicmp = reinterpret_cast<const struct icmphdr*>(buf + off_iicmp);
                                if (ntohs(iicmp->un.echo.id) == ident) is_reply_to_us = true;
                            }
                        }
                    }
                    if (ih->type == ICMP_DEST_UNREACH) { unreachable = true; done = true; }
                }

                if (!is_reply_to_us) continue;

                const double rtt_ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();

                hop.probes[static_cast<size_t>(p)].responded = true;
                hop.probes[static_cast<size_t>(p)].rtt_ms    = rtt_ms;
                hop.unreachable = hop.unreachable || unreachable;

                char ipstr[INET_ADDRSTRLEN];
                ::inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof(ipstr));
                if (hop.ip.empty()) hop.ip = ipstr;

                if (hop.mpls_labels.empty()) {
                    auto labels = parse_mpls_extensions(icmp_payload, icmp_payload_len, icmp_len_field);
                    if (!labels.empty()) hop.mpls_labels = std::move(labels);
                }
                break; // this probe is answered — move on to the next one
            }
        }

        if (!hop.ip.empty()) {
            struct in_addr hop_addr{};
            const bool priv = (::inet_pton(AF_INET, hop.ip.c_str(), &hop_addr) == 1) &&
                               is_private_v4(hop_addr);
            enrich_hop(hop, opts, priv);
            if (hop.ip == target_ip) { hop.is_destination = true; done = true; }
        }

        hops.push_back(std::move(hop));
    }

    return hops;
}

// ─── IPv6 traceroute ─────────────────────────────────────────────────────
// Same control flow as run_traceroute(); IPV6_UNICAST_HOPS replaces
// IP_TTL, ICMPv6 Echo/Time-Exceeded replace their v4 counterparts. Note
// that on Linux, AF_INET6/SOCK_RAW delivers payload starting at the
// ICMPv6 header — the kernel strips the outer IPv6 header (icmp_ping.hpp
// documents the same behavior for its own v6 sweep), so there is no
// iphlen offset to skip here.
std::vector<TracerouteHop> run_traceroute6(const std::string& target_ip6,
                                            const TracerouteOptions& opts)
{
    std::vector<TracerouteHop> hops;

    struct in6_addr dst6{};
    if (::inet_pton(AF_INET6, target_ip6.c_str(), &dst6) != 1) return hops;

    int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) return hops;
    struct FdGuard { int f; ~FdGuard() { if (f >= 0) ::close(f); } } guard{fd};

    {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    { int rcvbuf = 1 * 1024 * 1024; ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }

    struct sockaddr_in6 dst_addr{};
    dst_addr.sin6_family = AF_INET6;
    dst_addr.sin6_addr   = dst6;

    const uint16_t ident = static_cast<uint16_t>(::getpid() & 0xFFFFu);
    bool done = false;

    for (int ttl = 1; ttl <= opts.max_hops && !done; ++ttl) {
        if (::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0) break;

        TracerouteHop hop;
        hop.ttl = ttl;
        hop.probes.resize(static_cast<size_t>(opts.probes_per_hop));

        for (int p = 0; p < opts.probes_per_hop; ++p) {
            struct { struct icmp6_hdr hdr; uint8_t pad[32]; } pkt{};
            pkt.hdr.icmp6_type              = ICMP6_ECHO_REQUEST;
            pkt.hdr.icmp6_code              = 0;
            pkt.hdr.icmp6_id                = htons(ident);
            pkt.hdr.icmp6_seq               = htons(static_cast<uint16_t>(ttl * 100 + p));
            pkt.hdr.icmp6_cksum             = 0; // kernel fills via IPV6_CHECKSUM

            int on = 2; // offset of icmp6_cksum within the packet
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &on, sizeof(on));

            const auto t0 = std::chrono::steady_clock::now();
            if (::sendto(fd, &pkt, sizeof(pkt), 0,
                         reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr)) < 0) {
                continue;
            }

            struct pollfd pfd{ fd, POLLIN, 0 };
            const auto deadline = t0 + std::chrono::milliseconds(opts.timeout_ms);

            while (true) {
                const auto left_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          deadline - std::chrono::steady_clock::now()).count();
                if (left_ms <= 0) break;
                const int pr = ::poll(&pfd, 1, static_cast<int>(left_ms));
                if (pr <= 0) break;

                uint8_t buf[576];
                struct sockaddr_in6 from{};
                socklen_t fromlen = sizeof(from);
                const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                              reinterpret_cast<sockaddr*>(&from), &fromlen);
                if (n < static_cast<ssize_t>(sizeof(struct icmp6_hdr))) continue;

                const auto* ih = reinterpret_cast<const struct icmp6_hdr*>(buf);
                bool    is_reply_to_us = false;
                bool    unreachable    = false;
                uint8_t icmp_len_field = 0;
                const uint8_t* icmp_payload     = buf;
                const size_t   icmp_payload_len = static_cast<size_t>(n);

                if (ih->icmp6_type == ICMP6_ECHO_REPLY && ntohs(ih->icmp6_id) == ident) {
                    is_reply_to_us = true;
                    done           = true;
                } else if ((ih->icmp6_type == ICMP6_TIME_EXCEEDED && ih->icmp6_code == 0) ||
                           ih->icmp6_type == ICMP6_DST_UNREACH) {
                    // Same RFC 4884 layout as v4: length byte at offset 1 of
                    // the 4-byte "unused" block, i.e. buf+5. ICMPv6 doesn't
                    // strip an outer header on this recv path, so offsets
                    // are relative to buf directly (no iphlen here).
                    if (n >= 8) icmp_len_field = buf[5];

                    const size_t off_inner = 8u; // icmp6_hdr size
                    if (n >= static_cast<ssize_t>(off_inner + sizeof(struct ip6_hdr) + 8)) {
                        const auto* iip6 = reinterpret_cast<const struct ip6_hdr*>(buf + off_inner);
                        const size_t off_iicmp = off_inner + sizeof(struct ip6_hdr);
                        const auto* iicmp = reinterpret_cast<const struct icmp6_hdr*>(buf + off_iicmp);
                        (void)iip6;
                        if (ntohs(iicmp->icmp6_id) == ident) is_reply_to_us = true;
                    }
                    if (ih->icmp6_type == ICMP6_DST_UNREACH) { unreachable = true; done = true; }
                }

                if (!is_reply_to_us) continue;

                const double rtt_ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();

                hop.probes[static_cast<size_t>(p)].responded = true;
                hop.probes[static_cast<size_t>(p)].rtt_ms    = rtt_ms;
                hop.unreachable = hop.unreachable || unreachable;

                char ipstr[INET6_ADDRSTRLEN];
                ::inet_ntop(AF_INET6, &from.sin6_addr, ipstr, sizeof(ipstr));
                if (hop.ip.empty()) hop.ip = ipstr;

                if (hop.mpls_labels.empty()) {
                    auto labels = parse_mpls_extensions(icmp_payload, icmp_payload_len, icmp_len_field);
                    if (!labels.empty()) hop.mpls_labels = std::move(labels);
                }
                break;
            }
        }

        if (!hop.ip.empty()) {
            const bool link_local = hop.ip.rfind("fe80", 0) == 0;
            enrich_hop(hop, opts, link_local);
            if (hop.ip == target_ip6) { hop.is_destination = true; done = true; }
        }

        hops.push_back(std::move(hop));
    }

    return hops;
}

// ─── Output ──────────────────────────────────────────────────────────────
//
// Column widths are computed against the *plain* (uncolored) text, then
// the colored version is printed followed by manual space padding —
// padding a std::setw() field that already contains ANSI escape codes
// counts the escape bytes as visible width and silently breaks alignment,
// so the two must stay separate.
void print_traceroute_results(const std::string& target_display,
                               const std::vector<TracerouteHop>& hops,
                               int max_hops_requested)
{
    constexpr int ADDR_COL_WIDTH = 38;
    const int probes_per_hop = hops.empty() ? 0 : static_cast<int>(hops.front().probes.size());

    std::cout << "\n" << trcolor::bold << "Traceroute to " << target_display
               << trcolor::reset << trcolor::dim
               << "  (max " << max_hops_requested << " hops, "
               << probes_per_hop << " probes/hop)" << trcolor::reset << "\n\n";

    for (const auto& hop : hops) {
        std::cout << " " << trcolor::yellow << std::right << std::setw(2) << hop.ttl
                   << trcolor::reset << "  ";

        if (hop.ip.empty()) {
            std::cout << trcolor::dim << std::left << std::setw(ADDR_COL_WIDTH)
                       << "* * *  (no response)" << trcolor::reset << "\n";
            continue;
        }

        // Plain label first — used only to compute padding width.
        std::string addr_plain = hop.ip;
        if (!hop.hostname.empty() && hop.hostname != hop.ip)
            addr_plain += " (" + hop.hostname + ")";

        std::cout << trcolor::green << hop.ip << trcolor::reset;
        if (!hop.hostname.empty() && hop.hostname != hop.ip) {
            // Domain name printed in yellow, distinct from the IP in green.
            std::cout << " (" << trcolor::yellow << hop.hostname << trcolor::reset << ")";
        }
        const int pad = ADDR_COL_WIDTH - static_cast<int>(addr_plain.size());
        if (pad > 0) std::cout << std::string(static_cast<size_t>(pad), ' ');
        std::cout << " ";

        for (const auto& probe : hop.probes) {
            if (probe.responded) {
                std::cout << std::right << std::setw(7) << std::fixed
                           << std::setprecision(2) << probe.rtt_ms << " ms  ";
            } else {
                std::cout << trcolor::dim << std::right << std::setw(7) << "*"
                           << trcolor::reset << "     ";
            }
        }

        if (hop.is_destination) std::cout << trcolor::cyan << " [destination]" << trcolor::reset;
        if (hop.unreachable)    std::cout << trcolor::red   << " [unreachable]" << trcolor::reset;
        std::cout << "\n";

        if (!hop.mpls_labels.empty()) {
            std::cout << "      " << trcolor::dim << "\u2514\u2500 MPLS" << trcolor::reset << "  ";
            bool first = true;
            for (const auto& lbl : hop.mpls_labels) {
                if (!first) std::cout << "  |  ";
                first = false;
                std::cout << "label=" << lbl.label
                           << " exp=" << static_cast<int>(lbl.exp) << "(CoS)"
                           << " ttl=" << static_cast<int>(lbl.ttl)
                           << (lbl.bos ? " bos" : "");
            }
            std::cout << "\n";
        }

        if (hop.geo.resolved) {
            std::string loc = hop.geo.city;
            if (!hop.geo.region.empty())  loc += (loc.empty() ? "" : ", ") + hop.geo.region;
            if (!hop.geo.country.empty()) loc += (loc.empty() ? "" : ", ") + hop.geo.country;

            std::cout << "      " << trcolor::dim << "\u2514\u2500" << trcolor::reset << " "
                       << (hop.geo.asn.empty() ? "AS n/a" : hop.geo.asn)
                       << "  " << (hop.geo.isp.empty() ? hop.geo.org : hop.geo.isp);
            if (!loc.empty()) {
                std::cout << "  \u2014  " << loc << "  (" << std::fixed << std::setprecision(4)
                           << hop.geo.lat << ", " << hop.geo.lon << ")";
            }
            std::cout << "\n";
        }
    }
    std::cout << "\n";
}
