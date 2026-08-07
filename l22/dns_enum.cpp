#include "dns_enum.hpp"
#include "handler.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <random>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <thread>
#include <iomanip>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string green   = "\033[32m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string white   = "\033[97m";
    const std::string red     = "\033[91m";
    const std::string dim     = "\033[2m";    
    const std::string cyan    = "\033[36m";    
    const std::string bright_cyan = "\033[96m";
    
}

namespace {

#pragma pack(push, 1)
struct DnsHdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

void encode_name(const std::string& host, std::vector<uint8_t>& out) {
    size_t start = 0;
    std::string h = host;
    if (!h.empty() && h.back() == '.') h.pop_back();
    while (start < h.size()) {
        size_t dot = h.find('.', start);
        size_t len = (dot == std::string::npos) ? h.size() - start : dot - start;
        if (len > 63) len = 63;
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) out.push_back(static_cast<uint8_t>(h[start + i]));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
}

std::vector<uint8_t> build_query(uint16_t txn_id, const std::string& host, DnsRRType qtype) {
    std::vector<uint8_t> pkt;
    pkt.reserve(host.size() + 32);
    DnsHdr hdr{};
    hdr.id = htons(txn_id);
    hdr.flags = htons(0x0100); // recursion desired; AXFR caller clears this
    hdr.qdcount = htons(1);
    const auto* hp = reinterpret_cast<const uint8_t*>(&hdr);
    pkt.insert(pkt.end(), hp, hp + sizeof(hdr));
    encode_name(host, pkt);
    uint16_t qt = htons(static_cast<uint16_t>(qtype));
    uint16_t qc = htons(1);
    const auto* qtp = reinterpret_cast<const uint8_t*>(&qt);
    const auto* qcp = reinterpret_cast<const uint8_t*>(&qc);
    pkt.insert(pkt.end(), qtp, qtp + 2);
    pkt.insert(pkt.end(), qcp, qcp + 2);
    return pkt;
}

size_t skip_name(const uint8_t* buf, size_t len, size_t pos) {
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) return pos + 1;
        if ((b & 0xC0) == 0xC0) return pos + 2;
        pos += 1 + b;
    }
    return pos;
}

size_t decode_name(const uint8_t* buf, size_t len, size_t pos, std::string& out) {
    out.clear();
    size_t original_pos = pos;
    bool jumped = false;
    size_t hops = 0;
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) { pos += 1; break; }
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return original_pos;
            size_t target = (static_cast<size_t>(b & 0x3F) << 8) | buf[pos + 1];
            if (!jumped) { original_pos = pos + 2; jumped = true; }
            pos = target;
            if (++hops > 128) return original_pos;
            continue;
        }
        size_t label_len = b;
        pos += 1;
        if (pos + label_len > len) return original_pos;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(buf + pos), label_len);
        pos += label_len;
    }
    return jumped ? original_pos : pos;
}

std::string render_rdata(const uint8_t* buf, size_t len, size_t rpos, uint16_t rtype, uint16_t rdlen) {
    switch (rtype) {
        case 1: { // A
            if (rdlen != 4) return "";
            char out[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, buf + rpos, out, sizeof(out));
            return out;
        }
        case 28: { // AAAA
            if (rdlen != 16) return "";
            char out[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, buf + rpos, out, sizeof(out));
            return out;
        }
        case 2: case 5: case 12: { // NS, CNAME, PTR
            std::string name;
            decode_name(buf, len, rpos, name);
            return name;
        }
        case 15: { // MX: preference(2) + exchange name
            if (rdlen < 3) return "";
            uint16_t pref; memcpy(&pref, buf + rpos, 2); pref = ntohs(pref);
            std::string name;
            decode_name(buf, len, rpos + 2, name);
            return std::to_string(pref) + " " + name;
        }
        case 16: { // TXT: one or more length-prefixed strings, concatenated
            std::string out;
            size_t p = rpos, end = rpos + rdlen;
            while (p < end && p < len) {
                uint8_t slen = buf[p++];
                if (p + slen > len) break;
                out.append(reinterpret_cast<const char*>(buf + p), slen);
                p += slen;
            }
            return out;
        }
        case 6: { // SOA: mname, rname, serial, refresh, retry, expire, minimum
            std::string mname, rname;
            size_t p = decode_name(buf, len, rpos, mname);
            p = decode_name(buf, len, p, rname);
            if (p + 20 > len) return mname + " " + rname;
            uint32_t serial, refresh, retry, expire, minimum;
            memcpy(&serial, buf + p, 4);  serial  = ntohl(serial);  p += 4;
            memcpy(&refresh, buf + p, 4); refresh = ntohl(refresh); p += 4;
            memcpy(&retry, buf + p, 4);   retry   = ntohl(retry);   p += 4;
            memcpy(&expire, buf + p, 4);  expire  = ntohl(expire);  p += 4;
            memcpy(&minimum, buf + p, 4); minimum = ntohl(minimum);
            std::ostringstream ss;
            ss << mname << " " << rname << " " << serial << " " << refresh
               << " " << retry << " " << expire << " " << minimum;
            return ss.str();
        }
        case 33: { // SRV: priority(2) weight(2) port(2) target
            if (rdlen < 7) return "";
            uint16_t prio, weight, port;
            memcpy(&prio, buf + rpos, 2);   prio = ntohs(prio);
            memcpy(&weight, buf + rpos + 2, 2); weight = ntohs(weight);
            memcpy(&port, buf + rpos + 4, 2);   port = ntohs(port);
            std::string target;
            decode_name(buf, len, rpos + 6, target);
            std::ostringstream ss;
            ss << prio << " " << weight << " " << port << " " << target;
            return ss.str();
        }
        case 257: { // CAA: flags(1) tag_len(1) tag value
            if (rdlen < 2) return "";
            uint8_t flags = buf[rpos];
            uint8_t tag_len = buf[rpos + 1];
            if (2u + tag_len > rdlen) return "";
            std::string tag(reinterpret_cast<const char*>(buf + rpos + 2), tag_len);
            size_t val_off = rpos + 2 + tag_len;
            size_t val_len = rdlen - 2 - tag_len;
            std::string value(reinterpret_cast<const char*>(buf + val_off), val_len);
            std::ostringstream ss;
            ss << (int)flags << " " << tag << " \"" << value << "\"";
            return ss.str();
        }
        case 48: // DNSKEY
            return "<dnskey present, " + std::to_string(rdlen) + "B>";
        case 43: // DS
            return "<ds present, " + std::to_string(rdlen) + "B>";
        case 46: // RRSIG
            return "<rrsig present>";
        default:
            return "<type " + std::to_string(rtype) + ", " + std::to_string(rdlen) + "B>";
    }
}

// Parses every RR in the answer(+optionally authority/additional) section(s)
// of a raw DNS message into DnsRecord entries.
void parse_message(const uint8_t* buf, size_t len, std::vector<DnsRecord>& out,
                    const std::string& source_tag, bool include_authority = false) {
    if (len < sizeof(DnsHdr)) return;
    DnsHdr hdr{};
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t qd = ntohs(hdr.qdcount);
    uint16_t an = ntohs(hdr.ancount);
    uint16_t ns = ntohs(hdr.nscount);

    size_t pos = sizeof(DnsHdr);
    for (uint16_t i = 0; i < qd; ++i) {
        pos = skip_name(buf, len, pos);
        pos += 4;
        if (pos > len) return;
    }

    uint16_t total = an + (include_authority ? ns : 0);
    uint16_t seen_an = 0;
    for (uint16_t i = 0; i < an + ns; ++i) {
        if (i >= an && !include_authority) break;
        std::string owner;
        pos = decode_name(buf, len, pos, owner);
        if (pos + 10 > len) return;
        uint16_t rtype, rclass, rdlen;
        uint32_t ttl;
        memcpy(&rtype, buf + pos, 2);  rtype = ntohs(rtype);  pos += 2;
        memcpy(&rclass, buf + pos, 2); rclass = ntohs(rclass); pos += 2;
        memcpy(&ttl, buf + pos, 4);    ttl = ntohl(ttl);       pos += 4;
        memcpy(&rdlen, buf + pos, 2);  rdlen = ntohs(rdlen);   pos += 2;
        if (pos + rdlen > len) return;

        if (rclass == 1) {
            DnsRecord rec;
            rec.type = static_cast<DnsRRType>(rtype);
            rec.name = owner;
            rec.ttl = ttl;
            rec.value = render_rdata(buf, len, pos, rtype, rdlen);
            rec.source = source_tag;
            out.push_back(std::move(rec));
        }
        pos += rdlen;
        if (i < an) ++seen_an;
    }
    (void)total; (void)seen_an;
}

int make_udp_socket(int family) {
    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    return fd;
}

bool send_to_server(int fd, int family, const std::string& server,
                     const std::vector<uint8_t>& pkt, uint16_t port = 53) {
    sockaddr_storage ss{};
    socklen_t slen;
    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        if (inet_pton(AF_INET, server.c_str(), &a->sin_addr) != 1) return false;
        slen = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        if (inet_pton(AF_INET6, server.c_str(), &a->sin6_addr) != 1) return false;
        slen = sizeof(*a);
    }
    return sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&ss), slen) >= 0;
}

int family_of(const std::string& ip) {
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) return AF_INET6;
    return -1;
}

// System resolvers, read once, used when the user hasn't set
// --dns-servers/--dns-servers-tls.
std::vector<std::string> system_resolvers() {
    std::vector<std::string> out;
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (f && std::getline(f, line)) {
        if (line.rfind("nameserver", 0) == 0) {
            std::istringstream ss(line);
            std::string tok, ip;
            ss >> tok >> ip;
            if (!ip.empty()) out.push_back(ip);
        }
    }
    if (out.empty()) { out.push_back("1.1.1.1"); out.push_back("8.8.8.8"); }
    return out;
}

std::vector<std::string> active_server_list() {
    if (!g_dns_servers.empty()) return g_dns_servers;
    // Note: g_dns_tls_servers (DoT) isn't reused here — --dns-enum's generic
    // multi-type queries go out over UDP/TCP:53 in plaintext by design, same
    // as every other DNS enumeration tool; DoT is left to normal resolution.
    return system_resolvers();
}

} // namespace

// -----------------------------------------------------------------------
// Public generic query (UDP, TCP fallback on truncation, retries+timeout)
// -----------------------------------------------------------------------

bool dns_query_generic(const std::string& qname, DnsRRType qtype,
                        const std::vector<std::string>& servers,
                        int timeout_ms, int retries,
                        std::vector<DnsRecord>& out_records,
                        std::string* used_server) {
    if (servers.empty()) return false;
    std::mt19937 rng(std::random_device{}());

    for (int attempt = 0; attempt <= retries; ++attempt) {
        for (const auto& srv : servers) {
            int fam = family_of(srv);
            if (fam < 0) continue;
            int fd = make_udp_socket(fam);
            if (fd < 0) continue;

            uint16_t txn = static_cast<uint16_t>(rng());
            auto pkt = build_query(txn, qname, qtype);
            if (!send_to_server(fd, fam, srv, pkt)) { close(fd); continue; }

            pollfd pfd{fd, POLLIN, 0};
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr <= 0) { close(fd); continue; }

            uint8_t buf[4096];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n < static_cast<ssize_t>(sizeof(DnsHdr))) continue;

            DnsHdr hdr{};
            memcpy(&hdr, buf, sizeof(hdr));
            if (ntohs(hdr.id) != txn) continue; // stray/spoofed reply
            bool truncated = (ntohs(hdr.flags) & 0x0200) != 0;

            std::vector<DnsRecord> recs;
            parse_message(buf, static_cast<size_t>(n), recs, "active:" + srv);

            if (truncated) {
                // Retry same query over TCP for the full answer.
                int tfd = socket(fam, SOCK_STREAM, 0);
                if (tfd >= 0) {
                    sockaddr_storage ss{}; socklen_t slen;
                    if (fam == AF_INET) {
                        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
                        a->sin_family = AF_INET; a->sin_port = htons(53);
                        inet_pton(AF_INET, srv.c_str(), &a->sin_addr);
                        slen = sizeof(*a);
                    } else {
                        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
                        a->sin6_family = AF_INET6; a->sin6_port = htons(53);
                        inet_pton(AF_INET6, srv.c_str(), &a->sin6_addr);
                        slen = sizeof(*a);
                    }
                    if (connect(tfd, reinterpret_cast<sockaddr*>(&ss), slen) == 0) {
                        uint16_t plen = htons(static_cast<uint16_t>(pkt.size()));
                        std::vector<uint8_t> framed;
                        framed.insert(framed.end(), reinterpret_cast<uint8_t*>(&plen),
                                      reinterpret_cast<uint8_t*>(&plen) + 2);
                        framed.insert(framed.end(), pkt.begin(), pkt.end());
                        if (send(tfd, framed.data(), framed.size(), 0) > 0) {
                            uint8_t lenbuf[2];
                            if (recv(tfd, lenbuf, 2, MSG_WAITALL) == 2) {
                                uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
                                std::vector<uint8_t> rbuf(rlen);
                                if (recv(tfd, rbuf.data(), rlen, MSG_WAITALL) == rlen) {
                                    recs.clear();
                                    parse_message(rbuf.data(), rbuf.size(), recs, "active-tcp:" + srv);
                                }
                            }
                        }
                    }
                    close(tfd);
                }
            }

            if (!recs.empty() || (ntohs(hdr.flags) & 0x000F) == 3 /* NXDOMAIN, definitive */) {
                out_records = std::move(recs);
                if (used_server) *used_server = srv;
                return true;
            }
        }
    }
    return false;
}

// =======================================================================
// Section 2: AXFR (zone transfer) attempts
// =======================================================================

namespace {

ZoneTransferAttempt try_axfr(const std::string& domain, const std::string& ns_host,
                              const std::string& ns_ip, int timeout_ms,
                              std::vector<DnsRecord>& out_records) {
    ZoneTransferAttempt att;
    att.ns_host = ns_host;
    att.ns_ip = ns_ip;

    int fam = family_of(ns_ip);
    if (fam < 0) { att.error = "unresolvable NS"; return att; }

    int fd = socket(fam, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { att.error = "socket() failed"; return att; }

    sockaddr_storage ss{}; socklen_t slen;
    if (fam == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET; a->sin_port = htons(53);
        inet_pton(AF_INET, ns_ip.c_str(), &a->sin_addr);
        slen = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6; a->sin6_port = htons(53);
        inet_pton(AF_INET6, ns_ip.c_str(), &a->sin6_addr);
        slen = sizeof(*a);
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&ss), slen);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); att.error = "connect failed"; return att; }
    pollfd wfd{fd, POLLOUT, 0};
    if (poll(&wfd, 1, timeout_ms) <= 0) { close(fd); att.error = "connect timeout"; return att; }
    int soerr = 0; socklen_t soerrlen = sizeof(soerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerrlen);
    if (soerr != 0) { close(fd); att.error = "connect refused/error"; return att; }

    uint16_t txn = static_cast<uint16_t>(std::random_device{}());
    auto pkt = build_query(txn, domain, DnsRRType::AXFR);
    uint16_t plen = htons(static_cast<uint16_t>(pkt.size()));
    std::vector<uint8_t> framed;
    framed.insert(framed.end(), reinterpret_cast<uint8_t*>(&plen), reinterpret_cast<uint8_t*>(&plen) + 2);
    framed.insert(framed.end(), pkt.begin(), pkt.end());
    if (send(fd, framed.data(), framed.size(), 0) < 0) { close(fd); att.error = "send failed"; return att; }

    size_t soa_seen = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms * 3);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int remaining_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count());
        if (remaining_ms <= 0) break;
        int pr = poll(&pfd, 1, remaining_ms);
        if (pr <= 0) break;

        uint8_t lenbuf[2];
        ssize_t got = recv(fd, lenbuf, 2, MSG_WAITALL);
        if (got != 2) break;
        uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
        if (rlen == 0) break;
        std::vector<uint8_t> rbuf(rlen);
        if (recv(fd, rbuf.data(), rlen, MSG_WAITALL) != rlen) break;

        std::vector<DnsRecord> recs;
        parse_message(rbuf.data(), rbuf.size(), recs, "axfr:" + ns_host);
        if (recs.empty()) break; // REFUSED / NOTAUTH etc. -> empty answer section
        for (auto& r : recs) {
            if (r.type == DnsRRType::SOA) ++soa_seen;
            out_records.push_back(r);
        }
        att.succeeded = true;
        if (soa_seen >= 2) break; // AXFR framing: starts and ends with SOA
    }
    close(fd);

    if (att.succeeded) {
        att.records_pulled = out_records.size();
    } else if (att.error.empty()) {
        att.error = "refused or empty zone";
    }
    return att;
}

} // namespace

// =======================================================================
// Section 3: subdomain brute force (concurrent, non-blocking UDP pool)
// =======================================================================

namespace {

const std::vector<std::string>& builtin_subdomain_wordlist() {
    static const std::vector<std::string> list = {
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4",
        "webdisk","autodiscover","autoconfig","m","imap","test","ns","blog","pop3","dev",
        "www2","admin","forum","news","vpn","ns5","mail2","new","mysql","old","www1",
        "beta","dns","dns1","dns2","staging","shop","sql","secure","demo","cp","calendar",
        "wiki","web","media","email","images","img","static","cdn","api","api-dev","api-staging",
        "app","apps","mobile","gateway","gw","portal","auth","sso","login","id","idp",
        "dashboard","console","status","status-page","monitor","monitoring","grafana","kibana",
        "prometheus","jenkins","ci","git","gitlab","github","svn","repo","docker","registry",
        "k8s","kube","kubernetes","internal","intranet","corp","extranet","partner","partners",
        "vpn1","vpn2","remote","office","proxy","cache","backup","backups","db","db1","db2",
        "redis","elastic","es","search","files","file","upload","uploads","download","downloads",
        "assets","cdn1","cdn2","edge","origin","direct","legacy","archive","docs","support",
        "help","kb","tickets","chat","irc","voip","sip","meet","zoom","stream","video","tv",
        "ns0","mx","mx1","mx2","smtp1","smtp2","relay","alerts","exchange","owa","lync","skype",
        "sharepoint","confluence","jira","bugzilla","wordpress","cms","preprod","pre-prod",
        "sandbox","uat","qa","test1","test2","dev1","dev2","local","lab","labs","research",
    };
    return list;
}

struct BruteJob {
    std::string fqdn;
    DnsRRType type;
};

// Fires up to `concurrency` UDP queries in flight at once using poll(),
// mirroring the non-blocking + poll pattern shiv already uses for
// resolve_via_custom_dns in handler.cpp, generalized to A+AAAA and a
// wordlist instead of a single host.
void brute_force_resolve(const std::string& domain,
                          const std::vector<std::string>& words,
                          const std::vector<std::string>& servers,
                          int timeout_ms, int concurrency,
                          std::unordered_map<std::string, DiscoveredHost>& hosts) {
    if (servers.empty()) return;

    struct InFlight {
        int fd;
        std::string fqdn;
        uint16_t txn;
        DnsRRType type;
        std::string server;
    };

    std::vector<BruteJob> jobs;
    jobs.reserve(words.size() * 2);
    for (const auto& w : words) {
        std::string fqdn = w + "." + domain;
        jobs.push_back({fqdn, DnsRRType::A});
        jobs.push_back({fqdn, DnsRRType::AAAA});
    }

    size_t next_job = 0;
    std::vector<InFlight> inflight;
    inflight.reserve(concurrency);
    std::mt19937 rng(std::random_device{}());
    size_t server_rr = 0;

    auto launch_one = [&]() -> bool {
        if (next_job >= jobs.size()) return false;
        const auto& job = jobs[next_job++];
        const auto& srv = servers[server_rr++ % servers.size()];
        int fam = family_of(srv);
        if (fam < 0) return true; // skip, but keep pumping
        int fd = make_udp_socket(fam);
        if (fd < 0) return true;
        uint16_t txn = static_cast<uint16_t>(rng());
        auto pkt = build_query(txn, job.fqdn, job.type);
        if (!send_to_server(fd, fam, srv, pkt)) { close(fd); return true; }
        inflight.push_back({fd, job.fqdn, txn, job.type, srv});
        return true;
    };

    while (static_cast<int>(inflight.size()) < concurrency && launch_one()) {}

    auto batch_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (!inflight.empty()) {
        std::vector<pollfd> pfds;
        pfds.reserve(inflight.size());
        for (auto& f : inflight) pfds.push_back({f.fd, POLLIN, 0});

        int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            batch_deadline - std::chrono::steady_clock::now()).count());
        if (remaining < 0) remaining = 0;
        int pr = poll(pfds.data(), pfds.size(), std::min(remaining, 250));

        std::vector<size_t> done;
        if (pr > 0) {
            for (size_t i = 0; i < pfds.size(); ++i) {
                if (!(pfds[i].revents & POLLIN)) continue;
                uint8_t buf[4096];
                ssize_t n = recv(inflight[i].fd, buf, sizeof(buf), 0);
                if (n >= static_cast<ssize_t>(sizeof(DnsHdr))) {
                    std::vector<DnsRecord> recs;
                    parse_message(buf, static_cast<size_t>(n), recs,
                                  "active:" + inflight[i].server);
                    if (!recs.empty()) {
                        auto& host = hosts[inflight[i].fqdn];
                        host.hostname = inflight[i].fqdn;
                        host.sources.insert(DiscoverySource::ActiveBruteForce);
                        for (auto& r : recs)
                            if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA)
                                host.ips.insert(r.value);
                    }
                }
                done.push_back(i);
            }
        }

        if (std::chrono::steady_clock::now() >= batch_deadline) {
            // Drop anything still outstanding for this pass; brute force is
            // best-effort, not a guarantee every name gets a full retry.
            for (size_t i = 0; i < inflight.size(); ++i) done.push_back(i);
            std::sort(done.begin(), done.end());
            done.erase(std::unique(done.begin(), done.end()), done.end());
        }

        // Remove completed/expired, back to front so indices stay valid.
        std::sort(done.rbegin(), done.rend());
        for (size_t idx : done) {
            close(inflight[idx].fd);
            inflight.erase(inflight.begin() + idx);
            launch_one();
        }

        if (pr <= 0 && inflight.size() == pfds.size()) {
            // Nothing arrived and nothing was reaped (e.g. remaining==0 edge
            // case) — reset the deadline window for the newly-launched batch.
            batch_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        }
    }
}

} // namespace

// =======================================================================
// Section 4: email-security + DNSSEC presence
// =======================================================================

namespace {

const std::vector<std::string>& builtin_dkim_selectors() {
    static const std::vector<std::string> list = {
        "default","google","selector1","selector2","k1","k2","dkim","mail","smtp","s1","s2",
        "mandrill","mailo","mx","zoho","sendgrid","amazonses","pm","protonmail","fm1","fm2",
        "everlytickey1","everlytickey2","mailjet","dkim1","dkim2",
    };
    return list;
}

std::string first_txt(const std::vector<DnsRecord>& recs) {
    for (const auto& r : recs) if (r.type == DnsRRType::TXT) return r.value;
    return "";
}

void collect_email_security(const std::string& domain, const std::vector<std::string>& servers,
                             int timeout_ms, int retries,
                             const std::vector<std::string>& extra_selectors,
                             EmailSecurityPosture& out) {
    std::vector<DnsRecord> recs;

    // SPF lives in a plain TXT at the apex, identified by the "v=spf1" prefix.
    if (dns_query_generic(domain, DnsRRType::TXT, servers, timeout_ms, retries, recs)) {
        for (auto& r : recs) {
            if (r.type == DnsRRType::TXT && r.value.rfind("v=spf1", 0) == 0) {
                out.has_spf = true; out.spf_record = r.value; break;
            }
        }
    }

    recs.clear();
    if (dns_query_generic("_dmarc." + domain, DnsRRType::TXT, servers, timeout_ms, retries, recs)) {
        std::string v = first_txt(recs);
        if (!v.empty()) { out.has_dmarc = true; out.dmarc_record = v; }
    }

    recs.clear();
    if (dns_query_generic("default._bimi." + domain, DnsRRType::TXT, servers, timeout_ms, retries, recs)) {
        std::string v = first_txt(recs);
        if (!v.empty()) { out.has_bimi = true; out.bimi_record = v; }
    }

    recs.clear();
    if (dns_query_generic("_mta-sts." + domain, DnsRRType::TXT, servers, timeout_ms, retries, recs)) {
        std::string v = first_txt(recs);
        if (!v.empty()) { out.has_mta_sts_dns = true; out.mta_sts_dns_record = v; }
    }

    recs.clear();
    if (dns_query_generic("_smtp._tls." + domain, DnsRRType::TXT, servers, timeout_ms, retries, recs)) {
        std::string v = first_txt(recs);
        if (!v.empty()) { out.has_tls_rpt = true; out.tls_rpt_record = v; }
    }

    recs.clear();
    if (dns_query_generic(domain, DnsRRType::MX, servers, timeout_ms, retries, recs)) {
        for (auto& r : recs) if (r.type == DnsRRType::MX) out.mx_hosts.push_back(r.value);
    }

    std::vector<std::string> selectors = builtin_dkim_selectors();
    selectors.insert(selectors.end(), extra_selectors.begin(), extra_selectors.end());
    for (const auto& sel : selectors) {
        recs.clear();
        if (dns_query_generic(sel + "._domainkey." + domain, DnsRRType::TXT, servers,
                               timeout_ms, /*retries=*/0, recs)) {
            std::string v = first_txt(recs);
            if (!v.empty() && v.find("v=DKIM1") != std::string::npos)
                out.dkim_selectors_found.emplace_back(sel, v);
        }
    }
}

void collect_dnssec(const std::string& domain, const std::vector<std::string>& servers,
                     int timeout_ms, int retries, DnssecPosture& out) {
    std::vector<DnsRecord> recs;
    if (dns_query_generic(domain, DnsRRType::DNSKEY, servers, timeout_ms, retries, recs)) {
        for (auto& r : recs) if (r.type == DnsRRType::DNSKEY) { out.dnskey_present = true; ++out.dnskey_count; }
    }
    recs.clear();
    if (dns_query_generic(domain, DnsRRType::RRSIG, servers, timeout_ms, retries, recs)) {
        for (auto& r : recs) if (r.type == DnsRRType::RRSIG) { out.rrsig_seen = true; break; }
    }
    // DS lives in the *parent* zone; querying it against the domain's own
    // servers only tells us whether they happen to echo it back (rare) — a
    // correct check would walk up to the parent's NS, which is out of scope
    // for a single-pass sweep. Left false unless explicitly found here.
    recs.clear();
    if (dns_query_generic(domain, DnsRRType::DS, servers, timeout_ms, retries, recs)) {
        for (auto& r : recs) if (r.type == DnsRRType::DS) { out.ds_present_at_parent = true; break; }
    }
}

} // namespace

// =======================================================================
// Section 5: passive enumeration (crt.sh, Wayback CDX, RDAP, Team Cymru)
// =======================================================================

namespace {

size_t curl_write_cb(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t n = size * nmemb;
    if (size != 0 && n / size != nmemb) return 0;
    try { s->append(static_cast<char*>(contents), n); } catch (...) { return 0; }
    return n;
}

bool http_get(const std::string& url, std::string& out, long timeout_ms) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    out.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "shiv-dns-enum/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK && code >= 200 && code < 400;
}

// crt.sh: certificate-transparency-derived subdomains + historical names.
// Public, keyless, JSON output.
void passive_crtsh(const std::string& domain, int timeout_ms,
                    std::unordered_map<std::string, DiscoveredHost>& hosts) {
    std::string url = "https://crt.sh/?q=%25." + domain + "&output=json";
    std::string body;
    if (!http_get(url, body, timeout_ms)) return;
    try {
        json j = json::parse(body, nullptr, false);
        if (j.is_discarded() || !j.is_array()) return;
        for (auto& entry : j) {
            if (!entry.contains("name_value")) continue;
            std::string names = entry["name_value"].get<std::string>();
            std::istringstream ss(names);
            std::string line;
            while (std::getline(ss, line)) {
                if (line.empty()) continue;
                if (line[0] == '*') line = line.substr(2); // strip "*."
                std::transform(line.begin(), line.end(), line.begin(), ::tolower);
                if (line.size() < domain.size()) continue;
                if (line.compare(line.size() - domain.size(), domain.size(), domain) != 0) continue;
                auto& h = hosts[line];
                h.hostname = line;
                h.sources.insert(DiscoverySource::PassiveCertLog);
            }
        }
    } catch (...) { /* best-effort */ }
}

// Wayback Machine CDX API: URLs ever archived under *.domain — surfaces
// old staging/QA subdomains long since taken out of active DNS.
void passive_wayback(const std::string& domain, int timeout_ms, size_t sample_cap,
                      std::unordered_map<std::string, DiscoveredHost>& hosts,
                      std::vector<std::string>& sample_out) {
    std::string url = "http://web.archive.org/cdx/search/cdx?url=*." + domain +
                       "&output=text&fl=original&collapse=urlkey&limit=5000";
    std::string body;
    if (!http_get(url, body, timeout_ms)) return;

    static const std::regex host_re(R"(^[a-zA-Z]+://([^/:\s]+))");
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        std::smatch m;
        if (!std::regex_search(line, m, host_re)) continue;
        std::string h = m[1].str();
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        if (h.size() < domain.size()) continue;
        if (h.compare(h.size() - domain.size(), domain.size(), domain) != 0) continue;

        auto& rec = hosts[h];
        rec.hostname = h;
        rec.sources.insert(DiscoverySource::PassiveWayback);
        if (sample_out.size() < sample_cap) sample_out.push_back(line);
    }
}

// RDAP (RFC 7482/9083): modern, structured, keyless replacement for raw
// WHOIS text-scraping. rdap.org is a public bootstrap redirector to the
// authoritative registry/registrar RDAP server.
WhoisRdapInfo passive_rdap_domain(const std::string& domain, int timeout_ms) {
    WhoisRdapInfo info;
    std::string url = "https://rdap.org/domain/" + domain;
    std::string body;
    if (!http_get(url, body, timeout_ms)) return info;
    try {
        json j = json::parse(body, nullptr, false);
        if (j.is_discarded()) return info;
        info.found = true;
        info.raw_source_url = url;
        if (j.contains("events") && j["events"].is_array()) {
            for (auto& ev : j["events"]) {
                std::string action = ev.value("eventAction", "");
                std::string date = ev.value("eventDate", "");
                if (action == "registration") info.created = date;
                else if (action == "last changed") info.updated = date;
                else if (action == "expiration") info.expires = date;
            }
        }
        if (j.contains("status") && j["status"].is_array())
            for (auto& s : j["status"]) info.statuses.push_back(s.get<std::string>());
        if (j.contains("nameservers") && j["nameservers"].is_array())
            for (auto& ns : j["nameservers"])
                if (ns.contains("ldhName")) info.nameservers.push_back(ns["ldhName"].get<std::string>());
        if (j.contains("entities") && j["entities"].is_array()) {
            for (auto& e : j["entities"]) {
                if (!e.contains("roles")) continue;
                bool is_registrar = false;
                for (auto& r : e["roles"]) if (r.get<std::string>() == "registrar") is_registrar = true;
                if (!is_registrar) continue;
                if (e.contains("vcardArray") && e["vcardArray"].is_array() && e["vcardArray"].size() > 1) {
                    for (auto& field : e["vcardArray"][1]) {
                        if (field.is_array() && field.size() > 3 && field[0] == "fn")
                            info.registrar = field[3].get<std::string>();
                    }
                }
            }
        }
    } catch (...) { /* best-effort */ }
    return info;
}

// Team Cymru's whois "bulk" protocol: plaintext, single TCP round trip,
// gives ASN/BGP-prefix/country/allocation date for an IP — no HTTP, no key.
AsnInfo passive_asn_lookup(const std::string& ip) {
    AsnInfo info;
    info.ip = ip;
    int fam = family_of(ip);
    if (fam < 0) return info;

    int fd = socket(fam, SOCK_STREAM, 0);
    if (fd < 0) return info;

    sockaddr_storage ss{}; socklen_t slen;
    // whois.cymru.com
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = fam;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("whois.cymru.com", "43", &hints, &res) != 0 || !res) { close(fd); return info; }
    memcpy(&ss, res->ai_addr, res->ai_addrlen);
    slen = res->ai_addrlen;
    freeaddrinfo(res);

    struct timeval tv{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, reinterpret_cast<sockaddr*>(&ss), slen) != 0) { close(fd); return info; }
    std::string query = "begin\nverbose\n" + ip + "\nend\n";
    if (send(fd, query.data(), query.size(), 0) < 0) { close(fd); return info; }

    std::string resp;
    char buf[2048];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) resp.append(buf, n);
    close(fd);

    // Format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    std::istringstream ss2(resp);
    std::string line;
    while (std::getline(ss2, line)) {
        if (line.rfind("Bulk mode", 0) == 0 || line.find('|') == std::string::npos) continue;
        std::vector<std::string> fields;
        std::stringstream fs(line);
        std::string field;
        while (std::getline(fs, field, '|')) {
            size_t b = field.find_first_not_of(' ');
            size_t e = field.find_last_not_of(' ');
            fields.push_back(b == std::string::npos ? "" : field.substr(b, e - b + 1));
        }
        if (fields.size() >= 7) {
            info.asn = fields[0]; info.prefix = fields[2]; info.country = fields[3];
            info.registry = fields[4]; info.allocated = fields[5]; info.as_name = fields[6];
        }
        break; // first data line only (header already skipped)
    }
    return info;
}

} // namespace

// =======================================================================
// Section 6: orchestration
// =======================================================================

DnsEnumResult run_dns_enum(const std::string& domain, const DnsEnumOptions& opts) {
    DnsEnumResult result;
    result.domain = domain;
    auto servers = active_server_list();

    if (opts.do_active) {
        auto t0 = std::chrono::steady_clock::now();

        // 1. Apex record sweep.
        for (DnsRRType t : {DnsRRType::A, DnsRRType::AAAA, DnsRRType::NS, DnsRRType::MX,
                             DnsRRType::TXT, DnsRRType::SOA, DnsRRType::CAA}) {
            std::vector<DnsRecord> recs;
            if (dns_query_generic(domain, t, servers, opts.timeout_ms, opts.retries, recs))
                result.records.insert(result.records.end(), recs.begin(), recs.end());
        }

        // 2. Wildcard probe — random label that (almost certainly) doesn't exist.
        {
            std::mt19937 rng(std::random_device{}());
            std::string probe = "shiv-wc-" + std::to_string(rng()) + "." + domain;
            std::vector<DnsRecord> recs;
            if (dns_query_generic(probe, DnsRRType::A, servers, opts.timeout_ms, opts.retries, recs)) {
                for (auto& r : recs) {
                    if (r.type == DnsRRType::A) {
                        result.wildcard_dns = true;
                        result.wildcard_ip_sample = r.value;
                        break;
                    }
                }
            }
        }

        // 3. Zone transfer attempts against every discovered NS.
        if (opts.attempt_axfr) {
            std::vector<std::string> ns_names;
            for (auto& r : result.records) if (r.type == DnsRRType::NS) ns_names.push_back(r.value);
            for (auto& ns_name : ns_names) {
                std::vector<DnsRecord> a_recs;
                dns_query_generic(ns_name, DnsRRType::A, servers, opts.timeout_ms, opts.retries, a_recs);
                std::string ns_ip = a_recs.empty() ? "" : a_recs.front().value;
                if (ns_ip.empty()) continue;

                std::vector<DnsRecord> zone_recs;
                auto att = try_axfr(domain, ns_name, ns_ip, opts.timeout_ms, zone_recs);
                result.axfr_attempts.push_back(att);
                if (att.succeeded) {
                    result.records.insert(result.records.end(), zone_recs.begin(), zone_recs.end());
                    for (auto& r : zone_recs) {
                        if (r.name.empty()) continue;
                        std::string h = r.name;
                        if (!h.empty() && h.back() == '.') h.pop_back();
                        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
                        auto& dh = result.hosts[h];
                        dh.hostname = h;
                        dh.sources.insert(DiscoverySource::ActiveZoneTransfer);
                        if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA) dh.ips.insert(r.value);
                    }
                }
            }
        }

        // 4. Subdomain brute force (skipped/annotated if wildcard and not overridden).
        if (!result.wildcard_dns || opts.skip_wildcard_filter) {
            std::vector<std::string> words = builtin_subdomain_wordlist();
            if (!opts.wordlist_file.empty()) {
                std::ifstream f(opts.wordlist_file);
                std::string line;
                while (f && std::getline(f, line)) {
                    if (!line.empty()) words.push_back(line);
                }
            }
            brute_force_resolve(domain, words, servers, opts.timeout_ms,
                                 opts.brute_concurrency, result.hosts);

            if (result.wildcard_dns && !opts.skip_wildcard_filter) {
                for (auto& [name, h] : result.hosts) {
                    if (h.ips.count(result.wildcard_ip_sample))
                        h.wildcard_suspect = true;
                }
            }
        }

        // 5. Email security + DNSSEC.
        collect_email_security(domain, servers, opts.timeout_ms, opts.retries,
                                opts.extra_dkim_selectors, result.mail_security);
        collect_dnssec(domain, servers, opts.timeout_ms, opts.retries, result.dnssec);

        result.active_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }

    if (opts.do_passive) {
        auto t0 = std::chrono::steady_clock::now();

        if (opts.query_crtsh) passive_crtsh(domain, opts.passive_timeout_ms, result.hosts);
        if (opts.query_wayback)
            passive_wayback(domain, opts.passive_timeout_ms, opts.wayback_sample_cap,
                             result.hosts, result.wayback_urls_sample);
        if (opts.query_rdap) result.domain_whois = passive_rdap_domain(domain, opts.passive_timeout_ms);

        if (opts.query_asn) {
            std::unordered_set<std::string> unique_ips;
            for (auto& [name, h] : result.hosts) for (auto& ip : h.ips) unique_ips.insert(ip);
            for (auto& r : result.records)
                if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA) unique_ips.insert(r.value);
            for (const auto& ip : unique_ips) {
                AsnInfo info = passive_asn_lookup(ip);
                if (!info.asn.empty()) result.asn_lookups.push_back(info);
            }
        }

        result.passive_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }

    return result;
}

// =======================================================================
// Section 7: reporting
// =======================================================================

const char* dns_rrtype_name(DnsRRType t) {
    switch (t) {
        case DnsRRType::A: return "A";
        case DnsRRType::NS: return "NS";
        case DnsRRType::CNAME: return "CNAME";
        case DnsRRType::SOA: return "SOA";
        case DnsRRType::PTR: return "PTR";
        case DnsRRType::MX: return "MX";
        case DnsRRType::TXT: return "TXT";
        case DnsRRType::AAAA: return "AAAA";
        case DnsRRType::SRV: return "SRV";
        case DnsRRType::NAPTR: return "NAPTR";
        case DnsRRType::DS: return "DS";
        case DnsRRType::RRSIG: return "RRSIG";
        case DnsRRType::NSEC: return "NSEC";
        case DnsRRType::DNSKEY: return "DNSKEY";
        case DnsRRType::CAA: return "CAA";
        case DnsRRType::AXFR: return "AXFR";
        default: return "ANY";
    }
}

namespace {

std::string sanitize_echo(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
    }
    return out;
}

void print_section(const std::string& title) {
    std::cout << color::bold << color::cyan << "\n:: " << title << color::reset << "\n";
}

}

void print_dns_enum_result(const DnsEnumResult& r, const DnsEnumOptions& opts) {
    std::cout << "\n" << color::bold << color::cyan << "DNS Enumeration: " << color::reset
              << color::white << r.domain << color::reset << "\n";

    std::cout << color::bold << "\n:: Apex records\n" << color::reset;
    for (auto& rec : r.records) {
        if (rec.source.rfind("axfr", 0) == 0) continue; // shown separately
        std::cout << "  " << color::yellow << dns_rrtype_name(rec.type) << color::reset
                  << "\t" << rec.name << "\t" << rec.value
                  << color::dim << "  (ttl=" << rec.ttl << ")" << color::reset << "\n";
    }

    if (r.wildcard_dns) {
        std::cout << color::bold << "\n:: Wildcard DNS detected" << color::reset
                  << " -> " << r.wildcard_ip_sample
                  << color::dim << "  (brute-force hits matching this IP are flagged wildcard_suspect)"
                  << color::reset << "\n";
    }

    if (!r.axfr_attempts.empty()) {
        std::cout << color::bold << "\n:: Zone transfer (AXFR) attempts\n" << color::reset;
        for (auto& a : r.axfr_attempts) {
            if (a.succeeded) {
                std::cout << "  " << color::red << color::bold << "SUCCEEDED" << color::reset
                          << " against " << a.ns_host << " (" << a.ns_ip << ") — "
                          << a.records_pulled << " records pulled. Full zone contents exposed.\n";
            } else {
                std::cout << "  " << color::green << "refused" << color::reset
                          << "  " << a.ns_host << " (" << a.ns_ip << "): " << a.error << "\n";
            }
        }
    }

    size_t brute = 0, axfr = 0, cert = 0, wb = 0, wc = 0;
    for (auto& [name, h] : r.hosts) {
        for (auto s : h.sources) {
            if (s == DiscoverySource::ActiveBruteForce) ++brute;
            if (s == DiscoverySource::ActiveZoneTransfer) ++axfr;
            if (s == DiscoverySource::PassiveCertLog) ++cert;
            if (s == DiscoverySource::PassiveWayback) ++wb;
        }
        if (h.wildcard_suspect) ++wc;
    }
    std::cout << color::bold << "\n:: Subdomains — " << r.hosts.size() << " unique host(s)"
              << color::reset << "\n"
              << "  brute-force: " << brute << "   axfr: " << axfr
              << "   crt.sh: " << cert << "   wayback: " << wb
              << (wc ? ("   " + color::dim + "wildcard_suspect: " + std::to_string(wc) + color::reset) : "")
              << "\n";
    if (opts.verbose) {
        std::vector<std::string> names;
        names.reserve(r.hosts.size());
        for (auto& [name, h] : r.hosts) names.push_back(name);
        std::sort(names.begin(), names.end());
        for (auto& name : names) {
            const auto& h = r.hosts.at(name);
            std::cout << "    " << (h.wildcard_suspect ? color::dim : color::white) << name << color::reset;
            if (!h.ips.empty()) {
                std::cout << "  -> ";
                bool first = true;
                for (auto& ip : h.ips) { if (!first) std::cout << ", "; std::cout << ip; first = false; }
            }
            std::cout << "\n";
        }
    } else {
        std::cout << color::dim << "  (use --dns-enum-verbose to list every host)" << color::reset << "\n";
    }

    std::cout << color::bold << "\n:: Email security posture\n" << color::reset;
    auto flag = [](bool b) { return b ? (color::green + "yes" + color::reset)
                                       : (color::red + "no" + color::reset); };
    std::cout << "  SPF: " << flag(r.mail_security.has_spf);
    if (r.mail_security.has_spf) std::cout << "  " << color::dim << r.mail_security.spf_record << color::reset;
    std::cout << "\n  DMARC: " << flag(r.mail_security.has_dmarc);
    if (r.mail_security.has_dmarc) std::cout << "  " << color::dim << r.mail_security.dmarc_record << color::reset;
    std::cout << "\n  BIMI: " << flag(r.mail_security.has_bimi)
               << "   MTA-STS: " << flag(r.mail_security.has_mta_sts_dns)
               << "   TLS-RPT: " << flag(r.mail_security.has_tls_rpt) << "\n";
    if (!r.mail_security.dkim_selectors_found.empty()) {
        std::cout << "  DKIM selectors found: ";
        bool first = true;
        for (auto& [sel, val] : r.mail_security.dkim_selectors_found) {
            if (!first) std::cout << ", ";
            std::cout << sel; first = false;
        }
        std::cout << "\n";
    }

    std::cout << color::bold << "\n:: DNSSEC\n" << color::reset
              << "  DNSKEY: " << flag(r.dnssec.dnskey_present)
              << " (" << r.dnssec.dnskey_count << ")"
              << "   RRSIG observed: " << flag(r.dnssec.rrsig_seen) << "\n";

    if (r.domain_whois.found) {
        std::cout << color::bold << "\n:: WHOIS / RDAP\n" << color::reset
                  << "  registrar: " << r.domain_whois.registrar << "\n"
                  << "  created:   " << r.domain_whois.created << "\n"
                  << "  updated:   " << r.domain_whois.updated << "\n"
                  << "  expires:   " << r.domain_whois.expires << "\n";
    }

    if (!r.asn_lookups.empty()) {
        std::cout << color::bold << "\n:: ASN / infrastructure\n" << color::reset;
        for (auto& a : r.asn_lookups)
            std::cout << "  " << a.ip << "  AS" << a.asn << " " << a.as_name
                       << "  (" << a.prefix << ", " << a.country << ")\n";
    }

    if (!r.wayback_urls_sample.empty()) {
        std::cout << color::bold << "\n:: Wayback Machine sample (" << r.wayback_urls_sample.size()
                   << " of possibly more)\n" << color::reset;
        for (auto& u : r.wayback_urls_sample) std::cout << "  " << u << "\n";
    }

    std::cout << color::dim << "\nactive phase: " << r.active_duration.count()
              << "ms   passive phase: " << r.passive_duration.count() << "ms"
              << color::reset << "\n";
}

bool save_dns_enum_result(const DnsEnumResult& r, const std::string& path) {
    if (path.empty()) return false;
    json j;
    j["domain"] = r.domain;
    j["wildcard_dns"] = r.wildcard_dns;
    j["wildcard_ip_sample"] = r.wildcard_ip_sample;

    j["records"] = json::array();
    for (auto& rec : r.records)
        j["records"].push_back({{"type", dns_rrtype_name(rec.type)}, {"name", rec.name},
                                 {"value", rec.value}, {"ttl", rec.ttl}, {"source", rec.source}});

    j["axfr_attempts"] = json::array();
    for (auto& a : r.axfr_attempts)
        j["axfr_attempts"].push_back({{"ns_host", a.ns_host}, {"ns_ip", a.ns_ip},
                                       {"succeeded", a.succeeded}, {"records_pulled", a.records_pulled},
                                       {"error", a.error}});

    j["hosts"] = json::array();
    for (auto& [name, h] : r.hosts) {
        json hj;
        hj["hostname"] = h.hostname;
        hj["ips"] = h.ips;
        hj["wildcard_suspect"] = h.wildcard_suspect;
        json srcs = json::array();
        for (auto s : h.sources) {
            switch (s) {
                case DiscoverySource::ActiveBruteForce: srcs.push_back("active_bruteforce"); break;
                case DiscoverySource::ActiveZoneTransfer: srcs.push_back("active_axfr"); break;
                case DiscoverySource::ActiveRecordChain: srcs.push_back("active_record_chain"); break;
                case DiscoverySource::PassiveCertLog: srcs.push_back("passive_crtsh"); break;
                case DiscoverySource::PassiveWayback: srcs.push_back("passive_wayback"); break;
                case DiscoverySource::PassiveRdap: srcs.push_back("passive_rdap"); break;
            }
        }
        hj["sources"] = srcs;
        j["hosts"].push_back(hj);
    }

    j["mail_security"] = {
        {"spf", {{"present", r.mail_security.has_spf}, {"record", r.mail_security.spf_record}}},
        {"dmarc", {{"present", r.mail_security.has_dmarc}, {"record", r.mail_security.dmarc_record}}},
        {"bimi", {{"present", r.mail_security.has_bimi}, {"record", r.mail_security.bimi_record}}},
        {"mta_sts_dns", {{"present", r.mail_security.has_mta_sts_dns}, {"record", r.mail_security.mta_sts_dns_record}}},
        {"tls_rpt", {{"present", r.mail_security.has_tls_rpt}, {"record", r.mail_security.tls_rpt_record}}},
        {"mx_hosts", r.mail_security.mx_hosts},
    };
    json dkim = json::array();
    for (auto& [sel, val] : r.mail_security.dkim_selectors_found)
        dkim.push_back({{"selector", sel}, {"record", val}});
    j["mail_security"]["dkim_selectors_found"] = dkim;

    j["dnssec"] = {{"dnskey_present", r.dnssec.dnskey_present}, {"dnskey_count", r.dnssec.dnskey_count},
                    {"rrsig_seen", r.dnssec.rrsig_seen}, {"ds_present_at_parent", r.dnssec.ds_present_at_parent}};

    j["whois"] = {{"found", r.domain_whois.found}, {"registrar", r.domain_whois.registrar},
                   {"created", r.domain_whois.created}, {"updated", r.domain_whois.updated},
                   {"expires", r.domain_whois.expires}, {"statuses", r.domain_whois.statuses},
                   {"nameservers", r.domain_whois.nameservers}};

    j["asn_lookups"] = json::array();
    for (auto& a : r.asn_lookups)
        j["asn_lookups"].push_back({{"ip", a.ip}, {"asn", a.asn}, {"as_name", a.as_name},
                                     {"prefix", a.prefix}, {"country", a.country},
                                     {"registry", a.registry}, {"allocated", a.allocated}});

    j["wayback_sample"] = r.wayback_urls_sample;
    j["timing_ms"] = {{"active", r.active_duration.count()}, {"passive", r.passive_duration.count()}};

    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return true;
}
