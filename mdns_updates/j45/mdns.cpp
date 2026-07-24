#include "mdns.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <cstdint>
#include <net/if.h>
#include <sys/ioctl.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace {

constexpr int         MDNS_PORT  = 5353;
constexpr const char* MDNS_GROUP = "224.0.0.251";
constexpr uint16_t    T_A        = 1;
constexpr uint16_t    T_SRV      = 33;

std::mutex                                    g_mdns_mutex;
std::unordered_map<std::string, std::string>  g_hostname_by_ip;    // "192.168.1.64" -> "Android-7"
std::unordered_map<std::string, std::string>  g_name_by_hostname;  // "Android-7"    -> "Hridaya"

std::atomic<bool> g_mdns_running{false};
std::thread       g_mdns_thread;
int               g_mdns_sock = -1;

// Reads one DNS name starting at buf[offset], following compression
// pointers (RFC 1035 4.1.4) as needed. Raw, un-joined labels are appended
// to labels_out. `offset` is advanced past the name as it was ENCODED AT
// THE CALL SITE — a pointer always terminates the in-place encoding after
// its 2 bytes, regardless of how many hops it takes to resolve.
bool read_name(const uint8_t* buf, size_t len, size_t& offset,
               std::vector<std::string>& labels_out) {
    size_t pos = offset;
    bool   jumped = false;
    size_t after_first_jump = offset;
    int    hops = 0;

    while (pos < len) {
        uint8_t lab_len = buf[pos];
        if (lab_len == 0) {
            pos += 1;
            if (!jumped) after_first_jump = pos;
            break;
        }
        if ((lab_len & 0xC0) == 0xC0) {               // compression pointer
            if (pos + 1 >= len) return false;
            if (++hops > 32) return false;              // guard against loops
            size_t ptr = static_cast<size_t>((lab_len & 0x3F) << 8) | buf[pos + 1];
            if (!jumped) { after_first_jump = pos + 2; jumped = true; }
            if (ptr >= len) return false;
            pos = ptr;
            continue;
        }
        if (pos + 1 + lab_len > len) return false;
        labels_out.emplace_back(reinterpret_cast<const char*>(buf + pos + 1), lab_len);
        pos += 1 + lab_len;
    }

    offset = jumped ? after_first_jump : pos;
    return true;
}

std::string join_labels(const std::vector<std::string>& labels) {
    std::string out;
    for (size_t k = 0; k < labels.size(); ++k) {
        if (k) out += '.';
        out += labels[k];
    }
    return out;
}

std::string strip_local(std::string s) {
    static const std::string suffix = ".local";
    if (s.size() >= suffix.size() &&
        s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0) {
        s.resize(s.size() - suffix.size());
    }
    return s;
}

// "192.168.1.64" -> "64.1.168.192.in-addr.arpa" — the canonical PTR
// query name that asks a host "who are you" over mDNS.
std::string reverse_ip_to_arpa(const std::string& ip) {
    unsigned a, b, c, d;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "";
    return std::to_string(d) + "." + std::to_string(c) + "." +
           std::to_string(b) + "." + std::to_string(a) + ".in-addr.arpa";
}

// Pulls the value out of a `"key":"value"` pair from a raw mDNS instance
// label like `{"nm":"Hridaya","as":"[8193, 8194]","ip":"64"}`. Plain
// substring search is enough for this one bounded, well-known shape — no
// general JSON parser needed.
std::string extract_json_field(const std::string& blob, const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    size_t p = blob.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    size_t q = blob.find('"', p);
    if (q == std::string::npos) return "";
    return blob.substr(p, q - p);
}

void handle_packet(const uint8_t* buf, size_t n) {
    if (n < 12) return;

    uint16_t qdcount = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
    uint16_t ancount = static_cast<uint16_t>((buf[6] << 8) | buf[7]);
    uint16_t nscount = static_cast<uint16_t>((buf[8] << 8) | buf[9]);
    uint16_t arcount = static_cast<uint16_t>((buf[10] << 8) | buf[11]);

    size_t offset = 12;

    // Skip the question section — we only care about answers/authority/
    // additional RRs, but names later in the packet may point back into
    // here via compression, so we still have to walk past it correctly.
    for (uint16_t i = 0; i < qdcount; ++i) {
        std::vector<std::string> labels;
        if (!read_name(buf, n, offset, labels)) return;
        if (offset + 4 > n) return;
        offset += 4; // QTYPE + QCLASS
    }

    uint32_t total_rr = static_cast<uint32_t>(ancount) + nscount + arcount;
    for (uint32_t i = 0; i < total_rr; ++i) {
        std::vector<std::string> owner_labels;
        if (!read_name(buf, n, offset, owner_labels)) return;
        if (offset + 10 > n) return;

        uint16_t rtype = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
        uint16_t rdlen = static_cast<uint16_t>((buf[offset + 8] << 8) | buf[offset + 9]);
        size_t   rdata_off = offset + 10;
        if (rdata_off + rdlen > n) return;

        if (rtype == T_A && rdlen == 4 && !owner_labels.empty()) {
            // A record: owner name (minus ".local") is the hostname,
            // rdata is the IPv4 address — this is a direct hostname<->IP
            // link for whatever IP we're scanning.
            std::string hostname = strip_local(join_labels(owner_labels));

            char ip_str[INET_ADDRSTRLEN] = {0};
            struct in_addr a{};
            std::memcpy(&a.s_addr, buf + rdata_off, 4);
            inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));

            std::lock_guard<std::mutex> lock(g_mdns_mutex);
            g_hostname_by_ip[ip_str] = hostname;
        }
        else if (rtype == T_SRV && rdlen >= 6 && !owner_labels.empty()) {
            // SRV record: rdata is priority(2) weight(2) port(2) target-name.
            // Owner name's first label is often an instance blob like
            // {"nm":"Hridaya",...} — pull the friendly name out of it and
            // key it by the SRV target hostname (e.g. "Android-7"), so it
            // can be joined against the A-record hostname above.
            size_t target_off = rdata_off + 6;
            std::vector<std::string> target_labels;
            if (read_name(buf, n, target_off, target_labels) && !target_labels.empty()) {
                std::string target_host = strip_local(join_labels(target_labels));
                std::string nm = extract_json_field(owner_labels[0], "nm");
                if (!nm.empty()) {
                    std::lock_guard<std::mutex> lock(g_mdns_mutex);
                    g_name_by_hostname[target_host] = nm;
                }
            }
        }
    }
}

void listener_loop() {
    while (g_mdns_running.load(std::memory_order_relaxed)) {
        struct pollfd pfd{ g_mdns_sock, POLLIN, 0 };
        int pr = poll(&pfd, 1, 200); // 200ms tick so stop() is noticed promptly
        if (pr <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        uint8_t buf[4096];
        struct sockaddr_in src{};
        socklen_t sl = sizeof(src);
        ssize_t n = recvfrom(g_mdns_sock, buf, sizeof(buf), 0,
                              reinterpret_cast<struct sockaddr*>(&src), &sl);
        if (n <= 0) continue;
        handle_packet(buf, static_cast<size_t>(n));
    }
}

} // namespace

void start_mdns_listener(const std::string& interface) {
    if (g_mdns_running.exchange(true)) return; // already running

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { g_mdns_running = false; return; }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(MDNS_PORT);
    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        g_mdns_running = false;
        return;
    }

    struct ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (!interface.empty()) {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
            mreq.imr_interface.s_addr = sin->sin_addr.s_addr;
        }
    }
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(sock);
        g_mdns_running = false;
        return;
    }

    g_mdns_sock   = sock;
    g_mdns_thread = std::thread(listener_loop);
}

void send_mdns_query(const std::string& ip, const std::string& interface) {
    (void)interface; // socket is already bound/joined by start_mdns_listener
    if (g_mdns_sock < 0) return;

    std::string arpa = reverse_ip_to_arpa(ip);
    if (arpa.empty()) return;

    uint8_t pkt[512];
    size_t off = 0;
    auto put16 = [&](uint16_t v) {
        pkt[off++] = static_cast<uint8_t>(v >> 8);
        pkt[off++] = static_cast<uint8_t>(v & 0xFF);
    };

    put16(0); put16(0);   // Transaction ID, Flags (standard query)
    put16(1); put16(0); put16(0); put16(0); // QD=1, AN/NS/AR=0

    size_t start = 0;
    for (size_t i = 0; i <= arpa.size(); ++i) {
        if (i == arpa.size() || arpa[i] == '.') {
            uint8_t len = static_cast<uint8_t>(i - start);
            pkt[off++] = len;
            std::memcpy(pkt + off, arpa.data() + start, len);
            off += len;
            start = i + 1;
        }
    }
    pkt[off++] = 0;        // root label
    put16(12); put16(1);   // QTYPE=PTR, QCLASS=IN

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(MDNS_PORT);
    inet_pton(AF_INET, MDNS_GROUP, &dst.sin_addr);

    sendto(g_mdns_sock, pkt, off, 0,
           reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
}

void stop_mdns_listener() {
    if (!g_mdns_running.exchange(false)) return;
    if (g_mdns_thread.joinable()) g_mdns_thread.join();
    if (g_mdns_sock >= 0) { close(g_mdns_sock); g_mdns_sock = -1; }
}

MdnsDeviceInfo get_mdns_device_info(const std::string& ip) {
    MdnsDeviceInfo info;
    std::lock_guard<std::mutex> lock(g_mdns_mutex);
    auto hit = g_hostname_by_ip.find(ip);
    if (hit != g_hostname_by_ip.end()) {
        info.hostname = hit->second;
        auto nit = g_name_by_hostname.find(info.hostname);
        if (nit != g_name_by_hostname.end()) info.name = nit->second;
    }
    return info;
}

std::string format_mdns_device(const MdnsDeviceInfo& info) {
    if (info.hostname.empty() && info.name.empty()) return "";
    if (!info.hostname.empty() && !info.name.empty())
        return info.hostname + " (" + info.name + ")";
    return info.hostname.empty() ? info.name : info.hostname;
}
