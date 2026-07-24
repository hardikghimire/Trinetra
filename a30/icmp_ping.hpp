#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <chrono>
#include <vector>
#include <string>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <fcntl.h>

enum class IcmpHostState {
    Alive,               // type 0 code 0  — echo reply
    Dead,                // type 3 code 1  — host unreachable
    NetUnreachable,      // type 3 code 0  — network unreachable
    NetAdminProhibited,  // type 3 code 9  — net admin prohibited (ACL/router policy blocks subnet)
    HostAdminProhibited, // type 3 code 10 — host admin prohibited (host firewall/ACL denies IP)
    CommAdminProhibited, // type 3 code 13 — comm admin prohibited (iptables REJECT/firewall policy)
    NoResponse           // timeout — treat same as Dead for skip logic
};

struct IcmpResult {
    std::string      ip;
    IcmpHostState    state = IcmpHostState::NoResponse;
};

static uint16_t icmp_checksum(const void* data, size_t len) {
    const uint16_t* p = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

inline std::vector<IcmpResult> icmp_ping_sweep(
        const std::vector<std::string>& ips,
        int timeout_ms = 1200)
{
    constexpr size_t MAX_PARALLEL = 50000;
    std::vector<IcmpResult> results(ips.size());
    for (size_t i = 0; i < ips.size(); ++i)
        results[i].ip = ips[i];

    if (ips.empty()) return results;

    // Build ip→index map for fast reply lookup
    std::unordered_map<uint32_t, size_t> ip_to_idx;
    ip_to_idx.reserve(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) {
        in_addr a{};
        if (inet_pton(AF_INET, ips[i].c_str(), &a) == 1)
            ip_to_idx[a.s_addr] = i;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return results;   // fallback: no ping, scan everything

    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Larger receive buffer
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // Use PID as ICMP identifier so we don't pick up other processes' replies
    uint16_t ident = static_cast<uint16_t>(getpid() & 0xffff);

    // Send loop — process in batches of MAX_PARALLEL
    size_t total = ips.size();
    size_t sent  = 0;

    auto send_batch = [&](size_t from, size_t to) {
        for (size_t i = from; i < to && i < total; ++i) {
            in_addr a{};
            if (inet_pton(AF_INET, ips[i].c_str(), &a) != 1) continue;

            struct {
                struct icmphdr hdr;
                uint8_t        pad[8];   // minimum payload
            } pkt{};
            pkt.hdr.type             = ICMP_ECHO;
            pkt.hdr.code             = 0;
            pkt.hdr.un.echo.id       = htons(ident);
            pkt.hdr.un.echo.sequence = htons(static_cast<uint16_t>(i & 0xffff));
            pkt.hdr.checksum         = 0;
            pkt.hdr.checksum         = icmp_checksum(&pkt, sizeof(pkt));

            sockaddr_in dst{};
            dst.sin_family      = AF_INET;
            dst.sin_addr        = a;
            sendto(sock, &pkt, sizeof(pkt), 0,
                   reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        }
    };

    // Send all hosts in one pass (kernel buffers handle the burst)
    send_batch(0, total);

    // Receive loop — collect replies until timeout after last send
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);

    char buf[1500];
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{ sock, POLLIN, 0 };
        int remaining_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count());
        if (remaining_ms <= 0) break;
        int r = poll(&pfd, 1, std::min(remaining_ms, 50));
        if (r <= 0) continue;

        sockaddr_in src{};
        socklen_t   slen = sizeof(src);
        ssize_t     nb   = recvfrom(sock, buf, sizeof(buf), 0,
                                    reinterpret_cast<sockaddr*>(&src), &slen);
        if (nb < 0) continue;

        // Raw socket gives us the full IP packet
        if (nb < static_cast<ssize_t>(sizeof(struct ip))) continue;
        struct ip*    iph  = reinterpret_cast<struct ip*>(buf);
        int           iphlen = iph->ip_hl * 4;
        if (nb < iphlen + static_cast<int>(sizeof(struct icmphdr))) continue;
        struct icmphdr* ih = reinterpret_cast<struct icmphdr*>(buf + iphlen);

        uint32_t src_addr = iph->ip_src.s_addr;
        auto it = ip_to_idx.find(src_addr);
        if (it == ip_to_idx.end()) continue;
        size_t idx = it->second;

        // Already classified — keep first answer
        if (results[idx].state != IcmpHostState::NoResponse) continue;

        uint8_t type = ih->type;
        uint8_t code = ih->code;

        if (type == 0 && code == 0) {
            // Echo reply — but only accept if ident matches
            if (ntohs(ih->un.echo.id) != ident) continue;
            results[idx].state = IcmpHostState::Alive;
        } else if (type == 3) {

	    // ── Original bounds check ──────────────────────────────────────────
	    if (nb < iphlen + static_cast<int>(sizeof(struct icmphdr))
		            + static_cast<int>(sizeof(struct ip))) continue;

	    // ── Original: extract inner IP header ─────────────────────────────
	    struct ip* inner = reinterpret_cast<struct ip*>(
		buf + iphlen + sizeof(struct icmphdr));

	    // ── NEW: additional bounds check for inner ICMP header ────────────
	    int inner_iphlen = inner->ip_hl * 4;
	    if (nb < iphlen + static_cast<int>(sizeof(struct icmphdr))
		            + inner_iphlen
		            + static_cast<int>(sizeof(struct icmphdr))) continue;

	    // ── NEW: extract inner ICMP header and verify ident ───────────────
	    struct icmphdr* inner_icmp = reinterpret_cast<struct icmphdr*>(
		buf + iphlen + sizeof(struct icmphdr) + inner_iphlen);
	    if (ntohs(inner_icmp->un.echo.id) != ident) continue;  // ← not our packet

	    // ── Original: match target IP ──────────────────────────────────────
	    uint32_t target_addr = inner->ip_dst.s_addr;
	    auto it2 = ip_to_idx.find(target_addr);
	    if (it2 == ip_to_idx.end()) continue;
	    size_t tidx = it2->second;
	    if (results[tidx].state != IcmpHostState::NoResponse) continue;

	    // ── Original: classify by code ────────────────────────────────────
	    switch (code) {
		case 0:  results[tidx].state = IcmpHostState::NetUnreachable;      break;
		case 1:  results[tidx].state = IcmpHostState::Dead;                break;
		case 9:  results[tidx].state = IcmpHostState::NetAdminProhibited;  break;
		case 10: results[tidx].state = IcmpHostState::HostAdminProhibited; break;
		case 13: results[tidx].state = IcmpHostState::CommAdminProhibited; break;
		default: break;
	    }
	}
    }

    close(sock);
    return results;
}
