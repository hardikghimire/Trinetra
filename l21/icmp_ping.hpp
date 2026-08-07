#pragma once


#include <liburing.h>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <chrono>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <cstring>

// ─── Public result types ──────────────────────────────────────────────────────

enum class IcmpHostState : uint8_t {
    Alive,               // type 0  code 0  — echo reply
    Dead,                // type 3  code 1  — host unreachable
    NetUnreachable,      // type 3  code 0  — network unreachable
    NetAdminProhibited,  // type 3  code 9  — ACL/router blocks subnet
    HostAdminProhibited, // type 3  code 10 — host firewall/ACL denies IP
    CommAdminProhibited, // type 3  code 13 — iptables REJECT / firewall policy
    // ── fatal: no connectivity possible ─────────────────────────────────────
    ProtoUnreachable,    // type 3  code 2  — protocol not supported by host
    SrcRouteFailed,      // type 3  code 5  — source route failed
    NetUnknown,          // type 3  code 6  — destination network unknown
    HostUnknown,         // type 3  code 7  — destination host unknown
    SrcHostIsolated,     // type 3  code 8  — source host isolated
    HostPrecViolation,   // type 3  code 14 — host precedence violation
    NoRoute,             // type 1  code 0  — no route to destination
    // ── warnings: path-level issues (host might still be reachable) ──────────
    FragNeeded,          // type 3  code 4  — fragmentation needed, DF set
    TtlExceeded,         // type 11 code 0  — TTL expired in transit
    FragTimeout,         // type 11 code 1  — fragment reassembly time exceeded
    BadSpi,              // type 40 code 0  — bad security parameters index
    NoResponse           // timeout / no answer
};

struct IcmpResult {
    std::string   ip;
    IcmpHostState state = IcmpHostState::NoResponse;
    double        rtt_s = 0.0;   // time from sweep start to this host's reply; 0 if never matched
};

namespace icmp_detail {

static constexpr unsigned URING_DEPTH      = 4096u;
static constexpr size_t   MAX_SEND         = 50'000u;
static constexpr size_t   RECV_BUF_SIZE    = 1500u;
static constexpr unsigned RECV_SLOTS       = 512u;
static constexpr ssize_t  MIN_PKT          = static_cast<ssize_t>(sizeof(struct ip) + sizeof(struct icmphdr));
static constexpr uint64_t TAG_SEND_HI = 0x5300'0000'0000'0000ULL;  // 'S'
static constexpr uint64_t TAG_RECV_HI = 0x5200'0000'0000'0000ULL;  // 'R'
static constexpr uint64_t TAG_HI_MASK = 0xFF00'0000'0000'0000ULL;


inline uint16_t icmp_checksum(const void* data, size_t len) noexcept
{
    const auto* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len)          sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum  = (sum & 0xffffu) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// ── RAII: raw socket ──────────────────────────────────────────────────────────
struct RawSocket {
    int fd = -1;

    RawSocket() noexcept {
        fd = ::socket(AF_INET, SOCK_RAW,   IPPROTO_ICMP);
        if (fd < 0)
            fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    ~RawSocket() noexcept { if (fd >= 0) ::close(fd); }

    RawSocket(const RawSocket&)            = delete;
    RawSocket& operator=(const RawSocket&) = delete;

    bool valid() const noexcept { return fd >= 0; }
};

// ── RAII: io_uring instance ───────────────────────────────────────────────────
struct UringGuard {
    struct io_uring ring {};
    bool            ready = false;

    explicit UringGuard(unsigned depth) noexcept {
        struct io_uring_params p {};
        p.flags = IORING_SETUP_SINGLE_ISSUER;
        ready   = (io_uring_queue_init_params(depth, &ring, &p) == 0);
    }
    ~UringGuard() noexcept { if (ready) io_uring_queue_exit(&ring); }

    UringGuard(const UringGuard&)            = delete;
    UringGuard& operator=(const UringGuard&) = delete;
};

struct alignas(64) SendCtx {
    struct {
        struct icmphdr hdr;
        uint8_t        pad[8];   // minimum ICMP payload (keeps some routers happy)
    } pkt {};
    struct sockaddr_in dst {};
    struct iovec       iov {};
    struct msghdr      msg {};
};

// ── Per-receive slot (reused across many packets) ─────────────────────────────
struct alignas(64) RecvCtx {
    char               buf[RECV_BUF_SIZE] {};
    struct sockaddr_in src {};
    char               cmsg_buf[64] {};
    struct iovec       iov {};
    struct msghdr      msg {};
};

// ── Lightweight IPv6 address key (self-contained — does not depend on
//    scan.hpp's IPv6Key, so this header stays includable on its own) ──────
struct Icmp6Key {
    uint8_t bytes[16];
    bool operator==(const Icmp6Key& o) const noexcept {
        return memcmp(bytes, o.bytes, 16) == 0;
    }
};
struct Icmp6KeyHash {
    size_t operator()(const Icmp6Key& k) const noexcept {
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < 16; ++i) { h ^= k.bytes[i]; h *= 1099511628211ULL; }
        return static_cast<size_t>(h);
    }
};
inline Icmp6Key make_icmp6_key(const struct in6_addr& a) {
    Icmp6Key k; memcpy(k.bytes, &a, 16); return k;
}

static constexpr ssize_t MIN_PKT6 = static_cast<ssize_t>(sizeof(struct icmp6_hdr));

struct alignas(64) Send6Ctx {
    struct {
        struct icmp6_hdr hdr;
        uint8_t          pad[8];   // minimum payload, mirrors v4 SendCtx
    } pkt {};
    struct sockaddr_in6 dst {};
    struct iovec        iov {};
    struct msghdr       msg {};
};

// ── Per-receive slot for ICMPv6 (no outer IPv6 header present) ────────────
struct alignas(64) Recv6Ctx {
    char                buf[RECV_BUF_SIZE] {};
    struct sockaddr_in6 src {};
    struct iovec        iov {};
    struct msghdr       msg {};
};

} 

inline std::vector<IcmpResult> icmp_ping_sweep(
        const std::vector<std::string>& ips,
        int timeout_ms = 1200)
{
    using namespace icmp_detail;

    // ── 0. Result vector ──────────────────────────────────────────────────────
    std::vector<IcmpResult> results(ips.size());
    for (size_t i = 0; i < ips.size(); ++i)
        results[i].ip = ips[i];

    if (ips.empty()) return results;

    // ── 1. Open + harden socket ───────────────────────────────────────────────
    RawSocket sock;
    if (!sock.valid()) return results;

    {
        int fl = ::fcntl(sock.fd, F_GETFL, 0);
        if (fl < 0 || ::fcntl(sock.fd, F_SETFL, fl | O_NONBLOCK) < 0)
            return results;
    }

    {
        int rcvbuf = 4 * 1024 * 1024;
        ::setsockopt(sock.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    {
        struct sockaddr_in b {};
        b.sin_family      = AF_INET;
        b.sin_addr.s_addr = INADDR_ANY;
        ::bind(sock.fd, reinterpret_cast<const struct sockaddr*>(&b), sizeof(b));
    }

    // ── 2. IP → result-index lookup map ──────────────────────────────────────
    std::unordered_map<uint32_t, size_t> ip_to_idx;
    ip_to_idx.reserve(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) {
        struct in_addr a {};
        if (::inet_pton(AF_INET, ips[i].c_str(), &a) == 1)
            ip_to_idx.emplace(a.s_addr, i);   // duplicates: first wins
    }

    // ── 3. io_uring setup ─────────────────────────────────────────────────────
    UringGuard uring(URING_DEPTH);
    if (!uring.ready) return results;

    const size_t n = ips.size();
    auto send_ctxs = std::make_unique<SendCtx[]>(n);
    auto recv_ctxs = std::make_unique<RecvCtx[]>(RECV_SLOTS);
    const uint16_t ident = static_cast<uint16_t>(::getpid() & 0xffffu);

    // ── 6. Queue all SENDMSG SQEs; flush in chunks to avoid SQ overflow ───────
    size_t sends_queued = 0;

    auto do_submit = [&]() {
        if (sends_queued > 0)
            io_uring_submit(&uring.ring);
        sends_queued = 0;
    };

    for (size_t i = 0; i < n; ++i) {
        struct in_addr a {};
        if (::inet_pton(AF_INET, ips[i].c_str(), &a) != 1) continue;

        SendCtx& ctx = send_ctxs[i];

        // Build ICMP echo request
        ctx.pkt.hdr.type             = ICMP_ECHO;
        ctx.pkt.hdr.code             = 0;
        ctx.pkt.hdr.un.echo.id       = htons(ident);
        ctx.pkt.hdr.un.echo.sequence = htons(static_cast<uint16_t>(i & 0xffffu));
        ctx.pkt.hdr.checksum         = 0;
        ctx.pkt.hdr.checksum         = icmp_checksum(&ctx.pkt, sizeof(ctx.pkt));

        ctx.dst.sin_family      = AF_INET;
        ctx.dst.sin_addr        = a;

        ctx.iov.iov_base        = &ctx.pkt;
        ctx.iov.iov_len         = sizeof(ctx.pkt);

        ctx.msg.msg_name        = &ctx.dst;
        ctx.msg.msg_namelen     = sizeof(ctx.dst);
        ctx.msg.msg_iov         = &ctx.iov;
        ctx.msg.msg_iovlen      = 1;
        ctx.msg.msg_control     = nullptr;
        ctx.msg.msg_controllen  = 0;
        ctx.msg.msg_flags       = 0;

        // Obtain an SQE; if the ring is full flush first then retry once.
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) {
            do_submit();
            sqe = io_uring_get_sqe(&uring.ring);
            if (!sqe) continue;  // still no room — skip this host (NoResponse)
        }

        io_uring_prep_sendmsg(sqe, sock.fd, &ctx.msg, 0);
        // Embed index in low 48 bits; high byte = 'S' to identify send CQEs.
        io_uring_sqe_set_data64(sqe, TAG_SEND_HI | static_cast<uint64_t>(i));
        sends_queued++;

        // Flush every URING_DEPTH sends to keep the SQ from stalling.
        if (sends_queued % URING_DEPTH == 0)
            do_submit();
    }
    do_submit();  // flush any remainder

    // ── 7. Arm initial RECVMSG SQEs ──────────────────────────────────────────
    // Helper: (re-)arm one receive slot and return true if an SQE was obtained.
    auto arm_recv = [&](unsigned slot) -> bool {
        if (slot >= RECV_SLOTS) return false;
        RecvCtx& r = recv_ctxs[slot];

        r.iov.iov_base        = r.buf;
        r.iov.iov_len         = RECV_BUF_SIZE;

        r.msg.msg_name        = &r.src;
        r.msg.msg_namelen     = sizeof(r.src);
        r.msg.msg_iov         = &r.iov;
        r.msg.msg_iovlen      = 1;
        r.msg.msg_control     = r.cmsg_buf;
        r.msg.msg_controllen  = sizeof(r.cmsg_buf);
        r.msg.msg_flags       = 0;

        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) return false;

        io_uring_prep_recvmsg(sqe, sock.fd, &r.msg, 0);
        // High byte = 'R'; low 32 bits = slot index.
        io_uring_sqe_set_data64(sqe, TAG_RECV_HI | static_cast<uint64_t>(slot));
        return true;
    };

    for (unsigned s = 0; s < RECV_SLOTS; ++s)
        arm_recv(s);
    io_uring_submit(&uring.ring);

    const auto sweep_start  = std::chrono::steady_clock::now();
    const auto deadline     = sweep_start + std::chrono::milliseconds(timeout_ms);
    size_t hosts_classified = 0;
    const size_t hosts_n    = ip_to_idx.size();
    while (hosts_classified < hosts_n) {
        auto now_tp  = std::chrono::steady_clock::now();
        auto left_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           deadline - now_tp).count();
        if (left_ns <= 0) break;

        struct __kernel_timespec ts {
            .tv_sec  = left_ns / 1'000'000'000LL,
            .tv_nsec = left_ns % 1'000'000'000LL
        };

        struct io_uring_cqe* cqe = nullptr;
        int ret = io_uring_wait_cqe_timeout(&uring.ring, &cqe, &ts);

        if (ret == -ETIME || ret == -EINTR) break;
        if (ret < 0 || !cqe)               continue;

        struct CqeInfo { uint64_t user_data; int32_t bytes; };
        std::array<CqeInfo, 32> batch{};
        size_t n = 0;
        batch[n++] = { io_uring_cqe_get_data64(cqe), cqe->res };
        io_uring_cqe_seen(&uring.ring, cqe);

        struct io_uring_cqe* peeked[32];
        unsigned n_peeked = io_uring_peek_batch_cqe(&uring.ring, peeked, 32);
        for (unsigned pi = 0; pi < n_peeked && n < batch.size(); ++pi) {
            batch[n++] = { io_uring_cqe_get_data64(peeked[pi]), peeked[pi]->res };
            io_uring_cqe_seen(&uring.ring, peeked[pi]);
        }

        bool need_submit = false;

        for (size_t ci = 0; ci < n; ++ci) {
            if (hosts_classified >= hosts_n) break;

            const uint64_t ud  = batch[ci].user_data;
            const int32_t  res = batch[ci].bytes;

            // ── Send CQE: nothing to do (errors leave host as NoResponse) ─
            if ((ud & TAG_HI_MASK) == TAG_SEND_HI) continue;

            // ── Recv CQE ────────────────────────────────────────────────
            if ((ud & TAG_HI_MASK) != TAG_RECV_HI) continue;  // unknown tag

            const unsigned slot = static_cast<unsigned>(ud & 0xFFFF'FFFFu);
            if (slot >= RECV_SLOTS) continue;  // corrupted tag — skip

            // Re-arm this slot, but defer the actual submit() until the
            // whole batch has been processed.
            if (arm_recv(slot)) need_submit = true;

            if (res <= 0) continue;  // receive error or empty packet

            RecvCtx&       rctx = recv_ctxs[slot];
            const ssize_t  nb   = static_cast<ssize_t>(res);

            // ── Security: validate outer IP header ─────────────────────
            if (nb < MIN_PKT) continue;

            const auto* iph = reinterpret_cast<const struct ip*>(rctx.buf);
            if (iph->ip_v != 4u) continue;

            const int iphlen = iph->ip_hl * 4;
            if (iphlen < 20 || iphlen > 60) continue;
            if (nb < iphlen + static_cast<int>(sizeof(struct icmphdr))) continue;

            const auto* ih = reinterpret_cast<const struct icmphdr*>(
                                 rctx.buf + iphlen);
            const uint8_t type = ih->type;
            const uint8_t code = ih->code;

            // ── Echo reply (type 0, code 0) ─────────────────────────────
            if (type == ICMP_ECHOREPLY && code == 0) {
                if (ntohs(ih->un.echo.id) != ident) continue;

                auto it = ip_to_idx.find(iph->ip_src.s_addr);
                if (it == ip_to_idx.end()) continue;

                size_t idx = it->second;
                if (results[idx].state != IcmpHostState::NoResponse) continue;

                results[idx].state = IcmpHostState::Alive;
                results[idx].rtt_s = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - sweep_start).count();
                hosts_classified++;
                continue;
            }

            auto parse_inner = [&](size_t off_iip,
                                   const struct ip*&      iip_out,
                                   const struct icmphdr*& iicmp_out,
                                   size_t&                tidx_out) -> bool
            {
                if (nb < static_cast<ssize_t>(off_iip + 20u)) return false;
                const auto* iip = reinterpret_cast<const struct ip*>(
                                      rctx.buf + off_iip);
                if (iip->ip_v != 4u) return false;
                const int iiphlen = iip->ip_hl * 4;
                if (iiphlen < 20 || iiphlen > 60) return false;
                const size_t off_iicmp = off_iip + static_cast<size_t>(iiphlen);
                if (nb < static_cast<ssize_t>(off_iicmp + 8u)) return false;
                const auto* iicmp = reinterpret_cast<const struct icmphdr*>(
                                         rctx.buf + off_iicmp);
                if (ntohs(iicmp->un.echo.id) != ident) return false;
                auto it2 = ip_to_idx.find(iip->ip_dst.s_addr);
                if (it2 == ip_to_idx.end()) return false;
                iip_out   = iip;
                iicmp_out = iicmp;
                tidx_out  = it2->second;
                return true;
            };

            const size_t off_inner =
                static_cast<size_t>(iphlen) + sizeof(struct icmphdr);

            if (type == 1 && code == 0) {
                const struct ip*      iip_   = nullptr;
                const struct icmphdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(off_inner, iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;
                results[tidx_].state = IcmpHostState::NoRoute;
                hosts_classified++;
                continue;
            }

            if (type == 11 && (code == 0 || code == 1)) {
                const struct ip*      iip_   = nullptr;
                const struct icmphdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(off_inner, iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;
                results[tidx_].state = (code == 0)
                    ? IcmpHostState::TtlExceeded
                    : IcmpHostState::FragTimeout;
                hosts_classified++;
                continue;
            }

            if (type == 40 && code == 0) {
                const struct ip*      iip_   = nullptr;
                const struct icmphdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(off_inner, iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;
                results[tidx_].state = IcmpHostState::BadSpi;
                hosts_classified++;
                continue;
            }

            if (type == ICMP_DEST_UNREACH) {
                const struct ip*      iip_   = nullptr;
                const struct icmphdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(off_inner, iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;

                switch (code) {
                    case ICMP_NET_UNREACH:   results[tidx_].state = IcmpHostState::NetUnreachable;      break;
                    case ICMP_HOST_UNREACH:  results[tidx_].state = IcmpHostState::Dead;                break;
                    case 2:                  results[tidx_].state = IcmpHostState::ProtoUnreachable;    break;
                    case 4:                  results[tidx_].state = IcmpHostState::FragNeeded;          break;
                    case 5:                  results[tidx_].state = IcmpHostState::SrcRouteFailed;      break;
                    case 6:                  results[tidx_].state = IcmpHostState::NetUnknown;          break;
                    case 7:                  results[tidx_].state = IcmpHostState::HostUnknown;         break;
                    case 8:                  results[tidx_].state = IcmpHostState::SrcHostIsolated;     break;
                    case 9:                  results[tidx_].state = IcmpHostState::NetAdminProhibited;  break;
                    case 10:                 results[tidx_].state = IcmpHostState::HostAdminProhibited; break;
                    case ICMP_PKT_FILTERED:  results[tidx_].state = IcmpHostState::CommAdminProhibited; break;
                    case 14:                 results[tidx_].state = IcmpHostState::HostPrecViolation;   break;
                    default: break;
                }
                if (results[tidx_].state != IcmpHostState::NoResponse)
                    hosts_classified++;
            }
        } // batch loop

        if (need_submit) io_uring_submit(&uring.ring);
    } // CQE drain loop
    for (unsigned s = 0; s < RECV_SLOTS; ++s) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) break;
        io_uring_prep_cancel64(sqe,
            TAG_RECV_HI | static_cast<uint64_t>(s),
            IORING_ASYNC_CANCEL_ANY);
        io_uring_sqe_set_data64(sqe, 0);  // we won't inspect these CQEs
    }
    io_uring_submit(&uring.ring);

    {
        struct __kernel_timespec drain_ts {
            .tv_sec  = 0,
            .tv_nsec = 30'000'000L   // 30 ms
        };
        struct io_uring_cqe* cqe = nullptr;
        while (io_uring_wait_cqe_timeout(&uring.ring, &cqe, &drain_ts) == 0
               && cqe)
        {
            io_uring_cqe_seen(&uring.ring, cqe);
        }
    }
    return results;
}

inline std::vector<IcmpResult> icmp6_ping_sweep(
        const std::vector<std::string>& ips,
        int timeout_ms = 1200)
{
    using namespace icmp_detail;

    std::vector<IcmpResult> results(ips.size());
    for (size_t i = 0; i < ips.size(); ++i)
        results[i].ip = ips[i];

    if (ips.empty()) return results;

    // ── 1. Open ICMPv6 raw socket ─────────────────────────────────────────
    int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) return results;
    struct SockGuard { int fd; ~SockGuard() noexcept { if (fd >= 0) ::close(fd); } } guard{fd};

    {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
            return results;
    }
    { int rcvbuf = 4 * 1024 * 1024; ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }

    {
        int cksum_off = offsetof(struct icmp6_hdr, icmp6_cksum);
        ::setsockopt(fd, IPPROTO_ICMPV6, IPV6_CHECKSUM, &cksum_off, sizeof(cksum_off));
    }

    {
        struct icmp6_filter filt;
        ICMP6_FILTER_SETBLOCKALL(&filt);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY,        &filt);
        ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH,       &filt);
        ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED,     &filt);
        ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG,    &filt);
        ::setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
    }

    // ── 2. IP → result-index lookup map ──────────────────────────────────────
    std::unordered_map<Icmp6Key, size_t, Icmp6KeyHash> ip_to_idx;
    ip_to_idx.reserve(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) {
        struct in6_addr a {};
        if (::inet_pton(AF_INET6, ips[i].c_str(), &a) == 1)
            ip_to_idx.emplace(make_icmp6_key(a), i);   // duplicates: first wins
    }

    // ── 3. io_uring setup ─────────────────────────────────────────────────────
    UringGuard uring(URING_DEPTH);
    if (!uring.ready) return results;

    // ── 4. Heap-allocate I/O contexts ─────────────────────────────────────────
    const size_t n = ips.size();
    auto send_ctxs = std::make_unique<Send6Ctx[]>(n);
    auto recv_ctxs = std::make_unique<Recv6Ctx[]>(RECV_SLOTS);

    // ── 5. PID-bound ICMPv6 identifier ───────────────────────────────────────
    const uint16_t ident = static_cast<uint16_t>(::getpid() & 0xffffu);

    // ── 6. Queue all SENDMSG SQEs; flush in chunks to avoid SQ overflow ───────
    size_t sends_queued = 0;
    auto do_submit = [&]() { if (sends_queued > 0) io_uring_submit(&uring.ring); sends_queued = 0; };

    for (size_t i = 0; i < n; ++i) {
        struct in6_addr a {};
        if (::inet_pton(AF_INET6, ips[i].c_str(), &a) != 1) continue;

        Send6Ctx& ctx = send_ctxs[i];

        ctx.pkt.hdr.icmp6_type       = ICMP6_ECHO_REQUEST;
        ctx.pkt.hdr.icmp6_code       = 0;
        ctx.pkt.hdr.icmp6_cksum      = 0;   // filled by kernel (IPV6_CHECKSUM)
        ctx.pkt.hdr.icmp6_id         = htons(ident);
        ctx.pkt.hdr.icmp6_seq        = htons(static_cast<uint16_t>(i & 0xffffu));

        ctx.dst.sin6_family = AF_INET6;
        ctx.dst.sin6_addr   = a;

        ctx.iov.iov_base = &ctx.pkt;
        ctx.iov.iov_len  = sizeof(ctx.pkt);

        ctx.msg.msg_name    = &ctx.dst;
        ctx.msg.msg_namelen = sizeof(ctx.dst);
        ctx.msg.msg_iov     = &ctx.iov;
        ctx.msg.msg_iovlen  = 1;

        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) {
            do_submit();
            sqe = io_uring_get_sqe(&uring.ring);
            if (!sqe) continue;
        }

        io_uring_prep_sendmsg(sqe, fd, &ctx.msg, 0);
        io_uring_sqe_set_data64(sqe, TAG_SEND_HI | static_cast<uint64_t>(i));
        sends_queued++;
        if (sends_queued % URING_DEPTH == 0) do_submit();
    }
    do_submit();

    // ── 7. Arm initial RECVMSG SQEs ──────────────────────────────────────────
    auto arm_recv = [&](unsigned slot) -> bool {
        if (slot >= RECV_SLOTS) return false;
        Recv6Ctx& r = recv_ctxs[slot];

        r.iov.iov_base = r.buf;
        r.iov.iov_len  = RECV_BUF_SIZE;

        r.msg.msg_name    = &r.src;
        r.msg.msg_namelen = sizeof(r.src);
        r.msg.msg_iov     = &r.iov;
        r.msg.msg_iovlen  = 1;

        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) return false;

        io_uring_prep_recvmsg(sqe, fd, &r.msg, 0);
        io_uring_sqe_set_data64(sqe, TAG_RECV_HI | static_cast<uint64_t>(slot));
        return true;
    };
    for (unsigned s = 0; s < RECV_SLOTS; ++s) arm_recv(s);
    io_uring_submit(&uring.ring);

    // ── 8. CQE drain loop ─────────────────────────────────────────────────────
    const auto sweep_start  = std::chrono::steady_clock::now();
    const auto deadline     = sweep_start + std::chrono::milliseconds(timeout_ms);
    size_t hosts_classified = 0;
    const size_t hosts_n    = ip_to_idx.size();

    while (hosts_classified < hosts_n) {
        auto left_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           deadline - std::chrono::steady_clock::now()).count();
        if (left_ns <= 0) break;

        struct __kernel_timespec ts { .tv_sec = left_ns / 1'000'000'000LL, .tv_nsec = left_ns % 1'000'000'000LL };
        struct io_uring_cqe* cqe = nullptr;
        int ret = io_uring_wait_cqe_timeout(&uring.ring, &cqe, &ts);
        if (ret == -ETIME || ret == -EINTR) break;
        if (ret < 0 || !cqe) continue;

        struct CqeInfo { uint64_t user_data; int32_t bytes; };
        std::array<CqeInfo, 32> batch{};
        size_t n_cqe = 0;
        batch[n_cqe++] = { io_uring_cqe_get_data64(cqe), cqe->res };
        io_uring_cqe_seen(&uring.ring, cqe);

        struct io_uring_cqe* peeked[32];
        unsigned n_peeked = io_uring_peek_batch_cqe(&uring.ring, peeked, 32);
        for (unsigned pi = 0; pi < n_peeked && n_cqe < batch.size(); ++pi) {
            batch[n_cqe++] = { io_uring_cqe_get_data64(peeked[pi]), peeked[pi]->res };
            io_uring_cqe_seen(&uring.ring, peeked[pi]);
        }

        bool need_submit = false;

        for (size_t ci = 0; ci < n_cqe; ++ci) {
            if (hosts_classified >= hosts_n) break;

            const uint64_t ud  = batch[ci].user_data;
            const int32_t  res = batch[ci].bytes;

            if ((ud & TAG_HI_MASK) == TAG_SEND_HI) continue;
            if ((ud & TAG_HI_MASK) != TAG_RECV_HI) continue;

            const unsigned slot = static_cast<unsigned>(ud & 0xFFFF'FFFFu);
            if (slot >= RECV_SLOTS) continue;

            if (arm_recv(slot)) need_submit = true;
            if (res <= 0) continue;

            Recv6Ctx&     rctx = recv_ctxs[slot];
            const ssize_t nb   = static_cast<ssize_t>(res);

            // No outer IPv6 header — data starts at the ICMPv6 header.
            if (nb < MIN_PKT6) continue;

            const auto*   ih   = reinterpret_cast<const struct icmp6_hdr*>(rctx.buf);
            const uint8_t type = ih->icmp6_type;
            const uint8_t code = ih->icmp6_code;

            // ── Echo reply ───────────────────────────────────────────────
            if (type == ICMP6_ECHO_REPLY && code == 0) {
                if (ntohs(ih->icmp6_id) != ident) continue;

                auto it = ip_to_idx.find(make_icmp6_key(rctx.src.sin6_addr));
                if (it == ip_to_idx.end()) continue;

                size_t idx = it->second;
                if (results[idx].state != IcmpHostState::NoResponse) continue;

                results[idx].state = IcmpHostState::Alive;
                results[idx].rtt_s = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - sweep_start).count();
                hosts_classified++;
                continue;
            }

            // ── Error replies embed the original IPv6 header + ICMPv6
            //    echo header we sent, right after the outer ICMPv6 header.
            auto parse_inner = [&](const struct ip6_hdr*&  iip_out,
                                    const struct icmp6_hdr*& iicmp_out,
                                    size_t&                  tidx_out) -> bool
            {
                constexpr size_t off_iip = sizeof(struct icmp6_hdr);
                if (nb < static_cast<ssize_t>(off_iip + sizeof(struct ip6_hdr))) return false;
                const auto* iip = reinterpret_cast<const struct ip6_hdr*>(rctx.buf + off_iip);

                const size_t off_iicmp = off_iip + sizeof(struct ip6_hdr);
                if (nb < static_cast<ssize_t>(off_iicmp + 8u)) return false;
                const auto* iicmp = reinterpret_cast<const struct icmp6_hdr*>(rctx.buf + off_iicmp);

                if (ntohs(iicmp->icmp6_id) != ident) return false;

                auto it2 = ip_to_idx.find(make_icmp6_key(iip->ip6_dst));
                if (it2 == ip_to_idx.end()) return false;

                iip_out   = iip;
                iicmp_out = iicmp;
                tidx_out  = it2->second;
                return true;
            };

            // ── Destination Unreachable (RFC 4443 §3.1) ─────────────────
            if (type == ICMP6_DST_UNREACH) {
                const struct ip6_hdr*   iip_   = nullptr;
                const struct icmp6_hdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;

                switch (code) {
                    case ICMP6_DST_UNREACH_NOROUTE:   results[tidx_].state = IcmpHostState::NoRoute;             break;
                    case ICMP6_DST_UNREACH_ADMIN:     results[tidx_].state = IcmpHostState::CommAdminProhibited; break;
                    case ICMP6_DST_UNREACH_BEYONDSCOPE:results[tidx_].state = IcmpHostState::NetUnreachable;     break;
                    case ICMP6_DST_UNREACH_ADDR:      results[tidx_].state = IcmpHostState::Dead;                break;
                    case ICMP6_DST_UNREACH_NOPORT:    results[tidx_].state = IcmpHostState::ProtoUnreachable;    break;
                    default:                          results[tidx_].state = IcmpHostState::NetUnreachable;     break;
                }
                hosts_classified++;
                continue;
            }

            // ── Time Exceeded (RFC 4443 §3.3) ────────────────────────────
            if (type == ICMP6_TIME_EXCEEDED) {
                const struct ip6_hdr*   iip_   = nullptr;
                const struct icmp6_hdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;
                results[tidx_].state = (code == ICMP6_TIME_EXCEED_TRANSIT)
                    ? IcmpHostState::TtlExceeded
                    : IcmpHostState::FragTimeout;
                hosts_classified++;
                continue;
            }

            // ── Packet Too Big (RFC 4443 §3.2) ───────────────────────────
            if (type == ICMP6_PACKET_TOO_BIG) {
                const struct ip6_hdr*   iip_   = nullptr;
                const struct icmp6_hdr* iicmp_ = nullptr;
                size_t tidx_ = 0;
                if (!parse_inner(iip_, iicmp_, tidx_)) continue;
                if (results[tidx_].state != IcmpHostState::NoResponse) continue;
                results[tidx_].state = IcmpHostState::FragNeeded;
                hosts_classified++;
                continue;
            }
        } // batch loop

        if (need_submit) io_uring_submit(&uring.ring);
    } // CQE drain loop

    for (unsigned s = 0; s < RECV_SLOTS; ++s) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) break;
        io_uring_prep_cancel64(sqe, TAG_RECV_HI | static_cast<uint64_t>(s), IORING_ASYNC_CANCEL_ANY);
        io_uring_sqe_set_data64(sqe, 0);
    }
    io_uring_submit(&uring.ring);
    {
        struct __kernel_timespec drain_ts { .tv_sec = 0, .tv_nsec = 30'000'000L };
        struct io_uring_cqe* cqe = nullptr;
        while (io_uring_wait_cqe_timeout(&uring.ring, &cqe, &drain_ts) == 0 && cqe)
            io_uring_cqe_seen(&uring.ring, cqe);
    }
    return results;
}

inline std::vector<IcmpResult> ndp_neighbor_sweep(
        const std::vector<std::string>& ips,
        const uint8_t src_mac[6],
        int ifindex,
        int timeout_ms = 1200)
{
    using namespace icmp_detail;

    std::vector<IcmpResult> results(ips.size());
    for (size_t i = 0; i < ips.size(); ++i)
        results[i].ip = ips[i];

    if (ips.empty() || ifindex <= 0) return results;

    int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) return results;   // NS/NA needs CAP_NET_RAW, no DGRAM fallback
    struct SockGuard { int fd; ~SockGuard() noexcept { if (fd >= 0) ::close(fd); } } guard{fd};

    {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return results;
    }
    { int rcvbuf = 4 * 1024 * 1024; ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }

    // Kernel-computed ICMPv6 checksum (pseudo-header needs the src addr
    // the kernel picks for this interface/scope).
    {
        int cksum_off = offsetof(struct icmp6_hdr, icmp6_cksum);
        ::setsockopt(fd, IPPROTO_ICMPV6, IPV6_CHECKSUM, &cksum_off, sizeof(cksum_off));
    }

    // RFC 4861 hop-limit-255 requirement — see function comment above.
    {
        int hops = 255;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,   &hops, sizeof(hops));
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
    }

    // Only Neighbor Advertisements are relevant here.
    {
        struct icmp6_filter filt;
        ICMP6_FILTER_SETBLOCKALL(&filt);
        ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filt);
        ::setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
    }

    std::unordered_map<Icmp6Key, size_t, Icmp6KeyHash> ip_to_idx;
    ip_to_idx.reserve(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) {
        struct in6_addr a {};
        if (::inet_pton(AF_INET6, ips[i].c_str(), &a) == 1)
            ip_to_idx.emplace(make_icmp6_key(a), i);
    }

    UringGuard uring(URING_DEPTH);
    if (!uring.ready) return results;

    struct alignas(64) NdpSendCtx {
        struct nd_neighbor_solicit ns {};
        uint8_t   opt_type;
        uint8_t   opt_len;
        uint8_t   opt_mac[6];
        struct sockaddr_in6 dst {};
        struct iovec        iov {};
        struct msghdr       msg {};
    };
    struct alignas(64) NdpRecvCtx {
        char                buf[RECV_BUF_SIZE] {};
        struct sockaddr_in6 src {};
        struct iovec        iov {};
        struct msghdr       msg {};
    };

    const size_t n = ips.size();
    auto send_ctxs = std::make_unique<NdpSendCtx[]>(n);
    auto recv_ctxs = std::make_unique<NdpRecvCtx[]>(RECV_SLOTS);

    size_t sends_queued = 0;
    auto do_submit = [&]() { if (sends_queued > 0) io_uring_submit(&uring.ring); sends_queued = 0; };

    for (size_t i = 0; i < n; ++i) {
        struct in6_addr target {};
        if (::inet_pton(AF_INET6, ips[i].c_str(), &target) != 1) continue;

        NdpSendCtx& ctx = send_ctxs[i];

        ctx.ns.nd_ns_hdr.icmp6_type  = ND_NEIGHBOR_SOLICIT;
        ctx.ns.nd_ns_hdr.icmp6_code  = 0;
        ctx.ns.nd_ns_hdr.icmp6_cksum = 0;   // filled by kernel (IPV6_CHECKSUM)
        ctx.ns.nd_ns_reserved        = 0;
        ctx.ns.nd_ns_target          = target;

        ctx.opt_type = 1;   // ND_OPT_SOURCE_LINKADDR
        ctx.opt_len  = 1;   // length in 8-byte units (1 = 8 bytes total)
        memcpy(ctx.opt_mac, src_mac, 6);

        // Solicited-node multicast: ff02::1:ffXX:XXXX from target's last
        // 3 bytes (RFC 4291 §2.7.1).
        struct in6_addr solicited {};
        solicited.s6_addr[0]  = 0xff; solicited.s6_addr[1]  = 0x02;
        solicited.s6_addr[11] = 0x01; solicited.s6_addr[12] = 0xff;
        solicited.s6_addr[13] = target.s6_addr[13];
        solicited.s6_addr[14] = target.s6_addr[14];
        solicited.s6_addr[15] = target.s6_addr[15];

        ctx.dst.sin6_family   = AF_INET6;
        ctx.dst.sin6_addr     = solicited;
        ctx.dst.sin6_scope_id = static_cast<uint32_t>(ifindex);   // multicast has no route

        ctx.iov.iov_base = &ctx.ns;
        ctx.iov.iov_len  = sizeof(ctx.ns) + sizeof(ctx.opt_type) + sizeof(ctx.opt_len) + sizeof(ctx.opt_mac);
        // ns, opt_type, opt_len, opt_mac are laid out contiguously in the
        // struct (alignas(64) only pads the whole struct's end, not gaps
        // between these particular members) — safe to send as one iovec.

        ctx.msg.msg_name    = &ctx.dst;
        ctx.msg.msg_namelen = sizeof(ctx.dst);
        ctx.msg.msg_iov     = &ctx.iov;
        ctx.msg.msg_iovlen  = 1;

        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) {
            do_submit();
            sqe = io_uring_get_sqe(&uring.ring);
            if (!sqe) continue;
        }

        io_uring_prep_sendmsg(sqe, fd, &ctx.msg, 0);
        io_uring_sqe_set_data64(sqe, TAG_SEND_HI | static_cast<uint64_t>(i));
        sends_queued++;
        if (sends_queued % URING_DEPTH == 0) do_submit();
    }
    do_submit();

    auto arm_recv = [&](unsigned slot) -> bool {
        if (slot >= RECV_SLOTS) return false;
        NdpRecvCtx& r = recv_ctxs[slot];
        r.iov.iov_base = r.buf;
        r.iov.iov_len  = RECV_BUF_SIZE;
        r.msg.msg_name    = &r.src;
        r.msg.msg_namelen = sizeof(r.src);
        r.msg.msg_iov     = &r.iov;
        r.msg.msg_iovlen  = 1;
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) return false;
        io_uring_prep_recvmsg(sqe, fd, &r.msg, 0);
        io_uring_sqe_set_data64(sqe, TAG_RECV_HI | static_cast<uint64_t>(slot));
        return true;
    };
    for (unsigned s = 0; s < RECV_SLOTS; ++s) arm_recv(s);
    io_uring_submit(&uring.ring);

    const auto sweep_start  = std::chrono::steady_clock::now();
    const auto deadline     = sweep_start + std::chrono::milliseconds(timeout_ms);
    size_t hosts_classified = 0;
    const size_t hosts_n    = ip_to_idx.size();

    while (hosts_classified < hosts_n) {
        auto left_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           deadline - std::chrono::steady_clock::now()).count();
        if (left_ns <= 0) break;

        struct __kernel_timespec ts { .tv_sec = left_ns / 1'000'000'000LL, .tv_nsec = left_ns % 1'000'000'000LL };
        struct io_uring_cqe* cqe = nullptr;
        int ret = io_uring_wait_cqe_timeout(&uring.ring, &cqe, &ts);
        if (ret == -ETIME || ret == -EINTR) break;
        if (ret < 0 || !cqe) continue;

        struct CqeInfo { uint64_t user_data; int32_t bytes; };
        std::array<CqeInfo, 32> batch{};
        size_t n_cqe = 0;
        batch[n_cqe++] = { io_uring_cqe_get_data64(cqe), cqe->res };
        io_uring_cqe_seen(&uring.ring, cqe);

        struct io_uring_cqe* peeked[32];
        unsigned n_peeked = io_uring_peek_batch_cqe(&uring.ring, peeked, 32);
        for (unsigned pi = 0; pi < n_peeked && n_cqe < batch.size(); ++pi) {
            batch[n_cqe++] = { io_uring_cqe_get_data64(peeked[pi]), peeked[pi]->res };
            io_uring_cqe_seen(&uring.ring, peeked[pi]);
        }

        bool need_submit = false;

        for (size_t ci = 0; ci < n_cqe; ++ci) {
            if (hosts_classified >= hosts_n) break;

            const uint64_t ud  = batch[ci].user_data;
            const int32_t  res = batch[ci].bytes;

            if ((ud & TAG_HI_MASK) == TAG_SEND_HI) continue;
            if ((ud & TAG_HI_MASK) != TAG_RECV_HI) continue;

            const unsigned slot = static_cast<unsigned>(ud & 0xFFFF'FFFFu);
            if (slot >= RECV_SLOTS) continue;

            if (arm_recv(slot)) need_submit = true;
            if (res <= 0) continue;

            NdpRecvCtx&   rctx = recv_ctxs[slot];
            const ssize_t nb   = static_cast<ssize_t>(res);

            // No outer IPv6 header (AF_INET6/SOCK_RAW strips it) — buffer
            // starts at the NA's icmp6_hdr.
            if (nb < static_cast<ssize_t>(sizeof(struct nd_neighbor_advert))) continue;

            const auto* na = reinterpret_cast<const struct nd_neighbor_advert*>(rctx.buf);
            if (na->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT) continue;

            auto it = ip_to_idx.find(make_icmp6_key(na->nd_na_target));
            if (it == ip_to_idx.end()) continue;

            size_t idx = it->second;
            if (results[idx].state != IcmpHostState::NoResponse) continue;

            results[idx].state = IcmpHostState::Alive;
            results[idx].rtt_s = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - sweep_start).count();
            hosts_classified++;
        } // batch loop

        if (need_submit) io_uring_submit(&uring.ring);
    } // CQE drain loop

    for (unsigned s = 0; s < RECV_SLOTS; ++s) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) break;
        io_uring_prep_cancel64(sqe, TAG_RECV_HI | static_cast<uint64_t>(s), IORING_ASYNC_CANCEL_ANY);
        io_uring_sqe_set_data64(sqe, 0);
    }
    io_uring_submit(&uring.ring);
    {
        struct __kernel_timespec drain_ts { .tv_sec = 0, .tv_nsec = 30'000'000L };
        struct io_uring_cqe* cqe = nullptr;
        while (io_uring_wait_cqe_timeout(&uring.ring, &cqe, &drain_ts) == 0 && cqe)
            io_uring_cqe_seen(&uring.ring, cqe);
    }
    return results;
}

struct SynProbeResult {
    std::string ip;
    bool        alive = false;
};

namespace icmp_detail {

static constexpr std::array<uint16_t, 6> SYN_PROBE_PORTS =
    { 22, 80, 443, 21, 445, 3389 };

// IPv4 pseudo-header for the TCP checksum (RFC 793 §3.1).
struct TcpPseudoHdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

inline uint16_t tcp_checksum(uint32_t src_be, uint32_t dst_be,
                              const struct tcphdr* tcph) noexcept
{
    TcpPseudoHdr ph{};
    ph.src     = src_be;
    ph.dst     = dst_be;
    ph.zero    = 0;
    ph.proto   = IPPROTO_TCP;
    ph.tcp_len = htons(static_cast<uint16_t>(sizeof(struct tcphdr)));

    uint8_t buf[sizeof(ph) + sizeof(struct tcphdr)];
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, sizeof(struct tcphdr));
    return icmp_checksum(buf, sizeof(buf));
}

struct alignas(64) SynSendCtx {
    struct tcphdr      hdr {};
    struct sockaddr_in dst {};
    struct iovec       iov {};
    struct msghdr      msg {};
};

struct alignas(64) SynRecvCtx {
    char                buf[RECV_BUF_SIZE] {};
    struct sockaddr_in  src {};
    struct iovec        iov {};
    struct msghdr       msg {};
};

} 

inline std::vector<SynProbeResult> tcp_syn_probe_sweep(
        const std::vector<std::string>& ips,
        uint32_t local_ip,
        int timeout_ms = 1000)
{
    using namespace icmp_detail;

    std::vector<SynProbeResult> results(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) results[i].ip = ips[i];
    if (ips.empty() || local_ip == 0) return results;

    int sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return results;
    struct SockGuard { int fd; ~SockGuard() noexcept { if (fd >= 0) ::close(fd); } } guard{sock};

    {
        int fl = ::fcntl(sock, F_GETFL, 0);
        if (fl < 0 || ::fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) return results;
    }
    { int rcvbuf = 4 * 1024 * 1024; ::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }

    std::unordered_map<uint32_t, size_t> ip_to_idx;
    ip_to_idx.reserve(ips.size());
    for (size_t i = 0; i < ips.size(); ++i) {
        struct in_addr a{};
        if (::inet_pton(AF_INET, ips[i].c_str(), &a) == 1)
            ip_to_idx.emplace(a.s_addr, i);
    }

    UringGuard uring(URING_DEPTH);
    if (!uring.ready) return results;

    const size_t n_hosts = ips.size();
    const size_t n_ports  = SYN_PROBE_PORTS.size();
    auto send_ctxs = std::make_unique<SynSendCtx[]>(n_hosts * n_ports);
    auto recv_ctxs = std::make_unique<SynRecvCtx[]>(RECV_SLOTS);

    // PID-derived source port + ISN — same anti-cross-contamination /
    // anti-off-path-spoof role as icmp_ping_sweep()'s `ident`.
    const uint16_t src_port = static_cast<uint16_t>(40000 + (::getpid() & 0x1FFF));
    const uint32_t base_seq = 0x1000'0000u ^ static_cast<uint32_t>(::getpid());

    std::vector<bool> host_alive(n_hosts, false);
    size_t hosts_classified = 0;

    size_t sends_queued = 0;
    auto do_submit = [&]() { if (sends_queued > 0) io_uring_submit(&uring.ring); sends_queued = 0; };

    for (size_t i = 0; i < n_hosts; ++i) {
        struct in_addr a{};
        if (::inet_pton(AF_INET, ips[i].c_str(), &a) != 1) continue;

        for (size_t p = 0; p < n_ports; ++p) {
            SynSendCtx& ctx = send_ctxs[i * n_ports + p];

            ctx.hdr.th_sport = htons(src_port);
            ctx.hdr.th_dport = htons(SYN_PROBE_PORTS[p]);
            ctx.hdr.th_seq   = htonl(base_seq);
            ctx.hdr.th_ack   = 0;
            ctx.hdr.th_off   = 5;
            ctx.hdr.th_flags = TH_SYN;
            ctx.hdr.th_win   = htons(64240);
            ctx.hdr.th_sum   = 0;
            ctx.hdr.th_urp   = 0;
            ctx.hdr.th_sum   = tcp_checksum(local_ip, a.s_addr, &ctx.hdr);

            ctx.dst.sin_family = AF_INET;
            ctx.dst.sin_addr   = a;

            ctx.iov.iov_base = &ctx.hdr;
            ctx.iov.iov_len  = sizeof(ctx.hdr);
            ctx.msg.msg_name    = &ctx.dst;
            ctx.msg.msg_namelen = sizeof(ctx.dst);
            ctx.msg.msg_iov     = &ctx.iov;
            ctx.msg.msg_iovlen  = 1;

            struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
            if (!sqe) { do_submit(); sqe = io_uring_get_sqe(&uring.ring); if (!sqe) continue; }

            io_uring_prep_sendmsg(sqe, sock, &ctx.msg, 0);
            io_uring_sqe_set_data64(sqe, TAG_SEND_HI | static_cast<uint64_t>(i * n_ports + p));
            if (++sends_queued % URING_DEPTH == 0) do_submit();
        }
    }
    do_submit();

    auto arm_recv = [&](unsigned slot) -> bool {
        if (slot >= RECV_SLOTS) return false;
        SynRecvCtx& r = recv_ctxs[slot];
        r.iov.iov_base = r.buf;
        r.iov.iov_len  = RECV_BUF_SIZE;
        r.msg.msg_name    = &r.src;
        r.msg.msg_namelen = sizeof(r.src);
        r.msg.msg_iov      = &r.iov;
        r.msg.msg_iovlen   = 1;
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) return false;
        io_uring_prep_recvmsg(sqe, sock, &r.msg, 0);
        io_uring_sqe_set_data64(sqe, TAG_RECV_HI | static_cast<uint64_t>(slot));
        return true;
    };
    for (unsigned s = 0; s < RECV_SLOTS; ++s) arm_recv(s);
    io_uring_submit(&uring.ring);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (hosts_classified < n_hosts) {
        auto left_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           deadline - std::chrono::steady_clock::now()).count();
        if (left_ns <= 0) break;
        struct __kernel_timespec ts { .tv_sec = left_ns / 1'000'000'000LL, .tv_nsec = left_ns % 1'000'000'000LL };
        struct io_uring_cqe* cqe = nullptr;
        int ret = io_uring_wait_cqe_timeout(&uring.ring, &cqe, &ts);
        if (ret == -ETIME || ret == -EINTR) break;
        if (ret < 0 || !cqe) continue;

        struct CqeInfo { uint64_t user_data; int32_t bytes; };
        std::array<CqeInfo, 32> batch{};
        size_t bn = 0;
        batch[bn++] = { io_uring_cqe_get_data64(cqe), cqe->res };
        io_uring_cqe_seen(&uring.ring, cqe);
        struct io_uring_cqe* peeked[32];
        unsigned n_peeked = io_uring_peek_batch_cqe(&uring.ring, peeked, 32);
        for (unsigned pi = 0; pi < n_peeked && bn < batch.size(); ++pi) {
            batch[bn++] = { io_uring_cqe_get_data64(peeked[pi]), peeked[pi]->res };
            io_uring_cqe_seen(&uring.ring, peeked[pi]);
        }

        bool need_submit = false;
        for (size_t ci = 0; ci < bn; ++ci) {
            if (hosts_classified >= n_hosts) break;
            const uint64_t ud  = batch[ci].user_data;
            const int32_t  res = batch[ci].bytes;
            if ((ud & TAG_HI_MASK) == TAG_SEND_HI) continue;
            if ((ud & TAG_HI_MASK) != TAG_RECV_HI) continue;

            const unsigned slot = static_cast<unsigned>(ud & 0xFFFF'FFFFu);
            if (slot >= RECV_SLOTS) continue;
            if (arm_recv(slot)) need_submit = true;
            if (res <= 0) continue;

            SynRecvCtx& rctx = recv_ctxs[slot];
            const ssize_t nb = static_cast<ssize_t>(res);
            if (nb < static_cast<ssize_t>(sizeof(struct ip) + sizeof(struct tcphdr))) continue;

            const auto* iph = reinterpret_cast<const struct ip*>(rctx.buf);
            if (iph->ip_v != 4u) continue;
            const int iphlen = iph->ip_hl * 4;
            if (iphlen < 20 || iphlen > 60) continue;
            if (nb < iphlen + static_cast<int>(sizeof(struct tcphdr))) continue;

            const auto* tcph = reinterpret_cast<const struct tcphdr*>(rctx.buf + iphlen);
            if (ntohs(tcph->th_dport) != src_port) continue;               // not our probe
            if (ntohl(tcph->th_ack) != base_seq + 1) continue;             // anti-spoof check
            const uint8_t flags = tcph->th_flags;
            const bool syn_ack = (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK);
            const bool rst      = (flags & TH_RST) != 0;
            if (!syn_ack && !rst) continue;

            auto it = ip_to_idx.find(iph->ip_src.s_addr);
            if (it == ip_to_idx.end()) continue;
            size_t idx = it->second;
            if (host_alive[idx]) continue;

            host_alive[idx] = true;
            results[idx].alive = true;
            hosts_classified++;
        }
        if (need_submit) io_uring_submit(&uring.ring);
    }

    for (unsigned s = 0; s < RECV_SLOTS; ++s) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&uring.ring);
        if (!sqe) break;
        io_uring_prep_cancel64(sqe, TAG_RECV_HI | static_cast<uint64_t>(s), IORING_ASYNC_CANCEL_ANY);
        io_uring_sqe_set_data64(sqe, 0);
    }
    io_uring_submit(&uring.ring);
    {
        struct __kernel_timespec drain_ts { .tv_sec = 0, .tv_nsec = 30'000'000L };
        struct io_uring_cqe* cqe = nullptr;
        while (io_uring_wait_cqe_timeout(&uring.ring, &cqe, &drain_ts) == 0 && cqe)
            io_uring_cqe_seen(&uring.ring, cqe);
    }
    return results;
}
