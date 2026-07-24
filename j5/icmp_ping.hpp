#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  icmp_ping.hpp  —  io_uring-based ICMP echo sweep
//
//  Design goals
//  ────────────
//  • Minimal syscalls  : all sends batched into one io_uring_submit();
//                        receives drained from CQ without extra poll/recvfrom.
//  • Security hardened : strict packet validation, PID-bound IDENT, inner-ICMP
//                        verification, receive-buffer cap, non-root SOCK_DGRAM
//                        fallback, bounds checks on every pointer cast, and
//                        RAII resource guards (no leaks on early return).
//  • No UB             : every pointer offset is bounds-checked before use.
//  • Self-contained    : single header, no extra link dependency beyond liburing.
//
//  Requirements
//  ────────────
//  Kernel  >= 5.6   (IORING_OP_SENDMSG / IORING_OP_RECVMSG)
//  Library           liburing  (link with -luring)
//  Cap               CAP_NET_RAW  or  kernel >= 5.11 unprivileged ICMP sockets
// ─────────────────────────────────────────────────────────────────────────────

#include <liburing.h>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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
};

// ─── Implementation details (not part of the public API) ─────────────────────

namespace icmp_detail {

// ── Tunable constants ─────────────────────────────────────────────────────────

// io_uring SQ depth (must be a power of two).
static constexpr unsigned URING_DEPTH      = 4096u;

// Maximum hosts we burst-send before we start draining CQEs.
static constexpr size_t   MAX_SEND         = 50'000u;

// Receive buffer size per pending RECVMSG (one Ethernet MTU is sufficient).
static constexpr size_t   RECV_BUF_SIZE    = 1500u;

// Number of RECVMSG SQEs kept armed simultaneously.
static constexpr unsigned RECV_SLOTS       = 512u;

// Minimum valid incoming packet: outer IPv4 header + ICMP header.
static constexpr ssize_t  MIN_PKT          =
    static_cast<ssize_t>(sizeof(struct ip) + sizeof(struct icmphdr));

// User-data tags: high byte encodes the SQE kind so we can route CQEs.
static constexpr uint64_t TAG_SEND_HI = 0x5300'0000'0000'0000ULL;  // 'S'
static constexpr uint64_t TAG_RECV_HI = 0x5200'0000'0000'0000ULL;  // 'R'
static constexpr uint64_t TAG_HI_MASK = 0xFF00'0000'0000'0000ULL;

// ── Utilities ─────────────────────────────────────────────────────────────────

// RFC 792 one's-complement checksum.
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
        // Prefer CAP_NET_RAW; fall back to unprivileged ICMP datagram socket
        // (available since Linux 3.11 when net.ipv4.ping_group_range allows it).
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
        // SINGLE_ISSUER: one thread submits — matches our single-threaded design.
        // We deliberately avoid SQPOLL (needs CAP_SYS_NICE) to stay least-privilege.
        p.flags = IORING_SETUP_SINGLE_ISSUER;
        ready   = (io_uring_queue_init_params(depth, &ring, &p) == 0);
    }
    ~UringGuard() noexcept { if (ready) io_uring_queue_exit(&ring); }

    UringGuard(const UringGuard&)            = delete;
    UringGuard& operator=(const UringGuard&) = delete;
};

// ── Per-send context (must remain valid until its send-CQE arrives) ───────────
// Aligned to avoid any cache-line tearing on concurrent kernel DMA.
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

} // namespace icmp_detail

// ─── Public entry point ───────────────────────────────────────────────────────

/// Sweep @p ips with ICMP echo requests, using io_uring for batched I/O.
///
/// Syscall cost
/// ────────────
///  Old design  : 2 × N  (N × sendto  +  N × poll/recvfrom pairs)
///  This design : ~3–5   (1 submit for all sends, 1 submit to arm recvs,
///                         1 submit to cancel, plus wait-with-timeout calls)
///
/// @param ips        Dotted-decimal IPv4 addresses to probe.
/// @param timeout_ms Milliseconds to collect replies after sends complete.
/// @return           One IcmpResult per input IP, same order as @p ips.
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

    // Non-blocking: io_uring drives the I/O; blocking would stall the kernel
    // io-worker and defeat the whole purpose.
    {
        int fl = ::fcntl(sock.fd, F_GETFL, 0);
        if (fl < 0 || ::fcntl(sock.fd, F_SETFL, fl | O_NONBLOCK) < 0)
            return results;
    }

    // Cap the kernel receive ring to 4 MiB so an adversary flooding us with
    // spoofed replies cannot exhaust address-space (defence-in-depth).
    {
        int rcvbuf = 4 * 1024 * 1024;
        ::setsockopt(sock.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    // Bind to INADDR_ANY — for SOCK_DGRAM ICMP this is required; for SOCK_RAW
    // it is a no-op but harmless.
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

    // ── 4. Heap-allocate I/O contexts ─────────────────────────────────────────
    // unique_ptr guarantees cleanup on any return path (exception-safe).
    const size_t n = ips.size();
    auto send_ctxs = std::make_unique<SendCtx[]>(n);
    auto recv_ctxs = std::make_unique<RecvCtx[]>(RECV_SLOTS);

    // ── 5. PID-bound ICMP identifier ─────────────────────────────────────────
    // Using getpid() means we ignore replies that belong to other processes
    // running concurrent pings — prevents cross-contamination of results.
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

    // ── 8. CQE drain loop ─────────────────────────────────────────────────────
    // Process send- and recv-completions from the same CQ.
    // Exit when the deadline passes or every reachable host has been classified.

    const auto deadline     = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeout_ms);
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

        // EFFICIENCY: drain every completion already sitting in the CQ in
        // one pass, instead of one io_uring_submit() re-arm per packet.
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

    // Drain cancel + straggler CQEs with a short timeout so the kernel has
    // time to acknowledge the cancellations before we call queue_exit().
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

    // UringGuard  destructor → io_uring_queue_exit()
    // RawSocket   destructor → close(fd)
    // unique_ptrs destructor → delete[] send_ctxs, recv_ctxs
    return results;
}
