// async_io.cpp — see async_io.h for the design rationale.

#include "async_io.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <numeric>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "utils.hpp"

extern std::atomic<bool> terminate_flag;

namespace async_io {

namespace {

constexpr int   kMaxResponse   = 65536;
constexpr int   kChunk         = 4096;
constexpr int   kMaxEvents     = 256;
// Ceiling on how long a single epoll_wait() call may block. This used to be
// the FIXED wait every tick (kTickMs, 100ms flat), which meant two things
// were both true and both bad: (a) a shard sitting on a deadline 3ms away
// could still wait up to 100ms to notice it, so probe timeouts were only
// accurate to +/-100ms, and (b) a shard with nothing due for 10 minutes
// still spun a wakeup every 100ms for no reason. next_wait_ms() now computes
// an actual budget from the shard's nearest deadline and only falls back to
// this ceiling when nothing is pending soon (or nothing is in flight at
// all), keeping timeout accounting tight without busy-polling.
constexpr int   kMaxWaitMs     = 250;
// Floor so a deadline that's already essentially "now" doesn't turn into a
// 0ms epoll_wait() (which is a valid poll-and-return-immediately call, but
// looping on that if events also aren't ready yet would busy-spin).
constexpr int   kMinWaitMs     = 1;

// Default adaptive connect-timeout floor: even once RTT samples show a
// target is fast, don't let the computed budget drop below this — real
// networks jitter, and a floor this low still lets a filtered/black-holed
// port fail fast without waiting out a full fixed timeout on every probe.
constexpr int   kDefaultMinConnectMs = 250;
// Multiplier applied to the shard's rolling median connect RTT to get the
// adaptive budget. 4x median absorbs normal jitter while still cutting a
// conservative fixed 3s timeout down substantially once a shard has real
// samples from a responsive network.
constexpr int   kAdaptiveRttMultiplier = 4;
// Need at least this many samples before trusting the rolling median over
// the caller's own fixed timeouts.connect_sec.
constexpr size_t kMinRttSamplesForAdaptive = 5;

const char* kDefaultTls12Ciphers =
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256";

#if defined(TLS1_3_VERSION)
const char* kDefaultTls13Ciphersuites =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";
#endif

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Build a connected-or-in-progress non-blocking socket. Mirrors the address
// resolution logic of the old connect_with_timeout(), minus the blocking
// poll() at the end — the reactor itself waits for writability.
//
// src_port: SourcePort::Mode::FIXED binds the socket to a specific local
// port (e.g. 443) before connect(), for the last-resort fallback path
// described in async_io.h. This is NOT used by normal probes. When binding
// fails, `bind_errno` carries the errno (EACCES => no CAP_NET_BIND_SERVICE,
// EADDRINUSE => another connection is already holding that 4-tuple) so the
// caller can tell "no permission for this trick" apart from "target down".
int start_nonblocking_connect(const std::string& ip, int port,
                               const SourcePort& src_port,
                               bool& in_progress, int& bind_errno) {
    in_progress = false;
    bind_errno = 0;

    struct sockaddr_storage addr_storage{};
    socklen_t addr_len = 0;
    int family = make_sockaddr_from_ip(ip, static_cast<uint16_t>(port), addr_storage, addr_len);
    if (addr_len == 0) return -1;

    int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    // These are best-effort tuning, not correctness-critical, so a failure
    // here doesn't abort the connect -- but silently swallowing it made a
    // real SO_REUSEPORT failure (below) invisible when it mattered. Log and
    // keep going.
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[async_io] SO_KEEPALIVE failed for fd %d: %s\n", fd, strerror(errno));
    }
#ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[async_io] TCP_NODELAY failed for fd %d: %s\n", fd, strerror(errno));
    }
#endif

    if (src_port.mode == SourcePort::Mode::FIXED) {
        // Both flags are set defensively: SO_REUSEADDR lets us rebind a
        // 4-tuple that's sitting in TIME_WAIT from a previous fallback
        // attempt; SO_REUSEPORT (where available) additionally lets two
        // *sockets* share the exact port if the kernel allows it. Neither
        // one bypasses the fundamental one-4-tuple-at-a-time constraint —
        // callers using FIXED must still serialize (see async_io.h).
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            fprintf(stderr, "[async_io] SO_REUSEADDR failed for fd %d (src_port=%u): %s\n",
                    fd, src_port.port, strerror(errno));
        }
#ifdef SO_REUSEPORT
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
            // Not fatal by itself -- SO_REUSEADDR above is usually enough to
            // let a TIME_WAIT'd 4-tuple be rebound. But this is exactly the
            // kind of silent degradation that made the FIXED-source-port
            // retry logic in begin_connect() hard to trust; surface it.
            fprintf(stderr, "[async_io] SO_REUSEPORT failed for fd %d (src_port=%u): %s\n",
                    fd, src_port.port, strerror(errno));
        }
#endif
        struct sockaddr_storage bind_storage{};
        socklen_t bind_len = 0;
        if (family == AF_INET) {
            auto* b4 = reinterpret_cast<struct sockaddr_in*>(&bind_storage);
            b4->sin_family      = AF_INET;
            b4->sin_addr.s_addr = INADDR_ANY;
            b4->sin_port        = htons(src_port.port);
            bind_len = sizeof(struct sockaddr_in);
        } else {
            auto* b6 = reinterpret_cast<struct sockaddr_in6*>(&bind_storage);
            b6->sin6_family = AF_INET6;
            b6->sin6_addr   = in6addr_any;
            b6->sin6_port   = htons(src_port.port);
            bind_len = sizeof(struct sockaddr_in6);
        }
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&bind_storage), bind_len) < 0) {
            bind_errno = errno; // EACCES (no privilege) or EADDRINUSE (in use) are expected/handled
            close(fd);
            return -1;
        }
    }

    if (set_nonblocking(fd) < 0) {
        int nb_errno = errno;
        close(fd);
        errno = nb_errno;
        return -1;
    }

    int rc;
    for (;;) {
        rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr_storage), addr_len);
        if (rc == 0 || errno != EINTR) break;
        // connect() was interrupted by a signal before the kernel could
        // decide anything -- POSIX says retry it like any other EINTR'd
        // syscall. Previously this fell straight into the generic failure
        // branch below and got reported as CONNECT_FAILED even though the
        // target might be perfectly reachable.
    }
    if (rc == 0) {
        in_progress = false; // connected immediately (rare, e.g. loopback)
        return fd;
    }
    if (errno == EINPROGRESS) {
        in_progress = true;
        return fd;
    }
    int connect_errno = errno; // capture before close() can touch errno
    bind_errno = 0;            // this is a connect() failure, not a bind() failure
    close(fd);
    errno = connect_errno;
    return -1;
}

SSL_CTX* build_ssl_ctx(const TlsOptions& tls, bool verbose_unused) {
    (void)verbose_unused;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif

    const char* c12 = tls.cipher_list_tls12.empty() ? kDefaultTls12Ciphers
                                                      : tls.cipher_list_tls12.c_str();
    SSL_CTX_set_cipher_list(ctx, c12);

#if defined(TLS1_3_VERSION) && defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L
    const char* c13 = tls.ciphersuites_tls13.empty() ? kDefaultTls13Ciphersuites
                                                       : tls.ciphersuites_tls13.c_str();
    SSL_CTX_set_ciphersuites(ctx, c13);
#endif

    if (!tls.ca_file.empty() || !tls.ca_path.empty()) {
        const char* f = tls.ca_file.empty() ? nullptr : tls.ca_file.c_str();
        const char* p = tls.ca_path.empty() ? nullptr : tls.ca_path.c_str();
        SSL_CTX_load_verify_locations(ctx, f, p);
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    if (tls.verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    if (!tls.client_cert.empty() && !tls.client_key.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, tls.client_cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, tls.client_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    return ctx;
}

} // namespace

// PERF: process-wide SSL_CTX cache, keyed by everything that actually
// affects the resulting context. SNI is deliberately excluded — it's
// applied per-connection via SSL_set_tlsext_host_name() on the SSL*, not
// baked into the SSL_CTX. Without this, every capture_ssl() call (the
// upfront ssl_port_check() precheck run on EVERY non-sslports port, plus
// every strict/permissive/redirect attempt on real TLS ports) rebuilt a
// full SSL_CTX from scratch, including re-parsing the system CA store
// via SSL_CTX_set_default_verify_paths() every single time.
//
// SSL_CTX is documented thread-safe for concurrent SSL_new() once built,
// so handing the same cached pointer to many concurrent Operations is
// safe as long as nothing mutates it after construction (it doesn't).
std::mutex g_ssl_ctx_cache_mu;
std::unordered_map<std::string, SSL_CTX*> g_ssl_ctx_cache;

std::string ssl_ctx_cache_key(const TlsOptions& tls) {
    return tls.ca_file + "\x1f" + tls.ca_path + "\x1f" +
           tls.client_cert + "\x1f" + tls.client_key + "\x1f" +
           tls.cipher_list_tls12 + "\x1f" + tls.ciphersuites_tls13 + "\x1f" +
           (tls.verify_peer ? "1" : "0");
}

SSL_CTX* get_or_build_ssl_ctx(const TlsOptions& tls) {
    std::string key = ssl_ctx_cache_key(tls);
    std::lock_guard<std::mutex> lock(g_ssl_ctx_cache_mu);
    auto it = g_ssl_ctx_cache.find(key);
    if (it != g_ssl_ctx_cache.end()) return it->second;
    SSL_CTX* ctx = build_ssl_ctx(tls, false);
    if (ctx) g_ssl_ctx_cache.emplace(key, ctx);
    return ctx;
}

// ===========================================================================
// Reactor
// ===========================================================================

Reactor::Reactor(unsigned num_threads) {
    if (num_threads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        num_threads = hw == 0 ? 2 : std::clamp(hw, 2u, 8u);
    }
    static bool ssl_lib_init_done = false;
    if (!ssl_lib_init_done) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_lib_init_done = true;
    }

    shards_.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i) {
        auto shard = std::make_unique<EpollShard>();
        shard->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        shards_.push_back(std::move(shard));
    }
    rtt_samples_ms_.resize(num_threads);
    threads_.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i) {
        threads_.emplace_back([this, i] { worker_loop(*shards_[i]); });
    }
}

Reactor::~Reactor() {
    shutdown();
}

void Reactor::shutdown() {
    if (stop_.exchange(true)) return; // already shutting down
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    for (auto& shard : shards_) {
        if (shard->epoll_fd >= 0) close(shard->epoll_fd);
    }
}

void Reactor::submit(OperationPtr op) {
    if (!op) return;
    size_t idx = next_shard_.fetch_add(1, std::memory_order_relaxed) % shards_.size();
    op->owning_epoll_idx_ = static_cast<int>(idx);
    op->submit_time_ = Clock::now();
    EpollShard& shard = *shards_[idx];
    begin_connect(shard, std::move(op));
}

// ---------------------------------------------------------------------
// Deadline bookkeeping
// ---------------------------------------------------------------------
// set_deadline() is the ONLY place that should write op->stage_deadline_.
// It keeps shard.deadlines (the multimap driving sweep_timeouts() and
// next_wait_ms()) consistent with the field. Caller must hold shard.mu.
void Reactor::set_deadline(EpollShard& shard, OperationPtr& op, Clock::duration budget) {
    // Drop the stale index entry, if this op already had one (i.e. this is
    // a stage transition, not the very first deadline set for this op).
    if (op->stage_deadline_.time_since_epoch().count() != 0) {
        auto range = shard.deadlines.equal_range(op->stage_deadline_);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == op->fd_) { shard.deadlines.erase(it); break; }
        }
    }
    op->stage_deadline_ = Clock::now() + budget;
    shard.deadlines.emplace(op->stage_deadline_, op->fd_);
}

Clock::duration Reactor::adaptive_connect_budget(EpollShard& /*shard*/, const Operation& op) const {
    int fixed_ms = std::max(1, op.timeouts.connect_sec) * 1000;
    int floor_ms = op.timeouts.min_connect_ms > 0 ? op.timeouts.min_connect_ms
                                                    : kDefaultMinConnectMs;

    if (op.owning_epoll_idx_ < 0 ||
        static_cast<size_t>(op.owning_epoll_idx_) >= rtt_samples_ms_.size()) {
        return std::chrono::milliseconds(fixed_ms);
    }

    // Caller (begin_connect) holds shard.mu for this entire call, which is
    // the same lock step_connecting() takes before touching
    // rtt_samples_ms_[idx] — see the NOTE there for why that lock is
    // required (samples can be written from either the submitting thread or
    // a shard worker thread depending on whether connect() completed
    // synchronously or asynchronously).
    const auto& samples = rtt_samples_ms_[op.owning_epoll_idx_];
    if (samples.size() < kMinRttSamplesForAdaptive) {
        return std::chrono::milliseconds(fixed_ms);
    }

    std::vector<int64_t> sorted(samples.begin(), samples.end());
    std::sort(sorted.begin(), sorted.end());
    int64_t median = sorted[sorted.size() / 2];

    int64_t adaptive_ms = median * kAdaptiveRttMultiplier;
    adaptive_ms = std::clamp<int64_t>(adaptive_ms, floor_ms, fixed_ms);
    return std::chrono::milliseconds(adaptive_ms);
}

int Reactor::next_wait_ms(EpollShard& shard) const {
    std::lock_guard<std::mutex> lock(shard.mu);
    if (shard.deadlines.empty()) return kMaxWaitMs;
    auto soonest = shard.deadlines.begin()->first;
    auto now = Clock::now();
    if (soonest <= now) return kMinWaitMs; // already due — return fast, sweep will catch it
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(soonest - now).count();
    return static_cast<int>(std::clamp<int64_t>(ms, kMinWaitMs, kMaxWaitMs));
}

void Reactor::begin_connect(EpollShard& shard, OperationPtr op) {
    // UDP is not yet wired through this reactor -- start_nonblocking_connect()
    // always builds a SOCK_STREAM socket and calls connect() on it, which is
    // meaningless for datagram sockets. UDP needs its own stage (one
    // sendto()/recvfrom() pair, no connect()-handshake edge to wait on)
    // rather than reusing the TCP state machine; see control.cpp's
    // capture_udp(), which stays on its own blocking socket for now. Fail
    // loudly here instead of silently mis-handling it as TCP.
    if (op->proto == Proto::UDP) {
        op->last_errno = EPROTONOSUPPORT;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }

    bool in_progress = false;
    int bind_errno = 0;
    int fd = -1;

    // A FIXED source port (see async_io.h's SourcePort docs) shares one
    // local-port 4-tuple across every caller that uses it, so a still-live
    // TIME_WAIT entry left by the immediately preceding connection on that
    // same port can make bind() fail with EADDRINUSE even though the target
    // itself would otherwise respond fine. That's a transient collision, not
    // a genuine "can't reach this port" outcome, so retry it a bounded
    // number of times with a short backoff instead of reporting
    // CONNECT_FAILED on the first hit.
    //
    // This is centralized here (rather than duplicated in every capture_*
    // call site in control.cpp) so ALL reactor-based FIXED-source-port
    // operations get the same protection -- both the direct HTTP/HTTPS/NULL
    // probe fallback (Tier 3) and the full replayed probe cycle (Tier 4),
    // which calls capture_tcp()/capture_ssl() many times over per port.
    //
    // Safe to block here: submit() -> begin_connect() runs synchronously on
    // the CALLING thread, not a reactor worker thread, so sleeping doesn't
    // stall any other in-flight operation on this shard. FIXED-source-port
    // callers are already required to serialize themselves (see
    // async_io.h), so there is at most one such retry loop running at a
    // time process-wide.
    constexpr int kFixedPortBindMaxRetries   = 3;
    constexpr int kFixedPortBindRetryDelayMs = 150;

    int connect_errno = 0;

    for (int attempt = 0;; ++attempt) {
        fd = start_nonblocking_connect(op->ip, op->port, op->src_port, in_progress, bind_errno);
        if (fd >= 0) break;

        // Capture immediately -- start_nonblocking_connect() sets errno
        // right before returning -1, and nothing runs between that return
        // and this line that could clobber it.
        connect_errno = errno;

        // Two distinct transient collisions occur with a FIXED source port,
        // and both are retryable:
        //  - EADDRINUSE at bind()       -- another connection still holds
        //    the local port itself.
        //  - EADDRNOTAVAIL at connect() -- bind() succeeded, but the kernel
        //    refuses to let the same local port reconnect to the exact same
        //    remote ip:port while a TIME_WAIT entry from the immediately
        //    preceding attempt to THAT SAME target is still alive.
        bool retryable = (op->src_port.mode == SourcePort::Mode::FIXED &&
                          (bind_errno == EADDRINUSE ||
                           (bind_errno == 0 && connect_errno == EADDRNOTAVAIL)) &&
                          attempt < kFixedPortBindMaxRetries);
        if (!retryable) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(kFixedPortBindRetryDelayMs));
    }

    if (fd < 0) {
        op->last_errno = bind_errno != 0 ? bind_errno : connect_errno;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }
    op->fd_ = fd;
    op->stage_ = Operation::Stage::CONNECTING;

    {
        std::lock_guard<std::mutex> lock(shard.mu);
        shard.ops[fd] = op;
        set_deadline(shard, op, adaptive_connect_budget(shard, *op));
    }

    if (!in_progress) {
        // Connected synchronously (loopback etc.) — proceed straight to the
        // next stage on this thread; still safe since op isn't registered
        // with epoll yet for this transition.
        step_connecting(shard, op);
        return;
    }
    arm(shard, op, /*want_write=*/true);
}

void Reactor::arm(EpollShard& shard, OperationPtr op, bool want_write) {
    // CRITICAL ORDERING: every write to `op` for this stage transition must
    // land BEFORE epoll_ctl() registers/rearms the fd. The instant epoll_ctl
    // returns, another worker thread's epoll_wait() can observe the fd ready
    // and start mutating the same `op` (e.g. via advance()/step_*). If we
    // wrote to `op` after epoll_ctl(), that write races with the other
    // thread's read/write of the same object — confirmed via ThreadSanitizer
    // during development. Keeping the field write first (and epoll_ctl last)
    // establishes a clean single-owner-at-a-time handoff instead.
    op->armed_write_ = want_write;

    struct epoll_event ev{};
    ev.events = want_write ? (EPOLLOUT | EPOLLRDHUP) : (EPOLLIN | EPOLLRDHUP);
    ev.data.fd = op->fd_;

    int rc = epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, op->fd_, &ev);
    if (rc < 0 && errno == EEXIST) {
        rc = epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, op->fd_, &ev);
    }
    if (rc < 0) {
        // Anything other than the expected ADD->EEXIST->MOD fallback above
        // is a real failure (EBADF, ENOMEM, ENOSPC, ...). Previously this
        // was silently ignored: the op stayed registered nowhere and just
        // sat until sweep_timeouts() eventually timed it out, turning a
        // hard failure into a slow, misleading TIMEOUT/CONNECT_FAILED with
        // no indication of what actually went wrong. Fail it immediately
        // instead, with the real errno attached.
        int arm_errno = errno;
        fprintf(stderr, "[async_io] epoll_ctl failed for fd %d: %s\n",
                op->fd_, strerror(arm_errno));
        op->last_errno = arm_errno;
        switch (op->stage_) {
            case Operation::Stage::CONNECTING:
                finish(shard, op, OpResult::CONNECT_FAILED);
                break;
            case Operation::Stage::TLS_HANDSHAKE:
                finish(shard, op, OpResult::TLS_FAILED);
                break;
            case Operation::Stage::SENDING:
                finish(shard, op, OpResult::SEND_FAILED);
                break;
            case Operation::Stage::RECV_FIRST:
            case Operation::Stage::RECV_IDLE:
                finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
                break;
            default:
                break;
        }
    }
}

void Reactor::worker_loop(EpollShard& shard) {
    std::vector<struct epoll_event> events(kMaxEvents);
    while (!stop_.load(std::memory_order_relaxed)) {
        int wait_ms = next_wait_ms(shard);
        int n = epoll_wait(shard.epoll_fd, events.data(), kMaxEvents, wait_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            OperationPtr op;
            {
                std::lock_guard<std::mutex> lock(shard.mu);
                auto it = shard.ops.find(fd);
                if (it == shard.ops.end()) continue; // already finished/removed
                op = it->second;
            }
            advance(shard, op, events[i].events);
        }
        sweep_timeouts(shard);
    }

    // Reactor is stopping: fail out anything still in flight.
    std::vector<OperationPtr> remaining;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        for (auto& [fd, op] : shard.ops) remaining.push_back(op);
    }
    for (auto& op : remaining) finish(shard, op, OpResult::CANCELLED);
}

void Reactor::sweep_timeouts(EpollShard& shard) {
    auto now = Clock::now();
    std::vector<OperationPtr> expired;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        // shard.deadlines is ordered, so we only ever need to look at the
        // front: walk forward from begin() while entries are due, stop at
        // the first one that isn't. This replaces the old full scan over
        // every in-flight op on every single tick (O(in-flight) per tick,
        // regardless of how many were actually close to expiring) with
        // O(expired) work, which matters once hundreds of ports are in
        // flight on a shard simultaneously.
        auto it = shard.deadlines.begin();
        while (it != shard.deadlines.end() && it->first <= now) {
            auto op_it = shard.ops.find(it->second);
            if (op_it != shard.ops.end()) expired.push_back(op_it->second);
            it = shard.deadlines.erase(it);
        }
    }
    for (auto& op : expired) {
        switch (op->stage_) {
            case Operation::Stage::CONNECTING:
                finish(shard, op, OpResult::CONNECT_FAILED);
                break;
            case Operation::Stage::TLS_HANDSHAKE:
                finish(shard, op, OpResult::TLS_FAILED);
                break;
            case Operation::Stage::SENDING:
                finish(shard, op, OpResult::SEND_FAILED);
                break;
            case Operation::Stage::RECV_FIRST:
                // No data ever arrived within first_byte_sec — same
                // "filtered/no response" outcome the old code treated as an
                // empty result, not a hard error.
                finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
                break;
            case Operation::Stage::RECV_IDLE:
                // Had at least one byte, then idle timeout elapsed — this is
                // success with whatever we accumulated (mirrors old
                // recv_all_tcp()/capture_ssl() "close on idle" behavior).
                finish(shard, op, OpResult::SUCCESS);
                break;
            default:
                break;
        }
    }
}

void Reactor::advance(EpollShard& shard, OperationPtr op, uint32_t events) {
    if (events & (EPOLLERR | EPOLLHUP)) {
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen);
        op->last_errno = err;
        switch (op->stage_) {
            case Operation::Stage::CONNECTING:    finish(shard, op, OpResult::CONNECT_FAILED); return;
            case Operation::Stage::TLS_HANDSHAKE: finish(shard, op, OpResult::TLS_FAILED);      return;
            case Operation::Stage::SENDING:       finish(shard, op, OpResult::SEND_FAILED);     return;
            default:
                // EPOLLHUP during recv with data already collected is a
                // normal "peer closed" — treat like a clean EOF.
                finish(shard, op, op->recv_data.empty() ? OpResult::CONNECT_FAILED : OpResult::SUCCESS);
                return;
        }
    }

    switch (op->stage_) {
        case Operation::Stage::CONNECTING:    step_connecting(shard, op);   break;
        case Operation::Stage::TLS_HANDSHAKE:  step_tls_handshake(shard, op); break;
        case Operation::Stage::SENDING:       step_sending(shard, op);     break;
        case Operation::Stage::RECV_FIRST:    step_recv(shard, op, true);  break;
        case Operation::Stage::RECV_IDLE:     step_recv(shard, op, false); break;
        case Operation::Stage::DONE:          break;
    }
}

void Reactor::step_connecting(EpollShard& shard, OperationPtr op) {
    int err = 0; socklen_t elen = sizeof(err);
    if (getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
        op->last_errno = err;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }

    // Connection is up: record RTT (submit -> now) both on the op, for
    // callers/logging, and into this shard's rolling sample window, which
    // feeds adaptive_connect_budget() for subsequent connects on this shard.
    //
    // NOTE on locking: step_connecting() can run either on the ORIGINAL
    // calling thread (when start_nonblocking_connect() connects
    // synchronously, e.g. loopback — begin_connect() calls straight through
    // to here) or on a shard worker thread (the normal EINPROGRESS ->
    // epoll-notifies-writable path). Two different callers' threads can
    // therefore genuinely race on rtt_samples_ms_[idx] here, so this must be
    // guarded by shard.mu — the same lock adaptive_connect_budget() is read
    // under from begin_connect(). Do not remove this lock.
    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - op->submit_time_);
    op->connect_rtt = rtt;
    if (op->owning_epoll_idx_ >= 0 &&
        static_cast<size_t>(op->owning_epoll_idx_) < rtt_samples_ms_.size()) {
        std::lock_guard<std::mutex> lock(shard.mu);
        auto& samples = rtt_samples_ms_[op->owning_epoll_idx_];
        samples.push_back(rtt.count());
        if (samples.size() > kRttSampleWindow) samples.pop_front();
    }

    if (op->proto == Proto::TLS) {
        op->ssl_ctx_ = get_or_build_ssl_ctx(op->tls);
        if (!op->ssl_ctx_) { finish(shard, op, OpResult::TLS_FAILED); return; }
        op->ssl_ = SSL_new(op->ssl_ctx_);
        if (!op->ssl_) { finish(shard, op, OpResult::TLS_FAILED); return; }
        SSL_set_fd(op->ssl_, op->fd_);
        const std::string& sni = op->tls.sni.empty() ? op->ip : op->tls.sni;
        SSL_set_tlsext_host_name(op->ssl_, sni.c_str());
        if (op->tls.verify_peer) {
            X509_VERIFY_PARAM* param = SSL_get0_param(op->ssl_);
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            X509_VERIFY_PARAM_set1_host(param, sni.c_str(), 0);
        }
        op->stage_ = Operation::Stage::TLS_HANDSHAKE;
        {
            std::lock_guard<std::mutex> lock(shard.mu);
            // Reuse the connect timeout as the handshake budget's starting
            // point; extend it slightly since handshake is a few extra RTTs.
            set_deadline(shard, op, std::chrono::seconds(std::max(op->timeouts.connect_sec, 3)));
        }
        step_tls_handshake(shard, op);
        return;
    }

    // Plain TCP: go straight to sending (or receiving, if no payload).
    op->stage_ = Operation::Stage::SENDING;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        set_deadline(shard, op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
    }
    step_sending(shard, op);
}

void Reactor::step_tls_handshake(EpollShard& shard, OperationPtr op) {
    int rc = SSL_connect(op->ssl_);
    if (rc == 1) {
        op->stage_ = Operation::Stage::SENDING;
        {
            std::lock_guard<std::mutex> lock(shard.mu);
            set_deadline(shard, op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
        }
        step_sending(shard, op);
        return;
    }
    int sslerr = SSL_get_error(op->ssl_, rc);
    op->last_ssl_error = sslerr;
    if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
    if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
    ERR_clear_error();
    finish(shard, op, OpResult::TLS_FAILED);
}

void Reactor::step_sending(EpollShard& shard, OperationPtr op) {
    if (op->send_payload.empty()) {
        op->stage_ = Operation::Stage::RECV_FIRST;
        {
            std::lock_guard<std::mutex> lock(shard.mu);
            set_deadline(shard, op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
        }
        arm(shard, op, false);
        return;
    }

    while (op->sent_ < op->send_payload.size()) {
        const u8* base = op->send_payload.data() + op->sent_;
        size_t remain = op->send_payload.size() - op->sent_;

        if (op->proto == Proto::TLS) {
            int n = SSL_write(op->ssl_, base, static_cast<int>(remain));
            if (n > 0) { op->sent_ += static_cast<size_t>(n); continue; }
            int sslerr = SSL_get_error(op->ssl_, n);
            op->last_ssl_error = sslerr;
            if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
            if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
            ERR_clear_error();
            finish(shard, op, OpResult::SEND_FAILED);
            return;
        } else {
            ssize_t n = ::send(op->fd_, base, remain, 0);
            if (n > 0) { op->sent_ += static_cast<size_t>(n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { arm(shard, op, true); return; }
            op->last_errno = errno;
            finish(shard, op, OpResult::SEND_FAILED);
            return;
        }
    }

    op->stage_ = Operation::Stage::RECV_FIRST;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        set_deadline(shard, op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
    }
    arm(shard, op, false);
}

void Reactor::step_recv(EpollShard& shard, OperationPtr op, bool is_recv_first) {
    (void)is_recv_first;
    char buf[kChunk];
    // 0 => caller didn't set a per-Operation cap; fall back to the shared
    // default. See Operation::max_response_bytes in async_io.h.
    const size_t response_cap = op->max_response_bytes > 0
                                     ? op->max_response_bytes
                                     : static_cast<size_t>(kMaxResponse);

    for (;;) {
        if (op->recv_data.size() >= response_cap) {
            finish(shard, op, OpResult::SUCCESS);
            return;
        }

        if (op->proto == Proto::TLS) {
            int n = SSL_read(op->ssl_, buf, sizeof(buf));
            if (n > 0) {
                op->recv_data.insert(op->recv_data.end(), buf, buf + n);
                if (op->stage_ == Operation::Stage::RECV_FIRST) {
                    op->stage_ = Operation::Stage::RECV_IDLE;
                    int idle = op->timeouts.idle_sec > 0
                                   ? op->timeouts.idle_sec
                                   : std::max(2, op->timeouts.first_byte_sec / 2);
                    std::lock_guard<std::mutex> lock(shard.mu);
                    set_deadline(shard, op, std::chrono::seconds(idle));
                }
                continue; // drain further already-buffered TLS records without re-arming
            }
            int sslerr = SSL_get_error(op->ssl_, n);
            op->last_ssl_error = sslerr;
            if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
            if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
            // SSL_ERROR_ZERO_RETURN or SSL_ERROR_SSL/SYSCALL: treat as end
            // of response — matches old capture_ssl() behavior of breaking
            // out of the read loop on any non-positive SSL_read().
            ERR_clear_error();
            finish(shard, op, OpResult::SUCCESS);
            return;
        } else {
            ssize_t n = ::recv(op->fd_, buf, sizeof(buf), 0);
            if (n > 0) {
                op->recv_data.insert(op->recv_data.end(), buf, buf + n);
                if (op->stage_ == Operation::Stage::RECV_FIRST) {
                    // Previously returned immediately after the first
                    // successful recv(). That's wrong for services (e.g.
                    // telnetd) that send option negotiation/banner in
                    // separate segments with a real gap between them — the
                    // first recv() only ever captured the negotiation bytes.
                    // Switch to RECV_IDLE and keep draining, same as the TLS
                    // branch above, so a delayed second write still gets in.
                    op->stage_ = Operation::Stage::RECV_IDLE;
                    int idle = op->timeouts.idle_sec > 0
                                   ? op->timeouts.idle_sec
                                   : std::max(2, op->timeouts.first_byte_sec / 2);
                    std::lock_guard<std::mutex> lock(shard.mu);
                    set_deadline(shard, op, std::chrono::seconds(idle));
                }
                continue;
            }
            if (n == 0) { finish(shard, op, OpResult::SUCCESS); return; } // peer closed
            if (errno == EAGAIN || errno == EWOULDBLOCK) { arm(shard, op, false); return; }
            op->last_errno = errno;
            finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
            return;
        }
    }
}

void Reactor::close_and_free_tls(OperationPtr op) {
    if (op->ssl_) {
        SSL_shutdown(op->ssl_);
        SSL_free(op->ssl_);
        op->ssl_ = nullptr;
    }
    // PERF: op->ssl_ctx_ now points into the process-wide cache built by
    // get_or_build_ssl_ctx() and is shared across every Operation using
    // the same TLS options -- it must NOT be freed here. The cache owns
    // it for the process's lifetime; just drop the per-Operation pointer.
    op->ssl_ctx_ = nullptr;
}

void Reactor::finish(EpollShard& shard, OperationPtr op, OpResult r) {
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        auto it = shard.ops.find(op->fd_);
        if (it != shard.ops.end()) shard.ops.erase(it);
        // Also drop this op's entry from the deadline index so a stale
        // pointer can't linger in shard.deadlines after the fd is reused by
        // a later socket() call (which would otherwise let sweep_timeouts()
        // find the WRONG op under an old fd number and misfire on it).
        if (op->stage_deadline_.time_since_epoch().count() != 0) {
            auto range = shard.deadlines.equal_range(op->stage_deadline_);
            for (auto dit = range.first; dit != range.second; ++dit) {
                if (dit->second == op->fd_) { shard.deadlines.erase(dit); break; }
            }
        }
    }
    if (op->fd_ >= 0) {
        epoll_ctl(shard.epoll_fd, EPOLL_CTL_DEL, op->fd_, nullptr);
    }

    op->result.store(r, std::memory_order_release);
    op->ssl_handle = op->ssl_; // expose for the completion callback (cert extraction etc.)

    op->stage_ = Operation::Stage::DONE;

    if (op->on_complete) {
        op->on_complete(*op);
    }

    op->ssl_handle = nullptr;
    close_and_free_tls(op);
    if (op->fd_ >= 0) { close(op->fd_); op->fd_ = -1; }
}

// ===========================================================================
// run_blocking()
// ===========================================================================

Bytes run_blocking(Reactor& reactor, OperationPtr op) {
    // OneShotSignal (async_io.h) is futex-backed directly via
    // atomic::wait()/notify_all() — no separate mutex lock/unlock pair
    // around the completion flag, unlike the old mutex+condition_variable
    // pairing this replaces. Every run_blocking() call now costs exactly
    // one FUTEX_WAIT (this thread) + one FUTEX_WAKE (the reactor thread
    // that completes the op), and nothing else. Behavior is otherwise
    // unchanged: the caller's original on_complete (if any) still fires
    // first, and this still returns op->recv_data once complete.
    auto sig = std::make_shared<OneShotSignal>();

    auto user_cb = op->on_complete;
    op->on_complete = [sig, user_cb](Operation& o) {
        if (user_cb) user_cb(o);
        sig->signal();
    };

    reactor.submit(op);
    if (!sig->wait_interruptible([]{
            return terminate_flag.load(std::memory_order_relaxed);
        })) {
        // Interrupted (Ctrl+C): the operation is still in flight on a
        // reactor thread and may keep writing op->recv_data after we
        // return, so don't read it here -- hand back nothing and let the
        // caller unwind. The reactor thread still owns op via the
        // shared_ptr captured in on_complete, so this is safe; it just
        // finishes on its own and is swept up by emergency_cleanup().
        return {};
    }
    return op->recv_data;
}

namespace {
    // Guards the handoff of the desired thread count into the lazily
    // constructed shared_reactor() instance below. configure_shared_reactor()
    // must run before the first shared_reactor() call anywhere in the
    // process (see the ordering note in async_io.h) — g_shared_reactor_built
    // exists purely to make a late/misordered call a harmless no-op with a
    // diagnostic, instead of silently doing nothing or racing construction.
    std::atomic<unsigned> g_shared_reactor_threads{0};
    std::atomic<bool>     g_shared_reactor_built{false};
} // namespace

void configure_shared_reactor(unsigned num_threads) {
    if (g_shared_reactor_built.load(std::memory_order_acquire)) {
        fprintf(stderr,
                "[async_io] configure_shared_reactor(%u) ignored -- "
                "shared_reactor() was already constructed with a "
                "different thread count\n",
                num_threads);
        return;
    }
    g_shared_reactor_threads.store(num_threads, std::memory_order_release);
}

Reactor& shared_reactor() {
    static Reactor instance(g_shared_reactor_threads.load(std::memory_order_acquire));
    g_shared_reactor_built.store(true, std::memory_order_release);
    return instance;
}

} // namespace async_io
