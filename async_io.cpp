#include "async_io.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "utils.hpp"

extern std::atomic<bool> terminate_flag;

namespace async_io {

namespace {

constexpr int    kMaxResponse             = 65536;
constexpr int    kChunk                   = 4096;
constexpr int    kMaxEvents               = 256;
constexpr int    kMaxWaitMs               = 250;
constexpr int    kMinWaitMs               = 1;
// Floor of the adaptive connect budget. A floor that is too low produces false
// "connect failed" results on slow links once the sample window is filled by
// fast targets, so it is deliberately generous; callers can override it through
// Timeouts::min_connect_ms.
constexpr int    kDefaultMinConnectMs     = 1000;
constexpr int    kAdaptiveRttMultiplier   = 4;
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

#if defined(TLS1_3_VERSION) && OPENSSL_VERSION_NUMBER >= 0x10101000L
#define ASYNC_IO_HAVE_TLS13_SUITES 1
const char* kDefaultTls13Ciphersuites =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";
#endif

bool is_ip_literal(const std::string& s) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s.c_str(), &a4) == 1 ||
           inet_pton(AF_INET6, s.c_str(), &a6) == 1;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int start_nonblocking_connect(const std::string& ip, int port,
                               const SourcePort& src_port,
                               bool& in_progress, int& bind_errno) {
    in_progress = false;
    bind_errno = 0;

    if (port < 1 || port > 65535) { errno = EINVAL; return -1; }

    struct sockaddr_storage addr_storage{};
    socklen_t addr_len = 0;
    int family = make_sockaddr_from_ip(ip, static_cast<uint16_t>(port), addr_storage, addr_len);
    if (addr_len == 0) { errno = EINVAL; return -1; }

    int fd = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[async_io] SO_KEEPALIVE failed for fd %d: %s\n", fd, strerror(errno));
    }
#ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[async_io] TCP_NODELAY failed for fd %d: %s\n", fd, strerror(errno));
    }
#endif

    if (src_port.mode == SourcePort::Mode::FIXED) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            fprintf(stderr, "[async_io] SO_REUSEADDR failed for fd %d (src_port=%u): %s\n",
                    fd, src_port.port, strerror(errno));
        }
#ifdef SO_REUSEPORT
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
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
            bind_errno = errno;
            close(fd);
            errno = bind_errno;
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
    }
    if (rc == 0) {
        in_progress = false;
        return fd;
    }
    if (errno == EINPROGRESS) {
        in_progress = true;
        return fd;
    }
    int connect_errno = errno;
    close(fd);
    errno = connect_errno;
    return -1;
}

SSL_CTX* build_ssl_ctx(const TlsOptions& tls) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    const bool custom12 = !tls.cipher_list_tls12.empty();
    const char* c12 = custom12 ? tls.cipher_list_tls12.c_str() : kDefaultTls12Ciphers;
    if (SSL_CTX_set_cipher_list(ctx, c12) != 1) {
        fprintf(stderr, "[async_io] invalid TLS1.2 cipher list '%s'\n", c12);
        ERR_clear_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }

#ifdef ASYNC_IO_HAVE_TLS13_SUITES
    const bool custom13 = !tls.ciphersuites_tls13.empty();
    const char* c13 = custom13 ? tls.ciphersuites_tls13.c_str() : kDefaultTls13Ciphersuites;
    if (SSL_CTX_set_ciphersuites(ctx, c13) != 1) {
        fprintf(stderr, "[async_io] invalid TLS1.3 ciphersuites '%s'\n", c13);
        ERR_clear_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }
#endif

    if (!tls.ca_file.empty() || !tls.ca_path.empty()) {
        const char* f = tls.ca_file.empty() ? nullptr : tls.ca_file.c_str();
        const char* p = tls.ca_path.empty() ? nullptr : tls.ca_path.c_str();
        if (SSL_CTX_load_verify_locations(ctx, f, p) != 1) {
            fprintf(stderr, "[async_io] failed to load CA locations (file='%s' path='%s')\n",
                    tls.ca_file.c_str(), tls.ca_path.c_str());
            ERR_clear_error();
            // With verification on, silently continuing with an empty trust store
            // would turn every handshake into a failure that looks like a network
            // problem. Refuse to build the context instead.
            if (tls.verify_peer) { SSL_CTX_free(ctx); return nullptr; }
        }
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    SSL_CTX_set_verify(ctx, tls.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

    if (!tls.client_cert.empty() && !tls.client_key.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, tls.client_cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, tls.client_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            fprintf(stderr, "[async_io] failed to load client certificate/key\n");
            ERR_clear_error();
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    return ctx;
}

// The cache frees its contexts on destruction. It is first touched from the
// Reactor constructor, so it is constructed before (and therefore destroyed
// after) any static Reactor instance and its worker threads.
struct SslCtxCache {
    std::mutex mu;
    std::unordered_map<std::string, SSL_CTX*> map;
    ~SslCtxCache() {
        for (auto& kv : map) SSL_CTX_free(kv.second);
    }
};

SslCtxCache& ssl_ctx_cache() {
    static SslCtxCache cache;
    return cache;
}

std::string ssl_ctx_cache_key(const TlsOptions& tls) {
    return tls.ca_file + "\x1f" + tls.ca_path + "\x1f" +
           tls.client_cert + "\x1f" + tls.client_key + "\x1f" +
           tls.cipher_list_tls12 + "\x1f" + tls.ciphersuites_tls13 + "\x1f" +
           (tls.verify_peer ? "1" : "0");
}

SSL_CTX* get_or_build_ssl_ctx(const TlsOptions& tls) {
    std::string key = ssl_ctx_cache_key(tls);
    SslCtxCache& cache = ssl_ctx_cache();
    std::lock_guard<std::mutex> lock(cache.mu);
    auto it = cache.map.find(key);
    if (it != cache.map.end()) return it->second;
    SSL_CTX* ctx = build_ssl_ctx(tls);
    if (ctx) cache.map.emplace(key, ctx);
    return ctx;
}

void init_openssl_once() {
    static std::once_flag flag;
    std::call_once(flag, [] {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_ssl(0, nullptr);
#endif
    });
}

std::atomic<unsigned> g_shared_reactor_threads{0};
std::atomic<bool>     g_shared_reactor_built{false};

} // namespace

Reactor::Reactor(unsigned num_threads) {
    if (num_threads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        num_threads = hw == 0 ? 2 : std::clamp(hw, 2u, 8u);
    }
    init_openssl_once();
    (void)ssl_ctx_cache();   // fix static destruction order (see SslCtxCache)

    shards_.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i) {
        auto shard = std::make_unique<EpollShard>();
        shard->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        shard->wake_fd  = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        bool ok = shard->epoll_fd >= 0 && shard->wake_fd >= 0;
        if (ok) {
            struct epoll_event ev{};
            ev.events  = EPOLLIN;
            ev.data.fd = shard->wake_fd;
            ok = epoll_ctl(shard->epoll_fd, EPOLL_CTL_ADD, shard->wake_fd, &ev) == 0;
        }
        if (!ok) {
            int e = errno;
            if (shard->epoll_fd >= 0) close(shard->epoll_fd);
            if (shard->wake_fd  >= 0) close(shard->wake_fd);
            for (auto& s : shards_) { close(s->epoll_fd); close(s->wake_fd); }
            throw std::runtime_error(std::string("async_io: epoll/eventfd setup failed: ") + strerror(e));
        }
        shards_.push_back(std::move(shard));
    }
    threads_.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i) {
        threads_.emplace_back([this, i] { worker_loop(*shards_[i]); });
    }
}

Reactor::~Reactor() {
    shutdown();
}

void Reactor::wake(EpollShard& shard) {
    uint64_t one = 1;
    ssize_t rc;
    do { rc = ::write(shard.wake_fd, &one, sizeof(one)); } while (rc < 0 && errno == EINTR);
    // EAGAIN means the counter is saturated, i.e. a wake-up is already pending.
}

void Reactor::shutdown() {
    if (stop_.exchange(true)) return;
    for (auto& shard : shards_) wake(*shard);
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    // Workers are gone. Anything submitted after a worker's final drain is
    // completed here so that no caller is ever left waiting.
    for (auto& shard : shards_) {
        std::deque<OperationPtr> leftovers;
        {
            std::lock_guard<std::mutex> lock(shard->mu);
            shard->closed = true;
            leftovers.swap(shard->pending);
        }
        for (auto& op : leftovers) finish(*shard, op, OpResult::CANCELLED);
        std::vector<OperationPtr> rest;
        for (auto& kv : shard->ops) rest.push_back(kv.second);
        for (auto& op : rest) finish(*shard, op, OpResult::CANCELLED);
        if (shard->epoll_fd >= 0) { close(shard->epoll_fd); shard->epoll_fd = -1; }
        if (shard->wake_fd  >= 0) { close(shard->wake_fd);  shard->wake_fd  = -1; }
    }
}

void Reactor::submit(OperationPtr op) {
    if (!op) return;
    size_t idx = next_shard_.fetch_add(1, std::memory_order_relaxed) % shards_.size();
    op->shard_idx_ = static_cast<int>(idx);
    EpollShard& shard = *shards_[idx];
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        if (!shard.closed) {
            shard.pending.push_back(op);
            goto queued;
        }
    }
    // Reactor already shut down: complete synchronously, nothing else owns this op.
    finish(shard, op, OpResult::CANCELLED);
    return;
queued:
    wake(shard);
}

void Reactor::cancel(const OperationPtr& op) {
    if (!op) return;
    op->cancel_requested_.store(true, std::memory_order_release);
    int idx = op->shard_idx_;
    if (idx >= 0 && static_cast<size_t>(idx) < shards_.size()) wake(*shards_[idx]);
}

void Reactor::drain_pending(EpollShard& shard) {
    std::deque<OperationPtr> batch;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        batch.swap(shard.pending);
    }
    for (auto& op : batch) begin_connect(shard, op);
}

void Reactor::process_cancellations(EpollShard& shard) {
    std::vector<OperationPtr> cancelled;
    for (auto& kv : shard.ops) {
        if (kv.second->cancel_requested_.load(std::memory_order_acquire))
            cancelled.push_back(kv.second);
    }
    for (auto& op : cancelled) finish(shard, op, OpResult::CANCELLED);
}

void Reactor::set_deadline(EpollShard& shard, Operation& op, Clock::duration budget) {
    if (op.stage_deadline_.time_since_epoch().count() != 0) {
        auto range = shard.deadlines.equal_range(op.stage_deadline_);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == op.fd_) { shard.deadlines.erase(it); break; }
        }
    }
    op.stage_deadline_ = Clock::now() + budget;
    shard.deadlines.emplace(op.stage_deadline_, op.fd_);
}

Clock::duration Reactor::adaptive_connect_budget(const EpollShard& shard, const Operation& op) const {
    int fixed_ms = std::max(1, op.timeouts.connect_sec) * 1000;
    int floor_ms = op.timeouts.min_connect_ms > 0 ? op.timeouts.min_connect_ms
                                                    : kDefaultMinConnectMs;
    const auto& samples = shard.rtt_samples_ms;
    if (samples.size() < kMinRttSamplesForAdaptive) {
        return std::chrono::milliseconds(fixed_ms);
    }

    std::vector<int64_t> sorted(samples.begin(), samples.end());
    std::sort(sorted.begin(), sorted.end());
    int64_t median = sorted[sorted.size() / 2];

    int64_t adaptive_ms = median * kAdaptiveRttMultiplier;
    // never exceed the caller's ceiling, even if the floor is larger than it
    int64_t hi = fixed_ms;
    int64_t lo = std::min<int64_t>(floor_ms, hi);
    adaptive_ms = std::clamp<int64_t>(adaptive_ms, lo, hi);
    return std::chrono::milliseconds(adaptive_ms);
}

int Reactor::next_wait_ms(EpollShard& shard) const {
    if (shard.deadlines.empty()) return kMaxWaitMs;
    auto soonest = shard.deadlines.begin()->first;
    auto now = Clock::now();
    if (soonest <= now) return kMinWaitMs;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(soonest - now).count();
    return static_cast<int>(std::clamp<int64_t>(ms + 1, kMinWaitMs, kMaxWaitMs));
}

void Reactor::begin_connect(EpollShard& shard, OperationPtr op) {
    if (op->cancel_requested_.load(std::memory_order_acquire)) {
        finish(shard, op, OpResult::CANCELLED);
        return;
    }
    op->connect_start_ = Clock::now();

    bool in_progress = false;
    int bind_errno = 0;
    int fd = -1;
    constexpr int kFixedPortBindMaxRetries   = 3;
    constexpr int kFixedPortBindRetryDelayMs = 150;

    int connect_errno = 0;

    for (int attempt = 0;; ++attempt) {
        errno = 0;
        fd = start_nonblocking_connect(op->ip, op->port, op->src_port, in_progress, bind_errno);
        if (fd >= 0) break;
        connect_errno = errno;
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
    shard.ops[fd] = op;
    set_deadline(shard, *op, adaptive_connect_budget(shard, *op));

    if (!in_progress) {
        step_connecting(shard, op);
        return;
    }
    arm(shard, op, true);
}

void Reactor::arm(EpollShard& shard, OperationPtr op, bool want_write) {
    struct epoll_event ev{};
    ev.events = want_write ? EPOLLOUT : EPOLLIN;
    ev.data.fd = op->fd_;

    int rc = epoll_ctl(shard.epoll_fd,
                       op->epoll_registered_ ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                       op->fd_, &ev);
    if (rc == 0) { op->epoll_registered_ = true; return; }

    int arm_errno = errno;
    fprintf(stderr, "[async_io] epoll_ctl failed for fd %d: %s\n", op->fd_, strerror(arm_errno));
    op->last_errno = arm_errno;
    switch (op->stage_) {
        case Operation::Stage::CONNECTING:     finish(shard, op, OpResult::CONNECT_FAILED); break;
        case Operation::Stage::TLS_HANDSHAKE:  finish(shard, op, OpResult::TLS_FAILED);     break;
        case Operation::Stage::SENDING:        finish(shard, op, OpResult::SEND_FAILED);    break;
        case Operation::Stage::RECV_FIRST:
        case Operation::Stage::RECV_IDLE:
            finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
            break;
        default: break;
    }
}

void Reactor::worker_loop(EpollShard& shard) {
    std::vector<struct epoll_event> events(kMaxEvents);
    while (!stop_.load(std::memory_order_acquire)) {
        int wait_ms = next_wait_ms(shard);
        int n = epoll_wait(shard.epoll_fd, events.data(), kMaxEvents, wait_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[async_io] epoll_wait failed: %s -- worker exiting\n", strerror(errno));
            break;
        }
        bool woke = false;
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == shard.wake_fd) {
                uint64_t cnt;
                while (::read(shard.wake_fd, &cnt, sizeof(cnt)) > 0) {}
                woke = true;
                continue;
            }
            auto it = shard.ops.find(fd);
            if (it == shard.ops.end()) continue;
            OperationPtr op = it->second;
            advance(shard, op, events[i].events);
        }
        if (woke) {
            drain_pending(shard);
            process_cancellations(shard);
        }
        sweep_timeouts(shard);
    }

    // Final cleanup on this worker's own shard: nothing may be left PENDING.
    std::deque<OperationPtr> pend;
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        pend.swap(shard.pending);
    }
    for (auto& op : pend) finish(shard, op, OpResult::CANCELLED);
    std::vector<OperationPtr> remaining;
    for (auto& kv : shard.ops) remaining.push_back(kv.second);
    for (auto& op : remaining) finish(shard, op, OpResult::CANCELLED);
}

void Reactor::sweep_timeouts(EpollShard& shard) {
    auto now = Clock::now();
    std::vector<OperationPtr> expired;
    auto it = shard.deadlines.begin();
    while (it != shard.deadlines.end() && it->first <= now) {
        auto op_it = shard.ops.find(it->second);
        // Only expire the op if this entry is really its current deadline (guards
        // against a reused fd number picking up a stale entry).
        if (op_it != shard.ops.end() && op_it->second->stage_deadline_ == it->first)
            expired.push_back(op_it->second);
        it = shard.deadlines.erase(it);
    }
    for (auto& op : expired) {
        switch (op->stage_) {
            case Operation::Stage::CONNECTING:
                op->last_errno = ETIMEDOUT;
                finish(shard, op, OpResult::CONNECT_FAILED);
                break;
            case Operation::Stage::TLS_HANDSHAKE:
                finish(shard, op, OpResult::TLS_FAILED);
                break;
            case Operation::Stage::SENDING:
                finish(shard, op, OpResult::SEND_FAILED);
                break;
            case Operation::Stage::RECV_FIRST:
                finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
                break;
            case Operation::Stage::RECV_IDLE:
                finish(shard, op, OpResult::SUCCESS);
                break;
            default:
                break;
        }
    }
}

void Reactor::advance(EpollShard& shard, OperationPtr op, uint32_t events) {
    if (op->finished_.load(std::memory_order_acquire)) return;

    const bool failed = (events & (EPOLLERR | EPOLLHUP)) != 0;

    switch (op->stage_) {
        case Operation::Stage::CONNECTING:
            if (failed) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen);
                op->last_errno = err != 0 ? err : ECONNRESET;
                finish(shard, op, OpResult::CONNECT_FAILED);
                return;
            }
            // Only trust a writable event: a bare readiness report must never be
            // mistaken for a completed connect().
            if (events & EPOLLOUT) step_connecting(shard, op);
            return;

        case Operation::Stage::TLS_HANDSHAKE:
            if (failed) {
                // let OpenSSL see the alert/close if bytes are pending
                step_tls_handshake(shard, op);
                return;
            }
            step_tls_handshake(shard, op);
            return;

        case Operation::Stage::SENDING:
            if (failed) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen);
                op->last_errno = err != 0 ? err : ECONNRESET;
                finish(shard, op, OpResult::SEND_FAILED);
                return;
            }
            step_sending(shard, op);
            return;

        case Operation::Stage::RECV_FIRST:
        case Operation::Stage::RECV_IDLE:
            // A server that replies and closes (Connection: close) reports
            // EPOLLIN together with EPOLLHUP. Always drain what is buffered
            // instead of discarding the response.
            step_recv(shard, op);
            return;

        case Operation::Stage::DONE:
            return;
    }
}

void Reactor::step_connecting(EpollShard& shard, OperationPtr op) {
    int err = 0; socklen_t elen = sizeof(err);
    if (getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
        op->last_errno = err != 0 ? err : errno;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }
    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - op->connect_start_);
    op->connect_rtt = rtt;
    shard.rtt_samples_ms.push_back(rtt.count());
    if (shard.rtt_samples_ms.size() > kRttSampleWindow) shard.rtt_samples_ms.pop_front();

    if (op->proto == Proto::TLS) {
        op->ssl_ctx_ = get_or_build_ssl_ctx(op->tls);
        if (!op->ssl_ctx_) { finish(shard, op, OpResult::TLS_FAILED); return; }
        op->ssl_ = SSL_new(op->ssl_ctx_);
        if (!op->ssl_) { ERR_clear_error(); finish(shard, op, OpResult::TLS_FAILED); return; }
        SSL_set_fd(op->ssl_, op->fd_);

        const std::string& host = op->tls.sni.empty() ? op->ip : op->tls.sni;
        const bool host_is_ip = is_ip_literal(host);
        // RFC 6066: SNI carries a hostname, never an IP literal.
        if (!host_is_ip) SSL_set_tlsext_host_name(op->ssl_, host.c_str());
        if (op->tls.verify_peer) {
            X509_VERIFY_PARAM* param = SSL_get0_param(op->ssl_);
            if (host_is_ip) {
                X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str());
            } else {
                X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
            }
        }
        op->stage_ = Operation::Stage::TLS_HANDSHAKE;
        set_deadline(shard, *op, std::chrono::seconds(std::max(op->timeouts.connect_sec, 3)));
        step_tls_handshake(shard, op);
        return;
    }

    op->stage_ = Operation::Stage::SENDING;
    set_deadline(shard, *op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
    step_sending(shard, op);
}

void Reactor::step_tls_handshake(EpollShard& shard, OperationPtr op) {
    ERR_clear_error();
    int rc = SSL_connect(op->ssl_);
    if (rc == 1) {
        op->stage_ = Operation::Stage::SENDING;
        set_deadline(shard, *op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
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
    while (op->sent_ < op->send_payload.size()) {
        const u8* base = op->send_payload.data() + op->sent_;
        size_t remain = op->send_payload.size() - op->sent_;

        if (op->proto == Proto::TLS) {
            ERR_clear_error();
            int n = SSL_write(op->ssl_, base, static_cast<int>(std::min<size_t>(remain, 1 << 20)));
            if (n > 0) { op->sent_ += static_cast<size_t>(n); continue; }
            int sslerr = SSL_get_error(op->ssl_, n);
            op->last_ssl_error = sslerr;
            if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
            if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
            ERR_clear_error();
            finish(shard, op, OpResult::SEND_FAILED);
            return;
        } else {
            ssize_t n = ::send(op->fd_, base, remain, MSG_NOSIGNAL);
            if (n > 0) { op->sent_ += static_cast<size_t>(n); continue; }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { arm(shard, op, true); return; }
            op->last_errno = errno;
            finish(shard, op, OpResult::SEND_FAILED);
            return;
        }
    }

    op->stage_ = Operation::Stage::RECV_FIRST;
    set_deadline(shard, *op, std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec)));
    arm(shard, op, false);
}

void Reactor::step_recv(EpollShard& shard, OperationPtr op) {
    char buf[kChunk];
    const size_t response_cap = op->max_response_bytes > 0
                                     ? op->max_response_bytes
                                     : static_cast<size_t>(kMaxResponse);

    auto on_first_data = [&] {
        if (op->stage_ == Operation::Stage::RECV_FIRST) {
            op->stage_ = Operation::Stage::RECV_IDLE;
            int idle = op->timeouts.idle_sec > 0
                           ? op->timeouts.idle_sec
                           : std::max(2, op->timeouts.first_byte_sec / 2);
            set_deadline(shard, *op, std::chrono::seconds(idle));
        }
    };

    for (;;) {
        if (op->recv_data.size() >= response_cap) {
            finish(shard, op, OpResult::SUCCESS);
            return;
        }
        const size_t want = std::min<size_t>(sizeof(buf), response_cap - op->recv_data.size());

        if (op->proto == Proto::TLS) {
            ERR_clear_error();
            int n = SSL_read(op->ssl_, buf, static_cast<int>(want));
            if (n > 0) {
                op->recv_data.insert(op->recv_data.end(), buf, buf + n);
                on_first_data();
                continue;
            }
            int sslerr = SSL_get_error(op->ssl_, n);
            op->last_ssl_error = sslerr;
            if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
            if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
            ERR_clear_error();
            // clean close / peer reset after (possibly zero) data: report what we have
            finish(shard, op, OpResult::SUCCESS);
            return;
        } else {
            ssize_t n = ::recv(op->fd_, buf, want, 0);
            if (n > 0) {
                op->recv_data.insert(op->recv_data.end(), buf, buf + n);
                on_first_data();
                continue;
            }
            if (n == 0) { finish(shard, op, OpResult::SUCCESS); return; }   // peer closed
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) { arm(shard, op, false); return; }
            op->last_errno = errno;
            finish(shard, op, op->recv_data.empty() ? OpResult::TIMEOUT : OpResult::SUCCESS);
            return;
        }
    }
}

void Reactor::close_and_free_tls(OperationPtr op, bool graceful) {
    if (op->ssl_) {
        if (graceful) SSL_shutdown(op->ssl_);   // single non-blocking close_notify attempt
        SSL_free(op->ssl_);
        op->ssl_ = nullptr;
        ERR_clear_error();
    }
    op->ssl_ctx_ = nullptr;
}

void Reactor::finish(EpollShard& shard, OperationPtr op, OpResult r) {
    // Idempotent: a timeout, an event and a cancel may all race to finish the
    // same op; exactly one wins and closes the fd exactly once.
    if (op->finished_.exchange(true, std::memory_order_acq_rel)) return;

    if (op->fd_ >= 0) {
        auto it = shard.ops.find(op->fd_);
        if (it != shard.ops.end() && it->second == op) shard.ops.erase(it);
        if (op->stage_deadline_.time_since_epoch().count() != 0) {
            auto range = shard.deadlines.equal_range(op->stage_deadline_);
            for (auto dit = range.first; dit != range.second; ++dit) {
                if (dit->second == op->fd_) { shard.deadlines.erase(dit); break; }
            }
        }
        if (op->epoll_registered_ && shard.epoll_fd >= 0)
            epoll_ctl(shard.epoll_fd, EPOLL_CTL_DEL, op->fd_, nullptr);
    }

    op->stage_ = Operation::Stage::DONE;
    op->ssl_handle = (r == OpResult::SUCCESS) ? op->ssl_ : nullptr;
    op->result.store(r, std::memory_order_release);

    if (op->on_complete) {
        try { op->on_complete(*op); }
        catch (const std::exception& e) {
            fprintf(stderr, "[async_io] on_complete threw: %s\n", e.what());
        } catch (...) {
            fprintf(stderr, "[async_io] on_complete threw an unknown exception\n");
        }
    }

    op->ssl_handle = nullptr;
    close_and_free_tls(op, r == OpResult::SUCCESS);
    if (op->fd_ >= 0) { close(op->fd_); op->fd_ = -1; }
}

Bytes run_blocking(Reactor& reactor, OperationPtr op) {
    struct Waiter {
        std::mutex mu;
        std::condition_variable cv;
        bool done = false;
    };
    auto w = std::make_shared<Waiter>();

    auto user_cb = op->on_complete;
    op->on_complete = [w, user_cb](Operation& o) {
        if (user_cb) user_cb(o);
        {
            std::lock_guard<std::mutex> lk(w->mu);
            w->done = true;
        }
        w->cv.notify_all();
    };

    reactor.submit(op);

    std::unique_lock<std::mutex> lk(w->mu);
    bool cancel_sent = false;
    auto cancel_deadline = Clock::now();
    while (!w->done) {
        if (terminate_flag.load(std::memory_order_relaxed)) {
            if (!cancel_sent) {
                cancel_sent = true;
                cancel_deadline = Clock::now() + std::chrono::seconds(2);
                reactor.cancel(op);
            } else if (Clock::now() >= cancel_deadline) {
                return {};   // the reactor still owns op through its shared_ptr
            }
        }
        w->cv.wait_for(lk, std::chrono::milliseconds(100));
    }
    if (cancel_sent) return {};
    // done is set after the worker has finished writing recv_data (same mutex)
    return op->recv_data;
}

bool configure_shared_reactor(unsigned num_threads) {
    if (g_shared_reactor_built.load(std::memory_order_acquire)) {
        fprintf(stderr,
                "[async_io] configure_shared_reactor(%u) ignored -- "
                "shared_reactor() was already constructed\n", num_threads);
        return false;
    }
    g_shared_reactor_threads.store(num_threads, std::memory_order_release);
    return true;
}

namespace {
unsigned claim_shared_reactor_threads() {
    g_shared_reactor_built.store(true, std::memory_order_release);
    return g_shared_reactor_threads.load(std::memory_order_acquire);
}
}

Reactor& shared_reactor() {
    // The flag is raised before construction, so a configure call racing with
    // the first use is either honoured or reported, never silently lost.
    static Reactor instance(claim_shared_reactor_threads());
    return instance;
}

}
