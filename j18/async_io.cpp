// async_io.cpp — see async_io.h for the design rationale.

#include "async_io.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>

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

namespace async_io {

namespace {

constexpr int   kMaxResponse   = 65536;
constexpr int   kChunk         = 4096;
constexpr int   kMaxEvents     = 256;
// epoll_wait timeout: bounds how quickly we notice a stage deadline expiring
// even when no fd events are pending. 100ms keeps timeout accounting tight
// (a probe won't overrun its configured timeout by more than ~100ms) while
// staying cheap — a handful of wakeups/sec per shard even under load.
constexpr int   kTickMs        = 100;

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
int start_nonblocking_connect(const std::string& ip, int port, bool& in_progress) {
    in_progress = false;

    struct sockaddr_storage addr_storage{};
    socklen_t addr_len = 0;
    int family = AF_INET;

    {
        auto* a4 = reinterpret_cast<struct sockaddr_in*>(&addr_storage);
        if (inet_pton(AF_INET, ip.c_str(), &a4->sin_addr) == 1) {
            a4->sin_family = AF_INET;
            a4->sin_port   = htons(static_cast<uint16_t>(port));
            addr_len = sizeof(struct sockaddr_in);
            family   = AF_INET;
        }
    }
    if (addr_len == 0) {
        auto* a6 = reinterpret_cast<struct sockaddr_in6*>(&addr_storage);
        if (inet_pton(AF_INET6, ip.c_str(), &a6->sin6_addr) == 1) {
            a6->sin6_family = AF_INET6;
            a6->sin6_port   = htons(static_cast<uint16_t>(port));
            addr_len = sizeof(struct sockaddr_in6);
            family   = AF_INET6;
        }
    }
    if (addr_len == 0) return -1;

    int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_NODELAY
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif

    if (set_nonblocking(fd) < 0) { close(fd); return -1; }

    int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr_storage), addr_len);
    if (rc == 0) {
        in_progress = false; // connected immediately (rare, e.g. loopback)
        return fd;
    }
    if (errno == EINPROGRESS) {
        in_progress = true;
        return fd;
    }
    close(fd);
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
    EpollShard& shard = *shards_[idx];
    begin_connect(shard, std::move(op));
}

void Reactor::begin_connect(EpollShard& shard, OperationPtr op) {
    bool in_progress = false;
    int fd = start_nonblocking_connect(op->ip, op->port, in_progress);
    if (fd < 0) {
        op->last_errno = errno;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }
    op->fd_ = fd;
    op->stage_ = Operation::Stage::CONNECTING;
    op->stage_deadline_ = Clock::now() + std::chrono::seconds(op->timeouts.connect_sec);

    {
        std::lock_guard<std::mutex> lock(shard.mu);
        shard.ops[fd] = op;
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

    if (epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, op->fd_, &ev) < 0 && errno == EEXIST) {
        epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, op->fd_, &ev);
    }
}

void Reactor::worker_loop(EpollShard& shard) {
    std::vector<struct epoll_event> events(kMaxEvents);
    while (!stop_.load(std::memory_order_relaxed)) {
        int n = epoll_wait(shard.epoll_fd, events.data(), kMaxEvents, kTickMs);
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
        for (auto& [fd, op] : shard.ops) {
            if (now >= op->stage_deadline_) expired.push_back(op);
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

    if (op->proto == Proto::TLS) {
        op->ssl_ctx_ = build_ssl_ctx(op->tls, false);
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
        // Reuse the connect timeout as the handshake budget's starting
        // point; extend it slightly since handshake is a few extra RTTs.
        op->stage_deadline_ = Clock::now() + std::chrono::seconds(std::max(op->timeouts.connect_sec, 3));
        step_tls_handshake(shard, op);
        return;
    }

    // Plain TCP: go straight to sending (or receiving, if no payload).
    op->stage_ = Operation::Stage::SENDING;
    op->stage_deadline_ = Clock::now() + std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec));
    step_sending(shard, op);
}

void Reactor::step_tls_handshake(EpollShard& shard, OperationPtr op) {
    int rc = SSL_connect(op->ssl_);
    if (rc == 1) {
        op->stage_ = Operation::Stage::SENDING;
        op->stage_deadline_ = Clock::now() + std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec));
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
        op->stage_deadline_ = Clock::now() + std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec));
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
    op->stage_deadline_ = Clock::now() + std::chrono::seconds(std::max(1, op->timeouts.first_byte_sec));
    arm(shard, op, false);
}

void Reactor::step_recv(EpollShard& shard, OperationPtr op, bool is_recv_first) {
    (void)is_recv_first;
    char buf[kChunk];

    for (;;) {
        if (static_cast<int>(op->recv_data.size()) >= kMaxResponse) {
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
                    op->stage_deadline_ = Clock::now() + std::chrono::seconds(idle);
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
                    // Old recv_all_tcp() returned immediately after the
                    // first successful recv() rather than looping for more
                    // — preserve that exact behavior for TCP.
                    finish(shard, op, OpResult::SUCCESS);
                    return;
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
    if (op->ssl_ctx_) {
        SSL_CTX_free(op->ssl_ctx_);
        op->ssl_ctx_ = nullptr;
    }
}

void Reactor::finish(EpollShard& shard, OperationPtr op, OpResult r) {
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        auto it = shard.ops.find(op->fd_);
        if (it != shard.ops.end()) shard.ops.erase(it);
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
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto mu   = std::make_shared<std::mutex>();
    auto cv   = std::make_shared<std::condition_variable>();

    auto user_cb = op->on_complete;
    op->on_complete = [done, mu, cv, user_cb](Operation& o) {
        if (user_cb) user_cb(o);
        {
            std::lock_guard<std::mutex> lock(*mu);
            done->store(true, std::memory_order_release);
        }
        cv->notify_all();
    };

    reactor.submit(op);

    std::unique_lock<std::mutex> lock(*mu);
    cv->wait(lock, [&] { return done->load(std::memory_order_acquire); });
    return op->recv_data;
}

Reactor& shared_reactor() {
    static Reactor instance;
    return instance;
}

} // namespace async_io
