#include "async_io.hpp"

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
constexpr int   kMaxWaitMs     = 250;
constexpr int   kMinWaitMs     = 1;
constexpr int   kDefaultMinConnectMs = 250;
constexpr int   kAdaptiveRttMultiplier = 4;
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
    bind_errno = 0;           
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

} 

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
    if (stop_.exchange(true)) return;
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

void Reactor::set_deadline(EpollShard& shard, OperationPtr& op, Clock::duration budget) {
    if (op->stage_deadline_.time_since_epoch().count() != 0) {
        auto range = shard.deadlines.equal_range(op->stage_deadline_);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == op->fd_) { shard.deadlines.erase(it); break; }
        }
    }
    op->stage_deadline_ = Clock::now() + budget;
    shard.deadlines.emplace(op->stage_deadline_, op->fd_);
}

Clock::duration Reactor::adaptive_connect_budget(EpollShard&, const Operation& op) const {
    int fixed_ms = std::max(1, op.timeouts.connect_sec) * 1000;
    int floor_ms = op.timeouts.min_connect_ms > 0 ? op.timeouts.min_connect_ms
                                                    : kDefaultMinConnectMs;

    if (op.owning_epoll_idx_ < 0 ||
        static_cast<size_t>(op.owning_epoll_idx_) >= rtt_samples_ms_.size()) {
        return std::chrono::milliseconds(fixed_ms);
    }
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
    if (soonest <= now) return kMinWaitMs; 
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(soonest - now).count();
    return static_cast<int>(std::clamp<int64_t>(ms, kMinWaitMs, kMaxWaitMs));
}

void Reactor::begin_connect(EpollShard& shard, OperationPtr op) {
    if (op->proto == Proto::UDP) {
        op->last_errno = EPROTONOSUPPORT;
        finish(shard, op, OpResult::CONNECT_FAILED);
        return;
    }

    bool in_progress = false;
    int bind_errno = 0;
    int fd = -1;
    constexpr int kFixedPortBindMaxRetries   = 3;
    constexpr int kFixedPortBindRetryDelayMs = 150;

    int connect_errno = 0;

    for (int attempt = 0;; ++attempt) {
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

    {
        std::lock_guard<std::mutex> lock(shard.mu);
        shard.ops[fd] = op;
        set_deadline(shard, op, adaptive_connect_budget(shard, *op));
    }

    if (!in_progress) {
        step_connecting(shard, op);
        return;
    }
    arm(shard, op,true);
}

void Reactor::arm(EpollShard& shard, OperationPtr op, bool want_write) {
    op->armed_write_ = want_write;

    struct epoll_event ev{};
    ev.events = want_write ? (EPOLLOUT | EPOLLRDHUP) : (EPOLLIN | EPOLLRDHUP);
    ev.data.fd = op->fd_;

    int rc = epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, op->fd_, &ev);
    if (rc < 0 && errno == EEXIST) {
        rc = epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, op->fd_, &ev);
    }
    if (rc < 0) {
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
                if (it == shard.ops.end()) continue;
                op = it->second;
            }
            advance(shard, op, events[i].events);
        }
        sweep_timeouts(shard);
    }
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
    if (events & (EPOLLERR | EPOLLHUP)) {
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(op->fd_, SOL_SOCKET, SO_ERROR, &err, &elen);
        op->last_errno = err;
        switch (op->stage_) {
            case Operation::Stage::CONNECTING:    finish(shard, op, OpResult::CONNECT_FAILED); return;
            case Operation::Stage::TLS_HANDSHAKE: finish(shard, op, OpResult::TLS_FAILED);      return;
            case Operation::Stage::SENDING:       finish(shard, op, OpResult::SEND_FAILED);     return;
            default:
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
            set_deadline(shard, op, std::chrono::seconds(std::max(op->timeouts.connect_sec, 3)));
        }
        step_tls_handshake(shard, op);
        return;
    }

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
                continue;
            }
            int sslerr = SSL_get_error(op->ssl_, n);
            op->last_ssl_error = sslerr;
            if (sslerr == SSL_ERROR_WANT_READ)  { arm(shard, op, false); return; }
            if (sslerr == SSL_ERROR_WANT_WRITE) { arm(shard, op, true);  return; }
            ERR_clear_error();
            finish(shard, op, OpResult::SUCCESS);
            return;
        } else {
            ssize_t n = ::recv(op->fd_, buf, sizeof(buf), 0);
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
    op->ssl_ctx_ = nullptr;
}

void Reactor::finish(EpollShard& shard, OperationPtr op, OpResult r) {
    {
        std::lock_guard<std::mutex> lock(shard.mu);
        auto it = shard.ops.find(op->fd_);
        if (it != shard.ops.end()) shard.ops.erase(it);
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
    op->ssl_handle = op->ssl_;

    op->stage_ = Operation::Stage::DONE;

    if (op->on_complete) {
        op->on_complete(*op);
    }

    op->ssl_handle = nullptr;
    close_and_free_tls(op);
    if (op->fd_ >= 0) { close(op->fd_); op->fd_ = -1; }
}

Bytes run_blocking(Reactor& reactor, OperationPtr op) {
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
        return {};
    }
    return op->recv_data;
}

namespace {
    std::atomic<unsigned> g_shared_reactor_threads{0};
    std::atomic<bool>     g_shared_reactor_built{false};
}

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

}
