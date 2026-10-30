#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>

namespace async_io {

using u8    = uint8_t;
using Bytes = std::vector<u8>;
using Clock = std::chrono::steady_clock;

// UDP is intentionally not a reactor protocol: UDP probing is done by the
// blocking capture_udp() path in control.cpp.
enum class Proto { TCP, TLS };

enum class OpResult {
    PENDING,
    SUCCESS,
    CONNECT_FAILED,
    TLS_FAILED,
    SEND_FAILED,
    TIMEOUT,
    CANCELLED
};

struct TlsOptions {
    bool        verify_peer = false;
    std::string ca_file;
    std::string ca_path;
    std::string client_cert;
    std::string client_key;
    std::string sni;                 // empty => derived from the target (never an IP literal on the wire)
    std::string cipher_list_tls12;   // empty => built-in default list
    std::string ciphersuites_tls13;  // empty => built-in default list
};

struct Timeouts {
    int connect_sec    = 3;   // ceiling for the connect stage
    int first_byte_sec = 5;   // send stage + wait for first response byte
    int idle_sec       = 0;   // 0 => max(2, first_byte_sec / 2)
    int min_connect_ms = 0;   // floor of the adaptive connect budget; 0 => library default
};

struct SourcePort {
    enum class Mode { EPHEMERAL, FIXED };
    Mode mode = Mode::EPHEMERAL;
    uint16_t port = 0;
};

class Reactor;

class Operation {
public:
    // ---- inputs (set before submit) ----
    std::string ip;
    int         port = 0;
    Proto       proto = Proto::TCP;
    Bytes       send_payload;
    Timeouts    timeouts;
    TlsOptions  tls;
    SourcePort  src_port;
    size_t      max_response_bytes = 0;   // 0 => library default (64 KiB)

    // ---- outputs (valid once on_complete has run / result != PENDING) ----
    std::atomic<OpResult> result{OpResult::PENDING};
    Bytes       recv_data;
    int         last_errno     = 0;
    int         last_ssl_error = 0;
    std::chrono::milliseconds connect_rtt{0};   // TCP connect latency (reactor-measured)
    SSL*        ssl_handle = nullptr;           // only valid inside on_complete, SUCCESS + TLS only

    // Runs on a reactor thread. Must not block and must not throw.
    std::function<void(Operation&)> on_complete;

    Operation() = default;
    Operation(const Operation&) = delete;
    Operation& operator=(const Operation&) = delete;

private:
    friend class Reactor;

    enum class Stage { CONNECTING, TLS_HANDSHAKE, SENDING, RECV_FIRST, RECV_IDLE, DONE };

    int      fd_       = -1;
    SSL*     ssl_      = nullptr;
    SSL_CTX* ssl_ctx_  = nullptr;
    Stage    stage_    = Stage::CONNECTING;
    size_t   sent_     = 0;
    bool     epoll_registered_ = false;
    Clock::time_point stage_deadline_{};
    Clock::time_point connect_start_{};
    int      shard_idx_ = -1;
    std::atomic<bool> finished_{false};
    std::atomic<bool> cancel_requested_{false};
};

using OperationPtr = std::shared_ptr<Operation>;

// All per-operation state is owned by exactly one worker thread. submit() and
// cancel() only enqueue work and wake that worker, so no operation is ever
// touched from two threads at once.
class Reactor {
public:
    explicit Reactor(unsigned num_threads = 0);
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    // Always results in exactly one on_complete call (CANCELLED if the reactor is shut down).
    void submit(OperationPtr op);
    // Asks the owning worker to finish the op with CANCELLED. Safe to call at any time.
    void cancel(const OperationPtr& op);
    void shutdown();

private:
    struct EpollShard {
        int epoll_fd = -1;
        int wake_fd  = -1;
        std::mutex mu;                                   // guards pending / closed (and ops/deadlines for sweep)
        std::deque<OperationPtr> pending;
        bool closed = false;
        std::unordered_map<int, OperationPtr> ops;       // worker-thread only after submit
        std::multimap<Clock::time_point, int> deadlines; // worker-thread only
        std::deque<int64_t> rtt_samples_ms;              // worker-thread only
    };

    void worker_loop(EpollShard& shard);
    void drain_pending(EpollShard& shard);
    void process_cancellations(EpollShard& shard);
    void wake(EpollShard& shard);
    void begin_connect(EpollShard& shard, OperationPtr op);
    void advance(EpollShard& shard, OperationPtr op, uint32_t events);
    void step_connecting(EpollShard& shard, OperationPtr op);
    void step_tls_handshake(EpollShard& shard, OperationPtr op);
    void step_sending(EpollShard& shard, OperationPtr op);
    void step_recv(EpollShard& shard, OperationPtr op);
    void arm(EpollShard& shard, OperationPtr op, bool want_write);
    void finish(EpollShard& shard, OperationPtr op, OpResult r);
    void sweep_timeouts(EpollShard& shard);
    void close_and_free_tls(OperationPtr op, bool graceful);
    void set_deadline(EpollShard& shard, Operation& op, Clock::duration budget);
    Clock::duration adaptive_connect_budget(const EpollShard& shard, const Operation& op) const;
    int next_wait_ms(EpollShard& shard) const;

    std::vector<std::unique_ptr<EpollShard>> shards_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> next_shard_{0};
    static constexpr size_t kRttSampleWindow = 32;
};

Bytes run_blocking(Reactor& reactor, OperationPtr op);

// Returns true if the thread count was recorded. Returns false (and logs) if the
// shared reactor was already built, because its thread count can no longer change.
bool configure_shared_reactor(unsigned num_threads);
Reactor& shared_reactor();

}
