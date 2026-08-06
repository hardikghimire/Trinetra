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

enum class Proto { TCP, TLS, UDP };

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
    std::string sni;                
    std::string cipher_list_tls12;   
    std::string ciphersuites_tls13;  
};

struct Timeouts {
    int connect_sec    = 3;
    int first_byte_sec = 5;
    int idle_sec       = 0;
    int min_connect_ms = 0;
};

struct SourcePort {
    enum class Mode { EPHEMERAL, FIXED };
    Mode mode = Mode::EPHEMERAL;
    uint16_t port = 0; 
};

class Reactor;

class Operation {
public:
    std::string ip;
    int         port = 0;
    Proto       proto = Proto::TCP;
    Bytes       send_payload;          
    Timeouts    timeouts;
    TlsOptions  tls;                  
    SourcePort  src_port;             
    size_t      max_response_bytes = 0;
    std::atomic<OpResult> result{OpResult::PENDING};
    Bytes       recv_data;
    int         last_errno     = 0;
    int         last_ssl_error = 0;   
    std::chrono::milliseconds connect_rtt{0};
    SSL* ssl_handle = nullptr;
    std::function<void(Operation&)> on_complete;

    Operation() = default;
    Operation(const Operation&) = delete;
    Operation& operator=(const Operation&) = delete;

private:
    friend class Reactor;

    enum class Stage {
        CONNECTING,
        TLS_HANDSHAKE,
        SENDING,
        RECV_FIRST,
        RECV_IDLE,
        DONE
    };

    int      fd_      = -1;
    SSL*     ssl_      = nullptr;
    SSL_CTX* ssl_ctx_  = nullptr;
    Stage    stage_    = Stage::CONNECTING;
    size_t   sent_     = 0;
    bool     armed_write_ = false; 
    Clock::time_point stage_deadline_;
    Clock::time_point submit_time_;   
    int      owning_epoll_idx_ = -1;
};

using OperationPtr = std::shared_ptr<Operation>;
class OneShotSignal {
public:
    void signal() noexcept {
        done_.store(true, std::memory_order_release);
        done_.notify_all();
    }

    void wait() noexcept {
        bool v = done_.load(std::memory_order_acquire);
        while (!v) {
            done_.wait(false, std::memory_order_acquire);
            v = done_.load(std::memory_order_acquire);
        }
    }

    bool is_signaled() const noexcept {
        return done_.load(std::memory_order_acquire);
    }
    template <typename Pred>
    bool wait_interruptible(Pred&& is_interrupted,
                             std::chrono::milliseconds poll_interval =
                                 std::chrono::milliseconds(50)) noexcept {
        while (!done_.load(std::memory_order_acquire)) {
            if (is_interrupted()) return false;
            std::this_thread::sleep_for(poll_interval);
        }
        return true;
    }

private:
    std::atomic<bool> done_{false};
};

class Reactor {
public:
    explicit Reactor(unsigned num_threads = 0);
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;
    void submit(OperationPtr op);
    void shutdown();

private:

    struct EpollShard {
        int epoll_fd = -1;
        std::mutex mu;
        std::unordered_map<int, OperationPtr> ops;
        std::multimap<Clock::time_point, int > deadlines;
    };

    void worker_loop(EpollShard& shard);
    void begin_connect(EpollShard& shard, OperationPtr op);
    void advance(EpollShard& shard, OperationPtr op, uint32_t events);
    void step_connecting(EpollShard& shard, OperationPtr op);
    void step_tls_handshake(EpollShard& shard, OperationPtr op);
    void step_sending(EpollShard& shard, OperationPtr op);
    void step_recv(EpollShard& shard, OperationPtr op, bool is_recv_first);
    void arm(EpollShard& shard, OperationPtr op, bool want_write);
    void finish(EpollShard& shard, OperationPtr op, OpResult r);
    void sweep_timeouts(EpollShard& shard);
    void close_and_free_tls(OperationPtr op);
    void set_deadline(EpollShard& shard, OperationPtr& op, Clock::duration budget);
    Clock::duration adaptive_connect_budget(EpollShard& shard, const Operation& op) const;
    int next_wait_ms(EpollShard& shard) const;
    std::vector<std::unique_ptr<EpollShard>> shards_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> next_shard_{0};
    mutable std::vector<std::deque<int64_t>> rtt_samples_ms_;
    static constexpr size_t kRttSampleWindow = 32;
};

Bytes run_blocking(Reactor& reactor, OperationPtr op);
void configure_shared_reactor(unsigned num_threads);
Reactor& shared_reactor();

}
