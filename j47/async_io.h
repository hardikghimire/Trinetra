// async_io.h
//
// Shared non-blocking reactor for Shiv's version-detection probing.
//
// WHY THIS EXISTS
// ----------------
// The old capture_tcp()/capture_ssl()/... functions in control.cpp each did a
// blocking connect() + send() + recv() (or SSL_connect()/SSL_read()/SSL_write())
// on their own fd, so run_version_probe() could only ever have ONE port's
// socket in flight at a time. To probe many ports "at once" we need many
// sockets in flight concurrently without spawning a thread per socket.
//
// This reactor gives every capture_* function the same call shape it had
// before (fill in target/payload/timeouts, get bytes back) but the actual
// send/recv happens on a small shared pool of epoll loops, so hundreds of
// ports can have connects/sends/reads outstanding simultaneously.
//
// USAGE PATTERN
// -------------
//   auto op = std::make_shared<async_io::Operation>();
//   op->ip = ip; op->port = port; op->proto = async_io::Proto::TCP;
//   op->send_payload = payload;
//   op->timeouts = { .connect_sec = 3, .first_byte_sec = timeout_sec };
//   op->on_complete = [](async_io::Operation& o) {
//       // runs on a reactor thread — do the minimal work here (copy out
//       // o.recv_data, o.result) and hand off to your own thread pool for
//       // any heavier per-port staging/matching logic.
//   };
//   g_reactor.submit(op);
//
// For call sites that aren't async-ready yet, async_io::run_blocking() wraps
// submit() + a condition variable so the call looks exactly like the old
// blocking capture_*() functions — this lets us migrate control.cpp one
// function at a time without breaking the ones not yet converted.

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
    SUCCESS,          // completed; recv_data holds whatever arrived (may be empty on clean 0-byte close)
    CONNECT_FAILED,   // TCP connect() never completed (refused/timeout/unreachable)
    TLS_FAILED,       // TLS handshake failed
    SEND_FAILED,      // send()/SSL_write() hard-failed
    TIMEOUT,          // no data before first_byte_sec elapsed (distinct from CONNECT_FAILED)
    CANCELLED
};

// TLS parameters — mirrors the fields control.cpp's g_tls_config already carries.
struct TlsOptions {
    bool        verify_peer = false;
    std::string ca_file;
    std::string ca_path;
    std::string client_cert;
    std::string client_key;
    std::string sni;                 // required for Proto::TLS
    std::string cipher_list_tls12;   // empty => reactor default list
    std::string ciphersuites_tls13;  // empty => reactor default list
};

struct Timeouts {
    int connect_sec    = 3;
    int first_byte_sec = 5;
    // idle_sec: once the first byte/record has arrived, how long to keep
    // draining further reads before calling the response complete. Mirrors
    // the old recv_all_tcp()/capture_ssl() "shrink timeout after first byte"
    // behavior. 0 => auto = max(2, first_byte_sec/2), same as before.
    int idle_sec       = 0;

    // min_connect_ms: floor applied under the RTT-adaptive connect-timeout
    // logic (see Reactor's adaptive deadline tracking). Prevents a fast local
    // target's tiny measured RTT from producing an unrealistically short
    // deadline for the *next* op on a slow/remote target. 0 => reactor
    // default (250ms).
    int min_connect_ms = 0;
};

// Source-port control for a single Operation. Plain TCP/TLS ops normally use
// an ephemeral source port (SourcePortMode::EPHEMERAL, the default) chosen by
// the kernel — this is what every probe should use.
//
// FIXED exists ONLY for a last-resort fallback path (e.g. capture_fallback()
// in control.cpp trying source port 443 after every normal probe has already
// failed): some middleboxes/stateful firewalls are more permissive toward
// traffic that looks like an established-service's return traffic. Binding a
// low/well-known source port:
//   - requires CAP_NET_BIND_SERVICE or root for ports < 1024 — bind() may
//     fail with EACCES, which the reactor reports as CONNECT_FAILED with
//     last_errno == EACCES rather than crashing or silently ignoring it.
//   - only one in-flight connection can hold a given (local_ip, local_port,
//     remote_ip, remote_port) 4-tuple at a time, so FIXED-source-port ops
//     MUST be serialized by the caller (do not submit() more than one
//     concurrently for the same port) — the reactor sets SO_REUSEADDR (and
//     SO_REUSEPORT where available) to reduce but not eliminate
//     TIME_WAIT-related EADDRINUSE flakiness across back-to-back attempts.
//   - a second, distinct TIME_WAIT collision can surface as EADDRNOTAVAIL
//     at connect() time (not EADDRINUSE at bind() time): bind() succeeds,
//     but the kernel refuses to let the same local port reconnect to the
//     exact same remote ip:port while a TIME_WAIT entry from the previous
//     attempt to THAT SAME target is still alive. begin_connect() retries
//     both this and the bind()-stage EADDRINUSE case with the same bounded
//     backoff — see async_io.cpp.
struct SourcePort {
    enum class Mode { EPHEMERAL, FIXED };
    Mode mode = Mode::EPHEMERAL;
    uint16_t port = 0; // consulted only when mode == FIXED
};

class Reactor;

class Operation {
public:
    // ---- filled in by the caller before submit() ----
    std::string ip;
    int         port = 0;
    Proto       proto = Proto::TCP;
    Bytes       send_payload;          // may be empty (probe that only listens, e.g. NULL probe)
    Timeouts    timeouts;
    TlsOptions  tls;                   // only consulted if proto == Proto::TLS
    SourcePort  src_port;              // default EPHEMERAL — see SourcePort docs above

    // Cap on recv_data's size before the reactor stops reading and treats
    // the response as complete (OpResult::SUCCESS), independent of the
    // first_byte_sec/idle_sec timeouts. 0 => reactor default (64KB — see
    // kMaxResponse in async_io.cpp). Exposed per-Operation so a caller that
    // genuinely needs a larger capture (or wants to fail fast on a smaller
    // one) doesn't have to touch the shared compile-time constant.
    size_t      max_response_bytes = 0;

    // ---- filled in by the reactor as it runs / on completion ----
    std::atomic<OpResult> result{OpResult::PENDING};
    Bytes       recv_data;
    int         last_errno     = 0;
    int         last_ssl_error = 0;    // SSL_get_error() code, if proto == TLS and it failed
    // Measured connect RTT (submit -> connected). Only meaningful once
    // result != PENDING. Exposed for logging/tuning.
    std::chrono::milliseconds connect_rtt{0};

    // Valid ONLY during on_complete(), on the reactor thread, and only for
    // Proto::TLS: use it to call extract_tls_cert_info(ssl_handle) etc.
    // Do not store this pointer — it is freed right after on_complete returns.
    SSL* ssl_handle = nullptr;

    // Invoked exactly once, on a reactor worker thread, when the operation
    // reaches a terminal state (SUCCESS or any failure). Keep this callback
    // cheap: copy out what you need and hand heavier work to your own
    // thread pool, so you don't block the shared reactor thread.
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
    bool     armed_write_ = false; // current epoll interest direction (for logging/asserts)
    Clock::time_point stage_deadline_;
    Clock::time_point submit_time_;   // set right before begin_connect(); basis for connect_rtt
    int      owning_epoll_idx_ = -1;
};

using OperationPtr = std::shared_ptr<Operation>;

// A small pool of epoll-driven worker threads. One process-wide instance
// (g_reactor, declared below) is normally enough; every in-flight probe
// across every port shares these threads, so N ports = N concurrent sockets,
// not N threads.
class Reactor {
public:
    // num_threads == 0 => hardware_concurrency() (min 2, max 8 — probing is
    // I/O bound, more than a handful of epoll loops doesn't help and just
    // adds context-switch overhead).
    explicit Reactor(unsigned num_threads = 0);
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    // Thread-safe. Caller must keep the Operation alive (via the shared_ptr)
    // until on_complete has fired.
    void submit(OperationPtr op);

    // Stops all worker threads. Any operations still pending are completed
    // with OpResult::CANCELLED. Safe to call from destructor implicitly.
    void shutdown();

private:
    // deadlines_ is a multimap ordered by stage_deadline_ so sweep_timeouts()
    // and the adaptive epoll_wait() budget can both find "what's the soonest
    // deadline" in O(log n) instead of the old O(n) walk over every in-flight
    // op on every 100ms tick. Every stage transition that changes
    // op->stage_deadline_ must update its entry here via reindex_deadline()
    // (erase the old {old_deadline, fd} pair, insert the new one) — this is
    // the one invariant the rest of the reactor code must preserve.
    struct EpollShard {
        int epoll_fd = -1;
        std::mutex mu;
        std::unordered_map<int /*fd*/, OperationPtr> ops;
        std::multimap<Clock::time_point, int /*fd*/> deadlines;
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

    // Sets op->stage_deadline_ to now + budget and (re)inserts the
    // corresponding entry in shard.deadlines. Call this instead of writing
    // stage_deadline_ directly — callers must hold shard.mu.
    void set_deadline(EpollShard& shard, OperationPtr& op, Clock::duration budget);
    // Computes an adaptive connect-timeout budget for `op`: starts from
    // op->timeouts.connect_sec but is clamped down toward a rolling median
    // of recently-measured connect RTTs on this shard once enough samples
    // exist, so a batch of probes against a fast/local target isn't stuck
    // waiting out a conservative fixed timeout on every filtered port. Never
    // goes below timeouts.min_connect_ms (default 250ms) or above the
    // caller's own connect_sec ceiling.
    Clock::duration adaptive_connect_budget(EpollShard& shard, const Operation& op) const;
    // How long the next epoll_wait() should block: min(kTickMs, time until
    // the shard's soonest deadline), floored at 1ms. Falls back to kTickMs
    // when the shard has no in-flight ops, so an idle worker still wakes
    // periodically to notice shutdown.
    int next_wait_ms(EpollShard& shard) const;

    std::vector<std::unique_ptr<EpollShard>> shards_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> next_shard_{0};

    // Rolling connect-RTT samples per shard, used by adaptive_connect_budget().
    // Guarded by the owning shard's mu (stored alongside shards_ by index).
    mutable std::vector<std::deque<int64_t>> rtt_samples_ms_;
    static constexpr size_t kRttSampleWindow = 32;
};

// -----------------------------------------------------------------------
// run_blocking(): bridges old blocking call sites onto the reactor without
// requiring them to be rewritten yet. Submits `op`, blocks the calling
// thread (NOT a reactor thread) until on_complete fires, then returns
// op->recv_data. Any on_complete the caller set beforehand still runs first;
// this appends its own completion signal after it.
//
// This does NOT defeat the purpose of the reactor: the calling thread
// blocks, but the fd itself sits in the shared epoll loop the whole time,
// so many other operations (submitted by other threads probing other
// ports) still make progress concurrently. It's meant as a migration aid
// and for call sites (e.g. one-off ancillary checks) where a synchronous
// shape is genuinely simpler and doesn't sit on the hot path.
// -----------------------------------------------------------------------
Bytes run_blocking(Reactor& reactor, OperationPtr op);

// Process-wide shared reactor. Constructed lazily on first use.
Reactor& shared_reactor();

} // namespace async_io
