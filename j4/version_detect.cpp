#include "version_detect.h"
#include "probe.h"

#include <mutex>
#include <cstring>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

using clock_ms = std::chrono::steady_clock;
static long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               clock_ms::now().time_since_epoch()).count();
}

/* ── Lazy-loaded, read-only-after-init probe database ─────────────── */
static AllProbes   g_allprobes;
static bool         g_loaded = false;
static std::once_flag g_load_flag;
static bool          g_load_ok = false;

bool init_version_detection(const std::string& probe_file) {
    std::call_once(g_load_flag, [&]() {
        try {
            g_allprobes.loadFromFile(probe_file.c_str());
            g_load_ok = true;
        } catch (const std::exception& e) {
            std::cerr << "[-sV] failed to load " << probe_file
                      << ": " << e.what() << "\n";
            g_load_ok = false;
        }
        g_loaded = true;
    });
    return g_load_ok;
}

/* ── Reusable TLS context (see earlier efficiency note: build once) ── */
static SSL_CTX* get_shared_ssl_ctx() {
    static SSL_CTX* ctx = [] {
        SSL_CTX* c = SSL_CTX_new(TLS_client_method());
        if (c) {
            SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
            SSL_CTX_set_verify(c, SSL_VERIFY_NONE, nullptr); // we're fingerprinting, not validating
        }
        return c;
    }();
    return ctx;
}

/* ── Plain TCP connect with a real timeout (non-blocking + poll) ──── */
static int connect_with_timeout(const std::string& ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) { close(fd); return -1; }

    int rc = connect(fd, (sockaddr*)&addr, sizeof(addr));
    if (rc == 0) return fd; // connected immediately

    if (errno != EINPROGRESS) { close(fd); return -1; }

    pollfd pfd{fd, POLLOUT, 0};
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) { close(fd); return -1; } // timeout or error

    int so_err = 0; socklen_t len = sizeof(so_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len);
    if (so_err != 0) { close(fd); return -1; }

    return fd;
}

/* ── Connection handle: abstracts plain vs TLS so the driving loop
   below doesn't care which one it's talking to ──────────────────── */
struct Conn {
    int  fd  = -1;
    SSL* ssl = nullptr;

    bool open(const std::string& ip, uint16_t port, bool use_tls, int timeout_ms) {
        fd = connect_with_timeout(ip, port, timeout_ms);
        if (fd < 0) return false;
        if (!use_tls) return true;

        SSL_CTX* ctx = get_shared_ssl_ctx();
        if (!ctx) { close(fd); fd = -1; return false; }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_connect_state(ssl);

        // handshake with the same overall timeout budget
        pollfd pfd{fd, 0, 0};
        long deadline = now_ms() + timeout_ms;
        for (;;) {
            int r = SSL_connect(ssl);
            if (r == 1) return true;
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ)  pfd.events = POLLIN;
            else if (err == SSL_ERROR_WANT_WRITE) pfd.events = POLLOUT;
            else { close_conn(); return false; }

            long remain = deadline - now_ms();
            if (remain <= 0 || poll(&pfd, 1, remain) <= 0) { close_conn(); return false; }
        }
    }

    // returns bytes read, 0 on clean EOF, -1 on error/timeout
    int recv_some(uint8_t* buf, size_t len, int timeout_ms) {
        pollfd pfd{fd, POLLIN, 0};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
        if (ssl) return SSL_read(ssl, buf, (int)len);
        return (int)::recv(fd, buf, len, 0);
    }

    bool send_all(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            int n = ssl ? SSL_write(ssl, data + sent, (int)(len - sent))
                        : (int)::send(fd, data + sent, len - sent, 0);
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }

    void close_conn() {
        if (ssl)      { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (fd >= 0)  { close(fd); fd = -1; }
    }
    ~Conn() { close_conn(); }
};

/* ── Drive one open port through the probe state machine ──────────── */
ServiceVersionInfo detect_service_version(const std::string& ip,
                                           uint16_t port,
                                           int timeout_ms) {
    ServiceVersionInfo out;

    if (!g_loaded) init_version_detection(); // default path, lazy
    if (!g_load_ok) return out;              // DB missing — caller shows "?"

    ProbeEngine engine(&g_allprobes, /*version_intensity=*/7);
    ServiceNFO  svc(&g_allprobes);
    svc.portno = port;
    svc.proto  = IPPROTO_TCP;

    const int connect_timeout_ms = std::min(timeout_ms, DEFAULT_CONNECT_TIMEOUT);

    while (engine.hasMoreProbes(&svc)) {
        ServiceProbe* probe = svc.currentProbe();
        if (!probe) break;

        bool use_tls = (svc.tunnel == ServiceTunnel::SSL);

        Conn conn;
        if (!conn.open(ip, port, use_tls, connect_timeout_ms)) {
            if (engine.handleEOF(&svc, /*hadData=*/false, 0)) break;
            continue;
        }

        int slen = 0;
        const u8* pstr = probe->getProbeString(&slen);
        if (slen > 0 && !conn.send_all(pstr, (size_t)slen)) {
            if (engine.handleEOF(&svc, false, 0)) break;
            continue;
        }

        int  wait_budget = std::min(timeout_ms, probe->getTotalWaitMs());
        long deadline     = now_ms() + wait_budget;
        bool had_data     = false;
        bool decided      = false;
        uint8_t buf[8192];

        while (true) {
            long remain = deadline - now_ms();
            if (remain <= 0) break;
            int n = conn.recv_some(buf, sizeof(buf), (int)remain);
            if (n > 0) {
                had_data = true;
                if (engine.feedResponse(&svc, buf, n)) { decided = true; break; }
                continue; // keep accumulating for this probe
            }
            break; // EOF / error / timeout
        }

        long elapsed = wait_budget - (deadline - now_ms());
        conn.close_conn();

        if (!decided) {
            if (engine.handleEOF(&svc, had_data, elapsed)) break;
            // else: state machine advanced to the next probe, loop again
        }
        // if decided==true and hasMoreProbes() is still true, that means
        // scanThroughTunnel() just escalated to SSL — loop reconnects
        // with use_tls=true automatically on the next iteration.
    }

    ScanResult r = engine.buildResult(&svc);
    out.matched   = (r.state == ProbeState::FINISHED_HARDMATCHED ||
                      r.state == ProbeState::FINISHED_SOFTMATCHED);
    out.service   = r.service;
    out.product   = r.product;
    out.version   = r.version;
    out.extrainfo = r.extrainfo;
    return out;
}

std::string ServiceVersionInfo::combined() const {
    if (!matched) return "?";
    std::string s = product.empty() ? service : product;
    // lowercase + strip spaces to mimic the "openssh8.1" sample style
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    std::string s2;
    for (char c : s) if (c != ' ') s2 += c;
    if (!version.empty()) s2 += version;
    return s2.empty() ? "?" : s2;
}
