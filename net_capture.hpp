#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>


namespace net_capture {

enum class PortState {
    OPEN,       
    CLOSED,     
};

enum class Proto {
    TCP,
    QUIC,        
    DNS,        
};

enum class IpVersion {
    V4,
    V6,
};

enum class ColorMode {
    Auto,        
    Always,
    Never,
};

struct Finding {
    Proto       proto       = Proto::TCP;
    IpVersion   ip_version  = IpVersion::V4;
    std::string initiator_ip;
    uint16_t    initiator_port = 0;
    std::string responder_ip;
    uint16_t    responder_port = 0;
    PortState   state = PortState::OPEN;
    std::chrono::steady_clock::time_point observed_at;
};

struct Options {
    std::string iface;                 // e.g. "eth0"; empty = pick first non-loopback up interface
    int  pending_timeout_ms = 4000;     // how long a bare SYN/QUIC-Initial waits for a reply before being dropped
    int  sweep_interval_ms  = 1000;     // how often the expiry sweep runs
    bool verbose            = false;
    bool report_closed      = false;    // also emit CLOSED (SYN->RST) findings, not just OPEN
    uint16_t quic_port      = 443;      // UDP port watched for QUIC long-header Initial packets
    bool detect_quic        = true;     // set false to fall back to TCP-only capture
    uint16_t dns_port       = 53;       // UDP port watched for DNS query/response traffic
    bool detect_dns         = true;     // set false to disable DNS query/response correlation
    ColorMode color         = ColorMode::Auto;
    bool detect_established_traffic = true;
    int dedup_window_ms = 5000;
    int duration_ms = 0;
};

bool parse_duration_ms(const std::string& text, int& out_ms);

struct Stats {
    uint64_t packets_seen        = 0;
    uint64_t syn_seen            = 0;
    uint64_t synack_seen         = 0;
    uint64_t rst_seen            = 0;
    uint64_t matched_open        = 0;   // OPEN via an actually-observed SYN -> SYN-ACK
    uint64_t matched_closed      = 0;
    uint64_t pending_expired     = 0;
    uint64_t ack_seen               = 0; // bare ACK (no SYN/RST/PSH/FIN)
    uint64_t finack_seen            = 0; // FIN+ACK
    uint64_t pshack_seen            = 0; // PSH+ACK
    uint64_t psh_seen               = 0; // bare PSH (no ACK -- unusual but still evidence)
    uint64_t matched_open_established = 0;

    uint64_t quic_initial_seen    = 0;
    uint64_t quic_matched_open    = 0;
    uint64_t quic_pending_expired = 0;

    uint64_t dns_query_seen       = 0;
    uint64_t dns_matched_open     = 0;
    uint64_t dns_pending_expired  = 0;
    uint64_t duplicates_suppressed = 0;
};

class Capture {
public:
    explicit Capture(Options opts);
    ~Capture();

    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    bool run(const std::function<void(const Finding&)>& on_finding);

    void stop() noexcept;
    const Stats& stats() const noexcept { return stats_; }
    const std::string& last_error() const noexcept { return last_error_; }

private:
    struct PendingSyn {
        IpVersion   ip_version;
        std::string initiator_ip;
        uint16_t    initiator_port;
        std::string responder_ip;
        uint16_t    responder_port;
        uint32_t    syn_seq;
        std::chrono::steady_clock::time_point sent_at;
    };

    struct PendingQuic {
        IpVersion   ip_version;
        std::string initiator_ip;
        uint16_t    initiator_port;
        std::string responder_ip;
        uint16_t    responder_port;
        std::chrono::steady_clock::time_point sent_at;
    };

    struct PendingDns {
        IpVersion   ip_version;
        std::string initiator_ip;
        uint16_t    initiator_port;
        std::string responder_ip;
        uint16_t    responder_port;
        std::chrono::steady_clock::time_point sent_at;
    };
    struct ReportedKey {
        Proto       proto;
        IpVersion   ip_version;
        std::string initiator_ip;
        uint16_t    initiator_port;
        std::string responder_ip;
        uint16_t    responder_port;
        PortState   state;
        std::chrono::steady_clock::time_point last_reported;
    };

    Options     opts_;
    int         fd_ = -1;
    std::atomic<bool> stop_{false};
    Stats       stats_;
    std::string last_error_;
    std::vector<PendingSyn>  pending_;
    std::vector<PendingQuic> pending_quic_;
    std::vector<PendingDns>  pending_dns_;
    std::vector<ReportedKey> reported_;

    bool open_socket();
    void set_promisc(bool on);
    void handle_packet(const uint8_t* buf, size_t len,
                        const std::function<void(const Finding&)>& on_finding);
    void handle_ipv4(const uint8_t* ip_start, size_t ip_avail,
                      const std::function<void(const Finding&)>& on_finding);
    void handle_ipv6(const uint8_t* ip_start, size_t ip_avail,
                      const std::function<void(const Finding&)>& on_finding);
    void handle_tcp(IpVersion ver, const std::string& src_ip, const std::string& dst_ip,
                     const uint8_t* tcp_start, size_t tcp_avail,
                     const std::function<void(const Finding&)>& on_finding);
    void handle_udp(IpVersion ver, const std::string& src_ip, const std::string& dst_ip,
                     const uint8_t* udp_start, size_t udp_avail,
                     const std::function<void(const Finding&)>& on_finding);
    void handle_quic(IpVersion ver, const std::string& src_ip, uint16_t src_port,
                      const std::string& dst_ip, uint16_t dst_port,
                      const uint8_t* payload, size_t payload_len,
                      const std::function<void(const Finding&)>& on_finding);
    void handle_dns(IpVersion ver, const std::string& src_ip, uint16_t src_port,
                     const std::string& dst_ip, uint16_t dst_port,
                     const uint8_t* payload, size_t payload_len,
                     const std::function<void(const Finding&)>& on_finding);
    void sweep_expired();
    void close_socket() noexcept;
    bool dedupe_and_mark(const Finding& f);
};
int run_netradar(const Options& opts);

}
