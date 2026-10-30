#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <streambuf>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <utility>
#include <termios.h>
#include "scan.hpp"
#include "probe.hpp"

struct TargetLocality {
    bool onlink = false;
    bool same_network_internal = false;
    bool via_virtual_interface = false;
    bool corroborated = true;
    std::string routed_iface;
};

class TeeBuf : public std::streambuf {
    std::streambuf* real;
    std::ostringstream capture;
protected:
    int overflow(int c) override {
        if (c != EOF) {
            capture.put(static_cast<char>(c));
            real->sputc(static_cast<char>(c));
        }
        return c;
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        capture.write(s, n);
        return real->sputn(s, n);
    }
public:
    explicit TeeBuf(std::streambuf* r) : real(r) {}
    std::string str() const { return capture.str(); }
};

extern std::unordered_map<std::string, std::string> ip_to_domain_map;
extern std::vector<std::string> g_dns_bypassed_targets;
extern std::vector<std::string> g_dns_servers;
extern std::vector<std::string> g_dns_tls_servers;
extern std::string g_signature_conf_path;
extern int g_target_ip_pref;
extern bool g_saw_literal_target;
extern std::vector<std::pair<std::string, std::string>> g_eliminated_targets;
extern struct termios g_orig_termios;
extern bool g_termios_saved;
void restore_terminal_echo();
void trim_in_place(std::string& s);
void print_typewriter(std::ostream& os, const std::string& text,
                       std::chrono::milliseconds delay = std::chrono::milliseconds(1));

extern const char* kMantra;
void print_full_help();
bool resolve_domain_to_ip(const std::string& domain, std::string& resolved_ip);
bool custom_dns_configured();
void load_mac_vendors(const std::string& filename);
bool read_ips_from_file(const std::string& filename, std::vector<std::string>& ips);
bool process_ip_string(const std::string& ip_str, std::vector<std::string>& ips);
TargetLocality assess_target_locality(const std::string& target_ip, std::string interface = "");
std::vector<std::string> perform_sn_discovery(const std::vector<std::string>& ips,
                                               std::string& interface,
                                               size_t& down_hosts_out,
                                               std::unordered_map<uint32_t, std::string>& mac_cache_out);

void print_grepable_output(const std::string& target_spec,
                            const std::vector<std::string>& host_list,
                            bool ip_only = false);

void save_scan_results(const std::vector<RecPross>& results, const std::string& output_file,
                        const std::string& raw_log = "");

void emergency_cleanup();
void signal_handler(int sig);

void thread_worker(const std::vector<std::string>& thread_ips,
                   const std::vector<std::string>& thread_hostnames,
                   const std::vector<int>& ports,
                   PacketBufferPool& pool, int send_sock, std::vector<RecPross>& results, size_t main_batch_size,
                   uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered,
                   bool print_filtered_if_few, bool fast_scan, std::atomic<int>& down_hosts_count, ScanType scan_type,
                   uint8_t custom_ttl, uint8_t custom_dscp, uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                   const TcpBuildOptions& opts,
                   int user_rcvbuf_size, const std::string& source_ip, size_t send_uring_depth, size_t rcv_uring_depth,
                   uint16_t base_source_port, uint16_t retry_source_port, bool debug_packet, bool debug_rtt, bool debug_wsn, bool debug_ttl, bool debug_demux, bool debug_strack, bool debug_send, bool frag_out_of_order, bool frag_overlap, uint16_t frag_overlap_bytes, bool frag_zof, const SportRangeConfig& sport_range_cfg, const GsportConfig& gsport_cfg, int initial_rtt_ms, int port_timeout_min_ms, int
                   port_timeout_max_ms, RateConfig rate_config, JitterConfig jitter_config, BatchDelayConfig batch_delay_config,
                   BandwidthConfig bandwidth_config, bool is_threaded,
                   GlobalRecvCtx* g_recv, GlobalSendCtx* g_send, const std::string& user_interface,
                   const EthArpOptions& eth_opts, const std::unordered_map<uint32_t, std::string>& pre_resolved_arp_cache,
                   bool enable_version_detection = false, AllProbes* vprobes = nullptr,
                   const VersionDetectOptions& sv_opts = VersionDetectOptions{});
void load_signature_config(const std::string& path);
