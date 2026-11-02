#include "utils.hpp"
#include "public_db.hpp"
#include "parser.hpp"
#include <fstream>
#include <termios.h>
#include <cstdlib>
#include "scan.hpp"
#include "icmp_ping.hpp"
#include "traceroute.hpp"
#include "probe.hpp"
#include "async_io.hpp"
#include "netns_split.hpp"
#include "net_capture.hpp"
#include "os_detect.hpp"
#include <stdexcept>
#include <future>
#include <thread>
#include <ctime>
#include <map>
#include <algorithm>
#include <pthread.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sstream>
#include <set>
#include <iomanip>
#include <cstdio>
#include <cerrno>
#include <queue>
#include <unordered_set>
#include <csignal>
#include <charconv>
#include <array>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "handler.hpp"
#include "dns_enum.hpp"
#include "server.hpp"
#include <sys/utsname.h>
#include "dns_enum.hpp"
#include "ssl_enum.hpp"
#include "discover.hpp"


namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string green   = "\033[32m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string white   = "\033[97m";
    const std::string red     = "\033[91m";
    const std::string dim     = "\033[2m";    
    const std::string cyan    = "\033[36m";    
    const std::string bright_cyan = "\033[96m";
    
}

static std::string shiv_get_os_pretty_name() {
    std::ifstream f("/etc/os-release");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("PRETTY_NAME=", 0) == 0) {
            std::string val = line.substr(12);
            if (!val.empty() && val.front() == '"') val.erase(0, 1);
            if (!val.empty() && val.back() == '"') val.pop_back();
            return val;
        }
    }
    return "Unknown";
}

static std::string shiv_get_kernel_release() {
    struct utsname uts{};
    if (uname(&uts) == 0) return std::string(uts.release);
    return "Unknown";
}

static bool shiv_kernel_supports_io_uring(const std::string& release) {
    int major = 0, minor = 0;
    if (sscanf(release.c_str(), "%d.%d", &major, &minor) != 2) return false;
    if (major > 5) return true;
    if (major == 5 && minor >= 1) return true;
    return false;
}

static std::string shiv_enum_timestamp() {
    time_t now = time(nullptr);
    struct tm t;
    localtime_r(&now, &t);
    char buf[100];
    strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &t);
    return std::string(buf);
}

static void print_shiv_enum_banner(const std::string& scan_name) {
    std::cout << "\nStarting " << color::bold << "Shiv" << color::reset
               << " (" << color::yellow << scan_name << color::reset << ") at "
               << shiv_enum_timestamp() << "\n";
}

static bool network_is_up() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(53);
    if (inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr) != 1) {
        close(fd);
        return false;
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    close(fd);
    return rc == 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--server") {
        return server::run(argc, argv);
    }

    mallopt(M_ARENA_MAX, 2);          
    mallopt(M_MMAP_THRESHOLD, 1 << 20);
    mallopt(M_TRIM_THRESHOLD, -1); 
    mallopt(M_TOP_PAD, 4 << 20);
    std::streambuf* teeOut_orig = std::cout.rdbuf();
    std::streambuf* teeErr_orig = std::cerr.rdbuf();
    TeeBuf teeOut(teeOut_orig);
    TeeBuf teeErr(teeErr_orig);
    std::cout.rdbuf(&teeOut);
    std::cerr.rdbuf(&teeErr);

    load_mac_vendors("/usr/share/shiv/mac-vendors.txt");
    load_ip_range_databases(
        "/usr/share/shiv/aws.txt",
        "/usr/share/shiv/cloudflare_range.txt",
        "/usr/share/shiv/akamai.txt",
        "/usr/share/shiv/azure_range.txt",
        "/usr/share/shiv/digitalocean_range.txt",
        "/usr/share/shiv/google_range.txt",
        "/usr/share/shiv/alibaba.txt",
        "/usr/share/shiv/fastly.txt",
        "/usr/share/shiv/hetzner.txt",
        "/usr/share/shiv/vultr.txt",
        "/usr/share/shiv/zscaler.txt",
        "/usr/share/shiv/googlebot.txt",
        "/usr/share/shiv/linode.txt",
        "/usr/share/shiv/tor.txt");
        
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
        g_termios_saved = true;
        struct termios raw = g_orig_termios;
        raw.c_lflag &= ~(ECHO | ICANON); 
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        std::atexit(restore_terminal_echo);   
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    
    struct SignalRegistrar {
        static bool register_signals(struct sigaction* sa) {
            const std::pair<int, const char*> signals[] = {
                {SIGINT,  "SIGINT"},   {SIGSEGV, "SIGSEGV"}, {SIGABRT, "SIGABRT"},
                {SIGTERM, "SIGTERM"},  {SIGFPE,  "SIGFPE"},  {SIGBUS,  "SIGBUS"},
                {SIGILL,  "SIGILL"},   {SIGSYS,  "SIGSYS"},  {SIGPIPE, "SIGPIPE"},
                {SIGXCPU, "SIGXCPU"},  {SIGXFSZ, "SIGXFSZ"}
            };
            
            for (const auto& [sig, name] : signals) {
                if (sigaction(sig, sa, nullptr) == -1) {
                    std::cerr << "Failed to register " << name << ": " 
                              << strerror(errno) << std::endl;
                    return false;
                }
            }
            return true;
        }
    };

    if (!SignalRegistrar::register_signals(&sa)) {
        return 1;
    }

    {
        struct rlimit memlock_limit{};
        if (getrlimit(RLIMIT_MEMLOCK, &memlock_limit) == 0) {
            constexpr rlim_t DESIRED_MEMLOCK = 64ULL * 1024 * 1024; // 64 MiB
            if (memlock_limit.rlim_cur != RLIM_INFINITY &&
                memlock_limit.rlim_cur < DESIRED_MEMLOCK) {
                rlim_t new_soft = (memlock_limit.rlim_max == RLIM_INFINITY)
                                       ? DESIRED_MEMLOCK
                                       : std::min(DESIRED_MEMLOCK, memlock_limit.rlim_max);
                struct rlimit updated = memlock_limit;
                updated.rlim_cur = new_soft;
                if (setrlimit(RLIMIT_MEMLOCK, &updated) != 0) {
                    std::cerr << "[main] warning: could not raise RLIMIT_MEMLOCK ("
                              << strerror(errno)
                              << "); idle-ring creation may fail under concurrent load\n";
                }
            }
        }
    }

    struct Config {
       bool use_badsum = false,badsum_value_set = false,use_partial_badsum = false, fast_scan = true,use_file = true, print_individual_closed_filtered = false,
            print_filtered_if_few = false, graceful_scan = false,use_manual_tcp_checksum = false,
            sack_permitted = true, use_custom_data = false, generate_random_data = false,debug_packet = false,use_trial_api = false,expect_domain_for_trial = false,use_shodan_enum = false,
            force_sqpoll = false;
       uint16_t custom_badsum_value = 0, manual_tcp_checksum = 0,base_source_port = 0, retry_source_port = 8443, win_size = 0, custom_ip_flags = 0x4000,
                fixed_ip_id = 0, data_length = 0, nops_count = 0, mss_value = 1460,frag_offset_size  = 8,mtu_size = 0;
       int user_rcvbuf_size = -1,port_timeout_min_ms = 5,port_timeout_max_ms = 700;
       uint8_t custom_ttl = 64, window_scale = 7,custom_dscp = 0,custom_ip_tos = 0;SportRangeConfig sport_range_cfg;GsportConfig gsport_cfg;
       uint32_t seq_num = 0, timestamp_val = generate_tcp_tsval(), timestamp_ecr_custom = 0;
       size_t send_uring_depth = 2048, rcv_uring_depth = 0, main_batch_size = 500;
       bool batch_specified = false;
       bool debug_rtt = false;
       int initial_rtt_ms = 290;
       uint64_t rate_dyn_window_us = 200'000;
       uint32_t rate_dyn_min = 20, rate_dyn_max = 150;
       uint64_t batch_delay_dyn_min_us = 0;
       uint64_t batch_delay_dyn_max_us = 800'000;
       bool rate_explicit = false, rate_dyn_explicit = false;
       bool batch_delay_explicit = false, batch_delay_dyn_explicit = false;
       bool debug_wsn = false;
       bool debug_ttl = false;
       bool debug_demux = false;
       bool debug_strack = false;
       bool debug_send = false;
       bool use_ip_tos = false;
       bool use_fragmentation = false;
       bool frag_out_of_order = false;
       uint16_t frag_overlap_bytes = 8;
       bool frag_overlap = false;
       bool frag_zof = false; 
       ScanType scan_type = ScanType::SYN;
       bool scan_type_specified = false;
       std::string partial_badsum_type, source_ip, ip_file, port_spec, interface,
                   output_file, exclude_ports_spec, custom_data, tfo_cookie_str,trial_api_key,
                   target_spec_display;
       bool use_split = false;
       std::string split_iface, split_mac, split_ip, split_gw, split_ip6, split_gw6;
       bool split_iface_set = false, split_mac_set = false,
            split_ip_set = false, split_gw_set = false,
            split_ip6_set = false, split_gw6_set = false;
       std::vector<int> excluded_ports,parsed_ports;
       bool use_tfo_cookie = false, tfo_cookie_as_hex = false, tfo_cookie_random = false;
       uint64_t tfo_cookie_num = 0;
       size_t tfo_cookie_length = 0;
       bool    use_tcp_mptcp = false;
       bool    use_tcp_ao = false;
       uint8_t tcp_ao_keyid = 1, tcp_ao_rnextkeyid = 1, tcp_ao_mac_len = 12;
       bool    use_ip_router_alert = false;
       bool    use_ip_security = false;
       uint8_t ip_security_classification = 0x01;
       Ipv6ExtHeaderOptions ipv6_ext_opts;
       RateConfig rate_config;
       JitterConfig  jitter_config;
       BatchDelayConfig batch_delay_config;
       BandwidthConfig   bandwidth_config;
       PacketLengthConfig packet_length_config;
       IpIdMode ip_id_mode  = IpIdMode::RANDOM;
       bool skip_ping       = false;
       bool sn_scan         = false;
       bool sn6_scan        = false;
       bool traceroute           = false;
       int  traceroute_max_hops  = 30;
       int  traceroute_probes    = 3;
       int  traceroute_timeout_ms = 1000;
       bool traceroute_no_dns    = false;
       bool traceroute_no_geo    = false;
       int  traceroute_ip_version = 4;
       bool print_grepable  = false;
       bool enable_version_detection = false;
       int  sv_timeout_sec         = 3;
       int  sv_connect_timeout_sec = 0;
       int  sv_intensity           = 7;
       bool sv_udp                 = false;
       bool sv_force_raw           = false;
       bool sv_force_http          = false;
       bool sv_force_https         = false;
       bool sv_tls_verify          = false;
       bool sv_verbose             = false;
       std::string sv_save_file, sv_tls_ca_file, sv_tls_ca_path,
                   sv_tls_cert, sv_tls_key, sv_tls_sni, sv_host_override;
       EthArpOptions eth_opts;
       bool dns_enum_enabled = false;
       bool ssl_enum_enabled = false;
       bool netradar_enabled = false;
       int  netradar_duration_ms = 0;     
       bool netradar_time_specified = false;
       std::string discover_country;
       std::string discover_cn;
       std::string discover_org;
       bool        discover_owner = false;
       std::string discover_owner_name;
       std::string discover_ip;
       std::string discover_range;
       std::string discover_asn;   
   } config;
   
    std::vector<std::string> ips;
    int arg_idx = 1;
    auto parse_duration_allow_zero = [](const std::string& s, uint64_t& out, const char* opt) -> bool {
        if (s == "0" || s == "0ms" || s == "0s" || s == "0m") { out = 0; return true; }
        return parse_duration_to_us(s, out, opt);
    };
    auto parse_long_in = [](const std::string& s, const char* opt, long lo, long hi, long& out) -> bool {
        char* end = nullptr; errno = 0;
        long v = s.empty() ? 0 : std::strtol(s.c_str(), &end, 10);
        if (s.empty() || errno != 0 || end == s.c_str() || *end != '\0' || v < lo || v > hi) {
            std::cerr << opt << ": must be an integer between " << lo << " and " << hi << "\n";
            return false;
        }
        out = v; return true;
    };
    auto parse_dbl_in = [](const std::string& s, const char* opt, double lo, double hi, bool lo_excl, double& out) -> bool {
        char* end = nullptr; errno = 0;
        double v = s.empty() ? 0.0 : std::strtod(s.c_str(), &end);
        if (s.empty() || errno != 0 || end == s.c_str() || *end != '\0' || !std::isfinite(v)
            || v > hi || (lo_excl ? v <= lo : v < lo)) {
            std::cerr << opt << ": must be a number " << (lo_excl ? "> " : ">= ") << lo << " and <= " << hi << "\n";
            return false;
        }
        out = v; return true;
    };

    auto get_next_arg = [&](int& idx, const std::string& option_name) -> std::string {
        if (idx + 1 >= argc) {
            std::cerr << "Option " << option_name << " requires an argument\n";
            exit(1);
        }
        return argv[++idx];
    };
    auto sanitize_echo = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
        }
        return out;
    };
    
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) != "--dns-servers") continue;
        if (i + 1 >= argc) {
            std::cerr << "Option --dns-servers requires an argument\n";
            return 1;
        }
        std::string val = argv[i + 1];
        std::vector<std::string> parts;
        std::stringstream ss(val);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            trim_in_place(tok);
            if (!tok.empty()) parts.push_back(tok);
        }
        if (parts.empty() || parts.size() > 10) {
            std::cerr << "--dns-servers requires 1 to 10 comma-separated server IPs (got "
                      << parts.size() << ")\n";
            return 1;
        }
        for (const auto& p : parts) {
            if (get_ip_version(p.c_str()) == 0) {
                std::cerr << "--dns-servers: '" << p << "' is not a valid IPv4 or IPv6 address\n";
                return 1;
            }
        }
        g_dns_servers = std::move(parts);
        break;
    }
    
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) != "--dns-servers-tls") continue;
        if (i + 1 >= argc) {
            std::cerr << "Option --dns-servers-tls requires an argument\n";
            return 1;
        }
        std::string val = argv[i + 1];
        std::vector<std::string> parts;
        std::stringstream ss(val);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            trim_in_place(tok);
            if (!tok.empty()) parts.push_back(tok);
        }
        if (parts.empty() || parts.size() > 10) {
            std::cerr << "--dns-servers-tls requires 1 to 10 comma-separated server IPs (got "
                      << parts.size() << ")\n";
            return 1;
        }
        for (const auto& p : parts) {
            if (get_ip_version(p.c_str()) == 0) {
                std::cerr << "--dns-servers-tls: '" << p << "' is not a valid IPv4 or IPv6 address\n";
                return 1;
            }
        }
        g_dns_tls_servers = std::move(parts);
        break;
    }

    auto parse_uint16 = [](const std::string& str, const std::string& option_name) -> uint16_t {
        try {
            unsigned long value = std::stoul(str);
            if (value > std::numeric_limits<uint16_t>::max()) {
                throw std::out_of_range("value exceeds uint16_t maximum");
            }
            return static_cast<uint16_t>(value);
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str
                      << " (" << e.what() << ")\n";
            exit(1);
        }
    };

    auto parse_uint32 = [](const std::string& str, const std::string& option_name) -> uint32_t {
        try {
            return static_cast<uint32_t>(std::stoul(str));
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str << " (" << e.what() << ")\n";
            exit(1);
        }
    };
    auto parse_size_t = [](const std::string& str, const std::string& option_name) -> size_t {
        try {
            return std::stoul(str);
        } catch (const std::exception& e) {
            std::cerr << "Invalid value for " << option_name << ": " << str << " (" << e.what() << ")\n";
            exit(1);
        }
    };
    auto validate_uring_depth = [](size_t depth) -> bool {
        const std::vector<size_t> allowed_depths = {2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
        return std::find(allowed_depths.begin(), allowed_depths.end(), depth) != allowed_depths.end();
    };
    bool saw_dash4 = false, saw_dash6 = false;
    auto read_words = [&](int& idx, const char* flag) {
        std::string v = get_next_arg(idx, flag);
        while (idx + 1 < argc && argv[idx + 1][0] != '-') { v += ' '; v += argv[++idx]; }
        for (unsigned char ch : v) {
            if (ch < 0x20 || ch == 0x7F) { std::cerr << flag << ": disallowed control character\n"; exit(1); }
        }
        return v;
    };
    std::unordered_map<std::string, std::function<void(int&)>> option_handlers = {
        {"-iL", [&](int& idx) {
            config.ip_file = get_next_arg(idx, "-iL");
        }},
        
        {"--dns-servers", [&](int& idx) {
            get_next_arg(idx, "--dns-servers");
        }},
        
        {"--dns-servers-tls", [&](int& idx) {
            get_next_arg(idx, "--dns-servers-tls"); 
        }},
        
        {"--enum", [&](int& idx) {
            std::string arg_val = get_next_arg(idx, "--enum");
            std::vector<std::string> modules;
            std::stringstream ss(arg_val);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                trim_in_place(tok);
                if (!tok.empty()) modules.push_back(tok);
            }
            if (modules.empty()) {
                std::cerr << "--enum requires at least one of: shodan, dns, trail:<key> (e.g. --enum shodan,ssl,dns,trail:mykey)\n";
                exit(1);
            }
            for (const auto& mod : modules) {
                for (unsigned char c : mod) {
                    if (c < 0x20 || c == 0x7F) {
                        std::cerr << "--enum: module/key contains a disallowed control character\n";
                        exit(1);
                    }
                }
                if (mod == "shodan") {
                    config.use_shodan_enum = true;
                } else if (mod == "dns") {
		    config.dns_enum_enabled = true;
		} else if (mod == "ssl") {
		    config.ssl_enum_enabled = true;
		} else if (mod.rfind("trail:", 0) == 0) {
                    std::string key = mod.substr(6);
                    if (key.empty()) {
                        std::cerr << "--enum trail requires a key, e.g. --enum trail:<api-key>\n";
                        exit(1);
                    }
                    config.use_trial_api = true;
                    config.expect_domain_for_trial = true;
                    config.trial_api_key = key;
                } else if (mod == "trail") {
                    std::cerr << "--enum trail requires a key, e.g. --enum trail:<api-key>\n";
                    exit(1);
                } else {
                    std::cerr << "--enum: unknown module '" << sanitize_echo(mod)
                               << "' (expected shodan, dns, or trail:<key>)\n";
                    exit(1);
                }
            }
        }},
        
        {"--netradar", [&](int& idx) {
            config.netradar_enabled = true;
        }},
        
        {"--time", [&](int& idx) {
            std::string val = get_next_arg(idx, "--time");
            int ms = 0;
            if (!net_capture::parse_duration_ms(val, ms)) {
                std::cerr << "--time: invalid duration '" << sanitize_echo(val)
                           << "' (expected a positive integer with an optional s/m/h suffix, "
                              "e.g. 30s, 5m, 2h -- a bare number is treated as seconds)\n";
                exit(1);
            }
            config.netradar_duration_ms = ms;
            config.netradar_time_specified = true;
        }},
        
        {"--country", [&](int& idx) { config.discover_country = read_words(idx, "--country"); }},
        {"--cn", [&](int& idx) { config.discover_cn = read_words(idx, "--cn"); }},
        {"--org", [&](int& idx) { config.discover_org = read_words(idx, "--org"); }},
        {"--owner", [&](int& idx) {
            config.discover_owner = true;
            if (idx + 1 < argc && argv[idx + 1][0] != '-') config.discover_owner_name = read_words(idx, "--owner");
        }},
        {"--ip", [&](int& idx) { config.discover_ip = get_next_arg(idx, "--ip"); }},
        {"--range", [&](int& idx) { config.discover_range = get_next_arg(idx, "--range"); }},
        {"--asn", [&](int& idx) { config.discover_asn = get_next_arg(idx, "--asn"); }},
        {"--ipv4", [&](int&) { saw_dash4 = true; }},
        {"--ipv6", [&](int&) { saw_dash6 = true; }},
        
        {"--sport-range", [&](int& idx) {
	    std::string range_str = get_next_arg(idx, "--sport-range");
	    if (!parse_sport_range_config(range_str, config.sport_range_cfg)) {
		exit(1);
	    }
	}},
        
        {"--send-uring", [&](int& idx) {
            size_t depth = parse_size_t(get_next_arg(idx, "--send-uring"), "--send-uring");
            if (!validate_uring_depth(depth)) {
                std::cerr << "Invalid send uring depth. Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096\n";
                exit(1);
            }
            config.send_uring_depth = depth;
        }},
        
        {"--rate", [&](int& idx) {
	    std::string rate_str = get_next_arg(idx, "--rate");
	    if (!parse_rate_config(rate_str, config.rate_config)) {
		exit(1);
	    }
	    config.rate_explicit = true;
	}},
	
	{"--rate-dyn-window", [&](int& idx) {
            std::string val = get_next_arg(idx, "--rate-dyn-window");
            if (!parse_duration_to_us(val, config.rate_dyn_window_us, "--rate-dyn-window")) exit(1);
            config.rate_dyn_explicit = true;
        }},
        {"--rate-dyn-min", [&](int& idx) {
            std::string val = get_next_arg(idx, "--rate-dyn-min");
            if (val.find('-') != std::string::npos) {
                std::cerr << "--rate-dyn-min: must be a non-negative number\n"; exit(1);
            }
            try {
                unsigned long v = std::stoul(val);
                if (v == 0 || v > UINT32_MAX) { std::cerr << "--rate-dyn-min: must be between 1 and " << UINT32_MAX << "\n"; exit(1); }
                config.rate_dyn_min = static_cast<uint32_t>(v);
            } catch (...) { std::cerr << "--rate-dyn-min: invalid number\n"; exit(1); }
            config.rate_dyn_explicit = true;
        }},
        
        {"--rate-dyn-max", [&](int& idx) {
            std::string val = get_next_arg(idx, "--rate-dyn-max");
            if (val.find('-') != std::string::npos) {
                std::cerr << "--rate-dyn-max: must be a non-negative number\n"; exit(1);
            }
            try {
                unsigned long v = std::stoul(val);
                if (v == 0 || v > UINT32_MAX) { std::cerr << "--rate-dyn-max: must be between 1 and " << UINT32_MAX << "\n"; exit(1); }
                config.rate_dyn_max = static_cast<uint32_t>(v);
            } catch (...) { std::cerr << "--rate-dyn-max: invalid number\n"; exit(1); }
            config.rate_dyn_explicit = true;
        }},
        
        {"--batch-delay-dyn-min", [&](int& idx) {
            std::string val = get_next_arg(idx, "--batch-delay-dyn-min");
            if (!parse_duration_allow_zero(val, config.batch_delay_dyn_min_us, "--batch-delay-dyn-min")) exit(1);
            config.batch_delay_dyn_explicit = true;
        }},
        {"--batch-delay-dyn-max", [&](int& idx) {
            std::string val = get_next_arg(idx, "--batch-delay-dyn-max");
            if (!parse_duration_allow_zero(val, config.batch_delay_dyn_max_us, "--batch-delay-dyn-max")) exit(1);
            config.batch_delay_dyn_explicit = true;
        }},

	{"--batch-delay", [&](int& idx) {
	    std::string delay_arg;
	    if (idx + 1 < argc && argv[idx + 1][0] != '-') {
		delay_arg = argv[++idx];
	    }
	    if (!parse_batch_delay_config(delay_arg, config.batch_delay_config)) {
		exit(1);
	    }
	    config.batch_delay_explicit = true;
	}},
	
	{"--retry-delay-min", [&](int& idx) {
            std::string val = get_next_arg(idx, "--retry-delay-min");
            if (!parse_duration_allow_zero(val, g_cong_tune.retry_delay_min_us, "--retry-delay-min")) exit(1);
        }},
        {"--retry-delay-max", [&](int& idx) {
            std::string val = get_next_arg(idx, "--retry-delay-max");
            if (!parse_duration_to_us(val, g_cong_tune.retry_delay_max_us, "--retry-delay-max")) exit(1);
        }},
        {"--retry-delay-floor-div", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--retry-delay-floor-div"), "--retry-delay-floor-div", 1, 1000000, v)) exit(1);
            g_cong_tune.rtt_floor_div = static_cast<uint32_t>(v);
        }},
        {"--cong-curve", [&](int& idx) {
            double v;
            if (!parse_dbl_in(get_next_arg(idx, "--cong-curve"), "--cong-curve", 0.0, 1000.0, true, v)) exit(1);
            g_cong_tune.curve_exp = v;
        }},
        {"--cong-alpha-up", [&](int& idx) {
            double v;
            if (!parse_dbl_in(get_next_arg(idx, "--cong-alpha-up"), "--cong-alpha-up", 0.0, 1.0, true, v)) exit(1);
            g_cong_tune.alpha_up = v;
        }},
        {"--cong-alpha-down", [&](int& idx) {
            double v;
            if (!parse_dbl_in(get_next_arg(idx, "--cong-alpha-down"), "--cong-alpha-down", 0.0, 1.0, true, v)) exit(1);
            g_cong_tune.alpha_down = v;
        }},
        {"--rto-mult", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--rto-mult"), "--rto-mult", 1, 64, v)) exit(1);
            g_cong_tune.rto_mult = static_cast<int>(v);
        }},
        {"--rto-pad1", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--rto-pad1"), "--rto-pad1", 0, 10000, v)) exit(1);
            g_cong_tune.rto_pad1_ms = static_cast<int>(v);
        }},
        {"--rto-pad2", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--rto-pad2"), "--rto-pad2", 0, 10000, v)) exit(1);
            g_cong_tune.rto_pad2_ms = static_cast<int>(v);
        }},
        {"--buf-peak", [&](int& idx) {
            double v;
            if (!parse_dbl_in(get_next_arg(idx, "--buf-peak"), "--buf-peak", 1.0, 20.0, false, v)) exit(1);
            g_cong_tune.buf_peak_factor = v;
        }},
        {"--batch-settle", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--batch-settle"), "--batch-settle", 0, 5000000, v)) exit(1);
            g_cong_tune.batch_settle_us = static_cast<unsigned>(v);
        }},
        {"--sqpoll-threshold", [&](int& idx) {
            long v;
            if (!parse_long_in(get_next_arg(idx, "--sqpoll-threshold"), "--sqpoll-threshold", 0, 1L << 40, v)) exit(1);
            g_cong_tune.sqpoll_threshold = static_cast<size_t>(v);
        }},
        
	{"--bandwidth", [&](int& idx) {
            std::string bw_str = get_next_arg(idx, "--bandwidth");
            if (!parse_bandwidth_config(bw_str, config.bandwidth_config)) {
                exit(1);
            }
        }},
        
        {"--rcv-uring", [&](int& idx) {
            size_t depth = parse_size_t(get_next_arg(idx, "--rcv-uring"), "--rcv-uring");
            if (!validate_uring_depth(depth)) {
                std::cerr << "Invalid receive uring depth. Allowed values: 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096\n";
                exit(1);
            }
            config.rcv_uring_depth = depth;
        }},
        
        {"--packet-length", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--packet-length");
	    if (!parse_packet_length(val, config.packet_length_config)) {
		exit(1);
	    }
	}},
        
        {"-p", [&](int& idx) {
	    config.port_spec = get_next_arg(idx, "-p");
	    config.use_file = false;
	    config.parsed_ports = parse_ports(config.port_spec);
	    if (config.parsed_ports.size() <= 9) {
		config.print_individual_closed_filtered = true;
	    }
	}},
        
        {"--jitter", [&](int& idx) {
	    std::string jitter_arg;
	    if (idx + 1 < argc && argv[idx + 1][0] != '-') {
		jitter_arg = argv[++idx];
	    }
	    if (!parse_jitter_config(jitter_arg, config.jitter_config)) {
		exit(1);
	    }
	}},
	
	{"-h", [&](int& idx) {
            print_full_help();
            exit(0);
        }},
        
        {"--help", [&](int& idx) {
            print_full_help();
            exit(0);
        }},
        
        {"--port-timeout", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--port-timeout");

	    auto parse_ms = [](const std::string& s) -> int {
		try {
		    if (s.size() >= 2 && s.substr(s.size() - 2) == "ms")
			return static_cast<int>(std::stod(s.substr(0, s.size() - 2)));
		    if (!s.empty() && s.back() == 's')
			return static_cast<int>(std::stod(s.substr(0, s.size() - 1)) * 1000.0);
		    return static_cast<int>(std::stod(s));  // plain number = ms
		} catch (const std::exception&) {
		    std::cerr << "--port-timeout: invalid numeric value '" << s << "'\n";
		    exit(1);
		}
	    };

	    size_t dash = val.find('-');
	    // Handle negative or ambiguous: only split on dash after first char
	    for (size_t i = 1; i < val.size(); ++i) {
		if (val[i] == '-') { dash = i; break; }
	    }

	    if (dash == std::string::npos || dash == 0 || dash == val.size() - 1) {
		std::cerr << "--port-timeout: use format min-max e.g. 5ms-700ms or 5-700\n";
		exit(1);
	    }

	    int tmin = parse_ms(val.substr(0, dash));
	    int tmax = parse_ms(val.substr(dash + 1));

	    if (tmin < 1 || tmax < 1 || tmin > tmax) {
		std::cerr << "--port-timeout: min must be >= 1 and min <= max\n";
		exit(1);
	    }
	    if (tmax > 30000) {
		std::cerr << "--port-timeout: max cannot exceed 30000ms\n";
		exit(1);
	    }
	    config.port_timeout_min_ms = tmin;
	    config.port_timeout_max_ms = tmax;
	}},
        
        {"--inj-tfo-cookie", [&](int& idx) {
            std::string tfo_arg = get_next_arg(idx, "--inj-tfo-cookie");
            config.use_tfo_cookie = true;
            
            if (tfo_arg.find("len:") == 0) {
                std::string len_str = tfo_arg.substr(4);
                try {
                    config.tfo_cookie_length = std::stoul(len_str);
                    if (config.tfo_cookie_length < 1 || config.tfo_cookie_length > 253) {
                        std::cerr << "TFO random length must be 1-253 bytes\n";
                        exit(1);
                    }
                    config.tfo_cookie_random = true;
                    
                    if (config.tfo_cookie_length % 2 == 0) {
                        std::cout << "[INFO] TFO cookie length " << config.tfo_cookie_length 
                                  << " is EVEN. Auto-correcting to " 
                                  << (config.tfo_cookie_length + 1) << " (ODD)\n";
                        config.tfo_cookie_length++;
                    }
                    if (config.tfo_cookie_length < 5) {
                        config.tfo_cookie_length = 5;
                        std::cout << "[INFO] Minimum TFO cookie is 5 bytes\n";
                    }
                    std::cout << "TFO: Random cookie length: " << config.tfo_cookie_length << " bytes\n";
                } catch (const std::exception& e) {
                    std::cerr << "Invalid TFO length: " << len_str << "\n";
                    exit(1);
                }
            }
            else if (tfo_arg.find("str:") == 0) {
                config.tfo_cookie_str = tfo_arg.substr(4);
                size_t byte_count = config.tfo_cookie_str.length();
                if (byte_count % 2 == 0) {
                    std::cout << "[WARNING] String cookie will be " << byte_count 
                              << " bytes (EVEN). Auto-padding to make ODD.\n";
                }
                std::cout << "TFO: String cookie: \"" << config.tfo_cookie_str 
                          << "\" (" << byte_count << " bytes)\n";
            }
            else if (tfo_arg.find("hex:") == 0) {
                std::string hex_str = tfo_arg.substr(4);
                config.tfo_cookie_as_hex = true;
                config.tfo_cookie_str = "0x" + hex_str;
                size_t byte_count = hex_str.length() / 2;
                if (hex_str.length() % 2 != 0) byte_count++;
                if (byte_count % 2 == 0) {
                    std::cout << "[WARNING] Hex cookie will be " << byte_count 
                              << " bytes (EVEN). Auto-padding to make ODD.\n";
                }
                std::cout << "TFO: Hex cookie: 0x" << hex_str 
                          << " (" << byte_count << " bytes)\n";
            }
            else {
                std::cout << "[INFO] Auto-detecting TFO cookie type...\n";
                if ((tfo_arg.find("0x") == 0 || tfo_arg.find("0X") == 0) && tfo_arg.length() > 2) {
                    config.tfo_cookie_as_hex = true;
                    config.tfo_cookie_str = tfo_arg;
                    std::cout << "TFO: Hex cookie (legacy): " << tfo_arg << "\n";
                }
                else if (std::all_of(tfo_arg.begin(), tfo_arg.end(), ::isdigit)) {
                    try {
                        size_t num_val = std::stoul(tfo_arg);
                        if (num_val <= 253) {
                            config.tfo_cookie_random = true;
                            config.tfo_cookie_length = num_val;
                            std::cout << "TFO: Random length (legacy): " << num_val << " bytes\n";
                        } else {
                            config.tfo_cookie_num = num_val;
                            std::cout << "TFO: Numeric value (legacy): " << num_val << "\n";
                        }
                    } catch (...) {
                        config.tfo_cookie_str = tfo_arg;
                        std::cout << "TFO: String cookie (legacy): \"" << tfo_arg << "\"\n";
                    }
                }
                else {
                    config.tfo_cookie_str = tfo_arg;
                    std::cout << "TFO: String cookie (legacy): \"" << tfo_arg << "\"\n";
                }
            }
        }},

        {"--debug", [&](int& idx) {
	    std::string debug_arg = get_next_arg(idx, "--debug");
	    std::stringstream ss(debug_arg);
	    std::string token;
	    while (std::getline(ss, token, ',')) {
		if (token == "recv") {
		    config.debug_packet = true;
		} else if (token == "rtt") {
		    config.debug_rtt = true;
		} else if (token == "wsn") {
		    config.debug_wsn = true;
		} else if (token == "ttl") {
		    config.debug_ttl = true;
		} else if (token == "demux") {
		    config.debug_demux = true;
		} else if (token == "strack") {
		    config.debug_strack = true;
		} else if (token == "send") {
		    config.debug_send = true;
		} else {
		    std::cerr << "Invalid --debug token '" << token 
		              << "'. Valid: recv,rtt,wsn,ttl,demux,strack,send\n";
		    exit(1);
		}
	    }
	}},
        
        {"-b", [&](int& idx) {
            std::string batch_spec = get_next_arg(idx, "-b");
            try {
                size_t val = std::stoul(batch_spec);
                if (val < 1 || val > 65535) {
                    std::cerr << "Batch size must be between 1 and 65535\n";
                    exit(1);
                }
                config.main_batch_size = val;
            } catch (const std::exception& e) {
                std::cerr << "Invalid batch size: " << batch_spec << " (" << e.what() << ")\n";
                exit(1);
            }
            config.batch_specified = true;
        }},
        
         {"-g", [&](int& idx) {
            std::string gsport_str = get_next_arg(idx, "-g");
            if (!parse_gsport_config(gsport_str, config.gsport_cfg)) {
                exit(1);
            }
        }},
        
        {"--seq-num", [&](int& idx) {
            long temp_seq = 0;
            try {
                temp_seq = std::stol(get_next_arg(idx, "--seq-num"));
            } catch (const std::exception&) {
                std::cerr << "--seq-num: invalid numeric value\n";
                exit(1);
            }
            if (temp_seq < 0 || temp_seq > 4294967295U) {
                std::cerr << "Sequence number must be between 0 and 4294967295\n";
                exit(1);
            }
            config.seq_num = static_cast<uint32_t>(temp_seq);
        }},
        
        {"--win-size", [&](int& idx) {
           uint16_t value = parse_uint16(get_next_arg(idx, "--win-size"), "--win-size");
           if (value > 100000) {
                std::cerr << "Error: --win-size must be between 0 and 100000\n";
                exit(1);
           }
           config.win_size = value;
        }},
        
        {"--interface", [&](int& idx) {
            config.interface = get_next_arg(idx, "--interface");
            struct ifreq ifr_check;
            memset(&ifr_check, 0, sizeof(ifr_check));
            strncpy(ifr_check.ifr_name, config.interface.c_str(), IFNAMSIZ - 1);
            int check_sock = socket(AF_INET, SOCK_DGRAM, 0);
            bool iface_ok = false;
            if (check_sock >= 0) {
                if (ioctl(check_sock, SIOCGIFFLAGS, &ifr_check) == 0 && (ifr_check.ifr_flags & IFF_UP)) {
                    iface_ok = true;
                }
                close(check_sock);
            }
            if (!iface_ok) {
                std::cerr << "ioctl SIOCGIFADDR: No such device (interface does not exist or down)\n";
                exit(1);
            }
        }},
        
        {"--split", [&](int& idx) {
            config.use_split = true;
        }},
        
        {"--split-ip", [&](int& idx) {
            config.split_ip = get_next_arg(idx, "--split-ip");
            config.split_ip_set = true;
        }},
        
        {"--split-gw", [&](int& idx) {
            config.split_gw = get_next_arg(idx, "--split-gw");
            config.split_gw_set = true;
        }},
        
        {"--split-ip6", [&](int& idx) {
            config.split_ip6 = get_next_arg(idx, "--split-ip6");
            config.split_ip6_set = true;
        }},
        
        {"--split-gw6", [&](int& idx) {
            config.split_gw6 = get_next_arg(idx, "--split-gw6");
            config.split_gw6_set = true;
        }},
        
        {"--split-mac", [&](int& idx) {
            config.split_mac = get_next_arg(idx, "--split-mac");
            config.split_mac_set = true;
        }},
        
        {"--split-iface", [&](int& idx) {
            config.split_iface = get_next_arg(idx, "--split-iface");
            config.split_iface_set = true;
        }},
        
        {"-S", [&](int& idx) {
            config.source_ip = get_next_arg(idx, "-S");
        }},
        
        {"-G", [&](int& idx) {
            config.graceful_scan = true;
            config.fast_scan = false;
        }},
        
        {"--rcvbuf", [&](int& idx) {
            std::string buf_str = get_next_arg(idx, "--rcvbuf");
            try {
                size_t multiplier = 1;
                if (!buf_str.empty()) {
                    char last_char = std::tolower(buf_str.back());
                    if (last_char == 'k') {
                        multiplier = 1024;
                        buf_str.pop_back();
                    } else if (last_char == 'm') {
                        multiplier = 1024 * 1024;
                        buf_str.pop_back();
                    } else if (last_char == 'g') {
                        multiplier = 1024 * 1024 * 1024;
                        buf_str.pop_back();
                    }
                }
                long long computed_rcvbuf = static_cast<long long>(std::stoi(buf_str)) * static_cast<long long>(multiplier);
                if (computed_rcvbuf < 1024 || computed_rcvbuf > 100LL * 1024 * 1024) {
                    std::cerr << "Receive buffer size must be between 1KB and 100MB\n";
                    exit(1);
                }
                config.user_rcvbuf_size = static_cast<int>(computed_rcvbuf);
            } catch (const std::exception& e) {
                std::cerr << "Invalid receive buffer size: " << buf_str 
                          << " (use format: 128k, 2m, 1g, or plain bytes)\n";
                exit(1);
            }
        }},
        
        {"-o", [&](int& idx) {
            config.output_file = get_next_arg(idx, "-o");
        }},
        
        {"--exclude-ports", [&](int& idx) {
            config.exclude_ports_spec = get_next_arg(idx, "--exclude-ports");
            config.excluded_ports = parse_ports(config.exclude_ports_spec);
        }},
        
        {"-f", [&](int& idx) {
	    config.use_fragmentation = true;
	    std::string size_str = get_next_arg(idx, "-f");

	    if (size_str.empty()) {
		std::cerr << "-f: no size specified.\n"
		          << "    Usage: -f <size>  (default: 8)\n"
		          << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		          << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		exit(1);
	    }

	    // reject clearly non-numeric input early with a clean message
	    bool has_only_digits = !size_str.empty() &&
		                   std::all_of(size_str.begin(), size_str.end(), ::isdigit);
	    if (!has_only_digits) {
		std::cerr << "-f: invalid fragment size '" << size_str << "' (must be a number)\n";
		exit(1);
	    }

	    try {
		int val = std::stoi(size_str);
		if (val < 2 || val > 65528) {
		    std::cerr << "-f: size " << val << " is out of range.\n"
		              << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		              << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		    exit(1);
		}
		if (val % 2 != 0) {
		    std::cerr << "-f: size " << val << " is not a multiple of 2.\n"
		              << "    Standard range : 8-65528, multiple of 8 (RFC 791)\n"
		              << "    Experimental   : 2, 4, 6 (intentionally malformed, for evasion testing)\n";
		    exit(1);
		}
		// warn (don't exit) when using experimental sub-8 sizes
		if (val < 8) {
		    std::cerr << "[WARN] -f " << val << ": experimental fragment size — produces intentionally\n"
		              << "       malformed fragments that violate RFC 791. Use only for evasion testing.\n";
		}
		config.frag_offset_size = static_cast<uint16_t>(val);
	    } catch (const std::exception&) {
		std::cerr << "-f: invalid fragment size '" << size_str << "' (value out of integer range)\n";
		exit(1);
	    }
	}},
	
	{"--frag", [&](int& idx) {
	    config.use_fragmentation = true;
	    std::string frag_arg = get_next_arg(idx, "--frag");

	    if (frag_arg.empty()) {
		std::cerr << "--frag: no option specified. Available: ofo, lap, zof\n"
		          << "        Example: --frag ofo  or  --frag lap  or  --frag zof\n";
		exit(1);
	    }

	    std::string lap_peek_num = "";
	    bool has_lap = (frag_arg.find("lap") != std::string::npos);
	    if (has_lap && idx + 1 < argc) {
		std::string peek = argv[idx + 1];
		bool looks_like_number = !peek.empty() && peek[0] != '-' &&
		                         std::all_of(peek.begin(), peek.end(), ::isdigit);
		if (looks_like_number) {
		    lap_peek_num = peek;
		    ++idx;
		}
	    }

	    bool seen_ofo = false;
	    bool seen_zof = false;
	    bool seen_lap = false;

	    std::stringstream ss(frag_arg);
	    std::string token;
	    while (std::getline(ss, token, ',')) {
		if (token.empty()) continue;

		if (token == "ofo") {
		    if (seen_ofo) {
		        std::cerr << "--frag: duplicate token 'ofo'\n";
		        exit(1);
		    }
		    seen_ofo = true;
		    config.frag_out_of_order = true;

		} else if (token == "lap") {
		    if (seen_lap) {
		        std::cerr << "--frag: duplicate token 'lap'\n";
		        exit(1);
		    }
		    seen_lap = true;
		    config.frag_overlap_bytes = 8;
		    config.frag_overlap = true;
		    if (!lap_peek_num.empty()) {
		        try {
		            int oval = std::stoi(lap_peek_num);
		            if (oval < 8 || oval > 65520 || (oval % 8 != 0)) {
		                std::cerr << "--frag lap: overlap size must be a multiple of 8 "
		                          << "between 8 and 65520 (got " << oval << ").\n"
		                          << "        Note: sizes 2 and 6 are only for -f experimental mode, "
		                          << "not for --frag lap.\n";
		                exit(1);
		            }
		            config.frag_overlap_bytes = static_cast<uint16_t>(oval);
		        } catch (...) {
		            std::cerr << "--frag lap: invalid overlap size '" << lap_peek_num << "'\n";
		            exit(1);
		        }
		    }
		    std::cout << "[INFO] --frag lap: overlapping fragmentation enabled, "
		              << "overlap=" << config.frag_overlap_bytes << " bytes\n";

		} else if (token == "zof") {
		    if (seen_zof) {
		        std::cerr << "--frag: duplicate token 'zof'\n";
		        exit(1);
		    }
		    seen_zof = true;
		    config.frag_zof = true;
		    std::cout << "[INFO] --frag zof: zero-offset fragment will be sent last\n";

		} else {
		    std::cerr << "--frag: unknown token '" << token
		              << "'. Available: ofo, lap, zof\n";
		    exit(1);
		}
	    }

	    // zof and ofo are mutually exclusive
	    if (seen_zof && seen_ofo) {
		std::cerr << "--frag: 'zof' and 'ofo' cannot be used together.\n"
		          << "        zof sends the zero-offset fragment last;\n"
		          << "        ofo shuffles all fragments randomly, which destroys that guarantee.\n"
		          << "        Use one or the other.\n";
		exit(1);
	    }
	}},

	{"--mtu", [&](int& idx) {
	    std::string mtu_str = get_next_arg(idx, "--mtu");
	    int val = 0;
	    try {
		val = std::stoi(mtu_str);
	    } catch (...) {
		std::cerr << "--mtu: invalid value '" << mtu_str << "'\n";
		exit(1);
	    }
	    if (val < 22 || val > 65535) {
		std::cerr << "--mtu: value must be between 22 and 65535\n";
		exit(1);
	    }
	    int payload = val - 20;
	    if (payload % 2 != 0) {
		int adjusted = (payload / 2) * 2;
		if (adjusted < 2) adjusted = 2;
		std::cout << "[INFO] --mtu " << val << ": payload " << payload
		          << " bytes is not even "
		          << "Adjusting to MTU " << (adjusted + 20) << " (payload " << adjusted << " bytes)\n";
		val = adjusted + 20;
	    }
	    config.mtu_size          = static_cast<uint16_t>(val);
	    config.use_fragmentation = true;  // --mtu implies fragmentation
	}},
        
        {"--ws", [&](int& idx) {
            float ws_val = 0.0f;
            try {
                ws_val = std::stof(get_next_arg(idx, "--ws"));
            } catch (const std::exception&) {
                std::cerr << "--ws: invalid numeric value\n";
                exit(1);
            }
            if (ws_val < 0.0f || ws_val > 500.0f) {
                std::cerr << "Window scale must be between 0.5 and 30.0\n";
                exit(1);
            }
            config.window_scale = static_cast<uint8_t>(ws_val);
        }},
        
        {"--mss", [&](int& idx) {
            uint16_t mss = parse_uint16(get_next_arg(idx, "--mss"), "--mss");
            if (mss > 66666) {
                std::cerr << "Invalid value\n";
            }
            config.mss_value = mss;
        }},
        
        {"--t", [&](int& idx) {
            config.timestamp_val = parse_uint32(get_next_arg(idx, "--t"), "--t");
        }},
        
        {"--tsecr", [&](int& idx) {
            std::string tsecr_str = get_next_arg(idx, "--tsecr");
            try {
                if (tsecr_str.find("0x") == 0 || tsecr_str.find("0X") == 0) {
                    config.timestamp_ecr_custom = std::stoul(tsecr_str.substr(2), nullptr, 16);
                } else {
                    config.timestamp_ecr_custom = std::stoul(tsecr_str);
                }
            } catch (const std::exception& e) {
                std::cerr << "Invalid TSecr value: " << tsecr_str << " (" << e.what() << ")\n";
                exit(1);
            }
        }},
        
        {"--nops", [&](int& idx) {
            int temp_nops = 0;
            try {
                temp_nops = std::stoi(get_next_arg(idx, "--nops"));
            } catch (const std::exception&) {
                std::cerr << "--nops: invalid numeric value\n";
                exit(1);
            }
            if (temp_nops < 0 || temp_nops > 300) {
                std::cerr << "NOPs count must be between 0 and 300\n";
                exit(1);
            }
            config.nops_count = static_cast<uint16_t>(temp_nops);
        }},
        
        {"--set-rtt", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--set-rtt");
	    // Accept plain number (ms) or suffix: 290ms, 1s, 500ms
	    double ms_val = 0.0;
	    try {
		if (val.size() >= 2 && val.substr(val.size() - 2) == "ms") {
		    ms_val = std::stod(val.substr(0, val.size() - 2));
		} else if (!val.empty() && val.back() == 's') {
		    ms_val = std::stod(val.substr(0, val.size() - 1)) * 1000.0;
		} else {
		    ms_val = std::stod(val);  // plain number = ms
		}
	    } catch (const std::exception&) {
		std::cerr << "--set-rtt: invalid numeric value '" << val << "'\n";
		exit(1);
	    }
	    int rtt = static_cast<int>(ms_val);
	    if (rtt < 1 || rtt > 10000) {
		std::cerr << "--set-rtt: value must be between 1ms and 10000ms\n";
		exit(1);
	    }
	    config.initial_rtt_ms = rtt;
	}},
        
        {"--data", [&](int& idx) {
            config.custom_data = get_next_arg(idx, "--data");
            config.use_custom_data = true;
            config.generate_random_data = false;
        }},
        
        {"--data-length", [&](int& idx) {
            config.data_length = parse_uint16(get_next_arg(idx, "--data-length"), "--data-length");
            if (config.data_length > 1000) {
                std::cerr << "Data length too large (max 1000)\n";
                exit(1);
            }
            config.generate_random_data = true;
            config.use_custom_data = false;
        }},
        
        {"--sack", [&](int& idx) {
            std::string sack_str = get_next_arg(idx, "--sack");
            if (sack_str == "on" || sack_str == "1" || sack_str == "yes" || sack_str == "true") {
                config.sack_permitted = true;
            } else if (sack_str == "off" || sack_str == "0" || sack_str == "no" || sack_str == "false") {
                config.sack_permitted = false;
            } else {
                std::cerr << "Invalid SACK value. Use 'on' or 'off'\n";
                exit(1);
            }
        }},
        
        {"--src-mac", [&](int& idx) {
            std::string s = get_next_arg(idx, "--src-mac");
            if (!parse_mac(s, config.eth_opts.custom_src_mac)) {
                std::cerr << "Invalid --src-mac format, expected aa:bb:cc:dd:ee:ff\n";
                exit(1);
            }
            config.eth_opts.use_custom_src_mac = true;
        }},

        {"--dst-mac", [&](int& idx) {
            std::string s = get_next_arg(idx, "--dst-mac");
            if (!parse_mac(s, config.eth_opts.custom_dst_mac)) {
                std::cerr << "Invalid --dst-mac format, expected aa:bb:cc:dd:ee:ff\n";
                exit(1);
            }
            config.eth_opts.use_custom_dst_mac = true;
        }},

        {"--ether-type", [&](int& idx) {
            std::string s = get_next_arg(idx, "--ether-type");
            try {
                config.eth_opts.custom_ethertype = static_cast<uint16_t>(std::stoul(s, nullptr, 0));
            } catch (const std::exception&) {
                std::cerr << "--ether-type: invalid numeric value '" << s << "'\n";
                exit(1);
            }
            config.eth_opts.use_custom_ethertype = true;
        }},

        {"--vlan", [&](int& idx) {
            uint16_t vid = parse_uint16(get_next_arg(idx, "--vlan"), "--vlan");
            config.eth_opts.vlan_ids = { vid };
        }},

        {"--vlan-stack", [&](int& idx) {
            std::string v = get_next_arg(idx, "--vlan-stack");
            size_t comma = v.find(',');
            if (comma == std::string::npos) {
                std::cerr << "--vlan-stack requires format ID1,ID2\n";
                exit(1);
            }
            uint16_t id1 = parse_uint16(v.substr(0, comma), "--vlan-stack");
            uint16_t id2 = parse_uint16(v.substr(comma + 1), "--vlan-stack");
            config.eth_opts.vlan_ids = { id1, id2 };
        }},

        {"--ether-dst-multicast", [&](int& idx) {
            static const std::unordered_map<std::string, std::string> multicast_table = {
                {"ipv4-all", "01:00:5e:00:00:01"},
                {"stp",      "01:80:c2:00:00:00"},
                {"lldp",     "01:80:c2:00:00:0e"},
                {"all-nodes","33:33:00:00:00:01"}
            };
            std::string key = get_next_arg(idx, "--ether-dst-multicast");
            auto it = multicast_table.find(key);
            if (it == multicast_table.end()) {
                std::cerr << "Unknown multicast type: " << key << "\n";
                exit(1);
            }
            parse_mac(it->second, config.eth_opts.custom_dst_mac);
            config.eth_opts.use_custom_dst_mac = true;
        }},

        {"--ether-padding", [&](int& idx) {
            std::string v = get_next_arg(idx, "--ether-padding");
            if (v == "random") {
                config.eth_opts.random_padding = true;
                config.eth_opts.padding_size = 16;   // sensible default length for random padding
            } else {
                config.eth_opts.padding_size = parse_uint16(v, "--ether-padding");
            }
        }},
        
        {"--ttl", [&](int& idx) {
            int ttl_val = 0;
            try {
                ttl_val = std::stoi(get_next_arg(idx, "--ttl"));
            } catch (const std::exception&) {
                std::cerr << "--ttl: invalid numeric value\n";
                exit(1);
            }
            if (ttl_val < 0 || ttl_val > 259) {
                std::cerr << "TTL must be between 0 and 259\n";
                exit(1);
            }
            config.custom_ttl = static_cast<uint8_t>(ttl_val);
        }},
        
        {"--tcp-mtcp", [&](int& idx) {
            config.use_tcp_mptcp = true;
        }},

        {"--tcp-ao", [&](int& idx) {
            config.use_tcp_ao = true;
            // optional "keyid:rnextkeyid:maclen" e.g. --tcp-ao 1:1:16
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                std::string val = get_next_arg(idx, "--tcp-ao");
                size_t p1 = val.find(':');
                size_t p2 = (p1 == std::string::npos) ? std::string::npos
                                                        : val.find(':', p1 + 1);
                try {
                    if (p1 != std::string::npos) {
                        config.tcp_ao_keyid = static_cast<uint8_t>(std::stoi(val.substr(0, p1)));
                        if (p2 != std::string::npos) {
                            config.tcp_ao_rnextkeyid =
                                static_cast<uint8_t>(std::stoi(val.substr(p1 + 1, p2 - p1 - 1)));
                            config.tcp_ao_mac_len =
                                static_cast<uint8_t>(std::stoi(val.substr(p2 + 1)));
                        } else {
                            config.tcp_ao_rnextkeyid =
                                static_cast<uint8_t>(std::stoi(val.substr(p1 + 1)));
                        }
                    } else {
                        config.tcp_ao_keyid = static_cast<uint8_t>(std::stoi(val));
                    }
                } catch (...) {
                    std::cerr << "Invalid --tcp-ao value: " << val << "\n";
                    exit(1);
                }
            }
        }},

        {"--ip-rsa", [&](int& idx) {
            config.use_ip_router_alert = true;
        }},
        
        {"--hop", [&](int& idx) {
            std::string val = get_next_arg(idx, "--hop");
            if (!parse_hop_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--dest", [&](int& idx) {
            std::string val = get_next_arg(idx, "--dest");
            if (!parse_dest_option(val, config.ipv6_ext_opts)) exit(1);
        }},
        
        {"--route", [&](int& idx) {
            std::string val = get_next_arg(idx, "--route");
            if (!parse_route_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--ah", [&](int& idx) {
            std::string val = get_next_arg(idx, "--ah");
            if (!parse_ah_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--esp", [&](int& idx) {
            std::string val = get_next_arg(idx, "--esp");
            if (!parse_esp_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--flow", [&](int& idx) {
            std::string val = get_next_arg(idx, "--flow");
            if (!parse_flow_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--chain", [&](int& idx) {
            std::string val = get_next_arg(idx, "--chain");
            if (!parse_chain_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--stop", [&](int& idx) {
            std::string val = get_next_arg(idx, "--stop");
            if (!parse_stop_option(val, config.ipv6_ext_opts)) exit(1);
        }},

        {"--ip-security", [&](int& idx) {
            config.use_ip_security = true;
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                std::string val = get_next_arg(idx, "--ip-security");
                try {
                    config.ip_security_classification =
                        static_cast<uint8_t>(std::stoul(val, nullptr, 0));
                } catch (...) {
                    std::cerr << "Invalid --ip-security classification: " << val << "\n";
                    exit(1);
                }
            }
        }},
        
        {"--dscp", [&](int& idx) {
            std::string dscp_arg = get_next_arg(idx, "--dscp");
            if (!parse_dscp_value(dscp_arg, config.custom_dscp)) {
                exit(1);
            }
        }},
        
         {"-Pn", [&](int& idx) {
            config.skip_ping = true;
        }},
        {"-sn", [&](int& idx) {
            config.sn_scan = true;
        }},
        
        {"-sn6", [&](int& idx) {
            config.sn6_scan = true;
        }},
        
        {"--traceroute", [&](int& idx) {
            config.traceroute = true;
        }},
        {"-6", [&](int& idx) {
            config.traceroute_ip_version = 6;
            g_target_ip_pref = 6;
            saw_dash6 = true;
        }},
        {"-4", [&](int& idx) {
            g_target_ip_pref = 4;
            saw_dash4 = true;
        }},
        
        {"--grep", [&](int& idx) {
            config.print_grepable = true;
        }},
        
         {"-sV", [&](int& idx) {
            config.enable_version_detection = true;
        }},
        
         {"--sv-timeout", [&](int& idx) {
            try {
                config.sv_timeout_sec = std::stoi(get_next_arg(idx, "--sv-timeout"));
            } catch (const std::exception&) {
                std::cerr << "--sv-timeout: invalid numeric value\n";
                exit(1);
            }
        }},
        
         {"--intensity", [&](int& idx) {
            try {
                config.sv_intensity = std::stoi(get_next_arg(idx, "--intensity"));
            } catch (const std::exception&) {
                std::cerr << "--intensity: invalid numeric value\n";
                exit(1);
            }
        }},
        
         {"--udp",         [&](int& idx) { config.sv_udp = true; }},
         {"--force-raw",   [&](int& idx) { config.sv_force_raw = true; }},
         {"--force-http",  [&](int& idx) { config.sv_force_http = true;  config.sv_force_https = false; }},
         {"--force-https", [&](int& idx) { config.sv_force_https = true; config.sv_force_http  = false; }},
         {"--tls-verify",  [&](int& idx) { config.sv_tls_verify = true; }},
         {"--verbose",     [&](int& idx) { config.sv_verbose = true; }},
         {"--save", [&](int& idx) {
            config.sv_save_file = get_next_arg(idx, "--save");
        }},
        
         {"--tls-ca", [&](int& idx) {
            config.sv_tls_ca_file = get_next_arg(idx, "--tls-ca");
        }},
        
         {"--tls-ca-path", [&](int& idx) {
            config.sv_tls_ca_path = get_next_arg(idx, "--tls-ca-path");
        }},
        
         {"--tls-cert", [&](int& idx) {
            config.sv_tls_cert = get_next_arg(idx, "--tls-cert");
        }},
        
         {"--tls-key", [&](int& idx) {
            config.sv_tls_key = get_next_arg(idx, "--tls-key");
        }},
        
         {"--tls-sni", [&](int& idx) {
            config.sv_tls_sni = get_next_arg(idx, "--tls-sni");
        }},
        
         {"--host", [&](int& idx) {
            config.sv_host_override = get_next_arg(idx, "--host");
        }},
       
        
        {"--ip-tos", [&](int& idx) {
            std::string tos_arg = get_next_arg(idx, "--ip-tos");
            if (!parse_ip_tos_value(tos_arg, config.custom_ip_tos)) {
                exit(1);
            }
            config.use_ip_tos = true;
            // Report what was set so the user can verify
            uint8_t dscp_val = (config.custom_ip_tos >> 2) & 0x3F;
            uint8_t ecn_val  =  config.custom_ip_tos & 0x03;
            std::cout << "[ip-tos] TOS=0x" << std::hex << std::uppercase
                      << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(config.custom_ip_tos)
                      << std::dec << std::setfill(' ')
                      << "  DSCP=" << static_cast<unsigned>(dscp_val)
                      << "  ECN="  << static_cast<unsigned>(ecn_val)  << "\n";
        }},
        
        {"--ip-flags", [&](int& idx) {
            try {
                config.custom_ip_flags = static_cast<uint16_t>(std::stoi(get_next_arg(idx, "--ip-flags"), nullptr, 0));
            } catch (const std::exception&) {
                std::cerr << "--ip-flags: invalid numeric value\n";
                exit(1);
            }
        }},
        
        {"--ip-id", [&](int& idx) {
	    std::string mode_arg = get_next_arg(idx, "--ip-id");
	    if (!parse_ip_id_mode(mode_arg, config.ip_id_mode, config.fixed_ip_id)) {
		exit(1);
	    }
	}},
	{"--fixed-ip-id", [&](int& idx) {
	    std::string val = get_next_arg(idx, "--fixed-ip-id");
	    std::cerr << "[deprecated] --fixed-ip-id; use --ip-id " << val << " instead\n";
	    if (!parse_ip_id_mode(val, config.ip_id_mode, config.fixed_ip_id)) {
		exit(1);
	    }
	}},
        {"--badsum", [&](int& idx) {
            config.use_badsum = true;
            if (idx + 1 < argc && argv[idx + 1][0] != '-') {
                const char* arg = argv[++idx];
                try {
                    size_t pos;
                    long val = std::stol(arg, &pos, 0);
                    if (pos != std::strlen(arg) || val < 0 || val > 0xFFFF) {
                        std::cerr << "error: --badsum '" << arg
                                  << "' is not a valid 16-bit value (0x0000–0xFFFF)\n";
                        exit(1);
                    }
                    config.custom_badsum_value = static_cast<uint16_t>(val);
                    config.badsum_value_set = true;
                } catch (const std::exception&) {
                    std::cerr << "error: --badsum '" << arg
                              << "' is not a valid hex or decimal number\n";
                    exit(1);
                }
            }
        }},
        
        {"--prsum", [&](int& idx) {
            config.use_partial_badsum = true;
            config.partial_badsum_type = get_next_arg(idx, "--prsum");
        }},
        
        
        {"--inject-tfo-cookie", [&](int& idx) {
            option_handlers["--inj-tfo-cookie"](idx);
        }},

        {"--retry-sport", [&](int& idx) {
            config.retry_source_port = parse_uint16(get_next_arg(idx, "--retry-sport"), "--retry-sport");
            if (config.retry_source_port == 0) {
                std::cerr << "--retry-sport: port must be 1-65535\n";
                exit(1);
            }
        }},
        
        {"--os-detect", [&](int& idx) {
            g_os_detect = true;
        }},

        {"--sqpoll", [&](int& idx) {
            config.force_sqpoll = true;
        }}
    };
    std::unordered_map<std::string, ScanType> scan_type_map = {
        {"--syn-scan", ScanType::SYN}, {"-sS", ScanType::SYN},
        {"--fin-scan", ScanType::FIN}, {"-sF", ScanType::FIN},
        {"--ack-scan", ScanType::ACK}, {"-sA", ScanType::ACK},
        {"--null-scan", ScanType::NULL_SCAN}, {"-sN", ScanType::NULL_SCAN},
        {"--xmas-scan", ScanType::XMAS}, {"-sX", ScanType::XMAS},
        {"--window-scan", ScanType::WINDOW}, {"-sW", ScanType::WINDOW},
        {"--maimon-scan", ScanType::MAIMON}, {"-sM", ScanType::MAIMON},
        {"--cwr-scan", ScanType::CWR}, {"-sCW", ScanType::CWR},
        {"--ece-scan", ScanType::ECE}, {"-sE", ScanType::ECE},
        {"--urg-scan", ScanType::URG}, {"-sUG", ScanType::URG},
        {"--psh-scan", ScanType::PSH}, {"-sPH", ScanType::PSH},
        {"--hanuman-scan", ScanType::HANUMAN}, {"-sH", ScanType::HANUMAN},
        {"--kakabhusundi-scan", ScanType::KAKABHUSUNDI}, {"-sK", ScanType::KAKABHUSUNDI},
        {"--ganesh-scan", ScanType::GANESH}, {"-sG", ScanType::GANESH},
        {"--ram-scan", ScanType::RAM}, {"-sR", ScanType::RAM},
        {"--garud-scan", ScanType::GARUD}, {"-sD", ScanType::GARUD},
        {"--jatayu-scan", ScanType::JATAYU}, {"-sJ", ScanType::JATAYU}
    };

    if (!network_is_up()) {
        std::cerr << "network seems down, scan terminated\n";
        return 0;
    }
    
    for (int pre_idx = arg_idx; pre_idx < argc; ++pre_idx) {
        const std::string pre_arg = argv[pre_idx];
        if (pre_arg == "-6") g_target_ip_pref = 6;
        else if (pre_arg == "-4") g_target_ip_pref = 4;
    }

    while (arg_idx < argc) {
        std::string arg = argv[arg_idx];
        auto scan_it = scan_type_map.find(arg);
        if (scan_it != scan_type_map.end()) {
            config.scan_type = scan_it->second;
            config.scan_type_specified = true;
            arg_idx++;
            continue;
        }
        
        auto it = option_handlers.find(arg);
        if (it != option_handlers.end()) {
            it->second(arg_idx);
            arg_idx++;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        } else {
	   if (!process_ip_string(arg, ips)) {
	       return 1;          // parse_targets already printed the error
	   }
	   if (!config.target_spec_display.empty()) config.target_spec_display += ", ";
	   config.target_spec_display += arg;
	   arg_idx++;
	}
    }
    
    if (config.netradar_time_specified && !config.netradar_enabled) {
        std::cerr << "--time is only valid together with --netradar.\n";
        return 1;
    }

    if (config.netradar_enabled) {
        net_capture::Options nopts;
        nopts.verbose = config.sv_verbose;
        nopts.duration_ms = config.netradar_duration_ms;
        nopts.iface = config.interface;
        return net_capture::run_netradar(nopts);
    }

    if (saw_dash4 && saw_dash6) {
        std::cerr << "Error: -4 and -6 are mutually exclusive , default it use both\n";
        return 1;
    }

    if ((saw_dash4 || saw_dash6) && g_saw_literal_target) {
        std::cerr << "Error: -4/-6 only apply to DNS domain-name resolution — "
                      "not to literal IPs or CIDR ranges.\n";
        return 1;
    }
    
    const bool disc_country = !config.discover_country.empty();
    const bool disc_asnlist = !config.discover_cn.empty() || !config.discover_org.empty();
    const bool disc_reverse = !config.discover_ip.empty() || !config.discover_range.empty();
    const bool disc_routes  = !config.discover_asn.empty();
    const int  disc_modes   = disc_country + disc_asnlist + disc_reverse + disc_routes;

    if (disc_modes > 0) {
        if (!ips.empty() || !config.ip_file.empty() || config.scan_type_specified) {
            std::cerr << "Discovery options run on their own: don't combine them with targets, -iL or scan flags.\n";
            return 1;
        }
        if (disc_modes > 1) {
            std::cerr << "Use only one of --country, --cn/--org, --ip/--range, --asn at a time.\n";
            return 1;
        }
        if (!config.discover_ip.empty() && !config.discover_range.empty()) {
            std::cerr << "--ip and --range are mutually exclusive.\n";
            return 1;
        }
        if (disc_asnlist && config.discover_owner) {
            std::cerr << "--owner only applies to --country.\n";
            return 1;
        }
        if (disc_reverse && (config.discover_owner || saw_dash4 || saw_dash6)) {
            std::cerr << "--owner/-4/-6/--ipv4/--ipv6 don't apply to --ip/--range.\n";
            return 1;
        }
        std::cout.rdbuf(teeOut_orig);
        std::cerr.rdbuf(teeErr_orig);
        discover::Options dopts;
        dopts.want_v4     = !saw_dash6;
        dopts.want_v6     = !saw_dash4;
        dopts.verbose     = config.sv_verbose;
        dopts.output_file = config.output_file;
        if (disc_country) {
            dopts.mode       = discover::Mode::Ranges;
            dopts.country    = config.discover_country;
            dopts.owner      = config.discover_owner;
            dopts.owner_name = config.discover_owner_name;
        } else if (disc_asnlist) {
            dopts.mode    = discover::Mode::AsnList;
            dopts.country = config.discover_cn;
            dopts.org     = config.discover_org;
        } else if (disc_reverse) {
            dopts.mode  = discover::Mode::ReverseIp;
            dopts.ip    = config.discover_ip;
            dopts.range = config.discover_range;
        } else {
            dopts.mode = discover::Mode::AsnRoutes;
            dopts.asn  = config.discover_asn;
        }
        return discover::run(dopts);
    }
    if (config.discover_owner) {
        std::cerr << "--owner only applies to --country.\n";
        return 1;
    }

    if (config.use_split || config.graceful_scan) {
        if (config.graceful_scan && !config.use_split) {

        }
        SplitFileConf file_conf;
        std::string conf_err;
        bool have_conf = load_split_conf(kDefaultSplitConfPath, file_conf, conf_err);
        if (!have_conf) {
            std::cerr << color::yellow << "[--split] note: couldn't read "
                      << kDefaultSplitConfPath << " (" << conf_err
                      << ") -- using --split-* options only.\n" << color::reset;
        }

        SplitNsConfig split_cfg;

        // --split-iface overrides; otherwise fall back to --interface / auto-detect.
        // (shiv_split.conf has no interface field -- ns1.sh hardcoded "link eth0".)
        split_cfg.base_iface = config.split_iface_set ? config.split_iface : config.interface;

        // --split-mac overrides; otherwise CUSTOM_MAC from the conf file (optional either way).
        split_cfg.mac = config.split_mac_set ? config.split_mac
                       : (have_conf ? file_conf.mac : "");

        if (config.split_ip_set) {
            split_cfg.ip_cidr = config.split_ip;
        } else if (have_conf && !file_conf.ip_addr.empty()) {
            std::string cidr_err;
            if (!build_split_ip_cidr(file_conf.ip_addr, file_conf.ip_prefix, split_cfg.ip_cidr, cidr_err)) {
                std::cerr << color::red << "[--split] " << cidr_err << color::reset << "\n";
                return 1;
            }
        }

        // --split-gw overrides; otherwise GATEWAY from the conf file.
        split_cfg.gateway = config.split_gw_set ? config.split_gw
                           : (have_conf ? file_conf.gateway : "");
                           
        if (config.split_ip6_set) {
            split_cfg.ip6_cidr = config.split_ip6;
        } else if (have_conf && !file_conf.ip6_addr.empty()) {
            std::string cidr6_err;
            if (!build_split_ip6_cidr(file_conf.ip6_addr, file_conf.ip6_prefix, split_cfg.ip6_cidr, cidr6_err)) {
                std::cerr << color::red << "[--split] " << cidr6_err << color::reset << "\n";
                return 1;
            }
        }

        // --split-gw6 overrides; otherwise IP6_GATEWAY from the conf file.
        split_cfg.gateway6 = config.split_gw6_set ? config.split_gw6
                            : (have_conf ? file_conf.ip6_gateway : "");

        std::string split_err;
        if (!enter_split_namespace(split_cfg, split_err)) {
            std::cerr << color::red << "[--split] failed: " << split_err << color::reset << "\n"
                       << "  (needs root/CAP_SYS_ADMIN + CAP_NET_ADMIN; either fill in "
                       << kDefaultSplitConfPath << " or pass --split-ip/--split-gw explicitly)\n";
            return 1;
        }
    }
    RstBlockGuard rst_guard(config.graceful_scan);

    {
        std::string health_iface = config.interface.empty()
            ? (config.split_iface_set ? config.split_iface
               : (!ips.empty() ? autodetect_interface(get_local_ip(ips[0].c_str())) : ""))
            : config.interface;
        if (!health_iface.empty()) {
            InterfaceHealth health;
            if (assess_interface_health(health_iface, health)) {
                if (health.carrier_readable && !health.carrier_up) {
                    std::cerr << color::yellow << "[warning] interface " << health_iface
                              << " reports no carrier -- a scan that gets no replies from "
                              << "anyone is likely this, not 500 dead hosts.\n" << color::reset;
                }
                if (health.speed_mbps > 0 && health.speed_mbps < 1000) {
                     std::cerr << color::yellow << "[note] " << health_iface << " negotiated at "
                              << health.speed_mbps << " Mbps"
                              << (health.duplex_readable ? (health.full_duplex ? "" : " (half-duplex)") : "")
                              << " -- unusually slow scans may be your own link, not the target.\n"
                              << color::reset;
                }
            }
        }

        bool has_ipt = false, has_nft = false;
        detect_local_firewall_active(has_ipt, has_nft);
        if (has_ipt || has_nft) {
            std::cerr << color::yellow << "[note] local packet-filter rules present ("
                      << (has_ipt ? "iptables" : "") << (has_ipt && has_nft ? "+" : "")
                      << (has_nft ? "nftables" : "") << ") -- common with Docker/UFW/firewalld "
                      << "and usually harmless, but if a scan gets no replies at all, check "
                      << "for an OUTPUT/INPUT DROP rule before blaming the target.\n" << color::reset;
        }

        bool scanning_self = false;
        for (const auto& t : ips) {
            if (is_target_local_to_host(t)) { scanning_self = true; break; }
        }
        if (scanning_self) {
            int icmp_rl_ms = 0, icmp_rm = 0;
            if (get_icmp_ratelimit(icmp_rl_ms, icmp_rm) && icmp_rl_ms > 0) {
                std::cerr << color::yellow << "[note] local icmp_ratelimit=" << icmp_rl_ms
                          << "ms -- expect throttled/suppressed ICMP replies when scanning "
                          << "yourself or localhost.\n" << color::reset;
            }
        }
    }

    if (!config.ip_file.empty()) {
        if (!read_ips_from_file(config.ip_file, ips)) {
            return 1;
        }
        if (!config.target_spec_display.empty()) config.target_spec_display += ", ";
        config.target_spec_display += config.ip_file;
    }
    if (custom_dns_configured() && !config.use_trial_api) {
        if (ip_to_domain_map.empty()) {
            // Pure-IP run: no target anywhere ever used the resolver — hard
            // exit, single message, no need to name every target.
            std::cerr << color::yellow
                      << "IP is in resoluted form , it bypass resolvers , can't comproise scan, Exiting...\n"
                      << color::reset;
            return 1;
        } else if (!g_dns_bypassed_targets.empty()) {
            // Mixed run: at least one domain target did use the resolver,
            // so we don't exit — just name the specific target(s) that
            // didn't.
            for (const auto& t : g_dns_bypassed_targets) {
                std::cerr << color::yellow
                          << "IP is in resoluted form , it bypass resolvers , can't comproise scan"
                          << " (target: " << t << ")\n"
                          << color::reset;
            }
        }
    }

    if ((config.sn_scan || config.sn6_scan) && config.skip_ping && !config.scan_type_specified) {
        std::cerr << color::yellow
                  << "-Pn only allowed when used with -sn/-sn6 and -sS together\n"
                  << color::reset << "\n";
        return 1;
    }

    if (config.use_trial_api) {
        std::string target_domain;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg[0] == '-') {
                if (arg == "--enum") {
                    i++;  
                }
                continue;
            }
            target_domain = arg;
            break;
        }
    
        if (target_domain.empty()) {
            std::cerr << "Error: --enum trail:<key> requires a domain (e.g., example.com)\n";
            return 1;
        }

        print_shiv_enum_banner("TRAIL");
        std::cout << "\nSubdomain Enum for \"" << color::bold << sanitize_echo(target_domain) << color::reset << "\"\n";

        ips.clear();
        std::vector<std::string> subdomains = fetch_subdomains_from_api(target_domain, config.trial_api_key);
        if (subdomains.empty()) {
            std::cout << std::left << std::setw(20) << "API Lookup"
                      << ": " << color::yellow << "trying jq-less method..." << color::reset << "\n";
            subdomains = fetch_subdomains_from_api_no_jq(target_domain, config.trial_api_key);
        }

        if (subdomains.empty()) {
            std::cerr << std::left << std::setw(20) << "API Lookup"
                      << ": " << color::red << "no subdomains found or API request failed" << color::reset << "\n";
            return 1;
        }

        std::cout << "Subdomain Found : " << subdomains.size() << "\n";

        std::vector<std::string> unique_subdomains;
        std::unordered_set<std::string> seen;

        for (const auto& sub : subdomains) {
            if (seen.find(sub) == seen.end()) {
                seen.insert(sub);
                unique_subdomains.push_back(sub);
            }
        }
        subdomains = std::move(unique_subdomains);

        std::vector<std::string> resolved_ips;
        std::unordered_map<std::string, std::vector<std::string>> ip_to_domains;
        std::vector<std::string> unresolved_subdomains;

        for (const auto& subdomain : subdomains) {
            std::string resolved_ip;
            if (!resolve_domain_to_ip(subdomain, resolved_ip)) {
                unresolved_subdomains.push_back(subdomain);
                continue;
            }
            ip_to_domains[resolved_ip].push_back(subdomain);
        }

        if (!unresolved_subdomains.empty()) {
            std::cout << "Unresolved : " << color::yellow << unresolved_subdomains.size()
                      << color::reset << " | ";
            for (size_t i = 0; i < unresolved_subdomains.size(); ++i) {
                std::cout << color::yellow << sanitize_echo(unresolved_subdomains[i]) << color::reset;
                if (i + 1 < unresolved_subdomains.size()) std::cout << " , ";
            }
            std::cout << "\n";
        }

        std::cout << "Resolved IPs : " << ip_to_domains.size() << " unique ip addresses\n";

        std::vector<std::pair<std::string, std::vector<std::string>>> ip_domain_pairs(
            ip_to_domains.begin(), ip_to_domains.end());

        std::sort(ip_domain_pairs.begin(), ip_domain_pairs.end(),
            [](const auto& a, const auto& b) {
                return a.second.size() > b.second.size();
            });

        const int MAX_PER_ROW = 5;
        const std::string separator(70, '_');

        for (const auto& [ip, domains] : ip_domain_pairs) {
            std::cout << color::green << separator << color::reset << "\n";
            std::cout << "\nResolved Hosts for \"" << color::green << ip << color::reset << "\"\n";
            for (size_t i = 0; i < domains.size(); ++i) {
                std::cout << sanitize_echo(domains[i]);
                if ((i + 1) % MAX_PER_ROW == 0 || i + 1 == domains.size())
                    std::cout << "\n";
                else
                    std::cout << "  ";
            }
        }

        for (const auto& [ip, domains] : ip_domain_pairs) {
            resolved_ips.push_back(ip);
        }
        ips = resolved_ips;

        if (resolved_ips.empty()) { 
            std::cerr << color::red << "Error: No subdomains could be resolved." 
                      << color::reset << "\n";
            return 1;
        }
        std::cout << color::bold << "\nSummary" << color::reset << "\n";
        std::cout << std::left << std::setw(20) << "Total Subdomains" << ": " << subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Resolved to IPv4" << ": " << subdomains.size() - unresolved_subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Unresolved"       << ": " << unresolved_subdomains.size() << "\n";
        std::cout << std::left << std::setw(20) << "Unique IPs"       << ": " << ip_to_domains.size() << "\n\n";

        std::cout << color::bold << "Ready to scan " << ip_to_domains.size() 
                  << " unique IP addresses" << color::reset << "\n\n";
                  
    }
    
    if (!config.scan_type_specified && (config.use_trial_api || config.use_shodan_enum)) {
        if (config.skip_ping) {
            std::cerr << color::yellow
                      << "-Pn is a scan-only flag; ignored — no scan type (-sS/-sT/...) was given.\n"
                      << color::reset;
        }

        if (config.use_shodan_enum) {
            print_shiv_enum_banner("SHODAN");
            std::cout << "\n" << std::string(60, '-') << std::endl;
            std::cout << "SHODAN INTERNETDB ENUMERATION" << std::endl;
            std::cout << std::string(60, '-') << std::endl;
            std::set<std::string> unique_ips(ips.begin(), ips.end());
            int ip_count = 1;
            int total_ips = unique_ips.size();
            for (const auto& ip : unique_ips) {
                std::cout << "\n[" << ip_count << "/" << total_ips << "] ";
                std::cout.flush();

                std::string shodan_data = fetch_shodan_info(ip);
                if (!shodan_data.empty()) {
                    display_shodan_info(shodan_data, ip);
                } else {
                    std::cout << "No data for " << ip << std::endl;
                }

                ip_count++;
                if (ip_count <= total_ips) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }
        }
        if (config.print_grepable) {
            std::cout << "\n";
            print_grepable_output(config.target_spec_display, ips, config.use_trial_api);
        }

        return 0;
    }
    
     auto run_ssl_enum_step = [&]() {
        if (ips.empty()) {
            std::cerr << color::yellow
                      << "--enum ssl needs at least one resolved target IP.\n"
                      << color::reset;
            return;
        }
        std::vector<SslTarget> ssl_targets;
        ssl_targets.reserve(ips.size());
        for (const auto& ip : ips) {
            std::string hostname;
            auto it = ip_to_domain_map.find(ip);
            if (it != ip_to_domain_map.end()) hostname = it->second;
            ssl_targets.push_back({ip, hostname});
        }

        SslEnumOptions opts;
        opts.ports = !config.parsed_ports.empty() ? config.parsed_ports : std::vector<int>{443};

        print_shiv_enum_banner("SSL");
        auto results = run_ssl_enum_batch(ssl_targets, opts);
        for (auto& r : results) print_ssl_enum_result(r, opts);
    };
    
    auto run_dns_enum_step = [&]() {
        if (ip_to_domain_map.empty()) {
            std::cerr << color::yellow
                      << "--enum dns needs a domain name target (e.g. example.com), not a raw IP.\n"
                      << color::reset;
            return;
        }
        std::unordered_set<std::string> unique_domains;
        for (const auto& [ip, domain] : ip_to_domain_map) unique_domains.insert(domain);

        DnsEnumOptions opts;
        opts.ptr_sweep_prefix = true;
        if (const char* key = std::getenv("GOOGLE_CSE_API_KEY"))
            if (const char* cx = std::getenv("GOOGLE_CSE_CX")) {
                opts.google_dork = true;
                opts.google_api_key = key;
                opts.google_cx = cx;
            }

        for (const auto& domain : unique_domains) {
            print_shiv_enum_banner("DNS");
            auto result = run_dns_enum(domain, opts);
            print_dns_enum_result(result, opts);
        }
    };

    if (config.dns_enum_enabled && !config.scan_type_specified) {
        run_dns_enum_step();
        return 0;
    }
    
    if (config.ssl_enum_enabled && !config.scan_type_specified) {
        run_ssl_enum_step();
        return 0;
    }

    if (ips.size() > 5000000000) {
        std::cerr << color::red << "❌ Error: Maximum 5000000000 IPs supported" 
                  << color::reset << "\n";
        return 1;
    }
    if (ips.empty()) {
        std::string os_name         = shiv_get_os_pretty_name();
        std::string kernel_release  = shiv_get_kernel_release();
        bool io_uring_supported     = shiv_kernel_supports_io_uring(kernel_release);

        std::cerr
            << "\nOS               : " << color::green << os_name << color::reset << "\n"
            << "Kernel           : " << color::green << kernel_release << color::reset << "\n"
            << "IO_URING         : "
            << (io_uring_supported ? color::green : color::red)
            << (io_uring_supported ? "yes (Supported)" : "no (Not Supported)")
            << color::reset << "\n"
            << "Async I/O        : " << color::green << "IO_URING" << color::reset << "\n"
            << "Queue            : " << color::green << "moodycamel::ConcurrentQueue" << color::reset << "\n"
            << "SIMD             : " << color::green << "SSE2/AVX (intrinsics)" << color::reset << "\n"
            << "Memory           : " << color::green << "RAII" << color::reset << "\n"
            << "LinkLayer        : " << color::green << "yes" << color::reset << "\n"
            << "Sockets          : " << color::green << "Raw" << color::reset << "\n"
            << "IP-Stack         : " << color::green << "Dual" << color::reset << "\n"
            << "Isolation        : " << color::green << "Namespaces (CLONE_NEWNET)" << color::reset << "\n"
            << "Signals          : " << color::green << "SIGINT" << color::reset << "\n"
            << "Incident         : " << color::green << "checkpoints" << color::reset << "\n"
            << "VersionDetection : " << color::green << "Dual staged" << color::reset << "\n\n"
            << "Help:\n"
            << "  Run "
            << color::green << "shiv --help" << color::reset
            << " for more information and unleash the power.\n";

        return 1;
    }
    if (ips.size() > 5000000000000) {
        std::cerr << "Maximum 5000000000000 IPs supported\n";
        return 1;
    }
    std::vector<int> ports;
    if (config.use_file) {
        ports = read_ports_from_file("/usr/share/shiv/ports.txt");
    } else {
        ports = std::move(config.parsed_ports);
    }
    
    if (!config.excluded_ports.empty()) {
        std::vector<int> filtered_ports;
        std::sort(ports.begin(), ports.end());
        std::sort(config.excluded_ports.begin(), config.excluded_ports.end());
        
        std::set_difference(ports.begin(), ports.end(), 
                           config.excluded_ports.begin(), config.excluded_ports.end(),
                           std::back_inserter(filtered_ports));
        
        ports = filtered_ports;
        
        if (ports.empty()) {
            std::cerr << "No valid ports to scan after exclusion.\n";
            return 1;
        }
    }
    
    if (ports.size() <= 9) {
        config.print_individual_closed_filtered = true;
    }
    if (ports.size() <= 4) {
        config.print_filtered_if_few = true;
    }
    
        if (ports.empty() || terminate_flag) {
        std::cerr << "No valid ports to scan.\n";
        return 1;
    }
    
    if (config.batch_specified && config.main_batch_size > ports.size()) {
         std::cerr << "Batch size (-b " << config.main_batch_size
                   << ") must be equal to or less than the number of ports scanned ("
                   << ports.size() << ")\n";
        return 1;
    }

    if (config.rate_explicit && config.rate_dyn_explicit) {
        std::cerr << "--rate and --rate-dyn-* are not compatible with each other:\n"
                   << "  --rate switches the rate limiter to a fixed/random window,\n"
                   << "  which makes --rate-dyn-window/--rate-dyn-min/--rate-dyn-max have no effect.\n"
                   << "  Use --rate for a fixed window, or --rate-dyn-* to tune the adaptive default, not both.\n";
        return 1;
    }
    if (config.batch_delay_explicit && config.batch_delay_dyn_explicit) {
        std::cerr << "--batch-delay and --batch-delay-dyn-* are not compatible with each other:\n"
                   << "  --batch-delay switches to a fixed/random/range delay,\n"
                   << "  which makes --batch-delay-dyn-min/--batch-delay-dyn-max have no effect.\n"
                   << "  Use --batch-delay for a fixed delay, or --batch-delay-dyn-* to tune the adaptive default, not both.\n";
        return 1;
    }
    if (g_cong_tune.retry_delay_min_us > g_cong_tune.retry_delay_max_us) {
        std::cerr << "--retry-delay-min (" << g_cong_tune.retry_delay_min_us / 1000.0
                  << "ms) must be <= --retry-delay-max (" << g_cong_tune.retry_delay_max_us / 1000.0 << "ms)\n";
        return 1;
    }
    if (config.rate_dyn_min > config.rate_dyn_max) {
        std::cerr << "--rate-dyn-min (" << config.rate_dyn_min
                  << ") must be <= --rate-dyn-max (" << config.rate_dyn_max << ")\n";
        return 1;
    }
    if (config.batch_delay_dyn_min_us > config.batch_delay_dyn_max_us) {
        std::cerr << "--batch-delay-dyn-min (" << config.batch_delay_dyn_min_us / 1000.0
                  << "ms) must be <= --batch-delay-dyn-max (" << config.batch_delay_dyn_max_us / 1000.0 << "ms)\n";
        return 1;
    }
    static const std::unordered_map<ScanType, std::string> scan_names = {
        {ScanType::SYN, "SYN"}, {ScanType::FIN, "FIN"}, {ScanType::ACK, "ACK"},
        {ScanType::NULL_SCAN, "NULL"}, {ScanType::XMAS, "XMAS"}, {ScanType::WINDOW, "WINDOW"},
        {ScanType::MAIMON, "MAIMON"}, {ScanType::CWR, "CWR"}, {ScanType::ECE, "ECE"},
        {ScanType::URG, "URG"}, {ScanType::PSH, "PSH"}, {ScanType::HANUMAN, "HANUMAN"},
        {ScanType::KAKABHUSUNDI, "KAKABHUSUNDI"}, {ScanType::GANESH, "GANESH"},
        {ScanType::RAM, "RAM"}, {ScanType::GARUD, "GARUD"}, {ScanType::JATAYU, "JATAYU"}
    };

    std::string scan_name = scan_names.count(config.scan_type) 
                            ? scan_names.at(config.scan_type) 
                            : "UNKNOWN";
    auto total_scan_start = std::chrono::steady_clock::now();
    struct rusage ru_total_start{};
    getrusage(RUSAGE_SELF, &ru_total_start);
    bool all_targets_internal = !ips.empty();
    bool any_routed_internal_vlan   = false;
    bool any_routed_internal_tunnel = false;
    const bool discovery_only_run = (config.sn_scan || config.sn6_scan) && !config.scan_type_specified;
    if (!discovery_only_run) {
        for (const auto& t_ip : ips) {
            TargetLocality loc = assess_target_locality(t_ip, config.interface);
            if (!loc.onlink) {
                all_targets_internal = false;
                if (loc.same_network_internal) {
                     bool is_tunnel = !loc.routed_iface.empty() &&
                                      !is_vlan_interface(loc.routed_iface) &&
                                      (is_point_to_point_interface(loc.routed_iface) ||
                                       classify_interface_kind(loc.routed_iface) == "virtual");
                    if (is_tunnel) any_routed_internal_tunnel = true;
                    else           any_routed_internal_vlan   = true;
                }
                continue;
            }
            if (loc.via_virtual_interface && !loc.corroborated) {
                all_targets_internal = false;
            }
        }
        if (any_routed_internal_vlan) {
            std::cerr << "[i] some targets are routed-but-internal (different VLAN)\n";
        }
        if (any_routed_internal_tunnel) {
            std::cerr << "[i] some targets are routed via a separate tunnel/VPN interface\n";
        }
    }

    if (!config.rate_config.enabled) {
        config.rate_config.enabled       = true;
        config.rate_config.dynamic_mode  = true;
        config.rate_config.window_us     = config.rate_dyn_window_us;   // default 200'000
        config.rate_config.min_packets   = config.rate_dyn_min;         // default 20
        config.rate_config.max_packets   = config.rate_dyn_max;         // default 150
        config.rate_config.gate_by_retry = all_targets_internal;
    }
    if (!config.batch_delay_config.enabled) {
        config.batch_delay_config.enabled      = true;
        config.batch_delay_config.dynamic_mode = true;
        config.batch_delay_config.min_us       = config.batch_delay_dyn_min_us;   // default 0
        config.batch_delay_config.max_us       = config.batch_delay_dyn_max_us;   // default 800'000
    }
    const size_t pool_batch_cap = (config.send_uring_depth > 0)
        ? std::min(config.main_batch_size, config.send_uring_depth)
        : config.main_batch_size;
    PacketBufferPool pool(ports.size(), 1, pool_batch_cap);
    std::atomic<int> total_down_hosts{0};
    // ── -sV: load probe database once, up front, not per-batch/per-host ────
    AllProbes vprobes;
    bool version_probes_loaded = false;
    if (config.enable_version_detection) {
        try {
            vprobes.loadFromFile("/usr/share/nmap/nmap-service-probes");
            version_probes_loaded = true;
        } catch (const std::exception& e) {
            std::cerr << "[-sV] Failed to load service-probes: "
                      << e.what() << "\n";
        }
        constexpr unsigned kMaxConcurrentProbesHint = 16;
        unsigned reactor_threads = std::min({
            std::max(2u, std::thread::hardware_concurrency()),
            kMaxConcurrentProbesHint,
            std::max<unsigned>(2u, static_cast<unsigned>(std::min<size_t>(ports.size(), 8)))
        });
        async_io::configure_shared_reactor(reactor_threads);
    }

    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }
    track_raw_socket(send_sock);
    int reuseport = 1;
    if (setsockopt(send_sock, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseport)) < 0) {
        std::cerr << "Failed to set SO_REUSEPORT: " << strerror(errno) << std::endl;
        close(send_sock);
        return 1;
    }
    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Setsockopt IP_HDRINCL failed: " << strerror(errno) << std::endl;
        close(send_sock);
        return 1;
    }

    ips.erase(std::remove_if(ips.begin(), ips.end(),
        [](const std::string& s) { return s.empty(); }), ips.end());

    if (ips.empty()) {
        std::cerr << "No valid IPs to scan after expansion.\n";
        close(send_sock);
        return 1;
    }

    bool have_ipv6_target = std::any_of(ips.begin(), ips.end(),
        [](const std::string& s) { return get_ip_version(s.c_str()) == 6; });
        
    const bool wants_v6_ext = config.ipv6_ext_opts.use_hop_opts   || config.ipv6_ext_opts.use_dest_opts ||
                               config.ipv6_ext_opts.use_route_hdr || config.ipv6_ext_opts.use_ah        ||
                               config.ipv6_ext_opts.use_esp       ||
                               config.ipv6_ext_opts.chain_mode != ChainMode::NONE ||
                               config.ipv6_ext_opts.stop_mode  != StopMode::NONE;
    if (wants_v6_ext && !have_ipv6_target) {
        std::cerr << "--hop/--dest/--route/--ah/--esp/--chain/--stop only apply to IPv6 targets; "
                     "no IPv6 address is in the target list.\n";
        close(send_sock);
        return 1;
    }
    if (wants_v6_ext && config.use_fragmentation) {
        std::cerr << "--hop/--dest/--route/--ah/--esp/--chain/--stop cannot be combined with --fragment/--mtu "
                     "(IPv6 refragmentation doesn't yet carry hand-built extension headers).\n";
        close(send_sock);
        return 1;
    }
    if (config.ipv6_ext_opts.use_flow_label && !have_ipv6_target) {
        std::cerr << "--flow only applies to IPv6 targets; no IPv6 address is in the target list.\n";
        close(send_sock);
        return 1;
    }
    if (config.ipv6_ext_opts.chain_mode == ChainMode::SPLIT) {
        std::cerr << "--chain split is not implemented: it would require the IPv6 "
                     "fragmentation path (send_tcp_packets()'s per-fragment rebuild) to "
                     "become extension-header aware, which this codebase doesn't yet do.\n";
        close(send_sock);
        return 1;
    }

    // --chain only makes sense with at least one extension header enabled.
    if (config.ipv6_ext_opts.chain_mode != ChainMode::NONE) {
        bool any_hdr = config.ipv6_ext_opts.use_hop_opts  || config.ipv6_ext_opts.use_dest_opts ||
                       config.ipv6_ext_opts.use_route_hdr || config.ipv6_ext_opts.use_ah        ||
                       config.ipv6_ext_opts.use_esp;
        if (!any_hdr) {
            std::cerr << "--chain requires at least one of --hop/--dest/--route/--ah/--esp to be set.\n";
            close(send_sock);
            return 1;
        }
    }

    // --chain dup:<x> requires the matching header to actually be enabled.
    if (config.ipv6_ext_opts.chain_mode == ChainMode::DUP) {
        bool target_active =
            (config.ipv6_ext_opts.chain_dup_target == IPPROTO_HOPOPTS  && config.ipv6_ext_opts.use_hop_opts)  ||
            (config.ipv6_ext_opts.chain_dup_target == IPPROTO_DSTOPTS  && config.ipv6_ext_opts.use_dest_opts) ||
            (config.ipv6_ext_opts.chain_dup_target == IPPROTO_ROUTING && config.ipv6_ext_opts.use_route_hdr) ||
            (config.ipv6_ext_opts.chain_dup_target == IPPROTO_AH      && config.ipv6_ext_opts.use_ah);
        if (!target_active) {
            std::cerr << "--chain dup: the requested header isn't enabled "
                         "(pass the matching --hop/--dest/--route/--ah too).\n";
            close(send_sock);
            return 1;
        }
    }
    if (config.ipv6_ext_opts.stop_mode == StopMode::HOP && !config.ipv6_ext_opts.use_hop_opts) {
        std::cerr << "--stop hop requires --hop to be set.\n";
        close(send_sock);
        return 1;
    }
    if (config.ipv6_ext_opts.stop_mode == StopMode::ROUTE && !config.ipv6_ext_opts.use_route_hdr) {
        std::cerr << "--stop route requires --route to be set.\n";
        close(send_sock);
        return 1;
    }
    if (config.ipv6_ext_opts.stop_mode == StopMode::DEST) {
        if (!config.ipv6_ext_opts.use_dest_opts) {
            std::cerr << "--stop dest requires --dest to be set.\n";
            close(send_sock);
            return 1;
        }
        uint32_t dest_occurrences = 1;
        if (config.ipv6_ext_opts.chain_mode == ChainMode::DUP &&
            config.ipv6_ext_opts.chain_dup_target == IPPROTO_DSTOPTS) {
            dest_occurrences = config.ipv6_ext_opts.chain_dup_count;
        }
        if (config.ipv6_ext_opts.stop_dest_n > dest_occurrences) {
            std::cerr << "--stop dest:" << config.ipv6_ext_opts.stop_dest_n
                       << " requested but only " << dest_occurrences
                       << " Destination Options header(s) will be sent "
                          "(use --chain dup:dest:N to add more).\n";
            close(send_sock);
            return 1;
        }
    }
    
    int send_sock6 = -1;
    if (have_ipv6_target) {
        send_sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (send_sock6 < 0) {
            std::cerr << "IPv6 socket creation failed: " << strerror(errno)
                      << " — IPv6 targets in this run will fail to send.\n";
        } else if (setsockopt(send_sock6, SOL_SOCKET, SO_REUSEPORT,
                               &reuseport, sizeof(reuseport)) < 0) {
            std::cerr << "Failed to set SO_REUSEPORT on IPv6 socket: "
                      << strerror(errno) << " — closing it; IPv6 targets "
                         "in this run will fail to send.\n";
            close(send_sock6);
            send_sock6 = -1;
        } else if (setsockopt(send_sock6, IPPROTO_IPV6, IPV6_HDRINCL,
                               &one, sizeof(one)) < 0) {
            std::cerr << "Failed to set IPV6_HDRINCL on IPv6 socket: "
                      << strerror(errno) << " — closing it; IPv6 targets "
                         "in this run will fail to send.\n";
            close(send_sock6);
            send_sock6 = -1;
        } else {
            track_raw_socket(send_sock6);
        }
    }
    auto close_send_sockets = [&]() {
        if (send_sock >= 0) {
            untrack_raw_socket(send_sock);
            close(send_sock);
            send_sock = -1;
        }
        if (send_sock6 >= 0) {
            untrack_raw_socket(send_sock6);
            close(send_sock6);
            send_sock6 = -1;
        }
    };
    std::unordered_map<uint32_t, std::string> sn_mac_cache; 
    if (config.sn_scan || config.sn6_scan) {
        size_t down_hosts = 0;
        std::vector<std::string> alive = perform_sn_discovery(ips, config.interface, down_hosts, sn_mac_cache);

        if (!config.scan_type_specified) {
            // -sn/-sn6 used alone: discovery only, no port scan.
            if (config.print_grepable) {
                 print_grepable_output(config.target_spec_display, alive, config.use_trial_api);
            }
            close_send_sockets();
            return 0;
        }
        // -sn/-sn6 combined with -sS/-sF/etc: scan only the hosts that answered
        ips = std::move(alive);
        if (ips.empty()) {
            close_send_sockets();
            return 1;
        }
    }
    
    auto run_traceroute_for_targets = [&]() {
        TracerouteOptions topts;
        topts.max_hops       = config.traceroute_max_hops;
        topts.probes_per_hop = config.traceroute_probes;
        topts.timeout_ms     = config.traceroute_timeout_ms;
        topts.resolve_dns    = !config.traceroute_no_dns;
        topts.resolve_geoip  = !config.traceroute_no_geo;
        topts.interface      = config.interface;

        for (const auto& ip : ips) {
	    if (terminate_flag) break;
	    struct in6_addr target_addr6{};
	    const bool target_is_v6 = (::inet_pton(AF_INET6, ip.c_str(), &target_addr6) == 1);
	    auto hops = target_is_v6 ? run_traceroute6(ip, topts) : run_traceroute(ip, topts);
	    print_traceroute_results(ip, hops, topts.max_hops);
	}
    };

    if (config.traceroute) {
        const bool has_scan_flag = config.scan_type_specified;
        const bool has_pn_or_p   = config.skip_ping || !config.port_spec.empty();

        if (!has_scan_flag && has_pn_or_p) {
            std::cerr << color::red << "Error: " << color::reset
                       << "-Pn and -p are not valid together with --traceroute on its own.\n"
                       << "  Use " << color::yellow << "--traceroute" << color::reset
                       << " alone to trace only, or add a scan flag (e.g. "
                       << color::yellow << "-sS" << color::reset
                       << ") to run a scan and a traceroute together.\n";
            close_send_sockets();
            return 1;
        }

        if (!has_scan_flag) {
            // --traceroute used alone: trace only, nothing else to run.
            run_traceroute_for_targets();
            close_send_sockets();
            return 0;
        }
    }

    if (!config.skip_ping) {
        // Determine local subnet once for the first IP (representative)
        uint32_t ping_local_ip  = 0;
        uint32_t ping_netmask   = 0;
        bool     ping_subnet_ok = false;
        if (!ips.empty()) {
            ping_local_ip = get_local_ip(ips[0].c_str());
            if (ping_local_ip != 0) {
                std::string iface = autodetect_interface(ping_local_ip);
                int tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
                if (tmp_sock >= 0) {
                    uint8_t lip[4], mask[4];
                    memcpy(lip, &ping_local_ip, 4);
                    if (get_interface_ip_and_netmask(tmp_sock, iface.c_str(), lip, mask)) {
                        memcpy(&ping_netmask, mask, 4);
                        ping_subnet_ok = true;
                    }
                    close(tmp_sock);
                }
            }
        }

        // Collect only external IPs for pinging
        std::vector<std::string> external_ips;
        std::vector<size_t>      external_indices;
        for (size_t i = 0; i < ips.size(); ++i) {
            in_addr a{};
            if (inet_pton(AF_INET, ips[i].c_str(), &a) != 1) continue;
            uint32_t tip = a.s_addr;
            bool internal = ping_subnet_ok &&
                            is_same_subnet(tip, ping_local_ip, ping_netmask);
            if (!internal) {
                external_ips.push_back(ips[i]);
                external_indices.push_back(i);
            }
        }

        if (!external_ips.empty()) {
            auto ping_results = icmp_ping_sweep(external_ips, 1200);

            std::vector<std::string> surviving_ips;
            surviving_ips.reserve(ips.size());

            // Keep all internal IPs unchanged
            std::unordered_set<size_t> external_set(
                external_indices.begin(), external_indices.end());

            std::vector<bool> keep(ips.size(), true);
            

            for (size_t pi = 0; pi < ping_results.size(); ++pi) {
                const auto& pr  = ping_results[pi];
                size_t      idx = external_indices[pi];
                switch (pr.state) {
                    case IcmpHostState::Alive:
                        // fine — keep
                        break;
                    case IcmpHostState::Dead:
		        std::cout << "[ping] " << pr.ip
			          << " appears down (ICMP type 3 code 1: host unreachable) — skipping\n";
		        keep[idx] = false;
		        total_down_hosts++;
		        break;

		    case IcmpHostState::NoResponse:
		        std::cout << "[ping] " << pr.ip
			          << " no response (timeout — ICMP blocked or host down use -Pn) — skipping\n";
		        keep[idx] = false;
		        total_down_hosts++;
		        break;
                    case IcmpHostState::NetUnreachable:
                        std::cout << "[ping] " << pr.ip
                                  << " network unreachable"
                                     " (ICMP type 3 code 0: net unreachable)"
                                     " — skipping\n";
                        keep[idx] = false;
                        total_down_hosts++;
                        break;
                    case IcmpHostState::NetAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " network admin prohibited"
                                     " (ICMP type 3 code 9:"
                                     " ACL/router policy blocks subnet)"
                                     " — scanning anyway\n";
                        // keep = true: an active policy device replied,
                        // so the host exists — TCP ports may still be open.
                        break;
                    case IcmpHostState::HostAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " host admin prohibited"
                                     " (ICMP type 3 code 10:"
                                     " host firewall/ACL denies this IP)"
                                     " — scanning anyway\n";
                        // keep = true: host is reachable at network layer.
                        break;
                    case IcmpHostState::CommAdminProhibited:
                        std::cout << "[ping] " << pr.ip
                                  << " communication admin prohibited"
                                     " (ICMP type 3 code 13:"
                                     " iptables REJECT / firewall policy)"
                                     " — scanning anyway\n";
                        // keep = true: active REJECT means host is definitely up.
                        break;
                }
            }

            // Rebuild ips and single_results in-place, preserving order
            std::vector<std::string> new_ips;
            new_ips.reserve(ips.size());
            for (size_t i = 0; i < ips.size(); ++i) {
                if (keep[i]) new_ips.push_back(ips[i]);
            }
            ips = std::move(new_ips);

            if (ips.empty()) {
                close_send_sockets();
                return 1;
            }
        }
    }

    constexpr size_t TARGETS_PER_QUEUE = 1000;  

    if (!config.jitter_config.enabled) {
        std::string default_iface,  default_gw;
        std::string default_iface6, default_gw6;
        bool have_default_v4 = get_default_route(AF_INET,  default_iface,  default_gw);
        bool have_default_v6 = get_default_route(AF_INET6, default_iface6, default_gw6);

        bool targets_gateway = std::any_of(ips.begin(), ips.end(), [&](const std::string& ip) {
            return (have_default_v4 && ip == default_gw) ||
                   (have_default_v6 && ip == default_gw6);
        });

        if (any_routed_internal_tunnel) {
            config.jitter_config.enabled     = true;
            config.jitter_config.random_mode = false;
            config.jitter_config.delay_us    = 600;  
        } else if (targets_gateway) {
            config.jitter_config.enabled     = true;
            config.jitter_config.random_mode = false;
            config.jitter_config.delay_us    = 500;
        }
    }

    std::vector<RecPross> all_results(ips.size());

    const size_t total_targets = ips.size();
    size_t batch_start = 0;

    while (batch_start < total_targets && !terminate_flag) {
        size_t batch_end = std::min(batch_start + TARGETS_PER_QUEUE, total_targets);

        // Slice of IPs for this batch
        std::vector<std::string> batch_ips(
            ips.begin() + batch_start, ips.begin() + batch_end);

        std::vector<std::string> batch_hostnames;
        batch_hostnames.reserve(batch_ips.size());
        for (const auto& bip : batch_ips) {
            auto host_it = ip_to_domain_map.find(bip);
            batch_hostnames.push_back(
                host_it != ip_to_domain_map.end() ? host_it->second : std::string());
        }

        std::vector<RecPross> batch_results(batch_ips.size());
        const size_t batch_probe_volume = batch_ips.size() * ports.size();

        const bool rate_is_predictable =
            !(config.rate_config.enabled && config.rate_config.dynamic_mode);
        const bool batch_delay_is_predictable =
            !(config.batch_delay_config.enabled && config.batch_delay_config.dynamic_mode);
        const bool pacing_is_predictable = rate_is_predictable && batch_delay_is_predictable;

        constexpr double SQPOLL_MIN_DURATION_MS = 8000.0;      // predictable-pacing path
        const size_t SQPOLL_FALLBACK_VOLUME = g_cong_tune.sqpoll_threshold; // adaptive-pacing path

        const double estimated_duration_ms = estimate_scan_duration_ms(
            batch_probe_volume, config.rate_config, config.jitter_config,
            config.batch_delay_config, config.initial_rtt_ms);

        const bool enable_sqpoll = config.force_sqpoll || (
            pacing_is_predictable
                ? estimated_duration_ms >= SQPOLL_MIN_DURATION_MS
                : batch_probe_volume    >= SQPOLL_FALLBACK_VOLUME
        );

        //if (config.debug_packet) {
            //std::cerr << "[main] SQPOLL decision: hosts=" << batch_ips.size()
                      //<< " ports=" << ports.size()
                      //<< " volume=" << batch_probe_volume
                      //<< " pacing=" << (pacing_is_predictable ? "predictable" : "adaptive")
                     // << " est_duration_ms=" << estimated_duration_ms
                     // << " min_duration_ms=" << SQPOLL_MIN_DURATION_MS
                     // << " fallback_volume_threshold=" << SQPOLL_FALLBACK_VOLUME
                     // << " forced=" << (config.force_sqpoll ? "yes" : "no")
                      //<< " -> requested=" << (enable_sqpoll ? "yes" : "no") << "\n";
        //}

        {
            std::unique_ptr<GlobalRecvCtx> g_recv_ctx = init_global_recv_ctx(
                batch_ips, config.rcv_uring_depth, config.user_rcvbuf_size,
                enable_sqpoll);
            GlobalRecvCtx* g_recv = g_recv_ctx.get();
            if (!g_recv || !g_recv->valid) {
                std::cerr << "[main] Failed to init global recv context for batch "
                          << batch_start << "–" << batch_end << " — skipping\n";
                batch_start = batch_end;
                continue;
            }

            const int recv_wq_fd = g_recv->sqpoll_active ? g_recv->ring.ring_fd : -1;
            std::unique_ptr<GlobalSendCtx> g_send_ctx = init_global_send_ctx(
                send_sock, config.send_uring_depth, ports.size(), enable_sqpoll, send_sock6,
                recv_wq_fd);
            GlobalSendCtx* g_send = g_send_ctx.get();
            if (!g_send || !g_send->valid) {
                std::cerr << "[main] Failed to init global send context for batch "
                          << batch_start << "–" << batch_end << " — skipping\n";
                batch_start = batch_end;
                continue;
            }
            if (config.debug_packet || enable_sqpoll) {
                auto ring_state = [](bool active) {
                    return active ? (color::green + "active" + color::reset)
                                  : (color::red + "inactive" + color::reset);
                };
                std::cerr << "[main] SQPOLL: requested=" << (enable_sqpoll ? "yes" : "no")
                          << ", TX ring " << ring_state(g_send->sqpoll_active)
                          << ", RX ring " << ring_state(g_recv->sqpoll_active) << "\n";
            }

            if (total_targets > TARGETS_PER_QUEUE) {
                std::cout << "[batch] Scanning targets "
                          << (batch_start + 1) << "–" << batch_end
                          << " of " << total_targets << "\n";
            }

            TcpBuildOptions opts;
            opts.use_ip_tos              = config.use_ip_tos;
            opts.custom_ip_tos_byte      = config.custom_ip_tos;
            opts.use_manual_tcp_checksum = config.use_manual_tcp_checksum;
            opts.manual_tcp_checksum     = config.manual_tcp_checksum;
            opts.window_scale            = config.window_scale;
            opts.mss_value               = config.mss_value;
            opts.timestamp_val           = config.timestamp_val;
            opts.timestamp_ecr_custom    = config.timestamp_ecr_custom;
            opts.nops_count              = config.nops_count;
            opts.sack_permitted          = config.sack_permitted;
            opts.custom_data             = config.custom_data;
            opts.data_length             = config.data_length;
            opts.use_custom_data         = config.use_custom_data;
            opts.generate_random_data    = config.generate_random_data;
            opts.use_badsum              = config.use_badsum;
            opts.custom_badsum_value     = config.custom_badsum_value;
            opts.badsum_value_set        = config.badsum_value_set;
            opts.use_partial_badsum      = config.use_partial_badsum;
            opts.partial_badsum_type     = config.partial_badsum_type;
            opts.use_tfo_cookie          = config.use_tfo_cookie;
            opts.tfo_cookie_as_hex       = config.tfo_cookie_as_hex;
            opts.tfo_cookie_random       = config.tfo_cookie_random;
            opts.tfo_cookie_str          = config.tfo_cookie_str;
            opts.tfo_cookie_num          = config.tfo_cookie_num;
            opts.tfo_cookie_length       = config.tfo_cookie_length;
            opts.use_fragmentation       = config.use_fragmentation;
            opts.frag_size               = config.frag_offset_size;
            opts.mtu_size                = config.mtu_size;
            opts.packet_length_config    = config.packet_length_config;
            opts.use_tcp_mptcp              = config.use_tcp_mptcp;
            opts.use_tcp_ao                 = config.use_tcp_ao;
            opts.tcp_ao_keyid               = config.tcp_ao_keyid;
            opts.tcp_ao_rnextkeyid          = config.tcp_ao_rnextkeyid;
            opts.tcp_ao_mac_len             = config.tcp_ao_mac_len;
            opts.use_ip_router_alert        = config.use_ip_router_alert;
            opts.use_ip_security            = config.use_ip_security;
            opts.ip_security_classification = config.ip_security_classification;
            opts.ipv6_ext_opts = config.ipv6_ext_opts;
            VersionDetectOptions sv_opts_from_config;
            sv_opts_from_config.timeout_sec         = config.sv_timeout_sec;
            sv_opts_from_config.connect_timeout_sec = config.sv_connect_timeout_sec;
            sv_opts_from_config.intensity           = config.sv_intensity;
            sv_opts_from_config.udp                 = config.sv_udp;
            sv_opts_from_config.force_raw           = config.sv_force_raw;
            sv_opts_from_config.force_http          = config.sv_force_http;
            sv_opts_from_config.force_https         = config.sv_force_https;
            sv_opts_from_config.tls_verify          = config.sv_tls_verify;
            sv_opts_from_config.verbose             = config.sv_verbose;
            sv_opts_from_config.save_file           = config.sv_save_file;
            sv_opts_from_config.tls_ca_file         = config.sv_tls_ca_file;
            sv_opts_from_config.tls_ca_path         = config.sv_tls_ca_path;
            sv_opts_from_config.tls_cert            = config.sv_tls_cert;
            sv_opts_from_config.tls_key             = config.sv_tls_key;
            sv_opts_from_config.tls_sni             = config.sv_tls_sni;
            sv_opts_from_config.host_override       = config.sv_host_override;

            thread_worker(batch_ips, batch_hostnames, ports, pool, send_sock,
                 batch_results, config.main_batch_size, config.seq_num, config.win_size,
                 config.print_individual_closed_filtered, config.print_filtered_if_few, config.fast_scan,
                 total_down_hosts, config.scan_type, config.custom_ttl, config.custom_dscp, config.custom_ip_flags,
                 config.ip_id_mode, config.fixed_ip_id,
                 opts,
                 config.user_rcvbuf_size, config.source_ip,
                 config.send_uring_depth, config.rcv_uring_depth,
                 config.base_source_port, config.retry_source_port, config.debug_packet,
                 config.debug_rtt, config.debug_wsn, config.debug_ttl, config.debug_demux, config.debug_strack, config.debug_send,
                 config.frag_out_of_order, config.frag_overlap, config.frag_overlap_bytes, config.frag_zof,
                 config.sport_range_cfg, config.gsport_cfg, config.initial_rtt_ms,
                 config.port_timeout_min_ms, config.port_timeout_max_ms,
                 config.rate_config, config.jitter_config, config.batch_delay_config,
                 config.bandwidth_config,
                 false, g_recv, g_send, config.interface, config.eth_opts,sn_mac_cache,config.enable_version_detection && version_probes_loaded, &vprobes,sv_opts_from_config);
        }  // g_recv_ctx and g_send_ctx destroyed here — reader thread stops cleanly

        // Copy batch results into the correct global slot
        for (size_t j = 0; j < batch_results.size(); ++j) {
            all_results[batch_start + j] = std::move(batch_results[j]);
        }

        batch_start = batch_end;

        // Sleep 5 seconds between batches (not after the last one)
        if (batch_start < total_targets && !terminate_flag) {
            std::cout << "[batch] Waiting 5 seconds before next batch...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    emergency_cleanup();
    // all_results is already populated — no std::move needed here
    auto total_scan_end = std::chrono::steady_clock::now();
    auto total_duration = total_scan_end - total_scan_start;

    double total_elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        total_duration).count() / 1000.0;

    struct rusage ru_total_end{};
    getrusage(RUSAGE_SELF, &ru_total_end);
    double total_cpu_seconds =
        (ru_total_end.ru_utime.tv_sec  - ru_total_start.ru_utime.tv_sec)  +
        (ru_total_end.ru_utime.tv_usec - ru_total_start.ru_utime.tv_usec) / 1e6 +
        (ru_total_end.ru_stime.tv_sec  - ru_total_start.ru_stime.tv_sec)  +
        (ru_total_end.ru_stime.tv_usec - ru_total_start.ru_stime.tv_usec) / 1e6;

    std::cout << "\n";
    if (ips.size() > 1 || !g_eliminated_targets.empty()) {
    
        if (total_elapsed_ms < 1.0) {
            double total_elapsed_us = total_elapsed_ms * 1000;
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(1) 
                      << total_elapsed_us << " microseconds\n";
        } else if (total_elapsed_ms < 1000.0) {
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2) 
                      << total_elapsed_ms << " milliseconds\n";
        } else {
            double total_elapsed_seconds = total_elapsed_ms / 1000.0;
            std::cout << "Overall scan completed in " << std::fixed << std::setprecision(2) 
                      << total_elapsed_seconds << " seconds\n";
        }
        for (const auto& [eliminated_target, eliminated_ip] : g_eliminated_targets) {
            std::cout << "Eliminated : " << sanitize_echo(eliminated_target)
                      << " (duplicate ip [" << eliminated_ip << "])\n";
        }
        std::cout << "CPU time used: " << std::fixed << std::setprecision(3)
                  << total_cpu_seconds << " seconds (user+sys)\n";
    
    }
    if (!config.output_file.empty()) {
        save_scan_results(all_results, config.output_file, teeOut.str() + teeErr.str());
    }
    std::cout.rdbuf(teeOut_orig);
    std::cerr.rdbuf(teeErr_orig);

    if (terminate_flag) {
        std::cout << "\nScan interrupted by user.\n";
    }

    if (config.use_shodan_enum && !ips.empty() && !terminate_flag) {
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "SHODAN INTERNETDB ENUMERATION" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        std::set<std::string> unique_ips(ips.begin(), ips.end());
        int ip_count = 1;
        int total_ips = unique_ips.size();
        for (const auto& ip : unique_ips) {
            if (terminate_flag) {
                std::cout << "\nShodan enumeration interrupted by user.\n";
                break;
            }

            std::cout << "\n[" << ip_count << "/" << total_ips << "] ";
            std::cout.flush();
        
            std::string shodan_data = fetch_shodan_info(ip);
        
            if (!shodan_data.empty()) {
                display_shodan_info(shodan_data, ip);
            } else {
                std::cout << "No data for " << ip << std::endl;
            }
        
            ip_count++;
            if (ip_count <= total_ips && !terminate_flag) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }
    int total_down_hosts_count = total_down_hosts.load();
    if (total_down_hosts_count > 0) {
        print_output(PrintOutputType::DOWN_HOSTS_SUMMARY, "", 0, "", "", "",
                     0, 0, total_down_hosts_count, 0, 0, ips.size(), 
                     "", "", 0.0, "", false, true);
    }

    if (config.print_grepable) {
        std::cout << "\n";
        print_grepable_output(config.target_spec_display, ips, config.use_trial_api);
    }

    if (config.traceroute && config.scan_type_specified) {
        run_traceroute_for_targets();
    }
    
    if (config.dns_enum_enabled && config.scan_type_specified) {
        run_dns_enum_step();
    }
    if (config.ssl_enum_enabled && config.scan_type_specified) {
        run_ssl_enum_step();
    }

    return 0;
}
