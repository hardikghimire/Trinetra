#include "utils.hpp"
#include "public_db.hpp"
#include "scan.hpp"
#include "anomaly_analysis.hpp"
#include <stdexcept>
#include <netinet/ip_icmp.h>
#include <unordered_set>
#include <curl/curl.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <bitset>
#include <semaphore>
#include <bitset>

#ifdef __AVX2__
#include <immintrin.h>  
#else
#include <emmintrin.h>  
#endif


inline std::chrono::steady_clock::time_point steady_from_system(
        std::chrono::system_clock::time_point system_tp) {
    auto system_now = std::chrono::system_clock::now();
    auto steady_now = std::chrono::steady_clock::now();
    auto offset = system_tp - system_now;
    return steady_now + offset;
}

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string cyan    = "\033[96m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string green   = "\033[92m";
    const std::string white   = "\033[97m";
    const std::string dim     = "\033[90m";
    const std::string red     = "\033[91m";
    const std::string green_yellow = "\033[38;5;154m";
    const std::string orange = "\033[38;5;214m";
}

std::atomic<bool> terminate_flag(false);
std::atomic<int> filtered_ports_printed_count(0);
std::atomic<size_t> total_packets_sent(0);
std::mutex cout_mutex;
thread_local std::string* tl_port_output_buf = nullptr;
std::atomic<bool> recv_error_logged(false);
std::atomic<bool> network_disconnect_flag(false);  // NEW: set on network loss
using json = nlohmann::json;

thread_local moodycamel::ConcurrentQueue<char*> PacketBufferPool::buffer_queue;
thread_local std::vector<char> PacketBufferPool::slab;
thread_local char* PacketBufferPool::slab_start = nullptr;
thread_local char* PacketBufferPool::slab_end = nullptr;
const size_t PacketBufferPool::buffer_size;


PacketBufferPool::PacketBufferPool(size_t ports, size_t num_threads) : 
    pool_size(get_buffer_count(ports, num_threads)), 
    max_buffers(get_max_buffer_count(ports, num_threads)), 
    num_ports(ports) {
}

void PacketBufferPool::initialize_for_worker_thread() {
    initialize_thread_local_buffers();
}

char* PacketBufferPool::acquire() {
    initialize_thread_local_buffers();

    char* buffer = nullptr;
    if (buffer_queue.try_dequeue(buffer)) {
        return buffer;
    }

    return nullptr;
}

void PacketBufferPool::release(char* buffer) {
    if (buffer == nullptr || slab_start == nullptr || slab_end == nullptr) {
        return;
    }

    if (buffer >= slab_start && buffer < slab_end) {
        ptrdiff_t offset = buffer - slab_start;
        if ((offset % static_cast<ptrdiff_t>(buffer_size)) == 0) {
            buffer_queue.enqueue(buffer);
        }
    }
}


size_t PacketBufferPool::get_hardware_concurrency_or_default(size_t default_threads) {
    size_t hw_threads = std::thread::hardware_concurrency();
    return (hw_threads == 0) ? default_threads : hw_threads;
}

size_t PacketBufferPool::get_buffer_count(size_t ports, size_t num_threads) {
    num_threads = (num_threads == 0) ? get_hardware_concurrency_or_default() : num_threads;
    const size_t MIN_BUFFERS_PER_THREAD = 32;  // ← INCREASE from 16
    const size_t MAX_BUFFERS_PER_THREAD = 512;  // ← INCREASE from 256
    double scale_factor = std::log2(ports + 1);
    size_t buffers_based_on_ports = static_cast<size_t>(scale_factor * 20);  // ← INCREASE from 15
    size_t buffers_per_thread = std::clamp(
        buffers_based_on_ports / num_threads,
        MIN_BUFFERS_PER_THREAD,
        MAX_BUFFERS_PER_THREAD
    );
    size_t min_required = std::min(ports / num_threads + 1, size_t(128));  // ← INCREASE from 64
    buffers_per_thread = std::max(buffers_per_thread, min_required);
    return buffers_per_thread * num_threads;
}

size_t PacketBufferPool::get_max_buffer_count(size_t ports, size_t num_threads) {
    const double PEAK_FACTOR = 1.3;
    size_t base_count = get_buffer_count(ports, num_threads);
    size_t max_count = static_cast<size_t>(base_count * PEAK_FACTOR);
    const size_t ABSOLUTE_MAX = 2048;
    return std::min(max_count, ABSOLUTE_MAX);
}

void PacketBufferPool::initialize_thread_local_buffers() {
    if (!slab.empty()) {
        return;
    }

    slab.resize(pool_size * buffer_size);

    slab_start = slab.data();
    slab_end = slab_start + slab.size();

    for (size_t i = 0; i < pool_size; ++i) {
        buffer_queue.enqueue(slab_start + (i * buffer_size));
    }
}


static const std::unordered_map<std::string, std::string> s_icon_map = {
    {"ssh", "🔐"}, {"http", "🌐"}, {"https", "🌐🔒"}, {"ftp", "📁"},
    {"dns", "📡"}, {"smtp", "📧"}, {"pop3", "📬"}, {"imap", "📭"},
    {"rdp", "🖥️"}, {"vnc", "👁️"}, {"mysql", "🗄️"}, {"postgresql", "🐘"},
    {"telnet", "⌨️"}, {"snmp", "📊"}, {"ldap", "📇"}, {"sip", "📞"},
    {"ntp", "⏰"}, {"dhcp", "🔌"}, {"smb", "💼"},
    {"ftps", "🔒📁"}, {"sftp", "🔐📁"}, {"tftp", "📤"},
    {"kerberos", "🔑"}, {"mssql", "🗄️"}, {"oracle", "🗄️"},
    {"redis", "📦"}, {"mongodb", "🍃"}, {"elasticsearch", "🔍"},
    {"rabbitmq", "🐰"}, {"kafka", "🚀"}, {"nntp", "📰"},
    {"rsync", "🔄"}, {"nfs", "📂"}, {"cifs", "💼"},
    {"imap_ssl", "🔒📭"}, {"pop3_ssl", "🔒📬"}, {"smtps", "🔒📧"},
    {"ldaps", "🔒📇"}, {"webmin", "🛠️"}, {"syslog", "📜"},
    {"netbios", "🪟"}, {"iscsi", "💾"}, {"radius", "🛡️"},
    {"vpn", "🛡️"}, {"echo", "🔄"}, {"discard", "🗑️"},
    {"bgp", "🌐"}, {"rip", "📡"}, {"http_alt", "🌐"}, {"https_alt", "🔒"},
    {"ftp_data", "📤"}, {"finger", "👆"}, {"whois", "🔎"},
    {"auth", "🔑"}, {"daytime", "🌅"}, {"time", "⏱️"}, {"qotd", "💡"},
    {"chargen", "📝"}, {"printer", "🖨️"}, {"rpcbind", "🔗"},
    {"netbios_ns", "🪟"}, {"netbios_ssn", "🪟"}, {"microsoft_ds", "💼"},
    {"kpasswd", "🔑"}, {"imaps", "🔒📭"}, {"pop3s", "🔒📬"},
    {"socks", "🧦"}, {"proxy", "🌉"}, {"squid", "🦑"},
    {"couchdb", "🛋️"}, {"memcached", "📦"}, {"zookeeper", "🐘"},
    {"jenkins", "🔨"}, {"tomcat", "🐱"}, {"nginx", "🌐"},
    {"apache", "🌐"}, {"docker", "🐳"}, {"kubernetes", "☸️"},
    {"prometheus", "📈"}, {"grafana", "📊"}, {"influxdb", "📈"},
    {"irc", "💬"}, {"bitcoin", "₿"}, {"tor", "🧅"},
    {"openvpn", "🔒"}, {"pptp", "🔌"}, {"ipsec", "🛡️"},
    {"ike", "🔑"}, {"rtsp", "📹"}, {"rtmp", "📹"},
    {"teamspeak", "🎙️"}, {"minecraft", "⛏️"}, {"steam", "🎮"},
    {"x11", "🖼️"}, {"winrm", "🪟"}, {"ssh_alt", "🔐"},
    {"ftp_alt", "📁"}, {"smtp_alt", "📧"}, {"vnc_alt", "👁️"},
    {"rdp_alt", "🖥️"}, {"mysql_alt", "🗄️"}, {"postgres_alt", "🐘"},
    {"mssql_alt", "🗄️"}, {"elastic", "🔍"}, {"domain", "📡"},
    {"printer", "🖨️"}, {"syslog", "📜"}, {"snmptrap", "📢"},
    {"ldap", "📇"}, {"bootpc", "🔌"}, {"tacacs", "🛡️"},
    {"3000", "🌐"}, {"3001", "🌐"}, {"8080", "🌐"}, {"8081", "🌐"},
    {"8443", "🔒"}, {"8888", "🌐"}, {"9999", "🌐"}, {"10000", "🛠️"},
    {"27017", "🍃"}, {"6379", "📦"}, {"5432", "🐘"}, {"3306", "🗄️"},
    {"1433", "🗄️"}, {"3389", "🖥️"}, {"5900", "👁️"}, {"5901", "👁️"},
    {"5985", "🪟"}, {"6666", "💬"}, {"6667", "💬"}, {"31337", "☠️"},
    {"4444", "🛠️"}, {"5555", "🔄"}, {"12345", "🔑"}, {"5000", "🌐"},
    {"5001", "🌐"}, {"8000", "🌐"}, {"8001", "🌐"}, {"9000", "🌐"},
    {"9090", "📈"}, {"9200", "🔍"}, {"27000", "🎮"}, {"25565", "⛏️"},
    {"21", "📁"}, {"23", "⌨️"}, {"25", "📧"}, {"53", "📡"},
    {"80", "🌐"}, {"110", "📬"}, {"143", "📭"}, {"443", "🔒"},
    {"445", "💼"}, {"465", "🔒📧"}, {"993", "🔒📭"}, {"995", "🔒📬"},
    {"1723", "🔌"}, {"2049", "📂"}, {"3306", "🗄️"}, {"5432", "🐘"},
    {"6379", "📦"}, {"8080", "🌐"}, {"8443", "🔒"}, {"27017", "🍃"}
};


void print_output(PrintOutputType type,
                 const std::string& ip, uint16_t port, const std::string& state, const std::string& service,
                 const std::string& scan_name, uint16_t window_size, size_t port_count,
                 size_t open_count, size_t closed_count, size_t filtered_count, size_t host_count,
                 const std::string& mac_address, const std::string& vendor, double elapsed_seconds,
                 const std::string& not_shown_message, bool print_timestamp, bool show_service)
{
    std::lock_guard<std::mutex> lock(cout_mutex);

    auto format_time = []() -> std::string {
        time_t now = time(nullptr);
        struct tm* t = localtime(&now);
        char buf[100];
        strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", t);
        return std::string(buf);
    };

    // Returns a raw (uncolored) state word for column-width calculations
    auto raw_state = [](const std::string& s) -> std::string {
        if (s == "open")       return "open";
        if (s == "closed")     return "closed";
        if (s == "filtered")   return "filtered";
        if (s == "confused")   return "confused";
        if (s == "unfiltered") return "unfiltered";
        return s;
    };

    // Returns a colored state word
    auto colored_state = [&](const std::string& s) -> std::string {
        if (s == "open")       return color::green      + "open"        + color::reset;
        if (s == "closed")     return color::red        + "closed"      + color::reset;
        if (s == "filtered")   return color::yellow     + "filtered"    + color::reset;
        if (s == "confused")   return color::yellow     + "confused"    + color::reset;
        if (s == "unfiltered") return color::green_yellow + "unfiltered" + color::reset;
        return s;
    };

    auto get_service_icon = [](const std::string& svc) -> const std::string& {
        static const std::string fallback = "🔧";
        static const std::string empty;
        if (svc.empty() || svc == "unknown") return empty;
        auto it = s_icon_map.find(svc);
        return it != s_icon_map.end() ? it->second : fallback;
    };

    // nmap-style columnar port line:
    //   PORT(18)  STATE(12 raw chars)  SERVICE  ICON
    // ANSI codes in colored_state are invisible, so we pad based on raw length.
    auto print_port_line = [&](const std::string& port_str,
                               const std::string& st,
                               const std::string& svc,
                               const std::string& extra) {
        const int PORT_W  = 10;
        const int STATE_W = 10;

        std::string raw = raw_state(st);
        std::string col = colored_state(st);
        std::string icon = get_service_icon(svc);

        // Pad port column
        std::string port_num = std::to_string(port);
	std::string colored_port = color::yellow + port_num + color::reset + "/tcp";
	std::cout << std::left << colored_port << std::string(PORT_W > (int)port_str.size() ? PORT_W - port_str.size() : 0, ' ');

        // Print colored state then manually pad to STATE_W based on raw length
        std::cout << col;
        int pad = STATE_W - static_cast<int>(raw.size());
        if (pad > 0) std::cout << std::string(pad, ' ');

        // Service + icon
        std::cout << svc;
        if (!icon.empty())  std::cout << " " << icon;
        if (!extra.empty()) std::cout << "  " << color::dim << extra << color::reset;
        std::cout << "\n";
    };

    switch (type) {
        case PrintOutputType::OVERALL_HEADER: {
            if (print_timestamp) {
                std::cout << "\n" << "Starting " << color::bold << "Shiv" << color::reset
                          << " (" << color::yellow << scan_name << color::reset << ") at "
                          << format_time();
            }
            break;
        }
        case PrintOutputType::SCAN_HEADER: {
            if (print_timestamp) {
                std::cout << "\n" << "Starting " << color::bold << "Shiv" << color::reset
                          << " (" << color::yellow << scan_name << color::reset << ") at "
                          << format_time();
            }
            break;
        }

        // ── HOST_HEADER ──────────────────────────────────────────────────────
        // "Shiv scan report for <hostname> (<ip>)"
        case PrintOutputType::HOST_HEADER: {
            if (!ip.empty()) {
                std::string hostname = reverse_dns_lookup(ip);
                std::cout << "\n" << color::bold << "Shiv scan report for ";
                if (!hostname.empty() && hostname != ip
                    && hostname != "_gateway" && hostname != "gateway") {
                    std::cout << color::cyan << hostname << color::reset
                              << color::bold << " (" << ip << ")";
                } else if (hostname == "_gateway" || hostname == "gateway") {
                    std::cout << color::cyan << ip << color::reset
                              << color::bold << " (_gateway)";
                } else {
                    std::cout << color::cyan << ip << color::reset;
                }
                std::cout << color::reset << "\n\n";
            }
            break;
        }

        // ── PORT_TABLE_HEADER ────────────────────────────────────────────────
        // Column header: PORT  STATE  SERVICE
        case PrintOutputType::PORT_TABLE_HEADER: {
            std::cout << color::bold
                      << std::left << std::setw(10) << "PORT"
                      << std::setw(10) << "STATE"
                      << "SERVICE"
                      << color::reset << "\n";
            break;
        }

        // ── PORT_RESULT ──────────────────────────────────────────────────────
        // Every port discovery event (open / filtered few / closed individual).
        case PrintOutputType::PORT_RESULT: {
            std::string port_str = std::to_string(port) + "/tcp";
            std::string extra;

            // AFTER
	    if (state == "unfiltered") {
	        extra = "ACK";
	    } else if (state == "confused") {
	        if (!scan_name.empty() && scan_name != "SYN" && scan_name != "ACK")
		    extra = scan_name;
	    } else if (window_size > 0) {
	        extra = "WINDOW:" + std::to_string(window_size);
	    }
	    // ← icmp_note (not_shown_message) intentionally NOT put into extra here

	    if (state == "open" || state == "confused" || state == "unfiltered" || show_service) {
		print_port_line(port_str, state, service, extra);
	    }
            break;
        }

        // ── PORT_RESULT_CUSTOM ───────────────────────────────────────────────
        // Same layout as PORT_RESULT; handles WINDOW scan and non-SYN closed display.
        case PrintOutputType::PORT_RESULT_CUSTOM: {
            std::string port_str = std::to_string(port) + "/tcp";
            std::string extra;

            if (state == "confused") {
                extra = scan_name;
            } else if (scan_name == "WINDOW" && window_size > 0) {
                extra = "WINDOW:" + std::to_string(window_size);
            } else if (state == "closed"
                       && scan_name != "SYN"
                       && scan_name != "ACK"
                       && scan_name != "WINDOW") {
                extra = scan_name;
            } else if (!not_shown_message.empty()) {
                extra = not_shown_message;
            }

            print_port_line(port_str, state, service, extra);
            break;
        }

        // ── SCAN_SUMMARY ─────────────────────────────────────────────────────
        // In nmap style the port table IS the summary.
        // NOT_SHOWN_MESSAGE carries filtered/closed counts, so nothing more needed here.
        case PrintOutputType::SCAN_SUMMARY: {
            break;
        }

        // ── SCAN_TIMING ──────────────────────────────────────────────────────
        // "Duration           : 14.69s"
        case PrintOutputType::SCAN_TIMING: {
            std::cout << std::left << std::setw(15) << "Duration"
                      << ": ";
            if (elapsed_seconds < 0.001) {
                std::cout << std::fixed << std::setprecision(0)
                          << elapsed_seconds * 1e6 << "us\n";
            } else if (elapsed_seconds < 1.0) {
                std::cout << std::fixed << std::setprecision(0)
                          << elapsed_seconds * 1000.0 << "ms\n";
            } else {
                std::cout << std::fixed << std::setprecision(2)
                          << elapsed_seconds << "s\n";
            }
            break;
        }

        // ── RTT_INFO ─────────────────────────────────────────────────────────
        // "RTT                      : 0.274s"
        // elapsed_seconds is passed in milliseconds (result.learned_rtt_ms).
        case PrintOutputType::RTT_INFO: {
            std::cout << std::left << std::setw(15) << "RTT"
                      << ": ";
            if (elapsed_seconds > 0.0) {
                std::cout << std::fixed << std::setprecision(3)
                          << elapsed_seconds / 1000.0 << "s\n";
            } else {
                std::cout << color::dim << "N/A" << color::reset << "\n";
            }
            break;
        }

        // ── MAC_ADDRESS ──────────────────────────────────────────────────────
        // "MAC Address : aa:bb:cc:dd:ee:ff (Vendor)"
        case PrintOutputType::MAC_ADDRESS: {
	    if (!mac_address.empty()) {
		std::string v = vendor;
		// trim trailing whitespace/newlines from vendor
		while (!v.empty() && (v.back() == '\n' || v.back() == '\r' || v.back() == ' '))
		    v.pop_back();

		std::cout << std::left << std::setw(15) << "MAC Address"
                          << ": " << mac_address;
		if (!v.empty() && v != "unknown")
		    std::cout << " (" << color::green << v << color::reset << ")";
		std::cout << "\n";
	    }
	    break;
	}

        // ── OVERALL_COMPLETION ───────────────────────────────────────────────
        // Emits duration + response-rate stats at the very end (single-IP path).
        case PrintOutputType::OVERALL_COMPLETION: {
            size_t total_ports_scanned = open_count + closed_count + filtered_count;
            double response_rate = total_ports_scanned > 0
                ? (static_cast<double>(open_count + closed_count) / total_ports_scanned) * 100
                : 0.0;

            std::cout << std::left << std::setw(25) << "Duration"
                      << ": " << std::fixed << std::setprecision(2)
                      << elapsed_seconds << "s\n";
            std::cout << std::left << std::setw(25) << "Response rate"
                      << ": " << open_count + closed_count << "/"
                      << total_ports_scanned << " ports ("
                      << std::fixed << std::setprecision(1) << response_rate << "%)\n";
            break;
        }

        // ── THREAD_SUMMARY ───────────────────────────────────────────────────
        // Final line after all IPs done in multi-IP mode.
        case PrintOutputType::THREAD_SUMMARY: {
            //std::cout << "\n" << color::bold << scan_name << color::reset;
                      //<< " done: " << host_count
                      //<< " IP address" << (host_count != 1 ? "es" : "");
                      //<< " scanned"
                      //<< "  |  " << color::green << open_count << " open"  << color::reset
                      //<< "  " << color::red << closed_count << " closed" << color::reset
                      //<< "  " << color::yellow << filtered_count << " filtered" << color::reset
                      //<< "\n\n";
            break;
        }

        // ── MULTI_IP_SEPARATOR ───────────────────────────────────────────────
        // Thin divider between hosts in multi-IP scans.
        case PrintOutputType::MULTI_IP_SEPARATOR: {
            std::cout << "\n" << color::dim
                      << std::string(50, '-')
                      << color::reset << "\n";
            break;
        }

        // ── DOWN_HOSTS_SUMMARY ───────────────────────────────────────────────
        // "Note: N host(s) down (no ARP response)"
        case PrintOutputType::DOWN_HOSTS_SUMMARY: {
            if (open_count > 0) {   // open_count is repurposed as down-host count here
                if (host_count > 1) {
                    std::cout << color::yellow
                              << "Note: " << open_count
                              << " host(s) appear to be down (no ARP response)"
                              << color::reset << "\n";
                } else {
                    std::cout << color::red
                              << "Note: Host appears to be down (no ARP response)"
                              << color::reset << "\n";
                }
            }
            break;
        }

        // ── NOT_SHOWN_MESSAGE ────────────────────────────────────────────────
        // "Not shown      : 994 filtered tcp ports (no-response), 4 closed tcp ports (reset)"
        case PrintOutputType::NOT_SHOWN_MESSAGE: {
	    if (!not_shown_message.empty()) {
		std::string msg = not_shown_message;

		// color (reset) → red
		std::string from_reset = "(reset)";
		std::string to_reset   = color::red + "(reset)" + color::reset;
		size_t pos = msg.find(from_reset);
		if (pos != std::string::npos)
		    msg.replace(pos, from_reset.size(), to_reset);

		// color (no response) → yellow
		std::string from_noresp = "(no response)";
		std::string to_noresp   = color::yellow + "(no response)" + color::reset;
		pos = msg.find(from_noresp);
		if (pos != std::string::npos)
		    msg.replace(pos, from_noresp.size(), to_noresp);

		std::cout << std::left << std::setw(15) << "Not shown"
			  << ": " << msg << "\n";
	    }
	    break;
	}

        // ── INTERRUPTION_MESSAGE ─────────────────────────────────────────────
        case PrintOutputType::INTERRUPTION_MESSAGE: {
            std::cout << "\n" << color::red
                      << "Scan interrupted by user."
                      << color::reset << "\n";
            break;
        }

        // ── HOST_STATUS ──────────────────────────────────────────────────────
        case PrintOutputType::HOST_STATUS: {
            break;
        }
    }

    std::cout << std::flush;
}

std::string capture_output(PrintOutputType type,
    const std::string& ip, uint16_t port,
    const std::string& state, const std::string& service,
    const std::string& scan_name, uint16_t window_size,
    size_t port_count, size_t open_count, size_t closed_count,
    size_t filtered_count, size_t host_count,
    const std::string& mac_address, const std::string& vendor,
    double elapsed_seconds, const std::string& not_shown_message,
    bool print_timestamp, bool show_service)
{
    std::ostringstream oss;
    std::streambuf* old_buf = std::cout.rdbuf(oss.rdbuf());
    print_output(type, ip, port, state, service, scan_name, window_size,
                 port_count, open_count, closed_count, filtered_count,
                 host_count, mac_address, vendor, elapsed_seconds,
                 not_shown_message, print_timestamp, show_service);
    std::cout.rdbuf(old_buf);
    return oss.str();
}

bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                      uint8_t* src_mac, uint8_t* src_ip, 
                      const std::vector<uint8_t*>& target_IPs) {
    if (!src_mac || !src_ip || !ifname || !ring || target_IPs.empty()) {
        std::cerr << "send_arp_request: Invalid parameters\n";
        return false;
    }
    
    bool all_zero_mac = true;
    for (int i = 0; i < 6; i++) {
        if (src_mac[i] != 0) {
            all_zero_mac = false;
            break;
        }
    }
    if (all_zero_mac) {
        std::cerr << "send_arp_request: Invalid source MAC (all zeros)\n";
        return false;
    }
    
    bool all_zero_ip = true;
    for (int i = 0; i < 4; i++) {
        if (src_ip[i] != 0) {
            all_zero_ip = false;
            break;
        }
    }
    if (all_zero_ip) {
        std::cerr << "send_arp_request: Invalid source IP (all zeros)\n";
        return false;
    }
    
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        std::cerr << "send_arp_request: Invalid interface name: " << ifname << "\n";
        return false;
    }
    
    sockaddr_ll sa = {};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;
    memset(sa.sll_addr, 0xFF, ETH_ALEN);
    
    constexpr size_t BATCH_SIZE = 64;
    constexpr size_t PACKET_SIZE = sizeof(eth_frame) + sizeof(arp_header);
    alignas(64) uint8_t packet_template[PACKET_SIZE];
    memset(packet_template, 0, PACKET_SIZE);
    
    auto* eth = reinterpret_cast<eth_frame*>(packet_template);
    auto* arp = reinterpret_cast<arp_header*>(packet_template + sizeof(eth_frame));
    
    memset(eth->dst_mac, 0xFF, 6);  
    memcpy(eth->src_mac, src_mac, 6);
    eth->eth_type = htons(ETH_P_ARP);
    
    arp->htype = htons(1);           
    arp->ptype = htons(ETH_P_IP);    
    arp->hlen = 6;                   
    arp->plen = 4;                   
    arp->opcode = htons(1);         
    memcpy(arp->src_mac, src_mac, 6);
    memcpy(arp->src_ip, src_ip, 4);
    memset(arp->dst_mac, 0, 6);      
    
    int total_submitted = 0;
    const size_t total_packets = target_IPs.size();
    
    for (size_t i = 0; i < total_packets; ++i) {
        if (!target_IPs[i]) {
            std::cerr << "send_arp_request: target_IPs[" << i << "] is null\n";
            return false;
        }
    }
    
    std::vector<std::unique_ptr<uint8_t[]>> batch_buffers;
    
    for (size_t batch_start = 0; batch_start < total_packets && !terminate_flag; batch_start += BATCH_SIZE) {
        const size_t batch_end = std::min(batch_start + BATCH_SIZE, total_packets);
        const size_t batch_size = batch_end - batch_start;
        batch_buffers.emplace_back(std::make_unique<uint8_t[]>(batch_size * PACKET_SIZE));
        uint8_t* batch_buffer = batch_buffers.back().get();
        
        for (size_t i = 0; i < batch_size; ++i) {
            uint8_t* pkt_ptr = batch_buffer + i * PACKET_SIZE;
            memcpy(pkt_ptr, packet_template, PACKET_SIZE);
            arp_header* batch_arp = reinterpret_cast<arp_header*>(pkt_ptr + sizeof(eth_frame));
            memcpy(batch_arp->dst_ip, target_IPs[batch_start + i], 4);
            
            struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
            if (!sqe) {
                std::cerr << "send_arp_request: Failed to get SQE, ring may be full\n";
                for (auto& buf : batch_buffers) {
                    buf.reset();
                }
                return total_submitted > 0;
            }
            
            io_uring_prep_sendto(sqe, sock, pkt_ptr, PACKET_SIZE, 0,
                                 (sockaddr*)&sa, sizeof(sa));
            io_uring_sqe_set_data(sqe, nullptr);
            
            if (batch_arp->dst_ip[0] == 0 && batch_arp->dst_ip[1] == 0 && 
                batch_arp->dst_ip[2] == 0 && batch_arp->dst_ip[3] == 0) {
                std::cerr << "send_arp_request: Skipping packet with zero target IP\n";
                continue;
            }
        }
        
        int submitted = io_uring_submit(ring);
        if (submitted < 0) {
            std::cerr << "send_arp_request: io_uring_submit failed: " << strerror(errno) << "\n";
            break;
        }
        total_submitted += submitted;
        
        if (total_submitted > 0) {
            auto start = std::chrono::steady_clock::now();
            int processed = 0;
            const int MAX_WAIT_MS = 2000;
            
            // BATCH DRAINING: Process multiple completions per wait
            while (processed < submitted && !terminate_flag) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
                if (elapsed.count() > MAX_WAIT_MS) {
                    std::cerr << "send_arp_request: Timeout waiting for send completions\n";
                    break;
                }
                
                io_uring_cqe* cqe;
                struct __kernel_timespec ts = {
                    .tv_sec = 0,
                    .tv_nsec = 1000000  // 1ms timeout
                };
                int ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
                
                if (ret == 0) {
                    // Process first completion
                    if (cqe->res < 0) {
                        std::cerr << "send_arp_request: ARP send failed: " 
                                  << strerror(-cqe->res) << "\n";
                    }
                    io_uring_cqe_seen(ring, cqe);
                    processed++;
                    
                    // DRAIN ALL REMAINING COMPLETIONS WITHOUT WAITING
                    while (processed < submitted && 
                           io_uring_peek_cqe(ring, &cqe) == 0) {
                        if (cqe->res < 0) {
                            std::cerr << "send_arp_request: ARP send failed: " 
                                      << strerror(-cqe->res) << "\n";
                        }
                        io_uring_cqe_seen(ring, cqe);
                        processed++;
                    }
                } else if (ret == -ETIME) {
                    // No completions available, continue waiting
                    continue;
                } else if (ret != -EINTR) {
                    std::cerr << "send_arp_request: wait_cqe error: " << strerror(-ret) << "\n";
                    break;
                }
            }
            
            if (processed < submitted) {
                std::cerr << "send_arp_request: Only processed " << processed 
                          << " of " << submitted << " completions\n";
            }
        }
        batch_buffers.back().reset();
    }
    
    batch_buffers.clear();
    
    // Clean up any remaining CQEs
    if (total_submitted > 0) {
        io_uring_cqe* cqe;
        struct __kernel_timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 0  // Non-blocking cleanup
        };
        while (io_uring_wait_cqe_timeout(ring, &cqe, &ts) == 0) {
            io_uring_cqe_seen(ring, cqe);
        }
    }
    
    return total_submitted > 0;
}

bool receive_arp_reply(int sock, struct io_uring* ring, 
                      const std::vector<uint8_t*>& target_IPs,std::vector<uint8_t*>& macs,int timeout_ms) {
    if (!ring || target_IPs.empty() || macs.size() != target_IPs.size()) 
        return false;
    
    for (size_t i = 0; i < macs.size(); ++i) {
        if (!macs[i]) return false;
        memset(macs[i], 0, 6);
    }
    
    for (size_t i = 0; i < target_IPs.size(); ++i) {
        if (!target_IPs[i]) return false;
    }
    const size_t total_targets = target_IPs.size();
    std::vector<bool> resolved(total_targets, false);
    int total_resolved = 0;
    auto start_time = std::chrono::steady_clock::now();
    std::unordered_map<uint32_t, size_t> ip_to_index;
    ip_to_index.reserve(total_targets);
    for (size_t i = 0; i < total_targets; ++i) {
        uint32_t ip_val;
        memcpy(&ip_val, target_IPs[i], 4);
        if (ip_to_index.find(ip_val) != ip_to_index.end()) 
            return false;
        ip_to_index[ip_val] = i;
    }
    if (timeout_ms <= 0) return false;
    const size_t MIN_PACKET_SIZE = sizeof(eth_frame) + sizeof(arp_header);
    const size_t MAX_PACKET_SIZE = 1500;
    bool receive_pending = false;
    std::unique_ptr<uint8_t[]> current_buffer;
    current_buffer = std::make_unique<uint8_t[]>(MAX_PACKET_SIZE);
    if (!current_buffer) return false;
    struct iovec iov = {current_buffer.get(), MAX_PACKET_SIZE};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return false;
    io_uring_prep_recvmsg(sqe, sock, &msg, 0);
    io_uring_sqe_set_data(sqe, current_buffer.get());
    if (io_uring_submit(ring) > 0) {
        receive_pending = true;
        current_buffer.release();
    } else {
        return false;
    }
    while (total_resolved < total_targets && !terminate_flag) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - start_time).count();
        if (elapsed_ms > timeout_ms) break;
        if (receive_pending) {
            int remaining_ms = std::max(1, timeout_ms - static_cast<int>(elapsed_ms));
            struct __kernel_timespec timeout_ts = {
                .tv_sec = remaining_ms / 1000,
                .tv_nsec = (remaining_ms % 1000) * 1000000
            };
            struct io_uring_cqe *cqe;
            int ret = io_uring_wait_cqe_timeout(ring, &cqe, &timeout_ts);
            if (ret == 0) {
                int bytes_received = cqe->res;
                uint8_t* received_buffer = static_cast<uint8_t*>(io_uring_cqe_get_data(cqe));
                std::unique_ptr<uint8_t[]> buffer_cleanup(received_buffer);
                if (bytes_received > 0 && bytes_received >= static_cast<ssize_t>(MIN_PACKET_SIZE)) {
                    if (bytes_received <= static_cast<ssize_t>(MAX_PACKET_SIZE)) {
                        struct eth_frame* eth = reinterpret_cast<struct eth_frame*>(received_buffer);
                        if (ntohs(eth->eth_type) == ETH_P_ARP) {
                            struct arp_header* arp = reinterpret_cast<struct arp_header*>(
                                received_buffer + sizeof(eth_frame));
                            if (ntohs(arp->opcode) == 2 && arp->hlen == 6 && arp->plen == 4) {
                                uint32_t src_ip;
                                memcpy(&src_ip, arp->src_ip, 4); 
                                auto it = ip_to_index.find(src_ip);
                                if (it != ip_to_index.end() && !resolved[it->second]) {
                                    if (!(arp->src_mac[0] == 0xFF && arp->src_mac[1] == 0xFF &&
                                          arp->src_mac[2] == 0xFF && arp->src_mac[3] == 0xFF &&
                                          arp->src_mac[4] == 0xFF && arp->src_mac[5] == 0xFF) &&
                                        !(arp->src_mac[0] == 0 && arp->src_mac[1] == 0 &&
                                          arp->src_mac[2] == 0 && arp->src_mac[3] == 0 &&
                                          arp->src_mac[4] == 0 && arp->src_mac[5] == 0)) {
                                        memcpy(macs[it->second], arp->src_mac, 6);
                                        resolved[it->second] = true;
                                        total_resolved++;
                                    }
                                }
                            }
                        }
                    }
                } else if (bytes_received == 0) {
                    receive_pending = false;
                    break;
                } else if (bytes_received < 0 && bytes_received != -EAGAIN && 
                          bytes_received != -EWOULDBLOCK && bytes_received != -EINTR) {
                    receive_pending = false;
                    break;
                }
                io_uring_cqe_seen(ring, cqe);
                receive_pending = false;
                if (total_resolved < total_targets) {
                    current_buffer = std::make_unique<uint8_t[]>(MAX_PACKET_SIZE);
                    if (!current_buffer) break;
                    iov.iov_base = current_buffer.get();
                    msg.msg_iov = &iov;
                    sqe = io_uring_get_sqe(ring);
                    if (sqe) {
                        io_uring_prep_recvmsg(sqe, sock, &msg, 0);
                        io_uring_sqe_set_data(sqe, current_buffer.get());
                        if (io_uring_submit(ring) > 0) {
                            receive_pending = true;
                            current_buffer.release();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else if (ret == -ETIME) {
                receive_pending = false;
            } else if (ret < 0 && ret != -EINTR) {
                receive_pending = false;
                break;
            }
        } else {
            current_buffer = std::make_unique<uint8_t[]>(MAX_PACKET_SIZE);
            if (!current_buffer) break;
            iov.iov_base = current_buffer.get();
            msg.msg_iov = &iov;
            sqe = io_uring_get_sqe(ring);
            if (sqe) {
                io_uring_prep_recvmsg(sqe, sock, &msg, 0);
                io_uring_sqe_set_data(sqe, current_buffer.get());
                if (io_uring_submit(ring) > 0) {
                    receive_pending = true;
                    current_buffer.release();
                } else {
                    break;
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    if (receive_pending) {
        struct io_uring_cqe *cqe;
        if (io_uring_peek_cqe(ring, &cqe) == 0) {
            uint8_t* pending_buffer = static_cast<uint8_t*>(io_uring_cqe_get_data(cqe));
            if (pending_buffer) {
                std::unique_ptr<uint8_t[]> cleanup(pending_buffer);
            }
            io_uring_cqe_seen(ring, cqe);
        }
    }
    return total_resolved > 0;
}

uint32_t get_local_ip(const char *remote_ip) {
    static std::unordered_map<uint32_t, uint32_t> local_ip_cache;
    static std::mutex cache_mutex;

    struct in_addr addr{};
    if (inet_pton(AF_INET, remote_ip, &addr) <= 0) return 0;

    // Use first 3 octets as subnet key (cache per /24)
    uint32_t subnet_key = ntohl(addr.s_addr) >> 8;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = local_ip_cache.find(subnet_key);
        if (it != local_ip_cache.end()) return it->second;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    struct SocketGuard {
        int fd;
        ~SocketGuard() { if (fd >= 0) close(fd); }
    } guard{sock};
    sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(9)};
    remote.sin_addr = addr;
    if (connect(sock, (sockaddr*)&remote, sizeof(remote)) < 0) return 0;
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    uint32_t result = getsockname(sock, (sockaddr*)&local, &len) == 0
                      ? local.sin_addr.s_addr : 0;

    std::lock_guard<std::mutex> lock(cache_mutex);
    local_ip_cache[subnet_key] = result;
    return result;
}

bool build_packet(const PacketTask& task, char* packet_buffer, size_t buffer_size,
                  uint32_t src_ip, std::mt19937& rng, uint16_t ip_id, uint16_t win_size,
                  uint8_t ttl, uint8_t dscp,uint16_t ip_flags,bool use_ip_tos, uint8_t custom_ip_tos_byte, bool use_manual_tcp_checksum,
                  uint16_t manual_tcp_checksum, uint8_t window_scale, uint16_t mss_value,
                  uint32_t timestamp_val, uint32_t timestamp_ecr_custom, uint16_t nops_count,
                  bool sack_permitted, const std::string& custom_data, uint16_t data_length,
                  bool use_custom_data, bool generate_random_data, bool use_badsum,
                  uint16_t custom_badsum_value, bool use_partial_badsum,
                  const std::string& partial_badsum_type, bool use_tfo_cookie,
                  bool tfo_cookie_as_hex, bool tfo_cookie_random,
                  const std::string& tfo_cookie_str, uint64_t tfo_cookie_num,
                  size_t tfo_cookie_length, size_t& packet_len_out,uint16_t& effective_frag_out,bool use_fragmentation = false, uint16_t frag_size = 8, uint16_t mtu_size = 0,PacketLengthConfig packet_length_config = {}) {

    if (!packet_buffer || buffer_size == 0) {
        return false;
    }
    if (buffer_size < sizeof(struct ip) + sizeof(struct tcphdr)) {
        return false;
    }

    static const struct {
        uint8_t ip_base[20] = {
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        uint8_t tcp_base[20] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
    } templates;

    struct ip    *iph  = (struct ip *)packet_buffer;
    struct tcphdr *tcph = (struct tcphdr *)(packet_buffer + sizeof(struct ip));
    memcpy(iph,  templates.ip_base,  sizeof(templates.ip_base));
    memcpy(tcph, templates.tcp_base, sizeof(templates.tcp_base));
     iph->ip_tos = use_ip_tos ? custom_ip_tos_byte : static_cast<uint8_t>(dscp << 2);

    static constexpr size_t OPTIONS_STACK_CAP = 1024;
    uint8_t options[OPTIONS_STACK_CAP];
    size_t  opt_len = 0;

    size_t MAX_TCP_OPTIONS_SIZE = 40;
    bool intentional_malformed  = false;

    if (use_tfo_cookie && tfo_cookie_random && tfo_cookie_length > 100000) {
        intentional_malformed    = true;
        MAX_TCP_OPTIONS_SIZE     = std::min(static_cast<size_t>(1024),
                                            buffer_size - sizeof(struct ip)
                                                        - sizeof(struct tcphdr));
    }

    bool add_mss = true;
    if (add_mss && !(task.scan_type == ScanType::NULL_SCAN ||
                     task.scan_type == ScanType::XMAS)) {
        if (opt_len + 4 <= MAX_TCP_OPTIONS_SIZE) {
            options[opt_len++] = 0x02;
            options[opt_len++] = 0x04;
            options[opt_len++] = static_cast<uint8_t>(mss_value >> 8);
            options[opt_len++] = static_cast<uint8_t>(mss_value & 0xFF);
        }
    }

    bool add_ws = (window_scale > 0);
    if (add_ws && opt_len + 3 <= MAX_TCP_OPTIONS_SIZE) {
        options[opt_len++] = 0x03;
        options[opt_len++] = 0x03;
        options[opt_len++] = window_scale;
    }


    bool add_sack = sack_permitted;
    if (add_sack && opt_len + 2 <= MAX_TCP_OPTIONS_SIZE) {
        options[opt_len++] = 0x04;
        options[opt_len++] = 0x02;
    }


    bool add_ts = (timestamp_val != 0);
    if (add_ts && opt_len + 10 <= MAX_TCP_OPTIONS_SIZE) {
        options[opt_len++] = 0x08;
        options[opt_len++] = 0x0A;
        for (int i = 24; i >= 0; i -= 8)
            options[opt_len++] = static_cast<uint8_t>((timestamp_val      >> i) & 0xFF);
        for (int i = 24; i >= 0; i -= 8)
            options[opt_len++] = static_cast<uint8_t>((timestamp_ecr_custom >> i) & 0xFF);
    }


    if (use_tfo_cookie && task.use_tfo_cookie) {

        uint8_t cookie_data[1024];
        size_t  cookie_len = 0;

        if (task.tfo_cookie_random) {
            size_t req_len = task.tfo_cookie_length;

            if (intentional_malformed && task.tfo_cookie_random &&
                tfo_cookie_length > 100000) {
                size_t actual_generation =
                    std::min(req_len, static_cast<size_t>(1000));
                actual_generation =
                    std::min(actual_generation,
                             std::min(MAX_TCP_OPTIONS_SIZE - opt_len - 3,
                                      OPTIONS_STACK_CAP));
                std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
                for (size_t i = 0; i < actual_generation; ++i)
                    cookie_data[cookie_len++] = byte_dist(rng);
            } else {
                if (req_len == 0) req_len = 8;
                if (req_len > 253 && !intentional_malformed) req_len = 253;

                size_t space = MAX_TCP_OPTIONS_SIZE - opt_len - 3;
                space        = std::min(space, OPTIONS_STACK_CAP);
                req_len      = std::min(req_len, space);

                std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
                for (size_t i = 0; i < req_len; ++i)
                    cookie_data[cookie_len++] = byte_dist(rng);
            }

        } else if (task.tfo_cookie_as_hex && !task.tfo_cookie_str.empty()) {
            std::string hex_str = task.tfo_cookie_str;
            if (hex_str.find("0x") == 0 || hex_str.find("0X") == 0)
                hex_str = hex_str.substr(2);
            if (hex_str.length() % 2 != 0)
                hex_str = "0" + hex_str;

            size_t max_bytes = (MAX_TCP_OPTIONS_SIZE - opt_len - 3) / 2;
            max_bytes        = std::min(max_bytes, OPTIONS_STACK_CAP);
            size_t bytes_to_read = std::min(hex_str.length() / 2, max_bytes);

            for (size_t i = 0;
                 i < hex_str.length() && cookie_len < bytes_to_read;
                 i += 2) {
                std::string byte_str = hex_str.substr(i, 2);
                try {
                    cookie_data[cookie_len++] =
                        static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                } catch (...) {
                    cookie_data[cookie_len++] = 0;
                }
            }

        } else if (!task.tfo_cookie_str.empty()) {
            size_t max_len = std::min(MAX_TCP_OPTIONS_SIZE - opt_len - 3,
                                      OPTIONS_STACK_CAP);
            size_t str_len = std::min(task.tfo_cookie_str.length(), max_len);
            memcpy(cookie_data, task.tfo_cookie_str.data(), str_len);
            cookie_len = str_len;

        } else if (task.tfo_cookie_num > 0) {
            uint64_t num       = task.tfo_cookie_num;
            size_t   max_bytes = std::min(MAX_TCP_OPTIONS_SIZE - opt_len - 3,
                                          OPTIONS_STACK_CAP);
            size_t   bytes_needed = 0;
            uint64_t temp         = num;
            if (temp == 0) bytes_needed = 1;
            while (temp > 0) { bytes_needed++; temp >>= 8; }
            bytes_needed = std::min(bytes_needed, static_cast<size_t>(8));
            bytes_needed = std::min(bytes_needed, max_bytes);
            for (int i = static_cast<int>(bytes_needed) - 1; i >= 0; --i)
                cookie_data[cookie_len++] =
                    static_cast<uint8_t>((num >> (8 * (bytes_needed - 1 - i))) & 0xFF);

        } else {
            size_t max_bytes  = std::min(MAX_TCP_OPTIONS_SIZE - opt_len - 3,
                                         OPTIONS_STACK_CAP);
            size_t default_len = std::min(static_cast<size_t>(8), max_bytes);
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            for (size_t i = 0; i < default_len; ++i)
                cookie_data[cookie_len++] = byte_dist(rng);
        }

        if (cookie_len > 0) {
            if (intentional_malformed && task.tfo_cookie_random &&
                tfo_cookie_length > 100000) {
                uint8_t fake_length_byte2 =
                    static_cast<uint8_t>(tfo_cookie_length & 0xFF);
                if (opt_len + 3 <= MAX_TCP_OPTIONS_SIZE) {
                    options[opt_len++] = 34;
                    options[opt_len++] = fake_length_byte2;
                    options[opt_len++] = 0xF9;
                }
            } else {
                size_t total_option_size = 3 + cookie_len;
                if (opt_len + total_option_size <= MAX_TCP_OPTIONS_SIZE &&
                    opt_len + total_option_size <= OPTIONS_STACK_CAP) {
                    options[opt_len++] = 34;
                    options[opt_len++] = static_cast<uint8_t>(3 + cookie_len);
                    options[opt_len++] = 0xF9;
                    memcpy(options + opt_len, cookie_data, cookie_len);
                    opt_len += cookie_len;
                }
            }
        }
    }

    if (task.nops_count > 0) {
        size_t nops_to_add = task.nops_count;
        if (!intentional_malformed &&
            (opt_len + nops_to_add) > MAX_TCP_OPTIONS_SIZE)
            nops_to_add = MAX_TCP_OPTIONS_SIZE - opt_len;
        nops_to_add = std::min(nops_to_add, MAX_TCP_OPTIONS_SIZE - opt_len);
        nops_to_add = std::min(nops_to_add, OPTIONS_STACK_CAP - opt_len);
        for (size_t j = 0; j < nops_to_add; ++j)
            options[opt_len++] = 0x01;
    }

    if ((task.scan_type == ScanType::NULL_SCAN ||
         task.scan_type == ScanType::XMAS) && !task.use_tfo_cookie) {
        opt_len = 0;
    }

    if (!intentional_malformed) {
        while (opt_len % 4 != 0 && opt_len < MAX_TCP_OPTIONS_SIZE &&
               opt_len < OPTIONS_STACK_CAP)
            options[opt_len++] = 0x01;
    }

    if (intentional_malformed && opt_len <= 40) {
        size_t extra_bytes =
            std::min(static_cast<size_t>(100),
                     std::min(MAX_TCP_OPTIONS_SIZE - opt_len,
                              OPTIONS_STACK_CAP     - opt_len));
        for (size_t j = 0; j < extra_bytes; ++j)
            options[opt_len++] = 0xFF;
    }

    std::string payload;
    if (use_custom_data && !custom_data.empty()) {
        payload = custom_data;
    } else if (generate_random_data && data_length > 0) {
        payload.reserve(data_length);
        static const std::string chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "0123456789"
            "!@#$%^&*()_+-=[]{}|;:,.<>?/~`\"\\\n\r\t"
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
        std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);
        for (uint16_t i = 0;
             i < data_length &&
             i < (buffer_size - sizeof(struct ip) - sizeof(struct tcphdr) - opt_len);
             ++i)
            payload += chars[dist(rng)];
    } else if (!task.data.empty()) {
        payload = task.data;
    }

    size_t options_len      = opt_len;
    size_t data_len         = payload.length();
    size_t total_packet_len = sizeof(struct ip) + sizeof(struct tcphdr)
                            + options_len + data_len;

    if (total_packet_len > buffer_size) {
        if (intentional_malformed) {
            size_t max_options =
                buffer_size - (sizeof(struct ip) + sizeof(struct tcphdr) + data_len);
            if (max_options > 0) {
                options_len     = std::min(options_len, max_options);
                total_packet_len = sizeof(struct ip) + sizeof(struct tcphdr)
                                 + options_len + data_len;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    packet_len_out = total_packet_len;
    iph->ip_len    = htons(static_cast<uint16_t>(total_packet_len));
    iph->ip_id              = htons(ip_id);
    iph->ip_ttl             = ttl;
    // Compute fragmentation step and set ip_off
    effective_frag_out = 0;
    if (use_fragmentation || mtu_size > 0) {
        // mtu_size drives step if set; otherwise use explicit frag_size
        uint16_t raw_step = (mtu_size > 0)
            ? static_cast<uint16_t>(mtu_size - 20)   // subtract IP header
            : frag_size;
        // Enforce 8-byte alignment (IP frag offset unit is 8 bytes, RFC 791)
        raw_step = static_cast<uint16_t>((raw_step / 2) * 2);
        if (raw_step < 2) raw_step = 2;  // absolute minimum
        effective_frag_out = raw_step;
        // Set MF bit; the send loop will clear it on the last fragment
        iph->ip_off = htons(IP_MF);
    } else {
        iph->ip_off = htons(ip_flags);  // normal path, completely unchanged
    }
    iph->ip_src.s_addr      = src_ip;
    iph->ip_dst.s_addr      = task.dest.sin_addr.s_addr;

    tcph->th_sport          = htons(task.src_port);
    tcph->th_dport          = task.dest.sin_port;
    tcph->th_seq            = htonl(task.seq);
    tcph->th_ack            = htonl(task.ack);
    tcph->th_flags          = task.flags;

    uint16_t effective_win_size = win_size;
    if (win_size > 0 && task.scan_type != ScanType::WINDOW) {
        effective_win_size = win_size;
    } else if (task.scan_type == ScanType::WINDOW) {
        effective_win_size = 1024;
    } else {
        effective_win_size = 65535;
    }
    tcph->th_win = htons(effective_win_size);

    size_t tcp_header_size = sizeof(struct tcphdr) + options_len;
    tcph->th_off = tcp_header_size / 4;
    if (tcp_header_size / 4 > 15) {
        if (intentional_malformed) {
            tcph->th_off = 15;
        } else {
            tcph->th_off = 15;
        }
    }
    tcph->th_urp = 0;

    if (options_len > 0) {
        if (sizeof(struct ip) + sizeof(struct tcphdr) + options_len <= buffer_size)
            memcpy(packet_buffer + sizeof(struct ip) + sizeof(struct tcphdr),
                   options, options_len);
    }
    if (data_len > 0) {
        size_t payload_offset = sizeof(struct ip) + sizeof(struct tcphdr) + options_len;
        if (payload_offset + data_len <= buffer_size)
            memcpy(packet_buffer + payload_offset, payload.data(), data_len);
    }

    if (!use_manual_tcp_checksum) {
        size_t tcp_segment_len = sizeof(struct tcphdr) + options_len + data_len;
        struct {
            uint32_t src; uint32_t dst; uint8_t zero; uint8_t protocol; uint16_t tcp_len;
        } __attribute__((packed)) psh = {
            .src      = src_ip,
            .dst      = task.dest.sin_addr.s_addr,
            .zero     = 0,
            .protocol = IPPROTO_TCP,
            .tcp_len  = htons(tcp_segment_len)
        };
        alignas(uint16_t) uint8_t aligned_psh[sizeof(psh)];
	memcpy(aligned_psh, &psh, sizeof(psh));
	uint16_t *ptr16 = (uint16_t*)aligned_psh;

	uint32_t sum = 0;
	sum += ptr16[0]; sum += ptr16[1];
	sum += ptr16[2]; sum += ptr16[3];
	sum += ptr16[4]; sum += ptr16[5];
	ptr16       = (uint16_t*)tcph;
	size_t words = tcp_segment_len / 2;
	for (size_t j = 0; j < words; ++j)
    		sum += ptr16[j];
	if (tcp_segment_len % 2)
    		sum += ((uint8_t*)tcph)[tcp_segment_len - 1] << 8;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	tcph->th_sum = ~sum;
    } else {
        tcph->th_sum = manual_tcp_checksum;
    }

    if (use_badsum) {
        if (custom_badsum_value)
            tcph->th_sum = custom_badsum_value;
        else {
            static const uint16_t bad_patterns[] =
                {0x0000, 0xFFFF, 0x1234, 0x5678, 0x9ABC, 0xDEF0, 0xBEEF, 0xDEAD};
            std::uniform_int_distribution<size_t> dist(0, std::size(bad_patterns) - 1);
            tcph->th_sum = bad_patterns[dist(rng)];
        }
    } else if (use_partial_badsum) {
        uint16_t correct = ntohs(tcph->th_sum);
        uint16_t result  = correct;

        static thread_local std::mt19937 rnd(
            std::random_device{}() +
            std::hash<std::thread::id>{}(std::this_thread::get_id()));
        auto bit = [&](int n) { return uint16_t(1u << (n % 16)); };

        if      (partial_badsum_type == "lower")
            result = (correct & 0xFF00) | ((correct ^ 0x00FF) & 0x00FF);
        else if (partial_badsum_type == "upper")
            result = (correct & 0x00FF) | ((correct ^ 0xFF00) & 0xFF00);
        else if (partial_badsum_type == "bitflip")
            result = correct ^ bit(rnd());
        else if (partial_badsum_type == "middle")
            result = correct ^ 0x0FF0;
        else if (partial_badsum_type == "swap")
            result = (correct << 8) | (correct >> 8);
        else if (partial_badsum_type == "incremental")
            result = correct - 0x0100;
        else if (partial_badsum_type == "pattern") {
            static thread_local uint8_t idx = 0;
            static const uint16_t pat[] =
                {0xC3C3, 0x9696, 0x5A5A, 0xA5A5, 0x3C3C, 0x6969};
            result = correct ^ pat[idx++ % std::size(pat)];
        }
        else if (partial_badsum_type == "null")
            result = 0x0000;
        else if (partial_badsum_type == "msb")
            result = correct ^ 0x8000;
        else if (partial_badsum_type == "lsb3")
            result = correct ^ (rnd() & 0x0007);
        else if (partial_badsum_type == "rfc1141")
            result = correct ^ 0x1000;
        else if (partial_badsum_type == "seq-tied")
            result = correct ^ ((task.seq >> 16) & 0xFFFF);
        else if (partial_badsum_type == "port-tied")
            result = correct ^ (task.src_port ^ ntohs(task.dest.sin_port));
        else if (partial_badsum_type == "timestamp-lie")
            result = correct ^ ((task.custom_timestamp >> 16) & 0xFF);
        else if (partial_badsum_type == "ones-complement")
            result = ~correct;
        else if (partial_badsum_type == "walking-bit") {
            static thread_local uint8_t b = 0;
            result = correct ^ bit(b++);
        }
        else if (partial_badsum_type == "entropy") {
            std::uniform_int_distribution<uint16_t> dist(0, 0xFFFF);
            result = dist(rnd);
        }
        else if (partial_badsum_type == "valid-ish")
            result = correct + 1;
        else if (partial_badsum_type == "carry-break") {
            uint32_t s = correct + 0xFFFF;
            s = (s & 0xFFFF) + (s >> 16);
            result = s & 0xFFFF;  
        }
        else if (partial_badsum_type == "goodbye")
            result = correct ^ 0xFFFF;
        else
            result = correct ^ bit(rnd());

        tcph->th_sum = htons(result);
    }
    
    // ── --packet-length enforcement (MUST be after checksum) ─────────────────
    if (packet_length_config.enabled) {
        const size_t MIN_PKT = sizeof(struct ip) + sizeof(struct tcphdr);  // 40 bytes
        const size_t MAX_PKT = buffer_size;

        switch (packet_length_config.mode) {

            case PacketLengthMode::BIG: {
                // Lie only: claim bigger ip_len in header, real bytes unchanged
                uint16_t lie = static_cast<uint16_t>(
                    std::min<size_t>(total_packet_len + packet_length_config.big_delta, 65535u));
                iph->ip_len = htons(lie);
                // packet_len_out stays = real bytes sent on wire
                break;
            }

            case PacketLengthMode::SMALL: {
                // Lie only: claim smaller ip_len, real bytes unchanged
                size_t lie = std::max<size_t>(
                    total_packet_len - packet_length_config.small_delta, MIN_PKT);
                iph->ip_len = htons(static_cast<uint16_t>(lie));
                break;
            }

            case PacketLengthMode::BIG_EXACT: {
                // Pad real bytes to target, honest ip_len
                uint16_t target = packet_length_config.target_len;
                if (target > total_packet_len && target <= MAX_PKT) {
                    size_t pad = target - total_packet_len;
                    if (total_packet_len + pad <= buffer_size) {
                        memset(packet_buffer + total_packet_len, 0x00, pad);
                        total_packet_len += pad;
                        packet_len_out    = total_packet_len;
                        // Recompute TCP checksum to cover padding bytes
                        tcph->th_sum = 0;
                        size_t new_tcp_len = total_packet_len - sizeof(struct ip);
                        struct { uint32_t s,d; uint8_t z,p; uint16_t l; }
                            __attribute__((packed))
                            psh2 = { src_ip, task.dest.sin_addr.s_addr,
                                     0, IPPROTO_TCP,
                                     htons(static_cast<uint16_t>(new_tcp_len)) };
                        uint32_t sum = 0;
                        auto* pw = reinterpret_cast<uint16_t*>(&psh2);
                        for (size_t k = 0; k < sizeof(psh2)/2; ++k) sum += pw[k];
                        auto* td = reinterpret_cast<uint16_t*>(tcph);
                        size_t words = new_tcp_len / 2;
                        for (size_t k = 0; k < words; ++k) sum += td[k];
                        if (new_tcp_len % 2)
                            sum += static_cast<uint8_t*>(static_cast<void*>(tcph))[new_tcp_len-1] << 8;
                        sum = (sum >> 16) + (sum & 0xFFFF);
                        sum += (sum >> 16);
                        tcph->th_sum = ~static_cast<uint16_t>(sum);
                        iph->ip_len  = htons(static_cast<uint16_t>(total_packet_len));
                    }
                }
                break;
            }

            case PacketLengthMode::SMALL_EXACT: {
                // Truncate: shrink real bytes, honest ip_len
                uint16_t target = packet_length_config.target_len;
                if (target < total_packet_len && target >= MIN_PKT) {
                    total_packet_len = target;
                    packet_len_out   = total_packet_len;
                    // Recompute checksum for truncated segment
                    tcph->th_sum = 0;
                    size_t new_tcp_len = total_packet_len - sizeof(struct ip);
                    struct { uint32_t s,d; uint8_t z,p; uint16_t l; }
                        __attribute__((packed))
                        psh2 = { src_ip, task.dest.sin_addr.s_addr,
                                 0, IPPROTO_TCP,
                                 htons(static_cast<uint16_t>(new_tcp_len)) };
                    uint32_t sum = 0;
                    auto* pw = reinterpret_cast<uint16_t*>(&psh2);
                    for (size_t k = 0; k < sizeof(psh2)/2; ++k) sum += pw[k];
                    auto* td = reinterpret_cast<uint16_t*>(tcph);
                    size_t words = new_tcp_len / 2;
                    for (size_t k = 0; k < words; ++k) sum += td[k];
                    if (new_tcp_len % 2)
                        sum += static_cast<uint8_t*>(static_cast<void*>(tcph))[new_tcp_len-1] << 8;
                    sum = (sum >> 16) + (sum & 0xFFFF);
                    sum += (sum >> 16);
                    tcph->th_sum = ~static_cast<uint16_t>(sum);
                    iph->ip_len  = htons(static_cast<uint16_t>(total_packet_len));
                }
                break;
            }

            case PacketLengthMode::EXACT: {
                // Pad or shrink real bytes, honest ip_len
                uint16_t target = packet_length_config.target_len;
                if (target > total_packet_len && target <= MAX_PKT) {
                    size_t pad = target - total_packet_len;
                    if (total_packet_len + pad <= buffer_size) {
                        memset(packet_buffer + total_packet_len, 0x00, pad);
                        total_packet_len += pad;
                        packet_len_out    = total_packet_len;
                    }
                } else if (target < total_packet_len && target >= MIN_PKT) {
                    total_packet_len = target;
                    packet_len_out   = total_packet_len;
                }
                // Recompute checksum for new length
                tcph->th_sum = 0;
                size_t new_tcp_len = total_packet_len - sizeof(struct ip);
                struct { uint32_t s,d; uint8_t z,p; uint16_t l; }
                    __attribute__((packed))
                    psh2 = { src_ip, task.dest.sin_addr.s_addr,
                             0, IPPROTO_TCP,
                             htons(static_cast<uint16_t>(new_tcp_len)) };
                uint32_t sum = 0;
                auto* pw = reinterpret_cast<uint16_t*>(&psh2);
                for (size_t k = 0; k < sizeof(psh2)/2; ++k) sum += pw[k];
                auto* td = reinterpret_cast<uint16_t*>(tcph);
                size_t words = new_tcp_len / 2;
                for (size_t k = 0; k < words; ++k) sum += td[k];
                if (new_tcp_len % 2)
                    sum += static_cast<uint8_t*>(static_cast<void*>(tcph))[new_tcp_len-1] << 8;
                sum = (sum >> 16) + (sum & 0xFFFF);
                sum += (sum >> 16);
                tcph->th_sum = ~static_cast<uint16_t>(sum);
                iph->ip_len  = htons(static_cast<uint16_t>(total_packet_len));
                break;
            }

            case PacketLengthMode::CLAIMED: {
                // Pure lie: only set ip_len, real bytes and checksum unchanged
                iph->ip_len = htons(packet_length_config.target_len);
                break;
            }

            default: break;
        }
    }
    // ── end packet-length ─────────────────────────────────────────────────────

    return true;
}


int send_tcp_packets(int sock, const std::span<PacketTask> tasks, uint32_t src_ip, 
                     std::mt19937 &rng, PacketBufferPool &pool, uint16_t win_size,struct io_uring *send_ring, size_t batch_size, uint8_t custom_ttl,uint8_t custom_dscp,
                     uint16_t custom_ip_flags,IpIdMode ip_id_mode, uint16_t fixed_ip_id,bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum,
                     uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,
                     const std::string& custom_data, uint16_t data_length, bool use_custom_data, bool generate_random_data,
                     bool use_badsum, uint16_t custom_badsum_value,bool use_partial_badsum, const std::string& partial_badsum_type,
                     bool use_tfo_cookie, bool tfo_cookie_as_hex, bool tfo_cookie_random,const std::string& tfo_cookie_str, uint64_t tfo_cookie_num,
                     size_t tfo_cookie_length,bool use_fragmentation, uint16_t frag_size, uint16_t mtu_size,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,
                     bool use_ip_tos, uint8_t custom_ip_tos_byte,PacketLengthConfig packet_length_config,std::function<void(const std::vector<uint16_t>&,const std::vector<uint16_t>&)> on_pre_submit) {
                     
    struct FragInfo {
        char*    buf;
        size_t   total_len;
        iovec    iov;
        msghdr   msg;
    };
    
    struct ThreadLocalBuffers {
        std::vector<char*> packets;
        std::vector<struct msghdr> msgs;
        std::vector<struct iovec> iovs;
        std::vector<size_t> packet_lengths;
        std::vector<uint16_t> frag_steps;
        size_t max_capacity;
            struct FragMeta {
            struct iovec  iov;
            struct msghdr msg;
        };
        std::vector<FragMeta> frag_meta;  // flat slab, indexed by frag_meta_head
        size_t frag_meta_head = 0; 
        
        ThreadLocalBuffers() : max_capacity(0) {}
        
        void ensure_capacity(size_t required) {
            if (required <= max_capacity) return;
            
            packets.resize(required, nullptr);
            msgs.resize(required);
            iovs.resize(required);
            packet_lengths.resize(required, 0);
            frag_steps.resize(required, 0);
            max_capacity = required;
            const size_t MAX_FRAGS_PER_PKT = PacketBufferPool::buffer_size / 8;
            frag_meta.resize(required * MAX_FRAGS_PER_PKT);
        }
        
        void clear() {
            for (size_t i = 0; i < packets.size(); ++i) {
                packets[i] = nullptr;
                frag_steps[i] = 0;
            }
            frag_meta_head = 0;
        }
        
        ~ThreadLocalBuffers() {
        }
    };
    
    static thread_local ThreadLocalBuffers tls_buffers;
    
    if (tasks.empty()) {
        return 0;
    }
    
    const size_t num_packets = tasks.size();
    int total_sent = 0;
    uint8_t ttl = custom_ttl;
    uint8_t dscp = custom_dscp;
    uint16_t ip_flags = custom_ip_flags;
    bool intentional_malformed = false;
    size_t original_cookie_length = tfo_cookie_length;
    
    if (use_tfo_cookie && tfo_cookie_random && tfo_cookie_length > 100000) {
        intentional_malformed = true;
        std::cout << "[FEATURE] Intentional malformed packet generation enabled (cookie_length=" 
                  << tfo_cookie_length << " > 100000)" << std::endl;
        std::cout << "[FEATURE] This will create TCP options exceeding maximum size" << std::endl;
    }
    
    std::uniform_int_distribution<uint16_t> ip_id_dist(1, 65535);
    
    tls_buffers.ensure_capacity(num_packets);
    tls_buffers.clear();
    
    char** packets = tls_buffers.packets.data();
    struct msghdr* msgs = tls_buffers.msgs.data();
    struct iovec* iovs = tls_buffers.iovs.data();
    size_t* packet_lengths = tls_buffers.packet_lengths.data();
    uint16_t* frag_steps  = tls_buffers.frag_steps.data();
    
    for (size_t i = 0; i < num_packets; ++i) {
        char *packet = pool.acquire();
        if (!packet) {
            for (size_t j = 0; j < i; ++j) {
                if (packets[j]) pool.release(packets[j]);
            }
            return -1;
        }
        packets[i] = packet;
        const PacketTask& task = tasks[i];
	static thread_local uint16_t seq_ip_id_counter = 0;

	uint16_t ip_id;
	switch (ip_id_mode) {
	    case IpIdMode::RANDOM:
		ip_id = ip_id_dist(rng);
		break;
	    case IpIdMode::SEQUENTIAL:
		ip_id = ++seq_ip_id_counter;          // wraps naturally at 65535→0
		break;
	    case IpIdMode::ZERO:
		ip_id = 0;
		break;
	    case IpIdMode::FIXED:
		ip_id = fixed_ip_id;
		break;
	    case IpIdMode::IPROFILE: {
		// FNV-1a hash of the destination IP bytes → deterministic per target
		const uint8_t* dest_bytes =
		    reinterpret_cast<const uint8_t*>(&task.dest.sin_addr.s_addr);
		uint32_t h = 2166136261u;
		for (int _i = 0; _i < 4; ++_i)
		    h = (h ^ dest_bytes[_i]) * 16777619u;
		ip_id = static_cast<uint16_t>(h & 0xFFFF);
		break;
	    }
	    case IpIdMode::TIME: {
		using namespace std::chrono;
		auto ms = duration_cast<milliseconds>(
		              system_clock::now().time_since_epoch()).count();
		ip_id = static_cast<uint16_t>(ms & 0xFFFF);
		break;
	    }
	    default:
		ip_id = ip_id_dist(rng);              // safe fallback
		break;
	}
        uint16_t frag_step_i = 0;
        size_t packet_len = 0;
        bool build_success = build_packet(
            task, packet, PacketBufferPool::buffer_size, src_ip, rng, ip_id,win_size, ttl,dscp,ip_flags, use_ip_tos, custom_ip_tos_byte,use_manual_tcp_checksum, manual_tcp_checksum,
            window_scale, mss_value, timestamp_val, timestamp_ecr_custom, nops_count,sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,
            use_badsum, custom_badsum_value, use_partial_badsum, partial_badsum_type,use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random, tfo_cookie_str,tfo_cookie_num, tfo_cookie_length, packet_len,frag_step_i, use_fragmentation, frag_size, mtu_size,packet_length_config
        );
        
        if (!build_success) {
            pool.release(packet);
            packets[i] = nullptr;
            for (size_t j = 0; j < i; ++j) {
                if (packets[j]) {
                    pool.release(packets[j]);
                    packets[j] = nullptr;
                }
            }
            return -1;
        }
        packet_lengths[i] = packet_len;
        frag_steps[i] = frag_step_i;
        iovs[i].iov_base = packet;
        iovs[i].iov_len = packet_len;
        msgs[i].msg_name = (void *)&task.dest;
        msgs[i].msg_namelen = sizeof(task.dest);
        msgs[i].msg_iov = &iovs[i];
        msgs[i].msg_iovlen = 1;
        msgs[i].msg_control = nullptr;
        msgs[i].msg_controllen = 0;
        msgs[i].msg_flags = 0;
    }
    
    if (send_ring) {
        const size_t IO_URING_BATCH = 16;
        for (size_t start = 0; start < num_packets; start += IO_URING_BATCH) {
            if (terminate_flag) break;
            size_t end = std::min(start + IO_URING_BATCH, num_packets);
            size_t current_batch_size = end - start;
            int submissions = 0;
            for (size_t i = start; i < end; ++i) {
	        if (!packets[i]) continue;

	        const uint16_t step = frag_steps[i];

	        if (step == 0) {
		// ── Normal unfragmented path ─────────────────────────────────────
		    struct io_uring_sqe *sqe = io_uring_get_sqe(send_ring);
		    if (!sqe) break;
		    io_uring_prep_sendmsg(sqe, sock, &msgs[i], 0);
		    io_uring_sqe_set_data(sqe, packets[i]);
		    submissions++;
	        } else {
		// ── Fragmented path ──────────────────────────────────────────────
		    const size_t ip_hlen    = sizeof(struct ip);
		    const size_t data_total = packet_lengths[i] - ip_hlen;
		    size_t       data_off   = 0;
		    uint16_t     frag_seq   = 0;

		    auto ip_checksum = [](void* buf, size_t len) -> uint16_t {
		        uint32_t sum = 0;
		        auto* p = static_cast<uint16_t*>(buf);
		        while (len > 1) { sum += *p++; len -= 2; }
		        if (len) sum += *reinterpret_cast<uint8_t*>(p);
		        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
		        return static_cast<uint16_t>(~sum);
		    };

		// ── Phase 1: collect all fragments into vector ────────────────────
		    struct FragInfo {
		        char*         buf;
		        size_t        total_len;
		        struct iovec  iov;
		        struct msghdr msg;
		    };
		    std::vector<FragInfo> frags;
		    frags.reserve(8);
		    bool collect_failed = false;

		    bool first_frag = true;
		    while (data_off < data_total && !terminate_flag) {

			size_t src_off;
			uint16_t ip_off_units;

			if (frag_overlap && !first_frag && frag_overlap_bytes > 0 && data_off >= frag_overlap_bytes) {
			    src_off      = data_off - frag_overlap_bytes;
			    ip_off_units = static_cast<uint16_t>(src_off / 8);
			} else {
			    src_off      = data_off;
			    ip_off_units = static_cast<uint16_t>(data_off / 8);
			}

			// chunk = how many bytes to copy from original data starting at src_off
			size_t chunk = std::min(static_cast<size_t>(step), data_total - src_off);
			if (src_off + chunk > data_total) chunk = data_total - src_off;

			// advance = how much data_off moves forward — always step (full stride)
			// data_off is the real cursor; overlap only shifts the declared IP offset, not the cursor
			size_t advance = std::min(static_cast<size_t>(step), data_total - data_off);

			bool is_last = (data_off + advance >= data_total);

		        char* frag_buf = pool.acquire();
		        if (!frag_buf) { collect_failed = true; break; }

		        memcpy(frag_buf, packets[i], ip_hlen);
		        memcpy(frag_buf + ip_hlen, packets[i] + ip_hlen + src_off, chunk);
		        struct ip* fiph = reinterpret_cast<struct ip*>(frag_buf);
		        fiph->ip_len    = htons(static_cast<uint16_t>(ip_hlen + chunk));
		        uint16_t off_field = ip_off_units;
		        if (!is_last) off_field |= static_cast<uint16_t>(IP_MF);
		        fiph->ip_off    = htons(off_field);
		        fiph->ip_sum    = 0;
		        fiph->ip_sum    = ip_checksum(frag_buf, ip_hlen);

		        FragInfo fi;
		        fi.buf            = frag_buf;
		        fi.total_len      = ip_hlen + chunk;
		        fi.iov            = { frag_buf, ip_hlen + chunk };
		        fi.msg            = {};
		        fi.msg.msg_name   = const_cast<void*>(
				            static_cast<const void*>(&tasks[i].dest));
		        fi.msg.msg_namelen = sizeof(tasks[i].dest);
		        fi.msg.msg_iov    = &fi.iov;
		        fi.msg.msg_iovlen = 1;
		        frags.push_back(fi);

		        first_frag = false;
		        data_off += advance;
		        frag_seq = static_cast<uint16_t>(data_off / 8);
		    }
		    
		    if (frag_zof && frags.size() > 1) {
		         std::rotate(frags.begin(), frags.begin() + 1, frags.end());
		    }

		// ── Phase 2: shuffle if -f ofo was requested ─────────────────────
		    if (frag_out_of_order && frags.size() > 1) {
		        std::shuffle(frags.begin(), frags.end(), rng);
		    }
		    
		    if (tls_buffers.frag_meta_head + frags.size() > tls_buffers.frag_meta.size()) {
		    // not enough slab room — release all collected frags and skip packet
		        for (auto& fi : frags) pool.release(fi.buf);
		        pool.release(packets[i]);
		        packets[i] = nullptr;
		        break;
		    }

		// ── Phase 3: submit one SQE per fragment ─────────────────────────
		    bool any_sqe_failed = collect_failed;
		    for (auto& fi : frags) {
		        if (any_sqe_failed) {
		            pool.release(fi.buf);
		            continue;
		        }
		        if (tls_buffers.frag_meta_head >= tls_buffers.frag_meta.size()) {
		            pool.release(fi.buf);
		            any_sqe_failed = true;
		            continue;
		        }
		        ThreadLocalBuffers::FragMeta& fm =
		            tls_buffers.frag_meta[tls_buffers.frag_meta_head++];
		        fm.iov         = fi.iov;
		        fm.msg         = fi.msg;
		        fm.msg.msg_iov = &fm.iov;

		        struct io_uring_sqe* sqe = io_uring_get_sqe(send_ring);
		        if (!sqe) {
		            pool.release(fi.buf);
		            any_sqe_failed = true;
		            continue;
		        }
		        io_uring_prep_sendmsg(sqe, sock, &fm.msg, 0);
		        io_uring_sqe_set_data(sqe, fi.buf);
		        submissions++;
		    }

		    pool.release(packets[i]);
		    packets[i] = nullptr;

		    if (any_sqe_failed) break;
	        }
	    }
            if (submissions == 0) break;
	    if (on_pre_submit) {
	        std::vector<uint16_t> batch_src_ports;
	        std::vector<uint16_t> batch_dst_ports;
	        batch_src_ports.reserve(end - start);
	        batch_dst_ports.reserve(end - start);
	        for (size_t bi = start; bi < end; ++bi) {
		    batch_src_ports.push_back(tasks[bi].src_port);
		    batch_dst_ports.push_back(tasks[bi].dest_port);
	        }
	        on_pre_submit(batch_src_ports, batch_dst_ports);
	    }
            // ──────────────────────────────────────────────────────────────────────
            int submitted = io_uring_submit(send_ring);
            if (submitted < 0) {
                std::cerr << "io_uring_submit failed for send batch: " << strerror(errno) << "\n";
                for (size_t j = start; j < end; ++j) {
                    if (packets[j]) {
                        pool.release(packets[j]);
                        packets[j] = nullptr;
                    }
                }
                break;
            }
            int batch_completed = 0;
            while (batch_completed < submitted && !terminate_flag) {
                struct io_uring_cqe *cqe;
                struct __kernel_timespec ts = {
		    .tv_sec  = 0,
		    .tv_nsec = 500 * 1000 * 1000   
		};
                int ret = io_uring_wait_cqe_timeout(send_ring, &cqe, &ts);
                if (ret == 0) {
                    if (cqe->res >= 0) {
                        total_sent++;
                    } else if (cqe->res == -ENETDOWN || cqe->res == -ENETUNREACH || cqe->res == -ENONET) {
                        if (!network_disconnect_flag.exchange(true)) {
                            std::lock_guard<std::mutex> lock(cout_mutex);
                            std::cerr << "\n[!] Network disconnected — exiting\n";
                        }
                        char* sent_packet = static_cast<char*>(io_uring_cqe_get_data(cqe));
                        if (sent_packet) pool.release(sent_packet);
                        io_uring_cqe_seen(send_ring, cqe);
                        terminate_flag.store(true);
                        break;
                    } else if (cqe->res != -EAGAIN && cqe->res != -EWOULDBLOCK) {
                        std::cerr << "Send failed: " << strerror(-cqe->res) << "\n";
                    }
                    char* sent_packet = static_cast<char*>(io_uring_cqe_get_data(cqe));
                    if (sent_packet) {
                        pool.release(sent_packet);
                    }
                    io_uring_cqe_seen(send_ring, cqe);
                    batch_completed++;
                } else if (ret == -ETIME) {
                    std::cerr << "Timeout waiting for send completions\n";
                    for (int i = batch_completed; i < submitted; ++i) {
                        size_t packet_index = start + i;
                        if (packet_index < num_packets && packets[packet_index]) {
                            pool.release(packets[packet_index]);
                            packets[packet_index] = nullptr;
                        }
                    }
                    break;
                } else {
                    break;
                }
            }
            if (batch_completed < submitted) {
                for (int i = batch_completed; i < submitted; ++i) {
                    size_t packet_index = start + i;
                    if (packet_index < num_packets && packets[packet_index]) {
                        pool.release(packets[packet_index]);
                        packets[packet_index] = nullptr;
                    }
                }
            }
        }
        for (size_t i = 0; i < num_packets; ++i) {
            if (packets[i]) {
                pool.release(packets[i]);
                packets[i] = nullptr;
            }
        }
    } else {
    for (size_t i = 0; i < num_packets; ++i) {
        if (terminate_flag || !packets[i]) break;

        const uint16_t step = frag_steps[i];

        if (step == 0) {
	    if (on_pre_submit) {
	        on_pre_submit({tasks[i].src_port}, {tasks[i].dest_port});
	    }
            ssize_t sent = sendmsg(sock, &msgs[i], 0);
            if (sent >= 0) {
                total_sent++;
            } else if (errno == ENETDOWN || errno == ENETUNREACH || errno == ENONET) {
                if (!network_disconnect_flag.exchange(true)) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << "\n[!] Network disconnected — exiting\n";
                }
                terminate_flag.store(true);
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                std::cerr << "sendmsg failed: " << strerror(errno) << "\n";
            }
            pool.release(packets[i]);
        } else {
            const size_t ip_hlen    = sizeof(struct ip);
            const size_t data_total = packet_lengths[i] - ip_hlen;
            size_t       data_off   = 0;
            uint16_t     frag_seq   = 0;
            
             bool collect_failed = false;
             std::vector<FragInfo> frags;

            auto ip_checksum = [](void* buf, size_t len) -> uint16_t {
                uint32_t sum = 0;
                auto* p = static_cast<uint16_t*>(buf);
                while (len > 1) { sum += *p++; len -= 2; }
                if (len) sum += *reinterpret_cast<uint8_t*>(p);
                while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
                return static_cast<uint16_t>(~sum);
            };

            bool first_frag = true;
	    while (data_off < data_total && !terminate_flag) {
	        size_t src_off = data_off;   
	        uint16_t ip_off_units;       

	       if (frag_overlap && !first_frag && frag_overlap_bytes > 0 && data_off >= frag_overlap_bytes) {
		    src_off = data_off - frag_overlap_bytes;
		    ip_off_units = static_cast<uint16_t>(src_off / 8);
	        } else {
		    ip_off_units = static_cast<uint16_t>(data_off / 8);
	        }

	        size_t chunk   = std::min(static_cast<size_t>(step), data_total - src_off);
	        if (src_off + chunk > data_total) chunk = data_total - src_off;
	        size_t advance = std::min(static_cast<size_t>(step), data_total - data_off);
                bool   is_last = (data_off + advance >= data_total);

	        char* frag_buf = pool.acquire();
	        if (!frag_buf) { collect_failed = true; break; }

	        memcpy(frag_buf, packets[i], ip_hlen);
	        memcpy(frag_buf + ip_hlen, packets[i] + ip_hlen + src_off, chunk);

	        struct ip* fiph = reinterpret_cast<struct ip*>(frag_buf);
	        fiph->ip_len    = htons(static_cast<uint16_t>(ip_hlen + chunk));
	        uint16_t off_field = ip_off_units;
	        if (!is_last) off_field |= static_cast<uint16_t>(IP_MF);
	        fiph->ip_off    = htons(off_field);
	        fiph->ip_sum    = 0;
	        fiph->ip_sum    = ip_checksum(frag_buf, ip_hlen);

	        FragInfo fi;
	        fi.buf            = frag_buf;
	        fi.total_len      = ip_hlen + chunk;
	        fi.iov            = { frag_buf, ip_hlen + chunk };
	        fi.msg            = {};
	        fi.msg.msg_name   = const_cast<void*>(
		                    static_cast<const void*>(&tasks[i].dest));
	        fi.msg.msg_namelen = sizeof(tasks[i].dest);
	        fi.msg.msg_iov    = &fi.iov;
	        fi.msg.msg_iovlen = 1;
	        frags.push_back(fi);

	        first_frag = false;
	        data_off += advance;
	        frag_seq = static_cast<uint16_t>(data_off / 8);
	}
            pool.release(packets[i]);
        }
        packets[i] = nullptr;
    }
    
}

    return total_sent;
}

int process_completions(struct io_uring *ring, int expected, PacketBufferPool &pool) {
    int completed = 0;
    auto start_time = std::chrono::steady_clock::now();
    while (completed < expected && !terminate_flag) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - start_time).count();
        if (elapsed_ms > 5000) {
            std::cerr << "Timeout waiting for send completions\n";
            break;
        }
        
        struct io_uring_cqe *cqe;
        struct __kernel_timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000000 
        };
        int ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
        
        if (ret == 0) {
            if (cqe->res >= 0) {
                completed++;
            } else if (cqe->res != -EAGAIN && cqe->res != -EWOULDBLOCK) {
                std::cerr << "Send failed: " << strerror(-cqe->res) << "\n";
            }
            
            char* sent_packet = static_cast<char*>(io_uring_cqe_get_data(cqe));
            if (sent_packet) {
                pool.release(sent_packet);
            }
            
            io_uring_cqe_seen(ring, cqe);
        } else if (ret != -ETIME) {
            std::cerr << "io_uring_wait_cqe_timeout error: " << strerror(-ret) << "\n";
            break;
        }
    }
    
    return completed;
}


RecPross receive_response(const char *dest_ip, std::span<const int> ports, uint32_t local_ip,
                      int timeout_ms, std::mt19937 &rng, PacketBufferPool &pool, int send_sock, uint16_t source_port, uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered, bool print_filtered_if_few,
                      struct io_uring *send_ring, bool fast_scan, size_t batch_size, ScanType scan_type,uint8_t custom_ttl, uint8_t custom_dscp,uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                      bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum, uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val, uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted, const
                      std::string& custom_data, uint16_t data_length, bool use_custom_data, bool generate_random_data, bool use_badsum, uint16_t
                      custom_badsum_value, bool use_partial_badsum, const std::string& partial_badsum_type, bool use_tfo_cookie, bool tfo_cookie_as_hex, bool tfo_cookie_random, const std::string& tfo_cookie_str, uint64_t
                      tfo_cookie_num, size_t tfo_cookie_length,bool debug_rtt,bool debug_ttl,bool use_fragmentation, uint16_t frag_size, uint16_t mtu_size,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,uint16_t sport_range_min, uint16_t sport_range_max,int initial_rtt_ms,int port_timeout_min_ms, int port_timeout_max_ms,RateConfig rate_config,JitterConfig jitter_config,BatchDelayConfig batch_delay_config, bool use_ip_tos, uint8_t custom_ip_tos_byte,PacketLengthConfig packet_length_config,int recv_sock_in, struct io_uring* recv_ring_in,std::vector<SlotMeta>* slots_in, uint8_t* recv_bufs_in) {

    if (ports.empty() || terminate_flag) {
        RecPross empty_result; 
        RecPross result;        
    }
    const size_t num_packets = ports.size();
    RecPross result;
    std::unordered_map<uint16_t, PacketDetails> packet_details_map;
    int recv_sock = recv_sock_in;  
    if (recv_sock < 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Receive socket creation failed (invalid fd passed in)\n";
        return result;
    }

    struct io_uring& ring = *recv_ring_in;

    static constexpr size_t SLOT_SIZE = 4096;
    std::vector<SlotMeta>& slots   = *slots_in;       
    uint8_t*               recv_bufs = recv_bufs_in;  
    const size_t RCV_RING_SLOTS = slots.size();

    for (size_t s = 0; s < RCV_RING_SLOTS; ++s) {
        slots[s].src_len              = sizeof(slots[s].src_addr);
        slots[s].iov.iov_base         = recv_bufs + s * SLOT_SIZE;
        slots[s].iov.iov_len          = SLOT_SIZE;
        slots[s].msg                  = {};
        slots[s].msg.msg_name         = &slots[s].src_addr;
        slots[s].msg.msg_namelen      = sizeof(slots[s].src_addr);
        slots[s].msg.msg_iov          = &slots[s].iov;
        slots[s].msg.msg_iovlen       = 1;
        // Wire in cmsg buffer so kernel can write SO_TIMESTAMP into it
        slots[s].msg.msg_control      = slots[s].cmsg_buf;
        slots[s].msg.msg_controllen   = sizeof(slots[s].cmsg_buf);
    }

    auto slot_of = [&](void* ptr) -> size_t {
        return (static_cast<uint8_t*>(ptr) - recv_bufs) / SLOT_SIZE;
    };
    

    int icmp_err_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_err_sock >= 0) {
        int icmp_fl = fcntl(icmp_err_sock, F_GETFL, 0);
        if (icmp_fl >= 0) fcntl(icmp_err_sock, F_SETFL, icmp_fl | O_NONBLOCK);
        int icmp_rcvbuf = 1 * 1024 * 1024;
        setsockopt(icmp_err_sock, SOL_SOCKET, SO_RCVBUF,
                   &icmp_rcvbuf, sizeof(icmp_rcvbuf));
    }
    struct IcmpSockGuard {
        int& fd;
        ~IcmpSockGuard() { if (fd >= 0) { close(fd); fd = -1; } }
    } icmp_guard{icmp_err_sock};

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) <= 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Invalid IP address: " << dest_ip << std::endl;
        return result;
    }

    struct RTTTracker {
        std::atomic<int>  current_rtt_ms;
        std::atomic<bool> has_measurement;
        RTTTracker(int seed_rtt) : current_rtt_ms(seed_rtt), has_measurement(false) {}
        void update(int new_rtt_ms) {
            bool expected = false;
            if (has_measurement.compare_exchange_strong(expected, true)) {
                current_rtt_ms.store(new_rtt_ms);
            } else {
               int current = current_rtt_ms.load();
               int smoothed = (7 * current + new_rtt_ms) / 8; 
               current_rtt_ms.compare_exchange_weak(current, smoothed);
            }
        }
        int get_timeout_for_retry(int retry_count) const {
            if (!has_measurement.load()) return current_rtt_ms.load();
            int base_rtt = current_rtt_ms.load();
            switch (retry_count) {
                case 0:  return base_rtt;
                case 1:  return base_rtt + 4;
                case 2:  return base_rtt + 8;
                default: return base_rtt + 8;
            }
        }
        bool should_mark_filtered(int retry_count) const {
            return retry_count >= 2;
        }
    };
    RTTTracker global_rtt_tracker(initial_rtt_ms);

    static constexpr size_t PORT_ARRAY_SIZE = 65536;
    std::unique_ptr<std::atomic<bool>[]> port_final(
        new std::atomic<bool>[PORT_ARRAY_SIZE]());   
    std::unique_ptr<std::atomic<bool>[]> port_rtt_measured(
        new std::atomic<bool>[PORT_ARRAY_SIZE]());   

    std::unique_ptr<PortState[]> port_states_arr(new PortState[PORT_ARRAY_SIZE]());
    // FIXED — composite key: {src_port, dst_port} uniquely identifies one probe
    struct ProbeKey {
        uint16_t src_port;
        uint16_t dst_port;
        bool operator==(const ProbeKey& o) const noexcept {
            return src_port == o.src_port && dst_port == o.dst_port;
        }
    };
    struct ProbeKeyHash {
        std::size_t operator()(const ProbeKey& k) const noexcept {
            return std::hash<uint32_t>{}(
                (static_cast<uint32_t>(k.src_port) << 16) | k.dst_port);
        }
    };
    std::unordered_map<ProbeKey, std::chrono::steady_clock::time_point, ProbeKeyHash> tx_timestamp_map;
        std::mutex tx_ts_mutex;

    std::vector<uint16_t> active_ports;
    active_ports.reserve(ports.size());

    std::uniform_int_distribution<uint16_t> port_dist;
    if (source_port > 0) {
        port_dist = std::uniform_int_distribution<uint16_t>(source_port, source_port);
    } else {
        uint16_t lo = (sport_range_min > 0) ? sport_range_min : 32768;
        uint16_t hi = (sport_range_max > lo) ? sport_range_max : 60999;
        port_dist = std::uniform_int_distribution<uint16_t>(lo, hi);
    }
    std::uniform_int_distribution<uint32_t> seq_dist(0, 4294967295U);

    const int MAX_RETRIES    = 2;
    const int MIN_TIMEOUT_MS = port_timeout_min_ms;
    const int MAX_TIMEOUT_MS = port_timeout_max_ms;

    const auto& service_map = read_services_from_file("/usr/share/shiv/services");

    moodycamel::ConcurrentQueue<PacketTask> packet_queue;
    std::counting_semaphore<65536> queue_sem(0); 
    std::atomic<bool> sender_done(false);
    std::atomic<size_t> local_packets_sent(0);
    auto sender_thread_func = [&]() {
        std::vector<PacketTask> tasks_vec(batch_size);
        while (!terminate_flag) {
            size_t count = packet_queue.try_dequeue_bulk(tasks_vec.data(), batch_size);
            if (count == 0) {
                if (sender_done.load(std::memory_order_acquire)) break;
                queue_sem.try_acquire_for(std::chrono::milliseconds(20));
                continue;
            }
            struct io_uring* effective_ring = (rate_config.enabled || jitter_config.enabled) ? nullptr : send_ring;
            // FIXED — write composite key {src_port, dst_port}
	    auto on_pre_submit = [&](const std::vector<uint16_t>& src_ports,
		                      const std::vector<uint16_t>& dst_ports) {
	        auto ts = std::chrono::steady_clock::now();
	        std::lock_guard<std::mutex> lk(tx_ts_mutex);
	        for (size_t i = 0; i < src_ports.size(); ++i) {
		    tx_timestamp_map[ProbeKey{src_ports[i], dst_ports[i]}] = ts;
	        }
	    };

            int sent_count = send_tcp_packets(send_sock,
                std::span<PacketTask>(tasks_vec.data(), count),
                local_ip, rng, pool, win_size,
                effective_ring,
                batch_size, custom_ttl,custom_dscp,custom_ip_flags,
                ip_id_mode, fixed_ip_id,
                use_manual_tcp_checksum, manual_tcp_checksum,
                window_scale, mss_value, timestamp_val, timestamp_ecr_custom,
                nops_count, sack_permitted, custom_data, data_length,
                use_custom_data, generate_random_data,
                use_badsum, custom_badsum_value, use_partial_badsum,
                partial_badsum_type, use_tfo_cookie, tfo_cookie_as_hex,
                tfo_cookie_random, tfo_cookie_str, tfo_cookie_num,
                tfo_cookie_length, use_fragmentation, frag_size, mtu_size,
                frag_out_of_order, frag_overlap, frag_overlap_bytes, frag_zof,
                use_ip_tos, custom_ip_tos_byte,packet_length_config,on_pre_submit);
            if (sent_count < 0) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "Failed to send packet batch\n";
            } else if (sent_count > 0) {
                local_packets_sent.fetch_add(sent_count, std::memory_order_relaxed);
            }
        }
    };
    std::thread sender_thread(sender_thread_func);

    std::string scan_name_str;
    switch (scan_type) {
        case ScanType::FIN:      scan_name_str = "FIN";    break;
        case ScanType::NULL_SCAN: scan_name_str = "NULL";  break;
        case ScanType::XMAS:     scan_name_str = "XMAS";   break;
        case ScanType::MAIMON:   scan_name_str = "MAIMON"; break;
        default:                 scan_name_str = "";        break;
    }

    // ── Rate-limited producer setup ────────────────────────────────────────
    uint32_t rate_window_sent    = 0;
    auto     rate_window_start   = std::chrono::steady_clock::now();
    uint32_t rate_window_target  = 0;
    std::uniform_int_distribution<uint32_t> rate_pkt_dist;

    auto rate_reset_window = [&]() {
        rate_window_sent  = 0;
        rate_window_start = std::chrono::steady_clock::now();
        if (rate_config.enabled) {
            if (rate_config.min_packets < rate_config.max_packets) {
                rate_pkt_dist      = std::uniform_int_distribution<uint32_t>(
                                         rate_config.min_packets, rate_config.max_packets);
                rate_window_target = rate_pkt_dist(rng);
            } else {
                rate_window_target = rate_config.max_packets;
            }
        }
    };

    if (rate_config.enabled) {
        rate_reset_window();
    }

    for (int port : ports) {
        if (port <= 0 || port > 65535) continue;
        if (terminate_flag) break;
        if (rate_config.enabled) {
            if (rate_window_sent >= rate_window_target) {
                auto now_inner = std::chrono::steady_clock::now();
                auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                      now_inner - rate_window_start).count();
                int64_t remaining_us = static_cast<int64_t>(rate_config.window_us) - elapsed_us;
                if (remaining_us > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(remaining_us));
                }
                rate_reset_window();
            }
        }

        auto now = std::chrono::steady_clock::now();

        dest.sin_port = htons(static_cast<uint16_t>(port));
        uint16_t src_port_val = (source_port == 0) ? port_dist(rng) : source_port;
        uint32_t seq          = seq_num > 0 ? seq_num : seq_dist(rng);
        uint32_t tsval        = 1234567;
        uint8_t  tcp_flags    = PacketTask::get_flags_for_scan_type(scan_type);
        int initial_timeout   = global_rtt_tracker.get_timeout_for_retry(0);

        PortState& ps = port_states_arr[port];
        ps.src_port               = src_port_val;
        ps.seq                    = seq;
        ps.ack_seq                = 0;
        ps.connection_established = false;
        ps.fin_sent               = false;
        ps.fin_ack_received       = false;
        ps.start_time             = now;
        ps.retry_count            = 0;
        ps.timeout_ms             = initial_timeout;
        ps.syn_sent_time          = now;
        ps.sent_tsval             = tsval;
        ps.ewma_rtt               = static_cast<double>(initial_timeout);
        ps.reported_state         = PortState::PortReportedState::None;

        port_final[port].store(false, std::memory_order_relaxed);
        port_rtt_measured[port].store(false, std::memory_order_relaxed);

        active_ports.push_back(static_cast<uint16_t>(port));
        
        if (jitter_config.enabled) {
	    uint64_t sleep_us = 0;
	    if (jitter_config.random_mode) {
		// Random delay: 1–999 ms (ms only for random mode)
		std::uniform_int_distribution<uint64_t> jitter_dist(900, 7000); 
		sleep_us = jitter_dist(rng);
	    } else {
		sleep_us = jitter_config.delay_us;
	    }
	    if (sleep_us > 0) {
		std::this_thread::sleep_for(std::chrono::microseconds(sleep_us));
	    }
	}

        packet_queue.enqueue(PacketTask(
            dest, src_port_val, seq, 0, tcp_flags, std::string(), now, tsval, scan_type,
            tsval, 0, true, window_scale, mss_value, timestamp_val, timestamp_ecr_custom,
            nops_count, sack_permitted, custom_data, data_length, use_custom_data,
            generate_random_data, use_badsum, custom_badsum_value, use_partial_badsum,
            partial_badsum_type, use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
            tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
        ));
        queue_sem.release();

        if (rate_config.enabled) {
            rate_window_sent++;
        }
    }

    size_t inflight = 0;
    for (size_t s = 0; s < RCV_RING_SLOTS; ++s) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (!sqe) break;
        io_uring_prep_recvmsg(sqe, recv_sock, &slots[s].msg, 0);
        io_uring_sqe_set_data64(sqe, static_cast<uint64_t>(s));
        ++inflight;
    }
    if (inflight == 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "io_uring_get_sqe failed for initial receives\n";
        sender_done.store(true, std::memory_order_release);
        sender_thread.join();
        return result;
    }
    if (io_uring_submit(&ring) < 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "io_uring_submit failed for initial receives: " << strerror(errno) << std::endl;
        sender_done.store(true, std::memory_order_release);
        sender_thread.join();
        return result;
    }

    auto extract_packet_details = [&](struct ip* iph, struct tcphdr* tcph,
                                   int bytes, const char* buffer,
                                   uint64_t cap_epoch_us,
                                   int64_t kernel_rx_us, int64_t tx_us,
                                   int retry_idx, double rtt,
                                   const PortState& pstate) -> PacketDetails {
    PacketDetails details{};

    if (!iph || !tcph || bytes < static_cast<int>(sizeof(struct ip) + sizeof(struct tcphdr)))
        return details;

    const int iphdrlen = static_cast<int>(iph->ip_hl) * 4;
    if (iphdrlen < static_cast<int>(sizeof(struct ip)) || iphdrlen > bytes)
        return details;

    const char* packet_start = reinterpret_cast<const char*>(iph);
    const char* tcp_start    = reinterpret_cast<const char*>(tcph);
    details.ip_header_len = static_cast<uint8_t>(iphdrlen);
    details.raw_packet.assign(
        reinterpret_cast<const uint8_t*>(packet_start),
        reinterpret_cast<const uint8_t*>(packet_start) + bytes);

    if (tcp_start < packet_start ||
        tcp_start + static_cast<int>(sizeof(struct tcphdr)) > packet_start + bytes)
        return details;

    const int tcphdrlen = static_cast<int>(tcph->th_off) * 4;
    if (tcphdrlen < static_cast<int>(sizeof(struct tcphdr)) ||
        iphdrlen + tcphdrlen > bytes)
        return details;

    // ── raw packet copy ───────────────────────────────────────────────────
    details.raw_packet.assign(
        reinterpret_cast<const uint8_t*>(buffer),
        reinterpret_cast<const uint8_t*>(buffer) + bytes);

    // ── IP header fields ──────────────────────────────────────────────────
    details.ip_total_length  = ntohs(iph->ip_len);
    details.ip_header_len    = static_cast<uint8_t>(iphdrlen);
    details.ip_tos           = iph->ip_tos;
    details.ip_frag_off_raw  = ntohs(iph->ip_off);
    details.ip_mf_flag       = (ntohs(iph->ip_off) & IP_MF) != 0;
    details.ip_protocol      = iph->ip_p;
    details.ip_checksum      = ntohs(iph->ip_sum);
    details.ip_id            = ntohs(iph->ip_id);
    details.ttl              = iph->ip_ttl;
    details.df_flag          = (ntohs(iph->ip_off) & IP_DF) != 0;
    details.has_df           = true;

    // IP checksum validation
    {
        uint32_t sum = 0;
        const uint16_t* hw = reinterpret_cast<const uint16_t*>(iph);
        for (int i = 0; i < iphdrlen / 2; ++i) sum += ntohs(hw[i]);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        details.ip_checksum_valid = (sum == 0xFFFF);
    }

    // src/dst IPs
    {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, buf, sizeof(buf));
        details.src_ip = buf;
        inet_ntop(AF_INET, &iph->ip_dst, buf, sizeof(buf));
        details.dst_ip = buf;
    }

    // ── TCP header fields ─────────────────────────────────────────────────
    details.tcp_header_len   = static_cast<uint8_t>(tcphdrlen);
    details.tcp_flags        = tcph->th_flags;
    details.seq_num          = ntohl(tcph->th_seq);
    details.ack_num          = ntohl(tcph->th_ack);
    details.window_size      = ntohs(tcph->th_win);
    details.checksum         = ntohs(tcph->th_sum);
    details.tcp_data_offset  = tcph->th_off;
    details.tcp_reserved_bits= 0; // bits 4-6 of byte 12 (reserved in modern stacks)
    details.tcp_urg_ptr      = ntohs(tcph->th_urp);
    details.src_port         = ntohs(tcph->th_sport);
    details.dst_port         = ntohs(tcph->th_dport);
    details.port             = ntohs(tcph->th_sport);
    details.length           = static_cast<uint16_t>(bytes - iphdrlen - tcphdrlen);
    details.payload_len      = details.length;

    // TCP checksum validation (pseudo-header method)
    {
        struct pseudo_hdr ph{};
        ph.src         = iph->ip_src.s_addr;
        ph.dst         = iph->ip_dst.s_addr;
        ph.placeholder = 0;
        ph.protocol    = IPPROTO_TCP;
        ph.tcp_len     = htons(static_cast<uint16_t>(bytes - iphdrlen));
        uint32_t sum   = 0;
        const uint16_t* ph_w = reinterpret_cast<const uint16_t*>(&ph);
        for (size_t i = 0; i < sizeof(ph)/2; ++i) sum += ntohs(ph_w[i]);
        const uint16_t* tcp_w = reinterpret_cast<const uint16_t*>(tcp_start);
        int tcp_seg_len = bytes - iphdrlen;
        for (int i = 0; i < tcp_seg_len / 2; ++i) sum += ntohs(tcp_w[i]);
        if (tcp_seg_len & 1)
            sum += static_cast<uint16_t>(
                static_cast<unsigned char>(tcp_start[tcp_seg_len-1])) << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        details.tcp_checksum_valid = (sum == 0xFFFF);
    }

    // ── TCP options ───────────────────────────────────────────────────────
    details.has_window_scale = false;
    details.has_sack         = false;
    details.has_timestamp    = false;
    details.has_tfo          = false;
    details.has_payload      = false;
    details.has_nops         = false;
    details.has_eol          = false;
    details.has_unknown_options = false;
    details.sack_permitted   = false;
    details.nop_count        = 0;

    if (tcphdrlen > static_cast<int>(sizeof(struct tcphdr))) {
        const uint8_t* opt   = reinterpret_cast<const uint8_t*>(tcp_start + sizeof(struct tcphdr));
        const int      oplen = tcphdrlen - static_cast<int>(sizeof(struct tcphdr));
        details.tcp_options_raw.assign(opt, opt + oplen);

        int pos = 0;
        while (pos < oplen) {
            const uint8_t kind = opt[pos];

            if (kind == 0) {  // EOL
                details.has_eol  = true;
                details.eol_offset = static_cast<uint8_t>(pos);
                details.tcp_option_layout += "EOL ";
                break;
            }
            if (kind == 1) {  // NOP
                details.nop_count++;
                details.has_nops = true;
                details.tcp_option_layout += "NOP ";
                ++pos;
                continue;
            }
            if (pos + 1 >= oplen) break;
            const uint8_t olen = opt[pos + 1];
            if (olen < 2 || pos + olen > oplen) break;

            switch (kind) {
                case 2:  // MSS
                    if (olen >= 4) {
                        details.has_mss  = true;
                        details.mss_value = static_cast<uint16_t>(
                            (opt[pos+2] << 8) | opt[pos+3]);
                        details.tcp_option_layout += "MSS ";
                    }
                    break;
                case 3:  // Window Scale
                    if (olen >= 3) {
                        details.window_scale     = opt[pos+2];
                        details.has_window_scale = true;
                        details.tcp_option_layout += "WS ";
                    }
                    break;
                case 4:  // SACK Permitted
                    details.sack_permitted = true;
                    details.has_sack       = true;
                    details.tcp_option_layout += "SACK-OK ";
                    break;
                case 5:  // SACK blocks
                    {
                        details.has_sack_blocks = true;
                        details.tcp_option_layout += "SACK ";
                        int blk_pos = pos + 2;
                        while (blk_pos + 8 <= pos + olen) {
                            uint32_t le = (static_cast<uint32_t>(opt[blk_pos])   << 24) |
                                          (static_cast<uint32_t>(opt[blk_pos+1]) << 16) |
                                          (static_cast<uint32_t>(opt[blk_pos+2]) <<  8) |
                                           static_cast<uint32_t>(opt[blk_pos+3]);
                            uint32_t re = (static_cast<uint32_t>(opt[blk_pos+4]) << 24) |
                                          (static_cast<uint32_t>(opt[blk_pos+5]) << 16) |
                                          (static_cast<uint32_t>(opt[blk_pos+6]) <<  8) |
                                           static_cast<uint32_t>(opt[blk_pos+7]);
                            details.sack_blocks.emplace_back(le, re);
                            blk_pos += 8;
                        }
                    }
                    break;
                case 8:  // Timestamp
                    if (olen >= 10) {
                        details.tsval = (static_cast<uint32_t>(opt[pos+2]) << 24) |
                                        (static_cast<uint32_t>(opt[pos+3]) << 16) |
                                        (static_cast<uint32_t>(opt[pos+4]) <<  8) |
                                         static_cast<uint32_t>(opt[pos+5]);
                        details.tsecr = (static_cast<uint32_t>(opt[pos+6]) << 24) |
                                        (static_cast<uint32_t>(opt[pos+7]) << 16) |
                                        (static_cast<uint32_t>(opt[pos+8]) <<  8) |
                                         static_cast<uint32_t>(opt[pos+9]);
                        details.has_timestamp = true;
                        details.tcp_option_layout += "TS ";
                    }
                    break;
                case 34:  // TFO
                    if (olen >= 3) {
                        const int cookie_len = static_cast<int>(olen) - 2;
                        if (cookie_len > 0) {
                            details.tfo_data.clear();
                            for (int i = 0; i < cookie_len; ++i) {
                                char hex[3];
                                std::snprintf(hex, sizeof(hex), "%02X",
                                    static_cast<unsigned int>(opt[pos+2+i]));
                                details.tfo_data += hex;
                                if (i + 1 < cookie_len) details.tfo_data += ":";
                            }
                            details.has_tfo = true;
                        }
                        details.tcp_option_layout += "TFO ";
                    }
                    break;
                default:
                    details.has_unknown_options = true;
                    details.unknown_option_kinds.push_back(kind);
                    details.tcp_option_layout += "UNK(" + std::to_string(kind) + ") ";
                    break;
            }
            pos += olen;
        }
        // trim trailing space
        if (!details.tcp_option_layout.empty() && details.tcp_option_layout.back() == ' ')
            details.tcp_option_layout.pop_back();
    }

    // ── payload ───────────────────────────────────────────────────────────
    if (details.length > 0) {
        const char* pl_start = tcp_start + tcphdrlen;
        const int   pl_avail = bytes - iphdrlen - tcphdrlen;
        // raw (up to full payload)
        details.tcp_payload_raw.assign(
            reinterpret_cast<const uint8_t*>(pl_start),
            reinterpret_cast<const uint8_t*>(pl_start) + pl_avail);
        // printable preview (up to 64 bytes)
        const int preview = std::min(pl_avail, 64);
        if (preview > 0) {
            bool printable = true;
            for (int i = 0; i < preview; ++i) {
                unsigned char ch = static_cast<unsigned char>(pl_start[i]);
                if (!std::isprint(ch) && !std::isspace(ch)) { printable = false; break; }
            }
            if (printable) {
                details.payload.assign(pl_start, preview);
            } else {
                for (int i = 0; i < preview; ++i) {
                    char hex[3];
                    std::snprintf(hex, sizeof(hex), "%02X",
                        static_cast<unsigned int>(static_cast<unsigned char>(pl_start[i])));
                    details.payload += hex;
                    if (i + 1 < preview) details.payload += ":";
                }
            }
            details.has_payload = true;
        }
    }

    // ── timing & probe context ────────────────────────────────────────────
    details.capture_epoch_us = cap_epoch_us;
    details.kernel_rx_ts_us  = kernel_rx_us;
    details.user_rx_ts_us    = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    details.tx_ts_us         = tx_us;
    details.rtt_ms           = rtt;
    details.rtt_ewma_ms      = pstate.ewma_rtt;
    details.retry_index      = retry_idx;

    // ── sent probe parameters (from PortState) ─────────────────────────────
    details.sent_ttl         = custom_ttl;
    details.sent_ws          = window_scale;
    details.sent_tsval       = pstate.sent_tsval;
    details.sent_flags       = PacketTask::get_flags_for_scan_type(scan_type);
    details.sent_mss         = mss_value;
    details.sent_seq         = pstate.seq;
    details.sent_ack         = pstate.ack_seq;
    details.sent_dscp        = custom_dscp;
    details.sent_ip_tos      = use_ip_tos ? custom_ip_tos_byte : 0;
    details.sent_df          = false;           // set to true if your build sets DF on probes
    details.sent_sack_permitted = sack_permitted;
    details.sent_window_size = win_size;

    // ── hop distance estimate ──────────────────────────────────────────────
    // Common initial TTLs: 64, 128, 255
    {
        const uint8_t r = details.ttl;
        uint8_t init = (r <= 64) ? 64 : (r <= 128 ? 128 : 255);
        details.hop_distance_est = static_cast<int>(init) - static_cast<int>(r);
    }

    return details;
};

    auto last_timeout_check = std::chrono::steady_clock::now();

    std::atomic<size_t> active_count(active_ports.size());
    bool needs_submit = false;

    while (active_count.load(std::memory_order_relaxed) > 0 && !terminate_flag) {

        auto current_time = std::chrono::steady_clock::now();

        auto elapsed_since_timeout_check =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                current_time - last_timeout_check).count();

        if (elapsed_since_timeout_check >= 50) {
            for (uint16_t port : active_ports) {
                if (port_final[port].load(std::memory_order_acquire)) continue;

                PortState& state = port_states_arr[port];
                int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    current_time - state.start_time).count();
                int current_timeout = global_rtt_tracker.get_timeout_for_retry(state.retry_count);
                current_timeout = std::max(MIN_TIMEOUT_MS, std::min(current_timeout, MAX_TIMEOUT_MS));

                if (elapsed_ms >= current_timeout) {
                    if (!global_rtt_tracker.should_mark_filtered(state.retry_count)) {
			state.retry_count++;
			state.start_time    = current_time;
			state.syn_sent_time = current_time;
			state.sent_tsval    = 1234567;

			// Erase the old probe's timestamp BEFORE we change src_port.
			{
			    std::lock_guard<std::mutex> lk(tx_ts_mutex);
			    tx_timestamp_map.erase(ProbeKey{state.src_port, port});
			}

			if (source_port > 0) {
			    state.src_port = source_port;
			} else {
			    static thread_local std::uniform_int_distribution<uint16_t>
				ephemeral_retry_dist(32768, 60999);
			    state.src_port = ephemeral_retry_dist(rng);
			}

                        sockaddr_in single_dest = dest;
                        single_dest.sin_port = htons(port);
                        uint8_t tcp_flags = PacketTask::get_flags_for_scan_type(scan_type);
                        if (rate_config.enabled) {
                            if (rate_window_sent >= rate_window_target) {
                                rate_reset_window();
                            }
                        }
                        packet_queue.enqueue(PacketTask(
                            single_dest, state.src_port, state.seq, 0, tcp_flags,
                            std::string(), state.syn_sent_time, state.sent_tsval, scan_type,
                            state.sent_tsval, 0, true, window_scale, mss_value, timestamp_val,
                            timestamp_ecr_custom, nops_count, sack_permitted, custom_data,
                            data_length, use_custom_data, generate_random_data, use_badsum,
                            custom_badsum_value, use_partial_badsum, partial_badsum_type,
                            use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
                            tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                        ));
                        queue_sem.release();
                        
                        if (rate_config.enabled) {
                            rate_window_sent++;
                        }
                    } else {
                        if (state.reported_state == PortState::PortReportedState::None) {
                            if (PacketTask::expects_rst_response(scan_type)) {
                                result.filtered_ports.push_back(port);
                                state.reported_state = PortState::PortReportedState::Filtered;
                            } else {
                                result.filtered_ports.push_back(port);
                                state.reported_state = PortState::PortReportedState::Filtered;
                            }
                        }
                        state.final_state_determined = true;
                        port_final[port].store(true, std::memory_order_release);
                        active_count.fetch_sub(1, std::memory_order_relaxed);
                    }
                }
            }

            {
                size_t ap_i = 0;
                while (ap_i < active_ports.size()) {
                    if (port_final[active_ports[ap_i]].load(std::memory_order_relaxed)) {
                        active_ports[ap_i] = active_ports.back();
                        active_ports.pop_back();
                    } else {
                        ++ap_i;
                    }
                }
            }

            last_timeout_check = current_time;
        }

        struct __kernel_timespec timeout_ts = {
	    .tv_sec  = 0,
	    .tv_nsec = 50 * 1000 * 1000   
	};
        struct io_uring_cqe *cqe;
        int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &timeout_ts);

        if (ret == 0) {
            size_t slot_idx = static_cast<size_t>(io_uring_cqe_get_data64(cqe));
            int bytes = cqe->res;
            if (bytes == -ENETDOWN || bytes == -ENETUNREACH || bytes == -ENONET) {
                io_uring_cqe_seen(&ring, cqe);
                if (!network_disconnect_flag.exchange(true)) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << "\n[!] Network disconnected — exiting\n";
                }
                terminate_flag.store(true);
                sender_done.store(true, std::memory_order_release);
                sender_thread.join();
                return result;
            }

            io_uring_cqe_seen(&ring, cqe);
            --inflight;

            {
                SlotMeta& sm         = slots[slot_idx];
                sm.src_len           = sizeof(sm.src_addr);
                sm.msg.msg_namelen   = sizeof(sm.src_addr);
                sm.msg.msg_iovlen    = 1;
                sm.iov.iov_len       = SLOT_SIZE;
                // Restore cmsg buffer for next recv so kernel can write timestamp again
                sm.msg.msg_control    = sm.cmsg_buf;
                sm.msg.msg_controllen = sizeof(sm.cmsg_buf);

                struct io_uring_sqe *rsqe = io_uring_get_sqe(&ring);
                if (rsqe) {
                    io_uring_prep_recvmsg(rsqe, recv_sock, &sm.msg, 0);
                    io_uring_sqe_set_data64(rsqe, static_cast<uint64_t>(slot_idx));
                    needs_submit = true;
                    ++inflight;
                }
            }

            if (bytes > 0) {
                if (bytes >= static_cast<int>(sizeof(struct ip))) {
                    const char* buffer = reinterpret_cast<const char*>(
                        recv_bufs + slot_idx * SLOT_SIZE);
                    struct ip*    iph    = (struct ip*)buffer;
                    int           iphdrlen = iph->ip_hl * 4;
                    if (iph->ip_dst.s_addr == local_ip &&
                        iphdrlen >= static_cast<int>(sizeof(struct ip)) &&
                        iphdrlen <= bytes &&
                        iph->ip_p == IPPROTO_TCP &&
                        bytes >= iphdrlen + static_cast<int>(sizeof(struct tcphdr))) {
                        if (iph->ip_src.s_addr != dest.sin_addr.s_addr) {
			    continue;
		        }

                        struct tcphdr* tcph     = (struct tcphdr*)(buffer + iphdrlen);
                        uint16_t       dest_port = ntohs(tcph->th_sport);
                        // --- build timing context for new extract signature ---
                        int64_t kernel_rx_us_val = 0;
                        int64_t tx_us_val        = 0;
                        {
                            std::lock_guard<std::mutex> lk(tx_ts_mutex);
                            auto it = tx_timestamp_map.find(
                                ProbeKey{port_states_arr[dest_port].src_port, dest_port});
                            if (it != tx_timestamp_map.end()) {
                                tx_us_val = static_cast<int64_t>(
                                    std::chrono::duration_cast<std::chrono::microseconds>(
                                        it->second.time_since_epoch()).count());
                            }
                        }
                        // kernel SO_TIMESTAMP already resolved to rx_time above;
                        // re-derive epoch version here for the details struct
                        {
                            struct msghdr*  msg2  = &slots[slot_idx].msg;
                            struct cmsghdr* cmsg2 = CMSG_FIRSTHDR(msg2);
                            while (cmsg2) {
                                if (cmsg2->cmsg_level == SOL_SOCKET &&
                                    cmsg2->cmsg_type  == SO_TIMESTAMP) {
                                    struct timeval* tv2 = (struct timeval*)CMSG_DATA(cmsg2);
                                    kernel_rx_us_val = static_cast<int64_t>(tv2->tv_sec) * 1'000'000LL
                                                     + static_cast<int64_t>(tv2->tv_usec);
                                    break;
                                }
                                cmsg2 = CMSG_NXTHDR(msg2, cmsg2);
                            }
                        }

                        PortState& pstate_ref = port_states_arr[dest_port];
                        double rtt_here = pstate_ref.rtt_measured ? pstate_ref.ewma_rtt : 0.0;

                        // SO_TIMESTAMP epoch for capture_epoch_us
                        uint64_t cap_epoch = (kernel_rx_us_val > 0)
                            ? static_cast<uint64_t>(kernel_rx_us_val)
                            : static_cast<uint64_t>(
                                std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());

                        PacketDetails details = extract_packet_details(
                            iph, tcph, bytes, buffer,
                            cap_epoch,
                            kernel_rx_us_val, tx_us_val,
                            pstate_ref.retry_count, rtt_here, pstate_ref);
                        packet_details_map[dest_port]        = details;
                        result.packet_details[dest_port]     = details;
                        if (result.received_ttl == 0 && details.ttl != 0)
                            result.received_ttl = details.ttl;

                        if (dest_port > 0 &&
                            !port_final[dest_port].load(std::memory_order_acquire)) {

                            PortState& state = port_states_arr[dest_port];
			    if (!port_rtt_measured[dest_port].load(std::memory_order_relaxed) &&
			        (tcph->th_flags & (TH_SYN | TH_ACK | TH_RST))) {
				{
				    std::chrono::steady_clock::time_point tx_ref;
				    bool tx_found = false;
				    {
					std::lock_guard<std::mutex> lk(tx_ts_mutex);
					auto it = tx_timestamp_map.find(
					    ProbeKey{state.src_port, dest_port});   
					if (it != tx_timestamp_map.end()) {
					    tx_ref   = it->second;
					    tx_found = true;
					}
				    }
				    if (!tx_found) tx_ref = state.syn_sent_time;

				    // --- resolve RX time ---
				    std::chrono::steady_clock::time_point rx_time;
				    struct msghdr*  msg  = &slots[slot_idx].msg;
				    struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg);
				    bool got_timestamp = false;

				    while (cmsg) {
					if (cmsg->cmsg_level == SOL_SOCKET &&
					    cmsg->cmsg_type  == SO_TIMESTAMP) {
					    struct timeval* tv = (struct timeval*)CMSG_DATA(cmsg);
					    auto tv_duration = std::chrono::seconds(tv->tv_sec) +
							       std::chrono::microseconds(tv->tv_usec);
					    auto system_rx = std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(tv_duration));
					    rx_time       = steady_from_system(system_rx);
					    got_timestamp = true;
					    break;
					}
					cmsg = CMSG_NXTHDR(msg, cmsg);
				    }
				    if (!got_timestamp) rx_time = current_time;

				    // --- compute and sanity-check RTT ---
				    auto rtt_us    = std::chrono::duration_cast<std::chrono::microseconds>(
							 rx_time - tx_ref).count();
				    double rtt_ms  = rtt_us / 1000.0;
				    if (rtt_ms > 0.0 && rtt_ms < 30000.0) {
					int int_rtt_ms = static_cast<int>(std::ceil(rtt_ms));
					if (int_rtt_ms < 1) int_rtt_ms = 1;

					global_rtt_tracker.update(int_rtt_ms);
					state.ewma_rtt   = rtt_ms;
					state.rtt_measured = true;
					port_rtt_measured[dest_port].store(true, std::memory_order_relaxed);
				    }
				}
			    }

                            bool state_resolved = process_response(
                                state, dest_port, tcph, bytes, iph,
                                dest, packet_queue, queue_sem, scan_type, fast_scan, result,
                                service_map, current_time, window_scale, mss_value,
                                timestamp_val, timestamp_ecr_custom, nops_count,
                                sack_permitted, custom_data, data_length,
                                use_custom_data, generate_random_data,
                                print_individual_closed_filtered,
                                use_badsum, custom_badsum_value,
                                use_partial_badsum, partial_badsum_type,
                                use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
                                tfo_cookie_str, tfo_cookie_num, tfo_cookie_length,tl_port_output_buf);

                            if (state_resolved && state.final_state_determined &&
                                !port_final[dest_port].exchange(true,
                                    std::memory_order_acq_rel)) {
                                active_count.fetch_sub(1, std::memory_order_relaxed);
				std::lock_guard<std::mutex> lk(tx_ts_mutex);
				tx_timestamp_map.erase(ProbeKey{state.src_port, dest_port});
                            }
                        }
                    }
                }
            } else if (bytes < 0 &&
		   bytes != -EAGAIN &&
		   bytes != -EWOULDBLOCK &&
		   bytes != -EINTR) {
	    if (!recv_error_logged.exchange(true)) {
		std::cerr << "recvmsg error: " << strerror(-bytes) << "\n";
	    }
	}

        } else if (ret == -ETIME) {
        } else if (ret < 0 && ret != -EINTR) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "io_uring_wait_cqe_timeout error: " << strerror(-ret) << std::endl;
        }
        if (needs_submit) {
            io_uring_submit(&ring);
            needs_submit = false;
        }
        if (icmp_err_sock >= 0) {
            char         icmp_buf[1500];
            sockaddr_in  icmp_src{};
            socklen_t    icmp_slen = sizeof(icmp_src);
            ssize_t      icmp_nb;
            while ((icmp_nb = recvfrom(icmp_err_sock, icmp_buf, sizeof(icmp_buf),
                                       0,
                                       reinterpret_cast<sockaddr*>(&icmp_src),
                                       &icmp_slen)) > 0)
            {
                // Need at least outer IP header
                if (icmp_nb < static_cast<ssize_t>(sizeof(struct ip))) continue;
                struct ip* outer_iph    = reinterpret_cast<struct ip*>(icmp_buf);
                int        outer_iphlen = outer_iph->ip_hl * 4;
                if (outer_iphlen < static_cast<int>(sizeof(struct ip))) continue;
                if (icmp_nb < outer_iphlen +
                              static_cast<int>(sizeof(struct icmphdr))) continue;

                struct icmphdr* icmph = reinterpret_cast<struct icmphdr*>(
                    icmp_buf + outer_iphlen);

                // Only Destination Unreachable
                if (icmph->type != 3) continue;

                uint8_t code = icmph->code;
                // Only the three admin-prohibited codes
                if (code != 9 && code != 10 && code != 13) continue;

                // RFC 792: after ICMP header comes the original IP header
                // then first 8 bytes of original transport header (enough for ports)
                int inner_off = outer_iphlen +
                                static_cast<int>(sizeof(struct icmphdr));
                if (icmp_nb < inner_off +
                              static_cast<int>(sizeof(struct ip)) + 8) continue;

                struct ip* inner_iph    = reinterpret_cast<struct ip*>(
                    icmp_buf + inner_off);
                int        inner_iphlen = inner_iph->ip_hl * 4;
                if (icmp_nb < inner_off + inner_iphlen + 8) continue;

                // Verify destination of original probe = our target IP
                if (inner_iph->ip_dst.s_addr != dest.sin_addr.s_addr) continue;

                // Extract the destination port from the embedded TCP header
                // (first 8 bytes of TCP header = src_port[2] + dst_port[2] + seq[4])
                const uint8_t* tcp_start =
                    reinterpret_cast<const uint8_t*>(icmp_buf) +
                    inner_off + inner_iphlen;
                uint16_t blocked_port =
                    ntohs(*reinterpret_cast<const uint16_t*>(tcp_start + 2));

                if (blocked_port == 0) continue;
                if (port_final[blocked_port].load(
                        std::memory_order_acquire)) continue;

                PortState& state = port_states_arr[blocked_port];

                // Guard: only act on last retry so a TCP reply always wins
                if (!global_rtt_tracker.should_mark_filtered(
                        state.retry_count)) continue;

                // Guard: only classify if not already reported
                if (state.reported_state !=
                        PortState::PortReportedState::None) continue;

                // Record reason and finalise port
                IcmpFilterReason reason   = IcmpFilterReason::None;
                const char*      code_str = "";
                switch (code) {
                    case 9:
                        reason   = IcmpFilterReason::NetAdminProhibited;
                        code_str = "ICMP type 3 code 9: net-admin-prohibited"
                                   " (ACL/router policy blocks subnet)";
                        break;
                    case 10:
                        reason   = IcmpFilterReason::HostAdminProhibited;
                        code_str = "ICMP type 3 code 10: host-admin-prohibited"
                                   " (host firewall/ACL denies this IP)";
                        break;
                    case 13:
                        reason   = IcmpFilterReason::CommAdminProhibited;
                        code_str = "ICMP type 3 code 13: comm-admin-prohibited"
                                   " (iptables REJECT / firewall policy)";
                        break;
                    default: break;
                }

                result.filtered_ports.push_back(blocked_port);
                result.icmp_filter_reasons[blocked_port] = reason;
                state.reported_state         = PortState::PortReportedState::Filtered;
                state.final_state_determined = true;
                port_final[blocked_port].store(true, std::memory_order_release);
                active_count.fetch_sub(1, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lk(tx_ts_mutex);
                    tx_timestamp_map.erase(ProbeKey{state.src_port, blocked_port});
                }

                // Immediate per-port output when individual mode is on
                if (print_individual_closed_filtered) {
                    if (tl_port_output_buf) {
                        *tl_port_output_buf +=
                            std::string("│   ├─ 🔴 Port ") +
                            std::to_string(blocked_port) +
                            "/tcp  filtered  [" + code_str + "]\n";
                    }
                }
            } 
        }
       
    }

    while (inflight > 0) {
        struct io_uring_cqe *cqe;
        struct __kernel_timespec drain_ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
        int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &drain_ts);
        if (ret == 0) {
            io_uring_cqe_seen(&ring, cqe);
            --inflight;
        } else {
            break;  
        }
    }

    sender_done.store(true, std::memory_order_release);
    if (sender_thread.joinable()) {
        sender_thread.join();
        
    }

    int max_observed_rtt = 0;
    for (int port : ports) {
        PortState& state = port_states_arr[port];
    
        if (state.rtt_measured) {
            int rtt_int = static_cast<int>(state.ewma_rtt);
            if (state.ewma_rtt > 0 && rtt_int == 0) {
                rtt_int = 1;  // Minimum 1ms for display
            }
            result.rtt_debug_entries.push_back({port, static_cast<double>(state.ewma_rtt)});

            if (rtt_int > max_observed_rtt) {
                max_observed_rtt = rtt_int;
            }
        }
    }

    if (max_observed_rtt > 0) {
        result.learned_rtt_ms = max_observed_rtt;
    } else {
        result.learned_rtt_ms = global_rtt_tracker.has_measurement.load()
                        ? global_rtt_tracker.current_rtt_ms.load()
                        : 0;
    }

    result.packets_sent = local_packets_sent.load(std::memory_order_relaxed);
    return result;
}

void display_packet_details(const PacketDetails& d, bool debug_enabled) {
    if (!debug_enabled) return;

    // ── helpers ────────────────────────────────────────────────────────────
    auto yn = [](bool v) -> std::string {
        return v ? (color::green + "Yes" + color::reset)
                 : (color::red   + "No"  + color::reset);
    };
    auto set_notset = [](bool v) -> std::string {
        return v ? (color::green + "Set"     + color::reset)
                 : (color::red   + "Not Set" + color::reset);
    };
    auto hex16 = [](uint16_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << v;
        return ss.str();
    };
    auto hex8 = [](uint8_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(v);
        return ss.str();
    };
    auto hex32 = [](uint32_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << v;
        return ss.str();
    };

    auto tcp_flags_str = [](uint8_t flags) -> std::string {
        std::string s;
        if (flags & TH_FIN)  s += "FIN ";
        if (flags & TH_SYN)  s += "SYN ";
        if (flags & TH_RST)  s += "RST ";
        if (flags & TH_PUSH) s += "PSH ";
        if (flags & TH_ACK)  s += "ACK ";
        if (flags & TH_URG)  s += "URG ";
        if (flags & TH_ECE)  s += "ECE ";
        if (flags & TH_CWR)  s += "CWR ";
        if (s.empty()) s = "NONE";
        else if (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    };

    const bool syn_ack = ((d.tcp_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK));
    const bool rst_set = (d.tcp_flags & TH_RST) != 0;
    std::string state_text  = syn_ack && !rst_set ? "Open (SYN-ACK)"
                            : rst_set             ? "Closed (RST)"
                            :                       "Other TCP Response";
    std::string state_color = syn_ack && !rst_set ? color::green
                            : rst_set             ? color::red
                            :                       color::yellow;

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "\n";
    std::cout << color::cyan << "╔══════════════════════════════════════════════════════\n";
    std::cout << color::cyan << "║ 📦 Packet Details for Port " << d.port << "/tcp"
              << color::reset << "\n";
    std::cout << color::cyan << "╚══════════════════════════════════════════════════════\n"
              << color::reset;

    // ── Section 1: Endpoint Info ───────────────────────────────────────────
    std::cout << color::cyan << "├─ 🌐 Endpoints\n" << color::reset;
    std::cout << "│   ├─ Src IP:Port  : " << color::yellow << d.src_ip << ":" << d.src_port << color::reset << "\n";
    std::cout << "│   └─ Dst IP:Port  : " << color::yellow << d.dst_ip << ":" << d.dst_port << color::reset << "\n";

    // ── Section 2: IP Header ───────────────────────────────────────────────
    std::cout << color::cyan << "├─ 🔵 IP Header\n" << color::reset;
    std::cout << "│   ├─ IP ID        : " << color::yellow << d.ip_id         << color::reset << "\n";
    std::cout << "│   ├─ Total Length : " << color::yellow << d.ip_total_length << " B" << color::reset << "\n";
    std::cout << "│   ├─ Header Len   : " << color::yellow << static_cast<int>(d.ip_header_len) << " B" << color::reset << "\n";
    std::cout << "│   ├─ TTL          : " << color::yellow << static_cast<int>(d.ttl) << color::reset << "\n";
    std::cout << "│   ├─ Protocol     : " << color::yellow << static_cast<int>(d.ip_protocol) << color::reset << "\n";
    std::cout << "│   ├─ TOS          : " << color::yellow << hex8(d.ip_tos)  << color::reset << "\n";
    std::cout << "│   ├─ DF Flag      : " << set_notset(d.df_flag)            << "\n";
    std::cout << "│   ├─ MF Flag      : " << set_notset(d.ip_mf_flag)         << "\n";
    std::cout << "│   ├─ Frag Offset  : " << color::yellow << (d.ip_frag_off_raw & 0x1FFF) << color::reset << "\n";
    std::cout << "│   ├─ Checksum     : " << color::yellow << hex16(d.ip_checksum) << color::reset
              << "  valid=" << yn(d.ip_checksum_valid) << "\n";
    std::cout << "│   └─ Hop Distance : " << color::yellow << d.hop_distance_est << " hops" << color::reset << "\n";

    // ── Section 3: TCP Header ──────────────────────────────────────────────
    std::cout << color::cyan << "├─ 🟢 TCP Header\n" << color::reset;
    std::cout << "│   ├─ Src Port     : " << color::yellow << d.src_port      << color::reset << "\n";
    std::cout << "│   ├─ Flags        : " << color::yellow << tcp_flags_str(d.tcp_flags)
              << " (" << hex8(d.tcp_flags) << ")" << color::reset << "\n";
    std::cout << "│   ├─ Seq Num      : " << color::yellow << d.seq_num       << color::reset << "\n";
    std::cout << "│   ├─ Ack Num      : " << color::yellow << d.ack_num       << color::reset << "\n";
    std::cout << "│   ├─ Window       : " << color::yellow << d.window_size   << color::reset << "\n";
    std::cout << "│   ├─ Header Len   : " << color::yellow << static_cast<int>(d.tcp_header_len) << " B" << color::reset << "\n";
    std::cout << "│   ├─ Data Offset  : " << color::yellow << static_cast<int>(d.tcp_data_offset) << color::reset << "\n";
    std::cout << "│   ├─ URG Ptr      : " << color::yellow << d.tcp_urg_ptr   << color::reset << "\n";
    std::cout << "│   └─ Checksum     : " << color::yellow << hex16(d.checksum) << color::reset
              << "  valid=" << yn(d.tcp_checksum_valid) << "\n";

    // ── Section 4: TCP Options ─────────────────────────────────────────────
    std::cout << color::cyan << "├─ ⚙️  TCP Options\n" << color::reset;
    std::cout << "│   ├─ Layout       : " << color::yellow
              << (d.tcp_option_layout.empty() ? "(none)" : d.tcp_option_layout)
              << color::reset << "\n";
    std::cout << "│   ├─ MSS          : "
              << (d.has_mss ? color::yellow + std::to_string(d.mss_value) + color::reset
                            : color::dim + std::string("N/A") + color::reset) << "\n";
    std::cout << "│   ├─ Window Scale : "
              << (d.has_window_scale
                    ? color::yellow + std::to_string(static_cast<int>(d.window_scale)) + color::reset
                    : color::dim + std::string("N/A") + color::reset) << "\n";
    std::cout << "│   ├─ SACK-OK      : " << yn(d.sack_permitted) << "\n";
    std::cout << "│   ├─ SACK Blocks  : " << yn(d.has_sack_blocks);
    if (d.has_sack_blocks && !d.sack_blocks.empty()) {
        std::cout << "  [";
        for (size_t i = 0; i < d.sack_blocks.size(); ++i) {
            std::cout << d.sack_blocks[i].first << "-" << d.sack_blocks[i].second;
            if (i + 1 < d.sack_blocks.size()) std::cout << ", ";
        }
        std::cout << "]";
    }
    std::cout << "\n";
    std::cout << "│   ├─ Timestamp    : " << yn(d.has_timestamp)
              << "  TSval=" << color::yellow << d.tsval << color::reset
              << "  TSecr=" << color::yellow << d.tsecr << color::reset << "\n";
    std::cout << "│   ├─ TFO          : " << yn(d.has_tfo)
              << (d.has_tfo ? ("  data=" + color::yellow + d.tfo_data + color::reset) : "") << "\n";
    std::cout << "│   ├─ NOPs         : " << yn(d.has_nops) << "  count=" << d.nop_count << "\n";
    std::cout << "│   ├─ EOL          : " << yn(d.has_eol)
              << (d.has_eol ? "  offset=" + std::to_string(d.eol_offset) : "") << "\n";
    std::cout << "│   └─ Unknown Opts : " << yn(d.has_unknown_options);
    if (d.has_unknown_options) {
        std::cout << "  kinds=[";
        for (size_t i = 0; i < d.unknown_option_kinds.size(); ++i) {
            std::cout << static_cast<int>(d.unknown_option_kinds[i]);
            if (i + 1 < d.unknown_option_kinds.size()) std::cout << ",";
        }
        std::cout << "]";
    }
    std::cout << "\n";

    // ── Section 5: Payload ─────────────────────────────────────────────────
    std::cout << color::cyan << "├─ 📄 Payload\n" << color::reset;
    std::cout << "│   ├─ Length       : " << color::yellow << d.payload_len << " B" << color::reset << "\n";
    std::cout << "│   ├─ Has Payload  : " << yn(d.has_payload) << "\n";
    std::cout << "│   ├─ Preview      : ";
    if (d.payload.empty()) {
        std::cout << color::dim << "(empty)" << color::reset;
    } else {
        std::cout << color::yellow << d.payload.substr(0, 64)
                  << (d.payload.size() > 64 ? "..." : "") << color::reset;
    }
    std::cout << "\n";
    std::cout << "│   └─ Raw Hex (first 16 B): ";
    {
        size_t show = std::min(d.tcp_payload_raw.size(), size_t(16));
        for (size_t i = 0; i < show; ++i) {
            std::cout << color::yellow;
            char hx[3]; std::snprintf(hx, sizeof(hx), "%02X", d.tcp_payload_raw[i]);
            std::cout << hx << (i+1 < show ? " " : "") << color::reset;
        }
        if (d.tcp_payload_raw.size() > 16) std::cout << " ...";
        std::cout << "\n";
    }

    // ── Section 6: Timing ─────────────────────────────────────────────────
    std::cout << color::cyan << "├─ ⏱️  Timing\n" << color::reset;
    std::cout << "│   ├─ Capture Epoch   : " << color::yellow << d.capture_epoch_us << " µs" << color::reset << "\n";
    std::cout << "│   ├─ Kernel RX TS    : " << color::yellow << d.kernel_rx_ts_us  << " µs" << color::reset << "\n";
    std::cout << "│   ├─ User RX TS      : " << color::yellow << d.user_rx_ts_us    << " µs" << color::reset << "\n";
    std::cout << "│   ├─ TX TS           : " << color::yellow << d.tx_ts_us         << " µs" << color::reset << "\n";
    std::cout << "│   ├─ RTT             : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_ms   << " ms" << color::reset << "\n";
    std::cout << "│   ├─ RTT EWMA        : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_ewma_ms << " ms" << color::reset << "\n";
    std::cout << "│   ├─ RTT Jitter      : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_jitter_ms << " ms" << color::reset << "\n";
    std::cout << "│   ├─ RTT Outlier     : " << yn(d.rtt_outlier) << "\n";
    std::cout << "│   └─ TTL Outlier     : " << yn(d.ttl_outlier) << "\n";

    // ── Section 7: Probe Context ───────────────────────────────────────────
    std::cout << color::cyan << "├─ 🔬 Sent Probe\n" << color::reset;
    std::cout << "│   ├─ Retry Index  : " << color::yellow << d.retry_index << color::reset << "\n";
    std::cout << "│   ├─ Flags        : " << color::yellow << tcp_flags_str(d.sent_flags)
              << " (" << hex8(d.sent_flags) << ")" << color::reset << "\n";
    std::cout << "│   ├─ TTL          : " << color::yellow << static_cast<int>(d.sent_ttl) << color::reset << "\n";
    std::cout << "│   ├─ Window Scale : " << color::yellow << static_cast<int>(d.sent_ws)  << color::reset << "\n";
    std::cout << "│   ├─ TSval        : " << color::yellow << d.sent_tsval       << color::reset << "\n";
    std::cout << "│   ├─ MSS          : " << color::yellow << d.sent_mss         << color::reset << "\n";
    std::cout << "│   ├─ Seq          : " << color::yellow << d.sent_seq         << color::reset << "\n";
    std::cout << "│   ├─ Ack          : " << color::yellow << d.sent_ack         << color::reset << "\n";
    std::cout << "│   ├─ Window Size  : " << color::yellow << d.sent_window_size << color::reset << "\n";
    std::cout << "│   ├─ DSCP         : " << color::yellow << static_cast<int>(d.sent_dscp)   << color::reset << "\n";
    std::cout << "│   ├─ IP TOS       : " << color::yellow << hex8(d.sent_ip_tos) << color::reset << "\n";
    std::cout << "│   ├─ DF           : " << yn(d.sent_df)           << "\n";
    std::cout << "│   └─ SACK-OK      : " << yn(d.sent_sack_permitted) << "\n";

    // ── Section 8: Classification ──────────────────────────────────────────
    std::cout << color::cyan << "├─ 🏷️  Classification\n" << color::reset;
    std::cout << "│   ├─ Flow Hash    : " << color::yellow << hex32(d.flow_hash) << color::reset << "\n";
    std::cout << "│   ├─ Probe ID     : " << color::yellow << d.probe_id         << color::reset << "\n";
    std::cout << "│   ├─ Resp Index   : " << color::yellow << d.response_index   << color::reset << "\n";
    std::cout << "│   ├─ Duplicate    : " << yn(d.duplicate_response)           << "\n";
    std::cout << "│   ├─ Retransmit?  : " << yn(d.retransmission_suspect)       << "\n";
    std::cout << "│   ├─ Reason       : " << color::yellow
              << (d.classification_reason.empty() ? "(none)" : d.classification_reason)
              << color::reset << "\n";
    std::cout << "│   ├─ Anomaly Score: " << color::yellow << d.anomaly_score     << color::reset << "\n";
    std::cout << "│   ├─ Confidence   : " << color::yellow << std::fixed << std::setprecision(2)
              << d.anomaly_confidence << color::reset << "\n";
    std::cout << "│   └─ Tags         : ";
    if (d.signature_tags.empty()) {
        std::cout << color::dim << "(none)" << color::reset;
    } else {
        for (size_t i = 0; i < d.signature_tags.size(); ++i) {
            std::cout << color::yellow << d.signature_tags[i] << color::reset;
            if (i + 1 < d.signature_tags.size()) std::cout << ", ";
        }
    }
    std::cout << "\n";

    // ── Section 9: Raw Packet Hex Dump ─────────────────────────────────────
    std::cout << color::cyan << "├─ 🧮 Raw Packet (first 64 B)\n" << color::reset;
    {
        size_t show = std::min(d.raw_packet.size(), size_t(64));
        for (size_t i = 0; i < show; ++i) {
            if (i % 16 == 0) std::cout << "│   ";
            char hx[3]; std::snprintf(hx, sizeof(hx), "%02X", d.raw_packet[i]);
            std::cout << color::dim << hx << color::reset;
            std::cout << (((i+1) % 16 == 0 || i+1 == show) ? "\n" : " ");
        }
        if (d.raw_packet.size() > 64)
            std::cout << "│   ... (" << d.raw_packet.size() << " B total)\n";
    }

    // ── Raw Packet flag-byte context window ───────────────────────────────
    // ── Raw Packet flag-byte context window ───────────────────────────────
    {
        const size_t flag_byte_idx =
            (d.ip_header_len >= 20)
                ? static_cast<size_t>(d.ip_header_len) + 13u
                : SIZE_MAX;

        const bool is_synack = ((d.tcp_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
                               && !(d.tcp_flags & TH_RST);
        const bool is_rst    = (d.tcp_flags & TH_RST) != 0;

        const std::string& flag_color =
            is_synack ? color::green :
            is_rst    ? color::red   :
                        color::yellow;

        const std::string flag_label =
            is_synack ? "SYN-ACK" :
            is_rst    ? "RST"     :
                        [&]{ char b[5];
                             std::snprintf(b, sizeof(b), "0x%02X", d.tcp_flags);
                             return std::string(b); }();

        std::cout << color::cyan << "├─ 🧮 Raw Packet (flag context)" << color::reset << "\n";
        std::cout << "│   ";

        if (flag_byte_idx == SIZE_MAX || flag_byte_idx >= d.raw_packet.size()) {
            std::cout << color::dim << "(unavailable)" << color::reset << "\n";
        } else {
            const size_t window_before = 4;
            const size_t window_after  = 4;
            const size_t start = (flag_byte_idx >= window_before)
                                 ? flag_byte_idx - window_before : 0;
            const size_t end   = std::min(flag_byte_idx + window_after + 1,
                                          d.raw_packet.size());

            for (size_t i = start; i < end; ++i) {
                char hx[3];
                std::snprintf(hx, sizeof(hx), "%02X", d.raw_packet[i]);

                if (i == flag_byte_idx) {
                    std::cout << color::bold << flag_color << "[" << hx << "]" << color::reset;
                } else {
                    std::cout << color::white << hx << color::reset;
                }

                if (i + 1 < end) std::cout << " ";
            }

            std::cout << "  " << flag_color << color::bold
                      << "← " << flag_label << color::reset << "\n";
        }
    }

    std::cout << color::cyan << "└─ 📈 Summary" << color::reset << "\n";
    std::cout << "    └─ State: " << state_color << state_text << color::reset
              << " (" << color::yellow << __builtin_popcount(d.tcp_flags) << color::reset << " flags active)\n\n";

}

bool process_response(PortState& state, uint16_t dest_port, 
                                   struct tcphdr* tcph, int bytes, struct ip* iph,sockaddr_in& dest, moodycamel::ConcurrentQueue<PacketTask>& packet_queue, std::counting_semaphore<65536>& queue_sem,ScanType scan_type, bool fast_scan, RecPross& result,
                                   const std::unordered_map<uint16_t, std::string>& service_map,std::chrono::steady_clock::time_point current_time,uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,
                                   uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,const std::string& custom_data, uint16_t data_length,bool use_custom_data, bool generate_random_data, bool  
                                   print_individual_closed_filtered,bool use_badsum, uint16_t custom_badsum_value,bool use_partial_badsum, const std::string& partial_badsum_type,
                                   bool use_tfo_cookie, bool tfo_cookie_as_hex, bool tfo_cookie_random,const std::string& tfo_cookie_str, uint64_t tfo_cookie_num,size_t tfo_cookie_length,std::string* output_buf) {
    
    if (state.final_state_determined) {
        return false;
    }
        
    const uint32_t ack_num = ntohl(tcph->th_ack);
    const uint32_t expected_ack = state.seq + 1;

    if (!state.connection_established &&
        (tcph->th_flags & TH_ACK) && ack_num != expected_ack) {
        return false;
    }
    switch(scan_type) {
        case ScanType::RAM:
        case ScanType::JATAYU:
        case ScanType::GARUD:
        case ScanType::GANESH:
        case ScanType::SYN: {
            if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && !state.connection_established) {
                state.ack_seq = ntohl(tcph->th_seq) + 1;
                sockaddr_in single_dest = dest;
                single_dest.sin_port = htons(dest_port);
                
                if (!fast_scan) {
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, 
                        mss_value, timestamp_val, timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,
                        use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
                    queue_sem.release();
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_FIN | TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, mss_value, timestamp_val, 
                        timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
                    queue_sem.release();
                }
                
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.open_ports.push_back(dest_port);
                    state.reported_state = PortState::PortReportedState::Open;
                    std::string scan_name = "";
                    switch(scan_type) {
                        case ScanType::SYN: scan_name = "SYN"; break;
                        case ScanType::RAM: scan_name = "RAM"; break;
                        case ScanType::JATAYU: scan_name = "JATAYU"; break;
                        case ScanType::GARUD: scan_name = "GARUD"; break;
                        case ScanType::GANESH: scan_name = "GANESH"; break;
                        default: scan_name = "";
                    }
                    std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                    if (scan_type == ScanType::SYN) {
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT, "", dest_port,
                                        "open", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        } else {
                            print_output(PrintOutputType::PORT_RESULT, "", dest_port,
                                        "open", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        }
                    } else {
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "open", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        } else {
                            print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "open", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        }
                    }
                }
                
                state.connection_established = true;
                state.fin_sent = !fast_scan;
                
                if (fast_scan) {
                    state.final_state_determined = true;
                }
                return true;
            } else if (tcph->th_flags & TH_RST) {
            
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.closed_ports++;
                    state.reported_state = PortState::PortReportedState::Closed;
                    if (print_individual_closed_filtered) {
                        std::string scan_name = "";
                        switch(scan_type) {
                            case ScanType::SYN: scan_name = "SYN"; break;
                            case ScanType::RAM: scan_name = "RAM"; break;
                            case ScanType::JATAYU: scan_name = "JATAYU"; break;
                            case ScanType::GARUD: scan_name = "GARUD"; break;
                            case ScanType::GANESH: scan_name = "GANESH"; break;
                            default: scan_name = "";
                        }
                        std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                        
                        if (scan_type == ScanType::SYN) {
                            if (output_buf) {
                                *output_buf += capture_output(PrintOutputType::PORT_RESULT, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            } else {
                                print_output(PrintOutputType::PORT_RESULT, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            }
                        } else {
                            if (output_buf) {
                                *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            } else {
                                print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            }
                        }
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
        }
        case ScanType::FIN:
        case ScanType::NULL_SCAN:
        case ScanType::XMAS:
        case ScanType::MAIMON: {
            if (tcph->th_flags & TH_RST) {
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.closed_ports++;
                    state.reported_state = PortState::PortReportedState::Closed;
                    if (print_individual_closed_filtered) {
                        std::string scan_name = "";
                        switch(scan_type) {
                            case ScanType::FIN: scan_name = "FIN"; break;
                            case ScanType::NULL_SCAN: scan_name = "NULL"; break;
                            case ScanType::XMAS: scan_name = "XMAS"; break;
                            case ScanType::MAIMON: scan_name = "MAIMON"; break;
                            default: break;
                        }
                        std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        } else {
                            if (output_buf) {
                                *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            } else {
                                print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, scan_name, 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            }
                        }
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
        }
        case ScanType::ACK: {
            if (tcph->th_flags & TH_RST) {
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.open_ports.push_back(dest_port);
                    state.reported_state = PortState::PortReportedState::Open;
                    std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                    if (output_buf) {
                        *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "unfiltered", service, "ACK", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                    } else {
                        print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "unfiltered", service, "ACK", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
        }
        case ScanType::WINDOW: {
            if (tcph->th_flags & TH_RST) {
                uint16_t window_size = ntohs(tcph->th_win);
                bool likely_open = (window_size > 0);
                bool likely_closed = (window_size == 0);
                if (state.reported_state == PortState::PortReportedState::None) {
                    if (likely_open) {
                        result.open_ports.push_back(dest_port);
                        state.reported_state = PortState::PortReportedState::Open;
                        std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "open", service, "WINDOW", window_size, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        } else {
                            print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "open", service, "WINDOW", window_size, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        }
                    } else if (likely_closed) {
                        result.closed_ports++;
                        state.reported_state = PortState::PortReportedState::Closed;
                        if (print_individual_closed_filtered) {
                            std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                            if (output_buf) {
                                *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, "WINDOW", window_size, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            } else {
                                print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                            "closed", service, "WINDOW", window_size, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                            }
                        }
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
        }
        case ScanType::CWR:
        case ScanType::ECE:
        case ScanType::URG:
        case ScanType::PSH:
        case ScanType::HANUMAN:
        case ScanType::KAKABHUSUNDI: {
            // Check for SYN-ACK-ECE response (open port for KAKABHUSUNDI)
            if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && 
                !state.connection_established) {
                
                state.ack_seq = ntohl(tcph->th_seq) + 1;
                sockaddr_in single_dest = dest;
                single_dest.sin_port = htons(dest_port);
                
                if (!fast_scan) {
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, 
                        mss_value, timestamp_val, timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,
                        use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
                    queue_sem.release();
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_FIN | TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, mss_value, timestamp_val, 
                        timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
                    queue_sem.release();
                }
                
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.open_ports.push_back(dest_port);
                    state.reported_state = PortState::PortReportedState::Open;
                    
                    std::string scan_name = "";
                    switch(scan_type) {
                        case ScanType::CWR: scan_name = "CWR"; break;
                        case ScanType::ECE: scan_name = "ECE"; break;
                        case ScanType::URG: scan_name = "URG"; break;
                        case ScanType::PSH: scan_name = "PSH"; break;
                        case ScanType::HANUMAN: scan_name = "HANUMAN"; break;
                        case ScanType::KAKABHUSUNDI: scan_name = "KAKABHUSUNDI"; break;
                        default: break;
                    }
                    
                    std::string service = service_map.count(dest_port) ? 
                                          service_map.at(dest_port) : "unknown";
                    
                    if (output_buf) {
                        *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "open", service, scan_name, 0, 0, 0, 0, 0, 0,
                                    "", "", 0.0, "", false, true);
                    } else {
                        print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "open", service, scan_name, 0, 0, 0, 0, 0, 0,
                                    "", "", 0.0, "", false, true);
                    }
                }
                
                state.connection_established = true;
                state.fin_sent = !fast_scan;
                
                if (fast_scan) {
                    state.final_state_determined = true;
                }
                return true;
            }
            // Check for RST response (closed port)
            else if (tcph->th_flags & TH_RST) {
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.closed_ports++;
                    state.reported_state = PortState::PortReportedState::Closed;
                    
                    if (print_individual_closed_filtered) {
                        std::string scan_name = "";
                        switch(scan_type) {
                            case ScanType::CWR: scan_name = "CWR"; break;
                            case ScanType::ECE: scan_name = "ECE"; break;
                            case ScanType::URG: scan_name = "URG"; break;
                            case ScanType::PSH: scan_name = "PSH"; break;
                            case ScanType::HANUMAN: scan_name = "HANUMAN"; break;
                            case ScanType::KAKABHUSUNDI: scan_name = "KAKABHUSUNDI"; break;
                            default: break;
                        }
                        
                        std::string service = service_map.count(dest_port) ? 
                                              service_map.at(dest_port) : "unknown";
                        
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "closed", service, scan_name, 0, 0, 0, 0, 0, 0,
                                        "", "", 0.0, "", false, true);
                        } else {
                            print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "closed", service, scan_name, 0, 0, 0, 0, 0, 0,
                                        "", "", 0.0, "", false, true);
                        }
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
        }
        default:
            if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && !state.connection_established) {
                state.ack_seq = ntohl(tcph->th_seq) + 1;
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.open_ports.push_back(dest_port);
                    state.reported_state = PortState::PortReportedState::Open;
                    
                    std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                    if (output_buf) {
                        *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "open", service, "UNKNOWN-SCAN", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                    } else {
                        print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                    "open", service, "UNKNOWN-SCAN", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                    }
                }
                state.connection_established = true;
                state.final_state_determined = true;
                return true;
            } else if (tcph->th_flags & TH_RST) {
                if (state.reported_state == PortState::PortReportedState::None) {
                    result.closed_ports++;
                    state.reported_state = PortState::PortReportedState::Closed;
                    if (print_individual_closed_filtered) {
                        std::string service = service_map.count(dest_port) ? service_map.at(dest_port) : "unknown";
                        if (output_buf) {
                            *output_buf += capture_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "closed", service, "UNKNOWN-SCAN", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        } else {
                            print_output(PrintOutputType::PORT_RESULT_CUSTOM, "", dest_port,
                                        "closed", service, "UNKNOWN-SCAN", 0, 0, 0, 0, 0, 0, "", "", 0.0, "", false, true);
                        }
                    }
                }
                state.final_state_determined = true;
                return true;
            }
            break;
    }
    if (state.connection_established && state.fin_sent && !state.fin_ack_received) {
        if (tcph->th_flags & TH_FIN) {
            uint32_t data_len = bytes - (iph->ip_hl * 4) - (tcph->th_off * 4);
            sockaddr_in single_dest = dest;
            single_dest.sin_port = htons(dest_port);
            packet_queue.enqueue(PacketTask(
                single_dest, state.src_port, state.seq + 2, ntohl(tcph->th_seq) + data_len + 1, TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, mss_value, 
                timestamp_val, timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,use_badsum, custom_badsum_value,
                use_partial_badsum, partial_badsum_type,use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
            ));
            queue_sem.release();
            
            state.fin_ack_received = true;
            state.final_state_determined = true;
            return true;
        }
    }
    if (state.connection_established && !state.fin_sent && 
        (tcph->th_flags & TH_ACK) && !(tcph->th_flags & TH_SYN)) {
        if (state.reported_state == PortState::PortReportedState::Open) {
            state.final_state_determined = true;
            return true;
        }
    }

    return false;
}

void worker_thread(const char *ip, uint32_t local_ip, const char* source_ip, int timeout_ms, const std::vector<int>& ports, 
                   std::mt19937 &rng, PacketBufferPool &pool, int send_sock, RecPross &result, size_t main_batch_size, uint32_t seq_num,
                   uint16_t win_size, int ip_version, bool print_individual_closed_filtered, bool print_filtered_if_few, struct io_uring *send_ring, bool fast_scan,
                   ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp,uint16_t custom_ip_flags,IpIdMode ip_id_mode, uint16_t fixed_ip_id, bool use_manual_tcp_checksum, uint16_t manual_tcp_checksum,
                   uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,
                   const std::string& custom_data, uint16_t data_length, bool use_custom_data, bool generate_random_data, int user_rcvbuf_size,
                   size_t send_uring_depth, size_t rcv_uring_depth,bool use_badsum, uint16_t custom_badsum_value,
                   bool use_partial_badsum, const std::string& partial_badsum_type, bool use_tfo_cookie,bool tfo_cookie_as_hex,bool tfo_cookie_random,
                   const std::string& tfo_cookie_str,uint64_t tfo_cookie_num,size_t tfo_cookie_length, uint16_t source_port, bool debug_packet,bool debug_rtt,bool debug_wsn,bool debug_ttl,bool use_fragmentation, uint16_t frag_size, uint16_t mtu_size,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,uint16_t sport_range_min, uint16_t sport_range_max,int initial_rtt_ms,int port_timeout_min_ms, int port_timeout_max_ms, RateConfig rate_config,JitterConfig jitter_config,BatchDelayConfig batch_delay_config, bool use_ip_tos, uint8_t custom_ip_tos_byte,PacketLengthConfig packet_length_config,bool is_threaded) {
                   
    size_t effective_batch_size = main_batch_size;
    if (ports.empty() || terminate_flag) {
        return;
    }
     uint32_t effective_src_ip = local_ip;
     if (source_ip && strlen(source_ip) > 0) {
         struct in_addr addr;
         if (inet_pton(AF_INET, source_ip, &addr) == 1) {
             effective_src_ip = addr.s_addr;
         } else {
             std::cerr << "Invalid source IP: " << source_ip << std::endl;
             return;
         }
    }
    static const std::unordered_map<ScanType, std::string> scan_names = {
        {ScanType::SYN, "SYN"}, {ScanType::FIN, "FIN"}, {ScanType::ACK, "ACK"},
        {ScanType::NULL_SCAN, "NULL"}, {ScanType::XMAS, "XMAS"}, {ScanType::WINDOW, "WINDOW"},
        {ScanType::MAIMON, "MAIMON"}, {ScanType::CWR, "CWR"}, {ScanType::ECE, "ECE"},
        {ScanType::URG, "URG"}, {ScanType::PSH, "PSH"}, {ScanType::HANUMAN, "HANUMAN"},
        {ScanType::KAKABHUSUNDI, "KAKABHUSUNDI"}, {ScanType::GANESH, "GANESH"},
        {ScanType::RAM, "RAM"}, {ScanType::GARUD, "GARUD"}, {ScanType::JATAYU, "JATAYU"}
    };
    std::string scan_name = [&]() -> std::string {
        auto it = scan_names.find(scan_type);
        return it != scan_names.end() ? it->second : "UNKNOWN";
    }();
    
    if (ports.size() > 1) {
        if (is_threaded) {
            result.output_buffer += capture_output(PrintOutputType::SCAN_HEADER, ip, 0, "", "", scan_name,
                                                   0, ports.size(), 0, 0, 0, 0, "", "", 0.0, "", false, true);
        } else {
            print_output(PrintOutputType::SCAN_HEADER, ip, 0, "", "", scan_name,
                         0, ports.size(), 0, 0, 0, 0, "", "", 0.0, "", false, true);
        }
    }
    std::uniform_int_distribution<uint16_t> port_dist;
    if (source_port > 0) {
        port_dist = std::uniform_int_distribution<uint16_t>(source_port, source_port);
    } else {
        port_dist = std::uniform_int_distribution<uint16_t>(sport_range_min, sport_range_max);
    }
    std::uniform_int_distribution<uint32_t> seq_dist(0, 4294967295U);
    const size_t total_ports = ports.size();
    const size_t num_full_batches = total_ports / effective_batch_size;
    const size_t remaining_ports = total_ports % effective_batch_size;
    struct BatchRange { size_t start, end; };
    std::vector<BatchRange> batches;
    batches.reserve(num_full_batches + (remaining_ports > 0 ? 1 : 0));

    size_t start_idx = 0;
    for (size_t i = 0; i < num_full_batches; ++i) {
        size_t end_idx = start_idx + effective_batch_size;
        batches.push_back({start_idx, end_idx});
        start_idx = end_idx;
    }
    if (remaining_ports > 0) {
        size_t ports_per_batch = remaining_ports / (num_full_batches + 1);
        size_t extra_ports     = remaining_ports % (num_full_batches + 1);
        for (size_t i = 0; i < num_full_batches && ports_per_batch > 0; ++i) {
            size_t add_ports = ports_per_batch + (i < extra_ports ? 1 : 0);
            if (add_ports > 0) {
                batches[i].end += add_ports;  
                start_idx += add_ports;
            }
        }
        if (start_idx < total_ports) {
            batches.push_back({start_idx, total_ports});
        }
    }
    
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Receive socket creation failed: " << strerror(errno) << std::endl;
        return;
    }

    {
        const size_t port_count = ports.size();
        int rcvbuf_size = user_rcvbuf_size > 0 ? user_rcvbuf_size :
            (port_count <= 1000  ? 256  * 1024 :
             port_count <= 25000 ? 512  * 1024 :
             port_count <= 45000 ? 1024 * 1024 : 2 * 1024 * 1024);
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
        int ts_enable = 1;
        if (setsockopt(recv_sock, SOL_SOCKET, SO_TIMESTAMP, &ts_enable, sizeof(ts_enable)) < 0) {
            std::cerr << "SO_TIMESTAMP unavailable, RTT may include pacing delays\n";
        }
    }
    {
        int fl = fcntl(recv_sock, F_GETFL, 0);
        if (fl < 0 || fcntl(recv_sock, F_SETFL, fl | O_NONBLOCK) < 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "fcntl(O_NONBLOCK) failed: " << strerror(errno) << std::endl;
            close(recv_sock);
            return;
        }
    }

    int icmp_err_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_err_sock >= 0) {
        int icmp_fl = fcntl(icmp_err_sock, F_GETFL, 0);
        if (icmp_fl >= 0) fcntl(icmp_err_sock, F_SETFL, icmp_fl | O_NONBLOCK);
        int icmp_rcvbuf = 1 * 1024 * 1024;
        setsockopt(icmp_err_sock, SOL_SOCKET, SO_RCVBUF,
                   &icmp_rcvbuf, sizeof(icmp_rcvbuf));
    }
    // ─────────────────────────────────────────────────────────────────────────

    size_t rcv_queue_depth = rcv_uring_depth > 0
        ? rcv_uring_depth
        : std::min<size_t>(128, std::max<size_t>(32, ports.size() / 4));

    struct io_uring recv_ring;
    if (io_uring_queue_init(rcv_queue_depth, &recv_ring, IORING_SETUP_COOP_TASKRUN) < 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "io_uring_queue_init failed: " << strerror(errno) << std::endl;
        close(recv_sock);
        return;
    }

    static constexpr size_t SLOT_SIZE = 4096;
    const size_t RCV_RING_SLOTS = std::min<size_t>(rcv_queue_depth - 1,
                                  std::max<size_t>(8, rcv_queue_depth));

    std::unique_ptr<uint8_t[]> recv_buf_storage(new uint8_t[RCV_RING_SLOTS * SLOT_SIZE]());
    uint8_t* recv_bufs = recv_buf_storage.get();

    std::vector<SlotMeta> slots(RCV_RING_SLOTS);
    
    for (const auto& range : batches) {
        if (terminate_flag) break;
        if (range.start >= range.end) continue;
        std::span<const int> batch_ports(ports.data() + range.start, range.end - range.start);
        size_t scan_batch_size = std::min(effective_batch_size, batch_ports.size());
        if (is_threaded) {
            tl_port_output_buf = &result.output_buffer;
        }
        RecPross batch_result = receive_response(ip, batch_ports, effective_src_ip, timeout_ms, rng, pool, 
                                 send_sock, source_port, seq_num, win_size, print_individual_closed_filtered, print_filtered_if_few,send_ring, fast_scan, scan_batch_size, scan_type,
                                 custom_ttl,custom_dscp,custom_ip_flags, ip_id_mode, fixed_ip_id,use_manual_tcp_checksum, manual_tcp_checksum,window_scale, mss_value, timestamp_val,
                                 timestamp_ecr_custom, nops_count, sack_permitted,custom_data, data_length, use_custom_data, generate_random_data,
                                 use_badsum, custom_badsum_value, use_partial_badsum,partial_badsum_type, use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random, tfo_cookie_str, tfo_cookie_num, 
                                 tfo_cookie_length,debug_rtt,debug_ttl,use_fragmentation, frag_size, mtu_size,frag_out_of_order,frag_overlap, frag_overlap_bytes,frag_zof,sport_range_min,   
                                 sport_range_max,initial_rtt_ms,port_timeout_min_ms,port_timeout_max_ms,rate_config,jitter_config,batch_delay_config, use_ip_tos, custom_ip_tos_byte,packet_length_config,recv_sock,
                                 &recv_ring,&slots,recv_bufs);
        if (is_threaded) {
            tl_port_output_buf = nullptr;
        }
                                 
        result.closed_ports += batch_result.closed_ports;
        result.open_ports.insert(result.open_ports.end(), batch_result.open_ports.begin(), batch_result.open_ports.end());
        result.filtered_ports.insert(result.filtered_ports.end(), batch_result.filtered_ports.begin(), batch_result.filtered_ports.end());
        // Merge ICMP filter reasons from this batch into the overall result
        result.icmp_filter_reasons.insert(
            batch_result.icmp_filter_reasons.begin(),
            batch_result.icmp_filter_reasons.end());
        if (!batch_result.mac_address.empty() && result.mac_address.empty()) {
            result.mac_address = batch_result.mac_address;
        }
        result.packet_details.insert(batch_result.packet_details.begin(), batch_result.packet_details.end());
        if (batch_result.learned_rtt_ms > result.learned_rtt_ms) {
            result.learned_rtt_ms = batch_result.learned_rtt_ms;
        }
        result.packets_sent += batch_result.packets_sent;
        result.rtt_debug_entries.insert(result.rtt_debug_entries.end(),
            batch_result.rtt_debug_entries.begin(), batch_result.rtt_debug_entries.end());
            
        
        if (result.received_ttl == 0 && batch_result.received_ttl != 0)
            result.received_ttl = batch_result.received_ttl;
        if (batch_delay_config.enabled && !terminate_flag) {
            uint64_t sleep_us = 0;
            if (batch_delay_config.random_mode || batch_delay_config.range_mode) {
                std::uniform_int_distribution<uint64_t> dist(
                    batch_delay_config.min_us,
                    batch_delay_config.max_us
                );
                sleep_us = dist(rng);
            } else {
                sleep_us = batch_delay_config.delay_us;
            }
            if (sleep_us > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(sleep_us));
            }
        }
    }
    
    io_uring_queue_exit(&recv_ring);
    close(recv_sock);
    if (icmp_err_sock >= 0) { close(icmp_err_sock); icmp_err_sock = -1; } 
    
    if (result.filtered_ports.size() > 0 && result.filtered_ports.size() <= 4) {
        const auto& service_map = read_services_from_file("services");
        for (uint16_t fport : result.filtered_ports) {
            std::string fsvc = service_map.count(fport) ? service_map.at(fport) : "unknown";
            std::string icmp_note;
            auto rit = result.icmp_filter_reasons.find(fport);
            if (rit != result.icmp_filter_reasons.end()) {
                switch (rit->second) {
                    case IcmpFilterReason::NetAdminProhibited:
		        icmp_note = "Net-admin-prohibited"
				    " (" + color::red + "ACL/router policy blocks subnet" + color::reset + ")";
		        break;
		    case IcmpFilterReason::HostAdminProhibited:
		        icmp_note = "Host-admin-prohibited"
				    " (" + color::red + "host firewall/ACL denies this IP" + color::reset + ")";
		        break;
		    case IcmpFilterReason::CommAdminProhibited:
		        icmp_note = "Comm-admin-prohibited"
				    " (" + color::red + "iptables REJECT / firewall policy" + color::reset + ")";
		        break;
		    default:
		        break;
                }
            }
            if (is_threaded) {
                result.output_buffer += capture_output(PrintOutputType::PORT_RESULT,
                    "", fport, "filtered", fsvc, scan_name,
                    0, 0, 0, 0, 0, 0, "", "", 0.0,
                    icmp_note, false, true);
            } else {
                print_output(PrintOutputType::PORT_RESULT,
                    "", fport, "filtered", fsvc, scan_name,
                    0, 0, 0, 0, 0, 0, "", "", 0.0,
                    icmp_note, false, true);
            }
        }
    }

    {
        std::string layer3_reason;
	for (uint16_t fport : result.filtered_ports) {
	    auto rit = result.icmp_filter_reasons.find(fport);
	    if (rit != result.icmp_filter_reasons.end()) {
		std::string icmp_note;
		switch (rit->second) {
		    case IcmpFilterReason::NetAdminProhibited:
		        icmp_note = "Net-admin-prohibited"
		                    " (" + color::red + "ACL/router policy blocks subnet" + color::reset + ")";
		        break;
		    case IcmpFilterReason::HostAdminProhibited:
		        icmp_note = "Host-admin-prohibited"
		                    " (" + color::red + "host firewall/ACL denies this IP" + color::reset + ")";
		        break;
		    case IcmpFilterReason::CommAdminProhibited:
		        icmp_note = "Comm-admin-prohibited"
		                    " (" + color::red + "iptables REJECT / firewall policy" + color::reset + ")";
		        break;
		    default:
		        break;
		}
		if (!icmp_note.empty()) {
		    layer3_reason = "Reason         : " + icmp_note + " (port " + std::to_string(fport) + ")\n";
		}
		break;
	    }
	}

	std::string pkt_line = "\n" + layer3_reason
                             + "Packets sent   : " + std::to_string(result.packets_sent) + "\n";
        if (is_threaded) {
            result.output_buffer += pkt_line;
        } else {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << pkt_line;
        }
    }

    if (!terminate_flag && ports.size() > 1) {
        if (is_threaded) {
            result.output_buffer += capture_output(PrintOutputType::SCAN_SUMMARY, ip, 0, "", "", scan_name,
                                                   0, 0, result.open_ports.size(), result.closed_ports,
                                                   result.filtered_ports.size(), 0, "", "", 0.0, "", false, true);
        } else {
            print_output(PrintOutputType::SCAN_SUMMARY, ip, 0, "", "", scan_name,
                         0, 0, result.open_ports.size(), result.closed_ports,
                         result.filtered_ports.size(), 0, "", "", 0.0, "", false, true);
        }
    }
    

}

void print_rtt_debug(const std::vector<std::pair<int,double>>& entries) {
    if (entries.empty()) return;
    std::lock_guard<std::mutex> lock(cout_mutex);

    std::cout << color::dim << "RTT debug\n" << color::reset;

    const size_t INLINE_THRESHOLD = 10;

    if (entries.size() <= INLINE_THRESHOLD) {
        for (size_t i = 0; i < entries.size(); ++i) {
            int rtt_int = static_cast<int>(entries[i].second);
            if (entries[i].second > 0 && rtt_int == 0) rtt_int = 1;
            std::cout << "  port " << entries[i].first << "/tcp"
                      << "  ewma=" << std::fixed << std::setprecision(3)
                      << entries[i].second << "ms  int=" << rtt_int << "ms\n";
        }
    } else {
        // stats logic unchanged — only output lines change
        double min_rtt = entries[0].second, max_rtt = entries[0].second, sum_rtt = 0.0;
        int min_port = entries[0].first, max_port = entries[0].first;

        for (const auto& e : entries) {
            if (e.second < min_rtt) { min_rtt = e.second; min_port = e.first; }
            if (e.second > max_rtt) { max_rtt = e.second; max_port = e.first; }
            sum_rtt += e.second;
        }
        double avg_rtt = sum_rtt / static_cast<double>(entries.size());

        int avg_port = entries[0].first;
        double avg_closest = entries[0].second;
        double best_delta = std::abs(entries[0].second - avg_rtt);
        for (const auto& e : entries) {
            double delta = std::abs(e.second - avg_rtt);
            if (delta < best_delta) { best_delta = delta; avg_port = e.first; avg_closest = e.second; }
        }

        int min_int = static_cast<int>(min_rtt); if (min_rtt > 0 && min_int == 0) min_int = 1;
        int max_int = static_cast<int>(max_rtt); if (max_rtt > 0 && max_int == 0) max_int = 1;
        int avg_int = static_cast<int>(avg_closest); if (avg_closest > 0 && avg_int == 0) avg_int = 1;

        std::cout << std::left
                  << std::setw(12) << "  Sampled"  << ": " << entries.size() << " ports\n"
                  << std::setw(12) << "  Min ewma" << ": port " << min_port << "/tcp  "
                  << std::fixed << std::setprecision(3) << min_rtt << "ms  (int=" << min_int << "ms)\n"
                  << std::setw(12) << "  Avg ewma" << ": port " << avg_port << "/tcp  "
                  << avg_closest << "ms  (int=" << avg_int << "ms)\n"
                  << std::setw(12) << "  Max ewma" << ": port " << max_port << "/tcp  "
                  << max_rtt << "ms  (int=" << max_int << "ms)\n";
    }
}



