#include "utils.hpp"
#include <linux/filter.h>   
#include "public_db.hpp"
#include "scan.hpp"
#include "anomaly_analysis.hpp"
#include <queue>
#include <stdexcept>
#include <netinet/ip_icmp.h>
#include <unordered_set>
#include <array>
#include <curl/curl.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <bitset>
#include <array>
#include <shared_mutex>
#include <bitset>

#ifdef __AVX2__
#include <immintrin.h>  
#else
#include <emmintrin.h>  
#endif

// Add this function:
void reset_network_disconnect_flag() {
    if (network_disconnect_flag.exchange(false)) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "[INFO] Network disconnect flag reset for new target\n";
    }
}

// ── FIX (RTT accuracy) ───────────────────────────────────────────────────
// The old implementation called system_clock::now() and steady_clock::now()
// *inside* this function on every single packet, deriving the steady<->system
// offset fresh each time. Those two now() calls are not atomic with each
// other — under load (exactly when you're scanning fast) the scheduler can
// preempt the thread between them, so the "offset" carried anywhere from
// sub-microsecond to multi-millisecond scheduling jitter. That jitter fed
// straight into every RTT sample derived from a kernel RX timestamp, which
// is why RTT looked noisy/biased especially under load or with many targets.
//
// Fix: calibrate the offset ONCE (thread-safe static init, best-of-8
// back-to-back sample to minimize the calibration error itself), then reuse
// that fixed offset for the process lifetime. No more per-packet jitter.
inline int64_t steady_minus_system_offset_ns() {
    static const int64_t offset_ns = [] {
        int64_t best_gap_ns = std::numeric_limits<int64_t>::max();
        int64_t best_offset_ns = 0;
        for (int i = 0; i < 8; ++i) {
            auto s1  = std::chrono::steady_clock::now();
            auto sys = std::chrono::system_clock::now();
            auto s2  = std::chrono::steady_clock::now();
            int64_t gap_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(s2 - s1).count();
            if (gap_ns < best_gap_ns) {
                best_gap_ns = gap_ns;
                int64_t s_mid_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        s1.time_since_epoch()).count() + gap_ns / 2;
                int64_t sys_ns   = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        sys.time_since_epoch()).count();
                best_offset_ns = s_mid_ns - sys_ns;   // steady_ns = system_ns + offset
            }
        }
        return best_offset_ns;
    }();
    return offset_ns;
}

inline std::chrono::steady_clock::time_point steady_from_system(
        std::chrono::system_clock::time_point system_tp) {
    int64_t system_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             system_tp.time_since_epoch()).count();
    int64_t steady_ns = system_ns + steady_minus_system_offset_ns();
    return std::chrono::steady_clock::time_point(
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::nanoseconds(steady_ns)));
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
std::mutex sent_debug_mutex;
std::vector<SentPacketDetails> sent_debug_log;
thread_local std::string* tl_port_output_buf = nullptr;
std::atomic<bool> recv_error_logged(false);
std::atomic<bool> network_disconnect_flag(false);  // NEW: set on network loss
std::atomic<bool> g_send_fixed_file_active(false);  // set by init_global_send_ctx()
using json = nlohmann::json;

thread_local moodycamel::ConcurrentQueue<char*> PacketBufferPool::buffer_queue;
thread_local std::vector<char> PacketBufferPool::slab;
thread_local char* PacketBufferPool::slab_start = nullptr;
thread_local char* PacketBufferPool::slab_end = nullptr;
const size_t PacketBufferPool::buffer_size;


PacketBufferPool::PacketBufferPool(size_t ports, size_t num_threads, size_t batch_size) : 
    pool_size(get_buffer_count(ports, num_threads, batch_size)), 
    max_buffers(get_max_buffer_count(ports, num_threads, batch_size)), 
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

size_t PacketBufferPool::get_buffer_count(size_t ports, size_t num_threads, size_t batch_size) {
    num_threads = (num_threads == 0) ? get_hardware_concurrency_or_default() : num_threads;
    const size_t MIN_BUFFERS_PER_THREAD = 256;
    const size_t MAX_BUFFERS_PER_THREAD = 512;
    double scale_factor = std::log2(ports + 1);
    size_t buffers_based_on_ports = static_cast<size_t>(scale_factor * 20);
    size_t buffers_per_thread = std::clamp(
        buffers_based_on_ports / num_threads,
        MIN_BUFFERS_PER_THREAD,
        MAX_BUFFERS_PER_THREAD
    );
    size_t min_required = std::min(ports / num_threads + 1, size_t(128));
    buffers_per_thread = std::max(buffers_per_thread, min_required);
    // batch can never realistically exceed the number of ports scanned,
    // so size against whichever is actually smaller — avoids over-allocating
    // for a small scan just because -b was left at a large default/ceiling.
    size_t effective_batch = std::min(batch_size, ports);
    buffers_per_thread = std::max(buffers_per_thread, effective_batch * 2);
    return buffers_per_thread * num_threads;
}

size_t PacketBufferPool::get_max_buffer_count(size_t ports, size_t num_threads, size_t batch_size) {
    const double PEAK_FACTOR = 1.3;
    size_t base_count = get_buffer_count(ports, num_threads, batch_size);
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

    // NEW:
    auto format_time = []() -> std::string {
        time_t now = time(nullptr);
        struct tm t;
        localtime_r(&now, &t);  // Thread-safe version
        char buf[100];
        strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &t);
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

        // ── OVERALL_HEADER ───────────────────────────────────────────────────
        // Called for multi-IP scans before the loop starts.
        // nmap style: "Starting Shiv at <timestamp>"
        case PrintOutputType::OVERALL_HEADER: {
            if (print_timestamp) {
                std::cout << "\n" << "Starting " << color::bold << "Shiv" << color::reset
                          << " (" << color::yellow << scan_name << color::reset << ") at "
                          << format_time();
            }
            break;
        }

        // ── SCAN_HEADER ──────────────────────────────────────────────────────
        // Called for single-IP scans (fires instead of OVERALL_HEADER).
        // Same banner.
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

        // ── CPU_TIME ─────────────────────────────────────────────────────────
        // "CPU Time          : 0.11s (user+sys, via getrusage)"
        // elapsed_seconds here carries CPU-seconds (user+sys from getrusage),
        // NOT wall-clock — this is the efficiency metric, distinct from
        // Duration above which is wall-clock (the speed/responsiveness metric).
        // They intentionally diverge: SQPOLL, thread count, and spin-wait
        // tuning move this number without necessarily moving Duration.
        case PrintOutputType::CPU_TIME: {
            std::cout << std::left << std::setw(15) << "CPU Time"
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
            std::cout << "\n" << color::bold << scan_name << color::reset
                      << " done: " << host_count
                      << " IP address" << (host_count != 1 ? "es" : "")
                      << " scanned"
                      << "  |  " << color::green << open_count << " open"  << color::reset
                      << "  " << color::red << closed_count << " closed" << color::reset
                      << "  " << color::yellow << filtered_count << " filtered" << color::reset
                      << "\n\n";
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

// NEW:
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
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::streambuf* old_buf = std::cout.rdbuf(oss.rdbuf());
        print_output(type, ip, port, state, service, scan_name, window_size,
                     port_count, open_count, closed_count, filtered_count,
                     host_count, mac_address, vendor, elapsed_seconds,
                     not_shown_message, print_timestamp, show_service);
        std::cout.rdbuf(old_buf);
    }
    return oss.str();
}

bool set_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4], const uint8_t mac[6]) {
    if (!ifname || !ip_bytes || !mac) return false;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        std::cerr << "set_static_arp_entry: socket() failed: " << strerror(errno) << "\n";
        return false;
    }

    struct arpreq req{};
    auto* pa = reinterpret_cast<sockaddr_in*>(&req.arp_pa);
    pa->sin_family = AF_INET;
    memcpy(&pa->sin_addr, ip_bytes, 4);

    req.arp_ha.sa_family = ARPHRD_ETHER;
    memcpy(req.arp_ha.sa_data, mac, 6);

    // ATF_COM: entry is "complete" (has a valid hw address), so the kernel
    // will use it as-is. ATF_PERM: never age it out / never re-ARP for it.
    req.arp_flags = ATF_COM | ATF_PERM;

    std::strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);
    req.arp_dev[sizeof(req.arp_dev) - 1] = '\0';

    bool ok = (ioctl(s, SIOCSARP, &req) == 0);
    if (!ok) {
        char ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, ip_bytes, ip_str, sizeof(ip_str));
        std::cerr << "set_static_arp_entry: failed to pin " << ip_str
                  << " -> " << format_mac(mac) << " on " << ifname
                  << ": " << strerror(errno)
                  << " (need root/CAP_NET_ADMIN)\n";
    }
    close(s);
    return ok;
}

void delete_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4]) {
    if (!ifname || !ip_bytes) return;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct arpreq req{};
    auto* pa = reinterpret_cast<sockaddr_in*>(&req.arp_pa);
    pa->sin_family = AF_INET;
    memcpy(&pa->sin_addr, ip_bytes, 4);

    std::strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);
    req.arp_dev[sizeof(req.arp_dev) - 1] = '\0';

    // Best-effort cleanup — don't leave a permanent, possibly-spoofed ARP
    // entry sitting in the operator's kernel table after the scan exits.
    ioctl(s, SIOCDARP, &req);
    close(s);
}

bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                      uint8_t* src_mac, uint8_t* src_ip, 
                      const std::vector<uint8_t*>& target_IPs,
                      const EthArpOptions& eth_opts) {
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
    const size_t vlan_bytes  = eth_opts.vlan_ids.size() * 4;      // items 4/5: 4B per 802.1Q tag
    const size_t eth_hdr_len = 12 + vlan_bytes + 2;               // dst(6)+src(6)+tags+ethertype(2)
    const size_t PACKET_SIZE = eth_hdr_len + sizeof(arp_header) + eth_opts.padding_size; // item 7
    std::vector<uint8_t> packet_template(PACKET_SIZE, 0);

    uint8_t* eth_ptr = packet_template.data();
    memset(eth_ptr, 0xFF, 6);                                     // dst_mac = broadcast
    memcpy(eth_ptr + 6, eth_opts.use_custom_src_mac ? eth_opts.custom_src_mac : src_mac, 6); // item 2
    size_t off = 12;
    for (uint16_t vid : eth_opts.vlan_ids) {                      // items 4/5
        uint16_t tpid = htons(0x8100);
        uint16_t tci  = htons(vid & 0x0FFF);
        memcpy(eth_ptr + off, &tpid, 2); off += 2;
        memcpy(eth_ptr + off, &tci,  2); off += 2;
    }
    uint16_t final_ethertype = htons(eth_opts.use_custom_ethertype ? eth_opts.custom_ethertype : ETH_P_ARP); // item 1
    memcpy(eth_ptr + off, &final_ethertype, 2);
    off += 2;   // off == eth_hdr_len now

    auto* arp = reinterpret_cast<arp_header*>(packet_template.data() + eth_hdr_len);

    arp->htype = htons(1);           
    arp->ptype = htons(ETH_P_IP);    
    arp->hlen = 6;                   
    arp->plen = 4;                   
    uint16_t op_code = (eth_opts.arp_mode == ArpOpMode::REPLY) ? 2 : 1;   // gratuitous still opcode 1
    arp->opcode = htons(op_code);         
    memcpy(arp->src_mac, src_mac, 6);
    memcpy(arp->src_ip, src_ip, 4);
    if (eth_opts.arp_mode == ArpOpMode::GRATUITOUS) {
        memcpy(arp->dst_ip, src_ip, 4);   // gratuitous ARP announces our own IP as target
    }
    
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
	    if (target_IPs[batch_start + i][0] == 0 && 
		target_IPs[batch_start + i][1] == 0 && 
		target_IPs[batch_start + i][2] == 0 && 
		target_IPs[batch_start + i][3] == 0) {
		std::cerr << "send_arp_request: Skipping packet with zero target IP\n";
		continue;
	    }
	    
	    uint8_t* pkt_ptr = batch_buffer + i * PACKET_SIZE;
	    memcpy(pkt_ptr, packet_template.data(), PACKET_SIZE);
	    arp_header* batch_arp = reinterpret_cast<arp_header*>(pkt_ptr + eth_hdr_len);
	    memcpy(batch_arp->dst_ip, target_IPs[batch_start + i], 4);
	    if (eth_opts.padding_size > 0 && eth_opts.random_padding) {
	        uint8_t* pad = pkt_ptr + eth_hdr_len + sizeof(arp_header);
	        for (uint16_t k = 0; k < eth_opts.padding_size; k++) pad[k] = static_cast<uint8_t>(rand() & 0xFF);
	    }
	    
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
                      const std::vector<uint8_t*>& target_IPs,std::vector<uint8_t*>& macs,
                      const EthArpOptions& eth_opts, int timeout_ms) {
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
    const size_t vlan_bytes_rx  = eth_opts.vlan_ids.size() * 4;
    const size_t eth_hdr_len_rx = 12 + vlan_bytes_rx + 2;
    const size_t MIN_PACKET_SIZE = eth_hdr_len_rx + sizeof(arp_header);
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
                        size_t rx_off = 12;
                        uint16_t rx_ethertype;
                        memcpy(&rx_ethertype, received_buffer + rx_off, 2);
                        rx_ethertype = ntohs(rx_ethertype);
                        // Unwrap up to 2 stacked 802.1Q tags (items 4/5) if present on the wire.
                        for (int tag_i = 0; tag_i < 2 && rx_ethertype == 0x8100; tag_i++) {
                            rx_off += 4;
                            memcpy(&rx_ethertype, received_buffer + rx_off, 2);
                            rx_ethertype = ntohs(rx_ethertype);
                        }
                        rx_off += 2;
                        if (rx_ethertype == ETH_P_ARP) {
                            struct arp_header* arp = reinterpret_cast<struct arp_header*>(
                                received_buffer + rx_off);
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
                // SQ ring full — drain one pending CQE to free an SQE slot,
                // then let the outer loop retry io_uring_get_sqe next iteration.
                // 10 ms timeout matches the original worst-case sleep duration.
                struct io_uring_cqe* drain_cqe = nullptr;
                struct __kernel_timespec drain_ts = {
                    .tv_sec  = 0,
                    .tv_nsec = 10 * 1000 * 1000   // 10 ms
                };
                int drain_ret = io_uring_wait_cqe_timeout(ring, &drain_cqe, &drain_ts);
                if (drain_ret == 0 && drain_cqe) {
                    // This CQE is from our earlier recvmsg — we're in the
                    // !receive_pending branch so it's already been handled;
                    // just release it to free the CQE slot.
                    io_uring_cqe_seen(ring, drain_cqe);
                }
                // Loop continues; io_uring_get_sqe will succeed next iteration.
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
    static std::shared_mutex cache_mutex;

    struct in_addr addr{};
    if (inet_pton(AF_INET, remote_ip, &addr) <= 0) return 0;

    // Use first 3 octets as subnet key (cache per /24)
    uint32_t subnet_key = ntohl(addr.s_addr) >> 8;

    {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
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

    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    local_ip_cache[subnet_key] = result;
    return result;
}

bool build_packet(const PacketTask& task, char* packet_buffer, size_t buffer_size,
                  uint32_t src_ip, std::mt19937& rng, uint16_t ip_id, uint16_t win_size,
                  uint8_t ttl, uint8_t dscp, uint16_t ip_flags,
                  const TcpBuildOptions& opts,
                  size_t& packet_len_out, uint16_t& effective_frag_out,
                  bool debug_send = false) {

    // Local aliases: same names the body below has always used, now backed
    // by the shared opts struct instead of ~26 individual parameters.
    const bool&        use_ip_tos              = opts.use_ip_tos;
    const uint8_t&     custom_ip_tos_byte      = opts.custom_ip_tos_byte;
    const bool&        use_manual_tcp_checksum = opts.use_manual_tcp_checksum;
    const uint16_t&    manual_tcp_checksum     = opts.manual_tcp_checksum;
    const uint8_t&     window_scale            = opts.window_scale;
    const uint16_t&    mss_value               = opts.mss_value;
    const uint32_t&    timestamp_val           = opts.timestamp_val;
    const uint32_t&    timestamp_ecr_custom    = opts.timestamp_ecr_custom;
    const uint16_t&    nops_count              = opts.nops_count;
    const bool&        sack_permitted          = opts.sack_permitted;
    const std::string& custom_data             = opts.custom_data;
    const uint16_t&    data_length             = opts.data_length;
    const bool&        use_custom_data         = opts.use_custom_data;
    const bool&        generate_random_data    = opts.generate_random_data;
    const bool&        use_badsum              = opts.use_badsum;
    const uint16_t&    custom_badsum_value     = opts.custom_badsum_value;
    const bool&        badsum_value_set        = opts.badsum_value_set;
    const bool&        use_partial_badsum      = opts.use_partial_badsum;
    const std::string& partial_badsum_type     = opts.partial_badsum_type;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;
    const bool&        use_fragmentation       = opts.use_fragmentation;
    const uint16_t&    frag_size               = opts.frag_size;
    const uint16_t&    mtu_size                = opts.mtu_size;
    const PacketLengthConfig& packet_length_config = opts.packet_length_config;
    const bool&    use_tcp_mptcp              = opts.use_tcp_mptcp;
    const bool&    use_tcp_ao                 = opts.use_tcp_ao;
    const uint8_t& tcp_ao_keyid               = opts.tcp_ao_keyid;
    const uint8_t& tcp_ao_rnextkeyid          = opts.tcp_ao_rnextkeyid;
    const uint8_t& tcp_ao_mac_len             = opts.tcp_ao_mac_len;
    const bool&    use_ip_router_alert        = opts.use_ip_router_alert;
    const bool&    use_ip_security            = opts.use_ip_security;
    const uint8_t& ip_security_classification = opts.ip_security_classification;

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

    // ── IP options (Router Alert / IP Security) ──────────────────────────
    static constexpr size_t IP_OPTIONS_CAP = 40;   // max header is 60 bytes = 20 + 40
    uint8_t ip_options[IP_OPTIONS_CAP];
    size_t  ip_opt_len = 0;

    if (use_ip_router_alert && ip_opt_len + 4 <= IP_OPTIONS_CAP) {
        ip_options[ip_opt_len++] = 0x94;   // copied=1, class=0, number=20 (Router Alert)
        ip_options[ip_opt_len++] = 0x04;   // length
        ip_options[ip_opt_len++] = 0x00;   // value: 0 = "router shall examine packet"
        ip_options[ip_opt_len++] = 0x00;
    }

    if (use_ip_security && ip_opt_len + 11 <= IP_OPTIONS_CAP) {
        ip_options[ip_opt_len++] = 0x82;   // copied=1, class=0, number=2 (Security, RFC1108)
        ip_options[ip_opt_len++] = 0x0B;   // length = 11
        ip_options[ip_opt_len++] = ip_security_classification;
        for (int i = 0; i < 8; ++i)        // protection-authority flags + padding
            ip_options[ip_opt_len++] = 0x00;
    }

    while (ip_opt_len % 4 != 0 && ip_opt_len < IP_OPTIONS_CAP)
        ip_options[ip_opt_len++] = 0x01;   // NOP pad to 32-bit boundary (RFC 791)

    const size_t ip_hdr_len = sizeof(struct ip) + ip_opt_len;   // 20, 24, 28...

    if (buffer_size < ip_hdr_len + sizeof(struct tcphdr))
        return false;

    struct ip     *iph  = (struct ip *)packet_buffer;
    struct tcphdr *tcph = (struct tcphdr *)(packet_buffer + ip_hdr_len);
    memcpy(iph,  templates.ip_base,  sizeof(templates.ip_base));
    memcpy(tcph, templates.tcp_base, sizeof(templates.tcp_base));
    if (ip_opt_len > 0)
        memcpy(packet_buffer + sizeof(struct ip), ip_options, ip_opt_len);
    iph->ip_hl  = static_cast<uint8_t>(ip_hdr_len / 4);
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
    
    bool add_mptcp = use_tcp_mptcp;
    if (add_mptcp && opt_len + 12 <= MAX_TCP_OPTIONS_SIZE && opt_len + 12 <= OPTIONS_STACK_CAP) {
        options[opt_len++] = 30;                 // Kind: MPTCP
        options[opt_len++] = 12;                 // Length: MP_CAPABLE, sender key only
        options[opt_len++] = 0x01;               // Subtype=0(MP_CAPABLE) | Version=1
        options[opt_len++] = 0x00;               // Flags
        uint64_t sender_key = (static_cast<uint64_t>(rng()) << 32) | rng();
        for (int i = 56; i >= 0; i -= 8)
            options[opt_len++] = static_cast<uint8_t>((sender_key >> i) & 0xFF);
    }

    bool add_tcp_ao = use_tcp_ao;
    if (add_tcp_ao) {
        size_t ao_total = 4 + tcp_ao_mac_len;
        if (opt_len + ao_total <= MAX_TCP_OPTIONS_SIZE && opt_len + ao_total <= OPTIONS_STACK_CAP) {
            options[opt_len++] = 29;                              // Kind: TCP-AO
            options[opt_len++] = static_cast<uint8_t>(ao_total);  // Length
            options[opt_len++] = tcp_ao_keyid;
            options[opt_len++] = tcp_ao_rnextkeyid;
            for (uint8_t i = 0; i < tcp_ao_mac_len; ++i)
                options[opt_len++] = static_cast<uint8_t>(rng());  // placeholder MAC — no real key material, this is a probe not a real authenticated session
        }
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
                for (size_t i = 0; i < actual_generation; ++i)
    		    cookie_data[cookie_len++] = static_cast<uint8_t>(rng());
            } else {
                if (req_len == 0) req_len = 8;
                if (req_len > 253 && !intentional_malformed) req_len = 253;

                size_t space = MAX_TCP_OPTIONS_SIZE - opt_len - 3;
                space        = std::min(space, OPTIONS_STACK_CAP);
                req_len      = std::min(req_len, space);

                for (size_t i = 0; i < req_len; ++i)
                    cookie_data[cookie_len++] = static_cast<uint8_t>(rng());
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
            for (size_t i = 0; i < default_len; ++i)
    		cookie_data[cookie_len++] = static_cast<uint8_t>(rng());
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
        for (uint16_t i = 0;
	     i < data_length &&
	     i < (buffer_size - sizeof(struct ip) - sizeof(struct tcphdr) - opt_len);
	     ++i)
	    payload += chars[rng() % chars.size()];
    } else if (!task.data.empty()) {
        payload = task.data;
    }

    size_t options_len      = opt_len;
    size_t data_len         = payload.length();
    size_t total_packet_len = ip_hdr_len + sizeof(struct tcphdr)
                        + options_len + data_len;

    if (total_packet_len > buffer_size) {
        if (intentional_malformed) {
            size_t max_options =
    		buffer_size - (ip_hdr_len + sizeof(struct tcphdr) + data_len);
            if (max_options > 0) {
                options_len     = std::min(options_len, max_options);
                total_packet_len = ip_hdr_len + sizeof(struct tcphdr)
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
        uint16_t raw_step;
        if (mtu_size > 0) {
            // MTU path: must be RFC 791 compliant (8-byte aligned)
            raw_step = static_cast<uint16_t>(mtu_size - 20);
            raw_step = static_cast<uint16_t>((raw_step / 8) * 8);
            if (raw_step < 8) raw_step = 8;
        } else {
            // Explicit frag_size: allow experimental sub-8 sizes (2, 4, 6)
            raw_step = frag_size;
            raw_step = static_cast<uint16_t>((raw_step / 2) * 2);
            if (raw_step < 2) raw_step = 2;
        }
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
        if (ip_hdr_len + sizeof(struct tcphdr) + options_len <= buffer_size)
            memcpy(packet_buffer + ip_hdr_len + sizeof(struct tcphdr),
                   options, options_len);
    }
    if (data_len > 0) {
        size_t payload_offset = ip_hdr_len + sizeof(struct tcphdr) + options_len;
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
        if (badsum_value_set)
            tcph->th_sum = htons(custom_badsum_value);
        else {
            static const uint16_t bad_patterns[] =
                {0x0000, 0xFFFF, 0x1234, 0x5678, 0x9ABC, 0xDEF0, 0xBEEF, 0xDEAD};
            std::uniform_int_distribution<size_t> dist(0, std::size(bad_patterns) - 1);
            tcph->th_sum = htons(bad_patterns[dist(rng)]);
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
    
    // ── --packet-length enforcement (MUST be after checksum) ─────────────
    if (packet_length_config.enabled) {
        // Floor: never allowed to shrink into the IP header or the fixed
        // 20-byte TCP header -- only options/payload may be removed.
        // Already accounts for IP options if any are in use.
        const size_t MIN_PKT = ip_hdr_len + sizeof(struct tcphdr);
        const size_t MAX_PKT = buffer_size;
        // Boundary between "header+options" and "payload" in the buffer
        // we already built. A shrink target at or above this line only
        // eats into payload, so th_off needs no change.
        const size_t header_and_options_end =
            ip_hdr_len + sizeof(struct tcphdr) + options_len;

        const size_t target = packet_length_config.target_len;

        auto recompute_tcp_checksum = [&](size_t new_tcp_len) {
	    tcph->th_sum = 0;
	    struct { uint32_t s, d; uint8_t z, p; uint16_t l; }
		__attribute__((packed))
		psh2 = { src_ip, task.dest.sin_addr.s_addr,
		         0, IPPROTO_TCP,
		         htons(static_cast<uint16_t>(new_tcp_len)) };
	    uint32_t sum = 0;
	    uint8_t* raw = reinterpret_cast<uint8_t*>(&psh2);
	    for (size_t k = 0; k + 1 < sizeof(psh2); k += 2) {
		uint16_t w; memcpy(&w, raw + k, 2); sum += w;
	    }
	    uint8_t* tdata = reinterpret_cast<uint8_t*>(tcph);
	    for (size_t k = 0; k + 1 < new_tcp_len; k += 2) {
		uint16_t w; memcpy(&w, tdata + k, 2); sum += w;
	    }
	    if (new_tcp_len % 2)
		sum += tdata[new_tcp_len - 1] << 8;
	    sum = (sum >> 16) + (sum & 0xFFFF);
	    sum += (sum >> 16);
	    tcph->th_sum = ~static_cast<uint16_t>(sum);
	};

        if (target > total_packet_len) {
            // PAD: grow via trailing zero-byte payload only. Header and
            // options stay exactly as already built, so th_off is still
            // correct and no alignment restriction is needed for any N
            // up to buffer_size.
            size_t new_total = std::min<size_t>(target, MAX_PKT);
            size_t pad = new_total - total_packet_len;
            if (pad > 0 && total_packet_len + pad <= buffer_size) {
                memset(packet_buffer + total_packet_len, 0x00, pad);
                total_packet_len += pad;
                packet_len_out    = total_packet_len;
                recompute_tcp_checksum(total_packet_len - ip_hdr_len);
                iph->ip_len = htons(static_cast<uint16_t>(total_packet_len));
                fprintf(stderr, "[dbg] len=%zu th_sum=0x%04x\n", total_packet_len, ntohs(tcph->th_sum));
            }

        } else if (target < total_packet_len && target >= MIN_PKT) {
            // SHRINK: truncate from the tail. Truncating the tail removes
            // payload bytes before it ever touches TCP options, and the
            // MIN_PKT floor above guarantees the fixed TCP header and the
            // IP header are never reached.
            size_t new_total = target;
            if (new_total < header_and_options_end) {
                // The cut reaches into the options region. th_off counts
                // whole 32-bit words, so round the new header+options
                // length DOWN to a 4-byte boundary and recompute th_off
                // to match -- this is what keeps a shrunk packet from
                // being corrupt regardless of which N was requested.
                size_t new_tcp_header_len = new_total - ip_hdr_len;
                new_tcp_header_len = (new_tcp_header_len / 4) * 4;
                if (new_tcp_header_len < sizeof(struct tcphdr))
                    new_tcp_header_len = sizeof(struct tcphdr);
                new_total = ip_hdr_len + new_tcp_header_len;
                tcph->th_off = static_cast<uint8_t>(new_tcp_header_len / 4);
            }
            // else: cut only removes payload -- th_off already correct.

            total_packet_len = new_total;
            packet_len_out   = total_packet_len;
            recompute_tcp_checksum(total_packet_len - ip_hdr_len);
            iph->ip_len = htons(static_cast<uint16_t>(total_packet_len));
        }
        // target == total_packet_len, or target < MIN_PKT: no-op, packet
        // is left exactly as already built.
    }
    // ── end packet-length ───────────────────────────────────────────────────────────────────────────────────────
    if (debug_send) {
        SentPacketDetails sd;
        sd.dst_ip           = inet_ntoa(task.dest.sin_addr);
        sd.dst_port         = ntohs(task.dest.sin_port);
        sd.src_port         = task.src_port;

        sd.ip_id            = ntohs(iph->ip_id);
        sd.ip_total_length  = ntohs(iph->ip_len);
        sd.ip_header_len    = static_cast<uint8_t>(iph->ip_hl * 4);
        sd.ttl              = iph->ip_ttl;
        sd.ip_tos           = iph->ip_tos;
        sd.df_flag          = (ntohs(iph->ip_off) & IP_DF) != 0;
        sd.mf_flag          = (ntohs(iph->ip_off) & IP_MF) != 0;
        sd.ip_frag_off_raw  = ntohs(iph->ip_off) & 0x1FFF;
        sd.ip_checksum      = ntohs(iph->ip_sum);

        sd.tcp_flags        = tcph->th_flags;
        sd.seq_num          = ntohl(tcph->th_seq);
        sd.ack_num          = ntohl(tcph->th_ack);
        sd.window_size      = ntohs(tcph->th_win);
        sd.tcp_header_len   = static_cast<uint8_t>(tcph->th_off * 4);
        sd.tcp_data_offset  = tcph->th_off;
        sd.tcp_urg_ptr      = ntohs(tcph->th_urp);
        sd.checksum         = ntohs(tcph->th_sum);
        sd.checksum_mode    = use_manual_tcp_checksum ? "manual"
                             : use_badsum              ? "badsum"
                             : use_partial_badsum       ? ("partial-badsum:" + partial_badsum_type)
                                                         : "normal";

        sd.options_len      = opt_len;
        sd.has_mss          = add_mss;         sd.mss_value    = mss_value;
        sd.has_window_scale = add_ws;          sd.window_scale = window_scale;
        sd.sack_permitted   = add_sack;
        sd.has_timestamp    = add_ts;          sd.tsval = timestamp_val; sd.tsecr = timestamp_ecr_custom;
        sd.has_mptcp        = add_mptcp;
        sd.has_tcp_ao       = add_tcp_ao;
        sd.has_tfo          = use_tfo_cookie && task.use_tfo_cookie;

        sd.payload_len      = static_cast<uint16_t>(data_len);
        {
            size_t off  = ip_hdr_len + sizeof(struct tcphdr) + opt_len;
            size_t show = std::min<size_t>(data_len, 16);
            if (off + show <= buffer_size)
                sd.payload_preview.assign(packet_buffer + off, packet_buffer + off + show);
        }

        sd.total_packet_len       = total_packet_len;
        sd.fragmented             = (effective_frag_out != 0);
        sd.frag_step               = effective_frag_out;
        sd.intentional_malformed  = intentional_malformed;
        sd.packet_length_adjusted = packet_length_config.enabled;
        sd.packet_length_target   = packet_length_config.target_len;
        {
            std::lock_guard<std::mutex> lock(sent_debug_mutex);
            sent_debug_log.push_back(std::move(sd));
        }
    }

    return true;
}



int send_tcp_packets(int sock, const std::span<PacketTask> tasks, uint32_t src_ip, 
                     std::mt19937 &rng, PacketBufferPool &pool, uint16_t win_size,struct io_uring *send_ring, size_t batch_size, uint8_t custom_ttl,uint8_t custom_dscp,
                     uint16_t custom_ip_flags,IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                     const TcpBuildOptions& opts,
                     bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,
                     std::function<void(const std::vector<uint16_t>&,const std::vector<uint16_t>&)> on_pre_submit,
                     uint64_t* out_bytes_sent, bool debug_send) {

    // Local aliases: same names the body below has always used, now backed
    // by the shared opts struct instead of ~29 individual parameters.
    const bool&        use_manual_tcp_checksum = opts.use_manual_tcp_checksum;
    const uint16_t&    manual_tcp_checksum     = opts.manual_tcp_checksum;
    const uint8_t&     window_scale            = opts.window_scale;
    const uint16_t&    mss_value               = opts.mss_value;
    const uint32_t&    timestamp_val           = opts.timestamp_val;
    const uint32_t&    timestamp_ecr_custom    = opts.timestamp_ecr_custom;
    const uint16_t&    nops_count              = opts.nops_count;
    const bool&        sack_permitted          = opts.sack_permitted;
    const std::string& custom_data             = opts.custom_data;
    const uint16_t&    data_length             = opts.data_length;
    const bool&        use_custom_data         = opts.use_custom_data;
    const bool&        generate_random_data    = opts.generate_random_data;
    const bool&        use_badsum              = opts.use_badsum;
    const uint16_t&    custom_badsum_value     = opts.custom_badsum_value;
    const bool&        badsum_value_set        = opts.badsum_value_set;
    const bool&        use_partial_badsum      = opts.use_partial_badsum;
    const std::string& partial_badsum_type     = opts.partial_badsum_type;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;
    const bool&        use_fragmentation       = opts.use_fragmentation;
    const uint16_t&    frag_size               = opts.frag_size;
    const uint16_t&    mtu_size                = opts.mtu_size;
    const bool&        use_ip_tos              = opts.use_ip_tos;
    const uint8_t&     custom_ip_tos_byte      = opts.custom_ip_tos_byte;
    const PacketLengthConfig& packet_length_config = opts.packet_length_config;
                     
    struct FragInfo {
        char*    buf;
        size_t   total_len;
        iovec    iov;
        msghdr   msg;
    };
    
    struct BatchFrag {
        char*    buf;
        size_t   total_len;
        iovec    iov;
        msghdr   msg;
        size_t   orig_pkt_idx;
    };

    auto ip_checksum = [](void* buf, size_t len) -> uint16_t {
        uint32_t sum = 0;
        auto* p = static_cast<uint16_t*>(buf);
        while (len > 1) { sum += *p++; len -= 2; }
        if (len) sum += *reinterpret_cast<uint8_t*>(p);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    };
    
    struct ThreadLocalBuffers {
        std::vector<char*>          packets;
        std::vector<struct msghdr>  msgs;
        std::vector<struct iovec>   iovs;
        std::vector<size_t>         packet_lengths;
        std::vector<uint16_t>       frag_steps;
        size_t                      max_capacity = 0;
        // FragMeta slab removed — new TX path uses stack-allocated LocalFrag
        // inside the send loop, so no pre-allocated slab is needed.

        ThreadLocalBuffers() : max_capacity(0) {}

        void ensure_capacity(size_t required) {
            if (required <= max_capacity) return;
            packets.resize(required, nullptr);
            msgs.resize(required);
            iovs.resize(required);
            packet_lengths.resize(required, 0);
            frag_steps.resize(required, 0);
            max_capacity = required;
        }

        void clear() {
            for (size_t i = 0; i < packets.size(); ++i) {
                packets[i] = nullptr;
                frag_steps[i] = 0;
            }
        }

        ~ThreadLocalBuffers() {}
    };
    
    static thread_local ThreadLocalBuffers tls_buffers;
    
    if (tasks.empty()) {
        return 0;
    }
    
    const size_t num_packets = tasks.size();
    int total_sent = 0;
    uint64_t local_bytes_sent = 0;
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
            task, packet, PacketBufferPool::buffer_size, src_ip, rng, ip_id, win_size, ttl, dscp, ip_flags,
            opts, packet_len, frag_step_i, debug_send
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
    
    // ── Batch-build ALL fragments for ALL fragmented packets ──────────────
    // Non-fragmented packets (frag_steps[i] == 0) are untouched here.
    std::vector<BatchFrag> all_batch_frags;
    all_batch_frags.reserve(num_packets * 8);
    bool any_frag_collect_failed = false;

    for (size_t i = 0; i < num_packets; ++i) {
        if (frag_steps[i] == 0) continue;   // skip non-fragmented

        const size_t   ip_hlen    = static_cast<size_t>(
                                 reinterpret_cast<struct ip*>(packets[i])->ip_hl) * 4;
        const size_t   data_total = packet_lengths[i] - ip_hlen;
        const uint16_t step       = frag_steps[i];
        size_t         data_off   = 0;
        bool           first_frag = true;
        bool           collect_failed = false;

        while (data_off < data_total && !terminate_flag) {
            size_t   src_off = data_off;
            uint16_t ip_off_units;
            if (frag_overlap && !first_frag &&
                    frag_overlap_bytes > 0 &&
                    data_off >= frag_overlap_bytes) {
                src_off      = data_off - frag_overlap_bytes;
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
            fiph->ip_len = htons(static_cast<uint16_t>(ip_hlen + chunk));
            uint16_t off_field = ip_off_units;
            if (!is_last) off_field |= static_cast<uint16_t>(IP_MF);
            fiph->ip_off = htons(off_field);
            fiph->ip_sum = 0;
            fiph->ip_sum = ip_checksum(frag_buf, ip_hlen);

            BatchFrag bf;
            bf.buf             = frag_buf;
            bf.total_len       = ip_hlen + chunk;
            bf.iov             = { frag_buf, ip_hlen + chunk };
            bf.msg             = {};
            bf.msg.msg_name    = const_cast<void*>(
                                     static_cast<const void*>(&tasks[i].dest));
            bf.msg.msg_namelen = sizeof(tasks[i].dest);
            bf.msg.msg_iov     = &bf.iov;
            bf.msg.msg_iovlen  = 1;
            bf.orig_pkt_idx    = i;
            all_batch_frags.push_back(bf);

            first_frag = false;
            data_off  += advance;
        }

        // Release original buffer — fragments own the data now
        pool.release(packets[i]);
        packets[i] = nullptr;

        if (collect_failed) {
            // Release only THIS packet's fragments that were just added
            while (!all_batch_frags.empty() &&
                   all_batch_frags.back().orig_pkt_idx == i) {
                pool.release(all_batch_frags.back().buf);
                all_batch_frags.pop_back();
            }
            any_frag_collect_failed = true;
        } else {
            // ── Apply per-packet zof / out-of-order reordering ───────────
            // Find the start index of THIS packet's fragments in all_batch_frags.
            // They were just appended, so scan backward from the end.
            size_t grp_end = all_batch_frags.size();          // past-the-end
            size_t grp_start = grp_end;
            while (grp_start > 0 &&
                   all_batch_frags[grp_start - 1].orig_pkt_idx == i) {
                --grp_start;
            }
            size_t grp_size = grp_end - grp_start;

            if (grp_size > 1) {
                auto grp_begin = all_batch_frags.begin() + grp_start;
                auto grp_end_it = all_batch_frags.begin() + grp_end;

                // frag_zof: move first fragment to end (zero-offset first → last)
                if (frag_zof)
                    std::rotate(grp_begin, grp_begin + 1, grp_end_it);

                // frag_out_of_order: shuffle this packet's fragment group
                if (frag_out_of_order)
                    std::shuffle(grp_begin, grp_end_it, rng);
            }
        }
    }
    
    if (send_ring) {
        // ── Pipelined io_uring send: ring-capacity-aware, non-blocking reap ──
        //
        // SECURITY: we derive the window size from the actual ring depth so
        // io_uring_get_sqe() never returns nullptr mid-loop (that would silently
        // drop packets). We also transfer packet buffer ownership into SQE
        // user_data immediately and null packets[i] to prevent any double-free.
        //
        // EFFICIENCY: io_uring_peek_batch_cqe() drains all ready completions
        // in one syscall-free call. We only block (io_uring_wait_cqe_timeout)
        // when the ring is full and there is genuinely nothing to reap yet.

        const unsigned ring_cap = send_ring->sq.ring_entries;
        // Widened from (64,128): larger batches per submit matter most on
        // the non-SQPOLL fallback path, where io_uring_submit() is a real
        // io_uring_enter() syscall — fewer, bigger submits = fewer syscalls.
        // Still capped by ring_cap-1, so this only bites if depth (Change 4)
        // is also raised; otherwise it silently clamps back to ~ring_cap-1.
        const size_t   WINDOW   = std::min<size_t>(256 + (rng() % 769), ring_cap - 1);

        size_t next_pkt  = 0;   // next packets[] index to queue
        int    in_flight = 0;   // SQEs submitted, CQE not yet reaped

        // ── reap_cqes: drain completed send CQEs ──────────────────────────
        // block=true: if nothing is immediately ready, issue ONE blocking
        //             wait (up to 200ms), then resume batch-peeking.
        // block=false: pure non-blocking batch peek, returns when empty.
        auto reap_cqes = [&](bool block) {
            struct io_uring_cqe* cqes[64];
            while (in_flight > 0 && !terminate_flag) {
                unsigned n = io_uring_peek_batch_cqe(send_ring, cqes, 64);

                if (n == 0) {
                    if (!block) break;

                    struct io_uring_cqe* cqe = nullptr;
                    struct __kernel_timespec ts = {
                        .tv_sec  = 0,
                        .tv_nsec = 200 * 1000 * 1000   // 200ms
                    };
                    int ret = io_uring_wait_cqe_timeout(send_ring, &cqe, &ts); // ONE syscall
                    if (ret == -ETIME || ret == -EINTR) break;
                    if (ret < 0) {
                        std::cerr << "[TX] io_uring_wait_cqe_timeout: "
                                  << strerror(-ret) << "\n";
                        break;
                    }
                    if (cqe) {
                        // Process this single woken CQE directly, then loop
                        // back around to batch-peek for any siblings that
                        // completed alongside it.
                        const int res = cqe->res;
                        char* buf = static_cast<char*>(io_uring_cqe_get_data(cqe));
                        io_uring_cqe_seen(send_ring, cqe);
                        in_flight--;
                        if (buf) pool.release(buf);

                        if (res == -ENETDOWN || res == -ENETUNREACH || res == -ENONET) {
                            if (!network_disconnect_flag.exchange(true)) {
                                std::lock_guard<std::mutex> lock(cout_mutex);
                                std::cerr << "\n[!] Network disconnected — exiting\n";
                            }
                            terminate_flag.store(true);
                            return;
                        }
                        if (res >= 0) { total_sent++; local_bytes_sent += static_cast<uint64_t>(res); }
                        else if (res != -EAGAIN && res != -EWOULDBLOCK)
                            std::cerr << "[TX] send failed: " << strerror(-res) << "\n";
                    }
                    block = false;   // got at least one — switch to peek mode
                    continue;
                }

                // ── Process the whole peeked batch ──────────────────────────
                bool disconnect = false;
                for (unsigned k = 0; k < n; ++k) {
                    struct io_uring_cqe* c = cqes[k];
                    const int res = c->res;
                    char* buf = static_cast<char*>(io_uring_cqe_get_data(c));
                    in_flight--;
                    if (buf) pool.release(buf);

                    if (res == -ENETDOWN || res == -ENETUNREACH || res == -ENONET) {
                        if (!network_disconnect_flag.exchange(true)) {
                            std::lock_guard<std::mutex> lock(cout_mutex);
                            std::cerr << "\n[!] Network disconnected — exiting\n";
                        }
                        terminate_flag.store(true);
                        disconnect = true;
                        // We must still mark ALL n peeked CQEs as seen — we
                        // already consumed them from the queue via peek, so
                        // advancing by n (not k+1) is correct regardless of
                        // where in the batch the disconnect was detected.
                        break;
                    }
                    if (res >= 0) { total_sent++; local_bytes_sent += static_cast<uint64_t>(res); }
                    else if (res != -EAGAIN && res != -EWOULDBLOCK)
                        std::cerr << "[TX] send failed: " << strerror(-res) << "\n";
                }

                // Always advance by the full peeked count n: io_uring_peek_batch_cqe
                // already removed these n entries from kernel-visible state into
                // our local array, so the CQ ring head must move past all of them
                // regardless of how far the processing loop got before breaking.
                io_uring_cq_advance(send_ring, n);

                if (disconnect) return;
                block = false;
            }
        };

        // ── main pipeline loop ─────────────────────────────────────────────
        while ((next_pkt < num_packets || in_flight > 0) && !terminate_flag) {

            // Fill SQ: queue packets until we hit WINDOW in-flight or SQ full
            while (next_pkt < num_packets &&
                   in_flight < static_cast<int>(WINDOW) &&
                   !terminate_flag) {

                size_t pi = next_pkt;
                if (!packets[pi]) { next_pkt++; continue; }

                const uint16_t step = frag_steps[pi];

                if (step == 0) {
                    // ── Normal unfragmented packet ─────────────────────────
                    // SECURITY: check sqe availability before using it.
                    struct io_uring_sqe* sqe = io_uring_get_sqe(send_ring);
                    if (!sqe) break;  // SQ full; submit what we have

                    // Record TX timestamp BEFORE kernel touches the packet.
                    if (on_pre_submit)
                        on_pre_submit({tasks[pi].src_port}, {tasks[pi].dest_port});

                    if (g_send_fixed_file_active.load(std::memory_order_acquire)) {
                        io_uring_prep_sendmsg(sqe, SEND_SOCK_FIXED_IDX, &msgs[pi], 0);
                        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
                    } else {
                        io_uring_prep_sendmsg(sqe, sock, &msgs[pi], 0);
                    }
                    io_uring_sqe_set_data(sqe, packets[pi]);
                    packets[pi] = nullptr;  // ownership now in SQE user_data
                    in_flight++;
                    next_pkt++;

                } else {
                    // Fragmented: pre-built in all_batch_frags above.
                    // packets[pi] was released and nulled during batch build;
                    // the nullptr check above already skips this packet.
                    next_pkt++;
                }
            }

            // Submit + (conditionally) wait in ONE syscall instead of two.
            // When the ring is full (in_flight >= WINDOW) we know we're about
            // to block anyway, so fold the wait into the same io_uring_enter()
            // call that does the submit, exactly like the idle-wait pattern
            // at io_uring_submit_and_wait_timeout() used elsewhere (~line 3027).
            const bool will_block = (in_flight >= static_cast<int>(WINDOW));
            if (io_uring_sq_ready(send_ring) > 0 || will_block) {
                if (will_block) {
                    struct io_uring_cqe* cqe = nullptr;
                    struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 200'000'000 };
                    int ret = io_uring_submit_and_wait_timeout(send_ring, &cqe, 1, &ts, nullptr);
                    if (ret < 0 && ret != -ETIME && ret != -EINTR) {
                        std::cerr << "[TX] io_uring_submit_and_wait_timeout: "
                                  << strerror(-ret) << "\n";
                        break;
                    }
                    // cqe (if any) is left unseen on purpose — reap_cqes()'s
                    // peek_batch_cqe() below will pick it up along with any
                    // siblings that completed in the same wakeup.
                } else {
                    int submitted = io_uring_submit(send_ring);
                    if (submitted < 0) {
                        std::cerr << "[TX] io_uring_submit: "
                                  << strerror(-submitted) << "\n";
                        break;
                    }
                }
            }

            // Reap whatever's ready — non-blocking, since blocking (if any)
            // already happened above.
            reap_cqes(/*block=*/false);
        }

        // Final drain: reap ALL remaining in-flight CQEs unconditionally,
        // even if terminate_flag is set, to prevent pool buffer leaks.
        // reap_cqes() exits early on network-disconnect (terminate_flag set
        // inside the lambda), so we need a hard drain loop that ignores the flag.
        {
            while (in_flight > 0) {
                struct io_uring_cqe* cqe = nullptr;
                struct __kernel_timespec ts = { .tv_sec = 0,
                                                .tv_nsec = 200 * 1000 * 1000 };
                int ret = io_uring_wait_cqe_timeout(send_ring, &cqe, &ts);
                if (ret == -ETIME || ret == -EINTR || ret < 0) break;
                if (!cqe) break;
                char* buf = static_cast<char*>(io_uring_cqe_get_data(cqe));
                io_uring_cqe_seen(send_ring, cqe);
                in_flight--;
                if (buf) pool.release(buf);
            }
        }

        // Release any packets never queued (e.g. terminate_flag set before
        // they reached the SQ fill loop).
        for (size_t i = 0; i < num_packets; ++i) {
            if (packets[i]) {
                pool.release(packets[i]);
                packets[i] = nullptr;
            }
        }
        // ── Send all pre-built fragments via io_uring ─────────────────────
        if (!all_batch_frags.empty() && !any_frag_collect_failed) {

            // Fix iov pointers invalidated by vector reallocation during build.
            for (auto& bf : all_batch_frags)
                bf.msg.msg_iov = &bf.iov;

            // Call on_pre_submit once per original packet (first fragment only).
            if (on_pre_submit) {
                size_t prev_idx = SIZE_MAX;
                for (auto& bf : all_batch_frags) {
                    if (bf.orig_pkt_idx != prev_idx) {
                        on_pre_submit({tasks[bf.orig_pkt_idx].src_port},
                                      {tasks[bf.orig_pkt_idx].dest_port});
                        prev_idx = bf.orig_pkt_idx;
                    }
                }
            }

            // Pipeline all fragments through the ring, respecting WINDOW.
            // in_flight is already 0 here (main pipeline drained above).
            size_t frag_next = 0;
            const size_t frag_total = all_batch_frags.size();

            while ((frag_next < frag_total || in_flight > 0) && !terminate_flag) {

                // Fill SQ up to WINDOW
                while (frag_next < frag_total &&
                       in_flight < static_cast<int>(WINDOW) &&
                       !terminate_flag) {

                    BatchFrag& bf = all_batch_frags[frag_next];
                    struct io_uring_sqe* sqe = io_uring_get_sqe(send_ring);
                    if (!sqe) break;  // SQ full, submit what we have

                    if (g_send_fixed_file_active.load(std::memory_order_acquire)) {
                        io_uring_prep_sendmsg(sqe, SEND_SOCK_FIXED_IDX, &bf.msg, 0);
                        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
                    } else {
                        io_uring_prep_sendmsg(sqe, sock, &bf.msg, 0);
                    }
                    // Pass buf pointer as user_data so reap_cqes can release it.
                    io_uring_sqe_set_data(sqe, bf.buf);
                    bf.buf = nullptr;  // ownership transferred to SQE
                    in_flight++;
                    frag_next++;
                }

                // Submit + (conditionally) wait in ONE syscall instead of two.
            // When the ring is full (in_flight >= WINDOW) we know we're about
            // to block anyway, so fold the wait into the same io_uring_enter()
            // call that does the submit, exactly like the idle-wait pattern
            // at io_uring_submit_and_wait_timeout() used elsewhere (~line 3027).
            const bool will_block = (in_flight >= static_cast<int>(WINDOW));
            if (io_uring_sq_ready(send_ring) > 0 || will_block) {
                if (will_block) {
                    struct io_uring_cqe* cqe = nullptr;
                    struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 200'000'000 };
                    int ret = io_uring_submit_and_wait_timeout(send_ring, &cqe, 1, &ts, nullptr);
                    if (ret < 0 && ret != -ETIME && ret != -EINTR) {
                        std::cerr << "[TX-FRAG] io_uring_submit_and_wait_timeout: "
                                  << strerror(-ret) << "\n";
                        break;
                    }
                    // cqe (if any) is left unseen on purpose — reap_cqes()'s
                    // peek_batch_cqe() below will pick it up along with any
                    // siblings that completed in the same wakeup.
                } else {
                    int submitted = io_uring_submit(send_ring);
                    if (submitted < 0) {
                        std::cerr << "[TX-FRAG] io_uring_submit: "
                                  << strerror(-submitted) << "\n";
                        break;
                    }
                }
            }

            // Reap whatever's ready — non-blocking, since blocking (if any)
            // already happened above.
            reap_cqes(/*block=*/false);
        }

            // Hard drain: reap remaining fragment CQEs even if terminate_flag set.
            while (in_flight > 0) {
                struct io_uring_cqe* cqe = nullptr;
                struct __kernel_timespec ts = { .tv_sec = 0,
                                                .tv_nsec = 200 * 1000 * 1000 };
                int ret = io_uring_wait_cqe_timeout(send_ring, &cqe, &ts);
                if (ret == -ETIME || ret == -EINTR || ret < 0) break;
                if (!cqe) break;
                char* buf = static_cast<char*>(io_uring_cqe_get_data(cqe));
                io_uring_cqe_seen(send_ring, cqe);
                in_flight--;
                if (buf) pool.release(buf);
            }
        }

        // Release any fragments whose SQE was never submitted (terminate_flag
        // set mid-pipeline) or that failed pool acquire (buf already nullptr
        // for transferred ones, so this is safe).
        for (auto& bf : all_batch_frags) {
            if (bf.buf) { pool.release(bf.buf); bf.buf = nullptr; }
        }
        all_batch_frags.clear();
    } else {
        // sendmmsg() fallback removed — the io_uring path above is now the
        // only send path (see receive_response(): send_ring is always
        // passed, regardless of rate/jitter config). This branch is
        // unreachable in normal operation; it only guards against a null
        // ring being passed in by mistake, and still releases any buffers
        // so nothing leaks.
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "[TX] send_tcp_packets: send_ring is null — "
                         "an io_uring send context is required\n";
        }
        for (size_t i = 0; i < num_packets; ++i) {
            if (packets[i]) { pool.release(packets[i]); packets[i] = nullptr; }
        }
        for (auto& bf : all_batch_frags) {
            if (bf.buf) { pool.release(bf.buf); bf.buf = nullptr; }
        }
        all_batch_frags.clear();
    }

    if (out_bytes_sent) *out_bytes_sent = local_bytes_sent;
    return total_sent;
}


RecPross receive_response(const char *dest_ip, std::span<const int> ports, uint32_t local_ip,
                      std::mt19937 &rng, PacketBufferPool &pool, int send_sock, uint16_t source_port, uint16_t retry_source_port, uint32_t seq_num, uint16_t win_size, bool print_individual_closed_filtered, bool 
                      print_filtered_if_few,
                      struct io_uring *send_ring, bool fast_scan, size_t batch_size, ScanType scan_type,uint8_t custom_ttl, uint8_t custom_dscp,uint16_t custom_ip_flags, IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                      const TcpBuildOptions& opts,
                      bool debug_rtt,bool debug_ttl,bool debug_demux,bool debug_strack,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool
                      frag_zof,const SportRangeConfig& sport_range_cfg,const GsportConfig& gsport_cfg,int initial_rtt_ms,int port_timeout_min_ms, int port_timeout_max_ms,RateConfig rate_config,JitterConfig 
                      jitter_config,BatchDelayConfig
                      batch_delay_config, GlobalRecvCtx* g_recv, struct io_uring* idle_ring_ptr,
                      RateLimiterState* rate_state,
                      BandwidthConfig bandwidth_config, BandwidthLimiterState* bandwidth_state,
                      uint64_t initial_dispatch_delay_us, bool debug_send) {
    // Local aliases: same names the body below has always used, now backed
    // by the shared opts struct instead of ~29 individual parameters.
    const bool&        use_manual_tcp_checksum = opts.use_manual_tcp_checksum;
    const uint16_t&    manual_tcp_checksum     = opts.manual_tcp_checksum;
    const uint8_t&     window_scale            = opts.window_scale;
    const uint16_t&    mss_value               = opts.mss_value;
    const uint32_t&    timestamp_val           = opts.timestamp_val;
    const uint32_t&    timestamp_ecr_custom    = opts.timestamp_ecr_custom;
    const uint16_t&    nops_count              = opts.nops_count;
    const bool&        sack_permitted          = opts.sack_permitted;
    const std::string& custom_data             = opts.custom_data;
    const uint16_t&    data_length             = opts.data_length;
    const bool&        use_custom_data         = opts.use_custom_data;
    const bool&        generate_random_data    = opts.generate_random_data;
    const bool&        use_badsum              = opts.use_badsum;
    const uint16_t&    custom_badsum_value     = opts.custom_badsum_value;
    const bool&        badsum_value_set        = opts.badsum_value_set;
    const bool&        use_partial_badsum      = opts.use_partial_badsum;
    const std::string& partial_badsum_type     = opts.partial_badsum_type;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;
    const bool&        use_fragmentation       = opts.use_fragmentation;
    const uint16_t&    frag_size               = opts.frag_size;
    const uint16_t&    mtu_size                = opts.mtu_size;
    const bool&        use_ip_tos              = opts.use_ip_tos;
    const uint8_t&     custom_ip_tos_byte      = opts.custom_ip_tos_byte;
    const PacketLengthConfig& packet_length_config = opts.packet_length_config;

    if (ports.empty() || terminate_flag) {
        return RecPross{};
    }
    const size_t num_packets = ports.size();
    RecPross result;
    std::unordered_map<uint16_t, PacketDetails> packet_details_map;
    if (!g_recv || !g_recv->valid) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Receive context not initialised (g_recv invalid)\n";
        return result;
    }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) <= 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Invalid IP address: " << dest_ip << std::endl;
        return result;
    }
    // ── --debug demux support ────────────────────────────────────────────
    // Counts + events are local to this call (one call = one batch of
    // ports against one target); thread_worker() merges them into
    // result.demux_counts / result.demux_debug_entries after every batch,
    // and the merged, whole-scan totals get printed exactly once by
    // print_demux_debug() after that target's scan is completely done —
    // never from in here. That's what stops [demux] lines from
    // interleaving with the port table while the scan is still running.
    // Zero cost when debug_demux is false: every call site below is
    // guarded by `if (debug_demux)` so nothing extra is computed,
    // formatted, or allocated on the hot path by default.
    DemuxDebugCounters            demux_counts;
    std::vector<DemuxDebugEntry>  demux_entries;

    auto demux_log = [&](const char* tag, uint16_t port, const std::string& detail,
                          uint16_t src_port, uint8_t flags, int attempt, uint8_t ttl,
                          bool is_icmp) {
        if (!debug_demux) return;
        demux_entries.push_back(DemuxDebugEntry{
            dest_ip, port, tag, detail, src_port, flags, attempt, ttl, is_icmp
        });
    };
    // ── --debug strack support ───────────────────────────────────────────
    // Same buffering discipline as demux_log: local to this batch, merged
    // into result.strack_* by the caller, printed once after the whole
    // scan for this target is done. Zero cost when debug_strack is false.
    StrackCounters            strack_counts;
    std::vector<StrackEntry>  strack_entries;

    auto strack_log = [&](uint16_t port, StrackFinalState final_state,
                           int resolved_attempt, uint16_t src_port_used,
                           double rtt_ms, bool is_icmp) {
        if (!debug_strack) return;
        switch (resolved_attempt) {
            case 0:  strack_counts.resolved_attempt0++; break;
            case 1:  strack_counts.resolved_attempt1++; break;
            case 2:  strack_counts.resolved_attempt2++; break;
            default: strack_counts.unresolved++;        break;
        }
        strack_entries.push_back(StrackEntry{
            port, final_state, resolved_attempt, src_port_used, rtt_ms, is_icmp
        });
    };

    auto demux_flags_str = [](uint8_t flags) -> std::string {
        std::string s;
        if (flags & TH_SYN) s += "SYN,";
        if (flags & TH_ACK) s += "ACK,";
        if (flags & TH_RST) s += "RST,";
        if (flags & TH_FIN) s += "FIN,";
        if (!s.empty()) s.pop_back();  // drop trailing comma
        return s.empty() ? "none" : s;
    };

    bool idle_ring_ok = (idle_ring_ptr != nullptr);
    auto* my_queue = g_recv->queue_for(dest.sin_addr.s_addr);
    if (!my_queue) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "[receive_response] no recv queue for " << dest_ip << "\n";
        return result;
    }
    
    {
        RawPacket _discard[64];
        while (my_queue->try_dequeue_bulk(_discard, 64) > 0) {}
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
                case 1:  return base_rtt + 40;
                case 2:  return base_rtt + 100;
                default: return base_rtt + 100;
            }
        }
        bool should_mark_filtered(int retry_count) const {
            return retry_count >= 2;
        }
    };
    RTTTracker global_rtt_tracker(initial_rtt_ms);

    std::vector<int32_t> port_to_idx(65536, -1);

    // Sized to exactly what we're scanning, not 65536.
    std::vector<PortState>          port_states_arr(ports.size());
    std::vector<std::atomic<bool>>  port_final(ports.size());
    std::vector<std::atomic<bool>>  port_rtt_measured(ports.size());

    // Assigned sequentially in the init loop below; recovers the real
    // port number from an index when needed (htons(), composite keys).
    std::vector<uint16_t> idx_to_port(ports.size());

    // Running counter for the dense index space.
    size_t next_idx = 0;
    std::random_device _rd;
    const uint64_t sip_k0 = (static_cast<uint64_t>(_rd()) << 32) | _rd();
    const uint64_t sip_k1 = (static_cast<uint64_t>(_rd()) << 32) | _rd();

    auto compute_token = [&](uint16_t port) -> uint32_t {
        uint64_t v0 = sip_k0 ^ 0x736f6d6570736575ULL;
        uint64_t v1 = sip_k1 ^ 0x646f72616e646f6dULL;
        uint64_t v2 = sip_k0 ^ 0x6c7967656e657261ULL;
        uint64_t v3 = sip_k1 ^ 0x7465646279746573ULL;
        uint64_t m  = static_cast<uint64_t>(port);
        v3 ^= m;
        v0+=v1; v1=(v1<<13)|(v1>>51); v1^=v0; v0=(v0<<32)|(v0>>32);
        v2+=v3; v3=(v3<<16)|(v3>>48); v3^=v2;
        v0+=v3; v3=(v3<<21)|(v3>>43); v3^=v0;
        v2+=v1; v1=(v1<<17)|(v1>>47); v1^=v2; v2=(v2<<32)|(v2>>32);
        v0 ^= m;
        v2 ^= 0xff;
        for (int i = 0; i < 3; ++i) {
            v0+=v1; v1=(v1<<13)|(v1>>51); v1^=v0; v0=(v0<<32)|(v0>>32);
            v2+=v3; v3=(v3<<16)|(v3>>48); v3^=v2;
            v0+=v3; v3=(v3<<21)|(v3>>43); v3^=v0;
            v2+=v1; v1=(v1<<17)|(v1>>47); v1^=v2; v2=(v2<<32)|(v2>>32);
        }
        return static_cast<uint32_t>((v0^v1^v2^v3) & 0xFFFFFFFF);
    };

    // Token active only when seq is under our control (seq_num==0 means not user-forced)
    const bool use_token = (seq_num == 0);

    // PERF: was a 65536-slot `static thread_local std::array`, keyed by raw
    // port number (512KB per thread, reset in full on every call). Shrunk to
    // the dense per-scan index space (same `didx`/`pidx` used everywhere
    // else) so its footprint and reset cost scale with ports.size(), not
    // with the full uint16_t range. Plain local vector (heap-backed), not
    // thread_local/static: no cross-call staleness, no risk of a stale size
    // from a previous scan on a reused pool thread.
    std::vector<std::atomic<uint64_t>> tx_ts_table(ports.size());
    for (auto& slot : tx_ts_table) slot.store(0, std::memory_order_relaxed);

    std::vector<uint16_t> active_ports;
    active_ports.reserve(ports.size());

    std::uniform_int_distribution<uint32_t> seq_dist(0, 4294967295U);

    const int MAX_RETRIES    = 2;

    // These scan types treat "no response at all" as the actual signal
    // (open|filtered per RFC 793) — retrying doesn't change that signal,
    // it only triples packets sent and triples the wait. So for these,
    // one timeout with zero replies is enough to finalize the port.
    static const std::unordered_set<ScanType> no_retry_scan_types = {
        ScanType::FIN, ScanType::NULL_SCAN, ScanType::XMAS,
        ScanType::CWR, ScanType::URG, ScanType::PSH, ScanType::HANUMAN
    };
    const bool skip_retries = no_retry_scan_types.count(scan_type) > 0;

    // ── Per-port deadline heap ─────────────────────────────────────────────
    // Each port gets an exact expiry time pushed here when its SYN is sent.
    // The heap always surfaces the earliest expiry at top — O(log n) per
    // push/pop instead of O(n) linear scan every 50ms.
    using TP = std::chrono::steady_clock::time_point;
    struct HeapEntry {
        TP       deadline;
        uint16_t port;
        bool operator>(const HeapEntry& o) const { return deadline > o.deadline; }
    };
    std::priority_queue<HeapEntry,
                        std::vector<HeapEntry>,
                        std::greater<HeapEntry>> deadline_heap;
    // priority_queue wraps a vector internally — pre-reserve via constructor
    // to avoid repeated reallocations as ports are pushed.
    {
        std::vector<HeapEntry> backing;
        backing.reserve(ports.size());
        deadline_heap = std::priority_queue<HeapEntry,
                                            std::vector<HeapEntry>,
                                            std::greater<HeapEntry>>(
                            std::greater<HeapEntry>{}, std::move(backing));
    }
    // Staggering clock for deferred dynamic-delay retries: ensures each
    // deferred port's virtual deadline lands at/after the previous one,
    // so retries that fire close together don't cluster into a burst
    // once the heap catches up to them. Capped at "now + MAX_DELAY_US"
    // at the call site so the stagger cannot compound into unbounded
    // queueing when many retries pile up at once. Still 100%
    // non-blocking — this is just a timestamp, never slept on.
    std::chrono::steady_clock::time_point next_retry_dispatch_time =
        std::chrono::steady_clock::now();
    // ── end heap declaration ───────────────────────────────────────────────
    // ── end heap declaration ───────────────────────────────────────────────
    const int MIN_TIMEOUT_MS = port_timeout_min_ms;
    const int MAX_TIMEOUT_MS = port_timeout_max_ms;

    const auto& service_map = read_services_from_file("/usr/share/shiv/services");

    // BlockingConcurrentQueue instead of plain ConcurrentQueue: gives the
    // sender thread a true semaphore-based wait_dequeue_bulk_timed() below,
    // so it sleeps at zero CPU while idle but wakes immediately the instant
    // a packet is enqueued — no fixed spin window, no clock_nanosleep
    // polling fallback.
    moodycamel::BlockingConcurrentQueue<PacketTask> packet_queue;
    std::atomic<size_t> local_packets_sent(0);
    const size_t total_ports_count = ports.size();
    // FIX (output ordering, cross-thread case): tl_port_output_buf is
    // thread_local. The sender thread spawned below is a *different* OS
    // thread than the one that set tl_port_output_buf before calling
    // receive_response(), so on the sender thread that pointer reads back
    // as null — any diagnostic printed from inside sender_thread_func was
    // therefore *always* falling through to the unbuffered std::cerr path,
    // regardless of threaded/buffered mode, and could interleave with any
    // other target's output. Capture the buffer pointer explicitly (by
    // value) so the sender thread targets the same buffer as its caller.
    std::string* const captured_output_buf = tl_port_output_buf;

    // ── RNG race fix ─────────────────────────────────────────────────────
    // `rng` is owned by the calling (producer) thread and is used by the
    // producer loop below (rate_pkt_dist, port_dist, seq_dist, jitter_dist).
    // sender_thread_func runs on a separate std::thread and — via
    // send_tcp_packets()/build_packet() — also draws from an RNG
    // (window_dist, ip_id_dist). Sharing a single std::mt19937 between two
    // concurrently-running threads with no synchronization is a data race
    // (UB): std::mt19937::operator() mutates internal state on every call,
    // and there is no atomicity guarantee across those reads/writes.
    //
    // The fix here is to give the sender thread its own, independent
    // mt19937 instead of adding a mutex around every draw. A lock would
    // serialize the hottest paths in both threads (every packet's IP ID
    // and every pipeline window size, plus every port's src-port/seq/
    // jitter draw) purely for contention that has no reason to exist —
    // the sender thread's randomness (window sizing, IP ID) has no
    // correlation requirement with the producer's randomness (source
    // ports, sequence numbers, jitter). Decoupling them entirely is both
    // simpler and strictly faster: zero locking overhead, and the two
    // threads never touch each other's generator again.
    //
    // sender_rng is seeded here, on the producer thread, BEFORE
    // sender_thread is spawned below — so this one draw from `rng` is
    // still single-threaded/safe — and mixed with a high-resolution clock
    // sample so back-to-back receive_response() calls (each of which
    // creates/destroys its own sender_thread) don't seed correlated
    std::mt19937 sender_rng(rng() ^ static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    // Must be declared BEFORE sender_thread_func below: that lambda captures
    // by [&], which only reaches variables already in scope at the point of
    // the lambda's definition — bws is written to from inside that lambda
    // (see the fetch_add after send_tcp_packets()), so it can't be declared
    // any later than this.
    BandwidthLimiterState local_bandwidth_state;
    BandwidthLimiterState& bws = bandwidth_state ? *bandwidth_state : local_bandwidth_state;

    auto sender_thread_func = [&]() {
        std::vector<PacketTask> tasks_vec(batch_size);
        // Pure event-driven wait: BlockingConcurrentQueue::wait_dequeue_bulk()
        // (no timeout) blocks this thread at zero CPU until something is
        // actually enqueued — no periodic liveness poll. Shutdown is
        // signalled by enqueueing a single poison-pill PacketTask (see the
        // sender_done.store() site below), not by polling terminate_flag.
        while (true) {
            size_t count = packet_queue.wait_dequeue_bulk(
                tasks_vec.data(), batch_size);

            // Strip out any poison pill(s) before touching real work.
            // A poison pill carries no packet data; it exists only to
            // wake this blocking dequeue at shutdown.
            bool shutdown_requested = false;
            size_t real_count = 0;
            for (size_t i = 0; i < count; ++i) {
                if (tasks_vec[i].is_poison) {
                    shutdown_requested = true;
                } else {
                    if (real_count != i) tasks_vec[real_count] = std::move(tasks_vec[i]);
                    ++real_count;
                }
            }
            count = real_count;
            if (count == 0) {
                if (shutdown_requested) break;
                continue;
            }
            // io_uring is always used now — sendmmsg() fallback removed.
            // io_uring is always used now — sendmmsg() fallback removed.
            // Rate limiting and jitter are paced in the producer loop below
            // (per-port sleep before/after enqueue), and send_tcp_packets()
            // already submits one SQE per packet with on_pre_submit firing
            // immediately before each individual submission, so per-packet
            // timing accuracy does not depend on which send path is used.
            struct io_uring* effective_ring = send_ring;
            auto on_pre_submit = [&](const std::vector<uint16_t>& src_ports,
                                     const std::vector<uint16_t>& dst_ports) {
                auto ts = std::chrono::steady_clock::now();
                uint64_t ts_us = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        ts.time_since_epoch()).count());
                for (size_t i = 0; i < dst_ports.size(); ++i) {
                    // PERF/CORRECTNESS: look up pidx first — tx_ts_table is now
                    // sized to ports.size() and indexed by the dense idx, not
                    // the raw port. Guard the store behind the same pidx>=0
                    // check already used for port_states_arr.
                    int32_t pidx = port_to_idx[dst_ports[i]];
                    if (pidx >= 0) {
                        tx_ts_table[pidx].store(ts_us, std::memory_order_release);
                        port_states_arr[pidx].syn_sent_time = ts;
                    }
                }
            };

            uint64_t batch_bytes_sent = 0;
            int sent_count = send_tcp_packets(send_sock,
                std::span<PacketTask>(tasks_vec.data(), count),
                local_ip, sender_rng, pool, win_size,
                effective_ring,
                batch_size, custom_ttl,custom_dscp,custom_ip_flags,
                ip_id_mode, fixed_ip_id,
                opts,
                frag_out_of_order, frag_overlap, frag_overlap_bytes, frag_zof,
                on_pre_submit, &batch_bytes_sent, debug_send);
            if (bandwidth_config.enabled)
                bws.actual_bytes_sent.fetch_add(batch_bytes_sent, std::memory_order_relaxed);
            if (sent_count < 0) {
                std::string msg = "Failed to send packet batch\n";
                if (captured_output_buf) {
                    *captured_output_buf += msg;
                } else {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << msg;
                }
            } else if (sent_count > 0) {
                local_packets_sent.fetch_add(sent_count, std::memory_order_relaxed);
            }
            if (shutdown_requested) break;
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
    // rate_state persists across every batch call to receive_response() for
    // a given target (owned by worker_thread's per-target loop). Falling
    // back to a purely-local instance keeps this function safe to call
    // directly without a persistent state, but that fallback loses
    // cross-batch continuity — every real scan path passes rate_state.
    RateLimiterState local_rate_state;
    RateLimiterState& rs = rate_state ? *rate_state : local_rate_state;

    auto rate_reset_window = [&]() {
        rs.rate_window_sent  = 0;
        rs.rate_window_start = std::chrono::steady_clock::now();
        if (rate_config.enabled) {
            if (rate_config.min_packets < rate_config.max_packets) {
                rs.rate_pkt_dist      = std::uniform_int_distribution<uint32_t>(
                                         rate_config.min_packets, rate_config.max_packets);
                rs.rate_window_target = rs.rate_pkt_dist(rng);
            } else {
                rs.rate_window_target = rate_config.max_packets;
            }
        }
    };

    // Seed the window only the first time it's ever used for this target —
    // subsequent batches (subsequent calls to receive_response for the same
    // worker_thread/target) must keep counting against the SAME window
    // rather than restarting it, otherwise a rate target that's comparable
    // to or larger than one batch's port count never actually triggers a
    // throttling sleep, and --rate silently does nothing.
    if (rate_config.enabled && !rs.initialized) {
        rate_reset_window();
        rs.initialized = true;
    }

    // ── Non-blocking rate/jitter pacing ─────────────────────────────────────
    // NOTE: rate/jitter no longer block this thread with sleep_for()/spin.
    // Both are folded into a single "virtual dispatch clock" that only ever
    // moves forward on paper. Each port's ACTUAL send (packet_queue.enqueue)
    // is deferred to the exact same deadline_heap + heap-pop mechanism the
    // codebase already uses for retry pacing (see PortState::retry_send_deferred
    // and the "Heap-driven timeout processing" block below) — we're just
    // reusing that idiom for the FIRST send instead of only retries. This
    // preserves identical on-wire spacing (same cumulative delay math as the
    // old sleep_for/hybrid_delay_us code) with zero added syscalls and no
    // busy-spinning: the loop below is pure arithmetic + a heap push per port.
    auto virtual_now = std::chrono::steady_clock::now();
    if (initial_dispatch_delay_us > 0)
        virtual_now += std::chrono::microseconds(initial_dispatch_delay_us);

    for (int port : ports) {
        if (port <= 0 || port > 65535) continue;
        if (terminate_flag) break;
        if (rate_config.enabled) {
            if (rs.rate_window_sent >= rs.rate_window_target) {
                // Old code: sleep_for(remaining_us) then reset the window.
                // New code: push the virtual clock to the window's end
                // instead of actually sleeping — identical spacing, no
                // blocking. rate_reset_window() re-rolls window_target as
                // before; we then re-anchor its start to virtual time so
                // the next window is measured from the (virtual) instant
                // this one ended, not from wall-clock "now".
                auto window_end = rs.rate_window_start
                                 + std::chrono::microseconds(rate_config.window_us);
                if (window_end > virtual_now) virtual_now = window_end;
                rate_reset_window();
                rs.rate_window_start = virtual_now;
            }
        }
        if (bandwidth_config.enabled) {
            // Same virtual-clock idiom as the rate gate above: reserve this
            // port's estimated wire bytes against the window budget. If the
            // window can't absorb it, push virtual_now to the window's end —
            // no sleep, no syscall, just arithmetic that the deadline_heap
            // push below will honor automatically.
            uint64_t used = std::max(bws.reserved_bytes,
                                      bws.actual_bytes_sent.load(std::memory_order_relaxed));
            size_t est_bytes = estimate_packet_wire_bytes(opts, scan_type);
            if (used + est_bytes > bandwidth_config.total_bytes) {
                auto window_end = bws.window_start +
                    std::chrono::microseconds(bandwidth_config.window_us);
                if (window_end > virtual_now) virtual_now = window_end;
                bws.reserved_bytes = 0;
                bws.actual_bytes_sent.store(0, std::memory_order_relaxed);
                bws.window_start   = virtual_now;
                used = 0;
            }
            bws.reserved_bytes = used + est_bytes;
        }

        auto now = std::chrono::steady_clock::now();

        dest.sin_port = htons(static_cast<uint16_t>(port));
        uint16_t src_port_val = sport_range_cfg.stage_is_range[0]
            ? fast_uniform_port(rng, sport_range_cfg.stage_min[0], sport_range_cfg.stage_max[0])
            : gsport_cfg.stage_is_set[0]
                ? gsport_cfg.stage_port[0]
                : (source_port > 0 ? source_port : fast_uniform_port(rng, 32768, 60999));
        uint32_t seq          = use_token
                                ? compute_token(static_cast<uint16_t>(port))
                                : (seq_num > 0 ? seq_num : seq_dist(rng));
        uint32_t tsval        = 1234567;
        int initial_timeout   = global_rtt_tracker.get_timeout_for_retry(0);
        initial_timeout = std::max(port_timeout_min_ms, std::min(initial_timeout, port_timeout_max_ms));

        // SECURITY: port is already bounds-checked at line 2339
        // (1 <= port <= 65535), so this is a safe table write.
        port_to_idx[port]       = static_cast<int32_t>(next_idx);
        idx_to_port[next_idx]   = static_cast<uint16_t>(port);
        PortState& ps = port_states_arr[next_idx];
        ps.src_port               = src_port_val;
        ps.record_src_port(src_port_val, 0);   // initial send is always attempt 0
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
        ps.initial_send_deferred  = true;

        port_final[next_idx].store(false, std::memory_order_relaxed);
        port_rtt_measured[next_idx].store(false, std::memory_order_relaxed);

        active_ports.push_back(static_cast<uint16_t>(port));
        ++next_idx;

        // Jitter: advance the virtual clock instead of sleeping. Same
        // distribution/values as before, just applied on paper.
        if (jitter_config.enabled) {
	    uint64_t sleep_us = 0;
	    if (jitter_config.random_mode) {
		sleep_us = 900 + (rng() % 6101);
	    } else {
		sleep_us = jitter_config.delay_us;
	    }
	    virtual_now += std::chrono::microseconds(sleep_us);
	}

        // Push the port's SEND time onto the SAME deadline_heap used for
        // retries. clamp to "now" so a port with no rate/jitter delay ahead
        // of it dispatches immediately (heap pop condition is `<= now`).
        // NOTE: this is the send deadline, not the RTT-timeout deadline —
        // the RTT deadline is pushed by the heap-pop handler itself, right
        // after it actually performs the enqueue (see initial_send_deferred
        // branch in the "Heap-driven timeout processing" block).
        deadline_heap.push({std::max(virtual_now, now), static_cast<uint16_t>(port)});

        if (rate_config.enabled) {
            rs.rate_window_sent++;
        }
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

    // IP checksum validation skipped on hot RX path — result is display-only,
    // never gates any scan decision. Computing it over attacker-controlled
    // iphdrlen bytes is unnecessary work with no security benefit.
    details.ip_checksum_valid = true;  // sentinel: "not verified"

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

    // TCP checksum validation skipped on hot RX path — display-only field,
    // no scan decision depends on it.
    details.tcp_checksum_valid = true;  // sentinel: "not verified"

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
    std::atomic<size_t> ports_in_retry{0};
    bool needs_submit = false;
    // FIX (retry slowdown): IDLE_WAIT_CAP_NS is now a ceiling, not a fixed
    // wait. The old code always blocked the full 50ms here whenever the
    // queue was empty, *even when deadline_heap had a retry due sooner*.
    // The deadline_heap / deferred-retry machinery further down was already
    // designed to be non-blocking and precisely timed — but it only ever
    // gets to run once we return from this wait, so a retry due in, say,
    // 300us was still held up until the full 50ms elapsed. That's the
    // "dynamic retries not working" symptom: the scheduler's precision was
    // real, it just never got a chance to act on it. Now we compute the
    // wait as min(time-until-next-deadline, 50ms), so the loop wakes up
    // (almost) exactly when the next retry is due instead of up to 50ms late.
    //
    // EVENT-DRIVEN WAKEUP (MSG_RING): this wait is no longer the only way
    // the loop learns new data arrived. recv_reader_thread_func submits an
    // IORING_OP_MSG_RING into idle_ring_ptr the instant it dispatches a
    // packet for this host, which posts a CQE here and makes
    // io_uring_submit_and_wait_timeout() below return immediately —
    // idle_ret/tcqe handling is already generic and needs no special case
    // for that. Because of that, IDLE_WAIT_MIN_NS below now only bounds how
    // often we wake purely to re-check the retry-deadline heap (i.e. when
    // no packet has arrived), not how fast we react to real responses. RTTs
    // in this scanner run tens of milliseconds, so sub-millisecond retry
    // precision buys nothing — the floor is raised to 1ms to cut needless
    // timer-only wakeups roughly 10-20x versus the previous 50us floor.
    // 50 ms safety net for the *no scheduled work at all* fallback case (used
    // only when deadline_heap is empty, right below). When the heap DOES have
    // an entry, this is no longer used as a blanket ceiling — see
    // effective_cap_ns below.
    constexpr int64_t IDLE_WAIT_CAP_NS = 50 * 1000 * 1000;
    constexpr int64_t IDLE_WAIT_MIN_NS = 2 * 1000 * 1000;   // 2 ms floor — retry-timer granularity only;
                                                              // real packet arrivals still wake instantly via
                                                              // MSG_RING; this only throttles the *no-event*
                                                              // polling rate.
    // DEADLINE COALESCING: round the computed wait up to the next multiple
    // of this bucket width so that several retry/filtered-timeout deadlines
    // landing close together get drained by ONE wakeup (the heap-drain
    // while-loop further down already pops everything <= now in one pass)
    // instead of one io_uring_enter() per deadline. Only affects the timing
    // of internal timeout housekeeping — real packet arrivals still cut the
    // wait short instantly via MSG_RING, completely bypassing this bucket.
    // Keep this comfortably below MIN_TIMEOUT_MS/port_timeout_min_ms so it
    // never becomes a meaningful fraction of an actual RTT timeout.
    constexpr int64_t DEADLINE_COALESCE_NS = 3 * 1000 * 1000;  // 3 ms bucket

    while (active_count.load(std::memory_order_relaxed) > 0 && !terminate_flag) {
        RawPacket pkt_batch[32];
        size_t got = my_queue->try_dequeue_bulk(pkt_batch, 32);

    // Keep draining the queue in a tight, syscall-free loop as long as data
    // keeps coming — only fall back to the timed wait once it's genuinely
    // empty, so a burst of responses doesn't get throttled by the wait.
        while (got == 0 && active_count.load(std::memory_order_relaxed) > 0 && !terminate_flag) {
            int64_t wait_ns = IDLE_WAIT_CAP_NS;
            if (!deadline_heap.empty()) {
                auto now_wait = std::chrono::steady_clock::now();
                int64_t until_next_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                             deadline_heap.top().deadline - now_wait).count();

                // A --bandwidth window boundary is a precisely-known,
                // far-future deadline (up to window_us away) — not a
                // "might need to react sooner" event like a retry, so
                // there's no responsiveness cost to waiting the full
                // distance to it PROVIDED a real packet arrival can still
                // cut the wait short. That's only true on the idle_ring_ok
                // path (MSG_RING wakes it instantly); the clock_nanosleep
                // fallback below has no such wake, so its cap must stay at
                // the original 50ms regardless of --bandwidth, or RTT
                // measurement on that path would lose up to a full window's
                // worth of responsiveness.
                int64_t effective_cap_ns = IDLE_WAIT_CAP_NS;
                if (bandwidth_config.enabled && idle_ring_ok) {
                    effective_cap_ns = std::max(effective_cap_ns,
                        static_cast<int64_t>(bandwidth_config.window_us) * 1000);
                }

                // Round up to the next coalescing-bucket boundary. Truncating
                // integer division always rounds toward zero, so +1 before
                // multiplying guarantees we round UP, never down (and stays
                // safe even if until_next_ns is slightly negative because a
                // deadline was just barely missed by scheduling jitter).
                int64_t bucketed_ns = ((until_next_ns / DEADLINE_COALESCE_NS) + 1)
                                          * DEADLINE_COALESCE_NS;

                wait_ns = std::clamp(bucketed_ns, IDLE_WAIT_MIN_NS, effective_cap_ns);
            }
            if (idle_ring_ok) {
                struct __kernel_timespec ts = {
                    .tv_sec  = wait_ns / 1'000'000'000,
                    .tv_nsec = wait_ns % 1'000'000'000
                };
                struct io_uring_cqe* tcqe = nullptr;
                int idle_ret = io_uring_submit_and_wait_timeout(
                    idle_ring_ptr, &tcqe, 1, &ts, nullptr);
                if (idle_ret >= 0 && tcqe) io_uring_cqe_seen(idle_ring_ptr, tcqe);
            } else {
                struct __kernel_timespec ts = { .tv_sec = wait_ns / 1'000'000'000, .tv_nsec = wait_ns % 1'000'000'000 };
                clock_nanosleep(CLOCK_MONOTONIC, 0, reinterpret_cast<struct timespec*>(&ts), nullptr);
            }
            got = my_queue->try_dequeue_bulk(pkt_batch, 32);
            break;  // re-check active_count / process whatever we got, same as before
        }

        for (size_t pi = 0; pi < got; ++pi) {
            RawPacket& rp   = pkt_batch[pi];
            int        bytes = rp.len;
            const char* buffer = reinterpret_cast<const char*>(rp.data);
            struct ip*    iph    = (struct ip*)buffer;
            int           iphdrlen = iph->ip_hl * 4;

            if (iph->ip_dst.s_addr == local_ip &&
                iphdrlen >= static_cast<int>(sizeof(struct ip)) &&
                iphdrlen <= bytes &&
                iph->ip_p == IPPROTO_TCP &&
                bytes >= iphdrlen + static_cast<int>(sizeof(struct tcphdr))) {

                if (iph->ip_src.s_addr != dest.sin_addr.s_addr) continue;

                struct tcphdr* tcph      = (struct tcphdr*)(buffer + iphdrlen);
                uint16_t       dest_port = ntohs(tcph->th_sport);
                uint16_t       our_sport = ntohs(tcph->th_dport);

                if (dest_port == 0) continue;
                // SECURITY: dest_port is parsed from an untrusted packet
                // (tcph->th_sport). port_to_idx is fixed at 65536 entries
                // and dest_port is uint16_t, so this lookup is always
                // in-bounds. didx < 0 means this port isn't part of our
                // scan — drop the packet here before any further use.
                int32_t didx = port_to_idx[dest_port];
                if (__builtin_expect(didx < 0, 1)) {
                    if (debug_demux) {
                        demux_counts.unknown_port++;
                        demux_log("DROP unknown-port", dest_port,
                                   "not part of this scan, flags=" +
                                   demux_flags_str(tcph->th_flags),
                                   our_sport, tcph->th_flags, -1, iph->ip_ttl, false);
                    }
                    continue;
                }
                if (__builtin_expect(!port_states_arr[didx].accepts_src_port(our_sport), 0)) {
                    if (debug_demux) {
                        demux_counts.bad_src_port++;
                        demux_log("DROP bad-src-port", dest_port,
                                   "src_port=" + std::to_string(our_sport) +
                                   " was never used to probe this port, flags=" +
                                   demux_flags_str(tcph->th_flags),
                                   our_sport, tcph->th_flags,
                                   port_states_arr[didx].attempt_for_src_port(our_sport), iph->ip_ttl, false);
                    }
                    continue;
                }

                if (use_token) {
                    uint8_t flags = tcph->th_flags;
                    if (flags & TH_ACK) {
                        // PERF: compute_token(dest_port) was being recomputed
                        // (a ~10-round SipHash-style mix) on every inbound ACK.
                        // It's a pure function of dest_port and the per-scan
                        // keys, and the SYN we sent already stored that exact
                        // value in port_states_arr[didx].seq (see the init
                        // loop: `seq = use_token ? compute_token(port) : ...`,
                        // and it's never reassigned across retries — retries
                        // resend the same seq). Reuse it instead of
                        // recomputing: same correctness, one load instead of
                        // ~20 ALU/rotate ops, and it reuses a cache line
                        // (port_states_arr[didx]) already touched right below.
                        uint32_t expected_ack = port_states_arr[didx].seq + 1;
                        uint32_t got_ack      = ntohl(tcph->th_ack);
                        if (__builtin_expect(got_ack != expected_ack, 0)) {
                            if (debug_demux) {
                                demux_counts.bad_token++;
                                demux_log("DROP bad-token", dest_port,
                                           "ack=" + std::to_string(got_ack) +
                                           " expected=" + std::to_string(expected_ack) +
                                           " (spoofed or stale reply), flags=" +
                                           demux_flags_str(flags),
                                           our_sport, flags,
                                           port_states_arr[didx].attempt_for_src_port(our_sport), iph->ip_ttl, false);
                            }
                            continue;
                        }
                    } else if (flags & TH_RST) {
                        if (tx_ts_table[didx].load(std::memory_order_acquire) == 0) {
                            if (debug_demux) {
                                demux_counts.stale_rst++;
                                demux_log("DROP stale-rst", dest_port,
                                           "no outstanding probe for this port, flags=" +
                                           demux_flags_str(flags),
                                           our_sport, flags,
                                           port_states_arr[didx].attempt_for_src_port(our_sport), iph->ip_ttl, false);
                            }
                            continue;
                        }
                    }
                }

                if (debug_demux) {
                    demux_counts.matched++;
                    int matched_attempt = port_states_arr[didx].attempt_for_src_port(our_sport);
                    demux_log("MATCH", dest_port,
                               "idx=" + std::to_string(didx) +
                               " attempt=" + std::to_string(matched_attempt) +
                               " (retry_count now=" + std::to_string(port_states_arr[didx].retry_count) + ")" +
                               " ttl=" + std::to_string(iph->ip_ttl),
                               our_sport, tcph->th_flags,
                               matched_attempt, iph->ip_ttl, false);
                }

                int64_t kernel_rx_us_val = rp.kernel_rx_us;
                int64_t tx_us_val        = 0;
                {
                    uint64_t stored = tx_ts_table[didx].load(std::memory_order_acquire);
                    if (stored != 0)
                        tx_us_val = static_cast<int64_t>(stored);
                }

                PortState& pstate_ref = port_states_arr[didx];
                double rtt_here = pstate_ref.rtt_measured ? pstate_ref.ewma_rtt : 0.0;

                uint64_t cap_epoch = (kernel_rx_us_val > 0)
                    ? static_cast<uint64_t>(kernel_rx_us_val)
                    : static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());

                PacketDetails details = extract_packet_details(
                    iph, tcph, bytes, buffer, cap_epoch,
                    kernel_rx_us_val, tx_us_val,
                    pstate_ref.retry_count, rtt_here, pstate_ref);
                packet_details_map[dest_port]    = details;
                result.packet_details[dest_port] = details;
                if (result.received_ttl == 0 && details.ttl != 0)
                    result.received_ttl = details.ttl;

                if (dest_port > 0 && !port_final[didx].load(std::memory_order_acquire)) {
                    PortState& state = port_states_arr[didx];

                    if (!port_rtt_measured[didx].load(std::memory_order_relaxed) &&
                        (tcph->th_flags & (TH_SYN | TH_ACK | TH_RST))) {

                        std::chrono::steady_clock::time_point tx_ref;
                        bool tx_found = false;
                        {
                            uint64_t stored = tx_ts_table[didx].load(std::memory_order_acquire);
                            if (stored != 0) {
                                tx_ref = std::chrono::steady_clock::time_point(
                                    std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                        std::chrono::microseconds(stored)));
                                tx_found = true;
                            }
                        }
                        if (!tx_found) tx_ref = state.syn_sent_time;

                        std::chrono::steady_clock::time_point rx_time;
                        if (kernel_rx_us_val > 0) {
                            auto tv_duration = std::chrono::microseconds(kernel_rx_us_val);
                            auto system_rx = std::chrono::system_clock::time_point(
                                std::chrono::duration_cast<std::chrono::system_clock::duration>(tv_duration));
                            rx_time = steady_from_system(system_rx);
                        } else {
                            rx_time = std::chrono::steady_clock::now();
                        }

                        auto rtt_us = std::chrono::duration_cast<std::chrono::microseconds>(rx_time - tx_ref).count();
                        double rtt_ms = rtt_us / 1000.0;
                        if (rtt_ms > 0.0 && rtt_ms < 30000.0) {
                            // FIX: was std::ceil() — that rounds every single
                            // sample UP, so the tracked/reported RTT carried a
                            // systematic positive bias (worse the more samples
                            // land just above a whole ms). Round to nearest.
                            int int_rtt_ms = static_cast<int>(std::lround(rtt_ms));
                            if (int_rtt_ms < 1) int_rtt_ms = 1;
                            global_rtt_tracker.update(int_rtt_ms);
                            state.ewma_rtt     = rtt_ms;
                            state.rtt_measured = true;
                            port_rtt_measured[didx].store(true, std::memory_order_relaxed);
                        }
                    }

                    bool state_resolved = process_response(
                        state, dest_port, tcph, bytes, iph,
                        dest, packet_queue, scan_type, fast_scan, result,
                        service_map, std::chrono::steady_clock::now(), window_scale, mss_value,
                        timestamp_val, timestamp_ecr_custom, nops_count,
                        sack_permitted, custom_data, data_length,
                        use_custom_data, generate_random_data,
                        print_individual_closed_filtered,
                        use_badsum, custom_badsum_value, badsum_value_set,
                        use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,
                        tfo_cookie_str, tfo_cookie_num, tfo_cookie_length, tl_port_output_buf);

                    if (state_resolved && state.final_state_determined &&
                        !port_final[didx].exchange(true, std::memory_order_acq_rel)) {
                        active_count.fetch_sub(1, std::memory_order_relaxed);
                        tx_ts_table[didx].store(0, std::memory_order_release);
                        if (state.counted_in_retry) {
                            state.counted_in_retry = false;
                            ports_in_retry.fetch_sub(1, std::memory_order_relaxed);
                        }
                        StrackFinalState sfs =
                            state.reported_state == PortState::PortReportedState::Open   ? StrackFinalState::Open   :
                            state.reported_state == PortState::PortReportedState::Closed ? StrackFinalState::Closed :
                                                                                            StrackFinalState::Filtered;
                        strack_log(dest_port, sfs,
                                   state.attempt_for_src_port(our_sport), our_sport,
                                   state.rtt_measured ? state.ewma_rtt : -1.0, false);
                    }
                }
            }
        }

        if (got == 0) {
            // Drain up to 32 items in one bounded bulk op, then split by type.
            // TCP items go back on the queue; ICMP items collected for processing.
            // 32-item cap prevents O(N) churn when the queue is full of TCP packets.
            RawPacket mixed[32];
            const size_t mixed_got = my_queue->try_dequeue_bulk(mixed, 32);
            RawPacket icmp_pkts[8];
            size_t icmp_got = 0;
            for (size_t mi = 0; mi < mixed_got; ++mi) {
                if (mixed[mi].pkt_type == RawPacket::PktType::ICMP && icmp_got < 8) {
                    icmp_pkts[icmp_got++] = std::move(mixed[mi]);
                } else {
                    my_queue->enqueue(std::move(mixed[mi]));
                }
            }

            for (size_t ip = 0; ip < icmp_got; ++ip) {
                const RawPacket& rp        = icmp_pkts[ip];
                const char*      icmp_buf  = reinterpret_cast<const char*>(rp.data);
                const ssize_t    icmp_nb   = static_cast<ssize_t>(rp.len);

                // (1) Outer IP header
                if (icmp_nb < static_cast<ssize_t>(sizeof(struct ip))) continue;
                const struct ip* outer_iph    = reinterpret_cast<const struct ip*>(icmp_buf);
                const int        outer_iphlen = outer_iph->ip_hl * 4;
                if (outer_iphlen < static_cast<int>(sizeof(struct ip))) continue;
                if (icmp_nb < outer_iphlen + static_cast<int>(sizeof(struct icmphdr))) continue;

                const struct icmphdr* icmph = reinterpret_cast<const struct icmphdr*>(
                    icmp_buf + outer_iphlen);

                const uint8_t icmp_type = icmph->type;
                const uint8_t code      = icmph->code;

                // Reconstruct icmp_src for logging (from outer IP src)
                sockaddr_in icmp_src{};
                icmp_src.sin_family      = AF_INET;
                icmp_src.sin_addr.s_addr = outer_iph->ip_src.s_addr;

                // ── Fatal: type 1 code 0 — No Route to Destination ───────────
                if (icmp_type == 1 && code == 0) {
                    // FIX (output ordering): this used to write straight to
                    // std::cerr under cout_mutex, bypassing tl_port_output_buf.
                    // In a multi-target scan every other line for this target
                    // is buffered and flushed as one atomic block once the
                    // target finishes — this one line skipped that queue and
                    // printed immediately, so it showed up interleaved with
                    // whatever other targets' threads were printing at that
                    // instant. Route it through the same buffer so a given
                    // target's output is always one contiguous, ordered block.
                    std::string msg = "[ICMP FATAL] Type 1 Code 0: No Route to Destination"
                                       " from " + std::string(inet_ntoa(icmp_src.sin_addr)) +
                                       " — aborting scan of " + std::string(dest_ip) + "\n";
                    if (tl_port_output_buf) {
                        *tl_port_output_buf += msg;
                    } else {
                        std::lock_guard<std::mutex> lk(cout_mutex);
                        std::cerr << msg;
                    }
                    return result;
                }

                // ── Warnings: type 11 — Time Exceeded ────────────────────────
                if (icmp_type == 11 && (code == 0 || code == 1)) {
                    const char* wm = (code == 0)
                        ? "TTL Expired in Transit (ICMP type 11 code 0)"
                        : "Fragment Reassembly Time Exceeded (ICMP type 11 code 1)";
                    IcmpFilterReason wr = (code == 0)
                        ? IcmpFilterReason::TtlExpired
                        : IcmpFilterReason::FragReassemblyTimeout;
                    result.icmp_warnings.emplace_back(wr, std::string(wm));
                    continue;
                }

                // ── Warning: type 40 code 0 — Bad SPI ────────────────────────
                if (icmp_type == 40 && code == 0) {
                    result.icmp_warnings.emplace_back(
                        IcmpFilterReason::BadSpi,
                        std::string("Bad SPI (Security Parameters Index)"
                                    " (ICMP type 40 code 0)"));
                    continue;
                }

                // Everything below is type 3 (Destination Unreachable) only.
                if (icmp_type != 3) continue;

                // ── Fatal type 3 codes ────────────────────────────────────────
                switch (code) {
                    case 2: case 5: case 6: case 7: case 8: case 14: {
                        const char* fm = "";
                        switch (code) {
                            case 2:  fm = "Protocol Unreachable (ICMP type 3 code 2)";          break;
                            case 5:  fm = "Source Route Failed (ICMP type 3 code 5)";            break;
                            case 6:  fm = "Destination Network Unknown (ICMP type 3 code 6)";   break;
                            case 7:  fm = "Destination Host Unknown (ICMP type 3 code 7)";      break;
                            case 8:  fm = "Source Host Isolated (ICMP type 3 code 8)";          break;
                            case 14: fm = "Host Precedence Violation (ICMP type 3 code 14)";    break;
                        }
                        {
                            std::string msg = std::string("[ICMP FATAL] ") + fm +
                                               " from " + std::string(inet_ntoa(icmp_src.sin_addr)) +
                                               " — aborting scan of " + std::string(dest_ip) + "\n";
                            if (tl_port_output_buf) {
                                *tl_port_output_buf += msg;
                            } else {
                                std::lock_guard<std::mutex> lk(cout_mutex);
                                std::cerr << msg;
                            }
                        }
                        return result;
                    }
                    default: break;
                }

                // ── Warning: type 3 code 4 — Fragmentation Needed, DF set ────
                if (code == 4) {
                    result.icmp_warnings.emplace_back(
                        IcmpFilterReason::FragNeeded,
                        std::string("Fragmentation Needed, DF set (ICMP type 3 code 4)"));
                    continue;
                }

                // Only codes 9, 10, 13 proceed to inner-header parse.
                if (code != 9 && code != 10 && code != 13) continue;

                // (2) Inner IP header + 8-byte TCP stub
                const int inner_off = outer_iphlen + static_cast<int>(sizeof(struct icmphdr));
                if (icmp_nb < inner_off + static_cast<int>(sizeof(struct ip)) + 8) continue;

                const struct ip* inner_iph    = reinterpret_cast<const struct ip*>(
                    icmp_buf + inner_off);
                const int        inner_iphlen = inner_iph->ip_hl * 4;
                if (icmp_nb < inner_off + inner_iphlen + 8) continue;

                // Verify original probe was aimed at our target
                if (inner_iph->ip_dst.s_addr != dest.sin_addr.s_addr) continue;

                // Extract embedded TCP src/dst ports + seq (first 8 bytes of TCP)
                // SECURITY: blocked_port is uint16_t — port_to_idx[blocked_port]
                // is always in-bounds (65536 entries, uint16_t index).
                const uint8_t* tcp_start =
                    reinterpret_cast<const uint8_t*>(icmp_buf) + inner_off + inner_iphlen;
                const uint16_t inner_src_port =
                    ntohs(*reinterpret_cast<const uint16_t*>(tcp_start));
                const uint16_t blocked_port =
                    ntohs(*reinterpret_cast<const uint16_t*>(tcp_start + 2));
                const uint32_t inner_seq =
                    ntohl(*reinterpret_cast<const uint32_t*>(tcp_start + 4));

                if (blocked_port == 0) continue;

                const int32_t bidx = port_to_idx[blocked_port];
                if (bidx < 0) {
                    if (debug_demux) {
                        demux_counts.unknown_port++;
                        demux_log("DROP unknown-port (icmp)", blocked_port,
                                   "not part of this scan, icmp_code=" + std::to_string(code),
                                   inner_src_port, 0, -1, outer_iph->ip_ttl, true);
                    }
                    continue;
                }
                PortState& state = port_states_arr[bidx];
                if (!state.accepts_src_port(inner_src_port)) {
                    if (debug_demux) {
                        demux_counts.bad_src_port++;
                        demux_log("DROP bad-src-port (icmp)", blocked_port,
                                   "embedded src_port=" + std::to_string(inner_src_port) +
                                   " was never used to probe this port, icmp_code=" +
                                   std::to_string(code),
                                   inner_src_port, 0, state.attempt_for_src_port(inner_src_port), outer_iph->ip_ttl, true);
                    }
                    continue;
                }

                // ── token validation on embedded seq ──────────────────────────
                // PERF: compute_token(blocked_port) recomputed the SipHash-style
                // mix per ICMP-filtered packet. state.seq already holds that
                // exact value (see the send-side init loop) and is never
                // reassigned across retries, so it's a safe, equivalent, and
                // much cheaper substitute — also reuses `state`, which we
                // already fetched above instead of loading it twice.
                if (use_token && inner_seq != state.seq) {
                    if (debug_demux) {
                        demux_counts.bad_token++;
                        demux_log("DROP bad-token (icmp)", blocked_port,
                                   "embedded seq=" + std::to_string(inner_seq) +
                                   " expected=" + std::to_string(state.seq) +
                                   " (spoofed or stale ICMP), icmp_code=" + std::to_string(code),
                                   inner_src_port, 0, state.attempt_for_src_port(inner_src_port), outer_iph->ip_ttl, true);
                    }
                    continue;
                }
                if (port_final[bidx].load(std::memory_order_acquire)) continue;

                if (!global_rtt_tracker.should_mark_filtered(state.retry_count)) continue;
                if (state.reported_state != PortState::PortReportedState::None) continue;

                if (debug_demux) {
                    demux_counts.matched++;
                    int icmp_matched_attempt = state.attempt_for_src_port(inner_src_port);
                    demux_log("MATCH (icmp-filtered)", blocked_port,
                               "idx=" + std::to_string(bidx) +
                               " attempt=" + std::to_string(icmp_matched_attempt) +
                               " icmp_code=" + std::to_string(code),
                               inner_src_port, 0, icmp_matched_attempt, outer_iph->ip_ttl, true);
                }

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
                port_final[bidx].store(true, std::memory_order_release);
                active_count.fetch_sub(1, std::memory_order_relaxed);
                tx_ts_table[bidx].store(0, std::memory_order_release);
                if (state.counted_in_retry) {
                    state.counted_in_retry = false;
                    ports_in_retry.fetch_sub(1, std::memory_order_relaxed);
                }
                strack_log(blocked_port, StrackFinalState::Filtered,
                           state.attempt_for_src_port(inner_src_port), inner_src_port,
                           state.rtt_measured ? state.ewma_rtt : -1.0, true);

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
        // ── end ICMP drain ────────────────────────────────────────────────────
        // ── Heap-driven timeout processing ────────────────────────────────
        // Pop every entry whose deadline has already passed.
        // No wasted wakeups: only fires when a real timeout expires.
        // No linear scan: O(log n) heap pop per expired port.
        {
            auto now = std::chrono::steady_clock::now();
            while (!deadline_heap.empty() &&
                   deadline_heap.top().deadline <= now) {

                uint16_t port = deadline_heap.top().port;
                deadline_heap.pop();

                int32_t pidx = port_to_idx[port];
                if (pidx < 0) continue;
                if (port_final[pidx].load(std::memory_order_acquire)) continue;

                PortState& state = port_states_arr[pidx];

                if (state.initial_send_deferred) {
                    // ── deferred FIRST send: rate/jitter delay has elapsed ──
                    // The dispatch loop above only computed pacing and
                    // pushed this deadline; the actual packet is built and
                    // enqueued here, at the moment it's actually due. This
                    // is the non-blocking replacement for the old inline
                    // sleep_for()/hybrid_delay_us() calls in that loop.
                    state.initial_send_deferred = false;
                    state.syn_sent_time = now;   // real send time, for accurate RTT
                    state.start_time    = now;

                    sockaddr_in single_dest = dest;
                    single_dest.sin_port = htons(port);
                    uint8_t tcp_flags = PacketTask::get_flags_for_scan_type(scan_type);

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

                    // NOW push the real RTT-timeout deadline, anchored to
                    // the actual send instant — exactly the guarantee the
                    // old "push after sleep" comment described, just without
                    // ever blocking this thread to get there.
                    deadline_heap.push({now + std::chrono::milliseconds(state.timeout_ms), port});
                    continue;   // this pop is fully handled; don't fall into
                                // the retry_send_deferred / retry logic below
                }

                if (state.retry_send_deferred) {
                    // ── deferred dynamic-delay wakeup: actually send now ────
                    // We already decided to retry; we were just waiting our
                    // turn on the SAME heap instead of blocking the thread.
                    state.retry_send_deferred = false;
                    state.syn_sent_time = now;   // real send time, for accurate RTT
                    tx_ts_table[pidx].store(0, std::memory_order_release);

                    sockaddr_in single_dest = dest;
                    single_dest.sin_port = htons(port);
                    uint8_t tcp_flags = PacketTask::get_flags_for_scan_type(scan_type);

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
                    if (rate_config.enabled) rs.rate_window_sent++;

                    int next_to = global_rtt_tracker.get_timeout_for_retry(state.retry_count);
                    next_to = std::max(MIN_TIMEOUT_MS, std::min(next_to, MAX_TIMEOUT_MS));
                    deadline_heap.push({now + std::chrono::milliseconds(next_to), port});

                } else if (!skip_retries && !global_rtt_tracker.should_mark_filtered(state.retry_count)) {
                    // ── rate gate: NON-BLOCKING ──────────────────────────────
                    // Mirrors the initial-send path's virtual_now/window_end
                    // logic (see the dispatch loop above): instead of
                    // sleep_for()-ing this thread when the rate window is
                    // exhausted, re-push the SAME port onto deadline_heap at
                    // the window's reset instant and bail out of this pop.
                    // Crucially this check now runs BEFORE any state mutation
                    // (retry_count++, src_port reassignment, etc.) below, so
                    // re-popping this entry later is exactly equivalent to
                    // processing it now — nothing has been double-applied.
                    if (rate_config.enabled &&
                        rs.rate_window_sent >= rs.rate_window_target) {
                        auto window_end = rs.rate_window_start +
                            std::chrono::microseconds(rate_config.window_us);
                        if (window_end > now) {
                            deadline_heap.push({window_end, port});
                            continue;   // re-check this port once the window resets
                        }
                        rate_reset_window();
                    }
                    if (bandwidth_config.enabled) {
                        uint64_t used = std::max(bws.reserved_bytes,
                                                  bws.actual_bytes_sent.load(std::memory_order_relaxed));
                        size_t est_bytes = estimate_packet_wire_bytes(opts, scan_type);
                        if (used + est_bytes > bandwidth_config.total_bytes) {
                            auto window_end = bws.window_start +
                                std::chrono::microseconds(bandwidth_config.window_us);
                            if (window_end > now) {
                                deadline_heap.push({window_end, port});
                                continue;   // re-check once the window resets
                            }
                            bws.reserved_bytes = 0;
                            bws.actual_bytes_sent.store(0, std::memory_order_relaxed);
                            bws.window_start   = now;
                            used = 0;
                        }
                        bws.reserved_bytes = used + est_bytes;
                    }

                    // ── prepare retry ────────────────────────────────────────
                    state.retry_count++;
                    state.start_time    = now;
                    state.syn_sent_time = now;
                    state.sent_tsval    = 1234567;
                    // state.retry_count is 1 for the 1st retry (attempt 2)
                    // and 2 for the 2nd retry (attempt 3) at this point.
                    if (sport_range_cfg.stage_is_range[state.retry_count]) {
                        state.src_port = fast_uniform_port(rng,
                            sport_range_cfg.stage_min[state.retry_count],
                            sport_range_cfg.stage_max[state.retry_count]);
                    } else if (gsport_cfg.stage_is_set[state.retry_count]) {
                        state.src_port = gsport_cfg.stage_port[state.retry_count];
                    } else if (state.retry_count == 1) {
                        state.src_port = (retry_source_port > 0) ? retry_source_port
                            : (source_port > 0 ? source_port : fast_uniform_port(rng, 32768, 60999));
                    } else { // retry_count == 2
                        state.src_port = DEFAULT_RETRY2_SPORT;
                    }
                    state.record_src_port(state.src_port, state.retry_count);   // retry_count already bumped at line 3780

                    // ── Dynamic slowdown: NON-BLOCKING ──────────────────────
                    // Instead of sleeping this thread, defer the send by
                    // re-queuing this port on the SAME deadline_heap, further
                    // out in time. No syscall, no blocking, no busy-spin —
                    // it's just another event the existing loop will pop
                    // naturally when its time comes.
                    size_t pir;
                    if (state.retry_count == 1) {
                        pir = ports_in_retry.fetch_add(1, std::memory_order_relaxed) + 1;
                        state.counted_in_retry = true;
                    } else {
                        pir = ports_in_retry.load(std::memory_order_relaxed);
                    }
                    uint64_t timeout_us = static_cast<uint64_t>(
                        global_rtt_tracker.get_timeout_for_retry(state.retry_count)) * 1000ULL;

                    // pir is now a LIVE count of ports currently outstanding
                    // in retry (decremented in the three finalize sites
                    // above), so this ratio rises with active congestion
                    // and falls back down once those ports resolve —
                    // it is no longer a cumulative, one-way ratchet.
                    double filtered_ratio = static_cast<double>(pir) /
                        static_cast<double>(total_ports_count > 0 ? total_ports_count : 1);

                    // Delay scales with the current learned RTT-based
                    // timeout and with how much of the scan is currently
                    // stuck in retry. FILTERED_RATIO_DELAY_FACTOR (1/4 of
                    // the timeout at filtered_ratio==1.0) keeps the
                    // worst-case per-retry delay on the same order as a
                    // single RTT, rather than an arbitrary fraction.
                    //
                    // FIX (retry slowdown not scaling with RTT): the ceiling
                    // used to be a flat MAX_DELAY_US = 5000 (5ms), totally
                    // decoupled from timeout_us. For a LAN host (RTT ~1-2ms)
                    // that's roughly fine. For an internet host with RTT in
                    // the tens-to-hundreds of ms (e.g. 292ms measured here),
                    // the *intended* worst-case delay (0.25 * timeout_us) was
                    // being silently clamped down by 10-60x, so once the
                    // retry queue backed up, retries fired at ~5ms spacing
                    // regardless of how slow/congested the path already
                    // measured as being. That's what produces SYN-flood-like
                    // bursts against distant hosts, which their edge/rate
                    // limiters then drop nondeterministically — the exact
                    // run-to-run flakiness you're seeing (ports flipping
                    // open/filtered between identical back-to-back scans).
                    // The ceiling now scales with the target's own measured
                    // timeout: half of timeout_us, floored at the old 5ms
                    // (so fast LAN hosts aren't slowed down) and capped at an
                    // absolute 250ms so a single very slow/lossy path can't
                    // balloon the per-retry stagger without bound.
                    constexpr double   FILTERED_RATIO_DELAY_FACTOR = 0.6;
                    constexpr uint64_t MIN_DELAY_US         = 1000;    // floor: avoid effectively-zero stagger
                    constexpr uint64_t MAX_DELAY_FLOOR_US   = 20000;   // raised floor for the ceiling
                    constexpr uint64_t MAX_DELAY_ABS_CAP_US = 500000;  // 500ms absolute worst case
                    const uint64_t max_delay_us = std::clamp<uint64_t>(
                        timeout_us / 2, MAX_DELAY_FLOOR_US, MAX_DELAY_ABS_CAP_US);
                    uint64_t delay_us = static_cast<uint64_t>(
                        timeout_us * filtered_ratio * FILTERED_RATIO_DELAY_FACTOR);
                    delay_us = std::clamp(delay_us, MIN_DELAY_US, max_delay_us);

                    // Stagger against the previous deferred retry so
                    // simultaneous timeouts don't all re-fire in the same
                    // heap tick (burst avoidance). The stagger is capped at
                    // "now + max_delay_us" so a large pile-up of retries
                    // cannot compound into unbounded queueing — previously
                    // next_retry_dispatch_time accumulated without limit.
                    state.retry_send_deferred = true;
                    auto desired_time        = now + std::chrono::microseconds(delay_us);
                    auto staggered_time      = std::max(next_retry_dispatch_time, desired_time);
                    auto watermark_cap       = now + std::chrono::microseconds(max_delay_us);
                    auto dispatch_time       = std::min(staggered_time, watermark_cap);
                    next_retry_dispatch_time = dispatch_time;
                    deadline_heap.push({dispatch_time, port});

                } else {
                    // ── retries exhausted: mark filtered ──────────────────
                    // ── retries exhausted: mark filtered ──────────────────
                    if (state.reported_state == PortState::PortReportedState::None) {
                        result.filtered_ports.push_back(port);
                        state.reported_state = PortState::PortReportedState::Filtered;
                        // No packet ever matched this port — resolved_attempt=-1
                        // distinguishes "never answered" from "answered late
                        // via retry", which attempt_for_src_port() can't do
                        // here since there's no src_port on a non-existent reply.
                        strack_log(port, StrackFinalState::Filtered, -1, 0, -1.0, false);
                    }
                    state.final_state_determined = true;
                    port_final[pidx].store(true, std::memory_order_release);
                    active_count.fetch_sub(1, std::memory_order_relaxed);
                    if (state.counted_in_retry) {
                        state.counted_in_retry = false;
                        ports_in_retry.fetch_sub(1, std::memory_order_relaxed);
                    }
                }
            }
        }
        // ── end heap processing ───────────────────────────────────────────

    }

    {
        PacketTask poison_pill;
        poison_pill.is_poison = true;
        packet_queue.enqueue(std::move(poison_pill));
    }
    if (sender_thread.joinable()) {
        sender_thread.join();
    }
    int max_observed_rtt = 0;

    for (int port : ports) {
        if (port <= 0 || port > 65535) continue;
        int32_t fidx = port_to_idx[static_cast<uint16_t>(port)];
        if (fidx < 0) continue;
        PortState& state = port_states_arr[fidx];

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

    // --debug demux: hand this batch's buffered events/counters up to the
    // caller (thread_worker) instead of printing here. thread_worker merges
    // every batch's contribution into one whole-scan total for this target,
    // and print_demux_debug() prints that total exactly once, after the
    // scan finishes — see the comment above demux_log() for why.
    if (debug_demux) {
        result.demux_counts += demux_counts;
        result.demux_debug_entries.insert(result.demux_debug_entries.end(),
            demux_entries.begin(), demux_entries.end());
    }
    if (debug_strack) {
        result.strack_counts += strack_counts;
        result.strack_entries.insert(result.strack_entries.end(),
            strack_entries.begin(), strack_entries.end());
    }

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
    std::cout << color::cyan << "🌐 Endpoints\n" << color::reset;
    std::cout << "Src IP:Port  : " << color::yellow << d.src_ip << ":" << d.src_port << color::reset << "\n";
    std::cout << "Dst IP:Port  : " << color::yellow << d.dst_ip << ":" << d.dst_port << color::reset << "\n";

    // ── Section 2: IP Header ───────────────────────────────────────────────
    std::cout << color::cyan << "🔵 IP Header\n" << color::reset;
    std::cout << "IP ID        : " << color::yellow << d.ip_id         << color::reset << "\n";
    std::cout << "Total Length : " << color::yellow << d.ip_total_length << " B" << color::reset << "\n";
    std::cout << "Header Len   : " << color::yellow << static_cast<int>(d.ip_header_len) << " B" << color::reset << "\n";
    std::cout << "TTL          : " << color::yellow << static_cast<int>(d.ttl) << color::reset << "\n";
    std::cout << "Protocol     : " << color::yellow << static_cast<int>(d.ip_protocol) << color::reset << "\n";
    std::cout << "TOS          : " << color::yellow << hex8(d.ip_tos)  << color::reset << "\n";
    std::cout << "DF Flag      : " << set_notset(d.df_flag)            << "\n";
    std::cout << "MF Flag      : " << set_notset(d.ip_mf_flag)         << "\n";
    std::cout << "Frag Offset  : " << color::yellow << (d.ip_frag_off_raw & 0x1FFF) << color::reset << "\n";
    std::cout << "Checksum     : " << color::yellow << hex16(d.ip_checksum) << color::reset
              << "  valid=" << yn(d.ip_checksum_valid) << "\n";
    std::cout << "Hop Distance : " << color::yellow << d.hop_distance_est << " hops" << color::reset << "\n";

    // ── Section 3: TCP Header ──────────────────────────────────────────────
    std::cout << color::cyan << "🟢 TCP Header\n" << color::reset;
    std::cout << "Src Port     : " << color::yellow << d.src_port      << color::reset << "\n";
    std::cout << "Flags        : " << color::yellow << tcp_flags_str(d.tcp_flags)
              << " (" << hex8(d.tcp_flags) << ")" << color::reset << "\n";
    std::cout << "Seq Num      : " << color::yellow << d.seq_num       << color::reset << "\n";
    std::cout << "Ack Num      : " << color::yellow << d.ack_num       << color::reset << "\n";
    std::cout << "Window       : " << color::yellow << d.window_size   << color::reset << "\n";
    std::cout << "Header Len   : " << color::yellow << static_cast<int>(d.tcp_header_len) << " B" << color::reset << "\n";
    std::cout << "Data Offset  : " << color::yellow << static_cast<int>(d.tcp_data_offset) << color::reset << "\n";
    std::cout << "URG Ptr      : " << color::yellow << d.tcp_urg_ptr   << color::reset << "\n";
    std::cout << "Checksum     : " << color::yellow << hex16(d.checksum) << color::reset
              << "  valid=" << yn(d.tcp_checksum_valid) << "\n";

    // ── Section 4: TCP Options ─────────────────────────────────────────────
    std::cout << color::cyan << "⚙️  TCP Options\n" << color::reset;
    std::cout << "Layout       : " << color::yellow
              << (d.tcp_option_layout.empty() ? "(none)" : d.tcp_option_layout)
              << color::reset << "\n";
    std::cout << "MSS          : "
              << (d.has_mss ? color::yellow + std::to_string(d.mss_value) + color::reset
                            : color::dim + std::string("N/A") + color::reset) << "\n";
    std::cout << "Window Scale : "
              << (d.has_window_scale
                    ? color::yellow + std::to_string(static_cast<int>(d.window_scale)) + color::reset
                    : color::dim + std::string("N/A") + color::reset) << "\n";
    std::cout << "SACK-OK      : " << yn(d.sack_permitted) << "\n";
    std::cout << "SACK Blocks  : " << yn(d.has_sack_blocks);
    if (d.has_sack_blocks && !d.sack_blocks.empty()) {
        std::cout << "  [";
        for (size_t i = 0; i < d.sack_blocks.size(); ++i) {
            std::cout << d.sack_blocks[i].first << "-" << d.sack_blocks[i].second;
            if (i + 1 < d.sack_blocks.size()) std::cout << ", ";
        }
        std::cout << "]";
    }
    std::cout << "\n";
    std::cout << "Timestamp    : " << yn(d.has_timestamp)
              << "  TSval=" << color::yellow << d.tsval << color::reset
              << "  TSecr=" << color::yellow << d.tsecr << color::reset << "\n";
    std::cout << "TFO          : " << yn(d.has_tfo)
              << (d.has_tfo ? ("  data=" + color::yellow + d.tfo_data + color::reset) : "") << "\n";
    std::cout << "NOPs         : " << yn(d.has_nops) << "  count=" << d.nop_count << "\n";
    std::cout << "EOL          : " << yn(d.has_eol)
              << (d.has_eol ? "  offset=" + std::to_string(d.eol_offset) : "") << "\n";
    std::cout << "Unknown Opts : " << yn(d.has_unknown_options);
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
    std::cout << color::cyan << "📄 Payload\n" << color::reset;
    std::cout << "Length       : " << color::yellow << d.payload_len << " B" << color::reset << "\n";
    std::cout << "Has Payload  : " << yn(d.has_payload) << "\n";
    std::cout << "Preview      : ";
    if (d.payload.empty()) {
        std::cout << color::dim << "(empty)" << color::reset;
    } else {
        std::cout << color::yellow << d.payload.substr(0, 64)
                  << (d.payload.size() > 64 ? "..." : "") << color::reset;
    }
    std::cout << "\n";
    std::cout << "Raw Hex (first 16 B): ";
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
    std::cout << color::cyan << "⏱️  Timing\n" << color::reset;
    std::cout << "Capture Epoch   : " << color::yellow << d.capture_epoch_us << " µs" << color::reset << "\n";
    std::cout << "Kernel RX TS    : " << color::yellow << d.kernel_rx_ts_us  << " µs" << color::reset << "\n";
    std::cout << "User RX TS      : " << color::yellow << d.user_rx_ts_us    << " µs" << color::reset << "\n";
    std::cout << "TX TS           : " << color::yellow << d.tx_ts_us         << " µs" << color::reset << "\n";
    std::cout << "RTT             : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_ms   << " ms" << color::reset << "\n";
    std::cout << "RTT EWMA        : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_ewma_ms << " ms" << color::reset << "\n";
    std::cout << "RTT Jitter      : " << color::yellow << std::fixed << std::setprecision(3) << d.rtt_jitter_ms << " ms" << color::reset << "\n";
    std::cout << "RTT Outlier     : " << yn(d.rtt_outlier) << "\n";
    std::cout << "TTL Outlier     : " << yn(d.ttl_outlier) << "\n";

    // ── Section 7: Probe Context ───────────────────────────────────────────
    std::cout << color::cyan << "🔬 Sent Probe\n" << color::reset;
    std::cout << "Retry Index  : " << color::yellow << d.retry_index << color::reset << "\n";
    std::cout << "Flags        : " << color::yellow << tcp_flags_str(d.sent_flags)
              << " (" << hex8(d.sent_flags) << ")" << color::reset << "\n";
    std::cout << "TTL          : " << color::yellow << static_cast<int>(d.sent_ttl) << color::reset << "\n";
    std::cout << "Window Scale : " << color::yellow << static_cast<int>(d.sent_ws)  << color::reset << "\n";
    std::cout << "TSval        : " << color::yellow << d.sent_tsval       << color::reset << "\n";
    std::cout << "MSS          : " << color::yellow << d.sent_mss         << color::reset << "\n";
    std::cout << "Seq          : " << color::yellow << d.sent_seq         << color::reset << "\n";
    std::cout << "Ack          : " << color::yellow << d.sent_ack         << color::reset << "\n";
    std::cout << "Window Size  : " << color::yellow << d.sent_window_size << color::reset << "\n";
    std::cout << "DSCP         : " << color::yellow << static_cast<int>(d.sent_dscp)   << color::reset << "\n";
    std::cout << "IP TOS       : " << color::yellow << hex8(d.sent_ip_tos) << color::reset << "\n";
    std::cout << "DF           : " << yn(d.sent_df)           << "\n";
    std::cout << "SACK-OK      : " << yn(d.sent_sack_permitted) << "\n";

    // ── Section 8: Classification ──────────────────────────────────────────
    std::cout << color::cyan << "🏷️  Classification\n" << color::reset;
    std::cout << "Flow Hash    : " << color::yellow << hex32(d.flow_hash) << color::reset << "\n";
    std::cout << "Probe ID     : " << color::yellow << d.probe_id         << color::reset << "\n";
    std::cout << "Resp Index   : " << color::yellow << d.response_index   << color::reset << "\n";
    std::cout << "Duplicate    : " << yn(d.duplicate_response)           << "\n";
    std::cout << "Retransmit?  : " << yn(d.retransmission_suspect)       << "\n";
    std::cout << "Reason       : " << color::yellow
              << (d.classification_reason.empty() ? "(none)" : d.classification_reason)
              << color::reset << "\n";
    std::cout << "Anomaly Score: " << color::yellow << d.anomaly_score     << color::reset << "\n";
    std::cout << "Confidence   : " << color::yellow << std::fixed << std::setprecision(2)
              << d.anomaly_confidence << color::reset << "\n";
    std::cout << "Tags         : ";
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
    std::cout << color::cyan << "🧮 Raw Packet (first 64 B)\n" << color::reset;
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

    std::cout << color::cyan << "📈 Summary" << color::reset << "\n";
    std::cout << "    State: " << state_color << state_text << color::reset
              << " (" << color::yellow << __builtin_popcount(d.tcp_flags) << color::reset << " flags active)\n\n";

}

void display_sent_packet_details(const SentPacketDetails& d, bool debug_enabled) {
    if (!debug_enabled) return;

    auto yn = [](bool v) { return v ? (color::green + "Yes" + color::reset)
                                     : (color::red   + "No"  + color::reset); };
    auto hex16 = [](uint16_t v) {
        std::ostringstream ss; ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << v;
        return ss.str();
    };
    auto tcp_flags_str = [](uint8_t f) {
        std::string s;
        if (f & TH_FIN)  s += "FIN ";  if (f & TH_SYN) s += "SYN ";
        if (f & TH_RST)  s += "RST ";  if (f & TH_PUSH) s += "PSH ";
        if (f & TH_ACK)  s += "ACK ";  if (f & TH_URG) s += "URG ";
        if (f & TH_ECE)  s += "ECE ";  if (f & TH_CWR) s += "CWR ";
        if (s.empty()) s = "NONE"; else if (s.back()==' ') s.pop_back();
        return s;
    };

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "\n";
    std::cout << color::cyan << "╔══════════════════════════════════════════════════════\n";
    std::cout << color::cyan << "║ 🚀 Sent Packet — " << d.dst_ip << ":" << d.dst_port
              << " (src " << d.src_port << ")" << color::reset << "\n";
    std::cout << color::cyan << "╚══════════════════════════════════════════════════════\n" << color::reset;

    std::cout << color::cyan << "🔵 IP Header\n" << color::reset;
    std::cout << "IP ID        : " << color::yellow << d.ip_id << color::reset << "\n";
    std::cout << "Total Length : " << color::yellow << d.ip_total_length << " B" << color::reset << "\n";
    std::cout << "Header Len   : " << color::yellow << (int)d.ip_header_len << " B" << color::reset << "\n";
    std::cout << "TTL          : " << color::yellow << (int)d.ttl << color::reset << "\n";
    std::cout << "TOS          : " << color::yellow << hex16(d.ip_tos) << color::reset << "\n";
    std::cout << "DF/MF        : " << yn(d.df_flag) << " / " << yn(d.mf_flag)
              << "  frag_off=" << d.ip_frag_off_raw << "\n";
    std::cout << "IP Checksum  : " << color::yellow << hex16(d.ip_checksum) << color::reset << "\n";

    std::cout << color::cyan << "🟢 TCP Header\n" << color::reset;
    std::cout << "Flags        : " << color::yellow << tcp_flags_str(d.tcp_flags) << color::reset << "\n";
    std::cout << "Seq/Ack      : " << color::yellow << d.seq_num << " / " << d.ack_num << color::reset << "\n";
    std::cout << "Window       : " << color::yellow << d.window_size << color::reset << "\n";
    std::cout << "Header Len   : " << color::yellow << (int)d.tcp_header_len << " B"
              << " (options=" << d.options_len << " B)" << color::reset << "\n";
    std::cout << "Checksum     : " << color::yellow << hex16(d.checksum) << color::reset
              << "  mode=" << color::yellow << d.checksum_mode << color::reset << "\n";

    std::cout << color::cyan << "⚙️  TCP Options\n" << color::reset;
    std::cout << "MSS=" << yn(d.has_mss) << "(" << d.mss_value << ")"
              << "  WS=" << yn(d.has_window_scale) << "(" << (int)d.window_scale << ")"
              << "  SACK=" << yn(d.sack_permitted)
              << "  TS=" << yn(d.has_timestamp)
              << "  TFO=" << yn(d.has_tfo)
              << "  MPTCP=" << yn(d.has_mptcp)
              << "  TCP-AO=" << yn(d.has_tcp_ao) << "\n";

    std::cout << color::cyan << "📄 Payload / Sizing\n" << color::reset;
    std::cout << "Payload Len  : " << color::yellow << d.payload_len << " B" << color::reset << "\n";
    std::cout << "Total Pkt    : " << color::yellow << d.total_packet_len << " B" << color::reset << "\n";
    if (!d.payload_preview.empty()) {
        std::cout << "Preview Hex  : ";
        for (auto b : d.payload_preview) {
            char hx[3]; std::snprintf(hx, sizeof(hx), "%02X", b);
            std::cout << color::yellow << hx << color::reset << " ";
        }
        std::cout << "\n";
    }

    std::cout << color::cyan << "🧩 Fragmentation / Flags\n" << color::reset;
    std::cout << "Fragmented   : " << yn(d.fragmented)
              << (d.fragmented ? "  step=" + std::to_string(d.frag_step) : "") << "\n";
    std::cout << "Malformed    : " << yn(d.intentional_malformed) << "\n";
    if (d.packet_length_adjusted)
        std::cout << "--packet-length target=" << d.packet_length_target
                  << "  actual=" << d.total_packet_len << "\n";
}

void flush_sent_packet_debug() {
    std::lock_guard<std::mutex> lock(sent_debug_mutex);
    for (const auto& sd : sent_debug_log) {
        display_sent_packet_details(sd, true);
    }
    sent_debug_log.clear();
}

[[gnu::always_inline]] inline bool process_response(PortState& state, uint16_t dest_port, 
                                   struct tcphdr* tcph, int bytes, struct ip* iph,sockaddr_in& dest, moodycamel::BlockingConcurrentQueue<PacketTask>& packet_queue,ScanType scan_type, bool fast_scan, RecPross& result,
                                   const std::unordered_map<uint16_t, std::string>& service_map,std::chrono::steady_clock::time_point current_time,uint8_t window_scale, uint16_t mss_value, uint32_t timestamp_val,
                                   uint32_t timestamp_ecr_custom, uint16_t nops_count, bool sack_permitted,const std::string& custom_data, uint16_t data_length,bool use_custom_data, bool generate_random_data, bool  
                                   print_individual_closed_filtered,bool use_badsum, uint16_t custom_badsum_value, bool badsum_value_set, bool use_partial_badsum, const std::string& partial_badsum_type,
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
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_FIN | TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, mss_value, timestamp_val, 
                        timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
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
                    packet_queue.enqueue(PacketTask(
                        single_dest, state.src_port, state.seq + 1, state.ack_seq, TH_FIN | TH_ACK, std::string(), current_time, 0, scan_type, 1234567, 0, true, window_scale, mss_value, timestamp_val, 
                        timestamp_ecr_custom, nops_count, sack_permitted, custom_data, data_length, use_custom_data, generate_random_data,use_badsum, custom_badsum_value,use_partial_badsum, partial_badsum_type,
                        use_tfo_cookie, tfo_cookie_as_hex, tfo_cookie_random,tfo_cookie_str, tfo_cookie_num, tfo_cookie_length
                    ));
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

std::unique_ptr<GlobalSendCtx> init_global_send_ctx(
    int    sock,
    size_t send_uring_depth,
    size_t num_ports,
    bool   enable_sqpoll)
{
    if (sock < 0) {
        std::cerr << "[GlobalSend] invalid socket fd\n";
        return nullptr;
    }
    auto ctx = std::make_unique<GlobalSendCtx>();
    ctx->sock = sock;

    // SECURITY + RELIABILITY: set an explicit send buffer so the kernel
    // doesn't silently drop packets when the default (~200KB) fills under
    // burst. SO_SNDBUFFORCE bypasses the sysctl cap (requires CAP_NET_ADMIN).
    int sndbuf = 4 * 1024 * 1024;  // 4MB
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE,
                   &sndbuf, sizeof(sndbuf)) < 0)
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    {
        int actual = 0; socklen_t len = sizeof(actual);
        if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &actual, &len) == 0
                && actual < sndbuf)
            std::cerr << "[GlobalSend] sndbuf clamped to " << actual
                      << " — raise net.core.wmem_max for full performance\n";
    }

    size_t depth = send_uring_depth > 0
        ? send_uring_depth
        : std::min<size_t>(2048, std::max<size_t>(128, num_ports));
        
    depth--;
    depth |= depth >> 1; depth |= depth >> 2; depth |= depth >> 4;
    depth |= depth >> 8; depth |= depth >> 16;
    depth++;
    depth = std::max<size_t>(128, depth);

    // NOTE: do NOT add IORING_SETUP_SINGLE_ISSUER here.
    // send_tcp_packets() is called from sender_thread (a std::thread spawned
    // inside receive_response). SINGLE_ISSUER registers the first thread that
    // submits as the sole issuer; if init runs on one thread and submit runs
    // on another, the kernel returns EEXIST on every io_uring_submit() call.
    // SQPOLL is compatible with this: it changes who *drains* the SQ ring
    // (a kernel thread instead of the calling thread on io_uring_enter), not
    // who's allowed to write to it, so the multi-instantiation submit
    // pattern above is unaffected.
    //
    // SQPOLL: a kernel thread continuously watches this ring's SQ. As long
    // as it hasn't gone idle, io_uring_submit() becomes a pure userspace
    // ring-tail write — no io_uring_enter(2) syscall at all — which is the
    // main win on the TX hot path (one submit per batch-fill iteration).
    // sq_thread_idle is how long (ms) the poller spins with no work before
    // parking; if it parks, the next submit pays for one wakeup syscall,
    // which is still far cheaper than a syscall on every submit.
    //
    // enable_sqpoll gate: SQPOLL's kernel poller thread busy-spins on its
    // own core for essentially the entire active portion of the scan —
    // sq_thread_idle only trims the idle *tail* after the last submission,
    // it does nothing to reduce spinning while packets are still flowing.
    // Measured: a short single-host scan (~1300 probes, <1s) paid ~1.3
    // cores of sys time for SQPOLL on both rings while gaining no
    // measurable wall-clock improvement over the plain ring, because the
    // io_uring_enter syscalls SQPOLL elides were already cheap at that
    // volume. SQPOLL only pays for itself once probe volume is high enough
    // that the eliminated syscalls would have cost more than the core(s)
    // spent keeping the poller hot. The caller (main.cpp) decides
    // enable_sqpoll from total expected probe volume for the run; below
    // that threshold we skip straight to the plain COOP_TASKRUN ring.
    if (enable_sqpoll) {
        struct io_uring_params sqpoll_params{};
        // COOP_TASKRUN deliberately omitted here: on some kernels the
        // SQPOLL + COOP_TASKRUN combination is rejected with EINVAL (kernel
        // thread-driven completion conflicts with cooperative deferred
        // task-work). SQPOLL alone inits fine on those same kernels, so we
        // request it by itself and keep COOP_TASKRUN only on the plain-ring
        // fallback below.
        sqpoll_params.flags          = IORING_SETUP_SQPOLL;
        // sq_thread_idle was 2000ms — dropped to 50ms so the poller parks
        // promptly once a large scan's tail genuinely goes idle, instead of
        // spinning for up to 2s past the last batch regardless of scan
        // length. Still comfortably covers back-to-back-batch gaps.
        sqpoll_params.sq_thread_idle = 50;   // ms before the poller parks

        int sqpoll_ret = io_uring_queue_init_params(depth, &ctx->ring, &sqpoll_params);
        if (sqpoll_ret == 0) {
            ctx->sqpoll_active = true;
        } else {
            // liburing's queue_init functions return -errno directly, not -1
            // with errno set — strerror(errno) here would silently print
            // whatever errno happened to be left over from an unrelated
            // earlier call (often "Success"). strerror(-sqpoll_ret) is the
            // actual reason this call failed.
            std::cerr << "[GlobalSend] SQPOLL init failed (" << strerror(-sqpoll_ret)
                      << ") — falling back to non-SQPOLL ring\n";
            int plain_ret = io_uring_queue_init(depth, &ctx->ring, IORING_SETUP_COOP_TASKRUN);
            if (plain_ret < 0) {
                std::cerr << "[GlobalSend] io_uring_queue_init failed: "
                          << strerror(-plain_ret) << "\n";
                return nullptr;
            }
        }
    } else {
        // This is a performance opt-in, not a requirement to run: older
        // kernels, missing CAP_SYS_ADMIN on pre-5.11 kernels, or
        // RLIMIT_MEMLOCK exhaustion can all make SQPOLL init fail anyway,
        // so below-threshold scans go straight to the plain ring rather
        // than paying SQPOLL's init cost for a mode they won't benefit from.
        int plain_ret = io_uring_queue_init(depth, &ctx->ring, IORING_SETUP_COOP_TASKRUN);
        if (plain_ret < 0) {
            std::cerr << "[GlobalSend] io_uring_queue_init failed: "
                      << strerror(-plain_ret) << "\n";
            return nullptr;
        }
    }
    ctx->valid = true;

    // ── Fixed-file registration ─────────────────────────────────────────
    // sock is long-lived for the whole ring's lifetime, so registering it
    // once here lets every sendmsg SQE skip the kernel's fdget()/fdput()
    // atomic refcount pair per op.
    {
        int reg_ret = io_uring_register_files(&ctx->ring, &sock, 1);
        if (reg_ret == 0) {
            g_send_fixed_file_active.store(true, std::memory_order_release);
        } else {
            std::cerr << "[GlobalSend] io_uring_register_files failed ("
                      << strerror(-reg_ret)
                      << ") — falling back to raw-fd sendmsg\n";
            g_send_fixed_file_active.store(false, std::memory_order_release);
        }
    }

    return ctx;
}

std::unique_ptr<GlobalRecvCtx> init_global_recv_ctx(
    const std::vector<std::string>& target_ips,
    size_t                          rcv_uring_depth,
    int                             user_rcvbuf_size,
    bool                            enable_sqpoll)
{
    auto ctx = std::make_unique<GlobalRecvCtx>();

    // ── TCP recv socket ────────────────────────────────────────────────────
    ctx->tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (ctx->tcp_sock < 0) {
        std::cerr << "[GlobalRecv] TCP socket failed: " << strerror(errno) << "\n";
        return nullptr;
    }

    // SO_RCVBUFFORCE bypasses net.core.rmem_max cap (requires CAP_NET_ADMIN,
    // which Shiv already holds for SOCK_RAW). Falls back to SO_RCVBUF if
    // running without sufficient privilege.
    int rcvbuf = user_rcvbuf_size > 0 ? user_rcvbuf_size : 64 * 1024 * 1024;
    if (setsockopt(ctx->tcp_sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(ctx->tcp_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    // DEBUG: confirm the kernel didn't silently clamp SO_RCVBUF below what
    // we requested (common cause of silent drops under burst traffic).
    {
        int actual_rcvbuf = 0;
        socklen_t len = sizeof(actual_rcvbuf);
        if (getsockopt(ctx->tcp_sock, SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &len) == 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
        }
    }

    int ts = 1;
    setsockopt(ctx->tcp_sock, SOL_SOCKET, SO_TIMESTAMP, &ts, sizeof(ts));

    // DEBUG: SO_RXQ_OVFL reports (via cmsg) how many packets the kernel
    // dropped from THIS socket's receive queue because it was full --
    // a direct signal of receive-side buffer overflow.
#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif
    int rxq_ovfl = 1;
    setsockopt(ctx->tcp_sock, SOL_SOCKET, SO_RXQ_OVFL, &rxq_ovfl, sizeof(rxq_ovfl));

    {
        struct sock_filter tcp_filter[] = {
	    // Step 1: read IHL from byte 0, convert to byte count → store in X
	    { BPF_LD  | BPF_B   | BPF_ABS,  0, 0, 0     },  // A  = pkt[0]
	    { BPF_ALU | BPF_AND | BPF_K,    0, 0, 0x0f  },  // A &= 0x0f   (IHL in words)
	    { BPF_ALU | BPF_LSH | BPF_K,    0, 0, 2     },  // A <<= 2     (IHL in bytes)
	    { BPF_MISC| BPF_TAX,             0, 0, 0     },  // X  = A      (X = IP hdr len)

	    // Step 2: load TCP flags byte at [ip_hdr_len + 13], save a copy in X
	    { BPF_LD  | BPF_B   | BPF_IND,  0, 0, 13    },  // A = pkt[X+13] (TCP flags)
	    { BPF_MISC| BPF_TAX,             0, 0, 0     },  // X = flags (saved copy)

	    // Step 3: exact match SYN+ACK (both bits set, nothing else required)
	    { BPF_ALU | BPF_AND | BPF_K,    0, 0, 0x12  },  // A = flags & 0x12
	    { BPF_JMP | BPF_JEQ | BPF_K,    2, 0, 0x12  },  // == 0x12 exactly → jump to PASS

	    // Step 4: restore original flags, accept if RST bit set
	    { BPF_MISC| BPF_TXA,             0, 0, 0     },  // A = flags (restored)
	    { BPF_JMP | BPF_JSET | BPF_K,   0, 1, 0x04  },  // RST set → fall through to PASS

	    // PASS: deliver this packet to userspace
	    { BPF_RET | BPF_K,               0, 0, 65535 },

	    // DROP: discard — kernel frees the sk_buff immediately, no wakeup
	    { BPF_RET | BPF_K,               0, 0, 0     },
	};
        struct sock_fprog tcp_fprog = {
            .len    = static_cast<unsigned short>(
                          sizeof(tcp_filter) / sizeof(tcp_filter[0])),
            .filter = tcp_filter,
        };
        if (setsockopt(ctx->tcp_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                       &tcp_fprog, sizeof(tcp_fprog)) < 0) {
            std::cerr << "[GlobalRecv] BPF attach failed: " << strerror(errno)
                      << " — continuing without filter (more CPU noise)\n";
        }
    }
    // ── end BPF ───────────────────────────────────────────────────────────────

    int fl = fcntl(ctx->tcp_sock, F_GETFL, 0);
    if (fl < 0 || fcntl(ctx->tcp_sock, F_SETFL, fl | O_NONBLOCK) < 0) {
        std::cerr << "[GlobalRecv] fcntl O_NONBLOCK failed: " << strerror(errno) << "\n";
        return nullptr;
    }

    // ── ICMP socket: create, filter, and init metadata ────────────────────
    // Moved ahead of ring init (this used to happen further down, right
    // before the ICMP SQE-arming loop) so that both tcp_sock and icmp_sock
    // are known before we call io_uring_register_files() further below —
    // fixed-file registration needs the complete fd set up front.
    //
    // Security rationale: a single shared ICMP raw socket, created once here,
    // replaces the per-call icmp_err_sock that was being opened and closed
    // inside every receive_response() invocation. The old model had two
    // problems: (1) a new socket per call meant N concurrent scans had N
    // competing sockets all receiving the same ICMP error — last one to call
    // recvfrom won, others got EAGAIN; (2) recvfrom ran in a tight non-blocking
    // loop every 8 iterations, burning syscalls regardless of packet arrival.
    //
    // The new model: one socket, N_ICMP_SLOTS (4) recv SQEs permanently armed
    // in g_recv->ring. The reader thread delivers raw ICMP packets to the
    // appropriate per-target queue (keyed on the inner IP dst of the embedded
    // probe header), where receive_response() drains them alongside TCP packets.
    //
    // BPF filter accepts types 1, 3, 11, 40 — all types that receive_response
    // processes. Type 3 is the most common (Destination Unreachable).
    ctx->icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->icmp_sock >= 0) {
        // Non-blocking: io_uring will arm recvmsg SQEs; O_NONBLOCK prevents
        // the kernel from blocking on the socket if a CQE is reaped late.
        int icmp_fl = fcntl(ctx->icmp_sock, F_GETFL, 0);
        if (icmp_fl >= 0) fcntl(ctx->icmp_sock, F_SETFL, icmp_fl | O_NONBLOCK);

        int icmp_rcvbuf = 8 * 1024 * 1024;
        if (setsockopt(ctx->icmp_sock, SOL_SOCKET, SO_RCVBUFFORCE,
                       &icmp_rcvbuf, sizeof(icmp_rcvbuf)) < 0)
            setsockopt(ctx->icmp_sock, SOL_SOCKET, SO_RCVBUF,
                       &icmp_rcvbuf, sizeof(icmp_rcvbuf));

        // ── BPF: accept ICMP types 1, 3, 11, 40 only ────────────────────
        // Packet layout for IPPROTO_ICMP raw socket starts at outer IP header.
        //   pkt[0]     = version+IHL
        //   pkt[X + 0] = ICMP type  (X = IHL * 4)
        //
        // Encodes: accept if type ∈ {1, 3, 11, 40}, drop everything else.
        // Using a jump table avoids branching on each type individually.
        struct sock_filter icmp_filter[] = {
            // A = pkt[0]; A &= 0x0f; A <<= 2; X = A  (IP hdr length in bytes)
            { BPF_LD  | BPF_B   | BPF_ABS,  0, 0, 0    },
            { BPF_ALU | BPF_AND | BPF_K,    0, 0, 0x0f },
            { BPF_ALU | BPF_LSH | BPF_K,    0, 0, 2    },
            { BPF_MISC| BPF_TAX,             0, 0, 0    },
            // A = pkt[X]  (ICMP type byte)
            { BPF_LD  | BPF_B   | BPF_IND,  0, 0, 0    },
            // Accept type 3 (most common — Dest Unreachable)
            { BPF_JMP | BPF_JEQ | BPF_K,    3, 0, 3    },
            // Accept type 11 (Time Exceeded)
            { BPF_JMP | BPF_JEQ | BPF_K,    2, 0, 11   },
            // Accept type 1 (No Route to Dest)
            { BPF_JMP | BPF_JEQ | BPF_K,    1, 0, 1    },
            // Accept type 40 (Bad SPI)
            { BPF_JMP | BPF_JEQ | BPF_K,    0, 1, 40   },
            // PASS
            { BPF_RET | BPF_K,               0, 0, 65535},
            // DROP
            { BPF_RET | BPF_K,               0, 0, 0   },
        };
        struct sock_fprog icmp_fprog = {
            .len    = static_cast<unsigned short>(
                          sizeof(icmp_filter) / sizeof(icmp_filter[0])),
            .filter = icmp_filter,
        };
        if (setsockopt(ctx->icmp_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                       &icmp_fprog, sizeof(icmp_fprog)) < 0) {
            std::cerr << "[GlobalRecv] ICMP BPF attach failed: "
                      << strerror(errno) << " — continuing without filter\n";
        }
        // ── end BPF ──────────────────────────────────────────────────────

        // Init ICMP slot metadata (iov + msghdr each pointing at icmp_bufs[s])
        for (size_t s = 0; s < GlobalRecvCtx::N_ICMP_SLOTS; ++s) {
            ctx->icmp_src_lens[s]         = sizeof(ctx->icmp_src_addrs[s]);
            ctx->icmp_iovs[s].iov_base    = ctx->icmp_bufs[s].data();
            ctx->icmp_iovs[s].iov_len     = ctx->icmp_bufs[s].size();
            ctx->icmp_msgs[s]             = {};
            ctx->icmp_msgs[s].msg_name    = &ctx->icmp_src_addrs[s];
            ctx->icmp_msgs[s].msg_namelen = sizeof(ctx->icmp_src_addrs[s]);
            ctx->icmp_msgs[s].msg_iov     = &ctx->icmp_iovs[s];
            ctx->icmp_msgs[s].msg_iovlen  = 1;
        }
    } else {
        std::cerr << "[GlobalRecv] ICMP socket failed: " << strerror(errno)
                  << " — ICMP errors will not be detected\n";
        // Non-fatal: TCP scanning still works without ICMP.
    }
    // ── end ICMP socket setup (metadata only; SQE arming happens later,
    // after the ring exists and fixed-file registration has run) ──────────

    size_t depth = rcv_uring_depth > 0
        ? rcv_uring_depth
        : std::min<size_t>(1024, std::max<size_t>(128, target_ips.size() * 8));

    // HEADROOM: the ring is submitter for two kinds of SQEs beyond the
    // steady-state TCP/ICMP recv slots below — deferred slot rearms
    // (pending_rearm, pre-existing) and, as of the MSG_RING wake path in
    // recv_reader_thread_func, one wake SQE per distinct target that got
    // new data in a batch. With N_SLOTS sized as `depth - 1 - N_ICMP_SLOTS`,
    // the ring only ever has a single free SQE slot in steady state — not
    // enough for rearms alone under load, let alone rearms + wakes for
    // several targets in the same batch. Both get_sqe() call sites already
    // handle a full SQ gracefully (rearm defers to pending_rearm; a failed
    // wake just leaves that target on its timeout floor) so this isn't a
    // correctness fix, but without headroom most wakes would silently no-op
    // under any multi-target scan, defeating the point of the MSG_RING path.
    // N_SLOTS below is deliberately still derived from `depth`, not
    // ring_depth, so TCP/ICMP slot counts (and their buffer memory) are
    // unchanged from before — this only adds spare SQ capacity.
    const size_t WAKE_REARM_HEADROOM =
        std::clamp<size_t>(target_ips.size() * 2, 16, 256);
    const size_t ring_depth = depth + WAKE_REARM_HEADROOM;

    // SQPOLL here only removes the submit-side syscalls (the initial
    // io_uring_submit() that arms all TCP/ICMP recv slots, plus rearm
    // submissions folded into io_uring_submit_and_wait_timeout()). The
    // *wait* portion of submit_and_wait_timeout — actually blocking this
    // thread until a completion or the timeout fires — still needs its own
    // io_uring_enter(2) regardless of SQPOLL; there is no way to block a
    // thread without a syscall. So expect this ring's io_uring_enter count
    // to drop some, not collapse the way the TX ring's will.
    //
    // enable_sqpoll gated by the caller the same way as GlobalSend — see
    // that function's comment for the measured cost/benefit rationale.
    if (enable_sqpoll) {
        struct io_uring_params sqpoll_params{};
        // COOP_TASKRUN deliberately omitted here: on some kernels the
        // SQPOLL + COOP_TASKRUN combination is rejected with EINVAL (kernel
        // thread-driven completion conflicts with cooperative deferred
        // task-work). SQPOLL alone inits fine on those same kernels, so we
        // request it by itself and keep COOP_TASKRUN only on the plain-ring
        // fallback below.
        sqpoll_params.flags          = IORING_SETUP_SQPOLL;
        // See matching comment on the GlobalSend ring above: 2000ms let this
        // ring's poller thread spin a full core for the entire duration of
        // short scans. Dropped to 50ms so it parks promptly once responses
        // stop arriving.
        sqpoll_params.sq_thread_idle = 50;   // ms before the poller parks

        int sqpoll_ret = io_uring_queue_init_params(ring_depth, &ctx->ring, &sqpoll_params);
        if (sqpoll_ret == 0) {
            ctx->sqpoll_active = true;
        } else {
            // Same note as init_global_send_ctx: liburing returns -errno
            // directly here, so strerror(-sqpoll_ret) is the real reason,
            // not strerror(errno).
            std::cerr << "[GlobalRecv] SQPOLL init failed (" << strerror(-sqpoll_ret)
                      << ") — falling back to non-SQPOLL ring\n";
            int plain_ret = io_uring_queue_init(ring_depth, &ctx->ring,
                    IORING_SETUP_COOP_TASKRUN);
            if (plain_ret < 0) {
                std::cerr << "[GlobalRecv] io_uring_queue_init failed: " << strerror(-plain_ret) << "\n";
                return nullptr;
            }
        }
    } else {
        int plain_ret = io_uring_queue_init(ring_depth, &ctx->ring,
                IORING_SETUP_COOP_TASKRUN);
        if (plain_ret < 0) {
            std::cerr << "[GlobalRecv] io_uring_queue_init failed: " << strerror(-plain_ret) << "\n";
            return nullptr;
        }
    }
    ctx->valid = true;

    // ── Fixed-file registration ──────────────────────────────────────────
    // Register tcp_sock (and icmp_sock, if it opened) once here, before any
    // recvmsg SQE below is prepped, so every TCP/ICMP recv op — initial arm
    // and every rearm — can use IOSQE_FIXED_FILE and skip fdget()/fdput().
    {
        std::vector<int> reg_fds{ ctx->tcp_sock };
        if (ctx->icmp_sock >= 0) reg_fds.push_back(ctx->icmp_sock);

        int reg_ret = io_uring_register_files(&ctx->ring, reg_fds.data(),
                                               reg_fds.size());
        if (reg_ret == 0) {
            ctx->fixed_files_active = true;
            ctx->tcp_fixed_idx  = 0;
            ctx->icmp_fixed_idx = (ctx->icmp_sock >= 0) ? 1 : -1;
        } else {
            std::cerr << "[GlobalRecv] io_uring_register_files failed ("
                      << strerror(-reg_ret)
                      << ") — falling back to raw-fd recvmsg\n";
        }
    }

    // ── slot buffers ───────────────────────────────────────────────────────
    constexpr size_t SLOT_SIZE = 4096;
    const size_t     N_SLOTS   = depth - 1 < 8 ? 8 : depth - 1 - GlobalRecvCtx::N_ICMP_SLOTS;
    ctx->buf_storage = std::make_unique<uint8_t[]>(N_SLOTS * SLOT_SIZE);
    std::memset(ctx->buf_storage.get(), 0, N_SLOTS * SLOT_SIZE);
    ctx->bufs = ctx->buf_storage.get();
    ctx->slots.resize(N_SLOTS);

    for (size_t s = 0; s < N_SLOTS; ++s) {
        ctx->slots[s].src_len            = sizeof(ctx->slots[s].src_addr);
        ctx->slots[s].iov.iov_base       = ctx->bufs + s * SLOT_SIZE;
        ctx->slots[s].iov.iov_len        = SLOT_SIZE;
        ctx->slots[s].msg                = {};
        ctx->slots[s].msg.msg_name       = &ctx->slots[s].src_addr;
        ctx->slots[s].msg.msg_namelen    = sizeof(ctx->slots[s].src_addr);
        ctx->slots[s].msg.msg_iov        = &ctx->slots[s].iov;
        ctx->slots[s].msg.msg_iovlen     = 1;
        ctx->slots[s].msg.msg_control    = ctx->slots[s].cmsg_buf;
        ctx->slots[s].msg.msg_controllen = sizeof(ctx->slots[s].cmsg_buf);
    }

    // ── IP → index map AND per-target SPSC queues ─────────────────────────
    for (size_t i = 0; i < target_ips.size(); ++i) {
        struct in_addr a{};
        if (inet_pton(AF_INET, target_ips[i].c_str(), &a) == 1) {
            ctx->ip_to_idx[a.s_addr] = i;
            ctx->target_queues.emplace(
                a.s_addr,
                std::make_unique<moodycamel::ConcurrentQueue<RawPacket>>(8192));
        }
    }
    for (size_t s = 0; s < N_SLOTS; ++s) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) break;
        if (ctx->fixed_files_active) {
            io_uring_prep_recvmsg(sqe, ctx->tcp_fixed_idx, &ctx->slots[s].msg, 0);
            io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
        } else {
            io_uring_prep_recvmsg(sqe, ctx->tcp_sock, &ctx->slots[s].msg, 0);
        }
        io_uring_sqe_set_data64(sqe, static_cast<uint64_t>(s));
    }

    // ── ICMP socket: arm recv SQEs in the shared ring ─────────────────────
    // Socket creation, BPF filter, and slot metadata init already happened
    // earlier (right after the TCP socket's O_NONBLOCK setup, before ring
    // init) so that fixed-file registration above had both fds up front.
    // This just arms the N_ICMP_SLOTS recvmsg SQEs.
    // user_data = ICMP_SLOT_FLAG | slot_index — reader dispatches on flag.
    if (ctx->icmp_sock >= 0) {
        for (size_t s = 0; s < GlobalRecvCtx::N_ICMP_SLOTS; ++s) {
            struct io_uring_sqe* sqe = io_uring_get_sqe(&ctx->ring);
            if (!sqe) {
                std::cerr << "[GlobalRecv] No SQE for ICMP slot " << s << "\n";
                break;
            }
            if (ctx->fixed_files_active && ctx->icmp_fixed_idx >= 0) {
                io_uring_prep_recvmsg(sqe, ctx->icmp_fixed_idx,
                                      &ctx->icmp_msgs[s], 0);
                io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
            } else {
                io_uring_prep_recvmsg(sqe, ctx->icmp_sock,
                                      &ctx->icmp_msgs[s], 0);
            }
            io_uring_sqe_set_data64(sqe,
                GlobalRecvCtx::ICMP_SLOT_FLAG | static_cast<uint64_t>(s));
        }
    }
    // ── end ICMP SQE arming ────────────────────────────────────────────────

    ctx->reader_started = true;
    ctx->reader_thread  = std::thread(recv_reader_thread_func, ctx.get());

    return ctx;
}

void recv_reader_thread_func(GlobalRecvCtx* ctx) {
    constexpr size_t SLOT_SIZE = 4096;
    struct io_uring&        ring      = ctx->ring;
    std::vector<SlotMeta>&  slots     = ctx->slots;
    uint8_t*                recv_bufs = ctx->bufs;

    // SECURITY: pending_rearm holds both TCP slot indices (< slots.size())
    // and ICMP sentinels (slots.size() + icmp_slot_index). The decode in
    // the rearm loop below checks the range before any array access.
    std::vector<size_t> pending_rearm;
    std::unordered_set<size_t> pending_rearm_set;   // O(1) duplicate guard for pending_rearm

    // Non-static local counters — reset cleanly on every scan batch.
    // Static atomics were wrong: stale values from batch N triggered false
    // overflow alerts at the start of batch N+1.
    uint64_t lost_slot_warnings  = 0;
    uint64_t dbg_oversized_drops = 0;
    uint64_t dbg_rxq_ovfl_total  = 0;
    uint64_t dbg_cq_overflow_last = 0;
    uint64_t dbg_loop_iters      = 0;
    uint64_t dbg_slow_iters      = 0;
    auto     dbg_last_report     = std::chrono::steady_clock::now();

    // ── MSG_RING wake tracking ──────────────────────────────────────────
    // Targets that received at least one newly-dispatched packet this
    // batch. Deduped (a burst of packets for the same host only needs one
    // wake signal). Reused across iterations to avoid reallocating.
    std::unordered_set<uint32_t> woken_ips;

    // Submit all SQEs that were queued during init (TCP slots + ICMP slots).
    // Done here on the reader thread so that this thread is the sole submitter
    // for this ring — consistent with IORING_SETUP_SINGLE_ISSUER semantics
    // even without the flag, and safe for future re-enabling of that flag.
    io_uring_submit(&ring);

    while (!terminate_flag && !ctx->reader_stop.load(std::memory_order_acquire)) {

        // ── Re-arm deferred slots (TCP and ICMP) ──────────────────────────
        // Process pending_rearm before waiting for new CQEs so these slots
        // get back into the ring as soon as an SQE slot is free.
        for (size_t pi = 0; pi < pending_rearm.size(); ) {
            size_t slot_idx = pending_rearm[pi];
            struct io_uring_sqe* rsqe = io_uring_get_sqe(&ring);
            if (!rsqe) { ++pi; continue; }  // SQ still full, try next iteration

            if (slot_idx < slots.size()) {
                // TCP slot
                SlotMeta& sm = slots[slot_idx];
                sm.src_len            = sizeof(sm.src_addr);
                sm.msg.msg_namelen    = sizeof(sm.src_addr);
                sm.msg.msg_iovlen     = 1;
                sm.iov.iov_len        = SLOT_SIZE;
                sm.msg.msg_control    = sm.cmsg_buf;
                sm.msg.msg_controllen = sizeof(sm.cmsg_buf);
                if (ctx->fixed_files_active) {
                    io_uring_prep_recvmsg(rsqe, ctx->tcp_fixed_idx, &sm.msg, 0);
                    io_uring_sqe_set_flags(rsqe, IOSQE_FIXED_FILE);
                } else {
                    io_uring_prep_recvmsg(rsqe, ctx->tcp_sock, &sm.msg, 0);
                }
                io_uring_sqe_set_data64(rsqe, static_cast<uint64_t>(slot_idx));
            } else {
                // ICMP slot — sentinel = slots.size() + icmp_slot
                size_t icmp_slot = slot_idx - slots.size();
                // SECURITY: bounds-check the decoded index before any array access.
                if (icmp_slot >= GlobalRecvCtx::N_ICMP_SLOTS) {
                    // Corrupt sentinel — discard silently.
                    pending_rearm_set.erase(pending_rearm[pi]);
                    pending_rearm[pi] = pending_rearm.back();
                    pending_rearm.pop_back();
                    continue;
                }
                ctx->icmp_src_lens[icmp_slot]         = sizeof(ctx->icmp_src_addrs[icmp_slot]);
                ctx->icmp_msgs[icmp_slot].msg_namelen = sizeof(ctx->icmp_src_addrs[icmp_slot]);
                ctx->icmp_iovs[icmp_slot].iov_len     = ctx->icmp_bufs[icmp_slot].size();
                ctx->icmp_msgs[icmp_slot].msg_iovlen  = 1;
                if (ctx->fixed_files_active && ctx->icmp_fixed_idx >= 0) {
                    io_uring_prep_recvmsg(rsqe, ctx->icmp_fixed_idx,
                                          &ctx->icmp_msgs[icmp_slot], 0);
                    io_uring_sqe_set_flags(rsqe, IOSQE_FIXED_FILE);
                } else {
                    io_uring_prep_recvmsg(rsqe, ctx->icmp_sock,
                                          &ctx->icmp_msgs[icmp_slot], 0);
                }
                io_uring_sqe_set_data64(rsqe,
                    GlobalRecvCtx::ICMP_SLOT_FLAG |
                    static_cast<uint64_t>(icmp_slot));
            }
            // Swap-erase: O(1) removal, order doesn't matter for rearm queue.
            pending_rearm_set.erase(slot_idx);
            pending_rearm[pi] = pending_rearm.back();
            pending_rearm.pop_back();
        }

        // wait_nr=8: block until 8 CQEs are ready OR the timeout fires,
        // whichever comes first. Trades a small amount of RX latency for
        // far fewer io_uring_enter calls when completions trickle in one
        // at a time instead of arriving as a burst. If fewer than 8 land
        // before the timeout, -ETIME just means "not all 8 in time" —
        // nothing is lost, whatever did arrive stays in the CQ ring for
        // the next iteration's peek/wait to pick up.
        struct __kernel_timespec timeout_ts = { .tv_sec = 0,
                                                .tv_nsec = 50 * 1000 * 1000 };
        // min_wait_usec: once the FIRST cqe of this batch shows up, give
        // stragglers this long to join it before we give up on filling
        // all 8 — avoids paying the full 50ms whenever only 2-3 arrive.
        constexpr unsigned MIN_BATCH_SETTLE_US = 500; // tune 200-1000us
        struct io_uring_cqe* cqe;
        int ret = io_uring_submit_and_wait_min_timeout(
                      &ring, &cqe, 8, &timeout_ts, MIN_BATCH_SETTLE_US, nullptr);
        if (ret == -ETIME || ret == -EINTR) continue;
        if (ret < 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "[recv_reader] io_uring error: " << strerror(-ret) << "\n";
            continue;
        }
        if (__builtin_expect(!cqe, 0)) continue;

        auto dbg_iter_start = std::chrono::steady_clock::now();

        // ── Batch collection ───────────────────────────────────────────────
        // Drain the ENTIRE ready CQ ring in one syscall-free peek loop, not
        // just a fixed 33-entry slice. user_data is uint64_t — treat as
        // untrusted until bounds-checked below.
        struct CqeInfo { uint64_t user_data; int bytes; };
        constexpr size_t MAX_BATCH = 256;
        std::array<CqeInfo, MAX_BATCH> batch;
        size_t n = 0;

        // The CQE handed to us by submit_and_wait_timeout still needs its
        // own seen() call since it wasn't peeked into our array.
        batch[n++] = { io_uring_cqe_get_data64(cqe), cqe->res };
        io_uring_cqe_seen(&ring, cqe);

        // Keep peeking in chunks until the ring is empty or batch is full —
        // a single 32-wide peek can leave entries behind during a burst;
        // looping here costs zero extra syscalls since peek never blocks.
        struct io_uring_cqe* peeked[64];
        while (n < MAX_BATCH) {
            unsigned want = static_cast<unsigned>(
                std::min<size_t>(64, MAX_BATCH - n));
            unsigned n_peeked = io_uring_peek_batch_cqe(&ring, peeked, want);
            if (n_peeked == 0) break;

            for (unsigned pi = 0; pi < n_peeked; ++pi)
                batch[n++] = { io_uring_cqe_get_data64(peeked[pi]), peeked[pi]->res };

            io_uring_cq_advance(&ring, n_peeked);   // one advance per peek chunk

            if (n_peeked < want) break;   // ring drained, no point looping again
        }

        for (size_t ci = 0; ci < n; ++ci) {
            const uint64_t ud    = batch[ci].user_data;
            const int      bytes = batch[ci].bytes;

            // ── MSG_RING wake-ack ────────────────────────────────────────────
            // Completion of a wake signal WE submitted (targeting another
            // thread's idle_ring). It carries no recv data of its own — it's
            // just this ring's confirmation that the MSG_RING op finished.
            // Nothing to re-arm, nothing to dispatch. Checked first so it
            // can never be misread as a TCP slot index or collide with
            // ICMP_SLOT_FLAG.
            if (ud & GlobalRecvCtx::WAKE_ACK_FLAG) continue;

            // ── ICMP dispatch ──────────────────────────────────────────────
            if (ud & GlobalRecvCtx::ICMP_SLOT_FLAG) {
                const size_t icmp_slot = static_cast<size_t>(
                    ud & ~GlobalRecvCtx::ICMP_SLOT_FLAG);

                // SECURITY: bounds-check before any array access.
                if (icmp_slot < GlobalRecvCtx::N_ICMP_SLOTS) {
                    do {
                        if (bytes <= 0) break;

                        const uint8_t* pkt  = ctx->icmp_bufs[icmp_slot].data();
                        const int      plen = bytes;

                        if (plen < static_cast<int>(sizeof(struct ip))) break;
                        const struct ip* outer_iph =
                            reinterpret_cast<const struct ip*>(pkt);
                        const int outer_iphlen = outer_iph->ip_hl * 4;
                        if (outer_iphlen < static_cast<int>(sizeof(struct ip))) break;

                        if (plen < outer_iphlen +
                                static_cast<int>(sizeof(struct icmphdr))) break;

                        const int inner_off = outer_iphlen +
                            static_cast<int>(sizeof(struct icmphdr));
                        if (plen < inner_off +
                                static_cast<int>(sizeof(struct ip)) + 8) break;

                        const struct ip* inner_iph =
                            reinterpret_cast<const struct ip*>(pkt + inner_off);
                        const int inner_iphlen = inner_iph->ip_hl * 4;
                        if (plen < inner_off + inner_iphlen + 8) break;

                        auto* q = ctx->queue_for(inner_iph->ip_dst.s_addr);
                        if (q) {
                            RawPacket pkt_out;
                            pkt_out.pkt_type = RawPacket::PktType::ICMP;
                            const int copy_len =
                                (plen <= static_cast<int>(RawPacket::MAX_LEN))
                                ? plen : static_cast<int>(RawPacket::MAX_LEN);
                            std::memcpy(pkt_out.data, pkt, copy_len);
                            pkt_out.len = copy_len;
                            q->enqueue(std::move(pkt_out));
                            woken_ips.insert(inner_iph->ip_dst.s_addr);
                        }
                    } while (false);

                    // Re-arm: if SQ full, push to pending_rearm so the slot
                    // is recovered next iteration instead of lost permanently.
                    ctx->icmp_src_lens[icmp_slot] =
                        sizeof(ctx->icmp_src_addrs[icmp_slot]);
                    ctx->icmp_msgs[icmp_slot].msg_namelen =
                        sizeof(ctx->icmp_src_addrs[icmp_slot]);
                    ctx->icmp_iovs[icmp_slot].iov_len =
                        ctx->icmp_bufs[icmp_slot].size();
                    ctx->icmp_msgs[icmp_slot].msg_iovlen = 1;
                    {
                        struct io_uring_sqe* rsqe = io_uring_get_sqe(&ring);
                        if (rsqe) {
                            if (ctx->fixed_files_active && ctx->icmp_fixed_idx >= 0) {
                                io_uring_prep_recvmsg(rsqe, ctx->icmp_fixed_idx,
                                                      &ctx->icmp_msgs[icmp_slot], 0);
                                io_uring_sqe_set_flags(rsqe, IOSQE_FIXED_FILE);
                            } else {
                                io_uring_prep_recvmsg(rsqe, ctx->icmp_sock,
                                                      &ctx->icmp_msgs[icmp_slot], 0);
                            }
                            io_uring_sqe_set_data64(rsqe,
                                GlobalRecvCtx::ICMP_SLOT_FLAG |
                                static_cast<uint64_t>(icmp_slot));
                        } else {
                            // SECURITY: defer rather than lose the slot.
                            size_t icmp_sentinel = slots.size() + icmp_slot;
                            if (pending_rearm_set.insert(icmp_sentinel).second)
                                pending_rearm.push_back(icmp_sentinel);
                        }
                    }
                }
                // Corrupt icmp_slot: skip without re-arming (nothing to re-arm).
                continue;
            }

            // ── TCP dispatch ───────────────────────────────────────────────
            const size_t slot_idx  = static_cast<size_t>(ud);
            const int    tcp_bytes = bytes;

            // SECURITY: bounds-check user_data before any dereference.
            if (slot_idx >= slots.size()) continue;
            SlotMeta& sm = slots[slot_idx];

            if (tcp_bytes == -ENETDOWN || tcp_bytes == -ENETUNREACH ||
                tcp_bytes == -ENONET) {
                if (!network_disconnect_flag.exchange(true)) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << "\n[!] Network disconnected — exiting\n";
                }
                terminate_flag.store(true);
                break;
            }

            if (tcp_bytes > 0 &&
                tcp_bytes <= static_cast<int>(RawPacket::MAX_LEN)) {
                const char* buffer = reinterpret_cast<const char*>(
                    recv_bufs + slot_idx * SLOT_SIZE);
                const struct ip* iph = reinterpret_cast<const struct ip*>(buffer);
                int iphdrlen = iph->ip_hl * 4;

                if (iphdrlen >= static_cast<int>(sizeof(struct ip)) &&
                    iphdrlen <= tcp_bytes &&
                    iph->ip_p == IPPROTO_TCP &&
                    tcp_bytes >= iphdrlen +
                        static_cast<int>(sizeof(struct tcphdr)))
                {
                    auto* q = ctx->queue_for(iph->ip_src.s_addr);
                    if (q) {
                        RawPacket pkt;
                        pkt.pkt_type = RawPacket::PktType::TCP;
                        pkt.len      = tcp_bytes;
                        std::memcpy(pkt.data, buffer, tcp_bytes);

                        int64_t kernel_rx_us = 0;
                        for (struct cmsghdr* c = CMSG_FIRSTHDR(&sm.msg);
                             c; c = CMSG_NXTHDR(&sm.msg, c)) {
                            if (c->cmsg_level != SOL_SOCKET) continue;
                            if (c->cmsg_type == SO_TIMESTAMP) {
                                struct timeval* tv =
                                    reinterpret_cast<struct timeval*>(
                                        CMSG_DATA(c));
                                kernel_rx_us =
                                    static_cast<int64_t>(tv->tv_sec)
                                    * 1'000'000LL +
                                    static_cast<int64_t>(tv->tv_usec);
                            } else if (c->cmsg_type == SO_RXQ_OVFL) {
                                uint32_t ovfl = 0;
                                std::memcpy(&ovfl, CMSG_DATA(c), sizeof(ovfl));
                                if (ovfl > 0) {
                                    uint64_t prev = dbg_rxq_ovfl_total;
                                    dbg_rxq_ovfl_total = ovfl;
                                    if (ovfl != prev) {
                                        std::lock_guard<std::mutex> lk(cout_mutex);
                                        std::cerr << "[recv_reader] SO_RXQ_OVFL: "
                                                  << ovfl
                                                  << " kernel drops on TCP socket\n";
                                    }
                                }
                            }
                        }
                        pkt.kernel_rx_us = kernel_rx_us;
                        q->enqueue(std::move(pkt));
                        woken_ips.insert(iph->ip_src.s_addr);
                    }
                }
            } else if (tcp_bytes > static_cast<int>(RawPacket::MAX_LEN)) {
                ++dbg_oversized_drops;
            } else if (tcp_bytes < 0 &&
                       tcp_bytes != -EAGAIN &&
                       tcp_bytes != -EWOULDBLOCK &&
                       tcp_bytes != -EINTR) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "[recv_reader] recvmsg error: "
                          << strerror(-tcp_bytes) << "\n";
            }

            // Re-arm TCP slot
            sm.src_len            = sizeof(sm.src_addr);
            sm.msg.msg_namelen    = sizeof(sm.src_addr);
            sm.msg.msg_iovlen     = 1;
            sm.iov.iov_len        = SLOT_SIZE;
            sm.msg.msg_control    = sm.cmsg_buf;
            sm.msg.msg_controllen = sizeof(sm.cmsg_buf);

            {
                struct io_uring_sqe* rsqe = io_uring_get_sqe(&ring);
                if (rsqe) {
                    if (ctx->fixed_files_active) {
                        io_uring_prep_recvmsg(rsqe, ctx->tcp_fixed_idx, &sm.msg, 0);
                        io_uring_sqe_set_flags(rsqe, IOSQE_FIXED_FILE);
                    } else {
                        io_uring_prep_recvmsg(rsqe, ctx->tcp_sock, &sm.msg, 0);
                    }
                    io_uring_sqe_set_data64(rsqe, static_cast<uint64_t>(slot_idx));
                } else {
                    if (pending_rearm_set.insert(slot_idx).second)
                        pending_rearm.push_back(slot_idx);
                    ++lost_slot_warnings;
                    if (lost_slot_warnings <= 10 ||
                        lost_slot_warnings % 1000 == 0) {
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::cerr << "[recv_reader] slot " << slot_idx
                                  << " deferred re-arm (count="
                                  << lost_slot_warnings << ")\n";
                    }
                }
            }
        }

        // ── Wake targets whose queue just got new data ─────────────────────
        // For every distinct host we enqueued a packet for above, submit an
        // IORING_OP_MSG_RING to that host's registered idle_ring so its
        // receive_response() loop returns from io_uring_submit_and_wait_timeout
        // immediately instead of waiting out its poll interval. This is the
        // event-driven replacement for that loop discovering new data only
        // via periodic re-checks.
        //
        // SECURITY: the shared_lock is held across lookup *and* submit, not
        // just the lookup. unregister_idle_ring() (called when a target's
        // worker_thread tears down its idle_ring) blocks on the paired
        // unique_lock until we release this shared_lock, so the fd we submit
        // MSG_RING against here cannot be closed out from under us — see the
        // contract documented on GlobalRecvCtx::idle_ring_mu in scan.hpp.
        //
        // Best-effort: if the reader ring's SQ is momentarily full, or a
        // target simply isn't registered (not yet started, or already torn
        // down), we skip that signal silently. Nothing is lost — the target
        // host's own timeout floor is the safety net, this is purely a
        // latency optimization, never a correctness dependency.
        if (!woken_ips.empty()) {
            std::shared_lock idle_lock(ctx->idle_ring_mu);
            bool queued_wake = false;
            for (uint32_t wip : woken_ips) {
                auto it = ctx->idle_ring_fds.find(wip);
                if (it == ctx->idle_ring_fds.end()) continue;

                struct io_uring_sqe* wsqe = io_uring_get_sqe(&ring);
                if (!wsqe) break;  // SQ full — remaining wakes fall back to timeout

                io_uring_prep_msg_ring(wsqe, it->second, 0,
                                        GlobalRecvCtx::WAKE_ACK_FLAG, 0);
                io_uring_sqe_set_data64(wsqe, GlobalRecvCtx::WAKE_ACK_FLAG);
                queued_wake = true;
            }
            if (queued_wake) {
                // Submit now, while still holding idle_lock, so the actual
                // io_uring_enter() (the point at which the kernel posts the
                // CQE into the target ring) happens before any unregister
                // can proceed. Non-blocking: we only submit, we don't wait.
                int wret = io_uring_submit(&ring);
                if (wret < 0) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << "[recv_reader] MSG_RING submit: "
                              << strerror(-wret) << "\n";
                }
            }
            woken_ips.clear();
        }

        // ── CQ overflow recovery ───────────────────────────────────────────
        // If koverflow > last seen, some CQEs were dropped by the kernel.
        // Any slot whose CQE was lost is now permanently dead unless we
        // re-arm it explicitly. Re-queue all slots not already pending.
        if (ring.cq.koverflow) {
            uint64_t cur = *ring.cq.koverflow;
            if (cur != dbg_cq_overflow_last) {
                dbg_cq_overflow_last = cur;
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "[recv_reader] CQ overflow (" << cur
                          << " lost) — re-arming all slots\n";
                for (size_t s = 0; s < slots.size(); ++s) {
                    if (pending_rearm_set.insert(s).second)
                        pending_rearm.push_back(s);
                }
                for (size_t s = 0; s < GlobalRecvCtx::N_ICMP_SLOTS; ++s) {
                    size_t sentinel = slots.size() + s;
                    if (pending_rearm_set.insert(sentinel).second)
                        pending_rearm.push_back(sentinel);
                }
            }
        }

        auto dbg_iter_dur = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - dbg_iter_start).count();
        ++dbg_loop_iters;
        if (dbg_iter_dur > 20) ++dbg_slow_iters;

        auto dbg_now = std::chrono::steady_clock::now();
        if (dbg_now - dbg_last_report > std::chrono::seconds(2)) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            dbg_last_report = dbg_now;
        }
    }
}

void worker_thread(const char *ip, uint32_t local_ip, const char* source_ip, const std::vector<int>& ports, 
                   std::mt19937 &rng, PacketBufferPool &pool, int send_sock, RecPross &result, size_t main_batch_size, uint32_t seq_num,
                   uint16_t win_size, int ip_version, bool print_individual_closed_filtered, bool print_filtered_if_few, struct io_uring *send_ring, bool fast_scan,
                   ScanType scan_type, uint8_t custom_ttl, uint8_t custom_dscp,uint16_t custom_ip_flags,IpIdMode ip_id_mode, uint16_t fixed_ip_id,
                   const TcpBuildOptions& opts,
                   int user_rcvbuf_size,
                   size_t send_uring_depth, size_t rcv_uring_depth,
                   uint16_t source_port, uint16_t retry_source_port, bool debug_packet,bool debug_rtt,bool debug_wsn,bool debug_ttl,bool debug_demux,bool debug_strack,bool debug_send,bool frag_out_of_order,bool frag_overlap, uint16_t frag_overlap_bytes,bool frag_zof,
                   const SportRangeConfig& sport_range_cfg,const GsportConfig& gsport_cfg,int initial_rtt_ms,int port_timeout_min_ms, int
                   port_timeout_max_ms,RateConfig rate_config,JitterConfig jitter_config,BatchDelayConfig batch_delay_config,
                   BandwidthConfig bandwidth_config,bool is_threaded,GlobalRecvCtx* g_recv) {
                   
    // Local aliases: same names the body below has always used, now backed
    // by the shared opts struct instead of ~29 individual parameters.
    const bool&        use_manual_tcp_checksum = opts.use_manual_tcp_checksum;
    const uint16_t&    manual_tcp_checksum     = opts.manual_tcp_checksum;
    const uint8_t&     window_scale            = opts.window_scale;
    const uint16_t&    mss_value               = opts.mss_value;
    const uint32_t&    timestamp_val           = opts.timestamp_val;
    const uint32_t&    timestamp_ecr_custom    = opts.timestamp_ecr_custom;
    const uint16_t&    nops_count              = opts.nops_count;
    const bool&        sack_permitted          = opts.sack_permitted;
    const std::string& custom_data             = opts.custom_data;
    const uint16_t&    data_length             = opts.data_length;
    const bool&        use_custom_data         = opts.use_custom_data;
    const bool&        generate_random_data    = opts.generate_random_data;
    const bool&        use_badsum              = opts.use_badsum;
    const uint16_t&    custom_badsum_value     = opts.custom_badsum_value;
    const bool&        badsum_value_set        = opts.badsum_value_set;
    const bool&        use_partial_badsum      = opts.use_partial_badsum;
    const std::string& partial_badsum_type     = opts.partial_badsum_type;
    const bool&        use_tfo_cookie          = opts.use_tfo_cookie;
    const bool&        tfo_cookie_as_hex       = opts.tfo_cookie_as_hex;
    const bool&        tfo_cookie_random       = opts.tfo_cookie_random;
    const std::string& tfo_cookie_str          = opts.tfo_cookie_str;
    const uint64_t&    tfo_cookie_num          = opts.tfo_cookie_num;
    const size_t&      tfo_cookie_length       = opts.tfo_cookie_length;
    const bool&        use_fragmentation       = opts.use_fragmentation;
    const uint16_t&    frag_size               = opts.frag_size;
    const uint16_t&    mtu_size                = opts.mtu_size;
    const bool&        use_ip_tos              = opts.use_ip_tos;
    const uint8_t&     custom_ip_tos_byte      = opts.custom_ip_tos_byte;
    const PacketLengthConfig& packet_length_config = opts.packet_length_config;

    size_t effective_batch_size = main_batch_size;
    if (ports.empty() || terminate_flag) {
        return;
    }
    // Owns the --rate window state for this target's ENTIRE scan (every
    // batch in the loop below shares this one instance via pointer), so
    // the rate limiter's window carries across batch boundaries instead of
    // restarting — see RateLimiterState in scan.hpp for why that matters.
    RateLimiterState rate_state;
    BandwidthLimiterState bandwidth_state;
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
    std::uniform_int_distribution<uint32_t> seq_dist(0, 4294967295U);
    const size_t total_ports = ports.size();
    struct BatchRange { size_t start, end; };
    std::vector<BatchRange> batches;

    // Split [0, total_ports) into contiguous, non-overlapping ranges, each
    // capped at effective_batch_size, remainder spread evenly across
    // batches. Single cumulative-sum pass — no separate start_idx tracker
    // that can drift out of sync with batches[i].end (that drift was the
    // original bug: it silently dropped some ports and double-scanned
    // others whenever total_ports needed 2+ full batches plus a remainder).
    if (total_ports > 0) {
        const size_t num_batches = (total_ports + effective_batch_size - 1) / effective_batch_size;
        const size_t base_size   = total_ports / num_batches;
        const size_t extra       = total_ports % num_batches;
        batches.reserve(num_batches);
        size_t pos = 0;
        for (size_t i = 0; i < num_batches; ++i) {
            size_t this_size = base_size + (i < extra ? 1 : 0);
            batches.push_back({pos, pos + this_size});
            pos += this_size;
        }
    }
    
    if (!g_recv || !g_recv->valid) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "[worker_thread] g_recv not initialised — aborting\n";
        return;
    }
    struct io_uring idle_ring{};
    int  idle_ring_init_ret = io_uring_queue_init(2, &idle_ring, 0);
    bool idle_ring_ok       = (idle_ring_init_ret == 0);
    if (!idle_ring_ok) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "[worker_thread] idle_ring init failed for " << ip
                   << ": " << strerror(-idle_ring_init_ret)
                   << " — falling back to clock_nanosleep polling\n";
    }

    uint32_t dest_ip_key = 0;
    {
        struct in_addr addr{};
        if (inet_pton(AF_INET, ip, &addr) == 1) dest_ip_key = addr.s_addr;
    }
    if (idle_ring_ok && dest_ip_key != 0) {
        g_recv->register_idle_ring(dest_ip_key, idle_ring.ring_fd);
    }

    struct IcmpIdleRingGuard {
        struct io_uring* r; bool ok;
        GlobalRecvCtx* g_recv; uint32_t key;
        ~IcmpIdleRingGuard() {
            // CRITICAL ORDER: unregister first (blocks under unique_lock
            // until any in-flight signal submit from the reader thread
            // finishes), THEN tear down the ring. This is what prevents
            // the reader thread from submitting MSG_RING to a closed fd.
            if (g_recv && key != 0) g_recv->unregister_idle_ring(key);
            if (ok) io_uring_queue_exit(r);
        }
    } idle_ring_guard{&idle_ring, idle_ring_ok, g_recv, dest_ip_key};
    
    uint64_t pending_dispatch_delay_us = 0;   // computed for batch i, consumed by batch i's receive_response() call
    for (const auto& range : batches) {
        if (terminate_flag) break;
        if (range.start >= range.end) continue;
        std::span<const int> batch_ports(ports.data() + range.start, range.end - range.start);
        size_t scan_batch_size = std::min(effective_batch_size, batch_ports.size());
        if (is_threaded) {
            tl_port_output_buf = &result.output_buffer;
        }
        RecPross batch_result = receive_response(ip, batch_ports, effective_src_ip, rng, pool, 
                                 send_sock, source_port, retry_source_port, seq_num, win_size, print_individual_closed_filtered, print_filtered_if_few,send_ring, fast_scan, scan_batch_size, scan_type,
                                 custom_ttl,custom_dscp,custom_ip_flags, ip_id_mode, fixed_ip_id,
                                 opts,
                                   debug_rtt,debug_ttl,debug_demux,debug_strack,frag_out_of_order,frag_overlap, frag_overlap_bytes,frag_zof,sport_range_cfg,gsport_cfg,initial_rtt_ms,port_timeout_min_ms,port_timeout_max_ms,rate_config,jitter_config,batch_delay_config,
                                 g_recv, idle_ring_ok ? &idle_ring : nullptr, &rate_state,
                                 bandwidth_config, &bandwidth_state,
                                 pending_dispatch_delay_us, debug_send);
        pending_dispatch_delay_us = 0;   // consumed — cleared before batch i+1 computes its own
        if (is_threaded) {
            tl_port_output_buf = nullptr;
        }
                                 
        result.closed_ports += batch_result.closed_ports;
        result.open_ports.insert(result.open_ports.end(), batch_result.open_ports.begin(), batch_result.open_ports.end());
        result.filtered_ports.insert(result.filtered_ports.end(), batch_result.filtered_ports.begin(), batch_result.filtered_ports.end());
        // Merge ICMP filter reasons from this batch into the overall result
        // Merge ICMP filter reasons from this batch into the overall result
        result.icmp_filter_reasons.insert(
            batch_result.icmp_filter_reasons.begin(),
            batch_result.icmp_filter_reasons.end());
        // Merge non-fatal ICMP path warnings from this batch
        result.icmp_warnings.insert(
            result.icmp_warnings.end(),
            batch_result.icmp_warnings.begin(),
            batch_result.icmp_warnings.end());
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
        result.demux_counts += batch_result.demux_counts;
        result.demux_debug_entries.insert(result.demux_debug_entries.end(),
            batch_result.demux_debug_entries.begin(), batch_result.demux_debug_entries.end());
        result.strack_counts += batch_result.strack_counts;
        result.strack_entries.insert(result.strack_entries.end(),
            batch_result.strack_entries.begin(), batch_result.strack_entries.end());
            
        
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
            // NON-BLOCKING: hand the gap to the NEXT batch's
            // receive_response() call as a virtual-clock head start
            // (see initial_dispatch_delay_us) instead of sleeping this
            // thread now — same zero-syscall idiom as --rate/--jitter.
            pending_dispatch_delay_us = sleep_us;
        }
    }
    
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

// Renders a raw TCP flags byte the same way demux_flags_str() in
// receive_response() does, but as a free function so print_demux_debug()
// (called from main.cpp, after the scan is over) doesn't need access to
// that lambda's capture.
static std::string demux_render_flags(uint8_t flags) {
    std::string s;
    if (flags & TH_SYN) s += "SYN,";
    if (flags & TH_ACK) s += "ACK,";
    if (flags & TH_RST) s += "RST,";
    if (flags & TH_FIN) s += "FIN,";
    if (!s.empty()) s.pop_back();
    return s.empty() ? "none" : s;
}

// Prints one target's WHOLE-SCAN --debug demux report. Must only be
// called once, after every batch for that target has already been
// merged into `entries`/`counts` (thread_worker does this merge) — never
// from inside receive_response(), or output goes back to interleaving
// with the live port table.
//
// Layout:
//   1. one summary line: total matched / dropped (+ per-reason dropped counts)
//   2. every MATCHed *open* port, listed individually (there are always
//      few of these, and they're the ones you actually care about)
//   3. MATCHed non-open ports: listed individually if there are only a
//      few, otherwise collapsed into groups of (attempt, flags, ttl) —
//      in practice nearly every closed/filtered port on one target
//      replies with an identical shape, so this turns e.g. 71 near-
//      identical MATCH lines into 1-2 pattern lines instead
//   4. every DROP event, listed individually up to a cap (these are the
//      real anomalies — spoofed/stale replies, bad src ports, RSTs with
//      no outstanding probe — so they're worth seeing in full; only
//      degrades to counts-by-tag if a run produces a genuine flood)
void print_demux_debug(const std::string& target_ip,
                        const std::vector<DemuxDebugEntry>& entries,
                        const DemuxDebugCounters& counts,
                        const std::vector<uint16_t>& open_ports) {
    if (entries.empty()) return;
    std::lock_guard<std::mutex> lock(cout_mutex);

    uint64_t total_dropped = counts.unknown_port + counts.bad_src_port +
                              counts.bad_token + counts.stale_rst;

    std::cout << "\n" << color::dim << "Demux debug" << color::reset << "   : \n";
    std::cout << "    " << color::bold << "summary" << color::reset
               << " target=" << target_ip
               << color::green << " matched=" << counts.matched << color::reset
               << color::dim  << " dropped=" << total_dropped << color::reset
               << " (unknown_port=" << counts.unknown_port
               << " bad_src_port=" << counts.bad_src_port
               << " bad_token=" << counts.bad_token
               << " stale_rst=" << counts.stale_rst << ")\n";

    std::unordered_set<uint16_t> open_set(open_ports.begin(), open_ports.end());

    std::vector<const DemuxDebugEntry*> match_open, match_other, drops;
    match_open.reserve(open_ports.size());
    for (const auto& e : entries) {
        if (e.tag.rfind("MATCH", 0) == 0) {
            (open_set.count(e.port) ? match_open : match_other).push_back(&e);
        } else {
            drops.push_back(&e);
        }
    }

    for (const auto* ep : match_open) {
        const auto& e = *ep;
        std::cout << "    " << color::green << std::left << std::setw(7) << "open" << color::reset
                   << " " << std::setw(10) << (std::to_string(e.port) + "/tcp")
                   << ": attempt=" << e.attempt
                   << " src_port=" << e.src_port
                   << " flags=" << demux_render_flags(e.flags)
                   << " ttl=" << static_cast<int>(e.ttl)
                   << (e.is_icmp ? " (icmp)" : "") << "\n";
    }

    const size_t INLINE_THRESHOLD = 10;
    if (!match_other.empty()) {
        if (match_other.size() <= INLINE_THRESHOLD) {
            for (const auto* ep : match_other) {
                const auto& e = *ep;
                std::cout << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
                           << " " << std::setw(10) << (std::to_string(e.port) + "/tcp")
                           << ": attempt=" << e.attempt
                           << " src_port=" << e.src_port
                           << " flags=" << demux_render_flags(e.flags)
                           << " ttl=" << static_cast<int>(e.ttl)
                           << (e.is_icmp ? " (icmp)" : "") << "\n";
            }
        } else {
            // Group key packs (attempt, flags, ttl, is_icmp) into one
            // integer — cheaper than a std::map<std::tuple<...>> and
            // avoids pulling in <map>/<tuple> for this alone.
            std::unordered_map<uint64_t, std::vector<uint16_t>> groups;
            auto pack_key = [](int attempt, uint8_t flags, uint8_t ttl, bool is_icmp) -> uint64_t {
                return (static_cast<uint64_t>(static_cast<uint8_t>(attempt)) << 24) |
                       (static_cast<uint64_t>(flags) << 16) |
                       (static_cast<uint64_t>(ttl)   << 8)  |
                       (is_icmp ? 1u : 0u);
            };
            for (const auto* ep : match_other) {
                groups[pack_key(ep->attempt, ep->flags, ep->ttl, ep->is_icmp)].push_back(ep->port);
            }
            std::cout << "    " << color::red << std::left << std::setw(7) << "closed" << color::reset
                       << " " << match_other.size() << " ports matched, "
                       << groups.size() << " distinct pattern(s):\n";
            for (auto& [key, ports] : groups) {
                int      attempt = static_cast<int>((key >> 24) & 0xFF);
                uint8_t  flags   = static_cast<uint8_t>((key >> 16) & 0xFF);
                uint8_t  ttl     = static_cast<uint8_t>((key >> 8)  & 0xFF);
                bool     is_icmp = (key & 1u) != 0;
                std::sort(ports.begin(), ports.end());
                std::cout << "        x" << std::setw(4) << ports.size()
                           << " attempt=" << attempt
                           << " flags=" << demux_render_flags(flags)
                           << " ttl=" << static_cast<int>(ttl)
                           << (is_icmp ? " (icmp)" : "")
                           << "  ports " << ports.front() << "-" << ports.back() << "\n";
            }
        }
    }

    if (!drops.empty()) {
        std::cout << "    " << color::yellow << "dropped" << color::reset
                   << " " << drops.size() << " packet(s):\n";
        const size_t DROP_LIST_CAP = 30;
        size_t shown = 0;
        std::unordered_map<std::string, uint64_t> overflow_by_tag;
        for (const auto* ep : drops) {
            const auto& e = *ep;
            if (shown < DROP_LIST_CAP) {
                std::cout << "        " << color::dim << e.tag << color::reset
                           << " port=" << e.port
                           << " attempt=" << e.attempt
                           << " src_port=" << e.src_port
                           << " ttl=" << static_cast<int>(e.ttl)
                           << (e.is_icmp ? " (icmp)" : "")
                           << " — " << e.detail << "\n";
                ++shown;
            } else {
                overflow_by_tag[e.tag]++;
            }
        }
        for (auto& [tag, cnt] : overflow_by_tag) {
            std::cout << "        ... +" << cnt << " more " << tag << "\n";
        }
    }
}

// --debug strack: printed once per target after its scan is fully done.
// Complements --debug demux — demux explains why one packet was
// accepted/dropped; this summarizes each port's end-to-end resolution
// path (answered immediately vs needed a retry vs never answered).
//
// Layout follows the same "label : value" convention as Not shown /
// PORT_TABLE_HEADER, and the probe-1 line is broken down by final state
// so it's explicit which open/closed/filtered ports resolved immediately
// vs needed a retry — that split used to be implicit and confusing.
void print_strack_debug(const std::string& target_ip,
                         const std::vector<StrackEntry>& entries,
                         const StrackCounters& counts) {
    if (entries.empty() && counts.unresolved == 0) return;
    std::lock_guard<std::mutex> lock(cout_mutex);

    auto state_str = [](StrackFinalState s) -> const char* {
        return s == StrackFinalState::Open   ? "open"   :
               s == StrackFinalState::Closed ? "closed" : "filtered";
    };
    auto state_color = [](StrackFinalState s) -> const std::string& {
        return s == StrackFinalState::Open   ? color::green :
               s == StrackFinalState::Closed ? color::red   : color::dim;
    };

    int open0 = 0, closed0 = 0, filtered0 = 0;
    for (const auto& e : entries) {
        if (e.resolved_attempt != 0) continue;
        if      (e.final_state == StrackFinalState::Open)   ++open0;
        else if (e.final_state == StrackFinalState::Closed) ++closed0;
        else                                                ++filtered0;
    }

    std::cout << "\n" << color::dim << "State-transition debug" << color::reset
               << " : " << target_ip << "\n";

    std::cout << "    " << std::left << std::setw(20) << "Resolved (probe 1)"
               << ": " << counts.resolved_attempt0 << " port(s)";
    if (counts.resolved_attempt0 > 0)
        std::cout << "  (" << open0 << " open, " << closed0 << " closed, " << filtered0 << " filtered)";
    std::cout << "\n";

    std::cout << "    " << std::left << std::setw(20) << "Resolved (retry 1)"
               << ": " << counts.resolved_attempt1 << " port(s)\n";

    std::cout << "    " << std::left << std::setw(20) << "Resolved (retry 2)"
               << ": " << counts.resolved_attempt2 << " port(s)\n";

    std::cout << "    " << std::left << std::setw(20) << "Never responded"
               << ": " << counts.unresolved << " port(s) (filtered, all attempts exhausted)\n";

    std::vector<const StrackEntry*> needed_retry;
    for (const auto& e : entries)
        if (e.resolved_attempt >= 1) needed_retry.push_back(&e);

    if (!needed_retry.empty()) {
        std::sort(needed_retry.begin(), needed_retry.end(),
                  [](const StrackEntry* a, const StrackEntry* b) { return a->port < b->port; });
        std::cout << "\n    " << color::yellow << "Retry detail" << color::reset
                   << " (" << needed_retry.size() << " port(s) that needed a retry):\n";
        for (const auto* ep : needed_retry) {
            const auto& e = *ep;
            std::cout << "        " << state_color(e.final_state) << std::left << std::setw(7)
                       << state_str(e.final_state) << color::reset
                       << " " << std::setw(10) << (std::to_string(e.port) + "/tcp")
                       << ": attempt=" << e.resolved_attempt
                       << " src_port=" << e.src_port;
            if (e.rtt_ms >= 0.0)
                std::cout << " rtt=" << std::fixed << std::setprecision(1) << e.rtt_ms << "ms";
            std::cout << (e.is_icmp ? " (icmp)" : "") << "\n";
        }
    }
}


