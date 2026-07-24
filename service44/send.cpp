// send7.cpp - C++ conversion of send7.py
// Compile: g++ -std=c++17 -o send7 send7.cpp -lssl -lcrypto
// Usage:   ./send7 IP PORT

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <regex>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <optional>
#include <tuple>

// POSIX / BSD sockets
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

static bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

static std::string trim(const std::string& s) {
    size_t l = s.find_first_not_of(" \t\r\n");
    size_t r = s.find_last_not_of(" \t\r\n");
    if (l == std::string::npos) return "";
    return s.substr(l, r - l + 1);
}

static std::string first_line(const std::string& s) {
    size_t pos = s.find('\n');
    return trim(pos == std::string::npos ? s : s.substr(0, pos));
}

// ─────────────────────────────────────────────
// Socket utilities
// ─────────────────────────────────────────────
static int connect_to(const std::string& ip, int port, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    // set non-blocking for connect timeout
    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        // try hostname
        struct hostent* he = gethostbyname(ip.c_str());
        if (!he) { close(fd); return -1; }
        memcpy(&addr.sin_addr, he->h_addr, static_cast<size_t>(he->h_length));
    }

    connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv{ timeout_sec, 0 };
    int rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
    if (rc <= 0) { close(fd); return -1; }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err) { close(fd); return -1; }

    // restore blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    // set recv timeout
    struct timeval rtv{ timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

    return fd;
}

// ─────────────────────────────────────────────
// recv_full  (plain socket)
// ─────────────────────────────────────────────
static std::string recv_full_fd(int fd, int timeout_sec = 10) {
    struct timeval tv{ timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::string data;
    char buf[16384];
    while (true) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        data.append(buf, static_cast<size_t>(n));
        if (data.size() > 1048576) break;
        std::string low = to_lower(data);
        if (contains(low, "</html>") || contains(low, "</body>")) break;
    }
    return data;
}

// ─────────────────────────────────────────────
// recv_full  (TLS)
// ─────────────────────────────────────────────
static std::string recv_full_ssl(SSL* ssl) {
    std::string data;
    char buf[16384];
    while (true) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        data.append(buf, static_cast<size_t>(n));
        if (data.size() > 1048576) break;
        std::string low = to_lower(data);
        if (contains(low, "</html>") || contains(low, "</body>")) break;
    }
    return data;
}

// ─────────────────────────────────────────────
// tcp_banner
// ─────────────────────────────────────────────
static std::string tcp_banner(const std::string& ip, int port, int timeout_sec = 5) {
    int fd = connect_to(ip, port, timeout_sec);
    if (fd < 0) return "";

    struct timeval tv{ timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[4096] = {};
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    if (n <= 0) return "";
    return trim(std::string(buf, static_cast<size_t>(n)));
}

// ─────────────────────────────────────────────
// Protocol detection
// ─────────────────────────────────────────────
struct ProtoDetails {
    std::string type;
    std::map<std::string, std::string> details;
};

static std::optional<ProtoDetails> detect_protocol_from_banner(const std::string& banner) {
    if (banner.empty()) return std::nullopt;

    std::string fl = first_line(banner);
    std::string bl = to_lower(banner);

    // SSH
    std::regex ssh_re(R"(^SSH-(\d+\.\d+)-([^\s]+))");
    std::smatch m;
    if (std::regex_search(fl, m, ssh_re)) {
        return ProtoDetails{"SSH", {{"version", m[1]}, {"software", m[2]}, {"full_banner", fl}}};
    }
    // FTP / SMTP (220)
    if (starts_with(fl, "220 "))
        return ProtoDetails{"FTP", {{"banner", fl}}};
    // POP3
    if (starts_with(fl, "+OK"))
        return ProtoDetails{"POP3", {{"banner", fl}}};
    // IMAP
    if (starts_with(fl, "* OK"))
        return ProtoDetails{"IMAP", {{"banner", fl}}};
    // MySQL
    if (contains(bl, "mysql"))
        return ProtoDetails{"MySQL", {{"banner", fl.substr(0, 100)}}};
    // PostgreSQL
    if (contains(bl, "postgresql"))
        return ProtoDetails{"PostgreSQL", {{"banner", fl.substr(0, 100)}}};
    // Redis
    if (starts_with(fl, "-ERR") || contains(bl, "redis_version"))
        return ProtoDetails{"Redis", {{"banner", fl.substr(0, 100)}}};
    // Memcached
    if (starts_with(fl, "VERSION"))
        return ProtoDetails{"Memcached", {{"banner", fl}}};
    // MongoDB
    if (contains(bl, "mongodb"))
        return ProtoDetails{"MongoDB", {{"banner", fl.substr(0, 100)}}};
    // Telnet
    if (contains(bl, "telnet") || contains(bl, "login:") ||
        contains(bl, "password:") || contains(bl, "username:"))
        return ProtoDetails{"Telnet", {{"banner", fl.substr(0, 100)}}};
    // VNC
    if (contains(bl, "rfb"))
        return ProtoDetails{"VNC", {{"banner", fl}}};

    return std::nullopt;
}

// ─────────────────────────────────────────────
// is_likely_web_port
// ─────────────────────────────────────────────
static bool is_likely_web_port(int port) {
    static const std::set<int> web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 444};
    return web_ports.count(port) || port > 1024;
}

// ─────────────────────────────────────────────
// Extractor helpers (regex-based)
// ─────────────────────────────────────────────
static std::string regex_first(const std::string& text, const std::string& pat, int group = 1) {
    std::regex re(pat, std::regex::icase);
    std::smatch m;
    if (std::regex_search(text, m, re)) return trim(m[group].str());
    return "";
}

static std::string extract_server(const std::string& resp) {
    return regex_first(resp, R"(Server:\s*(.+?)(?:\r\n|$))");
}
static std::string extract_title(const std::string& resp) {
    return regex_first(resp, R"(<title>\s*([\s\S]+?)\s*</title>)");
}
static std::string extract_powered_by(const std::string& resp) {
    return regex_first(resp, R"(X-Powered-By:\s*(.+?)(?:\r\n|$))");
}
static int extract_status_code(const std::string& resp) {
    std::regex re(R"(HTTP/\d\.\d\s+(\d+))");
    std::smatch m;
    if (std::regex_search(resp, m, re)) return std::stoi(m[1].str());
    return 0;
}

// ─────────────────────────────────────────────
// NEW: extract <meta name="copyright" content="...">
// Returns the content value, or empty string if not found.
// ─────────────────────────────────────────────
static std::string extract_meta_copyright(const std::string& resp) {
    // Matches both attribute orderings:
    //   <meta name="copyright" content="VALUE">
    //   <meta content="VALUE" name="copyright">
    std::string v = regex_first(resp,
        R"(<meta[^>]+name\s*=\s*["\']copyright["\'][^>]+content\s*=\s*["\']([^"\']+)["\'])");
    if (!v.empty()) return v;
    return regex_first(resp,
        R"(<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+name\s*=\s*["\']copyright["\'])");
}

// ─────────────────────────────────────────────
// NEW: extract WWW-Authenticate header value
// ─────────────────────────────────────────────
static std::string extract_www_authenticate(const std::string& resp) {
    return regex_first(resp, R"(WWW-Authenticate:\s*(.+?)(?:\r\n|$))");
}

// ─────────────────────────────────────────────
// NEW: check if any Set-Cookie header contains PHPSESSID
// Returns the full cookie line that contains PHPSESSID, or empty.
// ─────────────────────────────────────────────
static std::string extract_phpsessid_cookie(const std::string& resp) {
    std::regex re(R"(Set-Cookie:\s*(.+?)(?:\r\n|$))", std::regex::icase);
    auto begin = std::sregex_iterator(resp.begin(), resp.end(), re);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string cookie = trim((*it)[1].str());
        if (to_lower(cookie).find("phpsessid") != std::string::npos)
            return cookie;
    }
    return "";
}

static std::map<std::string, std::string> extract_special_headers(const std::string& resp) {
    static const std::vector<std::string> special = {
        "X-Nextjs-Cache","CF-RAY","X-Drupal-Cache","X-Generator","X-Redirect-By",
        "X-AspNet-Version","X-AspNetMvc-Version","X-Powered-CMS","X-Drupal-Dynamic-Cache",
        "X-Mod-Pagespeed","X-Runtime","X-Version","X-Backend-Server","X-Application-Context",
        "X-Pingback","X-Served-By","X-Varnish","X-Cache","X-Cache-Hits","CF-Cache-Status",
        "X-Amz-Cf-Id","X-Amz-Cf-Pop","Via","Alt-Svc","X-Firefox-Spdy","X-NF-Request-ID",
        "X-ShopId","X-Wix-Request-Id","X-Recruiting","X-Turbo-Charged-By"
    };
    std::map<std::string, std::string> headers;
    for (const auto& h : special) {
        std::string v = regex_first(resp, h + R"(:\s*(.+?)(?:\r\n|$))");
        if (!v.empty()) headers[h] = v;
    }
    return headers;
}

static std::map<std::string, std::string> extract_security_headers(const std::string& resp) {
    static const std::vector<std::string> sec_hdrs = {
        "Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
        "X-Content-Type-Options","X-XSS-Protection","Referrer-Policy",
        "Permissions-Policy","Cross-Origin-Resource-Policy","Cross-Origin-Opener-Policy"
    };
    std::map<std::string, std::string> headers;
    for (const auto& h : sec_hdrs) {
        std::string v = regex_first(resp, h + R"(:\s*(.+?)(?:\r\n|$))");
        if (!v.empty()) headers[h] = v;
    }
    return headers;
}

static std::vector<std::string> extract_cookies(const std::string& resp) {
    std::vector<std::string> cookies;
    std::regex re(R"(Set-Cookie:\s*(.+?)(?:\r\n|$))", std::regex::icase);
    auto begin = std::sregex_iterator(resp.begin(), resp.end(), re);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
        cookies.push_back(trim((*it)[1].str()));
    return cookies;
}

static std::vector<std::string> detect_tech(const std::string& resp,
                                             const std::string& banner,
                                             const std::optional<ProtoDetails>& proto_info) {
    std::string text = to_lower(resp + banner);
    std::set<std::string> tech;

    // SSH
    if (proto_info && proto_info->type == "SSH") {
        auto sw  = proto_info->details.count("software") ? proto_info->details.at("software") : "Unknown";
        auto ver = proto_info->details.count("version")  ? proto_info->details.at("version")  : "Unknown";
        tech.insert("SSH (" + sw + ")");
        tech.insert("SSH Protocol Version: " + ver);
    } else {
        std::regex ssh_banner_re(R"(^SSH-\d+\.\d+)", std::regex::icase);
        if (contains(banner, "ssh-") || std::regex_search(banner, ssh_banner_re)) {
            tech.insert("SSH");
            std::smatch m;
            std::regex ssh_ver(R"((SSH-\d+\.\d+[^\s]*))", std::regex::icase);
            if (std::regex_search(banner, m, ssh_ver)) tech.insert(m[1].str());
        }
    }

    // Web servers
    if (contains(text, "apache"))     tech.insert("Apache");
    if (contains(text, "nginx"))      tech.insert("Nginx");
    if (contains(text, "nethsecurity")) tech.insert("NethSecurity");
    if (contains(text, "cgi") || contains(text, "cgi-bin")) tech.insert("CGI");
    if (contains(text, "php"))        tech.insert("PHP");

    // ── NEW: PHP confirmed via PHPSESSID cookie ──────────────────────────────
    {
        std::string phpsess = extract_phpsessid_cookie(resp);
        if (!phpsess.empty())
            tech.insert("PHP (PHPSESSID cookie)");
    }

    // Frameworks
    if (contains(text, "django"))     tech.insert("Django");
    if (contains(text, "rails") || contains(text, "ruby on rails")) tech.insert("Ruby on Rails");
    if (contains(text, "laravel"))    tech.insert("Laravel");
    if (contains(text, "spring"))     tech.insert("Spring");
    if (contains(text, "express"))    tech.insert("Express.js");

    // Databases
    if (contains(text, "mysql"))      tech.insert("MySQL");
    if (contains(text, "postgresql") || contains(text, "pgsql")) tech.insert("PostgreSQL");
    if (contains(text, "mongodb"))    tech.insert("MongoDB");
    if (contains(text, "redis"))      tech.insert("Redis");

    // CMS
    if (contains(text, "wordpress"))  tech.insert("WordPress");
    if (contains(text, "drupal"))     tech.insert("Drupal");
    if (contains(text, "joomla"))     tech.insert("Joomla");

    // ── NEW: WWW-Authenticate fingerprinting ─────────────────────────────────
    // The WWW-Authenticate realm / scheme can reveal the backend (e.g. Basic realm="WordPress")
    {
        std::string www_auth = extract_www_authenticate(resp);
        if (!www_auth.empty()) {
            std::string wa_low = to_lower(www_auth);
            // Detect common realm hints
            if (contains(wa_low, "wordpress"))  tech.insert("WordPress (WWW-Authenticate)");
            if (contains(wa_low, "drupal"))     tech.insert("Drupal (WWW-Authenticate)");
            if (contains(wa_low, "joomla"))     tech.insert("Joomla (WWW-Authenticate)");
            if (contains(wa_low, "apache"))     tech.insert("Apache (WWW-Authenticate)");
            if (contains(wa_low, "nginx"))      tech.insert("Nginx (WWW-Authenticate)");
            if (contains(wa_low, "iis"))        tech.insert("IIS (WWW-Authenticate)");
            if (contains(wa_low, "ntlm"))       tech.insert("NTLM Auth (Windows/IIS)");
            if (contains(wa_low, "negotiate"))  tech.insert("Kerberos/NTLM Auth (Windows)");
            if (contains(wa_low, "digest"))     tech.insert("Digest Auth");
            if (contains(wa_low, "bearer"))     tech.insert("OAuth/Bearer Token Auth");
        }
    }

    // ── NEW: <meta name="copyright"> fingerprinting ──────────────────────────
    // Common generators/CMS embed their name in the copyright meta tag
    {
        std::string mc = to_lower(extract_meta_copyright(resp));
        if (!mc.empty()) {
            if (contains(mc, "wordpress"))  tech.insert("WordPress (meta copyright)");
            if (contains(mc, "drupal"))     tech.insert("Drupal (meta copyright)");
            if (contains(mc, "joomla"))     tech.insert("Joomla (meta copyright)");
            if (contains(mc, "typo3"))      tech.insert("TYPO3 (meta copyright)");
            if (contains(mc, "magento"))    tech.insert("Magento (meta copyright)");
            if (contains(mc, "shopify"))    tech.insert("Shopify (meta copyright)");
            if (contains(mc, "wix"))        tech.insert("Wix (meta copyright)");
            if (contains(mc, "squarespace"))tech.insert("Squarespace (meta copyright)");
        }
    }

    return std::vector<std::string>(tech.begin(), tech.end());
}

// ─────────────────────────────────────────────
// SSL context wrapper  (move-only — no copies)
// ─────────────────────────────────────────────
struct SslCtx {
    std::string name;
    SSL_CTX*    ctx = nullptr;

    SslCtx() = default;
    SslCtx(std::string n, SSL_CTX* c) : name(std::move(n)), ctx(c) {}

    // Non-copyable — copying would share and then double-free the raw pointer
    SslCtx(const SslCtx&)            = delete;
    SslCtx& operator=(const SslCtx&) = delete;

    // Movable — transfers ownership, leaves source with nullptr
    SslCtx(SslCtx&& o) noexcept : name(std::move(o.name)), ctx(o.ctx) { o.ctx = nullptr; }
    SslCtx& operator=(SslCtx&& o) noexcept {
        if (this != &o) {
            if (ctx) SSL_CTX_free(ctx);
            name = std::move(o.name);
            ctx  = o.ctx;
            o.ctx = nullptr;
        }
        return *this;
    }

    ~SslCtx() { if (ctx) SSL_CTX_free(ctx); }
};

static std::vector<SslCtx> get_ssl_contexts() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    std::vector<SslCtx> ctxs;

    // Default TLS (cert verify disabled for scanning)
    SSL_CTX* c1 = SSL_CTX_new(TLS_client_method());
    if (c1) {
        SSL_CTX_set_verify(c1, SSL_VERIFY_NONE, nullptr);
        ctxs.push_back({"Default TLS", c1});
    }

    // Unverified (same, kept as 2nd fallback mirroring Python's _create_unverified_context)
    SSL_CTX* c2 = SSL_CTX_new(TLS_client_method());
    if (c2) {
        SSL_CTX_set_verify(c2, SSL_VERIFY_NONE, nullptr);
        ctxs.push_back({"Unverified", c2});
    }

    return ctxs;
}

// ─────────────────────────────────────────────
// HTTP probe  (plain)
// ─────────────────────────────────────────────
struct HttpResult { std::string status; std::string body; };

static HttpResult http_probe(const std::string& ip, int port) {
    int fd = connect_to(ip, port, 5);
    if (fd < 0) return {"FAILED", ""};

    std::string req = "GET / HTTP/1.1\r\nHost: " + ip + ":" + std::to_string(port) +
                      "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    send(fd, req.c_str(), req.size(), 0);
    std::string resp = recv_full_fd(fd, 10);
    close(fd);

    if (starts_with(resp, "HTTP/") || contains(resp, "Bad Request")) {
        if (contains(resp, "Bad Request") && contains(resp, "SSL-enabled"))
            return {"HTTPS_REQUIRED", resp};
        return {"HTTP", resp};
    }
    return {"NOT_HTTP", resp};
}

// ─────────────────────────────────────────────
// Invalid probe  (AAAAAAA\r\n\r\n)
// ─────────────────────────────────────────────
static std::string invalid_http_probe(const std::string& ip, int port,
                                       bool is_https = false, SSL_CTX* ctx = nullptr) {
    int fd = connect_to(ip, port, 6);
    if (fd < 0) return "";

    const char payload[] = "AAAAAAA\r\n\r\n";
    std::string resp;

    if (is_https && ctx) {
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, ip.c_str());
        if (SSL_connect(ssl) > 0) {
            SSL_write(ssl, payload, static_cast<int>(strlen(payload)));
            resp = recv_full_ssl(ssl);
        }
        SSL_free(ssl);
    } else {
        send(fd, payload, strlen(payload), 0);
        resp = recv_full_fd(fd, 10);
    }
    close(fd);
    return resp;
}

// ─────────────────────────────────────────────
// HTTPS probe with a given SSL_CTX
// ─────────────────────────────────────────────
static std::pair<std::string, std::string>
https_probe_with_context(const std::string& ip, int port, SSL_CTX* ctx,
                          const std::string& ctx_name);

// Forward-declare follow_redirects
static std::string follow_redirects(const std::string& ip, int port,
                                     const std::string& response,
                                     SSL_CTX* ctx, bool is_https, int max_redirects = 8);

static std::pair<std::string, std::string>
https_probe_with_context(const std::string& ip, int port, SSL_CTX* ctx,
                          const std::string& ctx_name) {
    int fd = connect_to(ip, port, 7);
    if (fd < 0) return {"", ctx_name};

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, ip.c_str());

    std::string resp;
    if (SSL_connect(ssl) > 0) {
        std::string req = "GET / HTTP/1.1\r\nHost: " + ip + ":" + std::to_string(port) +
                          "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
        SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));
        resp = recv_full_ssl(ssl);
        resp = follow_redirects(ip, port, resp, ctx, true);
    }
    SSL_free(ssl);
    close(fd);
    return {resp, ctx_name};
}

// ─────────────────────────────────────────────
// follow_redirects
// ─────────────────────────────────────────────
static std::string follow_redirects(const std::string& ip, int port,
                                     const std::string& response,
                                     SSL_CTX* ctx, bool is_https, int max_redirects) {
    std::string cur_resp = response;
    std::string cur_path = "/";

    for (int count = 0; count < max_redirects; ++count) {
        int status = extract_status_code(cur_resp);
        static const std::set<int> redirect_codes = {301, 302, 303, 307, 308};
        if (!redirect_codes.count(status)) break;

        std::string loc = regex_first(cur_resp, R"(Location:\s*(.+?)(?:\r\n|$))");
        if (loc.empty()) break;

        std::cout << "[*] Following redirect (" << (count + 1) << ") -> " << loc << "\n";

        if (!loc.empty() && loc[0] == '/') {
            cur_path = loc;
        } else {
            // extract path from full URL
            std::regex url_re(R"(https?://[^/]+(/.*))", std::regex::icase);
            std::smatch m;
            if (std::regex_search(loc, m, url_re))
                cur_path = m[1].str();
            else
                cur_path = "/";
        }

        int fd = connect_to(ip, port, 5);
        if (fd < 0) break;

        std::string req = "GET " + cur_path + " HTTP/1.1\r\nHost: " + ip + ":" +
                          std::to_string(port) + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";

        try {
            if (is_https && ctx) {
                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, fd);
                SSL_set_tlsext_host_name(ssl, ip.c_str());
                if (SSL_connect(ssl) > 0) {
                    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));
                    cur_resp = recv_full_ssl(ssl);
                }
                SSL_free(ssl);
            } else {
                send(fd, req.c_str(), req.size(), 0);
                cur_resp = recv_full_fd(fd, 10);
            }
        } catch (...) {
            close(fd);
            break;
        }
        close(fd);
    }
    return cur_resp;
}

// ─────────────────────────────────────────────
// Probe  (main logic)
// ─────────────────────────────────────────────
struct ProbeResult {
    std::string banner;
    std::string resp;
    std::string method;
    std::optional<ProtoDetails> protocol_info;
};

static ProbeResult probe(const std::string& ip, int port) {
    std::string banner = tcp_banner(ip, port);
    auto proto = detect_protocol_from_banner(banner);

    if (proto) {
        std::cout << "[*] Detected " << proto->type << " service on port " << port << "\n";
        if (proto->type == "SSH")
            return {banner, "", "SSH Service", proto};
        return {banner, "", proto->type + " Service", proto};
    }

    std::string bl = to_lower(banner);
    if (contains(bl, "ssh-") || contains(bl, "ftp") ||
        contains(bl, "smtp") || contains(bl, "pop3") ||
        contains(bl, "imap") || contains(bl, "telnet")) {
        std::string service = "Unknown";
        if (contains(bl, "ssh-"))  service = "SSH";
        else if (contains(bl, "ftp"))  service = "FTP";
        else if (contains(bl, "smtp")) service = "SMTP";
        return {banner, "", service + " Service", std::nullopt};
    }

    std::string resp;
    std::string method = "Banner Only";
    auto ssl_ctxs = get_ssl_contexts();

    if (is_likely_web_port(port) || trim(banner).empty()) {
        std::cout << "[*] Trying HTTP...\n";
        auto [status, http_resp] = http_probe(ip, port);
        resp = http_resp;

        if (status == "HTTP" && contains(resp, "HTTP/")) {
            int code = extract_status_code(resp);
            static const std::set<int> redir_codes = {301, 302, 303, 307, 308};
            if (redir_codes.count(code)) {
                std::cout << "[*] Following HTTP redirect...\n";
                std::string final = follow_redirects(ip, port, resp, nullptr, false);
                return {banner, final, "HTTP + Redirect", std::nullopt};
            }
            return {banner, resp, "HTTP", std::nullopt};
        }

        if (status == "HTTPS_REQUIRED") {
            std::cout << "[*] HTTPS required, trying HTTPS...\n";
            for (auto& sc : ssl_ctxs) {
                auto [https_resp, mname] = https_probe_with_context(ip, port, sc.ctx, sc.name);
                if (contains(https_resp, "HTTP/"))
                    return {banner, https_resp, mname, std::nullopt};
            }
        }
    }

    std::cout << "[*] Trying HTTPS fallback...\n";
    for (auto& sc : ssl_ctxs) {
        auto [https_resp, mname] = https_probe_with_context(ip, port, sc.ctx, sc.name);
        if (contains(https_resp, "HTTP/"))
            return {banner, https_resp, mname, std::nullopt};
        resp = https_resp;
    }

    // Invalid probe as last resort
    if ((trim(banner).empty() || trim(resp).empty() || !contains(resp, "HTTP/")) &&
        (is_likely_web_port(port) || port > 1024)) {
        std::cout << "[*] No banner or valid response - trying invalid probe (AAAAAAA)...\n";
        std::string inv = invalid_http_probe(ip, port, false);
        if (!inv.empty() && (contains(inv, "HTTP/") || inv.size() > 50)) {
            resp   = inv;
            method = "Invalid Probe (HTTP)";
        } else {
            for (auto& sc : ssl_ctxs) {
                std::string inv2 = invalid_http_probe(ip, port, true, sc.ctx);
                if (!inv2.empty() && (contains(inv2, "HTTP/") || inv2.size() > 50)) {
                    resp   = inv2;
                    method = "Invalid Probe (" + sc.name + ")";
                    break;
                }
            }
        }
    }

    return {banner, resp, method, std::nullopt};
}

// ─────────────────────────────────────────────
// main
// ─────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " IP PORT\n";
        std::cerr << "Example: " << argv[0] << " 51.161.8.88 444\n";
        return 1;
    }

    std::string ip = argv[1];
    int port       = std::stoi(argv[2]);

    // Current time
    std::time_t now = std::time(nullptr);
    char tbuf[32];
    std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::cout << std::string(60, '=') << "\n";
    std::cout << "Target          : " << ip << ":" << port << "\n";
    std::cout << "Scan Time       : " << tbuf << "\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "[*] Probing service...\n";

    auto [banner, resp, method, protocol_info] = probe(ip, port);

    std::string server        = extract_server(resp);
    std::string title         = extract_title(resp);
    std::string powered_by    = extract_powered_by(resp);
    int         status_code   = extract_status_code(resp);
    auto        tech          = detect_tech(resp, banner, protocol_info);
    auto        special_hdrs  = extract_special_headers(resp);
    auto        security_hdrs = extract_security_headers(resp);
    auto        cookies       = extract_cookies(resp);

    // ── NEW: extract the three new fingerprint fields ────────────────────────
    std::string meta_copyright   = extract_meta_copyright(resp);
    std::string www_authenticate = extract_www_authenticate(resp);
    std::string phpsessid_cookie = extract_phpsessid_cookie(resp);
    // ─────────────────────────────────────────────────────────────────────────

    std::cout << std::string(60, '=') << "\n";
    std::cout << "Connection Method : " << method << "\n";

    // SSH display
    if (protocol_info && protocol_info->type == "SSH") {
        auto& d = protocol_info->details;
        std::cout << "Service Type      : SSH (Secure Shell)\n";
        std::cout << "SSH Version       : " << (d.count("version")  ? d.at("version")  : "Unknown") << "\n";
        std::cout << "SSH Software      : " << (d.count("software") ? d.at("software") : "Unknown") << "\n";
        if (!banner.empty())
            std::cout << "Full Banner       : " << banner.substr(0, 200) << "\n";
    }
    // Other non-HTTP services
    else if (method == "FTP Service" || method == "SMTP Service" ||
             method == "POP3 Service" || method == "IMAP Service" ||
             method == "Telnet Service") {
        std::cout << "Service Type      : " << method << "\n";
        if (!banner.empty())
            std::cout << "Service Banner    : " << banner.substr(0, 200) << "\n";
    }
    // Web services
    else if (method == "HTTP" || method == "HTTP + Redirect" ||
             method == "Default TLS" || method == "Unverified" ||
             method == "Invalid Probe (HTTP)" || contains(method, "Invalid Probe")) {
        if (status_code) std::cout << "HTTP Status       : " << status_code << "\n";
        if (!server.empty())     std::cout << "Server            : " << server << "\n";
        if (!powered_by.empty()) std::cout << "Powered By        : " << powered_by << "\n";
        if (!title.empty())      std::cout << "Title             : " << title << "\n";

        // ── NEW: WWW-Authenticate ────────────────────────────────────────────
        if (!www_authenticate.empty()) {
            std::string wa_disp = www_authenticate.size() > 120
                                  ? www_authenticate.substr(0, 120) + "..."
                                  : www_authenticate;
            std::cout << "WWW-Authenticate  : " << wa_disp << "\n";
        }

        // ── NEW: meta copyright ─────────────────────────────────────────────
        if (!meta_copyright.empty()) {
            std::string mc_disp = meta_copyright.size() > 120
                                  ? meta_copyright.substr(0, 120) + "..."
                                  : meta_copyright;
            std::cout << "Meta Copyright    : " << mc_disp << "\n";
        }

        // ── NEW: PHPSESSID ──────────────────────────────────────────────────
        if (!phpsessid_cookie.empty()) {
            std::string ps_disp = phpsessid_cookie.size() > 120
                                  ? phpsessid_cookie.substr(0, 120) + "..."
                                  : phpsessid_cookie;
            std::cout << "PHP Session (PHPSESSID detected → PHP backend):\n";
            std::cout << "  " << ps_disp << "\n";
        }

        if (!tech.empty()) {
            std::cout << "Technologies      : ";
            for (size_t i = 0; i < tech.size(); ++i)
                std::cout << (i ? ", " : "") << tech[i];
            std::cout << "\n";
        }

        if (!security_hdrs.empty()) {
            std::cout << "\n--- Security Headers ---\n";
            for (auto& [h, v] : security_hdrs) {
                std::string vv = v.size() > 80 ? v.substr(0, 80) : v;
                std::cout << std::left;
                printf("%-30s: %s\n", h.c_str(), vv.c_str());
            }
        }

        if (!cookies.empty()) {
            std::cout << "\n--- Cookies (" << cookies.size() << " found) ---\n";
            int limit = static_cast<int>(std::min(cookies.size(), (size_t)5));
            for (int i = 0; i < limit; ++i) {
                std::string cv = cookies[i].size() > 100 ? cookies[i].substr(0, 100) : cookies[i];
                // ── NEW: annotate PHPSESSID inline ───────────────────────────
                std::string annotation = "";
                if (to_lower(cookies[i]).find("phpsessid") != std::string::npos)
                    annotation = "  ← PHP (PHPSESSID)";
                std::cout << "  " << (i + 1) << ". " << cv << annotation << "\n";
            }
            if (cookies.size() > 5)
                std::cout << "  ... and " << cookies.size() - 5 << " more\n";
        }

        if (!special_hdrs.empty()) {
            std::cout << "\n--- Special Headers ---\n";
            for (auto& [h, v] : special_hdrs)
                printf("%-25s: %s\n", h.c_str(), v.c_str());
        }
    }

    // Raw banner
    if (!trim(banner).empty() && method != "SSH Service") {
        std::cout << "\n--- Raw Banner ---\n";
        std::string b = banner.size() > 500 ? banner.substr(0, 500) : banner;
        std::cout << b << "\n";
        if (banner.size() > 500)
            std::cout << "... (truncated, total " << banner.size() << " bytes)\n";
    }

    return 0;
}
