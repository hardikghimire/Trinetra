#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <unordered_map>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <optional>
#include <thread>
#include <regex>
#include <future>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <poll.h>
#include <mutex>
#include <atomic>
#include "async_io.hpp"
#include "utils.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define COMPAT_SSL_library_init()         SSL_library_init()
#  define COMPAT_SSL_load_error_strings()   SSL_load_error_strings()
#  define COMPAT_OpenSSL_add_all_algorithms() OpenSSL_add_all_algorithms()
#else
#  define COMPAT_SSL_library_init()           ((void)0)
#  define COMPAT_SSL_load_error_strings()     ((void)0)
#  define COMPAT_OpenSSL_add_all_algorithms() ((void)0)
#endif


#include <zlib.h>         

#ifdef HAVE_BROTLI
#  include <brotli/decode.h>
#endif

#ifdef HAVE_ZSTD
#  include <zstd.h>
#endif

#include "probe.hpp"

static constexpr int MAX_RESPONSE = 65536;
static constexpr int CHUNK        = 4096;

extern std::atomic<bool> terminate_flag;
bool normalize_ip_string(const std::string& in, std::string& out);         
bool resolve_domain_to_ip(const std::string& domain, std::string& out_ip); 
bool custom_dns_configured();                                                       
bool resolve_ptr_via_configured_dns(const std::string& ip, std::string& out_domain);

namespace vlog {

inline bool color_enabled() {
    static const bool enabled = (isatty(fileno(stderr)) != 0);
    return enabled;
}

inline const char* RESET()  { return color_enabled() ? "\x1b[0m"  : ""; }
inline const char* BOLD()   { return color_enabled() ? "\x1b[1m"  : ""; }
inline const char* CYAN()   { return color_enabled() ? "\x1b[36m" : ""; } 
inline const char* GREEN()  { return color_enabled() ? "\x1b[32m" : ""; } 
inline const char* RED()    { return color_enabled() ? "\x1b[31m" : ""; } 
inline const char* YELLOW() { return color_enabled() ? "\x1b[33m" : ""; } 
inline const char* GRAY()   { return color_enabled() ? "\x1b[90m" : ""; } 
inline std::string pad(int level) { return std::string((size_t)level * 3, ' '); }
inline void phase(bool verbose, const std::string& title) {
    if (!verbose) return;
    fprintf(stderr, "\n%s%s%s%s\n", CYAN(), BOLD(), title.c_str(), RESET());
}

inline void line(bool verbose, const std::string& msg, int level = 1) {
    if (!verbose) return;
    fprintf(stderr, "%s%s·%s %s\n", pad(level).c_str(), GRAY(), RESET(), msg.c_str());
}

inline void ok(bool verbose, const std::string& msg, int level = 1) {
    if (!verbose) return;
    fprintf(stderr, "%s%s✓%s %s\n", pad(level).c_str(), GREEN(), RESET(), msg.c_str());
}

inline void fail(bool verbose, const std::string& msg, int level = 1) {
    if (!verbose) return;
    fprintf(stderr, "%s%s✗%s %s\n", pad(level).c_str(), RED(), RESET(), msg.c_str());
}

inline void warn(bool verbose, const std::string& msg, int level = 1) {
    if (!verbose) return;
    fprintf(stderr, "%s%s!%s %s\n", pad(level).c_str(), YELLOW(), RESET(), msg.c_str());
}

inline void kv(bool verbose, const std::string& key, const std::string& val, int level = 1) {
    if (!verbose) return;
    fprintf(stderr, "%s%s%-11s%s: %s\n", pad(level).c_str(), GRAY(), key.c_str(), RESET(), val.c_str());
}

inline void section(bool verbose, const std::string& title) {
    if (!verbose) return;
    fprintf(stderr, "\n%s%s── %s ──%s\n", GRAY(), BOLD(), title.c_str(), RESET());
}

} 

struct TlsCertInfo {
    std::string subject;         
    std::string issuer;           
    std::string not_before;       
    std::string not_after;        
    std::string serial;           
    std::string fingerprint_sha1; 
    std::string fingerprint_sha256; 
    std::vector<std::string> sans; 
    std::string tls_version;     
    std::string cipher;           
    bool        verify_ok = false; 
    std::string verify_error;     
    bool        populated = false; 

    void print(std::ostream &out) const {
        if (!populated) return;
        auto tls_emit = [&](const char *label, const std::string &val, size_t maxlen = 36) {
            if (val.empty()) return;
            std::string clean;
            clean.reserve(val.size());
            bool in_ws = false;
            for (unsigned char c : val) {
                if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
                    if (!in_ws) { clean += ' '; in_ws = true; }
                } else { clean += (char)c; in_ws = false; }
            }
            while (!clean.empty() && clean.front() == ' ') clean.erase(clean.begin());
            while (!clean.empty() && clean.back()  == ' ') clean.pop_back();
            if (clean.size() > maxlen) clean = clean.substr(0, maxlen - 3) + "...";
            out << "  |  " << std::left << std::setw(13) << label << ": " << clean << "\n";
        };
        tls_emit("TLS version", tls_version);
        tls_emit("Cipher", cipher, 48);
        tls_emit("Subject", subject, 64);
        tls_emit("Issuer", issuer, 64);
        tls_emit("Not before", not_before);
        tls_emit("Not after", not_after);
        tls_emit("Serial", serial, 48);
        tls_emit("SHA-1", fingerprint_sha1, 64);
        tls_emit("SHA-256", fingerprint_sha256, 100);
        for (size_t i = 0; i < sans.size() && i < 8; ++i)
            tls_emit(i == 0 ? "SANs" : "", sans[i], 64);
        if (sans.size() > 8) tls_emit("", "(+" + std::to_string(sans.size() - 8) + " more)");
        tls_emit("Verify", verify_ok ? std::string("ok") : (verify_error.empty() ? std::string("failed") : verify_error), 64);
    }
};

static std::string asn1_time_to_str(const ASN1_TIME *t)
{
    if (!t) return "";
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, t);
    char buf[128] = {};
    BIO_read(bio, buf, sizeof(buf) - 1);
    BIO_free(bio);
    return buf;
}

static std::string x509_name_to_str(X509_NAME *name)
{
    if (!name) return "";
    BIO *bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    char buf[512] = {};
    BIO_read(bio, buf, sizeof(buf) - 1);
    BIO_free(bio);
    return buf;
}

static std::string hex_encode(const unsigned char *data, unsigned int len)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 3);
    for (unsigned int i = 0; i < len; ++i) {
        if (i) out += ':';
        out += hex[(data[i] >> 4) & 0xf];
        out += hex[ data[i]       & 0xf];
    }
    return out;
}

static std::vector<std::string> extract_sans(X509 *cert)
{
    std::vector<std::string> out;
    GENERAL_NAMES *gnames = (GENERAL_NAMES *)X509_get_ext_d2i(
                                cert, NID_subject_alt_name, nullptr, nullptr);
    if (!gnames) return out;
    int n = sk_GENERAL_NAME_num(gnames);
    for (int i = 0; i < n; ++i) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(gnames, i);
        if (gn->type == GEN_DNS) {
            const char *s = (const char *)ASN1_STRING_get0_data(gn->d.dNSName);
            if (s) out.push_back(std::string("DNS:") + s);
        } else if (gn->type == GEN_IPADD) {
            const unsigned char *ip_bytes = ASN1_STRING_get0_data(gn->d.iPAddress);
            int ip_len = ASN1_STRING_length(gn->d.iPAddress);
            if (ip_len == 4) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ip_bytes, buf, sizeof(buf));
                out.push_back(std::string("IP:") + buf);
            } else if (ip_len == 16) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ip_bytes, buf, sizeof(buf));
                out.push_back(std::string("IP:") + buf);
            }
        }
    }
    GENERAL_NAMES_free(gnames);
    return out;
}

static TlsCertInfo extract_tls_cert_info(SSL *ssl)
{
    TlsCertInfo info;
    info.populated = true;

    // TLS version & cipher
    info.tls_version = SSL_get_version(ssl) ? SSL_get_version(ssl) : "unknown";
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    info.cipher = cipher ? SSL_CIPHER_get_name(cipher) : "unknown";

    // Verify result
    long vresult = SSL_get_verify_result(ssl);
    info.verify_ok = (vresult == X509_V_OK);
    if (!info.verify_ok)
        info.verify_error = X509_verify_cert_error_string(vresult);

    // Peer certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return info;

    info.subject = x509_name_to_str(X509_get_subject_name(cert));
    info.issuer  = x509_name_to_str(X509_get_issuer_name(cert));
    info.not_before = asn1_time_to_str(X509_get_notBefore(cert));
    info.not_after  = asn1_time_to_str(X509_get_notAfter(cert));

    // Serial number
    {
        BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), nullptr);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            if (hex) { info.serial = hex; OPENSSL_free(hex); }
            BN_free(bn);
        }
    }

    // Fingerprints
    {
        unsigned char sha1[EVP_MAX_MD_SIZE], sha256[EVP_MAX_MD_SIZE];
        unsigned int sha1_len = 0, sha256_len = 0;
        X509_digest(cert, EVP_sha1(),   sha1,   &sha1_len);
        X509_digest(cert, EVP_sha256(), sha256, &sha256_len);
        info.fingerprint_sha1   = hex_encode(sha1,   sha1_len);
        info.fingerprint_sha256 = hex_encode(sha256, sha256_len);
    }

    // SANs
    info.sans = extract_sans(cert);

    X509_free(cert);
    return info;
}

static std::string extract_header(const std::vector<u8> &resp,
                                  const std::string     &field_name)
{

    const size_t hard_cap = std::min(resp.size(), (size_t)8192);
    size_t header_end = hard_cap;

    // Search for \r\n\r\n
    for (size_t i = 0; i + 3 < hard_cap; ++i) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            header_end = i + 4;
            break;
        }
    }
    if (header_end == hard_cap) {
        for (size_t i = 0; i + 1 < hard_cap; ++i) {
            if (resp[i]=='\n' && resp[i+1]=='\n') {
                header_end = i + 2;
                break;
            }
        }
    }
    const std::string needle_lc = [&]() {
        std::string n = field_name;
        for (char &c : n) c = (char)tolower((unsigned char)c);
        return n;
    }();

    size_t pos = 0;
    while (pos < header_end && resp[pos] != '\r' && resp[pos] != '\n') ++pos;
    if (pos < header_end && resp[pos] == '\r') ++pos;
    if (pos < header_end && resp[pos] == '\n') ++pos;

    while (pos < header_end) {
        size_t line_start = pos;
        while (pos < header_end && resp[pos] != '\r' && resp[pos] != '\n') ++pos;
        size_t line_end = pos;
        if (pos < header_end && resp[pos] == '\r') ++pos;
        if (pos < header_end && resp[pos] == '\n') ++pos;

        if (line_end == line_start) break; 
        size_t colon = line_start;
        while (colon < line_end && resp[colon] != ':') ++colon;
        if (colon >= line_end) continue;
        size_t field_len = colon - line_start;
        if (field_len != needle_lc.size()) continue;
        bool match = true;
        for (size_t k = 0; k < field_len; ++k) {
            if ((char)tolower((unsigned char)resp[line_start + k]) != needle_lc[k]) {
                match = false; break;
            }
        }
        if (!match) continue;
        size_t val_start = colon + 1;
        while (val_start < line_end &&
               (resp[val_start] == ' ' || resp[val_start] == '\t')) ++val_start;

        size_t val_end = line_end;
        while (val_end > val_start &&
               (resp[val_end - 1] == ' ' || resp[val_end - 1] == '\t')) --val_end;

        return std::string(resp.begin() + (std::ptrdiff_t)val_start,
                           resp.begin() + (std::ptrdiff_t)val_end);
    }
    return "";
}

// Generic header collector: parses every "Name: value" line in the response
// header block into a map keyed by lowercased header name. Unlike
// extract_header() (which only knows about one hardcoded field name at a
// time), this lets signatures.conf reference ANY response header directly
// by name -- new header-based signatures need zero C++ changes.
// First occurrence of a repeated header wins, matching extract_header()'s
// behavior. Values are right/left trimmed of spaces/tabs the same way.
//
// dup_out (optional): if non-null, records "Name: first-value | second-value"
// for every header name seen more than once WITH DIFFERING values. A
// duplicated Server/X-Powered-By/Content-Length/etc. header with conflicting
// values is a classic sign of response splitting, a chunked-proxy rewrite,
// or a deliberately spoofed banner sitting in front of the real one -- and
// under the old first-wins-silently behavior that second value was thrown
// away with no trace at all, so this kind of tampering was invisible to the
// scanner. Exact-duplicate repeats (same name, same value) are NOT flagged;
// that's normal for some servers/proxies and not a useful signal.
static std::map<std::string, std::string> collect_all_headers(
    const std::vector<u8> &resp,
    std::vector<std::string> *dup_out = nullptr)
{
    std::map<std::string, std::string> headers;

    const size_t hard_cap = std::min(resp.size(), (size_t)8192);
    size_t header_end = hard_cap;

    for (size_t i = 0; i + 3 < hard_cap; ++i) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            header_end = i + 4;
            break;
        }
    }
    if (header_end == hard_cap) {
        for (size_t i = 0; i + 1 < hard_cap; ++i) {
            if (resp[i]=='\n' && resp[i+1]=='\n') {
                header_end = i + 2;
                break;
            }
        }
    }

    size_t pos = 0;
    // Skip the status line.
    while (pos < header_end && resp[pos] != '\r' && resp[pos] != '\n') ++pos;
    if (pos < header_end && resp[pos] == '\r') ++pos;
    if (pos < header_end && resp[pos] == '\n') ++pos;

    while (pos < header_end) {
        size_t line_start = pos;
        while (pos < header_end && resp[pos] != '\r' && resp[pos] != '\n') ++pos;
        size_t line_end = pos;
        if (pos < header_end && resp[pos] == '\r') ++pos;
        if (pos < header_end && resp[pos] == '\n') ++pos;

        if (line_end == line_start) break; // blank line -> end of headers

        size_t colon = line_start;
        while (colon < line_end && resp[colon] != ':') ++colon;
        if (colon >= line_end) continue; // malformed line, no colon

        std::string name(resp.begin() + (std::ptrdiff_t)line_start,
                         resp.begin() + (std::ptrdiff_t)colon);
        for (char &c : name) c = (char)tolower((unsigned char)c);

        size_t val_start = colon + 1;
        while (val_start < line_end &&
               (resp[val_start] == ' ' || resp[val_start] == '\t')) ++val_start;
        size_t val_end = line_end;
        while (val_end > val_start &&
               (resp[val_end - 1] == ' ' || resp[val_end - 1] == '\t')) --val_end;

        std::string value(resp.begin() + (std::ptrdiff_t)val_start,
                          resp.begin() + (std::ptrdiff_t)val_end);

        static const std::set<std::string> kMultiValueHeaders = { "set-cookie" };

        auto existing = headers.find(name);
        if (existing != headers.end()) {
            if (dup_out && existing->second != value &&
                !kMultiValueHeaders.count(name)) {
                std::string entry = name + ": \"" + existing->second + "\" | \"" + value + "\"";
                bool already_recorded = false;
                for (const auto &d : *dup_out) {
                    if (d == entry) { already_recorded = true; break; }
                }
                if (!already_recorded) dup_out->push_back(entry);
            }
            continue;
        }
        headers.emplace(std::move(name), std::move(value));
    }

    return headers;
}

static std::string extract_status_line(const std::vector<u8> &resp)
{
    const size_t limit = std::min(resp.size(), (size_t)256);
    std::string  s(resp.begin(), resp.begin() + (std::ptrdiff_t)limit);
    auto pos = s.find("\r\n");
    if (pos == std::string::npos) pos = s.find('\n');
    return pos != std::string::npos ? s.substr(0, pos) : s;
}

static int extract_status_code(const std::vector<u8> &resp)
{
    if (resp.size() < 12) return 0;
    // Bytes 9–11 are the 3-digit status code in "HTTP/x.y NNN"
    if (resp[0]!='H'||resp[1]!='T'||resp[2]!='T'||resp[3]!='P'||resp[4]!='/') return 0;
    if (!isdigit(resp[9]) || !isdigit(resp[10]) || !isdigit(resp[11])) return 0;
    return (resp[9]-'0')*100 + (resp[10]-'0')*10 + (resp[11]-'0');
}

/* Extract HTML <title> tag content - simple and robust */
static std::string extract_title(const std::vector<u8> &resp)
{
    size_t limit = std::min(resp.size(), (size_t)65536);
    std::string html(resp.begin(), resp.begin() + (std::ptrdiff_t)limit);
    
    // Convert to lowercase for case-insensitive search
    std::string lower_html = html;
    for (char &c : lower_html) {
        c = tolower((unsigned char)c);
    }
    
    // Find <title tag
    size_t start = lower_html.find("<title");
    if (start == std::string::npos) {
        return "";
    }
    
    // Find the > that closes the opening tag
    size_t gt = html.find('>', start);
    if (gt == std::string::npos) {
        return "";
    }
    
    // Find </title>
    size_t end = lower_html.find("</title>", gt);
    if (end == std::string::npos) {
        // Try to find next < or end of head as fallback
        end = lower_html.find("</head", gt);
        if (end == std::string::npos) {
            end = lower_html.length();
        }
    }
    
    // Extract title
    std::string title = html.substr(gt + 1, end - gt - 1);
    
    // Clean up whitespace
    while (!title.empty() && isspace((unsigned char)title.front())) title.erase(title.begin());
    while (!title.empty() && isspace((unsigned char)title.back())) title.pop_back();
    
    // Decode common HTML entities
    size_t pos;
    while ((pos = title.find("&amp;")) != std::string::npos) title.replace(pos, 5, "&");
    while ((pos = title.find("&lt;")) != std::string::npos)  title.replace(pos, 4, "<");
    while ((pos = title.find("&gt;")) != std::string::npos)  title.replace(pos, 4, ">");
    while ((pos = title.find("&quot;")) != std::string::npos) title.replace(pos, 6, "\"");
    while ((pos = title.find("&#39;")) != std::string::npos) title.replace(pos, 5, "'");
    while ((pos = title.find("&nbsp;")) != std::string::npos) title.replace(pos, 6, " ");
    
    // Normalize multiple spaces
    std::string result;
    bool last_was_space = false;
    for (char c : title) {
        if (isspace((unsigned char)c)) {
            if (!last_was_space) {
                result += ' ';
                last_was_space = true;
            }
        } else {
            result += c;
            last_was_space = false;
        }
    }
    
    // Trim again after normalization
    while (!result.empty() && result.front() == ' ') result.erase(result.begin());
    while (!result.empty() && result.back() == ' ') result.pop_back();
    
    // Limit length
    if (result.size() > 200) result = result.substr(0, 200) + "...";
    
    return result;
}

static bool basename_looks_interesting(const std::string &val)
{
    static const char *kPrefixes[] = {
        "manifest", "asset-manifest", "package", "version", "site"
    };
    std::string path = val;
    size_t qpos = path.find('?');
    if (qpos != std::string::npos) path = path.substr(0, qpos);
    size_t slash = path.find_last_of('/');
    std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
    std::string lower = base;
    for (char &c : lower) c = (char)tolower((unsigned char)c);

    if (lower.size() < 5 || lower.compare(lower.size() - 5, 5, ".json") != 0)
        return false;
    for (auto *pfx : kPrefixes) {
        size_t plen = std::strlen(pfx);
        if (lower.compare(0, plen, pfx) != 0) continue;
        if (lower.size() == plen + 5) return true;             
        char sep = lower[plen];
        if (sep == '-' || sep == '.' || sep == '_') return true;
    }
    return false;
}

static bool path_looks_interesting(const std::string &lower_val)
{
    static const char *kSubstrs[] = {
        "/version", "/api/version", "/status", "/health"
    };
    for (auto *kw : kSubstrs)
        if (lower_val.find(kw) != std::string::npos) return true;
    return false;
}


static void scan_link_rel_manifest(const std::string &html, std::vector<std::string> &out,
                                   size_t cap)
{
    size_t pos = 0;
    while (out.size() < cap) {
        size_t lt = html.find("<link", pos);
        if (lt == std::string::npos) break;
        size_t gt = html.find('>', lt);
        if (gt == std::string::npos) break;
        gt = std::min(gt, lt + 500);
        std::string tag = html.substr(lt, gt - lt);
        pos = lt + 5;

        std::string tag_lc = tag;
        for (char &c : tag_lc) c = (char)tolower((unsigned char)c);
        if (tag_lc.find("rel=\"manifest\"") == std::string::npos &&
            tag_lc.find("rel='manifest'") == std::string::npos)
            continue;

        size_t hpos = tag_lc.find("href=");
        if (hpos == std::string::npos) continue;
        size_t qpos = hpos + 5;
        if (qpos >= tag.size() || (tag[qpos] != '"' && tag[qpos] != '\'')) continue;
        char quote = tag[qpos];
        size_t end = tag.find(quote, qpos + 1);
        if (end == std::string::npos) continue;
        std::string val = tag.substr(qpos + 1, end - qpos - 1);

        if (val.empty() || val[0] == '#') continue;
        if (val.rfind("http://", 0) == 0 || val.rfind("https://", 0) == 0 ||
            val.rfind("//", 0) == 0) continue;   // cross-origin -- don't follow

        if (std::find(out.begin(), out.end(), val) == out.end())
            out.push_back(val);
    }
}

static std::vector<std::string> extract_asset_paths(const std::vector<u8> &resp)
{
    std::vector<std::string> out;
    const size_t limit = std::min(resp.size(), (size_t)65536);
    std::string html(resp.begin(), resp.begin() + (std::ptrdiff_t)limit);
    const size_t kCap = 12;
    scan_link_rel_manifest(html, out, kCap);
    auto scan_attr = [&](const char *attr) {
        size_t pos = 0;
        const size_t attr_len = std::strlen(attr);
        while (out.size() < kCap) {
            size_t apos = html.find(attr, pos);
            if (apos == std::string::npos) break;
            size_t qpos = apos + attr_len;
            if (qpos >= html.size() || html[qpos] != '"') { pos = apos + attr_len; continue; }
            size_t end = html.find('"', qpos + 1);
            if (end == std::string::npos) break;
            std::string val = html.substr(qpos + 1, end - qpos - 1);
            pos = end + 1;

            if (val.empty() || val[0] == '#') continue;
            if (val.rfind("http://", 0) == 0 || val.rfind("https://", 0) == 0 ||
                val.rfind("//", 0) == 0) continue;   // cross-origin -- don't follow
            if (std::find(out.begin(), out.end(), val) != out.end()) continue; // dedup

            std::string lower = val;
            for (char &c : lower) c = (char)tolower((unsigned char)c);

            if (basename_looks_interesting(val) || path_looks_interesting(lower))
                out.push_back(val);
        }
    };

    scan_attr("href=");
    scan_attr("src=");
    return out;
}

static std::string extract_report_to_group(const std::vector<u8> &resp)
{
    std::string raw = extract_header(resp, "Report-To");
    if (raw.empty()) return "";
    size_t pos = raw.find("\"group\"");
    if (pos == std::string::npos) return "";
    pos = raw.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = raw.find('"', pos);
    if (pos == std::string::npos) return "";
    size_t end = raw.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return raw.substr(pos + 1, end - pos - 1);
}

static std::string extract_coop_report_to(const std::vector<u8> &resp)
{
    std::string raw = extract_header(resp, "Cross-Origin-Opener-Policy-Report-Only");
    if (raw.empty()) return "";
    size_t pos = raw.find("report-to=");
    if (pos == std::string::npos) return "";
    pos += strlen("report-to=");
    if (pos >= raw.size()) return "";
    if (raw[pos] == '"') {
        size_t end = raw.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return raw.substr(pos + 1, end - pos - 1);
    }
    // Unquoted value fallback: read until ';', whitespace, or end.
    size_t end = raw.find_first_of("; \t", pos);
    return (end == std::string::npos) ? raw.substr(pos) : raw.substr(pos, end - pos);
}

struct HttpFingerprint {
    std::string phase;          // "initial" | "redirect-src" | "redirect-dst"
                                // | "4xx-plain" | "ssl-after-4xx" | "ssl-after-4xx-redirect-dst"
    int         status_code  = 0;
    std::string status_line;
    std::string server;         // Server: header value
    std::string osd_name;       // osd-name: header value (alternate identity)
    std::string powered_by;     // X-Powered-By: (optional)
    std::string title; 
    std::string via;            // Via: (optional)
    std::string x_generator;    // X-Generator: (optional)
    std::string location;       // Location: present on 3xx
    std::string redirect_url;   // resolved redirect URL (absolute or path)
    bool        is_redirect  = false;
    bool        is_4xx       = false;
    bool        is_ssl       = false;
    std::string raw_snippet;    // first 200 bytes of response (printable)
    TlsCertInfo tls_cert;       // populated when is_ssl == true

    // Every response header, lowercased-name -> value. Populated generically
    // for ALL headers (not just the ones with a dedicated field below), so
    // signatures.conf [platform.*] rules can reference any header by name
    // via field_any_nonempty without requiring a matching C++ field.
    std::map<std::string, std::string> raw_headers;

    // ---- Tamper / anomaly signals -----------------------------------------
    // Populated in fetch_and_fingerprint() from collect_all_headers()'s
    // dup_out, and in extract_html_body_signals() when the page's own
    // meta-generator claim contradicts what the structural (path/JS-global/
    // comment/body) evidence actually points to. Both are heuristics, not
    // proof -- surfaced to the operator as a flag, not auto-acted-on.
    std::vector<std::string> duplicate_headers; // "Name: \"v1\" | \"v2\""
    std::string               tamper_hint;       // e.g. "meta:generator claims WordPress but structural signals point to Joomla (score=5 vs 0)"

    // ---- CDN / Cache / Proxy infrastructure headers ----
    std::string x_amz_cf_pop;
    std::string x_amz_cf_id;
    std::string x_cache;
    std::string cf_ray;
    std::string cf_cache_status;
    std::string x_served_by;
    std::string x_cache_hits;
    std::string x_cache_lookup;
    std::string akamai_cache_key;
    std::string x_amz_request_id;
    std::string x_amz_id_2;
    std::string x_amz_version_id;
    std::string x_amz_sse;
    std::string x_amz_bucket_region;
    std::string x_amzn_request_id;
    std::string x_amzn_error_type;
    std::string x_via;
    std::string x_forwarded_for;
    std::string x_forwarded_proto;
    std::string x_real_ip;
    std::string x_haproxy_server_state;
    std::string x_varnish;
    std::string x_cacheable;
    std::string x_cache_status;
    std::string x_cache_expiry;
    std::string age;
    std::string x_drupal_cache;
    std::string x_drupal_dynamic_cache;
    std::string x_magento_cache_debug;
    std::string x_wordpress_cache;
    std::string x_prestashop_cache;
    // ---- Security ----
    std::string www_authenticate;
    std::string x_content_type_options;
    std::string strict_transport_security;
    std::string report_to_group;          // "group" value from Report-To: {"group":"NAME",...}
    std::string coop_report_to_group;     // report-to="NAME" from Cross-Origin-Opener-Policy-Report-Only
    // ---- APM / Tracing ----
    std::string x_newrelic_app_data;
    std::string x_request_id;
    std::string server_timing;
    std::string x_cloud_trace_context;
    // ---- CDN vendor specifics ----
    std::string x_cdn;
    std::string x_edge_location;
    std::string x_edge_connect;
    std::string x_edgeconnect_config;
    std::string x_edgeconnect_method;
    std::string x_cache_key;
    std::string x_timer;
    std::string x_host;
    std::string x_backend;
    std::string x_backend_server;
    std::string x_orig_cache;
    std::string x_proxy_cache;
    // ---- AWS extended ----
    std::string x_amz_storage_class;
    std::string x_amz_delete_marker;
    std::string x_amz_expiration;
    std::string x_amz_replication_status;
    std::string x_amz_request_charged;
    // ---- GCP / GCS ----
    std::string x_google_cache_control;
    std::string x_google_cache_hit;
    std::string x_google_load_balancer;
    std::string x_google_backend;
    std::string x_google_appengine_app;
    std::string x_google_appengine_country;
    std::string x_guploader;
    std::string x_gcs_bucket;
    std::string x_gcs_object_generation;
    // ---- Azure / MS Edge ----
    std::string x_ms_edge_ref;
    std::string x_ms_request_id;
    std::string x_ms_client_request_id;
    std::string x_ms_correlation_request_id;
    std::string x_azure_ref;
    std::string x_azure_request_id;
    std::string x_msedge_ref;
    // ---- Load balancer ----
    std::string x_lb_node;
    std::string x_lb_tag;
    std::string x_lb_instance;
    std::string x_lb_server;
    std::string x_lb_backend;
    std::string x_proxy_id;
    std::string x_proxy_server;
    std::string x_proxy_backend;
    std::string x_haproxy_node;
    std::string x_haproxy_backend;
    std::string x_haproxy_config;
    // ---- Nginx / Varnish / Squid ----
    std::string x_nginx_cache_status;
    std::string x_nginx_proxy;
    std::string x_cache_id;
    std::string x_cache_ttl;
    std::string x_cache_time;
    std::string x_cache_request;
    std::string x_cache_response;
    std::string x_cache_info;
    std::string x_squid_error;
    std::string x_squid_request_id;
    std::string x_varnish_cache;
    std::string x_varnish_age;
    std::string x_varnish_backend;
    std::string x_varnish_session;
    std::string x_varnish_hit;
    std::string x_varnish_ttl;
    // ---- Auth ----
    std::string x_auth_token;
    std::string x_auth_request_redirect;
    std::string x_auth_request_url;
    std::string x_auth_user;
    std::string x_auth_user_groups;
    std::string x_auth_service;
    std::string x_csrf_token;
    std::string x_csrf_param;
    std::string x_csrf_header;
    // ---- Debug / CMS ----
    std::string x_debug;
    std::string x_debug_token;
    std::string x_debug_token_link;
    std::string x_drupal_route;
    std::string x_drupal_ajax_token;
    std::string x_wordpress_theme;
    std::string x_wordpress_plugin;
    std::string x_magento_store;
    std::string x_magento_theme;
    std::string x_magento_layout;
    std::string x_prestashop_store;
    std::string x_prestashop_theme;
    // ---- Timing / Rate limiting ----
    std::string x_response_time;
    std::string x_execution_time;
    std::string x_process_time;
    std::string x_generator_duration;
    std::string x_powered_by_duration;
    std::string x_ratelimit_limit;
    std::string x_ratelimit_remaining;
    std::string x_ratelimit_reset;
    std::string x_ratelimit_retry_after;
    std::string x_ratelimit_resource;
    // ---- Misc ----
    std::string x_mailer;
    std::string x_php_script;
    std::string x_php_origin;
    std::string x_object_version;
    std::string x_object_delete_marker;
    std::string x_object_expiry;
    std::string x_object_storage_class;
    std::string x_bucket_location;
    std::string x_bucket_versioning;

    // ---- CI/CD / DevOps identity headers ----
    std::string x_jenkins;            // X-Jenkins: (Jenkins version string)
    std::string x_hudson;             // X-Hudson: (Hudson / older Jenkins)
    std::string x_teamcity_node_id;   // X-TeamCity-Node-Id:
    std::string x_gitlab_meta;        // X-Gitlab-Meta: (GitLab request metadata)
    std::string x_harness_account;    // x-harness-account: (Harness.io)

    // ---- HTML body signals (meta tags, comments, link tags, JS globals) ----
    // meta name="generator/software/author/framework/cms/powered-by/built-with" etc.
    std::string meta_generator;
    std::string meta_software;
    std::string meta_author;
    std::string meta_developer;
    std::string meta_framework;
    std::string meta_cms;
    std::string meta_powered_by;
    std::string meta_built_with;
    std::string meta_created_by;
    std::string meta_application_name;
    std::string meta_progid;
    std::string meta_msapplication_config;
    std::string meta_msapplication_tile_image;
    std::string meta_msapplication_tile_color;
    std::string meta_apple_title;
    std::string meta_apple_capable;
    std::vector<std::string> html_comments;   
    std::vector<std::string> link_platform_paths; 
    std::vector<std::string> js_globals;   
    std::string body_platform_hint;        
    // ---- Client-Side Routing / SPA location references (status-200 redirects) ----
    std::vector<std::string> spa_locations; // URLs found via JS location / meta-refresh patterns

    // Print fields only — caller controls the section header and deduplication.
    // 'seen_keys' accumulates field labels already printed so duplicates are skipped.
    void print(std::ostream &out,
               std::set<std::string> *seen_keys = nullptr,
               const std::string    &title_override = "",
               const std::set<std::string> *shown_values = nullptr) const {
        // Helper that skips a field if its label was already emitted.
        auto emit = [&](const std::string &label, const std::string &val) {
	    if (val.empty()) return;
	    if (seen_keys && seen_keys->count(label)) return;
	    if (shown_values) {
		std::string lv = val;
		for (char &c : lv) c = (char)tolower((unsigned char)c);
		if (shown_values->count(lv)) return;
	    }
	    if (seen_keys) seen_keys->insert(label);

	    // Normalize val: collapse embedded \r \n \t and whitespace runs to single space
	    std::string clean;
	    clean.reserve(val.size());
	    bool in_ws = false;
	    for (unsigned char c : val) {
		if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
		    if (!in_ws) { clean += ' '; in_ws = true; }
		} else { clean += (char)c; in_ws = false; }
	    }
	    while (!clean.empty() && clean.front() == ' ') clean.erase(clean.begin());
	    while (!clean.empty() && clean.back()  == ' ') clean.pop_back();

	    // Truncate val to fit box (80 chars max after label column, wide enough
	    // for merged redirect-hop values like "nginx | openresty | apache")
	    static constexpr size_t VAL_MAX = 80;
	    if (clean.size() > VAL_MAX) clean = clean.substr(0, VAL_MAX - 3) + "...";

	    out << "|  " << std::left << std::setw(13) << label << ": " << "\033[32m" << clean << "\033[0m" << "\n";
	};

        emit("Server",       server);
        emit("osd-name",     osd_name);
        emit("X-Powered-By", powered_by);
        emit("Report-To",    report_to_group);
        emit("COOP-Report",  coop_report_to_group);
        // Title: use override (from probe match) if provided, otherwise this FP's title
        if (!title_override.empty())
            emit("Title", title_override);
        else
            emit("Title", title);
        // Via: strip leading HTTP-version token (e.g. "1.1 ") before display,
        // and collapse CloudFront's long hash hostname to just "CloudFront".
        {
            std::string via_display = via;
            // Strip the leading version token ("1.1 ", "2 ", etc.)
            auto sp = via_display.find(' ');
            if (sp != std::string::npos)
                via_display = via_display.substr(sp + 1);
            // Trim any leading whitespace left over
            while (!via_display.empty() && via_display.front() == ' ')
                via_display.erase(via_display.begin());
            // Collapse CloudFront's "hash.cloudfront.net (CloudFront)" → "CloudFront"
            {
                std::string lower = via_display;
                for (char &c : lower) c = (char)tolower((unsigned char)c);
                if (lower.find("cloudfront") != std::string::npos)
                    via_display = "CloudFront";
            }
            emit("Proxy", via_display);
        }
        emit("X-Generator",  x_generator);
        if (!redirect_url.empty() && redirect_url != location)
            emit("Redirect->", redirect_url);

        // ---- Infrastructure / CDN / security headers (emit deduplicates) ----
        emit("X-Amz-Cf-Pop",           x_amz_cf_pop);
        emit("X-Amz-Cf-Id",            x_amz_cf_id);
        emit("X-Cache",                x_cache);
        emit("CF-Ray",                 cf_ray);
        emit("CF-Cache-Status",        cf_cache_status);
        emit("X-Served-By",            x_served_by);
        emit("X-Cache-Hits",           x_cache_hits);
        emit("X-Cache-Lookup",         x_cache_lookup);
        emit("Akamai-X-Get-Cache-Key", akamai_cache_key);
        emit("X-Amz-Request-Id",       x_amz_request_id);
        emit("X-Amz-Id-2",             x_amz_id_2);
        emit("x-amz-version-id",       x_amz_version_id);
        emit("X-Amz-SSE",              x_amz_sse);
        emit("X-Amz-Bucket-Region",    x_amz_bucket_region);
        emit("X-Amzn-RequestId",       x_amzn_request_id);
        emit("X-Amzn-Error-Type",      x_amzn_error_type);
        // Via already emitted above; emit() will skip if seen_keys tracks it
        emit("X-Via",                  x_via);
        emit("X-Forwarded-For",        x_forwarded_for);
        emit("X-Forwarded-Proto",      x_forwarded_proto);
        emit("X-Real-IP",              x_real_ip);
        emit("X-Haproxy-Server-State", x_haproxy_server_state);
        emit("X-Varnish",              x_varnish);
        emit("X-Cacheable",            x_cacheable);
        emit("X-Cache-Status",         x_cache_status);
        emit("X-Cache-Expiry",         x_cache_expiry);
        emit("Age",                    age);
        emit("X-Drupal-Cache",         x_drupal_cache);
        emit("X-Drupal-Dynamic-Cache", x_drupal_dynamic_cache);
        emit("X-Magento-Cache-Debug",  x_magento_cache_debug);
        emit("X-WordPress-Cache",      x_wordpress_cache);
        emit("X-Prestashop-Cache",     x_prestashop_cache);
        emit("WWW-Authenticate",       www_authenticate);
        // X-Content-Type-Options and Strict-Transport-Security intentionally omitted
        emit("X-NewRelic-App-Data",    x_newrelic_app_data);
        emit("X-Request-Id",           x_request_id);
        emit("Server-Timing",          server_timing);
        emit("X-Cloud-Trace-Context",  x_cloud_trace_context);
        emit("X-CDN",                  x_cdn);
        emit("X-Edge-Location",        x_edge_location);
        emit("X-Edge-Connect",         x_edge_connect);
        emit("X-EdgeConnect-Config",   x_edgeconnect_config);
        emit("X-EdgeConnect-Method",   x_edgeconnect_method);
        emit("X-Cache-Key",            x_cache_key);
        emit("X-Timer",                x_timer);
        emit("X-Host",                 x_host);
        emit("X-Backend",              x_backend);
        emit("X-Backend-Server",       x_backend_server);
        emit("X-Orig-Cache",           x_orig_cache);
        emit("X-Proxy-Cache",          x_proxy_cache);
        emit("X-Amz-Storage-Class",    x_amz_storage_class);
        emit("X-Amz-Delete-Marker",    x_amz_delete_marker);
        emit("X-Amz-Expiration",       x_amz_expiration);
        emit("X-Amz-Replication",      x_amz_replication_status);
        emit("X-Amz-Req-Charged",      x_amz_request_charged);
        emit("X-Google-Cache-Control", x_google_cache_control);
        emit("X-Google-Cache-Hit",     x_google_cache_hit);
        emit("X-Google-LB",            x_google_load_balancer);
        emit("X-Google-Backend",       x_google_backend);
        emit("X-GAE-App",              x_google_appengine_app);
        emit("X-GAE-Country",          x_google_appengine_country);
        emit("X-GUploader",            x_guploader);
        emit("X-GCS-Bucket",           x_gcs_bucket);
        emit("X-GCS-Object-Gen",       x_gcs_object_generation);
        emit("X-MS-Edge-Ref",          x_ms_edge_ref);
        emit("X-MS-RequestId",         x_ms_request_id);
        emit("X-MS-Client-RequestId",  x_ms_client_request_id);
        emit("X-MS-Correlation-ReqId", x_ms_correlation_request_id);
        emit("X-Azure-Ref",            x_azure_ref);
        emit("X-Azure-RequestId",      x_azure_request_id);
        emit("X-MSEdge-Ref",           x_msedge_ref);
        emit("X-LB-Node",              x_lb_node);
        emit("X-LB-Tag",               x_lb_tag);
        emit("X-LB-Instance",          x_lb_instance);
        emit("X-LB-Server",            x_lb_server);
        emit("X-LB-Backend",           x_lb_backend);
        emit("X-Proxy-Id",             x_proxy_id);
        emit("X-Proxy-Server",         x_proxy_server);
        emit("X-Proxy-Backend",        x_proxy_backend);
        emit("X-HAProxy-Node",         x_haproxy_node);
        emit("X-HAProxy-Backend",      x_haproxy_backend);
        emit("X-HAProxy-Config",       x_haproxy_config);
        emit("X-Nginx-Cache-Status",   x_nginx_cache_status);
        emit("X-Nginx-Proxy",          x_nginx_proxy);
        emit("X-Cache-Id",             x_cache_id);
        emit("X-Cache-TTL",            x_cache_ttl);
        emit("X-Cache-Time",           x_cache_time);
        emit("X-Cache-Request",        x_cache_request);
        emit("X-Cache-Response",       x_cache_response);
        emit("X-Cache-Info",           x_cache_info);
        emit("X-Squid-Error",          x_squid_error);
        emit("X-Squid-Request-Id",     x_squid_request_id);
        emit("X-Varnish-Cache",        x_varnish_cache);
        emit("X-Varnish-Age",          x_varnish_age);
        emit("X-Varnish-Backend",      x_varnish_backend);
        emit("X-Varnish-Session",      x_varnish_session);
        emit("X-Varnish-Hit",          x_varnish_hit);
        emit("X-Varnish-TTL",          x_varnish_ttl);
        emit("X-Auth-Token",           x_auth_token);
        emit("X-Auth-Req-Redirect",    x_auth_request_redirect);
        emit("X-Auth-Req-URL",         x_auth_request_url);
        emit("X-Auth-User",            x_auth_user);
        emit("X-Auth-User-Groups",     x_auth_user_groups);
        emit("X-Auth-Service",         x_auth_service);
        emit("X-CSRF-Token",           x_csrf_token);
        emit("X-CSRF-Param",           x_csrf_param);
        emit("X-CSRF-Header",          x_csrf_header);
        emit("X-Debug",                x_debug);
        emit("X-Debug-Token",          x_debug_token);
        emit("X-Debug-Token-Link",     x_debug_token_link);
        emit("X-Drupal-Route",         x_drupal_route);
        emit("X-Drupal-Ajax-Token",    x_drupal_ajax_token);
        emit("X-WordPress-Theme",      x_wordpress_theme);
        emit("X-WordPress-Plugin",     x_wordpress_plugin);
        emit("X-Magento-Store",        x_magento_store);
        emit("X-Magento-Theme",        x_magento_theme);
        emit("X-Magento-Layout",       x_magento_layout);
        emit("X-Prestashop-Store",     x_prestashop_store);
        emit("X-Prestashop-Theme",     x_prestashop_theme);
        emit("X-Response-Time",        x_response_time);
        emit("X-Execution-Time",       x_execution_time);
        emit("X-Process-Time",         x_process_time);
        emit("X-Generator-Duration",   x_generator_duration);
        emit("X-Powered-By-Duration",  x_powered_by_duration);
        emit("X-RateLimit-Limit",      x_ratelimit_limit);
        emit("X-RateLimit-Remaining",  x_ratelimit_remaining);
        emit("X-RateLimit-Reset",      x_ratelimit_reset);
        emit("X-RateLimit-Retry-After",x_ratelimit_retry_after);
        emit("X-RateLimit-Resource",   x_ratelimit_resource);
        emit("X-Mailer",               x_mailer);
        emit("X-PHP-Script",           x_php_script);
        emit("X-PHP-Origin",           x_php_origin);
        emit("X-Object-Version",       x_object_version);
        emit("X-Object-Delete-Marker", x_object_delete_marker);
        emit("X-Object-Expiry",        x_object_expiry);
        emit("X-Object-Storage-Class", x_object_storage_class);
        emit("X-Bucket-Location",      x_bucket_location);
        emit("X-Bucket-Versioning",    x_bucket_versioning);
        // ---- CI/CD / DevOps identity headers ----
        emit("X-Jenkins",             x_jenkins);
        emit("X-Hudson",              x_hudson);
        emit("X-TeamCity-NodeId",     x_teamcity_node_id);
        emit("X-Gitlab-Meta",         x_gitlab_meta);
        emit("X-Harness-Account",     x_harness_account);
        emit("meta:generator",      meta_generator);
        emit("meta:software",       meta_software);
        emit("meta:author",         meta_author);
        emit("meta:developer",      meta_developer);
        emit("meta:framework",      meta_framework);
        emit("meta:cms",            meta_cms);
        emit("meta:powered-by",     meta_powered_by);
        emit("meta:built-with",     meta_built_with);
        emit("meta:created-by",     meta_created_by);
        emit("meta:app-name",       meta_application_name);
        emit("meta:progid",         meta_progid);
        emit("meta:ms-config",      meta_msapplication_config);
        emit("meta:ms-tile-img",    meta_msapplication_tile_image);
        emit("meta:ms-tile-color",  meta_msapplication_tile_color);
        emit("meta:apple-title",    meta_apple_title);
        emit("meta:apple-capable",  meta_apple_capable);
        if (!body_platform_hint.empty())
            emit("Body Platform", "[" + body_platform_hint + "]");
        if (!tamper_hint.empty())
            emit("TAMPER?", "[" + tamper_hint + "]");
        for (size_t di = 0; di < duplicate_headers.size() && di < 5; ++di) {
            emit("Dup Header", duplicate_headers[di]);
        }
        // ---- SPA / Client-Side Routing locations ----
        for (size_t si = 0; si < spa_locations.size() && si < 5; ++si) {
            emit("SPA-Location", spa_locations[si]);
        }
        // html_comments block (lines 777–784) — replace with:
	if (!html_comments.empty()) {
	    for (const auto &c : html_comments) {
		if (seen_keys && seen_keys->count("html_comment:" + c)) continue;
		if (seen_keys) seen_keys->insert("html_comment:" + c);
		std::string val = c.size() > 42 ? c.substr(0, 39) + "..." : c;
		out << std::left << std::setw(13) << "HTML-Comment" << val << "\n";
	    }
	}

	// link_platform_paths block (lines 786–793) — replace with:
	if (!link_platform_paths.empty()) {
	    for (const auto &lp : link_platform_paths) {
		if (seen_keys && seen_keys->count("link_path:" + lp)) continue;
		if (seen_keys) seen_keys->insert("link_path:" + lp);
		std::string val = lp.size() > 42 ? lp.substr(0, 39) + "..." : lp;
		out << std::left << std::setw(13) << "Link-Path" << val << "\n";
	    }
	}

	// js_globals block (lines 795–802) — replace with:
	if (!js_globals.empty()) {
	    for (const auto &g : js_globals) {
		if (seen_keys && seen_keys->count("js_global:" + g)) continue;
		if (seen_keys) seen_keys->insert("js_global:" + g);
		std::string val = g.size() > 42 ? g.substr(0, 39) + "..." : g;
		out << std::left << std::setw(13) << "JS-Global" << val << "\n";
	    }
	}

        tls_cert.print(out);
    }
};

std::string g_signature_conf_path = "/usr/share/shiv/signatures.conf";


struct PathSigEntry { std::string needle; std::string label; };
struct AttrSigEntry { std::string attr;   std::string label; };

// An entry in signatures.conf's [identity_headers] section: a single HTTP
// response header that should be surfaced on the -sV version line whenever
// it's present. This is the ONLY thing you need to touch to make a new
// header show up there -- no HttpFingerprint field, no extract_header()
// call, no C++ recompile. Lookup happens directly against
// HttpFingerprint::raw_headers, which already captures every response
// header generically (see collect_all_headers()).
//   header : the HTTP header name, case-insensitive (e.g. "X-Powered-By-Plesk")
//   label  : what to print it as
//   bare   : true  -> the header's value is already self-descriptive and is
//                      printed as-is, e.g. Server: "cloudflare" -> "cloudflare"
//            false -> the value is just a bare token/number, so it's printed
//                      as "label: value", e.g. X-Jenkins: "2.440.3" ->
//                      "Jenkins: 2.440.3"
struct IdentityHeaderSpec { std::string header; std::string label; bool bare; };

struct PlatformRule {
    enum class Kind {
        PathContains,          // arg = substring to find in link_platform_paths entries
        JsGlobalEq,            // arg = exact string to match in js_globals entries
        CommentContains,       // arg = substring to find in html_comments entries
        MetaGeneratorContains, // arg = substring to find in meta_generator
        FieldAnyNonEmpty,      // arg = comma-separated HTTP header names; bump if any is present & non-empty
        BodyContains,          // arg = substring to find anywhere in the lowercased response body
                                //       (covers text outside href=/comments -- e.g. src="...", plain
                                //       visible text, inline JSON blobs)
        HeaderValueContains    // header = specific HTTP response header name (lowercased);
                                // arg    = substring to find inside THAT header's value (lowercased).
                                //          Unlike FieldAnyNonEmpty (presence-only), this lets a rule
                                //          key off *what a header says*, e.g. Server containing
                                //          "openresty" or "nginx", or X-Powered-By containing "PHP".
                                //          signatures.conf syntax: header_contains|Header=needle|weight
    };
    Kind        kind;
    std::string arg;
    std::string header;   // only used by HeaderValueContains
    int         weight = 1;
};

struct SuppressRule {
    std::string trigger_platform;
    int         trigger_min_score = 0;
    std::string suppressed_platform;
};

// NOTE: field_any_nonempty used to require each header to be registered here
// by hand as a named HttpFingerprint field. That's gone -- it now looks
// straight into HttpFingerprint::raw_headers (see the FieldAnyNonEmpty case
// in the scorer below), so any header can be referenced purely from
// signatures.conf. Underscores in the signatures.conf arg are treated as
// equivalent to hyphens (e.g. "x_iinfo" matches the "X-Iinfo" header), so
// existing entries using the old underscore convention keep working as-is.

class PlatformSignatureSet {
public:
    std::vector<std::string>                         js_globals;
    std::vector<PathSigEntry>                         path_sigs;
    std::vector<AttrSigEntry>                         attr_sigs;
    std::map<std::string, std::vector<PlatformRule>>  platform_rules; // platform name -> rules
    std::vector<std::string>                          meta_hint_platforms;
    std::vector<SuppressRule>                          suppress_rules;
    std::vector<IdentityHeaderSpec>                    identity_headers; // [identity_headers]

    static PlatformSignatureSet loadFromFile(const std::string &path);
};

namespace platform_sig_detail {

static inline std::string trim(const std::string &s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static inline std::vector<std::string> split_pipe(const std::string &line)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t p = line.find('|', start);
        if (p == std::string::npos) { parts.push_back(line.substr(start)); break; }
        parts.push_back(line.substr(start, p - start));
        start = p + 1;
    }
    return parts;
}

static inline std::vector<std::string> split_comma(const std::string &s)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t p = s.find(',', start);
        if (p == std::string::npos) { parts.push_back(trim(s.substr(start))); break; }
        parts.push_back(trim(s.substr(start, p - start)));
        start = p + 1;
    }
    return parts;
}

} // namespace platform_sig_detail

PlatformSignatureSet PlatformSignatureSet::loadFromFile(const std::string &path)
{
    using namespace platform_sig_detail;

    std::ifstream in(path);
    if (!in.is_open())
        throw std::runtime_error("cannot open '" + path + "'");

    PlatformSignatureSet sigs;
    std::string section;          // e.g. "jsglobals", "paths", "attrs", "meta_hint_platforms", "suppress"
    std::string current_platform; // set when section starts with "platform."

    std::string raw_line;
    size_t lineno = 0;
    while (std::getline(in, raw_line)) {
        ++lineno;
        // Strip trailing \r for files edited on Windows.
        if (!raw_line.empty() && raw_line.back() == '\r') raw_line.pop_back();
        // Right-trim only: data lines (e.g. [attrs] needles like " id=") may rely
        // on significant leading whitespace, so it must survive into 'line'.
        std::string line = raw_line;
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) line.pop_back();
        std::string check = trim(line); // used only to classify the line
        if (check.empty() || check[0] == '#') continue;

        if (check.front() == '[' && check.back() == ']') {
            section = check.substr(1, check.size() - 2);
            current_platform.clear();
            static const std::string kPlatformPrefix = "platform.";
            if (section.rfind(kPlatformPrefix, 0) == 0) {
                current_platform = section.substr(kPlatformPrefix.size());
                sigs.platform_rules.emplace(current_platform, std::vector<PlatformRule>{});
            }
            continue;
        }

        if (section == "jsglobals") {
            sigs.js_globals.push_back(check);
        }
        else if (section == "paths") {
            auto f = split_pipe(line);
            if (f.size() != 2) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [paths] entry needs 'needle|label'");
            }
            sigs.path_sigs.push_back({ trim(f[0]), trim(f[1]) });
        }
        else if (section == "attrs") {
            auto f = split_pipe(line);
            if (f.size() != 2) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [attrs] entry needs 'attr|label'");
            }
            sigs.attr_sigs.push_back({ f[0], trim(f[1]) }); // keep attr as-is (may have leading space)
        }
        else if (section == "meta_hint_platforms") {
            sigs.meta_hint_platforms.push_back(check);
        }
        else if (section == "identity_headers") {
            // header|label|bare
            auto f = split_pipe(line);
            if (f.size() != 3) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [identity_headers] entry needs 'header|label|bare'");
            }
            IdentityHeaderSpec spec;
            spec.header = trim(f[0]);
            spec.label  = trim(f[1]);
            std::string bare_str = trim(f[2]);
            for (char &c : bare_str) c = (char)tolower((unsigned char)c);
            if (bare_str == "true" || bare_str == "1")       spec.bare = true;
            else if (bare_str == "false" || bare_str == "0") spec.bare = false;
            else {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [identity_headers] bare flag must be true/false");
            }
            sigs.identity_headers.push_back(std::move(spec));
        }
        else if (section == "suppress") {
            // trigger_platform>=min_score|suppressed_platform
            auto f = split_pipe(line);
            if (f.size() != 2) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [suppress] entry needs 'Platform>=N|SuppressedPlatform'");
            }
            size_t ge = f[0].find(">=");
            if (ge == std::string::npos) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": [suppress] trigger must look like 'Platform>=N'");
            }
            SuppressRule r;
            r.trigger_platform    = trim(f[0].substr(0, ge));
            {
	        const std::string num = trim(f[0].substr(ge + 2));
	        char *endp = nullptr;
	        long v = std::strtol(num.c_str(), &endp, 10);
	        if (endp == num.c_str() || *endp != '\0') {
		    throw std::runtime_error(path + ":" + std::to_string(lineno) +
		                              ": [suppress] score must be a valid integer");
	        }
	        r.trigger_min_score = static_cast<int>(v);
	    }
            r.suppressed_platform = trim(f[1]);
            sigs.suppress_rules.push_back(std::move(r));
        }
        else if (!current_platform.empty()) {
            // Rule line inside [platform.NAME]: kind|arg|weight
            auto f = split_pipe(line);
            if (f.size() != 3) {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": platform rule needs 'kind|arg|weight'");
            }
            std::string kind_str = trim(f[0]);
            PlatformRule rule;
            rule.arg    = f[1]; // preserve as-is; some args (attrs) are meaningfully space-sensitive
            {
	        const std::string num = trim(f[2]);
	        char *endp = nullptr;
	        long v = std::strtol(num.c_str(), &endp, 10);
	        if (endp == num.c_str() || *endp != '\0') {
		    throw std::runtime_error(path + ":" + std::to_string(lineno) +
		                              ": platform rule weight must be a valid integer");
	        }
	        rule.weight = static_cast<int>(v);
	    }

            if      (kind_str == "path_contains")           rule.kind = PlatformRule::Kind::PathContains;
            else if (kind_str == "jsglobal_eq")              rule.kind = PlatformRule::Kind::JsGlobalEq;
            else if (kind_str == "comment_contains")         rule.kind = PlatformRule::Kind::CommentContains;
            else if (kind_str == "meta_generator_contains")  rule.kind = PlatformRule::Kind::MetaGeneratorContains;
            else if (kind_str == "field_any_nonempty")       rule.kind = PlatformRule::Kind::FieldAnyNonEmpty;
            else if (kind_str == "body_contains") {
                rule.kind = PlatformRule::Kind::BodyContains;
                // Stored lowercased up front since it's always matched against lbody.
                for (char &c : rule.arg) c = (char)tolower((unsigned char)c);
            }
            else if (kind_str == "header_contains") {
                // arg is "Header=needle"; split on the FIRST '=' so a needle
                // containing '=' (unlikely but not impossible) still works.
                rule.kind = PlatformRule::Kind::HeaderValueContains;
                size_t eq = rule.arg.find('=');
                if (eq == std::string::npos) {
                    throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                              ": header_contains arg must be 'Header=needle'");
                }
                rule.header = trim(rule.arg.substr(0, eq));
                rule.arg    = trim(rule.arg.substr(eq + 1));
                for (char &c : rule.header) { c = (char)tolower((unsigned char)c); if (c == '_') c = '-'; }
                for (char &c : rule.arg)    c = (char)tolower((unsigned char)c);
                if (rule.header.empty() || rule.arg.empty()) {
                    throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                              ": header_contains needs both a header name and a needle");
                }
            }
            else {
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                          ": unknown rule kind '" + kind_str + "'");
            }
            sigs.platform_rules[current_platform].push_back(std::move(rule));
        }
        // Lines outside any recognized section are ignored (forward-compatible).
    }

    return sigs;
}

static const PlatformSignatureSet &platform_signatures()
{
    static const PlatformSignatureSet sigs = [] {
        try {
            return PlatformSignatureSet::loadFromFile(g_signature_conf_path);
        } catch (const std::exception &e) {
            std::cerr << "[web-fp] failed to load signatures.conf: " << e.what()
                      << " -- platform/CMS detection disabled for this run\n";
            return PlatformSignatureSet{};
        }
    }();
    return sigs;
}

static std::vector<std::string> extract_spa_locations(const std::string &body);

static void extract_html_body_signals(const std::vector<u8> &resp,
                                      HttpFingerprint        &fp)
{
    // ---- locate body start -----------------------------------------------
    // We want everything after the blank line separating headers from body.
    size_t body_start = 0;
    const size_t limit = std::min(resp.size(), (size_t)MAX_RESPONSE);

    for (size_t i = 0; i + 3 < limit; ++i) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            body_start = i + 4;
            break;
        }
    }
    if (body_start == 0) {
        // Fallback: \n\n
        for (size_t i = 0; i + 1 < limit; ++i) {
            if (resp[i]=='\n' && resp[i+1]=='\n') {
                body_start = i + 2;
                break;
            }
        }
    }

    // If no separator found, scan whole buffer (e.g. raw HTML without HTTP headers)
    std::string body(resp.begin() + (std::ptrdiff_t)body_start,
                     resp.begin() + (std::ptrdiff_t)limit);

    // Lower-case copy for case-insensitive searches
    std::string lbody = body;
    for (char &c : lbody) c = (char)tolower((unsigned char)c);


    {
        // Collect all <meta ...> tags via manual find — avoids regex DFS stack overflow.
        // Helper: extract a quoted or unquoted attribute value from a tag string.
        auto get_attr = [](const std::string &tag, const std::string &attr_lc) -> std::string {
            // Work on a lowercased copy for matching, but extract value from original
            std::string ltag = tag;
            for (char &c : ltag) c = (char)tolower((unsigned char)c);

            size_t pos = 0;
            while (pos < ltag.size()) {
                size_t ap = ltag.find(attr_lc, pos);
                if (ap == std::string::npos) break;
                // Must be preceded by whitespace or start-of-string
                if (ap > 0 && !isspace((unsigned char)ltag[ap - 1])) { pos = ap + 1; continue; }
                size_t after = ap + attr_lc.size();
                // Skip spaces then '='
                while (after < ltag.size() && ltag[after] == ' ') ++after;
                if (after >= ltag.size() || ltag[after] != '=') { pos = ap + 1; continue; }
                ++after; // skip '='
                while (after < ltag.size() && ltag[after] == ' ') ++after;
                if (after >= ltag.size()) break;
                char q = ltag[after];
                if (q == '"' || q == '\'') {
                    ++after;
                    size_t vend = tag.find(q, after);
                    if (vend == std::string::npos) vend = tag.size();
                    std::string v = tag.substr(after, vend - after);
                    while (!v.empty() && isspace((unsigned char)v.front())) v.erase(v.begin());
                    while (!v.empty() && isspace((unsigned char)v.back()))  v.pop_back();
                    return v;
                } else {
                    // unquoted value
                    size_t vend = after;
                    while (vend < tag.size() && !isspace((unsigned char)tag[vend]) &&
                           tag[vend] != '>' && tag[vend] != '"' && tag[vend] != '\'') ++vend;
                    std::string v = tag.substr(after, vend - after);
                    while (!v.empty() && isspace((unsigned char)v.front())) v.erase(v.begin());
                    while (!v.empty() && isspace((unsigned char)v.back()))  v.pop_back();
                    return v;
                }
            }
            return "";
        };

        // Scan body for <meta ...> tags manually (bounded: skip tags > 500 chars)
        size_t scan_pos = 0;
        while (scan_pos < body.size()) {
            // case-insensitive find of "<meta"
            size_t mp = std::string::npos;
            for (size_t k = scan_pos; k + 5 <= body.size(); ++k) {
                if (tolower((unsigned char)body[k])   == '<' &&
                    tolower((unsigned char)body[k+1]) == 'm' &&
                    tolower((unsigned char)body[k+2]) == 'e' &&
                    tolower((unsigned char)body[k+3]) == 't' &&
                    tolower((unsigned char)body[k+4]) == 'a' &&
                    (isspace((unsigned char)body[k+5]) || body[k+5] == '>')) {
                    mp = k; break;
                }
            }
            if (mp == std::string::npos) break;

            // Find closing '>' — cap search at 500 chars to stay safe
            size_t ge = body.find('>', mp);
            if (ge == std::string::npos || ge - mp > 500) { scan_pos = mp + 5; continue; }
            scan_pos = ge + 1;

            std::string tag = body.substr(mp, ge - mp + 1);
            std::string name_val    = get_attr(tag, "name");
            std::string content_val = get_attr(tag, "content");

            if (name_val.empty() || content_val.empty()) continue;

            // lower-case the name for comparison
            std::string lname = name_val;
            for (char &c : lname) c = (char)tolower((unsigned char)c);

            if (lname == "generator")                  fp.meta_generator            = content_val;
            else if (lname == "software")              fp.meta_software             = content_val;
            else if (lname == "author")                fp.meta_author               = content_val;
            else if (lname == "developer")             fp.meta_developer            = content_val;
            else if (lname == "framework")             fp.meta_framework            = content_val;
            else if (lname == "cms")                   fp.meta_cms                  = content_val;
            else if (lname == "powered-by")            fp.meta_powered_by           = content_val;
            else if (lname == "built-with")            fp.meta_built_with           = content_val;
            else if (lname == "created-by")            fp.meta_created_by           = content_val;
            else if (lname == "application-name")      fp.meta_application_name     = content_val;
            else if (lname == "progid")                fp.meta_progid               = content_val;
            else if (lname == "msapplication-config")  fp.meta_msapplication_config = content_val;
            else if (lname == "msapplication-tileimage")
                                                       fp.meta_msapplication_tile_image  = content_val;
            else if (lname == "msapplication-tilecolor")
                                                       fp.meta_msapplication_tile_color  = content_val;
            else if (lname == "apple-mobile-web-app-title")
                                                       fp.meta_apple_title          = content_val;
            else if (lname == "apple-mobile-web-app-capable")
                                                       fp.meta_apple_capable        = content_val;
        }
    }

    {
        // Extract HTML comments manually — avoids [\s\S]{0,300}? regex DFS overflow.
        // Keywords that suggest a tech-reveal comment
        static const std::vector<std::string> kw = {
            "generated by", "built with", "powered by", "created with",
            "wordpress", "drupal", "magento", "joomla", "prestashop",
            "static generated", "generator:", "this site is", "wix.com",
            "shopify", "squarespace", "ghost", "typo3", "opencart"
        };

        size_t cpos = 0;
        while (cpos < body.size()) {
            size_t cs = body.find("<!--", cpos);
            if (cs == std::string::npos) break;
            size_t ce = body.find("-->", cs + 4);
            if (ce == std::string::npos) break;
            // Limit inner content to 300 chars
            size_t inner_len = ce - (cs + 4);
            if (inner_len <= 300) {
                std::string inner = body.substr(cs + 4, inner_len);
                // trim
                while (!inner.empty() && isspace((unsigned char)inner.front())) inner.erase(inner.begin());
                while (!inner.empty() && isspace((unsigned char)inner.back()))  inner.pop_back();
                if (!inner.empty()) {
                    std::string lower_inner = inner;
                    for (char &c : lower_inner) c = (char)tolower((unsigned char)c);
                    for (const auto &k : kw) {
                        if (lower_inner.find(k) != std::string::npos) {
                            // Collapse internal whitespace for cleaner output
                            std::string cleaned;
                            bool ws = false;
                            for (char c : inner) {
                                if (isspace((unsigned char)c)) { if (!ws) { cleaned += ' '; ws = true; } }
                                else                           { cleaned += c; ws = false; }
                            }
                            fp.html_comments.push_back(cleaned);
                            break;
                        }
                    }
                }
            }
            cpos = ce + 3;
        }
        // Deduplicate
        std::sort(fp.html_comments.begin(), fp.html_comments.end());
        fp.html_comments.erase(std::unique(fp.html_comments.begin(), fp.html_comments.end()),
                               fp.html_comments.end());
    }

    {
       
        size_t scan_p = 0;
        while (scan_p < body.size()) {
            // Case-insensitive find of '<p'
            size_t ptag = std::string::npos;
            for (size_t k = scan_p; k + 2 <= body.size(); ++k) {
                if ((body[k] == '<' || body[k] == '<') &&
                    tolower((unsigned char)body[k]) == '<' &&
                    tolower((unsigned char)body[k+1]) == 'p' &&
                    (isspace((unsigned char)body[k+2]) || body[k+2] == '>')) {
                    ptag = k; break;
                }
            }
            if (ptag == std::string::npos) break;
            // Find the '>' that closes the opening <p ...>
            size_t pgt = body.find('>', ptag);
            if (pgt == std::string::npos || pgt - ptag > 300) { scan_p = ptag + 2; continue; }
            std::string open_tag = body.substr(ptag, pgt - ptag + 1);
            // Check if class contains "command" (case-insensitive)
            std::string open_lc = open_tag;
            for (char &c : open_lc) c = (char)tolower((unsigned char)c);
            if (open_lc.find("class=") != std::string::npos &&
                open_lc.find("command") != std::string::npos)
            {
                // Extract text content up to </p>
                size_t content_start = pgt + 1;
                // Find </p> case-insensitively
                size_t close_pos = std::string::npos;
                for (size_t k = content_start; k + 3 <= body.size(); ++k) {
                    if (body[k] == '<' &&
                        tolower((unsigned char)body[k+1]) == '/' &&
                        tolower((unsigned char)body[k+2]) == 'p' &&
                        (body[k+3] == '>' || isspace((unsigned char)body[k+3]))) {
                        close_pos = k; break;
                    }
                }
                size_t text_end = (close_pos != std::string::npos)
                                ? close_pos : std::min(content_start + 200, body.size());
                std::string text = body.substr(content_start, text_end - content_start);
                // Strip any inner HTML tags
                std::string plain;
                bool in_tag = false;
                for (char c : text) {
                    if      (c == '<') in_tag = true;
                    else if (c == '>') in_tag = false;
                    else if (!in_tag) plain += c;
                }
                // Collapse whitespace
                std::string clean_text;
                bool ws2 = false;
                for (char c : plain) {
                    if (isspace((unsigned char)c)) { if (!ws2) { clean_text += ' '; ws2 = true; } }
                    else                           { clean_text += c; ws2 = false; }
                }
                while (!clean_text.empty() && clean_text.front() == ' ') clean_text.erase(clean_text.begin());
                while (!clean_text.empty() && clean_text.back()  == ' ') clean_text.pop_back();
                if (!clean_text.empty() && clean_text.size() <= 200) {
                    std::string entry = "[p.command] " + clean_text;
                    bool dup = false;
                    for (const auto &e : fp.html_comments) if (e == entry) { dup = true; break; }
                    if (!dup) fp.html_comments.push_back(entry);
                }
                scan_p = (close_pos != std::string::npos) ? close_pos + 4 : pgt + 1;
            } else {
                scan_p = pgt + 1;
            }
        }
    }


    {
        // Detect platform-specific URL paths in href attributes.
        // Manual scan of href="..." values — avoids regex DFS on large HTML bodies.
        // Signature data (needle -> label) comes from signatures.conf [paths].
        const auto &sigs = platform_signatures();

        size_t hpos = 0;
        while (hpos < lbody.size()) {
            // Find next href=
            size_t hp = lbody.find("href=", hpos);
            if (hp == std::string::npos) break;
            hpos = hp + 5;
            if (hpos >= lbody.size()) break;
            char q = lbody[hpos];
            if (q != '"' && q != '\'') continue;
            ++hpos;
            size_t val_end = lbody.find(q, hpos);
            if (val_end == std::string::npos || val_end - hpos > 300) continue;
            // lbody slice for this href value (already lowercase)
            std::string href_val = lbody.substr(hpos, val_end - hpos);
            // original-case value for display
            std::string href_orig = body.substr(hpos, val_end - hpos);
            hpos = val_end + 1;

            for (const auto &sig : sigs.path_sigs) {
                if (href_val.find(sig.needle) != std::string::npos) {
                    std::string entry = "[" + sig.label + "] " + href_orig;
                    bool dup = false;
                    for (const auto &existing : fp.link_platform_paths)
                        if (existing == entry) { dup = true; break; }
                    if (!dup) fp.link_platform_paths.push_back(entry);
                }
            }
        }
    }


    {
        // Collect all <script ...> blocks manually — avoids [\s\S]{0,8000}? DFS overflow.
        // Global names to search for come from signatures.conf [jsglobals].
        const auto &sigs = platform_signatures();

        std::vector<std::string> script_blocks;
        {
            size_t spos = 0;
            // lowercase body for case-insensitive tag search
            while (spos < body.size()) {
                // Find opening <script tag
                size_t tag_start = std::string::npos;
                for (size_t k = spos; k + 7 <= body.size(); ++k) {
                    if (tolower((unsigned char)body[k])   == '<' &&
                        tolower((unsigned char)body[k+1]) == 's' &&
                        tolower((unsigned char)body[k+2]) == 'c' &&
                        tolower((unsigned char)body[k+3]) == 'r' &&
                        tolower((unsigned char)body[k+4]) == 'i' &&
                        tolower((unsigned char)body[k+5]) == 'p' &&
                        tolower((unsigned char)body[k+6]) == 't' &&
                        (isspace((unsigned char)body[k+7]) || body[k+7] == '>')) {
                        tag_start = k; break;
                    }
                }
                if (tag_start == std::string::npos) break;
                // Find the '>' closing the opening tag
                size_t tag_gt = body.find('>', tag_start);
                if (tag_gt == std::string::npos) break;
                size_t content_start = tag_gt + 1;

                // Find </script>
                size_t close_pos = std::string::npos;
                for (size_t k = content_start; k + 9 <= body.size(); ++k) {
                    if (body[k] == '<' &&
                        tolower((unsigned char)body[k+1]) == '/' &&
                        tolower((unsigned char)body[k+2]) == 's' &&
                        tolower((unsigned char)body[k+3]) == 'c' &&
                        tolower((unsigned char)body[k+4]) == 'r' &&
                        tolower((unsigned char)body[k+5]) == 'i' &&
                        tolower((unsigned char)body[k+6]) == 'p' &&
                        tolower((unsigned char)body[k+7]) == 't' &&
                        (body[k+8] == '>' || isspace((unsigned char)body[k+8]))) {
                        close_pos = k; break;
                    }
                }
                if (close_pos == std::string::npos) break;

                size_t block_len = close_pos - content_start;
                if (block_len > 0 && block_len <= 8000)
                    script_blocks.push_back(body.substr(content_start, block_len));

                // Advance past </script>
                size_t close_gt = body.find('>', close_pos);
                spos = (close_gt != std::string::npos) ? close_gt + 1 : close_pos + 9;
            }
        }

        // For each script block, search for JS globals using simple find()
        // instead of constructing a new regex per global per block.
        for (const auto &block : script_blocks) {
            for (const auto &gname : sigs.js_globals) {
                // Patterns: "window.<gname>" or "var <gname>"
                bool found = (block.find("window." + gname) != std::string::npos ||
                              block.find("var "    + gname) != std::string::npos);
                if (found) {
                    std::string label = "window." + gname;
                    bool dup = false;
                    for (const auto &e : fp.js_globals)
                        if (e == label) { dup = true; break; }
                    if (!dup) fp.js_globals.push_back(label);
                }
            }
        }
    }

    {
        // Framework/CMS HTML attribute signatures come from signatures.conf [attrs].
        const auto &sigs = platform_signatures();

        for (const auto &sig : sigs.attr_sigs) {
            if (sig.label.empty()) continue;  // deliberately suppressed
            // Search in the lowercase body copy for case-insensitive match
            std::string la = sig.attr;
            for (char &c : la) c = (char)tolower((unsigned char)c);
            if (lbody.find(la) != std::string::npos) {
                std::string entry = "attr:" + sig.label;
                bool dup = false;
                for (const auto &e : fp.js_globals)
                    if (e == entry) { dup = true; break; }
                if (!dup) fp.js_globals.push_back(entry);
            }
        }
    }

    {
        // Score each platform/framework against the signals collected above.
        // All per-platform rules, meta-tag hints, and cross-platform suppression
        // (e.g. Next.js implies React, so don't double-report React) come from
        // signatures.conf [platform.*] / [meta_hint_platforms] / [suppress].
        const auto &sigs = platform_signatures();

        std::map<std::string, int> scores;
        auto bump = [&](const std::string &platform, int weight) { scores[platform] += weight; };

        for (const auto &[platform, rules] : sigs.platform_rules) {
            for (const auto &rule : rules) {
                switch (rule.kind) {
                    case PlatformRule::Kind::PathContains:
                        for (const auto &lp : fp.link_platform_paths)
                            if (lp.find(rule.arg) != std::string::npos) { bump(platform, rule.weight); break; }
                        break;

                    case PlatformRule::Kind::JsGlobalEq:
                        for (const auto &g : fp.js_globals)
                            if (g == rule.arg) { bump(platform, rule.weight); break; }
                        break;

                    case PlatformRule::Kind::CommentContains:
                        for (const auto &c : fp.html_comments)
                            if (c.find(rule.arg) != std::string::npos) { bump(platform, rule.weight); break; }
                        break;

                    case PlatformRule::Kind::MetaGeneratorContains:
                        if (fp.meta_generator.find(rule.arg) != std::string::npos)
                            bump(platform, rule.weight);
                        break;

                    case PlatformRule::Kind::FieldAnyNonEmpty: {
                        // arg = comma-separated list of HTTP header names (e.g. "X-Iinfo" or
                        // "x_iinfo" -- underscores and hyphens are interchangeable). Looked up
                        // directly against fp.raw_headers, so any response header can be used
                        // as a signature straight from signatures.conf with no C++ change.
                        bool any = false;
                        for (auto fname : platform_sig_detail::split_comma(rule.arg)) {
                            for (char &c : fname) {
                                c = (char)tolower((unsigned char)c);
                                if (c == '_') c = '-';
                            }
                            auto it = fp.raw_headers.find(fname);
                            if (it != fp.raw_headers.end() && !it->second.empty()) { any = true; break; }
                        }
                        if (any) bump(platform, rule.weight);
                        break;
                    }

                    case PlatformRule::Kind::BodyContains:
                        // rule.arg was already lowercased at parse time.
                        if (lbody.find(rule.arg) != std::string::npos)
                            bump(platform, rule.weight);
                        break;

                    case PlatformRule::Kind::HeaderValueContains: {
                        // rule.header and rule.arg were already lowercased at parse time.
                        auto it = fp.raw_headers.find(rule.header);
                        if (it != fp.raw_headers.end()) {
                            std::string lv = it->second;
                            for (char &c : lv) c = (char)tolower((unsigned char)c);
                            if (lv.find(rule.arg) != std::string::npos)
                                bump(platform, rule.weight);
                        }
                        break;
                    }
                }
            }
        }

        // Snapshot the *structural-only* scores (paths, JS globals, HTML
        // comments, response body, header presence) before meta-tag hints
        // get mixed in below. This is what lets us catch a spoofed
        // meta:generator: a page can trivially lie in a <meta name=generator>
        // tag (WAFs/honeypots sometimes do this on purpose to mislead
        // scanners), but faking convincing paths, JS globals, and body
        // content for a *different* platform at the same time is much
        // harder, so a strong disagreement between the two is a real signal.
        std::map<std::string, int> structural_scores = scores;

        // --- Generic CMS/framework hints from meta tags (meta_generator, meta_cms, ...) ---
        auto gen_hint = [&](const std::string &val, const std::string &platform, int w) {
            if (!val.empty()) {
                std::string lv = val;
                for (char &c : lv) c = (char)tolower((unsigned char)c);
                std::string lp = platform;
                for (char &c : lp) c = (char)tolower((unsigned char)c);
                if (lv.find(lp) != std::string::npos) bump(platform, w);
            }
        };
        for (const std::string &platform : sigs.meta_hint_platforms) {
            gen_hint(fp.meta_generator,  platform, 2);
            gen_hint(fp.meta_cms,        platform, 2);
            gen_hint(fp.meta_framework,  platform, 2);
            gen_hint(fp.meta_powered_by, platform, 1);
            gen_hint(fp.meta_built_with, platform, 1);
        }

        // --- Cross-platform suppression (e.g. Next.js >= 2 implies React; don't double-report) ---
        for (const auto &sr : sigs.suppress_rules) {
            auto it = scores.find(sr.trigger_platform);
            if (it != scores.end() && it->second >= sr.trigger_min_score)
                scores[sr.suppressed_platform] = 0;
            auto sit = structural_scores.find(sr.trigger_platform);
            if (sit != structural_scores.end() && sit->second >= sr.trigger_min_score)
                structural_scores[sr.suppressed_platform] = 0;
        }

                // Pick winner (score >= 2 to avoid single-field false positives)
        std::string best;
        int best_score = 1; // minimum threshold
        bool any_qualified = false;
        for (const auto &[name, score] : scores) {
            if (score > best_score) { best_score = score; best = name; any_qualified = true; }
        }

        // If two platforms tie, report both
        std::vector<std::string> tied;
        if (any_qualified) {
            for (const auto &[name, score] : scores)
                if (score == best_score && !name.empty()) tied.push_back(name);
        }

        if (tied.size() == 1)
            fp.body_platform_hint = tied[0] + " (score=" + std::to_string(best_score) + ")";
        else if (tied.size() > 1) {
            fp.body_platform_hint = "";
            for (size_t i = 0; i < tied.size(); ++i) {
                if (i) fp.body_platform_hint += " / ";
                fp.body_platform_hint += tied[i];
            }
            fp.body_platform_hint += " (tied, score=" + std::to_string(best_score) + ")";
        }

        // --- Generator-tag spoof check ---------------------------------
        // Find the platform name meta_generator itself literally claims
        // (if any), independent of the scored winner above.
        std::string claimed;
        {
            std::string lgen = fp.meta_generator;
            for (char &c : lgen) c = (char)tolower((unsigned char)c);
            for (const std::string &platform : sigs.meta_hint_platforms) {
                std::string lp = platform;
                for (char &c : lp) c = (char)tolower((unsigned char)c);
                if (!lp.empty() && lgen.find(lp) != std::string::npos) { claimed = platform; break; }
            }
        }

        // Strongest structural (non-meta-tag) platform, independent of what
        // the generator tag says.
        std::string structural_top;
        int structural_top_score = 1; // same "> 1" confidence bar as the main winner
        for (const auto &[name, score] : structural_scores) {
            if (score > structural_top_score) { structural_top_score = score; structural_top = name; }
        }

        if (!claimed.empty() && !structural_top.empty()) {
            std::string lc = claimed, ls = structural_top;
            for (char &c : lc) c = (char)tolower((unsigned char)c);
            for (char &c : ls) c = (char)tolower((unsigned char)c);
            int claimed_structural_score = 0;
            for (const auto &[name, score] : structural_scores) {
                std::string ln = name;
                for (char &c : ln) c = (char)tolower((unsigned char)c);
                if (ln == lc) { claimed_structural_score = score; break; }
            }
            // Flag only a *confident, contradicted* claim: real independent
            // structural evidence (score >= 3, i.e. more than one corroborating
            // signal) for a platform other than the one the generator tag
            // names, while that claimed platform has little/no structural
            // backing of its own. This intentionally stays quiet on weak/
            // single-signal cases to avoid crying wolf on ordinary noise
            // (shared JS libraries, boilerplate comments, etc.).
            if (lc != ls && structural_top_score >= 3 && claimed_structural_score <= 1) {
                fp.tamper_hint = "meta:generator claims '" + claimed + "' but structural evidence "
                                  "(paths/JS/comments/body/headers) points to '" + structural_top +
                                  "' (structural score " + std::to_string(structural_top_score) +
                                  " vs " + std::to_string(claimed_structural_score) + " for " + claimed + ")";
            }
        }
    }
    if (!fp.is_redirect) fp.spa_locations = extract_spa_locations(body);
}

static std::vector<u8> dechunk_body(const u8 *body_ptr, size_t body_len)
{
    std::vector<u8> out;
    out.reserve(body_len); // final size <= encoded size

    size_t pos = 0;
    while (pos < body_len) {
        // ---- find end of the chunk-size line (terminated by \r\n) -------
        size_t line_end = pos;
        while (line_end + 1 < body_len &&
               !(body_ptr[line_end] == '\r' && body_ptr[line_end + 1] == '\n'))
            ++line_end;
        if (line_end + 1 >= body_len) break; // malformed / truncated

        // Chunk-size may have extensions after ';' (e.g. "1a3;foo=bar") —
        // only the hex digits before ';' matter.
        size_t size_str_len = line_end - pos;
        std::string size_field(reinterpret_cast<const char *>(body_ptr + pos), size_str_len);
        size_t semi = size_field.find(';');
        if (semi != std::string::npos) size_field.resize(semi);

        // Trim any stray whitespace
        while (!size_field.empty() && isspace((unsigned char)size_field.back()))
            size_field.pop_back();

        size_t chunk_size = 0;
        char *endptr = nullptr;
        chunk_size = std::strtoul(size_field.c_str(), &endptr, 16);
        if (endptr == size_field.c_str()) break; // not valid hex — malformed

        size_t data_start = line_end + 2; // skip the \r\n after the size line

        if (chunk_size == 0) break; // terminating chunk — trailer/final CRLF follows, ignore

        if (data_start + chunk_size > body_len) {
            // Truncated/incomplete final chunk (e.g. connection cut mid-read):
            // take what we have and stop rather than reading out of bounds.
            size_t avail = body_len - data_start;
            out.insert(out.end(), body_ptr + data_start, body_ptr + data_start + avail);
            break;
        }

        out.insert(out.end(), body_ptr + data_start, body_ptr + data_start + chunk_size);

        pos = data_start + chunk_size;
        // Skip the trailing \r\n that follows each chunk's data
        if (pos + 1 < body_len && body_ptr[pos] == '\r' && body_ptr[pos + 1] == '\n')
            pos += 2;
    }

    return out;
}

static std::vector<u8> decompress_body(const std::vector<u8> &resp)
{
    // ---- 1. Find header/body boundary ------------------------------------
    size_t hdr_end = 0;
    for (size_t i = 0; i + 3 < resp.size(); ++i) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            hdr_end = i + 4;
            break;
        }
    }
    if (hdr_end == 0) {
        // Try \n\n fallback
        for (size_t i = 0; i + 1 < resp.size(); ++i) {
            if (resp[i]=='\n' && resp[i+1]=='\n') { hdr_end = i + 2; break; }
        }
    }
    if (hdr_end == 0 || hdr_end >= resp.size()) return resp; // no body

    // ---- 2. Extract Content-Encoding value (lowercase) -------------------
    std::string ce = extract_header(resp, "Content-Encoding");

    // ---- 2a. Extract Transfer-Encoding and dechunk first if needed -------
    std::string te = extract_header(resp, "Transfer-Encoding");
    for (char &c : te) c = (char)tolower((unsigned char)c);

    const u8 *raw_body_ptr = resp.data() + hdr_end;
    size_t    raw_body_len = resp.size() - hdr_end;

    std::vector<u8> dechunked_storage; // keeps dechunked bytes alive if used
    const u8 *body_ptr = raw_body_ptr;
    size_t    body_len = raw_body_len;

    if (te.find("chunked") != std::string::npos) {
        dechunked_storage = dechunk_body(raw_body_ptr, raw_body_len);
        body_ptr = dechunked_storage.data();
        body_len = dechunked_storage.size();
    }

    if (ce.empty()) {
        // No Content-Encoding: if we dechunked, we still need to hand back
        // the dechunked plaintext body instead of the wire-framed original.
        if (te.find("chunked") != std::string::npos) {
            std::vector<u8> out;
            out.reserve(hdr_end + body_len);
            out.insert(out.end(), resp.begin(), resp.begin() + (std::ptrdiff_t)hdr_end);
            out.insert(out.end(), body_ptr, body_ptr + body_len);
            return out;
        }
        return resp; // nothing to do
    }

    // Lowercase for comparison
    for (char &c : ce) c = (char)tolower((unsigned char)c);

    std::vector<u8> decompressed;
    bool success = false;

    // ---- 3a. gzip / deflate via zlib ------------------------------------
    if (ce.find("gzip") != std::string::npos ||
        ce.find("deflate") != std::string::npos)
    {
        // zlib inflateInit2 with windowBits=47 auto-detects gzip vs raw deflate
        z_stream zs{};
        zs.next_in  = const_cast<Bytef *>(body_ptr);
        zs.avail_in = (uInt)body_len;
        int wbits = (ce.find("gzip") != std::string::npos) ? 15 + 16  // gzip
                                                            : 15 + 32; // auto
        if (inflateInit2(&zs, wbits) == Z_OK) {
            decompressed.resize(body_len * 4 > 65536 ? body_len * 4 : 65536);
            zs.next_out  = decompressed.data();
            zs.avail_out = (uInt)decompressed.size();
            int ret;
            do {
                if (zs.avail_out == 0) {
                    size_t old = decompressed.size();
                    decompressed.resize(old * 2);
                    zs.next_out  = decompressed.data() + old;
                    zs.avail_out = (uInt)old;
                }
                ret = inflate(&zs, Z_SYNC_FLUSH);
            } while (ret == Z_OK || ret == Z_BUF_ERROR);
            if (ret == Z_STREAM_END || ret == Z_OK || ret == Z_BUF_ERROR) {
                decompressed.resize(zs.total_out);
                success = !decompressed.empty();
            }
            inflateEnd(&zs);
        }
        if (!success) {
            // deflate: try raw inflate (no zlib header) as last resort
            z_stream zs2{};
            zs2.next_in  = const_cast<Bytef *>(body_ptr);
            zs2.avail_in = (uInt)body_len;
            if (inflateInit2(&zs2, -15) == Z_OK) {
                decompressed.resize(body_len * 4 > 65536 ? body_len * 4 : 65536);
                zs2.next_out  = decompressed.data();
                zs2.avail_out = (uInt)decompressed.size();
                int ret2;
                do {
                    if (zs2.avail_out == 0) {
                        size_t old = decompressed.size();
                        decompressed.resize(old * 2);
                        zs2.next_out  = decompressed.data() + old;
                        zs2.avail_out = (uInt)old;
                    }
                    ret2 = inflate(&zs2, Z_SYNC_FLUSH);
                } while (ret2 == Z_OK || ret2 == Z_BUF_ERROR);
                if (ret2 == Z_STREAM_END || ret2 == Z_OK) {
                    decompressed.resize(zs2.total_out);
                    success = !decompressed.empty();
                }
                inflateEnd(&zs2);
            }
        }
    }

    // ---- 3b. Brotli (br) ------------------------------------------------
#ifdef HAVE_BROTLI
    else if (ce.find("br") != std::string::npos)
    {
        size_t decoded_size = body_len * 6 > 131072 ? body_len * 6 : 131072;
        decompressed.resize(decoded_size);
        BrotliDecoderResult bret = BrotliDecoderDecompress(
            body_len, body_ptr,
            &decoded_size, decompressed.data());
        if (bret == BROTLI_DECODER_RESULT_SUCCESS) {
            decompressed.resize(decoded_size);
            success = !decompressed.empty();
        } else {
            // Buffer too small: try larger buffer (some br bodies are very sparse)
            decoded_size = body_len * 20 > 524288 ? body_len * 20 : 524288;
            decompressed.resize(decoded_size);
            bret = BrotliDecoderDecompress(
                body_len, body_ptr,
                &decoded_size, decompressed.data());
            if (bret == BROTLI_DECODER_RESULT_SUCCESS) {
                decompressed.resize(decoded_size);
                success = !decompressed.empty();
            }
        }
    }
#else
    else if (ce.find("br") != std::string::npos)
    {
        // Brotli not compiled in — return the (already dechunked) body unchanged.
        // Build with -DHAVE_BROTLI -lbrotlidec to enable.
        fprintf(stderr, "  [decompress] br encoding detected but Brotli not compiled in"
                        " — body will be undecompressed\n");
        std::vector<u8> out;
        out.reserve(hdr_end + body_len);
        out.insert(out.end(), resp.begin(), resp.begin() + (std::ptrdiff_t)hdr_end);
        out.insert(out.end(), body_ptr, body_ptr + body_len);
        return out;
    }
#endif

    // ---- 3c. Zstandard (zstd) -------------------------------------------
#ifdef HAVE_ZSTD
    else if (ce.find("zstd") != std::string::npos)
    {
        unsigned long long const frame_size =
            ZSTD_getFrameContentSize(body_ptr, body_len);
        size_t alloc = (frame_size != ZSTD_CONTENTSIZE_UNKNOWN &&
                        frame_size != ZSTD_CONTENTSIZE_ERROR)
                     ? (size_t)frame_size
                     : body_len * 8 > 131072 ? body_len * 8 : 131072;
        decompressed.resize(alloc);
        size_t zret = ZSTD_decompress(decompressed.data(), alloc,
                                      body_ptr, body_len);
        if (!ZSTD_isError(zret)) {
            decompressed.resize(zret);
            success = !decompressed.empty();
        } else {
            fprintf(stderr, "  [decompress] zstd error: %s\n",
                    ZSTD_getErrorName(zret));
        }
    }
#else
    else if (ce.find("zstd") != std::string::npos)
    {
        fprintf(stderr, "  [decompress] zstd encoding detected but libzstd not compiled in"
                        " — body will be undecompressed\n");
        std::vector<u8> out;
        out.reserve(hdr_end + body_len);
        out.insert(out.end(), resp.begin(), resp.begin() + (std::ptrdiff_t)hdr_end);
        out.insert(out.end(), body_ptr, body_ptr + body_len);
        return out;
    }
#endif

    // ---- 4. Reassemble response: headers + decompressed body -------------
    if (!success || decompressed.empty()) {
        // Compression failed (or unrecognized ce) — still return the
        // dechunked-but-not-decompressed body rather than the raw wire
        // bytes, so downstream code never sees leftover chunk framing.
        std::vector<u8> out;
        out.reserve(hdr_end + body_len);
        out.insert(out.end(), resp.begin(), resp.begin() + (std::ptrdiff_t)hdr_end);
        out.insert(out.end(), body_ptr, body_ptr + body_len);
        return out;
    }

    std::vector<u8> out;
    out.reserve(hdr_end + decompressed.size());
    // Copy headers verbatim
    out.insert(out.end(), resp.begin(), resp.begin() + (std::ptrdiff_t)hdr_end);
    // Append decompressed body
    out.insert(out.end(), decompressed.begin(), decompressed.end());
    return out;
}

/* Populate an HttpFingerprint from a raw response buffer */
static HttpFingerprint make_http_fingerprint(const std::vector<u8> &resp,
                                             const std::string     &phase,
                                             bool                   is_ssl,
                                             const TlsCertInfo     &cert_info = TlsCertInfo{})
{

    const std::vector<u8> decompressed_buf = decompress_body(resp);
    const std::vector<u8> &effective       = decompressed_buf;

    HttpFingerprint fp;
    fp.phase       = phase;
    fp.is_ssl      = is_ssl;
    fp.status_code = extract_status_code(effective);
    fp.status_line = extract_status_line(effective);
    fp.server      = extract_header(effective, "Server");
    fp.osd_name    = extract_header(effective, "osd-name");
    fp.powered_by  = extract_header(effective, "X-Powered-By");
    fp.title       = extract_title(effective);
    fp.via         = extract_header(effective, "Via");
    fp.x_generator = extract_header(effective, "X-Generator");
    fp.location    = extract_header(effective, "Location");
    fp.raw_headers = collect_all_headers(effective, &fp.duplicate_headers);

    // ---- CDN / Cache / Proxy infrastructure headers ----
    fp.x_amz_cf_pop              = extract_header(effective, "X-Amz-Cf-Pop");
    fp.x_amz_cf_id               = extract_header(effective, "X-Amz-Cf-Id");
    fp.x_cache                   = extract_header(effective, "X-Cache");
    fp.cf_ray                    = extract_header(effective, "CF-Ray");
    fp.cf_cache_status           = extract_header(effective, "CF-Cache-Status");
    fp.x_served_by               = extract_header(effective, "X-Served-By");
    fp.x_cache_hits              = extract_header(effective, "X-Cache-Hits");
    fp.x_cache_lookup            = extract_header(effective, "X-Cache-Lookup");
    fp.akamai_cache_key          = extract_header(effective, "Akamai-X-Get-Cache-Key");
    fp.x_amz_request_id          = extract_header(effective, "X-Amz-Request-Id");
    fp.x_amz_id_2                = extract_header(effective, "X-Amz-Id-2");
    fp.x_amz_version_id          = extract_header(effective, "x-amz-version-id");
    fp.x_amz_sse                 = extract_header(effective, "X-Amz-Server-Side-Encryption");
    fp.x_amz_bucket_region       = extract_header(effective, "X-Amz-Bucket-Region");
    fp.x_amzn_request_id         = extract_header(effective, "X-Amzn-RequestId");
    fp.x_amzn_error_type         = extract_header(effective, "X-Amzn-Error-Type");
    fp.x_via                     = extract_header(effective, "X-Via");
    fp.x_forwarded_for           = extract_header(effective, "X-Forwarded-For");
    fp.x_forwarded_proto         = extract_header(effective, "X-Forwarded-Proto");
    fp.x_real_ip                 = extract_header(effective, "X-Real-IP");
    fp.x_haproxy_server_state    = extract_header(effective, "X-Haproxy-Server-State");
    fp.x_varnish                 = extract_header(effective, "X-Varnish");
    fp.x_cacheable               = extract_header(effective, "X-Cacheable");
    fp.x_cache_status            = extract_header(effective, "X-Cache-Status");
    fp.x_cache_expiry            = extract_header(effective, "X-Cache-Expiry");
    fp.age                       = extract_header(effective, "Age");
    fp.x_drupal_cache            = extract_header(effective, "X-Drupal-Cache");
    fp.x_drupal_dynamic_cache    = extract_header(effective, "X-Drupal-Dynamic-Cache");
    fp.x_magento_cache_debug     = extract_header(effective, "X-Magento-Cache-Debug");
    fp.x_wordpress_cache         = extract_header(effective, "X-WordPress-Cache");
    fp.x_prestashop_cache        = extract_header(effective, "X-Prestashop-Cache");
    // ---- Security ----
    fp.www_authenticate          = extract_header(effective, "WWW-Authenticate");
    fp.x_content_type_options    = extract_header(effective, "X-Content-Type-Options");
    fp.strict_transport_security = extract_header(effective, "Strict-Transport-Security");
    fp.report_to_group           = extract_report_to_group(effective);
    fp.coop_report_to_group      = extract_coop_report_to(effective);
    // ---- APM / Tracing ----
    fp.x_newrelic_app_data       = extract_header(effective, "X-NewRelic-App-Data");
    fp.x_request_id              = extract_header(effective, "X-Request-Id");
    fp.server_timing             = extract_header(effective, "Server-Timing");
    fp.x_cloud_trace_context     = extract_header(effective, "X-Cloud-Trace-Context");
    // ---- CDN vendor specifics ----
    fp.x_cdn                     = extract_header(effective, "X-CDN");
    fp.x_edge_location           = extract_header(effective, "X-Edge-Location");
    fp.x_edge_connect            = extract_header(effective, "X-Edge-Connect");
    fp.x_edgeconnect_config      = extract_header(effective, "X-EdgeConnect-Config");
    fp.x_edgeconnect_method      = extract_header(effective, "X-EdgeConnect-Method");
    fp.x_cache_key               = extract_header(effective, "X-Cache-Key");
    fp.x_timer                   = extract_header(effective, "X-Timer");
    fp.x_host                    = extract_header(effective, "X-Host");
    fp.x_backend                 = extract_header(effective, "X-Backend");
    fp.x_backend_server          = extract_header(effective, "X-Backend-Server");
    fp.x_orig_cache              = extract_header(effective, "X-Orig-Cache");
    fp.x_proxy_cache             = extract_header(effective, "X-Proxy-Cache");
    // ---- AWS extended ----
    fp.x_amz_storage_class       = extract_header(effective, "X-Amz-Storage-Class");
    fp.x_amz_delete_marker       = extract_header(effective, "X-Amz-Delete-Marker");
    fp.x_amz_expiration          = extract_header(effective, "X-Amz-Expiration");
    fp.x_amz_replication_status  = extract_header(effective, "X-Amz-Replication-Status");
    fp.x_amz_request_charged     = extract_header(effective, "X-Amz-Request-Charged");
    // ---- GCP / GCS ----
    fp.x_google_cache_control    = extract_header(effective, "X-Google-Cache-Control");
    fp.x_google_cache_hit        = extract_header(effective, "X-Google-Cache-Hit");
    fp.x_google_load_balancer    = extract_header(effective, "X-Google-Load-Balancer");
    fp.x_google_backend          = extract_header(effective, "X-Google-Backend");
    fp.x_google_appengine_app    = extract_header(effective, "X-Google-AppEngine-App");
    fp.x_google_appengine_country= extract_header(effective, "X-Google-AppEngine-Country");
    fp.x_guploader               = extract_header(effective, "X-GUploader");
    fp.x_gcs_bucket              = extract_header(effective, "X-GCS-Bucket");
    fp.x_gcs_object_generation   = extract_header(effective, "X-GCS-Object-Generation");
    // ---- Azure / MS Edge ----
    fp.x_ms_edge_ref             = extract_header(effective, "X-MS-Edge-Ref");
    fp.x_ms_request_id           = extract_header(effective, "X-MS-RequestId");
    fp.x_ms_client_request_id    = extract_header(effective, "X-MS-Client-RequestId");
    fp.x_ms_correlation_request_id = extract_header(effective, "X-MS-Correlation-RequestId");
    fp.x_azure_ref               = extract_header(effective, "X-Azure-Ref");
    fp.x_azure_request_id        = extract_header(effective, "X-Azure-RequestId");
    fp.x_msedge_ref              = extract_header(effective, "X-MSEdge-Ref");
    // ---- Load balancer ----
    fp.x_lb_node                 = extract_header(effective, "X-LB-Node");
    fp.x_lb_tag                  = extract_header(effective, "X-LB-Tag");
    fp.x_lb_instance             = extract_header(effective, "X-LB-Instance");
    fp.x_lb_server               = extract_header(effective, "X-LB-Server");
    fp.x_lb_backend              = extract_header(effective, "X-LB-Backend");
    fp.x_proxy_id                = extract_header(effective, "X-Proxy-Id");
    fp.x_proxy_server            = extract_header(effective, "X-Proxy-Server");
    fp.x_proxy_backend           = extract_header(effective, "X-Proxy-Backend");
    fp.x_haproxy_node            = extract_header(effective, "X-HAProxy-Node");
    fp.x_haproxy_backend         = extract_header(effective, "X-HAProxy-Backend");
    fp.x_haproxy_config          = extract_header(effective, "X-HAProxy-Config");
    // ---- Nginx / Varnish / Squid ----
    fp.x_nginx_cache_status      = extract_header(effective, "X-Nginx-Cache-Status");
    fp.x_nginx_proxy             = extract_header(effective, "X-Nginx-Proxy");
    fp.x_cache_id                = extract_header(effective, "X-Cache-Id");
    fp.x_cache_ttl               = extract_header(effective, "X-Cache-TTL");
    fp.x_cache_time              = extract_header(effective, "X-Cache-Time");
    fp.x_cache_request           = extract_header(effective, "X-Cache-Request");
    fp.x_cache_response          = extract_header(effective, "X-Cache-Response");
    fp.x_cache_info              = extract_header(effective, "X-Cache-Info");
    fp.x_squid_error             = extract_header(effective, "X-Squid-Error");
    fp.x_squid_request_id        = extract_header(effective, "X-Squid-Request-Id");
    fp.x_varnish_cache           = extract_header(effective, "X-Varnish-Cache");
    fp.x_varnish_age             = extract_header(effective, "X-Varnish-Age");
    fp.x_varnish_backend         = extract_header(effective, "X-Varnish-Backend");
    fp.x_varnish_session         = extract_header(effective, "X-Varnish-Session");
    fp.x_varnish_hit             = extract_header(effective, "X-Varnish-Hit");
    fp.x_varnish_ttl             = extract_header(effective, "X-Varnish-TTL");
    // ---- Auth ----
    fp.x_auth_token              = extract_header(effective, "X-Auth-Token");
    fp.x_auth_request_redirect   = extract_header(effective, "X-Auth-Request-Redirect");
    fp.x_auth_request_url        = extract_header(effective, "X-Auth-Request-URL");
    fp.x_auth_user               = extract_header(effective, "X-Auth-User");
    fp.x_auth_user_groups        = extract_header(effective, "X-Auth-User-Groups");
    fp.x_auth_service            = extract_header(effective, "X-Auth-Service");
    fp.x_csrf_token              = extract_header(effective, "X-CSRF-Token");
    fp.x_csrf_param              = extract_header(effective, "X-CSRF-Param");
    fp.x_csrf_header             = extract_header(effective, "X-CSRF-Header");
    // ---- Debug / CMS ----
    fp.x_debug                   = extract_header(effective, "X-Debug");
    fp.x_debug_token             = extract_header(effective, "X-Debug-Token");
    fp.x_debug_token_link        = extract_header(effective, "X-Debug-Token-Link");
    fp.x_drupal_route            = extract_header(effective, "X-Drupal-Route");
    fp.x_drupal_ajax_token       = extract_header(effective, "X-Drupal-Ajax-Token");
    fp.x_wordpress_theme         = extract_header(effective, "X-WordPress-Theme");
    fp.x_wordpress_plugin        = extract_header(effective, "X-WordPress-Plugin");
    fp.x_magento_store           = extract_header(effective, "X-Magento-Store");
    fp.x_magento_theme           = extract_header(effective, "X-Magento-Theme");
    fp.x_magento_layout          = extract_header(effective, "X-Magento-Layout");
    fp.x_prestashop_store        = extract_header(effective, "X-Prestashop-Store");
    fp.x_prestashop_theme        = extract_header(effective, "X-Prestashop-Theme");
    // ---- Timing / Rate limiting ----
    fp.x_response_time           = extract_header(effective, "X-Response-Time");
    fp.x_execution_time          = extract_header(effective, "X-Execution-Time");
    fp.x_process_time            = extract_header(effective, "X-Process-Time");
    fp.x_generator_duration      = extract_header(effective, "X-Generator-Duration");
    fp.x_powered_by_duration     = extract_header(effective, "X-Powered-By-Duration");
    fp.x_ratelimit_limit         = extract_header(effective, "X-RateLimit-Limit");
    fp.x_ratelimit_remaining     = extract_header(effective, "X-RateLimit-Remaining");
    fp.x_ratelimit_reset         = extract_header(effective, "X-RateLimit-Reset");
    fp.x_ratelimit_retry_after   = extract_header(effective, "X-RateLimit-Retry-After");
    fp.x_ratelimit_resource      = extract_header(effective, "X-RateLimit-Resource");
    // ---- Misc ----
    fp.x_mailer                  = extract_header(effective, "X-Mailer");
    fp.x_php_script              = extract_header(effective, "X-PHP-Script");
    fp.x_php_origin              = extract_header(effective, "X-PHP-Origin");
    fp.x_object_version          = extract_header(effective, "X-Object-Version");
    fp.x_object_delete_marker    = extract_header(effective, "X-Object-Delete-Marker");
    fp.x_object_expiry           = extract_header(effective, "X-Object-Expiry");
    fp.x_object_storage_class    = extract_header(effective, "X-Object-Storage-Class");
    fp.x_bucket_location         = extract_header(effective, "X-Bucket-Location");
    fp.x_bucket_versioning       = extract_header(effective, "X-Bucket-Versioning");
    // ---- CI/CD / DevOps identity headers ----
    fp.x_jenkins                 = extract_header(effective, "X-Jenkins");
    fp.x_hudson                  = extract_header(effective, "X-Hudson");
    fp.x_teamcity_node_id        = extract_header(effective, "X-TeamCity-Node-Id");
    fp.x_gitlab_meta             = extract_header(effective, "X-Gitlab-Meta");
    fp.x_harness_account         = extract_header(effective, "x-harness-account");
    fp.is_redirect = (fp.status_code >= 300 && fp.status_code < 400);
    fp.is_4xx      = (fp.status_code >= 400 && fp.status_code < 500);
    fp.tls_cert    = cert_info;

    // Build printable snippet (first 200 chars of response)
    size_t snip = std::min(effective.size(), (size_t)200);
    for (size_t i = 0; i < snip; ++i) {
        unsigned char c = effective[i];
        fp.raw_snippet += (c >= 32 && c < 127) ? (char)c : '.';
    }

    // ---- HTML body signals (meta tags, comments, links, JS globals) ----
    extract_html_body_signals(effective, fp);

    return fp;
}


static HttpFingerprint merge_http_fingerprints(
    const std::vector<HttpFingerprint> &fps)
{
    if (fps.empty()) return {};
    if (fps.size() == 1) return fps[0];   // nothing to merge
    auto merge_field = [](const std::vector<HttpFingerprint> &src,
                          std::string HttpFingerprint::*field) -> std::string {
        std::vector<std::string> seen_lc;   // lowercase copies for dedup
        std::vector<std::string> ordered;   // original-case, insertion order

        for (const auto &fp : src) {
            const std::string &val = fp.*field;
            if (val.empty()) continue;

            // Normalise: collapse whitespace, trim
            std::string clean;
            clean.reserve(val.size());
            bool ws = false;
            for (unsigned char c : val) {
                if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
                    if (!ws) { clean += ' '; ws = true; }
                } else { clean += (char)c; ws = false; }
            }
            while (!clean.empty() && clean.front() == ' ') clean.erase(clean.begin());
            while (!clean.empty() && clean.back()  == ' ') clean.pop_back();
            if (clean.empty()) continue;

            std::string lc = clean;
            for (char &c : lc) c = (char)tolower((unsigned char)c);
            bool dup = false;
            for (const auto &s : seen_lc) if (s == lc) { dup = true; break; }
            if (!dup) { seen_lc.push_back(lc); ordered.push_back(clean); }
        }

        if (ordered.empty()) return "";
        std::string result = ordered[0];
        for (size_t i = 1; i < ordered.size(); ++i) result += " | " + ordered[i];
        return result;
    };

    // Helper for vector<string> fields: union of all unique entries
    auto merge_vec = [](const std::vector<HttpFingerprint> &src,
                        std::vector<std::string> HttpFingerprint::*field)
        -> std::vector<std::string>
    {
        std::vector<std::string> result;
        for (const auto &fp : src) {
            for (const auto &v : fp.*field) {
                bool dup = false;
                std::string lv = v;
                for (char &c : lv) c = (char)tolower((unsigned char)c);
                for (const auto &r : result) {
                    std::string lr = r;
                    for (char &c : lr) c = (char)tolower((unsigned char)c);
                    if (lr == lv) { dup = true; break; }
                }
                if (!dup) result.push_back(v);
            }
        }
        return result;
    };

    HttpFingerprint merged;
    merged.phase = "merged";

    // Merge all simple string fields
    merged.server         = merge_field(fps, &HttpFingerprint::server);
    merged.osd_name       = merge_field(fps, &HttpFingerprint::osd_name);
    merged.powered_by     = merge_field(fps, &HttpFingerprint::powered_by);

    {
        auto is_redirect_title = [](const std::string &t) -> bool {
            if (t.size() < 13) return false;
            // lower-case compare of first 13 chars against "redirecting to"
            // (we check both 13-char prefix "redirecting t" and full "redirecting to ")
            static const char kRedirPrefix[] = "redirecting to";
            for (size_t i = 0; i < sizeof(kRedirPrefix) - 1 && i < t.size(); ++i) {
                if ((char)tolower((unsigned char)t[i]) != kRedirPrefix[i])
                    return false;
            }
            return true;
        };

        std::string best_title;
        std::string last_any_title;
        for (const auto &fp : fps) {
            if (fp.title.empty()) continue;
            last_any_title = fp.title;
            if (!is_redirect_title(fp.title))
                best_title = fp.title;   // keep updating — we want the LAST such title
        }
        merged.title = best_title.empty() ? last_any_title : best_title;
    }
    merged.via            = merge_field(fps, &HttpFingerprint::via);
    merged.x_generator    = merge_field(fps, &HttpFingerprint::x_generator);
    // Location / redirect_url: keep from last hop that had one
    for (const auto &fp : fps) {
        if (!fp.location.empty())     merged.location     = fp.location;
        if (!fp.redirect_url.empty()) merged.redirect_url = fp.redirect_url;
    }
    merged.x_amz_cf_pop              = merge_field(fps, &HttpFingerprint::x_amz_cf_pop);
    merged.x_amz_cf_id               = merge_field(fps, &HttpFingerprint::x_amz_cf_id);
    merged.x_cache                   = merge_field(fps, &HttpFingerprint::x_cache);
    merged.cf_ray                    = merge_field(fps, &HttpFingerprint::cf_ray);
    merged.cf_cache_status           = merge_field(fps, &HttpFingerprint::cf_cache_status);
    merged.x_served_by               = merge_field(fps, &HttpFingerprint::x_served_by);
    merged.x_cache_hits              = merge_field(fps, &HttpFingerprint::x_cache_hits);
    merged.x_cache_lookup            = merge_field(fps, &HttpFingerprint::x_cache_lookup);
    merged.akamai_cache_key          = merge_field(fps, &HttpFingerprint::akamai_cache_key);
    merged.x_amz_request_id         = merge_field(fps, &HttpFingerprint::x_amz_request_id);
    merged.x_amz_id_2                = merge_field(fps, &HttpFingerprint::x_amz_id_2);
    merged.x_amz_version_id         = merge_field(fps, &HttpFingerprint::x_amz_version_id);
    merged.x_amz_sse                 = merge_field(fps, &HttpFingerprint::x_amz_sse);
    merged.x_amz_bucket_region       = merge_field(fps, &HttpFingerprint::x_amz_bucket_region);
    merged.x_amzn_request_id        = merge_field(fps, &HttpFingerprint::x_amzn_request_id);
    merged.x_amzn_error_type        = merge_field(fps, &HttpFingerprint::x_amzn_error_type);
    merged.x_via                     = merge_field(fps, &HttpFingerprint::x_via);
    merged.x_forwarded_for           = merge_field(fps, &HttpFingerprint::x_forwarded_for);
    merged.x_forwarded_proto         = merge_field(fps, &HttpFingerprint::x_forwarded_proto);
    merged.x_real_ip                 = merge_field(fps, &HttpFingerprint::x_real_ip);
    merged.x_haproxy_server_state    = merge_field(fps, &HttpFingerprint::x_haproxy_server_state);
    merged.x_varnish                 = merge_field(fps, &HttpFingerprint::x_varnish);
    merged.x_cacheable               = merge_field(fps, &HttpFingerprint::x_cacheable);
    merged.x_cache_status            = merge_field(fps, &HttpFingerprint::x_cache_status);
    merged.x_cache_expiry            = merge_field(fps, &HttpFingerprint::x_cache_expiry);
    merged.age                       = merge_field(fps, &HttpFingerprint::age);
    merged.x_drupal_cache            = merge_field(fps, &HttpFingerprint::x_drupal_cache);
    merged.x_drupal_dynamic_cache    = merge_field(fps, &HttpFingerprint::x_drupal_dynamic_cache);
    merged.x_magento_cache_debug     = merge_field(fps, &HttpFingerprint::x_magento_cache_debug);
    merged.x_wordpress_cache         = merge_field(fps, &HttpFingerprint::x_wordpress_cache);
    merged.x_prestashop_cache        = merge_field(fps, &HttpFingerprint::x_prestashop_cache);
    merged.www_authenticate          = merge_field(fps, &HttpFingerprint::www_authenticate);
    merged.x_content_type_options    = merge_field(fps, &HttpFingerprint::x_content_type_options);
    merged.strict_transport_security = merge_field(fps, &HttpFingerprint::strict_transport_security);
    merged.report_to_group           = merge_field(fps, &HttpFingerprint::report_to_group);
    merged.coop_report_to_group      = merge_field(fps, &HttpFingerprint::coop_report_to_group);
    merged.x_newrelic_app_data       = merge_field(fps, &HttpFingerprint::x_newrelic_app_data);
    merged.x_request_id              = merge_field(fps, &HttpFingerprint::x_request_id);
    merged.server_timing             = merge_field(fps, &HttpFingerprint::server_timing);
    merged.x_cloud_trace_context     = merge_field(fps, &HttpFingerprint::x_cloud_trace_context);
    merged.x_cdn                     = merge_field(fps, &HttpFingerprint::x_cdn);
    merged.x_edge_location           = merge_field(fps, &HttpFingerprint::x_edge_location);
    merged.x_edge_connect            = merge_field(fps, &HttpFingerprint::x_edge_connect);
    merged.x_edgeconnect_config      = merge_field(fps, &HttpFingerprint::x_edgeconnect_config);
    merged.x_edgeconnect_method      = merge_field(fps, &HttpFingerprint::x_edgeconnect_method);
    merged.x_cache_key               = merge_field(fps, &HttpFingerprint::x_cache_key);
    merged.x_timer                   = merge_field(fps, &HttpFingerprint::x_timer);
    merged.x_host                    = merge_field(fps, &HttpFingerprint::x_host);
    merged.x_backend                 = merge_field(fps, &HttpFingerprint::x_backend);
    merged.x_backend_server         = merge_field(fps, &HttpFingerprint::x_backend_server);
    merged.x_orig_cache              = merge_field(fps, &HttpFingerprint::x_orig_cache);
    merged.x_proxy_cache             = merge_field(fps, &HttpFingerprint::x_proxy_cache);
    merged.x_amz_storage_class       = merge_field(fps, &HttpFingerprint::x_amz_storage_class);
    merged.x_amz_delete_marker       = merge_field(fps, &HttpFingerprint::x_amz_delete_marker);
    merged.x_amz_expiration          = merge_field(fps, &HttpFingerprint::x_amz_expiration);
    merged.x_amz_replication_status  = merge_field(fps, &HttpFingerprint::x_amz_replication_status);
    merged.x_amz_request_charged    = merge_field(fps, &HttpFingerprint::x_amz_request_charged);
    merged.x_google_cache_control    = merge_field(fps, &HttpFingerprint::x_google_cache_control);
    merged.x_google_cache_hit        = merge_field(fps, &HttpFingerprint::x_google_cache_hit);
    merged.x_google_load_balancer    = merge_field(fps, &HttpFingerprint::x_google_load_balancer);
    merged.x_google_backend          = merge_field(fps, &HttpFingerprint::x_google_backend);
    merged.x_google_appengine_app    = merge_field(fps, &HttpFingerprint::x_google_appengine_app);
    merged.x_google_appengine_country= merge_field(fps, &HttpFingerprint::x_google_appengine_country);
    merged.x_guploader               = merge_field(fps, &HttpFingerprint::x_guploader);
    merged.x_gcs_bucket              = merge_field(fps, &HttpFingerprint::x_gcs_bucket);
    merged.x_gcs_object_generation   = merge_field(fps, &HttpFingerprint::x_gcs_object_generation);
    merged.x_ms_edge_ref             = merge_field(fps, &HttpFingerprint::x_ms_edge_ref);
    merged.x_ms_request_id           = merge_field(fps, &HttpFingerprint::x_ms_request_id);
    merged.x_ms_client_request_id    = merge_field(fps, &HttpFingerprint::x_ms_client_request_id);
    merged.x_ms_correlation_request_id = merge_field(fps, &HttpFingerprint::x_ms_correlation_request_id);
    merged.x_azure_ref               = merge_field(fps, &HttpFingerprint::x_azure_ref);
    merged.x_azure_request_id        = merge_field(fps, &HttpFingerprint::x_azure_request_id);
    merged.x_msedge_ref              = merge_field(fps, &HttpFingerprint::x_msedge_ref);
    merged.x_lb_node                 = merge_field(fps, &HttpFingerprint::x_lb_node);
    merged.x_lb_tag                  = merge_field(fps, &HttpFingerprint::x_lb_tag);
    merged.x_lb_instance             = merge_field(fps, &HttpFingerprint::x_lb_instance);
    merged.x_lb_server               = merge_field(fps, &HttpFingerprint::x_lb_server);
    merged.x_lb_backend              = merge_field(fps, &HttpFingerprint::x_lb_backend);
    merged.x_proxy_id                = merge_field(fps, &HttpFingerprint::x_proxy_id);
    merged.x_proxy_server            = merge_field(fps, &HttpFingerprint::x_proxy_server);
    merged.x_proxy_backend           = merge_field(fps, &HttpFingerprint::x_proxy_backend);
    merged.x_haproxy_node            = merge_field(fps, &HttpFingerprint::x_haproxy_node);
    merged.x_haproxy_backend         = merge_field(fps, &HttpFingerprint::x_haproxy_backend);
    merged.x_haproxy_config          = merge_field(fps, &HttpFingerprint::x_haproxy_config);
    merged.x_nginx_cache_status      = merge_field(fps, &HttpFingerprint::x_nginx_cache_status);
    merged.x_nginx_proxy             = merge_field(fps, &HttpFingerprint::x_nginx_proxy);
    merged.x_cache_id                = merge_field(fps, &HttpFingerprint::x_cache_id);
    merged.x_cache_ttl               = merge_field(fps, &HttpFingerprint::x_cache_ttl);
    merged.x_cache_time              = merge_field(fps, &HttpFingerprint::x_cache_time);
    merged.x_cache_request           = merge_field(fps, &HttpFingerprint::x_cache_request);
    merged.x_cache_response          = merge_field(fps, &HttpFingerprint::x_cache_response);
    merged.x_cache_info              = merge_field(fps, &HttpFingerprint::x_cache_info);
    merged.x_squid_error             = merge_field(fps, &HttpFingerprint::x_squid_error);
    merged.x_squid_request_id        = merge_field(fps, &HttpFingerprint::x_squid_request_id);
    merged.x_varnish_cache           = merge_field(fps, &HttpFingerprint::x_varnish_cache);
    merged.x_varnish_age             = merge_field(fps, &HttpFingerprint::x_varnish_age);
    merged.x_varnish_backend         = merge_field(fps, &HttpFingerprint::x_varnish_backend);
    merged.x_varnish_session         = merge_field(fps, &HttpFingerprint::x_varnish_session);
    merged.x_varnish_hit             = merge_field(fps, &HttpFingerprint::x_varnish_hit);
    merged.x_varnish_ttl             = merge_field(fps, &HttpFingerprint::x_varnish_ttl);
    merged.x_auth_token              = merge_field(fps, &HttpFingerprint::x_auth_token);
    merged.x_auth_request_redirect   = merge_field(fps, &HttpFingerprint::x_auth_request_redirect);
    merged.x_auth_request_url        = merge_field(fps, &HttpFingerprint::x_auth_request_url);
    merged.x_auth_user               = merge_field(fps, &HttpFingerprint::x_auth_user);
    merged.x_auth_user_groups        = merge_field(fps, &HttpFingerprint::x_auth_user_groups);
    merged.x_auth_service            = merge_field(fps, &HttpFingerprint::x_auth_service);
    merged.x_csrf_token              = merge_field(fps, &HttpFingerprint::x_csrf_token);
    merged.x_csrf_param              = merge_field(fps, &HttpFingerprint::x_csrf_param);
    merged.x_csrf_header             = merge_field(fps, &HttpFingerprint::x_csrf_header);
    merged.x_debug                   = merge_field(fps, &HttpFingerprint::x_debug);
    merged.x_debug_token             = merge_field(fps, &HttpFingerprint::x_debug_token);
    merged.x_debug_token_link        = merge_field(fps, &HttpFingerprint::x_debug_token_link);
    merged.x_drupal_route            = merge_field(fps, &HttpFingerprint::x_drupal_route);
    merged.x_drupal_ajax_token       = merge_field(fps, &HttpFingerprint::x_drupal_ajax_token);
    merged.x_wordpress_theme         = merge_field(fps, &HttpFingerprint::x_wordpress_theme);
    merged.x_wordpress_plugin        = merge_field(fps, &HttpFingerprint::x_wordpress_plugin);
    merged.x_magento_store           = merge_field(fps, &HttpFingerprint::x_magento_store);
    merged.x_magento_theme           = merge_field(fps, &HttpFingerprint::x_magento_theme);
    merged.x_magento_layout          = merge_field(fps, &HttpFingerprint::x_magento_layout);
    merged.x_prestashop_store        = merge_field(fps, &HttpFingerprint::x_prestashop_store);
    merged.x_prestashop_theme        = merge_field(fps, &HttpFingerprint::x_prestashop_theme);
    merged.x_response_time           = merge_field(fps, &HttpFingerprint::x_response_time);
    merged.x_execution_time          = merge_field(fps, &HttpFingerprint::x_execution_time);
    merged.x_process_time            = merge_field(fps, &HttpFingerprint::x_process_time);
    merged.x_generator_duration      = merge_field(fps, &HttpFingerprint::x_generator_duration);
    merged.x_powered_by_duration     = merge_field(fps, &HttpFingerprint::x_powered_by_duration);
    merged.x_ratelimit_limit         = merge_field(fps, &HttpFingerprint::x_ratelimit_limit);
    merged.x_ratelimit_remaining     = merge_field(fps, &HttpFingerprint::x_ratelimit_remaining);
    merged.x_ratelimit_reset         = merge_field(fps, &HttpFingerprint::x_ratelimit_reset);
    merged.x_ratelimit_retry_after   = merge_field(fps, &HttpFingerprint::x_ratelimit_retry_after);
    merged.x_ratelimit_resource      = merge_field(fps, &HttpFingerprint::x_ratelimit_resource);
    merged.x_mailer                  = merge_field(fps, &HttpFingerprint::x_mailer);
    merged.x_php_script              = merge_field(fps, &HttpFingerprint::x_php_script);
    merged.x_php_origin              = merge_field(fps, &HttpFingerprint::x_php_origin);
    merged.x_object_version         = merge_field(fps, &HttpFingerprint::x_object_version);
    merged.x_object_delete_marker    = merge_field(fps, &HttpFingerprint::x_object_delete_marker);
    merged.x_object_expiry           = merge_field(fps, &HttpFingerprint::x_object_expiry);
    merged.x_object_storage_class    = merge_field(fps, &HttpFingerprint::x_object_storage_class);
    merged.x_bucket_location         = merge_field(fps, &HttpFingerprint::x_bucket_location);
    merged.x_bucket_versioning       = merge_field(fps, &HttpFingerprint::x_bucket_versioning);
    // CI/CD
    merged.x_jenkins                 = merge_field(fps, &HttpFingerprint::x_jenkins);
    merged.x_hudson                  = merge_field(fps, &HttpFingerprint::x_hudson);
    merged.x_teamcity_node_id        = merge_field(fps, &HttpFingerprint::x_teamcity_node_id);
    merged.x_gitlab_meta             = merge_field(fps, &HttpFingerprint::x_gitlab_meta);
    merged.x_harness_account         = merge_field(fps, &HttpFingerprint::x_harness_account);
    // Meta tags
    merged.meta_generator            = merge_field(fps, &HttpFingerprint::meta_generator);
    merged.meta_software             = merge_field(fps, &HttpFingerprint::meta_software);
    merged.meta_author               = merge_field(fps, &HttpFingerprint::meta_author);
    merged.meta_developer            = merge_field(fps, &HttpFingerprint::meta_developer);
    merged.meta_framework            = merge_field(fps, &HttpFingerprint::meta_framework);
    merged.meta_cms                  = merge_field(fps, &HttpFingerprint::meta_cms);
    merged.meta_powered_by           = merge_field(fps, &HttpFingerprint::meta_powered_by);
    merged.meta_built_with           = merge_field(fps, &HttpFingerprint::meta_built_with);
    merged.meta_created_by           = merge_field(fps, &HttpFingerprint::meta_created_by);
    merged.meta_application_name     = merge_field(fps, &HttpFingerprint::meta_application_name);
    merged.meta_progid               = merge_field(fps, &HttpFingerprint::meta_progid);
    merged.meta_msapplication_config = merge_field(fps, &HttpFingerprint::meta_msapplication_config);
    merged.meta_msapplication_tile_image  = merge_field(fps, &HttpFingerprint::meta_msapplication_tile_image);
    merged.meta_msapplication_tile_color  = merge_field(fps, &HttpFingerprint::meta_msapplication_tile_color);
    merged.meta_apple_title          = merge_field(fps, &HttpFingerprint::meta_apple_title);
    merged.meta_apple_capable        = merge_field(fps, &HttpFingerprint::meta_apple_capable);
    merged.body_platform_hint        = merge_field(fps, &HttpFingerprint::body_platform_hint);
    merged.duplicate_headers         = merge_vec(fps, &HttpFingerprint::duplicate_headers);
    merged.tamper_hint               = merge_field(fps, &HttpFingerprint::tamper_hint);

    // Vector fields: union
    merged.html_comments       = merge_vec(fps, &HttpFingerprint::html_comments);
    merged.link_platform_paths = merge_vec(fps, &HttpFingerprint::link_platform_paths);
    merged.js_globals          = merge_vec(fps, &HttpFingerprint::js_globals);
    merged.spa_locations       = merge_vec(fps, &HttpFingerprint::spa_locations);

    // SSL / cert: take from first SSL hop
    merged.is_ssl = false;
    for (const auto &fp : fps) {
        if (fp.is_ssl) {
            merged.is_ssl = true;
            if (!merged.tls_cert.populated && fp.tls_cert.populated)
                merged.tls_cert = fp.tls_cert;
        }
    }

    // Status: keep from the final (last) fingerprint
    merged.status_code = fps.back().status_code;
    merged.status_line = fps.back().status_line;
    merged.is_redirect = fps.back().is_redirect;
    merged.is_4xx      = fps.back().is_4xx;

    return merged;
}

// ============================================================================
// Version-line renderer
//
// Output model: up to kMaxSlots (10) "info" entries are shown per port,
// joined by " | ". Slot 1 is always the primary identity (product+version
// merged from the probe engine, or the HTTP Server: header — whichever is
// more informative). Every other slot is filled from a single generic,
// table-driven candidate list built from signatures.conf [identity_headers]
// plus a small fixed set of HTML-<meta>-tag-sourced fields.
//
// Adding support for a NEW *header* on the version line requires NO C++
// change at all any more: add one line to signatures.conf's
// [identity_headers] section (see PlatformSignatureSet::identity_headers,
// resolved against HttpFingerprint::raw_headers, which already captures
// every response header generically). The only fields still hardcoded below
// are the handful sourced from parsed HTML <meta> tags rather than headers
// (meta_generator, meta_cms, meta:author, ...) — those aren't in
// raw_headers because they were never HTTP headers to begin with, so a
// conf-file header table can't reach them. Anything HTTP-header-shaped
// (Server, X-Powered-By, X-Jenkins, X-Powered-By-Plesk, X-Aspnet-Version,
// whatever ships next) goes in signatures.conf, full stop.
// ============================================================================
static constexpr size_t kMaxSlots = 10;

// Fields whose raw value is already self-descriptive (contains a product
// name, e.g. meta:generator "WordPress 6.4.2") are printed bare. Fields that
// only carry a bare token/version number are printed as "Label: value" so
// the reader knows what the value refers to. This mirrors the bare/labeled
// distinction used by signatures.conf's [identity_headers] rows below —
// same rules, just for the HTML-<meta>-tag-sourced subset that a header
// table can't cover.
struct MetaFieldSpec {
    std::string HttpFingerprint::*field;
    const char                    *label;
    bool                            bare;
};

static const MetaFieldSpec kMetaIdentityFields[] = {
    // ---- self-descriptive (bare) ----
    { &HttpFingerprint::meta_generator,        "meta:generator",   true  },
    { &HttpFingerprint::meta_cms,              "meta:cms",         true  },
    { &HttpFingerprint::meta_framework,        "meta:framework",   true  },
    { &HttpFingerprint::meta_software,         "meta:software",    true  },
    { &HttpFingerprint::meta_powered_by,       "meta:powered-by",  true  },
    { &HttpFingerprint::meta_built_with,       "meta:built-with",  true  },
    { &HttpFingerprint::meta_created_by,       "meta:created-by",  true  },
    { &HttpFingerprint::meta_application_name, "app-name",         true  },
    // ---- bare-token fields: need the label to make sense of the value ----
    { &HttpFingerprint::meta_author,           "Author",           false },
    { &HttpFingerprint::meta_developer,        "Developer",        false },
};


static void print_result(const ScanResult                  &result,
                         const std::string                 &method_label,
                         const std::vector<HttpFingerprint> &http_fps,
                         bool                                confirmed_websocket)
{
    (void)method_label; // no longer printed

    const std::string bar(60, '=');
    std::vector<HttpFingerprint> effective_fps;
    if (http_fps.size() > 1) {
        effective_fps.push_back(merge_http_fingerprints(http_fps));
    } else {
        effective_fps = http_fps;
    }
    std::string fp_title;
    {
        auto is_redirect_title = [](const std::string &t) -> bool {
            static const char kPfx[] = "redirecting to";
            for (size_t i = 0; i < sizeof(kPfx) - 1 && i < t.size(); ++i)
                if ((char)tolower((unsigned char)t[i]) != kPfx[i]) return false;
            return t.size() >= sizeof(kPfx) - 1;
        };

        std::string last_any;
        const std::vector<HttpFingerprint> &scan_fps =
            (http_fps.size() > 1) ? http_fps : effective_fps;

        for (const auto &fp : scan_fps) {
            if (fp.title.empty()) continue;
            last_any = fp.title;
            if (!is_redirect_title(fp.title))
                fp_title = fp.title;   // updated to LAST non-redirect title
        }
        if (fp_title.empty()) fp_title = last_any;  // fallback

        // Trim SEO title: keep only the first segment before | separator.
        // e.g. "plucky-agen.fr | Plucky, le plaisir simple..."  -> "plucky-agen.fr"
        // e.g. "Plex Media Server 1.2.3"                        -> unchanged
        if (!fp_title.empty()) {
            size_t pipe = fp_title.find('|');
            if (pipe != std::string::npos)
                fp_title = fp_title.substr(0, pipe);
            // Trim whitespace
            size_t s = fp_title.find_first_not_of(" \t");
            size_t e = fp_title.find_last_not_of(" \t");
            fp_title = (s == std::string::npos) ? "" : fp_title.substr(s, e - s + 1);
            // If still too long after trimming, it's not a useful tech identity
            if (fp_title.size() > 50) fp_title = "";
        }
    }

    std::string display_version = result.version;
    std::string display_extra   = result.extrainfo;
    if (display_version.empty() && !display_extra.empty()) {
        display_version = display_extra;
        display_extra.clear();
    }

    // Helper to trim whitespace and normalize newlines/spaces
    auto clean_field = [](const std::string& s) -> std::string {
        std::string cleaned;
        cleaned.reserve(s.size());

        // First, collapse all whitespace (including newlines) to single spaces
        bool in_whitespace = false;
        for (char c : s) {
            if (c == '\r' || c == '\n' || c == '\t' || c == ' ') {
                if (!in_whitespace) {
                    cleaned += ' ';
                    in_whitespace = true;
                }
            } else {
                cleaned += c;
                in_whitespace = false;
            }
        }

        // Trim leading/trailing spaces
        size_t start = cleaned.find_first_not_of(" \t");
        if (start == std::string::npos) return "";
        size_t end = cleaned.find_last_not_of(" \t");
        cleaned = cleaned.substr(start, end - start + 1);

        return cleaned;
    };

    // Strip a redundant leading "version:"/"version " token from a value
    // that's about to be combined with a product name, so we don't print
    // "Jenkins CI server: version: 2.440.3" — just "Jenkins CI server: 2.440.3".
    auto strip_version_label = [](std::string s) -> std::string {
        std::string lower = s;
        for (char &c : lower) c = (char)tolower((unsigned char)c);
        if (lower.rfind("version:", 0) == 0)      s = s.substr(8);
        else if (lower.rfind("version ", 0) == 0) s = s.substr(7);
        size_t p = s.find_first_not_of(' ');
        return (p == std::string::npos) ? "" : s.substr(p);
    };

    // Clean the product/version fields
    std::string clean_product = clean_field(result.product);
    std::string clean_version = clean_field(display_version);
    std::string clean_extra   = clean_field(display_extra);
    std::string clean_service = clean_field(result.service);
    (void)clean_service;

    auto alnum_lc = [](const std::string &s) -> std::string {
        std::string r;
        r.reserve(s.size());
        for (unsigned char c : s)
            if (isalnum(c)) r += (char)tolower(c);
        return r;
    };

    // Does the string contain a digit sequence (version-like token)?
    auto has_version_token = [](const std::string &s) -> bool {
        for (char c : s) if (isdigit((unsigned char)c)) return true;
        return false;
    };

    // Is candidate 'a' subsumed by (or equal to) already-chosen 'b'?
    // True when the alnum core of one contains the alnum core of the other.
    auto is_subsumed = [&](const std::string &a, const std::string &b) -> bool {
        if (a.empty() || b.empty()) return false;
        std::string al = alnum_lc(a), bl = alnum_lc(b);
        if (al == bl) return true;
        // shorter one inside longer one
        if (al.size() <= bl.size()) return bl.find(al) != std::string::npos;
        return al.find(bl) != std::string::npos;
    };

    // Between two candidates for the same conceptual slot, pick the better one:
    // prefer the one with a version token; if tie, prefer the longer one.
    auto better_candidate = [&](const std::string &a, const std::string &b) -> const std::string & {
        bool av = has_version_token(a), bv = has_version_token(b);
        if (av && !bv) return a;
        if (bv && !av) return b;
        return (a.size() >= b.size()) ? a : b;
    };

    // ---- gather raw candidates from HTTP fingerprints ----------------------
    std::string fp_server, fp_osd, fp_powered_by, fp_x_generator, fp_via;
    std::string fp_report_to; // proxy/backend name from Report-To or COOP-Report-Only
    std::string fp_meta_generator, fp_meta_cms, fp_meta_framework,
                fp_meta_software, fp_meta_powered_by, fp_meta_built_with,
                fp_meta_app_name, fp_meta_created_by;

    for (const auto &fp : effective_fps) {
        if (fp_server.empty()           && !fp.server.empty())
            fp_server           = clean_field(fp.server);
        if (fp_osd.empty()              && !fp.osd_name.empty())
            fp_osd              = clean_field(fp.osd_name);
        if (fp_powered_by.empty()       && !fp.powered_by.empty())
            fp_powered_by       = clean_field(fp.powered_by);
        if (fp_x_generator.empty()      && !fp.x_generator.empty())
            fp_x_generator      = clean_field(fp.x_generator);
        if (fp_via.empty()              && !fp.via.empty())
            fp_via              = clean_field(fp.via);
        if (fp_report_to.empty()        && !fp.report_to_group.empty())
            fp_report_to        = clean_field(fp.report_to_group);
        if (fp_report_to.empty()        && !fp.coop_report_to_group.empty())
            fp_report_to        = clean_field(fp.coop_report_to_group);
        if (fp_meta_generator.empty()   && !fp.meta_generator.empty())
            fp_meta_generator   = clean_field(fp.meta_generator);
        if (fp_meta_cms.empty()         && !fp.meta_cms.empty())
            fp_meta_cms         = clean_field(fp.meta_cms);
        if (fp_meta_framework.empty()   && !fp.meta_framework.empty())
            fp_meta_framework   = clean_field(fp.meta_framework);
        if (fp_meta_software.empty()    && !fp.meta_software.empty())
            fp_meta_software    = clean_field(fp.meta_software);
        if (fp_meta_powered_by.empty()  && !fp.meta_powered_by.empty())
            fp_meta_powered_by  = clean_field(fp.meta_powered_by);
        if (fp_meta_built_with.empty()  && !fp.meta_built_with.empty())
            fp_meta_built_with  = clean_field(fp.meta_built_with);
        if (fp_meta_app_name.empty()    && !fp.meta_application_name.empty())
            fp_meta_app_name    = clean_field(fp.meta_application_name);
        if (fp_meta_created_by.empty()  && !fp.meta_created_by.empty())
            fp_meta_created_by  = clean_field(fp.meta_created_by);
    }

    // ---- generic table-driven pass ----------------------------------------
    // First-non-empty-fingerprint-wins, same rule as the hand-written
    // gathers above. Produces {raw, display, label} triples; "raw" is used
    // for subsumption checks, "display" is what actually gets printed.
    //
    // Two sources feed this, merged into one list so downstream dedup/print
    // logic doesn't need to know or care which one a candidate came from:
    //   1. signatures.conf [identity_headers] — any HTTP response header,
    //      looked up straight out of HttpFingerprint::raw_headers. This is
    //      the one to extend for a new header; no C++ change needed.
    //   2. kMetaIdentityFields — the handful of fields parsed out of HTML
    //      <meta> tags rather than headers, so they can't live in
    //      raw_headers and still need a named struct field.
    struct GenericCandidate { std::string raw; std::string display; std::string label; };
    std::vector<GenericCandidate> generic_candidates;

    for (const auto &spec : platform_signatures().identity_headers) {
        std::string header_lc = spec.header;
        for (char &c : header_lc) c = (char)tolower((unsigned char)c);

        std::string raw;
        for (const auto &fp : effective_fps) {
            auto it = fp.raw_headers.find(header_lc);
            if (it != fp.raw_headers.end() && !it->second.empty()) {
                raw = clean_field(it->second);
                break;
            }
        }
        if (raw.empty()) continue;
        std::string display = spec.bare ? raw : (spec.label + ": " + raw);
        generic_candidates.push_back({ raw, display, spec.label });
    }

    for (const auto &spec : kMetaIdentityFields) {
        std::string raw;
        for (const auto &fp : effective_fps) {
            const std::string &val = fp.*(spec.field);
            if (!val.empty()) { raw = clean_field(val); break; }
        }
        if (raw.empty()) continue;
        std::string display = spec.bare ? raw : (std::string(spec.label) + ": " + raw);
        generic_candidates.push_back({ raw, display, spec.label });
    }

    // ---- body_platform_hint: only add its own slot when it's NOT already
    // implied by a meta field just printed above ------------------------
    // body_platform_hint is the *scored* CMS/framework verdict from
    // extract_html_body_signals(): structural evidence (paths, JS globals,
    // HTML comments, body text) combined with meta-tag hints. When it agrees
    // with a meta field already on the line (e.g. meta:generator already
    // reads "Joomla 1.5"), printing "Joomla (score=2)" too is the same fact
    // twice with nothing new -- that's the "why is Joomla printed twice"
    // redundancy. It earns its own slot only when it names a platform not
    // already visible in ANY meta field gen_hint() scores against -- exactly
    // the useful case: no meta tag at all (or a misleading one), where
    // structural signals are the *only* reason the platform is known.
    {
        std::string hint, meta_gen, meta_cms, meta_fw, meta_pb, meta_bw;
        for (const auto &fp : effective_fps) {
            if (hint.empty()     && !fp.body_platform_hint.empty()) hint     = clean_field(fp.body_platform_hint);
            if (meta_gen.empty() && !fp.meta_generator.empty())     meta_gen = fp.meta_generator;
            if (meta_cms.empty() && !fp.meta_cms.empty())           meta_cms = fp.meta_cms;
            if (meta_fw.empty()  && !fp.meta_framework.empty())     meta_fw  = fp.meta_framework;
            if (meta_pb.empty()  && !fp.meta_powered_by.empty())    meta_pb  = fp.meta_powered_by;
            if (meta_bw.empty()  && !fp.meta_built_with.empty())    meta_bw  = fp.meta_built_with;
        }
        if (!hint.empty()) {
            std::string already = meta_gen + " " + meta_cms + " " + meta_fw + " " + meta_pb + " " + meta_bw;
            for (char &c : already) c = (char)tolower((unsigned char)c);

            // Strip the trailing "(score=N)" / "(tied, score=N)" annotation
            // to get just the platform name(s), possibly "A / B" if tied.
            std::string names = hint;
            size_t paren = names.find(" (");
            if (paren != std::string::npos) names = names.substr(0, paren);

            bool any_new = false;
            size_t start = 0;
            while (start <= names.size()) {
                size_t sep = names.find(" / ", start);
                std::string one = (sep == std::string::npos) ? names.substr(start)
                                                               : names.substr(start, sep - start);
                std::string lone = one;
                for (char &c : lone) c = (char)tolower((unsigned char)c);
                if (!lone.empty() && already.find(lone) == std::string::npos) any_new = true;
                if (sep == std::string::npos) break;
                start = sep + 3;
            }

            // The version line should show WHAT was detected, not the
            // internal confidence score that drove the decision -- "score=3"
            // is debugging detail, not identity info, and printing it here
            // was the same class of noise as the earlier Joomla duplication,
            // just triggered by a different case (a platform gen_hint()
            // never saw, e.g. a real WordPress site alongside spoofed
            // Drupal/HubSpot meta tags). 'names' (already stripped of the
            // "(score=N)"/"(tied, score=N)" suffix above) is what gets
            // shown; the full 'hint' -- WITH the score -- still exists on
            // fp.body_platform_hint for the verbose dump and stays
            // available to extract_html_body_signals()'s tamper check.
            if (any_new) generic_candidates.push_back({ names, names, "Platform" });
        }
    }

    auto extract_tech_version = [](const std::string &raw) -> std::string {
        if (raw.empty()) return raw;

        // Trim leading/trailing whitespace
        size_t s = 0, e = raw.size();
        while (s < e && isspace((unsigned char)raw[s])) ++s;
        while (e > s && isspace((unsigned char)raw[e-1])) --e;
        std::string val = raw.substr(s, e - s);
        if (val.empty()) return val;
        auto looks_clean = [](const std::string &v) -> bool {
            if (v.empty()) return true;
            // Too long to be a clean tech identity token
            if (v.size() > 60) return false;
            unsigned char fc = (unsigned char)v.front();
            if (!isalnum(fc)) return false;
            // Sentence/marketing punctuation — never in a tech version string
            for (unsigned char c : v) {
                if (c == ',' || c == '&' || c == '?' || c == '!'
                    || c == 0xE2  // UTF-8 lead byte for • … etc
                    || c == '|')  // pipe inside value = SEO title separator
                    return false;
            }
            // Check for suspiciously long alphanum runs (junk indicator)
            size_t run = 0;
            for (unsigned char c : v) {
                if (isalpha(c)) { ++run; if (run >= 10) return false; }
                else run = 0;
            }
            return true;
        };
        if (looks_clean(val)) return val;

        std::vector<std::string> tokens;
        {
            std::string tok;
            for (size_t i = 0; i <= val.size(); ++i) {
                char c = (i < val.size()) ? val[i] : '\0';
                if (i == val.size() || c == ' ' || c == '\t' || c == '/') {
                    if (!tok.empty()) { tokens.push_back(tok); tok.clear(); }
                } else {
                    tok += c;
                }
            }
        }

        // Helper: does this token look like a version number?
        auto is_version_tok = [](const std::string &t) -> bool {
            if (t.empty() || !isdigit((unsigned char)t[0])) return false;
            bool has_dot = false;
            for (char c : t) {
                if (c == '.' || c == '-' || isalnum((unsigned char)c)) {
                    if (c == '.') has_dot = true;
                } else return false;
            }
            return has_dot;
        };

        // Helper: does this token look like a tech name (not pure garbage)?
        // A tech-name token contains at least one letter and is <= 30 chars,
        // once trailing branding punctuation (the "!" in "Joomla!", trailing
        // ":" / ";") is stripped. That trailing punctuation is legitimately
        // part of some products' own branding and must not disqualify the
        // token -- it previously made extract_tech_version() silently drop
        // the product name (e.g. "Joomla! 1.5" -> just "1.5"), which both
        // looks like a parse failure and throws away real identity info an
        // operator needs. The stripped form is what's returned so the stray
        // punctuation doesn't show up on the version line either.
        auto is_tech_tok = [](const std::string &t) -> std::pair<bool, std::string> {
            std::string s = t;
            while (!s.empty() && (s.back() == '!' || s.back() == ':' || s.back() == ';'))
                s.pop_back();
            if (s.empty() || s.size() > 30) return { false, "" };
            bool has_letter = false;
            for (char c : s) {
                if (isalpha((unsigned char)c)) { has_letter = true; }
                else if (!isdigit((unsigned char)c) && c != '-' && c != '_' && c != '.') return { false, "" };
            }
            return { has_letter, s };
        };

        // Step 2+3: find first version token; take the preceding tech word if valid.
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (is_version_tok(tokens[i])) {
                if (i > 0) {
                    auto [ok, tech] = is_tech_tok(tokens[i-1]);
                    if (ok) {
                        // tech + version
                        return tech + " " + tokens[i];
                    }
                }
                // Step 4: bare version
                return tokens[i];
            }
        }

        if (val.size() <= 60) {
            bool has_sentence_punct = false;
            for (unsigned char c : val) {
                if (c == ',' || c == '&' || c == '?' || c == '!' || c == 0xE2)
                { has_sentence_punct = true; break; }
            }
            if (!has_sentence_punct) return val;
        }
        return "";  // discard — human/marketing text, not a tech identity
    };

    // ---- slot 1: primary identity ------------------------------------------
    // Merge probe-engine product + version/extrainfo into a single
    // "Product: Version" string (colon, not space) so it reads unambiguously
    // instead of floating around as a separate "version: X" fragment.
    std::string pv, pv_label;
    {
        std::string ver_part = !clean_version.empty() ? clean_version
                                                        : strip_version_label(clean_extra);
        if (!clean_product.empty() && !ver_part.empty()) {
            pv       = clean_product + ": " + ver_part;
            pv_label = "version";
        } else if (!clean_product.empty()) {
            pv       = clean_product;
            pv_label = "product";
        } else if (!ver_part.empty()) {
            pv       = ver_part;
            pv_label = "version";
        } else if (!clean_extra.empty()) {
            pv       = clean_extra;
            pv_label = "extra";
        }
    }

    std::string slot1, slot1_label;
    std::string pv_leftover; // set if pv loses to fp_server, so it isn't lost
    {
        if (!fp_server.empty() && !pv.empty()) {
            const std::string &winner = better_candidate(pv, fp_server);
            if (&winner == &fp_server) {
                slot1       = fp_server;
                slot1_label = "server";
                if (!is_subsumed(pv, fp_server)) pv_leftover = pv;
            } else {
                slot1       = pv;
                slot1_label = pv_label;
                if (!is_subsumed(fp_server, pv)) pv_leftover = fp_server;
            }
        } else if (!fp_server.empty()) {
            slot1       = fp_server;
            slot1_label = "server";
        } else if (!pv.empty()) {
            slot1       = pv;
            slot1_label = pv_label;
        }

        if (slot1.empty() && !fp_osd.empty()) {
            slot1 = fp_osd;
            slot1_label = "osd-name";
        }
    }

    struct LabeledCandidate { std::string value; std::string label; };

    // Header/meta candidates are listed BEFORE the HTML <title> on purpose:
    // a title is marketing copy ("Acme Inc — Home"), while these are actual
    // tech identity signals. Ties are broken by document order below, so
    // putting title last means it only wins slot2 when nothing more
    // informative is available.
    std::vector<LabeledCandidate> app_candidates_labeled;
    app_candidates_labeled.push_back({ fp_meta_app_name,  "app-name"       });
    app_candidates_labeled.push_back({ fp_powered_by,     "X-Powered-By"   });
    app_candidates_labeled.push_back({ fp_x_generator,    "X-Generator"    });
    app_candidates_labeled.push_back({ fp_meta_generator, "meta:generator" });
    app_candidates_labeled.push_back({ fp_meta_cms,       "meta:cms"       });
    app_candidates_labeled.push_back({ fp_meta_framework, "meta:framework" });
    app_candidates_labeled.push_back({ fp_meta_software,  "meta:software"  });
    app_candidates_labeled.push_back({ fp_meta_powered_by,"meta:powered-by"});
    app_candidates_labeled.push_back({ fp_meta_built_with,"meta:built-with"});
    app_candidates_labeled.push_back({ fp_meta_created_by,"meta:created-by"});
    app_candidates_labeled.push_back({ fp_title,          "title"          });

    // Dedup: among subsumption-related candidates keep the better one.
    std::vector<LabeledCandidate> app_winners;
    for (const auto &cand : app_candidates_labeled) {
        if (cand.value.empty()) continue;
        bool merged = false;
        for (auto &w : app_winners) {
            if (is_subsumed(cand.value, w.value) || is_subsumed(w.value, cand.value)) {
                if (&better_candidate(w.value, cand.value) == &cand.value) {
                    w.value = cand.value;
                    w.label = cand.label;
                }
                merged = true;
                break;
            }
        }
        if (!merged) app_winners.push_back(cand);
    }

    // The HTML title is the weakest identity signal we have (it's copy
    // written for humans, not tech fingerprinting) so it gets dropped
    // entirely once real header/meta identity info is available: either a
    // header carries an actual version token (e.g. "4.0.30319"), or there
    // are simply enough other identity candidates that the title would just
    // be crowding out more useful information.
    {
        size_t non_title_count = 0;
        bool   have_versioned  = false;
        for (const auto &w : app_winners) {
            if (w.label == "title") continue;
            ++non_title_count;
            if (has_version_token(w.value)) have_versioned = true;
        }
        if (have_versioned || non_title_count >= 3) {
            app_winners.erase(
                std::remove_if(app_winners.begin(), app_winners.end(),
                                [](const LabeledCandidate &w) { return w.label == "title"; }),
                app_winners.end());
        }
    }

    std::string slot2, slot2_label;
    size_t slot2_idx = std::string::npos;
    for (size_t i = 0; i < app_winners.size(); ++i) {
        if (!is_subsumed(app_winners[i].value, slot1)) {
            slot2       = app_winners[i].value;
            slot2_label = app_winners[i].label;
            slot2_idx   = i;
            break;
        }
    }

    std::string fp_asset_server, fp_asset_title;
    for (const auto &fp : http_fps) {
        if (fp.phase.rfind("asset-follow", 0) != 0) continue;
        if (fp_asset_server.empty() && !fp.server.empty()) fp_asset_server = clean_field(fp.server);
        if (fp_asset_title.empty()  && !fp.title.empty())  fp_asset_title  = clean_field(fp.title);
    }

    struct LabeledExtra { std::string value; std::string label; };
    std::vector<LabeledExtra> extra_candidates;


    if (!fp_server.empty() && !is_subsumed(fp_server, slot1))
        extra_candidates.push_back({ fp_server, "server" });
    if (!pv_leftover.empty() && !is_subsumed(pv_leftover, slot1))
        extra_candidates.push_back({ pv_leftover, pv_label.empty() ? "version" : pv_label });
    if (!fp_asset_server.empty() && !is_subsumed(fp_asset_server, fp_server)
        && !is_subsumed(fp_asset_server, slot1))
        extra_candidates.push_back({ fp_asset_server, "server (asset)" });
    if (!fp_asset_title.empty() && !is_subsumed(fp_asset_title, slot2)
        && !is_subsumed(fp_asset_title, slot1))
        extra_candidates.push_back({ fp_asset_title, "title (asset)" });
    // Note: value is what's actually printed for slots 3+ (see filled_slots
    // below), so a bare token like "cf-nel" needs its label folded in here —
    // otherwise it prints unlabeled and the reader has no idea what it is.
    if (!fp_via.empty())
        extra_candidates.push_back({ "Proxy: " + fp_via, "Proxy" });
    if (!fp_report_to.empty() && !is_subsumed(fp_report_to, fp_via))
        extra_candidates.push_back({ "Proxy: " + fp_report_to, "Proxy" });
    for (size_t i = 0; i < app_winners.size(); ++i) {
        if (i == slot2_idx) continue;
        extra_candidates.push_back({ app_winners[i].value, app_winners[i].label });
    }
    // Universal pass: anything generic_candidates picked up that isn't
    // already covered by slot1/slot2/an existing extra candidate.
    for (const auto &gc : generic_candidates) {
        bool dup = is_subsumed(gc.raw, slot1) || (!slot2.empty() && is_subsumed(gc.raw, slot2));
        if (!dup) {
            for (const auto &ec : extra_candidates) {
                if (is_subsumed(gc.raw, ec.value)) { dup = true; break; }
            }
        }
        if (!dup) extra_candidates.push_back({ gc.display, gc.label });
    }

    // Fill slot3..slot10 from extra_candidates, skipping anything already
    // covered (subsumed) by slot1, slot2, or an earlier extra slot.
    std::vector<std::string> filled_slots; // slot3..slotN values, in order
    {
        for (const auto &ec : extra_candidates) {
            if (filled_slots.size() + 2 >= kMaxSlots) break; // slot1+slot2 already used 2 of 10
            if (ec.value.empty()) continue;
            if (is_subsumed(ec.value, slot1)) continue;
            if (!slot2.empty() && is_subsumed(ec.value, slot2)) continue;
            bool dup = false;
            for (const auto &prior : filled_slots)
                if (is_subsumed(ec.value, prior)) { dup = true; break; }
            if (dup) continue;
            filled_slots.push_back(ec.value);
        }
    }

    auto apply_per_segment = [&](const std::string &val,
                                 std::function<std::string(const std::string &)> fn)
        -> std::string
    {
        const std::string pipe_sep = " | ";
        if (val.find(pipe_sep) == std::string::npos)
            return fn(val);   // single value — fast path

        std::string result;
        size_t pos = 0;
        while (pos <= val.size()) {
            size_t next = val.find(pipe_sep, pos);
            std::string seg = (next == std::string::npos)
                              ? val.substr(pos)
                              : val.substr(pos, next - pos);
            std::string extracted = fn(seg);
            if (!extracted.empty()) {
                if (!result.empty()) result += " & ";
                result += extracted;
            }
            if (next == std::string::npos) break;
            pos = next + pipe_sep.size();
        }
        return result.empty() ? val : result;
    };

    if (!slot1.empty())
        slot1 = apply_per_segment(slot1, extract_tech_version);
    if (!slot2.empty())
        slot2 = apply_per_segment(slot2, extract_tech_version);

    // ---- assemble final output ---------------------------------------------
    std::vector<std::string> out_parts;
    if (!slot1.empty()) out_parts.push_back(slot1);
    if (!slot2.empty()) out_parts.push_back(slot2);
    for (const auto &v : filled_slots) out_parts.push_back(v);
    if (out_parts.size() > kMaxSlots) out_parts.resize(kMaxSlots);

    // ---- tamper / anomaly marker -------------------------------------------
    // Appended AFTER the kMaxSlots cap (and not counted against it) so a
    // possible-spoofing signal can never get silently truncated off the end
    // of a long version line -- that's exactly the kind of response an
    // operator most needs to see. Two independent heuristics feed this:
    //   1. tamper_hint: meta:generator's claimed platform disagrees with
    //      what the structural (path/JS-global/comment/body) scorer found
    //      (see extract_html_body_signals) -- a common WAF/honeypot trick is
    //      serving a fake generator tag while running something else.
    //   2. duplicate_headers: the same header name appeared twice in one
    //      response with two different values -- a sign of response
    //      splitting, a rewriting proxy, or a spoofed banner layered in
    //      front of the real one.
    {
        std::string tamper_note;
        for (const auto &fp : effective_fps) {
            if (!fp.tamper_hint.empty()) { tamper_note = fp.tamper_hint; break; }
        }
        size_t dup_count = 0;
        for (const auto &fp : effective_fps) dup_count += fp.duplicate_headers.size();

        std::string marker;
        if (!tamper_note.empty()) marker = "TAMPER? " + tamper_note;
        if (dup_count > 0) {
            if (!marker.empty()) marker += "; ";
            marker += std::to_string(dup_count) + " duplicate header"
                      + (dup_count == 1 ? "" : "s") + " w/ conflicting values";
        }
        if (!marker.empty()) out_parts.push_back("[" + marker + "]");
    }

    if (confirmed_websocket) {
        std::cout << "\033[32mwebsocket\033[0m\n";
    } else if (!out_parts.empty()) {
        for (size_t i = 0; i < out_parts.size(); ++i) {
            if (i) std::cout << " | ";
            std::cout << "\033[32m" << out_parts[i] << "\033[0m";
        }
        bool redirect_followed = method_label.find("redirect") != std::string::npos;
        bool multi_hop         = http_fps.size() > 1;
        if (redirect_followed || multi_hop)
            std::cout << "  (need attention)";
        std::cout << "\n";
    } else {
        std::cout << "?\n";
    }

    {
        bool has_version = !clean_version.empty();
        bool has_server  = false;
        bool has_title   = !fp_title.empty();
        bool has_tls_fp  = false;
        TlsCertInfo best_cert;
        int  best_status = 0;

        for (const auto &fp : effective_fps) {
            if (!fp.server.empty())    has_server  = true;
            if (fp.is_ssl && fp.tls_cert.populated) {
                has_tls_fp  = true;
                // Take the first populated cert
                if (!best_cert.populated) {
                    best_cert   = fp.tls_cert;
                    best_status = fp.status_code;
                }
            }
        }

        bool no_info = !has_version && !has_server && !has_title;

        if (no_info && has_tls_fp && best_cert.populated &&
            !best_cert.subject.empty() &&
            (best_status == 404 || best_status == 0 || best_status == 200))
        {

            std::string cn;
            const std::string &subj = best_cert.subject;
            size_t cn_pos = subj.find("CN=");
            if (cn_pos == std::string::npos) {
                // Try case-insensitive
                std::string lsubj = subj;
                for (char &c : lsubj) c = (char)tolower((unsigned char)c);
                cn_pos = lsubj.find("cn=");
            }
            if (cn_pos != std::string::npos) {
                size_t val_start = cn_pos + 3;
                // Find end: next unescaped comma or end of string
                size_t val_end = val_start;
                while (val_end < subj.size()) {
                    if (subj[val_end] == '\\') { val_end += 2; continue; } // skip escaped char
                    if (subj[val_end] == ',')  break;
                    ++val_end;
                }
                cn = subj.substr(val_start, val_end - val_start);
                // Trim whitespace
                while (!cn.empty() && isspace((unsigned char)cn.front())) cn.erase(cn.begin());
                while (!cn.empty() && isspace((unsigned char)cn.back()))  cn.pop_back();
            }

            if (!cn.empty()) {
                std::cout << cn << "  [TLS cert fallback]\n";
                // Also print the full subject for context if it adds info
                if (best_cert.subject != cn)
                    std::cout << "Cert Subject : "
                              << best_cert.subject.substr(0, 52)
                              << (best_cert.subject.size() > 52 ? "..." : "")
                              << "\n";
                // Print TLS version so operator knows this came from a cert
                if (!best_cert.tls_version.empty())
                    std::cout << "TLS Ver : " << best_cert.tls_version << "\n";
            }
        }
    }

    if (result.service.empty() && result.product.empty() && effective_fps.empty())
        std::cout << "(no match found)\n";

    // Raw fingerprint only when there are no HTTP FPs
    if (!result.fingerprint.empty() && effective_fps.empty()) {
        std::cout << "\n+- Raw Fingerprint (first 200 chars) ----------------------\n";
        std::cout << result.fingerprint.substr(0, 200) << "\n";
        std::cout << "+-----------------------------------------------------------\n";
    }
}

static std::map<std::string, std::string> g_dns_cache;
static std::mutex                         g_dns_cache_mu;

static std::string resolve_host(const std::string &host)
{
    // -- 1. Numeric IP literal (v4 or v6) — delegate to shiv's normalizer --
    std::string norm;
    if (normalize_ip_string(host, norm)) return norm;

    // -- 2. Cache hit --------------------------------------------------------
    {
        std::lock_guard<std::mutex> lk(g_dns_cache_mu);
        auto it = g_dns_cache.find(host);
        if (it != g_dns_cache.end()) return it->second;
    }

    // -- 3. DNS resolution — one call now checks both A and AAAA records ----
    std::string result;
    if (resolve_domain_to_ip(host, result)) {
        std::lock_guard<std::mutex> lk(g_dns_cache_mu);
        g_dns_cache[host] = result;
        return result;
    }
    return host;
}

static bool is_ip_literal(const std::string &s)
{
    return get_ip_version(s.c_str()) != 0;
}

static bool is_lan_ip(const std::string &s)
{
    int ver = get_ip_version(s.c_str());

    if (ver == 4) {
        struct in_addr addr{};
        inet_pton(AF_INET, s.c_str(), &addr);
        uint32_t ip = ntohl(addr.s_addr);

        return ((ip & 0xFF000000) == 0x0A000000) ||  // 10.0.0.0/8
               ((ip & 0xFFF00000) == 0xAC100000) ||  // 172.16.0.0/12
               ((ip & 0xFFFF0000) == 0xC0A80000) ||  // 192.168.0.0/16
               ((ip & 0xFFFF0000) == 0xA9FE0000) ||  // 169.254.0.0/16
               ((ip & 0xFF000000) == 0x7F000000);    // 127.0.0.0/8
    }

    if (ver == 6) {
        struct in6_addr a6{};
        inet_pton(AF_INET6, s.c_str(), &a6);
        const uint8_t *b = a6.s6_addr;

        if ((b[0] & 0xFE) == 0xFC) return true;                 // fc00::/7  (ULA)
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // fe80::/10 (link-local)

        static const uint8_t loopback6[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
        return memcmp(b, loopback6, 16) == 0;                    // ::1
    }

    return false;
}

static std::string resolve_ip_to_domain(const std::string &ip)
{
    std::string cached;
    if (ptr_cache_lookup(ip, cached)) return cached;
    if (custom_dns_configured()) {
        std::string domain;
        bool ok = resolve_ptr_via_configured_dns(ip, domain);
        ptr_cache_store(ip, ok ? domain : "");
        return ok ? domain : "";
    }
    // Accept both IPv4 and IPv6 reverse-DNS lookups
    struct sockaddr_storage ss{};
    socklen_t ss_len = 0;
    make_sockaddr_from_ip(ip, 0, ss, ss_len);
    if (ss_len == 0) return ""; 
    auto prom = std::make_shared<std::promise<std::string>>();
    std::future<std::string> fut = prom->get_future();
    std::string ip_copy = ip;

    std::thread([prom, ss, ss_len, ip_copy]() mutable {
        char host[NI_MAXHOST] = {};
        int rc = getnameinfo(reinterpret_cast<const struct sockaddr *>(&ss),
                             ss_len, host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        std::string result = (rc == 0) ? host : "";
        if (!result.empty() && result.back() == '.') result.pop_back();
        if (result == ip_copy) result.clear();
        if (!result.empty()) {
            bool all_numdot = true;
            for (char c : result)
                if (!isdigit((unsigned char)c) && c != '.') { all_numdot = false; break; }
            if (all_numdot) result.clear();
        }
        try {
            prom->set_value(result);
        } catch (const std::future_error &) {
            // ignore -- shouldn't happen since prom is kept alive via the shared_ptr
        }
    }).detach();

    if (fut.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
        fprintf(stderr, "[Host] Reverse-DNS for %s timed out (2s) -- skipping PTR lookup\n",
                ip.c_str());
        return "";   // does NOT block -- the detached thread finishes on its own
    }
    std::string result = fut.get();
    ptr_cache_store(ip, result);
    return result;
}

static int connect_with_timeout(const std::string &ip, int port,
                                int connect_timeout_sec)
{
    // Build address — support both IPv4 and IPv6 targets.
    struct sockaddr_storage addr_storage{};
    socklen_t addr_len = 0;
    int family = make_sockaddr_from_ip(ip, (uint16_t)port, addr_storage, addr_len);
    if (addr_len == 0) return -1;  // not a valid IP address
    int fd = ::socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    // SO_KEEPALIVE: lets the OS detect dead connections during long reads
    {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    }
    // TCP_NODELAY: disable Nagle — we control framing ourselves; avoids 40ms delays
#ifdef TCP_NODELAY
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
#endif

    // Switch to non-blocking for the connect race
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { close(fd); return -1; }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }

    int rc = ::connect(fd, reinterpret_cast<struct sockaddr *>(&addr_storage), addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd); return -1;
    }

    if (rc != 0) {
        // EINPROGRESS — wait for writability via poll() (no FD_SETSIZE limit)
        struct pollfd pfd{ fd, POLLOUT, 0 };
        int timeout_ms = connect_timeout_sec * 1000;
        int ret;
        do {
            ret = ::poll(&pfd, 1, timeout_ms);
        } while (ret < 0 && errno == EINTR);

        if (ret <= 0) {
            // 0 = timeout (firewall drop); <0 = fatal poll error
            close(fd); return -1;
        }
        // Check for async connect error via SO_ERROR
        int err = 0; socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
            close(fd); return -1;
        }
    }

    // Restore blocking mode — callers set their own I/O timeouts via setsockopt
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    return fd;
}

static void set_io_timeouts(int fd, int timeout_sec)
{
    struct timeval tv{ timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static bool buffer_tail_has_html_close(const std::vector<u8> &data)
{
    static constexpr const char *kNeedles[] = { "</html>", "</body>" };
    size_t tail_start = data.size() > 64 ? data.size() - 64 : 0;
    const u8 *base = data.data() + tail_start;
    size_t    len  = data.size() - tail_start;

    for (const char *needle : kNeedles) {
        size_t nlen = strlen(needle);
        if (nlen > len) continue;
        for (size_t i = 0; i + nlen <= len; ++i) {
            bool match = true;
            for (size_t k = 0; k < nlen; ++k) {
                if ((char)tolower((unsigned char)base[i + k]) != needle[k]) {
                    match = false; break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

// Reactor tuning for the current scan (see VersionDetectOptions)
struct ReactorTuning {
    size_t      max_response_bytes = 0;
    std::string ciphers_tls12;
    std::string ciphersuites_tls13;
    int         min_connect_ms = 0;
};
static thread_local ReactorTuning g_tuning;
// Facts about the most recent plain-TCP capture on this thread (feeds tcpwrapped detection)
struct LastTcpCapture { bool eof_no_data = false; long elapsed_ms = -1; };
static thread_local LastTcpCapture g_last_tcp;

static std::vector<u8> capture_tcp(const std::string &ip, int port,
                                   int timeout_sec,
                                   const std::vector<u8> *payload,
                                   bool verbose,
                                   int connect_timeout_sec = 0,
                                   async_io::SourcePort src_port = {})
{
    // Default: connect timeout is min(3, timeout) — skip filtered ports fast
    if (connect_timeout_sec <= 0)
        connect_timeout_sec = std::min(3, timeout_sec);

    auto op = std::make_shared<async_io::Operation>();
    op->ip   = ip;
    op->port = port;
    op->proto = async_io::Proto::TCP;
    if (payload) op->send_payload = *payload;
    op->timeouts.connect_sec    = connect_timeout_sec;
    op->timeouts.first_byte_sec = timeout_sec;
    // idle_sec left at 0 => reactor default (max(2, timeout_sec/2)), same
    // math as the old recv_all_tcp()'s idle_timeout_sec.
    op->max_response_bytes = g_tuning.max_response_bytes ? g_tuning.max_response_bytes : (size_t)MAX_RESPONSE;
    op->timeouts.min_connect_ms = g_tuning.min_connect_ms;
    op->src_port = src_port; // default EPHEMERAL — every normal call site is unaffected

    const auto cap_t0 = std::chrono::steady_clock::now();
    auto data = async_io::run_blocking(async_io::shared_reactor(), op);
    g_last_tcp.elapsed_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - cap_t0).count();
    // SUCCESS with no bytes == the peer closed the connection (a timeout reports TIMEOUT)
    g_last_tcp.eof_no_data = data.empty() && op->result.load() == async_io::OpResult::SUCCESS;

    if (verbose) {
        auto r = op->result.load();
        if (r == async_io::OpResult::CONNECT_FAILED) {
            std::string hint;
            if (src_port.mode == async_io::SourcePort::Mode::FIXED) {
                if (op->last_errno == EACCES)
                    hint = " — no permission to bind that source port (need root/CAP_NET_BIND_SERVICE)";
                else if (op->last_errno == EADDRINUSE)
                    hint = " — source port already in use by another connection";
            }
            vlog::fail(verbose, "tcp connect failed (timeout=" + std::to_string(connect_timeout_sec) +
                       "s): " + strerror(op->last_errno) + hint, 2);
        } else if (payload && !payload->empty()) {
            vlog::line(verbose, "tcp: sent " + std::to_string(payload->size()) + " bytes", 2);
        }
    }
    return data;
}

struct TlsConfig {
    // Server certificate verification
    std::string ca_file;       // PEM CA bundle (e.g. /etc/ssl/certs/ca-certificates.crt)
    std::string ca_path;       // directory of hashed CA certs (alternative to ca_file)
    bool        verify_peer = false; // false = fingerprint only, no hard fail on bad cert

    // Mutual TLS (mTLS) — optional
    std::string client_cert;   // PEM client certificate file
    std::string client_key;    // PEM private key file for client cert

    // SNI override — if empty, the ip string is used
    std::string sni_name;

    bool has_client_cert() const { return !client_cert.empty() && !client_key.empty(); }
};

// Per-scan context. run_version_probe() may be called concurrently for many
// targets; every capture for one scan runs on the calling thread, so this state
// is thread_local instead of process-global (no cross-target Host/SNI/path mixups).
static thread_local bool        g_verbose = false;
static thread_local TlsConfig   g_tls_config;
static thread_local std::string g_hostname;
static thread_local std::string g_target_path = "/";
static TlsConfig snapshot_tls_config() { return g_tls_config; }
static std::mutex g_stdout_mu;        
static std::mutex g_srcport443_mu;
static std::vector<u8> capture_ssl(const std::string &ip, int port,
                                   int timeout_sec,
                                   const std::vector<u8> *payload,
                                   bool verbose,
                                   TlsCertInfo *cert_out = nullptr,
                                   int connect_timeout_sec = 0,
                                   const std::string &sni_override = "")
{
    // Default: connect timeout is min(3, timeout) — skip filtered ports fast
    if (connect_timeout_sec <= 0)
        connect_timeout_sec = std::min(3, timeout_sec);

    static bool ssl_initialised = false;
    if (!ssl_initialised) {
        // Use compat macros — no-ops on OpenSSL 1.1+, real calls on 1.0.x
        COMPAT_SSL_library_init();
        COMPAT_SSL_load_error_strings();
        COMPAT_OpenSSL_add_all_algorithms();
        ssl_initialised = true;
    }

    auto op = std::make_shared<async_io::Operation>();
    op->ip    = ip;
    op->port  = port;
    op->proto = async_io::Proto::TLS;
    if (payload) op->send_payload = *payload;
    op->timeouts.connect_sec    = connect_timeout_sec;
    op->timeouts.first_byte_sec = timeout_sec;
    const TlsConfig tls_cfg = snapshot_tls_config();
    op->max_response_bytes = g_tuning.max_response_bytes ? g_tuning.max_response_bytes : (size_t)MAX_RESPONSE;
    op->timeouts.min_connect_ms = g_tuning.min_connect_ms;
    op->tls.cipher_list_tls12  = g_tuning.ciphers_tls12;
    op->tls.ciphersuites_tls13 = g_tuning.ciphersuites_tls13;
    op->tls.verify_peer  = tls_cfg.verify_peer;
    op->tls.ca_file       = tls_cfg.ca_file;
    op->tls.ca_path       = tls_cfg.ca_path;
    op->tls.client_cert   = tls_cfg.client_cert;
    op->tls.client_key    = tls_cfg.client_key;
    op->tls.sni = !sni_override.empty()    ? sni_override
                : !tls_cfg.sni_name.empty() ? tls_cfg.sni_name
                                            : std::string();   // empty => reactor derives; IPs never sent as SNI

    struct CertState {
        std::mutex  mu;
        TlsCertInfo info;
        bool        got = false;
    };
    auto cert_state = std::make_shared<CertState>();
    op->on_complete = [cert_state](async_io::Operation &o) {
        if (o.ssl_handle && o.result.load() == async_io::OpResult::SUCCESS) {
            TlsCertInfo tmp = extract_tls_cert_info(o.ssl_handle);
            std::lock_guard<std::mutex> lk(cert_state->mu);
            cert_state->info = std::move(tmp);
            cert_state->got  = true;
        }
    };

    auto data = async_io::run_blocking(async_io::shared_reactor(), op);

    TlsCertInfo cert_info;
    bool        got_cert = false;
    {
        std::lock_guard<std::mutex> lk(cert_state->mu);
        if (cert_state->got) { cert_info = cert_state->info; got_cert = true; }
    }

    if (got_cert) {
        if (verbose) cert_info.print(std::cerr);
        if (cert_out) *cert_out = cert_info;
    }

    if (verbose) {
        auto r = op->result.load();
        switch (r) {
            case async_io::OpResult::CONNECT_FAILED:
                vlog::fail(verbose, "ssl connect failed (timeout=" + std::to_string(connect_timeout_sec) +
                           "s): " + strerror(op->last_errno), 2);
                break;
            case async_io::OpResult::TLS_FAILED: {
                std::string err_cat = "unknown";
                switch (op->last_ssl_error) {
                    case SSL_ERROR_SYSCALL:     err_cat = "syscall/IO error";         break;
                    case SSL_ERROR_SSL:         err_cat = "SSL protocol error";       break;
                    case SSL_ERROR_ZERO_RETURN: err_cat = "connection closed cleanly"; break;
                    case SSL_ERROR_WANT_READ:   err_cat = "want-read (timeout?)";     break;
                    case SSL_ERROR_WANT_WRITE:  err_cat = "want-write (timeout?)";    break;
                    default:                    err_cat = "other";                     break;
                }
                vlog::fail(verbose, "ssl handshake failed on " + ip + ":" + std::to_string(port), 2);
                vlog::line(verbose, err_cat + " (SSL_get_error=" + std::to_string(op->last_ssl_error) + ")", 3);
                break;
            }
            default:
                if (payload && !payload->empty())
                    vlog::line(verbose, "ssl: sent " + std::to_string(payload->size()) + " bytes", 2);
                break;
        }
    } else {
        ERR_clear_error();
    }

    return data;
}

static bool ssl_port_check(const std::string &ip, int port,
                            int connect_timeout_sec, bool verbose,
                            TlsCertInfo *cert_out = nullptr)
{
    TlsCertInfo cert;
    int check_timeout = std::clamp(connect_timeout_sec > 0 ? connect_timeout_sec : 3, 1, 5);

    auto r = capture_ssl(ip, port, check_timeout, nullptr,
                         verbose, &cert, check_timeout);

    bool tls_ok = cert.populated;
    if (cert_out) *cert_out = cert;

    if (tls_ok) vlog::ok(verbose, "port " + std::to_string(port) + ": TLS confirmed", 2);
    else        vlog::fail(verbose, "port " + std::to_string(port) + ": TLS not supported (plain TCP)", 2);

    return tls_ok;
}

static std::vector<u8> capture_ssl_permissive(const std::string &ip, int port,
                                              int timeout_sec,
                                              const std::vector<u8> *payload,
                                              bool verbose,
                                              TlsCertInfo *cert_out = nullptr,
                                              int connect_timeout_sec = 0,
                                              const std::string &sni_override = "")
{
    if (connect_timeout_sec <= 0)
        connect_timeout_sec = std::min(3, timeout_sec);

    static bool ssl_initialised = false;
    if (!ssl_initialised) {
        COMPAT_SSL_library_init();
        COMPAT_SSL_load_error_strings();
        COMPAT_OpenSSL_add_all_algorithms();
        ssl_initialised = true;
    }

    int fd = connect_with_timeout(ip, port, connect_timeout_sec);
    if (fd < 0) {
        vlog::fail(verbose, "ssl-permissive connect failed (timeout=" +
                   std::to_string(connect_timeout_sec) + "s): " + strerror(errno), 2);
        return {};
    }
    set_io_timeouts(fd, timeout_sec);

    // Build a maximally permissive SSL context ---------------------------------
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return {}; }

    // Accept any protocol version the build supports.
    // SSL_CTX_set_min_proto_version with 0 means "use the library's absolute
    // minimum" (typically TLS 1.0 or SSL 3.0 depending on build flags).
    SSL_CTX_set_min_proto_version(ctx, 0);
#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif

    // ALL ciphers including weak / export / NULL / anonymous suites.
    // @SECLEVEL=0 is required on OpenSSL 1.1+ to permit low-security suites.
    if (SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0") != 1) {
        vlog::warn(verbose, "ssl-permissive: ALL:@SECLEVEL=0 rejected, trying DEFAULT", 2);
        SSL_CTX_set_cipher_list(ctx, "DEFAULT");
    }

    // No peer verification, no hostname checking.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    vlog::line(verbose, "ssl-permissive: attempting on " + ip + ":" + std::to_string(port) +
               " (all versions, all ciphers, no cert validation)", 2);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return {}; }
    SSL_set_fd(ssl, fd);

    const TlsConfig tls_cfg = snapshot_tls_config();
    const std::string sni = !sni_override.empty()    ? sni_override
                           : !tls_cfg.sni_name.empty() ? tls_cfg.sni_name
                                                        : ip;
    if (!sni.empty() && !is_ip_literal(sni))   // never send an IP literal as SNI (RFC 6066)
        SSL_set_tlsext_host_name(ssl, sni.c_str());

    // Attempt the TLS handshake with permissive settings ----------------------
    if (SSL_connect(ssl) <= 0) {
        int ssl_err = SSL_get_error(ssl, -1);
        if (verbose) {
            vlog::fail(verbose, "ssl-permissive handshake failed on " + ip + ":" +
                       std::to_string(port) + " (even with permissive settings)", 2);
            std::string err_cat = "unknown";
            switch (ssl_err) {
                case SSL_ERROR_SYSCALL:     err_cat = "syscall/IO error";   break;
                case SSL_ERROR_SSL:         err_cat = "SSL protocol error"; break;
                case SSL_ERROR_ZERO_RETURN: err_cat = "closed cleanly";     break;
                default:                    err_cat = "other";             break;
            }
            vlog::line(verbose, err_cat + " (" + std::to_string(ssl_err) + ")", 3);
            unsigned long e;
            while ((e = ERR_get_error()) != 0) {
                char eb[256]; ERR_error_string_n(e, eb, sizeof(eb));
                vlog::line(verbose, std::string(eb), 3);
            }
        } else {
            ERR_clear_error();
        }
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return {};
    }

    // Extract cert info (best-effort; we already have VERIFY_NONE) -----------
    TlsCertInfo cert_info = extract_tls_cert_info(ssl);
    if (verbose) {
        cert_info.print(std::cerr);
        vlog::ok(verbose, "ssl-permissive handshake OK — version: " + cert_info.tls_version +
                  " | cipher: " + cert_info.cipher, 2);
    }
    if (cert_out) *cert_out = cert_info;

    bool send_ok = true;
    if (payload && !payload->empty()) {
        size_t off = 0;
        while (off < payload->size()) {
            int w = SSL_write(ssl, payload->data() + off, (int)(payload->size() - off));
            if (w <= 0) { send_ok = false; break; }
            off += (size_t)w;
        }
        if (!send_ok) vlog::fail(verbose, "ssl-permissive: send failed", 2);
    }

    // Read until EOF / timeout / cap. After the first bytes arrive, use a
    // shorter idle timeout so we don't wait the full first-byte budget.
    const int idle_timeout_sec = std::max(1, std::max(2, timeout_sec / 2));
    bool got_first = false;

    std::vector<u8> data;
    char buf[CHUNK];
    while (send_ok && (int)data.size() < MAX_RESPONSE) {
        int want = std::min<int>((int)sizeof(buf), MAX_RESPONSE - (int)data.size());
        int n = SSL_read(ssl, buf, want);
        if (n <= 0) break;
        data.insert(data.end(), buf, buf + n);
        if (!got_first) { got_first = true; set_io_timeouts(fd, idle_timeout_sec); }
    }
    ERR_clear_error();
    if (SSL_in_init(ssl) == 0) SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return data;
}

static std::vector<u8> capture_udp(const std::string &ip, int port,
                                   int timeout_sec,
                                   const std::vector<u8> *payload,
                                   bool verbose)
{

    int family = AF_INET;
    struct sockaddr_storage addr_storage{};
    socklen_t addr_len = 0;

    {
        struct sockaddr_in *a4 = reinterpret_cast<struct sockaddr_in *>(&addr_storage);
        if (inet_pton(AF_INET, ip.c_str(), &a4->sin_addr) == 1) {
            a4->sin_family = AF_INET;
            a4->sin_port   = htons((uint16_t)port);
            addr_len = sizeof(struct sockaddr_in);
            family   = AF_INET;
        }
    }
    if (addr_len == 0) {
        struct sockaddr_in6 *a6 = reinterpret_cast<struct sockaddr_in6 *>(&addr_storage);
        if (inet_pton(AF_INET6, ip.c_str(), &a6->sin6_addr) == 1) {
            a6->sin6_family = AF_INET6;
            a6->sin6_port   = htons((uint16_t)port);
            addr_len = sizeof(struct sockaddr_in6);
            family   = AF_INET6;
        }
    }
    if (addr_len == 0) return {}; 

    static const u8 WAKE = '\n';
    const u8 *pbuf = payload && !payload->empty() ? payload->data() : &WAKE;
    size_t    plen = payload && !payload->empty() ? payload->size()  : 1;

    for (int attempt = 1; attempt <= 2; attempt++) {
        vlog::line(verbose, "udp attempt " + std::to_string(attempt) + ": sending " +
                   std::to_string(plen) + "-byte probe", 2);
        int fd = ::socket(family, SOCK_DGRAM, 0);
        if (fd < 0) return {};
        struct timeval tv{ timeout_sec, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::sendto(fd, pbuf, plen, 0,
                 reinterpret_cast<struct sockaddr *>(&addr_storage), addr_len);
        if (attempt == 2)
            ::sendto(fd, "", 0, 0,
                     reinterpret_cast<struct sockaddr *>(&addr_storage), addr_len);
        std::vector<u8> data(CHUNK);
        struct sockaddr_storage from{}; socklen_t fromlen = sizeof(from);
        ssize_t n = ::recvfrom(fd, data.data(), data.size(), 0,
                               reinterpret_cast<struct sockaddr *>(&from), &fromlen);
        ::close(fd);
        if (n > 0) {
            vlog::ok(verbose, "udp attempt " + std::to_string(attempt) + " got " +
                      std::to_string(n) + " bytes", 2);
            data.resize((size_t)n);
            return data;
        }
        vlog::fail(verbose, "udp attempt " + std::to_string(attempt) + ": no response (" +
                   strerror(errno) + ")", 2);
    }
    vlog::fail(verbose, "udp: no response after 2 attempts", 2);
    return {};
}

static std::vector<u8> capture_mqtt(const std::string &ip, int port,
                                    int timeout_sec, bool verbose,
                                    int connect_timeout_sec = 0)
{
    if (connect_timeout_sec <= 0)
        connect_timeout_sec = std::min(3, timeout_sec);

    int fd = connect_with_timeout(ip, port, connect_timeout_sec);
    if (fd < 0) { vlog::fail(verbose, "mqtt connect failed", 2); return {}; }

    set_io_timeouts(fd, timeout_sec);

    std::vector<u8> collected;
    const char CLIENT_ID[] = "scan_probe";
    const int  cid_len     = (int)strlen(CLIENT_ID);

    u8 connect_pkt[64]; int ci = 0;
    connect_pkt[ci++] = 0x10; connect_pkt[ci++] = (u8)(12 + cid_len);
    connect_pkt[ci++] = 0x00; connect_pkt[ci++] = 0x04;
    connect_pkt[ci++] = 'M';  connect_pkt[ci++] = 'Q';
    connect_pkt[ci++] = 'T';  connect_pkt[ci++] = 'T';
    connect_pkt[ci++] = 0x04; connect_pkt[ci++] = 0x02;
    connect_pkt[ci++] = 0x00; connect_pkt[ci++] = 0x3c;
    connect_pkt[ci++] = 0x00; connect_pkt[ci++] = (u8)cid_len;
    memcpy(connect_pkt + ci, CLIENT_ID, cid_len); ci += cid_len;
    ::send(fd, connect_pkt, ci, 0);

    u8 connack[4] = {};
    ssize_t got = ::recv(fd, connack, 4, MSG_WAITALL);
    if (got < 4) {
        vlog::fail(verbose, "mqtt incomplete CONNACK (" + std::to_string(got) + " bytes)", 2);
        collected.insert(collected.end(), connack, connack + got);
        close(fd); return collected;
    }
    collected.insert(collected.end(), connack, connack + 4);
    if (connack[3] != 0) {
        vlog::fail(verbose, "mqtt broker requires auth (rc=" + std::to_string(connack[3]) + ")", 2);
        close(fd); return collected;
    }
    vlog::ok(verbose, "mqtt CONNACK OK", 2);

    const char TOPIC[] = "$SYS/broker/version"; const int tlen = (int)strlen(TOPIC);
    int rem = 2 + 2 + tlen + 1;
    u8 sub_pkt[64]; int si = 0;
    sub_pkt[si++] = 0x82; sub_pkt[si++] = (u8)rem;
    sub_pkt[si++] = 0x00; sub_pkt[si++] = 0x01;
    sub_pkt[si++] = 0x00; sub_pkt[si++] = (u8)tlen;
    memcpy(sub_pkt + si, TOPIC, tlen); si += tlen; sub_pkt[si++] = 0x00;
    ::send(fd, sub_pkt, si, 0);

    char buf[CHUNK];
    while ((int)collected.size() < MAX_RESPONSE && !terminate_flag) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        collected.insert(collected.end(), buf, buf + n);
    }
    close(fd);
    return collected;
}

struct ProbeFileInfo {
    std::set<int>                  ssl_ports;
    std::map<int, std::vector<u8>> tcp_ports;
    std::map<int, std::vector<u8>> udp_ports;
    bool has_tcp(int p) const { return tcp_ports.count(p) > 0; }
    bool has_udp(int p) const { return udp_ports.count(p) > 0; }
};

static std::vector<u8> unescape_probe_string(const std::string &raw)
{
    std::vector<u8> result; result.reserve(raw.size());
    size_t i = 0;
    while (i < raw.size()) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            char c = raw[i + 1];
            if      (c == 'r')  { result.push_back(0x0d); i += 2; }
            else if (c == 'n')  { result.push_back(0x0a); i += 2; }
            else if (c == 't')  { result.push_back(0x09); i += 2; }
            else if (c == '0')  { result.push_back(0x00); i += 2; }
            else if (c == 'x' && i + 3 < raw.size()) {
                std::string hex = raw.substr(i + 2, 2);
                result.push_back((u8)strtol(hex.c_str(), nullptr, 16)); i += 4;
            } else if (isdigit((unsigned char)c)) {
                std::string oct_str; size_t j = i + 1;
                while (j < raw.size() && isdigit((unsigned char)raw[j]) && oct_str.size() < 3)
                    oct_str += raw[j++];
                result.push_back((u8)strtol(oct_str.c_str(), nullptr, 8)); i = j;
            } else if (c == '\\') { result.push_back('\\'); i += 2; }
            else                  { result.push_back((u8)c); i += 2; }
        } else {
            result.push_back((u8)raw[i++]);
        }
    }
    return result;
}

static void substitute_probe_vars(std::vector<u8> &payload,
                                   const std::string &host,
                                   int port)
{
    std::string s(payload.begin(), payload.end());
    auto replace_all = [&](const std::string &from, const std::string &to) {
        size_t pos = 0;
        while ((pos = s.find(from, pos)) != std::string::npos) {
            s.replace(pos, from.size(), to);
            pos += to.size();
        }
    };
    replace_all("%H", host);
    replace_all("%P", std::to_string(port));
    payload.assign(s.begin(), s.end());
}

static std::optional<int> safe_stoi(const std::string &s) {
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos);
        if (pos != s.size()) return std::nullopt;   // trailing junk, e.g. "80x"
        return v;
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

static std::vector<int> expand_port_list(const std::string &token)
{
    std::vector<int> ports;
    std::istringstream ss(token);
    std::string part;
    while (std::getline(ss, part, ',')) {
        while (!part.empty() && isspace((unsigned char)part.front())) part.erase(part.begin());
        while (!part.empty() && isspace((unsigned char)part.back()))  part.pop_back();
        auto dash = part.find('-');
        if (dash != std::string::npos) {
            auto lo = safe_stoi(part.substr(0, dash));
            auto hi = safe_stoi(part.substr(dash + 1));
            if (!lo || !hi) {
                fprintf(stderr, "[!] expand_port_list: skipping malformed range '%s'\n", part.c_str());
                continue;
            }
            for (int p = *lo; p <= *hi; ++p) ports.push_back(p);
        } else if (!part.empty()) {
            auto v = safe_stoi(part);
            if (!v) {
                fprintf(stderr, "[!] expand_port_list: skipping malformed port '%s'\n", part.c_str());
                continue;
            }
            ports.push_back(*v);
        }
    }
    return ports;
}

// Build the port->payload tables from the probes already loaded into AllProbes
// (single source of truth; the probe file is no longer parsed a second time).
// First probe listing a port wins, matching nmap's probe-file order.
// Exclude directives are enforced by ProbeEngine::matchResponse.
static ProbeFileInfo build_probe_file_info(const AllProbes &probes)
{
    ProbeFileInfo info;
    auto add = [&](ServiceProbe *sp) {
        if (!sp) return;
        int len = 0;
        const u8 *ps = sp->getProbeString(&len);
        std::vector<u8> payload;
        if (ps && len > 0 && len <= MAX_RESPONSE) payload.assign(ps, ps + len);
        const int proto = sp->getProtocol();
        auto &table = (proto == IPPROTO_UDP) ? info.udp_ports : info.tcp_ports;
        if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return;
        for (auto it = sp->probablePortsBegin(); it != sp->probablePortsEnd(); ++it)
            if (!table.count((int)*it)) table[(int)*it] = payload;
        if (proto == IPPROTO_TCP) {
            for (auto it = sp->probableSslPortsBegin(); it != sp->probableSslPortsEnd(); ++it) {
                info.ssl_ports.insert((int)*it);
                if (!info.tcp_ports.count((int)*it)) info.tcp_ports[(int)*it] = payload;
            }
        }
    };
    add(probes.nullProbe);
    for (ServiceProbe *sp : probes.probes) add(sp);
    return info;
}

enum class ScanMethod { MQTT, SSL, TCP, UDP, FALLBACK };
struct MethodDecision { ScanMethod method; const std::vector<u8> *payload; };

static MethodDecision decide_method(int port, const ProbeFileInfo &info, bool force_udp)
{
    if (force_udp) {
        auto it = info.udp_ports.find(port);
        return { ScanMethod::UDP, it != info.udp_ports.end() ? &it->second : nullptr };
    }
    if (port == 1883) return { ScanMethod::MQTT, nullptr };
    if (info.ssl_ports.count(port)) {
        auto it = info.tcp_ports.find(port);
        return { ScanMethod::SSL, it != info.tcp_ports.end() ? &it->second : nullptr };
    }
    if (info.has_tcp(port)) {
        auto it = info.tcp_ports.find(port);
        return { ScanMethod::TCP, it != info.tcp_ports.end() ? &it->second : nullptr };
    }
    if (info.has_udp(port)) {
        auto it = info.udp_ports.find(port);
        return { ScanMethod::UDP, it != info.udp_ports.end() ? &it->second : nullptr };
    }
    return { ScanMethod::FALLBACK, nullptr };
}

static std::string bracket_if_ipv6(const std::string &host)
{
    if (!host.empty() && host.front() == '[') return host; // already bracketed
    if (get_ip_version(host.c_str()) == 6) return "[" + host + "]";
    return host;
}

static bool response_is_http_error(const std::vector<u8> &r)
{
    if (r.size() < 12) return false;
    if (r[0]!='H'||r[1]!='T'||r[2]!='T'||r[3]!='P'||r[4]!='/') return false;
    int code = (r[9]-'0')*100 + (r[10]-'0')*10 + (r[11]-'0');
    return (code >= 400 && code <= 599);
}

static const std::vector<std::string> kIpHostFallbacks = {
    "google.com", "azure.com", "microsoft.com"
};

static std::string make_host_header(const std::string &ip, int port, bool is_ssl,
                                    const std::string &override_host = "")
{
    const std::string &raw_host = !override_host.empty() ? override_host
                                : (!g_hostname.empty()   ? g_hostname : ip);
    std::string host = bracket_if_ipv6(raw_host);
    bool default_port = (is_ssl && port == 443) || (!is_ssl && port == 80);
    return default_port ? host : (host + ":" + std::to_string(port));
}
static const char *kDefaultUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36";

static const char *accept_encoding_value()
{
    // Advertise only what decompress_body() can actually decode in this build.
    return "gzip, deflate"
#ifdef HAVE_BROTLI
           ", br"
#endif
#ifdef HAVE_ZSTD
           ", zstd"
#endif
        ;
}

// The request target ends up in a raw HTTP request line: percent-encode anything
// that could break the line (CR/LF, spaces, control and non-ASCII bytes).
static std::string sanitize_request_target(const std::string &path)
{
    std::string out;
    out.reserve(path.size() + 1);
    if (path.empty() || path[0] != '/') out += '/';
    static const char hex[] = "0123456789ABCDEF";
    for (unsigned char c : path) {
        if (c <= 0x20 || c >= 0x7f) { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += (char)c;
    }
    return out;
}

static std::string make_get_request(const std::string &path, const std::string &ip,
                                    int port, bool is_ssl,
                                    const std::string &host_override = "")
{
    return "GET " + sanitize_request_target(path) + " HTTP/1.1\r\n"
           "Host: " + make_host_header(ip, port, is_ssl, host_override) + "\r\n"
           "User-Agent: " + kDefaultUserAgent + "\r\n"
           "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
           "Accept-Language: en-US,en;q=0.5\r\n"
           "Accept-Encoding: " + accept_encoding_value() + "\r\n"
           "Connection: close\r\n\r\n";
}

static HttpFingerprint follow_http_asset(const std::string &ip, int port,
                                         const std::string &path, bool is_ssl,
                                         int timeout_sec, bool verbose)
{
    std::string req = make_get_request(path, ip, port, is_ssl);
    std::vector<u8> payload(req.begin(), req.end());
    std::vector<u8> resp;
    if (is_ssl) {
        TlsCertInfo unused_cert;
        resp = capture_ssl(ip, port, timeout_sec, &payload, verbose, &unused_cert);
    } else {
        resp = capture_tcp(ip, port, timeout_sec, &payload, verbose);
    }
    if (resp.empty()) return HttpFingerprint{};
    return make_http_fingerprint(resp, "asset-follow:" + path, is_ssl);
}

static bool confirm_websocket_upgrade(const std::string &ip, int port,
                                      bool is_ssl, int timeout_sec, bool verbose)
{
    vlog::line(verbose, "websocket-confirm: status suggested possible upgrade -- "
               "sending Upgrade probe to " + ip + ":" + std::to_string(port) +
               (is_ssl ? "  (ssl)" : "  (plain)"), 1);

    std::string req = "GET / HTTP/1.1\r\n"
                       "Host: " + make_host_header(ip, port, is_ssl) + "\r\n"
                       "Connection: Upgrade\r\n"
                       "Upgrade: websocket\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    std::vector<u8> payload(req.begin(), req.end());

    std::vector<u8> resp;
    if (is_ssl) {
        TlsCertInfo unused_cert;
        resp = capture_ssl(ip, port, timeout_sec, &payload, verbose, &unused_cert);
    } else {
        resp = capture_tcp(ip, port, timeout_sec, &payload, verbose);
    }

    if (resp.empty()) {
        vlog::fail(verbose, "websocket-confirm: no response to Upgrade probe", 2);
        return false;
    }

    int code = extract_status_code(resp);
    vlog::line(verbose, "websocket-confirm: got status " + std::to_string(code), 2);
    if (code != 101) {
        vlog::fail(verbose, "websocket-confirm: status != 101 -- not a websocket upgrade", 2);
        return false;
    }

    std::string conn = extract_header(resp, "Connection");
    std::string upg  = extract_header(resp, "Upgrade");
    vlog::kv(verbose, "Connection", conn.empty() ? "(missing)" : conn, 2);
    vlog::kv(verbose, "Upgrade",    upg.empty()  ? "(missing)" : upg,  2);

    std::string conn_lc = conn, upg_lc = upg;
    for (auto &c : conn_lc) c = (char)tolower((unsigned char)c);
    for (auto &c : upg_lc)  c = (char)tolower((unsigned char)c);

    bool ok = conn_lc.find("upgrade")   != std::string::npos
           && upg_lc.find("websocket") != std::string::npos;

    if (ok) vlog::ok(verbose,   "websocket-confirm: Connection/Upgrade headers match -- confirmed", 2);
    else    vlog::fail(verbose, "websocket-confirm: 101 but headers don't confirm websocket -- rejecting", 2);

    return ok;
}

static std::vector<u8> capture_http_get(const std::string &ip, int port,
                                        int timeout_sec, bool verbose)
{

    std::vector<std::string> candidates;
    if (!g_hostname.empty() && (!is_ip_literal(g_hostname) || is_lan_ip(ip))) {
        candidates.push_back(g_hostname);
    } else {
        candidates = kIpHostFallbacks;
        candidates.push_back(ip);
    }

    for (size_t ci = 0; ci < candidates.size(); ++ci) {
        const std::string &host_cand = candidates[ci];
        std::string req = make_get_request("/", ip, port, /*is_ssl=*/false, host_cand);
        std::vector<u8> payload(req.begin(), req.end());
        vlog::line(verbose, "http-get: GET / -> " + ip + ":" + std::to_string(port) +
                   "  Host: " + host_cand, 2);
        auto r = capture_tcp(ip, port, timeout_sec, &payload, verbose);
        if (r.empty()) {
            // TCP connection failed — try next candidate (different Host won't help
            // a dead port, but attempt remaining entries anyway for completeness)
            vlog::fail(verbose, "http-get Host:" + host_cand + " -> no TCP response", 2);
            continue;
        }
        int code = extract_status_code(r);
        if (code == 400 && ci + 1 < candidates.size()) {
            vlog::line(verbose, "http-get Host:" + host_cand +
                       " got 400 Bad Request — trying next fallback host", 2);
            continue;   // 400: move to next Host candidate
        }
        // Any other status (200, 301, 403, 500 …) or 400 on last candidate: use it.
        return r;
    }
    return {};
}

static bool looks_like_tls_record(const std::vector<u8> &resp) {
    if (resp.size() < 5) return false;
    u8 content_type = resp[0];
    u8 ver_major     = resp[1];
    u8 ver_minor     = resp[2];
    if (content_type < 0x14 || content_type > 0x18) return false;
    if (ver_major != 0x03) return false;
    if (ver_minor > 0x04) return false;
    return true;
}

static bool is_redirect(const std::vector<u8> &resp) {
    if (resp.size() < 12) return false;
    std::string s(resp.begin(), resp.begin() + std::min(resp.size(), (size_t)20));
    static const std::regex re(R"(HTTP/[12][. ]\d*\s+3\d\d)");
    std::smatch m;
    return std::regex_search(s, m, re);
}

static std::string extract_location(const std::vector<u8> &resp) {
    const size_t hard_cap = std::min(resp.size(), (size_t)8192);
    size_t header_end = hard_cap;
    for (size_t i = 0; i + 3 < hard_cap; ++i) {
        if (resp[i]=='\r' && resp[i+1]=='\n' && resp[i+2]=='\r' && resp[i+3]=='\n') {
            header_end = i + 4;
            break;
        }
    }

    std::string s(resp.begin(), resp.begin() + (std::ptrdiff_t)header_end);
    static const std::regex re(R"([Ll]ocation:\s*([^\r\n]+))", std::regex::icase);
    std::smatch m;
    if (std::regex_search(s, m, re)) {
        std::string loc = m[1].str();
        while (!loc.empty() && (loc.back() == '\r' || loc.back() == '\n' || loc.back() == ' '))
            loc.pop_back();
        return loc;
    }
    return "";
}

static std::vector<std::string> extract_spa_locations(const std::string &body)
{
    std::vector<std::string> results;
    struct SpaPattern {
        const char *src;
        int         group;
    };
    static const SpaPattern kPatterns[] = {
        // 1. window.location = '...', location.href = '...', etc.
        {
            R"((?:window|document|self|top|parent)?\.?location(?:\.href)?\s*=\s*['"`]([^'"`]+)['"`])",
            1
        },
        // 2. location.replace('...'), location.assign('...')
        {
            R"((?:window|document|self|top|parent)?\.?location\.(?:replace|assign)\s*\(\s*['"`]([^'"`]+)['"`]\s*\))",
            1
        },
        // 3. location = var + '/path.ext'  (concatenation, extension-bounded)
        {
            R"(location(?:\.href)?\s*=\s*.{0,60}\+\s*['"`]([^'"`]+\.(?:html?|php|jsp|js|htm|json|asp|aspx))['"`])",
            1
        },
        // 4. .match(...)[N] + '/suffix'
        {
            R"(\.match\([^)]+\)\[\d\]\s*\+\s*['"`]([^'"`]+)['"`])",
            1
        },
        // 5. Template-literal: location = `...`
        {
            R"(location\s*=\s*`([^`]+)`)",
            1
        },
        // 6. location.pathname = '...'
        {
            R"(location\.pathname\s*=\s*['"`]([^'"`]+)['"`])",
            1
        },
        // 7. Inline event handler: onclick="...location='...'"
        {
            R"(on(?:click|load|submit|change)\s*=\s*['"][^'"]{0,120}location\s*=\s*['"`]([^'"`]+)['"`])",
            1
        },
        // 8. href="javascript:location.href=..."
        {
            R"(href\s*=\s*['"](?:javascript:)?location(?:\.href)?\s*=\s*([^'"]+)['"])",
            1
        },
        // 9. <meta http-equiv="refresh" content="...url=..." or similar>
        {
            R"(<meta[^>]{0,200}url\s*=\s*([^'">\s]+))",
            1
        },
        // 10. Quoted common admin/app paths: '/admin/index.html', '/dashboard.php', etc.
        {
            R"(['"`](/(?:web|admin|dashboard|ui|app|home|login|index)[^'"`]{0,80}\.(?:html?|php|jsp|js|htm|json|asp|aspx))['"`])",
            1
        },
    };

    // Pre-compile all patterns once
    static std::vector<std::regex> compiled;
    static bool compiled_ok = false;
    if (!compiled_ok) {
        compiled_ok = true;
        for (const auto &p : kPatterns) {
            try {
                compiled.emplace_back(p.src,
                    std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
            } catch (...) {
                compiled.emplace_back(); // placeholder so indices stay aligned
            }
        }
    }

    // Cap scan to first 65536 bytes of body to bound worst-case backtracking
    const std::string &scan_body = body.size() > 65536
                                 ? body.substr(0, 65536)
                                 : body;

    for (size_t pi = 0; pi < compiled.size(); ++pi) {
        const auto &re = compiled[pi];
        try {
            auto begin = std::sregex_iterator(scan_body.begin(), scan_body.end(), re);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                const std::smatch &m = *it;
                int grp = kPatterns[pi].group;
                if (grp < (int)m.size() && m[grp].matched) {
                    std::string url = m[grp].str();
                    // Trim whitespace
                    while (!url.empty() && isspace((unsigned char)url.front()))
                        url.erase(url.begin());
                    while (!url.empty() && isspace((unsigned char)url.back()))
                        url.pop_back();
                    // Skip empty, bare-JS, or data: URIs — not routable
                    if (url.empty()) continue;
                    if (url.find("javascript:") == 0) continue;
                    if (url.find("data:")       == 0) continue;
                    if (url.find("mailto:")     == 0) continue;
                    if (url.find("${")  != std::string::npos) continue; // template variable
                    // Skip if url is just a bare variable reference (no slash or dot)
                    bool has_slash_or_dot = false;
                    for (char c : url) {
                        if (c == '/' || c == '.') { has_slash_or_dot = true; break; }
                    }
                    if (!has_slash_or_dot) continue;
                    // Deduplicate
                    bool dup = false;
                    for (const auto &r2 : results) if (r2 == url) { dup = true; break; }
                    if (!dup) results.push_back(url);
                    if (results.size() >= 20) goto spa_done; // cap at 20 per response
                }
            }
        } catch (...) {
        }
    }
spa_done:
    return results;
}

struct ParsedUrl {
    std::string scheme;  
    std::string host;     
    int         port = 0;  
    std::string path;      
    std::string host_hdr;  
    std::string raw_host;
    std::string sni;       // value, not a reference: safe to copy/move/assign
};

static ParsedUrl parse_redirect_url(const std::string &loc,
                                    const std::string &cur_ip,
                                    int                cur_port,
                                    const std::string &cur_scheme)
{
    ParsedUrl out;

    // Relative path — keep everything from the current connection
    if (!loc.empty() && loc[0] == '/') {
        out.scheme   = cur_scheme;
        out.host     = cur_ip;
        out.port     = cur_port;
        out.path     = loc;
        out.host_hdr = cur_ip + ":" + std::to_string(cur_port);
        out.raw_host = cur_ip;   // will be overridden by caller's cur_sni
        out.sni      = cur_ip;
        return out;
    }
    static const std::regex url_re(
        R"(^(https?)://([^\s/:?#]+)(?::(\d+))?((?:/[^\s]*)?)$)",
        std::regex::icase);
    std::smatch m;
    if (!std::regex_match(loc, m, url_re)) {
        // Unparseable — stay on current connection, treat as root
        out.scheme   = cur_scheme;
        out.host     = cur_ip;
        out.port     = cur_port;
        out.path     = "/";
        out.host_hdr = cur_ip + ":" + std::to_string(cur_port);
        out.raw_host = cur_ip;   // will be overridden by caller's cur_sni
        out.sni      = cur_ip;
        return out;
    }

    out.scheme = m[1].str();
    // Convert scheme to lowercase
    for (char &c : out.scheme) c = (char)tolower((unsigned char)c);

    // Resolve the hostname to an IP for connecting
    std::string raw_host = m[2].str();
    out.host = resolve_host(raw_host);

    // Port: explicit > scheme default
    if (m[3].matched && !m[3].str().empty()) {
        const std::string ps = m[3].str();
        long pv = ps.size() <= 5 ? std::strtol(ps.c_str(), nullptr, 10) : 0;
        if (pv < 1 || pv > 65535) {          // bad port: signal failure, caller stops
            out.host.clear();
            out.port = 0;
            out.path = "/";
            return out;
        }
        out.port = (int)pv;
    } else {
        out.port = (out.scheme == "https") ? 443 : 80;
    }

    out.path = m[4].str().empty() ? "/" : m[4].str();
    bool is_default_port = (out.scheme == "https" && out.port == 443) ||
                           (out.scheme == "http"  && out.port == 80);
    out.host_hdr = is_default_port ? raw_host : (raw_host + ":" + std::to_string(out.port));
    out.raw_host = raw_host;
    out.sni      = raw_host;

    return out;
}

static std::vector<u8> follow_redirects_fp(
    const std::string              &origin_ip,    // starting IP
    int                             origin_port,  // starting port
    int                             timeout_sec,
    bool                            verbose,
    std::vector<u8>                 first_resp,
    std::vector<HttpFingerprint>   &http_fps_out,
    bool                            initial_is_ssl,
    int                             max_hops = 8)
{
    std::vector<u8> cur      = std::move(first_resp);
    std::string     cur_ip   = origin_ip;
    int             cur_port = origin_port;
    std::string     cur_scheme = initial_is_ssl ? "https" : "http";
    std::string     cur_sni  = !g_tls_config.sni_name.empty()
                                   ? g_tls_config.sni_name
                                   : origin_ip;

    for (int hop = 0; hop < max_hops && is_redirect(cur); ++hop) {
        std::string loc = extract_location(cur);
        if (loc.empty()) {
            vlog::fail(verbose, "redirect hop " + std::to_string(hop + 1) + ": no Location header, stopping", 2);
            break;
        }

        // -- Fingerprint the source (before following) ----------------------
        bool src_ssl = (cur_scheme == "https");
        std::string phase_src = (src_ssl ? "ssl-" : "") +
                                std::string("redirect-src-hop") + std::to_string(hop + 1);
        HttpFingerprint fp_src = make_http_fingerprint(cur, phase_src, src_ssl);
        fp_src.redirect_url = loc;
        http_fps_out.push_back(fp_src);

        // -- Parse destination URL ------------------------------------------
        ParsedUrl dst = parse_redirect_url(loc, cur_ip, cur_port, cur_scheme);
        bool dst_ssl  = (dst.scheme == "https");

        // For relative-path redirects, parse_redirect_url sets dst.sni = cur_ip
        // which is the resolved IP — carry forward the real hostname instead.
        if (!dst.sni.empty() && dst.sni == cur_ip)
            dst.sni = cur_sni;

        if (dst.host.empty() || dst.port <= 0) {
            vlog::fail(verbose, "redirect hop " + std::to_string(hop + 1) + ": unusable target, stopping", 2);
            break;
        }
        // SSRF guard: a remote target must not be able to steer the scanner at
        // loopback / private / link-local addresses via Location.
        if (dst.host != cur_ip && is_lan_ip(dst.host) && !is_lan_ip(origin_ip)) {
            vlog::fail(verbose, "redirect hop " + std::to_string(hop + 1) + ": refusing redirect to internal address " +
                       dst.host, 2);
            break;
        }
        vlog::line(verbose, "redirect hop " + std::to_string(hop + 1) + ": " + loc + " -> " +
                   dst.scheme + "://" + dst.host + ":" + std::to_string(dst.port) + dst.path +
                   "  (SNI: " + dst.sni + ")", 2);

        if (dst.scheme != cur_scheme || dst.host != cur_ip || dst.port != cur_port)
            vlog::line(verbose, "scheme/host/port change: [" + cur_scheme + " " + cur_ip + ":" +
                       std::to_string(cur_port) + "] -> [" + dst.scheme + " " + dst.host + ":" +
                       std::to_string(dst.port) + "]", 3);

        // -- Build the next request -----------------------------------------
        std::string req = "GET " + sanitize_request_target(dst.path) + " HTTP/1.1\r\n"
                          "Host: " + dst.host_hdr + "\r\n"
                          "User-Agent: Mozilla/5.0\r\n"
                          "Accept: */*\r\n"
                          "Connection: close\r\n\r\n";
        std::vector<u8> payload(req.begin(), req.end());
        std::vector<u8> next;
        TlsCertInfo cert_info;
        if (dst_ssl) {
            next = capture_ssl(dst.host, dst.port, timeout_sec, &payload, verbose,
                               &cert_info, /*connect_timeout_sec=*/0, dst.sni);
        } else {
            next = capture_tcp(dst.host, dst.port, timeout_sec, &payload, verbose);
        }

        if (next.empty()) {
            vlog::fail(verbose, "redirect hop " + std::to_string(hop + 1) + ": no response from " +
                       dst.host + ":" + std::to_string(dst.port) + ", stopping", 2);
            break;
        }

        // -- Fingerprint the destination response ---------------------------
        std::string phase_dst = (dst_ssl ? "ssl-" : "") +
                                std::string("redirect-dst-hop") + std::to_string(hop + 1);
        HttpFingerprint fp_dst = make_http_fingerprint(next, phase_dst, dst_ssl, cert_info);
        http_fps_out.push_back(fp_dst);

        // Advance state for next iteration
        cur        = std::move(next);
        cur_ip     = dst.host;
        cur_port   = dst.port;
        cur_scheme = dst.scheme;
        cur_sni    = dst.sni;   // carry the raw hostname forward for next hop's SNI
    }
    return cur;
}

// -- Thin compatibility wrappers so callers don't need changing -------------
static std::vector<u8> follow_redirects_tcp_fp(
    const std::string &ip, int port, int timeout_sec, bool verbose,
    std::vector<u8> first_resp, std::vector<HttpFingerprint> &fps, int max_hops = 8)
{
    return follow_redirects_fp(ip, port, timeout_sec, verbose,
                               std::move(first_resp), fps, false, max_hops);
}

static std::vector<u8> follow_redirects_ssl_fp(
    const std::string &ip, int port, int timeout_sec, bool verbose,
    std::vector<u8> first_resp, std::vector<HttpFingerprint> &fps, int max_hops = 8)
{
    return follow_redirects_fp(ip, port, timeout_sec, verbose,
                               std::move(first_resp), fps, true, max_hops);
}

struct TwinFpResult {
    std::vector<u8> best_response;  
    bool            ssl_used = false; 
};

static TwinFpResult do_400_ssl_twin_fingerprint(
    const std::string            &ip,
    int                           port,
    int                           timeout_sec,
    bool                          verbose,
    const std::vector<u8>        &plain_4xx_resp,
    std::vector<HttpFingerprint> &http_fps_out)
{
    TwinFpResult result;

    // -- Phase 1: fingerprint the plain 4xx response -----------------------
    HttpFingerprint fp_plain = make_http_fingerprint(plain_4xx_resp, "4xx-plain", /*ssl=*/false);
    http_fps_out.push_back(fp_plain);
    if (verbose) fp_plain.print(std::cerr);
    vlog::line(verbose, "twin-fp: plain HTTP returned " + std::to_string(fp_plain.status_code) +
               " — server likely requires SSL; retrying over TLS for twin fingerprint", 2);

    // -- Phase 2: retry over SSL/TLS ---------------------------------------
    std::string req = make_get_request("/", ip, port, /*is_ssl=*/true);
    std::vector<u8> payload(req.begin(), req.end());
    TlsCertInfo cert_info;
    auto ssl_resp = capture_ssl(ip, port, timeout_sec, &payload, verbose, &cert_info);

    if (ssl_resp.empty()) {
        vlog::fail(verbose, "twin-fp: SSL retry returned no data; keeping 4xx response", 2);
        result.best_response = plain_4xx_resp;
        result.ssl_used      = false;
        return result;
    }

    // -- Phase 3: fingerprint the SSL response -----------------------------
    HttpFingerprint fp_ssl = make_http_fingerprint(ssl_resp, "ssl-after-4xx", /*ssl=*/true,
                                                   cert_info);
    http_fps_out.push_back(fp_ssl);
    if (verbose) fp_ssl.print(std::cerr);

    // -- Phase 4: if the SSL response is also a redirect, follow it --------
    if (fp_ssl.is_redirect) {
        vlog::line(verbose, "twin-fp: SSL response is a " + std::to_string(fp_ssl.status_code) +
                   " redirect — following with dual FP", 2);
        ssl_resp = follow_redirects_ssl_fp(ip, port, timeout_sec, verbose,
                                           std::move(ssl_resp), http_fps_out);
    }

    result.best_response = std::move(ssl_resp);
    result.ssl_used      = true;
    return result;
}

static std::vector<u8> try_source_port_443_fallback(const std::string &ip, int port,
                                                     int timeout_sec, bool verbose,
                                                     const std::vector<u8> &http_payload)
{
    async_io::SourcePort src443;
    src443.mode = async_io::SourcePort::Mode::FIXED;
    src443.port = 443;

    std::lock_guard<std::mutex> lock(g_srcport443_mu);
    vlog::line(verbose, "last resort: retrying with source port 443", 1);
    auto r = capture_tcp(ip, port, timeout_sec, &http_payload, verbose,
                         /*connect_timeout_sec=*/0, src443);
    if (r.empty()) {
        vlog::fail(verbose, "no response even with source port 443 — target likely down/filtered", 1);
    }
    return r;
}

static std::vector<u8> capture_fallback(const std::string            &ip,
                                        int                           port,
                                        int                           timeout_sec,
                                        bool                          verbose,
                                        std::string                  &method_out,
                                        std::vector<HttpFingerprint> &http_fps_out)
{
    const std::string &req_path = g_target_path.empty() ? "/" : g_target_path;
    std::string http_str = make_get_request(req_path, ip, port, /*is_ssl=*/false);
    std::vector<u8> http_payload(http_str.begin(), http_str.end());

    vlog::phase(verbose, "Fallback chain");
    vlog::line(verbose, "trying plain HTTP", 1);
    auto r = capture_tcp(ip, port, timeout_sec, &http_payload, verbose);
    if (!r.empty()) {
        vlog::ok(verbose, "got HTTP response: " + std::to_string(r.size()) + " bytes", 1);
        int code = extract_status_code(r);

        // -- Auto-detect: 4xx on plain HTTP -> twin fingerprint with SSL ----
        if (code >= 400 && code < 500) {
            auto twin = do_400_ssl_twin_fingerprint(ip, port, timeout_sec, verbose,
                                                    r, http_fps_out);
            if (twin.ssl_used) {
                method_out = "ssl-after-4xx";
                return twin.best_response;
            }
            // SSL failed; fall through with the 4xx response
        }

        // -- Auto-detect: 3xx redirect -> dual fingerprint ------------------
        if (is_redirect(r)) {
            r = follow_redirects_tcp_fp(ip, port, timeout_sec, verbose,
                                        std::move(r), http_fps_out);
        } else {
            // Fingerprint a normal (non-redirect, non-4xx) HTTP response
            http_fps_out.push_back(make_http_fingerprint(r, "http-initial", false));
        }

        method_out = "http";
        return r;
    }
    vlog::fail(verbose, "no HTTP response", 1);

    vlog::line(verbose, "trying HTTPS fallback", 1);
    TlsCertInfo https_cert;
    r = capture_ssl(ip, port, timeout_sec, &http_payload, verbose, &https_cert);
    if (!r.empty()) {
        vlog::ok(verbose, "got HTTPS/SSL response: " + std::to_string(r.size()) + " bytes", 1);
        // -- Auto-detect: 3xx redirect over SSL -> dual fingerprint ---------
        if (is_redirect(r)) {
            r = follow_redirects_ssl_fp(ip, port, timeout_sec, verbose,
                                        std::move(r), http_fps_out);
        } else {
            http_fps_out.push_back(make_http_fingerprint(r, "https-initial", true, https_cert));
        }
        method_out = "Default TLS";
        return r;
    }
    vlog::fail(verbose, "no HTTPS/SSL response", 1);
    r = try_source_port_443_fallback(ip, port, timeout_sec, verbose, http_payload);
    if (!r.empty()) {
        int code = extract_status_code(r);
        if (code >= 400 && code < 500) {
            auto twin = do_400_ssl_twin_fingerprint(ip, port, timeout_sec, verbose,
                                                    r, http_fps_out);
            if (twin.ssl_used) {
                method_out = "ssl-after-4xx/srcport443";
                return twin.best_response;
            }
        }
        if (is_redirect(r)) {
            r = follow_redirects_tcp_fp(ip, port, timeout_sec, verbose,
                                        std::move(r), http_fps_out);
        } else {
            http_fps_out.push_back(make_http_fingerprint(r, "http-srcport443", false));
        }
        method_out = "http/srcport443";
        return r;
    }

    method_out = "none";
    return {};
}

// Follow the first SPA-style client-side redirect (JS location / meta-refresh) found
// in the fingerprints. Same safety rules as real redirects: scheme must be http(s),
// no hops onto internal addresses from a public target, one hop only.
static bool follow_spa_location(const std::string &ip, int port, bool is_ssl,
                                int timeout_sec, bool verbose,
                                std::vector<HttpFingerprint> &fps)
{
    std::string loc;
    for (const auto &fp : fps) {
        if (!fp.is_redirect && !fp.spa_locations.empty()) { loc = fp.spa_locations[0]; break; }
    }
    if (loc.empty() || loc.size() > 2048) return false;
    if (loc[0] != '/' && loc.rfind("http://", 0) != 0 && loc.rfind("https://", 0) != 0 &&
        loc.rfind("HTTP://", 0) != 0 && loc.rfind("HTTPS://", 0) != 0)
        return false;   // javascript:, data:, bare words, ...

    ParsedUrl dst = parse_redirect_url(loc, ip, port, is_ssl ? "https" : "http");
    if (dst.host.empty() || dst.port <= 0) return false;
    if (dst.host != ip && is_lan_ip(dst.host) && !is_lan_ip(ip)) {
        vlog::fail(verbose, "spa-follow: refusing internal address " + dst.host, 2);
        return false;
    }
    const bool dst_ssl = (dst.scheme == "https");
    if (dst.host == ip && dst.port == port && dst_ssl == is_ssl && dst.path == "/") return false; // same page

    vlog::line(verbose, "spa-follow: " + loc + " -> " + dst.scheme + "://" + dst.host + ":" +
               std::to_string(dst.port) + dst.path, 1);
    std::string req = "GET " + sanitize_request_target(dst.path) + " HTTP/1.1\r\n"
                      "Host: " + dst.host_hdr + "\r\n"
                      "User-Agent: " + std::string(kDefaultUserAgent) + "\r\n"
                      "Accept: */*\r\n"
                      "Connection: close\r\n\r\n";
    std::vector<u8> payload(req.begin(), req.end());
    std::vector<u8> resp;
    TlsCertInfo cert;
    if (dst_ssl) resp = capture_ssl(dst.host, dst.port, timeout_sec, &payload, verbose, &cert, 0, dst.sni);
    else         resp = capture_tcp(dst.host, dst.port, timeout_sec, &payload, verbose);
    if (resp.empty()) return false;
    fps.push_back(make_http_fingerprint(resp, std::string(dst_ssl ? "ssl-" : "") + "spa-follow", dst_ssl, cert));
    return true;
}

struct Args {
    // Raw target string (argv[1]) — kept for display only
    std::string target_raw;
    // Resolved fields (filled by parse_target + main)
    std::string ip;          // numeric IPv4 (after DNS resolution)
    std::string hostname;    // original hostname (used for SNI, Host header)
    std::string scheme;      // "http" | "https" | "" (auto-detect)
    std::string path;        // request path (default "/")
    uint16_t    port           = 0;
    int         timeout        = 3;   // read/response timeout (seconds)
    int         connect_timeout = 0;  // TCP SYN→ACK timeout; 0 = use timeout value
    int         intensity   = 7;
    bool        udp         = false;
    bool        force_raw   = false;
    bool        force_http  = false;
    bool        force_https = false;
    bool        verbose     = false;
    std::string save_file;
    // TLS certificate options
    std::string tls_ca_file;
    std::string tls_ca_path;
    std::string tls_cert;
    std::string tls_key;
    std::string tls_sni;
    bool        tls_verify = false;
    // --host override: if set, this value is used verbatim in the Host: header
    std::string host_override;
};

static int probe_read_timeout(const AllProbes &probes, int port,
                              int proto, int default_sec)
{
    int best_ms = 0;
    for (ServiceProbe *sp : probes.probes) {
        if (sp->getProtocol() != proto) continue;
        if (sp->portIsProbable(ServiceTunnel::NONE, (u16)port) ||
            sp->portIsProbable(ServiceTunnel::SSL,  (u16)port)) {
            int ms = sp->getTotalWaitMs();
            if (ms > best_ms) best_ms = ms;
        }
    }
    if (probes.nullProbe) {
        int ms = probes.nullProbe->getTotalWaitMs();
        if (ms > best_ms) best_ms = ms;
    }

    int probe_sec = (best_ms > 0) ? std::max(1, (best_ms + 999) / 1000) : 0;

    return std::max(default_sec, probe_sec);
}

int run_version_probe(AllProbes &probes, const std::string &target_ip,
                       uint16_t target_port, const VersionDetectOptions &opts)
{
    if (opts.reactor_threads) {
        static std::once_flag reactor_cfg_once;
        std::call_once(reactor_cfg_once, [&] { async_io::configure_shared_reactor(opts.reactor_threads); });
    }
    Args args;
    args.hostname       = target_ip;
    args.port           = target_port;
    args.ip             = target_ip;
    const std::string &ip = args.ip;
    args.verbose        = opts.verbose;
    args.timeout        = opts.timeout_sec;
    args.connect_timeout = opts.connect_timeout_sec;
    args.intensity      = opts.intensity;
    args.udp            = opts.udp;
    args.force_raw      = opts.force_raw;
    args.force_http     = opts.force_http;
    args.force_https    = opts.force_https;
    args.tls_verify     = opts.tls_verify;
    args.save_file      = opts.save_file;
    args.tls_ca_file    = opts.tls_ca_file;
    args.tls_ca_path    = opts.tls_ca_path;
    args.tls_cert       = opts.tls_cert;
    args.tls_key        = opts.tls_key;
    args.tls_sni        = opts.tls_sni;
    args.host_override  = opts.host_override;
    args.path           = opts.request_path.empty() ? "/" : opts.request_path;
    if (args.path.front() != '/') args.path.insert(args.path.begin(), '/');
    // Reject CR/LF/whitespace: the path is written into a raw HTTP request line.
    for (char &c : args.path) if (c == '\r' || c == '\n' || c == ' ' || (unsigned char)c < 0x20) c = '_';
    args.target_raw     = target_ip + ":" + std::to_string(target_port);
    args.scheme         = opts.force_https ? "https" : opts.force_http ? "http" : "";
    std::string effective_host;
    {
        g_tuning.max_response_bytes  = opts.max_response_bytes;
        g_tuning.ciphers_tls12       = opts.tls_ciphers_tls12;
        g_tuning.ciphersuites_tls13  = opts.tls_ciphersuites_tls13;
        g_tuning.min_connect_ms      = opts.min_connect_ms;
        g_tls_config = TlsConfig{};
        g_verbose = args.verbose;

        g_tls_config.ca_file     = args.tls_ca_file;
        g_tls_config.ca_path     = args.tls_ca_path;
        g_tls_config.client_cert = args.tls_cert;
        g_tls_config.client_key  = args.tls_key;
        g_tls_config.verify_peer = args.tls_verify;
        vlog::phase(g_verbose, "Resolving host");
        if (!args.host_override.empty()) {
            effective_host = args.host_override;
            vlog::line(g_verbose, "--host override: using '" + effective_host + "' in Host: header");
        } else if (is_ip_literal(args.hostname)) {
            if (is_lan_ip(args.hostname)) {
                effective_host = args.hostname;
                vlog::line(g_verbose, "LAN IP " + args.hostname + ": skipping reverse-DNS, using IP directly");
            } else {
                std::string rdns = resolve_ip_to_domain(args.hostname);
                if (!rdns.empty()) {
                    effective_host = rdns;
                    vlog::ok(g_verbose, "reverse-DNS " + args.hostname + " -> '" + rdns + "'; using domain in Host: header");
                } else {
                    effective_host = args.hostname;
                    vlog::fail(g_verbose, "reverse-DNS for " + args.hostname + " failed; using IP in Host: header");
                }
            }
        } else {
            effective_host = args.hostname;
        }

        g_tls_config.sni_name = args.tls_sni.empty() ? effective_host : args.tls_sni;

        g_hostname    = effective_host;
        g_target_path = args.path.empty() ? "/" : args.path;
    }

    vlog::phase(g_verbose, "Target");
    vlog::kv(g_verbose, "Target",   args.target_raw);
    vlog::kv(g_verbose, "Host",     args.hostname);
    vlog::kv(g_verbose, "Host Hdr", g_hostname);
    vlog::kv(g_verbose, "IP",       ip);
    vlog::kv(g_verbose, "Port",     std::to_string(args.port));
    vlog::kv(g_verbose, "Scheme",   args.scheme.empty() ? "auto-detect" : args.scheme);
    vlog::kv(g_verbose, "Path",     args.path);

    if (args.verbose) {
        vlog::phase(g_verbose, "TLS configuration");
        vlog::kv(g_verbose, "SNI",         g_tls_config.sni_name);
        vlog::kv(g_verbose, "CA file",     args.tls_ca_file.empty() ? "(system default)" : args.tls_ca_file);
        vlog::kv(g_verbose, "Verify peer", args.tls_verify ? "yes" : "no (info-only)");
        if (!args.tls_cert.empty())
            vlog::kv(g_verbose, "Client cert", args.tls_cert);
    }
    vlog::kv(g_verbose, "Timeouts", "connect=" + std::to_string(args.connect_timeout) + "s  read=" +
              std::to_string(args.timeout) + "s  idle=" + std::to_string(std::max(2, args.timeout / 2)) + "s");

    const ProbeFileInfo pfi = build_probe_file_info(probes);

    std::vector<u8>              response;
    std::string                  response_probe;      // probe whose payload produced `response` (match hint)
    long                         null_close_ms = -1;  // NULL probe: peer closed with no data after this many ms
    std::string                  method_label;
    int                          proto_int = IPPROTO_TCP;
    std::vector<HttpFingerprint> http_fps;

    if (args.udp) proto_int = IPPROTO_UDP;
    const int read_to = probe_read_timeout(probes, args.port, proto_int, args.timeout);
    vlog::kv(g_verbose, "Effective", "connect=" + std::to_string(args.connect_timeout) + "s  read=" +
              std::to_string(read_to) + "s (" + (read_to > args.timeout ? "probe-derived" : "user --timeout") +
              ")  idle=" + std::to_string(std::max(2, read_to / 2)) + "s");

    vlog::phase(g_verbose, "Capture");

    if (args.udp) {
        vlog::line(g_verbose, "capturing UDP response from " + ip + ":" + std::to_string(args.port), 1);
        auto dec = decide_method(args.port, pfi, true);

        std::vector<u8> udp_payload;
        const std::vector<u8> *pl = dec.payload;
        if (pl && !pl->empty()) {
            udp_payload = *pl;
            const std::string &probe_host = g_hostname.empty() ? ip : g_hostname;
            substitute_probe_vars(udp_payload, probe_host, args.port);
            pl = &udp_payload;
        }
        response = capture_udp(ip, args.port, read_to, pl, args.verbose);
        method_label = "udp";
        if (response.empty())
            vlog::fail(g_verbose, "udp: no response from " + ip + ":" + std::to_string(args.port), 1);

    } else if (args.force_raw) {
        vlog::line(g_verbose, "capturing raw TCP banner from " + ip + ":" + std::to_string(args.port), 1);
        response = capture_tcp(ip, args.port, read_to, nullptr, args.verbose,
                               args.connect_timeout);
        method_label = "raw_tcp";

    } else if (args.force_http) {
        vlog::line(g_verbose, "capturing HTTP response from " + ip + ":" + std::to_string(args.port) +
                   "  path: " + g_target_path, 1);
        std::string hs = make_get_request(g_target_path, ip, args.port, false);
        std::vector<u8> payload(hs.begin(), hs.end());
        response = capture_tcp(ip, args.port, read_to, &payload, args.verbose,
                               args.connect_timeout);
        method_label = "http";

        if (!response.empty()) {
            int code = extract_status_code(response);

            if (code >= 400 && code < 500) {
                vlog::line(g_verbose, "force-http: got " + std::to_string(code) +
                           " -> attempting 400-SSL twin fingerprint", 1);
                auto twin = do_400_ssl_twin_fingerprint(ip, args.port, read_to,
                                                        args.verbose, response, http_fps);
                if (twin.ssl_used) {
                    response     = std::move(twin.best_response);
                    method_label = "ssl-after-4xx";
                }
            }
            else if (is_redirect(response)) {
                response = follow_redirects_tcp_fp(ip, args.port, read_to,
                                                   args.verbose, std::move(response),
                                                   http_fps);
                method_label = "http-redirect";
            } else {
                http_fps.push_back(make_http_fingerprint(response, "http-initial", false));
            }
        }

    } else if (args.force_https) {
        vlog::line(g_verbose, "capturing HTTPS response from " + ip + ":" + std::to_string(args.port) +
                   "  path: " + g_target_path, 1);
        std::string hs = make_get_request(g_target_path, ip, args.port, true);
        std::vector<u8> payload(hs.begin(), hs.end());
        TlsCertInfo https_cert;
        response = capture_ssl(ip, args.port, read_to, &payload, args.verbose,
                               &https_cert, args.connect_timeout);
        method_label = "https";

        if (!response.empty()) {
            if (is_redirect(response)) {
                response = follow_redirects_ssl_fp(ip, args.port, read_to,
                                                   args.verbose, std::move(response),
                                                   http_fps);
                method_label = "https-redirect";
            } else {
                http_fps.push_back(make_http_fingerprint(response, "https-initial", true, https_cert));
            }
        }

    } else {
        auto dec = decide_method(args.port, pfi, false);
        if (dec.method == ScanMethod::MQTT) {
            vlog::line(g_verbose, "probe file: port " + std::to_string(args.port) + " -> MQTT handshake", 1);
            response = capture_mqtt(ip, args.port, read_to, args.verbose,
                                    args.connect_timeout);
            method_label = "mqtt";
            goto capture_done;
        }

        if (dec.method == ScanMethod::UDP) {
            proto_int = IPPROTO_UDP;
            vlog::line(g_verbose, "auto-detected UDP for port " + std::to_string(args.port) +
                       " (probe file has no TCP entry)", 1);
            std::vector<u8> udp_payload;
            const std::vector<u8> *pl = dec.payload;
            if (pl && !pl->empty()) {
                udp_payload = *pl;
                substitute_probe_vars(udp_payload, ip, args.port);
                pl = &udp_payload;
            }
            response = capture_udp(ip, args.port, read_to, pl, args.verbose);
            method_label = "udp";
            if (response.empty())
                vlog::fail(g_verbose, "udp: no response from " + ip + ":" + std::to_string(args.port), 1);
            goto capture_done;
        }
        bool is_ssl = false;
        if (dec.method == ScanMethod::SSL) {
            is_ssl = true;
            if (args.verbose) {
                vlog::line(g_verbose, "port " + std::to_string(args.port) +
                           " is declared as sslports -- verifying TLS support (diagnostic only)", 1);
                TlsCertInfo ssl_check_cert;
                bool strict_ok = ssl_port_check(ip, args.port, 3, args.verbose, &ssl_check_cert);
                if (!strict_ok) {
                    vlog::fail(g_verbose, "strict TLS handshake failed on port " + std::to_string(args.port) +
                               "; retrying with permissive SSL for diagnostics", 2);
                    TlsCertInfo perm_cert;
                    auto perm_test = capture_ssl_permissive(
                        ip, args.port, 3, nullptr, args.verbose, &perm_cert, args.connect_timeout);
                    if (!perm_test.empty() || !perm_cert.tls_version.empty())
                        vlog::ok(g_verbose, "permissive SSL handshake succeeded on port " +
                                 std::to_string(args.port) + " (version: " + perm_cert.tls_version + ")", 2);
                    else
                        vlog::fail(g_verbose, "permissive SSL also failed on port " + std::to_string(args.port) +
                                   "; port is declared sslports -- keeping SSL mode (not falling back to plain TCP)", 2);
                }
            }
        } else {
            {   // Always run: the result changes behaviour (is_ssl), so it must not depend on --verbose
                int precheck_to = std::min(2, args.connect_timeout > 0 ? args.connect_timeout : 2);
                vlog::line(g_verbose, "port " + std::to_string(args.port) + " not declared as sslports -- "
                           "running diagnostic TLS pre-check (timeout=" + std::to_string(precheck_to) +
                           "s); real probing will still self-detect TLS if this is skipped", 1);
                if (ssl_port_check(ip, args.port, precheck_to, args.verbose)) {
                    vlog::ok(g_verbose, "TLS confirmed on port " + std::to_string(args.port) +
                             " despite not being in sslports; switching to SSL mode", 2);
                    is_ssl = true;
                }
            }
        }

        struct ProbeAttempt { std::string name; std::vector<u8> payload; };
        std::vector<ProbeAttempt> attempts;
        std::set<std::string>     seen;

        auto add_attempt = [&](const std::string &name, const u8 *ps, int pslen) {
            if (!seen.insert(name).second) return;
            ProbeAttempt pa; pa.name = name;
            if (ps && pslen > 0) pa.payload.assign(ps, ps + pslen);
            attempts.push_back(std::move(pa));
        };

        vlog::phase(g_verbose, "Probe planning");

        if (probes.nullProbe) {
            int plen = 0; const u8 *ps = probes.nullProbe->getProbeString(&plen);
            vlog::line(g_verbose, std::string("phase 1: adding NULL probe '") + probes.nullProbe->getName() + "'", 1);
            add_attempt(probes.nullProbe->getName(), ps, plen);
        }

        int phase2_count = 0;
        for (ServiceProbe *sp : probes.probes) {
            if (sp->getProtocol() != IPPROTO_TCP) continue;
            if (!sp->portIsProbable(is_ssl ? ServiceTunnel::SSL : ServiceTunnel::NONE,
                                    (u16)args.port)) continue;
            int plen = 0; const u8 *ps = sp->getProbeString(&plen);
            vlog::line(g_verbose, "phase 2: port " + std::to_string(args.port) + " explicit -> probe '" +
                       sp->getName() + "' (rarity " + std::to_string(sp->getRarity()) + ")", 1);
            add_attempt(sp->getName(), ps, plen);
            phase2_count++;
        }
        if (phase2_count == 0)
            vlog::line(g_verbose, "phase 2: no probes explicitly list port " + std::to_string(args.port), 1);

        int phase3_count = 0;
        for (ServiceProbe *sp : probes.probes) {
            if (sp->getProtocol() != IPPROTO_TCP) continue;
            if (sp->portIsProbable(is_ssl ? ServiceTunnel::SSL : ServiceTunnel::NONE,
                                   (u16)args.port)) continue;
            if (sp->getRarity() > args.intensity) continue;
            int plen = 0; const u8 *ps = sp->getProbeString(&plen);
            vlog::line(g_verbose, "phase 3: rarity " + std::to_string(sp->getRarity()) + " <= intensity " +
                       std::to_string(args.intensity) + " -> probe '" + sp->getName() + "'", 1);
            add_attempt(sp->getName(), ps, plen);
            phase3_count++;
        }
        vlog::line(g_verbose, "phase 3: added " + std::to_string(phase3_count) +
                   " non-explicit probes (intensity cap: " + std::to_string(args.intensity) + ")", 1);
        vlog::kv(g_verbose, "Queued", std::to_string(attempts.size()) + " probes for port " +
                  std::to_string(args.port));

        vlog::phase(g_verbose, "Probing");

        for (size_t attempt_idx = 0; attempt_idx < attempts.size() && !terminate_flag; ++attempt_idx) {
            const ProbeAttempt &pa = attempts[attempt_idx];

            vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": " + pa.name +
                       "  (ssl: " + (is_ssl ? "yes" : "no") + ")", 1);

            if (pa.payload.empty()) {
                vlog::line(g_verbose, "payload: none (NULL banner grab)", 2);
            } else if (g_verbose) {
                std::string escaped;
                escaped.reserve(pa.payload.size());
                for (unsigned char c : pa.payload) {
                    if      (c == '\r') escaped += "\\r";
                    else if (c == '\n') escaped += "\\n";
                    else if (c == '\t') escaped += "\\t";
                    else if (c == '\\') escaped += "\\\\";
                    else if (c == '"')  escaped += "\\\"";
                    else if (c < 32 || c >= 127) {
                        char buf[6]; snprintf(buf, sizeof(buf), "\\x%02x", c);
                        escaped += buf;
                    } else escaped += (char)c;
                }
                vlog::line(g_verbose, "payload: " + std::to_string(pa.payload.size()) +
                           " bytes -- \"" + escaped + "\"", 2);
            }
            std::vector<u8> substituted_payload;
            const std::vector<u8> *pl = nullptr;

            if (!pa.payload.empty()) {
                substituted_payload = pa.payload;
                const std::string &probe_host = g_hostname.empty() ? ip : g_hostname;
                substitute_probe_vars(substituted_payload, probe_host, args.port);

                {
                    std::string s(substituted_payload.begin(), substituted_payload.end());
                    // NOTE: previously only matched "HTTP/1.1", which silently skipped this
                    // whole fixup for HTTP/1.0 probes -- including the stock GetRequest probe
                    // ("GET / HTTP/1.0\r\n\r\n"), the single most common probe run against any
                    // web port. HTTP/1.0 is legal without Host:, but plenty of real-world
                    // virtual-hosted/CDN-fronted targets need it anyway, so treat both versions
                    // the same way here.
                    bool is_http_req = (s.size() >= 4 &&
                        (s.rfind("GET ",  0) == 0 ||
                         s.rfind("HEAD ", 0) == 0 ||
                         s.rfind("POST ", 0) == 0) &&
                        (s.find("HTTP/1.1") != std::string::npos ||
                         s.find("HTTP/1.0") != std::string::npos));

                    if (is_http_req) {
                        std::string sl = s;
                        for (char &c : sl) c = (char)tolower((unsigned char)c);
                        bool has_host = sl.find("\r\nhost:") != std::string::npos ||
                                        sl.rfind("host:", 0) == 0;

                        if (!has_host) {
                            std::string host_val = make_host_header(ip, args.port, is_ssl);
                            size_t term = s.find("\r\n\r\n");
                            if (term != std::string::npos) {
                                s = s.substr(0, term) +
                                    "\r\nHost: " + host_val +
                                    s.substr(term);
                                vlog::line(g_verbose, "probe-fixup: injected Host: " + host_val +
                                           " into HTTP probe (was missing)", 2);
                            }
                        }

                        {
                            std::string sl2 = s;
                            for (char &c : sl2) c = (char)tolower((unsigned char)c);
                            bool has_ua = sl2.find("\r\nuser-agent:") != std::string::npos ||
                                         sl2.rfind("user-agent:", 0) == 0;
                            if (!has_ua) {
                                size_t term2 = s.find("\r\n\r\n");
                                if (term2 != std::string::npos) {
                                    s = s.substr(0, term2) +
                                        "\r\nUser-Agent: " + std::string(kDefaultUserAgent) +
                                        s.substr(term2);
                                    vlog::line(g_verbose, "probe-fixup: injected User-Agent "
                                               "into HTTP probe (was missing)", 2);
                                }
                            }
                        }

                        substituted_payload.assign(s.begin(), s.end());
                    }
                }

                pl = &substituted_payload;
            }

            std::vector<u8> r;
            TlsCertInfo probe_cert;
            const int probe_first_byte_to = 3;
            if (is_ssl) {
                r = capture_ssl(ip, args.port, probe_first_byte_to, pl, args.verbose,
                                &probe_cert, args.connect_timeout);
                if (r.empty() && !terminate_flag) {
                    vlog::line(args.verbose, "probe #" + std::to_string(attempt_idx) +
                               ": strict SSL returned empty; retrying with permissive SSL", 2);
                    TlsCertInfo perm_cert2;
                    r = capture_ssl_permissive(ip, args.port, probe_first_byte_to, pl,
                                               args.verbose, &perm_cert2,
                                               args.connect_timeout);
                    if (!r.empty() && !perm_cert2.tls_version.empty())
                        probe_cert = perm_cert2;
                }
            } else {
                r = capture_tcp(ip, args.port, probe_first_byte_to, pl, args.verbose,
                                args.connect_timeout);
            }
            if (!is_ssl && pa.payload.empty() && r.empty() && g_last_tcp.eof_no_data)
                null_close_ms = g_last_tcp.elapsed_ms;

            bool switched_to_ssl_midstream = false;
            if (!r.empty()) {
                if (!is_ssl && looks_like_tls_record(r)) {
                    char tls_hdr[16];
                    snprintf(tls_hdr, sizeof(tls_hdr), "0x%02x 0x%02x 0x%02x", r[0], r[1], r[2]);
                    vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + " '" + pa.name +
                               "' got " + std::to_string(r.size()) + " byte(s) that look like a raw TLS "
                               "record (" + tls_hdr + ") on a plaintext attempt -- port is actually TLS; "
                               "switching to SSL and retrying this probe instead of accepting it", 2);

                    is_ssl = true;
                    switched_to_ssl_midstream = true;

                    TlsCertInfo retry_cert;
                    std::vector<u8> r_ssl = capture_ssl(ip, args.port, probe_first_byte_to, pl,
                                                        args.verbose, &retry_cert,
                                                        args.connect_timeout);
                    if (r_ssl.empty() && !terminate_flag) {
                        TlsCertInfo retry_perm_cert;
                        r_ssl = capture_ssl_permissive(ip, args.port, probe_first_byte_to, pl,
                                                       args.verbose, &retry_perm_cert,
                                                       args.connect_timeout);
                    }

                    if (r_ssl.empty()) {
                        vlog::fail(g_verbose, "probe #" + std::to_string(attempt_idx) +
                                   ": SSL retry also produced nothing usable; discarding the "
                                   "TLS-alert bytes and trying next probe over SSL", 2);
                        continue;
                    }
                    r = std::move(r_ssl);
                }
                bool is_null_probe = pa.payload.empty();
                if (is_null_probe) {
                    int null_code = extract_status_code(r);
                    bool looks_http = (r.size() >= 5 &&
                                       r[0]=='H' && r[1]=='T' && r[2]=='T' &&
                                       r[3]=='P' && r[4]=='/');
                    if (looks_http && null_code != 0 && null_code != 200) {
                        vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": NULL probe got HTTP " +
                                   std::to_string(null_code) + " (not 200) on port " + std::to_string(args.port) +
                                   " -- web port, NULL probe incompatible; skipping to next probe", 2);
                        continue;
                    }
                }

                if (args.port == 9100 && pa.name == "hp-pjl" && response_is_http_error(r)) {
                    vlog::line(g_verbose, "port 9100: hp-pjl got HTTP error -- likely HTTP service, "
                               "not a printer; retrying with HTTP GET", 2);
                    auto hr = capture_http_get(ip, args.port, read_to, args.verbose);
                    if (!hr.empty()) {
                        vlog::ok(g_verbose, "port 9100: HTTP GET succeeded (" + std::to_string(hr.size()) +
                                 " bytes)", 2);
                        response     = std::move(hr);
                        method_label = "http/port9100-fallback";
                        goto capture_done;
                    }
                    vlog::fail(g_verbose, "port 9100: HTTP GET also failed, keeping hp-pjl response", 2);
                }
                bool probe_is_http_req = false;
                if (!pa.payload.empty() && pa.payload.size() >= 4) {
                    std::string ps_start(pa.payload.begin(),
                                         pa.payload.begin() + std::min(pa.payload.size(), (size_t)5));
                    probe_is_http_req = (ps_start.rfind("GET /", 0) == 0 ||
                                        ps_start.rfind("HEAD ", 0) == 0 ||
                                        ps_start.rfind("POST ", 0) == 0);
                }
                if (!probe_is_http_req && (!is_ssl || switched_to_ssl_midstream)) {
                    int non_http_code = extract_status_code(r);
                    bool looks_http_resp = (r.size() >= 5 &&
                                            r[0]=='H' && r[1]=='T' && r[2]=='T' &&
                                            r[3]=='P' && r[4]=='/');
                    if (looks_http_resp && non_http_code == 400) {
                        vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": non-HTTP probe '" +
                                   pa.name + "' got HTTP 400 Bad Request -> server is likely HTTP; "
                                   "falling back to GET / HTTP/1.1", 2);

                        const std::string &probe_host = g_hostname.empty() ? ip : g_hostname;
                        std::string get_req = "GET " + sanitize_request_target(g_target_path) + " HTTP/1.1\r\n"
                                             "Host: " + probe_host + "\r\n"
                                             "User-Agent: " + std::string(kDefaultUserAgent) + "\r\n"
                                             "Accept: */*\r\n"
                                             "Connection: close\r\n\r\n";
                        std::vector<u8> get_payload(get_req.begin(), get_req.end());

                        std::vector<u8> hr;
                        TlsCertInfo fallback_cert;
                        if (is_ssl) {
                            hr = capture_ssl(ip, args.port, read_to, &get_payload, args.verbose,
                                             &fallback_cert, args.connect_timeout);
                        } else {
                            hr = capture_tcp(ip, args.port, read_to, &get_payload, args.verbose,
                                             args.connect_timeout);
                        }
                        if (!hr.empty()) {
                            int hr_code = extract_status_code(hr);
                            vlog::ok(g_verbose, "probe #" + std::to_string(attempt_idx) + ": HTTP GET fallback got " +
                                     std::to_string(hr_code) + " (" + std::to_string(hr.size()) +
                                     " bytes) -- using this response", 2);
                            if (is_redirect(hr)) {
                                hr = follow_redirects_tcp_fp(ip, args.port, read_to,
                                                             args.verbose, std::move(hr),
                                                             http_fps);
                                method_label = "http-get-fallback-redirect/" + pa.name;
                            } else {
                                http_fps.push_back(
                                    make_http_fingerprint(hr, "http-get-fallback", is_ssl));
                                method_label = "http-get-fallback/" + pa.name;
                            }
                            response = std::move(hr);
                            goto capture_done;
                        }
                        vlog::fail(g_verbose, "probe #" + std::to_string(attempt_idx) +
                                   ": HTTP GET fallback also got no response; keeping original 400", 2);
                    }
                }

                // NOTE: previously gated on `!is_ssl`, so an HTTP probe (GET/HEAD/POST)
                // that got a 4xx over SSL/TLS -- e.g. the stock GetRequest probe hitting
                // a virtual-hosted HTTPS target without a Host: header -- had no retry
                // path at all and the raw 400 was accepted as final. Now both transports
                // are handled: plaintext keeps the original SSL-twin-fingerprint check
                // (in case the port actually needs SSL), SSL retries directly with a
                // proper Host-bearing GET over the same TLS connection.
                if (probe_is_http_req) {
                    int code = extract_status_code(r);
                    if (code >= 400 && code < 500) {
                        if (!is_ssl) {
                        vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": HTTP probe '" +
                                   pa.name + "' got " + std::to_string(code) + " -> trying 400-SSL twin FP", 2);
                        auto twin = do_400_ssl_twin_fingerprint(ip, args.port, read_to,
                                                                args.verbose, r, http_fps);
                        if (twin.ssl_used) {
                            response     = std::move(twin.best_response);
                            method_label = "ssl-after-4xx/" + pa.name;
                            goto capture_done;
                        }
                        vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": SSL failed; probe may "
                                   "have sent Host-less request -> retrying with proper Host: header GET", 2);
                        auto hr = capture_http_get(ip, args.port, read_to, args.verbose);
                        if (!hr.empty()) {
                            int hr_code = extract_status_code(hr);
                            vlog::ok(g_verbose, "probe #" + std::to_string(attempt_idx) + ": Host-header retry got " +
                                     std::to_string(hr_code) + " (" + std::to_string(hr.size()) +
                                     " bytes) -- using this response", 2);
                            if (is_redirect(hr)) {
                                hr = follow_redirects_tcp_fp(ip, args.port, read_to,
                                                             args.verbose, std::move(hr),
                                                             http_fps);
                                method_label = "http-host-retry-redirect/" + pa.name;
                            } else {
                                http_fps.push_back(
                                    make_http_fingerprint(hr, "http-host-retry", false));
                                method_label = "http-host-retry/" + pa.name;
                            }
                            response = std::move(hr);
                            goto capture_done;
                        }
                        vlog::fail(g_verbose, "probe #" + std::to_string(attempt_idx) +
                                   ": Host-header retry also got no response; keeping original 400", 2);
                        } else {
                            // Already on SSL -- do_400_ssl_twin_fingerprint (plaintext-to-SSL
                            // switch) and capture_http_get (plaintext-only) don't apply here.
                            // Retry directly over SSL with a well-formed, Host-bearing GET.
                            vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": HTTP probe '" +
                                       pa.name + "' got " + std::to_string(code) + " over SSL; probe may "
                                       "have sent Host-less request -> retrying with proper Host: header GET "
                                       "over SSL", 2);
                            std::string get_req_ssl = make_get_request(g_target_path, ip, args.port, is_ssl);
                            std::vector<u8> get_payload_ssl(get_req_ssl.begin(), get_req_ssl.end());

                            TlsCertInfo ssl_retry_cert;
                            std::vector<u8> hr = capture_ssl(ip, args.port, read_to, &get_payload_ssl,
                                                             args.verbose, &ssl_retry_cert,
                                                             args.connect_timeout);
                            if (hr.empty() && !terminate_flag) {
                                TlsCertInfo ssl_retry_perm_cert;
                                hr = capture_ssl_permissive(ip, args.port, read_to, &get_payload_ssl,
                                                            args.verbose, &ssl_retry_perm_cert,
                                                            args.connect_timeout);
                            }
                            if (!hr.empty()) {
                                int hr_code = extract_status_code(hr);
                                vlog::ok(g_verbose, "probe #" + std::to_string(attempt_idx) +
                                         ": SSL Host-header retry got " + std::to_string(hr_code) +
                                         " (" + std::to_string(hr.size()) + " bytes) -- using this response", 2);
                                if (is_redirect(hr)) {
                                    hr = follow_redirects_tcp_fp(ip, args.port, read_to,
                                                                 args.verbose, std::move(hr),
                                                                 http_fps);
                                    method_label = "http-host-retry-ssl-redirect/" + pa.name;
                                } else {
                                    http_fps.push_back(
                                        make_http_fingerprint(hr, "http-host-retry-ssl", true));
                                    method_label = "http-host-retry-ssl/" + pa.name;
                                }
                                response = std::move(hr);
                                goto capture_done;
                            }
                            vlog::fail(g_verbose, "probe #" + std::to_string(attempt_idx) +
                                       ": SSL Host-header retry also got no response; keeping original " +
                                       std::to_string(code), 2);
                        }
                    }

                    if (is_redirect(r)) {
                        if (is_ssl) {
                            vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": SSL HTTP probe '" +
                                       pa.name + "' got redirect -> SSL dual FP follow", 2);
                            r = follow_redirects_ssl_fp(ip, args.port, args.timeout,
                                                        args.verbose, std::move(r), http_fps);
                            method_label = "ssl-redirect/" + pa.name;
                        } else {
                            vlog::line(g_verbose, "probe #" + std::to_string(attempt_idx) + ": HTTP probe '" +
                                       pa.name + "' got redirect -> dual FP follow", 2);
                            r = follow_redirects_tcp_fp(ip, args.port, read_to,
                                                        args.verbose, std::move(r), http_fps);
                            method_label = "http-redirect/" + pa.name;
                        }
                        response = std::move(r);
                        goto capture_done;
                    }
                }

                vlog::ok(g_verbose, "probe #" + std::to_string(attempt_idx) + " '" + pa.name + "' got " +
                         std::to_string(r.size()) + " bytes -- using this response", 1);
                response     = std::move(r);
                response_probe = pa.name;
                method_label = is_ssl ? "ssl/" + pa.name : pa.name;
                goto capture_done;
            }
            vlog::fail(g_verbose, "probe #" + std::to_string(attempt_idx) + " '" + pa.name + "' -> no response", 1);
        }

        if (response.empty() && !terminate_flag) {
            vlog::line(g_verbose, "all probes exhausted, trying fallback chain", 1);
            response = capture_fallback(ip, args.port, args.timeout, args.verbose,
                                        method_label, http_fps);
        }
    }

    capture_done:
    if (response.empty()) {
        if (!args.udp && null_close_ms >= 0) {
            MatchContext mctx;
            mctx.closed_without_data = true;
            mctx.elapsed_ms = null_close_ms;
            ProbeEngine wrap_engine(&probes, args.intensity);
            ScanResult wr = wrap_engine.matchResponse((u16)args.port, IPPROTO_TCP, ServiceTunnel::NONE,
                                                      nullptr, 0, mctx);
            if (wr.state == ProbeState::FINISHED_TCPWRAPPED) {
                std::lock_guard<std::mutex> lk(g_stdout_mu);
                std::cout << std::left << std::setw(7) << target_port << ": tcpwrapped\n";
                return 0;
            }
        }
        fprintf(stdout, "%-7d: No response\n", args.port);
        return 1;
    }

    bool final_ssl = (method_label.rfind("ssl/", 0)          == 0 ||
                      method_label == "https"                      ||
                      method_label == "https-redirect"             ||
                      method_label == "Default TLS"                ||
                      method_label == "ssl-after-4xx"              ||
                      method_label.rfind("ssl-after-4xx/", 0) == 0 ||
                      method_label.rfind("ssl-redirect/", 0)  == 0);

    if (g_verbose) {
        vlog::section(g_verbose, "Capture summary");
        vlog::kv(g_verbose, "Bytes",     std::to_string(response.size()));
        vlog::kv(g_verbose, "Port",      std::to_string(args.port));
        vlog::kv(g_verbose, "Probe",     method_label);
        vlog::kv(g_verbose, "Transport", final_ssl ? "TLS/SSL" : "plain TCP");
        vlog::kv(g_verbose, "HTTP FPs",  std::to_string(http_fps.size()));

        fprintf(stderr, "\n%s%sResponse hex (%zu bytes)%s\n", vlog::GRAY(), vlog::BOLD(),
                response.size(), vlog::RESET());
        for (size_t i = 0; i < response.size(); i++) {
            fprintf(stderr, "%02x", response[i]);
            if ((i + 1) % 4 == 0) fprintf(stderr, " ");
            if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
        }
        if (response.size() % 32 != 0) fprintf(stderr, "\n");
    }

    if (!args.save_file.empty()) {
        std::ofstream ofs(args.save_file, std::ios::binary);
        if (ofs)
            ofs.write(reinterpret_cast<const char *>(response.data()),
                      (std::streamsize)response.size());
        vlog::ok(g_verbose, "saved " + std::to_string(response.size()) + " bytes to " + args.save_file, 1);
    }

    if (args.verbose) {
        std::string hex_preview;
        for (size_t i = 0; i < std::min(response.size(), (size_t)50); ++i) {
            char buf[4]; snprintf(buf, sizeof(buf), "%02x ", response[i]);
            hex_preview += buf;
        }
        vlog::line(g_verbose, "first 50 bytes (hex): " + hex_preview, 1);

        std::string ascii_preview;
        for (size_t i = 0; i < std::min(response.size(), (size_t)200); ++i) {
            unsigned char c = response[i];
            ascii_preview += (c >= 32 && c < 127) ? (char)c : '.';
        }
        vlog::line(g_verbose, "first 200 bytes (ascii): " + ascii_preview, 1);
    }

    ServiceTunnel tunnel = final_ssl ? ServiceTunnel::SSL : ServiceTunnel::NONE;

    ProbeEngine engine(&probes, args.intensity);

    if (args.port >= 9100 && args.port <= 9107 &&
        probes.isExcluded((u16)args.port, proto_int)) {
        engine.setIgnoreExclude(true);
        vlog::line(g_verbose, "overriding Exclude for port " + std::to_string(args.port), 1);
    }

    MatchContext match_ctx;
    if (!response_probe.empty()) match_ctx.probe_name = response_probe.c_str();
    ScanResult result = engine.matchResponse(
        (u16)args.port, proto_int, tunnel,
        response.data(), (int)response.size(), match_ctx);

    if (http_fps.empty() && !response.empty()) {
        HttpFingerprint fp = make_http_fingerprint(response, "final-response", final_ssl);
        if (!fp.title.empty())
            vlog::line(args.verbose, "fallback fingerprint title: " + fp.title, 1);
        http_fps.push_back(fp);
    }
    if (!args.udp && !response.empty()) {
        auto asset_candidates = extract_asset_paths(response);
        size_t followed = 0;
        for (const auto &cand : asset_candidates) {
             if (followed >= 4 || terminate_flag) break;
            HttpFingerprint afp = follow_http_asset(ip, args.port, cand,
                                                    final_ssl, read_to, args.verbose);
            ++followed;
            if (!afp.title.empty() || !afp.server.empty()) {
                vlog::line(args.verbose, "asset-follow " + cand +
                           " -> title='" + afp.title + "' server='" + afp.server + "'", 1);
                http_fps.push_back(afp);
            }
        }
    }

    if (!args.udp && !response.empty() && !terminate_flag)
        follow_spa_location(ip, args.port, final_ssl, read_to, args.verbose, http_fps);

    bool confirmed_websocket = false;
    for (const auto &fp : http_fps) {
        if (fp.status_code == 101 || fp.status_code == 501) {
            confirmed_websocket =
                confirm_websocket_upgrade(ip, args.port, final_ssl, read_to, args.verbose);
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_stdout_mu);
        std::cout << std::left << std::setw(7) << target_port << ": ";
        print_result(result, method_label, http_fps, confirmed_websocket);
    }
    return 0;
}
