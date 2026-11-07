#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace ts {

enum Region : uint8_t {
    R_STATUS = 0,
    R_HDR_NAME,
    R_HDR_VALUE,
    R_TITLE,
    R_META,
    R_COMMENT,
    R_SCRIPT,
    R_BODY,
    R_BANNER,
    R_COUNT
};

inline const char *region_name(Region r)
{
    static const char *n[R_COUNT] = { "status", "hdr-name", "hdr-value", "title",
                                      "meta", "comment", "script", "body", "banner" };
    return r < R_COUNT ? n[r] : "?";
}

inline const std::array<uint8_t, 256> &lower_table()
{
    static const std::array<uint8_t, 256> t = [] {
        std::array<uint8_t, 256> a{};
        for (int i = 0; i < 256; ++i) a[(size_t)i] = (uint8_t)((i >= 'A' && i <= 'Z') ? i + 32 : i);
        return a;
    }();
    return t;
}

inline bool is_alnum_c(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline bool is_digit_c(uint8_t c) { return c >= '0' && c <= '9'; }
inline bool is_alpha_c(uint8_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

inline std::string_view trim_sv(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t' || s.back()  == '\r' || s.back()  == '\n')) s.remove_suffix(1);
    return s;
}

inline bool ieq_lower(std::string_view a, std::string_view lower_b)
{
    if (a.size() != lower_b.size()) return false;
    const auto &lt = lower_table();
    for (size_t i = 0; i < a.size(); ++i)
        if (lt[(uint8_t)a[i]] != (uint8_t)lower_b[i]) return false;
    return true;
}

inline uint64_t mix64(uint64_t x)
{
    x ^= x >> 33; x *= 0xFF51AFD7ED558CCDULL;
    x ^= x >> 33; x *= 0xC4CEB9FE1A85EC53ULL;
    x ^= x >> 33;
    return x;
}

inline uint64_t hash64(const void *data, size_t n)
{
    const uint8_t *p = static_cast<const uint8_t *>(data);
    uint64_t h = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)n * 0xD6E8FEB86659FD93ULL);
    while (n >= 8) {
        uint64_t v; std::memcpy(&v, p, 8);
        h = mix64(h ^ v) + 0x9E3779B97F4A7C15ULL;
        p += 8; n -= 8;
    }
    uint64_t tail = 0;
    if (n) std::memcpy(&tail, p, n);
    h = mix64(h ^ tail ^ ((uint64_t)n << 56));
    return h;
}

inline bool forbidden_codepoint(uint32_t cp)
{
    if (cp < 0xA0) return true;
    if (cp == 0x00AD || cp == 0x034F || cp == 0x061C) return true;
    if (cp == 0x115F || cp == 0x1160 || cp == 0x17B4 || cp == 0x17B5) return true;
    if (cp >= 0x180B && cp <= 0x180F) return true;
    if (cp >= 0x200B && cp <= 0x200F) return true;
    if (cp >= 0x2028 && cp <= 0x202E) return true;
    if (cp >= 0x2060 && cp <= 0x206F) return true;
    if (cp == 0x3164 || cp == 0xFEFF || cp == 0xFFA0) return true;
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return true;
    if (cp >= 0xFFF0 && cp <= 0xFFFB) return true;
    if ((cp & 0xFFFEu) == 0xFFFEu) return true;
    if (cp >= 0x1BCA0 && cp <= 0x1BCA3) return true;
    if (cp >= 0x1D173 && cp <= 0x1D17A) return true;
    if (cp >= 0xE0000 && cp <= 0xE0FFF) return true;
    return false;
}

inline void sanitize_inplace(std::string &s)
{
    bool dirty = false;
    for (unsigned char c : s) if (c < 0x20 || c >= 0x7f) { dirty = true; break; }
    if (!dirty) return;

    std::string out;
    out.reserve(s.size());
    const size_t n = s.size();
    size_t i = 0;
    while (i < n) {
        const unsigned char c = (unsigned char)s[i];
        if (c == '\t') { out += ' '; ++i; continue; }
        if (c < 0x20 || c == 0x7f) { out += '.'; ++i; continue; }
        if (c < 0x80) { out += (char)c; ++i; continue; }

        size_t len = 0;
        uint32_t cp = 0;
        if      (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1Fu; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0Fu; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07u; }
        else { out += '?'; ++i; continue; }

        bool structural = (i + len <= n);
        if (structural) {
            for (size_t k = 1; k < len; ++k) {
                const unsigned char b = (unsigned char)s[i + k];
                if ((b & 0xC0) != 0x80) { structural = false; break; }
                cp = (cp << 6) | (b & 0x3Fu);
            }
        }
        if (structural) {
            if (len == 3 && cp < 0x800) structural = false;
            if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) structural = false;
            if (cp >= 0xD800 && cp <= 0xDFFF) structural = false;
        }
        if (!structural) { out += '?'; ++i; continue; }
        if (forbidden_codepoint(cp)) { out += '?'; i += len; continue; }
        out.append(s, i, len);
        i += len;
    }
    s.swap(out);
}

inline std::string sanitized(std::string s) { sanitize_inplace(s); return s; }

class MappedFile {
public:
    MappedFile() = default;
    MappedFile(const MappedFile &) = delete;
    MappedFile &operator=(const MappedFile &) = delete;
    MappedFile(MappedFile &&o) noexcept { steal(o); }
    MappedFile &operator=(MappedFile &&o) noexcept { if (this != &o) { close(); steal(o); } return *this; }
    ~MappedFile() { close(); }

    enum Perm { PERM_WARN, PERM_STRICT };

    bool open(const std::string &path, size_t max_bytes, std::string *err, Perm perm = PERM_WARN)
    {
        close();
        int oflags = O_RDONLY | O_CLOEXEC | O_NOCTTY;
        if (perm == PERM_STRICT) oflags |= O_NOFOLLOW;
        int fd = ::open(path.c_str(), oflags);
        if (fd < 0) { if (err) *err = "cannot open '" + path + "': " + std::strerror(errno); return false; }
        struct stat st {};
        if (::fstat(fd, &st) != 0) { if (err) *err = "fstat failed: " + std::string(std::strerror(errno)); ::close(fd); return false; }
        if (!S_ISREG(st.st_mode)) { if (err) *err = "'" + path + "' is not a regular file"; ::close(fd); return false; }
        if (st.st_size < 0 || (uint64_t)st.st_size > (uint64_t)max_bytes) {
            if (err) *err = "'" + path + "' exceeds the " + std::to_string(max_bytes) + "-byte limit";
            ::close(fd); return false;
        }
        const bool bad_mode  = (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        const bool bad_owner = (st.st_uid != 0 && st.st_uid != ::geteuid());
        if (bad_mode || bad_owner) {
            if (perm == PERM_STRICT) {
                if (err) *err = "'" + path + "' has unsafe ownership/permissions";
                ::close(fd); return false;
            }
            std::fprintf(stderr, "[warn] %s is %s%s%s -- anyone who can write it controls scan signatures\n",
                         path.c_str(), bad_mode ? "group/world-writable" : "",
                         (bad_mode && bad_owner) ? " and " : "", bad_owner ? "owned by another user" : "");
        }
        const size_t want = (size_t)st.st_size;
        mtime_ns_ = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
        if (want == 0) { ::close(fd); return true; }

        buf_.reset(new (std::nothrow) char[want]);
        if (!buf_) { if (err) *err = "out of memory reading '" + path + "'"; ::close(fd); mtime_ns_ = 0; return false; }
        size_t off = 0;
        while (off < want) {
            ssize_t r = ::read(fd, buf_.get() + off, want - off);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            off += (size_t)r;
        }
        ::close(fd);
        if (off != want) {
            buf_.reset(); mtime_ns_ = 0;
            if (err) *err = "short read on '" + path + "'";
            return false;
        }
        size_ = want;
        return true;
    }

    const char *data() const { return buf_.get(); }
    size_t size() const { return size_; }
    int64_t mtime_ns() const { return mtime_ns_; }
    std::string_view view() const { return std::string_view(buf_.get(), size_); }

    void close()
    {
        buf_.reset();
        size_ = 0; mtime_ns_ = 0;
    }

private:
    void steal(MappedFile &o)
    {
        buf_ = std::move(o.buf_); size_ = o.size_; mtime_ns_ = o.mtime_ns_;
        o.size_ = 0; o.mtime_ns_ = 0;
    }
    std::unique_ptr<char[]> buf_;
    size_t  size_ = 0;
    int64_t mtime_ns_ = 0;
};

struct ScanLimits {
    size_t max_bytes         = 2u << 20;
    size_t max_hits          = 4096;
    size_t max_hits_per_term = 4;
    size_t max_findings      = 24;
    int    min_score         = 2;
    int    presence_score    = 3;
    size_t version_window    = 96;
    size_t max_generic       = 12;
};

struct ScanStats {
    bool   truncated = false;
    bool   failed    = false;
    size_t hits      = 0;
};

inline constexpr size_t kMaxSigFileBytes = 64u << 20;
inline constexpr size_t kMaxTerms        = 400000;
inline constexpr size_t kMaxNodes        = 8000000;
inline constexpr size_t kMaxNeedleLen    = 120;
inline constexpr size_t kMaxProductLen   = 64;

struct Finding {
    std::string product;
    std::string version;
    std::string evidence;
    int         score   = 0;
    Region      region  = R_BODY;
    bool        generic = false;
    int         confidence = 1;
    int         ver_conf   = 0;
    bool        ver_blocked = false;
    uint16_t    rmask      = 0;
    int         hops_seen  = 1;
    std::array<uint64_t, 4> ev_set{};
    uint8_t     ev_n = 0;

    std::string display() const { return version.empty() ? product : product + " " + version; }
};

inline void ev_add(Finding &f, uint64_t h)
{
    for (uint8_t k = 0; k < f.ev_n; ++k) if (f.ev_set[k] == h) return;
    if (f.ev_n < f.ev_set.size()) f.ev_set[f.ev_n++] = h;
    else f.ev_set[f.ev_set.size() - 1] = h;
}

inline bool ev_has(const Finding &f, uint64_t h)
{
    for (uint8_t k = 0; k < f.ev_n; ++k) if (f.ev_set[k] == h) return true;
    return false;
}

inline uint64_t evidence_hash(const Finding &f)
{
    const auto &lt = lower_table();
    std::string k;
    k.reserve(f.product.size() + f.evidence.size() + 2);
    for (unsigned char c : f.product) k += (char)lt[c];
    k += '\0';
    k += (char)f.region;
    k += f.evidence;
    return hash64(k.data(), k.size());
}

inline const char *conf_name(int c)
{
    return c >= 3 ? "confirmed" : c == 2 ? "likely" : "possible";
}
inline const char *verconf_name(int c)
{
    return c >= 2 ? "adjacent" : c == 1 ? "nearby" : "none";
}

enum : uint8_t { F_SUBSTR = 1, F_NOVER = 2, F_STRICTVER = 4 };

struct TermRec {
    uint32_t product;
    uint8_t  len;
    uint8_t  flags;
    int8_t   w[R_COUNT];
    uint8_t  pad;
};
struct Node {
    uint32_t edge_off;
    uint16_t edge_cnt;
    uint16_t out_cnt;
    uint32_t out_off;
    uint32_t fail;
    uint32_t dict;
};
struct Edge {
    uint8_t  ch;
    uint8_t  pad[3];
    uint32_t to;
};
static_assert(sizeof(TermRec) == 16, "TermRec layout");
static_assert(sizeof(Node) == 20, "Node layout");
static_assert(sizeof(Edge) == 8, "Edge layout");

struct TermCtx {
    uint16_t hdr_id;
    uint16_t pad;
    uint32_t need_prod;
    uint32_t not_prod;
    uint16_t vmaj_lo;
    uint16_t vmaj_hi;
};
static_assert(sizeof(TermCtx) == 16, "TermCtx layout");

struct CacheHeader {
    char     magic[8];
    uint32_t version;
    uint32_t endian;
    uint64_t src_hash;
    uint64_t src_size;
    uint64_t payload_hash;
    uint64_t file_size;
    uint32_t n_terms, n_nodes, n_edges, n_outs, n_products, strings_bytes;
    uint64_t off_terms, off_nodes, off_edges, off_outs, off_strings;
    uint32_t n_hdrs, pad2;
    uint64_t off_ctx;
};
static_assert(sizeof(CacheHeader) == 128, "CacheHeader layout");

struct RawHit { uint32_t term; uint32_t start; uint32_t end; uint8_t region; };

inline bool cache_dir_trusted(const std::string &d)
{
    struct stat st {};
    if (::stat(d.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

inline std::string fallback_cache_path(const std::string &conf_path, bool create)
{
    std::string base;
    const char *xdg  = std::getenv("XDG_CACHE_HOME");
    const char *home = std::getenv("HOME");
    if (xdg && xdg[0] == '/') base = xdg;
    else if (home && home[0] == '/') base = std::string(home) + "/.cache";
    else return std::string();
    const std::string dir = base + "/shiv";
    if (create) { ::mkdir(base.c_str(), 0700); ::mkdir(dir.c_str(), 0700); }
    if (!cache_dir_trusted(dir)) return std::string();
    char name[40];
    std::snprintf(name, sizeof(name), "/%016llx.tscache", (unsigned long long)hash64(conf_path.data(), conf_path.size()));
    return dir + name;
}

class TermSet {
public:
    TermSet() = default;
    TermSet(const TermSet &) = delete;
    TermSet &operator=(const TermSet &) = delete;
    TermSet(TermSet &&) = default;
    TermSet &operator=(TermSet &&) = default;

    bool   empty()      const { return n_nodes_ <= 1; }
    size_t term_count() const { return n_terms_; }
    size_t node_count() const { return n_nodes_; }
    bool   from_cache() const { return from_cache_; }
    const TermRec &term(uint32_t i) const { return terms_[i]; }
    const TermCtx &ctx(uint32_t i) const { return ctxs_[i]; }
    size_t product_count() const { return products_.size(); }
    const std::string &hdr_list(uint16_t id) const { static const std::string e; return (id && id <= hdrs_.size()) ? hdrs_[id - 1] : e; }
    const std::string &product_name(uint32_t i) const { return products_[i]; }

    bool add_line(std::string_view line, std::string *err)
    {
        size_t p1 = line.find('|');
        if (p1 == std::string_view::npos) { if (err) *err = "[terms] entry needs 'needle|Product[|spec]'"; return false; }
        size_t p2 = line.find('|', p1 + 1);
        std::string_view needle  = trim_sv(line.substr(0, p1));
        std::string_view product = trim_sv(line.substr(p1 + 1, p2 == std::string_view::npos ? std::string_view::npos : p2 - p1 - 1));
        std::string_view spec    = p2 == std::string_view::npos ? std::string_view() : trim_sv(line.substr(p2 + 1));

        if (needle.size() < 3 || needle.size() > kMaxNeedleLen) { if (err) *err = "needle length must be 3.." + std::to_string(kMaxNeedleLen); return false; }
        if (product.empty() || product.size() > kMaxProductLen) { if (err) *err = "product name length must be 1.." + std::to_string(kMaxProductLen); return false; }
        for (unsigned char c : needle)  if (c < 0x20 || c == 0x7f) { if (err) *err = "control character in needle"; return false; }
        for (unsigned char c : product) if (c < 0x20 || c == 0x7f) { if (err) *err = "control character in product"; return false; }
        if (pending_.size() >= kMaxTerms) { if (err) *err = "too many terms (limit " + std::to_string(kMaxTerms) + ")"; return false; }

        Pending pt;
        const auto &lt = lower_table();
        pt.needle.reserve(needle.size());
        for (unsigned char c : needle) pt.needle += (char)lt[c];
        pt.product.assign(product.data(), product.size());
        static const int8_t defaults[R_COUNT] = { 0, 3, 3, 2, 2, 1, 1, 1, 3 };
        std::memcpy(pt.w, defaults, sizeof(defaults));
        pt.flags = 0;
        pt.vlo = 0; pt.vhi = 65535;

        size_t pos = 0;
        while (pos <= spec.size() && !spec.empty()) {
            size_t c = spec.find(',', pos);
            std::string_view tok = trim_sv(spec.substr(pos, c == std::string_view::npos ? std::string_view::npos : c - pos));
            pos = (c == std::string_view::npos) ? spec.size() + 1 : c + 1;
            if (tok.empty()) continue;
            if (tok == "sub")    { pt.flags |= F_SUBSTR;    continue; }
            if (tok == "nover")  { pt.flags |= F_NOVER;     continue; }
            if (tok == "strict") { pt.flags |= F_STRICTVER; continue; }
            if (tok.size() > 4 && tok.substr(0, 4) == "hdr:") {
                std::string h;
                for (unsigned char ch : tok.substr(4)) {
                    ch = lt[ch];
                    if (!(is_alnum_c(ch) || ch == '-' || ch == '_' || ch == ';')) { if (err) *err = "bad character in hdr: list"; return false; }
                    h += (char)ch;
                }
                if (h.empty() || h.size() > 64) { if (err) *err = "hdr: list length must be 1..64"; return false; }
                pt.hdr = std::move(h);
                continue;
            }
            if (tok.size() > 6 && tok.substr(0, 6) == "needs:") { pt.need.assign(trim_sv(tok.substr(6))); if (pt.need.empty() || pt.need.size() > kMaxProductLen) { if (err) *err = "bad needs: product"; return false; } continue; }
            if (tok.size() > 4 && tok.substr(0, 4) == "not:")   { pt.notp.assign(trim_sv(tok.substr(4))); if (pt.notp.empty() || pt.notp.size() > kMaxProductLen) { if (err) *err = "bad not: product"; return false; } continue; }
            if (tok.size() > 5 && tok.substr(0, 5) == "vmaj:") {
                std::string_view r = tok.substr(5);
                size_t dash = r.find('-');
                if (dash == std::string_view::npos || dash == 0 || dash + 1 >= r.size()) { if (err) *err = "vmaj: needs LO-HI"; return false; }
                unsigned lo = 0, hi = 0;
                for (char ch : r.substr(0, dash))  { if (!is_digit_c((uint8_t)ch)) { if (err) *err = "bad vmaj: LO"; return false; } lo = lo * 10 + (unsigned)(ch - '0'); if (lo > 65535) { if (err) *err = "vmaj: out of range"; return false; } }
                for (char ch : r.substr(dash + 1)) { if (!is_digit_c((uint8_t)ch)) { if (err) *err = "bad vmaj: HI"; return false; } hi = hi * 10 + (unsigned)(ch - '0'); if (hi > 65535) { if (err) *err = "vmaj: out of range"; return false; } }
                if (lo > hi) { if (err) *err = "vmaj: LO > HI"; return false; }
                pt.vlo = (uint16_t)lo; pt.vhi = (uint16_t)hi;
                continue;
            }
            if (tok.size() == 2 && is_digit_c((uint8_t)tok[1])) {
                int w = tok[1] - '0';
                switch (tok[0]) {
                    case 'H': pt.w[R_HDR_VALUE] = (int8_t)w; continue;
                    case 'N': pt.w[R_HDR_NAME]  = (int8_t)w; continue;
                    case 'T': pt.w[R_TITLE]     = (int8_t)w; continue;
                    case 'M': pt.w[R_META]      = (int8_t)w; continue;
                    case 'C': pt.w[R_COMMENT]   = (int8_t)w; continue;
                    case 'S': pt.w[R_SCRIPT]    = (int8_t)w; continue;
                    case 'B': pt.w[R_BODY]      = (int8_t)w; continue;
                    case 'X': pt.w[R_BANNER]    = (int8_t)w; continue;
                    case 'A': for (int r = 1; r < R_COUNT; ++r) pt.w[r] = (int8_t)w; continue;
                    default: break;
                }
            }
            if (err) *err = "unknown term spec token '" + std::string(tok) + "'";
            return false;
        }
        pending_.push_back(std::move(pt));
        return true;
    }

    bool build(std::string *err)
    {
        own_products_.clear();
        own_terms_.clear();
        own_ctxs_.clear();
        own_hdrs_.clear();
        needles_.clear();
        std::unordered_map<std::string, uint32_t> prod_idx;
        std::unordered_map<std::string, uint16_t> hdr_idx;
        auto intern_prod = [&](const std::string &name) -> uint32_t {
            auto it = prod_idx.find(name);
            if (it != prod_idx.end()) return it->second;
            uint32_t pi = (uint32_t)own_products_.size();
            own_products_.push_back(name); prod_idx.emplace(name, pi);
            return pi;
        };
        std::unordered_map<std::string, uint32_t> term_idx;
        for (auto &pt : pending_) {
            uint32_t pi = intern_prod(pt.product);
            TermCtx cx{};
            cx.vmaj_lo = pt.vlo; cx.vmaj_hi = pt.vhi;
            if (!pt.hdr.empty()) {
                auto hi = hdr_idx.find(pt.hdr);
                if (hi == hdr_idx.end()) {
                    if (own_hdrs_.size() >= 60000) { if (err) *err = "too many distinct hdr: lists"; return false; }
                    own_hdrs_.push_back(pt.hdr);
                    hi = hdr_idx.emplace(pt.hdr, (uint16_t)own_hdrs_.size()).first;
                }
                cx.hdr_id = hi->second;
            }
            if (!pt.need.empty()) cx.need_prod = intern_prod(pt.need) + 1;
            if (!pt.notp.empty()) cx.not_prod  = intern_prod(pt.notp) + 1;
            TermRec tr{};
            tr.product = pi; tr.len = (uint8_t)pt.needle.size(); tr.flags = pt.flags;
            std::memcpy(tr.w, pt.w, R_COUNT);
            std::string key = pt.needle; key += '\0'; key += pt.product; key += '\0'; key += pt.hdr;
            auto ti = term_idx.find(key);
            if (ti == term_idx.end()) { term_idx.emplace(std::move(key), (uint32_t)own_terms_.size()); own_terms_.push_back(tr); own_ctxs_.push_back(cx); needles_.push_back(pt.needle); }
            else { own_terms_[ti->second] = tr; own_ctxs_[ti->second] = cx; needles_[ti->second] = pt.needle; }
        }
        pending_.clear(); pending_.shrink_to_fit();

        struct BNode { std::vector<std::pair<uint8_t, uint32_t>> ch; std::vector<uint32_t> out; uint32_t fail = 0, dict = 0; };
        std::vector<BNode> bn(1);
        auto find_child = [&](uint32_t u, uint8_t c) -> uint32_t {
            for (auto &e : bn[u].ch) if (e.first == c) return e.second;
            return 0;
        };
        for (uint32_t t = 0; t < (uint32_t)needles_.size(); ++t) {
            uint32_t u = 0;
            for (unsigned char c : needles_[t]) {
                uint32_t v = find_child(u, c);
                if (!v) {
                    if (bn.size() >= kMaxNodes) { if (err) *err = "automaton too large"; return false; }
                    v = (uint32_t)bn.size();
                    bn.emplace_back();
                    bn[u].ch.emplace_back(c, v);
                }
                u = v;
            }
            bn[u].out.push_back(t);
        }
        std::vector<uint32_t> order; order.reserve(bn.size());
        order.push_back(0);
        for (size_t qi = 0; qi < order.size(); ++qi) {
            uint32_t u = order[qi];
            std::sort(bn[u].ch.begin(), bn[u].ch.end());
            for (auto &e : bn[u].ch) {
                uint32_t v = e.second;
                if (u == 0) bn[v].fail = 0;
                else {
                    uint32_t f = bn[u].fail, t = 0;
                    for (;;) { t = find_child(f, e.first); if (t || f == 0) break; f = bn[f].fail; }
                    bn[v].fail = t;
                }
                uint32_t f = bn[v].fail;
                bn[v].dict = bn[f].out.empty() ? bn[f].dict : f;
                order.push_back(v);
            }
        }
        std::vector<uint32_t> newid(bn.size());
        for (uint32_t i = 0; i < (uint32_t)order.size(); ++i) newid[order[i]] = i;

        own_nodes_.assign(bn.size(), Node{});
        own_edges_.clear();
        own_outs_.clear();
        for (uint32_t i = 0; i < (uint32_t)order.size(); ++i) {
            BNode &b = bn[order[i]];
            Node &nd = own_nodes_[i];
            nd.edge_off = (uint32_t)own_edges_.size();
            nd.edge_cnt = (uint16_t)b.ch.size();
            for (auto &e : b.ch) { Edge ed{}; ed.ch = e.first; ed.to = newid[e.second]; own_edges_.push_back(ed); }
            nd.out_off = (uint32_t)own_outs_.size();
            nd.out_cnt = (uint16_t)std::min<size_t>(b.out.size(), 65535);
            for (size_t k = 0; k < nd.out_cnt; ++k) own_outs_.push_back(b.out[k]);
            nd.fail = newid[b.fail];
            nd.dict = b.dict ? newid[b.dict] : 0;
        }
        needles_.clear(); needles_.shrink_to_fit();
        cache_file_.close();
        products_ = own_products_;
        hdrs_ = own_hdrs_;
        n_terms_ = own_terms_.size();
        n_nodes_ = own_nodes_.size();
        n_edges_ = own_edges_.size();
        n_outs_  = own_outs_.size();
        ctxs_ = own_ctxs_.data();
        terms_ = own_terms_.data(); nodes_ = own_nodes_.data(); edges_ = own_edges_.data(); outs_ = own_outs_.data();
        from_cache_ = false;
        build_root();
        return true;
    }

    bool load_cache(const std::string &path, uint64_t src_hash, uint64_t src_size)
    {
        MappedFile mf;
        std::string e;
        if (!mf.open(path, kMaxSigFileBytes * 2, &e, MappedFile::PERM_STRICT)) return false;
        if (mf.size() < sizeof(CacheHeader)) return false;
        const uint8_t *base = reinterpret_cast<const uint8_t *>(mf.data());
        if ((reinterpret_cast<uintptr_t>(base) & 7u) != 0) return false;
        CacheHeader h; std::memcpy(&h, base, sizeof(h));
        if (std::memcmp(h.magic, "SHIVTS03", 8) != 0 || h.version != 3 || h.endian != 0x01020304u) return false;
        if (h.src_hash != src_hash || h.src_size != src_size) return false;
        if (h.file_size != mf.size()) return false;
        if (h.n_nodes == 0 || h.n_nodes > kMaxNodes || h.n_terms > kMaxTerms) return false;

        auto section_ok = [&](uint64_t off, uint64_t count, uint64_t elem) {
            if (off < sizeof(CacheHeader) || (off & 7u)) return false;
            if (elem && count > (UINT64_MAX - off) / elem) return false;
            return off + count * elem <= h.file_size;
        };
        if (!section_ok(h.off_terms, h.n_terms, sizeof(TermRec)) || !section_ok(h.off_nodes, h.n_nodes, sizeof(Node)) ||
            !section_ok(h.off_edges, h.n_edges, sizeof(Edge)) || !section_ok(h.off_outs, h.n_outs, 4) ||
            !section_ok(h.off_strings, h.strings_bytes, 1) || !section_ok(h.off_ctx, h.n_terms, sizeof(TermCtx))) return false;
        if (h.n_hdrs > 60000 || h.n_products > kMaxTerms * 2) return false;
        if (hash64(base + sizeof(CacheHeader), mf.size() - sizeof(CacheHeader)) != h.payload_hash) return false;

        const TermRec *tr = reinterpret_cast<const TermRec *>(base + h.off_terms);
        const Node    *nd = reinterpret_cast<const Node *>(base + h.off_nodes);
        const Edge    *ed = reinterpret_cast<const Edge *>(base + h.off_edges);
        const uint32_t*ou = reinterpret_cast<const uint32_t *>(base + h.off_outs);
        const TermCtx *cx = reinterpret_cast<const TermCtx *>(base + h.off_ctx);

        std::vector<std::string> prods, hdr_tab;
        prods.reserve(h.n_products);
        {
            const char *s = reinterpret_cast<const char *>(base + h.off_strings);
            size_t pos = 0;
            for (uint32_t i = 0; i < h.n_products; ++i) {
                const void *z = pos < h.strings_bytes ? std::memchr(s + pos, 0, h.strings_bytes - pos) : nullptr;
                if (!z) return false;
                size_t len = (size_t)(static_cast<const char *>(z) - (s + pos));
                if (len > kMaxProductLen) return false;
                prods.emplace_back(s + pos, len);
                pos += len + 1;
            }
            hdr_tab.reserve(h.n_hdrs);
            for (uint32_t i = 0; i < h.n_hdrs; ++i) {
                const void *z = pos < h.strings_bytes ? std::memchr(s + pos, 0, h.strings_bytes - pos) : nullptr;
                if (!z) return false;
                size_t len = (size_t)(static_cast<const char *>(z) - (s + pos));
                if (len == 0 || len > 64) return false;
                hdr_tab.emplace_back(s + pos, len);
                pos += len + 1;
            }
        }

        for (uint32_t i = 0; i < h.n_terms; ++i)
            if (tr[i].product >= h.n_products || tr[i].len == 0 || tr[i].len > kMaxNeedleLen) return false;

        std::vector<uint8_t> depth(h.n_nodes, 0);
        for (uint32_t i = 0; i < h.n_nodes; ++i) {
            const Node &n = nd[i];
            if ((uint64_t)n.edge_off + n.edge_cnt > h.n_edges) return false;
            if ((uint64_t)n.out_off  + n.out_cnt  > h.n_outs)  return false;
            if (i == 0) {
                if (n.fail || n.dict || n.out_cnt) return false;
            } else {
                if (n.fail >= i || n.dict >= i) return false;
                if (depth[i] == 0) return false;
                if (depth[n.fail] >= depth[i]) return false;
                if (n.dict && (nd[n.dict].out_cnt == 0 || depth[n.dict] >= depth[i])) return false;
            }
            for (uint32_t k = 0; k < n.edge_cnt; ++k) {
                const Edge &g = ed[n.edge_off + k];
                if (g.to <= i || g.to >= h.n_nodes) return false;
                if (k && g.ch <= ed[n.edge_off + k - 1].ch) return false;
                if (depth[g.to] != 0) return false;
                if ((size_t)depth[i] + 1 > kMaxNeedleLen) return false;
                depth[g.to] = (uint8_t)(depth[i] + 1);
            }
            for (uint32_t k = 0; k < n.out_cnt; ++k) {
                const uint32_t t = ou[n.out_off + k];
                if (t >= h.n_terms) return false;
                if (tr[t].len != depth[i]) return false;
            }
        }
        for (uint32_t i = 0; i < h.n_outs; ++i) if (ou[i] >= h.n_terms) return false;
        for (uint32_t i = 0; i < h.n_terms; ++i) {
            if (cx[i].hdr_id > h.n_hdrs || cx[i].need_prod > h.n_products || cx[i].not_prod > h.n_products || cx[i].vmaj_lo > cx[i].vmaj_hi) return false;
        }

        cache_file_ = std::move(mf);
        base = reinterpret_cast<const uint8_t *>(cache_file_.data());
        terms_ = reinterpret_cast<const TermRec *>(base + h.off_terms);
        nodes_ = reinterpret_cast<const Node *>(base + h.off_nodes);
        edges_ = reinterpret_cast<const Edge *>(base + h.off_edges);
        outs_  = reinterpret_cast<const uint32_t *>(base + h.off_outs);
        ctxs_  = reinterpret_cast<const TermCtx *>(base + h.off_ctx);
        products_ = std::move(prods);
        hdrs_ = std::move(hdr_tab);
        n_terms_ = h.n_terms; n_nodes_ = h.n_nodes; n_edges_ = h.n_edges; n_outs_ = h.n_outs;
        own_terms_.clear(); own_nodes_.clear(); own_edges_.clear(); own_outs_.clear(); own_products_.clear(); own_ctxs_.clear(); own_hdrs_.clear();
        from_cache_ = true;
        build_root();
        return true;
    }

    bool save_cache(const std::string &path, uint64_t src_hash, uint64_t src_size) const
    {
        if (from_cache_ || n_nodes_ == 0) return false;
        std::string strings;
        for (auto &p : products_) { strings += p; strings += '\0'; }
        for (auto &hd : hdrs_)    { strings += hd; strings += '\0'; }

        auto align8 = [](size_t x) { return (x + 7) & ~(size_t)7; };
        CacheHeader h{};
        std::memcpy(h.magic, "SHIVTS03", 8);
        h.version = 3; h.endian = 0x01020304u; h.src_hash = src_hash; h.src_size = src_size;
        h.n_terms = (uint32_t)n_terms_; h.n_nodes = (uint32_t)n_nodes_; h.n_edges = (uint32_t)n_edges_;
        h.n_outs = (uint32_t)n_outs_; h.n_products = (uint32_t)products_.size(); h.strings_bytes = (uint32_t)strings.size();
        h.n_hdrs = (uint32_t)hdrs_.size();
        size_t off = sizeof(CacheHeader);
        h.off_terms = off;   off = align8(off + n_terms_ * sizeof(TermRec));
        h.off_nodes = off;   off = align8(off + n_nodes_ * sizeof(Node));
        h.off_edges = off;   off = align8(off + n_edges_ * sizeof(Edge));
        h.off_outs  = off;   off = align8(off + n_outs_ * 4);
        h.off_strings = off; off = align8(off + strings.size());
        h.off_ctx = off;     off = align8(off + n_terms_ * sizeof(TermCtx));
        h.file_size = off;

        std::vector<uint8_t> buf(off, 0);
        if (n_terms_) std::memcpy(buf.data() + h.off_terms, terms_, n_terms_ * sizeof(TermRec));
        std::memcpy(buf.data() + h.off_nodes, nodes_, n_nodes_ * sizeof(Node));
        if (n_edges_) std::memcpy(buf.data() + h.off_edges, edges_, n_edges_ * sizeof(Edge));
        if (n_outs_)  std::memcpy(buf.data() + h.off_outs, outs_, n_outs_ * 4);
        if (!strings.empty()) std::memcpy(buf.data() + h.off_strings, strings.data(), strings.size());
        if (n_terms_) std::memcpy(buf.data() + h.off_ctx, ctxs_, n_terms_ * sizeof(TermCtx));
        h.payload_hash = hash64(buf.data() + sizeof(CacheHeader), buf.size() - sizeof(CacheHeader));
        std::memcpy(buf.data(), &h, sizeof(h));

        std::string tmpl = path + ".XXXXXX";
        std::vector<char> tp(tmpl.begin(), tmpl.end()); tp.push_back('\0');
        int fd = ::mkstemp(tp.data());
        if (fd < 0) return false;
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        ::fchmod(fd, 0644);
        size_t w = 0;
        while (w < buf.size()) {
            ssize_t r = ::write(fd, buf.data() + w, buf.size() - w);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { ::close(fd); ::unlink(tp.data()); return false; }
            w += (size_t)r;
        }
        if (::fsync(fd) != 0) { ::close(fd); ::unlink(tp.data()); return false; }
        ::close(fd);
        if (::rename(tp.data(), path.c_str()) != 0) { ::unlink(tp.data()); return false; }
        return true;
    }

    bool load_cache_any(const std::string &conf_path, uint64_t src_hash, uint64_t src_size)
    {
        if (load_cache(conf_path + ".tscache", src_hash, src_size)) return true;
        const std::string alt = fallback_cache_path(conf_path, false);
        return !alt.empty() && load_cache(alt, src_hash, src_size);
    }

    bool save_cache_any(const std::string &conf_path, uint64_t src_hash, uint64_t src_size) const
    {
        if (save_cache(conf_path + ".tscache", src_hash, src_size)) return true;
        const std::string alt = fallback_cache_path(conf_path, true);
        return !alt.empty() && save_cache(alt, src_hash, src_size);
    }

    template <class Classify>
    void scan_raw(const uint8_t *data, size_t n, const ScanLimits &lim, std::vector<RawHit> &hits,
                  Classify &&classify, size_t priority_end, ScanStats *stats) const
    {
        if (n_nodes_ <= 1 || n_terms_ == 0 || !data) return;

        static thread_local std::vector<uint8_t> counts;
        static thread_local std::vector<size_t> touched;
        const size_t need = n_terms_ * (size_t)R_COUNT;
        if (counts.size() != need) { counts.assign(need, 0); touched.clear(); }
        touched.clear();

        struct Reset {
            std::vector<uint8_t> &c; std::vector<size_t> &t;
            ~Reset() { for (size_t k : t) c[k] = 0; t.clear(); }
        } reset{counts, touched};

        const auto &lt = lower_table();
        size_t hdr_hits = 0, body_hits = 0;
        uint32_t st = 0;
        for (size_t i = 0; i < n; ++i) {
            const uint8_t c = lt[data[i]];
            if (st == 0 && root_[c] == 0) {
                if (i >= priority_end && body_hits >= lim.max_hits) break;
                continue;
            }
            for (;;) {
                uint32_t nx = step(st, c);
                if (nx) { st = nx; break; }
                if (st == 0) break;
                st = nodes_[st].fail;
            }
            if (st == 0) continue;
            uint32_t s = nodes_[st].out_cnt ? st : nodes_[st].dict;
            while (s) {
                const Node &nd = nodes_[s];
                for (uint32_t k = 0; k < nd.out_cnt; ++k) {
                    const uint32_t t = outs_[nd.out_off + k];
                    const TermRec &tr = terms_[t];
                    const size_t end = i + 1;
                    if (tr.len > end) continue;
                    const size_t start = end - tr.len;
                    if (!(tr.flags & F_SUBSTR)) {
                        if (is_alnum_c(data[start]) && start > 0 && is_alnum_c(data[start - 1])) continue;
                        if (is_alnum_c(data[end - 1]) && end < n && is_alnum_c(data[end])) continue;
                    }
                    const Region r = classify(start);
                    if (tr.w[r] <= 0) continue;
                    const size_t slot = (size_t)t * R_COUNT + (size_t)r;
                    if (counts[slot] >= lim.max_hits_per_term) continue;
                    size_t &budget = (start < priority_end) ? hdr_hits : body_hits;
                    if (budget >= lim.max_hits) { if (stats) stats->truncated = true; continue; }
                    if (counts[slot]++ == 0) touched.push_back(slot);
                    ++budget;
                    hits.push_back(RawHit{ t, (uint32_t)start, (uint32_t)end, (uint8_t)r });
                }
                s = nd.dict;
            }
            if (i >= priority_end && body_hits >= lim.max_hits) break;
        }
        if (stats) stats->hits = hits.size();
    }

private:
    struct Pending { std::string needle, product, hdr, need, notp; int8_t w[R_COUNT]; uint8_t flags; uint16_t vlo = 0, vhi = 65535; };

    inline uint32_t step(uint32_t s, uint8_t c) const
    {
        if (s == 0) return root_[c];
        const Node &nd = nodes_[s];
        const Edge *e = edges_ + nd.edge_off;
        uint32_t k = nd.edge_cnt;
        if (k <= 8) {
            for (uint32_t i = 0; i < k; ++i) if (e[i].ch == c) return e[i].to;
            return 0;
        }
        uint32_t lo = 0, hi = k;
        while (lo < hi) {
            uint32_t mid = (lo + hi) >> 1;
            if (e[mid].ch < c) lo = mid + 1; else hi = mid;
        }
        return (lo < k && e[lo].ch == c) ? e[lo].to : 0;
    }

    void build_root()
    {
        std::memset(root_, 0, sizeof(root_));
        if (n_nodes_ == 0) return;
        const Node &r = nodes_[0];
        for (uint32_t i = 0; i < r.edge_cnt; ++i) root_[edges_[r.edge_off + i].ch] = edges_[r.edge_off + i].to;
    }

    std::vector<Pending>     pending_;
    std::vector<std::string> needles_;
    std::vector<TermRec>     own_terms_;
    std::vector<Node>        own_nodes_;
    std::vector<Edge>        own_edges_;
    std::vector<uint32_t>    own_outs_;
    std::vector<std::string> own_products_;
    std::vector<TermCtx>     own_ctxs_;
    std::vector<std::string> own_hdrs_;
    MappedFile               cache_file_;
    const TermRec *terms_ = nullptr;
    const Node    *nodes_ = nullptr;
    const Edge    *edges_ = nullptr;
    const uint32_t*outs_  = nullptr;
    const TermCtx *ctxs_  = nullptr;
    std::vector<std::string> products_;
    std::vector<std::string> hdrs_;
    size_t n_terms_ = 0, n_nodes_ = 0, n_edges_ = 0, n_outs_ = 0;
    bool   from_cache_ = false;
    uint32_t root_[256] = {};
};

class RegionIndex {
public:
    void build(const uint8_t *orig, size_t n)
    {
        http_ = n >= 5 && std::memcmp(orig, "HTTP/", 5) == 0;
        hdr_end_ = 0;
        default_region_ = R_BODY;
        ls_.clear(); col_.clear(); spans_.clear();
        if (!http_) {
            size_t probe = std::min<size_t>(n, 1024);
            bool markup = false;
            for (size_t i = 0; i + 5 <= probe; ++i)
                if (orig[i] == '<' && (starts_ci(orig, n, i, "<html") || starts_ci(orig, n, i, "<!doc"))) { markup = true; break; }
            default_region_ = markup ? R_BODY : R_BANNER;
            if (markup) scan_body(orig, 0, n);
            return;
        }
        const size_t kHdrCap = std::min<size_t>(n, 32768);
        size_t he = kHdrCap;
        for (size_t i = 0; i < kHdrCap; ++i) {
            if (orig[i] == '\n') {
                if (i + 1 < kHdrCap && orig[i + 1] == '\n') { he = i + 2; break; }
                if (i + 2 < kHdrCap && orig[i + 1] == '\r' && orig[i + 2] == '\n') { he = i + 3; break; }
            }
        }
        hdr_end_ = he;
        size_t pos = 0;
        while (pos < hdr_end_) {
            const void *nl = std::memchr(orig + pos, '\n', hdr_end_ - pos);
            size_t line_end = nl ? (size_t)(static_cast<const uint8_t *>(nl) - orig) : hdr_end_;
            ls_.push_back((uint32_t)pos);
            uint32_t colon = UINT32_MAX;
            if (ls_.size() > 1 && orig[pos] != ' ' && orig[pos] != '\t') {
                const void *c = std::memchr(orig + pos, ':', line_end - pos);
                if (c) colon = (uint32_t)(static_cast<const uint8_t *>(c) - orig);
            }
            col_.push_back(colon);
            pos = line_end + 1;
        }
        if (he < n) scan_body(orig, he, n);
    }

    Region classify(size_t off) const
    {
        if (http_ && off < hdr_end_) {
            if (ls_.empty()) return R_HDR_VALUE;
            size_t li = (size_t)(std::upper_bound(ls_.begin(), ls_.end(), (uint32_t)off) - ls_.begin());
            li = li ? li - 1 : 0;
            if (li == 0) return R_STATUS;
            uint32_t c = col_[li];
            return (c != UINT32_MAX && off < c) ? R_HDR_NAME : R_HDR_VALUE;
        }
        if (!spans_.empty()) {
            size_t lo = 0, hi = spans_.size();
            while (lo < hi) { size_t mid = (lo + hi) >> 1; if (spans_[mid].b <= off) lo = mid + 1; else hi = mid; }
            if (lo) { const Span &s = spans_[lo - 1]; if (off < s.e) return (Region)s.r; }
        }
        return default_region_;
    }

    std::string_view header_name_at(size_t off, const uint8_t *orig) const
    {
        if (!http_ || off >= hdr_end_ || ls_.empty()) return std::string_view();
        size_t li = (size_t)(std::upper_bound(ls_.begin(), ls_.end(), (uint32_t)off) - ls_.begin());
        li = li ? li - 1 : 0;
        while (li > 0 && col_[li] == UINT32_MAX) --li;
        if (li == 0) return std::string_view();
        size_t b = ls_[li], c = col_[li];
        if (c <= b) return std::string_view();
        return trim_sv(std::string_view(reinterpret_cast<const char *>(orig) + b, c - b));
    }

    bool   is_http()   const { return http_; }
    size_t header_end() const { return hdr_end_; }
    size_t line_count() const { return ls_.size(); }
    size_t line_start(size_t i) const { return ls_[i]; }
    size_t line_colon(size_t i) const { return col_[i]; }
    size_t line_end(size_t i, size_t n) const
    {
        size_t e = (i + 1 < ls_.size()) ? ls_[i + 1] : std::min(hdr_end_, n);
        return e;
    }

private:
    struct Span { uint32_t b, e; uint8_t r; };

    static bool starts_ci(const uint8_t *s, size_t n, size_t i, const char *lit)
    {
        const size_t l = std::strlen(lit);
        if (i + l > n) return false;
        const auto &lt = lower_table();
        for (size_t k = 0; k < l; ++k) if (lt[s[i + k]] != (uint8_t)lit[k]) return false;
        return true;
    }
    static size_t find_lit_ci(const uint8_t *s, size_t n, size_t from, const char *lit)
    {
        const size_t l = std::strlen(lit);
        if (from >= n || n - from < l) return (size_t)-1;
        const uint8_t *p = s + from, *end = s + n - l + 1;
        while (p < end) {
            p = static_cast<const uint8_t *>(std::memchr(p, (unsigned char)lit[0], (size_t)(end - p)));
            if (!p) return (size_t)-1;
            if (starts_ci(s, n, (size_t)(p - s), lit)) return (size_t)(p - s);
            ++p;
        }
        return (size_t)-1;
    }

    struct NextLit {
        const char *lit; size_t pos = 0; bool valid = false;
        explicit NextLit(const char *l) : lit(l) {}
        size_t find(const uint8_t *s, size_t n, size_t from)
        {
            if (valid && (pos == (size_t)-1 || pos >= from)) return pos;
            pos = find_lit_ci(s, n, from, lit); valid = true; return pos;
        }
    };

    void scan_body(const uint8_t *orig, size_t from, size_t n)
    {
        NextLit n_comment("-->"), n_script("</script"), n_title("</title");
        size_t i = from;
        while (i < n && spans_.size() < 100000) {
            const void *lp = std::memchr(orig + i, '<', n - i);
            if (!lp) break;
            i = (size_t)(static_cast<const uint8_t *>(lp) - orig);
            if (starts_ci(orig, n, i, "<!--")) {
                size_t e = n_comment.find(orig, n, i + 4);
                size_t end = (e == (size_t)-1) ? std::min(n, i + 4096) : e + 3;
                spans_.push_back({ (uint32_t)i, (uint32_t)end, R_COMMENT });
                i = end;
            } else if (starts_ci(orig, n, i, "<script") && i + 7 < n &&
                       (orig[i + 7] == ' ' || orig[i + 7] == '>' || orig[i + 7] == '\t' || orig[i + 7] == '\n' || orig[i + 7] == '\r')) {
                size_t e = n_script.find(orig, n, i + 7);
                size_t end = (e == (size_t)-1) ? n : e;
                spans_.push_back({ (uint32_t)i, (uint32_t)end, R_SCRIPT });
                i = std::max(end, i + 1);
            } else if (starts_ci(orig, n, i, "<title") && i + 6 < n && (orig[i + 6] == '>' || orig[i + 6] == ' ')) {
                const void *gt = std::memchr(orig + i, '>', n - i);
                size_t g = gt ? (size_t)(static_cast<const uint8_t *>(gt) - orig) : n;
                size_t e = n_title.find(orig, n, g);
                size_t end = (e == (size_t)-1) ? std::min(n, g + 512) : e;
                if (g + 1 < end) spans_.push_back({ (uint32_t)(g + 1), (uint32_t)end, R_TITLE });
                i = std::max(end, i + 1);
            } else if (starts_ci(orig, n, i, "<meta") && i + 5 < n &&
                       (orig[i + 5] == ' ' || orig[i + 5] == '\t' || orig[i + 5] == '\n' || orig[i + 5] == '\r')) {
                size_t lim = std::min(n, i + 1024);
                const void *gt = std::memchr(orig + i, '>', lim - i);
                size_t end = gt ? (size_t)(static_cast<const uint8_t *>(gt) - orig) + 1 : lim;
                spans_.push_back({ (uint32_t)i, (uint32_t)end, R_META });
                i = end;
            } else {
                ++i;
            }
        }
    }

    bool     http_ = false;
    size_t   hdr_end_ = 0;
    Region   default_region_ = R_BODY;
    std::vector<uint32_t> ls_, col_;
    std::vector<Span>     spans_;
};

inline bool ci_prefix(const uint8_t *p, size_t avail, const char *lit)
{
    size_t l = std::strlen(lit);
    if (avail < l) return false;
    const auto &lt = lower_table();
    for (size_t i = 0; i < l; ++i) if (lt[p[i]] != (uint8_t)lit[i]) return false;
    return true;
}

inline bool parse_version(const uint8_t *s, size_t from, size_t lim, std::string &out)
{
    size_t p = from;
    int comps = 0, dots = 0;
    uint32_t first = 0, second = 0, third = 0;
    for (;;) {
        size_t d0 = p; uint32_t val = 0;
        while (p < lim && is_digit_c(s[p]) && p - d0 < 6) { val = val * 10 + (uint32_t)(s[p] - '0'); ++p; }
        if (p == d0) break;
        if (p < lim && is_digit_c(s[p])) return false;
        if (comps == 0) first = val; else if (comps == 1) second = val; else if (comps == 2) third = val;
        ++comps;
        if (comps < 4 && p + 1 < lim && s[p] == '.' && is_digit_c(s[p + 1])) { ++p; ++dots; continue; }
        break;
    }
    if (comps == 0 || dots == 0) return false;
    if (comps >= 3 && first >= 1900 && first <= 2100 && second >= 1 && second <= 12 && third >= 1 && third <= 31) return false;
    size_t end = p;
    size_t t = p;
    if (t < lim && s[t] == '-' && t + 1 < lim && is_alpha_c(s[t + 1])) ++t;
    if (t < lim && is_alpha_c(s[t])) {
        size_t te = t;
        while (te < lim && (is_alnum_c(s[te]) || s[te] == '-' || s[te] == '_' ) && te - p < 16) ++te;
        while (te > t && (s[te - 1] == '-' || s[te - 1] == '_')) --te;
        end = te;
    }
    out.assign(reinterpret_cast<const char *>(s + from), end - from);
    return true;
}

inline unsigned version_major(const std::string &v)
{
    unsigned m = 0;
    for (char c : v) { if (!is_digit_c((uint8_t)c)) break; m = m * 10 + (unsigned)(c - '0'); if (m > 99999999u) break; }
    return m;
}

inline bool foreign_word_before(const uint8_t *s, size_t from, size_t q)
{
    size_t e = q, skipped = 0;
    while (e > from && skipped < 3) {
        uint8_t c = s[e - 1];
        if (c == ' ' || c == '/' || c == '-' || c == '_' || c == ':' || c == '=' || c == '(' || c == '\t') { --e; ++skipped; } else break;
    }
    size_t w = e;
    while (w > from && is_alpha_c(s[w - 1])) --w;
    size_t len = e - w;
    if (len < 2) return false;
    static const char *neutral[] = { "version", "ver", "release", "rel", "build", "rev", "edition", "ed" };
    const auto &lt = lower_table();
    for (const char *nw : neutral) {
        size_t l = std::strlen(nw);
        if (l != len) continue;
        bool eq = true;
        for (size_t i = 0; i < l; ++i) if (lt[s[w + i]] != (uint8_t)nw[i]) { eq = false; break; }
        if (eq) return false;
    }
    return true;
}

inline std::string extract_version(const uint8_t *orig, size_t n, size_t hit_end, Region region,
                                   bool strict, size_t window, uint16_t vlo, uint16_t vhi, int *conf_out)
{
    if (conf_out) *conf_out = 0;
    size_t from = hit_end;
    const bool header_like = (region == R_HDR_NAME || region == R_HDR_VALUE || region == R_STATUS);
    size_t lim = std::min(n, from + window);
    if (region == R_HDR_NAME) {
        for (size_t i = from; i < lim; ++i) {
            if (orig[i] == ':') { from = i + 1; break; }
            if (orig[i] == '\n') return std::string();
        }
        lim = std::min(n, from + window);
    }
    size_t stop = from;
    while (stop < lim) {
        uint8_t c = orig[stop];
        if (c == '\r' || c == '\n' || c == 0) break;
        if (!header_like && (c == '<' || c == '>')) break;
        ++stop;
    }
    lim = stop;
    if (from >= lim) return std::string();

    bool blocked = false;
    auto in_range = [&](const std::string &v) { unsigned m = version_major(v); bool ok = (m >= vlo && m <= vhi); if (!ok) blocked = true; return ok; };

    std::string v;
    size_t p = from, skipped = 0;
    auto is_sep = [](uint8_t c) { return c == ' ' || c == '/' || c == '_' || c == '-' || c == ':' || c == '=' || c == '(' || c == '"' || c == '\'' || c == '\t' || c == ','; };
    while (p < lim && is_sep(orig[p]) && skipped < 8) { ++p; ++skipped; }
    if (ci_prefix(orig + p, lim - p, "version")) {
        p += 7; skipped = 0;
        while (p < lim && is_sep(orig[p]) && skipped < 4) { ++p; ++skipped; }
    } else if (p + 1 < lim && (orig[p] == 'v' || orig[p] == 'V') && is_digit_c(orig[p + 1])) {
        ++p;
    }
    if (p < lim && is_digit_c(orig[p]) && parse_version(orig, p, lim, v) && in_range(v)) { if (conf_out) *conf_out = 2; return v; }
    v.clear();
    if (strict) { if (conf_out && blocked) *conf_out = -1; return std::string(); }

    for (size_t q = from; q < lim; ++q) {
        if (!is_digit_c(orig[q])) continue;
        if (q > from && (is_alnum_c(orig[q - 1]) || orig[q - 1] == '.')) { while (q < lim && is_digit_c(orig[q])) ++q; continue; }
        if (parse_version(orig, q, lim, v) && in_range(v) && !foreign_word_before(orig, from, q)) { if (conf_out) *conf_out = 1; return v; }
        v.clear();
        while (q < lim && is_digit_c(orig[q])) ++q;
    }
    if (conf_out && blocked) *conf_out = -1;
    return std::string();
}

inline bool deny_header(const std::string &lname)
{
    static const char *exact[] = {
        "date", "expires", "last-modified", "etag", "cache-control", "pragma", "connection", "keep-alive",
        "vary", "set-cookie", "location", "refresh", "link", "report-to", "nel", "alt-svc", "age",
        "strict-transport-security", "transfer-encoding", "permissions-policy", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "referrer-policy", "user-agent", "retry-after",
        "www-authenticate", "proxy-authenticate", "authorization", "upgrade", "range", "if-none-match",
        "if-modified-since", "origin", "host", "cookie", "traceparent", "tracestate", "x-request-id",
        "x-amz-cf-id", "x-amz-id-2", "x-amz-request-id", "cf-ray", "x-cache-hits", "server-timing",
    };
    for (const char *e : exact) if (lname == e) return true;
    static const char *prefixes[] = { "content-", "access-control-", "cross-origin-", "accept", "sec-", "if-" };
    for (const char *p : prefixes) if (lname.compare(0, std::strlen(p), p) == 0) return true;
    return false;
}

inline bool deny_token(const std::string &lt)
{
    static const char *t[] = { "http", "https", "mozilla", "applewebkit", "khtml", "gecko", "safari", "chrome",
                               "firefox", "version", "text", "application", "image", "audio", "video", "font",
                               "multipart", "charset", "utf", "iso", "rfc", "ietf", "tls", "ssl", "h2", "h3", "quic" };
    for (const char *x : t) if (lt == x) return true;
    return false;
}

namespace detail {

struct Acc {
    int      score = 0;
    int      un = 0;
    int      best_w = -1;
    Region   best_region = R_BODY;
    size_t   ev_start = 0, ev_end = 0;
    int      ver_w = -1;
    int      ver_conf = 0;
    bool     blocked = false;
    std::string version;
    uint16_t rmask = 0;
    uint32_t product = 0;
};

struct Contrib {
    uint32_t term, start, end, product, need, notp;
    Region   r;
    int      w;
};

struct Scratch {
    RegionIndex           idx;
    std::vector<RawHit>   hits;
    std::vector<Contrib>  cs;
    std::vector<uint32_t> order;
    std::vector<uint8_t>  dead;
    std::vector<uint16_t> seen;
    std::vector<uint32_t> seen_touched;
    std::vector<int32_t>  slot;
    std::vector<Acc>      accs;
};

inline Scratch &scratch()
{
    static thread_local Scratch s;
    return s;
}

inline void scan_impl(const TermSet &set, const uint8_t *data, size_t n, const ScanLimits &lim,
                      ScanStats *stats, std::vector<Finding> &out)
{
    Scratch &sc = scratch();
    const auto &lt = lower_table();
    RegionIndex &idx = sc.idx;
    idx.build(data, n);

    struct Cleanup {
        Scratch &s;
        ~Cleanup()
        {
            for (uint32_t t : s.seen_touched) if (t < s.seen.size()) s.seen[t] = 0;
            s.seen_touched.clear();
            for (const Acc &a : s.accs) if (a.product < s.slot.size()) s.slot[a.product] = -1;
            s.accs.clear();
            s.hits.clear();
            s.cs.clear();
        }
    } cleanup{sc};

    auto snippet = [&](size_t start, size_t end, Region r) {
        size_t b = start, e = end;
        if (r == R_HDR_NAME || r == R_HDR_VALUE || r == R_STATUS) {
            while (b > 0 && data[b - 1] != '\n') --b;
            e = std::min(n, std::max(end, b) + 56);
        } else {
            b = start > 12 ? start - 12 : 0;
            e = std::min(n, end + 48);
        }
        std::string s;
        for (size_t i = b; i < e && s.size() < 80; ++i) {
            if (data[i] == '\n' || data[i] == '\r') { if (r == R_HDR_NAME || r == R_HDR_VALUE || r == R_STATUS) break; s += ' '; continue; }
            s += (char)data[i];
        }
        sanitize_inplace(s);
        return s;
    };

    auto lower_str = [&](const std::string &s) {
        std::string k;
        k.reserve(s.size());
        for (unsigned char c : s) k += (char)lt[c];
        return k;
    };

    if (!set.empty()) {
        if (sc.seen.size() != set.term_count()) { sc.seen.assign(set.term_count(), 0); sc.seen_touched.clear(); }
        if (sc.slot.size() != set.product_count()) sc.slot.assign(set.product_count(), -1);
        sc.hits.clear();
        sc.cs.clear();
        sc.accs.clear();
        sc.hits.reserve(64);

        const size_t priority_end = idx.is_http() ? std::min(idx.header_end(), n) : 0;
        set.scan_raw(data, n, lim, sc.hits, [&](size_t off) { return idx.classify(off); }, priority_end, stats);

        for (const RawHit &h : sc.hits) {
            const TermRec &tr = set.term(h.term);
            const TermCtx &cx = set.ctx(h.term);
            const Region r = (Region)h.region;
            const int w = tr.w[r];
            if (w <= 0) continue;
            if (cx.hdr_id && r == R_HDR_VALUE) {
                std::string_view hn = idx.header_name_at(h.start, data);
                if (hn.empty()) continue;
                const std::string &lst = set.hdr_list(cx.hdr_id);
                bool okh = false;
                for (size_t ps = 0; ps <= lst.size() && !okh; ) {
                    size_t sc2 = lst.find(';', ps);
                    std::string_view one(lst.data() + ps, (sc2 == std::string::npos ? lst.size() : sc2) - ps);
                    if (!one.empty() && ieq_lower(hn, one)) okh = true;
                    if (sc2 == std::string::npos) break;
                    ps = sc2 + 1;
                }
                if (!okh) continue;
            }
            sc.cs.push_back(Contrib{ h.term, h.start, h.end, tr.product, cx.need_prod, cx.not_prod, r, w });
        }

        const size_t m = sc.cs.size();
        sc.dead.assign(m, 0);
        sc.order.resize(m);
        for (uint32_t i = 0; i < (uint32_t)m; ++i) sc.order[i] = i;
        std::sort(sc.order.begin(), sc.order.end(), [&](uint32_t a, uint32_t b) {
            const Contrib &x = sc.cs[a], &y = sc.cs[b];
            if (x.product != y.product) return x.product < y.product;
            if (x.r != y.r) return x.r < y.r;
            if (x.need != y.need) return x.need < y.need;
            if (x.notp != y.notp) return x.notp < y.notp;
            if (x.start != y.start) return x.start < y.start;
            if (x.end != y.end) return x.end > y.end;
            return x.term < y.term;
        });
        {
            uint32_t anchor = UINT32_MAX;
            for (uint32_t j : sc.order) {
                const Contrib &c = sc.cs[j];
                if (anchor == UINT32_MAX) { anchor = j; continue; }
                const Contrib &a = sc.cs[anchor];
                const bool same = a.product == c.product && a.r == c.r && a.need == c.need && a.notp == c.notp;
                if (same && c.start >= a.start && c.end <= a.end) {
                    if (c.w > a.w) { sc.dead[anchor] = 1; anchor = j; }
                    else sc.dead[j] = 1;
                } else {
                    anchor = j;
                }
            }
        }

        auto get_acc = [&](uint32_t product) -> size_t {
            int32_t &sl = sc.slot[product];
            if (sl < 0) {
                sl = (int32_t)sc.accs.size();
                sc.accs.emplace_back();
                sc.accs.back().product = product;
            }
            return (size_t)sl;
        };
        auto reset_seen = [&]() {
            for (uint32_t t : sc.seen_touched) sc.seen[t] = 0;
            sc.seen_touched.clear();
        };
        auto mark_seen = [&](uint32_t term, Region r) -> bool {
            uint16_t &mk = sc.seen[term];
            const uint16_t bit = (uint16_t)(1u << r);
            if (mk & bit) return false;
            if (!mk) sc.seen_touched.push_back(term);
            mk |= bit;
            return true;
        };

        for (size_t j = 0; j < m; ++j) {
            if (sc.dead[j]) continue;
            const Contrib &c = sc.cs[j];
            if (c.need || c.notp) continue;
            const size_t ai = get_acc(c.product);
            if (mark_seen(c.term, c.r)) sc.accs[ai].un = std::min(sc.accs[ai].un + c.w, 15);
        }
        reset_seen();

        auto is_present = [&](uint32_t product) {
            const int32_t sl = sc.slot[product];
            return sl >= 0 && sc.accs[(size_t)sl].un >= lim.presence_score;
        };

        for (size_t j = 0; j < m; ++j) {
            if (sc.dead[j]) continue;
            const Contrib &c = sc.cs[j];
            const TermRec &tr = set.term(c.term);
            const TermCtx &cx = set.ctx(c.term);
            if (c.need && !is_present(c.need - 1)) continue;
            if (c.notp && is_present(c.notp - 1)) continue;
            const size_t ai = get_acc(c.product);
            Acc &a = sc.accs[ai];
            if (mark_seen(c.term, c.r)) { a.score = std::min(a.score + c.w, 15); a.rmask |= (uint16_t)(1u << c.r); }
            if (c.w > a.best_w) { a.best_w = c.w; a.best_region = c.r; a.ev_start = c.start; a.ev_end = c.end; }
            if (!(tr.flags & F_NOVER)) {
                int vc = 0;
                std::string v = extract_version(data, n, c.end, c.r, (tr.flags & F_STRICTVER) != 0, lim.version_window, cx.vmaj_lo, cx.vmaj_hi, &vc);
                if (vc < 0) a.blocked = true;
                if (!v.empty() && (vc > a.ver_conf || (vc == a.ver_conf && c.w > a.ver_w))) { a.version = std::move(v); a.ver_w = c.w; a.ver_conf = vc; }
            }
        }
        reset_seen();

        for (const Acc &a : sc.accs) {
            if (a.score < lim.min_score) continue;
            Finding f;
            f.product  = sanitized(set.product_name(a.product));
            f.version  = a.version;
            f.ver_conf = a.version.empty() ? 0 : a.ver_conf;
            f.ver_blocked = a.version.empty() && a.blocked;
            f.score    = a.score;
            f.region   = a.best_region;
            f.rmask    = a.rmask;
            f.evidence = snippet(a.ev_start, a.ev_end, a.best_region);
            int nreg = 0;
            for (int r = 1; r < R_COUNT; ++r) if (a.rmask & (1u << r)) ++nreg;
            const bool strong_region = (a.best_region == R_HDR_VALUE || a.best_region == R_HDR_NAME || a.best_region == R_BANNER ||
                                        a.best_region == R_TITLE || a.best_region == R_META);
            f.confidence = (a.score >= 6 || (nreg >= 2 && a.score >= 4)) ? 3 : (a.score >= 3 ? 2 : 1);
            if (f.ver_conf == 2 && strong_region && f.confidence < 2) f.confidence = 2;
            ev_add(f, evidence_hash(f));
            out.push_back(std::move(f));
        }
    }

    if (idx.is_http()) {
        std::vector<std::string> keys;
        keys.reserve(out.size() + lim.max_generic);
        for (const Finding &f : out) keys.push_back(lower_str(f.product));

        size_t generic = 0;
        for (size_t li = 1; li < idx.line_count() && generic < lim.max_generic; ++li) {
            size_t colon = idx.line_colon(li);
            if (colon == UINT32_MAX) continue;
            size_t ls = idx.line_start(li), le = idx.line_end(li, n);
            while (le > ls && (data[le - 1] == '\r' || data[le - 1] == '\n')) --le;
            if (colon >= le || colon - ls > 64) continue;
            std::string hname;
            hname.reserve(colon - ls);
            for (size_t k = ls; k < colon; ++k) hname += (char)lt[data[k]];
            if (deny_header(hname)) continue;
            size_t vs = colon + 1;
            size_t per_line = 0;
            for (size_t p = vs; p < le && per_line < 6 && generic < lim.max_generic; ++p) {
                if (data[p] != '/' || p == vs) continue;
                size_t t = p;
                while (t > vs && (is_alnum_c(data[t - 1]) || data[t - 1] == '.' || data[t - 1] == '_' || data[t - 1] == '+' || data[t - 1] == '-') && p - t < 32) --t;
                size_t tl = p - t;
                if (tl < 2 || !is_alpha_c(data[t])) continue;
                if (p + 1 >= le || !is_digit_c(data[p + 1])) continue;
                std::string ver;
                if (!parse_version(data, p + 1, le, ver)) continue;
                std::string token((const char *)data + t, tl);
                std::string ltok;
                ltok.reserve(tl);
                for (size_t k = t; k < t + tl; ++k) ltok += (char)lt[data[k]];
                if (deny_token(ltok)) continue;
                bool dup = false;
                for (size_t k = 0; k < out.size(); ++k) {
                    Finding &f = out[k];
                    if (keys[k] == ltok && (f.version == ver || f.version.empty())) {
                        if (f.version.empty() && !f.ver_blocked) { f.version = ver; f.ver_conf = 2; }
                        dup = true; break;
                    }
                }
                if (dup) continue;
                Finding f;
                f.product = sanitized(token); f.version = sanitized(ver); f.score = 2; f.region = R_HDR_VALUE; f.generic = true; f.confidence = 1; f.ver_conf = 2; f.rmask = (uint16_t)(1u << R_HDR_VALUE);
                f.evidence = snippet(ls, le, R_HDR_VALUE);
                ev_add(f, evidence_hash(f));
                out.push_back(std::move(f));
                keys.push_back(ltok);
                ++generic; ++per_line;
            }
        }
    }

    std::stable_sort(out.begin(), out.end(), [](const Finding &a, const Finding &b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.generic != b.generic) return !a.generic;
        return a.product < b.product;
    });
    if (out.size() > lim.max_findings) out.resize(lim.max_findings);
}

}

inline std::vector<Finding> scan(const TermSet &set, const uint8_t *data, size_t n,
                                 const ScanLimits &lim = ScanLimits(), ScanStats *stats = nullptr)
{
    std::vector<Finding> out;
    if (!data || n == 0) return out;
    if (n > lim.max_bytes) n = lim.max_bytes;
    try {
        detail::scan_impl(set, data, n, lim, stats, out);
    } catch (...) {
        out.clear();
        if (stats) stats->failed = true;
    }
    return out;
}

inline void merge_findings(std::vector<Finding> &dst, const std::vector<Finding> &src)
{
    const auto &lt = lower_table();
    auto key = [&](const std::string &s) { std::string k; for (unsigned char c : s) if (is_alnum_c(c)) k += (char)lt[c]; return k; };
    for (const auto &f : src) {
        std::string kf = key(f.product);
        bool found = false;
        for (auto &d : dst) {
            if (key(d.product) != kf) continue;
            bool independent = false;
            for (uint8_t k = 0; k < f.ev_n; ++k) if (!ev_has(d, f.ev_set[k])) { independent = true; break; }
            if (f.score > d.score) { d.score = f.score; d.region = f.region; d.evidence = f.evidence; }
            if (!f.version.empty() && (d.version.empty() || f.ver_conf > d.ver_conf)) { d.version = f.version; d.ver_conf = f.ver_conf; }
            d.rmask |= f.rmask;
            d.generic = d.generic && f.generic;
            d.confidence = std::max(d.confidence, f.confidence);
            if (independent) {
                d.hops_seen += f.hops_seen;
                if (d.hops_seen >= 2 && d.confidence < 3) ++d.confidence;
            }
            for (uint8_t k = 0; k < f.ev_n; ++k) ev_add(d, f.ev_set[k]);
            found = true; break;
        }
        if (!found) dst.push_back(f);
    }
    std::stable_sort(dst.begin(), dst.end(), [](const Finding &a, const Finding &b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.score > b.score;
    });
}

}
