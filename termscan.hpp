// =============================================================================
// termscan.hpp  --  one-pass, location-agnostic term scanner for Shiv
//
//   term list (data, signatures.conf [terms])
//        |
//        v
//   Aho-Corasick automaton  ---- one pass over the WHOLE decoded response ---->  (term, offset)
//        |
//        v
//   offset -> region   (status line / header name / header value / <title> /
//                       <meta> / comment / <script> / body / raw banner)
//        |
//        v
//   per-region weight  ->  per-product score
//   offset -> bounded window -> hand-written version matcher -> "8.11.1"
//
// No header field, meta field or body region has to be named in C++ code.
// A new product is one line in [terms]; no recompile.
//
// Extras over the plain idea (v2):
//   * context rules per term:  hdr:<name[;name]>  (a header-VALUE hit only counts inside those headers; other regions unaffected)
//                              needs:<Product>     (only counts if <Product> has unconditional evidence)
//                              not:<Product>       (dropped if <Product> has unconditional evidence)
//                              vmaj:LO-HI          (reject versions whose major number is outside LO..HI)
//   * confidence levels (possible / likely / confirmed) + version confidence (nearby / adjacent)
//   * version fallback no longer steals the number of a DIFFERENT product ("nginx OpenSSL/1.1.1")
//   * amortised-linear body span indexer (unclosed <!-- / <title flood can no longer cost O(n^2))
//   * generic "Name/1.2.3" discovery inside EVERY header value, so products that
//     are in no signature list at all still show up (Server: Apache/2.4 OpenSSL/1.1.1f ...)
//   * mmap-based loading (MAP_POPULATE + madvise) of the signature file
//   * a compiled-automaton cache (<conf>.tscache) that is itself mmap'd and used
//     in place (zero parse, zero copy) on the next start; keyed by a hash of the
//     signature file, so it can never go stale
//   * hard limits everywhere (file size, term count, node count, scan bytes, hits)
//   * UTF-8 aware terminal sanitiser: target-controlled bytes (ESC, C1 controls,
//     bidi overrides) can never reach the operator's terminal
//
// Thread safety: a built TermSet is immutable; scan() uses thread_local scratch.
// =============================================================================
#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// ----------------------------------------------------------------------------
// Regions
// ----------------------------------------------------------------------------
enum Region : uint8_t {
    R_STATUS = 0,   // "HTTP/1.1 200 OK"
    R_HDR_NAME,     // left of the first ':' on a header line
    R_HDR_VALUE,    // right of it (and obs-fold continuation lines)
    R_TITLE,        // inside <title>..</title>
    R_META,         // inside a <meta ...> tag
    R_COMMENT,      // inside <!-- ... -->
    R_SCRIPT,       // inside a <script ...> tag or its body
    R_BODY,         // any other HTML / body byte
    R_BANNER,       // non-HTTP, non-HTML raw banner (SSH-2.0-..., 220 ftp ..., etc.)
    R_COUNT
};

inline const char *region_name(Region r)
{
    static const char *n[R_COUNT] = { "status", "hdr-name", "hdr-value", "title",
                                      "meta", "comment", "script", "body", "banner" };
    return r < R_COUNT ? n[r] : "?";
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
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

// 64-bit non-cryptographic hash, 8 bytes per step (cache keying / corruption check).
inline uint64_t hash64(const void *data, size_t n)
{
    const uint8_t *p = static_cast<const uint8_t *>(data);
    uint64_t h = 0x9E3779B97F4A7C15ULL ^ (uint64_t)n;
    while (n >= 8) {
        uint64_t v; std::memcpy(&v, p, 8);
        h ^= v; h *= 0xFF51AFD7ED558CCDULL; h ^= h >> 32;
        p += 8; n -= 8;
    }
    uint64_t tail = 0;
    if (n) { std::memcpy(&tail, p, n); h ^= tail; h *= 0xC4CEB9FE1A85EC53ULL; h ^= h >> 29; }
    return h;
}

// ----------------------------------------------------------------------------
// Terminal sanitiser.  Everything that came from a remote target and is about to
// be printed goes through this.  Valid UTF-8 is preserved; C0/C1 controls,
// invalid sequences, line/paragraph separators and bidi overrides become '.'/'?'.
// ----------------------------------------------------------------------------
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
        unsigned char c = (unsigned char)s[i];
        if (c == '\t') { out += ' '; ++i; continue; }
        if (c < 0x20 || c == 0x7f) { out += '.'; ++i; continue; }
        if (c < 0x80) { out += (char)c; ++i; continue; }

        size_t len = 0;
        if      (c >= 0xC2 && c <= 0xDF) len = 2;
        else if (c >= 0xE0 && c <= 0xEF) len = 3;
        else if (c >= 0xF0 && c <= 0xF4) len = 4;
        bool ok = (len != 0 && i + len <= n);
        if (ok) {
            for (size_t k = 1; k < len; ++k)
                if (((unsigned char)s[i + k] & 0xC0) != 0x80) { ok = false; break; }
        }
        if (ok) {
            unsigned char c1 = (unsigned char)s[i + 1];
            if (c == 0xE0 && c1 < 0xA0) ok = false;                 // overlong
            if (c == 0xED && c1 > 0x9F) ok = false;                 // surrogate
            if (c == 0xF0 && c1 < 0x90) ok = false;                 // overlong
            if (c == 0xF4 && c1 > 0x8F) ok = false;                 // > U+10FFFF
            if (c == 0xC2 && c1 < 0xA0) ok = false;                 // C1 controls U+0080..U+009F
            if (c == 0xE2 && c1 == 0x80) {                          // U+200E/F, 2028/9, 202A-E
                unsigned char c2 = (unsigned char)s[i + 2];
                if (c2 == 0x8E || c2 == 0x8F || c2 == 0xA8 || c2 == 0xA9 || (c2 >= 0xAA && c2 <= 0xAE)) ok = false;
            }
            if (c == 0xE2 && c1 == 0x81) {                          // U+2066..U+2069 bidi isolates
                unsigned char c2 = (unsigned char)s[i + 2];
                if (c2 >= 0xA6 && c2 <= 0xA9) ok = false;
            }
        }
        if (!ok) { out += '?'; ++i; continue; }
        out.append(s, i, len);
        i += len;
    }
    s.swap(out);
}

inline std::string sanitized(std::string s) { sanitize_inplace(s); return s; }

// ----------------------------------------------------------------------------
// Read-only file mapping.
//   * open(O_RDONLY|O_CLOEXEC|O_NOCTTY), fstat on the SAME descriptor (no TOCTOU)
//   * must be a regular file, size-capped
//   * mmap(MAP_PRIVATE|MAP_POPULATE) + madvise(SEQUENTIAL|WILLNEED[|HUGEPAGE])
//   * falls back to read() if mmap is refused (e.g. odd filesystems)
//   * warns (does not fail) if the file is group/world-writable or owned by
//     somebody other than root / the effective user
// NOTE: like any mmap consumer, truncating the file while it is being parsed can
// raise SIGBUS.  Replace signature files atomically (rename), do not truncate.
// ----------------------------------------------------------------------------
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
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
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
        size_ = (size_t)st.st_size;
        mtime_ns_ = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
        if (size_ == 0) { ::close(fd); return true; }

        int flags = MAP_PRIVATE;
#ifdef MAP_POPULATE
        flags |= MAP_POPULATE;           // pre-fault the whole file in one go
#endif
        void *m = ::mmap(nullptr, size_, PROT_READ, flags, fd, 0);
        if (m != MAP_FAILED) {
            map_ = m;
#ifdef MADV_SEQUENTIAL
            ::madvise(map_, size_, MADV_SEQUENTIAL);
#endif
#ifdef MADV_WILLNEED
            ::madvise(map_, size_, MADV_WILLNEED);
#endif
#ifdef MADV_HUGEPAGE
            if (size_ >= (size_t)(4u << 20)) ::madvise(map_, size_, MADV_HUGEPAGE);
#endif
            ::close(fd);
            return true;
        }
        // fallback: plain read()
        fallback_.resize(size_);
        size_t off = 0;
        while (off < size_) {
            ssize_t r = ::read(fd, fallback_.data() + off, size_ - off);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            off += (size_t)r;
        }
        ::close(fd);
        if (off != size_) { fallback_.clear(); size_ = 0; if (err) *err = "short read on '" + path + "'"; return false; }
        return true;
    }

    // Random-access hint for the lookup phase (cache files are probed, not streamed).
    void advise_random()
    {
#ifdef MADV_RANDOM
        if (map_) ::madvise(map_, size_, MADV_RANDOM);
#endif
    }

    const char *data() const { return map_ ? static_cast<const char *>(map_) : fallback_.data(); }
    size_t size() const { return size_; }
    int64_t mtime_ns() const { return mtime_ns_; }
    std::string_view view() const { return std::string_view(data(), size_); }

    void close()
    {
        if (map_) { ::munmap(map_, size_); map_ = nullptr; }
        fallback_.clear(); fallback_.shrink_to_fit();
        size_ = 0; mtime_ns_ = 0;
    }

private:
    void steal(MappedFile &o)
    {
        map_ = o.map_; size_ = o.size_; mtime_ns_ = o.mtime_ns_; fallback_ = std::move(o.fallback_);
        o.map_ = nullptr; o.size_ = 0; o.mtime_ns_ = 0;
    }
    void   *map_ = nullptr;
    size_t  size_ = 0;
    int64_t mtime_ns_ = 0;
    std::vector<char> fallback_;
};

// ----------------------------------------------------------------------------
// Limits (all hard caps)
// ----------------------------------------------------------------------------
struct ScanLimits {
    size_t max_bytes         = 2u << 20;   // never scan more than 2 MiB of one response
    size_t max_hits          = 2048;       // total raw automaton hits kept
    size_t max_hits_per_term = 4;          // one noisy term cannot flood the hit list
    size_t max_findings      = 24;
    int    min_score         = 2;          // product must reach this score to be reported
    size_t version_window    = 96;         // bytes inspected after a hit for a version
    size_t max_generic       = 12;         // generic Name/1.2.3 discoveries per response
};

inline constexpr size_t kMaxSigFileBytes = 64u << 20;   // 64 MiB signature file cap
inline constexpr size_t kMaxTerms        = 400000;
inline constexpr size_t kMaxNodes        = 8000000;
inline constexpr size_t kMaxNeedleLen    = 120;
inline constexpr size_t kMaxProductLen   = 64;

// ----------------------------------------------------------------------------
// Findings
// ----------------------------------------------------------------------------
struct Finding {
    std::string product;
    std::string version;
    std::string evidence;     // short sanitised snippet around the hit
    int         score   = 0;
    Region      region  = R_BODY;
    bool        generic = false;     // found by Name/1.2.3 discovery, not by a [terms] entry
    int         confidence = 1;      // 1 possible, 2 likely, 3 confirmed (see conf_name)
    int         ver_conf   = 0;      // 0 none, 1 nearby (same line/tag), 2 adjacent to the product name
    bool        ver_blocked = false; // a version was seen but rejected by the term's vmaj: range
    uint16_t    rmask      = 0;      // bit r set => a scored hit existed in region r
    int         hops_seen  = 1;      // number of responses (redirect hops) that reported it

    std::string display() const { return version.empty() ? product : product + " " + version; }
};

inline const char *conf_name(int c)
{
    return c >= 3 ? "confirmed" : c == 2 ? "likely" : "possible";
}
inline const char *verconf_name(int c)
{
    return c >= 2 ? "adjacent" : c == 1 ? "nearby" : "none";
}

// ----------------------------------------------------------------------------
// Compiled automaton
// ----------------------------------------------------------------------------
enum : uint8_t { F_SUBSTR = 1, F_NOVER = 2, F_STRICTVER = 4 };

struct TermRec {                    // 16 bytes
    uint32_t product;
    uint8_t  len;
    uint8_t  flags;
    int8_t   w[R_COUNT];            // 9
    uint8_t  pad;
};
struct Node {                       // 20 bytes
    uint32_t edge_off;
    uint16_t edge_cnt;
    uint16_t out_cnt;
    uint32_t out_off;
    uint32_t fail;
    uint32_t dict;                  // nearest proper-suffix node that has outputs (0 = none)
};
struct Edge {                       // 8 bytes
    uint8_t  ch;
    uint8_t  pad[3];
    uint32_t to;
};
static_assert(sizeof(TermRec) == 16, "TermRec layout");
static_assert(sizeof(Node) == 20, "Node layout");
static_assert(sizeof(Edge) == 8, "Edge layout");

struct TermCtx {                    // 16 bytes, parallel to TermRec
    uint16_t hdr_id;                // 0 = none, else 1-based index into the header-list table
    uint16_t pad;
    uint32_t need_prod;             // 0 = none, else product index + 1
    uint32_t not_prod;              // 0 = none, else product index + 1
    uint16_t vmaj_lo;               // accepted major-version range (default 0..65535)
    uint16_t vmaj_hi;
};
static_assert(sizeof(TermCtx) == 16, "TermCtx layout");

struct CacheHeader {                // 128 bytes
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

struct RawHit { uint32_t term; uint32_t start; uint32_t end; };

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
    // header-list id (1-based) -> "server;x-powered-by"
    const std::string &hdr_list(uint16_t id) const { static const std::string e; return (id && id <= hdrs_.size()) ? hdrs_[id - 1] : e; }
    const std::string &product_name(uint32_t i) const { return products_[i]; }

    // ---- building from "[terms]" lines ------------------------------------
    // line format:   needle | Product | spec
    //   spec = comma list of  H3 N3 T2 M2 C1 S1 B1 X3  (region weights 0..9),
    //          A<n> (all regions), sub (no word boundary), nover, strict,
    //          hdr:<name[;name]>, needs:<Product>, not:<Product>, vmaj:LO-HI
    //   Defaults: H3 N3 T2 M2 C1 S1 B1 X3, status-line 0, word-boundary on.
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
                for (unsigned char c : tok.substr(4)) {
                    c = lt[c];
                    if (!(is_alnum_c(c) || c == '-' || c == '_' || c == ';')) { if (err) *err = "bad character in hdr: list"; return false; }
                    h += (char)c;
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

    // Compile pending terms into the automaton.
    bool build(std::string *err)
    {
        // intern products, dedupe (needle,product) with last-wins
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

        // ---- trie ----
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
        // ---- BFS: failure + dictionary links; renumber nodes in BFS order ----
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

    // ---- compiled-automaton cache ------------------------------------------
    bool load_cache(const std::string &path, uint64_t src_hash, uint64_t src_size)
    {
        MappedFile mf;
        std::string e;
        if (!mf.open(path, kMaxSigFileBytes * 2, &e, MappedFile::PERM_STRICT)) return false;
        if (mf.size() < sizeof(CacheHeader)) return false;
        const uint8_t *base = reinterpret_cast<const uint8_t *>(mf.data());
        if ((reinterpret_cast<uintptr_t>(base) & 7u) != 0) return false;      // sections must be 8-aligned
        CacheHeader h; std::memcpy(&h, base, sizeof(h));
        if (std::memcmp(h.magic, "SHIVTS02", 8) != 0 || h.version != 2 || h.endian != 0x01020304u) return false;
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

        // products
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
        // structural validation: nothing in the scan loop may index out of range
        // or loop forever, even if the cache is corrupt.
        for (uint32_t i = 0; i < h.n_terms; ++i)
            if (tr[i].product >= h.n_products || tr[i].len == 0 || tr[i].len > kMaxNeedleLen) return false;
        for (uint32_t i = 0; i < h.n_nodes; ++i) {
            const Node &n = nd[i];
            if ((uint64_t)n.edge_off + n.edge_cnt > h.n_edges) return false;
            if ((uint64_t)n.out_off  + n.out_cnt  > h.n_outs)  return false;
            if (i == 0) { if (n.fail || n.dict || n.out_cnt) return false; }
            else if (n.fail >= i || n.dict >= i) return false;               // BFS order => strictly decreasing
            for (uint32_t k = 0; k < n.edge_cnt; ++k) {
                if (ed[n.edge_off + k].to <= i || ed[n.edge_off + k].to >= h.n_nodes) return false;
                if (k && ed[n.edge_off + k].ch <= ed[n.edge_off + k - 1].ch) return false;   // sorted, unique
            }
        }
        for (uint32_t i = 0; i < h.n_outs; ++i) if (ou[i] >= h.n_terms) return false;
        for (uint32_t i = 0; i < h.n_terms; ++i) {
            if (cx[i].hdr_id > h.n_hdrs || cx[i].need_prod > h.n_products || cx[i].not_prod > h.n_products || cx[i].vmaj_lo > cx[i].vmaj_hi) return false;
        }

        mf.advise_random();
        cache_map_ = std::move(mf);
        // the move keeps the same mapping address, so recompute pointers from the new owner
        base = reinterpret_cast<const uint8_t *>(cache_map_.data());
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
        std::memcpy(h.magic, "SHIVTS02", 8);
        h.version = 2; h.endian = 0x01020304u; h.src_hash = src_hash; h.src_size = src_size;
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
        std::memcpy(buf.data() + h.off_terms, terms_, n_terms_ * sizeof(TermRec));
        std::memcpy(buf.data() + h.off_nodes, nodes_, n_nodes_ * sizeof(Node));
        if (n_edges_) std::memcpy(buf.data() + h.off_edges, edges_, n_edges_ * sizeof(Edge));
        if (n_outs_)  std::memcpy(buf.data() + h.off_outs, outs_, n_outs_ * 4);
        std::memcpy(buf.data() + h.off_strings, strings.data(), strings.size());
        if (n_terms_) std::memcpy(buf.data() + h.off_ctx, ctxs_, n_terms_ * sizeof(TermCtx));
        h.payload_hash = hash64(buf.data() + sizeof(CacheHeader), buf.size() - sizeof(CacheHeader));
        std::memcpy(buf.data(), &h, sizeof(h));

        // atomic publish: unique temp file next to the target (O_EXCL, no symlink following), then rename
        std::string tmpl = path + ".XXXXXX";
        std::vector<char> tp(tmpl.begin(), tmpl.end()); tp.push_back('\0');
        int fd = ::mkstemp(tp.data());
        if (fd < 0) return false;
        ::fchmod(fd, 0644);
        size_t w = 0;
        while (w < buf.size()) {
            ssize_t r = ::write(fd, buf.data() + w, buf.size() - w);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { ::close(fd); ::unlink(tp.data()); return false; }
            w += (size_t)r;
        }
        ::close(fd);
        if (::rename(tp.data(), path.c_str()) != 0) { ::unlink(tp.data()); return false; }
        return true;
    }

    // ---- the one pass ---------------------------------------------------------
    // 'low' is the lower-cased copy of the response, 'n' its length.
    void scan_raw(const uint8_t *low, size_t n, const ScanLimits &lim, std::vector<RawHit> &hits) const
    {
        if (n_nodes_ <= 1 || n_terms_ == 0) return;
        static thread_local std::vector<uint8_t> per_term;
        if (per_term.size() < n_terms_) per_term.assign(n_terms_, 0);
        std::vector<uint32_t> touched;

        uint32_t st = 0;
        for (size_t i = 0; i < n; ++i) {
            const uint8_t c = low[i];
            for (;;) {
                uint32_t nx = step(st, c);
                if (nx) { st = nx; break; }
                if (st == 0) break;
                st = nodes_[st].fail;
            }
            uint32_t s = nodes_[st].out_cnt ? st : nodes_[st].dict;
            while (s) {
                const Node &nd = nodes_[s];
                for (uint32_t k = 0; k < nd.out_cnt; ++k) {
                    uint32_t t = outs_[nd.out_off + k];
                    const TermRec &tr = terms_[t];
                    size_t end = i + 1, start = end - tr.len;
                    if (!(tr.flags & F_SUBSTR)) {
                        // word boundary only on the side where the needle itself starts/ends alnum
                        // (needle bytes are lower-case, so the first/last byte is read from the text)
                        if (is_alnum_c(low[start]) && start > 0 && is_alnum_c(low[start - 1])) continue;
                        if (is_alnum_c(low[end - 1]) && end < n && is_alnum_c(low[end])) continue;
                    }
                    if (per_term[t] >= lim.max_hits_per_term) continue;
                    if (per_term[t]++ == 0) touched.push_back(t);
                    if (hits.size() >= lim.max_hits) goto done;
                    hits.push_back(RawHit{ t, (uint32_t)start, (uint32_t)end });
                }
                s = nodes_[s].dict;
            }
        }
    done:
        for (uint32_t t : touched) per_term[t] = 0;
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

    // build-time staging
    std::vector<Pending>     pending_;
    std::vector<std::string> needles_;
    // owned storage (when built from text)
    std::vector<TermRec>     own_terms_;
    std::vector<Node>        own_nodes_;
    std::vector<Edge>        own_edges_;
    std::vector<uint32_t>    own_outs_;
    std::vector<std::string> own_products_;
    std::vector<TermCtx>     own_ctxs_;
    std::vector<std::string> own_hdrs_;
    // mapped storage (when loaded from cache)
    MappedFile               cache_map_;
    // active views
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

// ----------------------------------------------------------------------------
// offset -> region
// ----------------------------------------------------------------------------
class RegionIndex {
public:
    void build(const uint8_t *orig, const uint8_t *low, size_t n)
    {
        http_ = n >= 5 && std::memcmp(orig, "HTTP/", 5) == 0;
        hdr_end_ = 0;
        default_region_ = R_BODY;
        if (!http_) {
            // raw banner unless it is clearly markup
            size_t probe = std::min<size_t>(n, 1024);
            bool markup = false;
            for (size_t i = 0; i + 5 <= probe; ++i)
                if (low[i] == '<' && (std::memcmp(low + i, "<html", 5) == 0 || std::memcmp(low + i, "<!doc", 5) == 0)) { markup = true; break; }
            default_region_ = markup ? R_BODY : R_BANNER;
            if (markup) scan_body(orig, low, 0, n);
            return;
        }
        const size_t kHdrCap = std::min<size_t>(n, 32768);
        size_t he = kHdrCap;
        for (size_t i = 0; i < kHdrCap; ++i) {
            if (low[i] == '\n') {
                if (i + 1 < kHdrCap && low[i + 1] == '\n') { he = i + 2; break; }
                if (i + 2 < kHdrCap && low[i + 1] == '\r' && low[i + 2] == '\n') { he = i + 3; break; }
            }
        }
        hdr_end_ = he;
        size_t pos = 0;
        while (pos < hdr_end_ && ls_.size() < 512) {
            const void *nl = std::memchr(orig + pos, '\n', hdr_end_ - pos);
            size_t line_end = nl ? (size_t)(static_cast<const uint8_t *>(nl) - orig) : hdr_end_;
            ls_.push_back((uint32_t)pos);
            uint32_t colon = UINT32_MAX;
            if (ls_.size() > 1) {
                const void *c = std::memchr(orig + pos, ':', line_end - pos);
                if (c) colon = (uint32_t)(static_cast<const uint8_t *>(c) - orig);
            }
            col_.push_back(colon);
            pos = line_end + 1;
        }
        if (he < n) scan_body(orig, low, he, n);
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

    // lower-cased header name of the line containing 'off' (walks back over folded lines)
    std::string_view header_name_at(size_t off, const uint8_t *low) const
    {
        if (!http_ || off >= hdr_end_ || ls_.empty()) return std::string_view();
        size_t li = (size_t)(std::upper_bound(ls_.begin(), ls_.end(), (uint32_t)off) - ls_.begin());
        li = li ? li - 1 : 0;
        while (li > 0 && col_[li] == UINT32_MAX) --li;
        if (li == 0) return std::string_view();
        size_t b = ls_[li], c = col_[li];
        if (c <= b) return std::string_view();
        return trim_sv(std::string_view(reinterpret_cast<const char *>(low) + b, c - b));
    }

    bool   is_http()   const { return http_; }
    size_t header_end() const { return hdr_end_; }
    size_t line_count() const { return ls_.size(); }
    size_t line_start(size_t i) const { return ls_[i]; }
    size_t line_colon(size_t i) const { return col_[i]; }   // UINT32_MAX if none
    size_t line_end(size_t i, size_t n) const
    {
        size_t e = (i + 1 < ls_.size()) ? ls_[i + 1] : std::min(hdr_end_, n);
        return e;
    }

private:
    struct Span { uint32_t b, e; uint8_t r; };

    static bool starts(const uint8_t *low, size_t n, size_t i, const char *lit)
    {
        size_t l = std::strlen(lit);
        return i + l <= n && std::memcmp(low + i, lit, l) == 0;
    }
    static size_t find_lit(const uint8_t *low, size_t n, size_t from, const char *lit)
    {
        size_t l = std::strlen(lit);
        if (from >= n || n - from < l) return (size_t)-1;
        const uint8_t *p = low + from, *end = low + n - l + 1;
        while (p < end) {
            p = static_cast<const uint8_t *>(std::memchr(p, (unsigned char)lit[0], (size_t)(end - p)));
            if (!p) return (size_t)-1;
            if (std::memcmp(p, lit, l) == 0) return (size_t)(p - low);
            ++p;
        }
        return (size_t)-1;
    }

    // Memoised "next occurrence" so repeated unclosed openers cannot make the body
    // indexer quadratic: a literal that is known to be absent (or whose next hit is
    // still ahead) is never searched for again.
    struct NextLit {
        const char *lit; size_t pos = 0; bool valid = false;
        explicit NextLit(const char *l) : lit(l) {}
        size_t find(const uint8_t *low, size_t n, size_t from)
        {
            if (valid && (pos == (size_t)-1 || pos >= from)) return pos;
            pos = find_lit(low, n, from, lit); valid = true; return pos;
        }
    };

    void scan_body(const uint8_t *orig, const uint8_t *low, size_t from, size_t n)
    {
        (void)orig;
        NextLit n_comment("-->"), n_script("</script"), n_title("</title");
        size_t i = from;
        while (i < n && spans_.size() < 100000) {
            const void *lt = std::memchr(low + i, '<', n - i);
            if (!lt) break;
            i = (size_t)(static_cast<const uint8_t *>(lt) - low);
            if (starts(low, n, i, "<!--")) {
                size_t e = n_comment.find(low, n, i + 4);
                size_t end = (e == (size_t)-1) ? std::min(n, i + 4096) : e + 3;
                spans_.push_back({ (uint32_t)i, (uint32_t)end, R_COMMENT });
                i = end;
            } else if (starts(low, n, i, "<script") && i + 7 < n && (low[i + 7] == ' ' || low[i + 7] == '>' || low[i + 7] == '\t' || low[i + 7] == '\n' || low[i + 7] == '\r')) {
                size_t e = n_script.find(low, n, i + 7);
                size_t end = (e == (size_t)-1) ? n : e;
                spans_.push_back({ (uint32_t)i, (uint32_t)end, R_SCRIPT });
                i = std::max(end, i + 1);
            } else if (starts(low, n, i, "<title") && i + 6 < n && (low[i + 6] == '>' || low[i + 6] == ' ')) {
                const void *gt = std::memchr(low + i, '>', n - i);
                size_t g = gt ? (size_t)(static_cast<const uint8_t *>(gt) - low) : n;
                size_t e = n_title.find(low, n, g);
                size_t end = (e == (size_t)-1) ? std::min(n, g + 512) : e;
                if (g + 1 < end) spans_.push_back({ (uint32_t)(g + 1), (uint32_t)end, R_TITLE });
                i = std::max(end, i + 1);
            } else if (starts(low, n, i, "<meta") && i + 5 < n && (low[i + 5] == ' ' || low[i + 5] == '\t' || low[i + 5] == '\n' || low[i + 5] == '\r')) {
                size_t lim = std::min(n, i + 1024);
                const void *gt = std::memchr(low + i, '>', lim - i);
                size_t end = gt ? (size_t)(static_cast<const uint8_t *>(gt) - low) + 1 : lim;
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
    std::vector<Span>     spans_;     // sorted, non-overlapping
};

// ----------------------------------------------------------------------------
// Version matcher (hand written, no regex, bounded)
//   N(.N){1,3}  followed by an optional short tag:  p1  k  rc1  -beta2  -ubuntu
// ----------------------------------------------------------------------------
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
        if (p < lim && is_digit_c(s[p])) return false;               // > 6 digits: not a version
        if (comps == 0) first = val; else if (comps == 1) second = val; else if (comps == 2) third = val;
        ++comps;
        if (comps < 4 && p + 1 < lim && s[p] == '.' && is_digit_c(s[p + 1])) { ++p; ++dots; continue; }
        break;
    }
    if (comps == 0 || dots == 0) return false;
    // calendar dates (2024.05.17) are not product versions
    if (comps >= 3 && first >= 1900 && first <= 2100 && second >= 1 && second <= 12 && third >= 1 && third <= 31) return false;
    size_t end = p;
    // short alphanumeric tag:  1.1.1k  8.9p1  2.0rc1  3.1-beta2  1.18.0-ubuntu
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

// true when the number at q is directly introduced by some OTHER word ("... OpenSSL 1.1.1"),
// i.e. it almost certainly belongs to a different product than the one we are looking at.
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

// conf_out: 2 = version adjacent to the product name, 1 = nearby in the same line/tag
inline std::string extract_version(const uint8_t *orig, size_t n, size_t hit_end, Region region,
                                   bool strict, size_t window, uint16_t vlo, uint16_t vhi, int *conf_out)
{
    if (conf_out) *conf_out = 0;
    size_t from = hit_end;
    const bool header_like = (region == R_HDR_NAME || region == R_HDR_VALUE || region == R_STATUS);
    size_t lim = std::min(n, from + window);
    if (region == R_HDR_NAME) {                       // version lives in the value, after the colon
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
    // A) adjacent:  <term> [sep]{0,8} [version] [v]N.N
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

    // B) nearest dotted version later in the same line / tag, but never one that is
    //    introduced by a different word (that number belongs to another product)
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

// ----------------------------------------------------------------------------
// Generic "Name/1.2.3" discovery in header values (products no list knows about)
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// The scanner entry point
// ----------------------------------------------------------------------------
inline std::vector<Finding> scan(const TermSet &set, const uint8_t *data, size_t n,
                                 const ScanLimits &lim = ScanLimits())
{
    std::vector<Finding> out;
    if (!data || n == 0) return out;
    if (n > lim.max_bytes) n = lim.max_bytes;

    static thread_local std::vector<uint8_t> low;
    low.resize(n);
    const auto &lt = lower_table();
    for (size_t i = 0; i < n; ++i) low[i] = lt[data[i]];

    RegionIndex idx;
    idx.build(data, low.data(), n);

    // evidence snippet around a hit
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

    // ---- 1. term hits ---------------------------------------------------------
    struct Acc { int score = 0; int best_w = -1; Region best_region = R_BODY; size_t ev_start = 0, ev_end = 0;
                 int ver_w = -1; int ver_conf = 0; bool blocked = false; std::string version; uint16_t rmask = 0; };
    std::unordered_map<uint32_t, Acc> acc;

    if (!set.empty()) {
        std::vector<RawHit> hits;
        hits.reserve(64);
        set.scan_raw(low.data(), n, lim, hits);

        // pass 1: classify every hit, apply hdr: filters, find products with UNCONDITIONAL evidence
        struct Contrib { uint32_t term; uint32_t start, end; Region r; int w; };
        std::vector<Contrib> cs;
        cs.reserve(hits.size());
        std::unordered_map<uint32_t, bool> present;           // product -> has unconditional evidence
        for (const RawHit &h : hits) {
            const TermRec &tr = set.term(h.term);
            const TermCtx &cx = set.ctx(h.term);
            Region r = idx.classify(h.start);
            int w = tr.w[r];
            if (w <= 0) continue;
            if (cx.hdr_id && r == R_HDR_VALUE) {               // header-value hits must sit in one of the named headers
                std::string_view hn = idx.header_name_at(h.start, low.data());
                if (hn.empty()) continue;
                const std::string &lst = set.hdr_list(cx.hdr_id);
                bool okh = false;
                for (size_t ps = 0; ps <= lst.size() && !okh; ) {
                    size_t sc = lst.find(';', ps);
                    std::string_view one(lst.data() + ps, (sc == std::string::npos ? lst.size() : sc) - ps);
                    if (!one.empty() && one == hn) okh = true;
                    if (sc == std::string::npos) break;
                    ps = sc + 1;
                }
                if (!okh) continue;
            }
            cs.push_back(Contrib{ h.term, h.start, h.end, r, w });
            if (!cx.need_prod && !cx.not_prod) present[tr.product] = true;
        }
        // pass 2: needs:/not: conditions, then scoring
        std::unordered_map<uint32_t, uint16_t> seen;      // term -> bitmask of regions already scored
        for (const Contrib &c : cs) {
            const TermRec &tr = set.term(c.term);
            const TermCtx &cx = set.ctx(c.term);
            if (cx.need_prod && !present.count(cx.need_prod - 1)) continue;
            if (cx.not_prod  &&  present.count(cx.not_prod  - 1)) continue;
            Region r = c.r; int w = c.w;
            Acc &a = acc[tr.product];
            uint16_t &m = seen[c.term];
            if (!(m & (1u << r))) { m |= (uint16_t)(1u << r); a.score = std::min(a.score + w, 15); a.rmask |= (uint16_t)(1u << r); }
            if (w > a.best_w) { a.best_w = w; a.best_region = r; a.ev_start = c.start; a.ev_end = c.end; }
            if (!(tr.flags & F_NOVER)) {
                int vc = 0;
                std::string v = extract_version(data, n, c.end, r, (tr.flags & F_STRICTVER) != 0, lim.version_window, cx.vmaj_lo, cx.vmaj_hi, &vc);
                if (vc < 0) a.blocked = true;
                if (!v.empty() && (vc > a.ver_conf || (vc == a.ver_conf && w > a.ver_w))) { a.version = std::move(v); a.ver_w = w; a.ver_conf = vc; }
            }
        }
        for (auto &kv : acc) {
            const Acc &a = kv.second;
            if (a.score < lim.min_score) continue;
            Finding f;
            f.product  = set.product_name(kv.first);
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
            out.push_back(std::move(f));
        }
    }

    // ---- 2. generic Name/1.2.3 discovery ---------------------------------------
    if (idx.is_http()) {
        size_t generic = 0;
        for (size_t li = 1; li < idx.line_count() && generic < lim.max_generic; ++li) {
            size_t colon = idx.line_colon(li);
            if (colon == UINT32_MAX) continue;
            size_t ls = idx.line_start(li), le = idx.line_end(li, n);
            while (le > ls && (data[le - 1] == '\r' || data[le - 1] == '\n')) --le;
            if (colon >= le || colon - ls > 64) continue;
            std::string hname((const char *)low.data() + ls, colon - ls);
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
                std::string ltok((const char *)low.data() + t, tl);
                if (deny_token(ltok)) continue;
                bool dup = false;
                for (auto &f : out) {
                    std::string lp; for (unsigned char c : f.product) lp += (char)lt[c];
                    if (lp == ltok && (f.version == ver || f.version.empty())) { if (f.version.empty() && !f.ver_blocked) { f.version = ver; f.ver_conf = 2; } dup = true; break; }
                }
                if (dup) continue;
                Finding f;
                f.product = sanitized(token); f.version = sanitized(ver); f.score = 2; f.region = R_HDR_VALUE; f.generic = true; f.confidence = 1; f.ver_conf = 2; f.rmask = (uint16_t)(1u << R_HDR_VALUE);
                f.evidence = snippet(ls, le, R_HDR_VALUE);
                out.push_back(std::move(f));
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
    return out;
}

// merge findings from several hops: union by case-insensitive product name,
// keep the higher score / better version, and treat the same product reported by
// two different responses as corroboration (confidence goes up one level, max 3).
inline void merge_findings(std::vector<Finding> &dst, const std::vector<Finding> &src)
{
    const auto &lt = lower_table();
    auto key = [&](const std::string &s) { std::string k; for (unsigned char c : s) if (is_alnum_c(c)) k += (char)lt[c]; return k; };
    for (const auto &f : src) {
        std::string kf = key(f.product);
        bool found = false;
        for (auto &d : dst) {
            if (key(d.product) != kf) continue;
            if (f.score > d.score) { d.score = f.score; d.region = f.region; d.evidence = f.evidence; }
            if (!f.version.empty() && (d.version.empty() || f.ver_conf > d.ver_conf)) { d.version = f.version; d.ver_conf = f.ver_conf; }
            d.rmask |= f.rmask;
            d.generic = d.generic && f.generic;
            d.confidence = std::max(d.confidence, f.confidence);
            d.hops_seen += f.hops_seen;
            if (d.hops_seen >= 2 && d.confidence < 3) ++d.confidence;
            found = true; break;
        }
        if (!found) dst.push_back(f);
    }
    std::stable_sort(dst.begin(), dst.end(), [](const Finding &a, const Finding &b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.score > b.score;
    });
}

} // namespace ts
