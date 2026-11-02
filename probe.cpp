#include "probe.hpp"
#include <cstdarg>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <strings.h>
#include <unordered_set>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


static char *cp_strndup(const char *s, size_t len) {
    char *r = (char *)malloc(len + 1);
    if (!r) throw std::bad_alloc();
    memcpy(r, s, len);
    r[len] = '\0';
    return r;
}

[[noreturn]] static void fatal(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    throw std::runtime_error(buf);
}

static void logError(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[ERROR] %s\n", buf);
}

static bool cstring_unescape(char *str, unsigned int *len) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src != '\\') { *dst++ = *src++; continue; }
        src++;
        if (!*src) return false;
        switch (*src) {
            case 'n':  *dst++ = '\n'; break;
            case 'r':  *dst++ = '\r'; break;
            case 't':  *dst++ = '\t'; break;
            case '0':  *dst++ = '\0'; break;
            case '\\': *dst++ = '\\'; break;
            case '/':  *dst++ = '/';  break;
            case 'x': {
                src++;
                if (!isxdigit((unsigned char)*src)) return false;
                char hi = *src++;
                if (!isxdigit((unsigned char)*src)) return false;
                char lo = *src;
                auto hex = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return c - 'A' + 10;
                };
                *dst++ = (char)((hex(hi) << 4) | hex(lo));
                break;
            }
            default: *dst++ = *src; break;
        }
        src++;
    }
    *dst = '\0';
    *len = (unsigned int)(dst - str);
    return true;
}


/* ═══════════════════════════ ExcludedPorts ═══════════════════════════ */

bool ExcludedPorts::contains(u16 port, int proto) const {
    const std::vector<u16> *v = nullptr;
    if      (proto == IPPROTO_TCP)  v = &tcp_ports;
    else if (proto == IPPROTO_UDP)  v = &udp_ports;
    else if (proto == IPPROTO_SCTP) v = &sctp_ports;
    else return false;
    return std::find(v->begin(), v->end(), port) != v->end();
}

void ExcludedPorts::parse(const std::string &spec) {
    /* Grammar: item (',' item)*, item := [T:|U:|S:] port | port '-' port.
     * A protocol prefix stays in force for the following items until replaced.
     * (The previous parser dropped every item after the first one that followed
     * a comma, e.g. "T:80,443,U:53" kept only 80.) */
    int forced_proto = -1;                       /* -1 = all protocols */
    const char *p = spec.c_str();

    auto add = [&](std::vector<u16> &v, long port) {
        u16 pp = (u16)port;
        if (std::find(v.begin(), v.end(), pp) == v.end()) v.push_back(pp);
    };

    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;

        if (p[1] == ':' && (p[0]=='T'||p[0]=='t'||p[0]=='U'||p[0]=='u'||p[0]=='S'||p[0]=='s')) {
            char c = (char)toupper((unsigned char)p[0]);
            forced_proto = (c == 'T') ? IPPROTO_TCP : (c == 'U') ? IPPROTO_UDP : IPPROTO_SCTP;
            p += 2;
            continue;
        }

        if (!isdigit((unsigned char)*p)) { p++; continue; }   /* skip junk, always make progress */

        char *ep = nullptr;
        long lo = strtol(p, &ep, 10);
        p = ep;
        long hi = lo;
        if (*p == '-') {
            p++;
            if (isdigit((unsigned char)*p)) { hi = strtol(p, &ep, 10); p = ep; }
        }
        if (lo < 0 || lo > 65535 || hi < lo) continue;
        if (hi > 65535) hi = 65535;

        for (long port = lo; port <= hi; port++) {
            if (forced_proto == IPPROTO_TCP  || forced_proto == -1) add(tcp_ports,  port);
            if (forced_proto == IPPROTO_UDP  || forced_proto == -1) add(udp_ports,  port);
            if (forced_proto == IPPROTO_SCTP || forced_proto == -1) add(sctp_ports, port);
        }
    }
}


/* ═══════════════════════════ ServiceProbeMatch ═══════════════════════ */

ServiceProbeMatch::ServiceProbeMatch() = default;

ServiceProbeMatch::~ServiceProbeMatch() {
    if (!initialized_) return;
    free(servicename_);
    free(matchstr_);
    free(tmpl_product_);
    free(tmpl_version_);
    free(tmpl_info_);
    free(tmpl_hostname_);
    free(tmpl_ostype_);
    free(tmpl_devicetype_);
    for (char *c : tmpl_cpe_) free(c);
    if (regex_) { pcre2_code_free(regex_); regex_ = nullptr; }
    if (pcre2_code *jc = jit_regex_.load()) { pcre2_code_free(jc); }
}

bool ServiceProbeMatch::nextTemplate(const char **matchtext,
                                     char modestr[4], char **tmplt,
                                     char flags[4], int lineno) {
    const char *p = *matchtext;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') return false;
    memset(modestr, 0, 4);

    int i = 0;
    for (; i < 3 && isalpha((unsigned char)p[i]); i++)
        modestr[i] = p[i];

    const char *q = p + i;

    if (strcmp(modestr, "cpe") == 0 && *q == ':') {
        q++;
        if (*q != '/')
            fatal("parse error (cpe expects '/' after ':') on line %d", lineno);
        p = q + 1;
    } else {
        if (*q == '\0' || isspace((unsigned char)*q))
            fatal("parse error (bare word '%s') on line %d", modestr, lineno);
        p = q + 1;
    }

    char delimchar = *q;
    const char *scan = p;
    while (*scan) {
        if (*scan == '\\' && *(scan + 1) != '\0') {
            scan += 2;
            continue;
        }
        if (*scan == delimchar) break;
        scan++;
    }
    if (*scan != delimchar)
        fatal("parse error (missing end delimiter '%c') on line %d", delimchar, lineno);

    *tmplt = cp_strndup(p, scan - p);

    p = scan + 1;
    memset(flags, 0, 4);
    for (i = 0; i < 3 && isalpha((unsigned char)p[i]); i++)
        flags[i] = p[i];
    const char *after = p + i;
    if (*after != '\0' && isalpha((unsigned char)*after)) {
        free(*tmplt); *tmplt = nullptr;
        fatal("parse error (flags too long) on line %d", lineno);
    }

    *matchtext = after;
    return true;
}

/* True if the pattern has an alternation ('|') outside any group or class. A
 * literal prefix must not be extracted from such a pattern: "^abc|def" can match
 * "def" anywhere. */
static bool has_toplevel_alternation(const char *p) {
    int depth = 0;
    bool in_class = false;
    for (; *p; ++p) {
        if (*p == '\\') { if (p[1]) ++p; continue; }
        if (in_class) { if (*p == ']') in_class = false; continue; }
        if (*p == '[') {
            in_class = true;
            if (p[1] == '^') ++p;
            if (p[1] == ']') ++p;
            continue;
        }
        if (*p == '(') ++depth;
        else if (*p == ')') { if (depth > 0) --depth; }
        else if (*p == '|' && depth == 0) return true;
    }
    return false;
}

static bool extract_anchor_literal_prefix(const char *pattern, bool caseless,
                                          std::string &out) {
    if (!pattern || pattern[0] != '^') return false;
    if (has_toplevel_alternation(pattern)) return false;
    const char *p = pattern + 1;
    std::string lit;
    while (*p) {
        char c = *p;
        if (c == '\\') {
            char n = *(p + 1);
            if (n == '\0') return false;
            switch (n) {
                case 'n': lit += '\n'; p += 2; continue;
                case 'r': lit += '\r'; p += 2; continue;
                case 't': lit += '\t'; p += 2; continue;
                case '0': lit += '\0'; p += 2; continue;
                case 'x': {
                    if (!isxdigit((unsigned char)p[2]) || !isxdigit((unsigned char)p[3]))
                        return false;
                    char hex[3] = { p[2], p[3], '\0' };
                    lit += (char)strtol(hex, nullptr, 16);
                    p += 4;
                    continue;
                }
                default:
                    if (ispunct((unsigned char)n)) { lit += n; p += 2; continue; }
                    return false;   // \d \s \w \b etc. — genuinely not literal
            }
        }
        if (strchr(".^$*+?()[]{}|", c)) {
            /* A quantifier that allows zero repetitions applies to the character
             * just before it, so that character is not guaranteed to be present. */
            if ((c == '*' || c == '?' || c == '{') && !lit.empty()) lit.pop_back();
            break;
        }
        lit += c;
        p++;
    }
    if (lit.size() < 3) return false;
    if (caseless) for (char &ch : lit) ch = (char)tolower((unsigned char)ch);
    out = std::move(lit);
    return true;
}

void ServiceProbeMatch::init(const char *matchtext, int lineno) {
    if (initialized_)
        fatal("%s: already initialised", __func__);
    if (!matchtext || !*matchtext)
        fatal("%s: no matchtext (line %d)", __func__, lineno);

    initialized_ = true;
    deflineno_   = lineno;

    while (isspace((unsigned char)*matchtext)) matchtext++;

    if (strncmp(matchtext, "softmatch ", 10) == 0) {
        isSoft_   = true;
        matchtext += 10;
    } else if (strncmp(matchtext, "match ", 6) == 0) {
        isSoft_   = false;
        matchtext += 6;
    } else {
        fatal("%s: must begin with \"match\" or \"softmatch\" (line %d)",
              __func__, lineno);
    }

    const char *sp = strchr(matchtext, ' ');
    if (!sp) fatal("%s: could not find service name (line %d)", __func__, lineno);
    servicename_ = cp_strndup(matchtext, sp - matchtext);
    matchtext    = sp;

    char modestr[4], flags[4];
    if (!nextTemplate(&matchtext, modestr, &matchstr_, flags, lineno))
        fatal("%s: missing regex (line %d)", __func__, lineno);
    if (strcmp(modestr, "m") != 0)
        fatal("%s: regex must begin with 'm' (line %d)", __func__, lineno);

    for (const char *fp = flags; *fp; fp++) {
        if      (*fp == 'i') flag_i_ = true;
        else if (*fp == 's') flag_s_ = true;
        else fatal("%s: illegal regex flag '%c' (line %d)", __func__, *fp, lineno);
    }
    has_prefix_filter_ = extract_anchor_literal_prefix(matchstr_, flag_i_, prefix_literal_);

    /* Version templates: p/ v/ i/ h/ o/ d/ cpe:/ */
    char *tmp = nullptr;
    while (nextTemplate(&matchtext, modestr, &tmp, flags, lineno)) {
        char **dest = nullptr;

        if (modestr[1] == '\0') {
            switch (modestr[0]) {
                case 'p': dest = &tmpl_product_;    break;
                case 'v': dest = &tmpl_version_;    break;
                case 'i': dest = &tmpl_info_;       break;
                case 'h': dest = &tmpl_hostname_;   break;
                case 'o': dest = &tmpl_ostype_;     break;
                case 'd': dest = &tmpl_devicetype_; break;
                default: break;
            }
        } else if (strcmp(modestr, "cpe") == 0) {
            tmpl_cpe_.push_back(tmp);
            tmp = nullptr;
            continue;
        }

        if (!dest) {
            free(tmp); tmp = nullptr;
            fatal("%s: unknown template specifier '%s' (line %d)", __func__, modestr, lineno);
        }
        if (*dest) free(*dest);
        *dest = tmp;
        tmp   = nullptr;
    }
}

char *ServiceProbeMatch::transformCPE(const char *s) {
    std::string out;
    out.reserve(strlen(s) * 2);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (strchr(":/?#[]@!$&'()*+,;=%<>\"", c)) {
            char buf[8]; snprintf(buf, sizeof(buf), "%%%02X", c); out += buf;
        } else if (isspace(c)) {
            out += '_';
        } else {
            out += (char)tolower(c);
        }
    }
    char *r = (char *)malloc(out.size() + 1);
    if (!r) throw std::bad_alloc();
    memcpy(r, out.c_str(), out.size() + 1);
    return r;
}

/* ── SubstArgs for $CMD(...) parsing ───────────────────────────── */
struct SubstArgs {
    int  num_args = 0;
    enum class Type { None, String, Int } types[5] = {};
    char str_args[5][128] = {};
    int  str_lens[5]      = {};
    int  int_args[5]      = {};
};

static int parseSubstArgs(SubstArgs *args, const char *p, const char **end) {
    *args = SubstArgs{};
    while (*p && *p != ')') {
        while (isspace((unsigned char)*p)) p++;
        if (*p == ')') break;

        if (*p == '"') {
            if (args->num_args >= 5) return -1;
            int idx = args->num_args;
            int len = 0;
            p++;
            while (*p) {
                if (*p == '"' && *(p - 1) != '\\') break;
                if (len >= 127) return -1;
                args->str_args[idx][len++] = *p++;
            }
            if (*p == '"') p++;
            args->str_args[idx][len] = '\0';
            unsigned int ulen = (unsigned int)len;
            cstring_unescape(args->str_args[idx], &ulen);
            args->str_lens[idx] = (int)ulen;
            args->types[idx]    = SubstArgs::Type::String;
            args->num_args++;
            p = strpbrk(p, ",)");
            if (!p) return -1;
            if (*p == ',') p++;
        } else {
            if (args->num_args >= 5) return -1;
            int idx = args->num_args;
            char *ep;
            args->int_args[idx] = (int)strtol(p, &ep, 0);
            if (ep == p) return -1;
            p = ep;
            args->types[idx] = SubstArgs::Type::Int;
            args->num_args++;
            p = strpbrk(p, ",)");
            if (!p) return -1;
            if (*p == ',') p++;
        }
    }
    if (*p == ')') p++;
    if (end) *end = p;
    return args->num_args;
}

static char *empty_cstr() {
    char *e = (char *)malloc(1);
    if (!e) throw std::bad_alloc();
    e[0] = '\0';
    return e;
}

char *ServiceProbeMatch::substVar(const char *tmplvar, const char **tmplvarend,
                                   const u8 *subject, size_t /*subjectlen*/,
                                   pcre2_match_data *md) {
    if (*tmplvar != '$') return nullptr;
    tmplvar++;

    char      substcmd[16] = {};
    u8        subnum        = 0;
    SubstArgs args;

    if (!isdigit((unsigned char)*tmplvar)) {
        const char *lp = strchr(tmplvar, '(');
        if (!lp) return nullptr;
        int cmdlen = (int)(lp - tmplvar);
        if (cmdlen <= 0 || cmdlen >= (int)sizeof(substcmd)) return nullptr;
        memcpy(substcmd, tmplvar, cmdlen);
        substcmd[cmdlen] = '\0';
        const char *ep = nullptr;
        if (parseSubstArgs(&args, lp + 1, &ep) < 0) return nullptr;
        tmplvar = ep;
    } else {
        subnum  = (u8)(*tmplvar - '0');
        tmplvar++;
    }
    if (tmplvarend) *tmplvarend = tmplvar;

    u32         ncap = pcre2_get_ovector_count(md);
    PCRE2_SIZE *ov   = pcre2_get_ovector_pointer(md);

    auto getCapture = [&](int n, PCRE2_SIZE &os, PCRE2_SIZE &oe) -> bool {
        if (n <= 0 || n > 9 || (u32)n >= ncap) return false;
        os = ov[n * 2];
        oe = ov[n * 2 + 1];
        return os != PCRE2_UNSET;
    };

    std::string result;

    if (substcmd[0] == '\0') {
        PCRE2_SIZE os, oe;
        if (!getCapture((int)subnum, os, oe)) return empty_cstr();
        result.assign((const char *)subject + os, oe - os);

    } else if (strcmp(substcmd, "P") == 0) {
        if (args.num_args != 1 || args.types[0] != SubstArgs::Type::Int) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) return empty_cstr();
        for (PCRE2_SIZE i = os; i < oe; i++)
            if (isprint((int)subject[i])) result += (char)subject[i];

    } else if (strcmp(substcmd, "SUBST") == 0) {
        if (args.num_args != 3
            || args.types[0] != SubstArgs::Type::Int
            || args.types[1] != SubstArgs::Type::String
            || args.types[2] != SubstArgs::Type::String) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) return empty_cstr();
        const char *find = args.str_args[1]; int flen = args.str_lens[1];
        const char *repl = args.str_args[2]; int rlen = args.str_lens[2];
        for (PCRE2_SIZE i = os; i < oe; ) {
            if (flen > 0 && (PCRE2_SIZE)(i + flen) <= oe
                && memcmp(subject + i, find, flen) == 0) {
                result.append(repl, rlen); i += flen;
            } else {
                result += (char)subject[i++];
            }
        }

    } else if (strcmp(substcmd, "I") == 0) {
        if (args.num_args != 2
            || args.types[0] != SubstArgs::Type::Int
            || args.types[1] != SubstArgs::Type::String
            || args.str_lens[1] != 1) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) return empty_cstr();
        if (oe - os > 8) return nullptr;
        bool big = (args.str_args[1][0] == '>');
        uint64_t val = 0;
        if (big) {
            for (PCRE2_SIZE i = os; i < oe; i++) val = (val << 8) | subject[i];
        } else {
            for (PCRE2_SIZE i = oe; i-- > os; ) val = (val << 8) | subject[i];
        }
        char buf[24]; snprintf(buf, sizeof(buf), "%llu", (unsigned long long)val);
        result = buf;

    } else {
        return nullptr;
    }

    char *out = (char *)malloc(result.size() + 1);
    if (!out) throw std::bad_alloc();
    memcpy(out, result.c_str(), result.size() + 1);
    return out;
}

int ServiceProbeMatch::doTmplSubst(const u8 *subject, size_t subjectlen,
                                    pcre2_match_data *md,
                                    const char *tmpl, char *out, int outlen,
                                    char *(*transform)(const char *)) {
    if (!tmpl || !out || outlen < 3) return -1;
    char *dst    = out;
    char *outend = out + outlen - 1;
    const char *src = tmpl;

    while (*src) {
        const char *dollar = strchr(src, '$');
        if (!dollar) {
            int rem = (int)strlen(src);
            if (dst + rem >= outend) return -1;
            memcpy(dst, src, rem); dst += rem; break;
        }
        int litlen = (int)(dollar - src);
        if (dst + litlen >= outend) return -1;
        memcpy(dst, src, litlen); dst += litlen; src = dollar;

        const char *varend = nullptr;
        char *subst = substVar(src, &varend, subject, subjectlen, md);
        if (!subst) return -1;

        if (transform) {
            char *tmp = transform(subst); free(subst);
            if (!tmp) return -1;
            subst = tmp;
        }

        int slen = (int)strlen(subst);
        if (dst + slen >= outend) { free(subst); return -1; }
        memcpy(dst, subst, slen); free(subst); dst += slen;
        src = varend;
    }
    *dst = '\0';

    /* Strip trailing whitespace and commas (index-based: never forms a pointer
     * before the start of the buffer). */
    size_t n = (size_t)(dst - out);
    while (n > 0 && (isspace((unsigned char)out[n - 1]) || out[n - 1] == ',')) out[--n] = '\0';
    return 0;
}

int ServiceProbeMatch::fillVersionStr(const u8 *subject, size_t subjectlen,
                                       MatchScratch &scratch) {
    pcre2_match_data *mdata = scratch.mdata;
    scratch.i_product[0] = scratch.i_version[0] = scratch.i_info[0] = '\0';
    scratch.i_hostname[0] = scratch.i_ostype[0] = scratch.i_devicetype[0] = '\0';
    scratch.i_cpe_a[0] = scratch.i_cpe_h[0] = scratch.i_cpe_o[0] = '\0';
    int ret = 0;

    auto fill = [&](const char *tmpl, char *out, int outlen, const char *name) {
        if (!tmpl) return;
        if (doTmplSubst(subject, subjectlen, mdata, tmpl, out, outlen) != 0) {
            logError("template substitution failed for %s (line %d)", name, deflineno_);
            out[0] = '\0'; ret = -1;
        }
    };

    fill(tmpl_product_,    scratch.i_product,    SERVICE_FIELD_LEN, "product");
    fill(tmpl_version_,    scratch.i_version,    SERVICE_FIELD_LEN, "version");
    fill(tmpl_info_,       scratch.i_info,       SERVICE_EXTRA_LEN, "info");
    fill(tmpl_hostname_,   scratch.i_hostname,   SERVICE_FIELD_LEN, "hostname");
    fill(tmpl_ostype_,     scratch.i_ostype,     SERVICE_TYPE_LEN,  "ostype");
    fill(tmpl_devicetype_, scratch.i_devicetype, SERVICE_TYPE_LEN,  "devicetype");

    for (const char *cpe_tmpl : tmpl_cpe_) {
        if (!cpe_tmpl || cpe_tmpl[0] == '\0') continue;

        char part = cpe_tmpl[0];
        char *dest = nullptr; int dlen = 0;
        if      (part == 'a') { dest = scratch.i_cpe_a; dlen = SERVICE_FIELD_LEN; }
        else if (part == 'h') { dest = scratch.i_cpe_h; dlen = SERVICE_FIELD_LEN; }
        else if (part == 'o') { dest = scratch.i_cpe_o; dlen = SERVICE_FIELD_LEN; }
        else continue;
        if (dest[0] != '\0') continue;
        char body[SERVICE_FIELD_LEN];
        body[0] = '\0';
        if (doTmplSubst(subject, subjectlen, mdata, cpe_tmpl, body, sizeof(body),
                        transformCPE) != 0) {
            logError("CPE template failed (line %d)", deflineno_);
            ret = -1;
            continue;
        }

        const int prefix_len = 5; /* strlen("cpe:/") */
        int body_len = (int)strlen(body);
        if (prefix_len + body_len < dlen) {
            memcpy(dest, "cpe:/", prefix_len);
            memcpy(dest + prefix_len, body, body_len + 1);
        } else {
            memcpy(dest, "cpe:/", prefix_len);
            memcpy(dest + prefix_len, body, dlen - prefix_len - 1);
            dest[dlen - 1] = '\0';
        }
    }
    return ret;
}

static constexpr int kJitAfterHits = 2;

/* ── PCRE2 arena allocator ──────────────────────────────────────────
 * Compiled patterns live for the whole process and are never individually
 * released, so a bump allocator keeps them contiguous and cheap. Anything that
 * does not fit (or any pointer outside the arena) falls back to malloc/free. */
static char         g_pcre2_arena[64 * 1024 * 1024];
static size_t       g_pcre2_arena_used = 0;
static std::mutex   g_pcre2_arena_mu;

static void *pcre2_arena_malloc(size_t size, void *) {
    std::lock_guard<std::mutex> lock(g_pcre2_arena_mu);
    size_t aligned = (size + 15) & ~size_t(15);
    if (aligned >= size && g_pcre2_arena_used + aligned <= sizeof(g_pcre2_arena)) {
        void *p = g_pcre2_arena + g_pcre2_arena_used;
        g_pcre2_arena_used += aligned;
        return p;
    }
    return malloc(size);
}

static void pcre2_arena_free(void *ptr, void *) {
    if (ptr < (void *)g_pcre2_arena ||
        ptr >= (void *)(g_pcre2_arena + sizeof(g_pcre2_arena))) {
        free(ptr);
    }
}

static pcre2_general_context *g_pcre2_gctx =
    pcre2_general_context_create(pcre2_arena_malloc, pcre2_arena_free, nullptr);
static pcre2_compile_context *g_pcre2_cctx =
    pcre2_compile_context_create(g_pcre2_gctx);

static pcre2_code *compile_pattern(const char *pattern, bool caseless, bool dotall,
                                   int *errcode, PCRE2_SIZE *erroffset) {
    uint32_t opts = 0;
    if (caseless) opts |= PCRE2_CASELESS;
    if (dotall)   opts |= PCRE2_DOTALL;
    return pcre2_compile((PCRE2_SPTR8)pattern, PCRE2_ZERO_TERMINATED, opts,
                         errcode, erroffset, g_pcre2_cctx);
}

bool ServiceProbeMatch::ensureCompiled() {
    if (compiled_.load(std::memory_order_acquire)) return true;
    if (compile_failed_.load(std::memory_order_acquire)) return false;

    std::lock_guard<std::mutex> lock(compile_mu_);
    if (compiled_.load(std::memory_order_relaxed)) return true;
    if (compile_failed_.load(std::memory_order_relaxed)) return false;

    int        errcode   = 0;
    PCRE2_SIZE erroffset = 0;
    regex_ = compile_pattern(matchstr_, flag_i_, flag_s_, &errcode, &erroffset);
    if (!regex_) {
        /* A bad pattern in the probe file must not take the scanner down from a
         * worker thread: report it once and treat the template as never matching. */
        PCRE2_UCHAR msg[256] = {};
        pcre2_get_error_message(errcode, msg, sizeof(msg));
        logError("illegal regex on line %d (offset %zu): %s -- template disabled: '%s'",
                 deflineno_, (size_t)erroffset, (const char *)msg, matchstr_);
        compile_failed_.store(true, std::memory_order_release);
        return false;
    }
    compiled_.store(true, std::memory_order_release);
    return true;
}

void ServiceProbeMatch::maybeJitCompile() {
    if (jit_attempted_.load(std::memory_order_acquire)) return;

    int hits = hit_count_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (hits <= kJitAfterHits) return;   // cheap to interpret -- not worth JIT yet

    std::lock_guard<std::mutex> lock(jit_compile_mu_);
    if (jit_attempted_.load(std::memory_order_relaxed)) return;

    int        errcode   = 0;
    PCRE2_SIZE erroffset = 0;
    pcre2_code *jc = compile_pattern(matchstr_, flag_i_, flag_s_, &errcode, &erroffset);
    if (jc) {
        if (pcre2_jit_compile(jc, PCRE2_JIT_COMPLETE) == 0)
            jit_regex_.store(jc, std::memory_order_release);   // publish only a finished object
        else
            pcre2_code_free(jc);
    }
    jit_attempted_.store(true, std::memory_order_release);
}

ServiceProbeMatch::MatchScratch::~MatchScratch() {
    if (jit_stack) pcre2_jit_stack_free(jit_stack);
    if (mctx)      pcre2_match_context_free(mctx);
    if (mdata)     pcre2_match_data_free(mdata);
}

ServiceProbeMatch::MatchScratch &ServiceProbeMatch::getScratch() {
    thread_local MatchScratch s;
    if (!s.mdata) {
        s.mdata = pcre2_match_data_create(10, g_pcre2_gctx);
        if (!s.mdata) throw std::bad_alloc();
    }
    if (!s.mctx) {
        s.mctx = pcre2_match_context_create(g_pcre2_gctx);
        if (!s.mctx) throw std::bad_alloc();
        pcre2_set_match_limit(s.mctx, 1000000);
#ifdef pcre2_set_depth_limit
        pcre2_set_depth_limit(s.mctx, 50000);
#else
        pcre2_set_recursion_limit(s.mctx, 50000);
#endif
        s.jit_stack = pcre2_jit_stack_create(32 * 1024, 1024 * 1024, nullptr);
        if (s.jit_stack) pcre2_jit_stack_assign(s.mctx, nullptr, s.jit_stack);
    }
    return s;
}

const MatchDetails *ServiceProbeMatch::testMatch(const u8 *buf, int buflen) {
    assert(initialized_);
    MatchScratch &scratch = getScratch();

    scratch.md_return_ = MatchDetails{};
    scratch.md_return_.isSoft = isSoft_;

    if (!buf || buflen < 0) return &scratch.md_return_;

    if (has_prefix_filter_) {
        size_t plen = prefix_literal_.size();
        if ((size_t)buflen < plen) return &scratch.md_return_;
        bool prefix_ok = flag_i_
            ? strncasecmp((const char *)buf, prefix_literal_.data(), plen) == 0
            : memcmp(buf, prefix_literal_.data(), plen) == 0;
        if (!prefix_ok) return &scratch.md_return_;
    }

    if (!ensureCompiled()) return &scratch.md_return_;
    maybeJitCompile();

    int rc;
    if (pcre2_code *jc = jit_regex_.load(std::memory_order_acquire)) {
        rc = pcre2_jit_match(jc, (PCRE2_SPTR8)buf, (PCRE2_SIZE)buflen,
                             0, 0, scratch.mdata, scratch.mctx);
        if (rc == PCRE2_ERROR_JIT_STACKLIMIT)       // fall back to the interpreter
            rc = pcre2_match(regex_, (PCRE2_SPTR8)buf, (PCRE2_SIZE)buflen,
                             0, 0, scratch.mdata, scratch.mctx);
    } else {
        rc = pcre2_match(regex_, (PCRE2_SPTR8)buf, (PCRE2_SIZE)buflen,
                         0, 0, scratch.mdata, scratch.mctx);
    }
    if (rc < 0) {
        if (rc == PCRE2_ERROR_MATCHLIMIT || rc == PCRE2_ERROR_DEPTHLIMIT) {
            logError("PCRE2 match limit hit (error %d) for service %s — "
                     "regex likely has catastrophic backtracking: '%s'",
                     rc, servicename_, matchstr_);
        } else if (rc != PCRE2_ERROR_NOMATCH) {
            logError("PCRE2 error %d matching service %s regex '%s'",
                     rc, servicename_, matchstr_);
        }
        return &scratch.md_return_;
    }

    fillVersionStr(buf, (size_t)buflen, scratch);
    if (scratch.i_product[0])    scratch.md_return_.product    = scratch.i_product;
    if (scratch.i_version[0])    scratch.md_return_.version    = scratch.i_version;
    if (scratch.i_info[0])       scratch.md_return_.info       = scratch.i_info;
    if (scratch.i_hostname[0])   scratch.md_return_.hostname   = scratch.i_hostname;
    if (scratch.i_ostype[0])     scratch.md_return_.ostype     = scratch.i_ostype;
    if (scratch.i_devicetype[0]) scratch.md_return_.devicetype = scratch.i_devicetype;
    if (scratch.i_cpe_a[0])      scratch.md_return_.cpe_a      = scratch.i_cpe_a;
    if (scratch.i_cpe_h[0])      scratch.md_return_.cpe_h      = scratch.i_cpe_h;
    if (scratch.i_cpe_o[0])      scratch.md_return_.cpe_o      = scratch.i_cpe_o;
    scratch.md_return_.serviceName = servicename_;
    return &scratch.md_return_;
}


/* ═══════════════════════════ ServiceProbe ════════════════════════════ */

ServiceProbe::ServiceProbe() { memset(fallbacks, 0, sizeof(fallbacks)); }

ServiceProbe::~ServiceProbe() {
    for (auto *m : matches_) delete m;
    free(fallbackStr);
    free(probename_);
    free(probestring_);
}

void ServiceProbe::setProbeString(const u8 *ps, int len) {
    free(probestring_);
    probestring_    = nullptr;
    probestringlen_ = len > 0 ? len : 0;
    if (len > 0) probestring_ = (u8 *)cp_strndup((const char *)ps, (size_t)len);
}

void ServiceProbe::setProbeDetails(char *pd, int lineno) {
    if (!pd || !*pd)
        fatal("Parse error on line %d: no arguments after 'Probe'", lineno);

    if      (strncmp(pd, "TCP ", 4) == 0) probeprotocol_ = IPPROTO_TCP;
    else if (strncmp(pd, "UDP ", 4) == 0) probeprotocol_ = IPPROTO_UDP;
    else fatal("Parse error on line %d: invalid protocol", lineno);
    pd += 4;

    if (!isalnum((unsigned char)*pd))
        fatal("Parse error on line %d: bad probe name", lineno);
    char *sp = strchr(pd, ' ');
    if (!sp) fatal("Parse error on line %d: nothing after probe name", lineno);
    free(probename_);
    probename_ = cp_strndup(pd, sp - pd);
    pd = sp + 1;

    if (*pd != 'q')
        fatal("Parse error on line %d: probe string must begin with 'q'", lineno);
    ++pd;
    char delim = *pd;
    if (delim == '\0')   /* previously read one byte past the terminator */
        fatal("Parse error on line %d: missing probe string delimiter", lineno);
    ++pd;
    char *ep = strchr(pd, delim);
    if (!ep) fatal("Parse error on line %d: no ending delimiter for probe string", lineno);
    *ep = '\0';
    unsigned int slen = 0;
    if (!cstring_unescape(pd, &slen))
        fatal("Parse error on line %d: bad probe string escaping", lineno);
    setProbeString((const u8 *)pd, (int)slen);
    /* Trailing options such as "no-payload" are accepted and ignored: nothing in
     * this scanner sends probes as UDP payloads. */
}

void ServiceProbe::setPortVector(std::vector<u16> *portv,
                                  const char *portstr, int lineno) {
    const char *cur = portstr;
    do {
        while (*cur && isspace((unsigned char)*cur)) cur++;
        if (!isdigit((unsigned char)*cur))
            fatal("Parse error on line %d: expected port number", lineno);
        char *ep;
        long lo = strtol(cur, &ep, 10);
        if (lo < 0 || lo > 65535) fatal("Parse error on line %d: port out of range", lineno);
        cur = ep;
        while (isspace((unsigned char)*cur)) cur++;
        long hi = lo;
        if (*cur == '-') {
            cur++;
            hi = strtol(cur, &ep, 10);
            if (hi < 0 || hi > 65535 || hi < lo)
                fatal("Parse error on line %d: port range invalid", lineno);
            cur = ep;
        }
        for (long p = lo; p <= hi; p++) portv->push_back((u16)p);
        while (isspace((unsigned char)*cur)) cur++;
        if (*cur == ',') cur++; else break;
    } while (*cur);
}

void ServiceProbe::setProbablePorts(ServiceTunnel tunnel,
                                     const char *portstr, int lineno) {
    if (tunnel == ServiceTunnel::NONE) setPortVector(&probableports_,    portstr, lineno);
    else                               setPortVector(&probablesslports_, portstr, lineno);
}

void ServiceProbe::setRarity(const char *val, int lineno) {
    char *endp = nullptr;
    long r = strtol(val, &endp, 10);
    if (endp == val || *endp != '\0') fatal("Rarity on line %d must be a valid integer", lineno);
    if (r < 1 || r > 9) fatal("Rarity on line %d must be 1–9", lineno);
    rarity_ = (int)r;
}

void ServiceProbe::addMatch(const char *matchline, int lineno) {
    auto m = std::make_unique<ServiceProbeMatch>();
    m->init(matchline, lineno);
    const char *sn = m->getName();
    ServiceProbeMatch *raw = m.get();
    matches_.push_back(raw);       // may throw; m still owns raw until release()
    m.release();
    if (!serviceIsPossible(sn)) detectedServices_.push_back(sn);
}

bool ServiceProbe::portIsProbable(ServiceTunnel tunnel, u16 portno) const {
    const std::vector<u16> &v = (tunnel == ServiceTunnel::SSL)
                                 ? probablesslports_ : probableports_;
    return std::find(v.begin(), v.end(), portno) != v.end();
}

bool ServiceProbe::portIsSSL(u16 portno) const {
    return std::find(probablesslports_.begin(), probablesslports_.end(), portno)
           != probablesslports_.end();
}

bool ServiceProbe::serviceIsPossible(const char *sname) const {
    for (auto *s : detectedServices_) if (strcmp(s, sname) == 0) return true;
    return false;
}

const MatchDetails *ServiceProbe::testMatch(const u8 *buf, int buflen) {
    for (auto *m : matches_) {
        const MatchDetails *md = m->testMatch(buf, buflen);
        if (md->serviceName) return md;
    }
    return nullptr;
}


/* ═══════════════════════════ AllProbes ═══════════════════════════════ */

AllProbes::AllProbes()  = default;
AllProbes::~AllProbes() { for (auto *p : probes) delete p; delete nullProbe; }

void AllProbes::loadFromFile(const char *filename) {
    parse_nmap_service_probe_file(this, filename);
}

ServiceProbe *AllProbes::getProbeByName(const char *name, int proto) const {
    if (proto == IPPROTO_TCP && nullProbe && strcmp(nullProbe->getName(), name) == 0)
        return nullProbe;
    for (auto *p : probes)
        if (p->getProtocol() == proto && strcmp(p->getName(), name) == 0) return p;
    for (auto *p : probes) if (strcmp(p->getName(), name) == 0) return p;
    return nullptr;
}

bool AllProbes::isExcluded(u16 port, int proto) const {
    if (!excluded_seen) return false;
    return excludedPorts.contains(port, proto);
}

const std::vector<ServiceProbe *> &AllProbes::probesForPort(int proto, ServiceTunnel tunnel,
                                                            u16 port) const {
    static const std::vector<ServiceProbe *> kNone;
    auto it = portIndex_.find(portIndexKey(proto, tunnel, port));
    return it == portIndex_.end() ? kNone : it->second;
}

void AllProbes::compileFallbacks() {
    if (nullProbe) nullProbe->fallbacks[0] = nullProbe;

    for (auto *probe : probes) {
        memset(probe->fallbacks, 0, sizeof(probe->fallbacks));
        probe->fallbacks[0] = probe;
        int i = 1;

        if (probe->fallbackStr) {
            char *fbcopy = strdup(probe->fallbackStr);
            if (!fbcopy) throw std::bad_alloc();
            char *save = nullptr;
            char *tok = strtok_r(fbcopy, ",\r\n\t ", &save);
            while (tok && i < MAXFALLBACKS - 1) {
                ServiceProbe *fb = getProbeByName(tok, probe->getProtocol());
                if (!fb) {
                    std::string t = tok;
                    free(fbcopy);
                    fatal("compileFallbacks: unknown fallback '%s' in probe '%s'",
                          t.c_str(), probe->getName());
                }
                probe->fallbacks[i++] = fb;
                tok = strtok_r(nullptr, ",\r\n\t ", &save);
            }
            bool overflow = tok && i >= MAXFALLBACKS - 1;
            free(fbcopy);
            if (overflow)
                fatal("compileFallbacks: MAXFALLBACKS exceeded for probe '%s'",
                      probe->getName());
            free(probe->fallbackStr);
            probe->fallbackStr = nullptr;
        }
        if (probe->getProtocol() == IPPROTO_TCP && nullProbe) {
            bool has_null = false;
            for (int j = 0; j < i; j++) {
                if (probe->fallbacks[j] == nullProbe) { has_null = true; break; }
            }
            if (!has_null && i < MAXFALLBACKS) {
                probe->fallbacks[i++] = nullProbe;
            }
        }
        if (i <= MAXFALLBACKS) probe->fallbacks[i] = nullptr;
    }
    for (auto *probe : probes) {
        std::unordered_set<ServiceProbe *> visited;
        for (int i = 0; i <= MAXFALLBACKS && probe->fallbacks[i]; i++) {
            ServiceProbe *fb = probe->fallbacks[i];
            if (!visited.insert(fb).second) {
                fatal("compileFallbacks: circular fallback detected in probe '%s' "
                      "(loop at '%s')", probe->getName(), fb->getName());
            }
        }
    }
    buildPortIndex();
}

void AllProbes::buildPortIndex() {
    portIndex_.clear();
    for (auto *probe : probes) {
        int proto = probe->getProtocol();
        for (auto it = probe->probablePortsBegin(); it != probe->probablePortsEnd(); ++it)
            portIndex_[portIndexKey(proto, ServiceTunnel::NONE, *it)].push_back(probe);
        for (auto it = probe->probableSslPortsBegin(); it != probe->probableSslPortsEnd(); ++it)
            portIndex_[portIndexKey(proto, ServiceTunnel::SSL, *it)].push_back(probe);
    }
}


/* ═══════════════════════ probe file parser ═══════════════════════════ */

namespace {
struct MmapGuard {
    void  *addr = nullptr;
    size_t len  = 0;
    ~MmapGuard() { if (addr && addr != MAP_FAILED && len) munmap(addr, len); }
};
} // namespace

void parse_nmap_service_probe_file(AllProbes *AP, const char *filename) {
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fatal("Cannot open nmap-service-probes file: %s", filename);

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        fatal("Cannot stat nmap-service-probes file: %s", filename);
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        fatal("nmap-service-probes file is not a regular file: %s", filename);
    }

    size_t filesize = (size_t)st.st_size;
    if (filesize == 0) { close(fd); AP->compileFallbacks(); return; }

    void *mapped = mmap(nullptr, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
        fatal("mmap failed on nmap-service-probes file: %s (%s)", filename, strerror(errno));

    MmapGuard guard{mapped, filesize};
    madvise(mapped, filesize, MADV_SEQUENTIAL);

    char *cursor = (char *)mapped;
    char *end    = cursor + filesize;

    int  lineno = 0;
    /* unique_ptr: a parse error (fatal() throws) no longer leaks the half-built probe */
    std::unique_ptr<ServiceProbe> newProbe;

    auto finishProbe = [&]() {
        if (!newProbe) return;
        const bool is_null_probe = newProbe->getProtocol() == IPPROTO_TCP &&
                                   strcmp(newProbe->getName(), "NULL") == 0;
        if (is_null_probe) {
            if (AP->nullProbe) fatal("Duplicate NULL probe at line %d", lineno);
            AP->nullProbe = newProbe.release();
        } else {
            AP->probes.push_back(newProbe.get());
            newProbe.release();
        }
    };

    while (cursor < end) {
        lineno++;

        char *nl   = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        char *line = cursor;
        cursor = nl ? nl + 1 : end;
        if (nl) *nl = '\0';
        else if (end > (char *)mapped) {
            /* last line without a trailing newline: it is not NUL-terminated inside
             * the mapping, so work on a private copy */
            static thread_local std::string lastline;
            lastline.assign(line, (size_t)(end - line));
            line = &lastline[0];
        }

        size_t linelen = strlen(line);
        if (linelen > 0 && line[linelen - 1] == '\r') line[linelen - 1] = '\0';

        if (line[0] == '\0' || line[0] == '#') continue;

        if (strncmp(line, "Exclude ", 8) == 0) {
            if (AP->excluded_seen)
                fatal("Only one Exclude directive allowed (line %d)", lineno);
            AP->excludedPorts.parse(line + 8);
            AP->excluded_seen = true;
            continue;
        }

        if (strncmp(line, "Probe ", 6) == 0) {
            finishProbe();
            newProbe = std::make_unique<ServiceProbe>();
            newProbe->setProbeDetails(line + 6, lineno);
            continue;
        }

        if (!newProbe)
            fatal("Unexpected directive outside Probe block at line %d: %s", lineno, line);

        if (strncmp(line, "ports ", 6) == 0) {
            newProbe->setProbablePorts(ServiceTunnel::NONE, line + 6, lineno);
        } else if (strncmp(line, "sslports ", 9) == 0) {
            newProbe->setProbablePorts(ServiceTunnel::SSL, line + 9, lineno);
        } else if (strncmp(line, "rarity ", 7) == 0) {
            newProbe->setRarity(line + 7, lineno);
        } else if (strncmp(line, "fallback ", 9) == 0) {
            free(newProbe->fallbackStr);
            newProbe->fallbackStr = strdup(line + 9);
            if (!newProbe->fallbackStr) throw std::bad_alloc();
        } else if (strncmp(line, "totalwaitms ", 12) == 0) {
            long ms = strtol(line + 12, nullptr, 10);
            if (ms < 100 || ms > 300000) fatal("Bad totalwaitms %ld on line %d", ms, lineno);
            newProbe->setTotalWaitMs((int)ms);
        } else if (strncmp(line, "match ", 6) == 0
                || strncmp(line, "softmatch ", 10) == 0) {
            newProbe->addMatch(line, lineno);
        }
        else if (strncmp(line, "tcpwrappedms ", 13) == 0) {
            long ms = strtol(line + 13, nullptr, 10);
            if (ms < 100 || ms > 300000) fatal("Bad tcpwrappedms %ld on line %d", ms, lineno);
            newProbe->setTcpWrappedMs((int)ms);
        }
    }
    finishProbe();
    AP->compileFallbacks();
}


/* ═══════════════════════════ ServiceNFO ══════════════════════════════ */

ServiceNFO::~ServiceNFO() {
    free(servicefp_);
}

void ServiceNFO::clearMatchFields() {
    memset(product_matched,    0, sizeof(product_matched));
    memset(version_matched,    0, sizeof(version_matched));
    memset(extrainfo_matched,  0, sizeof(extrainfo_matched));
    memset(hostname_matched,   0, sizeof(hostname_matched));
    memset(ostype_matched,     0, sizeof(ostype_matched));
    memset(devicetype_matched, 0, sizeof(devicetype_matched));
    memset(cpe_a_matched,      0, sizeof(cpe_a_matched));
    memset(cpe_h_matched,      0, sizeof(cpe_h_matched));
    memset(cpe_o_matched,      0, sizeof(cpe_o_matched));
}

void ServiceNFO::resetFingerprint() {
    free(servicefp_);
    servicefp_ = nullptr;
    servicefplen_ = servicefpalloc_ = 0;
}

void ServiceNFO::addFpChar(char c, int wrapat) {
    auto grow = [&]() {
        int na = (servicefpalloc_ == 0) ? 1024 : servicefpalloc_ * 2;
        char *n = (char *)realloc(servicefp_, (size_t)na);
        if (!n) throw std::bad_alloc();
        servicefp_ = n;
        servicefpalloc_ = na;
    };
    if (servicefpalloc_ - servicefplen_ < 8) grow();
    if (servicefplen_ % (wrapat + 1) == wrapat) {
        memcpy(servicefp_ + servicefplen_, "\nSF:", 4);
        servicefplen_ += 4;
        if (servicefpalloc_ - servicefplen_ < 8) grow();
    }
    servicefp_[servicefplen_++] = c;
}

void ServiceNFO::addFpString(const char *s, int wrapat) {
    while (*s) addFpChar(*s++, wrapat);
}

void ServiceNFO::addToFingerprint(const char *probeName,
                                   const u8 *resp, int resplen) {
    if (servicefplen_ > 2200) return;
    static constexpr int WRAP = 74;
    if (resplen < 0) resplen = 0;
    int used = std::min(resplen, 900);

    if (servicefplen_ == 0) {
        time_t  now  = time(nullptr);
        struct  tm lt = {};
        localtime_r(&now, &lt);
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
                 "SF-Port%hu-%s:V=custom%%I=%d%%D=%d/%d%%Time=%X%%P=custom",
                 portno, (proto == IPPROTO_TCP) ? "TCP" : "UDP", version_intensity,
                 lt.tm_mon + 1, lt.tm_mday, (unsigned int)now);
        if (tunnel == ServiceTunnel::SSL) {
            char ssl[16]; snprintf(ssl, sizeof(ssl), "%%T=SSL");
            strncat(hdr, ssl, sizeof(hdr) - strlen(hdr) - 1);
        }
        addFpString(hdr, WRAP);
    }

    char rec[256];
    snprintf(rec, sizeof(rec), "%%r(%s,%X,\"", probeName, resplen);
    addFpString(rec, WRAP);

    for (int i = 0; i < used; i++) {
        u8 c = resp[i];
        if (isalnum(c)) {
            addFpChar((char)c, WRAP);
        } else if (c == '\0') {
            if (i + 1 < used && isdigit((int)resp[i + 1]))
                addFpString("\\x00", WRAP);
            else
                addFpString("\\0", WRAP);
        } else if (strchr("\\?\"[]().*+$^|", c)) {
            addFpChar('\\', WRAP); addFpChar((char)c, WRAP);
        } else if (ispunct(c)) {
            addFpChar((char)c, WRAP);
        } else if (c == '\r') { addFpString("\\r", WRAP); }
        else if (c == '\n') { addFpString("\\n", WRAP); }
        else if (c == '\t') { addFpString("\\t", WRAP); }
        else { char esc[8]; snprintf(esc, sizeof(esc), "\\x%02x", c); addFpString(esc, WRAP); }
    }
    addFpChar('"', WRAP);
    addFpChar(')', WRAP);
    servicefp_[servicefplen_] = '\0';
}

const char *ServiceNFO::getFingerprint(int *flen) {
    if (servicefplen_ == 0) { if (flen) *flen = 0; return nullptr; }
    if (servicefpalloc_ - servicefplen_ < 4) {
        char *n = (char *)realloc(servicefp_, (size_t)servicefpalloc_ + 32);
        if (!n) throw std::bad_alloc();
        servicefp_ = n;
        servicefpalloc_ += 32;
    }
    servicefp_[servicefplen_]     = ';';
    servicefp_[servicefplen_ + 1] = '\0';
    if (flen) *flen = servicefplen_ + 1;
    return servicefp_;
}


/* ═══════════════════════════ ProbeEngine ═════════════════════════════ */

ProbeEngine::ProbeEngine(AllProbes *ap, int vi)
    : ap_(ap), version_intensity_(std::clamp(vi, 1, MAX_VERSION_INTENSITY)) {}

bool ProbeEngine::processMatch(const MatchDetails *md, ServiceNFO *svc) {
    if (!md || !md->serviceName) return false;

    /* A second soft match never replaces the first one. */
    if (md->isSoft && svc->probe_matched) return false;

    svc->probe_matched    = md->serviceName;
    svc->softMatchFound   = md->isSoft;

    /* Start from a clean slate: a hard match that follows a soft one must not
     * inherit product/version fields the hard match did not set itself. */
    svc->clearMatchFields();

    auto copyField = [](char *dst, size_t dlen, const char *src) {
        if (src) { strncpy(dst, src, dlen - 1); dst[dlen - 1] = '\0'; }
    };
    copyField(svc->product_matched,    sizeof(svc->product_matched),    md->product);
    copyField(svc->version_matched,    sizeof(svc->version_matched),    md->version);
    copyField(svc->extrainfo_matched,  sizeof(svc->extrainfo_matched),  md->info);
    copyField(svc->hostname_matched,   sizeof(svc->hostname_matched),   md->hostname);
    copyField(svc->ostype_matched,     sizeof(svc->ostype_matched),     md->ostype);
    copyField(svc->devicetype_matched, sizeof(svc->devicetype_matched), md->devicetype);
    copyField(svc->cpe_a_matched,      sizeof(svc->cpe_a_matched),      md->cpe_a);
    copyField(svc->cpe_h_matched,      sizeof(svc->cpe_h_matched),      md->cpe_h);
    copyField(svc->cpe_o_matched,      sizeof(svc->cpe_o_matched),      md->cpe_o);

    return !md->isSoft;
}

bool ProbeEngine::scanThroughTunnel(ServiceNFO *svc) {
    if (svc->probe_matched && strncmp(svc->probe_matched, "ssl/", 4) == 0) {
        const char *stripped = svc->probe_matched + 4;
        strncpy(svc->probe_matched_stripped, stripped,
                sizeof(svc->probe_matched_stripped) - 1);
        svc->probe_matched_stripped[sizeof(svc->probe_matched_stripped) - 1] = '\0';
        svc->probe_matched = svc->probe_matched_stripped;
        svc->tunnel        = ServiceTunnel::SSL;
        return false;
    }

    if (svc->tunnel != ServiceTunnel::NONE) return false;

    if (!svc->probe_matched
     || (strcmp(svc->probe_matched, "ssl")  != 0
      && strcmp(svc->probe_matched, "dtls") != 0))
        return false;

    /* Matched "ssl": the real service is inside the tunnel, so restart matching
     * from scratch with the SSL probe set. */
    svc->tunnel         = ServiceTunnel::SSL;
    svc->probe_matched  = nullptr;
    svc->softMatchFound = false;
    svc->clearMatchFields();
    svc->resetFingerprint();
    return true;
}

ScanResult ProbeEngine::buildResult(ServiceNFO *svc) const {
    ScanResult r;
    r.port   = svc->portno;
    r.proto  = svc->proto;
    r.state  = svc->probe_state;
    r.tunnel = svc->tunnel;

    if (svc->probe_matched)        r.service    = svc->probe_matched;
    if (*svc->product_matched)     r.product    = svc->product_matched;
    if (*svc->version_matched)     r.version    = svc->version_matched;
    if (*svc->extrainfo_matched)   r.extrainfo  = svc->extrainfo_matched;
    if (*svc->hostname_matched)    r.hostname   = svc->hostname_matched;
    if (*svc->ostype_matched)      r.ostype     = svc->ostype_matched;
    if (*svc->devicetype_matched)  r.devicetype = svc->devicetype_matched;
    if (*svc->cpe_a_matched)       r.cpe_a      = svc->cpe_a_matched;
    if (*svc->cpe_h_matched)       r.cpe_h      = svc->cpe_h_matched;
    if (*svc->cpe_o_matched)       r.cpe_o      = svc->cpe_o_matched;

    const char *fp = svc->getFingerprint();
    if (fp) r.fingerprint = fp;
    return r;
}

ScanResult ProbeEngine::matchResponse(u16 port, int proto,
                                       ServiceTunnel tunnel,
                                       const u8 *data, int datalen,
                                       const MatchContext &ctx) {
    if (!ignore_exclude_ && ap_->isExcluded(port, proto)) {
        ScanResult r;
        r.port    = port; r.proto = proto;
        r.state   = ProbeState::FINISHED_EXCLUDED;
        r.service = "Excluded from version scan";
        return r;
    }

    ServiceNFO svc;
    svc.portno = port; svc.proto = proto; svc.tunnel = tunnel;
    svc.version_intensity = version_intensity_;

    if (!data || datalen <= 0) {
        /* tcpwrapped: TCP peer accepted and then closed at once, sending nothing. */
        if (proto == IPPROTO_TCP && ctx.closed_without_data && ctx.elapsed_ms >= 0) {
            const int limit = ap_->nullProbe ? ap_->nullProbe->getTcpWrappedMs() : DEFAULT_TCPWRAPPEDMS;
            if (ctx.elapsed_ms < limit) {
                svc.probe_state = ProbeState::FINISHED_TCPWRAPPED;
                ScanResult r = buildResult(&svc);
                r.service = "tcpwrapped";
                return r;
            }
        }
        svc.probe_state = ProbeState::FINISHED_NOMATCH;
        return buildResult(&svc);
    }

    /* The probe that actually produced this response gets its own match list first. */
    ServiceProbe *hinted = nullptr;
    if (ctx.probe_name && *ctx.probe_name) hinted = ap_->getProbeByName(ctx.probe_name, proto);

    /* Tries one probe's match list (and its fallbacks); true only on a HARD match. */
    auto tryProbeSet = [&](ServiceProbe *probe) -> bool {
        if (!probe) return false;
        const MatchDetails *md = nullptr;
        for (int d = 0; d < MAXFALLBACKS + 1; d++) {
            ServiceProbe *fb = probe->fallbacks[d];
            if (!fb) break;
            md = fb->testMatch(data, datalen);
            if (md && md->serviceName) break;
            md = nullptr;
        }
        if (!md) return false;
        return processMatch(md, &svc);   // copies out of the per-thread scratch right away
    };

    /* 0. the probe that generated this response */
    if (hinted && tryProbeSet(hinted)) {
        if (!scanThroughTunnel(&svc)) goto done_hard;
    }

    /* 1. NULL probe — always tried first for TCP, no port filter */
    if (proto == IPPROTO_TCP && ap_->nullProbe && ap_->nullProbe != hinted) {
        if (tryProbeSet(ap_->nullProbe)) {
            if (!scanThroughTunnel(&svc)) goto done_hard;
        }
    }

    /* 2. probes that explicitly list this port (for this tunnel type) */
    for (auto *probe : ap_->probesForPort(proto, svc.tunnel, port)) {
        if (probe == hinted) continue;
        if (svc.softMatchFound && !probe->serviceIsPossible(svc.probe_matched)) continue;
        if (tryProbeSet(probe)) {
            if (!scanThroughTunnel(&svc)) goto done_hard;
        }
    }
    if (svc.probe_matched && !svc.softMatchFound) goto done_hard;

    /* 3. all other probes, limited by rarity / soft-match service */
    for (auto *probe : ap_->probes) {
        if (probe->getProtocol() != proto) continue;
        if (probe == hinted) continue;
        if (probe->portIsProbable(svc.tunnel, port)) continue;   // already done in step 2
        if (!svc.softMatchFound && probe->getRarity() > version_intensity_) continue;
        if (svc.softMatchFound && version_intensity_ < 9
            && !probe->serviceIsPossible(svc.probe_matched)) continue;
        if (tryProbeSet(probe)) {
            if (!scanThroughTunnel(&svc)) goto done_hard;
        }
    }

    /* 4. UDP probes that list this port as DTLS (sslports) */
    if (proto == IPPROTO_UDP && svc.tunnel == ServiceTunnel::NONE) {
        for (auto *probe : ap_->probes) {
            if (probe->getProtocol() != IPPROTO_UDP) continue;
            if (!probe->portIsSSL(port)) continue;
            svc.tunnel = ServiceTunnel::SSL;
            if (tryProbeSet(probe)) {
                if (!scanThroughTunnel(&svc)) goto done_hard;
            }
            svc.tunnel = ServiceTunnel::NONE;
        }
    }

    svc.probe_state = svc.softMatchFound ? ProbeState::FINISHED_SOFTMATCHED
                                         : ProbeState::FINISHED_NOMATCH;
    if (svc.probe_state == ProbeState::FINISHED_NOMATCH)
        svc.addToFingerprint("(all probes)", data, datalen);
    return buildResult(&svc);

done_hard:
    svc.probe_state = ProbeState::FINISHED_HARDMATCHED;
    return buildResult(&svc);
}
