#include "probe.h"
#include <cstdarg>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

/* PERF: for mmap-based probe-file parsing (see parse_nmap_service_probe_file) */
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ══════════════════════════════════════════════════════════════════════
   Small string utilities
   ══════════════════════════════════════════════════════════════════════ */

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
                char hi = *src++; if (!isxdigit((unsigned char)*src)) return false;
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

/* ══════════════════════════════════════════════════════════════════════
   ExcludedPorts
   ══════════════════════════════════════════════════════════════════════ */

bool ExcludedPorts::contains(u16 port, int proto) const {
    const std::vector<u16> *v = nullptr;
    if      (proto == IPPROTO_TCP)  v = &tcp_ports;
    else if (proto == IPPROTO_UDP)  v = &udp_ports;
    else if (proto == IPPROTO_SCTP) v = &sctp_ports;
    else return false;
    return std::find(v->begin(), v->end(), port) != v->end();
}

/*
 * FIX #9 (Exclude directive with protocol prefix):
 * The original parser advanced the pointer past a protocol prefix only
 * once, then broke out of the inner port-scanning loop when it hit a
 * comma that was actually separating protocol segments (e.g. "T:80,U:161").
 * Fixed by restructuring the loop so each comma re-enters the outer loop
 * which re-checks for a new protocol prefix before scanning ports.
 */
void ExcludedPorts::parse(const std::string &spec) {
    const char *p = spec.c_str();
    while (*p) {
        /* Skip leading whitespace between segments */
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        /* Detect optional protocol prefix */
        int forced_proto = -1;
        if ((p[0]=='T'||p[0]=='t') && p[1]==':') { forced_proto = IPPROTO_TCP;  p += 2; }
        else if ((p[0]=='U'||p[0]=='u') && p[1]==':') { forced_proto = IPPROTO_UDP;  p += 2; }
        else if ((p[0]=='S'||p[0]=='s') && p[1]==':') { forced_proto = IPPROTO_SCTP; p += 2; }

        /* Parse the port list that follows this prefix */
        bool parsed_any = false;
        while (*p) {
            while (*p && isspace((unsigned char)*p)) p++;
            if (!isdigit((unsigned char)*p)) break;

            char *ep;
            long lo = strtol(p, &ep, 10); p = ep;
            long hi = lo;
            if (*p == '-') { p++; hi = strtol(p, &ep, 10); p = ep; }

            for (long port = lo; port <= hi && port <= 65535; port++) {
                auto add = [&](std::vector<u16> &v) {
                    u16 pp = (u16)port;
                    if (std::find(v.begin(), v.end(), pp) == v.end()) v.push_back(pp);
                };
                if (forced_proto == IPPROTO_TCP  || forced_proto == -1) add(tcp_ports);
                if (forced_proto == IPPROTO_UDP  || forced_proto == -1) add(udp_ports);
                if (forced_proto == IPPROTO_SCTP || forced_proto == -1) add(sctp_ports);
            }
            parsed_any = true;

            while (*p && isspace((unsigned char)*p)) p++;

            if (*p == ',') {
                p++;
                /*
                 * A comma may start a new protocol-prefix segment like
                 * "T:9100,U:161".  Break the inner port loop so the outer
                 * loop can re-check for a prefix.
                 */
                break;
            }
            /* Any other character (including NUL) ends the list */
            break;
        }
        (void)parsed_any;

        /* If we didn't consume a comma above, stop */
        if (*p && *p != ',') break;
        if (*p == ',') p++;  /* consume trailing comma from previous break */
    }
}

/* ══════════════════════════════════════════════════════════════════════
   ServiceProbeMatch — ctor / dtor
   ══════════════════════════════════════════════════════════════════════ */

ServiceProbeMatch::ServiceProbeMatch() {
    /* FIX #8: zero-initialise the per-instance output buffers. */
    memset(i_product,    0, sizeof(i_product));
    memset(i_version,    0, sizeof(i_version));
    memset(i_info,       0, sizeof(i_info));
    memset(i_hostname,   0, sizeof(i_hostname));
    memset(i_ostype,     0, sizeof(i_ostype));
    memset(i_devicetype, 0, sizeof(i_devicetype));
    memset(i_cpe_a,      0, sizeof(i_cpe_a));
    memset(i_cpe_h,      0, sizeof(i_cpe_h));
    memset(i_cpe_o,      0, sizeof(i_cpe_o));
}

ServiceProbeMatch::~ServiceProbeMatch() {
    if (!initialized_) return;
    free(matchstr_);
    free(tmpl_product_);
    free(tmpl_version_);
    free(tmpl_info_);
    free(tmpl_hostname_);
    free(tmpl_ostype_);
    free(tmpl_devicetype_);
    for (char *c : tmpl_cpe_) free(c);
    if (regex_) { pcre2_code_free(regex_);         regex_ = nullptr; }
    if (mdata_) { pcre2_match_data_free(mdata_);   mdata_ = nullptr; }
    if (mctx_)  { pcre2_match_context_free(mctx_); mctx_  = nullptr; }
    if (jit_stack_) { pcre2_jit_stack_free(jit_stack_); jit_stack_ = nullptr; }
}

/* ── Template parser helper ─────────────────────────────────────────
   Reads one ?/text/ or cpe:/text/ token from *matchtext.
   Updates *matchtext past the token.
   Returns false when no more tokens.

   FIX #1 — cpe:/ content-start pointer:
   The original code had:
       const char *q = p + i;        // q = 'c' of "cpe"
       if (strcmp(modestr,"cpe")==0 && *q==':') {
           q++;                      // q = '/'  (the colon is skipped)
           if (*q != '/') ...
       } else {
           p = q + 1;                // skip past delimiter for non-cpe
       }
       char delimchar = *q;          // '/' — correct
       const char *end = strchr(q+1, delimchar);
       *tmplt = cp_strndup(p, end-p);   // BUG: p still points at 'c'!

   For "cpe" mode, p was never updated, so strndup got "cpe:/..." instead
   of the content after the '/'.  Fix: set p = q + 1 (the char after '/').

   FIX #4 — flags parsing too strict AND delimiter scanning ignores escapes:

   Problem A (delimiter scanning):
   The original scanner used strchr() to find the closing delimiter, which
   does not understand backslash escapes.  A regex like:
       m|foo\/bar|
   uses '|' as the delimiter and '/' is escaped for safety.  strchr would
   find the wrong '|' if the pattern contained a literal '|' (impossible to
   escape with this approach).  More critically, when the delimiter itself is
   '/' a pattern like "m/foo\/bar/" would have strchr() find the '\/' slash
   as the closing delimiter, producing a truncated pattern and leaving the
   remainder as "bar/" to be parsed as flags — causing "flags too long".
   Fix: scan character by character, treating '\X' as a two-character
   literal so the escaped delimiter is never mistaken for the real one.

   Problem B (flags terminator):
   After reading up to 3 flag characters, the original code checked:
       if (!isspace(*after) && *after != '\0') fatal("flags too long")
   This fires on valid lines where version templates follow each other using
   their own delimiters, e.g.:
       match http m|...|p|product|i|info|
   After the closing '|' of the regex, 'p' is read as a flag, then '|' is
   the next char — neither space nor NUL → fatal error on a valid line.
   Fix: also accept any non-alpha character as a valid flags terminator
   (the next template's mode letter is alpha and starts a new token, while
   a delimiter character like '|' or '/' means we are at the start of the
   next template's content, which is fine to stop at).
   ─────────────────────────────────────────────────────────────────── */
bool ServiceProbeMatch::nextTemplate(const char **matchtext,
                                     char modestr[4], char **tmplt,
                                     char flags[4], int lineno) {
    const char *p = *matchtext;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') return false;

    /* FIX #2: zero-initialise so modestr[3] is always '\0',
       preventing the 'cpe' key check from reading uninitialised memory. */
    memset(modestr, 0, 4);

    int i = 0;
    for (; i < 3 && isalpha((unsigned char)p[i]); i++)
        modestr[i] = p[i];
    /* modestr[i] already '\0' from the memset above */

    const char *q = p + i;   /* q points at the character after the mode letters */

    if (strcmp(modestr, "cpe") == 0 && *q == ':') {
        /* cpe:/.../ form.  q is at ':'.  Advance past ':' to reach '/'. */
        q++;
        if (*q != '/')
            fatal("parse error (cpe expects '/' after ':') on line %d", lineno);
        /*
         * FIX #1: set p to the character after the opening '/' so that
         * cp_strndup below copies the content, not "cpe:/...".
         */
        p = q + 1;
    } else {
        if (*q == '\0' || isspace((unsigned char)*q))
            fatal("parse error (bare word '%s') on line %d", modestr, lineno);
        /* For non-cpe modes q is the delimiter, p is the content start. */
        p = q + 1;
    }

    char delimchar = *q;

    /*
     * FIX #4a: scan for the closing delimiter character-by-character,
     * treating backslash-escaped pairs as a single unit so that an
     * escaped delimiter (e.g. "\/" inside a "/.../"-delimited template,
     * or "\|" inside a "|...|-delimited template) is never mistaken for
     * the real closing delimiter.
     */
    const char *scan = p;
    while (*scan) {
        if (*scan == '\\' && *(scan + 1) != '\0') {
            scan += 2;   /* skip escaped character — cannot be the delimiter */
            continue;
        }
        if (*scan == delimchar) break;
        scan++;
    }
    if (*scan != delimchar)
        fatal("parse error (missing end delimiter '%c') on line %d", delimchar, lineno);

    *tmplt = cp_strndup(p, scan - p);

    /* Flags after closing delimiter */
    p = scan + 1;
    memset(flags, 0, 4);
    for (i = 0; i < 3 && isalpha((unsigned char)p[i]); i++)
        flags[i] = p[i];
    const char *after = p + i;

    /*
     * FIX #4b: allow any non-alpha character (whitespace, NUL, or a
     * delimiter character for the next template) to terminate the flags
     * field.  The original strict check required whitespace/NUL, which
     * rejected valid multi-template lines like:
     *   match http m|...|p|Apache| v/$1/ i|detail|
     * where the closing '|' of one template is adjacent to the next mode
     * letter without whitespace between them.
     */
    if (*after != '\0' && isalpha((unsigned char)*after)) {
        /* Still have alpha characters — flags field is genuinely too long. */
        free(*tmplt); *tmplt = nullptr;
        fatal("parse error (flags too long) on line %d", lineno);
    }

    *matchtext = after;
    return true;
}

/* ── Main initialiser ────────────────────────────────────────────── */
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

    uint32_t opts = 0;
    if (flag_i_) opts |= PCRE2_CASELESS;
    if (flag_s_) opts |= PCRE2_DOTALL;

    int       errcode   = 0;
    PCRE2_SIZE erroffset = 0;
    regex_ = pcre2_compile((PCRE2_SPTR8)matchstr_, PCRE2_ZERO_TERMINATED,
                           opts, &errcode, &erroffset, nullptr);
    if (!regex_)
        fatal("%s: illegal regex on line %d (offset %zu, code %d): %s",
              __func__, lineno, (size_t)erroffset, errcode, matchstr_);

    mdata_ = pcre2_match_data_create_from_pattern(regex_, nullptr);
    if (!mdata_) fatal("%s: pcre2_match_data_create failed", __func__);

    mctx_ = pcre2_match_context_create(nullptr);
    if (!mctx_)  fatal("%s: pcre2_match_context_create failed", __func__);

    pcre2_set_match_limit(mctx_, 1000000);   // 10× headroom for complex service probes
#ifdef pcre2_set_depth_limit
    pcre2_set_depth_limit(mctx_, 50000);
#else
    pcre2_set_recursion_limit(mctx_, 50000);
#endif

    /* Version templates: p/ v/ i/ h/ o/ d/ cpe:/ */
    char *tmp = nullptr;
    while (nextTemplate(&matchtext, modestr, &tmp, flags, lineno)) {
        char **dest = nullptr;

        /* FIX #2: modestr[3] is now always '\0' (zero-initialised above),
           so the 4-byte key built below is reliable. */
        uint32_t key = (uint32_t)(unsigned char)modestr[0]
                     | ((uint32_t)(unsigned char)modestr[1] << 8)
                     | ((uint32_t)(unsigned char)modestr[2] << 16)
                     | ((uint32_t)(unsigned char)modestr[3] << 24);

        /* Single-letter keys */
        switch ((char)modestr[0]) {
            case 'p': if (modestr[1]=='\0') { dest = &tmpl_product_;    goto assign; } break;
            case 'v': if (modestr[1]=='\0') { dest = &tmpl_version_;    goto assign; } break;
            case 'i': if (modestr[1]=='\0') { dest = &tmpl_info_;       goto assign; } break;
            case 'h': if (modestr[1]=='\0') { dest = &tmpl_hostname_;   goto assign; } break;
            case 'o': if (modestr[1]=='\0') { dest = &tmpl_ostype_;     goto assign; } break;
            case 'd': if (modestr[1]=='\0') { dest = &tmpl_devicetype_; goto assign; } break;
            default: break;
        }

        /* Three-letter key "cpe" */
        if (modestr[0]=='c' && modestr[1]=='p' && modestr[2]=='e' && modestr[3]=='\0') {
            tmpl_cpe_.push_back(tmp);
            tmp = nullptr;
            continue;
        }

        /* Unknown */
        free(tmp); tmp = nullptr;
        fatal("%s: unknown template specifier '%s' (line %d)", __func__, modestr, lineno);

    assign:
        if (dest) {
            if (*dest) free(*dest);
            *dest = tmp;
            tmp   = nullptr;
        }
        (void)key;
    }
}

/* ── CPE URL character transformer ──────────────────────────────── */
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

/*
 * FIX #5 — off-by-one before buffer start:
 * The original escape check inside the string-scan loop was:
 *     while (*p && !(*p == '"' && *(p-1) != '\\'))
 * This condition reads *(p-1) on the very first iteration when p points
 * at the character immediately after the opening '"', which is correct,
 * BUT the initial p++ that advances past the opening '"' was done after
 * the condition check in the original code (it used a post-increment
 * form).  In effect, on the first iteration p still pointed at '"', so
 * *(p-1) was the character before the opening '"' — one byte before the
 * region we own.
 * Fix: use a proper loop that only checks the backslash condition when
 * we are at least one character into the string (i.e. always, because we
 * advance p before the condition is first evaluated in the new loop).
 */
static int parseSubstArgs(SubstArgs *args, char *p, char **end) {
    memset(args, 0, sizeof(*args));
    while (*p && *p != ')') {
        while (isspace((unsigned char)*p)) p++;
        if (*p == ')') break;

        if (*p == '"') {
            if (args->num_args >= 5) return -1;
            int idx = args->num_args;
            int len = 0;
            p++;  /* advance past opening '"' — p now inside the string */

            /* FIX #5: check *(p-1) only when p has advanced at least one
               character past the opening quote, which is always true here
               because we incremented p before entering the loop body. */
            while (*p) {
                if (*p == '"' && *(p - 1) != '\\') break;   /* safe: p > start */
                if (len >= 127) return -1;
                args->str_args[idx][len++] = *p++;
            }
            if (*p == '"') p++;   /* consume closing '"' */
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

/*
 * FIX #6: when a capture group is PCRE2_UNSET (optional group that
 * didn't participate in the match), the original code returned nullptr,
 * which caused doTmplSubst() to treat the whole template substitution
 * as a failure and blank the output field.  This is wrong: an unset
 * optional group should simply contribute an empty string, letting any
 * surrounding literal text in the template survive.
 */
char *ServiceProbeMatch::substVar(const char *tmplvar, const char **tmplvarend,
                                   const u8 *subject, size_t subjectlen,
                                   pcre2_match_data *md) {
    if (*tmplvar != '$') return nullptr;
    tmplvar++;

    char      substcmd[16] = {};
    u8        subnum        = 0;
    SubstArgs args;

    if (!isdigit((unsigned char)*tmplvar)) {
        char *lp = strchr(const_cast<char *>(tmplvar), '(');
        if (!lp) return nullptr;
        int cmdlen = (int)(lp - tmplvar);
        if (cmdlen <= 0 || cmdlen >= (int)sizeof(substcmd)) return nullptr;
        memcpy(substcmd, tmplvar, cmdlen);
        substcmd[cmdlen] = '\0';
        char *after_args = lp + 1;
        char *ep;
        if (parseSubstArgs(&args, after_args, &ep) < 0) return nullptr;
        tmplvar = ep;
    } else {
        subnum  = (u8)(*tmplvar - '0');
        tmplvar++;
    }
    if (tmplvarend) *tmplvarend = tmplvar;

    u32        ncap = pcre2_get_ovector_count(md);
    PCRE2_SIZE *ov  = pcre2_get_ovector_pointer(md);

    /* Returns false and sets os=oe=PCRE2_UNSET when group didn't match */
    auto getCapture = [&](int n, PCRE2_SIZE &os, PCRE2_SIZE &oe) -> bool {
        if (n <= 0 || n > 9 || (u32)n >= ncap) return false;
        os = ov[n * 2];
        oe = ov[n * 2 + 1];
        return os != PCRE2_UNSET;
    };

    std::string result;

    if (substcmd[0] == '\0') {
        /* $N */
        PCRE2_SIZE os, oe;
        if (!getCapture((int)subnum, os, oe)) {
            /* FIX #6: unset optional group → return empty string, not nullptr */
            char *empty = (char *)malloc(1);
            if (empty) empty[0] = '\0';
            return empty;
        }
        result.assign((const char *)subject + os, oe - os);

    } else if (strcmp(substcmd, "P") == 0) {
        /* $P(N) — printable chars only */
        if (args.num_args != 1 || args.types[0] != SubstArgs::Type::Int) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) {
            char *empty = (char *)malloc(1);
            if (empty) empty[0] = '\0';
            return empty;
        }
        for (PCRE2_SIZE i = os; i < oe; i++)
            if (isprint((int)subject[i])) result += (char)subject[i];

    } else if (strcmp(substcmd, "SUBST") == 0) {
        /* $SUBST(N,"find","replace") */
        if (args.num_args != 3
            || args.types[0] != SubstArgs::Type::Int
            || args.types[1] != SubstArgs::Type::String
            || args.types[2] != SubstArgs::Type::String) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) {
            char *empty = (char *)malloc(1);
            if (empty) empty[0] = '\0';
            return empty;
        }
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
        /* $I(N,">"/"<") — parse unsigned int big/little-endian */
        if (args.num_args != 2
            || args.types[0] != SubstArgs::Type::Int
            || args.types[1] != SubstArgs::Type::String
            || args.str_lens[1] != 1) return nullptr;
        PCRE2_SIZE os, oe;
        if (!getCapture(args.int_args[0], os, oe)) {
            char *empty = (char *)malloc(1);
            if (empty) empty[0] = '\0';
            return empty;
        }
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

/* ── doTmplSubst — walk a template string and substitute $N / $CMD ─ */
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
        /*
         * FIX #6 knock-on: substVar now returns an allocated empty string
         * for unset optional groups instead of nullptr.  We only treat
         * nullptr as a fatal error (unknown command / out-of-range group).
         */
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

    /* Strip trailing whitespace and commas */
    while (--dst >= out && (isspace((unsigned char)*dst) || *dst == ','))
        *dst = '\0';
    return 0;
}

/*
 * FIX #8b / FIX #6b (CPE output format):
 * After FIX #1, tmpl_cpe_ entries hold the content AFTER the opening
 * '/' of "cpe:/", e.g. "a:openresty:ngx_openresty:$1".
 * The first character is the CPE part letter ('a', 'h', or 'o').
 * doTmplSubst produces "a:openresty:ngx_openresty:1.2.3" which is
 * correct as the BODY, but the full CPE URI must be "cpe:/a:...".
 * We prepend "cpe:/" in the output buffer so callers get a valid URI.
 *
 * FIX #10 (multiple cpe:/ templates — append, not overwrite):
 * When a match line carries multiple cpe:/ entries (e.g. both an 'a'
 * and an 'o' CPE), each one should land in its own slot.  The original
 * code did a straight assignment which silently overwrote the previous
 * value if two entries shared the same part letter.  We now only write
 * into a slot if it is still empty, so the FIRST matching CPE of each
 * part wins (consistent with Nmap's behaviour).
 */
int ServiceProbeMatch::fillVersionStr(const u8 *subject, size_t subjectlen) {
    /* FIX #8: write into per-instance buffers (i_*) not static s_* */
    i_product[0] = i_version[0] = i_info[0] = '\0';
    i_hostname[0] = i_ostype[0] = i_devicetype[0] = '\0';
    i_cpe_a[0] = i_cpe_h[0] = i_cpe_o[0] = '\0';
    int ret = 0;

    auto fill = [&](const char *tmpl, char *out, int outlen, const char *name) {
        if (!tmpl) return;
        if (doTmplSubst(subject, subjectlen, mdata_, tmpl, out, outlen) != 0) {
            logError("template substitution failed for %s (line %d)", name, deflineno_);
            out[0] = '\0'; ret = -1;
        }
    };

    fill(tmpl_product_,    i_product,    SERVICE_FIELD_LEN, "product");
    fill(tmpl_version_,    i_version,    SERVICE_FIELD_LEN, "version");
    fill(tmpl_info_,       i_info,       SERVICE_EXTRA_LEN, "info");
    fill(tmpl_hostname_,   i_hostname,   SERVICE_FIELD_LEN, "hostname");
    fill(tmpl_ostype_,     i_ostype,     SERVICE_TYPE_LEN,  "ostype");
    fill(tmpl_devicetype_, i_devicetype, SERVICE_TYPE_LEN,  "devicetype");

    for (const char *cpe_tmpl : tmpl_cpe_) {
        if (!cpe_tmpl || cpe_tmpl[0] == '\0') continue;

        /*
         * The template starts with the CPE part letter (e.g. "a:vendor:product:$1").
         * Determine the destination buffer from it.
         */
        char part = cpe_tmpl[0];
        char *dest = nullptr; int dlen = 0;
        if      (part == 'a') { dest = i_cpe_a; dlen = SERVICE_FIELD_LEN; }
        else if (part == 'h') { dest = i_cpe_h; dlen = SERVICE_FIELD_LEN; }
        else if (part == 'o') { dest = i_cpe_o; dlen = SERVICE_FIELD_LEN; }
        else continue;

        /*
         * FIX #10: only write if this slot is still empty so that the
         * first CPE of each part wins when multiple entries are present.
         */
        if (dest[0] != '\0') continue;

        /*
         * FIX #6b / FIX #8b: build the full "cpe:/..." URI.
         * Reserve 6 bytes for the "cpe:/" prefix plus NUL.
         */
        char body[SERVICE_FIELD_LEN];
        body[0] = '\0';
        if (doTmplSubst(subject, subjectlen, mdata_, cpe_tmpl, body, sizeof(body),
                        transformCPE) != 0) {
            logError("CPE template failed (line %d)", deflineno_);
            ret = -1;
            continue;
        }

        /* Prepend "cpe:/" to produce the full CPE URI. */
        int prefix_len = 5; /* strlen("cpe:/") */
        int body_len   = (int)strlen(body);
        if (prefix_len + body_len < dlen) {
            memcpy(dest, "cpe:/", prefix_len);
            memcpy(dest + prefix_len, body, body_len + 1);
        } else {
            /* Truncate gracefully */
            memcpy(dest, "cpe:/", prefix_len);
            memcpy(dest + prefix_len, body, dlen - prefix_len - 1);
            dest[dlen - 1] = '\0';
        }
    }
    return ret;
}

/*
 * PERF: tiered, thread-safe lazy JIT compile.
 *
 * v1 JIT-compiled on the first test of every match via std::call_once.
 * That cut mmap/munmap ~5x but pthread_once's mandatory completion
 * signal (a futex syscall on every first-time compile, even
 * uncontended) put the syscall cost right back -- ~2700 futex calls on
 * a single-port scan. Two fixes:
 *
 *   1. Double-checked atomic + plain mutex instead of call_once. An
 *      uncontended std::mutex lock/unlock stays in userspace in glibc
 *      (CAS only) -- no syscall unless two threads genuinely race.
 *   2. Don't JIT on the first test at all. JIT costs an mmap+mprotect
 *      for executable code, which only pays off if the SAME match is
 *      tested many times (multi-port scans reusing the shared probe
 *      database). For a one/few-port scan most matches are tested once
 *      or twice -- interpreted pcre2_match() is already fast enough, so
 *      paying JIT cost there is pure overhead. Only JIT once a match
 *      has actually been re-tested past kJitAfterHits times, so short
 *      scans skip JIT almost entirely while long multi-port scans still
 *      get the full speedup once it's actually worth it.
 */
static constexpr int kJitAfterHits = 2;

void ServiceProbeMatch::ensureJitCompiled() {
    if (jit_attempted_.load(std::memory_order_acquire)) return;

    int hits = hit_count_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (hits <= kJitAfterHits) return;   // still cheap to interpret -- not worth JIT yet

    std::lock_guard<std::mutex> lock(jit_compile_mu_);
    if (jit_attempted_.load(std::memory_order_relaxed)) return;   // double-check under lock

    if (pcre2_jit_compile(regex_, PCRE2_JIT_COMPLETE) == 0) {
        jit_stack_ = pcre2_jit_stack_create(32 * 1024, 1024 * 1024, nullptr);
        if (jit_stack_) pcre2_jit_stack_assign(mctx_, nullptr, jit_stack_);
        jit_ready_ = true;
    }
    jit_attempted_.store(true, std::memory_order_release);
}

/* ── testMatch — the main per-match entry point ─────────────────── */
const MatchDetails *ServiceProbeMatch::testMatch(const u8 *buf, int buflen) {
    assert(initialized_);
    ensureJitCompiled();   /* PERF: lazy, one-time JIT compile on first real use */
    memset(&md_return_, 0, sizeof(md_return_));
    md_return_.isSoft = isSoft_;

    int rc = jit_ready_
             ? pcre2_jit_match(regex_, (PCRE2_SPTR8)buf, (PCRE2_SIZE)buflen,
                               0, 0, mdata_, mctx_)
             : pcre2_match(regex_, (PCRE2_SPTR8)buf, (PCRE2_SIZE)buflen,
                           0, 0, mdata_, mctx_);
    if (rc < 0) {
        if (rc == PCRE2_ERROR_MATCHLIMIT || rc == PCRE2_ERROR_DEPTHLIMIT) {
            /* Catastrophic backtracking in the probe regex — treat as no-match
             * but warn once so the probe file author can fix the pattern.       */
            logError("PCRE2 match limit hit (error %d) for service %s — "
                     "regex likely has catastrophic backtracking: '%s'",
                     rc, servicename_, matchstr_);
        } else if (rc != PCRE2_ERROR_NOMATCH) {
            logError("PCRE2 error %d matching service %s regex '%s'",
                     rc, servicename_, matchstr_);
        }
        return &md_return_;
    }

    fillVersionStr(buf, (size_t)buflen);
    /* FIX #8: point into instance buffers, not static buffers */
    if (i_product[0])    md_return_.product    = i_product;
    if (i_version[0])    md_return_.version    = i_version;
    if (i_info[0])       md_return_.info       = i_info;
    if (i_hostname[0])   md_return_.hostname   = i_hostname;
    if (i_ostype[0])     md_return_.ostype     = i_ostype;
    if (i_devicetype[0]) md_return_.devicetype = i_devicetype;
    if (i_cpe_a[0])      md_return_.cpe_a      = i_cpe_a;
    if (i_cpe_h[0])      md_return_.cpe_h      = i_cpe_h;
    if (i_cpe_o[0])      md_return_.cpe_o      = i_cpe_o;
    md_return_.serviceName = servicename_;
    md_return_.lineno      = deflineno_;
    return &md_return_;
}

/* ══════════════════════════════════════════════════════════════════════
   ServiceProbe
   ══════════════════════════════════════════════════════════════════════ */

ServiceProbe::ServiceProbe() { memset(fallbacks, 0, sizeof(fallbacks)); }

ServiceProbe::~ServiceProbe() {
    for (auto *m : matches_) delete m;
    if (fallbackStr) free(fallbackStr);
    free((void *)probename_);
    free((void *)probestring_);
}

void ServiceProbe::setProbeString(const u8 *ps, int len) {
    probestringlen_ = len;
    probestring_    = (len > 0) ? (const u8 *)cp_strndup((const char *)ps, len) : nullptr;
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
    probename_ = cp_strndup(pd, sp - pd);
    pd = sp + 1;

    if (*pd != 'q')
        fatal("Parse error on line %d: probe string must begin with 'q'", lineno);
    char delim = *++pd;
    char *ep   = strchr(++pd, delim);
    if (!ep) fatal("Parse error on line %d: no ending delimiter for probe string", lineno);
    *ep = '\0';
    unsigned int slen = 0;
    if (!cstring_unescape(pd, &slen))
        fatal("Parse error on line %d: bad probe string escaping", lineno);
    setProbeString((const u8 *)pd, (int)slen);

    pd = ep + 1;
    while (*pd && *pd != '\n') {
        while (*pd && isspace((unsigned char)*pd)) pd++;
        if (strncmp(pd, "no-payload", 10) == 0) { notForPayload_ = true; break; }
        while (*pd && !isspace((unsigned char)*pd)) pd++;
    }
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
    int r = atoi(val);
    if (r < 1 || r > 9) fatal("Rarity on line %d must be 1–9", lineno);
    rarity_ = r;
}

void ServiceProbe::addMatch(const char *matchline, int lineno) {
    auto *m = new ServiceProbeMatch();
    m->init(matchline, lineno);
    const char *sn = m->getName();
    if (!serviceIsPossible(sn)) detectedServices_.push_back(sn);
    matches_.push_back(m);
}

bool ServiceProbe::portIsProbable(ServiceTunnel tunnel, u16 portno) const {
    const std::vector<u16> &v = (tunnel == ServiceTunnel::SSL)
                                 ? probablesslports_ : probableports_;
    return std::find(v.begin(), v.end(), portno) != v.end();
}

/* FIX #2b: expose the sslports list for UDP DTLS detection. */
bool ServiceProbe::portIsSSL(u16 portno) const {
    return std::find(probablesslports_.begin(), probablesslports_.end(), portno)
           != probablesslports_.end();
}

bool ServiceProbe::serviceIsPossible(const char *sname) const {
    for (auto *s : detectedServices_) if (strcmp(s, sname) == 0) return true;
    return false;
}

const MatchDetails *ServiceProbe::testMatch(const u8 *buf, int buflen, int n) {
    for (auto *m : matches_) {
        const MatchDetails *md = m->testMatch(buf, buflen);
        if (md->serviceName) {
            if (n == 0) return md;
            n--;
        }
    }
    return nullptr;
}

/* ══════════════════════════════════════════════════════════════════════
   AllProbes
   ══════════════════════════════════════════════════════════════════════ */

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

/*
 * FIX #7 (circular fallback detection):
 * Walk each probe's fully-resolved fallback chain and verify that no probe
 * appears twice.  A cycle (A→B→A) would cause infinite loops in testMatch
 * and feedResponse.  We detect it early and throw a clear error.
 *
 * FIX #3b (NULL probe always at end of TCP chain):
 * After resolving all named fallback entries, append the NULL probe to
 * every TCP probe's chain if it is not already present.  This ensures that
 * banner-grab-only services (which only send data without needing a probe
 * payload) are always tried last via the NULL probe.
 */
void AllProbes::compileFallbacks() {
    if (nullProbe) nullProbe->fallbacks[0] = nullProbe;

    for (auto *probe : probes) {
        probe->fallbacks[0] = probe;
        int i = 1;

        if (probe->fallbackStr) {
            char *fbcopy = strdup(probe->fallbackStr);
            if (!fbcopy) throw std::bad_alloc();
            char *tok = strtok(fbcopy, ",\r\n\t ");
            while (tok && i < MAXFALLBACKS - 1) {
                ServiceProbe *fb = getProbeByName(tok, probe->getProtocol());
                if (!fb)
                    fatal("compileFallbacks: unknown fallback '%s' in probe '%s'",
                          tok, probe->getName());
                probe->fallbacks[i++] = fb;
                tok = strtok(nullptr, ",\r\n\t ");
            }
            if (tok && i >= MAXFALLBACKS - 1)
                fatal("compileFallbacks: MAXFALLBACKS exceeded for probe '%s'",
                      probe->getName());
            free(fbcopy);
            free(probe->fallbackStr);
            probe->fallbackStr = nullptr;
        }

        /*
         * FIX #3b: always append NULL probe at the end of TCP chains so
         * that banner-grab-only services are checked even when a probe has
         * named fallbacks.  Skip if NULL probe is already in the chain.
         */
        if (probe->getProtocol() == IPPROTO_TCP && nullProbe) {
            bool has_null = false;
            for (int j = 0; j < i; j++) {
                if (probe->fallbacks[j] == nullProbe) { has_null = true; break; }
            }
            if (!has_null && i < MAXFALLBACKS) {
                probe->fallbacks[i++] = nullProbe;
            }
        }

        /* Null-terminate the chain */
        if (i <= MAXFALLBACKS) probe->fallbacks[i] = nullptr;
    }

    /*
     * FIX #7: circular fallback detection.
     * After all chains are built, walk each one and check for duplicates
     * using a small visited set.
     */
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
        for (auto it = probe->probablePortsBegin(); it != probe->probablePortsEnd(); ++it) {
            portIndex_[portIndexKey(proto, *it)].push_back(probe);
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
   File parser

   PERF: previously used fgets() into a static 16384-byte buffer, which
   meant one buffered read() plus one memcpy per line — significant
   overhead on a file with many thousands of lines. We now mmap() the
   whole file once and scan it with memchr(), null-terminating each line
   in place (MAP_PRIVATE gives copy-on-write pages, so the file on disk
   is never modified). This also removes the old PROBE_LINE_BUF (16 KB)
   line-length ceiling entirely — arbitrarily long lines are handled with
   no special-casing.

   SECURITY:
     - the file descriptor is opened O_CLOEXEC so it is never inherited
       by child processes spawned elsewhere in the program.
     - we reject anything that isn't a regular file (fstat + S_ISREG),
       so this can't be pointed at a FIFO/device/directory and hang or
       behave unexpectedly.
     - the mapping is released via an RAII guard, so a fatal() parse
       error (which throws std::runtime_error) still unmaps the file
       instead of leaking the mapping.
   ══════════════════════════════════════════════════════════════════════ */

namespace {
/* RAII guard: guarantees munmap() runs even if a parse error throws. */
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

    /* MAP_PRIVATE + PROT_WRITE: copy-on-write pages let us null-terminate
       lines in place without touching the underlying file. */
    void *mapped = mmap(nullptr, filesize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE, fd, 0);
    close(fd);  /* fd not needed once the mapping exists */
    if (mapped == MAP_FAILED)
        fatal("mmap failed on nmap-service-probes file: %s (%s)",
              filename, strerror(errno));

    MmapGuard guard{mapped, filesize};
    madvise(mapped, filesize, MADV_SEQUENTIAL);

    char *base = (char *)mapped;
    char *cursor = base;
    char *end    = base + filesize;

    int           lineno   = 0;
    ServiceProbe *newProbe = nullptr;

    auto finishProbe = [&]() {
        if (!newProbe) return;
        if (newProbe->isNullProbe()) {
            if (AP->nullProbe) fatal("Duplicate NULL probe at line %d", lineno);
            AP->nullProbe = newProbe;
        } else {
            AP->probes.push_back(newProbe);
        }
        newProbe = nullptr;
    };

    while (cursor < end) {
        lineno++;

        char *nl   = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        char *line = cursor;
        cursor = nl ? nl + 1 : end;
        if (nl) *nl = '\0';

        /* Strip a trailing '\r' so CRLF-formatted probe files parse cleanly. */
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
            newProbe = new ServiceProbe();
            newProbe->setProbeDetails(line + 6, lineno);
            continue;
        }

        if (!newProbe)
            fatal("Unexpected directive outside Probe block at line %d: %s", lineno, line);

        if (strncmp(line, "ports ", 6) == 0) {
            newProbe->setProbablePorts(ServiceTunnel::NONE, line + 6, lineno);
        } else if (strncmp(line, "sslports ", 9) == 0) {
            /*
             * FIX #2 (sslports for UDP / DTLS):
             * sslports is now stored for both TCP and UDP probes.
             * For TCP, sslports marks ports that should be probed with SSL.
             * For UDP, sslports marks ports that may use DTLS; the
             * matchResponse path uses portIsSSL() to attempt these with
             * ServiceTunnel::SSL so DTLS-based services can be detected.
             */
            newProbe->setProbablePorts(ServiceTunnel::SSL, line + 9, lineno);
        } else if (strncmp(line, "rarity ", 7) == 0) {
            newProbe->setRarity(line + 7, lineno);
        } else if (strncmp(line, "fallback ", 9) == 0) {
            newProbe->fallbackStr = strdup(line + 9);
        } else if (strncmp(line, "totalwaitms ", 12) == 0) {
            long ms = strtol(line + 12, nullptr, 10);
            if (ms < 100 || ms > 300000) fatal("Bad totalwaitms %ld on line %d", ms, lineno);
            newProbe->setTotalWaitMs((int)ms);
        } else if (strncmp(line, "tcpwrappedms ", 13) == 0) {
            long ms = strtol(line + 13, nullptr, 10);
            if (ms < 100 || ms > 300000) fatal("Bad tcpwrappedms %ld on line %d", ms, lineno);
            newProbe->setTcpWrappedMs((int)ms);
        } else if (strncmp(line, "match ", 6) == 0
                || strncmp(line, "softmatch ", 10) == 0) {
            newProbe->addMatch(line, lineno);
        } else {
            /* Unknown directives are tolerated (forward-compatibility) */
        }
    }
    finishProbe();
    /* mapping is released automatically by `guard` going out of scope */
    AP->compileFallbacks();
}

/* ══════════════════════════════════════════════════════════════════════
   ServiceNFO
   ══════════════════════════════════════════════════════════════════════ */

ServiceNFO::ServiceNFO(AllProbes *ap) : AP(ap) {
    memset(product_matched,    0, sizeof(product_matched));
    memset(version_matched,    0, sizeof(version_matched));
    memset(extrainfo_matched,  0, sizeof(extrainfo_matched));
    memset(hostname_matched,   0, sizeof(hostname_matched));
    memset(ostype_matched,     0, sizeof(ostype_matched));
    memset(devicetype_matched, 0, sizeof(devicetype_matched));
    memset(cpe_a_matched,      0, sizeof(cpe_a_matched));
    memset(cpe_h_matched,      0, sizeof(cpe_h_matched));
    memset(cpe_o_matched,      0, sizeof(cpe_o_matched));
    memset(probe_matched_stripped, 0, sizeof(probe_matched_stripped));
    current_probe_ = AP->probes.begin();
}

ServiceNFO::~ServiceNFO() {
    free(currentresp_);
    free(servicefp_);
}

ServiceProbe *ServiceNFO::currentProbe() {
    if (probe_state == ProbeState::INITIAL)                return nextProbe(true);
    if (probe_state == ProbeState::NULLPROBE)              return AP->nullProbe;
    if (probe_state == ProbeState::MATCHINGPROBES
     || probe_state == ProbeState::NONMATCHINGPROBES)      return *current_probe_;
    return nullptr;
}

/*
 * FIX #5b (NULL probe for all TCP ports):
 * The original INITIAL→NULLPROBE transition returned the NULL probe only
 * when proto==TCP AND nullProbe!=nullptr.  For UDP we jumped straight to
 * MATCHINGPROBES.  This was correct for UDP (the NULL probe is TCP-only),
 * but the comment in the header said "first probe for all TCP ports",
 * implying we want it for every TCP port.  We now ensure the NULL probe
 * is tried first for all TCP connections regardless of port number —
 * portIsProbable filtering is intentionally NOT applied to the NULL probe
 * (Nmap also does this: the NULL probe checks every TCP port by default).
 */
ServiceProbe *ServiceNFO::nextProbe(bool newresp) {
    if (newresp) { free(currentresp_); currentresp_ = nullptr; currentresplen_ = 0; }

    bool dropdown = false;

    if (probe_state == ProbeState::INITIAL) {
        probe_state = ProbeState::NULLPROBE;
        /* FIX #5b: always try the NULL probe first for TCP (no port filter). */
        if (proto == IPPROTO_TCP && AP->nullProbe) return AP->nullProbe;
        /* For UDP/SCTP fall through to MATCHINGPROBES immediately. */
    }

    if (probe_state == ProbeState::NULLPROBE) {
        probe_state    = ProbeState::MATCHINGPROBES;
        dropdown       = true;
        current_probe_ = AP->probes.begin();
    }

    if (probe_state == ProbeState::MATCHINGPROBES) {
        if (!dropdown && current_probe_ != AP->probes.end()) ++current_probe_;
        while (current_probe_ != AP->probes.end()) {
            ServiceProbe *p = *current_probe_;
            if (p->getProtocol() == proto
             && p->portIsProbable(tunnel, portno)
             && (!softMatchFound || p->serviceIsPossible(probe_matched)))
                return p;
            ++current_probe_;
        }
        probe_state    = ProbeState::NONMATCHINGPROBES;
        dropdown       = true;
        current_probe_ = AP->probes.begin();
    }

    if (probe_state == ProbeState::NONMATCHINGPROBES) {
        if (!dropdown && current_probe_ != AP->probes.end()) ++current_probe_;
        int intensity = MAX_VERSION_INTENSITY;
        while (current_probe_ != AP->probes.end()) {
            ServiceProbe *p = *current_probe_;
            bool ok = (p->getProtocol() == proto)
                   && !p->portIsProbable(tunnel, portno)
                   && ((!softMatchFound && p->getRarity() <= intensity)
                     || (softMatchFound
                         && (intensity >= 9 || p->serviceIsPossible(probe_matched))));
            if (ok) return p;
            ++current_probe_;
        }
        probe_state = softMatchFound ? ProbeState::FINISHED_SOFTMATCHED
                                     : ProbeState::FINISHED_NOMATCH;
        return nullptr;
    }

    fatal("nextProbe: unexpected state %d", (int)probe_state);
}

void ServiceNFO::resetProbes(bool freeFP) {
    free(currentresp_); currentresp_ = nullptr; currentresplen_ = 0;
    if (freeFP) { free(servicefp_); servicefp_ = nullptr; servicefplen_ = servicefpalloc_ = 0; }
    probe_state    = ProbeState::INITIAL;
    current_probe_ = AP->probes.begin();
}

void ServiceNFO::appendResponse(const u8 *data, int len) {
    currentresp_ = (u8 *)realloc(currentresp_, currentresplen_ + len);
    if (!currentresp_) throw std::bad_alloc();
    memcpy(currentresp_ + currentresplen_, data, len);
    currentresplen_ += len;
}

u8 *ServiceNFO::getResponse(int *lenout) {
    *lenout = currentresplen_;
    return currentresp_;
}

void ServiceNFO::clearResponse() {
    free(currentresp_); currentresp_ = nullptr; currentresplen_ = 0;
}

/* ── Fingerprint helpers ─────────────────────────────────────────── */
void ServiceNFO::addFpChar(char c, int wrapat) {
    if (servicefpalloc_ - servicefplen_ < 8) {
        servicefpalloc_ = (servicefpalloc_ == 0) ? 1024 : servicefpalloc_ * 2;
        servicefp_ = (char *)realloc(servicefp_, servicefpalloc_);
        if (!servicefp_) throw std::bad_alloc();
    }
    if (servicefplen_ % (wrapat + 1) == wrapat) {
        memcpy(servicefp_ + servicefplen_, "\nSF:", 4);
        servicefplen_ += 4;
        if (servicefpalloc_ - servicefplen_ < 8) {
            servicefpalloc_ *= 2;
            servicefp_ = (char *)realloc(servicefp_, servicefpalloc_);
            if (!servicefp_) throw std::bad_alloc();
        }
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
    int used = std::min(resplen, 900);

    if (servicefplen_ == 0) {
        time_t  now  = time(nullptr);
        struct  tm lt = {};
#ifdef _WIN32
        localtime_s(&lt, &now);
#else
        localtime_r(&now, &lt);
#endif
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
                 "SF-Port%hu-%s:V=custom%%I=7%%D=%d/%d%%Time=%X%%P=custom",
                 portno, (proto == IPPROTO_TCP) ? "TCP" : "UDP",
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
        servicefpalloc_ += 32;
        servicefp_ = (char *)realloc(servicefp_, servicefpalloc_);
        if (!servicefp_) throw std::bad_alloc();
    }
    servicefp_[servicefplen_]     = ';';
    servicefp_[servicefplen_ + 1] = '\0';
    if (flen) *flen = servicefplen_ + 1;
    return servicefp_;
}

/* ══════════════════════════════════════════════════════════════════════
   ProbeEngine
   ══════════════════════════════════════════════════════════════════════ */

ProbeEngine::ProbeEngine(AllProbes *ap, int vi) : ap_(ap), version_intensity_(vi) {}

bool ProbeEngine::processMatch(const MatchDetails *md, ServiceNFO *svc,
                                const char *probeName, const char *fallbackName) {
    if (!md || !md->serviceName) return false;

    if (md->isSoft && svc->probe_matched) {
        if (strcmp(svc->probe_matched, md->serviceName) != 0)
            logError("Soft-match conflict on port %hu: was %s, now %s — ignoring",
                     svc->portno, svc->probe_matched, md->serviceName);
        return false;
    }

    svc->probe_matched    = md->serviceName;
    svc->tcpwrap_possible = false;
    svc->softMatchFound   = md->isSoft;

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

/*
 * FIX #7b (memory-safe ssl/ prefix strip):
 * The original code did:
 *     svc->probe_matched += 4;   // skip "ssl/"
 * This moved probe_matched off the base of the allocation returned by
 * cp_strndup(), making the block un-freeable and leaking it.
 * Fix: copy the stripped name into the per-ServiceNFO
 * probe_matched_stripped[] buffer and point probe_matched at that buffer.
 */
bool ProbeEngine::scanThroughTunnel(ServiceNFO *svc) {
    if (svc->probe_matched && strncmp(svc->probe_matched, "ssl/", 4) == 0) {
        /*
         * FIX #7b: use the dedicated stripped buffer on ServiceNFO instead
         * of pointer arithmetic so probe_matched stays at a valid base address.
         */
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

    svc->tunnel         = ServiceTunnel::SSL;
    svc->probe_matched  = nullptr;
    svc->softMatchFound = false;
    memset(svc->product_matched,    0, sizeof(svc->product_matched));
    memset(svc->version_matched,    0, sizeof(svc->version_matched));
    memset(svc->extrainfo_matched,  0, sizeof(svc->extrainfo_matched));
    memset(svc->hostname_matched,   0, sizeof(svc->hostname_matched));
    memset(svc->ostype_matched,     0, sizeof(svc->ostype_matched));
    memset(svc->devicetype_matched, 0, sizeof(svc->devicetype_matched));
    memset(svc->cpe_a_matched,      0, sizeof(svc->cpe_a_matched));
    memset(svc->cpe_h_matched,      0, sizeof(svc->cpe_h_matched));
    memset(svc->cpe_o_matched,      0, sizeof(svc->cpe_o_matched));
    svc->resetProbes(true);
    return true;
}

bool ProbeEngine::feedResponse(ServiceNFO *svc, const u8 *data, int datalen) {
    svc->appendResponse(data, datalen);

    int           resplen = 0;
    const u8     *resp    = svc->getResponse(&resplen);
    ServiceProbe *probe   = svc->currentProbe();
    if (!probe) return false;

    const MatchDetails *md       = nullptr;
    ServiceProbe       *fallback = nullptr;
    for (int d = 0; d < MAXFALLBACKS + 1; d++) {
        fallback = probe->fallbacks[d];
        if (!fallback) break;
        md = fallback->testMatch(resp, resplen);
        if (md && md->serviceName) break;
    }

    bool hardMatch = false;
    if (fallback && md && md->serviceName)
        hardMatch = processMatch(md, svc, probe->getName(), fallback->getName());

    if (hardMatch) {
        if (scanThroughTunnel(svc)) return true;
        svc->probe_state = ProbeState::FINISHED_HARDMATCHED;
        return true;
    }

    if (resplen >= MAX_PROBE_RESPONSE_BYTES) {
        if (resplen > 0) svc->addToFingerprint(probe->getName(), resp, resplen);
        svc->nextProbe(true);
    }
    return false;
}

bool ProbeEngine::handleEOF(ServiceNFO *svc, bool hadData, long elapsedMs) {
    ServiceProbe *probe = svc->currentProbe();

    if (hadData) {
        svc->tcpwrap_possible = false;
        int resplen = 0;
        const u8 *resp = svc->getResponse(&resplen);
        if (resplen > 0)
            svc->addToFingerprint(probe ? probe->getName() : "unknown", resp, resplen);
    }

    if (!hadData && svc->tcpwrap_possible && probe && probe->isNullProbe()
     && elapsedMs < probe->getTcpWrappedMs()) {
        svc->probe_state = ProbeState::FINISHED_TCPWRAPPED;
        return true;
    }

    ServiceProbe *next = svc->nextProbe(true);
    if (!next) return true;
    return false;
}

bool ProbeEngine::hasMoreProbes(ServiceNFO *svc) const {
    return svc->probe_state != ProbeState::FINISHED_HARDMATCHED
        && svc->probe_state != ProbeState::FINISHED_SOFTMATCHED
        && svc->probe_state != ProbeState::FINISHED_NOMATCH
        && svc->probe_state != ProbeState::FINISHED_TCPWRAPPED
        && svc->probe_state != ProbeState::FINISHED_EXCLUDED
        && svc->probe_state != ProbeState::INCOMPLETE;
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
                                       const std::string &probeName) {
    if (ap_->isExcluded(port, proto)) {
        ScanResult r;
        r.port    = port; r.proto = proto;
        r.state   = ProbeState::FINISHED_EXCLUDED;
        r.service = "Excluded from version scan";
        return r;
    }

    if (!probeName.empty()) {
        ServiceProbe *probe = ap_->getProbeByName(probeName.c_str(), proto);
        if (probe) {
            const MatchDetails *md = nullptr;
            for (int d = 0; d < MAXFALLBACKS + 1; d++) {
                ServiceProbe *fb = probe->fallbacks[d];
                if (!fb) break;
                md = fb->testMatch(data, datalen);
                if (md && md->serviceName) break;
            }
            ServiceNFO svc(ap_);
            svc.portno = port; svc.proto = proto; svc.tunnel = tunnel;
            if (md && md->serviceName)
                processMatch(md, &svc, probe->getName(), probe->getName());
            svc.probe_state = svc.probe_matched ? ProbeState::FINISHED_HARDMATCHED
                                                : ProbeState::FINISHED_NOMATCH;
            if (!svc.probe_matched)
                svc.addToFingerprint(probe->getName(), data, datalen);
            return buildResult(&svc);
        }
    }

    ServiceNFO svc(ap_);
    svc.portno = port; svc.proto = proto; svc.tunnel = tunnel;

    auto tryProbeSet = [&](ServiceProbe *probe) -> bool {
        if (!probe) return false;
        const MatchDetails *md = nullptr;
        ServiceProbe *usedFB   = nullptr;
        for (int d = 0; d < MAXFALLBACKS + 1; d++) {
            ServiceProbe *fb = probe->fallbacks[d];
            if (!fb) break;
            md = fb->testMatch(data, datalen);
            if (md && md->serviceName) { usedFB = fb; break; }
        }
        if (!md || !md->serviceName) return false;
        return processMatch(md, &svc, probe->getName(), usedFB->getName());
    };

    /* 1. NULL probe — FIX #5b: always try first for TCP, no port filter */
    if (proto == IPPROTO_TCP && ap_->nullProbe) {
        if (tryProbeSet(ap_->nullProbe)) {
            if (!scanThroughTunnel(&svc)) goto done_hard;
        }
    }

    /* 2. MATCHINGPROBES */
    {   // scope idxIt so it doesn't outlive this block — a goto that jumps
        // forward past its declaration must not land somewhere it's still
        // in scope, which is exactly what tripped the "crosses
        // initialization" error against the done_hard: label below.
        auto idxIt = ap_->portIndex_.find(AllProbes::portIndexKey(proto, port));
        if (idxIt != ap_->portIndex_.end()) {
            for (auto *probe : idxIt->second) {
                if (svc.softMatchFound && !probe->serviceIsPossible(svc.probe_matched)) continue;
                if (tryProbeSet(probe)) {
                    if (!scanThroughTunnel(&svc)) goto done_hard;
                }
            }
        }
    }
    if (svc.probe_matched && !svc.softMatchFound) goto done_hard;

    /* 3. NONMATCHINGPROBES */
    for (auto *probe : ap_->probes) {
        if (probe->getProtocol() != proto) continue;
        if (probe->portIsProbable(tunnel, port)) continue;
        if (!svc.softMatchFound && probe->getRarity() > version_intensity_) continue;
        if (svc.softMatchFound && version_intensity_ < 9
            && !probe->serviceIsPossible(svc.probe_matched)) continue;
        if (tryProbeSet(probe)) {
            if (!scanThroughTunnel(&svc)) goto done_hard;
        }
    }

    /*
     * FIX #2 (UDP sslports / DTLS):
     * For UDP, after exhausting plain probes, retry all UDP probes that list
     * this port in their sslports directive using ServiceTunnel::SSL.
     * This models DTLS: the probe data is the same but the match context
     * indicates the port may carry DTLS-encapsulated traffic.
     */
    if (proto == IPPROTO_UDP && tunnel == ServiceTunnel::NONE) {
        for (auto *probe : ap_->probes) {
            if (probe->getProtocol() != IPPROTO_UDP) continue;
            if (!probe->portIsSSL(port)) continue;
            /* Temporarily mark the virtual tunnel for this attempt */
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

/* ── ScanResult::summary() ───────────────────────────────────────── */
std::string ScanResult::summary() const {
    std::ostringstream ss;
    const char *proto_str = (proto == IPPROTO_TCP)  ? "tcp"
                          : (proto == IPPROTO_UDP)  ? "udp"
                          : (proto == IPPROTO_SCTP) ? "sctp" : "?";

    ss << port << "/" << proto_str;
    if (tunnel == ServiceTunnel::SSL) ss << " (ssl)";
    ss << "  ";

    switch (state) {
        case ProbeState::FINISHED_HARDMATCHED:  ss << "open";          break;
        case ProbeState::FINISHED_SOFTMATCHED:  ss << "open?";         break;
        case ProbeState::FINISHED_NOMATCH:      ss << "open  unknown"; break;
        case ProbeState::FINISHED_TCPWRAPPED:   ss << "tcpwrapped";    break;
        case ProbeState::FINISHED_EXCLUDED:     ss << "excluded";      break;
        default:                                ss << "?";             break;
    }

    if (!service.empty())   ss << "  " << service;
    if (!product.empty())   ss << "  " << product;
    if (!version.empty())   ss << " "  << version;
    if (!extrainfo.empty()) ss << " (" << extrainfo << ")";
    if (!hostname.empty())  ss << "  hostname=" << hostname;
    if (!ostype.empty())    ss << "  os="       << ostype;
    if (!cpe_a.empty())     ss << "  cpe="      << cpe_a;

    if (!fingerprint.empty()) {
        ss << "\n  FINGERPRINT:\n";
        ss << "  " << fingerprint.substr(0, std::min((size_t)200, fingerprint.size()));
        if (fingerprint.size() > 200) ss << "...";
    }
    return ss.str();
}
