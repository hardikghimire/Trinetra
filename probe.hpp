#pragma once

#include <netinet/in.h>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <atomic>

/* ── PCRE2 ── */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

/* ── Compat typedefs (mirrors Nmap's nbase types) ── */
using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

/* ── Tuneable limits (every constant here is referenced) ── */
static constexpr int DEFAULT_SERVICEWAITMS  = 5000;   // default per-probe totalwaitms
static constexpr int DEFAULT_TCPWRAPPEDMS   = 3000;   // default tcpwrappedms (nmap default)
static constexpr int MAXFALLBACKS           = 20;
static constexpr int MAX_VERSION_INTENSITY  = 9;
static constexpr int SERVICE_FIELD_LEN      = 80;
static constexpr int SERVICE_EXTRA_LEN      = 256;
static constexpr int SERVICE_TYPE_LEN       = 32;

/* ── Tunnel type ── */
enum class ServiceTunnel : uint8_t {
    NONE = 0,
    SSL  = 1,
};

/* ── Final state of a match run. matchResponse() is a one-shot matcher, so only
 *    terminal states exist (there is no incremental probe state machine). ── */
enum class ProbeState : uint8_t {
    FINISHED_HARDMATCHED,
    FINISHED_SOFTMATCHED,
    FINISHED_NOMATCH,
    FINISHED_EXCLUDED,
    FINISHED_TCPWRAPPED,   // peer closed the connection immediately without sending anything
};

/* ── Result of a single regex match attempt ── */
struct MatchDetails {
    bool        isSoft      = false;
    const char *serviceName = nullptr;   /* owned by the ServiceProbeMatch */
    const char *product    = nullptr;
    const char *version    = nullptr;
    const char *info       = nullptr;
    const char *hostname   = nullptr;
    const char *ostype     = nullptr;
    const char *devicetype = nullptr;
    const char *cpe_a      = nullptr;
    const char *cpe_o      = nullptr;
    const char *cpe_h      = nullptr;
};

/* ── Excluded port list ── */
struct ExcludedPorts {
    std::vector<u16> tcp_ports;
    std::vector<u16> udp_ports;
    std::vector<u16> sctp_ports;

    bool contains(u16 port, int proto) const;
    /* Parse "T:9100-9107,U:161,T:80,443" style specs. A T:/U:/S: prefix applies to
     * every following item until the next prefix; items without any prefix apply
     * to all protocols. */
    void parse(const std::string &spec);
};

/* ════════════════════════════════════════════════════════
   ServiceProbeMatch — one match/softmatch line
   ════════════════════════════════════════════════════════ */
class ServiceProbeMatch {
public:
    ServiceProbeMatch();
    ~ServiceProbeMatch();
    ServiceProbeMatch(const ServiceProbeMatch &) = delete;
    ServiceProbeMatch &operator=(const ServiceProbeMatch &) = delete;

    void init(const char *matchtext, int lineno);

    /* Thread-safe. The returned pointer (and every string inside it) lives in
     * per-thread scratch memory: it is valid only until the next testMatch() call
     * on the SAME thread, so consume or copy it immediately. */
    const MatchDetails *testMatch(const u8 *buf, int buflen);

    const char *getName() const { return servicename_; }
    bool        isSoft()  const { return isSoft_; }

private:
    /* ── identity ── */
    int         deflineno_   = -1;
    bool        initialized_ = false;
    char       *servicename_ = nullptr;   /* owned (malloc) */
    char       *matchstr_    = nullptr;   /* raw regex text, owned */
    bool        isSoft_      = false;
    std::string prefix_literal_;
    bool        has_prefix_filter_ = false;

    /* ── PCRE2 objects ── */
    pcre2_code          *regex_  = nullptr;      /* interpreter copy; never JIT-compiled */
    bool                 flag_i_ = false;
    bool                 flag_s_ = false;
    std::atomic<bool>    compiled_       {false};
    std::atomic<bool>    compile_failed_ {false};
    std::mutex           compile_mu_;
    bool ensureCompiled();                       /* false => regex is invalid, never matches */

    /* PCRE2 forbids JIT-compiling a pattern that other threads may be matching
     * with, so the JIT version is a SEPARATE compiled copy that is published
     * atomically once ready. Threads use whichever copy they load; the
     * interpreter copy always stays valid. */
    std::atomic<pcre2_code *> jit_regex_     {nullptr};
    std::atomic<bool>         jit_attempted_ {false};
    std::atomic<int>          hit_count_     {0};
    std::mutex                jit_compile_mu_;
    void maybeJitCompile();

    /* One scratch area PER THREAD (shared by all templates), so memory does not
     * grow with probe-file size and nothing mutable is shared between threads. */
    struct MatchScratch {
        pcre2_match_data    *mdata     = nullptr;
        pcre2_match_context *mctx      = nullptr;
        pcre2_jit_stack     *jit_stack = nullptr;
        MatchDetails md_return_{};
        char i_product   [SERVICE_FIELD_LEN]   = {};
        char i_version   [SERVICE_FIELD_LEN]   = {};
        char i_info      [SERVICE_EXTRA_LEN]   = {};
        char i_hostname  [SERVICE_FIELD_LEN]   = {};
        char i_ostype    [SERVICE_TYPE_LEN]    = {};
        char i_devicetype[SERVICE_TYPE_LEN]    = {};
        char i_cpe_a     [SERVICE_FIELD_LEN]   = {};
        char i_cpe_h     [SERVICE_FIELD_LEN]   = {};
        char i_cpe_o     [SERVICE_FIELD_LEN]   = {};
        ~MatchScratch();
    };
    static MatchScratch &getScratch();

    /* ── Version templates (owned strings) ── */
    char *tmpl_product_    = nullptr;
    char *tmpl_version_    = nullptr;
    char *tmpl_info_       = nullptr;
    char *tmpl_hostname_   = nullptr;
    char *tmpl_ostype_     = nullptr;
    char *tmpl_devicetype_ = nullptr;
    std::vector<char *> tmpl_cpe_;

    bool nextTemplate(const char **matchtext,
                      char modestr[4], char **tmplt, char flags[4],
                      int lineno);

    int  fillVersionStr(const u8 *subject, size_t subjectlen, MatchScratch &scratch);
    int  doTmplSubst(const u8 *subject, size_t subjectlen,
                     pcre2_match_data *md,
                     const char *tmpl, char *out, int outlen,
                     char *(*transform)(const char *) = nullptr);

    static char *substVar(const char *tmplvar, const char **tmplvarend,
                          const u8 *subject, size_t subjectlen,
                          pcre2_match_data *md);
    static char *transformCPE(const char *s);
};

/* ════════════════════════════════════════════════════════
   ServiceProbe — one Probe block in nmap-service-probes
   ════════════════════════════════════════════════════════ */
class ServiceProbe {
public:
    ServiceProbe();
    ~ServiceProbe();
    ServiceProbe(const ServiceProbe &) = delete;
    ServiceProbe &operator=(const ServiceProbe &) = delete;

    /* Accessors */
    const char *getName()         const { return probename_; }
    int         getProtocol()     const { return probeprotocol_; }
    bool        isNullProbe()     const { return probestringlen_ == 0; }
    int         getRarity()       const { return rarity_; }
    int         getTotalWaitMs()  const { return totalwaitms_; }
    void        setTotalWaitMs(int ms)  { totalwaitms_ = ms; }
    int         getTcpWrappedMs() const { return tcpwrappedms_; }
    void        setTcpWrappedMs(int ms) { tcpwrappedms_ = ms; }

    const u8 *getProbeString(int *len) const {
        *len = probestringlen_;
        return probestring_;
    }

    /* Parsing (called from file parser) */
    void setProbeDetails(char *pd, int lineno);
    void setProbeString(const u8 *ps, int len);
    void setProbablePorts(ServiceTunnel tunnel, const char *portstr, int lineno);
    void setRarity(const char *val, int lineno);
    void addMatch(const char *matchline, int lineno);
    bool portIsProbable(ServiceTunnel tunnel, u16 portno) const;
    bool portIsSSL(u16 portno) const;
    bool serviceIsPossible(const char *sname) const;
    /* Returns the first matching template, or nullptr. Same lifetime rule as
     * ServiceProbeMatch::testMatch(). */
    const MatchDetails *testMatch(const u8 *buf, int buflen);

    char          *fallbackStr                  = nullptr;
    ServiceProbe  *fallbacks[MAXFALLBACKS + 1]  = {};

    std::vector<u16>::const_iterator probablePortsBegin()    const { return probableports_.begin(); }
    std::vector<u16>::const_iterator probablePortsEnd()      const { return probableports_.end();   }
    std::vector<u16>::const_iterator probableSslPortsBegin() const { return probablesslports_.begin(); }
    std::vector<u16>::const_iterator probableSslPortsEnd()   const { return probablesslports_.end();   }

private:
    char       *probename_       = nullptr;
    u8         *probestring_     = nullptr;
    int         probestringlen_  = 0;
    int         probeprotocol_   = -1;
    int         rarity_          = 5;
    int         totalwaitms_     = DEFAULT_SERVICEWAITMS;
    int         tcpwrappedms_    = DEFAULT_TCPWRAPPEDMS;

    std::vector<u16> probableports_;     /* plain TCP/UDP ports */
    std::vector<u16> probablesslports_;  /* SSL-wrapped ports   */

    std::vector<const char *>        detectedServices_;
    std::vector<ServiceProbeMatch *> matches_;

    void setPortVector(std::vector<u16> *portv, const char *portstr, int lineno);
};

/* ════════════════════════════════════════════════════════
   AllProbes — the global probe database
   ════════════════════════════════════════════════════════ */
class AllProbes {
public:
    AllProbes();
    ~AllProbes();
    AllProbes(const AllProbes &) = delete;
    AllProbes &operator=(const AllProbes &) = delete;

    /* Load and parse nmap-service-probes file (throws std::runtime_error) */
    void loadFromFile(const char *filename);
    void compileFallbacks();

    ServiceProbe *getProbeByName(const char *name, int proto) const;
    bool          isExcluded(u16 port, int proto) const;

    /* Probes that list `port` for this proto/tunnel, in probe-file order. Never null. */
    const std::vector<ServiceProbe *> &probesForPort(int proto, ServiceTunnel tunnel, u16 port) const;

    std::vector<ServiceProbe *> probes;   /* all non-null probes */
    ServiceProbe               *nullProbe = nullptr;
    ExcludedPorts excludedPorts;
    bool          excluded_seen = false;

private:
    /* plain-port index and ssl-port index are separate: a probe listed only under
     * sslports must be found for tunnel==SSL and only then. */
    std::unordered_map<uint32_t, std::vector<ServiceProbe *>> portIndex_;
    void buildPortIndex();
    static uint32_t portIndexKey(int proto, ServiceTunnel tunnel, u16 port) {
        return (static_cast<uint32_t>(proto) << 17) |
               (static_cast<uint32_t>(tunnel == ServiceTunnel::SSL ? 1 : 0) << 16) | port;
    }
};

/* ════════════════════════════════════════════════════════
   ServiceNFO — result accumulator for one port under match
   ════════════════════════════════════════════════════════ */
class ServiceNFO {
public:
    ServiceNFO() = default;
    ~ServiceNFO();
    ServiceNFO(const ServiceNFO &) = delete;
    ServiceNFO &operator=(const ServiceNFO &) = delete;

    u16  portno = 0;
    int  proto  = IPPROTO_TCP;
    int  version_intensity = 7;   /* recorded in the fingerprint header only */

    ServiceTunnel tunnel = ServiceTunnel::NONE;

    const char *probe_matched  = nullptr;  /* service name, or nullptr */
    bool        softMatchFound = false;

    char product_matched   [SERVICE_FIELD_LEN] = {};
    char version_matched   [SERVICE_FIELD_LEN] = {};
    char extrainfo_matched [SERVICE_EXTRA_LEN] = {};
    char hostname_matched  [SERVICE_FIELD_LEN] = {};
    char ostype_matched    [SERVICE_TYPE_LEN]  = {};
    char devicetype_matched[SERVICE_TYPE_LEN]  = {};
    char cpe_a_matched     [SERVICE_FIELD_LEN] = {};
    char cpe_h_matched     [SERVICE_FIELD_LEN] = {};
    char cpe_o_matched     [SERVICE_FIELD_LEN] = {};
    char probe_matched_stripped[SERVICE_FIELD_LEN] = {};

    ProbeState probe_state = ProbeState::FINISHED_NOMATCH;

    void clearMatchFields();
    void resetFingerprint();

    /* Service fingerprint (unmatched services) */
    void        addToFingerprint(const char *probeName, const u8 *resp, int resplen);
    const char *getFingerprint(int *flen = nullptr);

private:
    char *servicefp_      = nullptr;
    int   servicefplen_   = 0;
    int   servicefpalloc_ = 0;

    void addFpChar(char c, int wrapat);
    void addFpString(const char *s, int wrapat);
};

/* ════════════════════════════════════════════════════════
   ScanResult — what we know after running all probes
   ════════════════════════════════════════════════════════ */
struct ScanResult {
    u16           port       = 0;
    int           proto      = IPPROTO_TCP;
    ProbeState    state      = ProbeState::FINISHED_NOMATCH;
    ServiceTunnel tunnel     = ServiceTunnel::NONE;
    std::string   service;
    std::string   product;
    std::string   version;
    std::string   extrainfo;
    std::string   hostname;
    std::string   ostype;
    std::string   devicetype;
    std::string   cpe_a, cpe_h, cpe_o;
    std::string   fingerprint;
};

/* ════════════════════════════════════════════════════════
   ProbeEngine — matches one captured response against the probe database
   ════════════════════════════════════════════════════════ */
/* Optional facts about how the response was captured. */
struct MatchContext {
    const char *probe_name = nullptr;          /* probe whose payload produced the response (tried first) */
    bool        closed_without_data = false;   /* peer closed (EOF) and sent nothing */
    long        elapsed_ms = -1;               /* connect-to-close time of that attempt; -1 = unknown */
};

class ProbeEngine {
public:
    explicit ProbeEngine(AllProbes *ap, int version_intensity = 4);

    ScanResult matchResponse(u16 port, int proto, ServiceTunnel tunnel,
                             const u8 *data, int datalen,
                             const MatchContext &ctx = MatchContext{});

    void setIgnoreExclude(bool v) { ignore_exclude_ = v; }

private:
    AllProbes *ap_;
    int        version_intensity_;
    bool       ignore_exclude_ = false;

    ScanResult buildResult(ServiceNFO *svc) const;
    bool processMatch(const MatchDetails *md, ServiceNFO *svc);
    bool scanThroughTunnel(ServiceNFO *svc);
};

struct VersionDetectOptions {
    int         timeout_sec         = 3;    // read/response timeout
    int         connect_timeout_sec = 0;    // 0 = same as timeout_sec
    int         intensity           = 4;    // 1-9
    bool        udp                 = false;
    bool        force_raw           = false;
    bool        force_http          = false;
    bool        force_https         = false;
    bool        tls_verify          = false;
    bool        verbose             = false;
    std::string save_file;
    std::string tls_ca_file;
    std::string tls_ca_path;
    std::string tls_cert;
    std::string tls_key;
    std::string tls_sni;
    std::string host_override;      // --sv-host: force the Host:/SNI value
    std::string request_path = "/"; // path used by --http/--https and the fallback chain

    // Reactor tuning (0 / empty = built-in defaults)
    size_t      max_response_bytes  = 0;    // per-capture cap
    std::string tls_ciphers_tls12;
    std::string tls_ciphersuites_tls13;
    int         min_connect_ms      = 0;    // floor of the adaptive connect timeout
    unsigned    reactor_threads     = 0;    // only effective before the first scan
};

/* ── Free helpers ── */
void parse_nmap_service_probe_file(AllProbes *AP, const char *filename);

int run_version_probe(AllProbes &probes, const std::string &target_ip,
                       uint16_t target_port,
                       const VersionDetectOptions &opts = VersionDetectOptions{});
