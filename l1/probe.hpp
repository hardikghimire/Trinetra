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

/* ── Tuneable limits ── */
static constexpr int DEFAULT_SERVICEWAITMS       = 5000;
static constexpr int DEFAULT_TCPWRAPPEDMS        = 2000;
static constexpr int DEFAULT_CONNECT_TIMEOUT     = 5000;
static constexpr int DEFAULT_CONNECT_SSL_TIMEOUT = 8000;
static constexpr int MAXFALLBACKS                = 20;
static constexpr int MAX_VERSION_INTENSITY = 9;
static constexpr int SERVICE_FIELD_LEN = 80;
static constexpr int SERVICE_EXTRA_LEN = 256;
static constexpr int SERVICE_TYPE_LEN  = 32;
static constexpr int MAX_PROBE_RESPONSE_BYTES = 4096;
static constexpr int PROBE_LINE_BUF = 16384;

/* ── Tunnel type ── */
enum class ServiceTunnel : uint8_t {
    NONE = 0,
    SSL  = 1,
};

/* ── Probe-state machine ── */
enum class ProbeState : uint8_t {
    INITIAL,
    NULLPROBE,
    MATCHINGPROBES,
    NONMATCHINGPROBES,
    FINISHED_HARDMATCHED,
    FINISHED_SOFTMATCHED,
    FINISHED_NOMATCH,
    FINISHED_TCPWRAPPED,
    FINISHED_EXCLUDED,
    INCOMPLETE,
};

/* ── Result of a single regex match attempt ── */
struct MatchDetails {
    bool        isSoft      = false;
    const char *serviceName = nullptr;  /* charpool lifetime */
    int         lineno      = -1;
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
    /* Parse "T:9100-9107,U:161" style spec */
    void parse(const std::string &spec);
};

/* ════════════════════════════════════════════════════════
   ServiceProbeMatch — one match/softmatch line
   ════════════════════════════════════════════════════════ */
class ServiceProbeMatch {
public:
    ServiceProbeMatch();
    ~ServiceProbeMatch();
    void init(const char *matchtext, int lineno);
    const MatchDetails *testMatch(const u8 *buf, int buflen);

    const char *getName()   const { return servicename_; }
    int         getLineNo() const { return deflineno_; }
    bool        isSoft()    const { return isSoft_; }

private:
    /* ── identity ── */
    int         deflineno_   = -1;
    bool        initialized_ = false;
    const char *servicename_ = nullptr;   /* owned by string pool */
    char       *matchstr_    = nullptr;   /* raw regex text, owned */
    bool        isSoft_      = false;
    std::string prefix_literal_;
    bool        has_prefix_filter_ = false;

    /* ── PCRE2 objects ── */
    pcre2_code          *regex_  = nullptr;
    bool                 flag_i_ = false;
    bool                 flag_s_ = false;
    std::atomic<bool> compiled_ {false};
    std::mutex        compile_mu_;
    void ensureCompiled();                    /* defined in probe.cpp, called from testMatch() */

    bool              jit_ready_     = false;
    std::atomic<bool> jit_attempted_ {false}; /* fast, lock-free "already decided" check */
    std::atomic<int>  hit_count_     {0};     /* how many times this match has been tested */
    std::mutex        jit_compile_mu_;        /* only ever taken on the rare compile path */
    void ensureJitCompiled();                 /* defined in probe.cpp, called from testMatch() */
    struct MatchScratch {
        pcre2_match_data    *mdata        = nullptr;
        pcre2_match_context *mctx         = nullptr;
        pcre2_jit_stack     *jit_stack    = nullptr;
        bool                  jit_attached = false;
        /* CONCURRENCY FIX: these used to be per-instance members on
         * ServiceProbeMatch, which is shared across all worker threads via
         * ServiceProbe::matches_. Two threads calling testMatch() on the same
         * match template at the same time would race on this state and could
         * silently return a corrupted MatchDetails. They now live inside
         * MatchScratch, which getScratch() keys per-thread (thread_local
         * scratch_map keyed by `this`), so each thread gets its own copy and
         * there is no shared mutable state left in the hot match path. */
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
    MatchScratch &getScratch();             

    /* ── Version templates (owned strings) ── */
    char *tmpl_product_    = nullptr;
    char *tmpl_version_    = nullptr;
    char *tmpl_info_       = nullptr;
    char *tmpl_hostname_   = nullptr;
    char *tmpl_ostype_     = nullptr;
    char *tmpl_devicetype_ = nullptr;
    std::vector<char *> tmpl_cpe_;  /* multiple cpe:/ entries allowed */

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

    /* Accessors */
    const char *getName()         const { return probename_; }
    int         getProtocol()     const { return probeprotocol_; }
    bool        isNullProbe()     const { return probestringlen_ == 0; }
    int         getRarity()       const { return rarity_; }
    int         getTotalWaitMs()  const { return totalwaitms_; }
    int         getTcpWrappedMs() const { return tcpwrappedms_; }
    bool        isNotForPayload() const { return notForPayload_; }
    void setTotalWaitMs(int ms)  { totalwaitms_ = ms; }
    void setTcpWrappedMs(int ms) { tcpwrappedms_ = ms; }

    const u8 *getProbeString(int *len) const {
        *len = probestringlen_;
        return probestring_;
    }

    /* Parsing (called from file parser) */
    void setProbeDetails(char *pd, int lineno);
    void setProbeString(const u8 *ps, int len);
    void setProbeProtocol(int proto)  { probeprotocol_ = proto; }
    void setProbablePorts(ServiceTunnel tunnel, const char *portstr, int lineno);
    void setRarity(const char *val, int lineno);
    void addMatch(const char *matchline, int lineno);
    bool portIsProbable(ServiceTunnel tunnel, u16 portno) const;
    bool portIsSSL(u16 portno) const;
    bool serviceIsPossible(const char *sname) const;
    const MatchDetails *testMatch(const u8 *buf, int buflen, int n = 0);
    char          *fallbackStr                  = nullptr;
    ServiceProbe  *fallbacks[MAXFALLBACKS + 1]  = {};

    std::vector<u16>::const_iterator probablePortsBegin() const { return probableports_.begin(); }
    std::vector<u16>::const_iterator probablePortsEnd()   const { return probableports_.end();   }

private:
    const char *probename_       = nullptr;
    const u8   *probestring_     = nullptr;
    int         probestringlen_  = 0;
    int         probeprotocol_   = -1;
    int         rarity_          = 5;
    int         totalwaitms_     = DEFAULT_SERVICEWAITMS;
    int         tcpwrappedms_    = DEFAULT_TCPWRAPPEDMS;
    bool        notForPayload_   = false;

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

    /* Load and parse nmap-service-probes file */
    void loadFromFile(const char *filename);
    void compileFallbacks();

    /* Lookup */
    ServiceProbe *getProbeByName(const char *name, int proto) const;
    bool          isExcluded(u16 port, int proto) const;
    std::vector<ServiceProbe *> probes;   /* all non-null probes */
    ServiceProbe               *nullProbe = nullptr;
    ExcludedPorts excludedPorts;
    bool          excluded_seen = false;

    std::unordered_map<uint32_t, std::vector<ServiceProbe*>> portIndex_;
    void buildPortIndex();
    static uint32_t portIndexKey(int proto, u16 port) {
        return (static_cast<uint32_t>(proto) << 16) | port;
    }
};

/* ════════════════════════════════════════════════════════
   ServiceNFO — state for one open port under scan
   ════════════════════════════════════════════════════════ */
class ServiceNFO {
public:
    explicit ServiceNFO(AllProbes *ap);
    ~ServiceNFO();

    /* ── Identity ── */
    u16  portno = 0;
    int  proto  = IPPROTO_TCP;   /* IPPROTO_TCP / UDP / SCTP */

    /* ── Tunnel / SSL ── */
    ServiceTunnel tunnel           = ServiceTunnel::NONE;
    bool          tcpwrap_possible = true;

    /* ── Match results ── */
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

    /* ── Probe machine ── */
    ProbeState probe_state = ProbeState::INITIAL;

    ServiceProbe *currentProbe();
    ServiceProbe *nextProbe(bool newresp);
    void          resetProbes(bool freeFP);

    /* ── Response accumulator ── */
    void appendResponse(const u8 *data, int len);
    u8  *getResponse(int *lenout);
    void clearResponse();

    /* ── Service fingerprint (unmatched services) ── */
    void        addToFingerprint(const char *probeName, const u8 *resp, int resplen);
    const char *getFingerprint(int *flen = nullptr);

    AllProbes *AP = nullptr;

private:
    std::vector<ServiceProbe *>::iterator current_probe_;

    u8   *currentresp_    = nullptr;
    int   currentresplen_ = 0;

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

    std::string summary() const;
};

/* ════════════════════════════════════════════════════════
   ProbeEngine — ties everything together without sockets
   ════════════════════════════════════════════════════════ */
class ProbeEngine {
public:
    explicit ProbeEngine(AllProbes *ap, int version_intensity = 0);
    bool feedResponse(ServiceNFO *svc, const u8 *data, int datalen);
    bool handleEOF(ServiceNFO *svc, bool hadData, long elapsedMs);

    /* Returns true if there are more probes to try. */
    bool hasMoreProbes(ServiceNFO *svc) const;

    /* Build the final ScanResult from a finished ServiceNFO. */
    ScanResult buildResult(ServiceNFO *svc) const;
    ScanResult matchResponse(u16 port, int proto, ServiceTunnel tunnel,
                             const u8 *data, int datalen,
                             const std::string &probeName = "");

    int versionIntensity() const { return version_intensity_; }

private:
    AllProbes *ap_;
    int        version_intensity_;

    bool processMatch(const MatchDetails *md, ServiceNFO *svc,
                      const char *probeName, const char *fallbackName);
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
};

/* ── Free helpers ── */
void parse_nmap_service_probe_file(AllProbes *AP, const char *filename);

int run_version_probe(AllProbes &probes, const std::string &target_ip,
                       uint16_t target_port,
                       const VersionDetectOptions &opts = VersionDetectOptions{});
