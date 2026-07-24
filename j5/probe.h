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

/* Maximum version-intensity that gates rarity checks */
static constexpr int MAX_VERSION_INTENSITY = 9;

/* Field size limits (mirrors service_scan.cc #defines) */
static constexpr int SERVICE_FIELD_LEN = 80;
static constexpr int SERVICE_EXTRA_LEN = 256;
static constexpr int SERVICE_TYPE_LEN  = 32;

/* Maximum response bytes we keep testing against regexes before moving on */
static constexpr int MAX_PROBE_RESPONSE_BYTES = 4096;

/*
 * FIX #3: bumped from 4096 to 16384 — long match/cpe lines in
 * nmap-service-probes easily exceed 4 KB and would be silently
 * truncated by fgets(), cutting the regex string in the middle
 * and causing pcre2_compile() to fail with a confusing error.
 */
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

    /*
     * Filled in by version templates.
     * FIX #8: These pointers point into per-instance buffers inside
     * ServiceProbeMatch, not into shared static arrays.  Multiple
     * ServiceProbeMatch objects (e.g. on different threads or in the same
     * loop) no longer clobber each other's results.
     */
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

    /*
     * Parse a full "match" or "softmatch" line.
     * Must be called before testMatch().
     * Throws std::runtime_error on syntax error.
     */
    void init(const char *matchtext, int lineno);

    /*
     * Test buf against this match's regex.
     * Returns a pointer to an internal MatchDetails (valid until next call
     * on THIS instance).
     * FIX #8: result is stored in per-instance buffers — no shared statics.
     * serviceName will be nullptr on a miss.
     */
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

    /* ── PCRE2 objects ── */
    pcre2_code          *regex_  = nullptr;
    pcre2_match_data    *mdata_  = nullptr;
    pcre2_match_context *mctx_   = nullptr;
    bool                 flag_i_ = false;
    bool                 flag_s_ = false;

    /* ── Version templates (owned strings) ── */
    char *tmpl_product_    = nullptr;
    char *tmpl_version_    = nullptr;
    char *tmpl_info_       = nullptr;
    char *tmpl_hostname_   = nullptr;
    char *tmpl_ostype_     = nullptr;
    char *tmpl_devicetype_ = nullptr;
    std::vector<char *> tmpl_cpe_;  /* multiple cpe:/ entries allowed */

    /*
     * FIX #8: per-instance output buffers instead of shared static storage.
     * Static storage caused every testMatch() call to overwrite the buffers
     * from previous calls, making it impossible to hold two MatchDetails
     * pointers at the same time.
     */
    MatchDetails md_return_;
    char i_product   [SERVICE_FIELD_LEN];
    char i_version   [SERVICE_FIELD_LEN];
    char i_info      [SERVICE_EXTRA_LEN];
    char i_hostname  [SERVICE_FIELD_LEN];
    char i_ostype    [SERVICE_TYPE_LEN];
    char i_devicetype[SERVICE_TYPE_LEN];
    char i_cpe_a     [SERVICE_FIELD_LEN];
    char i_cpe_h     [SERVICE_FIELD_LEN];
    char i_cpe_o     [SERVICE_FIELD_LEN];

    /* ── Internal helpers ── */

    /*
     * Reads one version-template token from *matchtext and advances it.
     *
     * FIX #1 (cpe:/ parser): the original code advanced `p` past the
     * mode letters, then for the "cpe:" case it incremented `q` past ':'
     * but left `p` pointing at the original mode string start. Fixed by
     * setting `p = q + 1` (char after the opening '/') before strndup.
     *
     * FIX #4 (flags parsing too strict): The original check required that
     * the character after the flags field be whitespace or NUL. This
     * rejected valid lines where version templates are separated by their
     * own delimiters (e.g. "p|product text|i|info text|") because the
     * character after the flags of one template is the next template's
     * mode letter or another non-space. Fixed by also accepting any
     * non-alpha character (a delimiter) as a valid flags terminator.
     * Additionally, the original code used strchr() to find the closing
     * delimiter which cannot skip over escaped delimiter sequences. Fixed
     * by scanning character-by-character and honouring backslash-escapes
     * (FIX #1a / FIX #4a).
     */
    bool nextTemplate(const char **matchtext,
                      char modestr[4], char **tmplt, char flags[4],
                      int lineno);

    int  fillVersionStr(const u8 *subject, size_t subjectlen);
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

    /* Port queries */
    bool portIsProbable(ServiceTunnel tunnel, u16 portno) const;

    /*
     * FIX #2b (UDP sslports): Returns true if portno is listed in the
     * sslports directive for this probe.  Used by matchResponse to attempt
     * DTLS-tunnel detection on UDP ports that the probe file marks as SSL.
     */
    bool portIsSSL(u16 portno) const;

    /* Service-possibility optimisation (post-softmatch filter) */
    bool serviceIsPossible(const char *sname) const;

    /*
     * Run all match lines against buf.
     * n=0 → return first match; n>0 → skip first n matches.
     * Returns nullptr if no matches at all in this probe.
     */
    const MatchDetails *testMatch(const u8 *buf, int buflen, int n = 0);

    /* Fallback chain (compiled by AllProbes::compileFallbacks) */
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

    /*
     * Compile fallback chains (called automatically by loadFromFile).
     * FIX #7 (circular fallback): detects A→B→A cycles and throws
     * std::runtime_error instead of looping forever.
     * FIX #3b (NULL probe fallback): ensures the NULL probe is appended
     * at the end of every TCP probe's fallback chain even when a fallback
     * directive is present, so banner-grab-only services are not missed.
     */
    void compileFallbacks();

    /* Lookup */
    ServiceProbe *getProbeByName(const char *name, int proto) const;
    bool          isExcluded(u16 port, int proto) const;

    std::vector<ServiceProbe *> probes;   /* all non-null probes */
    ServiceProbe               *nullProbe = nullptr;

    ExcludedPorts excludedPorts;
    bool          excluded_seen = false;
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

    /*
     * FIX #7b: When scanThroughTunnel() strips the "ssl/" prefix from
     * probe_matched it must not do pointer arithmetic on the pool-owned
     * string (which makes the pointer un-freeable).  We keep a small
     * per-instance buffer for the stripped copy so probe_matched can
     * safely point into it.
     */
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
    explicit ProbeEngine(AllProbes *ap, int version_intensity = 7);

    /*
     * Feed a raw response buffer for a given port + protocol.
     * Returns true  → hard match found (or SSL upgrade needed).
     * Returns false → keep reading / move to next probe.
     */
    bool feedResponse(ServiceNFO *svc, const u8 *data, int datalen);

    /*
     * Called when the connection closed without data (EOF/reset).
     * Returns true if the service is done.
     */
    bool handleEOF(ServiceNFO *svc, bool hadData, long elapsedMs);

    /* Returns true if there are more probes to try. */
    bool hasMoreProbes(ServiceNFO *svc) const;

    /* Build the final ScanResult from a finished ServiceNFO. */
    ScanResult buildResult(ServiceNFO *svc) const;

    /*
     * Offline / testing path: given a response blob for a
     * (port, proto, tunnel) combination, run the complete match logic
     * and return a ScanResult without any networking.
     */
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

/* ── Free helpers ── */
void parse_nmap_service_probe_file(AllProbes *AP, const char *filename);

int run_version_probe(AllProbes &probes, const std::string &target_ip,
                       int target_port, bool verbose = false);
