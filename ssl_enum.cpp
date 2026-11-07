#include "ssl_enum.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <optional>
#include <unordered_map>
#include <array>

#include <nlohmann/json.hpp>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/ct.h>

using json = nlohmann::json;

// ---------------------------------------------------------------------
// Console palette -- same codes as dns_enum.cpp / main.cpp so report
// output looks consistent across enumeration modules.
// ---------------------------------------------------------------------
namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string green   = "\033[32m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string white   = "\033[97m";
    const std::string red     = "\033[91m";
    const std::string dim     = "\033[2m";
    const std::string cyan    = "\033[36m";
}

namespace {

// -----------------------------------------------------------------
// RAII wrappers around OpenSSL's ref-counted C objects. Every X509*,
// SSL*, SSL_CTX* handed back by a "get" function is owned by us and
// must be freed exactly once on every exit path, including timeouts
// and error branches -- wrapping in unique_ptr makes that a
// compile-time property instead of something to re-audit by hand
// every time this file is touched.
// -----------------------------------------------------------------
struct X509Deleter     { void operator()(X509* p)      const { X509_free(p); } };
struct SSLCtxDeleter   { void operator()(SSL_CTX* p)    const { SSL_CTX_free(p); } };
struct SSLDeleter      { void operator()(SSL* p)        const { SSL_free(p); } };
struct BIODeleter      { void operator()(BIO* p)        const { BIO_free(p); } };
struct GenNamesDeleter { void operator()(GENERAL_NAMES* p) const { GENERAL_NAMES_free(p); } };

using X509Ptr    = std::unique_ptr<X509, X509Deleter>;
using SSLCtxPtr  = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;
using SSLPtr     = std::unique_ptr<SSL, SSLDeleter>;
using BIOPtr     = std::unique_ptr<BIO, BIODeleter>;
using GenNamesPtr= std::unique_ptr<GENERAL_NAMES, GenNamesDeleter>;

// Safety caps on server-controlled string/list fields. A malicious or
// misbehaving server can put almost anything in a certificate; these
// bounds keep a single hostile handshake from blowing up memory/log
// output rather than trusting X.509 field sizes to be well-behaved.
constexpr size_t kMaxFieldLen   = 1024;
constexpr size_t kMaxSanEntries = 200;

std::string clamp_len(std::string s) {
    if (s.size() > kMaxFieldLen) { s.resize(kMaxFieldLen); s += "...(truncated)"; }
    return s;
}

// Strips control characters before anything server-supplied hits the
// terminal or a JSON string -- same policy main.cpp/dns_enum.cpp apply
// to untrusted text.
std::string sanitize_echo(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) out.push_back((c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c));
    return out;
}

bool icontains(const std::string& hay, const char* needle) {
    return std::search(hay.begin(), hay.end(), needle, needle + std::strlen(needle),
                        [](char a, char b) {
                            return std::tolower(static_cast<unsigned char>(a)) ==
                                   std::tolower(static_cast<unsigned char>(b));
                        }) != hay.end();
}

// ---------------------------------------------------------------------
// Small ASN.1 -> std::string helpers (structured accessors, not text
// scraping of `openssl x509` output).
// ---------------------------------------------------------------------

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    return (len > 0 && data) ? std::string(data, static_cast<size_t>(len)) : std::string();
}

std::string name_to_string(X509_NAME* name) {
    if (!name) return {};
    BIOPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) return {};
    X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253);
    return clamp_len(bio_to_string(bio.get()));
}

std::string asn1_time_to_string(const ASN1_TIME* t) {
    if (!t) return {};
    BIOPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) return {};
    ASN1_TIME_print(bio.get(), t);
    return bio_to_string(bio.get());
}

std::string bignum_hex(const ASN1_INTEGER* serial) {
    if (!serial) return {};
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) return {};
    char* hex = BN_bn2hex(bn);
    std::string s = hex ? hex : "";
    OPENSSL_free(hex);
    BN_free(bn);
    return s;
}

std::string hex_digest(const unsigned char* data, unsigned len) {
    static const char* hexd = "0123456789ABCDEF";
    std::string out;
    out.reserve(static_cast<size_t>(len) * 3);
    for (unsigned i = 0; i < len; ++i) {
        if (i) out.push_back(':');
        out.push_back(hexd[data[i] >> 4]);
        out.push_back(hexd[data[i] & 0xF]);
    }
    return out;
}

// ---------------------------------------------------------------------
// Certificate field extraction.
// ---------------------------------------------------------------------

CertIdentity extract_identity(X509* cert) {
    CertIdentity id;
    id.subject    = name_to_string(X509_get_subject_name(cert));
    id.issuer     = name_to_string(X509_get_issuer_name(cert));
    id.serial_hex = bignum_hex(X509_get_serialNumber(cert));
    id.not_before = asn1_time_to_string(X509_get0_notBefore(cert));
    id.not_after  = asn1_time_to_string(X509_get0_notAfter(cert));

    const X509_ALGOR* sig_alg = nullptr;
    X509_get0_signature(nullptr, &sig_alg, cert);
    if (sig_alg) {
        int nid = OBJ_obj2nid(sig_alg->algorithm);
        const char* ln = OBJ_nid2ln(nid);
        id.sig_alg = ln ? ln : "unknown";
    }
    return id;
}

PubKeyInfo extract_pubkey_info(X509* cert) {
    PubKeyInfo out;
    EVP_PKEY* pkey_raw = X509_get_pubkey(cert); // up-refs; we own this copy
    if (!pkey_raw) return out;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_raw, EVP_PKEY_free);

    int id = EVP_PKEY_id(pkey.get());
    const char* ln = OBJ_nid2ln(id);
    out.algorithm = ln ? ln : "unknown";
    out.bits = EVP_PKEY_bits(pkey.get());

    unsigned char* der = nullptr;
    int der_len = i2d_PUBKEY(pkey.get(), &der); // SubjectPublicKeyInfo DER
    if (der_len > 0 && der) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (mctx) {
            EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mctx, der, static_cast<size_t>(der_len));
            EVP_DigestFinal_ex(mctx, digest, &digest_len);
            EVP_MD_CTX_free(mctx);
            out.spki_sha256 = hex_digest(digest, digest_len);
        }
    }
    OPENSSL_free(der);
    return out;
}

std::string cert_fingerprint(X509* cert, const EVP_MD* md) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!X509_digest(cert, md, digest, &digest_len)) return {};
    return hex_digest(digest, digest_len);
}

std::vector<std::string> extract_dns_sans(X509* cert) {
    std::vector<std::string> names;
    GenNamesPtr gens(static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)));
    if (!gens) return names;

    int count = sk_GENERAL_NAME_num(gens.get());
    for (int i = 0; i < count && names.size() < kMaxSanEntries; ++i) {
        const GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens.get(), i);
        if (gen->type != GEN_DNS) continue;
        ASN1_IA5STRING* dns = gen->d.dNSName;
        names.push_back(clamp_len(std::string(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(dns)),
            static_cast<size_t>(ASN1_STRING_length(dns)))));
    }
    return names;
}

KeyUsageInfo extract_key_usage(X509* cert) {
    KeyUsageInfo k;
    uint32_t ku = X509_get_key_usage(cert); // UINT32_MAX if the extension is absent
    if (ku != static_cast<uint32_t>(-1)) {
        k.present             = true;
        k.digital_signature   = (ku & KU_DIGITAL_SIGNATURE) != 0;
        k.key_encipherment    = (ku & KU_KEY_ENCIPHERMENT)  != 0;
        k.key_cert_sign       = (ku & KU_KEY_CERT_SIGN)     != 0;
        k.non_repudiation     = (ku & KU_NON_REPUDIATION)   != 0;
        k.key_agreement       = (ku & KU_KEY_AGREEMENT)     != 0;
        k.crl_sign            = (ku & KU_CRL_SIGN)          != 0;
    }
    return k;
}

std::vector<std::string> extract_eku(X509* cert) {
    std::vector<std::string> out;
    int idx = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    if (idx < 0) return out;
    X509_EXTENSION* ext = X509_get_ext(cert, idx);
    if (!ext) return out;
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(X509V3_EXT_d2i(ext));
    if (!eku) return out;
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
        const char* ln = OBJ_nid2ln(OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)));
        out.push_back(ln ? ln : "unknown");
    }
    EXTENDED_KEY_USAGE_free(eku);
    return out;
}

BasicConstraintsInfo extract_basic_constraints(X509* cert) {
    BasicConstraintsInfo b;
    BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
    if (bc) {
        b.present = true;
        b.is_ca = (bc->ca != 0);
        b.pathlen = bc->pathlen ? static_cast<int>(ASN1_INTEGER_get(bc->pathlen)) : -1;
        BASIC_CONSTRAINTS_free(bc);
    }
    return b;
}

std::vector<SctInfo> extract_scts(X509* cert) {
    std::vector<SctInfo> out;
    STACK_OF(SCT)* scts = static_cast<STACK_OF(SCT)*>(
        X509_get_ext_d2i(cert, NID_ct_precert_scts, nullptr, nullptr));
    if (!scts) return out;
    int n = sk_SCT_num(scts);
    for (int i = 0; i < n; ++i) {
        SCT* sct = sk_SCT_value(scts, i);
        unsigned char* log_id = nullptr;
        size_t log_id_len = SCT_get0_log_id(sct, &log_id);
        SctInfo s;
        s.log_id_hex = hex_digest(log_id, static_cast<unsigned>(log_id_len));
        s.timestamp_ms = SCT_get_timestamp(sct);
        out.push_back(std::move(s));
    }
    SCT_LIST_free(scts);
    return out;
}

AiaCrlInfo extract_aia_crl(X509* cert) {
    AiaCrlInfo out;
    AUTHORITY_INFO_ACCESS* aia = static_cast<AUTHORITY_INFO_ACCESS*>(
        X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr));
    if (aia) {
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); ++i) {
            ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
            if (!ad || !ad->location || ad->location->type != GEN_URI) continue;
            ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
            std::string url = clamp_len(std::string(
                reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                static_cast<size_t>(ASN1_STRING_length(uri))));
            int nid = OBJ_obj2nid(ad->method);
            if (nid == NID_ad_OCSP) out.ocsp_urls.push_back(std::move(url));
            else if (nid == NID_ad_ca_issuers) out.ca_issuer_urls.push_back(std::move(url));
        }
        AUTHORITY_INFO_ACCESS_free(aia);
    }

    STACK_OF(DIST_POINT)* crldp = static_cast<STACK_OF(DIST_POINT)*>(
        X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr));
    if (crldp) {
        for (int i = 0; i < sk_DIST_POINT_num(crldp); ++i) {
            DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
            if (!dp || !dp->distpoint || dp->distpoint->type != 0) continue; // 0 = fullname
            GENERAL_NAMES* gens = dp->distpoint->name.fullname;
            for (int j = 0; j < sk_GENERAL_NAME_num(gens); ++j) {
                GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, j);
                if (gen->type != GEN_URI) continue;
                ASN1_IA5STRING* uri = gen->d.uniformResourceIdentifier;
                out.crl_urls.push_back(clamp_len(std::string(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                    static_cast<size_t>(ASN1_STRING_length(uri)))));
            }
        }
        sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    }
    return out;
}

// Heuristic weakness flags -- genuinely new value over info3.cpp, since
// a pentest report cares less about "here is the cert" and more about
// "here is what's wrong with it".
void assess_weaknesses(SslHandshakeResult& out) {
    if (icontains(out.pubkey.algorithm, "rsa") && out.pubkey.bits > 0 && out.pubkey.bits < 2048) {
        out.weak_key = true;
    } else if ((icontains(out.pubkey.algorithm, "ec") || icontains(out.pubkey.algorithm, "prime")) &&
               out.pubkey.bits > 0 && out.pubkey.bits < 224) {
        out.weak_key = true;
    }

    out.self_signed = (!out.leaf.subject.empty() && out.leaf.subject == out.leaf.issuer);

    if (icontains(out.leaf.sig_alg, "md5"))
        out.signature_algorithm_warnings.push_back(out.leaf.sig_alg + " (MD5 is cryptographically broken)");
    else if (icontains(out.leaf.sig_alg, "sha1"))
        out.signature_algorithm_warnings.push_back(out.leaf.sig_alg + " (SHA-1 signatures are deprecated)");
}

void assess_validity_window(X509* cert, SslHandshakeResult& out) {
    const ASN1_TIME* nb = X509_get0_notBefore(cert);
    const ASN1_TIME* na = X509_get0_notAfter(cert);
    // X509_cmp_time(t, NULL) compares against "now": <0 means t is in the
    // past, >0 means t is in the future, 0 is an error/unparseable time.
    if (na && X509_cmp_time(na, nullptr) < 0) out.expired = true;
    if (nb && X509_cmp_time(nb, nullptr) > 0) out.not_yet_valid = true;
}

std::string drain_openssl_errors() {
    std::string msg;
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!msg.empty()) msg += "; ";
        msg += buf;
    }
    return msg.empty() ? "TLS handshake failed" : msg;
}

// ---------------------------------------------------------------------
// Non-blocking socket helpers.
// ---------------------------------------------------------------------

int family_of(const std::string& ip) {
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) return AF_INET6;
    return -1;
}

int make_nonblocking_socket(int family) {
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}

bool start_connect(int fd, int family, const std::string& ip, int port) {
    sockaddr_storage ss{};
    socklen_t slen;
    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, ip.c_str(), &a->sin_addr) != 1) return false;
        slen = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, ip.c_str(), &a->sin6_addr) != 1) return false;
        slen = sizeof(*a);
    }
    int rc = connect(fd, reinterpret_cast<sockaddr*>(&ss), slen);
    if (rc == 0) return true;              // connected synchronously (e.g. loopback)
    return errno == EINPROGRESS;           // normal case for a non-blocking connect
}

// ---------------------------------------------------------------------
// OpenSSL callbacks. Both are dual-purpose (server+client) in libssl,
// documented per-role here since misreading the return-value contract
// is a classic source of subtle handshake bugs.
// ---------------------------------------------------------------------

// We deliberately accept every certificate at the verify-callback layer
// so the handshake always completes -- including against self-signed,
// expired, or hostname-mismatched certs -- because an enumeration tool
// needs to *see* those certs to report on them, not bail out before it
// can. Nothing about the real verdict is lost: SSL_get_verify_result()
// on the completed connection still returns OpenSSL's actual validation
// result, which is what we record and report. This connection is only
// ever used to read the handshake/cert; no application data is sent.
int always_accept_verify_cb(int /*preverify_ok*/, X509_STORE_CTX* /*store_ctx*/) {
    return 1;
}

// Client-role stapled-OCSP callback: return a POSITIVE value to accept
// (whether or not a response was actually stapled -- OCSP stapling is
// opportunistic, so "none sent" is not an error), 0 to reject, negative
// only for a genuine internal error. (The opposite convention is used
// server-side; SSL_CTX_set_tlsext_status_cb's return-value meaning flips
// with the role, which is worth spelling out since it's easy to get
// backwards.)
int ocsp_status_cb(SSL* ssl, void* /*arg*/) {
    auto* out = static_cast<SslHandshakeResult*>(SSL_get_app_data(ssl));
    const unsigned char* resp = nullptr;
    long resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
    if (out && resp && resp_len > 0) {
        out->ocsp_stapled = true;
        out->ocsp_response_size = static_cast<size_t>(resp_len);
    }
    return 1;
}

// ---------------------------------------------------------------------
// Job model + async engine.
//
// One "job" is a single (ip, port, SNI-mode) probe. The engine below
// multiplexes every in-flight connect()/TLS-handshake through a single
// poll() loop -- no thread-per-connection, no blocking sockets -- with
// the number of simultaneously-open sockets bounded by
// opts.concurrency, refilling the pool from the job queue as each
// connection finishes (success, failure, or timeout). This mirrors the
// state-machine shape dns_enum.cpp's dns_query_batch() uses for UDP.
// ---------------------------------------------------------------------

struct SslJobSpec {
    std::string ip;
    int port = 0;
    std::string hostname;   // only meaningful when send_sni is true
    bool send_sni = false;
    int family = AF_INET;
    size_t out_idx = 0;     // index into the flat results vector

    // When non-zero, pins this single connection's negotiable range via
    // SSL_set_min/max_proto_version (which overrides the SSL_CTX-level
    // range independently, so this works even though the shared ctx sets
    // its own floor). Used for the four version-support probe jobs; left
    // at 0 for a normal, unrestricted handshake.
    int forced_min_version = 0;
    int forced_max_version = 0;
};

void finalize_handshake(SSL* ssl, const SslJobSpec& job, SslHandshakeResult& out,
                         const SslEnumOptions& opts) {
    out.success = true;
    out.error.clear();
    out.tls_version = SSL_get_version(ssl);
    const char* cn = SSL_get_cipher_name(ssl);
    out.cipher_name = cn ? cn : "unknown";
    out.verify_result_code = SSL_get_verify_result(ssl);
    out.verify_result_string = X509_verify_cert_error_string(out.verify_result_code);

    X509* leaf_raw = SSL_get1_peer_certificate(ssl); // +1 ref, we own it
    if (!leaf_raw) {
        out.success = false;
        out.error = "server presented no certificate";
        return;
    }
    X509Ptr leaf(leaf_raw);

    out.leaf   = extract_identity(leaf.get());
    out.pubkey = extract_pubkey_info(leaf.get());
    out.sans   = extract_dns_sans(leaf.get());

    if (job.send_sni && !job.hostname.empty()) {
        out.hostname_verified =
            X509_check_host(leaf.get(), job.hostname.c_str(), job.hostname.size(), 0, nullptr) == 1;
    }

    out.sha1_fingerprint   = cert_fingerprint(leaf.get(), EVP_sha1());
    out.sha256_fingerprint = cert_fingerprint(leaf.get(), EVP_sha256());

    out.key_usage          = extract_key_usage(leaf.get());
    out.extended_key_usage = extract_eku(leaf.get());
    out.basic_constraints  = extract_basic_constraints(leaf.get());
    out.scts               = extract_scts(leaf.get());
    out.aia_crl            = extract_aia_crl(leaf.get());

    assess_validity_window(leaf.get(), out);
    assess_weaknesses(out);

    out.chain.push_back(out.leaf);
    if (opts.fetch_chain) {
        STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl); // NOT owned by us
        if (chain) {
            int n = sk_X509_num(chain);
            for (int i = 0; i < n && out.chain.size() < opts.max_chain_certs; ++i) {
                X509* c = sk_X509_value(chain, i);
                if (!c) continue;
                CertIdentity cid = extract_identity(c);
                // In the client role SSL_get_peer_cert_chain() commonly
                // includes the leaf again as element 0 -- skip an exact
                // duplicate so the report doesn't show it twice.
                if (i == 0 && cid.serial_hex == out.leaf.serial_hex && cid.subject == out.leaf.subject)
                    continue;
                out.chain.push_back(std::move(cid));
            }
        }
    }
}

std::vector<SslHandshakeResult> run_ssl_jobs(const std::vector<SslJobSpec>& jobs,
                                              const SslEnumOptions& opts) {
    std::vector<SslHandshakeResult> results(jobs.size());
    for (size_t i = 0; i < jobs.size(); ++i) {
        results[i].target_ip = jobs[i].ip;
        results[i].hostname  = jobs[i].send_sni ? jobs[i].hostname : std::string();
        results[i].port      = jobs[i].port;
        results[i].sni_sent  = jobs[i].send_sni;
        results[i].family    = (jobs[i].family == AF_INET) ? "IPv4" : "IPv6";
        results[i].success   = false;
        results[i].error     = "not attempted";
    }
    if (jobs.empty()) return results;

    SSLCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        for (auto& r : results) r.error = "failed to create SSL_CTX";
        return results;
    }
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(ctx.get()); // load system trust store
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, always_accept_verify_cb);
    SSL_CTX_set_tlsext_status_type(ctx.get(), TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx.get(), ocsp_status_cb);

    struct InFlight {
        int fd = -1;
        SSLPtr ssl;
        enum class St { Connecting, Handshaking } st = St::Connecting;
        bool want_write = true;
        size_t job_idx = 0;
        std::chrono::steady_clock::time_point deadline;
    };

    const int max_concurrency = std::max(1, opts.concurrency);
    size_t next_job = 0;
    std::vector<InFlight> inflight;
    inflight.reserve(static_cast<size_t>(max_concurrency));

    auto close_inflight = [](InFlight& f) {
        if (f.ssl) { SSL_shutdown(f.ssl.get()); f.ssl.reset(); }
        if (f.fd >= 0) { close(f.fd); f.fd = -1; }
    };

    auto launch_one = [&]() -> bool {
        while (next_job < jobs.size()) {
            const auto& j = jobs[next_job];
            int fd = make_nonblocking_socket(j.family);
            if (fd < 0) {
                results[j.out_idx].error = std::string("socket(): ") + std::strerror(errno);
                ++next_job;
                continue;
            }
            if (!start_connect(fd, j.family, j.ip, j.port)) {
                results[j.out_idx].error = std::string("connect(): ") + std::strerror(errno);
                close(fd);
                ++next_job;
                continue;
            }
            InFlight f;
            f.fd = fd;
            f.st = InFlight::St::Connecting;
            f.want_write = true;
            f.job_idx = next_job;
            f.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(opts.timeout_ms);
            inflight.push_back(std::move(f));
            ++next_job;
            return true;
        }
        return false;
    };

    while (static_cast<int>(inflight.size()) < max_concurrency && launch_one()) {}

    while (!inflight.empty()) {
        std::vector<pollfd> pfds;
        pfds.reserve(inflight.size());
        for (auto& f : inflight) {
            short events = (f.st == InFlight::St::Connecting) ? POLLOUT
                                                                : (f.want_write ? POLLOUT : POLLIN);
            pfds.push_back({f.fd, events, 0});
        }

        auto now = std::chrono::steady_clock::now();
        auto soonest = inflight.front().deadline;
        for (auto& f : inflight) soonest = std::min(soonest, f.deadline);
        int wait_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(soonest - now).count());
        if (wait_ms < 0) wait_ms = 0;
        wait_ms = std::min(wait_ms, 200); // wake periodically to reap timeouts / launch queued jobs

        poll(pfds.data(), pfds.size(), wait_ms);
        now = std::chrono::steady_clock::now();

        std::vector<size_t> finished;
        finished.reserve(inflight.size());

        for (size_t i = 0; i < inflight.size(); ++i) {
            InFlight& f = inflight[i];
            const bool timed_out = now >= f.deadline;
            const short revents = pfds[i].revents;
            const bool err_event = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
            auto& out = results[jobs[f.job_idx].out_idx];

            if (f.st == InFlight::St::Connecting) {
                if (!(revents & POLLOUT) && !err_event && !timed_out) continue;
                if (timed_out) {
                    out.error = "connect timeout";
                    close_inflight(f); finished.push_back(i); continue;
                }
                int so_err = 0; socklen_t sl = sizeof(so_err);
                getsockopt(f.fd, SOL_SOCKET, SO_ERROR, &so_err, &sl);
                if (so_err != 0 || err_event) {
                    out.error = std::string("connect failed: ") + std::strerror(so_err ? so_err : ECONNRESET);
                    close_inflight(f); finished.push_back(i); continue;
                }

                SSL* raw = SSL_new(ctx.get());
                if (!raw) {
                    out.error = "SSL_new() failed";
                    close_inflight(f); finished.push_back(i); continue;
                }
                f.ssl.reset(raw);
                SSL_set_fd(f.ssl.get(), f.fd);
                SSL_set_app_data(f.ssl.get(), &out);
                const auto& j = jobs[f.job_idx];
                if (j.forced_min_version != 0) SSL_set_min_proto_version(f.ssl.get(), j.forced_min_version);
                if (j.forced_max_version != 0) SSL_set_max_proto_version(f.ssl.get(), j.forced_max_version);
                if (j.send_sni && !j.hostname.empty()) {
                    SSL_set_tlsext_host_name(f.ssl.get(), j.hostname.c_str());
                    // Also drives X509_V_ERR_HOSTNAME_MISMATCH detection as
                    // part of the standard verify-chain walk.
                    SSL_set1_host(f.ssl.get(), j.hostname.c_str());
                }
                f.st = InFlight::St::Handshaking;
                f.want_write = true;
                // fall through: attempt the handshake immediately instead
                // of waiting for another poll() tick.
            }

            if (f.st == InFlight::St::Handshaking) {
                if (timed_out) {
                    out.error = "TLS handshake timeout";
                    close_inflight(f); finished.push_back(i); continue;
                }
                int rc = SSL_connect(f.ssl.get());
                if (rc == 1) {
                    finalize_handshake(f.ssl.get(), jobs[f.job_idx], out, opts);
                    close_inflight(f); finished.push_back(i); continue;
                }
                int sslerr = SSL_get_error(f.ssl.get(), rc);
                if (sslerr == SSL_ERROR_WANT_READ)       { f.want_write = false; continue; }
                if (sslerr == SSL_ERROR_WANT_WRITE)      { f.want_write = true;  continue; }
                out.error = drain_openssl_errors();
                close_inflight(f); finished.push_back(i); continue;
            }
        }

        std::sort(finished.begin(), finished.end());
        for (auto it = finished.rbegin(); it != finished.rend(); ++it) {
            inflight.erase(inflight.begin() + static_cast<long>(*it));
        }

        while (static_cast<int>(inflight.size()) < max_concurrency && launch_one()) {}
    }

    return results;
}

} // namespace

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

std::vector<SslEnumResult> run_ssl_enum_batch(const std::vector<SslTarget>& targets,
                                               const SslEnumOptions& opts) {
    std::vector<SslEnumResult> results(targets.size());
    for (size_t i = 0; i < targets.size(); ++i) {
        results[i].target_ip = targets[i].ip;
        results[i].hostname  = targets[i].hostname;
    }
    if (targets.empty()) return results;

    std::vector<int> ports = opts.ports.empty() ? std::vector<int>{443} : opts.ports;

    // Fixed order used everywhere version-support is indexed/printed:
    // TLS 1.0, 1.1, 1.2, 1.3.
    static const std::array<std::pair<int, int>, 4> kVersionProbes = {{
        {TLS1_VERSION,   TLS1_VERSION},
        {TLS1_1_VERSION, TLS1_1_VERSION},
        {TLS1_2_VERSION, TLS1_2_VERSION},
        {TLS1_3_VERSION, TLS1_3_VERSION},
    }};

    enum class JobKind { Primary, Variance, VersionProbe };
    struct JobMeta {
        size_t target_idx;
        JobKind kind;
        size_t version_idx      = 0; // index into kVersionProbes, when kind == VersionProbe
        size_t primary_flat_idx = 0; // which Primary job this belongs to, when kind == VersionProbe
    };
    std::vector<SslJobSpec> jobs;
    std::vector<JobMeta> meta;
    jobs.reserve(targets.size() * ports.size() * (opts.detect_protocol_support ? 5 : 1) + targets.size());
    meta.reserve(jobs.capacity());

    for (size_t ti = 0; ti < targets.size(); ++ti) {
        const auto& t = targets[ti];
        int fam = family_of(t.ip);
        if (fam < 0) {
            SslHandshakeResult bad;
            bad.target_ip = t.ip;
            bad.error = "not a valid IPv4/IPv6 address";
            results[ti].handshakes.push_back(std::move(bad));
            continue;
        }
        const bool have_hostname = !t.hostname.empty();
        for (int port : ports) {
            SslJobSpec j;
            j.ip = t.ip; j.port = port; j.hostname = t.hostname;
            j.send_sni = have_hostname;
            j.family = fam;
            size_t primary_flat_idx = jobs.size();
            j.out_idx = primary_flat_idx;
            jobs.push_back(j);
            meta.push_back({ti, JobKind::Primary, 0, 0});

            if (opts.detect_protocol_support) {
                for (size_t vi = 0; vi < kVersionProbes.size(); ++vi) {
                    SslJobSpec vj = j; // same ip/port/hostname/SNI-mode/family
                    vj.forced_min_version = kVersionProbes[vi].first;
                    vj.forced_max_version = kVersionProbes[vi].second;
                    vj.out_idx = jobs.size();
                    jobs.push_back(vj);
                    meta.push_back({ti, JobKind::VersionProbe, vi, primary_flat_idx});
                }
            }
        }
        if (opts.check_sni_variance && have_hostname && !ports.empty()) {
            SslJobSpec j;
            j.ip = t.ip; j.port = ports.front(); j.hostname.clear();
            j.send_sni = false;
            j.family = fam;
            j.out_idx = jobs.size();
            jobs.push_back(j);
            meta.push_back({ti, JobKind::Variance, 0, 0});
        }
    }

    if (jobs.empty()) return results;

    std::vector<SslHandshakeResult> flat = run_ssl_jobs(jobs, opts);

    // Pass 1: file away Primary and Variance results. VersionProbe results
    // are read (not moved) in pass 2 below, once every Primary's landing
    // spot in results[ti].handshakes is known.
    std::vector<std::optional<SslHandshakeResult>> variance_probe(targets.size());
    std::unordered_map<size_t, std::pair<size_t, size_t>> primary_location; // flat_idx -> (target_idx, handshake_idx)
    for (size_t i = 0; i < flat.size(); ++i) {
        size_t ti = meta[i].target_idx;
        switch (meta[i].kind) {
            case JobKind::Variance:
                variance_probe[ti] = std::move(flat[i]);
                break;
            case JobKind::Primary:
                results[ti].handshakes.push_back(std::move(flat[i]));
                primary_location[i] = {ti, results[ti].handshakes.size() - 1};
                break;
            case JobKind::VersionProbe:
                break; // handled in pass 2
        }
    }

    // Pass 2: fold each VersionProbe's pass/fail into its Primary's
    // version_support matrix.
    for (size_t i = 0; i < flat.size(); ++i) {
        if (meta[i].kind != JobKind::VersionProbe) continue;
        auto it = primary_location.find(meta[i].primary_flat_idx);
        if (it == primary_location.end()) continue;
        auto [ti, hidx] = it->second;
        auto& vs = results[ti].handshakes[hidx].version_support;
        vs.probed = true;
        const bool ok = flat[i].success;
        switch (meta[i].version_idx) {
            case 0: vs.tls1_0 = ok; break;
            case 1: vs.tls1_1 = ok; break;
            case 2: vs.tls1_2 = ok; break;
            case 3: vs.tls1_3 = ok; break;
        }
    }

    for (size_t ti = 0; ti < targets.size(); ++ti) {
        if (!variance_probe[ti].has_value()) continue;
        results[ti].checked_sni_variance = true;
        for (auto& h : results[ti].handshakes) {
            if (h.port == ports.front() && h.sni_sent) {
                if (h.success && variance_probe[ti]->success) {
                    results[ti].sni_vs_no_sni_same_cert =
                        (h.sha256_fingerprint == variance_probe[ti]->sha256_fingerprint);
                }
                break;
            }
        }
    }

    // Dual-stack comparison: only meaningful when the caller has passed
    // two targets that share a hostname but differ in address family
    // (e.g. the A and AAAA records for the same domain).
    std::unordered_map<std::string, std::vector<size_t>> by_hostname;
    for (size_t ti = 0; ti < targets.size(); ++ti) {
        if (!targets[ti].hostname.empty()) by_hostname[targets[ti].hostname].push_back(ti);
    }
    for (auto& [hostname, idxs] : by_hostname) {
        (void)hostname;
        if (idxs.size() < 2) continue;
        const SslHandshakeResult* v4 = nullptr;
        const SslHandshakeResult* v6 = nullptr;
        for (size_t ti : idxs) {
            for (auto& h : results[ti].handshakes) {
                if (!h.success || h.port != ports.front() || !h.sni_sent) continue;
                if (h.family == "IPv4" && !v4) v4 = &h;
                if (h.family == "IPv6" && !v6) v6 = &h;
            }
        }
        if (v4 && v6) {
            bool same = (v4->sha256_fingerprint == v6->sha256_fingerprint);
            for (size_t ti : idxs) {
                results[ti].checked_dual_stack = true;
                results[ti].ipv4_ipv6_same_cert = same;
            }
        }
    }

    return results;
}

SslEnumResult run_ssl_enum(const std::string& target_ip, const std::string& hostname_hint,
                            const SslEnumOptions& opts) {
    std::vector<SslTarget> targets{{target_ip, hostname_hint}};
    auto results = run_ssl_enum_batch(targets, opts);
    return results.empty() ? SslEnumResult{} : std::move(results.front());
}

namespace {

// -----------------------------------------------------------------
// Small report-layout helpers. Everything renders through a fixed
// label column so fields line up regardless of value length, plus a
// couple of box-drawing rules to visually separate targets/handshakes
// from each other -- replaces the old flat "Label : value" dump.
// -----------------------------------------------------------------
constexpr int kLabelWidth = 11;

std::string label(const std::string& text) {
    std::string s = color::dim + std::string("  ") + text;
    int pad = kLabelWidth - static_cast<int>(text.size());
    if (pad > 0) s += std::string(static_cast<size_t>(pad), ' ');
    s += color::reset + color::dim + ": " + color::reset;
    return s;
}

std::string rule(char c, int len, const std::string& col) {
    return col + std::string(static_cast<size_t>(len), c) + color::reset;
}

std::string ok_badge(bool good, const std::string& good_text, const std::string& bad_text) {
    return good ? (color::green + good_text + color::reset)
                : (color::red   + bad_text  + color::reset);
}

// Colors the CN=, O=, and C= components of an RFC2253 DN string (as
// produced by X509_NAME_print_ex(..., XN_FLAG_RFC2253)) green, so the
// fields a reader scans for first stand out from the rest of a long
// subject/issuer line. Splits on unescaped commas only, since RFC2253
// escapes a literal comma with a backslash rather than quoting it.
std::string colorize_dn(const std::string& dn) {
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i = 0; i < dn.size(); ++i) {
        if (dn[i] == '\\' && i + 1 < dn.size()) { cur += dn[i]; cur += dn[i + 1]; ++i; continue; }
        if (dn[i] == ',') { parts.push_back(cur); cur.clear(); continue; }
        cur += dn[i];
    }
    parts.push_back(cur);

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += color::dim + std::string(",") + color::reset;
        std::string safe = sanitize_echo(parts[i]);
        bool highlight = safe.rfind("CN=", 0) == 0 || safe.rfind("O=", 0) == 0 || safe.rfind("C=", 0) == 0;
        out += highlight ? (color::green + safe + color::reset) : safe;
    }
    return out;
}

// One "TLSv1.2 ✓" / "TLSv1.0 ✗" chip, colored green/red, with the
// currently-negotiated version additionally bolded so it stands out
// from the rest of the support matrix.
std::string version_chip(const std::string& name, bool supported, bool is_negotiated) {
    std::string chip = (supported ? color::green : color::red)
                      + name + (supported ? " \u2713" : " \u2717") + color::reset;
    if (is_negotiated) chip = color::bold + chip + color::bold; // re-bold after the reset above
    return chip;
}

} // namespace

void print_ssl_enum_result(const SslEnumResult& r, const SslEnumOptions& opts) {
    const std::string header = r.target_ip + (r.hostname.empty() ? "" : "  (" + r.hostname + ")");
    std::cout << "\n" << rule('=', static_cast<int>(header.size()) + 4, color::cyan) << "\n"
               << color::bold << color::cyan << "  " << header << color::reset << "\n"
               << rule('=', static_cast<int>(header.size()) + 4, color::cyan) << "\n";

    for (const auto& h : r.handshakes) {
        std::string title = h.family + " " + h.target_ip + ":" + std::to_string(h.port);
        std::cout << "\n" << color::bold << color::blue << "\u25B8 " << title << color::reset
                   << (h.sni_sent ? "" : (color::dim + std::string("  [no SNI]") + color::reset)) << "\n"
                   << rule('-', static_cast<int>(title.size()) + 2, color::blue) << "\n";

        if (!h.success) {
            std::cout << label("Status") << color::red << "handshake failed" << color::reset
                       << color::dim << "  (" << sanitize_echo(h.error) << ")" << color::reset << "\n";
            continue;
        }

        // --- Protocol / cipher, plus the full version-support matrix ---
        std::cout << label("Negotiated") << color::bold << h.tls_version << color::reset
                   << color::dim << "  cipher " << color::reset << h.cipher_name << "\n";

        if (h.version_support.probed) {
            std::cout << label("Protocols")
                       << version_chip("TLSv1.0", h.version_support.tls1_0, h.tls_version == "TLSv1")
                       << "  " << version_chip("TLSv1.1", h.version_support.tls1_1, h.tls_version == "TLSv1.1")
                       << "  " << version_chip("TLSv1.2", h.version_support.tls1_2, h.tls_version == "TLSv1.2")
                       << "  " << version_chip("TLSv1.3", h.version_support.tls1_3, h.tls_version == "TLSv1.3")
                       << "\n";
            if (h.version_support.tls1_0 || h.version_support.tls1_1)
                std::cout << label("") << color::yellow
                           << "server still accepts a deprecated TLS version" << color::reset << "\n";
        }

        // --- Certificate identity ---
        std::cout << label("Subject") << colorize_dn(h.leaf.subject) << "\n";
        std::cout << label("Issuer") << colorize_dn(h.leaf.issuer) << "\n";
        std::cout << label("Validity") << h.leaf.not_before << color::dim << "  ->  " << color::reset
                   << h.leaf.not_after;
        if (h.expired)       std::cout << "  " << color::red    << "[EXPIRED]"       << color::reset;
        if (h.not_yet_valid) std::cout << "  " << color::red    << "[NOT YET VALID]" << color::reset;
        std::cout << "\n";

        std::cout << label("Key") << h.pubkey.algorithm << " (" << h.pubkey.bits << " bits)"
                   << (h.weak_key ? ("  " + color::red + "[WEAK KEY]" + color::reset) : "") << "\n";
        std::cout << label("SPKI pin") << color::dim << "sha256/" << color::reset << h.pubkey.spki_sha256 << "\n";
        std::cout << label("SHA256fp") << h.sha256_fingerprint << "\n";

        if (h.sni_sent) {
            std::cout << label("Hostname") << ok_badge(h.hostname_verified, "MATCH", "MISMATCH") << "\n";
        }
        std::cout << label("Verify") << (h.verify_result_code == X509_V_OK
                       ? (color::green + std::string("OK") + color::reset)
                       : (color::yellow + h.verify_result_string + color::reset)) << "\n";

        if (h.self_signed)
            std::cout << label("") << color::yellow << "self-signed certificate" << color::reset << "\n";
        for (auto& w : h.signature_algorithm_warnings)
            std::cout << label("") << color::yellow << "weak signature algorithm: " << w << color::reset << "\n";

        // --- Revocation / transparency ---
        std::cout << label("OCSP") << (h.ocsp_stapled
                       ? (color::green + std::string("stapled") + color::reset + color::dim + ", " +
                          std::to_string(h.ocsp_response_size) + " bytes" + color::reset)
                       : (color::dim + std::string("not stapled") + color::reset)) << "\n";
        for (auto& u : h.aia_crl.ocsp_urls) std::cout << label("OCSP URL") << u << "\n";
        for (auto& u : h.aia_crl.crl_urls)
            std::cout << label("CRL") << color::green << u << color::reset << "\n";
        if (!h.scts.empty())
            std::cout << label("CT") << h.scts.size() << " embedded SCT(s)\n";

        if (opts.fetch_chain && h.chain.size() > 1) {
            std::cout << label("Chain") << color::dim << h.chain.size() << " certs, including leaf" << color::reset << "\n";
            for (size_t i = 0; i < h.chain.size(); ++i)
                std::cout << "      " << color::dim << "[" << i << "]" << color::reset
                           << " subject=" << sanitize_echo(h.chain[i].subject)
                           << color::dim << "  issuer=" << color::reset << sanitize_echo(h.chain[i].issuer) << "\n";
        }

        if (!h.sans.empty()) {
            std::cout << "\n" << label("SANs") << color::dim << h.sans.size() << " total" << color::reset << "\n";
            for (auto& s : h.sans) std::cout << "      " << sanitize_echo(s) << "\n";
        }
    }

    if (r.checked_sni_variance || r.checked_dual_stack) std::cout << "\n";
    if (r.checked_sni_variance) {
        std::cout << color::bold << "  \u25B8 SNI vs no-SNI" << color::reset << color::dim << " -> " << color::reset
                   << (r.sni_vs_no_sni_same_cert
                           ? (color::green + std::string("same certificate") + color::reset)
                           : (color::yellow + std::string("DIFFERENT certificate served without SNI") + color::reset))
                   << "\n";
    }
    if (r.checked_dual_stack) {
        std::cout << color::bold << "  \u25B8 IPv4 vs IPv6" << color::reset << color::dim << " -> " << color::reset
                   << (r.ipv4_ipv6_same_cert
                           ? (color::green + std::string("same certificate") + color::reset)
                           : (color::yellow + std::string("DIFFERENT certificate served over IPv6") + color::reset))
                   << "\n";
    }
}

bool save_ssl_enum_result(const std::vector<SslEnumResult>& results, const std::string& path) {
    if (path.empty()) return false;

    json j = json::array();
    for (auto& r : results) {
        json tj;
        tj["target_ip"] = r.target_ip;
        tj["hostname"] = r.hostname;
        tj["checked_sni_variance"] = r.checked_sni_variance;
        tj["sni_vs_no_sni_same_cert"] = r.sni_vs_no_sni_same_cert;
        tj["checked_dual_stack"] = r.checked_dual_stack;
        tj["ipv4_ipv6_same_cert"] = r.ipv4_ipv6_same_cert;

        json handshakes = json::array();
        for (auto& h : r.handshakes) {
            json hj;
            hj["ip"] = h.target_ip;
            hj["port"] = h.port;
            hj["family"] = h.family;
            hj["sni_sent"] = h.sni_sent;
            hj["hostname"] = h.hostname;
            hj["success"] = h.success;
            hj["error"] = h.error;
            if (h.success) {
                hj["tls_version"] = h.tls_version;
                hj["cipher"] = h.cipher_name;
                hj["version_support"] = {
                    {"probed", h.version_support.probed},
                    {"tls1_0", h.version_support.tls1_0},
                    {"tls1_1", h.version_support.tls1_1},
                    {"tls1_2", h.version_support.tls1_2},
                    {"tls1_3", h.version_support.tls1_3},
                };
                hj["subject"] = h.leaf.subject;
                hj["issuer"] = h.leaf.issuer;
                hj["serial"] = h.leaf.serial_hex;
                hj["not_before"] = h.leaf.not_before;
                hj["not_after"] = h.leaf.not_after;
                hj["sig_alg"] = h.leaf.sig_alg;
                hj["pubkey_algorithm"] = h.pubkey.algorithm;
                hj["pubkey_bits"] = h.pubkey.bits;
                hj["spki_sha256"] = h.pubkey.spki_sha256;
                hj["sans"] = h.sans;
                hj["hostname_verified"] = h.hostname_verified;
                hj["sha1_fingerprint"] = h.sha1_fingerprint;
                hj["sha256_fingerprint"] = h.sha256_fingerprint;
                hj["verify_result_code"] = h.verify_result_code;
                hj["verify_result_string"] = h.verify_result_string;
                hj["ocsp_stapled"] = h.ocsp_stapled;
                hj["ocsp_response_size"] = h.ocsp_response_size;
                hj["weak_key"] = h.weak_key;
                hj["expired"] = h.expired;
                hj["not_yet_valid"] = h.not_yet_valid;
                hj["self_signed"] = h.self_signed;
                hj["signature_algorithm_warnings"] = h.signature_algorithm_warnings;
                hj["key_usage"] = {
                    {"present", h.key_usage.present},
                    {"digital_signature", h.key_usage.digital_signature},
                    {"key_encipherment", h.key_usage.key_encipherment},
                    {"key_cert_sign", h.key_usage.key_cert_sign},
                    {"non_repudiation", h.key_usage.non_repudiation},
                    {"key_agreement", h.key_usage.key_agreement},
                    {"crl_sign", h.key_usage.crl_sign},
                };
                hj["extended_key_usage"] = h.extended_key_usage;
                hj["basic_constraints"] = {
                    {"present", h.basic_constraints.present},
                    {"is_ca", h.basic_constraints.is_ca},
                    {"pathlen", h.basic_constraints.pathlen},
                };
                json scts = json::array();
                for (auto& s : h.scts) scts.push_back({{"log_id", s.log_id_hex}, {"timestamp_ms", s.timestamp_ms}});
                hj["scts"] = scts;
                hj["ocsp_urls"] = h.aia_crl.ocsp_urls;
                hj["ca_issuer_urls"] = h.aia_crl.ca_issuer_urls;
                hj["crl_urls"] = h.aia_crl.crl_urls;

                json chain = json::array();
                for (auto& c : h.chain)
                    chain.push_back({{"subject", c.subject}, {"issuer", c.issuer}, {"serial", c.serial_hex}});
                hj["chain"] = chain;
            }
            handshakes.push_back(std::move(hj));
        }
        tj["handshakes"] = std::move(handshakes);
        j.push_back(std::move(tj));
    }

    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return static_cast<bool>(out);
}
