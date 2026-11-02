#pragma once

#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <chrono>

// ---------------------------------------------------------------------
// TLS / certificate enumeration module ("--enum ssl").
//
// Structured, async re-implementation of what info3.cpp prototyped as a
// single-shot blocking CLI tool: instead of one openssl s_client-style
// handshake per process invocation, this module drives many concurrent
// non-blocking TCP+TLS handshakes (poll()-multiplexed, same shape as
// dns_enum.hpp's dns_query_batch engine) and returns structured results
// for the report layer to render or serialize — no text scraping, no
// blocking-socket-per-target design.
// ---------------------------------------------------------------------

struct CertIdentity {
    std::string subject;
    std::string issuer;
    std::string serial_hex;
    std::string not_before;
    std::string not_after;
    std::string sig_alg;
};

struct PubKeyInfo {
    std::string algorithm;
    int bits = 0;
    std::string spki_sha256; // colon-hex SHA-256 of SubjectPublicKeyInfo (SPKI pin)
};

struct KeyUsageInfo {
    bool present = false;
    bool digital_signature = false;
    bool key_encipherment  = false;
    bool key_cert_sign     = false;
    bool non_repudiation   = false;
    bool key_agreement     = false;
    bool crl_sign          = false;
};

struct BasicConstraintsInfo {
    bool present = false;
    bool is_ca = false;
    int  pathlen = -1; // -1 = unset
};

struct SctInfo {
    std::string log_id_hex;
    uint64_t    timestamp_ms = 0;
};

// Per-protocol-version support matrix for a single (ip, port, SNI-mode)
// target. Populated by forcing four extra lightweight handshakes (one
// pinned to each of TLS 1.0/1.1/1.2/1.3 via SSL_set_min/max_proto_version)
// alongside the normal, unrestricted handshake -- because a single
// negotiated handshake only tells you the *highest* version both sides
// picked, never what else the server (and locally-built OpenSSL) is
// willing to speak. Whether TLS 1.0/1.1 show up at all also depends on
// the local OpenSSL build actually supporting them.
struct TlsVersionSupport {
    bool probed  = false; // false if detect_protocol_support was off or probing failed to run
    bool tls1_0  = false;
    bool tls1_1  = false;
    bool tls1_2  = false;
    bool tls1_3  = false;
};

struct AiaCrlInfo {
    std::vector<std::string> ocsp_urls;
    std::vector<std::string> ca_issuer_urls;
    std::vector<std::string> crl_urls;
};

// One completed (or failed) handshake attempt against a single
// (ip, port, SNI-mode) combination.
struct SslHandshakeResult {
    std::string target_ip;
    std::string hostname;      // SNI hostname used; empty if send_sni was false
    int         port = 0;
    bool        sni_sent = false;
    std::string family;        // "IPv4" | "IPv6"

    bool        success = false;
    std::string error;         // populated when !success (connect/handshake failure reason)

    std::string tls_version;    // version actually negotiated by this handshake
    std::string cipher_name;
    TlsVersionSupport version_support; // full protocol matrix (see TlsVersionSupport)

    CertIdentity leaf;
    PubKeyInfo   pubkey;
    std::vector<std::string> sans;
    bool         hostname_verified = false; // X509_check_host() against SAN/CN, RFC 6125

    std::string sha1_fingerprint;
    std::string sha256_fingerprint;

    KeyUsageInfo          key_usage;
    std::vector<std::string> extended_key_usage;
    BasicConstraintsInfo  basic_constraints;
    std::vector<SctInfo>  scts;
    AiaCrlInfo             aia_crl;

    long        verify_result_code = -1;
    std::string verify_result_string;

    bool   ocsp_stapled = false;
    size_t ocsp_response_size = 0;

    std::vector<CertIdentity> chain; // [0] = leaf, then intermediates as presented by the server

    // Findings beyond what info3.cpp reported — heuristic weaknesses
    // worth flagging directly in a pentest report.
    bool weak_key         = false;  // RSA < 2048 bits, or EC < 224 bits
    bool expired          = false;
    bool not_yet_valid    = false;
    bool self_signed      = false;  // subject == issuer (heuristic, not full chain proof)
    std::vector<std::string> signature_algorithm_warnings; // e.g. "sha1WithRSAEncryption", "md5WithRSAEncryption"
};

// Aggregated view for a single logical target (one ip [+ hostname]),
// across every port/mode probed.
struct SslEnumResult {
    std::string target_ip;
    std::string hostname; // empty if none supplied (IP-only target)

    std::vector<SslHandshakeResult> handshakes;

    // Cross-checks, populated only when the inputs make them meaningful
    // (see run_ssl_enum_batch doc comment).
    bool checked_sni_variance     = false;
    bool sni_vs_no_sni_same_cert  = false;

    bool checked_dual_stack       = false; // true if this hostname had both an IPv4 and IPv6 target in the same batch
    bool ipv4_ipv6_same_cert      = false;
};

struct SslEnumOptions {
    bool enabled = false;

    std::vector<int> ports = {443};

    int timeout_ms   = 4000;  // per-connection deadline (connect + full handshake)
    int concurrency  = 64;    // bounded concurrent in-flight connections across the whole batch

    bool check_sni_variance = true;  // also probe once without SNI and compare the returned leaf cert
    bool fetch_chain        = true;  // capture intermediate certs presented by the server
    size_t max_chain_certs  = 16;    // hard cap so a pathological/malicious chain can't exhaust memory

    // Also run 4 extra pinned handshakes per primary (ip, port, SNI-mode)
    // probe to build a full TLSv1.0/1.1/1.2/1.3 support matrix, instead of
    // only reporting whatever version the unrestricted handshake happened
    // to negotiate. Adds up to 4x the connections per port when on.
    bool detect_protocol_support = true;

    bool verbose = false;
    std::string save_json_file; // empty = don't save
};

// Single target, single logical unit of work: one IP, optionally with a
// hostname to use for SNI + hostname-verification + SAN reporting.
struct SslTarget {
    std::string ip;
    std::string hostname; // empty => no SNI, no hostname-verification check
};

// Runs the full probe set (every opts.ports entry, plus the SNI-variance
// check when applicable) against every target concurrently, using a
// single poll()-driven event loop — not one thread or blocking socket
// per target. Safe to pass a mix of IPv4 and IPv6 targets; if two
// targets share the same non-empty hostname, ipv4_ipv6_same_cert is
// computed between them automatically.
std::vector<SslEnumResult> run_ssl_enum_batch(const std::vector<SslTarget>& targets,
                                               const SslEnumOptions& opts);

// Convenience wrapper for a single target.
SslEnumResult run_ssl_enum(const std::string& target_ip, const std::string& hostname_hint,
                            const SslEnumOptions& opts);

// Pretty, colorized console report (matches the palette used by
// print_dns_enum_result / the rest of shiv's output).
void print_ssl_enum_result(const SslEnumResult& result, const SslEnumOptions& opts);

// Writes the full result as JSON.
bool save_ssl_enum_result(const std::vector<SslEnumResult>& results, const std::string& path);
