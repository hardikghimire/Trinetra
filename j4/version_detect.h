#ifndef VERSION_DETECT_HPP
#define VERSION_DETECT_HPP

#include <string>
#include <cstdint>

// One-line summary of what shiv's -sV needs per open port.
struct ServiceVersionInfo {
    bool        matched = false;
    std::string service;   // e.g. "ssh", "http"
    std::string product;   // e.g. "OpenSSH"
    std::string version;   // e.g. "8.1"
    std::string extrainfo;

    // "openssh8.1"-style combined string for the sample output format.
    std::string combined() const;
};

// Loads the nmap-service-probes DB once (lazy init, called automatically
// on first use). Safe to call explicitly and early if you want load
// errors surfaced before the scan starts (e.g. right after arg parsing
// when config.version_detection is true).
// Returns false (and logs to stderr) if the probe file can't be loaded.
bool init_version_detection(const std::string& probe_file ="nmap-service-probes.txt");

// Runs the probe engine against ip:port over its own sockets.
// Thread-safe to call concurrently (each call opens its own connection;
// AllProbes is read-only after init).
ServiceVersionInfo detect_service_version(const std::string& ip,
                                           uint16_t port,
                                           int timeout_ms = 4000);

#endif
