#pragma once
#include <string>

// Configuration for --split. Mirrors the variables at the top of ns1.sh,
// but everything here is applied in-process via unshare(2) + rtnetlink +
// ioctl instead of shelling out to `ip`/`sudo`.
struct SplitNsConfig {
    std::string base_iface;          // physical iface to bridge off, e.g. "eth0".
                                      // empty => auto-detected from the default route.
    std::string mac;                 // optional custom MAC for the macvlan device.
                                      // empty => kernel-assigned.
    std::string ip_cidr;             // REQUIRED, e.g. "192.168.1.114/24"
    std::string gateway;             // REQUIRED, e.g. "192.168.1.254"
    std::string veth_name = "shivmv0"; // name of the macvlan device
};

// Mirrors ns1.sh's variable block exactly (NS, CUSTOM_MAC, IP_ADDR,
// IP_PREFIX, GATEWAY, DNS1, DNS2) so the same mental model / file carries
// over. IP_PREFIX may be either a bare number ("24") or a dotted netmask
// ("255.255.255.0"), same as the comment in ns1.sh allows.
struct SplitFileConf {
    std::string ns_label;   // NS=          (informational/log label only)
    std::string mac;        // CUSTOM_MAC=
    std::string ip_addr;    // IP_ADDR=
    std::string ip_prefix;  // IP_PREFIX=   ("24" or "255.255.255.0")
    std::string gateway;    // GATEWAY=
    std::string dns1;       // DNS1=
    std::string dns2;       // DNS2=
};

// Default location --split reads its settings from when no --split-*
// option overrides them. Shell-variable-style file: KEY="VALUE" per line,
// '#' comments allowed, same layout as ns1.sh's header block.
inline constexpr const char* kDefaultSplitConfPath = "/usr/share/shiv/shiv_split.conf";

// Parses kDefaultSplitConfPath (or any given path) into `out`.
// Returns false (with `err` set) if the file can't be opened; a missing
// conf file is not fatal by itself -- the caller falls back to whatever
// --split-* options were given on the command line.
bool load_split_conf(const std::string& path, SplitFileConf& out, std::string& err);

// Combines an IP_ADDR + IP_PREFIX pair (numeric "24" OR dotted
// "255.255.255.0") into a canonical "ip/prefixlen" CIDR string suitable
// for SplitNsConfig::ip_cidr.
bool build_split_ip_cidr(const std::string& ip_addr, const std::string& ip_prefix_field,
                          std::string& cidr_out, std::string& err);


// Moves the CALLING PROCESS into a brand-new, anonymous network namespace
// containing a single macvlan (bridge-mode) interface bound to base_iface,
// already assigned cfg.ip_cidr and a default route via cfg.gateway, and
// brought up. Equivalent to the whole of ns1.sh, minus DNS (the scanner's
// existing --dns-servers/g_dns_servers path should be used instead, since
// this namespace deliberately has no /etc/resolv.conf of its own).
//
// MUST be called before any socket() the scanner opens for the actual
// scan (raw sockets, TCP connects, etc.) -- everything created after a
// successful call lives inside the new namespace automatically, with no
// further plumbing required. The namespace is anonymous and process-
// scoped: it disappears by itself when this process exits, no cleanup
// step is needed (unlike ns1.sh's persistent `ip netns add`).
//
// Returns true on success. On failure, `err` is set to a human-readable
// reason. A false return should be treated as fatal by the caller -- on
// some failure paths the process may already have been moved into the
// new (still unconfigured) namespace.
bool enter_split_namespace(const SplitNsConfig& cfg, std::string& err);

