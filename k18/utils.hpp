#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>
#include <cerrno>

unsigned short checksum(void *b, int len);
const std::unordered_map<uint16_t, std::string>& read_services_from_file(const std::string &filename);
std::vector<int> parse_ports(const std::string &port_spec);
std::vector<int> read_ports_from_file(const std::string &filename);

// Returns 4 for a valid IPv4 literal, 6 for a valid IPv6 literal, 0 if neither.
int get_ip_version(const char* ip);

int make_sockaddr_from_ip(const std::string& ip, uint16_t port,
                           struct sockaddr_storage& out, socklen_t& out_len);

// IPv4 interface lookup by local address (existing, unchanged behavior/perf).
std::string autodetect_interface(uint32_t local_ip);

// IPv6 overload — same name, resolved at compile time, zero extra runtime cost
// on the IPv4 path since it's a different overload, not a branch.
std::string autodetect_interface(const struct in6_addr& local_ip6);

bool get_interface_mac(int sock, const char* ifname, uint8_t* mac);
bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask);
// IPv6 counterpart. Can't be an overload of the function above: ip/netmask are
// both uint8_t* there too, so the signatures would be identical and ambiguous.
// Picks the first non-link-local (global/ULA) address on ifname, falling back
// to link-local if that's all the interface has.
bool get_interface_ip6(const char* ifname, uint8_t* ip6 /*16 bytes*/, uint8_t* prefix_len /*may be null*/);

bool parse_mac(const std::string& mac_str, uint8_t* out_mac);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
std::string reverse_dns_lookup(const std::string& ip_address);
// Shared PTR (reverse-DNS) cache — reverse_dns_lookup() (utils.cpp) and
// resolve_ip_to_domain() (control.cpp) both resolve IP -> hostname for the
// same target; sharing this cache means a given IP is only reverse-resolved
// once per run regardless of which caller asks first.
bool ptr_cache_lookup(const std::string& ip, std::string& out_domain);
void ptr_cache_store(const std::string& ip, const std::string& domain);
std::string format_mac(const uint8_t* mac);
std::string get_current_time();

// Human-readable IPv6 formatting, mirrors format_mac's role for MACs.
std::string format_ipv6(const uint8_t* ip6 /*16 bytes*/);

// Parses "addr/prefixlen" for either address family in one place instead of
// each caller re-implementing inet_pton + range-check. family must be
// AF_INET or AF_INET6; prefix is bounds-checked against that family (0-32
// / 0-128). Rejects non-numeric prefixes and invalid address literals.
// Used by netns_split.cpp for both --split-ip (v4) and --split-ip6 (v6).
bool parse_cidr_generic(const std::string& cidr, int family,
                         std::string& ip_out, uint8_t& prefix_out);

// ---- on-link ground-truth helpers (route table / neighbor cache) ----
// These give a topology-based answer instead of the old address-range
// guess (RFC1918-only). Public IPs on a VPS bridge, colo /29s, or public
// cloud subnets are all genuinely L2-adjacent and should classify as
// on-link — these helpers ask the kernel directly instead of assuming.

// Queries the kernel routing table (RTM_GETROUTE over NETLINK_ROUTE) for
// how target_ip would actually be routed. Returns true on success;
// out_iface receives the outgoing interface name, out_is_onlink is true
// only when the route has no gateway hop (direct/scope-link — the
// kernel's own definition of "on this segment"). family must be AF_INET
// or AF_INET6.
bool route_lookup(const std::string& target_ip, int family,
                   std::string& out_iface, bool& out_is_onlink);

// Checks the kernel's IPv4 ARP table (/proc/net/arp) for an already
// resolved (ATF_COMPLETE) entry for target_ip. A hit is proof of on-link
// reachability without sending a probe packet. IPv4 only — there is no
// /proc equivalent for the IPv6 neighbor table; a v6 version would need
// RTM_GETNEIGH over the same netlink socket as route_lookup.
bool neighbor_cache_has_entry_v4(const std::string& target_ip);

// True if ifname is a point-to-point link (IFF_POINTOPOINT) — e.g. some
// cloud providers hand out a /32 with routing handled entirely via the
// gateway rather than a real broadcast subnet. ARP/NDP will never work
// on links like this even if route_lookup reports them as on-link.
bool is_point_to_point_interface(const std::string& ifname);

#endif
