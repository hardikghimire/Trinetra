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
std::string format_mac(const uint8_t* mac);
std::string get_current_time();

// Human-readable IPv6 formatting, mirrors format_mac's role for MACs.
std::string format_ipv6(const uint8_t* ip6 /*16 bytes*/);

#endif
