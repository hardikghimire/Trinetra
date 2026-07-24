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
int get_ip_version(const char* ip);
int make_sockaddr_from_ip(const std::string& ip, uint16_t port,struct sockaddr_storage& out, socklen_t& out_len);
std::string autodetect_interface(uint32_t local_ip);
std::string autodetect_interface(const struct in6_addr& local_ip6);
bool get_interface_mac(int sock, const char* ifname, uint8_t* mac);
bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask);
bool get_interface_ip6(const char* ifname, uint8_t* ip6 , uint8_t* prefix_len);
bool parse_mac(const std::string& mac_str, uint8_t* out_mac);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
std::string reverse_dns_lookup(const std::string& ip_address);
bool ptr_cache_lookup(const std::string& ip, std::string& out_domain);
void ptr_cache_store(const std::string& ip, const std::string& domain);
std::string format_mac(const uint8_t* mac);
std::string get_current_time();
std::string format_ipv6(const uint8_t* ip6);
bool parse_cidr_generic(const std::string& cidr, int family,
                         std::string& ip_out, uint8_t& prefix_out);
bool route_lookup(const std::string& target_ip, int family,
                   std::string& out_iface, bool& out_is_onlink);
bool neighbor_cache_has_entry_v4(const std::string& target_ip);
bool is_point_to_point_interface(const std::string& ifname);
void load_ip_range_databases(const std::string& aws_path,
                              const std::string& cloudflare_path,
                              const std::string& akamai_path,
                              const std::string& azure_path,
                              const std::string& digitalocean_path,
                              const std::string& google_path,
                              const std::string& alibaba_path,
                              const std::string& fastly_path,
                              const std::string& hetzner_path,
                              const std::string& vultr_path,
                              const std::string& zscaler_path,
                              const std::string& googlebot_path,
                              const std::string& linode_path,
                              const std::string& tor_path);
bool lookup_ip_provider(const std::string& ip, std::string& out_label);

#endif
