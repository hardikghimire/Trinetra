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
#include <cstring>
#include <cerrno>

unsigned short checksum(void *b, int len);
const std::unordered_map<uint16_t, std::string>& read_services_from_file(const std::string &filename);
std::vector<int> parse_ports(const std::string &port_spec);
std::vector<int> read_ports_from_file(const std::string &filename);
int get_ip_version(const char* ip);
std::string autodetect_interface(uint32_t local_ip);
bool get_interface_mac(int sock, const char* ifname, uint8_t* mac);
bool get_interface_ip_and_netmask(int sock, const char* ifname, uint8_t* ip, uint8_t* netmask);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
std::string reverse_dns_lookup(const std::string& ip_address);
std::string format_mac(const uint8_t* mac);
std::string get_current_time();

#endif
