#pragma once

#include "scan.hpp"

bool send_arp_request(int sock, struct io_uring* ring, const char* ifname,
                       uint8_t* src_mac, uint8_t* src_ip,
                       const std::vector<uint8_t*>& target_IPs,
                       const EthArpOptions& eth_opts);

bool receive_arp_reply(int sock, struct io_uring* ring,
                        const std::vector<uint8_t*>& target_IPs,
                        std::vector<uint8_t*>& macs,
                        const EthArpOptions& eth_opts,
                        int initial_rtt_ms,
                        const char* ifname,
                        uint8_t* src_mac,
                        uint8_t* src_ip,
                        int max_retries,
                        int min_round_timeout_ms,
                        int max_round_timeout_ms,
                        std::vector<double>* out_rtt_ms);

bool set_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4], const uint8_t mac[6]);
void delete_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4]);
