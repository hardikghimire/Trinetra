#ifndef PARSER_HPP
#define PARSER_HPP

#include "scan.hpp"
#include <string>
#include <string_view>
#include <cstdint>

bool parse_sport_range_config(const std::string& arg, SportRangeConfig& out);
bool parse_gsport_config(const std::string& arg, GsportConfig& out);
bool parse_duration_to_us(std::string_view s, uint64_t& out, const char* flag_name);
bool parse_rate_config(const std::string& arg, RateConfig& out);
bool parse_jitter_config(const std::string& arg, JitterConfig& out);
bool parse_batch_delay_config(const std::string& arg, BatchDelayConfig& out);
bool parse_bandwidth_config(const std::string& arg, BandwidthConfig& out);
bool parse_packet_length(const std::string& arg, PacketLengthConfig& out);
bool parse_dscp_value(const std::string& arg, uint8_t& out_dscp);
bool parse_ip_tos_value(const std::string& arg, uint8_t& out_tos);
bool parse_ip_id_mode(const std::string& arg, IpIdMode& out_mode, uint16_t& out_value);
bool parse_hop_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_dest_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_route_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_ah_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_esp_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_flow_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool chain_token_to_proto(const std::string& tok, uint8_t& proto);
bool parse_chain_option(const std::string& arg, Ipv6ExtHeaderOptions& out);
bool parse_stop_option(const std::string& arg, Ipv6ExtHeaderOptions& out);

#endif
