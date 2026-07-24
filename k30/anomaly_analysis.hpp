#ifndef ANOMALY_ANALYSIS_HPP
#define ANOMALY_ANALYSIS_HPP

#include <vector>
#include <unordered_map>
#include <cstdint>
#include "scan.hpp"   // for PacketDetails

void display_ttl_analysis(const std::vector<std::pair<int,double>>& rtt_entries,
                          uint8_t sent_ttl,
                          uint8_t received_ttl,
                          const char* dest_ip,
                          bool dest_responded);

// dest_ip is now required. Previously the WSN adaptive baseline was a single
// process-wide static history shared across every scanned target, so one
// host's traffic could shift the threshold used to judge a completely
// different host. WSN history is now keyed per destination IP, the same way
// TTL analysis already works -- pass the same IP string used for
// display_ttl_analysis's dest_ip. See anomaly_analysis.cpp for the rest of
// the reasoning.
void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,
                          uint8_t sent_ws,
                          const char* dest_ip);

#endif
