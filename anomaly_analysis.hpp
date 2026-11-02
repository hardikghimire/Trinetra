#ifndef ANOMALY_ANALYSIS_HPP
#define ANOMALY_ANALYSIS_HPP

#include <vector>
#include <unordered_map>
#include <cstdint>
#include "scan.hpp"   

void display_ttl_analysis(const std::vector<std::pair<int,double>>& rtt_entries,
                          uint8_t sent_ttl,
                          uint8_t received_ttl,
                          const char* dest_ip,
                          bool dest_responded);
void display_wsn_analysis(const std::unordered_map<uint16_t, PacketDetails>& packet_details,
                          uint8_t sent_ws,
                          const char* dest_ip);

#endif
