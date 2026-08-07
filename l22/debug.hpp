#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include "scan.hpp"

extern std::mutex cout_mutex;
void print_rtt_debug(const std::vector<std::pair<int, double>>& entries);
void print_demux_debug(const std::string& target_ip,
                        const std::vector<DemuxDebugEntry>& entries,
                        const DemuxDebugCounters& counts,
                        const std::vector<uint16_t>& open_ports);

void print_strack_debug(const std::string& target_ip,
                         const std::vector<StrackEntry>& entries,
                         const StrackCounters& counts);
