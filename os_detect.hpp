#pragma once

#include "scan.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern bool g_os_detect;

namespace osdetect {

struct Context {
    ScanType scan_type       = ScanType::SYN;
    uint8_t  sent_flags      = TH_SYN;
    uint8_t  sent_ttl        = 0;
    uint16_t sent_window     = 0;
    uint16_t sent_mss        = 0;
    uint8_t  sent_ws         = 0;
    bool     offered_ws      = false;
    bool     offered_sack    = false;
    bool     offered_ts      = false;
    bool     sent_syn        = true;   
    bool     sent_ecn_setup  = false;  
};

struct Candidate {
    std::string name;
    std::string family;
    double      score = 0.0; 
    double      prob  = 0.0;   
};

struct Evidence {
    std::string text;
    double      delta = 0.0;   
};

struct Fingerprint {
    int n_synack = 0;
    int n_rst    = 0;
    int ttl_observed = 0;
    int ttl_init     = 0;
    int hops         = 0;
    bool ttl_plausible = true;
    std::string layout;              
    int  window      = -1;
    int  window_k    = 0;            
    int  mss         = -1;
    int  wscale      = -1;
    int  df          = -1;           
    std::string ipid;               
    std::string isn;                 
    std::string ts;                  
    double ts_hz = 0.0;
    std::string ecn;                
    std::string uptime;              
    std::vector<std::string> quirks;
    double window_consistency = 1.0; 
    double layout_consistency = 1.0; 
};

struct Group {
    std::string label;               
    std::vector<uint16_t> ports;     
    Fingerprint fp;
    std::vector<Candidate> ranked;   
    std::vector<std::pair<std::string, double>> families;  
    std::vector<Evidence> evidence;  
    double      family_prob = 0.0;   
    double      confidence = 0.0;    
    std::string confidence_label;    
    bool        unrecognised = false;
    double      unknown_prob = 0.0;  
    std::string ambiguity;           
};

struct Result {
    bool have_data = false;
    int  samples_total = 0;
    int  n_stacks = 0;              
    std::vector<Group>       groups;
    std::vector<std::string> notes;  
};

Context make_context(ScanType scan_type, const TcpBuildOptions& opts,
                     uint8_t sent_ttl, uint16_t sent_window);
Result analyze(const std::unordered_map<uint16_t, PacketDetails>& packet_details,
               const Context& ctx);
std::string render(const Result& r, const std::string& target_ip, bool verbose = false);
std::string render_json(const Result& r, const std::string& target_ip);

} 
