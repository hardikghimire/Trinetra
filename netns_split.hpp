#pragma once
#include <string>
#include <atomic>
#include <cstdint>


struct SplitNsConfig {
    std::string base_iface;                             
    std::string mac;                                             
    std::string ip_cidr;           
    std::string gateway;           
    std::string ip6_cidr;           
    std::string gateway6;            
    std::string veth_name = "shivmv0";
};

struct SplitFileConf {
    std::string ns_label;          
    std::string mac;         
    std::string ip_addr;     
    std::string ip_prefix;    
    std::string gateway;      
    std::string ip6_addr;     
    std::string ip6_prefix;   
    std::string ip6_gateway;  

};

inline constexpr const char* kDefaultSplitConfPath = "/usr/share/shiv/shiv_split.conf";
bool load_split_conf(const std::string& path, SplitFileConf& out, std::string& err);
bool build_split_ip_cidr(const std::string& ip_addr, const std::string& ip_prefix_field,
                          std::string& cidr_out, std::string& err);
bool build_split_ip6_cidr(const std::string& ip6_addr, const std::string& ip6_prefix_field,
                           std::string& cidr_out, std::string& err);
bool block_outbound_rst(std::string& err);
bool unblock_outbound_rst(std::string& err);

struct RstBlockGuard {
    bool active = false;
    explicit RstBlockGuard(bool enable);
    ~RstBlockGuard();
    RstBlockGuard(const RstBlockGuard&)            = delete;
    RstBlockGuard& operator=(const RstBlockGuard&) = delete;
};

bool enter_split_namespace(const SplitNsConfig& cfg, std::string& err);
extern std::atomic<bool> g_in_split_ns;
extern std::atomic<uint64_t> g_split_ns_entered_at_ms;
