#ifndef PUBLIC_DB_HPP
#define PUBLIC_DB_HPP

#include <locale>
#include <string>
#include "public_db.hpp"
#include <curl/curl.h>                 
#include <nlohmann/json.hpp>           
#include <iostream>
#include <vector>
#include <atomic>

extern std::atomic<bool> terminate_flag;
std::string fetch_shodan_info(const std::string& ip_address);
void display_shodan_info(const std::string& json_data, const std::string& ip_address);

std::vector<std::string> fetch_subdomains_from_api(const std::string& domain, const std::string& api_key);
std::vector<std::string> fetch_subdomains_from_api_no_jq(const std::string& domain, const std::string& api_key);

#endif

