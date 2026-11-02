#include <chrono>
#include <mutex>
#include "public_db.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <regex>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cctype>
#include <chrono>
#include <ctime>
#include "utils.hpp"
using json = nlohmann::json;


bool resolve_domain_to_ip(const std::string& domain, std::string& out_ip);

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string cyan    = "\033[96m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string green   = "\033[92m";
    const std::string white   = "\033[97m";
    const std::string dim     = "\033[90m";
    const std::string red     = "\033[91m";
    const std::string green_yellow = "\033[38;5;154m";
    const std::string orange = "\033[38;5;214m";
}

int curl_abort_progress_callback(void* , curl_off_t, curl_off_t,
                                  curl_off_t, curl_off_t) {
    return terminate_flag.load(std::memory_order_relaxed) ? 1 : 0;
}

std::string fetch_shodan_info(const std::string& ip_address) {

    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    bool is_valid_ip = false;
    if (inet_pton(AF_INET, ip_address.c_str(), &(sa.sin_addr)) == 1) {
        is_valid_ip = true;
    }
    else if (inet_pton(AF_INET6, ip_address.c_str(), &(sa6.sin6_addr)) == 1) {
        is_valid_ip = true;
    }
    
    if (!is_valid_ip) {
        return ""; 
    }
    std::string url = "https://internetdb.shodan.io/" + ip_address;
    
    CURL* curl = curl_easy_init();
    std::string response;
    if (!curl) {
        return "";
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "shiv/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);                              
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, curl_abort_progress_callback); 
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return "";
    }
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code >= 300 && response_code < 400) {
        curl_easy_cleanup(curl);
        return ""; 
    }
    
    curl_easy_cleanup(curl);
    return response;
}

void display_shodan_info(const std::string& json_data, const std::string& ip_address) {
    if (json_data.empty()) {
        std::cout << "\n" << color::yellow << "[!] No Shodan data available for " << ip_address << color::reset << std::endl;
        return;
    }

    const int width = 62;

    auto print_heading = [&](const std::string& text) {
        std::cout << "\n" << color::bold << color::cyan << text << color::reset << "\n";
        std::cout << color::dim << std::string(width, '=') << color::reset << "\n";
    };

    auto print_subheading = [&](const std::string& text, const std::string& text_color = color::bold) {
        std::cout << "\n" << text_color << text << color::reset << "\n";
        std::cout << color::dim << std::string(width, '-') << color::reset << "\n";
    };

    auto print_kv = [&](const std::string& key, const std::string& value, const std::string& value_color = "") {
        std::cout << "  " << std::left << std::setw(14) << key << " : "
                   << (value_color.empty() ? "" : value_color) << value
                   << (value_color.empty() ? "" : color::reset) << "\n";
    };

    // Prints a list of items in clean, aligned columns (no tree glyphs)
    auto print_list = [&](const std::vector<std::string>& items, const std::string& item_color = "") {
        if (items.empty()) return;

        int num_columns = 1;
        if (items.size() > 30)      num_columns = 4;
        else if (items.size() > 20) num_columns = 3;
        else if (items.size() > 10) num_columns = 2;

        size_t items_per_column = (items.size() + num_columns - 1) / num_columns;
        std::vector<size_t> col_widths(num_columns, 0);
        for (int col = 0; col < num_columns; col++) {
            for (size_t row = 0; row < items_per_column; row++) {
                size_t index = row + col * items_per_column;
                if (index < items.size())
                    col_widths[col] = std::max(col_widths[col], items[index].size());
            }
        }

        for (size_t row = 0; row < items_per_column; row++) {
            std::cout << "  ";
            for (int col = 0; col < num_columns; col++) {
                size_t index = row + col * items_per_column;
                if (index < items.size()) {
                    std::cout << (item_color.empty() ? "" : item_color)
                               << std::left << std::setw((int)col_widths[col] + 3) << items[index]
                               << (item_color.empty() ? "" : color::reset);
                }
            }
            std::cout << "\n";
        }
    };

    try {
        auto data = json::parse(json_data);

        print_heading("SHODAN INTELLIGENCE REPORT : " + ip_address);

        // Network Information
        print_subheading("Network Information");
        print_kv("IP Address", ip_address, color::cyan);

        bool has_network_info = false;
        if (data.find("asn") != data.end() && !data["asn"].is_null()) {
            print_kv("ASN", data["asn"].get<std::string>());
            has_network_info = true;
        }

        std::string org_str = "";
        if (data.find("org") != data.end() && !data["org"].is_null()) {
            org_str = data["org"].get<std::string>();
            if (org_str.length() > 40) org_str = org_str.substr(0, 37) + "...";
            print_kv("Organization", org_str, color::yellow);
            has_network_info = true;
        }

        if (data.find("country") != data.end() && !data["country"].is_null()) {
            print_kv("Country", data["country"].get<std::string>());
            has_network_info = true;
        }

        if (data.find("city") != data.end() && !data["city"].is_null()) {
            print_kv("City", data["city"].get<std::string>());
            has_network_info = true;
        }

        if (!has_network_info) {
            print_kv("Info", "No additional network info", color::dim);
        }

        // CPEs Section
        if (data.find("cpes") != data.end() && data["cpes"].size() > 0) {
            std::vector<std::string> cpes;
            for (const auto& cpe : data["cpes"]) {
                std::string cpe_str = cpe.get<std::string>();
                if (cpe_str.length() > 40) cpe_str = cpe_str.substr(0, 37) + "...";
                cpes.push_back(cpe_str);
            }
            print_subheading("Software / CPEs (" + std::to_string(cpes.size()) + ")");
            print_list(cpes);
        }

        // Hostnames Section
        if (data.find("hostnames") != data.end() && data["hostnames"].size() > 0) {
            std::vector<std::string> hostnames;
            for (const auto& hostname : data["hostnames"]) {
                std::string host = hostname.get<std::string>();
                if (host.length() > 30) host = host.substr(0, 27) + "...";
                hostnames.push_back(host);
            }
            print_subheading("Hostnames (" + std::to_string(hostnames.size()) + ")");
            print_list(hostnames);
        }

        // Ports Section
        if (data.find("ports") != data.end() && data["ports"].size() > 0) {
            std::vector<std::string> ports;
            for (const auto& port : data["ports"]) {
                ports.push_back(std::to_string(port.get<int>()) + "/tcp");
            }
            print_subheading("Open Ports (" + std::to_string(ports.size()) + ")");
            print_list(ports);
        }

        // Tags Section
        if (data.find("tags") != data.end() && data["tags"].size() > 0) {
            std::vector<std::string> tags;
            for (const auto& tag : data["tags"]) {
                tags.push_back(tag.get<std::string>());
            }
            print_subheading("Tags (" + std::to_string(tags.size()) + ")");
            print_list(tags);
        }

        // Vulnerabilities Section
        if (data.find("vulns") != data.end() && data["vulns"].size() > 0) {
            std::vector<std::string> vulns;
            for (const auto& vuln : data["vulns"]) {
                vulns.push_back(vuln.get<std::string>());
            }
            print_subheading("Vulnerabilities (" + std::to_string(vulns.size()) + ")", color::bold + color::red);
            print_list(vulns, color::red);
        } else {
            print_subheading("Vulnerabilities");
            std::cout << "  " << color::green << "None found" << color::reset << "\n";
        }

        std::cout << "\n" << color::dim << std::string(width, '=') << color::reset << "\n";

    } catch (const json::exception& e) {
        std::cout << "\n" << color::red << "[!] Error parsing Shodan JSON: " << e.what() << color::reset << std::endl;
    } catch (const std::exception& e) {
        std::cout << "\n" << color::red << "[!] Shodan error: " << e.what() << color::reset << std::endl;
    }
}

std::vector<std::string> fetch_subdomains_from_api(const std::string& domain,
                                                    const std::string& api_key) {
    std::vector<std::string> subdomains;
 
    CURL* curl = curl_easy_init();
    if (!curl) return subdomains;
 
    std::string response;
    struct curl_slist* headers = nullptr;
    for (char c : api_key) {
        if (c == '\r' || c == '\n') {
            std::cerr << "fetch_subdomains_from_api: API key contains illegal "
                         "characters (CR/LF) — aborting to prevent header injection\n";
            curl_easy_cleanup(curl);
            return subdomains;
        }
    }
 
    headers = curl_slist_append(headers, ("APIKEY: " + api_key).c_str());
 
    char* escaped = curl_easy_escape(curl, domain.c_str(), 0);
    if (!escaped) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return subdomains;
    }
 
    std::string url =
        "https://api.securitytrails.com/v1/domain/" + std::string(escaped) +
        "/subdomains?children_only=false&include_inactive=true";
    curl_free(escaped);
    struct curl_slist* resolve_list = nullptr;
    std::string api_ip;
    if (resolve_domain_to_ip("api.securitytrails.com", api_ip)) {
        std::string resolve_entry = "api.securitytrails.com:443:" + api_ip;
        resolve_list = curl_slist_append(resolve_list, resolve_entry.c_str());
    }
 
    curl_easy_setopt(curl, CURLOPT_URL,              url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,        headers);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,           resolve_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,     WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,         &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,           10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,    0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,     "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,    1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,    2L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,         0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,         0L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,        0L);                             
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,  curl_abort_progress_callback);    
 
    if (curl_easy_perform(curl) == CURLE_OK) {
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200) {
            try {
                auto data = nlohmann::json::parse(response);
                if (data.contains("subdomains") && data["subdomains"].is_array()) {
                    for (const auto& item : data["subdomains"]) {
                        if (item.is_string()) {
                            subdomains.push_back(item.get<std::string>() + "." + domain);
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "JSON parse error: " << e.what() << std::endl;
            }
        }
    }
 
    curl_slist_free_all(headers);
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
    return subdomains;
}

std::vector<std::string> fetch_subdomains_from_api_no_jq(const std::string& domain,
                                                          const std::string& api_key) {
    std::vector<std::string> subdomains;
 
    std::regex domain_regex("^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$");
    if (!std::regex_match(domain, domain_regex)) {
        std::cerr << "Invalid domain format: " << domain << std::endl;
        return subdomains;
    }
 
    CURL* curl = curl_easy_init();
    if (!curl) return subdomains;
 
    std::string response;
    struct curl_slist* headers = nullptr;
    for (char c : api_key) {
        if (c == '\r' || c == '\n') {
            std::cerr << "fetch_subdomains_from_api_no_jq: API key contains "
                         "illegal characters (CR/LF) — aborting\n";
            curl_easy_cleanup(curl);
            return subdomains;
        }
    }
 
    headers = curl_slist_append(headers, ("APIKEY: " + api_key).c_str());
 
    char* escaped = curl_easy_escape(curl, domain.c_str(), 0);
    if (!escaped) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return subdomains;
    }
 
    std::string url =
        "https://api.securitytrails.com/v1/domain/" + std::string(escaped) +
        "/subdomains?children_only=false&include_inactive=true";
    curl_free(escaped);

    struct curl_slist* resolve_list = nullptr;
    std::string api_ip;
    if (resolve_domain_to_ip("api.securitytrails.com", api_ip)) {
        std::string resolve_entry = "api.securitytrails.com:443:" + api_ip;
        resolve_list = curl_slist_append(resolve_list, resolve_entry.c_str());
    }
 
    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,        resolve_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,2L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,     0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,     0L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,        0L);                             
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,  curl_abort_progress_callback);    
    CURLcode res = curl_easy_perform(curl);
 
    if (res == CURLE_OK) {
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200) {
            try {
                auto data = nlohmann::json::parse(response);
                if (data.contains("subdomains") && data["subdomains"].is_array()) {
                    for (const auto& item : data["subdomains"]) {
                        if (item.is_string()) {
                            std::string sub = item.get<std::string>();
                            if (std::regex_match(sub, domain_regex)) {
                                subdomains.push_back(sub + "." + domain);
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "JSON parse error: " << e.what() << std::endl;
            }
        }
    } else {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
    }
 
    curl_slist_free_all(headers);
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
 
    std::cout << "Found " << subdomains.size() << " subdomains" << std::endl;
    return subdomains;
}


