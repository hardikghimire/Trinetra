#ifndef DISCOVER_HPP
#define DISCOVER_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace discover {

struct Country {
    const char* iso2;
    const char* iso3;
    const char* name;
    const char* aliases;
};

struct CountryMatch {
    enum class How { None, Exact, Prefix, Fuzzy };
    const Country*                country = nullptr;
    How                           how     = How::None;
    std::vector<const Country*>   suggestions;
};

CountryMatch resolve_country(const std::string& input);
size_t country_count();

enum class Mode { None, AsnList, Ranges, ReverseIp, AsnRoutes };

struct Options {
    Mode        mode = Mode::None;
    std::string country;
    std::string org;
    bool        owner = false;
    std::string owner_name;
    bool        want_v4 = true;
    bool        want_v6 = true;
    std::string ip;
    std::string range;
    std::string asn;
    int         connect_timeout_sec = 10;
    int         total_timeout_sec   = 60;
    bool        verbose = false;
    std::string output_file;
    int         dns_timeout_ms  = 2500;
    int         dns_concurrency = 8;
    bool        owner_ptr_fallback = false;
    std::vector<std::string> dns_servers;
};

int run(const Options& opts);

}

#endif
