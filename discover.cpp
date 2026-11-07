#include "discover.hpp"
#include <curl/curl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern std::atomic<bool> terminate_flag;
extern std::vector<std::string> g_dns_servers;

namespace discover {

static const Country kCountries[] = {
    {"AF","AFG","Afghanistan",""},
    {"AL","ALB","Albania",""},
    {"DZ","DZA","Algeria",""},
    {"AD","AND","Andorra",""},
    {"AO","AGO","Angola",""},
    {"AG","ATG","Antigua and Barbuda","antigua|barbuda"},
    {"AR","ARG","Argentina",""},
    {"AM","ARM","Armenia",""},
    {"AU","AUS","Australia",""},
    {"AT","AUT","Austria",""},
    {"AZ","AZE","Azerbaijan",""},
    {"BS","BHS","Bahamas","the bahamas"},
    {"BH","BHR","Bahrain",""},
    {"BD","BGD","Bangladesh",""},
    {"BB","BRB","Barbados",""},
    {"BY","BLR","Belarus","byelorussia"},
    {"BE","BEL","Belgium",""},
    {"BZ","BLZ","Belize",""},
    {"BJ","BEN","Benin",""},
    {"BT","BTN","Bhutan",""},
    {"BO","BOL","Bolivia","plurinational state of bolivia"},
    {"BA","BIH","Bosnia and Herzegovina","bosnia|herzegovina|bosnia herzegovina"},
    {"BW","BWA","Botswana",""},
    {"BR","BRA","Brazil","brasil"},
    {"BN","BRN","Brunei","brunei darussalam"},
    {"BG","BGR","Bulgaria",""},
    {"BF","BFA","Burkina Faso",""},
    {"BI","BDI","Burundi",""},
    {"CV","CPV","Cabo Verde","cape verde"},
    {"KH","KHM","Cambodia","kampuchea"},
    {"CM","CMR","Cameroon",""},
    {"CA","CAN","Canada",""},
    {"CF","CAF","Central African Republic","car"},
    {"TD","TCD","Chad",""},
    {"CL","CHL","Chile",""},
    {"CN","CHN","China","prc|peoples republic of china|mainland china"},
    {"CO","COL","Colombia",""},
    {"KM","COM","Comoros",""},
    {"CG","COG","Congo","republic of the congo|congo brazzaville|congo republic"},
    {"CD","COD","Democratic Republic of the Congo","drc|dr congo|congo kinshasa|congo democratic republic|zaire"},
    {"CR","CRI","Costa Rica",""},
    {"CI","CIV","Cote d'Ivoire","ivory coast|cote divoire"},
    {"HR","HRV","Croatia",""},
    {"CU","CUB","Cuba",""},
    {"CY","CYP","Cyprus",""},
    {"CZ","CZE","Czechia","czech republic"},
    {"DK","DNK","Denmark",""},
    {"DJ","DJI","Djibouti",""},
    {"DM","DMA","Dominica",""},
    {"DO","DOM","Dominican Republic","dominicana"},
    {"EC","ECU","Ecuador",""},
    {"EG","EGY","Egypt",""},
    {"SV","SLV","El Salvador",""},
    {"GQ","GNQ","Equatorial Guinea",""},
    {"ER","ERI","Eritrea",""},
    {"EE","EST","Estonia",""},
    {"SZ","SWZ","Eswatini","swaziland"},
    {"ET","ETH","Ethiopia",""},
    {"FJ","FJI","Fiji",""},
    {"FI","FIN","Finland",""},
    {"FR","FRA","France",""},
    {"GA","GAB","Gabon",""},
    {"GM","GMB","Gambia","the gambia"},
    {"GE","GEO","Georgia","sakartvelo"},
    {"DE","DEU","Germany","deutschland"},
    {"GH","GHA","Ghana",""},
    {"GR","GRC","Greece","hellas"},
    {"GD","GRD","Grenada",""},
    {"GT","GTM","Guatemala",""},
    {"GN","GIN","Guinea",""},
    {"GW","GNB","Guinea-Bissau","guinea bissau"},
    {"GY","GUY","Guyana",""},
    {"HT","HTI","Haiti",""},
    {"HN","HND","Honduras",""},
    {"HU","HUN","Hungary",""},
    {"IS","ISL","Iceland",""},
    {"IN","IND","India","bharat"},
    {"ID","IDN","Indonesia",""},
    {"IR","IRN","Iran","islamic republic of iran|persia"},
    {"IQ","IRQ","Iraq",""},
    {"IE","IRL","Ireland","eire|republic of ireland"},
    {"IL","ISR","Israel",""},
    {"IT","ITA","Italy","italia"},
    {"JM","JAM","Jamaica",""},
    {"JP","JPN","Japan","nippon"},
    {"JO","JOR","Jordan",""},
    {"KZ","KAZ","Kazakhstan",""},
    {"KE","KEN","Kenya",""},
    {"KI","KIR","Kiribati",""},
    {"KW","KWT","Kuwait",""},
    {"KG","KGZ","Kyrgyzstan","kirghizia|kyrgyz republic"},
    {"LA","LAO","Laos","lao|lao pdr|lao peoples democratic republic"},
    {"LV","LVA","Latvia",""},
    {"LB","LBN","Lebanon",""},
    {"LS","LSO","Lesotho",""},
    {"LR","LBR","Liberia",""},
    {"LY","LBY","Libya",""},
    {"LI","LIE","Liechtenstein",""},
    {"LT","LTU","Lithuania",""},
    {"LU","LUX","Luxembourg",""},
    {"MG","MDG","Madagascar",""},
    {"MW","MWI","Malawi",""},
    {"MY","MYS","Malaysia",""},
    {"MV","MDV","Maldives",""},
    {"ML","MLI","Mali",""},
    {"MT","MLT","Malta",""},
    {"MH","MHL","Marshall Islands",""},
    {"MR","MRT","Mauritania",""},
    {"MU","MUS","Mauritius",""},
    {"MX","MEX","Mexico",""},
    {"FM","FSM","Micronesia","federated states of micronesia"},
    {"MD","MDA","Moldova","republic of moldova"},
    {"MC","MCO","Monaco",""},
    {"MN","MNG","Mongolia",""},
    {"ME","MNE","Montenegro",""},
    {"MA","MAR","Morocco",""},
    {"MZ","MOZ","Mozambique",""},
    {"MM","MMR","Myanmar","burma"},
    {"NA","NAM","Namibia",""},
    {"NR","NRU","Nauru",""},
    {"NP","NPL","Nepal",""},
    {"NL","NLD","Netherlands","holland|the netherlands"},
    {"NZ","NZL","New Zealand","aotearoa"},
    {"NI","NIC","Nicaragua",""},
    {"NE","NER","Niger",""},
    {"NG","NGA","Nigeria",""},
    {"KP","PRK","North Korea","dprk|democratic peoples republic of korea|korea north|n korea"},
    {"MK","MKD","North Macedonia","macedonia"},
    {"NO","NOR","Norway",""},
    {"OM","OMN","Oman",""},
    {"PK","PAK","Pakistan",""},
    {"PW","PLW","Palau",""},
    {"PA","PAN","Panama",""},
    {"PG","PNG","Papua New Guinea",""},
    {"PY","PRY","Paraguay",""},
    {"PE","PER","Peru",""},
    {"PH","PHL","Philippines","the philippines"},
    {"PL","POL","Poland",""},
    {"PT","PRT","Portugal",""},
    {"QA","QAT","Qatar",""},
    {"RO","ROU","Romania",""},
    {"RU","RUS","Russia","russian federation"},
    {"RW","RWA","Rwanda",""},
    {"KN","KNA","Saint Kitts and Nevis","st kitts and nevis|saint kitts|st kitts|st christopher|kitts and nevis"},
    {"LC","LCA","Saint Lucia","st lucia"},
    {"VC","VCT","Saint Vincent and the Grenadines","st vincent and the grenadines|saint vincent|st vincent|grenadines"},
    {"WS","WSM","Samoa",""},
    {"SM","SMR","San Marino",""},
    {"ST","STP","Sao Tome and Principe","sao tome|sao tome e principe"},
    {"SA","SAU","Saudi Arabia","ksa"},
    {"SN","SEN","Senegal",""},
    {"RS","SRB","Serbia",""},
    {"SC","SYC","Seychelles",""},
    {"SL","SLE","Sierra Leone",""},
    {"SG","SGP","Singapore",""},
    {"SK","SVK","Slovakia","slovak republic"},
    {"SI","SVN","Slovenia",""},
    {"SB","SLB","Solomon Islands",""},
    {"SO","SOM","Somalia",""},
    {"ZA","ZAF","South Africa","rsa"},
    {"KR","KOR","South Korea","republic of korea|korea south|s korea|rok"},
    {"SS","SSD","South Sudan",""},
    {"ES","ESP","Spain","espana"},
    {"LK","LKA","Sri Lanka","ceylon"},
    {"SD","SDN","Sudan",""},
    {"SR","SUR","Suriname",""},
    {"SE","SWE","Sweden",""},
    {"CH","CHE","Switzerland","swiss"},
    {"SY","SYR","Syria","syrian arab republic"},
    {"TJ","TJK","Tajikistan",""},
    {"TZ","TZA","Tanzania","united republic of tanzania"},
    {"TH","THA","Thailand","siam"},
    {"TL","TLS","Timor-Leste","east timor|timor leste"},
    {"TG","TGO","Togo",""},
    {"TO","TON","Tonga",""},
    {"TT","TTO","Trinidad and Tobago","trinidad|tobago"},
    {"TN","TUN","Tunisia",""},
    {"TR","TUR","Turkiye","turkey"},
    {"TM","TKM","Turkmenistan",""},
    {"TV","TUV","Tuvalu",""},
    {"UG","UGA","Uganda",""},
    {"UA","UKR","Ukraine",""},
    {"AE","ARE","United Arab Emirates","uae|emirates"},
    {"GB","GBR","United Kingdom","uk|britain|great britain|united kingdom of great britain and northern ireland"},
    {"US","USA","United States","usa|america|united states of america|the united states|us of a"},
    {"UY","URY","Uruguay",""},
    {"UZ","UZB","Uzbekistan",""},
    {"VU","VUT","Vanuatu",""},
    {"VE","VEN","Venezuela","bolivarian republic of venezuela"},
    {"VN","VNM","Vietnam","viet nam"},
    {"YE","YEM","Yemen",""},
    {"ZM","ZMB","Zambia",""},
    {"ZW","ZWE","Zimbabwe",""},
    {"VA","VAT","Vatican City","holy see|vatican"},
    {"PS","PSE","Palestine","state of palestine|palestinian territories|palestinian territory"},
    {"TW","TWN","Taiwan","republic of china|chinese taipei|formosa"},
    {"HK","HKG","Hong Kong","hong kong sar"},
    {"MO","MAC","Macao","macau|macao sar"},
    {"XK","XKX","Kosovo",""},
};
static constexpr size_t kCountryCount = sizeof(kCountries) / sizeof(kCountries[0]);
static_assert(kCountryCount == 199, "country table must hold 195 UN members/observers + 4 extras");
size_t country_count() { return kCountryCount; }

namespace {

inline bool is_alnum_ascii(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline char lower_ascii(char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; }

constexpr char kLatin1[65] =
    "AAAAAAACEEEEIIIIDNOOOOO*OUUUUYTs"
    "aaaaaaaceeeeiiiidnooooo/ouuuuyty";

char latin1_base(unsigned char second) {
    if (second < 0x80 || second > 0xBF) return 0;
    const char m = kLatin1[second - 0x80];
    return is_alnum_ascii(static_cast<unsigned char>(m)) ? lower_ascii(m) : 0;
}

template <class F>
void scan_alnum(std::string_view in, F&& emit) {
    for (size_t i = 0; i < in.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (c < 0x80) {
            emit(is_alnum_ascii(c) ? lower_ascii(static_cast<char>(c)) : '\0');
        } else if (c == 0xC3 && i + 1 < in.size() && static_cast<unsigned char>(in[i + 1]) >= 0x80 &&
                   static_cast<unsigned char>(in[i + 1]) <= 0xBF) {
            emit(latin1_base(static_cast<unsigned char>(in[i + 1])));
            ++i;
        } else {
            emit('\0');
        }
    }
}

std::string normalize(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    scan_alnum(in, [&](char c) { if (c) out.push_back(c); });
    return out;
}

void tokenize(std::string_view in, std::vector<std::string>& out) {
    std::string cur;
    scan_alnum(in, [&](char c) {
        if (c) {
            cur.push_back(c);
        } else if (!cur.empty()) {
            out.push_back(std::move(cur));
            cur.clear();
        }
    });
    if (!cur.empty()) out.push_back(std::move(cur));
}

void sanitize_inplace(std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == 0x7F) { ++i; continue; }
        if (c == 0xC2 && i + 1 < s.size()) {
            const unsigned char d = static_cast<unsigned char>(s[i + 1]);
            if (d >= 0x80 && d <= 0x9F) { i += 2; continue; }
        }
        if (c == 0xE2 && i + 2 < s.size()) {
            const unsigned char d = static_cast<unsigned char>(s[i + 1]);
            const unsigned char e = static_cast<unsigned char>(s[i + 2]);
            if ((d == 0x80 && e >= 0xAA && e <= 0xAE) || (d == 0x81 && e >= 0xA6 && e <= 0xA9)) { i += 3; continue; }
        }
        out.push_back(s[i]);
        ++i;
    }
    s.swap(out);
}

constexpr int kEditMax = 64;

int edit_distance(std::string_view a, std::string_view b, int limit) {
    const int la = static_cast<int>(a.size()), lb = static_cast<int>(b.size());
    if (std::abs(la - lb) > limit || la > kEditMax || lb > kEditMax) return limit + 1;
    int r0[kEditMax + 1], r1[kEditMax + 1], r2[kEditMax + 1];
    int* pp = r0;
    int* p = r1;
    int* c = r2;
    for (int j = 0; j <= lb; ++j) p[j] = j;
    for (int i = 1; i <= la; ++i) {
        c[0] = i;
        int row_min = c[0];
        for (int j = 1; j <= lb; ++j) {
            const int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int v = std::min({p[j] + 1, c[j - 1] + 1, p[j - 1] + cost});
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) v = std::min(v, pp[j - 2] + 1);
            c[j] = v;
            row_min = std::min(row_min, v);
        }
        if (row_min > limit) return limit + 1;
        int* t = pp;
        pp = p;
        p = c;
        c = t;
    }
    return p[lb];
}

int approx_sub(std::string_view pat, std::string_view text, int limit) {
    const int m = static_cast<int>(pat.size());
    if (m == 0 || m > kEditMax) return limit + 1;
    int prev[kEditMax + 1], cur[kEditMax + 1];
    for (int i = 0; i <= m; ++i) prev[i] = i;
    int best = prev[m];
    for (size_t j = 0; j < text.size() && best > 0; ++j) {
        cur[0] = 0;
        for (int i = 1; i <= m; ++i) {
            const int cost = (pat[i - 1] == text[j]) ? 0 : 1;
            cur[i] = std::min({prev[i] + 1, cur[i - 1] + 1, prev[i - 1] + cost});
        }
        best = std::min(best, cur[m]);
        std::memcpy(prev, cur, sizeof(int) * static_cast<size_t>(m + 1));
    }
    return best;
}

struct Index {
    std::unordered_map<std::string, const Country*>              exact;
    std::vector<std::pair<std::string, const Country*>>         names;
    const Country*                                              by_iso2[26][26] = {};

    void add(const std::string& key, const Country* c, bool is_name) {
        if (key.empty()) return;
        exact.emplace(key, c);
        if (is_name) names.emplace_back(key, c);
    }

    Index() {
        exact.reserve(kCountryCount * 6);
        names.reserve(kCountryCount * 3);
        for (const Country& c : kCountries) {
            by_iso2[c.iso2[0] - 'A'][c.iso2[1] - 'A'] = &c;
            add(normalize(c.iso2), &c, false);
            add(normalize(c.iso3), &c, false);
            add(normalize(c.name), &c, true);
            std::string_view al(c.aliases);
            while (!al.empty()) {
                size_t bar = al.find('|');
                std::string_view one = al.substr(0, bar);
                add(normalize(one), &c, true);
                if (bar == std::string_view::npos) break;
                al.remove_prefix(bar + 1);
            }
        }
    }
};

const Index& index() {
    static const Index idx;
    return idx;
}

std::string_view trim_sv(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t' || s.back()  == '\r' || s.back()  == '\n')) s.remove_suffix(1);
    return s;
}

void push_unique(std::vector<const Country*>& v, const Country* c) {
    if (std::find(v.begin(), v.end(), c) == v.end()) v.push_back(c);
}

}

CountryMatch resolve_country(const std::string& input) {
    CountryMatch r;
    const Index& idx = index();
    std::string_view raw = trim_sv(input);
    if (raw.size() == 2 && is_alnum_ascii(raw[0]) && is_alnum_ascii(raw[1]) &&
        !(raw[0] >= '0' && raw[0] <= '9') && !(raw[1] >= '0' && raw[1] <= '9')) {
        int a = std::toupper(static_cast<unsigned char>(raw[0])) - 'A';
        int b = std::toupper(static_cast<unsigned char>(raw[1])) - 'A';
        if (const Country* c = idx.by_iso2[a][b]) { r.country = c; r.how = CountryMatch::How::Exact; return r; }
    }

    const std::string n = normalize(raw);
    if (n.empty()) return r;
    if (auto it = idx.exact.find(n); it != idx.exact.end()) {
        r.country = it->second; r.how = CountryMatch::How::Exact; return r;
    }
    std::vector<const Country*> prefix_hits;
    if (n.size() >= 3) {
        for (const auto& [key, c] : idx.names)
            if (key.size() >= n.size() && key.compare(0, n.size(), n) == 0) push_unique(prefix_hits, c);
        if (prefix_hits.size() == 1) { r.country = prefix_hits[0]; r.how = CountryMatch::How::Prefix; return r; }
    }
    if (n.size() >= 4) {
        const int max_d = (n.size() >= 8) ? 2 : 1;
        int best = max_d + 1;
        std::vector<const Country*> best_c;
        for (const auto& [key, c] : idx.names) {
            int d = edit_distance(n, key, max_d);
            if (d > max_d) continue;
            if (d < best) { best = d; best_c.clear(); best_c.push_back(c); }
            else if (d == best) push_unique(best_c, c);
        }
        if (best_c.size() == 1) { r.country = best_c[0]; r.how = CountryMatch::How::Fuzzy; return r; }
    }
    for (const Country* c : prefix_hits) { if (r.suggestions.size() < 8) push_unique(r.suggestions, c); }
    if (n.size() >= 3) {
        for (const auto& [key, c] : idx.names) {
            if (r.suggestions.size() >= 8) break;
            if (key.find(n) != std::string::npos) push_unique(r.suggestions, c);
        }
    }
    if (r.suggestions.size() < 5) {
        std::vector<std::pair<int, const Country*>> scored;
        for (const auto& [key, c] : idx.names) {
            int d = edit_distance(n, key, 3);
            if (d <= 3) scored.emplace_back(d, c);
        }
        std::sort(scored.begin(), scored.end(),
                  [](const auto& x, const auto& y) { return x.first < y.first; });
        for (const auto& [d, c] : scored) {
            (void)d;
            if (r.suggestions.size() >= 5) break;
            push_unique(r.suggestions, c);
        }
    }
    return r;
}

namespace {

__extension__ typedef unsigned __int128 u128;

using V4 = std::pair<uint32_t, uint32_t>;
struct V6 { u128 lo, hi; };

bool parse_u64(std::string_view s, uint64_t& out) {
    if (s.empty()) return false;
    auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

bool parse_v4_addr(std::string_view s, uint32_t& host) {
    if (s.empty() || s.size() > 15) return false;
    char buf[16];
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    in_addr a{};
    if (inet_pton(AF_INET, buf, &a) != 1) return false;
    host = ntohl(a.s_addr);
    return true;
}

bool parse_v6_addr(std::string_view s, u128& host) {
    if (s.empty() || s.size() > 45) return false;
    char buf[48];
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    in6_addr a{};
    if (inet_pton(AF_INET6, buf, &a) != 1) return false;
    u128 v = 0;
    for (int i = 0; i < 16; ++i) v = (v << 8) | a.s6_addr[i];
    host = v;
    return true;
}

V4 v4_from_prefix(uint32_t base, unsigned len) {
    uint32_t mask = 0xFFFFFFFFu << (32 - len);
    uint32_t lo = base & mask;
    return {lo, lo | ~mask};
}

V6 v6_from_prefix(u128 base, unsigned len) {
    u128 host_mask = (static_cast<u128>(1) << (128 - len)) - 1;
    u128 lo = base & ~host_mask;
    return {lo, lo | host_mask};
}

bool parse_v4_cidr(std::string_view s, V4& out) {
    size_t slash = s.find('/');
    if (slash == std::string_view::npos) return false;
    uint32_t base;
    uint64_t len;
    if (!parse_v4_addr(s.substr(0, slash), base)) return false;
    if (!parse_u64(s.substr(slash + 1), len) || len < 1 || len > 32) return false;
    out = v4_from_prefix(base, static_cast<unsigned>(len));
    return true;
}

bool parse_v6_cidr(std::string_view s, V6& out) {
    size_t slash = s.find('/');
    if (slash == std::string_view::npos) return false;
    u128 base;
    uint64_t len;
    if (!parse_v6_addr(s.substr(0, slash), base)) return false;
    if (!parse_u64(s.substr(slash + 1), len) || len < 1 || len > 128) return false;
    out = v6_from_prefix(base, static_cast<unsigned>(len));
    return true;
}

int ctz128(u128 x) {
    uint64_t lo = static_cast<uint64_t>(x);
    return lo ? __builtin_ctzll(lo) : 64 + __builtin_ctzll(static_cast<uint64_t>(x >> 64));
}
int floor_log2_128(u128 x) {
    uint64_t hi = static_cast<uint64_t>(x >> 64);
    return hi ? 127 - __builtin_clzll(hi) : 63 - __builtin_clzll(static_cast<uint64_t>(x));
}

std::vector<V4> merge_v4(std::vector<V4> v) {
    std::sort(v.begin(), v.end());
    std::vector<V4> out;
    out.reserve(v.size());
    for (const V4& iv : v) {
        if (!out.empty() && static_cast<uint64_t>(iv.first) <= static_cast<uint64_t>(out.back().second) + 1)
            out.back().second = std::max(out.back().second, iv.second);
        else
            out.push_back(iv);
    }
    return out;
}

std::vector<V6> merge_v6(std::vector<V6> v) {
    std::sort(v.begin(), v.end(), [](const V6& a, const V6& b) { return a.lo < b.lo; });
    std::vector<V6> out;
    out.reserve(v.size());
    const u128 kMax = ~static_cast<u128>(0);
    for (const V6& iv : v) {
        if (!out.empty() && (out.back().hi == kMax || iv.lo <= out.back().hi + 1))
            out.back().hi = std::max(out.back().hi, iv.hi);
        else
            out.push_back(iv);
    }
    return out;
}

size_t emit_v4(V4 iv, std::string* out, std::vector<std::pair<std::string, uint32_t>>* samples = nullptr) {
    size_t lines = 0;
    uint64_t cur = iv.first, end = iv.second;
    char ip[INET_ADDRSTRLEN];
    while (cur <= end) {
        const uint64_t remaining = end - cur + 1;
        const uint64_t align = cur ? (cur & (~cur + 1)) : (1ULL << 32);
        const uint64_t fit   = 1ULL << (63 - __builtin_clzll(remaining));
        const uint64_t size  = std::min(align, fit);
        const unsigned prefix = 32 - static_cast<unsigned>(__builtin_ctzll(size));
        in_addr a{};
        a.s_addr = htonl(static_cast<uint32_t>(cur));
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        if (out) {
            *out += ip;
            *out += '/';
            *out += std::to_string(prefix);
            *out += '\n';
        }
        if (samples) {
            const uint32_t sample = static_cast<uint32_t>(cur + (size > 1 ? 1 : 0));
            samples->emplace_back(std::string(ip) + "/" + std::to_string(prefix), sample);
        }
        ++lines;
        cur += size;
    }
    return lines;
}

size_t emit_v6(V6 iv, std::string* out, std::vector<std::pair<std::string, u128>>* samples = nullptr) {
    size_t lines = 0;
    char ip[INET6_ADDRSTRLEN];
    const u128 kMax = ~static_cast<u128>(0);
    u128 cur = iv.lo;
    const u128 end = iv.hi;
    for (;;) {
        int take;
        if (cur == 0 && end == kMax) {
            take = 128;
        } else {
            const u128 remaining = end - cur + 1;
            const int align = (cur == 0) ? 128 : ctz128(cur);
            const int fit   = floor_log2_128(remaining);
            take = std::min(align, fit);
        }
        in6_addr a{};
        for (int i = 0; i < 16; ++i) a.s6_addr[i] = static_cast<uint8_t>(cur >> (8 * (15 - i)));
        inet_ntop(AF_INET6, &a, ip, sizeof(ip));
        if (out) {
            *out += ip;
            *out += '/';
            *out += std::to_string(128 - take);
            *out += '\n';
        }
        if (samples) {
            const u128 sample = cur + (take > 0 ? static_cast<u128>(1) : static_cast<u128>(0));
            samples->emplace_back(std::string(ip) + "/" + std::to_string(128 - take), sample);
        }
        ++lines;
        if (take >= 128) break;
        const u128 step = static_cast<u128>(1) << take;
        if (end - cur < step) break;
        cur += step;
        if (cur > end || cur == 0) break;
    }
    return lines;
}

}

namespace {

constexpr size_t kMaxOwnerLookups = 20000;
constexpr size_t kBulkChunkSize   = 500;
constexpr int    kCymruWhoisPort  = 43;

std::vector<std::string> owner_system_resolvers() {
    std::vector<std::string> out;
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (f && std::getline(f, line)) {
        if (line.rfind("nameserver", 0) == 0) {
            std::istringstream ss(line);
            std::string tok, ip;
            ss >> tok >> ip;
            if (!ip.empty()) out.push_back(ip);
        }
    }
    if (out.empty()) { out.push_back("1.1.1.1"); out.push_back("8.8.8.8"); }
    return out;
}

std::string trim_field(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> split_pipe(const std::string& line) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t p = line.find('|', start);
        out.push_back(trim_field(line.substr(start, p == std::string::npos ? std::string::npos : p - start)));
        if (p == std::string::npos) break;
        start = p + 1;
    }
    return out;
}

size_t decode_dns_name(const uint8_t* buf, size_t len, size_t pos, std::string& out) {
    out.clear();
    size_t cur = pos;
    size_t after_first_jump = std::string::npos;
    int jumps = 0;
    while (cur < len) {
        uint8_t c = buf[cur];
        if (c == 0) { cur += 1; break; }
        if ((c & 0xC0) == 0xC0) {
            if (cur + 1 >= len || ++jumps > 20) return len;
            size_t ptr = (static_cast<size_t>(c & 0x3F) << 8) | buf[cur + 1];
            if (after_first_jump == std::string::npos) after_first_jump = cur + 2;
            cur = ptr;
            continue;
        }
        size_t label_len = c;
        cur += 1;
        if (cur + label_len > len) return len;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char*>(buf + cur), label_len);
        cur += label_len;
    }
    return (after_first_jump != std::string::npos) ? after_first_jump : cur;
}

std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& qname, uint16_t qtype) {
    std::vector<uint8_t> pkt;
    pkt.reserve(qname.size() + 18);
    auto put16 = [&](uint16_t v) { uint16_t n = htons(v); pkt.push_back(static_cast<uint8_t>(n & 0xFF)); pkt.push_back(static_cast<uint8_t>(n >> 8)); };
    pkt.push_back(static_cast<uint8_t>(id >> 8)); pkt.push_back(static_cast<uint8_t>(id & 0xFF));
    put16(0x0100);
    put16(1); put16(0); put16(0); put16(0);
    size_t start = 0;
    while (start <= qname.size()) {
        size_t dot = qname.find('.', start);
        size_t end = (dot == std::string::npos) ? qname.size() : dot;
        size_t label_len = end - start;
        if (label_len > 63) return {};
        pkt.push_back(static_cast<uint8_t>(label_len));
        pkt.insert(pkt.end(), qname.begin() + start, qname.begin() + end);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt.push_back(0);
    put16(qtype);
    put16(1);
    return pkt;
}

bool parse_dns_answer(const uint8_t* buf, size_t len, uint16_t want_type,
                       size_t answers_start, uint16_t ancount, std::string& out) {
    size_t pos = answers_start;
    for (uint16_t i = 0; i < ancount; ++i) {
        std::string name;
        pos = decode_dns_name(buf, len, pos, name);
        if (pos + 10 > len) return false;
        uint16_t rtype, rdlen;
        memcpy(&rtype, buf + pos, 2); rtype = ntohs(rtype); pos += 2;
        pos += 2;
        pos += 4;
        memcpy(&rdlen, buf + pos, 2); rdlen = ntohs(rdlen); pos += 2;
        if (pos + rdlen > len) return false;
        if (rtype == want_type) {
            if (want_type == 16) {
                std::string txt;
                size_t p = pos, end = pos + rdlen;
                while (p < end) {
                    uint8_t slen = buf[p++];
                    if (p + slen > end) break;
                    txt.append(reinterpret_cast<const char*>(buf + p), slen);
                    p += slen;
                }
                out = txt;
                return true;
            }
            if (want_type == 12) {
                std::string name2;
                decode_dns_name(buf, len, pos, name2);
                out = name2;
                return true;
            }
        }
        pos += rdlen;
    }
    return false;
}

uint16_t next_dns_id() {
    thread_local std::mt19937 gen{std::random_device{}()};
    return static_cast<uint16_t>(gen());
}

bool udp_dns_query_one(const std::string& server, const std::string& qname, uint16_t qtype,
                        int timeout_ms, std::string& out) {
    sockaddr_storage ss{};
    socklen_t sl = 0;
    int fam = 0;
    in_addr a4{};
    in6_addr a6{};
    if (inet_pton(AF_INET, server.c_str(), &a4) == 1) {
        auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
        sa->sin_family = AF_INET;
        sa->sin_port = htons(53);
        sa->sin_addr = a4;
        sl = sizeof(sockaddr_in);
        fam = AF_INET;
    } else if (inet_pton(AF_INET6, server.c_str(), &a6) == 1) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(53);
        sa->sin6_addr = a6;
        sl = sizeof(sockaddr_in6);
        fam = AF_INET6;
    } else {
        return false;
    }

    const uint16_t id = next_dns_id();
    std::vector<uint8_t> pkt = build_dns_query(id, qname, qtype);
    if (pkt.empty()) return false;

    int fd = socket(fam, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, reinterpret_cast<sockaddr*>(&ss), sl) != 0 ||
        send(fd, pkt.data(), pkt.size(), 0) != static_cast<ssize_t>(pkt.size())) {
        close(fd);
        return false;
    }

    uint8_t buf[2048];
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n < 12) return false;
    const size_t len = static_cast<size_t>(n);

    uint16_t rid;
    std::memcpy(&rid, buf, 2);
    if (ntohs(rid) != id) return false;
    uint16_t rflags;
    std::memcpy(&rflags, buf + 2, 2);
    rflags = ntohs(rflags);
    if ((rflags & 0x000F) != 0) return false;
    uint16_t qdc, anc;
    std::memcpy(&qdc, buf + 4, 2);
    qdc = ntohs(qdc);
    std::memcpy(&anc, buf + 6, 2);
    anc = ntohs(anc);
    if (anc == 0) return false;

    size_t pos = 12;
    for (uint16_t i = 0; i < qdc; ++i) {
        std::string dummy;
        pos = decode_dns_name(buf, len, pos, dummy);
        pos += 4;
        if (pos > len) return false;
    }
    return parse_dns_answer(buf, len, qtype, pos, anc, out);
}

bool udp_dns_query(const std::vector<std::string>& servers, const std::string& qname,
                    uint16_t qtype, int timeout_ms, std::string& out) {
    for (const auto& srv : servers) {
        if (terminate_flag.load(std::memory_order_relaxed)) return false;
        if (udp_dns_query_one(srv, qname, qtype, timeout_ms, out) && !out.empty()) return true;
    }
    return false;
}

std::string ptr_qname_v4(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF)
       << ".in-addr.arpa";
    return ss.str();
}
std::string nibble_reversed_v6(u128 ip) {
    std::ostringstream ss;
    for (int i = 0; i < 32; ++i) ss << std::hex << static_cast<int>((ip >> (i * 4)) & 0xF) << ".";
    return ss.str();
}
std::string ptr_qname_v6(u128 ip) { return nibble_reversed_v6(ip) + "ip6.arpa"; }

std::string v4_to_string(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return buf;
}

std::string v6_to_string(u128 ip) {
    in6_addr a{};
    for (int i = 0; i < 16; ++i) a.s6_addr[15 - i] = static_cast<uint8_t>((ip >> (i * 8)) & 0xFF);
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

int connect_with_timeout(const char* host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char portbuf[8];
    std::snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (getaddrinfo(host, portbuf, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        bool connected = (rc == 0);
        if (!connected && errno == EINPROGRESS) {
            pollfd pfd{fd, POLLOUT, 0};
            if (poll(&pfd, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                connected = (err == 0);
            }
        }
        if (connected) {
            fcntl(fd, F_SETFL, flags);
            timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            freeaddrinfo(res);
            return fd;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

constexpr size_t kMaxWhoisResponse = 8u * 1024 * 1024;
constexpr int    kWhoisDeadlineSec = 30;

bool bulk_cymru_query(const std::vector<std::string>& ip_strings, int timeout_ms,
                       std::unordered_map<std::string, std::string>& out_labels) {
    int fd = connect_with_timeout("whois.cymru.com", kCymruWhoisPort, timeout_ms);
    if (fd < 0) return false;

    std::string req = "begin\nverbose\n";
    for (const auto& s : ip_strings) { req += s; req += '\n'; }
    req += "end\n";

    size_t sent = 0;
    while (sent < req.size()) {
        if (terminate_flag.load(std::memory_order_relaxed)) { close(fd); return false; }
        const ssize_t n = send(fd, req.data() + sent, req.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) { close(fd); return false; }
        sent += static_cast<size_t>(n);
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWhoisDeadlineSec);
    std::string resp;
    char buf[16384];
    for (;;) {
        if (terminate_flag.load(std::memory_order_relaxed)) break;
        if (resp.size() > kMaxWhoisResponse || std::chrono::steady_clock::now() > deadline) break;
        const ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    if (resp.empty()) return false;

    size_t pos = 0;
    bool first = true;
    while (pos < resp.size()) {
        const size_t nl = resp.find('\n', pos);
        std::string line = resp.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? resp.size() : nl + 1;
        if (first) { first = false; continue; }
        if (line.empty()) continue;
        std::vector<std::string> f = split_pipe(line);
        if (f.size() < 7) continue;
        const std::string& asn = f[0];
        if (asn.empty() || asn == "NA") continue;
        std::string name = f[6];
        sanitize_inplace(name);
        out_labels[f[1]] = name.empty() ? ("AS" + asn) : (name + " (AS" + asn + ")");
    }
    return true;
}

void resolve_owners(const std::vector<std::pair<std::string, uint32_t>>& v4_samples,
                     const std::vector<std::pair<std::string, u128>>& v6_samples,
                     const Options& opts,
                     std::vector<std::string>& v4_labels, std::vector<std::string>& v6_labels,
                     size_t& resolved, size_t& attempted) {
    v4_labels.assign(v4_samples.size(), std::string());
    v6_labels.assign(v6_samples.size(), std::string());
    resolved = 0;
    attempted = v4_samples.size() + v6_samples.size();
    if (attempted == 0) return;

    const size_t cap = std::min(attempted, kMaxOwnerLookups);
    if (cap < attempted)
        std::cerr << "[discover] --owner: capped at " << kMaxOwnerLookups << " of " << attempted
                   << " ranges to bound lookup load\n";

    std::vector<std::string> ip_text(cap);
    for (size_t i = 0; i < cap; ++i) {
        ip_text[i] = (i < v4_samples.size()) ? v4_to_string(v4_samples[i].second)
                                              : v6_to_string(v6_samples[i - v4_samples.size()].second);
    }

    std::vector<std::pair<size_t, size_t>> chunks;
    for (size_t start = 0; start < cap; start += kBulkChunkSize)
        chunks.emplace_back(start, std::min(start + kBulkChunkSize, cap));

    const int nworkers = std::max(1, std::min({static_cast<int>(chunks.size()), opts.dns_concurrency, 8}));
    std::atomic<size_t> next_chunk{0};
    std::unordered_map<std::string, std::string> labels;
    labels.reserve(cap);
    std::mutex labels_mu;

    auto worker = [&]() {
        for (;;) {
            size_t ci = next_chunk.fetch_add(1);
            if (ci >= chunks.size() || terminate_flag.load(std::memory_order_relaxed)) return;
            const auto [a, b] = chunks[ci];
            std::vector<std::string> batch(ip_text.begin() + static_cast<long>(a), ip_text.begin() + static_cast<long>(b));
            std::unordered_map<std::string, std::string> local;
            if (bulk_cymru_query(batch, opts.dns_timeout_ms, local)) {
                std::lock_guard<std::mutex> lk(labels_mu);
                for (auto& kv : local) labels.emplace(std::move(kv.first), std::move(kv.second));
            }
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(nworkers);
    for (int t = 0; t < nworkers; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    std::vector<size_t> unresolved;
    for (size_t i = 0; i < cap; ++i) {
        auto it = labels.find(ip_text[i]);
        if (it != labels.end()) {
            if (i < v4_samples.size()) v4_labels[i] = it->second;
            else v6_labels[i - v4_samples.size()] = it->second;
            ++resolved;
        } else if (opts.owner_ptr_fallback) {
            unresolved.push_back(i);
        }
    }

    if (!unresolved.empty() && !terminate_flag.load(std::memory_order_relaxed)) {
        std::vector<std::string> servers = !opts.dns_servers.empty() ? opts.dns_servers
                                          : !g_dns_servers.empty()   ? g_dns_servers
                                                                      : owner_system_resolvers();
        if (!servers.empty()) {
            std::atomic<size_t> uidx{0};
            const int pfworkers = std::max(1, std::min({static_cast<int>(unresolved.size()), opts.dns_concurrency, 8}));
            auto pworker = [&]() {
                for (;;) {
                    size_t k = uidx.fetch_add(1);
                    if (k >= unresolved.size() || terminate_flag.load(std::memory_order_relaxed)) return;
                    size_t i = unresolved[k];
                    std::string ptr;
                    bool ok = (i < v4_samples.size())
                        ? udp_dns_query(servers, ptr_qname_v4(v4_samples[i].second), 12, opts.dns_timeout_ms, ptr)
                        : udp_dns_query(servers, ptr_qname_v6(v6_samples[i - v4_samples.size()].second), 12, opts.dns_timeout_ms, ptr);
                    if (ok && !ptr.empty()) {
                        if (ptr.back() == '.') ptr.pop_back();
                        std::string label = "ptr:" + ptr;
                        if (i < v4_samples.size()) v4_labels[i] = label;
                        else v6_labels[i - v4_samples.size()] = label;
                    }
                }
            };
            std::vector<std::thread> ppool;
            ppool.reserve(pfworkers);
            for (int t = 0; t < pfworkers; ++t) ppool.emplace_back(pworker);
            for (auto& th : ppool) th.join();
            for (size_t i : unresolved) {
                bool got = (i < v4_samples.size()) ? !v4_labels[i].empty() : !v6_labels[i - v4_samples.size()].empty();
                if (got) ++resolved;
            }
        }
    }
}

}

namespace {

enum class Kind { NwDb, ApnicDelegated, RirV4, RirV6 };

struct Job {
    char cc[3] = {0, 0, 0};
    bool want_v4 = true;
    bool want_v6 = true;
};

constexpr size_t kMaxLine         = 8 * 1024;
constexpr size_t kCapStreamBytes  = 128u * 1024 * 1024;
constexpr size_t kCapPageBytes    = 4u * 1024 * 1024;
constexpr size_t kCapAsnPageBytes = 256u * 1024 * 1024;
constexpr size_t kCapReplyBytes   = 8u * 1024 * 1024;

struct Xfer {
    std::string url;
    size_t      cap = kCapPageBytes;
    bool        not_found_ok = false;
    CURL*       easy = nullptr;
    size_t      total_bytes = 0;
    long        http = 0;
    double      secs = 0.0;
    bool        aborted = false;
    const char* abort_reason = nullptr;
    bool        done = false;
    bool        ok = false;
    std::string note;
    std::string body;

    virtual ~Xfer() = default;
    virtual bool on_data(const char* p, size_t n) { body.append(p, n); return true; }
    virtual void on_finish() {}
    virtual void on_fail() { body.clear(); }
    virtual void on_reset() {}

    bool ingest(const char* p, size_t n) {
        total_bytes += n;
        if (total_bytes > cap) { aborted = true; abort_reason = "response too large"; return false; }
        return on_data(p, n);
    }

    void reset() {
        easy = nullptr;
        total_bytes = 0;
        http = 0;
        secs = 0.0;
        aborted = false;
        abort_reason = nullptr;
        done = false;
        ok = false;
        note.clear();
        body.clear();
        on_reset();
    }
};

struct Source : Xfer {
    Kind        kind = Kind::NwDb;
    const char* label = "";
    const Job*  job = nullptr;
    bool        streaming = true;
    std::string buf;
    std::vector<V4> v4;
    std::vector<V6> v6;

    bool on_data(const char* p, size_t n) override;
    void on_finish() override;
    void on_fail() override { v4.clear(); v6.clear(); buf.clear(); }
};

size_t split_pipe(std::string_view line, std::string_view* f, size_t max) {
    size_t n = 0;
    while (n + 1 < max) {
        size_t bar = line.find('|');
        if (bar == std::string_view::npos) break;
        f[n++] = line.substr(0, bar);
        line.remove_prefix(bar + 1);
    }
    f[n++] = line;
    return n;
}

void apnic_line(Source& s, std::string_view line) {
    if (line[0] == '#') return;
    const size_t p1 = line.find('|');
    if (p1 == std::string_view::npos || p1 + 3 >= line.size()) return;
    if (line[p1 + 3] != '|' || line[p1 + 1] != s.job->cc[0] || line[p1 + 2] != s.job->cc[1]) return;

    std::string_view f[8];
    if (split_pipe(line, f, 8) < 7) return;
    if (!(f[6] == "allocated" || f[6] == "assigned")) return;

    if (f[2] == "ipv4") {
        if (!s.job->want_v4) return;
        uint32_t start;
        uint64_t count;
        if (!parse_v4_addr(f[3], start) || !parse_u64(f[4], count) || count == 0) return;
        uint64_t last = static_cast<uint64_t>(start) + count - 1;
        if (last > 0xFFFFFFFFull) return;
        s.v4.emplace_back(start, static_cast<uint32_t>(last));
    } else if (f[2] == "ipv6") {
        if (!s.job->want_v6) return;
        u128 start;
        uint64_t plen;
        if (!parse_v6_addr(f[3], start) || !parse_u64(f[4], plen) || plen < 1 || plen > 128) return;
        s.v6.push_back(v6_from_prefix(start, static_cast<unsigned>(plen)));
    }
}

void rir_line(Source& s, std::string_view line) {
    line = trim_sv(line);
    if (line.empty() || line[0] == '#') return;
    if (s.kind == Kind::RirV4) {
        V4 iv;
        if (parse_v4_cidr(line, iv)) s.v4.push_back(iv);
    } else {
        V6 iv;
        if (parse_v6_cidr(line, iv)) s.v6.push_back(iv);
    }
}

void handle_line(Source& s, std::string_view line) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) return;
    if (s.kind == Kind::ApnicDelegated) apnic_line(s, line);
    else                                rir_line(s, line);
}

bool feed(Source& s, const char* p, size_t len) {
    if (!s.streaming) { s.buf.append(p, len); return true; }

    size_t pos = 0;
    if (!s.buf.empty()) {
        const char* nl = static_cast<const char*>(std::memchr(p, '\n', len));
        if (!nl) {
            if (s.buf.size() + len > kMaxLine) { s.aborted = true; s.abort_reason = "line too long (not a delegation file?)"; return false; }
            s.buf.append(p, len);
            return true;
        }
        const size_t n = static_cast<size_t>(nl - p);
        s.buf.append(p, n);
        handle_line(s, s.buf);
        s.buf.clear();
        pos = n + 1;
    }
    while (pos < len) {
        const char* start = p + pos;
        const char* nl = static_cast<const char*>(std::memchr(start, '\n', len - pos));
        if (!nl) {
            if (len - pos > kMaxLine) { s.aborted = true; s.abort_reason = "line too long (not a delegation file?)"; return false; }
            s.buf.assign(start, len - pos);
            break;
        }
        const size_t n = static_cast<size_t>(nl - start);
        handle_line(s, std::string_view(start, n));
        pos += n + 1;
    }
    return true;
}

void finish(Source& s) {
    if (s.streaming) {
        if (!s.buf.empty()) { handle_line(s, s.buf); s.buf.clear(); }
        return;
    }
    const std::string_view body(s.buf);
    bool country_ok = false;
    for (size_t pos = 0; (pos = body.find("/country/", pos)) != std::string_view::npos; ) {
        pos += 9;
        if (pos + 2 <= body.size() &&
            lower_ascii(body[pos]) == lower_ascii(s.job->cc[0]) &&
            lower_ascii(body[pos + 1]) == lower_ascii(s.job->cc[1]) &&
            (pos + 2 == body.size() || !is_alnum_ascii(static_cast<unsigned char>(body[pos + 2])))) {
            country_ok = true;
            break;
        }
    }
    if (!country_ok) {
        s.note = "page is not attributed to this country (org page of an unrelated entity) - ignored";
        return;
    }

    static constexpr std::string_view kKey = "CIDR:</span>";
    size_t pos = 0;
    while ((pos = body.find(kKey, pos)) != std::string_view::npos) {
        pos += kKey.size();
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n')) ++pos;
        size_t e = pos;
        while (e < body.size() && ((body[e] >= '0' && body[e] <= '9') || body[e] == '.' || body[e] == '/')) ++e;
        V4 iv;
        if (e > pos && parse_v4_cidr(body.substr(pos, e - pos), iv)) s.v4.push_back(iv);
        pos = e;
    }
    s.buf.clear();
    s.buf.shrink_to_fit();
}

bool Source::on_data(const char* p, size_t n) { return feed(*this, p, n); }
void Source::on_finish() { finish(*this); }

#if LIBCURL_VERSION_NUM >= 0x074700
const std::string* cached_ca_bundle() {
    static const std::string bundle = [] {
        const char* path = nullptr;
        curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);
        if (vi && vi->cainfo && vi->cainfo[0]) path = vi->cainfo;
        static const char* fallbacks[] = {
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        };
        std::ifstream f;
        if (path) f.open(path, std::ios::binary);
        for (size_t i = 0; !f.is_open() && i < 3; ++i) f.open(fallbacks[i], std::ios::binary);
        if (!f.is_open()) return std::string();
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }();
    return bundle.empty() ? nullptr : &bundle;
}
#endif

size_t write_cb(char* p, size_t sz, size_t nm, void* ud) {
    auto* x = static_cast<Xfer*>(ud);
    if (terminate_flag.load(std::memory_order_relaxed)) {
        x->aborted = true;
        x->abort_reason = "interrupted";
        return 0;
    }
    const size_t len = sz * nm;
    return x->ingest(p, len) ? len : 0;
}

void configure_easy(Xfer& x, const Options& o, CURLSH* share) {
    CURL* h = x.easy;
    curl_easy_setopt(h, CURLOPT_URL, x.url.c_str());
    curl_easy_setopt(h, CURLOPT_PRIVATE, &x);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &x);

    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(h, CURLOPT_BUFFERSIZE, 262144L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "Shiv-discover/1.0");
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, static_cast<long>(o.connect_timeout_sec));
    curl_easy_setopt(h, CURLOPT_TIMEOUT, static_cast<long>(o.total_timeout_sec));
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, 20L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 3L);
    if (share) curl_easy_setopt(h, CURLOPT_SHARE, share);
#if LIBCURL_VERSION_NUM >= 0x074700
    if (const std::string* bundle = cached_ca_bundle()) {
        curl_blob blob{const_cast<char*>(bundle->data()), bundle->size(), CURL_BLOB_COPY};
        curl_easy_setopt(h, CURLOPT_CAINFO_BLOB, &blob);
    }
#endif
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS));
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS));
#endif
}

CURLMcode wait_multi(CURLM* m, int ms, int* nfds) {
#if LIBCURL_VERSION_NUM >= 0x074200
    return curl_multi_poll(m, nullptr, 0, ms, nfds);
#else
    return curl_multi_wait(m, nullptr, 0, ms, nfds);
#endif
}
std::string nwdb_slug(const char* name) {
    std::string out;
    for (const char* p = name; *p; ++p) {
        unsigned char c = static_cast<unsigned char>(*p);
        if (is_alnum_ascii(c)) out.push_back(lower_ascii(static_cast<char>(c)));
        else if ((c == ' ' || c == '-') && !out.empty() && out.back() != '-') out.push_back('-');
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    return out;
}
bool err_tty() { static const bool t = isatty(STDERR_FILENO) != 0; return t; }
bool out_tty() { static const bool t = isatty(STDOUT_FILENO) != 0; return t; }
const char* col(const char* c) { return err_tty() ? c : ""; }
const char* colo(const char* c) { return out_tty() ? c : ""; }
constexpr const char* kReset = "\033[0m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kYellow = "\033[93m";
constexpr const char* kRed = "\033[91m";
constexpr const char* kBlue = "\033[94m";
constexpr const char* kBold = "\033[1m";

std::string format_time() {
    const std::time_t t = std::time(nullptr);
    std::string s(std::ctime(&t));
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

using ProgressFn = std::function<void(size_t, size_t)>;

int run_transfers(const std::vector<Xfer*>& xs, const Options& o, size_t concurrency, const ProgressFn& progress) {
    if (xs.empty()) return 0;
    CURLM* multi = curl_multi_init();
    if (!multi) return 1;
    CURLSH* share = curl_share_init();
    if (share) {
        curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    }
    if (concurrency == 0) concurrency = 1;
    curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, static_cast<long>(concurrency));

    size_t next = 0, active = 0, finished = 0;

    auto launch = [&]() {
        while (next < xs.size() && active < concurrency) {
            Xfer* x = xs[next++];
            x->easy = curl_easy_init();
            if (!x->easy) {
                x->done = true;
                x->ok = false;
                x->note = "curl_easy_init failed";
                ++finished;
                if (progress) progress(finished, xs.size());
                continue;
            }
            configure_easy(*x, o, share);
            curl_multi_add_handle(multi, x->easy);
            ++active;
            if (o.verbose) std::cerr << "[discover]   GET " << x->url << "\n";
        }
    };

    auto reap = [&]() {
        int left = 0;
        while (CURLMsg* m = curl_multi_info_read(multi, &left)) {
            if (m->msg != CURLMSG_DONE) continue;
            CURL* h = m->easy_handle;
            char* priv = nullptr;
            curl_easy_getinfo(h, CURLINFO_PRIVATE, &priv);
            Xfer* x = reinterpret_cast<Xfer*>(priv);
            const CURLcode rc = m->data.result;
            curl_multi_remove_handle(multi, h);
            if (active > 0) --active;
            ++finished;
            if (x) {
                long http = 0;
                curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &http);
                curl_easy_getinfo(h, CURLINFO_TOTAL_TIME, &x->secs);
                x->http = http;
                x->done = true;
                x->easy = nullptr;
                if (rc == CURLE_OK || (rc == CURLE_HTTP_RETURNED_ERROR && http == 404 && x->not_found_ok)) {
                    x->on_finish();
                    x->ok = x->note.empty();
                } else {
                    x->ok = false;
                    if (x->aborted && x->abort_reason)        x->note = x->abort_reason;
                    else if (rc == CURLE_HTTP_RETURNED_ERROR) x->note = "HTTP " + std::to_string(http);
                    else                                       x->note = curl_easy_strerror(rc);
                    x->on_fail();
                }
            }
            curl_easy_cleanup(h);
            if (progress) progress(finished, xs.size());
        }
    };

    int running = 0;
    while (!terminate_flag.load(std::memory_order_relaxed)) {
        launch();
        curl_multi_perform(multi, &running);
        reap();
        if (active == 0 && next >= xs.size()) break;
        if (next < xs.size() && active < concurrency) continue;
        int nfds = 0;
        if (wait_multi(multi, 200, &nfds) != CURLM_OK) break;
    }

    for (Xfer* x : xs) {
        if (x->easy) {
            curl_multi_remove_handle(multi, x->easy);
            curl_easy_cleanup(x->easy);
            x->easy = nullptr;
        }
    }
    curl_multi_cleanup(multi);
    if (share) curl_share_cleanup(share);
    return terminate_flag.load(std::memory_order_relaxed) ? 130 : 0;
}

struct CurlGlobal {
    bool ok;
    CurlGlobal() : ok(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {}
    ~CurlGlobal() { if (ok) curl_global_cleanup(); }
    CurlGlobal(const CurlGlobal&) = delete;
    CurlGlobal& operator=(const CurlGlobal&) = delete;
};

void save_file(const Options& o, const std::string& text) {
    if (o.output_file.empty()) return;
    std::ofstream f(o.output_file, std::ios::binary | std::ios::trunc);
    if (!f) {
        std::cerr << col(kRed) << "[discover] cannot write '" << o.output_file << "'" << col(kReset) << "\n";
        return;
    }
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    std::cerr << "[discover] saved  : " << o.output_file << "\n";
}

void write_out(const Options& o, const std::string& text) {
    std::cout.write(text.data(), static_cast<std::streamsize>(text.size()));
    std::cout.flush();
    save_file(o, text);
}

bool pick_country(const std::string& input, const Country*& out, CountryMatch::How& how) {
    CountryMatch m = resolve_country(input);
    if (!m.country) {
        std::cerr << col(kRed) << "[discover] unknown country '" << input << "'" << col(kReset) << "\n";
        if (!m.suggestions.empty()) {
            std::cerr << "[discover] did you mean:\n";
            for (const Country* c : m.suggestions)
                std::cerr << "             " << c->name << "  (" << c->iso2 << ")\n";
        } else {
            std::cerr << "[discover] use a country name (\"nepal\", \"south korea\") or an ISO code (NP, NPL).\n";
        }
        return false;
    }
    out = m.country;
    how = m.how;
    return true;
}

void print_country_line(const Country& country, CountryMatch::How how, const std::string& input) {
    std::cerr << col(kBold) << "[discover] country : " << country.name << " (" << country.iso2 << ")" << col(kReset);
    if (how == CountryMatch::How::Prefix) std::cerr << "   <- '" << input << "' matched by prefix";
    if (how == CountryMatch::How::Fuzzy)  std::cerr << "   <- '" << input << "' corrected to closest name";
    std::cerr << "\n";
}

std::string pad_right(const std::string& s, size_t w) {
    std::string out = s;
    if (out.size() < w) out.append(w - out.size(), ' ');
    return out;
}

}

namespace {

struct Cleaned {
    std::vector<std::string> tokens;
    std::string compact;
};

constexpr std::string_view kNoise[] = {
    "ag", "and", "bhd", "bv", "co", "company", "corp", "corporation", "gmbh", "inc", "incorporated",
    "limited", "llc", "llp", "ltd", "of", "plc", "private", "pte", "pty", "pvt", "sa", "sdn", "the"
};

bool is_noise(std::string_view t) {
    return std::binary_search(std::begin(kNoise), std::end(kNoise), t);
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

std::string_view strip_owner_suffixes(std::string_view s) {
    s = trim_sv(s);
    if (!s.empty() && s.back() == ')') {
        const size_t p = s.rfind("(AS");
        if (p != std::string_view::npos && s.size() >= p + 4 && all_digits(s.substr(p + 3, s.size() - p - 4)))
            s = trim_sv(s.substr(0, p));
    }
    const size_t comma = s.rfind(',');
    if (comma != std::string_view::npos) {
        const std::string_view cc = trim_sv(s.substr(comma + 1));
        if (cc.size() == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z')
            s = s.substr(0, comma);
    }
    return s;
}

struct OwnerLabelParts {
    std::string_view org;
    std::string_view country;
    std::string_view asn_digits;
};

OwnerLabelParts split_owner_label(std::string_view s) {
    OwnerLabelParts out;
    s = trim_sv(s);
    if (!s.empty() && s.back() == ')') {
        const size_t p = s.rfind("(AS");
        if (p != std::string_view::npos && s.size() >= p + 4 && all_digits(s.substr(p + 3, s.size() - p - 4))) {
            out.asn_digits = s.substr(p + 3, s.size() - p - 4);
            s = trim_sv(s.substr(0, p));
        }
    }
    const size_t comma = s.rfind(',');
    if (comma != std::string_view::npos) {
        const std::string_view cc = trim_sv(s.substr(comma + 1));
        if (cc.size() == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z') {
            out.country = cc;
            s = trim_sv(s.substr(0, comma));
        }
    }
    out.org = s;
    return out;
}

struct OwnerRow {
    std::string asn, range, country, org;
};

void collect_owner_rows(const std::vector<std::pair<std::string, uint32_t>>& v4_samples,
                        const std::vector<std::string>& v4_labels,
                        const std::vector<std::pair<std::string, u128>>& v6_samples,
                        const std::vector<std::string>& v6_labels,
                        const std::vector<char>* keep4, const std::vector<char>* keep6,
                        std::vector<OwnerRow>& rows) {
    auto add = [&](const std::string& range, const std::string& label) {
        OwnerRow r;
        r.range = range;
        if (!label.empty()) {
            const OwnerLabelParts p = split_owner_label(label);
            r.org = std::string(p.org);
            r.country = std::string(p.country);
            if (!p.asn_digits.empty()) r.asn = "(AS" + std::string(p.asn_digits) + ")";
        }
        rows.push_back(std::move(r));
    };
    for (size_t i = 0; i < v4_samples.size(); ++i) {
        if (keep4 && !(*keep4)[i]) continue;
        add(v4_samples[i].first, v4_labels[i]);
    }
    for (size_t i = 0; i < v6_samples.size(); ++i) {
        if (keep6 && !(*keep6)[i]) continue;
        add(v6_samples[i].first, v6_labels[i]);
    }
}

constexpr size_t kAsnColMin = 16, kRangeColMin = 28, kCountryColMin = 16;

void render_owner_table(const std::vector<OwnerRow>& rows, bool color, std::string& out, bool with_range = true) {
    size_t w1 = kAsnColMin, w2 = kRangeColMin, w3 = kCountryColMin;
    for (const OwnerRow& r : rows) {
        w1 = std::max(w1, r.asn.size() + 2);
        if (with_range) w2 = std::max(w2, r.range.size() + 2);
        w3 = std::max(w3, r.country.size() + 2);
    }
    if (color) out += colo(kGreen);
    out += pad_right("ASN", w1);
    if (with_range) out += pad_right("RANGE", w2);
    out += pad_right("COUNTRY", w3);
    out += "ORGANIZATION";
    if (color) out += colo(kReset);
    out += "\n\n";
    for (const OwnerRow& r : rows) {
        if (color) out += colo(kBlue);
        out += pad_right(r.asn, w1);
        if (color) out += colo(kReset);
        if (with_range) out += pad_right(r.range, w2);
        out += pad_right(r.country, w3);
        if (color) out += colo(kYellow);
        out += r.org;
        if (color) out += colo(kReset);
        out += "\n";
    }
}

bool is_iso2(std::string_view s) {
    if (s.size() != 2) return false;
    for (const Country& c : kCountries)
        if (c.iso2[0] == s[0] && c.iso2[1] == s[1]) return true;
    return false;
}

void split_trailing_cc(std::string& name, std::string& cc) {
    cc.clear();
    const size_t n = name.size();
    if (n < 4 || !is_iso2(std::string_view(name).substr(n - 2))) return;
    size_t cut;
    if (name[n - 3] == ',') cut = n - 3;
    else if (n >= 5 && name[n - 3] == ' ' && name[n - 4] == ',') cut = n - 4;
    else return;
    cc = name.substr(n - 2);
    name.resize(cut);
    while (!name.empty() && name.back() == ' ') name.pop_back();
}

Cleaned clean_name(std::string_view in, bool fallback_all) {
    std::vector<std::string> raw;
    tokenize(strip_owner_suffixes(in), raw);
    Cleaned out;
    out.tokens.reserve(raw.size());
    for (const std::string& t : raw)
        if (!is_noise(t)) out.tokens.push_back(t);
    if (out.tokens.empty() && fallback_all) out.tokens = raw;
    size_t n = 0;
    for (const std::string& t : out.tokens) n += t.size();
    out.compact.reserve(n);
    for (const std::string& t : out.tokens) out.compact += t;
    return out;
}

int tol_for(size_t len) { return len <= 3 ? 0 : (len <= 7 ? 1 : 2); }

bool token_matches(const std::string& q, const std::string& t, bool fuzzy) {
    if (q == t) return true;
    if (!fuzzy) return q.size() >= 3 && t.size() > q.size() && t.compare(0, q.size(), q) == 0;
    const int tol = tol_for(q.size());
    return tol > 0 && edit_distance(q, t, tol) <= tol;
}

bool all_tokens_match(const Cleaned& q, const Cleaned& o, bool fuzzy) {
    for (const std::string& qt : q.tokens) {
        bool hit = false;
        for (const std::string& ot : o.tokens) {
            if (token_matches(qt, ot, fuzzy)) { hit = true; break; }
        }
        if (!hit) return false;
    }
    return true;
}

int org_score(const Cleaned& q, const Cleaned& o) {
    if (q.tokens.empty() || o.tokens.empty()) return 0;
    if (q.tokens == o.tokens) return 5;
    if (q.compact.size() >= 4 && o.compact.find(q.compact) != std::string::npos) return 4;
    if (all_tokens_match(q, o, false)) return 3;
    if (all_tokens_match(q, o, true)) return 2;
    if (q.compact.size() >= 5) {
        const int tol = tol_for(q.compact.size());
        if (approx_sub(q.compact, o.compact, tol) <= tol) return 1;
    }
    return 0;
}

int keep_threshold(int best) { return best >= 3 ? 3 : 1; }

struct Nearest {
    static constexpr size_t kMax = 5;
    std::vector<std::pair<int, std::string>> items;

    void offer(int d, const std::string& s) {
        if (items.size() == kMax && d >= items.back().first) return;
        for (const auto& it : items)
            if (it.second == s) return;
        auto pos = std::upper_bound(items.begin(), items.end(), d,
                                    [](int v, const std::pair<int, std::string>& p) { return v < p.first; });
        items.insert(pos, {d, s});
        if (items.size() > kMax) items.pop_back();
    }
};

uint32_t label_asn(std::string_view label) {
    const size_t p = label.rfind("(AS");
    if (p == std::string_view::npos || label.empty() || label.back() != ')' || label.size() < p + 4) return 0;
    uint64_t v = 0;
    if (!parse_u64(label.substr(p + 3, label.size() - p - 4), v) || v == 0 || v > 0xFFFFFFFFull) return 0;
    return static_cast<uint32_t>(v);
}

bool parse_asn_arg(std::string_view in, uint32_t& asn) {
    in = trim_sv(in);
    if (in.size() >= 2 && lower_ascii(in[0]) == 'a' && lower_ascii(in[1]) == 's') in.remove_prefix(2);
    uint64_t v = 0;
    if (in.size() > 10 || !parse_u64(in, v) || v == 0 || v > 0xFFFFFFFFull) return false;
    asn = static_cast<uint32_t>(v);
    return true;
}

struct OwnerMatcher {
    Cleaned  q;
    uint32_t asn = 0;

    int score(const std::string& label) const {
        if (asn) return label_asn(label) == asn ? 5 : 0;
        return org_score(q, clean_name(label, true));
    }
};

bool make_owner_matcher(const std::string& name, OwnerMatcher& m) {
    uint32_t asn = 0;
    if (parse_asn_arg(name, asn)) { m.asn = asn; return true; }
    m.q = clean_name(name, false);
    return !m.q.tokens.empty();
}

struct OwnerFilter {
    std::vector<char> keep4, keep6;
    size_t kept_orgs = 0;
    int    best = 0;
    Nearest nearest;
};

void apply_owner_filter(const OwnerMatcher& m, const std::vector<std::string>& l4,
                        const std::vector<std::string>& l6, OwnerFilter& f) {
    std::unordered_map<std::string, int> cache;
    auto score_of = [&](const std::string& label) -> int {
        if (label.empty()) return 0;
        auto it = cache.find(label);
        if (it != cache.end()) return it->second;
        const int s = m.score(label);
        cache.emplace(label, s);
        return s;
    };
    for (const auto& l : l4) f.best = std::max(f.best, score_of(l));
    for (const auto& l : l6) f.best = std::max(f.best, score_of(l));
    f.keep4.assign(l4.size(), 0);
    f.keep6.assign(l6.size(), 0);
    if (f.best == 0) {
        if (m.asn == 0) {
            for (const auto& kv : cache) {
                const Cleaned c = clean_name(kv.first, true);
                const int d = approx_sub(m.q.compact, c.compact, 4);
                if (d <= 4) f.nearest.offer(d, kv.first);
            }
        }
        return;
    }
    const int th = keep_threshold(f.best);
    std::unordered_set<std::string> orgs;
    for (size_t i = 0; i < l4.size(); ++i)
        if (score_of(l4[i]) >= th) { f.keep4[i] = 1; orgs.insert(l4[i]); }
    for (size_t i = 0; i < l6.size(); ++i)
        if (score_of(l6[i]) >= th) { f.keep6[i] = 1; orgs.insert(l6[i]); }
    f.kept_orgs = orgs.size();
}

[[maybe_unused]] uint64_t v4_cidr_size(const std::string& cidr) {
    const size_t slash = cidr.find('/');
    uint64_t p = 32;
    if (slash != std::string::npos) parse_u64(std::string_view(cidr).substr(slash + 1), p);
    return p > 32 ? 0 : (1ULL << (32 - p));
}

}

namespace {

struct AsnRow {
    std::string asn, name, c3, c4;
};

void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool ci_starts(std::string_view s, size_t pos, std::string_view lit) {
    if (pos + lit.size() > s.size()) return false;
    for (size_t i = 0; i < lit.size(); ++i)
        if (lower_ascii(s[pos + i]) != lit[i]) return false;
    return true;
}

bool tag_boundary(char c) {
    return c == '>' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/';
}

size_t find_open_tag(std::string_view s, std::string_view name, size_t from) {
    for (;;) {
        const size_t p = s.find('<', from);
        if (p == std::string_view::npos) return p;
        if (ci_starts(s, p + 1, name)) {
            const size_t after = p + 1 + name.size();
            if (after >= s.size()) return std::string_view::npos;
            if (tag_boundary(s[after])) return p;
        }
        from = p + 1;
    }
}

size_t find_close_tag(std::string_view s, std::string_view name, size_t from) {
    for (;;) {
        const size_t p = s.find("</", from);
        if (p == std::string_view::npos) return p;
        if (ci_starts(s, p + 2, name)) {
            const size_t after = p + 2 + name.size();
            if (after >= s.size() || tag_boundary(s[after])) return p;
        }
        from = p + 2;
    }
}

bool decode_entity(std::string_view ent, uint32_t& cp) {
    if (ent == "amp") { cp = '&'; return true; }
    if (ent == "lt") { cp = '<'; return true; }
    if (ent == "gt") { cp = '>'; return true; }
    if (ent == "quot") { cp = '"'; return true; }
    if (ent == "apos") { cp = '\''; return true; }
    if (ent == "nbsp") { cp = ' '; return true; }
    if (ent.size() >= 2 && ent[0] == '#') {
        uint64_t v = 0;
        std::string_view digits = ent.substr(1);
        int base = 10;
        if (!digits.empty() && (digits[0] == 'x' || digits[0] == 'X')) { base = 16; digits.remove_prefix(1); }
        if (digits.empty() || digits.size() > 7) return false;
        auto r = std::from_chars(digits.data(), digits.data() + digits.size(), v, base);
        if (r.ec != std::errc() || r.ptr != digits.data() + digits.size() || v > 0x10FFFF) return false;
        cp = static_cast<uint32_t>(v);
        return true;
    }
    return false;
}

std::string html_text(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    bool pending_space = false;
    auto put = [&](char c) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { pending_space = !out.empty(); return; }
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) return;
        if (pending_space) { out.push_back(' '); pending_space = false; }
        out.push_back(c);
    };
    for (size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (c == '<') {
            const size_t e = s.find('>', i);
            if (e == std::string_view::npos) break;
            i = e + 1;
            continue;
        }
        if (c == '&') {
            const size_t semi = s.find(';', i);
            uint32_t cp = 0;
            if (semi != std::string_view::npos && semi - i <= 10 && decode_entity(s.substr(i + 1, semi - i - 1), cp)) {
                std::string tmp;
                append_utf8(tmp, cp == 0xA0 ? ' ' : cp);
                for (char t : tmp) put(t);
                i = semi + 1;
                continue;
            }
        }
        put(c);
        ++i;
    }
    return out;
}

bool valid_asn_cell(const std::string& s) {
    return s.size() >= 3 && s.size() <= 12 && lower_ascii(s[0]) == 'a' && lower_ascii(s[1]) == 's' &&
           all_digits(std::string_view(s).substr(2));
}

constexpr size_t kMaxRowsPerPage = 200000;
constexpr size_t kMaxAsnRowBytes = 256u * 1024;
constexpr size_t kStreamTail     = 16;

bool parse_asn_row(std::string_view row, AsnRow& out) {
    std::string cells[4];
    size_t n = 0, cp = 0;
    while (n < 4 && (cp = find_open_tag(row, "td", cp)) != std::string_view::npos) {
        const size_t gt = row.find('>', cp);
        if (gt == std::string_view::npos) break;
        const size_t ce = find_close_tag(row, "td", gt);
        cells[n++] = html_text(row.substr(gt + 1, ce == std::string_view::npos ? std::string_view::npos : ce - gt - 1));
        cp = (ce == std::string_view::npos) ? row.size() : ce + 4;
    }
    if (n < 2 || !valid_asn_cell(cells[0]) || cells[1].empty()) return false;
    sanitize_inplace(cells[1]);
    if (cells[1].empty()) return false;
    AsnRow r;
    r.asn = std::move(cells[0]);
    r.asn[0] = 'A';
    r.asn[1] = 'S';
    r.name = std::move(cells[1]);
    if (all_digits(cells[2]) && cells[2].size() <= 10) r.c3 = std::move(cells[2]);
    if (all_digits(cells[3]) && cells[3].size() <= 10) r.c4 = std::move(cells[3]);
    out = std::move(r);
    return true;
}

[[maybe_unused]] void parse_asn_rows(std::string_view body, std::vector<AsnRow>& rows) {
    std::string_view scope = body;
    const size_t tb = find_open_tag(body, "tbody", 0);
    if (tb != std::string_view::npos) {
        const size_t te = find_close_tag(body, "tbody", tb);
        scope = body.substr(tb, te == std::string_view::npos ? std::string_view::npos : te - tb);
    }
    size_t pos = 0;
    while (rows.size() < kMaxRowsPerPage && (pos = find_open_tag(scope, "tr", pos)) != std::string_view::npos) {
        const size_t tr_end = find_close_tag(scope, "tr", pos);
        const std::string_view row = scope.substr(pos, tr_end == std::string_view::npos ? std::string_view::npos : tr_end - pos);
        pos = (tr_end == std::string_view::npos) ? scope.size() : tr_end + 4;
        AsnRow r;
        if (parse_asn_row(row, r)) rows.push_back(std::move(r));
    }
}

struct AsnRowStream {
    enum class State { Pre, Body, Done };
    State                state = State::Pre;
    std::string          carry;
    std::vector<AsnRow>  pre_rows;
    std::vector<AsnRow>  rows;

    void reset() {
        state = State::Pre;
        std::string().swap(carry);
        std::vector<AsnRow>().swap(pre_rows);
        std::vector<AsnRow>().swap(rows);
    }

    bool feed(std::string_view chunk) {
        if (state == State::Done) return true;
        carry.append(chunk.data(), chunk.size());
        const std::string_view sv(carry);
        size_t pos = 0;
        for (;;) {
            const size_t tr = find_open_tag(sv, "tr", pos);
            const std::string_view region = (tr == std::string_view::npos) ? sv : sv.substr(0, tr);
            if (state == State::Pre) {
                const size_t tb = find_open_tag(region, "tbody", pos);
                if (tb != std::string_view::npos) {
                    state = State::Body;
                    std::vector<AsnRow>().swap(pre_rows);
                    pos = tb + 6;
                    continue;
                }
            }
            if (state == State::Body) {
                const size_t te = find_close_tag(region, "tbody", pos);
                if (te != std::string_view::npos) {
                    state = State::Done;
                    std::string().swap(carry);
                    return true;
                }
            }
            if (tr == std::string_view::npos) {
                if (sv.size() > kStreamTail) pos = std::max(pos, sv.size() - kStreamTail);
                break;
            }
            const size_t end = find_close_tag(sv, "tr", tr);
            if (end == std::string_view::npos) { pos = tr; break; }
            AsnRow r;
            if (parse_asn_row(sv.substr(tr, end - tr), r)) {
                std::vector<AsnRow>& dst = (state == State::Pre) ? pre_rows : rows;
                if (dst.size() >= kMaxRowsPerPage) {
                    state = State::Done;
                    std::string().swap(carry);
                    return true;
                }
                dst.push_back(std::move(r));
            }
            pos = end + 4;
        }
        carry.erase(0, pos);
        return carry.size() <= kMaxAsnRowBytes;
    }

    void finish() {
        if (state != State::Done && !carry.empty()) {
            const std::string_view sv(carry);
            const size_t tr = find_open_tag(sv, "tr", 0);
            if (tr != std::string_view::npos) {
                AsnRow r;
                if (parse_asn_row(sv.substr(tr), r))
                    (state == State::Pre ? pre_rows : rows).push_back(std::move(r));
            }
        }
        if (state == State::Pre) rows.swap(pre_rows);
        std::string().swap(carry);
    }
};

bool is_domain_line(std::string_view l) {
    if (l.empty() || l.size() > 300) return false;
    bool dot = false;
    for (char ch : l) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '.') dot = true;
        else if (!(is_alnum_ascii(c) || c == '-' || c == '_' || c == '*' || c == ',')) return false;
    }
    return dot;
}

constexpr size_t kMaxDomains = 200000;

bool parse_reverse_body(std::string_view body, std::vector<std::string>& domains, std::string& message) {
    std::unordered_set<std::string> seen;
    bool first = true;
    size_t pos = 0;
    while (pos < body.size() && domains.size() < kMaxDomains) {
        const size_t nl = body.find('\n', pos);
        std::string_view line = body.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = (nl == std::string_view::npos) ? body.size() : nl + 1;
        line = trim_sv(line);
        if (line.empty()) continue;
        if (!is_domain_line(line)) {
            if (first) {
                message.assign(line.substr(0, 200));
                sanitize_inplace(message);
                return false;
            }
            continue;
        }
        first = false;
        std::string d(line);
        if (seen.insert(d).second) domains.push_back(std::move(d));
    }
    return true;
}

bool normalize_range24(std::string_view in, std::string& out, bool& adjusted) {
    in = trim_sv(in);
    const size_t slash = in.find('/');
    if (slash == std::string_view::npos) return false;
    uint32_t base = 0;
    uint64_t len = 0;
    if (!parse_v4_addr(in.substr(0, slash), base) || !parse_u64(in.substr(slash + 1), len) || len != 24) return false;
    adjusted = (base & 0xFFu) != 0;
    out = v4_to_string(base & 0xFFFFFF00u) + "/24";
    return true;
}

void json_skip_ws(std::string_view s, size_t& p) {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) ++p;
}

bool json_hex4(std::string_view s, size_t& p, uint32_t& out) {
    if (p + 4 > s.size()) return false;
    uint64_t v = 0;
    auto r = std::from_chars(s.data() + p, s.data() + p + 4, v, 16);
    if (r.ec != std::errc() || r.ptr != s.data() + p + 4) return false;
    out = static_cast<uint32_t>(v);
    p += 4;
    return true;
}

bool json_read_string(std::string_view s, size_t& p, std::string& out) {
    if (p >= s.size() || s[p] != '"') return false;
    ++p;
    out.clear();
    while (p < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[p++]);
        if (c == '"') return true;
        if (out.size() > 4096 || c < 0x20) return false;
        if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
        if (p >= s.size()) return false;
        const char e = s[p++];
        switch (e) {
            case '"':  out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'u': {
                uint32_t cp = 0;
                if (!json_hex4(s, p, cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    uint32_t lo = 0;
                    size_t q = p + 2;
                    if (p + 1 < s.size() && s[p] == '\\' && s[p + 1] == 'u' && json_hex4(s, q, lo) &&
                        lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        p = q;
                    } else {
                        cp = '?';
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = '?';
                }
                append_utf8(out, cp);
                break;
            }
            default: return false;
        }
    }
    return false;
}

bool json_find_string(std::string_view s, std::string_view key, std::string& out) {
    std::string needle = "\"";
    needle += key;
    needle += '"';
    size_t from = 0;
    while ((from = s.find(needle, from)) != std::string_view::npos) {
        size_t p = from + needle.size();
        from = p;
        json_skip_ws(s, p);
        if (p >= s.size() || s[p] != ':') continue;
        ++p;
        json_skip_ws(s, p);
        if (json_read_string(s, p, out)) return true;
    }
    return false;
}

constexpr size_t kMaxRoutes = 200000;

bool json_string_array(std::string_view s, size_t from, std::string_view key, std::vector<std::string>& out) {
    std::string needle = "\"";
    needle += key;
    needle += '"';
    size_t f = s.find(needle, from);
    while (f != std::string_view::npos) {
        size_t p = f + needle.size();
        json_skip_ws(s, p);
        if (p < s.size() && s[p] == ':') {
            ++p;
            json_skip_ws(s, p);
            if (p < s.size() && s[p] == '[') {
                ++p;
                for (;;) {
                    json_skip_ws(s, p);
                    if (p >= s.size()) return false;
                    if (s[p] == ']') return true;
                    if (s[p] == ',') { ++p; continue; }
                    std::string v;
                    if (!json_read_string(s, p, v) || out.size() >= kMaxRoutes) return false;
                    out.push_back(std::move(v));
                }
            }
        }
        f = s.find(needle, f + needle.size());
    }
    return false;
}

}

namespace {

int run_ranges(const Options& opts) {
    const Country* cp = nullptr;
    CountryMatch::How how = CountryMatch::How::None;
    if (!pick_country(opts.country, cp, how)) return 1;
    const Country& country = *cp;

    Job job;
    job.cc[0] = country.iso2[0];
    job.cc[1] = country.iso2[1];
    job.want_v4 = opts.want_v4;
    job.want_v6 = opts.want_v6;
    if (!job.want_v4 && !job.want_v6) {
        std::cerr << "[discover] nothing to do: both IPv4 and IPv6 are disabled\n";
        return 1;
    }

    const bool filtering = opts.owner && !opts.owner_name.empty();
    OwnerMatcher matcher;
    if (filtering && !make_owner_matcher(opts.owner_name, matcher)) {
        std::cerr << col(kRed) << "[discover] --owner: '" << opts.owner_name << "' has no searchable words"
                  << col(kReset) << "\n";
        return 1;
    }

    const std::string cc_lower = [&] {
        std::string s(country.iso2);
        for (char& c : s) c = lower_ascii(c);
        return s;
    }();

    print_country_line(country, how, opts.country);

    std::vector<std::unique_ptr<Source>> sources;
    auto add = [&](Kind k, const char* label, std::string url, bool streaming, size_t cap) {
        auto s = std::make_unique<Source>();
        s->kind = k;
        s->label = label;
        s->url = std::move(url);
        s->job = &job;
        s->streaming = streaming;
        s->cap = cap;
        sources.push_back(std::move(s));
    };
    if (job.want_v4)
        add(Kind::NwDb, "networksdb", "https://networksdb.io/ip-addresses-of/" + nwdb_slug(country.name), false, kCapPageBytes);
    add(Kind::ApnicDelegated, "apnic-delegated", "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest", true, kCapStreamBytes);
    if (job.want_v4)
        add(Kind::RirV4, "rir-list-v4", "https://www-public.telecom-sudparis.eu/~maigron/rir-stats/rir-delegations/ip-lists/ipv4/" + cc_lower + "-ipv4-list.txt", true, kCapStreamBytes);
    if (job.want_v6)
        add(Kind::RirV6, "rir-list-v6", "https://www-public.telecom-sudparis.eu/~maigron/rir-stats/rir-delegations/ip-lists/ipv6/" + cc_lower + "-ipv6-list.txt", true, kCapStreamBytes);

    std::vector<Xfer*> xs;
    xs.reserve(sources.size());
    for (auto& s : sources) xs.push_back(s.get());

    const int rc = run_transfers(xs, opts, xs.size(), nullptr);
    if (rc == 130) {
        std::cerr << "[discover] interrupted - transfers aborted, partial results discarded\n";
        return 130;
    }
    if (rc != 0) {
        std::cerr << col(kRed) << "[discover] curl_multi_init failed" << col(kReset) << "\n";
        return 1;
    }

    size_t ok_count = 0;
    std::vector<V4> all_v4;
    std::vector<V6> all_v6;
    for (auto& s : sources) {
        if (s->ok) {
            ++ok_count;
            all_v4.insert(all_v4.end(), s->v4.begin(), s->v4.end());
            all_v6.insert(all_v6.end(), s->v6.begin(), s->v6.end());
        }
    }
    if (ok_count == 0) {
        std::cerr << col(kRed) << "[discover] every source failed - check connectivity / country code" << col(kReset) << "\n";
        return 1;
    }

    std::string text;
    size_t out_v4 = 0, out_v6 = 0;
    std::vector<std::pair<std::string, uint32_t>> v4_samples;
    std::vector<std::pair<std::string, u128>>     v6_samples;
    if (job.want_v4) {
        std::vector<V4> merged = merge_v4(std::move(all_v4));
        for (const V4& iv : merged) out_v4 += emit_v4(iv, opts.owner ? nullptr : &text, opts.owner ? &v4_samples : nullptr);
    }
    if (job.want_v6) {
        std::vector<V6> merged = merge_v6(std::move(all_v6));
        for (const V6& iv : merged) out_v6 += emit_v6(iv, opts.owner ? nullptr : &text, opts.owner ? &v6_samples : nullptr);
    }

    if (out_v4 + out_v6 == 0) {
        std::cerr << col(kYellow) << "[discover] no ranges found for " << country.name << " (" << country.iso2 << ")" << col(kReset) << "\n";
        return 1;
    }

    if (!opts.owner) {
        write_out(opts, text);
        return 0;
    }

    std::vector<std::string> v4_labels, v6_labels;
    size_t owners_resolved = 0, owners_attempted = 0;
    resolve_owners(v4_samples, v6_samples, opts, v4_labels, v6_labels, owners_resolved, owners_attempted);
    (void)owners_resolved;
    (void)owners_attempted;

    OwnerFilter flt;
    if (filtering) {
        apply_owner_filter(matcher, v4_labels, v6_labels, flt);
        if (flt.best == 0) {
            std::cerr << col(kYellow) << "[discover] no range owner matched '" << opts.owner_name << "'" << col(kReset) << "\n";
            if (!flt.nearest.items.empty()) {
                std::cerr << "[discover] did you mean:\n";
                for (const auto& it : flt.nearest.items) std::cerr << "             " << it.second << "\n";
            }
            return 1;
        }
        if (flt.best < 3)
            std::cerr << "[discover] no exact owner match - showing closest (typo-tolerant) matches\n";
    }

    std::vector<OwnerRow> rows;
    collect_owner_rows(v4_samples, v4_labels, v6_samples, v6_labels,
                       filtering ? &flt.keep4 : nullptr, filtering ? &flt.keep6 : nullptr, rows);

    std::string colored, plain;
    render_owner_table(rows, true, colored);
    render_owner_table(rows, false, plain);
    std::cout << colored;
    std::cout.flush();
    save_file(opts, plain);
    return 0;
}

struct AsnHit {
    int      score;
    size_t   page;
    size_t   idx;
    AsnRow   row;
};

struct AsnCollector {
    const Cleaned*           query = nullptr;
    std::vector<AsnHit>      hits;
    std::vector<std::string> names;
    std::unordered_set<uint64_t> seen;
    size_t                   total_rows = 0;

    void add(size_t page, std::vector<AsnRow>&& rows) {
        size_t idx = 0;
        for (AsnRow& r : rows) {
            const size_t i = idx++;
            uint64_t key = 0;
            for (size_t k = 2; k < r.asn.size(); ++k) key = key * 10 + static_cast<uint64_t>(r.asn[k] - '0');
            if (!seen.insert(key).second) continue;
            ++total_rows;
            if (!query) {
                hits.push_back({0, page, i, std::move(r)});
                continue;
            }
            const int sc = org_score(*query, clean_name(r.name, true));
            if (sc > 0) hits.push_back({sc, page, i, std::move(r)});
            else names.push_back(std::move(r.name));
        }
    }
};

struct AsnPage : Xfer {
    size_t         index = 0;
    AsnCollector*  sink = nullptr;
    AsnRowStream   stream;

    bool on_data(const char* p, size_t n) override {
        if (stream.feed(std::string_view(p, n))) return true;
        aborted = true;
        abort_reason = "malformed page (row too large)";
        return false;
    }
    void on_finish() override {
        stream.finish();
        sink->add(index, std::move(stream.rows));
        stream.reset();
    }
    void on_fail() override { body.clear(); stream.reset(); }
    void on_reset() override { stream.reset(); }
};

constexpr size_t kScanConcurrency  = 8;
constexpr size_t kRetryConcurrency = 2;

int run_asn_list(const Options& opts) {
    const bool filtering = !opts.org.empty();
    Cleaned query;
    if (filtering) {
        query = clean_name(opts.org, false);
        if (query.tokens.empty()) {
            std::cerr << col(kRed) << "[discover] --org: '" << opts.org << "' has no searchable words" << col(kReset) << "\n";
            return 1;
        }
    }

    std::vector<const Country*> targets;
    if (!opts.country.empty()) {
        const Country* cp = nullptr;
        CountryMatch::How how = CountryMatch::How::None;
        if (!pick_country(opts.country, cp, how)) return 1;
        print_country_line(*cp, how, opts.country);
        targets.push_back(cp);
    } else if (filtering) {
        targets.reserve(kCountryCount);
        for (const Country& c : kCountries) targets.push_back(&c);
        std::cerr << "[discover] --org without --cn: scanning all " << targets.size() << " country pages\n";
    } else {
        std::cerr << col(kRed) << "[discover] give --cn <country> and/or --org <name>" << col(kReset) << "\n";
        return 1;
    }

    AsnCollector sink;
    sink.query = filtering ? &query : nullptr;

    std::vector<std::unique_ptr<AsnPage>> pages;
    pages.reserve(targets.size());
    std::vector<Xfer*> xs;
    xs.reserve(targets.size());
    for (size_t i = 0; i < targets.size(); ++i) {
        auto p = std::make_unique<AsnPage>();
        p->url = std::string("https://ipgeolocation.io/browse/asn/countries/") + targets[i]->iso2;
        p->cap = kCapAsnPageBytes;
        p->not_found_ok = true;
        p->index = i;
        p->sink = &sink;
        xs.push_back(p.get());
        pages.push_back(std::move(p));
    }

    const bool multi = targets.size() > 1;
    ProgressFn progress;
    if (multi) {
        progress = [](size_t done, size_t total) {
            if (err_tty()) std::cerr << "\r[discover] country pages " << done << "/" << total << std::flush;
            else if (done == total || done % 25 == 0) std::cerr << "[discover] country pages " << done << "/" << total << "\n";
        };
    }

    int rc = run_transfers(xs, opts, multi ? kScanConcurrency : 1, progress);
    if (multi && err_tty()) std::cerr << "\n";

    if (rc == 0) {
        std::vector<Xfer*> failed;
        for (auto& p : pages)
            if (!p->ok && !p->aborted) { p->reset(); failed.push_back(p.get()); }
        if (!failed.empty()) {
            if (multi) std::cerr << "[discover] retrying " << failed.size() << " failed page(s)\n";
            Options ropts = opts;
            ropts.total_timeout_sec = static_cast<int>(std::max<long long>(
                opts.total_timeout_sec, std::min<long long>(2LL * opts.total_timeout_sec, 600)));
            rc = run_transfers(failed, ropts, kRetryConcurrency, nullptr);
        }
    }
    if (rc == 130) {
        std::cerr << "[discover] interrupted - partial results discarded\n";
        return 130;
    }
    if (rc != 0) {
        std::cerr << col(kRed) << "[discover] curl_multi_init failed" << col(kReset) << "\n";
        return 1;
    }

    size_t failed_pages = 0;
    std::string last_note, failed_list;
    for (size_t i = 0; i < pages.size(); ++i) {
        if (pages[i]->ok) continue;
        ++failed_pages;
        last_note = pages[i]->note;
        if (failed_pages <= 8) {
            if (!failed_list.empty()) failed_list += ", ";
            failed_list += targets[i]->iso2;
            failed_list += " (" + pages[i]->note + ")";
        }
    }
    if (failed_pages == pages.size()) {
        std::cerr << col(kRed) << "[discover] every page failed: " << last_note << col(kReset) << "\n";
        return 1;
    }
    if (failed_pages > 0)
        std::cerr << col(kYellow) << "[discover] " << failed_pages << " page(s) failed: " << failed_list
                  << (failed_pages > 8 ? ", ..." : "") << " - results may be incomplete" << col(kReset) << "\n";

    if (sink.total_rows == 0) {
        std::cerr << col(kYellow) << "[discover] no ASN rows found - the page has none for this country or its layout changed"
                  << col(kReset) << "\n";
        return 1;
    }

    std::vector<AsnHit>& hits = sink.hits;
    if (filtering) {
        if (hits.empty()) {
            std::cerr << col(kYellow) << "[discover] no organisation matched '" << opts.org << "'" << col(kReset) << "\n";
            Nearest nearest;
            for (const std::string& n : sink.names) {
                const Cleaned c = clean_name(n, true);
                const int d = approx_sub(query.compact, c.compact, 4);
                if (d <= 4) nearest.offer(d, n);
            }
            if (!nearest.items.empty()) {
                std::cerr << "[discover] did you mean:\n";
                for (const auto& it : nearest.items) std::cerr << "             " << it.second << "\n";
            }
            return 1;
        }
        std::sort(hits.begin(), hits.end(), [](const AsnHit& a, const AsnHit& b) {
            if (a.score != b.score) return a.score > b.score;
            if (a.page != b.page) return a.page < b.page;
            return a.idx < b.idx;
        });
        const int th = keep_threshold(hits.front().score);
        if (hits.front().score < 3)
            std::cerr << "[discover] no exact organisation match - showing closest (typo-tolerant) matches\n";
        hits.erase(std::remove_if(hits.begin(), hits.end(), [th](const AsnHit& h) { return h.score < th; }), hits.end());
    }

    std::vector<OwnerRow> table;
    table.reserve(hits.size());
    for (AsnHit& h : hits) {
        OwnerRow r;
        r.asn = h.row.asn;
        r.org = h.row.name;
        split_trailing_cc(r.org, r.country);
        if (r.country.empty()) r.country = "-";
        table.push_back(std::move(r));
    }
    std::string colored, plain;
    render_owner_table(table, true, colored, false);
    render_owner_table(table, false, plain, false);
    std::cout << colored;
    std::cout.flush();
    save_file(opts, plain);
    std::cerr << col(kBold) << "[discover] result  : " << col(kReset) << hits.size() << " ASN(s)";
    if (filtering) std::cerr << " matching '" << opts.org << "'";
    std::cerr << "  [from " << sink.total_rows << " ASNs on " << (pages.size() - failed_pages) << "/" << pages.size() << " page(s)]\n";
    return 0;
}

int run_reverse(const Options& opts) {
    std::string query;
    if (!opts.ip.empty()) {
        uint32_t host = 0;
        if (!parse_v4_addr(trim_sv(opts.ip), host)) {
            std::string shown = opts.ip;
            sanitize_inplace(shown);
            if (shown.size() > 64) shown.resize(64);
            std::cerr << col(kRed) << "[discover] --ip: '" << shown << "' is not a valid IPv4 address" << col(kReset) << "\n";
            return 1;
        }
        query = v4_to_string(host);
    } else {
        bool adjusted = false;
        if (!normalize_range24(opts.range, query, adjusted)) {
            std::cerr << col(kRed) << "[discover] --range: only IPv4 /24 ranges are supported (e.g. 103.48.88.0/24)"
                      << col(kReset) << "\n";
            return 1;
        }
        if (adjusted) std::cerr << "[discover] --range: host bits cleared, using " << query << "\n";
    }

    Xfer page;
    page.url = "https://api.hackertarget.com/reverseiplookup/?q=" + query;
    page.cap = kCapReplyBytes;
    std::vector<Xfer*> xs{&page};
    const int rc = run_transfers(xs, opts, 1, nullptr);
    if (rc == 130) { std::cerr << "[discover] interrupted\n"; return 130; }
    if (rc != 0 || !page.ok) {
        std::cerr << col(kRed) << "[discover] hackertarget request failed: " << (page.note.empty() ? "internal error" : page.note)
                  << col(kReset) << "\n";
        return 1;
    }

    std::vector<std::string> domains;
    std::string message;
    if (!parse_reverse_body(page.body, domains, message)) {
        if (message.find("API count exceeded") != std::string::npos)
            std::cerr << col(kRed) << "[discover] hackertarget daily quota exceeded - try later or from another IP" << col(kReset) << "\n";
        else
            std::cerr << col(kYellow) << "[discover] hackertarget: " << message << col(kReset) << "\n";
        return 1;
    }
    if (domains.empty()) {
        std::cerr << col(kYellow) << "[discover] no domains found for " << query << col(kReset) << "\n";
        return 1;
    }
    std::string text;
    for (const std::string& d : domains) { text += d; text += '\n'; }
    write_out(opts, text);
    std::cerr << col(kBold) << "[discover] result  : " << col(kReset) << domains.size() << " domain(s) for " << query << "\n";
    return 0;
}

int run_asn_routes(const Options& opts) {
    uint32_t asn = 0;
    if (!parse_asn_arg(opts.asn, asn)) {
        std::string shown = opts.asn;
        sanitize_inplace(shown);
        if (shown.size() > 64) shown.resize(64);
        std::cerr << col(kRed) << "[discover] --asn: '" << shown << "' is not a valid ASN (use AS45353 or 45353)" << col(kReset) << "\n";
        return 1;
    }
    if (!opts.want_v4 && !opts.want_v6) {
        std::cerr << "[discover] nothing to do: both IPv4 and IPv6 are disabled\n";
        return 1;
    }

    Xfer page;
    page.url = "https://ip.guide/AS" + std::to_string(asn);
    page.cap = kCapReplyBytes;
    std::vector<Xfer*> xs{&page};
    const int rc = run_transfers(xs, opts, 1, nullptr);
    if (rc == 130) { std::cerr << "[discover] interrupted\n"; return 130; }
    if (rc != 0 || !page.ok) {
        if (page.note == "HTTP 404")
            std::cerr << col(kRed) << "[discover] AS" << asn << " not found" << col(kReset) << "\n";
        else
            std::cerr << col(kRed) << "[discover] ip.guide request failed: " << (page.note.empty() ? "internal error" : page.note)
                      << col(kReset) << "\n";
        return 1;
    }

    const std::string_view b(page.body);
    const size_t rp = b.find("\"routes\"");
    if (rp == std::string_view::npos) {
        std::cerr << col(kRed) << "[discover] unexpected response from ip.guide (no routes object)" << col(kReset) << "\n";
        return 1;
    }

    std::vector<std::string> r4, r6;
    json_string_array(b, rp, "v4", r4);
    json_string_array(b, rp, "v6", r6);

    std::string name, org, cc;
    json_find_string(b, "name", name);
    json_find_string(b, "organization", org);
    json_find_string(b, "country", cc);
    sanitize_inplace(name);
    sanitize_inplace(org);
    sanitize_inplace(cc);
    std::string label = name;
    if (!org.empty() && org != name) label = label.empty() ? org : label + " - " + org;
    if (label.empty()) label = "-";
    if (cc.empty()) cc = "-";
    const std::string asn_s = "AS" + std::to_string(asn);

    std::vector<OwnerRow> rows;
    std::unordered_set<std::string> seen;
    size_t n4 = 0, n6 = 0;
    if (opts.want_v4) {
        for (const std::string& r : r4) {
            V4 iv;
            if (parse_v4_cidr(r, iv) && seen.insert(r).second) { rows.push_back({asn_s, r, cc, label}); ++n4; }
        }
    }
    if (opts.want_v6) {
        for (const std::string& r : r6) {
            V6 iv;
            if (parse_v6_cidr(r, iv) && seen.insert(r).second) { rows.push_back({asn_s, r, cc, label}); ++n6; }
        }
    }

    if (n4 + n6 == 0) {
        std::cerr << col(kYellow) << "[discover] no routes found for AS" << asn << col(kReset) << "\n";
        return 1;
    }
    std::string colored, plain;
    render_owner_table(rows, true, colored);
    render_owner_table(rows, false, plain);
    std::cout << colored;
    std::cout.flush();
    save_file(opts, plain);
    std::cerr << col(kBold) << "[discover] result  : " << col(kReset);
    if (opts.want_v4) std::cerr << n4 << " IPv4 routes";
    if (opts.want_v4 && opts.want_v6) std::cerr << ", ";
    if (opts.want_v6) std::cerr << n6 << " IPv6 routes";
    std::cerr << "\n";
    return 0;
}

}

int run(const Options& opts) {
    std::cerr << "\nStarting " << col(kBold) << "Shiv" << col(kReset) << " (" << col(kYellow) << "DISCOVERY"
              << col(kReset) << ") at " << format_time() << "\n";
    CurlGlobal cg;
    if (!cg.ok) {
        std::cerr << col(kRed) << "[discover] curl_global_init failed" << col(kReset) << "\n";
        return 1;
    }
    switch (opts.mode) {
        case Mode::Ranges:    return run_ranges(opts);
        case Mode::AsnList:   return run_asn_list(opts);
        case Mode::ReverseIp: return run_reverse(opts);
        case Mode::AsnRoutes: return run_asn_routes(opts);
        case Mode::None:      break;
    }
    std::cerr << col(kRed) << "[discover] no discovery mode selected" << col(kReset) << "\n";
    return 1;
}

}

#ifdef DISCOVER_SELFTEST
std::atomic<bool> terminate_flag(false);
std::vector<std::string> g_dns_servers;

#include <set>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::cerr << "FAIL line " << __LINE__ << ": " #c "\n"; ++g_fail; } } while (0)

int main() {
    using namespace discover;
    std::set<std::string> i2, i3;
    for (const Country& c : kCountries) {
        CHECK(i2.insert(c.iso2).second);
        CHECK(i3.insert(c.iso3).second);
        CHECK(std::strlen(c.iso2) == 2 && std::strlen(c.iso3) == 3);
    }
    CHECK(country_count() == 199);
    CHECK(std::strlen("AAAAAAACEEEEIIIIDNOOOOO*OUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty") == 64);
    CHECK(std::is_sorted(std::begin(kNoise), std::end(kNoise)));
    for (const Country& c : kCountries) {
        CHECK(resolve_country(c.iso2).country == &c);
        CHECK(resolve_country(c.iso3).country == &c);
        CHECK(resolve_country(c.name).country == &c);
        std::string_view al(c.aliases);
        while (!al.empty()) {
            const size_t bar = al.find('|');
            std::string one(al.substr(0, bar));
            CHECK(resolve_country(one).country == &c);
            if (bar == std::string_view::npos) break;
            al.remove_prefix(bar + 1);
        }
    }
    auto iso = [](const char* s) {
        auto m = resolve_country(s);
        return m.country ? std::string(m.country->iso2) : std::string("??");
    };
    CHECK(iso("nepal") == "NP");   CHECK(iso("  NEPAL ") == "NP");  CHECK(iso("np") == "NP");   CHECK(iso("NPL") == "NP");
    CHECK(iso("United States") == "US"); CHECK(iso("usa") == "US"); CHECK(iso("uk") == "GB");
    CHECK(iso("South Korea") == "KR");   CHECK(iso("north-korea") == "KP");
    CHECK(iso("Côte d'Ivoire") == "CI"); CHECK(iso("Türkiye") == "TR"); CHECK(iso("são tomé") == "ST");
    CHECK(iso("neth") == "NL");
    CHECK(iso("nepl") == "NP");
    CHECK(iso("nepla") == "NP");
    CHECK(iso("germny") == "DE");
    CHECK(iso("bangaldesh") == "BD");
    CHECK(iso("kazakstan") == "KZ");
    CHECK(iso("ind") == "IN");
    CHECK(iso("guinea") == "GN");  CHECK(iso("niger") == "NE"); CHECK(iso("nigeria") == "NG");
    CHECK(iso("sudan") == "SD");   CHECK(iso("south sudan") == "SS");
    CHECK(iso("xx") == "??");      CHECK(iso("") == "??");  CHECK(iso("atlantis") == "??");
    CHECK(!resolve_country("mal").country && !resolve_country("mal").suggestions.empty());
    CHECK(!resolve_country("korea").country);

    std::string t;
    CHECK(emit_v4({0x1B220000u, 0x1B22FFFFu}, &t) == 1 && t == "27.34.0.0/16\n");
    t.clear(); CHECK(emit_v4({0x0A000000u, 0x0A0002FFu}, &t) == 2 && t == "10.0.0.0/23\n10.0.2.0/24\n");
    t.clear(); CHECK(emit_v4({0x0A000001u, 0x0A000006u}, &t) == 4);
    t.clear(); CHECK(emit_v4({0u, 0xFFFFFFFFu}, &t) == 1 && t == "0.0.0.0/0\n");
    CHECK(emit_v4({0x0A000000u, 0x0A0000FFu}, nullptr) == 1);
    std::vector<V4> v = {{10, 20}, {21, 30}, {5, 12}, {100, 200}};
    auto mv = merge_v4(v);
    CHECK(mv.size() == 2 && mv[0] == V4(5, 30) && mv[1] == V4(100, 200));
    V6 a, b;
    CHECK(parse_v6_cidr("2405:d000::/32", a) && parse_v6_cidr("2405:d001::/32", b));
    auto m6 = merge_v6({b, a});
    CHECK(m6.size() == 1);
    t.clear(); CHECK(emit_v6(m6[0], &t) == 1 && t == "2405:d000::/31\n");
    V6 all;
    CHECK(parse_v6_cidr("::/1", all));

    Job job;
    job.cc[0] = 'N';
    job.cc[1] = 'P';
    const std::string body =
        "2|apnic|20260919|9999|19830613|20260918|+1000\n"
        "apnic|*|ipv4|*|9999|summary\n"
        "apnic|NP|ipv4|27.34.0.0|32768|20100322|allocated\n"
        "apnic|IN|ipv4|1.6.0.0|65536|20100322|allocated\n"
        "apnic|NP|ipv4|103.1.92.0|1024|20110316|assigned\r\n"
        "apnic|NP|ipv4|202.79.32.0|8192|20100629|reserved\n"
        "apnic|NP|ipv6|2405:8d40::|32|20120523|allocated\n"
        "apnic|NP|ipv4|202.166.192.0|4096|20100629|allocated";
    for (size_t cut = 0; cut <= body.size(); ++cut) {
        Source s;
        s.kind = Kind::ApnicDelegated;
        s.job = &job;
        CHECK(s.ingest(body.data(), cut) && s.ingest(body.data() + cut, body.size() - cut));
        s.on_finish();
        CHECK(s.v4.size() == 3 && s.v6.size() == 1);
        CHECK(s.v4[0] == V4(0x1B220000u, 0x1B227FFFu));
        CHECK(s.v4[1] == V4(0x67015C00u, 0x67015FFFu));
    }
    {
        Source s;
        s.kind = Kind::ApnicDelegated;
        s.job = &job;
        for (char ch : body) CHECK(s.ingest(&ch, 1));
        s.on_finish();
        CHECK(s.v4.size() == 3 && s.v6.size() == 1);
    }
    {
        Job j4 = job;
        j4.want_v6 = false;
        Source s;
        s.kind = Kind::ApnicDelegated;
        s.job = &j4;
        s.ingest(body.data(), body.size());
        s.on_finish();
        CHECK(s.v6.empty() && s.v4.size() == 3);
    }
    {
        Source s;
        s.kind = Kind::RirV4;
        s.job = &job;
        const std::string l = "# generated\n27.34.0.0/17\n\n bad line\n103.1.92.0/22\n";
        s.ingest(l.data(), l.size());
        s.on_finish();
        CHECK(s.v4.size() == 2 && s.v4[0] == V4(0x1B220000u, 0x1B227FFFu));
    }
    {
        Source s;
        s.kind = Kind::RirV4;
        s.job = &job;
        s.cap = 8;
        const std::string l = "27.34.0.0/17\n27.34.0.0/17\n";
        CHECK(!s.ingest(l.data(), l.size()) && s.aborted);
    }
    {
        const std::string html = "<a href=\"/country/NP\">Nepal</a><span>CIDR:</span> 14.137.53.0/24 <span>CIDR:</span> 102.38.241.0/24 <span>CIDR:</span> 14.137.51.128/25";
        Source s;
        s.kind = Kind::NwDb;
        s.job = &job;
        s.streaming = false;
        s.ingest(html.data(), html.size());
        s.on_finish();
        CHECK(s.note.empty() && s.v4.size() == 3 && s.v4[2] == V4(0x0E893380u, 0x0E8933FFu));
        Source s2;
        s2.kind = Kind::NwDb;
        s2.job = &job;
        s2.streaming = false;
        const std::string other = "<a href=\"/country/US\">x</a> <span>CIDR:</span> 1.2.3.0/24";
        s2.ingest(other.data(), other.size());
        s2.on_finish();
        CHECK(!s2.note.empty() && s2.v4.empty());
    }
    CHECK(nwdb_slug("Nepal") == "nepal");
    CHECK(nwdb_slug("United States") == "united-states");
    CHECK(nwdb_slug("Cote d'Ivoire") == "cote-divoire");

    CHECK(edit_distance("nepla", "nepal", 1) == 1);
    CHECK(edit_distance("kitten", "sitting", 3) == 3);
    CHECK(edit_distance("abc", "abc", 0) == 0);
    CHECK(edit_distance("abcdef", "uvwxyz", 2) == 3);
    CHECK(approx_sub("wolrdlink", "worldlinkcommunications", 2) == 2);
    CHECK(approx_sub("link", "worldlink", 1) == 0);

    auto score = [](const char* q, const char* name) {
        return org_score(clean_name(q, false), clean_name(name, true));
    };
    CHECK(score("sky broadband", "Sky Broadband Pvt. Ltd, NP") == 5);
    CHECK(score("SKY-BROADBAND", "Sky Broadband Pvt. Ltd, NP") == 5);
    CHECK(score("skybroadband", "Sky Broadband Pvt. Ltd, NP") == 4);
    CHECK(score("broadband", "Sky Broadband Pvt. Ltd, NP") == 4);
    CHECK(score("broadband sky", "Sky Broadband Pvt. Ltd, NP") == 3);
    CHECK(score("sky brodaband", "Sky Broadband Pvt. Ltd, NP") == 2);
    CHECK(score("sky broadbnad", "Sky Broadband Pvt. Ltd, NP") == 2);
    CHECK(score("mercantile ofice", "Mercantile Office Systems, NP") == 2);
    CHECK(score("worldl", "WorldLink Communications Pvt Ltd") == 4);
    CHECK(score("wolrd link", "WorldLink Communications Pvt Ltd") == 1);
    CHECK(score("nitc", "NITC: IT Agency of Government of Nepal") == 4);
    CHECK(score("net", "Nepal Electricity Authority, NP") == 0);
    CHECK(score("net", "Internet Ltd") == 0);
    CHECK(score("nepal telecom", "Sky Broadband Pvt. Ltd, NP") == 0);
    CHECK(score("np", "Sky Broadband Pvt. Ltd, NP") == 0);
    CHECK(score("kacific", "KBSPL-AS-AP - Kacific Broadband Satellites Pte Ltd, SG (AS135409)") == 4);
    CHECK(clean_name("Pvt. Ltd.", false).tokens.empty());
    CHECK(!clean_name("Pvt. Ltd.", true).tokens.empty());
    {
        const Cleaned c = clean_name("Kacific Broadband Satellites Pte Ltd, SG (AS135409)", true);
        CHECK(c.tokens.size() == 3 && c.compact == "kacificbroadbandsatellites");
    }
    CHECK(label_asn("MOS-NP - Mercantile Office Systems, NP (AS4613)") == 4613);
    CHECK(label_asn("no asn here") == 0);
    CHECK(label_asn("x (AS)") == 0);
    {
        OwnerMatcher m1, m2, m3;
        CHECK(make_owner_matcher("AS4613", m1) && m1.asn == 4613);
        CHECK(make_owner_matcher("4613", m2) && m2.asn == 4613);
        CHECK(make_owner_matcher("mercantile office", m3) && m3.asn == 0);
        CHECK(m1.score("MOS-NP - Mercantile Office Systems, NP (AS4613)") == 5);
        CHECK(m1.score("X (AS4614)") == 0);
        CHECK(m3.score("MOS-NP - Mercantile Office Systems, NP (AS4613)") == 4);
        CHECK(!make_owner_matcher("pvt ltd", m3));
        std::vector<std::string> l4 = {"MOS-NP - Mercantile Office Systems, NP (AS4613)", "", "WLINK-NEPAL-AS-AP - WorldLink Communications Pvt Ltd, NP (AS17501)"};
        std::vector<std::string> l6 = {"WLINK-NEPAL-AS-AP - WorldLink Communications Pvt Ltd, NP (AS17501)"};
        OwnerFilter f;
        OwnerMatcher wl;
        CHECK(make_owner_matcher("worldlnk", wl));
        apply_owner_filter(wl, l4, l6, f);
        CHECK(f.best == 2 && f.keep4[2] && !f.keep4[0] && !f.keep4[1] && f.keep6[0] && f.kept_orgs == 1);
        OwnerFilter g;
        OwnerMatcher none;
        CHECK(make_owner_matcher("zzzzzz", none));
        apply_owner_filter(none, l4, l6, g);
        CHECK(g.best == 0 && !g.keep4[0]);
    }
    CHECK(v4_cidr_size("10.0.0.0/24") == 256);
    CHECK(v4_cidr_size("10.0.0.0/32") == 1);
    {
        Nearest n;
        n.offer(3, "c"); n.offer(1, "a"); n.offer(2, "b"); n.offer(1, "a");
        n.offer(4, "d"); n.offer(5, "e"); n.offer(6, "f"); n.offer(0, "z");
        CHECK(n.items.size() == 5 && n.items[0].second == "z" && n.items[1].second == "a" && n.items[4].second == "d");
    }

    {
        const std::string html =
            "<html><table><thead><tr><th>ASN</th><th>Org</th></tr></thead><tbody>"
            "<tr><td><span>AS135303</span></td><td><span>NETTV Pvt. Ltd., NP</span></td><td><span>1</span></td><td><span>0</span></td></tr>\n"
            "<TR class=\"x\">\n<TD><span>AS58504</span></TD>\n<TD><span>TECHMINDS &amp; NETWORKS\n PVT. LTD., NP</span></TD><TD><span>16</span></TD><TD><span>20</span></TD></TR>"
            "<tr><td><span>bogus</span></td><td><span>skip me</span></td></tr>"
            "<tr><td><span>AS4613</span></td><td><span>Mercantile&nbsp;Office Systems, NP</span></td><td><span>32</span></td><td><span>0</span></td></tr>"
            "<tr><td><span>AS9</span></td><td><span>bad\x1b[31m</span></td></tr>"
            "</tbody></table></html>";
        std::vector<AsnRow> rows;
        parse_asn_rows(html, rows);
        CHECK(rows.size() == 4);
        CHECK(rows[0].asn == "AS135303" && rows[0].name == "NETTV Pvt. Ltd., NP" && rows[0].c3 == "1" && rows[0].c4 == "0");
        CHECK(rows[1].asn == "AS58504" && rows[1].name == "TECHMINDS & NETWORKS PVT. LTD., NP" && rows[1].c3 == "16" && rows[1].c4 == "20");
        CHECK(rows[2].name == "Mercantile Office Systems, NP");
        CHECK(rows[3].name == "bad[31m");
        std::vector<AsnRow> none;
        parse_asn_rows("<html>nothing</html>", none);
        CHECK(none.empty());
        AsnCollector sink;
        const Cleaned q = clean_name("mercantile", false);
        sink.query = &q;
        sink.add(0, std::move(rows));
        CHECK(sink.total_rows == 4 && sink.hits.size() == 1 && sink.hits[0].row.asn == "AS4613" && sink.names.size() == 3);
    }
    CHECK(html_text("  a &lt;b&gt; &#65;&#x42; <i>c</i>\n\t d &bogus; ") == "a <b> AB c d &bogus;");

    {
        std::vector<std::string> d;
        std::string msg;
        CHECK(parse_reverse_body("a.example.com\r\nb.example.org\na.example.com\n\nc-d.example.net\n", d, msg));
        CHECK(d.size() == 3 && d[0] == "a.example.com" && d[2] == "c-d.example.net");
        d.clear();
        CHECK(!parse_reverse_body("API count exceeded - Increase Quota with Membership", d, msg));
        CHECK(msg.find("API count exceeded") != std::string::npos && d.empty());
        d.clear();
        CHECK(!parse_reverse_body("error check your search parameter\x1b[2J", d, msg));
        CHECK(msg.find('\x1b') == std::string::npos);
        d.clear();
        CHECK(!parse_reverse_body("No DNS A records found for 1.2.3.4", d, msg));
        d.clear();
        CHECK(!parse_reverse_body("error", d, msg));
        d.clear();
        CHECK(parse_reverse_body("ok.example.com\nsome junk line\nfine.example.com\n", d, msg) && d.size() == 2);
        d.clear();
        CHECK(parse_reverse_body("", d, msg) && d.empty());
    }
    CHECK(is_domain_line("*.example.com") && is_domain_line("a_b.example.com,1.2.3.4"));
    CHECK(!is_domain_line("nodots") && !is_domain_line("has space.com") && !is_domain_line("a.com;rm"));
    {
        std::string out;
        bool adj = false;
        CHECK(normalize_range24("103.48.88.0/24", out, adj) && out == "103.48.88.0/24" && !adj);
        CHECK(normalize_range24(" 103.48.88.33/24 ", out, adj) && out == "103.48.88.0/24" && adj);
        CHECK(!normalize_range24("103.48.88.0/23", out, adj));
        CHECK(!normalize_range24("103.48.88.0/25", out, adj));
        CHECK(!normalize_range24("103.48.88.0", out, adj));
        CHECK(!normalize_range24("2001:db8::/24", out, adj));
        CHECK(!normalize_range24("103.48.88.0/024x", out, adj));
    }
    {
        uint32_t asn = 0;
        CHECK(parse_asn_arg("AS45353", asn) && asn == 45353);
        CHECK(parse_asn_arg("as45353", asn) && asn == 45353);
        CHECK(parse_asn_arg(" 45353 ", asn) && asn == 45353);
        CHECK(parse_asn_arg("4294967295", asn) && asn == 4294967295u);
        CHECK(!parse_asn_arg("4294967296", asn));
        CHECK(!parse_asn_arg("AS", asn) && !parse_asn_arg("AS0", asn) && !parse_asn_arg("", asn));
        CHECK(!parse_asn_arg("AS45x", asn) && !parse_asn_arg("AS-1", asn) && !parse_asn_arg("12345678901", asn));
    }
    {
        const std::string js =
            "{\n  \"asn\": 45353,\n  \"name\": \"NITC-AS-AP - NITC: IT Agency \\u00e9 \\\"Nepal\\\" \\ud83d\\ude00\",\n"
            "  \"organization\": \"NITC\",\n  \"country\": \"NP\",\n  \"rir\": \"APNIC\",\n"
            "  \"routes\": {\n    \"v4\": [\n      \"103.69.124.0/24\",\n      \"202.45.144.0/22\"\n    ],\n    \"v6\": []\n  }\n}";
        std::string name, rir;
        CHECK(json_find_string(js, "name", name) && name == "NITC-AS-AP - NITC: IT Agency \xC3\xA9 \"Nepal\" \xF0\x9F\x98\x80");
        CHECK(json_find_string(js, "rir", rir) && rir == "APNIC");
        CHECK(!json_find_string(js, "missing", rir));
        const size_t rp = js.find("\"routes\"");
        std::vector<std::string> r4, r6;
        CHECK(json_string_array(js, rp, "v4", r4) && r4.size() == 2 && r4[1] == "202.45.144.0/22");
        CHECK(json_string_array(js, rp, "v6", r6) && r6.empty());
        std::vector<std::string> bad;
        CHECK(!json_string_array("{\"v4\": [1, 2]}", 0, "v4", bad));
        CHECK(!json_string_array("{\"v4\": [\"a\"", 0, "v4", bad));
        std::string s;
        CHECK(!json_find_string("{\"k\": \"bad\\q\"}", "k", s));
        CHECK(!json_find_string("{\"k\": \"unterminated", "k", s));
        CHECK(json_find_string("{\"k\": \"\\ud800x\"}", "k", s) && s == "?x");
    }


    {
        const std::string html =
            "<html><table><thead><tr><th>ASN</th><th>Org</th></tr></thead><tbody class=\"x\">"
            "<tr><td><span>AS135303</span></td><td><span>NETTV Pvt. Ltd., NP</span></td><td><span>1</span></td><td><span>0</span></td></tr>\n"
            "<TR class=\"x\">\n<TD><span>AS58504</span></TD>\n<TD><span>TECHMINDS &amp; NETWORKS\n PVT. LTD., NP</span></TD><TD><span>16</span></TD><TD><span>20</span></TD></TR>"
            "<tr><td><span>bogus</span></td><td><span>skip me</span></td></tr>"
            "<tr><td><span>AS4613</span></td><td><span>Mercantile&nbsp;Office Systems, NP</span></td><td><span>32</span></td><td><span>0</span></td></tr>"
            "</tbody></table><table><tbody><tr><td>AS1</td><td>after tbody</td></tr></tbody></table></html>";
        std::vector<AsnRow> ref;
        parse_asn_rows(html, ref);
        CHECK(ref.size() == 3);
        const size_t chunks[] = {1, 2, 3, 5, 7, 16, 64, 1000, 100000};
        for (size_t cs : chunks) {
            AsnRowStream st;
            bool ok = true;
            for (size_t i = 0; i < html.size(); i += cs)
                ok = st.feed(std::string_view(html).substr(i, cs)) && ok;
            st.finish();
            CHECK(ok);
            CHECK(st.rows.size() == ref.size());
            for (size_t i = 0; i < ref.size() && i < st.rows.size(); ++i)
                CHECK(st.rows[i].asn == ref[i].asn && st.rows[i].name == ref[i].name &&
                      st.rows[i].c3 == ref[i].c3 && st.rows[i].c4 == ref[i].c4);
        }
        const std::string nobody =
            "<table><tr><td>AS7</td><td>No Tbody Net, US</td></tr><tr><td>AS8</td><td>Second, US</td></tr></table>";
        AsnRowStream st2;
        for (size_t i = 0; i < nobody.size(); i += 4) st2.feed(std::string_view(nobody).substr(i, 4));
        st2.finish();
        CHECK(st2.rows.size() == 2 && st2.rows[1].asn == "AS8");
        AsnRowStream st3;
        st3.feed("<tbody><tr><td>AS9</td><td>trunc");
        st3.finish();
        CHECK(st3.rows.size() == 1 && st3.rows[0].name == "trunc");
        AsnRowStream st4;
        st4.feed("<tbody><tr>");
        CHECK(!st4.feed(std::string(kMaxAsnRowBytes + 10, 'x')));
        AsnRowStream big;
        std::string many = "<tbody>";
        for (int i = 0; i < 5000; ++i)
            many += "<tr><td>AS" + std::to_string(100 + i) + "</td><td>Org " + std::to_string(i) + ", NP</td></tr>";
        many += "</tbody>";
        for (size_t i = 0; i < many.size(); i += 4096) big.feed(std::string_view(many).substr(i, 4096));
        big.finish();
        CHECK(big.rows.size() == 5000 && big.carry.empty());
        big.reset();
        CHECK(big.rows.empty());
    }

    {
        std::string n = "WorldLink Communications, NP", cc;
        split_trailing_cc(n, cc);
        CHECK(n == "WorldLink Communications" && cc == "NP");
        n = "Acme, LLC"; split_trailing_cc(n, cc);
        CHECK(n == "Acme, LLC" && cc.empty());
        n = "Foo Ltd,BD"; split_trailing_cc(n, cc);
        CHECK(n == "Foo Ltd" && cc == "BD");
        n = "NP"; split_trailing_cc(n, cc);
        CHECK(n == "NP" && cc.empty());

        std::vector<OwnerRow> rows{{"AS141219", "103.156.108.0/23", "BD", "WORLDLINK-AS-AP - World Link"}};
        std::string plain;
        render_owner_table(rows, false, plain);
        CHECK(plain.rfind("ASN", 0) == 0 && plain.find("RANGE") != std::string::npos &&
              plain.find("103.156.108.0/23") != std::string::npos && plain.find('\033') == std::string::npos);
        std::string plain3;
        render_owner_table(rows, false, plain3, false);
        CHECK(plain3.find("RANGE") == std::string::npos && plain3.find("COUNTRY") != std::string::npos);

        std::string s = std::string("a\x1b[31mb") + "\xC2\x9B" + "c" + "\xE2\x80\xAE" + "d\xC3\xA9";
        sanitize_inplace(s);
        CHECK(s == "a[31mbcd\xC3\xA9");
    }

    std::cerr << (g_fail ? "SELFTEST FAILED\n" : "SELFTEST OK\n");
    return g_fail ? 1 : 0;
}
#endif
