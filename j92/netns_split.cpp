#include "netns_split.hpp"
#include "utils.hpp"   // parse_mac(), parse_cidr_generic() -- shared instead of duplicated here

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sched.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

namespace {

constexpr size_t kNlBufSize = 8192;

struct NlMsg {
    char buf[kNlBufSize];
    struct nlmsghdr* nlh;
    NlMsg() {
        memset(buf, 0, sizeof(buf));
        nlh = reinterpret_cast<struct nlmsghdr*>(buf);
    }
};

// nlh always points at the start of an NlMsg::buf (kNlBufSize bytes, fixed
// stack buffer) -- every caller constructs it that way. Bounds-checked
// here so a future caller passing unbounded-length data (e.g. a
// user-controlled interface name) can't walk this write off the end of
// that stack buffer; current callers all pass small/fixed-size data, but
// this guard makes that a documented invariant instead of a silent
// assumption.
void nl_put(struct nlmsghdr* nlh, int type, const void* data, size_t len) {
    size_t rta_len = RTA_LENGTH(len);
    size_t new_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta_len);
    if (new_len > kNlBufSize) {
        // Fail closed: abort rather than write past the buffer. This
        // should never trigger with current callers -- if it does, it
        // means an attribute grew unexpectedly large and silently
        // truncating or corrupting a privileged netlink request would be
        // far worse than a clean crash.
        std::abort();
    }
    auto* rta = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = static_cast<unsigned short>(rta_len);
    if (len) memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = static_cast<uint32_t>(new_len);
}
void nl_put_u32(struct nlmsghdr* nlh, int type, uint32_t v) { nl_put(nlh, type, &v, sizeof(v)); }
void nl_put_str(struct nlmsghdr* nlh, int type, const std::string& s) {
    nl_put(nlh, type, s.c_str(), s.size() + 1);
}

struct rtattr* nl_nest_start(struct nlmsghdr* nlh, int type) {
    auto* nest = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    nl_put(nlh, type, nullptr, 0);
    return nest;
}
void nl_nest_end(struct nlmsghdr* nlh, struct rtattr* nest) {
    nest->rta_len = static_cast<unsigned short>(
        (reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len)) -
        reinterpret_cast<char*>(nest));
}

int open_rtnl_socket() {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Sends nlh (already fully built) and waits for its ACK.
// Returns 0 on success, or the kernel's negative errno on failure.
//
// Uses recvfrom() (not recv()) and checks two things any other local
// process could otherwise spoof on a raw AF_NETLINK socket: that the
// reply actually came from the kernel (nl_pid == 0, not some other local
// process's port), and that its nlmsg_seq matches the request we just
// sent (rejecting stale/unsolicited messages instead of misreading one
// as this call's ACK).
int nl_talk(int fd, struct nlmsghdr* nlh, uint32_t seq) {
    nlh->nlmsg_seq    = seq;
    nlh->nlmsg_flags |= NLM_F_ACK;

    struct sockaddr_nl dst{};
    dst.nl_family = AF_NETLINK;
    struct iovec iov{nlh, nlh->nlmsg_len};
    struct msghdr msg{};
    msg.msg_name    = &dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (sendmsg(fd, &msg, 0) < 0) return -errno;

    char rbuf[kNlBufSize];
    struct sockaddr_nl src{};
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(fd, rbuf, sizeof(rbuf), 0,
                          reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) return -errno;

    if (src.nl_family != AF_NETLINK || src.nl_pid != 0) {
        return -EIO; // not actually from the kernel -- ignore
    }

    for (auto* rh = reinterpret_cast<struct nlmsghdr*>(rbuf);
         NLMSG_OK(rh, static_cast<size_t>(n)); rh = NLMSG_NEXT(rh, n)) {
        if (rh->nlmsg_seq != seq) continue; // not a reply to this request
        if (rh->nlmsg_type == NLMSG_ERROR) {
            auto* e = reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(rh));
            return e->error; // 0 == success ack
        }
    }
    return -EIO;
}

bool detect_default_iface(std::string& iface_out) {
    std::ifstream f("/proc/net/route");
    if (!f) return false;
    std::string line;
    std::getline(f, line); // header
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string ifn, dest, gw, flags, refcnt, use, metric, mask;
        iss >> ifn >> dest >> gw >> flags >> refcnt >> use >> metric >> mask;
        if (dest == "00000000" && mask == "00000000") {
            iface_out = ifn;
            return true;
        }
    }
    return false;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool dotted_mask_to_prefix(const std::string& mask, uint8_t& prefix_out) {
    struct in_addr addr;
    if (inet_pton(AF_INET, mask.c_str(), &addr) != 1) return false;
    uint32_t m = ntohl(addr.s_addr);
    uint32_t inv = ~m;
    if ((inv & (inv + 1)) != 0) return false; // bits must be a contiguous run from the MSB
    uint8_t p = 0;
    for (int i = 31; i >= 0; --i) {
        if (m & (1u << i)) p++;
        else break;
    }
    if (p < 32 && (m & ((p == 0) ? 0xFFFFFFFFu : ((1u << (32 - p)) - 1))) != 0) return false;
    prefix_out = p;
    return true;
}

// Rejects address literals that are syntactically valid but unusable as a
// host/gateway address (unspecified, broadcast, multicast, loopback) --
// inet_pton() alone accepts these, so a typo like "0.0.0.0" or "::" would
// otherwise silently produce a namespace with a nonsensical config instead
// of a clear error.
bool is_unusable_v4(const struct in_addr& a) {
    uint32_t h = ntohl(a.s_addr);
    if (h == 0u)          return true; // 0.0.0.0 (unspecified)
    if (h == 0xFFFFFFFFu) return true; // 255.255.255.255 (broadcast)
    if ((h >> 28) == 0xEu) return true; // 224.0.0.0/4 (multicast)
    if ((h >> 24) == 0x7Fu) return true; // 127.0.0.0/8 (loopback)
    return false;
}

bool is_unusable_v6(const struct in6_addr& a) {
    if (IN6_IS_ADDR_UNSPECIFIED(&a)) return true; // ::
    if (IN6_IS_ADDR_MULTICAST(&a))   return true; // ff00::/8
    if (IN6_IS_ADDR_LOOPBACK(&a))    return true; // ::1
    return false;
}

// Deletes `name` if it currently exists (e.g. a macvlan orphaned in the root
// namespace by a previous --split run that died between creating it and
// moving it into its new namespace). No-op, returns true, if it doesn't
// exist. Equivalent to `ip link del <name>` when found.
bool delete_link_if_exists(int nl_fd, const std::string& name, std::string& err) {
    unsigned idx = if_nametoindex(name.c_str());
    if (idx == 0) return true; // nothing to clean up

    NlMsg m;
    m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    m.nlh->nlmsg_type  = RTM_DELLINK;
    m.nlh->nlmsg_flags = NLM_F_REQUEST;
    auto* ifi = reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(m.nlh));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index  = static_cast<int>(idx);

    int rc = nl_talk(nl_fd, m.nlh, 0);
    if (rc != 0) {
        err = "found a leftover '" + name + "' from a previous run but could not remove it: "
              + strerror(-rc);
        return false;
    }
    return true;
}

bool ioctl_iface_up(const std::string& name, std::string& err) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { err = std::string("socket(AF_INET) failed: ") + strerror(errno); return false; }
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        err = "SIOCGIFFLAGS(" + name + ") failed: " + strerror(errno);
        close(s); return false;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        err = "SIOCSIFFLAGS(" + name + ") failed: " + strerror(errno);
        close(s); return false;
    }
    close(s);
    return true;
}

bool ioctl_iface_ipv4(const std::string& name, const std::string& ip, uint8_t prefix, std::string& err) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { err = std::string("socket(AF_INET) failed: ") + strerror(errno); return false; }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sin->sin_addr) != 1) {
        err = "invalid IPv4 address: " + ip; close(s); return false;
    }
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
        err = "SIOCSIFADDR(" + name + ") failed: " + strerror(errno);
        close(s); return false;
    }

    uint32_t mask_h = prefix == 0 ? 0u : (~0u << (32 - prefix));
    sin->sin_addr.s_addr = htonl(mask_h);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
        err = "SIOCSIFNETMASK(" + name + ") failed: " + strerror(errno);
        close(s); return false;
    }
    close(s);
    return true;
}

bool ioctl_iface_mac(const std::string& name, const std::string& mac, std::string& err) {
    uint8_t b[6];
    if (!parse_mac(mac, b)) { err = "invalid MAC address: " + mac; return false; } // utils.hpp
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { err = std::string("socket(AF_INET) failed: ") + strerror(errno); return false; }
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, b, 6);
    if (ioctl(s, SIOCSIFHWADDR, &ifr) < 0) {
        err = "SIOCSIFHWADDR(" + name + ") failed: " + strerror(errno);
        close(s); return false;
    }
    close(s);
    return true;
}

// IPv6 has no ioctl-based address-assignment path that's reliable across
// kernels (the legacy in6_ifreq/SIOCSIFADDR trick is fragile and
// deprecated) -- netlink RTM_NEWADDR is the correct, modern way to do
// this, same mechanism `ip -6 addr add` itself uses under the hood.
bool nl_add_addr6(int nl_fd, unsigned ifindex, const struct in6_addr& addr,
                   uint8_t prefix, std::string& err) {
    NlMsg m;
    m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    m.nlh->nlmsg_type  = RTM_NEWADDR;
    m.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    auto* ifa = reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(m.nlh));
    ifa->ifa_family    = AF_INET6;
    ifa->ifa_prefixlen = prefix;
    ifa->ifa_flags     = 0;
    ifa->ifa_scope     = 0; // global
    ifa->ifa_index     = ifindex;

    nl_put(m.nlh, IFA_LOCAL,   &addr, sizeof(addr));
    nl_put(m.nlh, IFA_ADDRESS, &addr, sizeof(addr));

    int rc = nl_talk(nl_fd, m.nlh, 10);
    if (rc != 0) {
        err = "failed to add IPv6 address: " + std::string(strerror(-rc));
        return false;
    }
    return true;
}

bool nl_add_route4(int nl_fd, unsigned ifindex, const struct in_addr& gw, std::string& err) {
    NlMsg m;
    m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    m.nlh->nlmsg_type  = RTM_NEWROUTE;
    m.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    auto* rtm = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(m.nlh));
    rtm->rtm_family   = AF_INET;
    rtm->rtm_dst_len  = 0;
    rtm->rtm_src_len  = 0;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
    rtm->rtm_type     = RTN_UNICAST;

    nl_put(m.nlh, RTA_GATEWAY, &gw, sizeof(gw));
    nl_put_u32(m.nlh, RTA_OIF, ifindex);

    int rc = nl_talk(nl_fd, m.nlh, 11);
    if (rc != 0) {
        err = "failed to add IPv4 default route: " + std::string(strerror(-rc));
        return false;
    }
    return true;
}

bool nl_add_route6(int nl_fd, unsigned ifindex, const struct in6_addr& gw, std::string& err) {
    NlMsg m;
    m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    m.nlh->nlmsg_type  = RTM_NEWROUTE;
    m.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    auto* rtm = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(m.nlh));
    rtm->rtm_family   = AF_INET6;
    rtm->rtm_dst_len  = 0;
    rtm->rtm_src_len  = 0;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
    rtm->rtm_type     = RTN_UNICAST;

    nl_put(m.nlh, RTA_GATEWAY, &gw, sizeof(gw));
    nl_put_u32(m.nlh, RTA_OIF, ifindex);

    int rc = nl_talk(nl_fd, m.nlh, 12);
    if (rc != 0) {
        err = "failed to add IPv6 default route: " + std::string(strerror(-rc));
        return false;
    }
    return true;
}

} // namespace

bool build_split_ip_cidr(const std::string& ip_addr, const std::string& ip_prefix_field,
                          std::string& cidr_out, std::string& err) {
    struct in_addr tmp;
    if (ip_addr.empty() || inet_pton(AF_INET, ip_addr.c_str(), &tmp) != 1) {
        err = "invalid IP_ADDR: '" + ip_addr + "'";
        return false;
    }
    uint8_t prefix = 0;
    if (ip_prefix_field.find('.') != std::string::npos) {
        if (!dotted_mask_to_prefix(ip_prefix_field, prefix)) {
            err = "invalid IP_PREFIX netmask: '" + ip_prefix_field + "'";
            return false;
        }
    } else {
        try {
            int p = std::stoi(ip_prefix_field);
            if (p < 0 || p > 32) throw std::out_of_range("prefix");
            prefix = static_cast<uint8_t>(p);
        } catch (...) {
            err = "invalid IP_PREFIX: '" + ip_prefix_field + "'";
            return false;
        }
    }
    cidr_out = ip_addr + "/" + std::to_string(static_cast<int>(prefix));
    return true;
}

bool build_split_ip6_cidr(const std::string& ip6_addr, const std::string& ip6_prefix_field,
                           std::string& cidr_out, std::string& err) {
    struct in6_addr tmp;
    if (ip6_addr.empty() || inet_pton(AF_INET6, ip6_addr.c_str(), &tmp) != 1) {
        err = "invalid IP6_ADDR: '" + ip6_addr + "'";
        return false;
    }
    // No dotted-mask form for IPv6 -- always a bare prefix length.
    uint8_t prefix = 0;
    try {
        int p = std::stoi(ip6_prefix_field);
        if (p < 0 || p > 128) throw std::out_of_range("prefix");
        prefix = static_cast<uint8_t>(p);
    } catch (...) {
        err = "invalid IP6_PREFIX: '" + ip6_prefix_field + "'";
        return false;
    }
    cidr_out = ip6_addr + "/" + std::to_string(static_cast<int>(prefix));
    return true;
}

bool load_split_conf(const std::string& path, SplitFileConf& out, std::string& err) {
    std::ifstream f(path);
    if (!f) {
        err = "cannot open '" + path + "'";
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key  = trim(t.substr(0, eq));
        std::string rest = trim(t.substr(eq + 1));
        std::string value;
        if (!rest.empty() && rest[0] == '"') {
            size_t close = rest.find('"', 1);
            value = (close == std::string::npos) ? rest.substr(1) : rest.substr(1, close - 1);
        } else {
            size_t hash = rest.find('#');
            value = trim(hash == std::string::npos ? rest : rest.substr(0, hash));
        }
        if      (key == "NS")           out.ns_label    = value;
        else if (key == "CUSTOM_MAC")   out.mac         = value;
        else if (key == "IP_ADDR")      out.ip_addr     = value;
        else if (key == "IP_PREFIX")    out.ip_prefix   = value;
        else if (key == "GATEWAY")      out.gateway     = value;
        else if (key == "IP6_ADDR")     out.ip6_addr    = value;
        else if (key == "IP6_PREFIX")   out.ip6_prefix  = value;
        else if (key == "IP6_GATEWAY")  out.ip6_gateway = value;
        else if (key == "DNS1")         out.dns1        = value;
        else if (key == "DNS2")         out.dns2        = value;
    }
    return true;
}

bool enter_split_namespace(const SplitNsConfig& cfg, std::string& err) {
    bool want_v4 = !cfg.ip_cidr.empty() || !cfg.gateway.empty();
    bool want_v6 = !cfg.ip6_cidr.empty() || !cfg.gateway6.empty();

    if (!want_v4 && !want_v6) {
        err = "--split requires IPv4 (--split-ip + --split-gw) and/or "
              "IPv6 (--split-ip6 + --split-gw6) configuration";
        return false;
    }
    if (want_v4 && (cfg.ip_cidr.empty() || cfg.gateway.empty())) {
        err = "--split-ip and --split-gw must both be set together (IPv4 config is incomplete)";
        return false;
    }
    if (want_v6 && (cfg.ip6_cidr.empty() || cfg.gateway6.empty())) {
        err = "--split-ip6 and --split-gw6 must both be set together (IPv6 config is incomplete)";
        return false;
    }

    std::string ip4; uint8_t prefix4 = 0;
    struct in_addr ip4_check{}, gw4_check{};
    if (want_v4) {
        if (!parse_cidr_generic(cfg.ip_cidr, AF_INET, ip4, prefix4)) { // utils.hpp
            err = "--split-ip must be IPv4 CIDR form, e.g. 192.168.1.114/24";
            return false;
        }
        inet_pton(AF_INET, ip4.c_str(), &ip4_check); // already validated by parse_cidr_generic
        if (is_unusable_v4(ip4_check)) {
            err = "--split-ip is not a usable host address (unspecified/broadcast/multicast/loopback)";
            return false;
        }
        if (inet_pton(AF_INET, cfg.gateway.c_str(), &gw4_check) != 1) {
            err = "--split-gw is not a valid IPv4 address";
            return false;
        }
        if (is_unusable_v4(gw4_check)) {
            err = "--split-gw is not a usable gateway address (unspecified/broadcast/multicast/loopback)";
            return false;
        }
    }

    std::string ip6; uint8_t prefix6 = 0;
    struct in6_addr ip6_check{}, gw6_check{};
    if (want_v6) {
        if (!parse_cidr_generic(cfg.ip6_cidr, AF_INET6, ip6, prefix6)) { // utils.hpp
            err = "--split-ip6 must be IPv6 CIDR form, e.g. 2001:db8::114/64";
            return false;
        }
        inet_pton(AF_INET6, ip6.c_str(), &ip6_check); // already validated by parse_cidr_generic
        if (is_unusable_v6(ip6_check)) {
            err = "--split-ip6 is not a usable host address (unspecified/multicast/loopback)";
            return false;
        }
        if (inet_pton(AF_INET6, cfg.gateway6.c_str(), &gw6_check) != 1) {
            err = "--split-gw6 is not a valid IPv6 address";
            return false;
        }
        if (is_unusable_v6(gw6_check)) {
            err = "--split-gw6 is not a usable gateway address (unspecified/multicast/loopback)";
            return false;
        }
    }

    std::string base_iface = cfg.base_iface;
    if (base_iface.empty() && !detect_default_iface(base_iface)) {
        err = "could not auto-detect a default-route interface; pass --split-iface explicitly";
        return false;
    }
    unsigned base_idx = if_nametoindex(base_iface.c_str());
    if (base_idx == 0) {
        err = "interface not found: " + base_iface;
        return false;
    }

    // 1) Netlink socket opened NOW, while we're still in the root netns.
    //    A netlink fd keeps the namespace it was opened in even after this
    //    process later calls unshare(CLONE_NEWNET) -- that's exactly what
    //    lets us move the macvlan device (created below, in the root ns)
    //    into our own brand-new namespace in step 4.
    int nl_root = open_rtnl_socket();
    if (nl_root < 0) { err = "failed to open root netlink socket"; return false; }

    // 1b) Self-heal: if a previous --split run died between creating the
    //     macvlan (step 2 below) and moving it into its own namespace
    //     (step 4), it's left sitting, unused, in the root namespace --
    //     nothing ever auto-removes it since it was never inside a
    //     namespace that gets torn down on process exit. Clear it out
    //     before trying to create a fresh one with the same name.
    if (!delete_link_if_exists(nl_root, cfg.veth_name, err)) {
        close(nl_root);
        return false;
    }

    // 2) Create the macvlan device in the root namespace, bridged off
    //    base_iface -- the code equivalent of:
    //      ip link add macvlan0 link eth0 type macvlan mode bridge
    //    This is L2-level and family-agnostic -- one macvlan device carries
    //    both the v4 and v6 addresses configured below.
    {
        NlMsg m;
        m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        m.nlh->nlmsg_type  = RTM_NEWLINK;
        m.nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
        auto* ifi = reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(m.nlh));
        ifi->ifi_family = AF_UNSPEC;

        nl_put_u32(m.nlh, IFLA_LINK, base_idx);
        nl_put_str(m.nlh, IFLA_IFNAME, cfg.veth_name);

        struct rtattr* linkinfo = nl_nest_start(m.nlh, IFLA_LINKINFO);
        nl_put_str(m.nlh, IFLA_INFO_KIND, "macvlan");
        struct rtattr* infodata = nl_nest_start(m.nlh, IFLA_INFO_DATA);
        nl_put_u32(m.nlh, IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);
        nl_nest_end(m.nlh, infodata);
        nl_nest_end(m.nlh, linkinfo);

        int rc = nl_talk(nl_root, m.nlh, 1);
        if (rc != 0) {
            close(nl_root);
            err = "failed to create macvlan '" + cfg.veth_name + "': " + strerror(-rc);
            return false;
        }
    }

    unsigned mv_idx = if_nametoindex(cfg.veth_name.c_str());
    if (mv_idx == 0) {
        close(nl_root);
        err = "macvlan device was created but could not be found afterwards";
        return false;
    }

    // 3) Detach: from here on this process lives in a brand-new, empty
    //    net namespace (only `lo`, down, auto-assigned 127.0.0.1/8).
    //    Equivalent to `ip netns add` + entering it, minus the persistent
    //    bind-mount under /var/run/netns -- we don't need a *named*
    //    namespace since only this process ever needs to be in it, and it
    //    is reclaimed automatically the moment this process exits.
    if (unshare(CLONE_NEWNET) != 0) {
        close(nl_root);
        err = std::string("unshare(CLONE_NEWNET) failed: ") + strerror(errno) +
              " (needs root / CAP_SYS_ADMIN, same as ns1.sh's sudo calls)";
        return false;
    }

    // 4) Move the macvlan device into our (now current) namespace, by
    //    pid -- equivalent to `ip link set macvlan0 netns scan-ns`.
    {
        NlMsg m;
        m.nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        m.nlh->nlmsg_type  = RTM_NEWLINK;
        m.nlh->nlmsg_flags = NLM_F_REQUEST;
        auto* ifi = reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(m.nlh));
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index  = static_cast<int>(mv_idx);

        nl_put_u32(m.nlh, IFLA_NET_NS_PID, static_cast<uint32_t>(getpid()));

        int rc = nl_talk(nl_root, m.nlh, 2);
        close(nl_root);
        if (rc != 0) {
            err = "failed to move '" + cfg.veth_name + "' into new namespace: " + strerror(-rc);
            return false;
        }
    }

    // 5) Fully inside the new namespace now: bring lo up, set the
    //    macvlan's MAC, assign whichever of v4/v6 were configured, bring
    //    it up, add the matching default route(s) -- the dual-stack
    //    equivalent of ns1.sh (its DNS step is intentionally skipped; use
    //    --dns-servers instead, see enter_split_namespace's caller).
    if (!ioctl_iface_up("lo", err)) return false;
    if (!cfg.mac.empty() && !ioctl_iface_mac(cfg.veth_name, cfg.mac, err)) return false;

    int nl_new = open_rtnl_socket();
    if (nl_new < 0) { err = "failed to open netlink socket in new namespace"; return false; }

    if (want_v4 && !ioctl_iface_ipv4(cfg.veth_name, ip4, prefix4, err)) {
        close(nl_new); return false;
    }
    if (want_v6) {
        struct in6_addr addr6{};
        inet_pton(AF_INET6, ip6.c_str(), &addr6);
        if (!nl_add_addr6(nl_new, mv_idx, addr6, prefix6, err)) { close(nl_new); return false; }
    }

    if (!ioctl_iface_up(cfg.veth_name, err)) { close(nl_new); return false; }

    if (want_v4) {
        struct in_addr gw4{};
        inet_pton(AF_INET, cfg.gateway.c_str(), &gw4);
        if (!nl_add_route4(nl_new, mv_idx, gw4, err)) { close(nl_new); return false; }
    }
    if (want_v6) {
        struct in6_addr gw6{};
        inet_pton(AF_INET6, cfg.gateway6.c_str(), &gw6);
        if (!nl_add_route6(nl_new, mv_idx, gw6, err)) { close(nl_new); return false; }
    }

    close(nl_new);
    return true;
}
