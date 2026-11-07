#include "utils.hpp"
#include <netinet/ip6.h>
#include <linux/filter.h>   
#include "public_db.hpp"
#include "scan.hpp"
#include "anomaly_analysis.hpp"
#include <queue>
#include <stdexcept>
#include <netinet/ip_icmp.h>
#include <unordered_set>
#include <array>
#include <curl/curl.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <cmath>
#include <bitset>
#include <array>
#include <shared_mutex>
#include <bitset>

#ifdef __AVX2__
#include <immintrin.h>  
#else
#include <emmintrin.h>  
#endif

#include "arp_handler.hpp"

bool set_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4], const uint8_t mac[6]) {
    if (!ifname || !ip_bytes || !mac) return false;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        std::cerr << "set_static_arp_entry: socket() failed: " << strerror(errno) << "\n";
        return false;
    }

    struct arpreq req{};
    auto* pa = reinterpret_cast<sockaddr_in*>(&req.arp_pa);
    pa->sin_family = AF_INET;
    memcpy(&pa->sin_addr, ip_bytes, 4);

    req.arp_ha.sa_family = ARPHRD_ETHER;
    memcpy(req.arp_ha.sa_data, mac, 6);
    req.arp_flags = ATF_COM | ATF_PERM;

    std::strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);
    req.arp_dev[sizeof(req.arp_dev) - 1] = '\0';

    bool ok = (ioctl(s, SIOCSARP, &req) == 0);
    if (!ok) {
        char ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, ip_bytes, ip_str, sizeof(ip_str));
        std::cerr << "set_static_arp_entry: failed to pin " << ip_str
                  << " -> " << format_mac(mac) << " on " << ifname
                  << ": " << strerror(errno)
                  << " (need root/CAP_NET_ADMIN)\n";
    }
    close(s);
    return ok;
}

void delete_static_arp_entry(const char* ifname, const uint8_t ip_bytes[4]) {
    if (!ifname || !ip_bytes) return;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct arpreq req{};
    auto* pa = reinterpret_cast<sockaddr_in*>(&req.arp_pa);
    pa->sin_family = AF_INET;
    memcpy(&pa->sin_addr, ip_bytes, 4);

    std::strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);
    req.arp_dev[sizeof(req.arp_dev) - 1] = '\0';
    ioctl(s, SIOCDARP, &req);
    close(s);
}

// ─────────────────────────────────────────────────────────────────────────
// Shared packet-framing helpers. Both the initial burst (send_arp_request)
// and every retransmit round (retransmit_arp_requests) build the exact same
// Ethernet+ARP broadcast frame, differing only in the per-target dst_ip.
// Pulling that out here means the framing logic — VLAN tags, custom
// ethertype, gratuitous-ARP handling — only has to be written once, and the
// retransmit path no longer needs its own (previously raw-sendto) copy.
// ─────────────────────────────────────────────────────────────────────────
namespace {

struct ArpPacketLayout {
    size_t eth_hdr_len;
    size_t packet_size;
};

ArpPacketLayout compute_arp_layout(const EthArpOptions& eth_opts) {
    const size_t vlan_bytes  = eth_opts.vlan_ids.size() * 4;   // 4B per 802.1Q tag
    const size_t eth_hdr_len = 12 + vlan_bytes + 2;            // dst(6)+src(6)+tags+ethertype(2)
    const size_t packet_size = eth_hdr_len + sizeof(arp_header) + eth_opts.padding_size;
    return { eth_hdr_len, packet_size };
}

// Fills in everything except arp->dst_ip (the caller sets that per-target).
void build_arp_template(uint8_t* eth_ptr, const ArpPacketLayout& layout,
                         uint8_t* src_mac, uint8_t* src_ip,
                         const EthArpOptions& eth_opts) {
    memset(eth_ptr, 0xFF, 6);   // dst_mac = broadcast
    memcpy(eth_ptr + 6, eth_opts.use_custom_src_mac ? eth_opts.custom_src_mac : src_mac, 6);

    size_t off = 12;
    for (uint16_t vid : eth_opts.vlan_ids) {
        uint16_t tpid = htons(0x8100);
        uint16_t tci  = htons(vid & 0x0FFF);
        memcpy(eth_ptr + off, &tpid, 2); off += 2;
        memcpy(eth_ptr + off, &tci,  2); off += 2;
    }
    uint16_t final_ethertype = htons(eth_opts.use_custom_ethertype ? eth_opts.custom_ethertype : ETH_P_ARP);
    memcpy(eth_ptr + off, &final_ethertype, 2);

    auto* arp = reinterpret_cast<arp_header*>(eth_ptr + layout.eth_hdr_len);
    arp->htype  = htons(1);
    arp->ptype  = htons(ETH_P_IP);
    arp->hlen   = 6;
    arp->plen   = 4;
    arp->opcode = htons((eth_opts.arp_mode == ArpOpMode::REPLY) ? 2 : 1);
    memcpy(arp->src_mac, src_mac, 6);
    memcpy(arp->src_ip, src_ip, 4);
    if (eth_opts.arp_mode == ArpOpMode::GRATUITOUS) {
        memcpy(arp->dst_ip, src_ip, 4);   // gratuitous ARP announces our own IP as target
    }
}

sockaddr_ll make_broadcast_sockaddr(int ifindex) {
    sockaddr_ll sa{};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;
    memset(sa.sll_addr, 0xFF, ETH_ALEN);
    return sa;
}

// Queues one ARP request per still-unresolved target as an io_uring SQE —
// this replaces the old retransmit_arp_requests(), which called a blocking
// sendto() per host on every retry round (the single biggest source of raw
// syscalls in ARP-based host discovery). Sends are fire-and-forget: they're
// tagged with a null user_data pointer, which receive_arp_reply's existing
// CQE loop already recognizes and skips (`if (tagged == 0) continue;`), so
// no new completion-handling logic is needed there.
//
// Returns the number of SQEs actually queued, so the caller knows how many
// completions to wait for before it's safe to free `pkt_pool`.
size_t retransmit_arp_requests_uring(struct io_uring* ring, int sock,
                                      const sockaddr_ll& sa,
                                      const ArpPacketLayout& layout,
                                      const std::vector<uint8_t>& packet_template,
                                      const std::vector<uint8_t*>& unresolved_IPs,
                                      std::vector<std::unique_ptr<uint8_t[]>>& pkt_pool) {
    if (unresolved_IPs.empty() || !ring) return 0;

    size_t queued = 0;
    for (uint8_t* target_ip : unresolved_IPs) {
        if (!target_ip) continue;
        if (target_ip[0] == 0 && target_ip[1] == 0 && target_ip[2] == 0 && target_ip[3] == 0) continue;

        auto pkt = std::make_unique<uint8_t[]>(layout.packet_size);
        memcpy(pkt.get(), packet_template.data(), layout.packet_size);
        auto* arp = reinterpret_cast<arp_header*>(pkt.get() + layout.eth_hdr_len);
        memcpy(arp->dst_ip, target_ip, 4);

        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            io_uring_submit(ring);          // free up SQ slots, retry once
            sqe = io_uring_get_sqe(ring);
            if (!sqe) break;                // still full — remaining targets get picked up next round
        }

        io_uring_prep_sendto(sqe, sock, pkt.get(), layout.packet_size, 0,
                              (sockaddr*)&sa, sizeof(sa));
        io_uring_sqe_set_data(sqe, nullptr);

        pkt_pool.push_back(std::move(pkt));  // keep alive until the caller drains this many completions
        queued++;
    }

    if (queued > 0) io_uring_submit(ring);
    return queued;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// send_arp_request — queues the *entire* target list as io_uring SQEs before
// waiting on anything, then reaps all completions in a single bulk drain.
//
// The previous version submitted in chunks of 64 and fully drained each
// chunk's completions before building the next chunk — that's fine
// correctness-wise, but it serializes what should be one async burst into
// many small io_uring_enter round trips (waiting on chunk N's sends to
// finish buys nothing; nothing after this function depends on it). This
// version keeps the same per-target validation and error handling, just
// queues first and waits once.
// ─────────────────────────────────────────────────────────────────────────
bool send_arp_request(int sock, struct io_uring* ring, const char* ifname, 
                      uint8_t* src_mac, uint8_t* src_ip, 
                      const std::vector<uint8_t*>& target_IPs,
                      const EthArpOptions& eth_opts) {
    if (!src_mac || !src_ip || !ifname || !ring || target_IPs.empty()) {
        std::cerr << "send_arp_request: Invalid parameters\n";
        return false;
    }
    
    bool all_zero_mac = true;
    for (int i = 0; i < 6; i++) {
        if (src_mac[i] != 0) { all_zero_mac = false; break; }
    }
    if (all_zero_mac) {
        std::cerr << "send_arp_request: Invalid source MAC (all zeros)\n";
        return false;
    }
    
    bool all_zero_ip = true;
    for (int i = 0; i < 4; i++) {
        if (src_ip[i] != 0) { all_zero_ip = false; break; }
    }
    if (all_zero_ip) {
        std::cerr << "send_arp_request: Invalid source IP (all zeros)\n";
        return false;
    }
    
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        std::cerr << "send_arp_request: Invalid interface name: " << ifname << "\n";
        return false;
    }

    for (size_t i = 0; i < target_IPs.size(); ++i) {
        if (!target_IPs[i]) {
            std::cerr << "send_arp_request: target_IPs[" << i << "] is null\n";
            return false;
        }
    }

    const sockaddr_ll sa = make_broadcast_sockaddr(ifindex);
    const ArpPacketLayout layout = compute_arp_layout(eth_opts);

    std::vector<uint8_t> packet_template(layout.packet_size, 0);
    build_arp_template(packet_template.data(), layout, src_mac, src_ip, eth_opts);

    const size_t total_packets = target_IPs.size();

    // One flat buffer holding every packet for this call — kept alive until
    // the bulk drain below finishes. For realistic ARP sweep sizes (a handful
    // of /16s at most) this is a few MB at worst; trading that for one drain
    // pass instead of one per 64-packet chunk is the right trade here.
    auto packets = std::make_unique<uint8_t[]>(total_packets * layout.packet_size);

    int total_submitted = 0;

    for (size_t i = 0; i < total_packets && !terminate_flag; ++i) {
        if (target_IPs[i][0] == 0 && target_IPs[i][1] == 0 &&
            target_IPs[i][2] == 0 && target_IPs[i][3] == 0) {
            std::cerr << "send_arp_request: Skipping packet with zero target IP\n";
            continue;
        }

        uint8_t* pkt_ptr = packets.get() + i * layout.packet_size;
        memcpy(pkt_ptr, packet_template.data(), layout.packet_size);
        auto* pkt_arp = reinterpret_cast<arp_header*>(pkt_ptr + layout.eth_hdr_len);
        memcpy(pkt_arp->dst_ip, target_IPs[i], 4);
        if (eth_opts.padding_size > 0 && eth_opts.random_padding) {
            uint8_t* pad = pkt_ptr + layout.eth_hdr_len + sizeof(arp_header);
            for (uint16_t k = 0; k < eth_opts.padding_size; k++) pad[k] = static_cast<uint8_t>(rand() & 0xFF);
        }

        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            int submitted = io_uring_submit(ring);
            if (submitted > 0) total_submitted += submitted;
            sqe = io_uring_get_sqe(ring);
            if (!sqe) {
                std::cerr << "send_arp_request: SQE ring saturated, "
                          << (total_packets - i) << " target(s) skipped this call "
                          << "(consider a deeper ring for very large target lists)\n";
                break;
            }
        }

        io_uring_prep_sendto(sqe, sock, pkt_ptr, layout.packet_size, 0,
                             (sockaddr*)&sa, sizeof(sa));
        io_uring_sqe_set_data(sqe, nullptr);
    }

    {
        int submitted = io_uring_submit(ring);
        if (submitted < 0) {
            std::cerr << "send_arp_request: io_uring_submit failed: " << strerror(-submitted) << "\n";
        } else {
            total_submitted += submitted;
        }
    }

    // ---- single bulk drain for the whole call, instead of one per 64-packet chunk ----
    if (total_submitted > 0) {
        auto start = std::chrono::steady_clock::now();
        int processed = 0;
        const int MAX_WAIT_MS = 2000;

        while (processed < total_submitted && !terminate_flag) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed_ms >= MAX_WAIT_MS) {
                std::cerr << "send_arp_request: Timeout waiting for send completions ("
                          << processed << "/" << total_submitted << ")\n";
                break;
            }

            int remaining_ms = static_cast<int>(MAX_WAIT_MS - elapsed_ms);
            io_uring_cqe* cqe;
            struct __kernel_timespec ts = {
                .tv_sec  = remaining_ms / 1000,
                .tv_nsec = (remaining_ms % 1000) * 1000000
            };
            int ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
            
            if (ret == 0) {
                unsigned head;
                unsigned batch_n = 0;
                io_uring_for_each_cqe(ring, head, cqe) {
                    if (cqe->res < 0) {
                        std::cerr << "send_arp_request: ARP send failed: " 
                                  << strerror(-cqe->res) << "\n";
                    }
                    batch_n++;
                }
                io_uring_cq_advance(ring, batch_n);
                processed += batch_n;
            } else if (ret == -ETIME) {
                continue;
            } else if (ret != -EINTR) {
                std::cerr << "send_arp_request: wait_cqe error: " << strerror(-ret) << "\n";
                break;
            }
        }
        
        if (processed < total_submitted) {
            std::cerr << "send_arp_request: Only processed " << processed
                      << " of " << total_submitted << " completions -- "
                      << "forcing a blocking drain before freeing the buffer\n";
            while (processed < total_submitted) {
                io_uring_cqe* cqe;
                int ret = io_uring_wait_cqe(ring, &cqe);
                if (ret < 0) {
                    std::cerr << "send_arp_request: forced drain wait_cqe error: "
                              << strerror(-ret) << "\n";
                    break;
                }
                if (cqe->res < 0) {
                    std::cerr << "send_arp_request: ARP send failed: "
                              << strerror(-cqe->res) << "\n";
                }
                io_uring_cqe_seen(ring, cqe);
                processed++;
            }
        }
    }
    
    return total_submitted > 0;
}

// ─────────────────────────────────────────────────────────────────────────
// receive_arp_reply — unchanged resolution/round-timeout logic, except:
//   1. the broadcast sockaddr and packet template are now built once, up
//      front, instead of being rebuilt from scratch on every retransmit
//      round;
//   2. retransmits are queued through the ring (retransmit_arp_requests_uring)
//      instead of a blocking sendto() loop;
//   3. because retransmit sends are now async, their buffers can't be freed
//      the moment the loop moves on — pending_retransmit_sends tracks how
//      many send completions are still outstanding, and the final cleanup
//      section drains exactly that many before the function (and its local
//      buffer pool) goes out of scope.
// ─────────────────────────────────────────────────────────────────────────
bool receive_arp_reply(int sock, struct io_uring* ring, 
                      const std::vector<uint8_t*>& target_IPs,std::vector<uint8_t*>& macs,
                      const EthArpOptions& eth_opts, int initial_rtt_ms,
                      const char* ifname, uint8_t* src_mac, uint8_t* src_ip,
                      int max_retries, int min_round_timeout_ms, int max_round_timeout_ms,
                      std::vector<double>* out_rtt_ms) {
    if (!ring || target_IPs.empty() || macs.size() != target_IPs.size()) 
        return false;
    for (size_t i = 0; i < macs.size(); ++i) {
        if (!macs[i]) return false;
        memset(macs[i], 0, 6);
    }
    for (size_t i = 0; i < target_IPs.size(); ++i) {
        if (!target_IPs[i]) return false;
    }

    {
        int rcvbuf = 4 * 1024 * 1024;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
            setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    const size_t total_targets = target_IPs.size();
    if (out_rtt_ms) out_rtt_ms->assign(total_targets, 0.0);
    std::vector<bool> resolved(total_targets, false);
    int total_resolved = 0;
    if (initial_rtt_ms <= 0) initial_rtt_ms = 100;
    if (max_retries < 0) max_retries = 0;
    if (min_round_timeout_ms <= 0) min_round_timeout_ms = 20;
    if (max_round_timeout_ms < min_round_timeout_ms) max_round_timeout_ms = min_round_timeout_ms;

    double ewma_rtt_ms = static_cast<double>(initial_rtt_ms);
    auto compute_round_timeout = [&]() -> int {
        double t = ewma_rtt_ms * 3.0;   // headroom for jitter
        if (t < min_round_timeout_ms) t = min_round_timeout_ms;
        if (t > max_round_timeout_ms) t = max_round_timeout_ms;
        return static_cast<int>(t);
    };

    std::unordered_map<uint32_t, size_t> ip_to_index;
    ip_to_index.reserve(total_targets);
    for (size_t i = 0; i < total_targets; ++i) {
        uint32_t ip_val;
        memcpy(&ip_val, target_IPs[i], 4);
        if (ip_to_index.find(ip_val) != ip_to_index.end()) 
            return false;
        ip_to_index[ip_val] = i;
    }
    const size_t vlan_bytes_rx  = eth_opts.vlan_ids.size() * 4;
    const size_t eth_hdr_len_rx = 12 + vlan_bytes_rx + 2;
    const size_t MIN_PACKET_SIZE = eth_hdr_len_rx + sizeof(arp_header);
    const size_t MAX_PACKET_SIZE = 1500;
    const size_t POOL_SIZE = std::min<size_t>(64, std::max<size_t>(total_targets, 8));
    struct RecvSlot {
        std::unique_ptr<uint8_t[]> buf;
        struct iovec  iov{};
        struct msghdr msg{};
        bool in_flight = false;
    };
    std::vector<RecvSlot> pool(POOL_SIZE);

    auto arm_slot = [&](size_t idx) -> bool {
        RecvSlot& s = pool[idx];
        if (!s.buf) s.buf = std::make_unique<uint8_t[]>(MAX_PACKET_SIZE);
        s.iov.iov_base = s.buf.get();
        s.iov.iov_len  = MAX_PACKET_SIZE;
        s.msg = {};
        s.msg.msg_iov    = &s.iov;
        s.msg.msg_iovlen = 1;
        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        if (!sqe) return false;
        io_uring_prep_recvmsg(sqe, sock, &s.msg, 0);
        io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(idx + 1));
        s.in_flight = true;
        return true;
    };

    size_t armed = 0;
    for (size_t i = 0; i < POOL_SIZE; ++i) {
        if (arm_slot(i)) ++armed; else break;
    }
    if (armed == 0) return false;
    io_uring_submit(ring);

    // ---- retransmit setup: build the broadcast frame once, reuse every round ----
    int ifindex = if_nametoindex(ifname);
    const bool can_retransmit = (ifindex != 0 && src_mac && src_ip);
    const sockaddr_ll retransmit_sa = can_retransmit ? make_broadcast_sockaddr(ifindex) : sockaddr_ll{};
    const ArpPacketLayout retransmit_layout = compute_arp_layout(eth_opts);
    std::vector<uint8_t> retransmit_template;
    if (can_retransmit) {
        retransmit_template.assign(retransmit_layout.packet_size, 0);
        build_arp_template(retransmit_template.data(), retransmit_layout, src_mac, src_ip, eth_opts);
    }
    // Holds every retransmit packet buffer queued this call; nothing here is
    // freed until pending_retransmit_sends (below) confirms the kernel is
    // done reading them.
    std::vector<std::unique_ptr<uint8_t[]>> retransmit_pkt_pool;
    size_t pending_retransmit_sends = 0;

    int attempts_used = 0;   // retransmit rounds consumed so far (not counting the initial send)
    auto round_start = std::chrono::steady_clock::now();
    int  round_timeout_ms = compute_round_timeout();

    while (total_resolved < total_targets && !terminate_flag) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_in_round_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - round_start).count();

        if (elapsed_in_round_ms >= round_timeout_ms) {
            if (attempts_used >= max_retries) break;   // out of retries — accept whoever answered
            if (can_retransmit) {
                std::vector<uint8_t*> unresolved_ips;
                unresolved_ips.reserve(total_targets - total_resolved);
                for (size_t i = 0; i < total_targets; ++i) {
                    if (!resolved[i]) unresolved_ips.push_back(target_IPs[i]);
                }
                pending_retransmit_sends += retransmit_arp_requests_uring(
                    ring, sock, retransmit_sa, retransmit_layout, retransmit_template,
                    unresolved_ips, retransmit_pkt_pool);
            }
            attempts_used++;
            round_start = current_time;
            round_timeout_ms = compute_round_timeout();
            continue;
        }

        int remaining_ms = std::max(1, round_timeout_ms - static_cast<int>(elapsed_in_round_ms));
        struct __kernel_timespec timeout_ts = {
            .tv_sec  = remaining_ms / 1000,
            .tv_nsec = (remaining_ms % 1000) * 1000000
        };
        struct io_uring_cqe *cqe = nullptr;
        int ret = io_uring_wait_cqe_timeout(ring, &cqe, &timeout_ts);
        if (ret == -ETIME) continue;
        if (ret == -EINTR) continue;
        if (ret != 0) break;
        unsigned head;
        unsigned cqe_count = 0;
        io_uring_for_each_cqe(ring, head, cqe) {
            cqe_count++;
            uintptr_t tagged = reinterpret_cast<uintptr_t>(io_uring_cqe_get_data(cqe));
            int bytes_received = cqe->res;
            if (tagged == 0) {
                // A retransmit send completion (fire-and-forget) — not a recv slot.
                if (pending_retransmit_sends > 0) pending_retransmit_sends--;
                continue;
            }
            size_t slot_idx = static_cast<size_t>(tagged - 1);
            if (slot_idx >= pool.size()) continue;
            RecvSlot& s = pool[slot_idx];
            s.in_flight = false;

            if (bytes_received > 0
                && bytes_received >= static_cast<ssize_t>(MIN_PACKET_SIZE)
                && bytes_received <= static_cast<ssize_t>(MAX_PACKET_SIZE)) {
                uint8_t* received_buffer = s.buf.get();
                size_t rx_off = 12;
                uint16_t rx_ethertype;
                memcpy(&rx_ethertype, received_buffer + rx_off, 2);
                rx_ethertype = ntohs(rx_ethertype);
                for (int tag_i = 0; tag_i < 2 && rx_ethertype == 0x8100; tag_i++) {
                    rx_off += 4;
                    memcpy(&rx_ethertype, received_buffer + rx_off, 2);
                    rx_ethertype = ntohs(rx_ethertype);
                }
                rx_off += 2;
                if (rx_ethertype == ETH_P_ARP &&
                    rx_off + sizeof(arp_header) <= static_cast<size_t>(bytes_received)) {
                    struct arp_header* arp = reinterpret_cast<struct arp_header*>(
                        received_buffer + rx_off);
                    if (ntohs(arp->opcode) == 2 && arp->hlen == 6 && arp->plen == 4) {
                        uint32_t src_ip_rx;
                        memcpy(&src_ip_rx, arp->src_ip, 4); 
                        auto it = ip_to_index.find(src_ip_rx);
                        if (it != ip_to_index.end() && !resolved[it->second]) {
                            if (!(arp->src_mac[0] == 0xFF && arp->src_mac[1] == 0xFF &&
                                  arp->src_mac[2] == 0xFF && arp->src_mac[3] == 0xFF &&
                                  arp->src_mac[4] == 0xFF && arp->src_mac[5] == 0xFF) &&
                                !(arp->src_mac[0] == 0 && arp->src_mac[1] == 0 &&
                                  arp->src_mac[2] == 0 && arp->src_mac[3] == 0 &&
                                  arp->src_mac[4] == 0 && arp->src_mac[5] == 0)) {
                                memcpy(macs[it->second], arp->src_mac, 6);
                                resolved[it->second] = true;
                                total_resolved++;
                                double sample_ms = static_cast<double>(
                                    std::chrono::duration_cast<std::chrono::microseconds>(
                                        current_time - round_start).count()) / 1000.0;
                                ewma_rtt_ms = (ewma_rtt_ms * 0.75) + (sample_ms * 0.25);
                                if (out_rtt_ms) (*out_rtt_ms)[it->second] = sample_ms;
                            }
                        }
                    }
                }
            }
            if (total_resolved < total_targets) arm_slot(slot_idx);
        }
        io_uring_cq_advance(ring, cqe_count);
        io_uring_submit(ring);
    }

    // ---- cleanup any recvmsg requests still outstanding ----
    for (size_t i = 0; i < pool.size(); ++i) {
        if (!pool[i].in_flight) continue;
        struct io_uring_cqe* cqe = nullptr;
        struct __kernel_timespec drain_ts = {.tv_sec = 0, .tv_nsec = 0};
        if (io_uring_wait_cqe_timeout(ring, &cqe, &drain_ts) == 0 && cqe) {
            io_uring_cqe_seen(ring, cqe);
        }
    }

    // ---- drain any retransmit sends still in flight before their buffers
    //      (owned by retransmit_pkt_pool, about to go out of scope) get freed.
    //      Bounded wait: if the kernel genuinely never completes them, we give
    //      up rather than hang — better a leaked few-hundred-byte alloc than a
    //      stuck scan.
    while (pending_retransmit_sends > 0) {
        struct io_uring_cqe* cqe = nullptr;
        struct __kernel_timespec drain_ts = {.tv_sec = 0, .tv_nsec = 30'000'000L};
        if (io_uring_wait_cqe_timeout(ring, &cqe, &drain_ts) != 0 || !cqe) break;
        uintptr_t tagged = reinterpret_cast<uintptr_t>(io_uring_cqe_get_data(cqe));
        io_uring_cqe_seen(ring, cqe);
        if (tagged == 0) pending_retransmit_sends--;
        // tagged != 0 here would be a stray recv completion; harmless to ignore.
    }

    return total_resolved > 0;
}
