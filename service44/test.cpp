// hp_ws_discovery.cpp
// Compile: g++ -o hp_ws_discovery hp_ws_discovery.cpp -std=c++11
// Usage: ./hp_ws_discovery [target_ip] [target_port]

#include <iostream>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

// The SOAP probe (same as Python version)
const std::string PROBE = "<soap:Envelope xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">\n";

void send_ws_discovery_probe(const std::string& target_ip, int target_port = 3702, int timeout_sec = 5) {
    
    std::cout << "================================================================" << std::endl;
    std::cout << "HP WS-Discovery Probe (C++ with empty packet trigger)" << std::endl;
    std::cout << "Target: " << target_ip << ":" << target_port << std::endl;
    std::cout << "================================================================" << std::endl;
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[-] Failed to create socket: " << strerror(errno) << std::endl;
        return;
    }
    
    // Set socket options
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "[-] Failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
    }
    
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "[-] Failed to set receive timeout: " << strerror(errno) << std::endl;
    }
    
    // Bind to any available port (to receive response)
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;  // Let OS choose port
    
    if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        std::cerr << "[-] Failed to bind socket: " << strerror(errno) << std::endl;
        close(sock);
        return;
    }
    
    // Get the port we bound to
    struct sockaddr_in bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    getsockname(sock, (struct sockaddr*)&bound_addr, &addr_len);
    std::cout << "[*] Bound to local port: " << ntohs(bound_addr.sin_port) << std::endl;
    
    // Set up target address
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "[-] Invalid target IP: " << target_ip << std::endl;
        close(sock);
        return;
    }
    
    // Step 1: Send the probe
    std::cout << "\n[*] Sending probe (" << PROBE.length() << " bytes)..." << std::endl;
    std::cout << "    Content: " << PROBE.substr(0, 60) << "..." << std::endl;
    
    ssize_t sent = sendto(sock, PROBE.c_str(), PROBE.length(), 0,
                          (struct sockaddr*)&target_addr, sizeof(target_addr));
    
    if (sent < 0) {
        std::cerr << "[-] Failed to send probe: " << strerror(errno) << std::endl;
        close(sock);
        return;
    }
    std::cout << "[+] Sent " << sent << " bytes" << std::endl;
    
    // Step 2: Send empty packet (THE FIX - this triggers the response)
    std::cout << "[*] Sending empty packet (0 bytes) as trigger..." << std::endl;
    
    sent = sendto(sock, "", 0, 0,
                  (struct sockaddr*)&target_addr, sizeof(target_addr));
    
    if (sent < 0) {
        std::cerr << "[-] Failed to send empty packet: " << strerror(errno) << std::endl;
        close(sock);
        return;
    }
    std::cout << "[+] Sent empty packet (trigger)" << std::endl;
    
    // Step 3: Wait for response
    std::cout << "[*] Waiting for response (timeout: " << timeout_sec << "s)..." << std::endl;
    
    char buffer[8192];
    struct sockaddr_in response_addr;
    socklen_t response_addr_len = sizeof(response_addr);
    
    ssize_t received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                                 (struct sockaddr*)&response_addr, &response_addr_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cout << "\n[-] No response received (timeout)" << std::endl;
            std::cout << "[!] Possible reasons:" << std::endl;
            std::cout << "    1. Not an HP WS-Discovery device" << std::endl;
            std::cout << "    2. Firewall blocking response" << std::endl;
            std::cout << "    3. Device not listening on this port" << std::endl;
        } else {
            std::cerr << "[-] Error receiving response: " << strerror(errno) << std::endl;
        }
        close(sock);
        return;
    }
    
    buffer[received] = '\0';
    char response_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &response_addr.sin_addr, response_ip, sizeof(response_ip));
    
    std::cout << "\n[+] Received " << received << " bytes from " << response_ip 
              << ":" << ntohs(response_addr.sin_port) << std::endl;
    
    std::cout << "\n================================================================" << std::endl;
    std::cout << "RESPONSE:" << std::endl;
    std::cout << "================================================================" << std::endl;
    
    std::string response(buffer, received);
    std::cout << response.substr(0, 1000) << std::endl;
    if (response.length() > 1000) {
        std::cout << "... and " << (response.length() - 1000) << " more bytes" << std::endl;
    }
    
    // Check for HP signatures
    std::cout << "\n================================================================" << std::endl;
    std::cout << "KEY FINDINGS:" << std::endl;
    std::cout << "================================================================" << std::endl;
    
    if (response.find("xmlns:hpd=") != std::string::npos ||
        response.find("hp.com/schemas") != std::string::npos) {
        std::cout << "[✓] HP DEVICE DETECTED!" << std::endl;
        
        // Extract HP namespace
        size_t hpd_start = response.find("xmlns:hpd=\"");
        if (hpd_start != std::string::npos) {
            size_t hpd_end = response.find("\"", hpd_start + 12);
            if (hpd_end != std::string::npos) {
                std::string hp_ns = response.substr(hpd_start + 12, hpd_end - hpd_start - 12);
                std::cout << "  HP Namespace: " << hp_ns << std::endl;
            }
        }
        
        // Extract error code
        size_t error_start = response.find("Unknown error -");
        if (error_start != std::string::npos) {
            size_t error_end = response.find("'", error_start);
            if (error_end != std::string::npos) {
                std::string error = response.substr(error_start, error_end - error_start);
                std::cout << "  Error: " << error << std::endl;
            }
        }
        
        // Extract management URL (if present)
        size_t xaddrs_start = response.find("<wsd:XAddrs>");
        if (xaddrs_start != std::string::npos) {
            size_t xaddrs_end = response.find("</wsd:XAddrs>", xaddrs_start);
            if (xaddrs_end != std::string::npos) {
                std::string xaddrs = response.substr(xaddrs_start + 13, xaddrs_end - xaddrs_start - 13);
                std::cout << "  Management URL: " << xaddrs << std::endl;
            }
        }
        
    } else if (response.find("ProbeMatches") != std::string::npos) {
        std::cout << "[✓] WS-Discovery Device Detected (non-HP)" << std::endl;
    } else {
        std::cout << "[?] Unknown response format" << std::endl;
    }
    
    close(sock);
}

int main(int argc, char* argv[]) {
    std::string target_ip = "203.229.194.163";
    int target_port = 3702;
    
    if (argc > 1) {
        target_ip = argv[1];
    }
    if (argc > 2) {
        target_port = std::stoi(argv[2]);
    }
    
    send_ws_discovery_probe(target_ip, target_port);
    
    return 0;
}
