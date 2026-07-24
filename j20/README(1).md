# Project-tripundra <img src="https://github.com/hardikghimire/project-tripundra/blob/91c4c9b26787b5b0e80a6e9dc0c928fba9ab21ae/shiv.gif" width="130" height="130" align="center" />

## Sending Packets
- **Primary Method**: It uses `io_uring_prep_sendmsg()` for async I/O
- **Alternative Method**: `send_tcp_packets()` function in `scan.cpp` uses `sendmsg()` system call
- **For ARP**: `send_arp_request()` uses `io_uring_prep_sendto()` for batch ARP requests
- **Raw Sockets**: Created with `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` to craft custom IP/TCP headers

## Receiving Packets
- **Primary Method**: `receive_response()` uses `io_uring_prep_recvmsg()` for async reception
- **Raw Socket**: Created with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` to receive TCP responses
- **For ARP**: `receive_arp_reply()` uses `io_uring_prep_recvmsg()` for ARP response reception
- **Non-blocking I/O**: Sockets are set to non-blocking mode using `fcntl()` with `O_NONBLOCK`

## Processing & Architecture
- **Async I/O via io_uring**:
  - Send rings: `io_uring_queue_init()` for batch sending
  - Receive rings: `io_uring_queue_init()` for batch receiving
  - Timeouts: `io_uring_wait_cqe_timeout()` for response timeout handling
  - Queue depths configurable via `--send-uring` and `--rcv-uring`

## Concurrent Processing
- `moodycamel::ConcurrentQueue` for packet task queuing
- Separate sender thread for packet transmission
- `std::atomic` flags for thread coordination (`terminate_flag`)
- `std::mutex` for output synchronization (`cout_mutex`)

## Buffer Management
- Custom `PacketBufferPool` for memory pooling
- Thread-local buffer pools to reduce contention
- Concurrent queue for buffer reuse

# Features

- **Smart EMWA RTT**: Adaptive incremental RTT with retries (previous learn incremental RTT)
- **State machine scan**: Scan with proper 4-way handshake (graceful connection closure)
- **Raw access**: Code provides proper raw packet access for educational purposes
- **SIGINT handling**: Emergency protocol activation, prevents scanner crashes with real-time protection
- **RAII**: Uses RAII for automatic cleanup when objects go out of scope (exception-safe resource management)
- **Output**: Prints scan output in modern format
- **Checksum manipulation**: Advanced mathematical invalid checksum patterns and bit manipulation for testing
- **TCP flags**: Added two new TCP flags: ECE and CWR
- **Public Databases**: Supports two public databases (Security Trials and Shodan InternetDB)
- **DNS resolution**: Provides flexible DNS resolution



![EnlightenmentDiscordServerGIF](https://github.com/user-attachments/assets/4859d23e-4469-4417-8403-ff38f9a1dc1f)

# Default Scan
 <img src="https://github.com/hardikghimire/project-tripundra/blob/main/basic_scan.jpg">

 
# PublicDB Scan (--enum)
 <img src="https://github.com/hardikghimire/project-tripundra/blob/main/--enum_public_b.jpg">


# Debug Response (--debug is option,  packet is category)
 <img src="https://github.com/hardikghimire/project-tripundra/blob/main/debug_packet.jpg">


# State Machine Scan
 <img src="https://github.com/hardikghimire/project-tripundra/blob/main/statefull_scan_-G.jpg">


# State Machine Scan Handshake
 <img src="https://github.com/hardikghimire/project-tripundra/blob/main/statefull_scan_response_prevent_rst.jpg">

 

