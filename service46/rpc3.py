import socket
import struct
import random
import time

TARGET = "109.143.70.111"
PORT = 111

def send_rpc_request(procedure, xid=None):
    """Send RPC request and return response"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    
    if xid is None:
        xid = random.randint(1, 0xffffffff)
    
    # Build RPC call
    # program=100000 (rpcbind), version=2
    header = struct.pack(">6I", xid, 0, 2, 100000, 2, procedure)
    auth_null = struct.pack(">II", 0, 0)  # credential
    auth_null2 = struct.pack(">II", 0, 0)  # verifier
    
    pkt = header + auth_null + auth_null2
    
    print(f"[*] Sending {procedure_name(procedure)} (xid={xid})")
    print(f"    Packet: {pkt.hex()}")
    s.sendto(pkt, (TARGET, PORT))
    
    try:
        data, addr = s.recvfrom(4096)
        print(f"[+] Received {len(data)} bytes")
        print(f"    Response hex: {data.hex()}")
        
        # Parse response
        if len(data) >= 24:
            resp_xid, msg_type, reply_stat = struct.unpack(">III", data[:12])
            verf_flavor, verf_len, accept_stat = struct.unpack(">III", data[12:24])
            
            print(f"\n[+] Response XID: {resp_xid} (sent {xid})")
            print(f"    Message Type: {msg_type} (1=REPLY)")
            print(f"    Reply Status: {reply_stat} (0=ACCEPTED)")
            print(f"    Accept Status: {accept_stat} (0=SUCCESS)")
            
            return data, accept_stat == 0
        else:
            print("[-] Response too short")
            return None, False
            
    except socket.timeout:
        print("[-] Timeout - no response")
        return None, False
    except Exception as e:
        print(f"[-] Error: {e}")
        return None, False
    finally:
        s.close()

def procedure_name(proc):
    names = {0: "NULL", 1: "SET", 2: "UNSET", 3: "GETPORT", 4: "DUMP", 5: "CALLIT"}
    return names.get(proc, f"procedure-{proc}")

def parse_dump_response(data):
    """Parse RPC DUMP response"""
    if not data or len(data) < 24:
        return
    
    print("\n" + "="*70)
    print("Registered RPC Services:")
    print("="*70)
    print(f"{'Program':<12} {'Version':<10} {'Protocol':<8} {'Port':<8} {'Service'}")
    print("-"*60)
    
    # The response after the RPC header contains the mappings
    # Format: [pointer (4 bytes)] + array of mappings
    # Each mapping: 5 integers (20 bytes)
    
    offset = 24  # Skip RPC reply header
    
    # Try to parse as direct array first
    pos = offset
    count = 0
    
    while pos + 20 <= len(data):
        try:
            prog, vers, prot, port, owner = struct.unpack(">IIIII", data[pos:pos+20])
            
            # Check for terminator
            if prog == 0 and vers == 0 and prot == 0 and port == 0:
                break
            
            # Protocol number to name
            if prot == 6:
                proto = "TCP"
            elif prot == 17:
                proto = "UDP"
            elif prot == 1:
                proto = "ICMP"
            else:
                proto = str(prot)
            
            # Common RPC program names
            service_map = {
                100000: "rpcbind",
                100003: "NFS",
                100005: "mountd",
                100007: "YPbind",
                100008: "yppasswdd",
                100009: "ypserv",
                100011: "rquotad",
                100012: "sprayd",
                100020: "cmsd",
                100021: "nlockmgr",
                100024: "status",
                100029: "rstatd",
                100068: "cmsd",
                100083: "tirpc",
                100227: "NFS_ACL",
            }
            service = service_map.get(prog, "")
            
            print(f"{prog:<12} {vers:<10} {proto:<8} {port:<8} {service}")
            count += 1
            pos += 20
            
        except struct.error:
            break
    
    if count == 0:
        print("No mappings found. Raw data:")
        print(data[offset:].hex())
    else:
        print(f"\n[+] Total: {count} service registrations")

def main():
    print("RPC Client for target: {}:{}\n".format(TARGET, PORT))
    
    # Try NULL call
    print("Test 1: RPC NULL Call")
    print("-" * 40)
    data, success = send_rpc_request(0)
    
    if success:
        print("\n✓ RPC service is alive and responding\n")
        
        # Try DUMP call
        print("Test 2: RPC DUMP Call")
        print("-" * 40)
        data, success = send_rpc_request(4)
        
        if success and data:
            parse_dump_response(data)
        else:
            print("\n[-] DUMP call failed")
    else:
        print("\n[-] RPC service not responding to NULL call")
        
        # Alternative: Try GETPORT call
        print("\nTest 2: RPC GETPORT (asking for rpcbind's port)")
        print("-" * 40)
        # GETPORT: program=100000, version=2, protocol=TCP (6)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        xid = random.randint(1, 0xffffffff)
        # GETPORT procedure (3) with arguments: program, version, protocol
        header = struct.pack(">6I", xid, 0, 2, 100000, 2, 3)
        auth = struct.pack(">II", 0, 0) * 2
        args = struct.pack(">III", 100000, 2, 6)  # program, version, protocol
        pkt = header + auth + args
        s.sendto(pkt, (TARGET, PORT))
        
        try:
            data, addr = s.recvfrom(1024)
            if len(data) >= 28:
                # Parse response - port should be at offset 24-28
                port = struct.unpack(">I", data[24:28])[0]
                print(f"[+] rpcbind reports its TCP port as: {port}")
                if port == 0:
                    print("    (not registered or not available)")
        except:
            pass
        finally:
            s.close()

if __name__ == "__main__":
    main()
