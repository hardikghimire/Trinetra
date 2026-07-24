#!/usr/bin/env python3
import socket
import binascii

# IKE Main Mode probe with 8 transforms (ike-scan default)
ike_probe = bytes.fromhex(
    "00000000000000000000000000000000"  # Initiator SPI (8) + Responder SPI (4)
    "01100200"                          # Next payload: SA, version 1.0, Main Mode
    "00000000"                          # Flags
    "0000016c"                          # Total length (364 bytes)
    "01010048"                          # SA payload
    "00000001"                          # Proposal #1
    "00000008"                          # 8 transforms
    # Transform 1: 3DES-CBC, SHA1, MODP1024
    "00000020" "01000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 2: 3DES-CBC, MD5, MODP1024
    "00000020" "02000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 3: DES-CBC, SHA1, MODP1024
    "00000020" "03000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 4: DES-CBC, MD5, MODP1024
    "00000020" "04000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 5: 3DES-CBC, SHA1, MODP768
    "00000020" "05000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 6: 3DES-CBC, MD5, MODP768
    "00000020" "06000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 7: DES-CBC, SHA1, MODP768
    "00000020" "07000000" "00000000" "00001401" "01000000" "00000000"
    # Transform 8: DES-CBC, MD5, MODP768
    "00000020" "08000000" "00000000" "00001401" "01000000" "00000000"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

# Bind to source port 500 (like ike-scan)
sock.bind(('', 500))

print(f"[*] Sending IKE probe (364 bytes) to 145.224.94.61:500")
sock.sendto(ike_probe, ('145.224.94.61', 500))

try:
    data, addr = sock.recvfrom(1024)
    print(f"[+] Received {len(data)} bytes from {addr}")
    print(f"    Hex: {binascii.hexlify(data).decode()}")
    
    # Check for NO-PROPOSAL-CHOSEN (notify type 14)
    if len(data) > 28 and data[28] == 0x0e:
        print("[!] Server response: NO-PROPOSAL-CHOSEN (IKE active)")
    else:
        print("[?] Unknown response type")
        
except socket.timeout:
    print("[-] No response - UDP 500 may be filtered or service down")

sock.close()
