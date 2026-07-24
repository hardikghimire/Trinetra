import socket

PROBE = b'<soap:Envelope xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">\n'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

target = ("203.229.194.163", 7627)

# Send payload
sock.sendto(PROBE, target)
print(f"Sent probe ({len(PROBE)} bytes) from port {sock.getsockname()[1]}")

# Send empty packet immediately after — this is what socat does and what triggers the reply
sock.sendto(b'', target)
print("Sent empty packet")

try:
    data, addr = sock.recvfrom(8192)
    print(f"\nGot {len(data)} bytes from {addr}")
    print(data.decode('utf-8', errors='replace'))
except socket.timeout:
    print("Timeout")
finally:
    sock.close()
