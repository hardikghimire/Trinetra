import socket
import threading

PROBE = b'<soap:Envelope xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">\n'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
target = ("109.158.87.125", 7547)

response = []

def listen():
    try:
        data, addr = sock.recvfrom(8192)
        response.append((data, addr))
    except socket.timeout:
        pass

# Start listener BEFORE sending
t = threading.Thread(target=listen)
t.start()

sock.sendto(PROBE, target)
sock.sendto(b'', target)

t.join()
sock.close()

if response:
    data, addr = response[0]
    print(f"Got {len(data)} bytes from {addr}")
    print(data.decode('utf-8', errors='replace'))
else:
    print("Timeout")
