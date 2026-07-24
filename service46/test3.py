import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

try:
    sock.connect(("172.217.27.243", 443))
    
    # Try different request formats
    requests = [
        b"GET / HTTP/1.0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"HEAD / HTTP/1.0\r\n\r\n",
        b"\r\n",  # Just a newline
    ]
    
    for req in requests:
        sock.send(req)
        try:
            data = sock.recv(4096)
            print(f"Request: {req[:30]}")
            print(f"Response ({len(data)} bytes):")
            print(data[:200])
            print("-" * 50)
        except:
            pass
            
except Exception as e:
    print(f"Error: {e}")
finally:
    sock.close()
