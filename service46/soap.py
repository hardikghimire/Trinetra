import socket

def grab_banner(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        sock.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        response = sock.recv(4096)
        print(response.decode('utf-8', errors='replace'))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

grab_banner("109.158.87.125", 7547)
