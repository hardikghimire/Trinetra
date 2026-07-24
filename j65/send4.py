import socket
import ssl
import sys
import re
from urllib.parse import urlparse

# -----------------------------
# Full Response Receiver
# -----------------------------
def recv_full(sock_or_tls, timeout=10):
    data = b""
    try:
        sock_or_tls.settimeout(timeout)
        while True:
            chunk = sock_or_tls.recv(16384)
            if not chunk:
                break
            data += chunk
            if len(data) > 1048576:
                break
            if b"</html>" in data.lower() or b"</body>" in data.lower():
                break
    except:
        pass
    return data.decode(errors="ignore")


# -----------------------------
# TCP Banner
# -----------------------------
def tcp_banner(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((ip, port))
        banner = sock.recv(2048).decode(errors="ignore")
        return banner.strip()
    except:
        return ""
    finally:
        try: sock.close()
        except: pass


# -----------------------------
# Check if port is likely web service
# -----------------------------
def is_likely_web_port(port):
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000}
    return port in web_ports or port > 1024  # High ports often used for web


# -----------------------------
# Plain HTTP Probe
# -----------------------------
def http_probe(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        sock.send(req.encode())
        resp = recv_full(sock)
        
        if resp.startswith("HTTP/") or "Bad Request" in resp:
            if "Bad Request" in resp and "SSL-enabled" in resp:
                return "HTTPS_REQUIRED", resp
            return "HTTP", resp
        return "NOT_HTTP", resp
    except:
        return "FAILED", ""
    finally:
        try: sock.close()
        except: pass


# -----------------------------
# HTTPS Probe
# -----------------------------
def https_probe_with_context(ip, port, context, context_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(7)
    try:
        sock.connect((ip, port))
        tls = context.wrap_socket(sock, server_hostname=ip)
        
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        tls.send(req.encode())
        
        resp = recv_full(tls)
        final_resp = follow_redirects(ip, port, resp, context, is_https=True)
        return final_resp, context_name
    except:
        return "", context_name
    finally:
        try: tls.close()
        except: pass
        try: sock.close()
        except: pass


def follow_redirects(ip, port, response, context, is_https=True, max_redirects=8):
    count = 0
    current_path = "/"
    while count < max_redirects:
        status = extract_status_code(response)
        if status not in (301, 302, 303, 307, 308):
            break

        match = re.search(r"Location:\s*(.+?)(?:\r\n|$)", response, re.IGNORECASE)
        if not match:
            break

        location = match.group(1).strip()
        print(f"[*] Following redirect ({count+1}) → {location}")

        if location.startswith('/'):
            current_path = location
        else:
            parsed = urlparse(location)
            current_path = parsed.path or '/'

        # New request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((ip, port))
            if is_https:
                tls = context.wrap_socket(sock, server_hostname=ip)
                req = f"GET {current_path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                tls.send(req.encode())
                response = recv_full(tls)
            else:
                req = f"GET {current_path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                response = recv_full(sock)
        except:
            break
        finally:
            try: sock.close()
            except: pass
        count += 1
    return response


def get_ssl_contexts():
    contexts = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('Default TLS', ctx))
    except: pass
    try:
        ctx = ssl._create_unverified_context()
        contexts.append(('Unverified', ctx))
    except: pass
    return contexts


# -----------------------------
# Extractors
# -----------------------------
def extract_server(resp):
    m = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def extract_title(resp):
    m = re.search(r"<title>\s*(.+?)\s*</title>", resp, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""

def extract_status_code(resp):
    m = re.search(r"HTTP/\d\.\d\s+(\d+)", resp)
    return int(m.group(1)) if m else 0

def detect_tech(resp, banner):
    text = (resp + banner).lower()
    tech = []
    if "ssh" in banner or "ssh-" in banner: tech.append("SSH")
    if "ftp" in banner or "220 " in banner: tech.append("FTP")
    if "apache" in text: tech.append("Apache")
    if "nethsecurity" in text: tech.append("NethSecurity")
    if "cgi" in text: tech.append("CGI")
    return list(set(tech))


# -----------------------------
# Main Probe Logic
# -----------------------------
def probe(ip, port):
    banner = tcp_banner(ip, port)
    
    # If clear non-HTTP service from banner
    if any(x in banner.lower() for x in ["ssh-", "ftp", "smtp", "220 ", "ehlo", "250 "]):
        return banner, "", "Banner Only"
    
    # Try HTTP only if likely web port or no banner
    if is_likely_web_port(port) or not banner.strip():
        print("[*] Trying HTTP...")
        status, resp = http_probe(ip, port)
        
        if status == "HTTP" and "HTTP/" in resp:
            if extract_status_code(resp) in (301, 302, 303, 307, 308):
                print("[*] Following HTTP redirect...")
                final = follow_redirects(ip, port, resp, None, is_https=False)
                return banner, final, "HTTP + Redirect"
            return banner, resp, "HTTP"
        
        if status == "HTTPS_REQUIRED":
            print("[*] HTTPS required, trying HTTPS...")
            for name, ctx in get_ssl_contexts():
                resp, method = https_probe_with_context(ip, port, ctx, name)
                if "HTTP/" in resp:
                    return banner, resp, method
            return banner, "", "HTTPS Required"

    # Fallback: Try HTTPS anyway on unknown/high ports
    print("[*] Trying HTTPS fallback...")
    for name, ctx in get_ssl_contexts():
        resp, method = https_probe_with_context(ip, port, ctx, name)
        if "HTTP/" in resp:
            return banner, resp, method

    return banner, "", "Banner Only"


# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 send4.py IP PORT")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    print("====================================")
    print(f"Target : {ip}:{port}")
    print("====================================")
    print("[*] Probing...")
    
    banner, resp, method = probe(ip, port)

    server = extract_server(resp)
    title = extract_title(resp)
    status_code = extract_status_code(resp)
    tech = detect_tech(resp, banner)
    powered_by = ""  # You can add later

    print("====================================")
    print(f"Connection Method : {method}")
    
    if status_code:
        print(f"HTTP Status       : {status_code}")
    if server:
        print(f"Server            : {server}")
    if title:
        print(f"Title             : {title}")
    if tech:
        print(f"Technologies      : {', '.join(tech)}")
    
    if banner.strip():
        print(f"\nBanner:\n{banner.strip()}")
    
    print("====================================")


if __name__ == "__main__":
    main()
