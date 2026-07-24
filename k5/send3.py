import socket
import ssl
import sys
import re
from urllib.parse import urlparse

# -----------------------------
# TLS/SSL Context configurations
# -----------------------------
def get_ssl_contexts(hostname):
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
# Receive Full Response
# -----------------------------
def recv_full(sock_or_tls, timeout=8):
    sock_or_tls.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock_or_tls.recv(16384)
            if not chunk:
                break
            data += chunk
            if len(data) > 1048576:  # 1MB limit
                break
            if b"</html>" in data.lower() or b"</body>" in data.lower():
                break
    except:
        pass
    return data.decode(errors="ignore")


# -----------------------------
# TCP banner (unchanged)
# -----------------------------
def tcp_banner(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((ip, port))
        return sock.recv(2048).decode(errors="ignore")
    except:
        return ""
    finally:
        try: sock.close()
        except: pass


# -----------------------------
# HTTP Probe
# -----------------------------
def http_probe(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        sock.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
        sock.send(req.encode())
        response = recv_full(sock)
        
        if "Bad Request" in response and "SSL-enabled server" in response:
            return "HTTPS_REQUIRED"
        return response
    except:
        return ""
    finally:
        try: sock.close()
        except: pass


# -----------------------------
# HTTPS Single Probe with Redirect
# -----------------------------
def https_probe_with_context(ip, port, context, context_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    try:
        sock.connect((ip, port))
        tls = context.wrap_socket(sock, server_hostname=ip)
        
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
        tls.send(req.encode())
        
        response = recv_full(tls)
        # Follow redirects
        final_response = follow_redirects(ip, port, response, context, is_https=True)
        
        return final_response, context_name
    except Exception as e:
        return f"ERROR: {str(e)[:80]}", context_name
    finally:
        try: tls.close()
        except: pass
        try: sock.close()
        except: pass


def follow_redirects(ip, port, response, context, is_https=True, max_redirects=10):
    redirect_count = 0
    current_path = "/"
    
    while redirect_count < max_redirects:
        status = extract_status_code(response)
        if status not in (301, 302, 303, 307, 308):
            break
            
        loc_match = re.search(r"Location:\s*(.+?)(?:\r\n|$)", response, re.IGNORECASE)
        if not loc_match:
            break
            
        location = loc_match.group(1).strip()
        print(f"[*] Following redirect ({redirect_count+1}) → {location}")
        
        if location.startswith('/'):
            current_path = location
        else:
            parsed = urlparse(location)
            current_path = parsed.path or '/'
        
        # New request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(6)
            sock.connect((ip, port))
            tls = context.wrap_socket(sock, server_hostname=ip) if is_https else None
            
            req = f"GET {current_path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            (tls if is_https else sock).send(req.encode())
            response = recv_full(tls if is_https else sock)
        except:
            break
        finally:
            try: (tls.close() if tls else None)
            except: pass
            try: sock.close()
            except: pass
            
        redirect_count += 1
    
    return response


# -----------------------------
# HTTPS All Versions
# -----------------------------
def https_probe_all_versions(ip, port):
    # Try default first
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        response, method = https_probe_with_context(ip, port, ctx, "Standard HTTPS")
        if "HTTP/" in response:
            return response, method
    except:
        pass

    for name, ctx in get_ssl_contexts(ip):
        response, method = https_probe_with_context(ip, port, ctx, name)
        if "HTTP/" in response:
            return response, method
    
    return "", "No working TLS version found"


# -----------------------------
# Smart Probe
# -----------------------------
def probe(ip, port):
    banner = tcp_banner(ip, port)
    
    http_response = http_probe(ip, port)
    
    if http_response == "HTTPS_REQUIRED" or (http_response and "HTTP/" in http_response):
        print(f"[*] HTTP/HTTPS detected, probing with TLS support...")
        if http_response == "HTTPS_REQUIRED":
            https_response, method = https_probe_all_versions(ip, port)
            return banner, https_response, method
        else:
            # Handle HTTP redirect if any
            status = extract_status_code(http_response)
            if status in (301, 302, 303, 307, 308):
                print(f"[*] Following HTTP redirect...")
                final = follow_redirects(ip, port, http_response, None, is_https=False)
                return banner, final or http_response, "HTTP + Redirect"
            return banner, http_response, "HTTP (plain)"
    
    # Non-HTTP service (SSH, FTP, etc.)
    if banner.strip():
        return banner, "", "Banner Only"
    
    # Try HTTPS as last resort
    print(f"[*] Trying HTTPS fallback...")
    https_response, method = https_probe_all_versions(ip, port)
    return banner, https_response, method


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

def extract_powered_by(resp):
    m = re.search(r"X-Powered-By:\s*(.+)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def detect_tech(resp, banner):
    text = (resp + banner).lower()
    tech = []
    if "php" in text: tech.append("PHP")
    if "apache" in text: tech.append("Apache")
    if "nginx" in text: tech.append("Nginx")
    if "nethsecurity" in text: tech.append("NethSecurity")
    if "cgi" in text or "cgi-bin" in text: tech.append("CGI")
    if "ssh" in text or "ssh-" in banner: tech.append("SSH")
    return list(set(tech))


# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 send2.py IP PORT")
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
    powered_by = extract_powered_by(resp)

    print("====================================")
    print(f"Connection Method : {method}")
    
    if status_code:
        print(f"HTTP Status       : {status_code}")
    if server:
        print(f"Server            : {server}")
    if powered_by:
        print(f"Powered By        : {powered_by}")
    if title:
        print(f"Title             : {title}")
    if tech:
        print(f"Technologies      : {', '.join(tech)}")
    
    if banner.strip():
        print(f"\nBanner:\n{banner.strip()}")
    
    print("====================================")


if __name__ == "__main__":
    main()
