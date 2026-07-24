import socket
import ssl
import sys
import re
from urllib.parse import urlparse
from datetime import datetime

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
# TCP Banner with enhanced detection
# -----------------------------
def tcp_banner(ip, port, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        banner = sock.recv(4096).decode(errors="ignore")
        return banner.strip()
    except socket.timeout:
        return ""
    except ConnectionRefusedError:
        return ""
    except:
        return ""
    finally:
        try: sock.close()
        except: pass


# -----------------------------
# Advanced Protocol Detection
# -----------------------------
def detect_protocol_from_banner(banner):
    """Detect service protocol from banner"""
    if not banner:
        return None, None
    
    banner_first_line = banner.split('\n')[0].strip()
    banner_lower = banner.lower()
    
    # SSH Detection (most important for your case)
    ssh_match = re.match(r"^SSH-(\d+\.\d+)-([^\s]+)", banner_first_line)
    if ssh_match:
        version, software = ssh_match.groups()
        return "SSH", {
            "version": version,
            "software": software,
            "full_banner": banner_first_line
        }
    
    # FTP Detection
    if banner_first_line.startswith("220 "):
        return "FTP", {"banner": banner_first_line}
    
    # SMTP Detection
    if banner_first_line.startswith("220 "):
        return "SMTP", {"banner": banner_first_line}
    
    # POP3 Detection
    if banner_first_line.startswith("+OK"):
        return "POP3", {"banner": banner_first_line}
    
    # IMAP Detection
    if banner_first_line.startswith("* OK"):
        return "IMAP", {"banner": banner_first_line}
    
    # MySQL Detection
    mysql_match = re.search(r"mysql", banner_lower)
    if mysql_match:
        return "MySQL", {"banner": banner_first_line[:100]}
    
    # PostgreSQL Detection
    if "postgresql" in banner_lower:
        return "PostgreSQL", {"banner": banner_first_line[:100]}
    
    # Redis Detection
    if banner_first_line.startswith("+OK") or banner_first_line.startswith("-ERR") or "redis_version" in banner_lower:
        return "Redis", {"banner": banner_first_line[:100]}
    
    # Memcached Detection
    if banner_first_line.startswith("VERSION"):
        return "Memcached", {"banner": banner_first_line}
    
    # MongoDB Detection
    if "mongodb" in banner_lower:
        return "MongoDB", {"banner": banner_first_line[:100]}
    
    # Telnet Detection
    if any(x in banner_lower for x in ["telnet", "login:", "password:", "username:"]):
        return "Telnet", {"banner": banner_first_line[:100]}
    
    # VNC Detection
    if "rfb" in banner_lower:
        return "VNC", {"banner": banner_first_line}
    
    return None, None


# -----------------------------
# Check if port is likely web service
# -----------------------------
def is_likely_web_port(port):
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 444}
    return port in web_ports or port > 1024


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
# Invalid Probe (for error-based fingerprinting)
# -----------------------------
def invalid_http_probe(ip, port, is_https=False, context=None):
    """Send malformed request AAAAAAA\r\n\r\n to elicit error responses with server info"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    try:
        sock.connect((ip, port))
        if is_https and context:
            tls = context.wrap_socket(sock, server_hostname=ip)
            payload = b"AAAAAAA\r\n\r\n"
            tls.send(payload)
            resp = recv_full(tls)
            return resp
        else:
            payload = b"AAAAAAA\r\n\r\n"
            sock.send(payload)
            resp = recv_full(sock)
            return resp
    except:
        return ""
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
# Extractors - Enhanced with all requested headers
# -----------------------------
def extract_server(resp):
    m = re.search(r"Server:\s*(.+?)(?:\r\n|$)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def extract_title(resp):
    m = re.search(r"<title>\s*(.+?)\s*</title>", resp, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""

def extract_powered_by(resp):
    m = re.search(r"X-Powered-By:\s*(.+?)(?:\r\n|$)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def extract_status_code(resp):
    m = re.search(r"HTTP/\d\.\d\s+(\d+)", resp)
    return int(m.group(1)) if m else 0


def extract_special_headers(resp):
    """Extract all requested special headers"""
    headers = {}
    special = [
        "X-Nextjs-Cache", "CF-RAY", "X-Drupal-Cache", "X-Generator", "X-Redirect-By",
        "X-AspNet-Version", "X-AspNetMvc-Version", "X-Powered-CMS", "X-Drupal-Dynamic-Cache",
        "X-Mod-Pagespeed", "X-Runtime", "X-Version", "X-Backend-Server", "X-Application-Context",
        "X-Pingback", "X-Served-By", "X-Varnish", "X-Cache", "X-Cache-Hits", "CF-Cache-Status",
        "X-Amz-Cf-Id", "X-Amz-Cf-Pop", "Via", "Alt-Svc", "X-Firefox-Spdy", "X-NF-Request-ID",
        "X-ShopId", "X-Wix-Request-Id", "X-Recruiting", "X-Turbo-Charged-By"
    ]
    
    for h in special:
        m = re.search(rf"{h}:\s*(.+?)(?:\r\n|$)", resp, re.IGNORECASE)
        if m:
            headers[h] = m.group(1).strip()
    return headers


def detect_tech(resp, banner, protocol_info=None):
    text = (resp + banner).lower()
    tech = []
    
    # SSH detection with version extraction
    if protocol_info and protocol_info.get('type') == 'SSH':
        tech.append(f"SSH ({protocol_info['details'].get('software', 'Unknown')})")
        tech.append(f"SSH Protocol Version: {protocol_info['details'].get('version', 'Unknown')}")
    elif "ssh" in banner or "ssh-" in banner or re.match(r"^SSH-\d+\.\d+", banner):
        tech.append("SSH")
        ssh_version_match = re.search(r"(SSH-\d+\.\d+[^\s]*)", banner, re.IGNORECASE)
        if ssh_version_match:
            tech.append(ssh_version_match.group(1))
    
    # Web server detection
    if "apache" in text: 
        tech.append("Apache")
    if "nginx" in text: 
        tech.append("Nginx")
    if "nethsecurity" in text: 
        tech.append("NethSecurity")
    if "cgi" in text or "cgi-bin" in text: 
        tech.append("CGI")
    if "php" in text: 
        tech.append("PHP")
    
    # Framework detection
    if "django" in text: 
        tech.append("Django")
    if "rails" in text or "ruby on rails" in text: 
        tech.append("Ruby on Rails")
    if "laravel" in text: 
        tech.append("Laravel")
    if "spring" in text: 
        tech.append("Spring")
    if "express" in text: 
        tech.append("Express.js")
    
    # Database detection
    if "mysql" in text: 
        tech.append("MySQL")
    if "postgresql" in text or "pgsql" in text: 
        tech.append("PostgreSQL")
    if "mongodb" in text: 
        tech.append("MongoDB")
    if "redis" in text: 
        tech.append("Redis")
    
    # Other technologies
    if "wordpress" in text: 
        tech.append("WordPress")
    if "drupal" in text: 
        tech.append("Drupal")
    if "joomla" in text: 
        tech.append("Joomla")
    
    return list(set(tech))


def extract_security_headers(resp):
    """Extract security-related headers"""
    security_headers = {}
    headers = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
        "Permissions-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Opener-Policy"
    ]
    
    for h in headers:
        m = re.search(rf"{h}:\s*(.+?)(?:\r\n|$)", resp, re.IGNORECASE)
        if m:
            security_headers[h] = m.group(1).strip()
    return security_headers


def extract_cookies(resp):
    """Extract Set-Cookie headers"""
    cookies = re.findall(r"Set-Cookie:\s*(.+?)(?:\r\n|$)", resp, re.IGNORECASE)
    return cookies


# -----------------------------
# Main Probe Logic
# -----------------------------
def probe(ip, port):
    banner = tcp_banner(ip, port)
    protocol_info = None
    
    # Check for protocol from banner first
    proto_type, proto_details = detect_protocol_from_banner(banner)
    
    if proto_type:
        protocol_info = {'type': proto_type, 'details': proto_details}
        print(f"[*] Detected {proto_type} service on port {port}")
        
        # For SSH, we don't need to try HTTP at all
        if proto_type == "SSH":
            return banner, "", "SSH Service", protocol_info
        else:
            # For other protocols, return banner info
            return banner, "", f"{proto_type} Service", protocol_info
    
    # Original checks for other services
    if any(x in banner.lower() for x in ["ssh-", "ftp", "smtp", "pop3", "imap", "telnet"]):
        # Extract which service
        service = "Unknown"
        if "ssh-" in banner.lower():
            service = "SSH"
        elif "ftp" in banner.lower():
            service = "FTP"
        elif "smtp" in banner.lower():
            service = "SMTP"
        return banner, "", f"{service} Service", None
    
    # Web service detection
    resp = ""
    method = "Banner Only"
    
    if is_likely_web_port(port) or not banner.strip():
        print("[*] Trying HTTP...")
        status, http_resp = http_probe(ip, port)
        resp = http_resp
        
        if status == "HTTP" and "HTTP/" in resp:
            if extract_status_code(resp) in (301, 302, 303, 307, 308):
                print("[*] Following HTTP redirect...")
                final = follow_redirects(ip, port, resp, None, is_https=False)
                return banner, final, "HTTP + Redirect", None
            return banner, resp, "HTTP", None
        
        if status == "HTTPS_REQUIRED":
            print("[*] HTTPS required, trying HTTPS...")
            for name, ctx in get_ssl_contexts():
                https_resp, method_name = https_probe_with_context(ip, port, ctx, name)
                if "HTTP/" in https_resp:
                    return banner, https_resp, method_name, None
            # If HTTPS also fails, try invalid probe later
    
    print("[*] Trying HTTPS fallback...")
    for name, ctx in get_ssl_contexts():
        https_resp, method_name = https_probe_with_context(ip, port, ctx, name)
        if "HTTP/" in https_resp:
            return banner, https_resp, method_name, None
        resp = https_resp  # keep last response for fallback

    # === INVALID PROBE AS LAST RESORT (only when no banner and no valid HTTP response) ===
    if (not banner.strip() or not resp.strip() or "HTTP/" not in resp) and (is_likely_web_port(port) or port > 1024):
        print("[*] No banner or valid response - trying invalid probe (AAAAAAA)...")
        # Try plain first
        invalid_resp = invalid_http_probe(ip, port, is_https=False)
        if invalid_resp and ("HTTP/" in invalid_resp or len(invalid_resp) > 50):
            resp = invalid_resp
            method = "Invalid Probe (HTTP)"
        else:
            # Try over HTTPS
            for name, ctx in get_ssl_contexts():
                invalid_resp = invalid_http_probe(ip, port, is_https=True, context=ctx)
                if invalid_resp and ("HTTP/" in invalid_resp or len(invalid_resp) > 50):
                    resp = invalid_resp
                    method = f"Invalid Probe ({name})"
                    break

    return banner, resp, method, protocol_info


# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 send6.py IP PORT")
        print("Example: python3 send6.py 51.161.8.88 444")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    print("=" * 60)
    print(f"Target          : {ip}:{port}")
    print(f"Scan Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("[*] Probing service...")
    
    banner, resp, method, protocol_info = probe(ip, port)

    # Extract all possible information
    server = extract_server(resp)
    title = extract_title(resp)
    powered_by = extract_powered_by(resp)
    status_code = extract_status_code(resp)
    tech = detect_tech(resp, banner, protocol_info)
    special_headers = extract_special_headers(resp)
    security_headers = extract_security_headers(resp)
    cookies = extract_cookies(resp)

    print("=" * 60)
    print(f"Connection Method : {method}")
    
    # Display protocol-specific information
    if protocol_info and protocol_info['type'] == 'SSH':
        print(f"Service Type      : SSH (Secure Shell)")
        print(f"SSH Version       : {protocol_info['details'].get('version', 'Unknown')}")
        print(f"SSH Software      : {protocol_info['details'].get('software', 'Unknown')}")
        if banner:
            print(f"Full Banner       : {banner[:200]}")
    
    elif method in ["FTP Service", "SMTP Service", "POP3 Service", "IMAP Service", "Telnet Service"]:
        print(f"Service Type      : {method}")
        if banner:
            print(f"Service Banner    : {banner[:200]}")
    
    elif method in ["HTTP", "HTTP + Redirect", "Default TLS", "Unverified", "Invalid Probe (HTTP)"] or "Invalid Probe" in method:
        # Web service output
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
        
        # Security headers
        if security_headers:
            print("\n--- Security Headers ---")
            for h, v in sorted(security_headers.items()):
                print(f"{h:<30}: {v[:80]}")
        
        # Cookies
        if cookies:
            print(f"\n--- Cookies ({len(cookies)} found) ---")
            for i, cookie in enumerate(cookies[:5], 1):
                print(f"  {i}. {cookie[:100]}")
            if len(cookies) > 5:
                print(f"  ... and {len(cookies)-5} more")
        
        # Special headers
        if special_headers:
            print("\n--- Special Headers ---")
            for h, v in sorted(special_headers.items()):
                print(f"{h:<25}: {v}")
    
    # Show banner for any service that has one
    if banner.strip() and method != "SSH Service":
        print(f"\n--- Raw Banner ---")
        print(banner[:500])
        if len(banner) > 500:
            print(f"... (truncated, total {len(banner)} bytes)")


if __name__ == "__main__":
    main()
