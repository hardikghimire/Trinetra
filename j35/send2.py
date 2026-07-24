import socket
import ssl
import sys
import re
from urllib.parse import urlparse

# -----------------------------
# TLS/SSL Context configurations
# -----------------------------
def get_ssl_contexts(hostname):
    """Generate different SSL contexts for various TLS versions"""
    contexts = []
    
    # Method 1: Default context (most secure)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('Default TLS', ctx))
    except:
        pass
    
    # Method 2: TLS 1.3 only
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('TLS 1.3 only', ctx))
    except:
        pass
    
    # Method 3: TLS 1.2 only
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('TLS 1.2 only', ctx))
    except:
        pass
    
    # Method 4: TLS 1.1 only
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('TLS 1.1 only', ctx))
    except:
        pass
    
    # Method 5: TLS 1.0 only
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts.append(('TLS 1.0 only', ctx))
    except:
        pass
    
    # Method 6: SSLv23 (legacy - most compatible)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow weak ciphers
        try:
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        except:
            pass
        contexts.append(('SSLv23 (Legacy)', ctx))
    except:
        pass
    
    # Method 7: Custom context with no security (max compatibility)
    try:
        ctx = ssl._create_unverified_context()
        # Try to enable all protocols
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        except:
            pass
        contexts.append(('Unverified (Max Compat)', ctx))
    except:
        pass
    
    return contexts

# -----------------------------
# TCP banner (SSH/FTP/SMTP)
# -----------------------------
def tcp_banner(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((ip, port))
        try:
            return sock.recv(2048).decode(errors="ignore")
        except:
            return ""
    except:
        return ""
    finally:
        try:
            sock.close()
        except:
            pass

# -----------------------------
# HTTP
# -----------------------------
def http_probe(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        sock.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: close\r\n\r\n"
        sock.send(req.encode())
        response = sock.recv(8192).decode(errors="ignore")
        
        # Check if response indicates bad request due to HTTPS
        if "Bad Request" in response and "speaking plain HTTP to an SSL-enabled server" in response:
            return "HTTPS_REQUIRED"
        return response
    except:
        return ""
    finally:
        try:
            sock.close()
        except:
            pass

# -----------------------------
# HTTPS with specific SSL context
# -----------------------------
def https_probe_with_context(ip, port, context, context_name):
    """HTTPS probe with specific SSL context"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        sock.connect((ip, port))
        tls = context.wrap_socket(sock, server_hostname=ip)
        
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: close\r\n\r\n"
        tls.send(req.encode())
        
        response = tls.recv(8192).decode(errors="ignore")
        return response, context_name
    except ssl.SSLError as e:
        if "wrong version number" in str(e).lower():
            return "WRONG_VERSION", context_name
        elif "unsupported protocol" in str(e).lower():
            return "UNSUPPORTED_PROTOCOL", context_name
        else:
            return f"SSL_ERROR: {str(e)[:50]}", context_name
    except Exception as e:
        return f"ERROR: {str(e)[:50]}", context_name
    finally:
        try:
            tls.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass

# -----------------------------
# Enhanced HTTPS probe with all TLS versions
# -----------------------------
def https_probe_all_versions(ip, port):
    """Try all TLS versions and return first successful response"""
    
    # First try standard HTTPS
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        response, method = https_probe_with_context(ip, port, ctx, "Standard HTTPS")
        if response and not response.startswith(("SSL_ERROR:", "WRONG_VERSION", "UNSUPPORTED_PROTOCOL", "ERROR:")):
            if "Bad Request" not in response or "HTTP/1.1 200" in response:
                return response, method
    except:
        pass
    
    # Try all SSL contexts
    contexts = get_ssl_contexts(ip)
    
    for context_name, ctx in contexts:
        response, method = https_probe_with_context(ip, port, ctx, context_name)
        
        # Check if we got a valid response
        if response and not response.startswith(("SSL_ERROR:", "WRONG_VERSION", "UNSUPPORTED_PROTOCOL", "ERROR:")):
            # Check if it's a valid HTTP response
            if "HTTP/" in response:
                # Success - found working TLS version
                return response, context_name
    
    return "", "No working TLS version found"

# -----------------------------
# Smart probe with TLS fallback
# -----------------------------
def probe(ip, port):
    """Smart probe that tries HTTP first, then HTTPS with all TLS versions"""
    
    banner = tcp_banner(ip, port)
    
    # Try HTTP first
    http_response = http_probe(ip, port)
    
    # If HTTP response indicates HTTPS is required
    if http_response == "HTTPS_REQUIRED":
        print(f"[*] HTTP requires HTTPS, trying HTTPS with all TLS versions...")
        https_response, tls_method = https_probe_all_versions(ip, port)
        return banner, https_response, tls_method
    
    # If HTTP returned actual content
    if http_response and len(http_response) > 50:
        # Check if it's a valid web page (not just an error)
        if "HTTP/" in http_response and ("200" in http_response[:20] or "301" in http_response[:20] or "302" in http_response[:20]):
            return banner, http_response, "HTTP (plain)"
        # If HTTP got error but might work with HTTPS
        elif "Bad Request" in http_response or "SSL" in http_response:
            print(f"[*] HTTP returned error, trying HTTPS...")
            https_response, tls_method = https_probe_all_versions(ip, port)
            if https_response:
                return banner, https_response, tls_method
    
    # Try HTTPS with all versions as fallback
    if not http_response or len(http_response) < 50:
        print(f"[*] No HTTP response, trying HTTPS with all TLS versions...")
        https_response, tls_method = https_probe_all_versions(ip, port)
        if https_response:
            return banner, https_response, tls_method
    
    return banner, http_response if http_response else "", "No response"

# -----------------------------
# Extract functions
# -----------------------------
def extract_server(resp):
    m = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def extract_title(resp):
    m = re.search(r"<title>(.*?)</title>", resp, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""

def extract_status_code(resp):
    """Extract HTTP status code from response"""
    m = re.search(r"HTTP/\d\.\d\s+(\d+)", resp)
    return int(m.group(1)) if m else 0

def detect_tech(resp, banner):
    text = (resp + banner).lower()
    tech = []

    if "php" in text:
        tech.append("PHP")
    if "asp.net" in text or "aspx" in text:
        tech.append("ASP.NET")
    if "express" in text:
        tech.append("Node.js")
    if "nginx" in text:
        tech.append("Nginx")
    if "apache" in text:
        tech.append("Apache")
    if "django" in text or "flask" in text or "gunicorn" in text:
        tech.append("Python")
    if "tomcat" in text or "jsp" in text:
        tech.append("Java")
    if "ssh" in text or "ssh-" in text:
        tech.append("SSH")
    if "ftp" in text or text.startswith("220"):
        tech.append("FTP")
    if "smtp" in text or "220 " in text[:20]:
        tech.append("SMTP")
    if "wordpress" in text:
        tech.append("WordPress")
    if "nethsecurity" in text:
        tech.append("NethSecurity")
    if "cgi-bin" in text or "cgi" in text:
        tech.append("CGI")

    return list(set(tech))

def extract_powered_by(resp):
    """Extract X-Powered-By header"""
    m = re.search(r"X-Powered-By:\s*(.+)", resp, re.IGNORECASE)
    return m.group(1).strip() if m else ""

# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 send.py IP PORT")
        print("Example: python3 send.py 79.62.110.118 446")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    print("====================================")
    print(f"Target : {ip}:{port}")
    print("====================================")
    print("[*] Probing...")
    
    banner, resp, method = probe(ip, port)

    if not resp:
        print("[-] No response received from any protocol/TLS version")
        print("====================================")
        sys.exit(1)

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
