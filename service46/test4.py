#!/usr/bin/env python3
"""
NULL Probe (q||) - Opens TLS connection without sending any data.
Dumps raw certificate information to debug parsing issues.
"""

import socket
import ssl
import sys
import argparse
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def null_probe_with_openssl(target_ip, port=30115, timeout=10):
    """
    NULL probe using pyOpenSSL for better certificate parsing.
    """
    print(f"[*] NULL Probe (q||) connecting to {target_ip}:{port}...")
    print(f"[*] Using pyOpenSSL for certificate parsing...")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        print(f"[+] TCP connection established")
        
        ssl_sock = context.wrap_socket(sock, server_hostname=target_ip)
        print(f"[+] TLS handshake completed")
        
        # Get DER encoded certificate
        der_cert = ssl_sock.getpeercert(binary_form=True)
        
        # Try to parse with cryptography
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        
        print("\n" + "="*60)
        print("CERTIFICATE INFORMATION (cryptography):")
        print("="*60)
        
        # Extract subject
        subject = cert.subject
        print(f"  Subject: {subject}")
        
        # Extract CN
        cn = None
        for attribute in subject:
            if attribute.oid._name == 'commonName':
                cn = attribute.value
                print(f"  commonName (CN): {cn}")
        
        # Extract all subject fields
        print("\n  Subject Components:")
        for attribute in subject:
            print(f"    {attribute.oid._name}: {attribute.value}")
        
        # Extract issuer
        issuer = cert.issuer
        print(f"\n  Issuer: {issuer}")
        for attribute in issuer:
            print(f"    {attribute.oid._name}: {attribute.value}")
        
        # Extract validity
        print(f"\n  Valid From: {cert.not_valid_before}")
        print(f"  Valid To: {cert.not_valid_after}")
        
        # Extract SAN
        try:
            san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            print(f"  SAN: {san.value}")
        except:
            print("  SAN: Not present")
        
        print("="*60)
        
        # Check for CN=Wazuh
        if cn and cn == "Wazuh":
            print(f"\n✅ MATCH FOUND: CN={cn}")
            print("   This is the WAZUH AGENT REGISTRATION SERVICE")
            return True
        elif cn:
            print(f"\n⚠️  Certificate CN={cn} (not Wazuh)")
            return False
        else:
            print(f"\n⚠️  No Common Name found in certificate")
            # Dump raw certificate as fallback
            print("\n[DEBUG] Raw certificate dump:")
            for i, byte in enumerate(der_cert[:100]):
                print(f"{byte:02x}", end=" ")
                if (i + 1) % 16 == 0:
                    print()
            print()
            return False
            
    except ImportError as e:
        print(f"\n❌ Missing module: {e}")
        print("   Install with: pip install cryptography pyOpenSSL")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False
    finally:
        if 'ssl_sock' in locals():
            ssl_sock.close()

def null_probe_raw_tls(target_ip, port=30115, timeout=10):
    """
    Raw TLS probe using only built-in ssl module with binary cert dump.
    """
    print(f"\n[*] NULL Probe with raw TLS (built-in ssl)...")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        ssl_sock = context.wrap_socket(sock, server_hostname=target_ip)
        
        # Get raw certificate
        der_cert = ssl_sock.getpeercert(binary_form=True)
        
        print(f"[+] Certificate size: {len(der_cert)} bytes")
        
        # Try to get dict representation (what your script used)
        cert_dict = ssl_sock.getpeercert()
        print(f"[+] Certificate dict keys: {cert_dict.keys() if cert_dict else 'None'}")
        
        # Check if 'subject' exists
        if 'subject' in cert_dict:
            print(f"[+] Subject found: {cert_dict['subject']}")
        else:
            print("[!] No 'subject' key in certificate dictionary")
            print(f"[!] Available keys: {list(cert_dict.keys()) if cert_dict else 'None'}")
            
            # Try alternate parsing
            for key, value in cert_dict.items():
                if 'cn' in key.lower() or 'subject' in key.lower():
                    print(f"    {key}: {value}")
        
        # Search for CN in any field
        cn_found = False
        if cert_dict:
            for key, value in cert_dict.items():
                if isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, (list, tuple)):
                            for subitem in item:
                                if isinstance(subitem, tuple) and len(subitem) >= 2:
                                    if subitem[0] == 'commonName':
                                        print(f"\n✅ Found CN via dict search: {subitem[1]}")
                                        cn_found = True
                                        if subitem[1] == "Wazuh":
                                            return True
        
        if not cn_found:
            print("\n[DEBUG] Raw certificate hex (first 100 bytes):")
            for i, byte in enumerate(der_cert[:100]):
                print(f"{byte:02x}", end=" ")
                if (i + 1) % 16 == 0:
                    print()
            print()
            
        ssl_sock.close()
        return False
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='NULL Probe for Wazuh Detection')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=30115)
    parser.add_argument('-t', '--timeout', type=int, default=10)
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("NULL PROBE (q||) - Wazuh Detection")
    print("="*60 + "\n")
    
    # Try with cryptography (best parsing)
    result = null_probe_with_openssl(args.target, args.port, args.timeout)
    
    # If that fails, try raw TLS method
    if not result:
        result = null_probe_raw_tls(args.target, args.port, args.timeout)
    
    print("\n" + "="*60)
    if result:
        print("✅ CONFIRMED: Wazuh Agent Registration Service")
    else:
        print("❌ Could not confirm Wazuh service")
        print("   Check that:")
        print("   1. The target is reachable")
        print("   2. Port is correct")
        print("   3. Service uses TLS with CN=Wazuh")
    print("="*60 + "\n")

if __name__ == "__main__":
    sys.exit(main())
