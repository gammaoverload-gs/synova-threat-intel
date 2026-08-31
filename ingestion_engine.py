import email
from email import policy
import re
import socket
import requests

def parse_eml(file_bytes):
    """Parses raw EML bytes into headers, body, and attachments."""
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    headers = {k: v for k, v in msg.items()}
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
    return headers, body, msg

def extract_ip_hops(headers):
    """Extracts relay IP hops from 'Received' headers in sequential order."""
    received_headers = headers.get_all('Received', []) if hasattr(headers, 'get_all') else [headers.get('Received', '')]
    if isinstance(received_headers, str):
        received_headers = [received_headers]

    ip_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    hops = []
    
    for r in reversed(received_headers):  # Chronological order
        found_ips = re.findall(ip_regex, str(r))
        for ip in found_ips:
            # Filter out private / local IPs
            if not is_private_ip(ip) and ip not in hops:
                hops.append(ip)
    return hops

def is_private_ip(ip):
    """Checks if an IPv4 address is private or loopback."""
    parts = list(map(int, ip.split('.')))
    if parts[0] in (10, 127):
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False

def geolocate_ip(ip):
    """Fetches GeoLocation metadata for a public IP."""
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,query", timeout=4)
        data = res.json()
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return None

def verify_email_auth(headers):
    """Extracts and verifies SPF, DKIM, and DMARC status from headers."""
    auth_results = headers.get('Authentication-Results', '')
    received_spf = headers.get('Received-SPF', '')
    
    spf_status = "PASS" if "spf=pass" in auth_results.lower() or "pass" in received_spf.lower() else "FAIL/UNKNOWN"
    dkim_status = "PASS" if "dkim=pass" in auth_results.lower() else "FAIL/UNKNOWN"
    dmarc_status = "PASS" if "dmarc=pass" in auth_results.lower() else "FAIL/UNKNOWN"
    
    return {
        "SPF": spf_status,
        "DKIM": dkim_status,
        "DMARC": dmarc_status,
        "Raw_Auth": auth_results
    }
