import re
from urllib.parse import urlparse

# Social Engineering keywords grouped by intent
INTENT_PATTERNS = {
    "Urgency / Fear": [r"\burgent\b", r"\baccount suspended\b", r"\bimmediate action\b", r"\b24 hours\b", r"\bverify immediately\b"],
    "Financial Lure": [r"\binvoice\b", r"\bpayment due\b", r"\bwire transfer\b", r"\bbitcoin\b", r"\blottery\b", r"\bbonus\b"],
    "Credential Harvesting": [r"\blogin\b", r"\bupdate password\b", r"\bconfirm credentials\b", r"\breset access\b"]
}

def analyze_email_intent(body, subject):
    """Analyzes text body for social engineering triggers."""
    combined_text = f"{subject} {body}".lower()
    detected_intents = []
    
    for category, patterns in INTENT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined_text):
                detected_intents.append(category)
                break
                
    return list(set(detected_intents))

def extract_and_analyze_urls(body):
    """Extracts URLs and evaluates suspicious traits."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body)
    
    suspicious_urls = []
    for u in set(urls):
        parsed = urlparse(u)
        hostname = parsed.netloc.lower()
        
        is_suspicious = False
        reasons = []
        
        # Check IP-based hostnames
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
            is_suspicious = True
            reasons.append("Direct IP address used as URL host")
            
        # Check excessive subdomains
        if hostname.count('.') > 3:
            is_suspicious = True
            reasons.append("Abnormal subdomain depth")
            
        suspicious_urls.append({
            "url": u,
            "host": hostname,
            "suspicious": is_suspicious,
            "reasons": reasons
        })
        
    return suspicious_urls

def compute_threat_score(auth_results, intents, urls, header_mismatch):
    """Calculates risk score (0-100) based on weighted forensic triggers."""
    score = 0
    flags = []
    
    # 1. Authentication Failures (Max 40 pts)
    if auth_results.get("SPF") != "PASS":
        score += 15
        flags.append("SPF check failed or unverified")
    if auth_results.get("DKIM") != "PASS":
        score += 15
        flags.append("DKIM signature missing or invalid")
    if auth_results.get("DMARC") != "PASS":
        score += 10
        flags.append("DMARC alignment failed")
        
    # 2. Header Discrepancies (Max 20 pts)
    if header_mismatch:
        score += 20
        flags.append("Return-Path and From header domains mismatch")
        
    # 3. Intent & Urgency (Max 20 pts)
    if len(intents) > 0:
        score += min(len(intents) * 10, 20)
        flags.append(f"Detected manipulation cues: {', '.join(intents)}")
        
    # 4. Malicious URL Patterns (Max 20 pts)
    suspicious_url_count = sum(1 for item in urls if item['suspicious'])
    if suspicious_url_count > 0:
        score += min(suspicious_url_count * 10, 20)
        flags.append("Suspicious URL structures identified")
        
    risk_level = "LOW"
    if score >= 70:
        risk_level = "CRITICAL / HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
        
    return min(score, 100), risk_level, flags
