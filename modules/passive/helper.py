import re
from datetime import datetime

def _parse_dates(date_obj):
    """Parse various date formats into YYYY-MM-DD string"""
    if not date_obj:
        return ""
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d")
    elif isinstance(date_obj, str):
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(date_obj, fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
        return date_obj[:10]
    return str(date_obj)

def _parse_list(obj):
    """Convert input to a list of strings"""
    if not obj:
        return []
    if isinstance(obj, list):
        return [str(item).strip() for item in obj]
    return [str(obj).strip()]

def _parse_contact(contact, raw_text, contact_type):
    """Parse contact information into dictionary"""
    if not contact:
        return {}
    if isinstance(contact, str):
        return {"raw": contact}

    contact_dict = {}
    fields = ['name', 'organization', 'address', 'city', 'state', 
              'zipcode', 'country', 'email', 'phone', 'fax']
    for field in fields:
        if hasattr(contact, field):
            contact_dict[field] = getattr(contact, field)
    return contact_dict

def detect_privacy_service(raw_text):
    """Detect privacy protection services in WHOIS text"""
    privacy_indicators = [
        "Domains By Proxy", 
        "WhoisGuard", 
        "Privacy Protect",
        "REDACTED FOR PRIVACY",
        "Data Protected",
        "Anonymized"
    ]
    for indicator in privacy_indicators:
        if indicator in raw_text:
            return {"protected": True, "service": indicator}
    return {"protected": False, "service": ""}

def extract_abuse_contact(raw_text):
    """Extract abuse contact email or phone"""
    email_match = re.search(r"abuse\s*[^@]*@\S+", raw_text, re.IGNORECASE)
    phone_match = re.search(r"abuse\s*phone:\s*[\d\s\+\-]+", raw_text, re.IGNORECASE)
    if email_match:
        return email_match.group(0).strip()
    if phone_match:
        return phone_match.group(0).strip()
    return ""

def detect_suspicious_keywords(raw_text):
    """Detect suspicious keywords in WHOIS text"""
    keywords = ["spam", "phishing", "malware", "botnet", "exploit"]
    return [kw for kw in keywords if re.search(rf"\b{kw}\b", raw_text, re.IGNORECASE)]

