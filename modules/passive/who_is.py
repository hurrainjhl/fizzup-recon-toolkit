import whois
import re
from datetime import datetime
from urllib.parse import urlparse
from utils.cache import cache_result
from utils.logger import recon_logger
from modules.reporting import generate_report

# ===================== Helper Functions =====================
def _parse_dates(date_obj):
    """Parse various date formats from WHOIS responses"""
    if not date_obj:
        return ""
    
    if isinstance(date_obj, list):
        # Return the earliest date for multiple entries
        return min(date_obj).strftime("%Y-%m-%d")
    elif isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d")
    elif isinstance(date_obj, str):
        try:
            return datetime.strptime(date_obj.split('T')[0], "%Y-%m-%d").strftime("%Y-%m-%d")
        except:
            return date_obj
    return ""

def _parse_list(items):
    """Normalize various list formats from WHOIS responses"""
    if not items:
        return []
    
    if isinstance(items, list):
        return list(set(item.strip().lower() for item in items if item))
    elif isinstance(items, str):
        return [item.strip().lower() for item in items.split(',') if item.strip()]
    return []

def _parse_contact(contact, raw_text=None, contact_type=""):
    """Extract and structure contact information"""
    if not contact:
        return {}
    
    contact_info = {}
    fields = [
        'name', 'organization', 'email', 
        'phone', 'address', 'city', 
        'state', 'zipcode', 'country'
    ]
    
    # Handle list of contacts
    if isinstance(contact, list):
        contact = contact[0]
    
    for field in fields:
        value = getattr(contact, field, None)
        if not value:
            continue
            
        if isinstance(value, list):
            contact_info[field] = value[0].strip()
        else:
            contact_info[field] = value.strip()
    
    return contact_info

def detect_privacy_service(raw_text):
    """Identify privacy protection services in WHOIS data"""
    if not raw_text:
        return {"protected": False, "service": ""}
    
    privacy_indicators = {
        "whoisguard": "WhoisGuard",
        "domainsbyproxy": "Domains By Proxy",
        "privacyprotect": "PrivacyProtect.org",
        "protecteddomains": "ProtectedDomains",
        "anonymize": "Anonymize",
        "redacted": "Redacted for Privacy",
        "contactprivacy": "Contact Privacy Inc.",
        "proxy": "Proxy Service"
    }
    
    raw_text = raw_text.lower()
    for key, service in privacy_indicators.items():
        if key in raw_text:
            return {"protected": True, "service": service}
    
    # Check for common patterns
    patterns = [
        r"privacy\s*service",
        r"data\s*masked",
        r"redact\w+",
        r"protected\s*domain",
        r"whois\s*privacy"
    ]
    
    for pattern in patterns:
        if re.search(pattern, raw_text, re.IGNORECASE):
            return {"protected": True, "service": "Generic Privacy Service"}
    
    return {"protected": False, "service": ""}

def extract_abuse_contact(raw_text):
    """Extract abuse contact information from WHOIS data"""
    if not raw_text:
        return ""
    
    patterns = [
        r"abuse\s*[^@]*@\s*[\w\.-]+",
        r"abuse\s*contact:\s*[\w\.-]+@[\w\.-]+",
        r"abuse\s*email:\s*[\w\.-]+@[\w\.-]+"
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, raw_text, re.IGNORECASE)
        if matches:
            return matches[0].replace(' ', '').lower()
    
    return ""

def detect_suspicious_keywords(raw_text):
    """Identify suspicious keywords in WHOIS data"""
    if not raw_text:
        return []
    
    keywords = [
        "phishing", "malware", "spam", "scam", "criminal", 
        "fraud", "unauthorized", "exploit", "suspicious", 
        "compromised", "blackhat", "hack", "carding"
    ]
    
    found = []
    for kw in keywords:
        if re.search(rf"\b{kw}\b", raw_text, re.IGNORECASE):
            found.append(kw)
    
    return list(set(found))

# ===================== Main WHOIS Functions =====================
def whois_interactive():
    """Interactive WHOIS lookup interface"""
    print("\n" + "="*50)
    print("Advanced WHOIS Lookup".center(50))
    print("="*50)

    domain = input("\nEnter domain to lookup (e.g., example.com):\n>>> ").strip()

    print("\n" + "-"*20 + " Lookup Options " + "-"*20)
    print("1. Standard lookup (default)")
    print("2. Extended lookup (with security analysis)")
    print("3. Raw WHOIS data only")
    option_choice = input(">>> ").strip() or "1"

    extended = option_choice == "2"
    raw_only = option_choice == "3"

    print("\n\033[93mPerforming WHOIS lookup...\033[0m")
    result = whois_lookup(domain, extended=extended, raw_only=raw_only)

    display_results(result)

    if input("\nGenerate report? (y/N): ").lower() == "y":
        filename = input("Report filename (default: whois_report.html): ").strip() or "whois_report.html"
        report_path = generate_report({"WHOIS": result}, filename)
        print(f"\n\033[92mReport generated at: {report_path}\033[0m")
    
    return result

@cache_result(expiry=86400)
def whois_lookup(domain, extended=True, raw_only=False):
    """Perform WHOIS lookup with enhanced parsing and security analysis"""
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc

    result = {
        "domain": domain,
        "dates": {"created": "", "expires": "", "updated": "", "age_days": None},
        "registrar": {"name": "", "iana_id": "", "url": ""},
        "name_servers": [],
        "status": [],
        "contacts": {"registrant": {}, "admin": {}, "tech": {}},
        "security": {
            "dnssec": "", 
            "privacy_proxy": False, 
            "privacy_service": "",
            "abuse_contact": "",
            "suspicious_keywords": [],
            "expiry_status": ""
        },
        "raw": "",
        "metrics": {"expiry_days": None, "update_recency": None},
        "tld": domain.split('.')[-1] if '.' in domain else "",
        "scan_type": "WHOIS Lookup",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        w = whois.whois(domain)
        result["raw"] = w.text

        if raw_only:
            return result

        # Parse dates
        result["dates"]["created"] = _parse_dates(w.creation_date)
        result["dates"]["expires"] = _parse_dates(w.expiration_date)
        result["dates"]["updated"] = _parse_dates(w.updated_date)

        # Calculate date metrics
        if result["dates"]["created"]:
            try:
                created_dt = datetime.strptime(result["dates"]["created"], "%Y-%m-%d")
                result["dates"]["age_days"] = (datetime.now() - created_dt).days
            except:
                pass

        if result["dates"]["expires"]:
            try:
                expires_dt = datetime.strptime(result["dates"]["expires"], "%Y-%m-%d")
                result["metrics"]["expiry_days"] = (expires_dt - datetime.now()).days
            except:
                pass

        if result["dates"]["updated"]:
            try:
                updated_dt = datetime.strptime(result["dates"]["updated"], "%Y-%m-%d")
                result["metrics"]["update_recency"] = (datetime.now() - updated_dt).days
            except:
                pass

        # Registrar information
        result["registrar"]["name"] = w.registrar or "Unknown"
        result["registrar"]["iana_id"] = getattr(w, 'iana_id', '') or ''
        result["registrar"]["url"] = getattr(w, 'registrar_url', '') or ''

        # Name servers and status
        result["name_servers"] = _parse_list(w.name_servers)
        result["status"] = _parse_list(w.status)

        # Contact information
        result["contacts"]["registrant"] = _parse_contact(getattr(w, 'registrant', None), w.text, "registrant")
        result["contacts"]["admin"] = _parse_contact(getattr(w, 'admin', None), w.text, "admin")
        result["contacts"]["tech"] = _parse_contact(getattr(w, 'tech', None), w.text, "tech")

        # Security information
        result["security"]["dnssec"] = getattr(w, 'dnssec', 'Not Detected') or 'Not Detected'
        
        privacy_info = detect_privacy_service(w.text)
        result["security"]["privacy_proxy"] = privacy_info["protected"]
        result["security"]["privacy_service"] = privacy_info["service"]
        
        if extended:
            result["security"]["abuse_contact"] = extract_abuse_contact(w.text)
            result["security"]["suspicious_keywords"] = detect_suspicious_keywords(w.text)
            
            if result["metrics"]["expiry_days"] is not None:
                result["security"]["expiry_status"] = "expired" if result["metrics"]["expiry_days"] < 0 else "active"

    except whois.parser.PywhoisError as e:
        result["error"] = f"WHOIS lookup failed: {str(e)}"
        recon_logger.error(f"WHOIS failed for {domain}: {str(e)}")
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        recon_logger.exception(f"WHOIS exception for {domain}")

    return result

def display_results(result):
    """Display WHOIS results in a user-friendly format"""
    print("\n\033[1;36m=== WHOIS Results ===\033[0m")
    print(f"\033[93mDomain:\033[0m {result['domain']}")
    print(f"\033[93mTLD:\033[0m {result['tld']}")

    if "error" in result:
        print(f"\n\033[91mError: {result['error']}\033[0m")
        return

    # Dates section
    print("\n\033[1;36mRegistration Dates:\033[0m")
    if result['dates']['created']:
        print(f"Created: {result['dates']['created']} ({result['dates']['age_days'] or '?'} days ago)")
    if result['dates']['expires']:
        status = "\033[91mEXPIRED\033[0m" if result['metrics']['expiry_days'] and result['metrics']['expiry_days'] < 0 else "\033[92mACTIVE\033[0m"
        days = abs(result['metrics']['expiry_days']) if result['metrics']['expiry_days'] is not None else '?'
        print(f"Expires: {result['dates']['expires']} ({days} days) [{status}]")
    if result['dates']['updated']:
        recency = result['metrics']['update_recency'] or '?'
        print(f"Last Updated: {result['dates']['updated']} ({recency} days ago)")

    # Registrar section
    if result['registrar']['name']:
        print("\n\033[1;36mRegistrar:\033[0m")
        print(f"Name: {result['registrar']['name']}")
        if result['registrar']['iana_id']:
            print(f"IANA ID: {result['registrar']['iana_id']}")
        if result['registrar']['url']:
            print(f"URL: {result['registrar']['url']}")

    # Name servers section
    if result['name_servers']:
        print("\n\033[1;36mName Servers:\033[0m")
        for ns in result['name_servers'][:10]:  # Limit to 10 nameservers
            print(f"- {ns}")
        if len(result['name_servers']) > 10:
            print(f"... and {len(result['name_servers']) - 10} more")

    # Security information section
    print("\n\033[1;36mSecurity Information:\033[0m")
    print(f"DNSSEC: {result['security']['dnssec']}")
    privacy_status = '\033[92mYes\033[0m' if result['security']['privacy_proxy'] else '\033[91mNo\033[0m'
    print(f"Privacy Protection: {privacy_status}")
    
    if result['security']['privacy_proxy']:
        print(f"Privacy Service: {result['security']['privacy_service']}")
    
    if result['security'].get('abuse_contact'):
        print(f"Abuse Contact: {result['security']['abuse_contact']}")
    
    if result['security'].get('suspicious_keywords'):
        print("\n\033[91mSuspicious Keywords Found:\033[0m")
        for kw in set(result['security']['suspicious_keywords']):
            print(f"- {kw.capitalize()}")
    
    if result['security'].get('expiry_status'):
        status = "Expired" if result['security']['expiry_status'] == "expired" else "Active"
        color = "\033[91m" if status == "Expired" else "\033[92m"
        print(f"\nDomain Status: {color}{status}\033[0m")
