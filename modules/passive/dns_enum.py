import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.dnssec
import socket
import time
import ipaddress
import json
import requests
from utils.cache import cache_result
from utils.logger import recon_logger
from concurrent.futures import ThreadPoolExecutor, as_completed

# Cloudflare IP ranges from their API
CLOUDFLARE_IPS = requests.get('https://api.cloudflare.com/client/v4/ips').json()['result']

@cache_result(expiry=3600)  # Cache for 1 hour
def dns_enum(
    domain: str,
    record_types: list = None,
    check_dnssec: bool = True,
    check_zone_transfer: bool = True,
    check_cloud: bool = True,
    check_subdomains: bool = False,
    threads: int = 10
) -> dict:
    """
    Advanced DNS enumeration with comprehensive reconnaissance features
    
    Parameters:
        domain: Target domain name
        record_types: Specific record types to query (default: common types)
        check_dnssec: Enable DNSSEC validation
        check_zone_transfer: Test for DNS zone transfer vulnerability
        check_cloud: Detect cloud provider protections
        check_subdomains: Perform basic subdomain enumeration
        threads: Number of concurrent threads for subdomain checks
    
    Returns dictionary with:
        - DNS records
        - Security status (DNSSEC, zone transfer)
        - Cloud protections
        - Subdomain enumeration
        - Reverse lookups
    """
    # Default record types
    if not record_types:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "DNSKEY", "DS", "RRSIG"]
    
    results = {
        "domain": domain,
        "records": {},
        "security": {
            "dnssec": False,
            "zone_transfer_vulnerable": False,
            "zone_transfer_servers": []
        },
        "cloud": {},
        "subdomains": {},
        "reverse": {},
        "timestamp": int(time.time())
    }
    
    # Configure resolver with fallback to Google DNS
    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolver.nameservers or ['8.8.8.8', '8.8.4.4']
    
    # 1. DNSSEC Validation
    if check_dnssec:
        results["security"]["dnssec"] = _validate_dnssec(domain, resolver)
    
    # 2. Record Enumeration
    for rtype in record_types:
        try:
            recon_logger.info(f"Querying {rtype} records for {domain}")
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            
            if rtype in ["PTR"]:
                # PTR records are handled in reverse lookups
                continue
                
            record_list = []
            for rdata in answers:
                record_value = str(rdata)
                
                # Handle special record types
                if rtype == "SOA":
                    record_value = _parse_soa_record(record_value)
                elif rtype == "MX":
                    record_value = {
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange)
                    }
                
                record_list.append(record_value)
                
                # Perform reverse lookup for IP addresses
                if rtype in ["A", "AAAA"]:
                    ip = str(rdata)
                    if ip not in results["reverse"]:
                        results["reverse"][ip] = reverse_lookup(ip)
            
            results["records"][rtype] = record_list
            time.sleep(0.1)  # Prevent rate limiting
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["records"][rtype] = []
        except dns.resolver.Timeout:
            recon_logger.warning(f"DNS timeout for {rtype} record")
            results["records"][rtype] = ["Timeout"]
        except Exception as e:
            recon_logger.error(f"DNS error for {rtype}: {str(e)}")
            results["records"][rtype] = [f"Error: {str(e)}"]
    
    # 3. Zone Transfer Vulnerability Check
    if check_zone_transfer:
        results["security"].update(_check_zone_transfer(domain, results["records"].get("NS", [])))
    
    # 4. Cloud Provider Detection
    if check_cloud:
        results["cloud"] = _detect_cloud_providers(
            results["records"].get("A", []),
            results["records"].get("AAAA", []),
            results["records"].get("TXT", [])
        )
    
    # 5. Subdomain Enumeration
    if check_subdomains:
        results["subdomains"] = _enumerate_subdomains(
            domain, 
            results["records"].get("NS", []),
            resolver,
            threads
        )
    
    # 6. DMARC/DKIM/SPF Checks
    results["records"]["DMARC"] = _get_dmarc_record(domain, resolver)
    results["records"]["DKIM"] = _get_dkim_records(domain, resolver)
    results["records"]["SPF"] = _get_spf_record(domain, resolver)
    
    return results

def _validate_dnssec(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """Perform comprehensive DNSSEC validation"""
    try:
        # Check for DNSKEY records
        dnskey = resolver.resolve(domain, 'DNSKEY')
        rrsig = resolver.resolve(domain, 'RRSIG')
        
        # Validate DNSSEC chain
        name = dns.name.from_text(domain)
        for r in dnskey.response.answer:
            if r.rdtype == dns.rdatatype.DNSKEY:
                dnskey_rrset = r
        for r in rrsig.response.answer:
            if r.rdtype == dns.rdatatype.RRSIG:
                rrsig_rrset = r
                
        dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {name: dnskey_rrset})
        return True
    except dns.resolver.NoAnswer:
        recon_logger.debug("No DNSSEC records found")
    except dns.dnssec.ValidationFailure as e:
        recon_logger.warning(f"DNSSEC validation failed: {str(e)}")
    except Exception as e:
        recon_logger.error(f"DNSSEC check error: {str(e)}")
    return False

def _check_zone_transfer(domain: str, nameservers: list) -> dict:
    """Test for DNS zone transfer vulnerability"""
    results = {
        "zone_transfer_vulnerable": False,
        "zone_transfer_servers": []
    }
    
    for ns in nameservers:
        try:
            # Strip trailing dot from nameserver
            ns_server = ns.rstrip('.')
            recon_logger.info(f"Attempting zone transfer from {ns_server}")
            
            # Perform AXFR request
            zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
            if zone:
                results["zone_transfer_vulnerable"] = True
                results["zone_transfer_servers"].append(ns_server)
                
                # Save first 5 records as sample
                records = []
                for name, node in zone.nodes.items():
                    rdatas = node.rdatasets
                    for rdata in rdatas:
                        records.append(f"{name} {rdata}")
                    if len(records) >= 5:
                        break
                results["zone_transfer_sample"] = records
        except dns.xfr.TransferError:
            # Zone transfer failed (expected behavior)
            pass
        except Exception as e:
            recon_logger.debug(f"Zone transfer failed on {ns_server}: {str(e)}")
    
    return results

def _detect_cloud_providers(ipv4: list, ipv6: list, txt_records: list) -> dict:
    """Detect cloud providers and protections"""
    providers = {}
    
    # Check Cloudflare
    for ip in ipv4 + ipv6:
        if _is_cloudflare_ip(ip):
            providers["Cloudflare"] = {"protection": True, "type": "CDN/WAF"}
            break
    
    # Check AWS Route53 from NS records
    for record in txt_records:
        if "amazonaws" in record:
            providers["AWS"] = {"protection": False, "type": "DNS/Hosting"}
            if "cloudfront" in record:
                providers["AWS CloudFront"] = {"protection": True, "type": "CDN"}
    
    # Check Azure DNS
    for record in txt_records:
        if "azure" in record or "msdc" in record:
            providers["Azure"] = {"protection": False, "type": "DNS/Hosting"}
    
    # Check Google Cloud
    for record in txt_records:
        if "google" in record or "googleusercontent" in record:
            providers["Google Cloud"] = {"protection": False, "type": "DNS/Hosting"}
            if "google-site-verification" in record:
                providers["Google Cloud"]["protection"] = True
    
    # Check other providers
    cloud_indicators = {
        "akamai": "Akamai",
        "fastly": "Fastly",
        "incapsula": "Imperva",
        "sucuri": "Sucuri",
        "cloudfront": "AWS CloudFront"
    }
    
    for record in txt_records:
        for indicator, provider in cloud_indicators.items():
            if indicator in record:
                providers[provider] = {"protection": True, "type": "CDN/WAF"}
    
    return providers

def _is_cloudflare_ip(ip: str) -> bool:
    """Check if IP belongs to Cloudflare using updated ranges"""
    ip_obj = ipaddress.ip_address(ip)
    
    # Check IPv4 ranges
    for cidr in CLOUDFLARE_IPS["ipv4_cidrs"]:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    
    # Check IPv6 ranges
    for cidr in CLOUDFLARE_IPS["ipv6_cidrs"]:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    
    return False

def _enumerate_subdomains(
    domain: str, 
    nameservers: list, 
    resolver: dns.resolver.Resolver,
    threads: int = 10
) -> dict:
    """Perform basic subdomain enumeration using common prefixes"""
    common_prefixes = [
        "www", "mail", "webmail", "ftp", "smtp", "pop", "imap", 
        "admin", "secure", "vpn", "api", "dev", "test", "staging",
        "static", "cdn", "blog", "shop", "app", "portal", "cpanel"
    ]
    
    results = {"found": [], "tested": len(common_prefixes)}
    
    # Use first nameserver for direct queries
    if nameservers:
        resolver.nameservers = [nameservers[0].rstrip('.')]
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full_domain, "A", lifetime=2)
            return full_domain, [str(r) for r in answers]
        except Exception:
            return None
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_subdomain, prefix) for prefix in common_prefixes]
        
        for future in as_completed(futures):
            if result := future.result():
                results["found"].append({
                    "subdomain": result[0],
                    "ips": result[1]
                })
    
    return results

def _get_dmarc_record(domain: str, resolver: dns.resolver.Resolver) -> list:
    """Get DMARC record for domain"""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        return [str(r) for r in answers]
    except Exception:
        return []

def _get_dkim_records(domain: str, resolver: dns.resolver.Resolver) -> dict:
    """Get common DKIM records for domain"""
    common_selectors = [
        "google", "selector1", "selector2", "dkim", "domainkey",
        "everlytickey1", "everlytickey2", "k1", "mxvault"
    ]
    
    results = {}
    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")
            results[selector] = [str(r) for r in answers]
        except Exception:
            continue
    
    return results

def _get_spf_record(domain: str, resolver: dns.resolver.Resolver) -> list:
    """Get SPF record for domain"""
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [str(r) for r in answers if "v=spf1" in str(r)]
        return spf_records
    except Exception:
        return []

def _parse_soa_record(soa: str) -> dict:
    """Parse SOA record into structured data"""
    parts = soa.split()
    if len(parts) >= 7:
        return {
            "mname": parts[0],
            "rname": parts[1],
            "serial": parts[2],
            "refresh": parts[3],
            "retry": parts[4],
            "expire": parts[5],
            "minimum": parts[6]
        }
    return soa

@cache_result(expiry=3600)
def reverse_lookup(ip: str) -> dict:
    """Comprehensive reverse DNS lookup with additional checks"""
    results = {
        "ptr": [],
        "domain": "",
        "hostnames": [],
        "services": []
    }
    
    try:
        # Standard PTR lookup
        ptr_name = dns.reversename.from_address(ip)
        ptr_answers = dns.resolver.resolve(ptr_name, "PTR")
        results["ptr"] = [str(r) for r in ptr_answers]
        
        # Extract primary domain from PTR
        if results["ptr"]:
            hostname = results["ptr"][0].rstrip('.')
            results["hostnames"] = [hostname]
            
            # Extract domain (last two parts)
            parts = hostname.split('.')
            if len(parts) >= 2:
                results["domain"] = f"{parts[-2]}.{parts[-1]}"
        
        # Service detection by port scan
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                
                # Check common ports
                common_ports = [80, 443, 22, 25, 53, 21, 8080]
                for port in common_ports:
                    if s.connect_ex((ip, port)) == 0:
                        service = socket.getservbyport(port, 'tcp') if port != 53 else "dns"
                        results["services"].append(f"{service} ({port})")
        except Exception:
            pass
    except dns.resolver.NXDOMAIN:
        results["ptr"] = ["No PTR record"]
    except Exception as e:
        results["error"] = str(e)
    
    return results

# Example usage
if __name__ == "__main__":
    results = dns_enum(
        "example.com",
        check_dnssec=True,
        check_zone_transfer=True,
        check_cloud=True,
        check_subdomains=True,
        threads=15
    )
    print(json.dumps(results, indent=2))
