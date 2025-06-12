#!/usr/bin/env python3
import os
import time
import json
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

# Configuration
CONFIG = {
    'brute_force_size': 10000,
    'max_threads': 100,
    'wordlist_path': 'wordlists/subdomains.txt'
}

# Helper functions to replace utils.helpers
def get_wordlist(path, max_size=None):
    """
    Read wordlist from file and return as list
    
    :param path: Path to wordlist file
    :param max_size: Maximum number of words to return
    :return: List of words
    """
    if not os.path.isfile(path):
        print(f"\033[91mWordlist file not found: {path}\033[0m")
        return []
    
    with open(path, 'r', errors='ignore') as f:
        words = f.read().splitlines()
    
    # Filter out comments and empty lines
    words = [w.strip() for w in words if w.strip() and not w.startswith('#')]
    
    if max_size and len(words) > max_size:
        return words[:max_size]
    
    return words

def validate_domain(domain):
    """
    Simple domain validation
    :param domain: Domain to validate
    :return: True if valid, False otherwise
    """
    if not domain:
        return False
    # Simple check for domain format
    if '.' not in domain:
        return False
    return True

def subdomain_scan(domain, use_bruteforce=True, validate=True, brute_force_size=None, max_threads=None):
    """
    Perform subdomain enumeration using multiple techniques
    
    :param domain: Target domain (e.g., example.com)
    :param use_bruteforce: Enable brute-force discovery
    :param validate: Validate DNS resolution
    :param brute_force_size: Size of brute-force wordlist
    :param max_threads: Maximum threads for brute-force
    :return: Results dictionary
    """
    results = {
        'unique_subdomains': 0,
        'subdomains': {},
        'source_stats': {},
        'validation': {},
        'error': None
    }
    
    try:
        # Public sources (simplified for example)
        sources = {
            'crt.sh': get_crtsh_subdomains(domain),
            'dnsdumpster': get_dnsdumpster_subdomains(domain),
            'virustotal': get_virustotal_subdomains(domain)
        }
        
        # Add brute-force if enabled
        if use_bruteforce:
            size = brute_force_size or CONFIG['brute_force_size']
            threads = max_threads or CONFIG['max_threads']
            sources['bruteforce'] = brute_force_subdomains(domain, size, threads)
        
        # Process results
        all_subs = set()
        for source, subdomains in sources.items():
            results['subdomains'][source] = subdomains
            results['source_stats'][source] = len(subdomains)
            all_subs.update(subdomains)
        
        results['unique_subdomains'] = len(all_subs)
        
        # DNS validation
        if validate and all_subs:
            results['validation'] = validate_subdomains(domain, all_subs)
            
    except Exception as e:
        results['error'] = str(e)
    
    return results

def subdomain_scan_interactive(domain):
    """Interactive subdomain scanning interface"""
    print("\n" + "="*50)
    print("Subdomain Enumeration Tool".center(50))
    print("="*50)
    
    # Scan options
    print("\n" + "-"*20 + " Scan Options " + "-"*20)
    print("Enable brute-force discovery? (Y/n)")
    brute_choice = input(">>> ").strip().lower()
    use_bruteforce = brute_choice != 'n'
    
    print("\nEnable DNS validation? (Y/n)")
    validate_choice = input(">>> ").strip().lower()
    validate = validate_choice != 'n'
    
    # Advanced options
    print("\n" + "-"*20 + " Advanced Options " + "-"*20)
    print(f"Brute-force list size (default: {CONFIG['brute_force_size']}):")
    brute_size = input(">>> ").strip()
    brute_force_size = int(brute_size) if brute_size.isdigit() else CONFIG['brute_force_size']
    
    print(f"Max threads (default: {CONFIG['max_threads']}):")
    max_threads = input(">>> ").strip()
    max_threads = int(max_threads) if max_threads.isdigit() else CONFIG['max_threads']
    
    print("\nStarting subdomain enumeration...")
    
    start_time = time.time()
    results = subdomain_scan(
        domain, 
        use_bruteforce, 
        validate,
        brute_force_size,
        max_threads
    )
    duration = time.time() - start_time
    
    # Print results summary
    print("\n" + "="*50)
    print("Scan Results Summary".center(50))
    print("="*50)
    print(f"Target Domain: {domain}")
    print(f"Scan Duration: {duration:.2f} seconds")
    print(f"Total Sources Used: {len(results['subdomains'])}")
    print(f"Unique Subdomains Found: {results['unique_subdomains']}")
    
    if results.get('error'):
        print(f"\nError occurred: {results['error']}")
        return results
    
    # Print source statistics
    print("\nSource Statistics:")
    for source, count in results["source_stats"].items():
        print(f"  {source}: {count} subdomains")
    
    # Print validation results if enabled
    if validate and 'validation' in results:
        print("\nValidation Results:")
        print(f"  Resolved: {len(results['validation'].get('resolved', []))}")
        print(f"  Unresolved: {len(results['validation'].get('unresolved', []))}")
        print(f"  Wildcard DNS: {'Yes' if results['validation'].get('wildcard') else 'No'}")
        if results['validation'].get('wildcard'):
            print(f"  Wildcard IPs: {', '.join(results['validation'].get('wildcard_ips', []))}")
    
    # Ask to show resolved subdomains
    if validate and results['validation'].get('resolved'):
        print("\nShow resolved subdomains? (y/N)")
        if input(">>> ").strip().lower() == 'y':
            print("\nResolved Subdomains:")
            for sub in results['validation']['resolved']:
                ips = ', '.join(sub['ips'])
                print(f"  {sub['subdomain']}: {ips}")
    
    # Ask to save results
    print("\nSave results to file? (Y/n)")
    if input(">>> ").strip().lower() != 'n':
        filename = f"subdomains_{domain}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {filename}")
    
    return results

# Helper functions (simplified implementations)
def get_crtsh_subdomains(domain):
    """Get subdomains from crt.sh"""
    # In a real implementation, you would query crt.sh
    return [f"sub1.{domain}", f"sub2.{domain}"]

def get_dnsdumpster_subdomains(domain):
    """Get subdomains from DNSDumpster"""
    # In a real implementation, you would query DNSDumpster
    return [f"api.{domain}", f"mail.{domain}"]

def get_virustotal_subdomains(domain):
    """Get subdomains from VirusTotal"""
    # In a real implementation, you would query VirusTotal
    return [f"www.{domain}", f"dev.{domain}"]

def brute_force_subdomains(domain, size=10000, max_threads=100):
    """Perform brute-force subdomain discovery"""
    wordlist = get_wordlist(CONFIG['wordlist_path'], size)
    if not wordlist:
        print("\033[91mBrute-force disabled: wordlist unavailable\033[0m")
        return []
    
    subdomains = []
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # We break the wordlist into chunks to avoid overwhelming memory
        chunk_size = 1000
        for i in range(0, len(wordlist), chunk_size):
            chunk = wordlist[i:i+chunk_size]
            for result in executor.map(check_subdomain, chunk):
                if result:
                    subdomains.append(result)
    
    return subdomains

def validate_subdomains(domain, subdomains):
    """Validate DNS resolution for subdomains"""
    resolved = []
    unresolved = []
    wildcard_ips = set()
    
    # Check for wildcard DNS
    try:
        # Use a random subdomain that likely doesn't exist
        test_domain = f"this-subdomain-should-not-exist-12345.{domain}"
        answers = dns.resolver.resolve(test_domain, 'A')
        wildcard_ips.update(str(r) for r in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        print(f"Wildcard check error: {e}")
    
    # Validate each subdomain
    for sub in subdomains:
        try:
            answers = dns.resolver.resolve(sub, 'A')
            ips = [str(r) for r in answers]
            resolved.append({
                'subdomain': sub,
                'ips': ips
            })
            # Check if it matches wildcard IPs
            if wildcard_ips and set(ips) == wildcard_ips:
                # This subdomain might be a wildcard, so we mark it as such?
                # We don't remove it, but we note that it's a wildcard
                pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            unresolved.append(sub)
        except Exception as e:
            print(f"Error resolving {sub}: {e}")
            unresolved.append(sub)
    
    return {
        'resolved': resolved,
        'unresolved': unresolved,
        'wildcard': bool(wildcard_ips),
        'wildcard_ips': list(wildcard_ips)
    }

if __name__ == "__main__":
    # Example usage
    results = subdomain_scan_interactive("example.com")
