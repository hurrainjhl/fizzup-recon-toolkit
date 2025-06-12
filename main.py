#!/usr/bin/env python3
import os
import sys
import time
from utils.async_runner import async_runner
from modules.passive.who_is import whois_lookup, whois_interactive
from modules.passive.dns_enum import dns_enum
from modules.passive.subdomain import subdomain_scan
from modules.active.port_scan import port_scan, port_scan_interactive, port_scan_help
from modules.active.banners import banner_grab_interactive
from modules.active.tech_detect import TechnologyDetector
from modules.reporting import generate_report  # Fixed import

# ASCII Banner
BANNER = """
\033[94m
███████╗██╗███████╗███████╗██╗   ██╗██████╗ 
██╔════╝██║╚══███╔╝╚══███╔╝██║   ██║██╔══██╗
█████╗  ██║  ███╔╝   ███╔╝ ██║   ██║██████╔╝
██╔══╝  ██║ ███╔╝   ███╔╝  ██║   ██║██╔═══╝ 
██║     ██║███████╗███████╗╚██████╔╝██║     
╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     
\033[0m
\033[1;35mAdvanced Reconnaissance Toolkit v2.0\033[0m
\033[90mComprehensive Security Assessment Platform\033[0m
"""

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    """Display program banner"""
    clear_screen()
    print(BANNER)
    print("\033[93m" + "=" * 65 + "\033[0m")
    print()

def prompt_menu(options, title="Select Option"):
    """Display a menu and return user choice"""
    print(f"\n\033[1;36m{title}:\033[0m")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    
    while True:
        try:
            choice = int(input("\n>>> Enter choice: ").strip())
            if 1 <= choice <= len(options):
                return choice
            print("\033[91mInvalid choice. Please try again.\033[0m")
        except ValueError:
            print("\033[91mPlease enter a number.\033[0m")

def get_target():
    """Prompt for target domain/IP"""
    print("\n\033[1;36mEnter Target (domain or IP address):\033[0m")
    target = input(">>> ").strip()
    return target

def passive_scan_menu(target):
    """Passive reconnaissance menu"""
    results = {"passive": {}}
    
    modules = [
        "WHOIS Lookup",
        "DNS Enumeration",
        "Subdomain Discovery",
        "Run ALL Passive Scans"
    ]
    
    choice = prompt_menu(modules, "Passive Recon Modules")
    
    # WHOIS Lookup
    if choice in [1, 4]:
        print("\n\033[93mStarting WHOIS lookup...\033[0m")
        results["passive"]["WHOIS"] = whois_interactive()  # Use interactive mode
        print("\033[92mWHOIS lookup completed!\033[0m")
    
    # DNS Enumeration
    if choice in [2, 4]:
        print("\n\033[93mStarting DNS enumeration...\033[0m")
        results["passive"]["DNS"] = dns_enum(target)
        print("\033[92mDNS enumeration completed!\033[0m")
    
    # Subdomain Discovery
    if choice in [3, 4]:
        print("\n\033[93mStarting subdomain discovery...\033[0m")
        results["passive"]["SUBDOMAINS"] = subdomain_scan(target)
        print("\033[92mSubdomain discovery completed!\033[0m")
    
    return results

def active_scan_menu(target):
    """Active reconnaissance menu"""
    results = {"active": {}}
    
    modules = [
        "Port Scanning",
        "Service Banner Analysis",
        "Technology Detection",
        "Run ALL Active Scans"
    ]
    
    choice = prompt_menu(modules, "Active Recon Modules")
    
    # Port Scanning
    if choice in [1, 4]:
        print("\n\033[93mStarting port scan...\033[0m")
        if input("Use interactive mode? (y/n): ").lower() == 'y':
            results["active"]["PORT_SCAN"] = port_scan_interactive()
        else:
            ports = input("Port range (e.g., 1-1024): ").strip() or "1-1024"
            scan_type = input("Scan type (syn/connect/udp/all): ").strip() or "syn"
            results["active"]["PORT_SCAN"] = port_scan(target, ports=ports, scan_type=scan_type)
        print("\033[92mPort scan completed!\033[0m")
    
    # Banner Analysis
    if choice in [2, 4]:
        print("\n\033[93mStarting banner analysis...\033[0m")
        ports = input("Ports to scan (comma separated): ").strip()
        port_list = [int(p.strip()) for p in ports.split(',')] if ports else None
        results["active"]["BANNERS"] = banner_grab_interactive(target, ports=port_list)
        print("\033[92mBanner analysis completed!\033[0m")
    
    # Technology Detection
    if choice in [3, 4]:
       print("\n\033[93mStarting technology detection...\033[0m")
       url = input(f"URL to scan (default: http://{target}): ").strip() or f"http://{target}"
       detector = TechnologyDetector()
       results["active"]["TECH"] = detector.detect_technology(url, depth=2)
       print("\033[92mTechnology detection completed!\033[0m")
    
    return results

def generate_report_menu(results, target):
    """Generate report menu"""
    if not results.get('passive') and not results.get('active'):
        print("\033[91mNo scan results to report!\033[0m")
        return
    
    if input("\nGenerate report? (y/n): ").lower() == 'y':
        filename = input("Report filename (default: report.html): ").strip() or "report.html"
        report_path = generate_report(results, filename)  # Fixed function call
        print(f"\n\033[92mReport generated at: {report_path}\033[0m")
        print("\033[93mOpen this file in a web browser to view the full report.\033[0m")

def main():
    """Main program flow"""
    show_banner()
    
    # Main menu
    main_options = [
        "Passive Reconnaissance",
        "Active Reconnaissance",
        "Full Reconnaissance (Passive + Active)",
        "Help / Documentation",
        "Exit"
    ]
    
    results = {}
    target = ""
    
    while True:
        choice = prompt_menu(main_options, "Main Menu")
        
        # Get target if not already set (MOVED THIS SECTION UP)
        if not target and choice in [1, 2, 3]:  # Only for scan options
            target = get_target()
            results["target"] = target
        
        # Exit
        if choice == 5:
            print("\n\033[93mExiting FizzUp Recon Toolkit. Goodbye!\033[0m")
            sys.exit(0)
        
        # Help/Docs
        if choice == 4:
            print("\n\033[94mFizzUp Recon Toolkit Documentation:\033[0m")
            print(port_scan_help())
            input("\nPress Enter to continue...")
            show_banner()
            continue
                     
        # Get target if not already set
        if not target:
            target = get_target()
            results["target"] = target
        
        # Passive Recon
        if choice in [1, 3]:
            passive_results = passive_scan_menu(target)
            results.update(passive_results)
        
        # Active Recon
        if choice in [2, 3]:
            active_results = active_scan_menu(target)
            results.update(active_results)
        
        # Generate report
        generate_report_menu(results, target)
        
        # Next action
        cont = input("\nPerform another operation? (y/n): ").lower()
        if cont != 'y':
            print("\n\033[93mExiting FizzUp Recon Toolkit. Goodbye!\033[0m")
            break
        
        show_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\033[93mOperation cancelled by user. Exiting.\033[0m")
        sys.exit(1)

