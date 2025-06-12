from typing import Dict, Union, List, Optional
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor

def banner_grab_interactive(
    target: Optional[str] = None, 
    ports: Optional[List[int]] = None
) -> Dict[str, Union[str, List[dict]]]:
    """Interactive banner grabbing interface with guided options"""
    print("\n" + "="*50)
    print("Advanced Banner Grabber".center(50))
    print("="*50)
    
    # Use provided target or prompt for it
    if not target:
        print("\nEnter target IP/domain:")
        target = input(">>> ").strip()
        if not target:
            print("Target is required!")
            return {"error": "No target specified"}
    
    # Use provided ports or show selection menu
    if not ports:
        print("\n" + "-"*20 + " Port Selection " + "-"*20)
        print("1. Common Ports (HTTP, SSH, FTP, SMTP, etc.)")
        print("2. Web Servers (80, 443, 8080, 8443)")
        print("3. Database Ports (1433, 1521, 3306, 5432, 27017)")
        print("4. Full Service Scan (100+ common services)")
        print("5. Custom Ports")
        port_choice = input(">>> ").strip() or "1"
        
        port_profiles = {
            "1": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995],
            "2": [80, 443, 8000, 8080, 8443, 8888],
            "3": [1433, 1521, 3306, 5432, 27017, 6379],
            "4": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
                  587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
                  6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017]
        }
        
        if port_choice == "5":
            print("\nEnter custom ports (comma separated):")
            print("Example: 80,443,8000-9000,22")
            custom_input = input(">>> ").strip()
            ports = parse_port_input(custom_input)
        else:
            ports = port_profiles.get(port_choice, port_profiles["1"])
    
    if not ports:
        print("No valid ports selected!")
        return {"error": "No ports specified"}
    
    # Advanced options
    print("\n" + "-"*20 + " Advanced Options " + "-"*20)
    print("Connection timeout (seconds, default 3.0):")
    try:
        timeout = float(input(">>> ").strip() or "3.0")
    except ValueError:
        timeout = 3.0
        print(f"Invalid timeout, using default: {timeout}")
    
    print("Concurrency level (default 100):")
    try:
        concurrency = int(input(">>> ").strip() or "100")
    except ValueError:
        concurrency = 100
        print(f"Invalid concurrency, using default: {concurrency}")
    
    print("Enable vulnerability detection? (Y/n):")
    vuln_detect = (input(">>> ").strip().lower() or "y") == "y"
    
    print("Enable metadata extraction? (Y/n):")
    metadata = (input(">>> ").strip().lower() or "y") == "y"
    
    print("\nStarting banner grab on {} ports...".format(len(ports)))
    
    # Run the scan
    results = grab_banners(
        target=target,
        ports=ports,
        timeout=timeout,
        max_concurrency=concurrency
    )
    
    # Display results
    print("\n" + "="*50)
    print("Banner Grab Results".center(50))
    print("="*50)
    print(f"Target: {target}")
    print(f"Ports scanned: {len(ports)}")
    print(f"Services found: {len(results.get('banners', []))}")
    
    if 'error' in results:
        print(f"\nError: {results['error']}")
        return results
    
    if results.get('banners'):
        print("\nPORT   SERVICE     VERSION")
        print("-" * 50)
        for banner in results['banners']:
            port = banner.get('port', '?')
            service = banner.get('service', 'unknown').ljust(10)
            version = banner.get('version', '')
            if not version and banner.get('software'):
                version = banner.get('software')
            print(f"{port:<6} {service} {version}")
            
            # Show vulnerabilities if detected
            if vuln_detect and banner.get('vulnerabilities'):
                print("  [!] Vulnerabilities:")
                for vuln in banner['vulnerabilities']:
                    print(f"      - {vuln}")
            
            # Show metadata if enabled
            if metadata and banner.get('metadata'):
                print("  [*] Metadata:")
                for k, v in banner['metadata'].items():
                    print(f"      - {k}: {v}")
    
    print("\n" + "="*50)
    print("Scan completed!")
    return results

def parse_port_input(input_str: str) -> List[int]:
    """Parse custom port input into list of integers"""
    ports = []
    parts = input_str.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    # Remove duplicates and sort
    return sorted(set(ports))

def grab_banners(
    target: str,
    ports: List[int],
    timeout: float = 3.0,
    max_concurrency: int = 100
) -> Dict[str, Union[str, List[dict]]]:
    """Actual banner grabbing implementation"""
    results = {"banners": []}
    
    async def scan_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            
            # Try to get banner with common protocol-specific probes
            banner = ""
            if port in [21, 22, 25, 110, 143, 587]:
                # Send empty line to trigger response
                writer.write(b"\r\n")
                await writer.drain()
                banner = (await reader.read(1024)).decode(errors='ignore')
            else:
                # Send HTTP-like request for web ports
                if port in [80, 443, 8080, 8443]:
                    writer.write(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                else:
                    # Generic probe
                    writer.write(b"\r\n")
                await writer.drain()
                banner = (await reader.read(1024)).decode(errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            return {
                "port": port,
                "banner": banner,
                "service": guess_service(port, banner),
                "status": "open"
            }
        except Exception as e:
            return {
                "port": port,
                "error": str(e),
                "status": "closed" if "refused" in str(e).lower() else "filtered"
            }

    async def main_scan():
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def limited_scan(port):
            async with semaphore:
                return await scan_port(port)
                
        return await asyncio.gather(*[limited_scan(port) for port in ports])
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    scan_results = loop.run_until_complete(main_scan())
    loop.close()
    
    # Process results and extract metadata
    for result in scan_results:
        if result.get("banner"):
            banner_info = {
                "port": result["port"],
                "service": result["service"],
                "banner": result["banner"],
                "software": extract_software(result["banner"]),
                "version": extract_version(result["banner"]),
                "metadata": extract_metadata(result["banner"]),
                "vulnerabilities": []
            }
            results["banners"].append(banner_info)
    
    return results

def guess_service(port: int, banner: str) -> str:
    """Guess service based on port and banner"""
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "OracleDB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }
    
    # Try to get service from banner if possible
    if "SSH" in banner:
        return "SSH"
    if "HTTP" in banner or "Apache" in banner or "nginx" in banner:
        return "HTTP" if port != 443 else "HTTPS"
    if "FTP" in banner:
        return "FTP"
    
    # Fallback to port-based guessing
    return service_map.get(port, "unknown")

def extract_software(banner: str) -> str:
    """Extract software name from banner"""
    common_software = [
        "Apache", "nginx", "Microsoft-IIS", "OpenSSH", "vsFTPd",
        "Postfix", "Exim", "Sendmail", "MySQL", "PostgreSQL",
        "Redis", "MongoDB", "ProFTPD", "Pure-FTPd", "Courier",
        "Dovecot", "Cyrus", "Oracle", "SQL Server"
    ]
    
    for software in common_software:
        if software in banner:
            return software
    return ""

def extract_version(banner: str) -> str:
    """Extract version number from banner"""
    import re
    version_patterns = [
        r"(\d+\.\d+(\.\d+)?)",  # Standard version pattern
        r"([A-Za-z]+/\d+\.\d+)",  # HTTP-style (Apache/2.4.52)
        r"(v\d+\.\d+\.\d+)",      # v-prefixed versions
        r"(\d+\.\d+[a-z])",       # Version with letter suffix
        r"(\d{4}[a-z]?\d?[a-z]?)" # Year-based versions
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return ""

def extract_metadata(banner: str) -> Dict[str, str]:
    """Extract metadata from banner"""
    metadata = {}
    
    # Server header extraction
    if "Server:" in banner:
        server = banner.split("Server:")[1].split("\n")[0].strip()
        metadata["Server"] = server
    
    # HTTP methods
    if "Allow:" in banner:
        methods = banner.split("Allow:")[1].split("\n")[0].strip()
        metadata["HTTP Methods"] = methods
    
    # Cookies
    if "Set-Cookie:" in banner:
        cookies = [c.split(";")[0] for c in banner.split("Set-Cookie:")[1:]]
        metadata["Cookies"] = ", ".join(cookies)
    
    # Security headers
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection"
    ]
    
    for header in security_headers:
        if header in banner:
            value = banner.split(header + ":")[1].split("\n")[0].strip()
            metadata[header] = value
    
    return metadata
