import socket
import nmap
import time
import ipaddress
from datetime import datetime
from typing import List, Dict, Tuple, Union, Optional
from utils.logger import recon_logger
from concurrent.futures import ThreadPoolExecutor, as_completed

def port_scan_interactive() -> Dict:
    """Interactive port scanning interface with Nmap-like options"""
    print("\n" + "="*50)
    print("Nmap-style Port Scanner".center(50))
    print("="*50)
    
    # Target input
    print("\nEnter target IP/domain (comma separated for multiple):")
    print("Example: scanme.nmap.org, 192.168.1.0/24, 10.0.0.1-100")
    targets = input(">>> ").strip()
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    
    # Scan type selection
    print("\n" + "-"*20 + " Scan Techniques " + "-"*20)
    print("1. TCP SYN Scan (default, fast, requires root)")
    print("2. TCP Connect Scan (no root, slower)")
    print("3. UDP Scan (slow, requires root)")
    print("4. Comprehensive (SYN+UDP)")
    print("5. ACK Scan (firewall detection)")
    print("6. Window Scan (advanced detection)")
    scan_choice = input(">>> ").strip() or "1"
    scan_type = {
        "1": "syn", 
        "2": "connect", 
        "3": "udp", 
        "4": "all",
        "5": "ack",
        "6": "window"
    }.get(scan_choice, "syn")
    
    # Port selection
    print("\n" + "-"*20 + " Port Selection " + "-"*20)
    print("1. Quick Scan (Top 100 ports)")
    print("2. Standard Scan (Common ports, default)")
    print("3. Full Port Scan (All 65535 ports)")
    print("4. Custom Port Range")
    mode_choice = input(">>> ").strip() or "2"
    
    custom_ports = ""
    if mode_choice == "4":
        print("\nEnter custom ports (ex: 80,443,8000-9000,22):")
        custom_ports = input(">>> ").strip()
        mode = "custom"
    else:
        mode = {"1": "quick", "2": "smart", "3": "full"}.get(mode_choice, "smart")
    
    # Timing template
    print("\n" + "-"*20 + " Timing Template " + "-"*20)
    print("1. Paranoid (0) - Very slow, stealthy")
    print("2. Sneaky (1) - Quite slow")
    print("3. Polite (2) - Slower, less bandwidth")
    print("4. Normal (3) - Default")
    print("5. Aggressive (4) - Faster, might miss ports")
    print("6. Insane (5) - Very fast, aggressive")
    timing_choice = input(">>> ").strip() or "4"
    timing = {"1": "0", "2": "1", "3": "2", "4": "3", "5": "4", "6": "5"}.get(timing_choice, "3")
    
    # Additional options
    print("\n" + "-"*20 + " Additional Options " + "-"*20)
    print("Enable OS detection? (y/N):")
    os_detect = input(">>> ").strip().lower() == "y"
    print("Enable service/version detection? (y/N):")
    sv_detect = input(">>> ").strip().lower() == "y"
    print("Enable script scanning? (y/N):")
    script_scan = input(">>> ").strip().lower() == "y"
    
    # Calculate timeout based on scan type and timing
    base_timeout = {
        "0": 300, "1": 180, "2": 120, 
        "3": 60, "4": 30, "5": 15
    }.get(timing, 60)
    
    if scan_type in ("udp", "all"):
        base_timeout *= 2
    
    if mode == "full":
        base_timeout *= 1.5
    
    print(f"\nStarting {scan_type.upper()} scan with timing T{timing}...")
    
    return port_scan(
        target=target_list,
        ports=custom_ports,
        mode=mode,
        scan_type=scan_type,
        timing_template=timing,
        os_detection=os_detect,
        service_detection=sv_detect,
        script_scan=script_scan,
        host_timeout=base_timeout
    )

def port_scan(
    target: Union[str, List[str]],
    ports: str = "",
    mode: str = "smart",
    scan_type: str = "syn",
    timing_template: str = "3",
    os_detection: bool = False,
    service_detection: bool = True,
    script_scan: bool = False,
    host_timeout: float = 120.0,
    max_threads: int = 1,
    custom_args: str = ""
) -> Dict[str, Union[str, List[dict]]]:
    """
    Enhanced Nmap-style port scanner with comprehensive options
    
    Args:
        target: Single target or list of targets (IPs, hostnames, CIDR ranges)
        ports: Custom port specification (overrides mode if provided)
        mode: Scan profile ("quick", "smart", "full")
        scan_type: "syn", "connect", "udp", "all", "ack", "window"
        timing_template: 0-5 (paranoid to insane)
        os_detection: Enable OS fingerprinting
        service_detection: Enable service/version detection
        script_scan: Enable NSE script scanning
        host_timeout: Timeout per host in seconds
        max_threads: Maximum concurrent scans
        custom_args: Raw Nmap arguments (overrides other settings)
    
    Returns:
        Dictionary with scan results in Nmap-like structure
    """
    if not target:
        raise ValueError("Target cannot be empty")
    
    if isinstance(target, str):
        targets = [target]
    else:
        targets = target
    
    # Resolve targets to IPs (handling CIDR ranges and hostnames)
    target_mapping = {}
    resolved_targets = []
    for t in targets:
        try:
            # Handle CIDR ranges and IP ranges directly
            if '/' in t or '-' in t:
                target_mapping[t] = t
                resolved_targets.append(t)
            else:
                ipaddress.ip_address(t)
                target_mapping[t] = t
                resolved_targets.append(t)
        except ValueError:
            try:
                ip = socket.gethostbyname(t)
                target_mapping[t] = ip
                resolved_targets.append(ip)
            except socket.gaierror:
                recon_logger.warning(f"Could not resolve host: {t}")
                target_mapping[t] = None
    
    # Configure scan profiles
    port_profiles = {
        "quick": "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
        "smart": "21-23,25,53,80,110-111,135,139,143,389,443,445,465,587,993,995,1723,3306,3389,5900,5985,6379,8000-9000",
        "full": "1-65535"
    }
    
    port_range = ports if ports else port_profiles.get(mode.lower(), "1-1024")
    
    scan_meta = {
        "scan_type": scan_type,
        "mode": mode,
        "port_range": port_range,
        "timing_template": f"T{timing_template}",
        "os_detection": os_detection,
        "service_detection": service_detection,
        "script_scan": script_scan,
        "host_timeout": host_timeout,
        "max_threads": max_threads,
        "start_time": datetime.utcnow().isoformat(),
        "source_ip": socket.gethostbyname(socket.gethostname()),
        "targets_count": len(targets),
        "custom_args": custom_args
    }
    
    results = {
        "scan_metadata": scan_meta,
        "results": {},
        "status": "started",
        "stats": {
            "targets_completed": 0,
            "hosts_up": 0,
            "ports_scanned": 0,
            "open_ports": 0,
            "services_found": 0
        }
    }
    
    recon_logger.info(f"Starting {scan_type.upper()} {mode} scan on {len(resolved_targets)} targets")
    
    # Sequential scan for nmap-like output
    for original, resolved_ip in target_mapping.items():
        if not resolved_ip:
            results["results"][original] = {"error": "DNS resolution failed"}
            recon_logger.error(f"Scan failed for {original}: DNS resolution failed")
            continue
            
        try:
            target_result = _scan_single_target(
                original,
                resolved_ip,
                port_range,
                scan_type,
                timing_template,
                os_detection,
                service_detection,
                script_scan,
                host_timeout,
                custom_args
            )
            results["results"][original] = target_result
            
            # Update stats
            if "error" not in target_result:
                results["stats"]["targets_completed"] += 1
                if target_result["host_status"] == "up":
                    results["stats"]["hosts_up"] += 1
                results["stats"]["ports_scanned"] += target_result.get("ports_scanned", 0)
                results["stats"]["open_ports"] += len(target_result.get("open_ports", []))
                results["stats"]["services_found"] += len(target_result.get("services", []))
            
            # Print nmap-style results
            _print_nmap_results(original, resolved_ip, target_result)
            
        except Exception as e:
            error_msg = f"Scan failed for {original}: {str(e)}"
            recon_logger.error(error_msg, exc_info=True)
            results["results"][original] = {"error": error_msg}
            print(f"\nScan failed for {original}: {str(e)}")
    
    results["status"] = "completed"
    scan_meta["end_time"] = datetime.utcnow().isoformat()
    scan_duration = datetime.fromisoformat(scan_meta["end_time"]) - datetime.fromisoformat(scan_meta["start_time"])
    
    print("\n" + "="*50)
    print("Scan Summary".center(50))
    print("="*50)
    print(f"Scan completed in {scan_duration.total_seconds():.2f} seconds")
    print(f"Hosts scanned: {results['stats']['targets_completed']}")
    print(f"Hosts up: {results['stats']['hosts_up']}")
    print(f"Open ports found: {results['stats']['open_ports']}")
    print("="*50)
    
    recon_logger.success(
        f"Scan completed: {results['stats']['open_ports']} open ports found across {results['stats']['hosts_up']} hosts"
    )
    
    return results

def _print_nmap_results(original: str, resolved_ip: str, result: Dict):
    """Print Nmap-style results for a single target"""
    print(f"\nNmap scan report for {original} ({resolved_ip})")
    print(f"Host is {'up' if result['host_status'] == 'up' else 'down'}", end="")
    if 'scan_duration' in result:
        print(f" (scanned in {result['scan_duration']:.2f}s)")
    else:
        print()
    
    if "error" in result:
        print(f"Error: {result['error']}")
        return
    
    if result["host_status"] == "down":
        print("Note: Host seems down. If you know it's up, try -Pn option")
        return
    
    print(f"Scanned {result['ports_scanned']} ports in {result['scan_duration']:.2f} seconds")
    
    if result["open_ports"]:
        print("\nPORT     STATE    SERVICE        VERSION")
        for port_info in result["open_ports"]:
            state = port_info["state"].ljust(7)
            service = port_info.get("service", "unknown").ljust(12)
            version = port_info.get("version", "")
            print(f"{port_info['port']}/{port_info['protocol']:<5} {state} {service} {version}")
    else:
        print("\nNo open ports found")
    
    if 'os_guesses' in result:
        print("\nOS detection:")
        for os_guess in result["os_guesses"]:
            print(f"{os_guess['name']} (accuracy: {os_guess['accuracy']}%)")
    
    if 'scripts' in result:
        print("\nNSE Script Results:")
        for script in result['scripts']:
            print(f"| {script['id']}:")
            print(f"|   {script['output']}")

def _scan_single_target(
    original_target: str,
    resolved_ip: str,
    port_range: str,
    scan_type: str,
    timing_template: str,
    os_detection: bool,
    service_detection: bool,
    script_scan: bool,
    host_timeout: float,
    custom_args: str = ""
) -> Dict[str, Union[str, List[dict]]]:
    """Perform a single target scan with comprehensive Nmap options"""
    result = {
        "target": original_target,
        "resolved_ip": resolved_ip,
        "host_status": "down",
        "ports_scanned": 0,
        "open_ports": [],
        "services": [],
        "scan_duration": 0.0
    }
    
    start_time = time.time()
    
    try:
        scan_args = _build_scan_args(
            scan_type,
            timing_template,
            os_detection,
            service_detection,
            script_scan,
            host_timeout,
            custom_args
        )
        
        nm = nmap.PortScanner()
        recon_logger.debug(f"Scanning {original_target} ({resolved_ip}) with args: {scan_args}")
        
        scan_result = nm.scan(resolved_ip, port_range, arguments=scan_args)
        
        # Look for results using resolved IP
        if resolved_ip not in scan_result['scan']:
            recon_logger.info(f"Host {original_target} ({resolved_ip}) not in scan results")
            return result
        
        host_result = scan_result['scan'][resolved_ip]
        result["ports_scanned"] = int(host_result.get("nmap", {}).get("scanstats", {}).get("totalports", 0))
        
        if host_result['status']['state'] != "up":
            recon_logger.info(f"Host {original_target} ({resolved_ip}) is down")
            return result
        
        result["host_status"] = "up"
        
        # Process open ports
        for proto in ['tcp', 'udp']:
            if proto in host_result:
                for port, port_data in host_result[proto].items():
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                        "cpe": port_data.get("cpe", ""),
                        "reason": port_data.get("reason", ""),
                        "conf": port_data.get("conf", "")
                    }
                    if port_data["state"] == "open":
                        result["open_ports"].append(port_info)
                    result["services"].append(port_info)
        
        result["open_ports"] = sorted(result["open_ports"], key=lambda x: x["port"])
        recon_logger.info(f"Found {len(result['open_ports'])} open ports on {original_target}")
        
        # Add OS detection if available
        if 'osmatch' in host_result:
            result["os_guesses"] = []
            for os in host_result["osmatch"]:
                os_info = {
                    "name": os["name"],
                    "accuracy": os["accuracy"],
                    "osclass": [{
                        "type": oc["type"],
                        "vendor": oc["vendor"],
                        "osfamily": oc["osfamily"],
                        "osgen": oc["osgen"],
                        "accuracy": oc["accuracy"]
                    } for oc in os.get("osclass", [])]
                }
                result["os_guesses"].append(os_info)
        
        # Add script results if available
        if 'hostscript' in host_result:
            result["scripts"] = []
            for script in host_result['hostscript']:
                result["scripts"].append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                    "elements": script.get("elements", {})
                })
    
    except nmap.PortScannerError as e:
        error_msg = f"Nmap error: {str(e)}"
        recon_logger.error(f"Nmap error for {original_target} ({resolved_ip}): {error_msg}")
        result["error"] = error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        recon_logger.exception(f"Error scanning {original_target} ({resolved_ip})")
        result["error"] = error_msg
    
    result["scan_duration"] = time.time() - start_time
    return result

def _build_scan_args(
    scan_type: str,
    timing_template: str,
    os_detection: bool,
    service_detection: bool,
    script_scan: bool,
    host_timeout: float,
    custom_args: str
) -> str:
    """Build comprehensive Nmap arguments based on scan options"""
    if custom_args:
        return custom_args
    
    base_args = [
        f"-T{timing_template}",
        "--open",
        "-Pn",
        f"--host-timeout {host_timeout}s",
        "--min-rate 100",
        "--max-retries 2"
    ]
    
    # Scan type arguments
    scan_types = {
        "syn": "-sS",
        "connect": "-sT",
        "udp": "-sU",
        "all": "-sS -sU",
        "ack": "-sA",
        "window": "-sW"
    }
    base_args.append(scan_types.get(scan_type.lower(), "-sS"))
    
    # Service/version detection
    if service_detection:
        base_args.append("-sV --version-light")
    
    # OS detection
    if os_detection:
        base_args.append("-O --osscan-limit")
    
    # Script scanning
    if script_scan:
        base_args.append("--script=default,safe")
    
    return " ".join(base_args)

def port_scan_help() -> str:
    """Return detailed usage instructions for port_scan function"""
    help_text = """
    ===== Nmap-style Port Scanner =====
    
    Features:
    - Multiple target specification (IPs, hostnames, CIDR ranges)
    - Various scan techniques (SYN, Connect, UDP, etc.)
    - Port selection profiles (quick, smart, full)
    - Adjustable timing templates (T0-T5)
    - OS fingerprinting
    - Service/version detection
    - Script scanning
    - Comprehensive results reporting
    
    Interactive Mode:
      Call port_scan_interactive() for guided scanning
    
    Programmatic Usage:
      results = port_scan(
          target="scanme.nmap.org",  # or list of targets
          ports="22,80,443",         # optional
          mode="smart",              # quick/smart/full
          scan_type="syn",           # syn/connect/udp/all/ack/window
          timing_template="3",       # 0-5 (T0-T5)
          os_detection=False,
          service_detection=True,
          script_scan=False,
          host_timeout=120.0,
          max_threads=1,
          custom_args=""
      )
    
    Scan Techniques:
      1. SYN Scan (-sS): Fast, stealthy, requires root
      2. Connect Scan (-sT): No root, more detectable
      3. UDP Scan (-sU): Slow, requires root
      4. Comprehensive (-sS -sU): Both TCP and UDP
      5. ACK Scan (-sA): Firewall mapping
      6. Window Scan (-sW): Advanced detection
    
    Timing Templates:
      T0: Paranoid (very slow, stealthy)
      T1: Sneaky
      T2: Polite
      T3: Normal (default)
      T4: Aggressive
      T5: Insane (fastest, may miss ports)
    
    Output Includes:
      - Scan metadata and timing
      - Per-target results with:
        * Host status (up/down)
        * Open ports with service info
        * OS detection results
        * Script output
      - Summary statistics
    
    Note: Some scan types require root privileges
    """
    return help_text
