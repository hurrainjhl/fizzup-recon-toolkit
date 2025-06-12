# modules/active/tech_detect.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import dns.resolver
import time
import subprocess
import logging
from urllib.parse import urlparse, urljoin
from typing import Optional
from bs4 import BeautifulSoup
from packaging import version

# Logger fallback
try:
    from utils.logger import recon_logger
except ImportError:
    recon_logger = logging.getLogger("recon")
    recon_logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    recon_logger.addHandler(handler)

# Cache fallback
try:
    from utils.cache import CacheManager
except ImportError:
    class CacheManager:
        def __init__(self, default_ttl: int = 3600):
            self.store = {}
        def get(self, key): return self.store.get(key)
        def set(self, key, value): self.store[key] = value
        def clear(self): self.store = {}

CONFIG = {
    "CACHE_TTL": 3600,
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconTool/3.0",
    "REQUEST_TIMEOUT": 15,
    "MAX_REDIRECTS": 5,
    "RETRIES": 3,
    "BACKOFF_FACTOR": 0.5,
    "RETRY_STATUS": [500, 502, 503, 504, 429],
    "ALLOWED_METHODS": ["GET", "HEAD"],
    "CRAWL_DELAY": 0.5
}

class TechnologyDetector:
    @staticmethod
    def detect_technology(url: str, depth: int = 1) -> dict:
        """Main technology detection function - maintains same interface"""
        detector = TechnologyDetector.__Detector()
        return detector._detect(url, depth)
    
    class __Detector:
        """Internal implementation class"""
        def __init__(self):
            self.cache = CacheManager(default_ttl=CONFIG["CACHE_TTL"])
            self.signature_db = self._load_signatures()

        def _create_session(self) -> requests.Session:
            session = requests.Session()
            session.headers.update({"User-Agent": CONFIG["USER_AGENT"]})
            session.max_redirects = CONFIG["MAX_REDIRECTS"]
            
            retry_strategy = Retry(
                total=CONFIG["RETRIES"],
                backoff_factor=CONFIG["BACKOFF_FACTOR"],
                status_forcelist=CONFIG["RETRY_STATUS"],
                allowed_methods=CONFIG["ALLOWED_METHODS"]
            )
            
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            return session

        def _fetch_url(self, session: requests.Session, url: str) -> Optional[requests.Response]:
            try:
                response = session.get(
                    url, 
                    timeout=CONFIG["REQUEST_TIMEOUT"],
                    allow_redirects=True,
                    verify=True
                )
                return response
            except requests.exceptions.SSLError:
                recon_logger.warning(f"SSL verification failed for {url}. Trying without verification...")
                try:
                    response = session.get(
                        url, 
                        timeout=CONFIG["REQUEST_TIMEOUT"],
                        allow_redirects=True,
                        verify=False
                    )
                    return response
                except requests.exceptions.RequestException as e:
                    recon_logger.error(f"Request failed even without SSL verification: {e}")
                    return None
            except requests.exceptions.RequestException as e:
                recon_logger.warning(f"Request failed for {url}: {e}")
                return None
            except Exception as e:
                recon_logger.error(f"Unexpected error fetching {url}: {e}")
                return None

        def _enhanced_detect(self, html: str, headers: dict, cookies: dict, url: str) -> dict:
            """Detect technologies using multiple signatures"""
            results = {}

            # HTML content analysis
            for category, signatures in self.signature_db.items():
                for pattern, tech in signatures.items():
                    if re.search(pattern, html, re.IGNORECASE):
                        results[tech] = {
                            "confidence": 85,
                            "source": "html",
                            "category": category
                        }

            # Header analysis
            server_header = headers.get("Server", "")
            x_powered_by = headers.get("X-Powered-By", "")

            for pattern, tech in self.signature_db["server_headers"].items():
                if re.search(pattern, server_header, re.IGNORECASE):
                    results[tech] = {
                        "confidence": 95,
                        "source": "server_header",
                        "category": "server"
                    }

            for pattern, tech in self.signature_db["x_powered_by"].items():
                if re.search(pattern, x_powered_by, re.IGNORECASE):
                    results[tech] = {
                        "confidence": 90,
                        "source": "x_powered_by",
                        "category": "framework"
                    }

            # Cookie analysis
            for pattern, tech in self.signature_db["cookies"].items():
                for cookie in cookies:
                    if re.search(pattern, cookie, re.IGNORECASE):
                        results[tech] = {
                            "confidence": 80,
                            "source": "cookie",
                            "category": "platform"
                        }

            return results

        def _security_analysis(self, headers: dict, cookies: dict) -> dict:
            """Analyze security headers and cookie settings"""
            security = {
                "headers": {},
                "cookies": {},
                "vulnerabilities": []
            }

            # Security headers check
            security_headers = {
                "Content-Security-Policy": "Missing",
                "X-Content-Type-Options": "Missing",
                "X-Frame-Options": "Missing",
                "Strict-Transport-Security": "Missing",
                "X-XSS-Protection": "Missing",
                "Referrer-Policy": "Missing"
            }

            for header in security_headers:
                if header in headers:
                    security_headers[header] = "Present"
                    security["headers"][header] = headers[header]

            # Cookie security attributes
            secure_cookies = 0
            http_only_cookies = 0
            samesite_none = 0

            for name, value in cookies.items():
                cookie_str = f"{name}={value}"
                if "__Secure-" in name or "__Host-" in name:
                    secure_cookies += 1
                if "HttpOnly" in cookie_str:
                    http_only_cookies += 1
                if "SameSite=None" in cookie_str:
                    samesite_none += 1

            security["cookies"] = {
                "total": len(cookies),
                "secure": secure_cookies,
                "http_only": http_only_cookies,
                "samesite_none": samesite_none
            }

            # Vulnerability indicators
            if "Server" in headers and "Apache" in headers["Server"]:
                if "2.4.49" in headers["Server"] or "2.4.50" in headers["Server"]:
                    security["vulnerabilities"].append("Apache Path Traversal (CVE-2021-41773)")
            
            if "X-Powered-By" in headers and "PHP" in headers["X-Powered-By"]:
                match = re.search(r"PHP/(\d+\.\d+\.\d+)", headers["X-Powered-By"])
                if match and version.parse(match.group(1)) < version.parse("8.0.0"):
                    security["vulnerabilities"].append("Outdated PHP version")

            return security

        def _dns_analysis(self, domain: str) -> dict:
            """Robust DNS analysis with multiple resolvers"""
            # Skip DNS for local domains
            if domain in ["localhost", "127.0.0.1"]:
                return {"local_domain": True}
            
            dns_results = {}
            resolvers = [
                ['1.1.1.1', '1.0.0.1'],    # Cloudflare DNS (more reliable)
                ['8.8.8.8', '8.8.4.4'],     # Google DNS
                ['9.9.9.9', '149.112.112.112']  # Quad9 DNS
            ]
            
            record_types = ['A', 'MX', 'TXT', 'CNAME', 'NS']
            
            for resolver_ips in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = resolver_ips
                    resolver.timeout = 3  # Reduced timeout
                    resolver.lifetime = 6  # Reduced total time
                    
                    for rtype in record_types:
                        try:
                            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                            records = []
                            
                            for rdata in answers:
                                if rtype == 'TXT':
                                    records.append(rdata.to_text().strip('"'))
                                else:
                                    records.append(str(rdata))
                            
                            if records:
                                dns_results[f"{rtype.lower()}_records"] = records
                                
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            continue
                        except dns.exception.Timeout:
                            recon_logger.debug(f"DNS query for {rtype} records timed out")
                            continue
                
                except Exception as e:
                    recon_logger.debug(f"DNS resolver {resolver_ips} failed: {e}")
                    continue
                
                # If we got any records, use these results
                if dns_results:
                    break
            
            # Service detection
            mx_records = dns_results.get('mx_records', [])
            txt_records = dns_results.get('txt_records', [])
            
            if any("google" in mx.lower() for mx in mx_records):
                dns_results['email_service'] = "Google Workspace"
            if any("protection.outlook.com" in txt.lower() for txt in txt_records):
                dns_results['email_service'] = "Microsoft 365"
            if any("cloudflare" in txt.lower() for txt in txt_records):
                dns_results['proxy_service'] = "Cloudflare"
            if any("amazonses.com" in txt.lower() for txt in txt_records):
                dns_results['email_service'] = "Amazon SES"
                
            # CDN detection
            cname_records = dns_results.get('cname_records', [])
            if any("cloudflare" in cname.lower() for cname in cname_records):
                dns_results['cdn'] = "Cloudflare"
            if any("akamai" in cname.lower() for cname in cname_records):
                dns_results['cdn'] = "Akamai"
            if any("awsdns" in cname.lower() for cname in cname_records):
                dns_results['cdn'] = "Amazon CloudFront"

            return dns_results

        def _consolidate_results(self, method_results: dict) -> dict:
            """Combine detection results from multiple methods"""
            consolidated = {}
            confidence_map = {
                "server_header": 95,
                "x_powered_by": 90,
                "html": 85,
                "cookie": 80
            }
            
            for method, results in method_results.items():
                for tech, info in results.items():
                    base_confidence = confidence_map.get(info.get("source", method), 75)
                    
                    if tech not in consolidated:
                        consolidated[tech] = {
                            "confidence": base_confidence,
                            "sources": [info.get("source", method)],
                            "categories": [info.get("category", "unknown")]
                        }
                    else:
                        # Increase confidence for multiple detections
                        consolidated[tech]["confidence"] = min(100, consolidated[tech]["confidence"] + 5)
                        consolidated[tech]["sources"].append(info.get("source", method))
                        
                        # Add new category if different
                        new_category = info.get("category", "unknown")
                        if new_category not in consolidated[tech]["categories"]:
                            consolidated[tech]["categories"].append(new_category)
            
            return consolidated

        def _security_scoring(self, security_data: dict) -> dict:
            """Calculate security score based on headers and cookies"""
            if not security_data:
                return {"score": 0}
            
            score = 50
            headers = security_data.get("headers", {})
            cookies = security_data.get("cookies", {})
            
            # Header scoring
            header_points = {
                "Content-Security-Policy": 15,
                "Strict-Transport-Security": 15,
                "X-Content-Type-Options": 10,
                "X-Frame-Options": 10,
                "Referrer-Policy": 5,
                "X-XSS-Protection": 5
            }
            
            for header, points in header_points.items():
                if header in headers:
                    score += points
                    
            # Cookie scoring
            total_cookies = cookies.get("total", 0)
            if total_cookies > 0:
                secure_ratio = cookies.get("secure", 0) / total_cookies
                http_only_ratio = cookies.get("http_only", 0) / total_cookies
                
                if secure_ratio == 1.0:
                    score += 15
                elif secure_ratio >= 0.8:
                    score += 10
                elif secure_ratio >= 0.5:
                    score += 5
                    
                if http_only_ratio == 1.0:
                    score += 10
                elif http_only_ratio >= 0.8:
                    score += 7
                elif http_only_ratio >= 0.5:
                    score += 3
                    
                if cookies.get("samesite_none", 0) > 0:
                    score -= 10
            
            # Vulnerability penalties
            vuln_count = len(security_data.get("vulnerabilities", []))
            score -= min(30, vuln_count * 10)
            
            return {
                "score": max(0, min(100, score)),
                "details": security_data
            }

        def _whatweb_detect(self, domain: str) -> dict:
            """Fallback detection using whatweb command-line tool"""
            try:
                result = subprocess.check_output(
                    ["whatweb", domain],
                    stderr=subprocess.DEVNULL,
                    timeout=30
                ).decode().strip()
                
                # Parse whatweb output
                technologies = []
                if "[" in result and "]" in result:
                    # Extract technologies between first brackets
                    tech_part = result.split("[", 1)[1].split("]", 1)[0]
                    technologies = [t.strip() for t in tech_part.split(",") if t.strip()]
                
                # Format results
                whatweb_results = {}
                for tech in technologies:
                    whatweb_results[tech] = {
                        "confidence": 80,
                        "source": "whatweb",
                        "category": "unknown"
                    }
                return whatweb_results
            except subprocess.TimeoutExpired:
                recon_logger.warning("whatweb detection timed out after 30 seconds")
                return {}
            except Exception as e:
                recon_logger.error(f"whatweb detection failed: {e}")
                return {}

        def _load_signatures(self) -> dict:
            """Load detection signatures"""
            return {
                "html": {
                    r"wp-content": "WordPress",
                    r"drupal-settings-json": "Drupal",
                    r"Joomla!": "Joomla",
                    r"laravel": "Laravel",
                    r"react\.js": "React",
                    r"vue\.js": "Vue.js",
                    r"angular\.js": "AngularJS",
                    r"bootstrap": "Bootstrap",
                    r"jquery": "jQuery",
                    r"next\.js": "Next.js",
                    r"nuxt\.js": "Nuxt.js"
                },
                "server_headers": {
                    r"cloudflare": "Cloudflare",
                    r"aws": "Amazon Web Services",
                    r"nginx": "Nginx",
                    r"apache": "Apache",
                    r"iis": "Microsoft IIS",
                    r"cloudfront": "Amazon CloudFront"
                },
                "x_powered_by": {
                    r"PHP": "PHP",
                    r"ASP\.NET": "ASP.NET",
                    r"Express": "Express.js",
                    r"WordPress": "WordPress",
                    r"Drupal": "Drupal"
                },
                "cookies": {
                    r"wordpress_logged_in": "WordPress",
                    r"drupal_uid": "Drupal",
                    r"joomla": "Joomla",
                    r"laravel_session": "Laravel",
                    r"csrftoken": "Django",
                    r"express.sid": "Express.js",
                    r"symfony": "Symfony"
                }
            }

        def _crawl_analysis(self, session: requests.Session, base_url: str, depth: int = 1, max_pages: int = 10) -> dict:
            """Crawl website to detect technologies on multiple pages"""
            visited = set()
            to_visit = [(base_url, 0)]
            results = {}
            base_domain = urlparse(base_url).netloc
            
            while to_visit and len(visited) < max_pages:
                current_url, current_depth = to_visit.pop(0)
                
                if current_url in visited or current_depth > depth:
                    continue
                visited.add(current_url)
                
                response = self._fetch_url(session, current_url)
                if not response or not response.ok:
                    continue
                    
                page_html = response.text
                headers = response.headers
                cookies = {**session.cookies.get_dict(), **response.cookies.get_dict()}
                
                detected = self._enhanced_detect(page_html, headers, cookies, current_url)
                if detected:
                    results[current_url] = detected
                    
                # Parse and collect internal links
                if current_depth < depth:
                    soup = BeautifulSoup(page_html, 'html.parser')
                    for tag in soup.find_all('a', href=True):
                        href = tag.get('href')
                        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                            continue
                        
                        try:
                            link = urljoin(current_url, href)
                            parsed_link = urlparse(link)
                            
                            # Normalize URL
                            link = parsed_link.scheme + "://" + parsed_link.netloc + parsed_link.path
                            if parsed_link.query:
                                link += "?" + parsed_link.query
                                
                            if parsed_link.netloc == base_domain and link not in visited:
                                to_visit.append((link, current_depth + 1))
                        except Exception as e:
                            recon_logger.warning(f"Error processing link {href}: {e}")
                
                # Polite crawling delay
                time.sleep(CONFIG["CRAWL_DELAY"])
                
            return results

        def _detect(self, url: str, depth: int) -> dict:
            """Internal detection implementation"""
            session = self._create_session()
            parsed = urlparse(url)
            
            if not parsed.scheme:
                url = "http://" + url
            elif parsed.scheme not in ["http", "https"]:
                url = "https://" + parsed.netloc + parsed.path

            domain = parsed.netloc
            is_local = domain in ["localhost", "127.0.0.1"]

            # Try HTTP detection first
            response = self._fetch_url(session, url)
            if not response:
                recon_logger.warning("Primary detection methods failed, falling back to whatweb")
                whatweb_results = self._whatweb_detect(domain)
                return {
                    "url": url,
                    "status": "Failed",
                    "technologies": whatweb_results,
                    "stats": {"technologies_count": len(whatweb_results)},
                    "security": {"score": 0},
                    "dns": {"local_domain": is_local},
                    "crawled": {},
                    "headers": {},
                    "cookies": {}
                }

            html = response.text
            headers = response.headers
            cookies = session.cookies.get_dict()

            # Run detection methods
            enhanced_results = self._enhanced_detect(html, headers, cookies, url)
            security_data = self._security_analysis(headers, cookies)
            crawl_results = self._crawl_analysis(session, url, depth)
            dns_info = {"local_domain": is_local} if is_local else self._dns_analysis(domain)
            
            # Consolidate results
            consolidated = self._consolidate_results({"enhanced": enhanced_results})
            tech_count = len(consolidated)

            # Fallback to whatweb if no technologies detected
            if not consolidated:
                recon_logger.warning("No technologies detected, falling back to whatweb")
                whatweb_results = self._whatweb_detect(domain)
                if whatweb_results:
                    consolidated = whatweb_results
                    tech_count = len(whatweb_results)

            return {
                "url": url,
                "status": response.status_code,
                "technologies": consolidated,
                "stats": {"technologies_count": tech_count},
                "security": self._security_scoring(security_data),
                "dns": dns_info,
                "crawled": crawl_results,
                "headers": dict(headers),
                "cookies": cookies
            }
