import os
import base64
import json
import re
from datetime import datetime
from pathlib import Path
from utils.visualizer import DataVisualizer

class ReportGenerator:
    """Generates professional HTML reports from reconnaissance data"""
    
    def __init__(self, results: dict, output_file: str = "recon_report.html"):
        self.results = results
        self.output_file = output_file
        self.visualizer = DataVisualizer()
        self.report_content = []
        self.css = self._get_css()
        self.js = self._get_js()
        
    def generate_report(self):
        """Generate and save the HTML report in reports directory"""
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Ensure filename has .html extension
        if not self.output_file.endswith(".html"):
            self.output_file += ".html"
        
        # Prepend reports directory to path if not absolute
        if not Path(self.output_file).is_absolute():
            self.output_file = reports_dir / self.output_file
        
        self._build_html_head()
        self._build_header()
        self._build_summary_section()
        
        # Passive Recon Sections
        if self.results.get("passive"):
            self._add_section_title("Passive Reconnaissance Results")
            if "WHOIS" in self.results["passive"]:
                self._build_whois_section()
            if "DNS" in self.results["passive"]:
                self._build_dns_section()
            if "SUBDOMAINS" in self.results["passive"]:
                self._build_subdomains_section()
        
        # Active Recon Sections
        if self.results.get("active"):
            self._add_section_title("Active Reconnaissance Results")
            if "PORT_SCAN" in self.results["active"]:
                self._build_port_scan_section()
            if "BANNERS" in self.results["active"]:
                self._build_banners_section()
            if "TECH" in self.results["active"]:
                self._build_tech_section()
        
        self._build_footer()
        
        # Save the report
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(self.report_content))
            
        return os.path.abspath(self.output_file)
    
    def _build_html_head(self):
        """Build HTML head with CSS and JS"""
        self.report_content.extend([
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f'<title>Recon Report: {self.results["target"]}</title>',
            '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">',
            f'<style>{self.css}</style>',
            '</head>',
            '<body>',
            f'<script>{self.js}</script>'
        ])
    
    def _build_header(self):
        """Build report header"""
        target = self.results["target"]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.report_content.extend([
            '<header>',
            '<div class="header-content">',
            '<div class="banner">',
            '<h1>UHZ RECONNAISSANCE REPORT</h1>',
            '</div>',
            '<div class="header-info">',
            f'<h2>Target: <span class="highlight">{target}</span></h2>',
            f'<p>Generated on: <span class="highlight">{timestamp}</span></p>',
            '</div>',
            '</div>',
            '</header>',
            '<main class="container">'
        ])
    
    def _build_summary_section(self):
        """Build summary section with key findings"""
        summary = []
        
        # Passive recon summary
        if self.results.get("passive"):
            summary.append('<h3>Passive Recon Summary</h3><ul>')
            if "WHOIS" in self.results["passive"]:
                whois = self.results["passive"]["WHOIS"]
                summary.append(f'<li>Domain registered on: {whois["dates"]["created"]}</li>')
                if whois["dates"].get("expires") and whois["metrics"].get("expiry_days"):
                    summary.append(f'<li>Expires on: {whois["dates"]["expires"]} ({whois["metrics"]["expiry_days"]} days remaining)</li>')
            
            if "DNS" in self.results["passive"]:
                dns = self.results["passive"]["DNS"]
                summary.append(f'<li>{len(dns["records"].get("A", []))} IPv4 records found</li>')
                if dns["security"].get("dnssec"):
                    summary.append(f'<li>DNSSEC: {dns["security"]["dnssec"]}</li>')
            
            if "SUBDOMAINS" in self.results["passive"]:
                subs = self.results["passive"]["SUBDOMAINS"]
                if subs.get("unique_subdomains") is not None:
                    summary.append(f'<li>{subs["unique_subdomains"]} unique subdomains discovered</li>')
            summary.append('</ul>')
        
        # Active recon summary
        if self.results.get("active"):
            summary.append('<h3>Active Recon Summary</h3><ul>')
            if "PORT_SCAN" in self.results["active"]:
                ports = self.results["active"]["PORT_SCAN"]
                if ports["stats"].get("open_ports") is not None:
                    summary.append(f'<li>{ports["stats"]["open_ports"]} open ports found</li>')
            
            if "BANNERS" in self.results["active"]:
                banners = self.results["active"]["BANNERS"]
                if banners.get("banners") is not None:
                    summary.append(f'<li>{len(banners["banners"])} services identified</li>')
            
            if "TECH" in self.results["active"]:
                tech = self.results["active"]["TECH"]
                if tech["stats"].get("technologies_count") is not None:
                    summary.append(f'<li>{tech["stats"]["technologies_count"]} technologies detected</li>')
            summary.append('</ul>')
        
        if summary:
            self.report_content.extend([
                '<section class="summary">',
                '<h2><i class="fas fa-clipboard-list"></i> Executive Summary</h2>',
                '<div class="summary-content">',
                *summary,
                '</div>',
                '</section>'
            ])
    
    def _build_whois_section(self):
        """Build WHOIS section"""
        whois = self.results["passive"]["WHOIS"]
        contacts = []
        
        for contact_type, details in whois.get("contacts", {}).items():
            contacts.append(f'<h3>{contact_type.capitalize()} Contact</h3>')
            contacts.append('<table class="contact-table">')
            for field, value in details.items():
                if field != "privacy_proxy" and value:
                    contacts.append(f'<tr><th>{field.capitalize()}</th><td>{value}</td></tr>')
            contacts.append('</table>')
        
        # Create timeline chart if dates available
        timeline_img = ""
        if whois.get("dates"):
            dates = {
                "Created": whois["dates"].get("created", ""),
                "Updated": whois["dates"].get("updated", ""),
                "Expires": whois["dates"].get("expires", "")
            }
            # Filter out empty dates
            valid_dates = {k: v for k, v in dates.items() if v}
            if valid_dates:
                timeline_chart = self.visualizer.generate_bar_chart(
                    valid_dates,
                    "Domain Timeline",
                    "Event",
                    "Date"
                )
                timeline_img = self.visualizer.figure_to_base64(timeline_chart)
        
        self.report_content.extend([
            '<section class="whois">',
            '<h2><i class="fas fa-globe"></i> WHOIS Information</h2>',
            '<div class="grid-container">',
            '<div class="details">',
            '<h3>Domain Details</h3>',
            '<table>'
        ])
        
        # Add registrar info if available
        if whois.get("registrar"):
            self.report_content.append(f'<tr><th>Registrar</th><td>{whois["registrar"].get("name", "N/A")}</td></tr>')
            self.report_content.append(f'<tr><th>IANA ID</th><td>{whois["registrar"].get("iana_id", "N/A")}</td></tr>')
        
        # Add dates
        if whois.get("dates"):
            self.report_content.extend([
                f'<tr><th>Created</th><td>{whois["dates"].get("created", "N/A")}</td></tr>',
                f'<tr><th>Updated</th><td>{whois["dates"].get("updated", "N/A")}</td></tr>',
                f'<tr><th>Expires</th><td>{whois["dates"].get("expires", "N/A")}'
            ])
            
            # Add expiry days if available
            if whois.get("metrics") and whois["metrics"].get("expiry_days") is not None:
                self.report_content.append(f' ({whois["metrics"]["expiry_days"]} days)</td></tr>')
            else:
                self.report_content.append('</td></tr>')
        
        # Add security info
        if whois.get("security"):
            self.report_content.extend([
                f'<tr><th>DNSSEC</th><td>{whois["security"].get("dnssec", "N/A")}</td></tr>',
                f'<tr><th>Privacy Protection</th><td>{whois["security"].get("privacy_service", "None")}</td></tr>'
            ])
        
        self.report_content.extend([
            '</table>',
            '<h3>Name Servers</h3>',
            '<ul>'
        ])
        
        # Add name servers
        if whois.get("name_servers"):
            self.report_content.extend([f'<li>{ns}</li>' for ns in whois["name_servers"]])
        else:
            self.report_content.append('<li>No name servers found</li>')
            
        self.report_content.extend([
            '</ul>',
            '</div>',
            '<div class="contacts">',
            *contacts,
            '</div>',
            '</div>'
        ])
        
        # Add timeline chart if available
        if timeline_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{timeline_img}" alt="Domain Timeline">',
                '</div>'
            ])
            
        self.report_content.append('</section>')
    
    def _build_dns_section(self):
        """Build DNS section with records and charts"""
        dns = self.results["passive"]["DNS"]
        
        # Prepare record tables
        record_tables = []
        for rtype, records in dns.get("records", {}).items():
            if records:
                record_tables.append(f'<h3>{rtype} Records</h3>')
                record_tables.append('<table class="record-table">')
                
                # Handle special record types
                if rtype == "MX":
                    record_tables.append('<tr><th>Preference</th><th>Exchange</th></tr>')
                    for record in records:
                        if isinstance(record, dict):
                            record_tables.append(f'<tr><td>{record.get("preference", "")}</td><td>{record.get("exchange", "")}</td></tr>')
                        else:
                            record_tables.append(f'<tr><td colspan="2">{record}</td></tr>')
                elif rtype == "SOA":
                    record_tables.append('<tr><th>MName</th><th>RName</th><th>Serial</th><th>Refresh</th><th>Retry</th><th>Expire</th><th>Minimum</th></tr>')
                    for record in records:
                        if isinstance(record, dict):
                            record_tables.append(
                                f'<tr><td>{record.get("mname", "")}</td><td>{record.get("rname", "")}</td>'
                                f'<td>{record.get("serial", "")}</td><td>{record.get("refresh", "")}</td>'
                                f'<td>{record.get("retry", "")}</td><td>{record.get("expire", "")}</td>'
                                f'<td>{record.get("minimum", "")}</td></tr>'
                            )
                        else:
                            record_tables.append(f'<tr><td colspan="7">{record}</td></tr>')
                else:
                    record_tables.append('<tr><th>Value</th></tr>')
                    for record in records:
                        record_tables.append(f'<tr><td>{record}</td></tr>')
                
                record_tables.append('</table>')
        
        # Create record type distribution chart if records available
        record_img = ""
        if dns.get("records"):
            record_counts = {rtype: len(recs) for rtype, recs in dns["records"].items() if recs}
            if record_counts:
                record_chart = self.visualizer.generate_bar_chart(
                    record_counts,
                    "Record Type Distribution",
                    "Record Type",
                    "Count"
                )
                record_img = self.visualizer.figure_to_base64(record_chart)
        
        # Security findings
        security_findings = []
        if dns.get("security"):
            if "dnssec" in dns["security"]:
                security_findings.append(f'<li><strong>DNSSEC:</strong> {dns["security"]["dnssec"]}</li>')
            if "zone_transfer_vulnerable" in dns["security"]:
                security_findings.append(f'<li><strong>Zone Transfer Vulnerable:</strong> {dns["security"]["zone_transfer_vulnerable"]}</li>')
        
        if dns.get("cloud"):
            cloud_services = ", ".join(dns["cloud"].keys())
            security_findings.append(f'<li><strong>Cloud Services:</strong> {cloud_services}</li>')
        
        self.report_content.extend([
            '<section class="dns">',
            '<h2><i class="fas fa-server"></i> DNS Enumeration</h2>',
            '<div class="dns-content">',
            *record_tables,
            '</div>'
        ])
        
        if record_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{record_img}" alt="Record Type Distribution">',
                '</div>'
            ])
        
        if security_findings:
            self.report_content.extend([
                '<div class="security">',
                '<h3>Security Findings</h3>',
                '<ul>',
                *security_findings,
                '</ul>',
                '</div>'
            ])
            
        self.report_content.append('</section>')
    
    def _build_subdomains_section(self):
        """Build subdomains section with tables and charts"""
        subs = self.results["passive"]["SUBDOMAINS"]
        
        # Create source distribution chart if stats available
        source_img = ""
        if subs.get("source_stats"):
            source_chart = self.visualizer.generate_pie_chart(
                dict(subs["source_stats"]),
                "Discovery Sources"
            )
            source_img = self.visualizer.figure_to_base64(source_chart)
        
        # Prepare subdomain tables
        sub_tables = []
        if subs.get("subdomains"):
            for source, subdomains in subs["subdomains"].items():
                if subdomains:
                    sub_tables.append(f'<h3>{source.capitalize()} ({len(subdomains)} subdomains)</h3>')
                    sub_tables.append('<table class="subdomain-table">')
                    sub_tables.append('<tr><th>Subdomain</th></tr>')
                    for sub in subdomains:
                        sub_tables.append(f'<tr><td>{sub}</td></tr>')
                    sub_tables.append('</table>')
        
        self.report_content.extend([
            '<section class="subdomains">',
            '<h2><i class="fas fa-sitemap"></i> Subdomain Discovery</h2>',
            '<div class="stats">'
        ])
        
        if subs.get("unique_subdomains") is not None:
            self.report_content.append(f'<p><strong>Total Subdomains:</strong> {subs["unique_subdomains"]}</p>')
        if "wildcard" in subs.get("validation", {}):
            self.report_content.append(f'<p><strong>Wildcard DNS:</strong> {subs["validation"]["wildcard"]}</p>')
        
        self.report_content.append('</div>')
        
        if source_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{source_img}" alt="Discovery Sources">',
                '</div>'
            ])
        
        if sub_tables:
            self.report_content.extend([
                '<div class="subdomain-lists">',
                *sub_tables,
                '</div>'
            ])
        else:
            self.report_content.append('<p>No subdomains found</p>')
            
        self.report_content.append('</section>')
    
    def _build_port_scan_section(self):
        """Build port scan section with visualizations"""
        ports = self.results["active"]["PORT_SCAN"]
        
        # Prepare port table
        port_table = ['<table class="port-table">']
        port_table.append('<tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Product</th></tr>')
        
        if ports.get("results"):
            for host, data in ports["results"].items():
                if data.get("services"):
                    for service in data["services"]:
                        port_table.append(
                            f'<tr><td>{service.get("port", "")}</td><td>{service.get("protocol", "")}</td>'
                            f'<td>{service.get("service", "")}</td><td>{service.get("version", "")}</td>'
                            f'<td>{service.get("product", "")}</td></tr>'
                        )
        port_table.append('</table>')
        
        # Create port distribution chart
        port_img = ""
        service_img = ""
        
        if ports.get("results"):
            port_counts = {}
            service_counts = {}
            
            for host, data in ports["results"].items():
                if data.get("services"):
                    for service in data["services"]:
                        port = service.get("port", "")
                        svc = service.get("service", "")
                        
                        if port:
                            port_counts[port] = port_counts.get(port, 0) + 1
                        if svc:
                            service_counts[svc] = service_counts.get(svc, 0) + 1
            
            if port_counts:
                port_chart = self.visualizer.generate_bar_chart(
                    port_counts,
                    "Open Port Distribution",
                    "Port Number",
                    "Host Count"
                )
                port_img = self.visualizer.figure_to_base64(port_chart)
            
            if service_counts:
                service_chart = self.visualizer.generate_pie_chart(
                    service_counts,
                    "Service Distribution"
                )
                service_img = self.visualizer.figure_to_base64(service_chart)
        
        self.report_content.extend([
            '<section class="port-scan">',
            '<h2><i class="fas fa-plug"></i> Port Scanning Results</h2>',
            '<div class="stats">'
        ])
        
        if ports.get("scan_metadata") and ports["scan_metadata"].get("targets_count") is not None:
            self.report_content.append(f'<p><strong>Targets Scanned:</strong> {ports["scan_metadata"]["targets_count"]}</p>')
        if ports.get("stats") and ports["stats"].get("open_ports") is not None:
            self.report_content.append(f'<p><strong>Open Ports Found:</strong> {ports["stats"]["open_ports"]}</p>')
        if ports.get("stats") and ports["stats"].get("services_found") is not None:
            self.report_content.append(f'<p><strong>Services Found:</strong> {ports["stats"]["services_found"]}</p>')
        
        self.report_content.append('</div>')
        self.report_content.extend(port_table)
        
        if port_img and service_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{port_img}" alt="Open Port Distribution">',
                f'<img src="{service_img}" alt="Service Distribution">',
                '</div>'
            ])
        
        self.report_content.append('</section>')
    
    def _build_banners_section(self):
        """Build banners section with service details"""
        banners = self.results["active"]["BANNERS"]
        
        # Prepare banner table
        banner_table = ['<table class="banner-table">']
        banner_table.append('<tr><th>Port</th><th>Service</th><th>Banner</th><th>Vulnerabilities</th></tr>')
        
        if banners.get("banners"):
            for banner in banners["banners"]:
                vulns = ", ".join(banner.get("vulnerabilities", [])) or "None"
                banner_table.append(
                    f'<tr><td>{banner.get("port", "")}</td><td>{banner.get("service", "")}</td>'
                    f'<td><div class="banner-text">{banner.get("banner", "")}</div></td>'
                    f'<td>{vulns}</td></tr>'
                )
        banner_table.append('</table>')
        
        # Create vulnerability distribution chart
        vuln_img = ""
        if banners.get("banners"):
            vuln_counts = {}
            for banner in banners["banners"]:
                for vuln in banner.get("vulnerabilities", []):
                    vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
            
            if vuln_counts:
                vuln_chart = self.visualizer.generate_bar_chart(
                    vuln_counts,
                    "Vulnerability Distribution",
                    "Vulnerability Type",
                    "Count"
                )
                vuln_img = self.visualizer.figure_to_base64(vuln_chart)
        
        self.report_content.extend([
            '<section class="banners">',
            '<h2><i class="fas fa-flag"></i> Service Banner Analysis</h2>',
            '<div class="stats">'
        ])
        
        if banners.get("banners") is not None:
            self.report_content.append(f'<p><strong>Services Analyzed:</strong> {len(banners["banners"])}</p>')
        if vuln_counts:
            self.report_content.append(f'<p><strong>Vulnerabilities Found:</strong> {sum(vuln_counts.values())}</p>')
        
        self.report_content.append('</div>')
        self.report_content.extend(banner_table)
        
        if vuln_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{vuln_img}" alt="Vulnerability Distribution">',
                '</div>'
            ])
        
        self.report_content.append('</section>')
    
    def _build_tech_section(self):
        """Build technology detection section"""
        tech = self.results["active"]["TECH"]
        
        # Prepare technology table
        tech_table = ['<table class="tech-table">']
        tech_table.append('<tr><th>Technology</th><th>Confidence</th><th>Version</th><th>Categories</th></tr>')
        
        if tech.get("technologies"):
            for tech_name, details in tech["technologies"].items():
                categories = ", ".join(details.get("categories", []))
                tech_table.append(
                    f'<tr><td>{tech_name}</td><td>{details.get("confidence", "")}%</td>'
                    f'<td>{details.get("version", "N/A")}</td><td>{categories}</td></tr>'
                )
        tech_table.append('</table>')
        
        # Create technology category chart
        category_img = ""
        if tech.get("technologies"):
            category_counts = {}
            for details in tech["technologies"].values():
                for category in details.get("categories", []):
                    category_counts[category] = category_counts.get(category, 0) + 1
            
            if category_counts:
                category_chart = self.visualizer.generate_pie_chart(
                    category_counts,
                    "Technology Categories"
                )
                category_img = self.visualizer.figure_to_base64(category_chart)
        
        self.report_content.extend([
            '<section class="tech">',
            '<h2><i class="fas fa-microchip"></i> Technology Stack</h2>',
            '<div class="stats">'
        ])
        
        if tech.get("stats") and tech["stats"].get("technologies_count") is not None:
            self.report_content.append(f'<p><strong>Technologies Identified:</strong> {tech["stats"]["technologies_count"]}</p>')
        
        self.report_content.append('</div>')
        self.report_content.extend(tech_table)
        
        if category_img:
            self.report_content.extend([
                '<div class="chart-container">',
                f'<img src="{category_img}" alt="Technology Categories">',
                '</div>'
            ])
        
        self.report_content.append('</section>')
    
    def _add_section_title(self, title: str):
        """Add section title with decorative element"""
        self.report_content.extend([
            f'<div class="section-title">',
            f'<h2>{title}</h2>',
            f'<div class="divider"></div>',
            f'</div>'
        ])
    
    def _build_footer(self):
        """Build report footer"""
        self.report_content.extend([
            '</main>',
            '<footer>',
            '<div class="footer-content">',
            f'<p>Report generated by UHZ Reconnaissance Tool on {datetime.now().strftime("%Y-%m-%d")}</p>',
            '<p class="disclaimer">This report contains sensitive security information. Handle with care.</p>',
            '</div>',
            '</footer>',
            '</body>',
            '</html>'
        ])
    
    def _get_css(self):
        """Return CSS styles for the report"""
        return """
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --accent: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
            --success: #2ecc71;
            --warning: #f39c12;
            --danger: #e74c3c;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        header {
            background: linear-gradient(135deg, var(--secondary), var(--dark));
            color: white;
            padding: 2rem 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }
        
        .banner h1 {
            font-size: 2.5rem;
            letter-spacing: 2px;
            text-align: center;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header-info {
            text-align: center;
            margin-top: 1.5rem;
        }
        
        .header-info h2 {
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }
        
        .highlight {
            color: var(--warning);
            font-weight: bold;
        }
        
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        
        section {
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.05);
            padding: 2rem;
            margin-bottom: 2rem;
            transition: transform 0.3s ease;
        }
        
        section:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.1);
        }
        
        h2 {
            color: var(--secondary);
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        h2 i {
            color: var(--primary);
        }
        
        h3 {
            color: var(--dark);
            margin: 1.5rem 0 1rem;
        }
        
        .summary {
            background: linear-gradient(to right, #e3f2fd, #bbdefb);
        }
        
        .summary-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        
        .summary ul {
            padding-left: 1.5rem;
        }
        
        .summary li {
            margin-bottom: 0.5rem;
        }
        
        .grid-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }
        
        @media (max-width: 768px) {
            .grid-container {
                grid-template-columns: 1fr;
            }
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.9rem;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border: 1px solid #ddd;
        }
        
        th {
            background-color: var(--primary);
            color: white;
            font-weight: 600;
        }
        
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        
        .contact-table th {
            background-color: var(--dark);
        }
        
        .record-table th {
            background-color: var(--secondary);
        }
        
        .port-table th {
            background-color: var(--accent);
        }
        
        .banner-table th {
            background-color: #9b59b6;
        }
        
        .tech-table th {
            background-color: #27ae60;
        }
        
        .banner-text {
            max-width: 300px;
            overflow: auto;
            max-height: 100px;
            font-family: monospace;
            font-size: 0.8rem;
            white-space: pre-wrap;
        }
        
        .chart-container {
            margin: 2rem 0;
            text-align: center;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .section-title {
            margin: 3rem 0 2rem;
            text-align: center;
        }
        
        .section-title h2 {
            display: inline-block;
            background: var(--primary);
            color: white;
            padding: 0.5rem 2rem;
            border-radius: 30px;
            border-bottom: none;
        }
        
        .divider {
            height: 3px;
            background: linear-gradient(to right, transparent, var(--primary), transparent);
            margin: 0.5rem auto;
            width: 80%;
        }
        
        .security ul {
            padding-left: 1.5rem;
            margin: 1rem 0;
        }
        
        .security li {
            margin-bottom: 0.5rem;
        }
        
        .subdomain-lists {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .subdomain-table {
            font-size: 0.85rem;
        }
        
        .stats {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border-left: 4px solid var(--primary);
        }
        
        .stats p {
            margin-bottom: 0.5rem;
        }
        
        footer {
            background: var(--dark);
            color: white;
            text-align: center;
            padding: 1.5rem 0;
            margin-top: 3rem;
        }
        
        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }
        
        .disclaimer {
            margin-top: 1rem;
            font-style: italic;
            color: #bbb;
            font-size: 0.9rem;
        }
        """
    
    def _get_js(self):
        """Return JavaScript for interactive elements"""
        return """
        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
        
        // Print functionality
        document.getElementById('print-btn').addEventListener('click', () => {
            window.print();
        });
        
        // Collapsible sections
        document.querySelectorAll('section h2').forEach(header => {
            header.addEventListener('click', () => {
                const section = header.parentElement;
                section.classList.toggle('collapsed');
            });
        });
        """

def generate_report(results: dict, output_file: str = "recon_report.html"):
    """
    Generate and save an HTML report from recon results
    Reports are saved in the reports/ directory by default
    """
    generator = ReportGenerator(results, output_file)
    return generator.generate_report()

# Example usage
if __name__ == "__main__":
    # Sample data structure for testing
    sample_results = {
        "target": "example.com",
        "passive": {
            "WHOIS": {
                "domain": "example.com",
                "dates": {
                    "created": "1995-08-14",
                    "expires": "2024-08-13",
                    "updated": "2023-08-14",
                    "age_days": 10345
                },
                "registrar": {
                    "name": "RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY",
                    "iana_id": "376",
                    "url": "http://res-dom.iana.org"
                },
                "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
                "contacts": {
                    "registrant": {
                        "name": "REDACTED FOR PRIVACY",
                        "organization": "REDACTED FOR PRIVACY",
                        "email": "REDACTED FOR PRIVACY",
                        "phone": "REDACTED FOR PRIVACY",
                        "address": "REDACTED FOR PRIVACY",
                        "privacy_proxy": True
                    }
                },
                "security": {
                    "dnssec": "unsigned",
                    "privacy_proxy": True,
                    "privacy_service": "Redacted For Privacy"
                },
                "metrics": {
                    "expiry_days": 285,
                    "update_recency": 30
                }
            }
        }
    }
    
    report_path = generate_report(sample_results, "sample_report.html")
    print(f"Report generated at: {report_path}")
