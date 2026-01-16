#!/usr/bin/env python3
import requests
import json
import re
import os
import sys
from colorama import Fore, Style
from urllib.parse import urlparse, urljoin, quote
import hashlib
from datetime import datetime

class ScannerBase:
    """Base class for all scanners"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Pentest-Scanner/2.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        })
        self.timeout = 10
        self.verbose = True
    
    def log(self, message, level="INFO"):
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DEBUG": Fore.MAGENTA
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = colors.get(level, Fore.WHITE)
        print(f"{Fore.WHITE}[{timestamp}] {color}[{level}] {message}{Style.RESET_ALL}")
    
    def make_request(self, url, method="GET", **kwargs):
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, **kwargs)
            elif method.upper() == "POST":
                response = self.session.post(url, timeout=self.timeout, **kwargs)
            elif method.upper() == "PUT":
                response = self.session.put(url, timeout=self.timeout, **kwargs)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, timeout=self.timeout, **kwargs)
            else:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            
            return response
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed: {e}", "ERROR")
            return None
    
    def extract_links(self, html, base_url):
        """Extract links from HTML"""
        links = set()
        patterns = [
            r'href=[\'"]?([^\'" >]+)',
            r'src=[\'"]?([^\'" >]+)',
            r'action=[\'"]?([^\'" >]+)',
        ]
        
        for pattern in patterns:
            found = re.findall(pattern, html, re.IGNORECASE)
            for link in found:
                if link.startswith(('http://', 'https://', '//')):
                    links.add(link)
                elif link.startswith('/'):
                    links.add(urljoin(base_url, link))
                else:
                    links.add(urljoin(base_url, '/' + link))
        
        return list(links)
    
    def is_same_domain(self, url1, url2):
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False

def save_results(results, scanner_name):
    """Save scan results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results/{scanner_name}_{timestamp}.json"
    
    os.makedirs("results", exist_ok=True)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    return filename

def load_payloads(payload_file):
    """Load payloads from file"""
    payloads_dir = "payloads"
    filepath = os.path.join(payloads_dir, payload_file)
    
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    
    return []

def generate_report(vulnerabilities, target):
    """Generate HTML report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Pentest Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .critical {{ color: #ff0000; font-weight: bold; }}
        .high {{ color: #ff6600; }}
        .medium {{ color: #ffcc00; }}
        .low {{ color: #0099ff; }}
        .info {{ color: #666666; }}
        .vuln {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
        .proof {{ background: #f5f5f5; padding: 10px; font-family: monospace; }}
    </style>
</head>
<body>
    <h1>Web Vulnerability Scan Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan Date:</strong> {timestamp}</p>
    <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
    
    <h2>Findings:</h2>
"""
    
    for vuln in vulnerabilities:
        severity_class = vuln.get('severity', 'medium').lower()
        html += f"""
    <div class="vuln">
        <h3 class="{severity_class}">{vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Medium')}</h3>
        <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
        <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
        <p><strong>Proof:</strong></p>
        <div class="proof">{vuln.get('proof', 'N/A')}</div>
    </div>
"""
    
    html += """
</body>
</html>
"""
    
    filename = f"results/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w') as f:
        f.write(html)
    
    return filename
