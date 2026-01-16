#!/usr/bin/env python3
"""
Api Scanner
Author: Pentest Framework
"""

import requests
import sys
from colorama import Fore, Style
from utils import ScannerBase, save_results

class ApiScanner(ScannerBase):
    def __init__(self):
        super().__init__()
        self.module_name = "api_scanner"
        self.vulnerabilities = []
    
    def scan(self, target):
        """Main scanning function"""
        print(f"[36m\n[+] Scanning {target} for Api Scanner...[0m")
        
        # Implement scanning logic here
        self.check_vulnerability(target)
        
        return self.vulnerabilities
    
    def check_vulnerability(self, target):
        """Check for specific vulnerability"""
        try:
            # Add your scanning logic
            test_url = f"{target}/test"
            response = requests.get(test_url, timeout=10)
            
            # Example check
            if response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "api_scanner",
                    "url": target,
                    "severity": "Medium",
                    "description": "Potential vulnerability found",
                    "proof": "Response code 200"
                })
                
        except Exception as e:
            print(f"[31m[-] Error: {e}[0m")
    
    def generate_payloads(self):
        """Generate test payloads"""
        payloads = []
        # Add payloads specific to this vulnerability
        return payloads

def main():
    scanner = ApiScanner()
    target = input("Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    results = scanner.scan(target)
    
    if results:
        print(f"[32m\n[+] Found {len(results)} vulnerabilities![0m")
        for vuln in results:
            print(f"[33m- {vuln['description']}[0m")
        
        # Save results
        filename = save_results(results, scanner.module_name)
        print(f"[36m[+] Results saved to {filename}[0m")
    else:
        print(f"[31m[-] No vulnerabilities found[0m")

if __name__ == "__main__":
    main()
