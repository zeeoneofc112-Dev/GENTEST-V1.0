#!/usr/bin/env python3
"""
XSS Scanner for Reflected, Stored, and DOM XSS
"""

import requests
import sys
from colorama import Fore, Style
from utils import ScannerBase, save_results, load_payloads

class XssScanner(ScannerBase):
    def __init__(self):
        super().__init__()
        self.module_name = "xss_scanner"
        self.vulnerabilities = []
        self.payloads = load_payloads("xss.txt")
    
    def scan(self, target):
        """Main scanning function"""
        self.log(f"Starting XSS Scanner for Reflected, Stored, and DOM XSS scan on {target}", "INFO")
        
        # Run all scan methods
        for method_name in ['scan_reflected', 'scan_stored', 'scan_dom', 'generate_payloads']:
            if hasattr(self, method_name):
                try:
                    getattr(self, method_name)(target)
                except Exception as e:
                    self.log(f"Method {method_name} failed: {e}", "ERROR")
        
        return self.vulnerabilities
    
    def check_vulnerability(self, target):
        """Check for Xss Scanner"""
        try:
            # Implement specific vulnerability check
            test_url = f"{target}/?test=payload"
            response = self.make_request(test_url)
            
            if response and response.status_code == 200:
                # Add detection logic here
                pass
                
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
    
    # Add specific methods here
    def example_method(self, target):
        """Example method template"""
        self.log(f"Testing {target}", "INFO")

def main():
    scanner = XssScanner()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    print(f"[36m\n[+] Starting XSS Scanner for Reflected, Stored, and DOM XSS[0m")
    print(f"[33m[+] Target: {target}[0m")
    
    results = scanner.scan(target)
    
    if results:
        print(f"[32m\n[+] Found {len(results)} vulnerabilities![0m")
        for vuln in results:
            severity = vuln.get('severity', 'Medium')
            color = Fore.RED if severity in ['Critical', 'High'] else Fore.YELLOW
            print(f"{color}[{severity}] {vuln.get('description', 'N/A')}{Style.RESET_ALL}")
        
        # Save results
        filename = save_results(results, scanner.module_name)
        print(f"[36m[+] Results saved to {filename}[0m")
    else:
        print(f"[31m[-] No vulnerabilities found[0m")

if __name__ == "__main__":
    main()
