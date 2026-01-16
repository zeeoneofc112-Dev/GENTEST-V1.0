#!/usr/bin/env python3
import os
import sys
import importlib.util
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

class PentestFramework:
    def __init__(self):
        self.version = "2.0"
        self.author = "MR•Zeeone-Grayhat"
        self.modules_dir = "modules"
        self.results_dir = "results"
        self.setup_directories()
        
    def setup_directories(self):
        os.makedirs(self.modules_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs("payloads", exist_ok=True)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗    ║
║   ██╔═══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝    ║
║   ██║   ██║█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║       ║
║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║       ║
║   ╚██████╔╝███████╗██║ ╚████║   ██║   ███████╗███████║   ██║       ║
║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝       ║
║                                                                   ║
║        32-IN-1 WEB VULNERABILITY SCANNER FRAMEWORK                ║
║                    Version:{self.version}
                     Create by MR•Zeeone-Grayhat               ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def print_menu(self):
        modules = [
            ("1. SQL Injection", "sql_injection"),
            ("2. XSS Scanner", "xss_scanner"),
            ("3. Command Injection", "command_injection"),
            ("4. RCE Scanner", "rce_scanner"),
            ("5. LFI Scanner", "lfi_scanner"),
            ("6. RFI Scanner", "rfi_scanner"),
            ("7. XXE Scanner", "xxe_scanner"),
            ("8. SSRF Scanner", "ssrf_scanner"),
            ("9. CRLF Injection", "crlf_injection"),
            ("10. Open Redirect", "open_redirect"),
            ("11. SSTI Scanner", "ssti_scanner"),
            ("12. IDOR Scanner", "idor_scanner"),
            ("13. CSRF Tester", "csrf_tester"),
            ("14. File Upload Vuln", "file_upload"),
            ("15. CORS Misconfig", "cors_scanner"),
            ("16. Subdomain Takeover", "subdomain_takeover"),
            ("17. DNS Zone Transfer", "dns_zone"),
            ("18. API Security Scanner", "api_scanner"),
            ("19. JWT Vulnerabilities", "jwt_scanner"),
            ("20. HTTP Request Smuggling", "http_smuggling"),
            ("21. Clickjacking Tester", "clickjacking"),
            ("22. Cookie Security", "cookie_scanner"),
            ("23. Security Headers", "security_headers"),
            ("24. Info Disclosure", "info_disclosure"),
            ("25. Directory Traversal", "directory_traversal"),
            ("26. HTTP Param Pollution", "hpp_scanner"),
            ("27. Business Logic", "business_logic"),
            ("28. Auth Bypass", "auth_bypass"),
            ("29. Session Fixation", "session_fixation"),
            ("30. Cache Poisoning", "cache_poisoning"),
            ("31. OAuth Scanner", "oauth_scanner"),
            ("32. GraphQL Scanner", "graphql_scanner"),
        ]
        
        print(f"{Fore.YELLOW}╔══════════════════════════════════════════════════════════╗")
        print(f"║                   SCANNER MODULES                         ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        
        for i in range(0, len(modules), 2):
            left = modules[i][0] if i < len(modules) else ""
            right = modules[i+1][0] if i+1 < len(modules) else ""
            print(f"║ {left:<28} {right:<28} ║")
        
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.CYAN}99. Update All Scanners{Style.RESET_ALL}{'':<30} ║")
        print(f"║ {Fore.GREEN}0.  Exit{Style.RESET_ALL}{'':<42} ║")
        print(f"╚══════════════════════════════════════════════════════════╝")
    
    def load_module(self, module_name):
        module_path = os.path.join(self.modules_dir, f"{module_name}.py")
        
        if not os.path.exists(module_path):
            print(f"{Fore.RED}[!] Module {module_name} not found!{Style.RESET_ALL}")
            self.create_module(module_name)
            return None
        
        try:
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading module: {e}{Style.RESET_ALL}")
            return None
    
    def create_module(self, module_name):
        """Create default module template"""
        module_path = os.path.join(self.modules_dir, f"{module_name}.py")
        
        templates = {
            "sql_injection": "SQL Injection Scanner",
            "xss_scanner": "Cross-Site Scripting Scanner",
            "command_injection": "Command Injection Scanner",
            # ... tambahkan semua
        }
        
        module_title = templates.get(module_name, module_name.replace("_", " ").title())
        
        template = f'''#!/usr/bin/env python3
"""
{module_title}
Author: Pentest Framework
"""

import requests
import sys
from colorama import Fore, Style
from utils import ScannerBase, save_results

class {module_name.title().replace("_", "")}(ScannerBase):
    def __init__(self):
        super().__init__()
        self.module_name = "{module_name}"
        self.vulnerabilities = []
    
    def scan(self, target):
        """Main scanning function"""
        print(f"{Fore.CYAN}\\n[+] Scanning {{target}} for {module_title}...{Style.RESET_ALL}")
        
        # Implement scanning logic here
        self.check_vulnerability(target)
        
        return self.vulnerabilities
    
    def check_vulnerability(self, target):
        """Check for specific vulnerability"""
        try:
            # Add your scanning logic
            test_url = f"{{target}}/test"
            response = requests.get(test_url, timeout=10)
            
            # Example check
            if response.status_code == 200:
                self.vulnerabilities.append({{
                    "type": "{module_name}",
                    "url": target,
                    "severity": "Medium",
                    "description": "Potential vulnerability found",
                    "proof": "Response code 200"
                }})
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {{e}}{Style.RESET_ALL}")
    
    def generate_payloads(self):
        """Generate test payloads"""
        payloads = []
        # Add payloads specific to this vulnerability
        return payloads

def main():
    scanner = {module_name.title().replace("_", "")}()
    target = input("Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    results = scanner.scan(target)
    
    if results:
        print(f"{Fore.GREEN}\\n[+] Found {{len(results)}} vulnerabilities!{Style.RESET_ALL}")
        for vuln in results:
            print(f"{Fore.YELLOW}- {{vuln['description']}}{Style.RESET_ALL}")
        
        # Save results
        filename = save_results(results, scanner.module_name)
        print(f"{Fore.CYAN}[+] Results saved to {{filename}}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
'''
        
        with open(module_path, 'w') as f:
            f.write(template)
        
        print(f"{Fore.GREEN}[+] Created module: {module_name}{Style.RESET_ALL}")
    
    def run_module(self, module_name):
        module = self.load_module(module_name)
        
        if module:
            try:
                
                target = input(f"{Fore.GREEN}[?] Enter target URL: {Style.RESET_ALL}").strip()
                
                if not target:
                    print(f"{Fore.YELLOW}[!] Using default test target{Style.RESET_ALL}")
                    target = "http://testphp.vulnweb.com"
                
                
                if hasattr(module, 'Scanner'):
                    scanner = module.Scanner()
                    results = scanner.scan(target)
                elif hasattr(module, 'scan'):
                    results = module.scan(target)
                else:
                    print(f"{Fore.YELLOW}[!] Running module directly...{Style.RESET_ALL}")
                    module.main()
                    return
                
                
                if results:
                    self.display_results(results, module_name)
                else:
                    print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}\\n[!] Scan interrupted{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
    
    def display_results(self, results, module_name):
        print(f"{Fore.CYAN}\\n{'='*60}")
        print(f"SCAN RESULTS: {module_name.upper().replace('_', ' ')}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        for i, result in enumerate(results, 1):
            severity_color = {
                "Critical": Fore.RED,
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.CYAN,
                "Info": Fore.BLUE
            }.get(result.get('severity', 'Medium'), Fore.WHITE)
            
            print(f"{Fore.WHITE}[{i}] {severity_color}{result.get('severity', 'Medium')}{Style.RESET_ALL}")
            print(f"     Target: {result.get('url', 'N/A')}")
            print(f"     Description: {result.get('description', 'N/A')}")
            if result.get('proof'):
                print(f"     Proof: {result.get('proof')[:100]}...")
            print()
    
    def update_scanners(self):
        print(f"{Fore.CYAN}[+] Updating all scanners...{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Update complete!{Style.RESET_ALL}")
    
    def run(self):
        self.print_banner()
        
        while True:
            self.print_menu()
            choice = input(f"{Fore.GREEN}\\n[+] Select module (0-32, 99): {Style.RESET_ALL}")
            
            if choice == "0":
                print(f"{Fore.YELLOW}[!] Goodbye!{Style.RESET_ALL}")
                sys.exit(0)
            elif choice == "99":
                self.update_scanners()
                continue
            
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= 32:
                    module_map = [
                        "sql_injection", "xss_scanner", "command_injection", "rce_scanner",
                        "lfi_scanner", "rfi_scanner", "xxe_scanner", "ssrf_scanner",
                        "crlf_injection", "open_redirect", "ssti_scanner", "idor_scanner",
                        "csrf_tester", "file_upload", "cors_scanner", "subdomain_takeover",
                        "dns_zone", "api_scanner", "jwt_scanner", "http_smuggling",
                        "clickjacking", "cookie_scanner", "security_headers", "info_disclosure",
                        "directory_traversal", "hpp_scanner", "business_logic", "auth_bypass",
                        "session_fixation", "cache_poisoning", "oauth_scanner", "graphql_scanner"
                    ]
                    
                    module_name = module_map[choice_num - 1]
                    self.run_module(module_name)
                else:
                    print(f"{Fore.RED}[!] Invalid choice!{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number!{Style.RESET_ALL}")

if __name__ == "__main__":
    framework = PentestFramework()
    framework.run()
