#!/usr/bin/env python3
"""
PENTEST-WEB FRAMEWORK V1.1
32-in-1 Web Vulnerability Scanner
Menggabungkan struktur baru dengan menu legacy 32 modules
Created by: MR•Zeeone-Grayhat
Supporting by: Team CyberCrime Indonesia
"""

import os
import sys
import json
import importlib.util
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

class PentestWebV1_1:
    def __init__(self):
        self.version = "1.1"
        self.author = "MR•Zeeone-Grayhat"
        self.team = "Team CyberCrime Indonesia"
        self.setup_directories()
        self.load_config()
        
    def setup_directories(self):
        """Setup semua directory sesuai struktur baru"""
        directories = [
            "scanners", "utils", "payloads",
            "payloads/sqli", "payloads/xss", "payloads/api", "payloads/common",
            "results", "reports", "logs", "modules"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def load_config(self):
        """Load configuration"""
        default_config = {
            "version": "1.1",
            "scanning": {
                "timeout": 10,
                "threads": 3,
                "user_agent": "Pentest-Web/v1.1",
                "follow_redirects": True
            }
        }
        
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                self.config = json.load(f)
        else:
            self.config = default_config
            with open("config.json", "w") as f:
                json.dump(default_config, f, indent=2)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
╔════════════════════════════════════════════════════════════════════╗
║    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗    ║
║   ██╔═══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝    ║
║   ██║   ██║█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║       ║
║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║       ║
║   ╚██████╔╝███████╗██║ ╚████║   ██║   ███████╗███████║   ██║       ║
║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝       ║
║                                                                    ║
║        32-IN-1 WEB VULNERABILITY SCANNER FRAMEWORK                 ║
║                    Version:{self.version}                          ║
║                    Create by MR•Zeeone-Grayhat                     ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def print_menu(self):
        """Print menu 32 vulnerability types (legacy style)"""
        menu_items = [
            ("1.  SQL Injection", "sql_injection"),
            ("2.  XSS (Reflected, Stored, DOM)", "xss_scanner"),
            ("3.  Command Injection", "command_injection"),
            ("4.  RCE (Remote Code Execution)", "rce_scanner"),
            ("5.  LFI (Local File Inclusion)", "lfi_scanner"),
            ("6.  RFI (Remote File Inclusion)", "rfi_scanner"),
            ("7.  XXE (XML External Entity)", "xxe_scanner"),
            ("8.  SSRF (Server Side Request Forgery)", "ssrf_scanner"),
            ("9.  CRLF Injection", "crlf_injection"),
            ("10. Open Redirect", "open_redirect"),
            ("11. SSTI (Server Side Template Injection)", "ssti_scanner"),
            ("12. IDOR (Insecure Direct Object Reference)", "idor_scanner"),
            ("13. CSRF (Cross-Site Request Forgery)", "csrf_tester"),
            ("14. File Upload Bypass", "file_upload"),
            ("15. CORS Misconfiguration", "cors_scanner"),
            ("16. Subdomain Takeover", "subdomain_takeover"),
            ("17. DNS Zone Transfer", "dns_zone"),
            ("18. API Security Issues", "api_scanner"),
            ("19. JWT Vulnerabilities", "jwt_scanner"),
            ("20. HTTP Request Smuggling", "http_smuggling"),
            ("21. Clickjacking", "clickjacking"),
            ("22. Cookie Security", "cookie_scanner"),
            ("23. Security Headers Missing", "security_headers"),
            ("24. Information Disclosure", "info_disclosure"),
            ("25. Directory Traversal", "directory_traversal"),
            ("26. HTTP Parameter Pollution", "hpp_scanner"),
            ("27. Business Logic Flaws", "business_logic"),
            ("28. Authentication Bypass", "auth_bypass"),
            ("29. Session Fixation", "session_fixation"),
            ("30. Web Cache Poisoning", "cache_poisoning"),
            ("31. OAuth Vulnerabilities", "oauth_scanner"),
            ("32. GraphQL Vulnerabilities", "graphql_scanner"),
        ]
        
        print(f"{Fore.YELLOW}╔══════════════════════════════════════════════════════════╗")
        print(f"║              32 VULNERABILITY SCANNERS                     ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        
        
        for i in range(0, len(menu_items), 2):
            left = menu_items[i][0] if i < len(menu_items) else ""
            right = menu_items[i+1][0] if i+1 < len(menu_items) else ""
            print(f"║ {left:<30} {right:<25} ║")
        
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.CYAN}33. Advanced Deep Scanner{Style.RESET_ALL}{'':<28} ║")
        print(f"║ {Fore.CYAN}34. Parameter Discovery Tool{Style.RESET_ALL}{'':<26} ║")
        print(f"║ {Fore.CYAN}35. Generate Reports{Style.RESET_ALL}{'':<31} ║")
        print(f"║ {Fore.GREEN}99. Update/Install Modules{Style.RESET_ALL}{'':<24} ║")
        print(f"║ {Fore.RED}0.  Exit{Style.RESET_ALL}{'':<40} ║")
        print(f"╚══════════════════════════════════════════════════════════╝")
    
    def load_module(self, module_name):
        """Load module dari folder modules/"""
        module_path = f"modules/{module_name}.py"
        
        if not os.path.exists(module_path):
            print(f"{Fore.RED}[!] Module {module_name} not found!{Style.RESET_ALL}")
            self.create_module_template(module_name)
            return None
        
        try:
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading module: {e}{Style.RESET_ALL}")
            return None
    
    def create_module_template(self, module_name):
        """Create template untuk module baru"""
        module_path = f"modules/{module_name}.py"
        
        template = f'''#!/usr/bin/env python3
"""
{module_name.replace('_', ' ').title()} Scanner
Pentest-Web v1.1
"""

import requests
import sys
from colorama import Fore, Style

def scan(target):
    """Main scan function"""
    print(f"{Fore.CYAN}\\n[+] Scanning {{target}} for {module_name.replace('_', ' ')}{Style.RESET_ALL}")
    
    # Example scanning logic
    try:
        response = requests.get(target, timeout=10)
        
        # Check for vulnerabilities
        vulnerabilities = []
        
        # Add your scanning logic here
        # ...
        
        return vulnerabilities
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {{e}}{Style.RESET_ALL}")
        return []

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    results = scan(target)
    
    if results:
        print(f"{Fore.GREEN}\\n[+] Found {{len(results)}} vulnerabilities!{Style.RESET_ALL}")
        for vuln in results:
            print(f"{Fore.YELLOW}- {{vuln.get('description', 'Vulnerability found')}}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
'''
        
        with open(module_path, "w") as f:
            f.write(template)
        
        print(f"{Fore.GREEN}[+] Created module template: {module_name}.py{Style.RESET_ALL}")
    
    def run_legacy_module(self, module_num):
        """Run legacy module dari menu 1-32"""
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
        
        if 1 <= module_num <= 32:
            module_name = module_map[module_num - 1]
            module = self.load_module(module_name)
            
            if module:
                try:
                    
                    target = input(f"{Fore.GREEN}[?] Enter target URL: {Style.RESET_ALL}").strip()
                    if not target:
                        print(f"{Fore.YELLOW}[!] Using default test target{Style.RESET_ALL}")
                        target = "http://testphp.vulnweb.com"
                    
                    
                    if hasattr(module, 'main'):
                        module.main()
                    elif hasattr(module, 'scan'):
                        results = module.scan(target)
                        self.display_results(results, module_name)
                    else:
                        print(f"{Fore.YELLOW}[!] Running module directly...{Style.RESET_ALL}")
                        os.system(f"python3 modules/{module_name}.py {target}")
                        
                except KeyboardInterrupt:
                    print(f"{Fore.YELLOW}\\n[!] Scan interrupted{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
    
    def run_advanced_scanner(self):
        """Run advanced scanner dari folder scanners/"""
        print(f"{Fore.CYAN}[+] Loading Advanced Deep Scanner...{Style.RESET_ALL}")
        
        try:
            from scanners.deep_scanner import DeepScanner
            scanner = DeepScanner()
            
            target = input(f"{Fore.GREEN}[?] Enter target URL: {Style.RESET_ALL}").strip()
            
            print(f"{Fore.YELLOW}[*] Starting deep scan...{Style.RESET_ALL}")
            results = scanner.comprehensive_scan(target)
            
            self.display_results(results, "Deep Scanner")
            
        except ImportError:
            print(f"{Fore.RED}[!] Deep Scanner not available{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] Creating basic deep scanner...{Style.RESET_ALL}")
            self.create_basic_deep_scanner()
    
    def run_parameter_discovery(self):
        """Run parameter discovery tool"""
        print(f"{Fore.CYAN}[+] Loading Parameter Discovery Tool...{Style.RESET_ALL}")
        
        try:
            from scanners.param_discoverer import ParameterDiscoverer
            discoverer = ParameterDiscoverer()
            
            target = input(f"{Fore.GREEN}[?] Enter target URL: {Style.RESET_ALL}").strip()
            
            print(f"{Fore.YELLOW}[*] Discovering parameters...{Style.RESET_ALL}")
            params = discoverer.discover_all_parameters(target)
            
            self.display_parameters(params)
            
        except ImportError:
            print(f"{Fore.RED}[!] Parameter Discoverer not available{Style.RESET_ALL}")
    
    def display_results(self, results, scanner_name):
        """Display scan results"""
        if not results:
            print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}\\n{'='*60}")
        print(f"SCAN RESULTS: {scanner_name}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        for i, result in enumerate(results, 1):
            severity = result.get('severity', 'Medium')
            color = {
                'Critical': Fore.RED,
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.CYAN,
                'Info': Fore.GREEN
            }.get(severity, Fore.WHITE)
            
            print(f"{Fore.WHITE}[{i}] {color}{severity}: {result.get('type', 'Vulnerability')}{Style.RESET_ALL}")
            print(f"     URL: {result.get('url', 'N/A')}")
            print(f"     Parameter: {result.get('parameter', 'N/A')}")
            if result.get('evidence'):
                print(f"     Evidence: {result.get('evidence')[:80]}...")
            print()
    
    def display_parameters(self, params):
        """Display discovered parameters"""
        print(f"{Fore.CYAN}\\n{'='*60}")
        print(f"PARAMETER DISCOVERY RESULTS")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        total = sum(len(p) for p in params.values())
        print(f"{Fore.GREEN}[+] Total parameters found: {total}{Style.RESET_ALL}")
        
        for param_type, param_list in params.items():
            if param_list:
                print(f"{Fore.YELLOW}\\n[{param_type.upper()}]: {len(param_list)} parameters{Style.RESET_ALL}")
                for param in param_list[:10]:  
                    print(f"  - {param}")
                if len(param_list) > 10:
                    print(f"  ... and {len(param_list)-10} more")
    
    def generate_reports(self):
        """Generate reports from scan results"""
        print(f"{Fore.CYAN}[+] Report Generator{Style.RESET_ALL}")
        
        
        result_files = []
        if os.path.exists("results"):
            result_files = [f for f in os.listdir("results") if f.endswith('.json')]
        
        if not result_files:
            print(f"{Fore.RED}[-] No scan results found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}[*] Available scan results:{Style.RESET_ALL}")
        for i, file in enumerate(result_files[:10], 1):
            print(f"  {i}. {file}")
        
        choice = input(f"{Fore.GREEN}[?] Select result file (1-{len(result_files)}): {Style.RESET_ALL}")
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(result_files):
                selected_file = result_files[idx]
                
                
                with open(f"results/{selected_file}", "r") as f:
                    results = json.load(f)
                
                
                from utils.report_generator import ReportGenerator
                generator = ReportGenerator()
                report_file = generator.generate_html_report(results, selected_file.replace('.json', ''))
                
                print(f"{Fore.GREEN}[+] Report generated: {report_file}{Style.RESET_ALL}")
                
        except (ValueError, IndexError):
            print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}[!] Report generator not available{Style.RESET_ALL}")
    
    def update_install_modules(self):
        """Update atau install semua modules"""
        print(f"{Fore.CYAN}[+] Updating/Installing Modules...{Style.RESET_ALL}")
        
        # Create semua directory
        self.setup_directories()
        
        
        self.create_basic_modules()
        
        # Create payload files
        self.create_payload_files()
        
        # Create scanner files
        self.create_scanner_files()
        
        # Create utility files
        self.create_utility_files()
        
        print(f"{Fore.GREEN}[✓] All modules updated/installed!{Style.RESET_ALL}")
    
    def create_basic_modules(self):
        """Create basic 32 modules"""
        modules = [
            "sql_injection", "xss_scanner", "command_injection", "rce_scanner",
            "lfi_scanner", "rfi_scanner", "xxe_scanner", "ssrf_scanner",
            "crlf_injection", "open_redirect", "ssti_scanner", "idor_scanner",
            "csrf_tester", "file_upload", "cors_scanner", "subdomain_takeover",
            "dns_zone", "api_scanner", "jwt_scanner", "http_smuggling",
            "clickjacking", "cookie_scanner", "security_headers", "info_disclosure",
            "directory_traversal", "hpp_scanner", "business_logic", "auth_bypass",
            "session_fixation", "cache_poisoning", "oauth_scanner", "graphql_scanner"
        ]
        
        for module in modules:
            module_path = f"modules/{module}.py"
            if not os.path.exists(module_path):
                self.create_module_template(module)
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} modules/{module}.py")
    
    def create_payload_files(self):
        """Create basic payload files"""
        # Create directories
        for subdir in ["sqli", "xss", "api", "common"]:
            os.makedirs(f"payloads/{subdir}", exist_ok=True)
        
        # Create common parameters file
        common_params = [
            "id", "user", "username", "email", "password",
            "search", "query", "q", "page", "limit",
            "file", "path", "url", "redirect", "token",
            "session", "key", "secret", "action", "method"
        ]
        
        with open("payloads/common/parameters.txt", "w") as f:
            f.write("\n".join(common_params))
        
        # Create SQLi payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--",
        ]
        
        with open("payloads/sqli/get_params.txt", "w") as f:
            f.write("\n".join(sqli_payloads))
        
        print(f"{Fore.GREEN}[+] Created payload files{Style.RESET_ALL}")
    
    def create_scanner_files(self):
        """Create basic scanner files"""
        scanners = [
            ("deep_scanner.py", "DeepScanner"),
            ("param_discoverer.py", "ParameterDiscoverer"),
            ("enhanced_sqli.py", "EnhancedSQLiScanner"),
        ]
        
        for filename, classname in scanners:
            scanner_path = f"scanners/{filename}"
            if not os.path.exists(scanner_path):
                with open(scanner_path, "w") as f:
                    f.write(f'''#!/usr/bin/env python3
"""
{filename.replace('.py', '').replace('_', ' ').title()}
Pentest-Web v1.1
"""

class {classname}:
    def __init__(self):
        pass
    
    def scan(self, target):
        print("Scanner ready - Implement scanning logic here")
        return []

if __name__ == "__main__":
    scanner = {classname}()
    scanner.scan("http://example.com")
''')
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} scanners/{filename}")
    
    def create_utility_files(self):
        """Create basic utility files"""
        utils = [
            "crawler.py",
            "param_extractor.py", 
            "response_analyzer.py",
            "report_generator.py",
            "payload_manager.py",
            "session_manager.py"
        ]
        
        for util in utils:
            util_path = f"utils/{util}"
            if not os.path.exists(util_path):
                with open(util_path, "w") as f:
                    f.write(f'''#!/usr/bin/env python3
"""
{util.replace('.py', '').replace('_', ' ').title()}
Pentest-Web v1.1
"""

print("{util.replace('.py', '').replace('_', ' ').title()} Utility")
''')
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} utils/{util}")
    
    def create_basic_deep_scanner(self):
        """Create basic deep scanner"""
        scanner_code = '''#!/usr/bin/env python3
"""
Basic Deep Scanner
Pentest-Web v1.1
"""

import requests
import re
from colorama import Fore, Style

class DeepScanner:
    def __init__(self):
        self.session = requests.Session()
    
    def comprehensive_scan(self, url):
        """Basic comprehensive scan"""
        results = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for common vulnerabilities
            if self.check_sqli(response.text):
                results.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'url': url,
                    'evidence': 'SQL pattern detected'
                })
            
            if self.check_xss(response.text):
                results.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'url': url,
                    'evidence': 'XSS pattern detected'
                })
            
            # Check headers
            if self.check_headers(response.headers):
                results.append({
                    'type': 'Security Headers',
                    'severity': 'Medium',
                    'url': url,
                    'evidence': 'Missing security headers'
                })
            
        except Exception as e:
            print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_sqli(self, content):
        """Check for SQL injection patterns"""
        patterns = [
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"Unclosed quotation mark",
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def check_xss(self, content):
        """Check for XSS patterns"""
        patterns = [
            r"<script>alert",
            r"onerror=",
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def check_headers(self, headers):
        """Check security headers"""
        security_headers = [
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-Content-Type-Options',
        ]
        
        missing = []
        for header in security_headers:
            if header not in headers:
                missing.append(header)
        
        return len(missing) > 0

if __name__ == "__main__":
    scanner = DeepScanner()
    
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ")
    
    results = scanner.comprehensive_scan(target)
    
    if results:
        print(f"{Fore.GREEN}[+] Found {len(results)} vulnerabilities!{Style.RESET_ALL}")
        for r in results:
            print(f"{Fore.YELLOW}- {r['type']}: {r['severity']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")
'''
        
        with open("scanners/deep_scanner.py", "w") as f:
            f.write(scanner_code)
        
        print(f"{Fore.GREEN}[+] Created basic deep scanner{Style.RESET_ALL}")
    
    def run(self):
        """Main execution loop"""
        self.print_banner()
        
        while True:
            self.print_menu()
            choice = input(f"{Fore.GREEN}\\n[+] Select option (0-35, 99): {Style.RESET_ALL}")
            
            if choice == "0":
                print(f"{Fore.YELLOW}[!] Thank you for using Pentest-Web!{Style.RESET_ALL}")
                sys.exit(0)
            
            elif choice == "99":
                self.update_install_modules()
                continue
            
            try:
                choice_num = int(choice)
                
                if 1 <= choice_num <= 32:
                    self.run_legacy_module(choice_num)
                
                elif choice_num == 33:
                    self.run_advanced_scanner()
                
                elif choice_num == 34:
                    self.run_parameter_discovery()
                
                elif choice_num == 35:
                    self.generate_reports()
                
                else:
                    print(f"{Fore.RED}[!] Invalid option!{Style.RESET_ALL}")
                    
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a number!{Style.RESET_ALL}")

if __name__ == "__main__":
    
    try:
        import requests
        import colorama
    except ImportError:
        print(f"{Fore.YELLOW}[!] Installing requirements...{Style.RESET_ALL}")
        os.system("pip install requests colorama")
    
    
    framework = PentestWebV1_1()
    framework.run()
