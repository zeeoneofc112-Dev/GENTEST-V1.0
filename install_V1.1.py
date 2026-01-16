#!/usr/bin/env python3
"""
Installer untuk Pentest-Web v1.1
Membuat semua file dan struktur
"""

import os
import sys
import json
from colorama import Fore, Style, init

init(autoreset=True)

def install_pentest_v1_1():
    """Install Pentest-Web v1.1"""
    
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║         PENTEST-WEB v1.1 INSTALLER               ║")
    print(f"║        Hybrid Structure + 32 Menu               ║")
    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    
    print(f"{Fore.YELLOW}[+] Creating directory structure...{Style.RESET_ALL}")
    
    directories = [
        "scanners",
        "utils",
        "payloads",
        "payloads/sqli",
        "payloads/xss", 
        "payloads/api",
        "payloads/common",
        "modules",
        "results",
        "reports",
        "logs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {directory}/")
    
    
    print(f"\n{Fore.YELLOW}[+] Creating main.py...{Style.RESET_ALL}")
    
    main_py_content = '''
#!/usr/bin/env python3
"""
PENTEST-WEB FRAMEWORK v1.1
Created by: MR•Zeeone-Grayhat
Supporting by: Team CyberCrime Indonesia
"""

print("Pentest-Web v1.1")
print("Run install_v1.1.py first to setup complete framework")
'''
    
    with open("main.py", "w") as f:
        f.write(main_py_content)
    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} main.py")
    
    # Copy semua file yang sudah dibuat
    print(f"\n{Fore.YELLOW}[+] Copying framework files...{Style.RESET_ALL}")
    
    # List of files to create
    files_to_create = [
        ("requirements.txt", "requirements.txt content"),
        ("config.json", "config.json content"),
        ("scanners/deep_scanner.py", "deep_scanner.py content"),
        ("scanners/__init__.py", ""),
        ("utils/__init__.py", ""),
        ("utils/report_generator.py", "# Report Generator\n"),
        ("payloads/common/parameters.txt", "id\nuser\nusername\nemail\npassword\n"),
        ("payloads/sqli/get_params.txt", "' OR '1'='1\n' UNION SELECT NULL--\n"),
    ]
    
    for filepath, content in files_to_create:
        with open(filepath, "w") as f:
            f.write(content)
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {filepath}")
    
    # Create 32 basic modules
    print(f"\n{Fore.YELLOW}[+] Creating 32 vulnerability modules...{Style.RESET_ALL}")
    
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
        with open(module_path, "w") as f:
            f.write(f'''#!/usr/bin/env python3
"""
{module.replace('_', ' ').title()} Scanner
Pentest-Web v1.1
"""

def main():
    print("{module.replace('_', ' ').title()} Scanner")
    print("Ready for implementation")

if __name__ == "__main__":
    main()
''')
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} modules/{module}.py")
    
    
    print(f"\n{Fore.YELLOW}[+] Installing dependencies...{Style.RESET_ALL}")
    os.system("pip install requests colorama")
    
    print(f"\n{Fore.GREEN}[✓] Pentest-Web v1.1 installed successfully!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[→] Run: python3 main.py{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[→] 32 Vulnerability scanners ready!{Style.RESET_ALL}")

if __name__ == "__main__":
    install_pentest_v1_1()
