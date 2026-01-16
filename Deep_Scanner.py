#!/usr/bin/env python3
"""
Deep Scanner - Comprehensive vulnerability scanner
Tests multiple injection points and vulnerability types
"""

import requests
import re
import json
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urljoin

class DeepScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Pentest-Web/v1.1)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
    
    def comprehensive_scan(self, url):
        """Comprehensive deep scan"""
        results = []
        
        print(f"{Fore.CYAN}[*] Starting deep scan on: {url}{Style.RESET_ALL}")
        
        try:
            # Initial request
            response = self.session.get(url, timeout=10)
            
            # 1. Test GET parameters
            results.extend(self.test_get_parameters(url))
            
            # 2. Test POST parameters
            results.extend(self.test_post_parameters(url))
            
            # 3. Test headers
            results.extend(self.test_headers(url))
            
            # 4. Test cookies
            results.extend(self.test_cookies(url))
            
            # 5. Check security headers
            results.extend(self.check_security_headers(response.headers, url))
            
            # 6. Check information disclosure
            results.extend(self.check_info_disclosure(response.text, url))
            
            # 7. Crawl for more endpoints
            endpoints = self.crawl_endpoints(response.text, url)
            print(f"{Fore.YELLOW}[*] Found {len(endpoints)} additional endpoints{Style.RESET_ALL}")
            
            # Test each endpoint
            for endpoint in endpoints[:5]:  # Limit to 5 endpoints
                endpoint_url = urljoin(url, endpoint)
                results.extend(self.test_basic_endpoint(endpoint_url))
            
        except Exception as e:
            print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_get_parameters(self, url):
        """Test GET parameters for various vulnerabilities"""
        results = []
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                # Test SQLi
                test_url = self.inject_payload(url, param, "' OR '1'='1")
                if self.test_sqli(test_url):
                    results.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': test_url,
                        'parameter': param,
                        'evidence': 'SQL pattern detected'
                    })
                
                # Test XSS
                test_url = self.inject_payload(url, param, "<script>alert(1)</script>")
                if self.test_xss(test_url):
                    results.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'url': test_url,
                        'parameter': param,
                        'evidence': 'XSS payload reflected'
                    })
                
                # Test LFI
                test_url = self.inject_payload(url, param, "../../../etc/passwd")
                if self.test_lfi(test_url):
                    results.append({
                        'type': 'LFI',
                        'severity': 'High',
                        'url': test_url,
                        'parameter': param,
                        'evidence': 'File inclusion detected'
                    })
        
        return results
    
    def test_post_parameters(self, url):
        """Test POST parameters"""
        results = []
        
        # Common parameter names
        common_params = ['id', 'user', 'username', 'email', 'password', 'search', 'file']
        
        for param in common_params:
            # Test with SQLi payload
            data = {param: "' OR '1'='1"}
            if self.test_post_sqli(url, data):
                results.append({
                    'type': 'SQL Injection (POST)',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': param,
                    'evidence': 'SQL pattern in POST response'
                })
            
            # Test with XSS payload
            data = {param: "<script>alert(1)</script>"}
            if self.test_post_xss(url, data):
                results.append({
                    'type': 'XSS (POST)',
                    'severity': 'High',
                    'url': url,
                    'parameter': param,
                    'evidence': 'XSS payload in POST response'
                })
        
        return results
    
    def test_headers(self, url):
        """Test header injection"""
        results = []
        
        header_payloads = {
            'X-Forwarded-For': "127.0.0.1",
            'User-Agent': "Pentest-Web-Scanner",
            'Referer': url,
        }
        
        for header, value in header_payloads.items():
            try:
                self.session.headers[header] = value
                response = self.session.get(url, timeout=5)
                
                # Check if header value appears in response
                if value in response.text:
                    results.append({
                        'type': 'Header Injection',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': header,
                        'evidence': f'Header value reflected: {value[:50]}'
                    })
                    
            except:
                pass
        
        return results
    
    def test_cookies(self, url):
        """Test cookie manipulation"""
        results = []
        
        cookie_payloads = {
            'session': 'test123',
            'auth': 'true',
            'admin': '1',
        }
        
        for cookie, value in cookie_payloads.items():
            try:
                self.session.cookies.set(cookie, value)
                response = self.session.get(url, timeout=5)
                
                # Check for cookie reflection
                if value in response.text:
                    results.append({
                        'type': 'Cookie Manipulation',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': cookie,
                        'evidence': f'Cookie value reflected: {value}'
                    })
                    
            except:
                pass
        
        return results
    
    def check_security_headers(self, headers, url):
        """Check for security headers"""
        results = []
        
        security_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': [],
            'X-Content-Type-Options': ['nosniff'],
            'Strict-Transport-Security': [],
            'X-XSS-Protection': ['1; mode=block'],
        }
        
        for header, expected in security_headers.items():
            if header not in headers:
                results.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': header,
                    'evidence': f'Missing security header: {header}'
                })
            elif expected and headers[header] not in expected:
                results.append({
                    'type': 'Weak Security Header',
                    'severity': 'Low',
                    'url': url,
                    'parameter': header,
                    'evidence': f'Weak {header}: {headers[header]}'
                })
        
        return results
    
    def check_info_disclosure(self, content, url):
        """Check for information disclosure"""
        results = []
        
        sensitive_patterns = {
            'API Keys': r'(?i)(api[_-]?key|secret[_-]?key)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'IP Addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Error Messages': r'(?i)(error|exception|warning|stack trace|syntax error)',
            'Directory Listing': r'<title>Index of /',
        }
        
        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                results.append({
                    'type': 'Information Disclosure',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': data_type,
                    'evidence': f'Found {len(matches)} {data_type.lower()}'
                })
        
        return results
    
    def crawl_endpoints(self, html, base_url):
        """Crawl untuk endpoints"""
        endpoints = set()
        
        # Extract links
        links = re.findall(r'href=[\'"]([^\'"]+)[\'"]', html)
        endpoints.update(links)
        
        # Extract form actions
        forms = re.findall(r'<form[^>]*action=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
        endpoints.update(forms)
        
        return list(endpoints)
    
    def test_basic_endpoint(self, url):
        """Basic test untuk endpoint"""
        results = []
        
        try:
            response = self.session.get(url, timeout=5)
            
            # Check for common issues
            if response.status_code == 403:
                results.append({
                    'type': 'Access Control',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'HTTP Status',
                    'evidence': '403 Forbidden - Potential access control issue'
                })
            
            elif response.status_code == 500:
                results.append({
                    'type': 'Server Error',
                    'severity': 'Low',
                    'url': url,
                    'parameter': 'HTTP Status',
                    'evidence': '500 Internal Server Error'
                })
            
        except:
            pass
        
        return results
    
    def inject_payload(self, url, param_name, payload):
        """Inject payload ke URL"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        if param_name in query:
            query[param_name] = [payload]
        
        # Rebuild URL
        new_query = '&'.join([f"{k}={v[0]}" for k, v in query.items()])
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def test_sqli(self, url):
        """Test untuk SQL injection"""
        try:
            response = self.session.get(url, timeout=5)
            
            sql_patterns = [
                r"You have an error in your SQL syntax",
                r"Warning: mysql",
                r"Unclosed quotation mark",
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
                    
        except:
            pass
        
        return False
    
    def test_xss(self, url):
        """Test untuk XSS"""
        try:
            response = self.session.get(url, timeout=5)
            payload = "<script>alert(1)</script>"
            return payload in response.text
        except:
            return False
    
    def test_lfi(self, url):
        """Test untuk LFI"""
        try:
            response = self.session.get(url, timeout=5)
            return 'root:' in response.text or 'daemon:' in response.text
        except:
            return False
    
    def test_post_sqli(self, url, data):
        """Test POST SQLi"""
        try:
            response = self.session.post(url, data=data, timeout=5)
            
            sql_patterns = [
                r"You have an error in your SQL syntax",
                r"Warning: mysql",
                r"Unclosed quotation mark",
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
                    
        except:
            pass
        
        return False
    
    def test_post_xss(self, url, data):
        """Test POST XSS"""
        try:
            response = self.session.post(url, data=data, timeout=5)
            payload = "<script>alert(1)</script>"
            return payload in response.text
        except:
            return False


if __name__ == "__main__":
    import sys
    
    scanner = DeepScanner()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()
    
    print(f"{Fore.CYAN}[+] Starting Deep Scan...{Style.RESET_ALL}")
    results = scanner.comprehensive_scan(target)
    
    if results:
        print(f"{Fore.GREEN}[+] Found {len(results)} vulnerabilities!{Style.RESET_ALL}")
        for r in results:
            severity_color = Fore.RED if r['severity'] in ['Critical', 'High'] else Fore.YELLOW
            print(f"{severity_color}[{r['severity']}] {r['type']}{Style.RESET_ALL}")
            print(f"  URL: {r['url']}")
            print(f"  Parameter: {r['parameter']}")
            print()
    else:
        print(f"{Fore.RED}[-] No vulnerabilities found{Style.RESET_ALL}")
