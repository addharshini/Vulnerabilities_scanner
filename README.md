# 🔍 Vulnerabilities Scanner

A lightweight, Python-based scanner that automatically detects common web vulnerabilities such as **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, and **Cross-Site Request Forgery (CSRF)** by crawling and testing HTML forms in a target website.


## 📌 Features

- Parses and analyzes all forms on a target webpage
- Automatically fills and submits forms with malicious payloads
- Detects:
  - SQL Injection (classic `' OR '1'='1`)
  - XSS via JavaScript injection (`<script>alert()</script>`)
  - CSRF by simulating fake requests
- CLI-based and beginner-friendly
- Uses only Python’s built-in modules



## 🛠️ Requirements

No external libraries required. Works with Python 3.x out of the box.



## ⚠️ Disclaimer

This tool is for **educational and authorized testing only**.  
Do not use it on websites without explicit permission. Unauthorized scanning is illegal and unethical.

## 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/addharshini/Vulnerabilities_scanner.git
   cd Vulnerabilities_scanner

2.  Run the script:
    ```bash 
    python3 vul_scanner.py
    
3.  When prompted, enter a target URL:
    
    ```bash
    Enter the URL to scan: https://example.com 

* * *

🔍 What It Scans
----------------

### ✅ SQL Injection (SQLi)

*   Sends SQL payloads like `' OR '1'='1` into all form inputs
    
*   Flags a possible vulnerability if common error keywords appear in the response (e.g., "syntax", "error")
    

### ✅ Cross-Site Scripting (XSS)

*   Injects JavaScript payloads into form inputs
    
*   Flags a vulnerability if the payload is reflected in the response
    

### ✅ Cross-Site Request Forgery (CSRF)

*   Submits forms with fake CSRF tokens
    
*   Flags a vulnerability if the server accepts the forged request
    

* * *

### 📄 License

MIT License © 2025 Divya Dharshini

* * *

### 🤝 Contributions

Pull requests are welcome! For major changes, please open an issue first.

* * *
