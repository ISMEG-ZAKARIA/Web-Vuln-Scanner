# Web Vulnerability Scanner

A simple **Python tool** designed to help penetration testers identify and exploit common web application vulnerabilities. This project automates some of the manual processes involved in web application security testing, allowing pentesters to quickly assess the security of web applications.

## Features

- **SQL Injection**: Detect and test for SQL Injection vulnerabilities by sending specially crafted inputs.
- **XSS (Cross-Site Scripting)**: Identify Cross-Site Scripting vulnerabilities in web forms.
- **CSRF (Cross-Site Request Forgery)**: Scan for potential CSRF vulnerabilities in web applications.
- **Directory Traversal**: Search for directory traversal flaws that could expose sensitive files.
- **Automated Scanning**: Speed up penetration testing by automating scans against common vulnerabilities.

## Why This Tool?

This tool helps penetration testers save time during web app assessments by automating the detection of common vulnerabilities. It’s especially helpful for **bug bounty hunters**, **web application security professionals**, and anyone looking to automate parts of their web security testing process.

## Installation

Follow the steps below to install and use the Web Vulnerability Scanner:

### Prerequisites

You will need **Python 3** and **pip** (Python package manager) installed on your machine.

1. Clone the repository:

    ```bash
    git clone https://github.com/ISMEG-ZAKARIA/web-vuln-scanner.git
    cd web-vuln-scanner
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

    The dependencies include common libraries like `requests`, `beautifulsoup4`, and others that are used to interact with web pages.

### Usage

Once the tool is installed, you can use it by following these steps:

1. Run the scanner with a target URL:

    ```bash
    python scanner.py http://targetsite.com
    ```

2. The scanner will automatically check for vulnerabilities, including:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Cross-Site Request Forgery (CSRF)
    - Directory Traversal

3. After the scan, results will be printed to the terminal, highlighting any vulnerabilities found.

### Example

```bash
$ python scanner.py http://example.com
Scanning http://example.com for vulnerabilities...
- SQL Injection: Vulnerable
- XSS: Not Vulnerable
- CSRF: Vulnerable
- Directory Traversal: Not Vulnerable

Scan complete! Vulnerabilities detected: 2
