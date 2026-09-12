# Log-Sentry: Web Access Log Security Analyzer

A lightweight command-line incident response triage tool written in Python. Analyzes web server access logs (Nginx / Apache Combined Log Format) to detect common attack vectors and automated reconnaissance activity.

## Features
- **Attack Pattern Detection:** Identifies indicators of Directory Traversal, SQL Injection (SQLi), Cross-Site Scripting (XSS), and sensitive file reconnaissance (`.env`, `.git`, admin endpoints).
- **Scanning Profiling:** Detects directory brute-forcing via HTTP 404 frequency analysis.
- **Zero External Dependencies:** Built purely with the Python standard library for rapid deployment in minimal or air-gapped environments.

## Usage
```bash
python3 analyzer.py <path_to_access_log>