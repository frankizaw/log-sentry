# Web Access Log Analyzer

A lightweight Python script for parsing web server access logs (Nginx / Apache Combined Format) to identify common attack signatures and scanning activity.

Created as a practical exercise in log parsing, regular expressions, and basic intrusion detection principles.

## Overview
The script reads access log files line-by-line using standard Python libraries, parses request metadata, and performs signature matching against common malicious URI patterns.

### Current Features
- **Signature Detection:** Flags basic indicators of:
  - Directory Traversal (`../`, `/etc/passwd`)
  - SQL Injection (basic boolean and union payloads)
  - Reconnaissance on common sensitive paths (`.env`, `.git`, admin endpoints)
  - Basic Cross-Site Scripting (XSS) script tags
- **Scanning Frequency Analysis:** Aggregates HTTP `404 Not Found` responses per IP address to surface brute-force path enumeration.
- **Zero External Dependencies:** Relies purely on the Python standard library (`sys`, `re`, `collections`).

## Usage
```bash
python3 analyzer.py <path_to_log_file>