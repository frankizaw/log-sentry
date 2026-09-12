Log Sentry

Small Python tool for checking web server access logs for common suspicious requests.

The project started as a simple experiment with parsing access logs and detecting a few common web attack patterns. It is not meant to replace a proper WAF, SIEM, or other security monitoring tools.

What it checks

Currently, Log Sentry looks for:

Directory traversal attempts
Basic SQL injection patterns
Basic XSS payloads
Requests for sensitive paths such as .env, .git, and wp-login.php
IP addresses generating a large number of HTTP 404 responses

The detection is based on simple pattern matching, so false positives and missed detections are possible.

Requirements
Python 3.8+
No external packages are required
Usage

Run the analyzer against an access log:

python3 analyzer.py sample_access.log


You can also provide your own Nginx/Apache-style access log:

python3 analyzer.py /var/log/nginx/access.log


The tool prints the suspicious requests it finds and a short summary of the IPs responsible for the most 404 responses.

Example

The repository includes a small sample log containing a few normal requests and some intentionally suspicious ones.

Running:

python3 analyzer.py sample_access.log


will produce output similar to:

=== Log Sentry ===

[ALERT] 192.168.1.20 - Directory Traversal
[ALERT] 192.168.1.21 - SQL Injection
[ALERT] 192.168.1.22 - Cross-Site Scripting (XSS)

=== Top 404 sources ===

192.168.1.30: 12
192.168.1.31: 8


The exact output depends on the contents of the log file.

Limitations

This is currently a small proof-of-concept project.

Some things that are intentionally not handled yet:

URL encoding and more advanced payload obfuscation
Different access log formats
Time-based analysis of requests
More accurate detection of brute-force/scanning activity
Persistent storage or historical analysis
Tests for all detection rules

Because of this, the results should be treated as indicators for further investigation rather than definitive security findings.

Project structure
log-sentry/
├── analyzer.py
├── sample_access.log
└── README.md

Why I made it

I wanted a small project to experiment with access-log parsing and basic detection of suspicious web requests without relying on external Python libraries.

It is intentionally simple for now, and there are plenty of areas where the detection logic could be improved.