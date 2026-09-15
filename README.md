# Log Sentry

A small Python script that scans web server access logs and flags requests that look like common attacks.

I built this to practice log parsing, regular expressions, and basic security concepts while learning Python and cybersecurity.

*Czytaj po polsku: [README.pl.md](README.pl.md)*

## What it does

- Reads an Nginx/Apache access log file line by line.
- Checks each request path against a list of patterns for:
  - Directory traversal (`../`, `/etc/passwd`)
  - SQL injection (basic `UNION SELECT`, `OR 1=1` style payloads)
  - Requests probing for sensitive files (`.env`, `.git`, admin login pages)
  - Basic XSS (`<script>` tags)
- Counts how many `404 Not Found` responses each IP address gets, to spot IPs scanning for pages that don't exist.
- Prints a short report at the end.

No external libraries — just Python's standard library (`sys`, `re`, `collections`).

## Usage

```bash
python3 analyzer.py <path_to_log_file>
```

Example:

```bash
python3 analyzer.py sample_access.log
```

## Status

This is a learning project, not a production security tool. Detection is based on simple pattern matching and can be fooled — it's a starting point for understanding how basic intrusion detection works, not a replacement for a real WAF/IDS.
