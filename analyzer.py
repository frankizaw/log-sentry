#!/usr/bin/env python3
"""
Log-Sentry: Web Access Log Security Analyzer & Triage Tool.
Detects common web attack patterns and anomalous reconnaissance activity.
"""

import sys
import re
from collections import Counter

SUSPICIOUS_PATTERNS = {
    "Directory Traversal": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"/win\.ini"],
    "SQL Injection": [r"union.*select", r"select.*from", r"'\s*or\s*'?1'?='?1", r"exec\(", r"['\")]\s*--"],
    "Sensitive Files / Recon": [r"\.env", r"\.git", r"wp-config", r"wp-login", r"phpmyadmin"],
    "Cross-Site Scripting (XSS)": [r"<script.*?>", r"javascript:", r"alert\(", r"onerror="]
}

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

def analyze_logs(file_path):
    total_requests = 0
    not_found_ips = Counter()
    detected_threats = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                match = LOG_PATTERN.match(line)
                if not match:
                    continue

                total_requests += 1
                data = match.groupdict()
                ip = data["ip"]
                path = data["path"]
                status = data["status"]

                if status == "404":
                    not_found_ips[ip] += 1

                lower_path = path.lower()
                for category, signatures in SUSPICIOUS_PATTERNS.items():
                    for sig in signatures:
                        if re.search(sig, lower_path):
                            detected_threats.append({
                                "line": line_no,
                                "ip": ip,
                                "category": category,
                                "path": path,
                                "status": status
                            })
                            break

    except FileNotFoundError:
        print(f"[-] Error: Target file '{file_path}' not found.")
        sys.exit(1)

    print("=" * 65)
    print("                 LOG-SENTRY TRIAGE REPORT               ")
    print("=" * 65)
    print(f"Total Requests Analyzed : {total_requests}")
    print(f"Threat Signatures Found : {len(detected_threats)}")
    print("-" * 65)

    print("\n[!] Detected Security Incidents & Suspicious Requests:")
    if detected_threats:
        for threat in detected_threats:
            print(f"  [Line {threat['line']}] Source IP: {threat['ip']:<15} | Category: {threat['category']}")
            print(f"      -> Path: {threat['path']} (Status: {threat['status']})")
    else:
        print("  No anomalies detected.")

    print("\n[!] Top Reconnaissance / 404 Status Probers:")
    top_scanners = not_found_ips.most_common(5)
    if top_scanners:
        for ip, count in top_scanners:
            print(f"  IP: {ip:<15} -> {count} failed requests (404)")
    else:
        print("  No 404 responses found.")
    print("=" * 65)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <path_to_access_log>")
        sys.exit(1)

    analyze_logs(sys.argv[1])