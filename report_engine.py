#!/usr/bin/env python3
# report_engine.py — Generate Markdown report for bug bounty submission

import os
import openai
import sqlite3
import pathlib
from datetime import datetime

# === CONFIG ===
TARGET = "projectdiscovery.io"
WORKSPACE = pathlib.Path("workspace") / TARGET
DB_PATH = "bugbounty.db"
POC_DIR = WORKSPACE / "poc"
REPORTS_DIR = WORKSPACE / "reports"

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def fetch_verified_findings():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT host, vulnerability, severity, confidence, date
        FROM findings
        WHERE target = ? AND status = 'triaged'
    """, (TARGET,))
    rows = cursor.fetchall()
    conn.close()

    findings = []
    for row in rows:
        findings.append({
            "host": row[0],
            "vulnerability": row[1],
            "severity": row[2],
            "confidence": row[3],
            "date": row[4]
        })
    return findings

def load_poc_for_host(host):
    filename = f"poc_{host.replace('https://', '').replace('/', '_')}.md"
    path = POC_DIR / filename
    if path.exists():
        with open(path, "r") as f:
            return f.read()
    return "(No PoC file found for this host)"

def ask_gpt_for_report(finding, poc):
    print(f"[+] Generating report for {finding['host']}")
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert bug bounty report writer. Create a detailed and concise HackerOne-style report "
                "using the following structure:\n\n"
                "# Vulnerability Report\n"
                "## Affected Host\n"
                "## Summary\n"
                "## Steps to Reproduce\n"
                "## Impact\n"
                "## PoC\n"
                "## Recommended Remediation\n"
            )
        },
        {
            "role": "user",
            "content": (
                f"Host: {finding['host']}\n"
                f"Vulnerability: {finding['vulnerability']}\n"
                f"Severity: {finding['severity']}\n"
                f"Confidence: {finding['confidence']}\n"
                f"Date Triaged: {finding['date']}\n"
                f"PoC:\n{poc}"
            )
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        response_format={"type": "text"}
    )

    return response.choices[0].message.content.strip()

def save_report(host, content):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"report_{host.replace('https://', '').replace('/', '_')}.md"
    path = REPORTS_DIR / filename
    with open(path, "w") as f:
        f.write(content)
    print(f"[✔] Report saved to {path}")

def main():
    findings = fetch_verified_findings()
    if not findings:
        print("[!] No triaged findings found to report.")
        return

    for finding in findings:
        poc = load_poc_for_host(finding['host'])
        try:
            report = ask_gpt_for_report(finding, poc)
            save_report(finding['host'], report)
        except Exception as e:
            print(f"[!] Failed to generate report for {finding['host']}: {e}")

if __name__ == "__main__":
    main()
