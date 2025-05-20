#!/usr/bin/env python3
# ai_triage.py — GPT-4o triage for bug bounty recon (OpenAI v1.x compatible + error-handled)

import os
import openai
import sqlite3
import json
import pathlib
import sys
from datetime import datetime

# === CONFIG ===
TARGET = sys.argv[1] if len(sys.argv) > 1 else "projectdiscovery.io"
WORKSPACE = pathlib.Path("workspace") / TARGET
DB_PATH = "bugbounty.db"
LIVE_HOSTS_FILE = WORKSPACE / "live_hosts.txt"

# ✅ OpenAI Client (v1.x)
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def load_hosts(path):
    with open(path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def create_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        host TEXT,
        vulnerability TEXT,
        severity TEXT,
        confidence REAL,
        date TEXT,
        status TEXT
    )""")
    conn.commit()
    conn.close()

def triage_targets(hosts):
    print(f"[+] Sending {len(hosts)} hosts to GPT-4o...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    f"You are an elite bug bounty triage assistant. "
                    f"Analyze this list of live hosts for {TARGET}. "
                    "Prioritize which targets are most likely to yield valuable vulnerabilities. "
                    "For each, return JSON with: host, likely_vuln, severity (low/med/high), "
                    "confidence (0-1), and recommend one test/tool."
                )
            },
            {
                "role": "user",
                "content": json.dumps(hosts[:20])
            }
        ],
        response_format={"type": "json_object"}
    )

    # Decode GPT JSON safely
    content = response.choices[0].message.content.strip()
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return [data]  # Single object
        return data  # Already a list
    except Exception as e:
        print("[!] Failed to parse GPT response:", e)
        print(content)
        return []

def save_findings(prioritized):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for item in prioritized:
        try:
            c.execute("""
                INSERT INTO findings (target, host, vulnerability, severity, confidence, date, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                TARGET,
                item['host'],
                item['likely_vuln'],
                item['severity'],
                float(item['confidence']),
                datetime.now().isoformat(),
                'triaged'
            ))
        except Exception as err:
            print(f"[!] Error saving item {item}: {err}")
    conn.commit()
    conn.close()

def main():
    create_db()
    hosts = load_hosts(LIVE_HOSTS_FILE)
    if not hosts:
        print("[!] No hosts found in live_hosts.txt.")
        return
    prioritized = triage_targets(hosts)
    if not prioritized:
        print("[!] No prioritized results to save.")
        return
    save_findings(prioritized)
    print(f"[✔] Triage complete. Saved {len(prioritized)} entries to bugbounty.db")

if __name__ == "__main__":
    main()
