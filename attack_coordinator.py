#!/usr/bin/env python3
# attack_coordinator.py — Build attack plans from GPT-4o

import os
import openai
import sqlite3
import json
import sys
from datetime import datetime

DB_PATH = "bugbounty.db"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "projectdiscovery.io"
OUTPUT_FILE = f"workspace/{TARGET}/attack_plan.json"

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def fetch_triaged_findings():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT host, vulnerability, severity, confidence
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
            "confidence": row[3]
        })
    return findings

def ask_gpt_to_plan_attacks(findings):
    print(f"[+] Sending {len(findings)} findings to GPT-4o to generate attack plan...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert bug bounty hunter. Given a list of hosts and suspected vulnerabilities, "
                    "create an attack plan. For each host, identify how the findings could be chained together, "
                    "what tools or payloads should be used, and what indicators of success to look for. "
                    "Return JSON structured like this:\n\n"
                    "{ host, chain_description, tools, payloads, success_signals }"
                )
            },
            {
                "role": "user",
                "content": json.dumps(findings[:25])
            }
        ],
        response_format={"type": "json_object"}
    )

    content = response.choices[0].message.content.strip()
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return [data]
        return data
    except Exception as e:
        print("[!] Failed to parse GPT response:", e)
        print(content)
        return []

def save_attack_plan(plan):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(plan, f, indent=2)
    print(f"[✔] Attack plan saved to {OUTPUT_FILE}")

def main():
    findings = fetch_triaged_findings()
    if not findings:
        print("[!] No triaged findings found.")
        return

    plan = ask_gpt_to_plan_attacks(findings)
    if not plan:
        print("[!] GPT did not return an attack plan.")
        return

    save_attack_plan(plan)

if __name__ == "__main__":
    main()
