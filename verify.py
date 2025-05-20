#!/usr/bin/env python3
# verify.py — Generate AI-assisted PoCs from attack_plan.json

import os
import json
import openai
import pathlib
from datetime import datetime

# === CONFIG ===
TARGET = "projectdiscovery.io"  # You can make this dynamic later
WORKSPACE = pathlib.Path("workspace") / TARGET
PLAN_FILE = WORKSPACE / "attack_plan.json"
POC_DIR = WORKSPACE / "poc"
EVIDENCE_DIR = WORKSPACE / "evidence"

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def load_attack_plan(path):
    with open(path, "r") as f:
        return json.load(f)

def ask_gpt_for_poc(entry):
    print(f"[+] Generating PoC for {entry['host']}")
    messages = [
        {
            "role": "system",
            "content": (
                "You are a senior penetration tester. Given a target, vulnerability description, payloads, "
                "and suggested tools, generate a step-by-step proof of concept (PoC). "
                "Respond in this Markdown structure:\n\n"
                "# PoC for <host>\n"
                "## Summary\n"
                "- Chain: <chain_description>\n"
                "- Tools: <tools>\n"
                "- Payloads: <payloads>\n"
                "## Steps\n"
                "1. <Step-by-step instructions>\n"
                "2. Include curl commands or requests snippets\n"
                "## Success Signals\n"
                "- Describe what to look for to confirm success"
            )
        },
        {
            "role": "user",
            "content": json.dumps({
                "host": entry["host"],
                "vulnerability": entry["chain_description"],
                "tools": entry.get("tools", []),
                "payloads": entry.get("payloads", []),
                "success_signals": entry.get("success_signals", [])
            })
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        response_format={"type": "text"}
    )
    return response.choices[0].message.content.strip()

def save_poc_file(host, content):
    os.makedirs(POC_DIR, exist_ok=True)
    filename = f"poc_{host.replace('https://', '').replace('/', '_')}.md"
    path = POC_DIR / filename
    with open(path, "w") as f:
        f.write(content)
    print(f"[✔] Saved PoC to {path}")

def main():
    if not PLAN_FILE.exists():
        print("[!] No attack plan found.")
        return

    attack_plan = load_attack_plan(PLAN_FILE)
    for entry in attack_plan:
        try:
            poc = ask_gpt_for_poc(entry)
            save_poc_file(entry['host'], poc)
        except Exception as e:
            print(f"[!] Failed to generate PoC for {entry['host']}: {e}")

if __name__ == "__main__":
    main()
