#!/usr/bin/env python3
# roi_tracker.py — Log time spent and earnings per finding

import sqlite3
import pathlib
import sys

DB_PATH = "bugbounty.db"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "projectdiscovery.io"

def list_triaged_hosts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, host, vulnerability FROM findings WHERE target = ? ORDER BY date DESC", (TARGET,))
    rows = c.fetchall()
    conn.close()
    return rows

def update_roi(finding_id, time_spent, payout):
    hourly = round(payout / time_spent, 2) if time_spent > 0 else 0.0
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE findings
        SET time_spent = ?, payout = ?, hourly_rate = ?
        WHERE id = ?
    """, (time_spent, payout, hourly, finding_id))
    conn.commit()
    conn.close()
    return hourly

def main():
    print(f"[+] ROI Tracker for: {TARGET}\n")
    findings = list_triaged_hosts()
    if not findings:
        print("[!] No triaged findings found.")
        return

    for row in findings:
        fid, host, vuln = row
        print(f"\nID {fid} → {host}")
        print(f"  → {vuln}")
        try:
            time_spent = float(input("  Time spent (hrs): "))
            payout = float(input("  Payout received ($): "))
            rate = update_roi(fid, time_spent, payout)
            print(f"  ✅ Logged. Hourly rate: ${rate}/hr")
        except Exception as e:
            print(f"  [!] Skipped due to error: {e}")

if __name__ == "__main__":
    main()
