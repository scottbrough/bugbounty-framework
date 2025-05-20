#!/usr/bin/env python3
# discover.py — Automated asset discovery (passive + active)

import os, subprocess, pathlib, sys
from concurrent.futures import ThreadPoolExecutor

# Input: target domain
TARGET = sys.argv[1] if len(sys.argv) > 1 else "example.com"
OUT = pathlib.Path("workspace") / TARGET
OUT.mkdir(parents=True, exist_ok=True)

def run(cmd):
    print(f"[+] Running: {cmd}")
    subprocess.run(cmd, shell=True)

def run_passive_enum():
    cmds = [
        f"subfinder -d {TARGET} -all -o {OUT/'subfinder.txt'}",
        f"assetfinder --subs-only {TARGET} > {OUT/'assetfinder.txt'}",
        f"amass enum -passive -d {TARGET} -o {OUT/'amass_passive.txt'}",
        f"github-subdomains -d {TARGET} -o {OUT/'github_subs.txt'}"
    ]
    with ThreadPoolExecutor() as pool:
        pool.map(run, cmds)

def run_active_enum():
    cmds = [
        f"amass enum -active -d {TARGET} -o {OUT/'amass_active.txt'}",
        f"dnsx -d {TARGET} -w ~/wordlists/subdomains-top10000.txt -o {OUT/'dnsx_brute.txt'}",
        f"ffuf -u https://FUZZ.{TARGET} -w ~/wordlists/subdomains-top10000.txt -o {OUT/'ffuf_vhost.json'}"
    ]
    with ThreadPoolExecutor() as pool:
        pool.map(run, cmds)

def probe_live_hosts():
    combined = OUT / "all_subs.txt"
    with open(combined, "w") as f:
        for file in OUT.glob("*.txt"):
            f.write(open(file).read())
    os.system(f"cat {combined} | sort -u | httpx -silent -o {OUT/'live_hosts.txt'}")

def main():
    run_passive_enum()
    run_active_enum()
    probe_live_hosts()
    print("[✔] Discovery complete.")

if __name__ == "__main__":
    main()
