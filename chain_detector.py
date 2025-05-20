#!/usr/bin/env python3
# chain_detector.py — Identify and analyze vulnerability chains for higher severity impact

import os
import openai
import sqlite3
import json
import pathlib
import sys
from datetime import datetime
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("chain_detector")

# Database configuration
DB_PATH = "bugbounty.db"

# OpenAI client initialization
try:
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except Exception as e:
    logger.error(f"Failed to initialize OpenAI client: {e}")
    sys.exit(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Detect and analyze vulnerability chains")
    parser.add_argument("target", nargs="?", default="", help="Target domain to analyze")
    parser.add_argument("--list", "-l", action="store_true", help="List available targets in database")
    parser.add_argument("--output", "-o", help="Custom output file path")
    parser.add_argument("--min-findings", "-m", type=int, default=2, 
                       help="Minimum number of findings required to analyze chains (default: 2)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def list_available_targets():
    """List all targets with findings in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT target, COUNT(*) FROM findings GROUP BY target")
    targets = cursor.fetchall()
    conn.close()
    
    if not targets:
        logger.info("No targets found in database.")
        return
    
    logger.info("\nAvailable targets:")
    for target, count in targets:
        logger.info(f"  - {target} ({count} findings)")

def fetch_all_findings(target):
    """Fetch all triaged findings for a target and group them by host."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, host, vulnerability, severity, confidence
        FROM findings
        WHERE target = ? AND status = 'triaged'
    """, (target,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        logger.info(f"No findings found for target: {target}")
        return {}

    findings_by_host = {}
    for row in rows:
        fid, host, vuln, severity, confidence = row
        if host not in findings_by_host:
            findings_by_host[host] = []
        
        findings_by_host[host].append({
            "id": fid,
            "vulnerability": vuln,
            "severity": severity,
            "confidence": confidence
        })
    
    # Filter out hosts with only one finding (can't form a chain)
    findings_by_host = {host: findings for host, findings in findings_by_host.items() 
                        if len(findings) >= args.min_findings}
    
    return findings_by_host

def analyze_vulnerability_chains(findings_by_host, target):
    """Use GPT-4o to analyze potential vulnerability chains for each host."""
    if not findings_by_host:
        logger.info("No hosts with multiple findings to analyze for chains.")
        return []
    
    logger.info(f"Analyzing potential chains across {len(findings_by_host)} hosts...")
    
    # Create system prompt for analysis
    system_prompt = """You are an expert penetration tester specializing in vulnerability chaining. 
    
    For each host with multiple vulnerabilities, analyze how they could be combined into attack chains 
    that result in higher severity impacts. Focus on realistic, practical attack chains.
    
    Consider these chain patterns:
    1. Authentication bypass + privilege escalation
    2. Information disclosure + authentication bypass
    3. XSS + CSRF + privilege escalation
    4. SSRF + internal service access + RCE
    5. SQL injection + authentication bypass + data access
    
    For each chain, provide:
    - A concise name for the chain
    - Description of how vulnerabilities connect
    - Step-by-step attack path
    - Individual findings used (include IDs)
    - Original severities of individual findings
    - Combined severity (low/medium/high/critical)
    - Technical details with specific endpoints/parameters
    - Business impact explaining the real-world consequences
    - Evidence requirements to demonstrate the chain
    
    Return JSON with an array of chain objects."""
    
    # Split hosts into smaller batches if there are many
    host_items = list(findings_by_host.items())
    batch_size = 5
    all_chains = []
    
    for i in range(0, len(host_items), batch_size):
        batch = dict(host_items[i:i+batch_size])
        logger.info(f"Processing batch {i//batch_size + 1}/{(len(host_items) + batch_size - 1)//batch_size}...")
        
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"""Analyze these vulnerabilities for {target} and identify viable chains:
                    
                    {json.dumps(batch, indent=2)}
                    
                    Focus on realistic attack chains that a real attacker could exploit.
                    Return a JSON array of chain objects, one for each viable chain you identify."""}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            content = response.choices[0].message.content.strip()
            result = json.loads(content)
            
            # Extract the chains array from the response
            chains = result.get("chains", [])
            if not chains and isinstance(result, list):
                chains = result  # Handle case where GPT returns direct array
            elif not chains and "results" in result:
                chains = result.get("results", [])
                
            all_chains.extend(chains)
            
        except Exception as e:
            logger.error(f"Error analyzing batch: {e}")
            logger.error(f"Batch data: {json.dumps(batch, indent=2)}")
    
    return all_chains

def save_chain_analysis(chains, target, output_path=None):
    """Save the chain analysis results to a JSON file."""
    if not chains:
        logger.info("No chains to save.")
        return
    
    # Determine output file path
    if output_path:
        output_file = output_path
    else:
        workspace = pathlib.Path("workspace") / target
        workspace.mkdir(parents=True, exist_ok=True)
        output_file = workspace / "chain_analysis.json"
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Save the analysis
    with open(output_file, "w") as f:
        json.dump({
            "target": target,
            "analysis_date": datetime.now().isoformat(),
            "chains": chains
        }, f, indent=2)
    
    logger.info(f"Chain analysis saved to {output_file}")
    return output_file

def update_database_with_chains(chains, target):
    """Update the database with identified vulnerability chains."""
    if not chains:
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if chains table exists, create if not
    c.execute("""
    CREATE TABLE IF NOT EXISTS chains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        host TEXT,
        name TEXT,
        description TEXT,
        finding_ids TEXT,
        original_severities TEXT,
        combined_severity TEXT,
        technical_details TEXT,
        business_impact TEXT,
        evidence_requirements TEXT,
        date_identified TEXT
    )
    """)
    
    # Insert each chain into the database
    count = 0
    for chain in chains:
        try:
            finding_ids = ','.join([str(f) for f in chain.get("finding_ids", [])])
            original_severities = ','.join(chain.get("original_severities", []))
            
            c.execute("""
                INSERT INTO chains (
                    target, host, name, description, finding_ids, 
                    original_severities, combined_severity, technical_details,
                    business_impact, evidence_requirements, date_identified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target,
                chain.get("host", ""),
                chain.get("name", ""),
                chain.get("description", ""),
                finding_ids,
                original_severities,
                chain.get("combined_severity", ""),
                chain.get("technical_details", ""),
                chain.get("business_impact", ""),
                chain.get("evidence_requirements", ""),
                datetime.now().isoformat()
            ))
            count += 1
        except Exception as e:
            logger.error(f"Error saving chain to database: {e}")
            logger.error(f"Chain data: {json.dumps(chain, indent=2)}")
    
    conn.commit()
    conn.close()
    return count

def generate_markdown_report(chains, target, output_file=None):
    """Generate a Markdown report with the chain analysis results."""
    if not chains:
        return None
    
    # Determine output file path for the report
    if output_file:
        report_path = pathlib.Path(output_file).with_suffix('.md')
    else:
        workspace = pathlib.Path("workspace") / target
        report_path = workspace / "chain_analysis_report.md"
    
    # Generate report content
    report = f"""# Vulnerability Chain Analysis for {target}
    
*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

## Summary

This report identifies {len(chains)} potential vulnerability chains that could be leveraged for increased impact. Each chain combines multiple lower-severity findings into a higher-severity attack path.

## Identified Chains

"""
    
    # Add each chain to the report
    for i, chain in enumerate(chains, 1):
        report += f"""### Chain {i}: {chain.get('name', 'Unnamed Chain')}

**Host:** {chain.get('host', 'Unknown')}  
**Combined Severity:** {chain.get('combined_severity', 'Unknown')}

**Description:**  
{chain.get('description', 'No description provided.')}

**Attack Path:**  
{chain.get('attack_path', 'No attack path provided.')}

**Technical Details:**  
{chain.get('technical_details', 'No technical details provided.')}

**Business Impact:**  
{chain.get('business_impact', 'No business impact provided.')}

**Evidence Requirements:**  
{chain.get('evidence_requirements', 'No evidence requirements provided.')}

**Component Vulnerabilities:**  
{', '.join([f"Finding #{id} ({sev})" for id, sev in zip(chain.get('finding_ids', []), chain.get('original_severities', []))])}

---

"""
    
    # Save the report
    with open(report_path, "w") as f:
        f.write(report)
    
    logger.info(f"Chain analysis report saved to {report_path}")
    return report_path

def analyze_chain_roi(chains):
    """Analyze ROI potential for identified chains."""
    if not chains:
        return
    
    # Simple ROI analysis based on severity
    severity_values = {
        "low": {"min": 50, "max": 250},
        "medium": {"min": 250, "max": 1500},
        "high": {"min": 1500, "max": 5000},
        "critical": {"min": 5000, "max": 25000}
    }
    
    logger.info("\nChain ROI Analysis:")
    logger.info("-" * 50)
    logger.info(f"{'Chain':<20} {'Severity':<10} {'Est. Value':<15}")
    logger.info("-" * 50)
    
    for i, chain in enumerate(chains, 1):
        severity = chain.get("combined_severity", "").lower()
        if severity in severity_values:
            min_val = severity_values[severity]["min"]
            max_val = severity_values[severity]["max"]
            logger.info(f"Chain {i:<16} {severity.capitalize():<10} ${min_val}-${max_val}")
        else:
            logger.info(f"Chain {i:<16} Unknown     N/A")
    
    logger.info("-" * 50)

def main():
    global args
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # List available targets if requested
    if args.list:
        list_available_targets()
        return 0
    
    # Validate target
    target = args.target
    if not target:
        logger.error("No target specified. Use --list to see available targets.")
        return 1
    
    # Fetch findings from database
    findings_by_host = fetch_all_findings(target)
    if not findings_by_host:
        return 1
    
    # Analyze vulnerability chains
    chains = analyze_vulnerability_chains(findings_by_host, target)
    if not chains:
        logger.info("No viable vulnerability chains identified.")
        return 0
    
    # Save chain analysis
    output_file = save_chain_analysis(chains, target, args.output)
    
    # Update database
    count = update_database_with_chains(chains, target)
    logger.info(f"Added {count} chains to database.")
    
    # Generate markdown report
    report_path = generate_markdown_report(chains, target, args.output)
    
    # Analyze ROI potential
    analyze_chain_roi(chains)
    
    logger.info(f"\n[✓] Chain analysis complete! Identified {len(chains)} potential chains.")
    logger.info(f"    JSON saved to: {output_file}")
    if report_path:
        logger.info(f"    Report saved to: {report_path}")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
