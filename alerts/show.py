#!/usr/bin/env python3
"""
alerts/show.py
Terminal alert viewer CLI for PROVBIND Role 4.
Displays color-coded alerts categorized by severity bucket for live demo presentation.
"""

import os
import sys
import json
import argparse

class Colors:
    CRITICAL = "\033[91m\033[1m"  # Bold Red
    HIGH     = "\033[93m\033[1m"  # Bold Yellow
    MEDIUM   = "\033[94m"         # Blue
    LOW      = "\033[92m"         # Green
    RESET    = "\033[0m"
    BOLD     = "\033[1m"

def format_alert(alert):
    bucket = alert.get("bucket", "low").upper()
    score = alert.get("score", 0)
    alert_id = alert.get("alert_id", "alr-????")
    chain_id = alert.get("chain_id", "chain-????")
    time_str = alert.get("time", "")
    container = alert.get("container", "")
    cls = alert.get("class", "")
    subcls = alert.get("subclass", "")
    violated = alert.get("violated_clause", "")
    
    attr = alert.get("attribution", {})
    layer = attr.get("layer") or "Side-Loaded (No Layer)"
    proc_chain = " -> ".join(attr.get("process_chain", []))

    signing = alert.get("signing_identity", {})
    builder = signing.get("builder_id", "unknown")
    commit = signing.get("source_commit", "unknown")

    if bucket == "CRITICAL":
        color = Colors.CRITICAL
    elif bucket == "HIGH":
        color = Colors.HIGH
    elif bucket == "MEDIUM":
        color = Colors.MEDIUM
    else:
        color = Colors.LOW

    output = f"{color}[{bucket} - Score {score}]{Colors.RESET} {Colors.BOLD}{alert_id}{Colors.RESET} (Chain: {chain_id})\n"
    output += f"  🕒 Time:      {time_str}\n"
    output += f"  📦 Container: {container}\n"
    output += f"  ⚡ Deviation: {cls} ({subcls})\n"
    output += f"  📜 Violated:  {violated}\n"
    output += f"  🔍 Layer:     {layer}\n"
    output += f"  🔗 Lineage:   {proc_chain}\n"
    output += f"  🔏 Provenance: Builder={builder} | Commit={commit}\n"
    output += f"  🔒 Merkle Leaf: Log Index k={alert.get('log_k')}\n"
    output += "-" * 60
    return output

def main():
    parser = argparse.ArgumentParser(description="PROVBIND Live Alert Viewer")
    parser.add_argument("--run", default="./run", help="Path to run directory")
    args = parser.parse_args()

    alerts_file = os.path.join(args.run, "alerts.jsonl")
    print(f"{Colors.BOLD}============================================================{Colors.RESET}")
    print(f"{Colors.BOLD}🛡️  PROVBIND CONTINUOUS INTEGRITY VERIFICATION - ALERTS LIVE VIEW{Colors.RESET}")
    print(f"{Colors.BOLD}============================================================{Colors.RESET}\n")

    if not os.path.exists(alerts_file):
        print(f"Waiting for alerts in {alerts_file}...")
        sys.exit(0)

    count = 0
    with open(alerts_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
                try:
                    alert = json.loads(line)
                    print(format_alert(alert))
                except json.JSONDecodeError:
                    continue

    print(f"\nTotal Alerts Displayed: {count}")

if __name__ == "__main__":
    main()
