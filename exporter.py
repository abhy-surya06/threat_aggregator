

import csv
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def ensure_output_dir(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)


def export_ip_blocklist(ioc_list: list, output_dir: str, min_severity: str = "LOW") -> str:
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = severity_rank.get(min_severity, 0)

    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, "ip_blocklist.txt")

    ips = [
        ioc["value"]
        for ioc in ioc_list
        if ioc["type"] == "ip" and severity_rank.get(ioc.get("severity", "LOW"), 0) >= min_rank
    ]

    with open(filepath, "w", encoding="utf-8") as f:
        # Header comment (informational — most firewalls ignore # lines)
        f.write(f"# IOC Aggregator — IP Blocklist\n")
        f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Minimum Severity Filter: {min_severity}\n")
        f.write(f"# Total IPs: {len(ips)}\n\n")
        for ip in ips:
            f.write(ip + "\n")

    logger.info(f"[EXPORTER] IP blocklist written: {filepath} ({len(ips)} entries)")
    return filepath


def export_domain_blocklist(ioc_list: list, output_dir: str, min_severity: str = "LOW") -> str:
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = severity_rank.get(min_severity, 0)

    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, "domain_blocklist.txt")

    domains = [
        ioc["value"]
        for ioc in ioc_list
        if ioc["type"] == "domain" and severity_rank.get(ioc.get("severity", "LOW"), 0) >= min_rank
    ]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# IOC Aggregator — Domain Blocklist\n")
        f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Minimum Severity Filter: {min_severity}\n")
        f.write(f"# Total Domains: {len(domains)}\n\n")
        for domain in domains:
            f.write(domain + "\n")

    logger.info(f"[EXPORTER] Domain blocklist written: {filepath} ({len(domains)} entries)")
    return filepath


def export_csv(ioc_list: list, output_dir: str) -> str:
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, "ioc_report.csv")

    fieldnames = ["value", "type", "severity", "feed_count", "sources"]

    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in ioc_list:
            writer.writerow({
                "value":      ioc.get("value", ""),
                "type":       ioc.get("type", ""),
                "severity":   ioc.get("severity", ""),
                "feed_count": ioc.get("feed_count", 0),
                # Join list of sources into a pipe-separated string
                "sources":    "|".join(ioc.get("sources", [])),
            })

    logger.info(f"[EXPORTER] CSV report written: {filepath}")
    return filepath


def export_json(ioc_list: list, output_dir: str) -> str:
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, "ioc_report.json")

    export_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_iocs":   len(ioc_list),
        "iocs":         ioc_list
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    logger.info(f"[EXPORTER] JSON report written: {filepath}")
    return filepath


def export_summary_report(summary: dict, output_dir: str) -> str:
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, "summary_report.txt")

    lines = [
        "=" * 55,
        "  IOC THREAT FEED AGGREGATOR - SUMMARY REPORT",
        "=" * 55,
        f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        f"  Total Unique IOCs: {summary.get('total_iocs', 0)}",
        "",
        "  --- Breakdown by IOC Type ---",
    ]

    for ioc_type, count in sorted(summary.get("by_type", {}).items()):
        lines.append(f"    {ioc_type:<20} {count:>6} entries")

    lines.append("")
    lines.append("  --- Breakdown by Severity ---")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for sev in severity_order:
        count = summary.get("by_severity", {}).get(sev, 0)
        # Build a simple bar chart with asterisks
        bar = "*" * min(count, 40)
        lines.append(f"    {sev:<10} {count:>6}  {bar}")

    lines.append("")
    lines.append("=" * 55)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"[EXPORTER] Summary report written: {filepath}")
    return filepath
