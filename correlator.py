"""
correlator.py - IOC Correlation & Severity Scoring Module
-----------------------------------------------------------
Once we have a clean, deduplicated list of IOCs, we want to
"score" each one. The idea: if an IP appears in 3 different
threat feeds, it's more suspicious than one appearing in just 1.

This module assigns a severity level to each IOC based on
how many independent sources reported it.

Severity scale used:
  - 1 source  → LOW
  - 2 sources → MEDIUM
  - 3+ sources → HIGH
  - Any IOC seen in 5+ sources → CRITICAL
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


# Severity thresholds — easy to change for tuning
SEVERITY_MAP = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
}
CRITICAL_THRESHOLD = 5  # 5 or more sources = CRITICAL


def assign_severity(source_count: int) -> str:
    """
    Assign a severity label based on how many feeds reported this IOC.

    Args:
        source_count (int): Number of unique feeds that reported this IOC.

    Returns:
        str: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
    """
    if source_count >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    return SEVERITY_MAP.get(source_count, "HIGH")  # >3 defaults to HIGH


def correlate(ioc_list: list) -> list:
    """
    Enrich each IOC in the list with:
      - feed_count: how many unique feeds reported it
      - severity: computed from feed_count

    Input: list of normalised IOC dicts (from normalizer.py)
    Output: same list with 'feed_count' and 'severity' added to each dict.
    """

    # Summary stats for logging
    severity_counts = defaultdict(int)

    enriched = []
    for ioc in ioc_list:
        sources    = ioc.get("sources", [])
        feed_count = len(sources)
        severity   = assign_severity(feed_count)

        # Add correlation fields
        enriched_ioc = {**ioc, "feed_count": feed_count, "severity": severity}
        enriched.append(enriched_ioc)
        severity_counts[severity] += 1

    # Log a summary breakdown
    logger.info(f"[CORRELATOR] Severity breakdown: {dict(severity_counts)}")
    logger.info(f"[CORRELATOR] Total correlated IOCs: {len(enriched)}")

    # Sort: CRITICAL → HIGH → MEDIUM → LOW (most dangerous first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    enriched.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return enriched


def generate_summary_report(ioc_list: list) -> dict:
    """
    Build a summary dictionary suitable for writing a report.

    Returns a dict with total counts per type and per severity.
    """
    report = {
        "total_iocs": len(ioc_list),
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
    }

    for ioc in ioc_list:
        report["by_type"][ioc.get("type", "unknown")] += 1
        report["by_severity"][ioc.get("severity", "UNKNOWN")] += 1

    # Convert defaultdicts to regular dicts for clean output
    report["by_type"]     = dict(report["by_type"])
    report["by_severity"] = dict(report["by_severity"])

    return report
