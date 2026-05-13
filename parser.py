"""
parser.py - IOC Extraction / Parsing Module
--------------------------------------------
This module extracts Indicators of Compromise (IOCs) from raw text.
It uses regular expressions (regex) to find IPs, domains, URLs,
file hashes, and email addresses.

Think of it as the "detector" in the pipeline:
it reads raw data and spots the suspicious patterns.
"""

import re           # Python's built-in regex library
import ipaddress    # Python's built-in module to validate IP addresses
import logging

logger = logging.getLogger(__name__)


# ============================================================
# REGEX PATTERNS - These are the "detection rules"
# ============================================================

# IPv4 address pattern: matches things like 192.168.1.1
# \b = word boundary (avoids matching partial numbers)
IP_PATTERN = re.compile(
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
)

# Domain pattern: matches things like evil.com, sub.domain.org
# Avoids matching IPs (no 4 pure-number segments)
# Requires at least a 2-letter TLD (top-level domain)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:[a-zA-Z]{2,})\b'
)

# URL pattern: matches http/https URLs
URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>\[\]]+',
    re.IGNORECASE
)

# Hash patterns for common malware file hashes
MD5_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Email address pattern
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)


# ============================================================
# VALIDATION HELPERS
# ============================================================

def is_valid_ip(ip_str: str) -> bool:
    """
    Validate an IP string using Python's ipaddress module.
    Also rejects private/loopback IPs (they aren't real threats).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Skip private ranges (10.x.x.x, 192.168.x.x, etc.)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Basic domain sanity check.
    Rejects domains that look like IPs (all numeric segments).
    """
    parts = domain.split(".")
    # Reject if all parts are numeric (it's an IP, not a domain)
    if all(p.isdigit() for p in parts):
        return False
    # Must have at least 2 parts (e.g., "evil.com")
    if len(parts) < 2:
        return False
    return True


# ============================================================
# EXTRACTION FUNCTIONS
# ============================================================

def extract_ips(text: str) -> list:
    """Find all valid IPv4 addresses in the given text."""
    candidates = IP_PATTERN.findall(text)
    valid = [ip for ip in candidates if is_valid_ip(ip)]
    logger.debug(f"[PARSER] Extracted {len(valid)} valid IPs.")
    return valid


def extract_domains(text: str, extracted_ips: list = None) -> list:
    """
    Find domain names in text.
    We pass in already-found IPs to avoid re-labeling them as domains.
    """
    ip_set = set(extracted_ips or [])
    candidates = DOMAIN_PATTERN.findall(text)
    valid = []
    for d in candidates:
        d_clean = d.lower().strip(".")
        # Skip if it's actually an IP address
        if d_clean in ip_set:
            continue
        if is_valid_domain(d_clean):
            valid.append(d_clean)
    logger.debug(f"[PARSER] Extracted {len(valid)} domains.")
    return valid


def extract_urls(text: str) -> list:
    """Find all HTTP/HTTPS URLs in text."""
    urls = URL_PATTERN.findall(text)
    logger.debug(f"[PARSER] Extracted {len(urls)} URLs.")
    return urls


def extract_hashes(text: str) -> dict:
    """
    Find file hashes (MD5, SHA1, SHA256) in text.
    Returns a dict with keys 'md5', 'sha1', 'sha256'.
    We check longest first to avoid a SHA256 being matched as MD5.
    """
    # Remove all SHA256 matches from the text before looking for shorter hashes
    sha256_matches = SHA256_PATTERN.findall(text)
    text_no256 = SHA256_PATTERN.sub("", text)

    sha1_matches = SHA1_PATTERN.findall(text_no256)
    text_no_sha1 = SHA1_PATTERN.sub("", text_no256)

    md5_matches = MD5_PATTERN.findall(text_no_sha1)

    logger.debug(f"[PARSER] Hashes — MD5: {len(md5_matches)}, SHA1: {len(sha1_matches)}, SHA256: {len(sha256_matches)}")
    return {
        "md5":    [h.lower() for h in md5_matches],
        "sha1":   [h.lower() for h in sha1_matches],
        "sha256": [h.lower() for h in sha256_matches],
    }


def extract_emails(text: str) -> list:
    """Find email addresses in text."""
    emails = EMAIL_PATTERN.findall(text)
    logger.debug(f"[PARSER] Extracted {len(emails)} emails.")
    return emails


# ============================================================
# MAIN PARSE FUNCTION
# ============================================================

def parse_feed(raw_text: str, feed_name: str = "unknown") -> list:
    """
    Run all extraction functions on the raw feed text.
    Returns a flat list of IOC dictionaries.

    Each IOC looks like:
    {
        "value": "1.2.3.4",
        "type":  "ip",
        "source": "feed_name"
    }
    """
    if not raw_text:
        logger.warning(f"[PARSER] Empty content for feed: {feed_name}")
        return []

    iocs = []

    # --- Extract IPs ---
    ips = extract_ips(raw_text)
    for ip in ips:
        iocs.append({"value": ip, "type": "ip", "source": feed_name})

    # --- Extract Domains (exclude already-found IPs) ---
    domains = extract_domains(raw_text, extracted_ips=ips)
    for domain in domains:
        iocs.append({"value": domain, "type": "domain", "source": feed_name})

    # --- Extract URLs ---
    urls = extract_urls(raw_text)
    for url in urls:
        iocs.append({"value": url, "type": "url", "source": feed_name})

    # --- Extract Hashes ---
    hashes = extract_hashes(raw_text)
    for h in hashes["md5"]:
        iocs.append({"value": h, "type": "hash_md5", "source": feed_name})
    for h in hashes["sha1"]:
        iocs.append({"value": h, "type": "hash_sha1", "source": feed_name})
    for h in hashes["sha256"]:
        iocs.append({"value": h, "type": "hash_sha256", "source": feed_name})

    # --- Extract Emails ---
    emails = extract_emails(raw_text)
    for email in emails:
        iocs.append({"value": email, "type": "email", "source": feed_name})

    logger.info(f"[PARSER] Total IOCs extracted from '{feed_name}': {len(iocs)}")
    return iocs
