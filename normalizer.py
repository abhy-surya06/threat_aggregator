

import logging

logger = logging.getLogger(__name__)


def normalize_value(value: str, ioc_type: str) -> str:
    """
    Normalise a single IOC value based on its type.

    Rules:
      - All types: strip leading/trailing whitespace
      - IPs, domains, emails: convert to lowercase
      - Hashes: convert to lowercase (hashes are case-insensitive)
      - URLs: strip trailing slashes
      - Domains: strip leading dots
    """
    value = value.strip()

    if ioc_type in ("ip", "domain", "email", "hash_md5", "hash_sha1", "hash_sha256"):
        value = value.lower()

    if ioc_type == "domain":
        value = value.lstrip(".")  # Remove any leading dot artefacts

    if ioc_type == "url":
        value = value.rstrip("/")  # Normalise trailing slash

    return value


def normalize_and_deduplicate(ioc_list: list) -> list:
    """
    Takes a list of raw IOC dicts (from parser.py) and:
    1. Normalises each IOC value
    2. Removes exact duplicates
    3. If same IOC appears in multiple feeds, merges the source info

    Input format per IOC:
        {"value": "1.2.3.4", "type": "ip", "source": "feed_A"}

    Output format per IOC:
        {"value": "1.2.3.4", "type": "ip", "sources": ["feed_A", "feed_B"]}
    """

    # We use a dictionary keyed by (value, type) to track seen IOCs
    # This makes deduplication O(1) per IOC instead of O(n)
    seen = {}  # key: (normalised_value, type) -> index in result list
    result = []

    for ioc in ioc_list:
        raw_value  = ioc.get("value", "")
        ioc_type   = ioc.get("type", "unknown")
        source     = ioc.get("source", "unknown")

        # Skip empty values
        if not raw_value:
            continue

        # Normalise the value
        norm_value = normalize_value(raw_value, ioc_type)

        if not norm_value:
            continue

        # Create a unique key for this IOC
        dedup_key = (norm_value, ioc_type)

        if dedup_key in seen:
            # Already seen this IOC — just add the new source if not already listed
            existing = result[seen[dedup_key]]
            if source not in existing["sources"]:
                existing["sources"].append(source)
        else:
            # New IOC — add it to the result list
            seen[dedup_key] = len(result)
            result.append({
                "value":   norm_value,
                "type":    ioc_type,
                "sources": [source]
            })

    logger.info(f"[NORMALIZER] {len(ioc_list)} raw IOCs → {len(result)} unique after dedup.")
    return result
