
import argparse
import logging
import sys
import yaml  # pip install pyyaml (or use json if preferred)

from loader     import load_feed
from parser     import parse_feed
from normalizer import normalize_and_deduplicate
from correlator import correlate, generate_summary_report
from exporter   import (
    export_ip_blocklist,
    export_domain_blocklist,
    export_csv,
    export_json,
    export_summary_report,
)


# ============================================================
# LOGGING SETUP
# ============================================================

def setup_logging(log_level: str = "INFO"):
    """
    Configure logging to write to both the console and a log file.
    This is important in a SOC environment so you have an audit trail.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),             # Console output
            logging.FileHandler("ioc_aggregator.log"),     # File output
        ]
    )


# ============================================================
# CONFIG LOADING
# ============================================================

def load_config(config_path: str) -> dict:
    """
    Load the YAML configuration file.
    Falls back gracefully if the file is missing.
    """
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        logging.info(f"[MAIN] Config loaded from: {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"[MAIN] Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"[MAIN] YAML parse error in config: {e}")
        sys.exit(1)


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline(config: dict):
    """
    Execute the full IOC aggregation pipeline.
    """
    feeds      = config.get("feeds", [])
    output_cfg = config.get("output", {})
    output_dir = output_cfg.get("directory", "output")
    min_sev    = output_cfg.get("min_severity", "LOW")

    if not feeds:
        logging.warning("[MAIN] No feeds defined in config. Nothing to process.")
        return

    all_raw_iocs = []

    # ---- STEP 1 & 2: Load + Parse each feed ----
    for feed in feeds:
        name    = feed.get("name", "unnamed_feed")
        source  = feed.get("source", "")
        enabled = feed.get("enabled", True)

        if not enabled:
            logging.info(f"[MAIN] Skipping disabled feed: {name}")
            continue

        if not source:
            logging.warning(f"[MAIN] Feed '{name}' has no source defined. Skipping.")
            continue

        logging.info(f"[MAIN] Processing feed: {name}")

        # Load raw content from URL or file
        raw_text = load_feed(source)

        if not raw_text:
            logging.warning(f"[MAIN] No content loaded for feed: {name}")
            continue

        # Extract IOCs from the raw text
        iocs = parse_feed(raw_text, feed_name=name)
        all_raw_iocs.extend(iocs)
        logging.info(f"[MAIN] Feed '{name}' contributed {len(iocs)} raw IOCs.")

    logging.info(f"[MAIN] Total raw IOCs from all feeds: {len(all_raw_iocs)}")

    # ---- STEP 3: Normalise + Deduplicate ----
    unique_iocs = normalize_and_deduplicate(all_raw_iocs)

    # ---- STEP 4: Correlate + Score ----
    correlated_iocs = correlate(unique_iocs)

    # ---- STEP 5: Export ----
    formats = output_cfg.get("formats", ["ip_blocklist", "domain_blocklist", "csv", "json", "summary"])

    if "ip_blocklist" in formats:
        export_ip_blocklist(correlated_iocs, output_dir, min_severity=min_sev)

    if "domain_blocklist" in formats:
        export_domain_blocklist(correlated_iocs, output_dir, min_severity=min_sev)

    if "csv" in formats:
        export_csv(correlated_iocs, output_dir)

    if "json" in formats:
        export_json(correlated_iocs, output_dir)

    if "summary" in formats:
        summary = generate_summary_report(correlated_iocs)
        export_summary_report(summary, output_dir)

    logging.info("[MAIN] Pipeline complete. Outputs saved to: " + output_dir)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    # Parse command-line arguments
    arg_parser = argparse.ArgumentParser(
        description="IOC Threat Feed Aggregator — Cybersecurity Tool"
    )
    arg_parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file (default: config.yaml)"
    )
    arg_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)"
    )
    args = arg_parser.parse_args()

    # Set up logging first
    setup_logging(args.log_level)

    # Load config and run the pipeline
    config = load_config(args.config)
    run_pipeline(config)
