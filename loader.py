"""
loader.py - Feed Loader Module
--------------------------------
This module is responsible for loading threat feed content
from either a URL (online feed) or a local file path.

It acts as the "input layer" of the pipeline.
Think of it like a librarian: you give it an address,
it fetches the book (threat data) for you.
"""

import requests  # For fetching data from URLs
import logging   # For writing log messages during execution

# Set up a logger specifically for this module
logger = logging.getLogger(__name__)


def load_feed(source: str, timeout: int = 10) -> str:
    """
    Load raw text content from a URL or a local file.

    Parameters:
        source (str): A URL starting with 'http' or a local file path.
        timeout (int): How many seconds to wait before giving up on a URL.

    Returns:
        str: The raw text content of the feed, or an empty string on failure.
    """

    # ---- Case 1: The source is a URL ----
    if source.startswith("http://") or source.startswith("https://"):
        try:
            logger.info(f"[LOADER] Fetching URL: {source}")
            response = requests.get(source, timeout=timeout)

            # raise_for_status() will throw an error if HTTP status != 200
            response.raise_for_status()

            logger.info(f"[LOADER] Successfully fetched {len(response.text)} characters from URL.")
            return response.text

        except requests.exceptions.Timeout:
            logger.error(f"[LOADER] Timeout while fetching: {source}")
        except requests.exceptions.ConnectionError:
            logger.error(f"[LOADER] Connection error for: {source}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"[LOADER] HTTP error {e} for: {source}")
        except Exception as e:
            logger.error(f"[LOADER] Unexpected error fetching URL {source}: {e}")

    # ---- Case 2: The source is a local file path ----
    else:
        try:
            logger.info(f"[LOADER] Reading local file: {source}")
            with open(source, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            logger.info(f"[LOADER] Read {len(content)} characters from file.")
            return content

        except FileNotFoundError:
            logger.error(f"[LOADER] File not found: {source}")
        except PermissionError:
            logger.error(f"[LOADER] Permission denied reading: {source}")
        except Exception as e:
            logger.error(f"[LOADER] Unexpected error reading file {source}: {e}")

    # If anything went wrong, return empty string (safe fallback)
    return ""
