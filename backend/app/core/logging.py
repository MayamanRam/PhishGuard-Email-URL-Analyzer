"""Project-Level Logging Configuration for PhishGuard.

Provides structured, safe console and file logging.
"""

import logging
import sys
from pathlib import Path


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure and return the root logger for PhishGuard."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    log_format = (
        "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s"
    )
    date_format = "%Y-%m-%dT%H:%M:%SZ"

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    logger = logging.getLogger("phishguard")
    logger.setLevel(numeric_level)
    return logger


logger = logging.getLogger("phishguard")

