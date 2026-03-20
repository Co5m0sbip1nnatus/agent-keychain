"""
Agent Keychain Logger
Structured logging that never includes secret values.
"""

import logging
import os

LOG_DIR = os.path.expanduser("~/.agent-keychain")
LOG_FILE = os.path.join(LOG_DIR, "agent-keychain.log")


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with file and console handlers."""
    logger = logging.getLogger(f"agent-keychain.{name}")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File handler — detailed logs
    os.makedirs(LOG_DIR, exist_ok=True)
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # Console handler — warnings and above only
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(ch)

    return logger
