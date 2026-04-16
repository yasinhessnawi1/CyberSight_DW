"""
CyberSight DW -- Shared logging configuration.
Adds a RotatingFileHandler so every service writes structured logs
to a shared volume that the API service can tail.
Falls back to stdout-only if the log directory is not writable.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.environ.get("LOG_DIR", "/logs")


def setup_logging(service_name: str, level: int = logging.INFO) -> None:
    fmt = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    root = logging.getLogger()
    root.setLevel(level)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        fh = RotatingFileHandler(
            os.path.join(LOG_DIR, f"{service_name}.log"),
            maxBytes=5_000_000,
            backupCount=3,
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        root.warning(
            "Could not open log file in %s -- falling back to stdout only", LOG_DIR
        )
