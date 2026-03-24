"""
Logging utility for BugScanner.
Provides structured, colour-coded console + file logging.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.logging import RichHandler

_configured = False


def setup_logger(verbose: bool = False, log_file: str | None = None) -> None:
    """
    Configure root logger with Rich console handler and optional file handler.
    Call this once at startup.
    """
    global _configured
    if _configured:
        return

    level = logging.DEBUG if verbose else logging.INFO

    handlers: list[logging.Handler] = [
        RichHandler(
            rich_tracebacks=True,
            show_path=False,
            markup=True,
        )
    ]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
        handlers.append(fh)
    else:
        # Always write a debug log alongside reports
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = Path("./reports/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / f"bugscanner_{ts}.log", encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
        fh.setLevel(logging.DEBUG)
        handlers.append(fh)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "chardet", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger (call setup_logger first)."""
    return logging.getLogger(name)
