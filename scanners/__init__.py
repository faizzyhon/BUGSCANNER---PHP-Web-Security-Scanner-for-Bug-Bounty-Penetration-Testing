"""Scanner modules package — one module per vulnerability class."""

from .base import BaseScanner, Finding

__all__ = ["BaseScanner", "Finding"]
