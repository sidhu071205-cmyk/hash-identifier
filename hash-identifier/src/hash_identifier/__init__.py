"""
hash_identifier — identify hash types by prefix, length, and shape.
"""

from .core import identify, HashCandidate
from .formatter import format_table, format_json

__all__ = ["identify", "HashCandidate", "format_table", "format_json"]
__version__ = "1.0.0"
