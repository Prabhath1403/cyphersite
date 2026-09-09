"""Compiled Binary Scanner module."""

from app.core.binary_scanner.scanner import BinaryScanner
from app.core.binary_scanner.format_parser import parse_binary, extract_strings, ParsedBinaryInfo
from app.core.binary_scanner.signatures import (
    SYMBOL_SIGNATURES,
    SYMBOL_PREFIX_RULES,
    STRING_PATTERNS,
    BinaryCryptoSignature,
)

__all__ = [
    "BinaryScanner",
    "parse_binary",
    "extract_strings",
    "ParsedBinaryInfo",
    "SYMBOL_SIGNATURES",
    "SYMBOL_PREFIX_RULES",
    "STRING_PATTERNS",
    "BinaryCryptoSignature",
]
