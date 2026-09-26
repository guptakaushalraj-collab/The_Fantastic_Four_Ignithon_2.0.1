"""Shared helpers for the command-line entry points.

They make the CLIs behave the same on Windows as on Linux and macOS: output is
always UTF-8 (the reports contain ₹ and →, which a Windows console can't encode),
and input files are read whatever encoding PowerShell's ``>`` gave them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def setup_io() -> None:
    """Write UTF-8 to stdout and stderr, and read stdin as UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8-sig", errors="replace")


def decode(data: bytes) -> str:
    """Decode text written as UTF-8 (with or without a BOM) or UTF-16.

    Windows PowerShell 5 writes UTF-16 when output is redirected with ``>``.
    """
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def read_text(path: Path) -> str:
    return decode(path.read_bytes())


def check_files(parser: argparse.ArgumentParser, *paths: Path | None) -> None:
    """Stop with a one-line message, not a traceback, when an input file is missing."""
    for path in paths:
        if path is None:
            continue
        if not path.exists():
            parser.error(f"file not found: {path}")
        if path.is_dir():
            parser.error(f"{path} is a folder; give the file inside it")
