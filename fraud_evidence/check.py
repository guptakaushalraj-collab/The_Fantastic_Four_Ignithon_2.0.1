"""Check that this machine can run the whole pipeline.

    python -m fraud_evidence.check

Prints one line per requirement with how to fix anything missing, and exits
with status 1 if something the sample case needs is absent.
"""

from __future__ import annotations

import importlib
import subprocess
import sys

from .cli import setup_io
from .ingestion.ocr import TESSERACT_HELP, find_tesseract

PACKAGES = [
    # (import name, pip name, needed for)
    ("PIL", "pillow", "screenshots"),
    ("pytesseract", "pytesseract", "screenshots"),
    ("pdfplumber", "pdfplumber", "PDF evidence"),
    ("pytest", "pytest", "running the tests"),
    ("jsonschema", "jsonschema", "7 schema tests (optional)"),
]
OPTIONAL = {"jsonschema"}


def _import(name: str) -> str | None:
    """None if the package imports, else why it doesn't."""
    try:
        importlib.import_module(name)
        return None
    except ImportError:
        return "not installed: pip install -r requirements.txt"
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # a broken 'cryptography' install panics inside pdfplumber
        return f"fails to load ({type(exc).__name__}); try: pip install --upgrade cffi cryptography"


def _tesseract() -> tuple[bool, str]:
    cmd = find_tesseract()
    if not cmd:
        return False, TESSERACT_HELP
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=30)
    except OSError as exc:
        return False, f"{cmd} does not run: {exc}"
    version = (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else cmd
    return True, f"{version} ({cmd})"


def main() -> int:
    setup_io()
    failed = False
    print(f"[ok]   Python {sys.version.split()[0]}")
    for module, pip_name, purpose in PACKAGES:
        problem = _import(module)
        if problem is None:
            print(f"[ok]   {pip_name}")
        else:
            optional = module in OPTIONAL
            failed |= not optional
            print(f"[{'skip' if optional else 'FAIL'}] {pip_name} ({purpose}): {problem}")
    ok, detail = _tesseract()
    failed |= not ok
    print(f"[ok]   tesseract: {detail}" if ok else f"[FAIL] tesseract: {detail}")
    print()
    print("Some requirements are missing; fix the FAIL lines above." if failed
          else "All set.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
