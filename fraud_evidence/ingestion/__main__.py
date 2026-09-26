"""CLI: ``python -m fraud_evidence.ingestion [--type TYPE] (FILE | FOLDER | --text TEXT)...``

Writes one JSON record per line (JSON Lines) for each ingested item, to stdout or --out.
A folder stands for every file in it, so no shell wildcard is needed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli import setup_io
from .models import EvidenceType
from .pipeline import EvidenceIngestor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.ingestion",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", type=Path,
                        help="evidence files, or folders of them, to ingest")
    parser.add_argument("--text", action="append", default=[],
                        help="raw text evidence (repeatable); use '-' to read stdin")
    parser.add_argument("--type", choices=[t.value for t in EvidenceType],
                        help="force the evidence type instead of auto-detecting")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument("--out", type=Path,
                        help="write JSON Lines to this file instead of stdout (use this on Windows)")
    args = parser.parse_args(argv)
    setup_io()

    if not args.files and not args.text:
        parser.error("provide at least one file or --text")

    files: list[Path] = []
    for path in args.files:
        if path.is_dir():
            inside = sorted(p for p in path.iterdir() if p.is_file() and not p.name.startswith("."))
            if not inside:
                parser.error(f"folder is empty: {path}")
            files += inside
        elif path.is_file():
            files.append(path)
        else:
            parser.error(f"file not found: {path}")

    ingestor = EvidenceIngestor()
    items: list = list(files)
    items += [sys.stdin.read() if t == "-" else t for t in args.text]

    lines = []
    for item, evidence in zip(items, ingestor.ingest_many(items, evidence_type=args.type)):
        lines.append(json.dumps(evidence.to_dict(), ensure_ascii=False,
                                indent=2 if args.pretty else None, default=str))
        name = item.name if isinstance(item, Path) else "--text"
        for warning in evidence.warnings:
            print(f"warning: {name}: {warning}", file=sys.stderr)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {len(lines)} item(s) to {args.out}", file=sys.stderr)
    else:
        print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
