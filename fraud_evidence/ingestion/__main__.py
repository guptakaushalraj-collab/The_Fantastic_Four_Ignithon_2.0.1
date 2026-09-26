"""CLI: ``python -m fraud_evidence.ingestion [--type TYPE] (FILE | --text TEXT)...``

Prints one JSON record per line (JSON Lines) for each ingested item.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import EvidenceType
from .pipeline import EvidenceIngestor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.ingestion",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", type=Path, help="evidence files to ingest")
    parser.add_argument("--text", action="append", default=[],
                        help="raw text evidence (repeatable); use '-' to read stdin")
    parser.add_argument("--type", choices=[t.value for t in EvidenceType],
                        help="force the evidence type instead of auto-detecting")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = parser.parse_args(argv)

    if not args.files and not args.text:
        parser.error("provide at least one file or --text")

    ingestor = EvidenceIngestor()
    items: list = list(args.files)
    items += [sys.stdin.read() if t == "-" else t for t in args.text]

    for evidence in ingestor.ingest_many(items, evidence_type=args.type):
        print(json.dumps(evidence.to_dict(), ensure_ascii=False,
                         indent=2 if args.pretty else None, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
