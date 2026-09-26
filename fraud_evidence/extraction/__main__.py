"""CLI: extract key fields from Module 1 output.

    python -m fraud_evidence.ingestion chat.png --text "..." \\
        | python -m fraud_evidence.extraction --out case.json

Reads Module 1 JSON Lines from files or stdin. With ``--out`` the records
are merged into a JSON case file; otherwise they are printed as JSON Lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli import check_files, read_text, setup_io
from .extractor import InformationExtractor
from .reputation import ListProvider, URLReputationScorer
from .store import JsonEvidenceStore


def _read_lines(paths: list[Path]):
    texts = [read_text(p) for p in paths] if paths else [sys.stdin.read()]
    for text in texts:
        for line in text.splitlines():
            if line.strip():
                yield json.loads(line)


def _read_list(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [ln.strip() for ln in read_text(path).splitlines()
            if ln.strip() and not ln.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.extraction",
                                     description="Extract key fields from normalized evidence.")
    parser.add_argument("inputs", nargs="*", type=Path,
                        help="Module 1 JSON Lines files (default: stdin)")
    parser.add_argument("--out", type=Path, help="write/merge records into this JSON case file")
    parser.add_argument("--case-id", help="case identifier stored in the case file")
    parser.add_argument("--blocklist", type=Path, help="file of known-bad domains, one per line")
    parser.add_argument("--allowlist", type=Path, help="file of trusted domains, one per line")
    parser.add_argument("--pretty", action="store_true", help="indent JSON Lines output")
    args = parser.parse_args(argv)
    setup_io()
    check_files(parser, *args.inputs, args.blocklist, args.allowlist)

    providers = []
    if args.blocklist or args.allowlist:
        providers.append(ListProvider(_read_list(args.blocklist), _read_list(args.allowlist)))
    extractor = InformationExtractor(URLReputationScorer(providers))
    records = extractor.extract_many(_read_lines(args.inputs))

    if args.out:
        store = JsonEvidenceStore(args.out, case_id=args.case_id)
        store.add_many(records)
        print(f"wrote {len(records)} record(s) to {store.save()}", file=sys.stderr)
    else:
        for record in records:
            print(json.dumps(record, ensure_ascii=False, indent=2 if args.pretty else None,
                             default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
