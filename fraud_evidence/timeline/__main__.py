"""CLI: build a chronological timeline from Module 2 output.

    python -m fraud_evidence.timeline cases/CASE-001.json --format text
    python -m fraud_evidence.ingestion ... | python -m fraud_evidence.extraction \\
        | python -m fraud_evidence.timeline --format markdown

Accepts a Module 2 case file (``{"records": [...]}``), a JSON list, or
JSON Lines, from files or stdin.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .builder import DEFAULT_TZ, TimelineBuilder
from .render import render_markdown, render_text


def load_records(text: str) -> tuple[list[dict], str | None]:
    text = text.strip()
    if not text:
        return [], None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()], None
    if isinstance(doc, dict) and "records" in doc:
        return doc["records"], doc.get("case_id")
    return (doc if isinstance(doc, list) else [doc]), None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.timeline",
                                     description="Build a chronological fraud timeline.")
    parser.add_argument("inputs", nargs="*", type=Path,
                        help="Module 2 case files or JSON Lines (default: stdin)")
    parser.add_argument("--format", choices=["json", "text", "markdown"], default="json")
    parser.add_argument("--tz", default=DEFAULT_TZ,
                        help=f"zone for timestamps without an offset (default {DEFAULT_TZ})")
    parser.add_argument("--case-id", help="case identifier (defaults to the case file's)")
    parser.add_argument("--out", type=Path, help="write output to this file instead of stdout")
    args = parser.parse_args(argv)

    records, case_id = [], None
    sources = [p.read_text(encoding="utf-8") for p in args.inputs] or [sys.stdin.read()]
    for text in sources:
        loaded, file_case = load_records(text)
        records.extend(loaded)
        case_id = case_id or file_case

    timeline = TimelineBuilder(args.tz).build(records, case_id=args.case_id or case_id)
    if args.format == "text":
        output = render_text(timeline)
    elif args.format == "markdown":
        output = render_markdown(timeline)
    else:
        output = json.dumps(timeline, ensure_ascii=False, indent=2, default=str)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
