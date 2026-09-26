"""CLI: flag gaps and contradictions in a fraud timeline.

    python -m fraud_evidence.consistency cases/CASE-001-timeline.json --format text
    python -m fraud_evidence.timeline cases/CASE-001.json | python -m fraud_evidence.consistency

Accepts a Module 3 timeline (``{"events": [...]}``). Module 2 output (a case
file, JSON list or JSON Lines) is also accepted and turned into a timeline first.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli import check_files, read_text, setup_io
from ..timeline.__main__ import load_records
from ..timeline.builder import DEFAULT_TZ, TimelineBuilder
from .detector import ConsistencyChecker
from .render import render_markdown, render_text


def load_timeline(texts: list[str], tz: str = DEFAULT_TZ, case_id: str | None = None) -> dict:
    """Return the timeline in ``texts``, or build one from the Module 2 records they hold."""
    if len(texts) == 1:
        try:
            doc = json.loads(texts[0])
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and "events" in doc:
            return {**doc, "case_id": case_id or doc.get("case_id")}

    records, file_case = [], None
    for text in texts:
        loaded, found = load_records(text)
        records.extend(loaded)
        file_case = file_case or found
    return TimelineBuilder(tz).build(records, case_id=case_id or file_case)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.consistency",
                                     description="Flag gaps and contradictions in a fraud timeline.")
    parser.add_argument("inputs", nargs="*", type=Path,
                        help="Module 3 timeline, or Module 2 case files / JSON Lines (default: stdin)")
    parser.add_argument("--format", choices=["json", "text", "markdown"], default="json")
    parser.add_argument("--tz", default=DEFAULT_TZ,
                        help=f"zone used when building a timeline from Module 2 records (default {DEFAULT_TZ})")
    parser.add_argument("--case-id", help="case identifier (defaults to the input's)")
    parser.add_argument("--out", type=Path, help="write output to this file instead of stdout")
    args = parser.parse_args(argv)
    setup_io()
    check_files(parser, *args.inputs)

    texts = [read_text(p) for p in args.inputs] or [sys.stdin.read()]
    report = ConsistencyChecker().check(load_timeline(texts, args.tz, args.case_id))
    if args.format == "text":
        output = render_text(report)
    elif args.format == "markdown":
        output = render_markdown(report)
    else:
        output = json.dumps(report, ensure_ascii=False, indent=2, default=str)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
