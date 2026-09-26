"""CLI: generate an incident report.

    # From a Module 2 case file (runs the timeline, flags and redaction itself):
    python -m fraud_evidence.report cases/CASE-001.json --format markdown --out report.md

    # From the outputs of the earlier modules:
    python -m fraud_evidence.report --timeline timeline.json --evidence redacted.json \\
        --flags issues.json --format markdown

The timeline and flags are computed when not given. Evidence files may be a
case file, a JSON list or JSON Lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..consistency.__main__ import load_timeline
from ..timeline.__main__ import load_records
from ..timeline.builder import DEFAULT_TZ
from .builder import IncidentReportBuilder
from .render import render_markdown, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.report",
                                     description="Generate a fraud incident report.")
    parser.add_argument("records", nargs="*", type=Path,
                        help="Module 2 case files or JSON Lines to build everything from")
    parser.add_argument("--timeline", type=Path, help="Module 3 timeline JSON")
    parser.add_argument("--evidence", type=Path, nargs="+", help="Module 5 redacted evidence")
    parser.add_argument("--flags", type=Path, help="Module 4 flags JSON")
    parser.add_argument("--format", choices=["json", "text", "markdown"], default="json")
    parser.add_argument("--tz", default=DEFAULT_TZ,
                        help=f"zone used when building the timeline (default {DEFAULT_TZ})")
    parser.add_argument("--case-id", help="case identifier (defaults to the input's)")
    parser.add_argument("--no-redact", action="store_true",
                        help="skip the final redaction pass (internal use only)")
    parser.add_argument("--out", type=Path, help="write output to this file instead of stdout")
    args = parser.parse_args(argv)

    if not (args.records or args.timeline) and sys.stdin.isatty():
        parser.error("give Module 2 records, or --timeline")

    builder = IncidentReportBuilder(redact=not args.no_redact)
    read = lambda p: p.read_text(encoding="utf-8")  # noqa: E731

    flags = json.loads(read(args.flags)) if args.flags else None
    evidence = None
    for path in args.evidence or []:
        evidence = (evidence or []) + load_records(read(path))[0]

    if args.timeline:
        timeline = load_timeline([read(args.timeline)], args.tz, args.case_id)
        raw = [r for p in args.records for r in load_records(read(p))[0]]
    else:
        texts = [read(p) for p in args.records] or [sys.stdin.read()]
        timeline = load_timeline(texts, args.tz, args.case_id)
        raw = [r for t in texts for r in load_records(t)[0]]
    if evidence is None and raw:
        # Raw Module 2 records: redact them before they reach the report.
        evidence = builder.redactor.redact(raw).document
    report = builder.build(timeline, evidence, flags, args.case_id)

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
