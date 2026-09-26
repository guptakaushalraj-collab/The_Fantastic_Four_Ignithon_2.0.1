"""CLI: generate an incident report.

    # From a Module 2 case file (runs the timeline, flags and redaction itself):
    python -m fraud_evidence.report cases/CASE-001.json --out reports/CASE-001
    # -> reports/CASE-001.json and reports/CASE-001.txt (the human-readable report)

    # From the outputs of the earlier modules:
    python -m fraud_evidence.report --timeline timeline.json --evidence redacted.json \\
        --flags issues.json --format text

The timeline and flags are computed when not given. Evidence files may be a
case file, a JSON list or JSON Lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli import check_files, read_text, setup_io
from ..consistency.__main__ import load_timeline
from ..timeline.__main__ import load_records
from ..timeline.builder import DEFAULT_TZ
from .builder import IncidentReportBuilder
from .render import render_markdown, render_text, save_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.report",
                                     description="Generate a fraud incident report.")
    parser.add_argument("records", nargs="*", type=Path,
                        help="Module 2 case files or JSON Lines to build everything from")
    parser.add_argument("--timeline", type=Path, help="Module 3 timeline JSON")
    parser.add_argument("--evidence", type=Path, nargs="+", help="Module 5 redacted evidence")
    parser.add_argument("--flags", type=Path, help="Module 4 flags JSON")
    parser.add_argument("--format", nargs="+", choices=["json", "text", "markdown"],
                        help="output format(s); default: json on stdout, json and text with --out")
    parser.add_argument("--tz", default=DEFAULT_TZ,
                        help=f"zone used when building the timeline (default {DEFAULT_TZ})")
    parser.add_argument("--case-id", help="case identifier (defaults to the input's)")
    parser.add_argument("--no-redact", action="store_true",
                        help="skip the final redaction pass (internal use only)")
    parser.add_argument("--out", type=Path,
                        help="write the report to files named after this path (.json, .txt, .md)")
    args = parser.parse_args(argv)
    setup_io()
    check_files(parser, *args.records, args.timeline, args.flags, *(args.evidence or []))

    if not (args.records or args.timeline) and sys.stdin.isatty():
        parser.error("give Module 2 records, or --timeline")

    builder = IncidentReportBuilder(redact=not args.no_redact)
    read = read_text

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

    if args.out:
        for path in save_report(report, args.out, tuple(args.format or ("json", "text"))).values():
            print(f"wrote {path}", file=sys.stderr)
    else:
        renderers = {"json": lambda r: json.dumps(r, ensure_ascii=False, indent=2, default=str),
                     "text": render_text, "markdown": render_markdown}
        print("\n\n".join(renderers[f](report) for f in args.format or ["json"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
