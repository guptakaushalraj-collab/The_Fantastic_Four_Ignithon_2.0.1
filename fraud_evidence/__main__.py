"""Run the whole pipeline in one command: raw evidence in, incident report out.

    python -m fraud_evidence EVIDENCE [EVIDENCE ...] [--case-id CASE-001] [--out reports]

EVIDENCE is a file or a folder of files (screenshots, PDFs, CSV/JSON exports,
chat exports, SMS text). Writes everything to <out>/<case-id>/:

    report.txt      the human-readable incident report       (Module 6)
    report.json     the same report as JSON                  (Module 6)
    evidence.jsonl  normalized evidence                      (Module 1)
    case.json       extracted fields, NOT redacted           (Module 2)
    timeline.txt    events in time order                     (Module 3)
    flags.txt       gaps and contradictions                  (Module 4)
    redacted.json   case file with personal data removed     (Module 5)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import expand_inputs, setup_io
from .consistency import check_timeline
from .consistency import render_text as render_flags
from .extraction import InformationExtractor, JsonEvidenceStore
from .ingestion import EvidenceIngestor
from .redaction import Redactor
from .report import IncidentReportBuilder, save_report
from .timeline import build_timeline
from .timeline import render_text as render_timeline
from .timeline.builder import DEFAULT_TZ


def _write(path: Path, text: str) -> None:
    path.write_text(text.rstrip("\n") + "\n", encoding="utf-8")


def _money(amounts: dict) -> str:
    return ", ".join(f"{'₹' if c == 'INR' else c + ' '}{v:,.2f}" for c, v in amounts.items()) or "none"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m fraud_evidence",
        description="Turn raw fraud evidence into an incident report (all six modules).")
    parser.add_argument("evidence", nargs="*", type=Path,
                        help="evidence files, or folders of them")
    parser.add_argument("--text", action="append", default=[],
                        help="evidence typed or pasted as text, such as an SMS (repeatable)")
    parser.add_argument("--case-id", default="CASE-001", help="case name (default CASE-001)")
    parser.add_argument("--out", type=Path, default=Path("reports"),
                        help="folder for the results (default: reports)")
    parser.add_argument("--tz", default=DEFAULT_TZ,
                        help=f"time zone of the evidence (default {DEFAULT_TZ})")
    parser.add_argument("--print", action="store_true", dest="print_report",
                        help="also print the full text report")
    args = parser.parse_args(argv)
    setup_io()
    if not args.evidence and not args.text:
        parser.error("give at least one evidence file or folder, or --text")

    files = expand_inputs(parser, args.evidence)
    folder = args.out / args.case_id
    folder.mkdir(parents=True, exist_ok=True)
    say = lambda msg: print(msg, file=sys.stderr, flush=True)  # noqa: E731

    say(f"[1/6] Reading {len(files) + len(args.text)} item(s) of evidence")
    items: list = [*files, *args.text]
    evidence = EvidenceIngestor().ingest_many(items)
    for item, ev in zip(items, evidence):
        name = item.name if isinstance(item, Path) else "--text"
        say(f"      {name}: {ev.evidence_type.value}")
        for warning in ev.warnings:
            say(f"      warning: {warning}")
    _write(folder / "evidence.jsonl", "\n".join(
        json.dumps(ev.to_dict(), ensure_ascii=False, default=str) for ev in evidence))

    say("[2/6] Extracting names, amounts, dates and links")
    records = InformationExtractor().extract_many(ev.to_dict() for ev in evidence)
    case_path = folder / "case.json"
    case_path.unlink(missing_ok=True)  # a re-run replaces the case, it doesn't add to it
    store = JsonEvidenceStore(case_path, case_id=args.case_id)
    store.add_many(records)
    store.save()

    say("[3/6] Building the timeline")
    timeline = build_timeline(records, case_id=args.case_id, tz=args.tz)
    _write(folder / "timeline.txt", render_timeline(timeline))

    say("[4/6] Checking for gaps and contradictions")
    flags = check_timeline(timeline)
    _write(folder / "flags.txt", render_flags(flags))

    say("[5/6] Redacting personal data")
    redactor = Redactor()
    redacted = redactor.redact(records).document
    _write(folder / "redacted.json", json.dumps(
        {"case_id": args.case_id, "records": redacted}, ensure_ascii=False, indent=2, default=str))

    say("[6/6] Writing the incident report")
    report = IncidentReportBuilder(redactor).build(timeline, redacted, flags, args.case_id)
    paths = save_report(report, folder / "report", ("json", "text"))

    facts = report["executive_summary"]["key_facts"]
    say("")
    say(f"Assessment:  {report['executive_summary']['assessment']}")
    say(f"Total loss:  {_money(facts.get('total_loss') or {})}")
    say(f"Flags:       {report['flags']['summary']['issue_count']}")
    say(f"Report:      {paths['text']}")
    say(f"JSON:        {paths['json']}")
    if args.print_report:
        print(paths["text"].read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
