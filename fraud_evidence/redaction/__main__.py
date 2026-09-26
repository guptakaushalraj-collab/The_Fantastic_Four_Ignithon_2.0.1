"""CLI: redact sensitive data from structured evidence.

    python -m fraud_evidence.redaction cases/CASE-001.json --out cases/CASE-001-redacted.json
    python -m fraud_evidence.timeline cases/CASE-001.json | python -m fraud_evidence.redaction

Accepts any module's JSON output (a case file, timeline or issue report) or
JSON Lines, from files or stdin, and writes it back in the same shape. A
count of what was redacted goes to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli import check_files, read_text, setup_io
from .redactor import PLACEHOLDER, SENSITIVE_TYPES, Redactor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fraud_evidence.redaction",
                                     description="Replace sensitive data with [REDACTED].")
    parser.add_argument("inputs", nargs="*", type=Path, help="JSON or JSON Lines files (default: stdin)")
    parser.add_argument("--types", default=",".join(SENSITIVE_TYPES),
                        help=f"comma-separated types to redact (default: {','.join(SENSITIVE_TYPES)})")
    parser.add_argument("--placeholder", default=PLACEHOLDER)
    parser.add_argument("--out", type=Path, help="write output to this file instead of stdout")
    args = parser.parse_args(argv)
    setup_io()
    check_files(parser, *args.inputs)

    try:
        redactor = Redactor([t.strip() for t in args.types.split(",") if t.strip()], args.placeholder)
    except ValueError as exc:
        parser.error(str(exc))

    outputs, counts = [], {}
    for text in [read_text(p) for p in args.inputs] or [sys.stdin.read()]:
        text = text.strip()
        if not text:
            continue
        try:
            docs, lines = [json.loads(text)], False
        except json.JSONDecodeError:
            docs, lines = [json.loads(line) for line in text.splitlines() if line.strip()], True
        # Redact a whole file at once, so a value found in one record is removed from all.
        result = redactor.redact(docs)
        for kind, n in result.counts.items():
            counts[kind] = counts.get(kind, 0) + n
        outputs.extend(json.dumps(d, ensure_ascii=False, default=str) if lines
                       else json.dumps(d, ensure_ascii=False, indent=2, default=str)
                       for d in result.document)

    output = "\n".join(outputs)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    summary = ", ".join(f"{n} {kind}" for kind, n in counts.items()) or "nothing"
    print(f"redacted {summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
