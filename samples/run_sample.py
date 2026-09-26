"""Run the whole pipeline on the made-up sample case: raw files -> incident report.

    python samples/run_sample.py [output-folder]      (default: out)

Works the same on Windows, macOS and Linux.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASE = ROOT / "samples" / "case-001"

STEPS = [
    ("Checking the setup", ["fraud_evidence.check"]),
    ("Module 1: ingesting raw evidence",
     ["fraud_evidence.ingestion", str(CASE), "--out", "{out}/evidence.jsonl"]),
    ("Module 2: extracting fields into a case file",
     ["fraud_evidence.extraction", "{out}/evidence.jsonl", "--out", "{out}/CASE-001.json",
      "--case-id", "CASE-001"]),
    ("Module 3: building the timeline",
     ["fraud_evidence.timeline", "{out}/CASE-001.json", "--format", "text",
      "--out", "{out}/timeline.txt"]),
    ("Module 4: checking for gaps and contradictions",
     ["fraud_evidence.consistency", "{out}/CASE-001.json", "--format", "text",
      "--out", "{out}/flags.txt"]),
    ("Module 5: redacting personal data",
     ["fraud_evidence.redaction", "{out}/CASE-001.json", "--out", "{out}/redacted.json"]),
    ("Module 6: writing the incident report",
     ["fraud_evidence.report", "{out}/CASE-001.json", "--out", "{out}/report/CASE-001"]),
]


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "out").resolve()
    out.mkdir(parents=True, exist_ok=True)
    for number, (title, args) in enumerate(STEPS):
        print(f"\n[{number}/{len(STEPS) - 1}] {title}", flush=True)
        command = [sys.executable, "-m"] + [a.format(out=out) for a in args]
        if subprocess.run(command, cwd=ROOT).returncode != 0:
            print(f"\nStopped: this step failed. Fix the message above and run again.")
            return 1
    print(f"\nDone. Human-readable report: {out / 'report' / 'CASE-001.txt'}")
    print(f"     Machine-readable report: {out / 'report' / 'CASE-001.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
