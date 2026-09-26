#!/usr/bin/env bash
# Runs the whole pipeline on the made-up sample case: raw files -> incident report.
# Usage: bash samples/run_sample.sh [output-dir]   (default: out/)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-out}"
mkdir -p "$OUT"

echo "1/6 Ingesting raw evidence (Module 1)"
python -m fraud_evidence.ingestion samples/case-001/* > "$OUT/evidence.jsonl"

echo "2/6 Extracting fields into a case file (Module 2)"
python -m fraud_evidence.extraction "$OUT/evidence.jsonl" --out "$OUT/CASE-001.json" --case-id CASE-001 > /dev/null

echo "3/6 Building the timeline (Module 3)"
python -m fraud_evidence.timeline "$OUT/CASE-001.json" --format text > "$OUT/timeline.txt"

echo "4/6 Checking for gaps and contradictions (Module 4)"
python -m fraud_evidence.consistency "$OUT/CASE-001.json" --format text > "$OUT/flags.txt"

echo "5/6 Redacting personal data (Module 5)"
python -m fraud_evidence.redaction "$OUT/CASE-001.json" --out "$OUT/redacted.json"

echo "6/6 Writing the incident report (Module 6)"
python -m fraud_evidence.report "$OUT/CASE-001.json" --out "$OUT/report/CASE-001"

echo
echo "Done. Human-readable report: $OUT/report/CASE-001.txt"
echo "     Machine-readable report: $OUT/report/CASE-001.json"
