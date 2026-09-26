"""The made-up case in samples/case-001, run end to end as an evaluator would."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fraud_evidence.ingestion import EvidenceIngestor, EvidenceType
from fraud_evidence.ingestion.transactions import parse_transaction_text

ROOT = Path(__file__).resolve().parent.parent
CASE = ROOT / "samples" / "case-001"


def test_chat_about_payments_is_a_message():
    chat = (CASE / "02_whatsapp_chat.txt").read_text()
    assert EvidenceIngestor.detect_text_type(chat) is EvidenceType.MESSAGE
    # A bank alert is still a transaction.
    alert = (CASE / "03_upi_debit_alert.txt").read_text()
    assert EvidenceIngestor.detect_text_type(alert) is EvidenceType.TRANSACTION


@pytest.mark.parametrize("text, timestamp", [
    ("Rs 4,999 paid to a@ybl 12 Sep 2026, 10:44 AM", "2026-09-12T10:44:00"),
    ("Rs 50 debited on 12-03-24 at 23:05:09", "2024-03-12T23:05:09"),
    ("Rs 50 debited on 12-03-24 12:10 AM", "2024-03-12T00:10:00"),
    ("Rs 50 debited on 12-03-24 12:30 PM", "2024-03-12T12:30:00"),
    ("Rs 50 debited on 12-03-24 via UPI", "2024-03-12T00:00:00"),
])
def test_alert_time_of_day(text, timestamp):
    assert parse_transaction_text(text)["timestamp"] == timestamp


def test_sample_case_end_to_end(tmp_path):
    pytest.importorskip("pdfplumber")
    pytest.importorskip("pytesseract")
    if not shutil.which("tesseract"):
        pytest.skip("tesseract is not installed")
    subprocess.run(["bash", str(ROOT / "samples" / "run_sample.sh"), str(tmp_path)],
                   check=True, capture_output=True)
    report = json.loads((tmp_path / "report" / "CASE-001.json").read_text())
    text = (tmp_path / "report" / "CASE-001.txt").read_text()
    facts = report["executive_summary"]["key_facts"]
    assert report["executive_summary"]["assessment"] == "Fraud with financial loss"
    assert facts["total_loss"] == {"INR": 4999.0}
    assert facts["fraudulent_payment_count"] == 1 and facts["failed_attempt_count"] == 1
    assert facts["first_contact_at"] == "2026-09-12T10:40:12+05:30"
    for secret in ("kyc.helpdesk@ybl", "98765 43210", "50431698659", "XX8659"):
        assert secret not in text and secret not in json.dumps(report)
    assert "625512345678" in text  # the UTR is kept for the bank
