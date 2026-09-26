import json

import pytest

from fraud_evidence.consistency import check_timeline
from fraud_evidence.extraction import InformationExtractor, JsonEvidenceStore
from fraud_evidence.ingestion import EvidenceIngestor
from fraud_evidence.redaction import PLACEHOLDER, redact
from fraud_evidence.report import IncidentReportBuilder, build_report, render_markdown, render_text
from fraud_evidence.report.__main__ import main
from fraud_evidence.timeline import build_timeline

SCAM_SMS = ("VM-SBIINB: Dear customer your account will be blocked today. "
            "Update KYC at http://sbi-kyc.top/verify")
SCAM_CHAT = ("[12/03/24, 10:40:00 AM] SBI Support: Sir pay Rs 5000 verification fee to "
             "kyc.help@ybl immediately or call 98765 43210")
DEBIT_SMS = ("Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA kyc.help@ybl "
             "UPI Ref 412345678901")
FOLLOW_UP = "[13/03/24, 09:00:00 AM] SBI Support: Pay Rs 2000 tax to release refund or legal action"

SENSITIVE = ["kyc.help@ybl", "98765 43210", "XX1234"]
SECTIONS = ["executive_summary", "timeline", "evidence", "flags", "fraud_attempt_log"]


def extract(item, **metadata):
    return InformationExtractor().extract(EvidenceIngestor().ingest(item, metadata=metadata))


@pytest.fixture
def records():
    return [
        extract(SCAM_SMS, timestamp="2024-03-12T10:15:00"),
        extract(SCAM_CHAT),
        extract(DEBIT_SMS),
        # A receipt for the same payment as the SMS alert.
        extract({"amount": 5000, "to": "kyc.help@ybl", "date": "2024-03-12 10:45:00",
                 "transaction_id": "412345678901"}),
        extract({"amount": 2000, "to": "kyc.help@ybl", "date": "2024-03-13 09:30:00",
                 "status": "FAILED"}),
        extract(FOLLOW_UP),
    ]


@pytest.fixture
def report(records):
    return IncidentReportBuilder().build_from_records(records, case_id="CASE-1")


def leaks(document) -> list[str]:
    text = json.dumps(document, ensure_ascii=False)
    return [s for s in SENSITIVE if s in text]


# --------------------------------------------------------------- structure

def test_report_has_all_sections(report):
    assert all(k in report for k in SECTIONS)
    assert report["case_id"] == "CASE-1" and report["redacted"] is True
    assert report["timezone"] == "Asia/Kolkata"
    json.dumps(report, ensure_ascii=False)


def test_executive_summary(report):
    es = report["executive_summary"]
    facts = es["key_facts"]
    assert es["assessment"] == "Fraud with financial loss"
    # The SMS alert and the receipt are one payment: counted once.
    assert facts["fraudulent_payment_count"] == 1
    assert facts["total_loss"] == {"INR": 5000.0}
    assert facts["failed_attempt_count"] == 1
    assert facts["first_contact_at"] == "2024-03-12T10:15:00+05:30"
    assert facts["first_loss_at"] == "2024-03-12T10:45:00+05:30"
    assert facts["contact_channels"] == ["SMS", "chat"]
    assert facts["evidence_count"] == 6
    assert "1 fraudulent payment of ₹5,000.00 was made (recorded in 2 documents)" in es["text"]
    assert "between 2024-03-12 10:15 and 2024-03-13 09:30" in es["text"]
    assert "1 further payment attempt to the suspects failed" in es["text"]
    assert "redacted in this report" in es["text"]


@pytest.mark.parametrize("items, assessment", [
    ([], "No fraud indicators found"),
    ([SCAM_SMS], "Suspicious contact, no payment found"),
])
def test_assessment_without_loss(items, assessment):
    records = [extract(t, timestamp="2024-03-12T10:15:00") for t in items]
    report = IncidentReportBuilder().build_from_records(records)
    assert report["executive_summary"]["assessment"] == assessment
    assert report["executive_summary"]["key_facts"]["total_loss"] == {}


def test_attempt_only_assessment():
    records = [extract(SCAM_CHAT), extract({"amount": 900, "to": "kyc.help@ybl",
                                            "date": "2024-03-12 11:00:00", "status": "FAILED"})]
    report = IncidentReportBuilder().build_from_records(records)
    assert report["executive_summary"]["assessment"] == "Attempted fraud, no confirmed loss"


def test_timeline_section(report):
    rows = report["timeline"]
    assert [r["sequence"] for r in rows] == list(range(1, len(rows) + 1))
    assert rows[0]["event_type"] == "suspicious_message"
    assert {"timestamp", "stage", "severity", "title", "description"} <= set(rows[0])
    assert "actors" not in rows[0]  # raw party details stay out of the report


def test_evidence_table_cross_references(report, records):
    rows = report["evidence"]
    assert [r["evidence_id"] for r in rows] == [r["evidence_id"] for r in records]
    by_id = {r["evidence_id"]: r for r in rows}
    sms = by_id[records[0]["evidence_id"]]
    assert sms["events"] == [1, 2] and sms["sender"] == "VM-SBIINB"
    statement = by_id[records[2]["evidence_id"]]
    assert statement["timestamp"] == "2024-03-12"  # date-only, not midnight
    assert statement["summary"] == "Debit of ₹5,000.00, ref 412345678901"
    flagged = {f for r in rows for f in r["flags"]}
    assert flagged == {i["issue_id"] for i in report["flags"]["issues"] if i["evidence_ids"]}


def test_flags_section(report):
    flags = report["flags"]
    types = {i["issue_type"] for i in flags["issues"]}
    assert {"missing_sender_id", "duplicate_transaction", "missing_transaction_id"} <= types
    assert flags["summary"]["issue_count"] == len(flags["issues"])


def test_fraud_attempt_log(report):
    log = report["fraud_attempt_log"]
    assert [a["entry"] for a in log] == list(range(1, len(log) + 1))
    assert [a["action"] for a in log] == [
        "Scam contact", "Phishing link sent", "Scam contact", "Payment to suspect",
        "Payment to suspect", "Follow-up demand after loss", "Payment to suspect attempted"]
    payment = log[3]
    assert payment["outcome"] == "money lost" and payment["amount"] == 5000.0
    assert payment["transaction_id"] == "412345678901"  # references are kept
    assert payment["counterparty"] == PLACEHOLDER
    assert log[1]["url"] == "http://sbi-kyc.top/verify"
    assert log[-1]["outcome"] == "failed"


# ---------------------------------------------------------------- redaction

def test_report_contains_no_sensitive_data(records, report):
    assert leaks(records)  # sanity check: the input does
    assert leaks(report) == []


def test_unredacted_inputs_are_redacted_in_report(records):
    # Timeline and flags carry raw identifiers; the report must still be clean.
    timeline = build_timeline(records)
    report = build_report(timeline, redact(records), check_timeline(timeline))
    assert leaks(timeline) and leaks(report) == []


def test_redaction_can_be_turned_off(records):
    timeline = build_timeline(records)
    report = build_report(timeline, records, redact=False)
    assert report["redacted"] is False and "kyc.help@ybl" in json.dumps(report)


def test_flags_and_evidence_are_optional(records):
    timeline = build_timeline(records, case_id="CASE-2")
    report = build_report(timeline)
    assert report["case_id"] == "CASE-2"
    assert report["flags"]["issues"]  # computed from the timeline
    assert len(report["evidence"]) == len(records)  # built from the timeline's events
    assert leaks(report) == []


def test_given_flags_are_used(records):
    timeline = build_timeline(records)
    flags = {"summary": {"issue_count": 0}, "issues": []}
    report = build_report(timeline, redact(records), flags)
    assert report["flags"]["issues"] == []
    assert all(r["flags"] == [] for r in report["evidence"])


# ---------------------------------------------------------------- rendering

def test_markdown(report):
    md = render_markdown(report)
    assert md.startswith("# Incident report — CASE-1")
    for heading in ("## 1. Executive summary", "## 2. Timeline of events", "## 3. Evidence",
                    "## 4. Flags: missing and contradictory information", "## 5. Fraud attempt log"):
        assert heading in md
    assert "**Assessment:** Fraud with financial loss" in md
    assert "| Total loss | ₹5,000.00 |" in md
    assert leaks(md) == []


def test_text(report):
    text = render_text(report)
    assert text.startswith("INCIDENT REPORT — CASE-1")
    assert "Total loss: ₹5,000.00" in text and "FRAUD ATTEMPT LOG" in text


def test_empty_report_renders():
    report = IncidentReportBuilder().build_from_records([])
    assert "No fraud attempts recorded." in render_markdown(report)
    assert "No gaps or contradictions found." in render_markdown(report)
    assert report["executive_summary"]["text"] == "No evidence was provided."
    render_text(report)


# ---------------------------------------------------------------------- CLI

def test_cli_from_case_file(tmp_path, records):
    store = JsonEvidenceStore(tmp_path / "case.json", case_id="CASE-9")
    store.add_many(records)
    store.save()
    out = tmp_path / "report.md"
    assert main([str(tmp_path / "case.json"), "--format", "markdown", "--out", str(out)]) == 0
    md = out.read_text()
    assert md.startswith("# Incident report — CASE-9") and leaks(md) == []


def test_cli_from_module_outputs(tmp_path, records, capsys):
    timeline = build_timeline(records, case_id="CASE-3")
    files = {
        "timeline.json": timeline,
        "flags.json": check_timeline(timeline),
        "evidence.json": {"case_id": "CASE-3", "records": redact(records)},
    }
    for name, doc in files.items():
        (tmp_path / name).write_text(json.dumps(doc))
    assert main(["--timeline", str(tmp_path / "timeline.json"),
                 "--evidence", str(tmp_path / "evidence.json"),
                 "--flags", str(tmp_path / "flags.json")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["case_id"] == "CASE-3" and len(report["evidence"]) == len(records)
    assert leaks(report) == []


def test_cli_timeline_with_raw_records_redacts_them(tmp_path, records, capsys):
    (tmp_path / "timeline.json").write_text(json.dumps(build_timeline(records)))
    jsonl = tmp_path / "records.jsonl"
    jsonl.write_text("\n".join(json.dumps(r) for r in records))
    assert main([str(jsonl), "--timeline", str(tmp_path / "timeline.json"), "--format", "text"]) == 0
    out = capsys.readouterr().out
    assert "INCIDENT REPORT" in out and leaks(out) == []
