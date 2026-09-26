import json

import pytest

from fraud_evidence.extraction import InformationExtractor, JsonEvidenceStore
from fraud_evidence.ingestion import EvidenceIngestor
from fraud_evidence.timeline import (
    TimelineBuilder,
    build_timeline,
    find_indicators,
    is_suspicious,
    render_markdown,
    render_text,
)
from fraud_evidence.timeline.__main__ import main
from fraud_evidence.timeline.builder import humanize_delta

SCAM_SMS = ("VM-SBIINB: Dear customer your account will be blocked today. "
            "Update KYC at http://sbi-kyc.top/verify")
SCAM_CHAT = ("[12/03/24, 10:40:00 AM] SBI Support: Sir pay Rs 5000 verification fee to "
             "kyc.help@ybl immediately\n[12/03/24, 10:41:10 AM] Me: ok sending")
DEBIT_SMS = ("Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA kyc.help@ybl "
             "UPI Ref 412345678901")
FOLLOW_UP = "[13/03/24, 09:00:00 AM] SBI Support: Pay Rs 2000 tax to release refund or legal action"


def extract(text, **metadata):
    return InformationExtractor().extract(EvidenceIngestor().ingest(text, metadata=metadata))


@pytest.fixture
def scam_case():
    # Deliberately out of order: the timeline must sort them.
    return [
        extract(FOLLOW_UP),
        extract(DEBIT_SMS),
        extract(SCAM_CHAT),
        extract(SCAM_SMS, timestamp="2024-03-12T10:15:00"),
        extract("hxxps://bit.ly/sbi-refund"),
    ]


# -------------------------------------------------------------- indicators

def test_find_indicators():
    assert find_indicators("Your account is blocked, share OTP immediately") == [
        "urgency", "account_threat", "credential_request"]
    assert find_indicators("See you at lunch tomorrow") == []


def test_indicators_ignore_words_inside_identifiers():
    assert "credential_request" not in find_indicators("pay to kyc.help@ybl or visit x.com/otp")


def test_is_suspicious_rules():
    assert is_suspicious(["payment_request"])
    assert not is_suspicious(["reward_bait"])
    assert is_suspicious(["reward_bait", "urgency"])
    assert is_suspicious([], has_bad_url=True)


def test_humanize_delta():
    from datetime import timedelta
    assert humanize_delta(timedelta(days=1, hours=2, minutes=5)) == "1d 2h 5m"
    assert humanize_delta(timedelta(seconds=30)) == "30s"


# ---------------------------------------------------------------- timeline

def test_full_attack_chain_is_ordered(scam_case):
    tl = build_timeline(scam_case, case_id="CASE-1")
    events = tl["events"]
    assert [e["event_type"] for e in events] == [
        "suspicious_message", "malicious_url", "suspicious_message",
        "fraudulent_payment", "follow_up_message", "suspicious_url",
    ]
    assert [e["sequence"] for e in events] == [1, 2, 3, 4, 5, 6]
    assert events[0]["timestamp"] == "2024-03-12T10:15:00+05:30"
    assert events[1]["url"] == "http://sbi-kyc.top/verify"
    assert events[2]["since_previous"] == "25m"
    assert events[5]["timestamp"] is None  # undated evidence goes last

    s = tl["summary"]
    assert s["attack_chain"] == ("suspicious message → malicious URL → fraudulent payment → "
                                 "follow-up message")
    assert s["total_loss"] == {"INR": 5000.0}
    assert s["undated_event_count"] == 1
    assert s["suspect_identifiers"] == ["VM-SBIINB", "kyc.help@ybl"]
    assert s["highest_severity"] == "critical"
    assert tl["case_id"] == "CASE-1"


def test_fraudulent_payment_links_back_to_evidence(scam_case):
    events = build_timeline(scam_case)["events"]
    payment = next(e for e in events if e["event_type"] == "fraudulent_payment")
    chat = next(r for r in scam_case if r["message"] and r["message"]["platform"] == "chat"
                and "kyc.help@ybl" in r["contacts"]["upi_ids"])
    assert chat["evidence_id"] in payment["linked_evidence"]
    assert payment["stage"] == "fraud" and payment["severity"] == "critical"
    assert payment["amount"] == {"value": 5000.0, "currency": "INR", "direction": "debit"}
    assert "XX1234" in payment["description"]


def test_date_only_events_sort_after_timed_events_that_day():
    records = [extract(DEBIT_SMS), extract(SCAM_CHAT)]
    events = build_timeline(records)["events"]
    assert events[0]["event_type"] == "suspicious_message"
    assert events[1]["time_precision"] == "date"
    assert events[1]["timestamp"] == "2024-03-12"
    assert events[1]["since_previous"] is None


def test_same_time_events_follow_kill_chain_order():
    rec = extract(SCAM_SMS, timestamp="2024-03-12T10:15:00")
    events = build_timeline([rec])["events"]
    assert [e["stage"] for e in events] == ["contact", "lure"]


def test_timezone_aware_timestamps_are_normalized():
    email = extract("From: a@evil.info\nDate: Tue, 12 Mar 2024 04:45:00 +0000\n"
                    "Subject: Refund\n\nShare your OTP to get refund")
    chat = extract("[12/03/24, 10:00:00 AM] X: Your account is blocked, send OTP")
    events = build_timeline([email, chat])["events"]
    # 04:45 UTC is 10:15 IST, so it comes after the 10:00 IST chat.
    assert [e["evidence_type"] for e in events] == ["message", "message"]
    assert events[0]["timestamp"] == "2024-03-12T10:00:00+05:30"
    assert events[1]["timestamp"] == "2024-03-12T10:15:00+05:30"
    other = TimelineBuilder("UTC").build([email])["events"][0]
    assert other["timestamp"] == "2024-03-12T04:45:00+00:00"


def test_benign_evidence_does_not_create_chain():
    tl = build_timeline([extract("[12/03/24, 10:00:00 AM] Mom: Dinner at 8?"),
                         extract("https://www.hdfcbank.com")])
    assert [e["event_type"] for e in tl["events"]] == ["message", "url"]
    assert tl["summary"]["attack_chain"] is None
    assert tl["summary"]["highest_severity"] == "info"


def test_unlinked_debit_after_contact_is_flagged():
    records = [extract(SCAM_SMS, timestamp="2024-03-12T10:15:00"),
               extract("Rs 999 debited from A/c XX1234 to VPA shop@okaxis on 13-03-24 UPI")]
    payment = build_timeline(records)["events"][-1]
    assert payment["event_type"] == "transaction"
    assert payment["details"]["follows_suspicious_contact"] is True
    assert payment["severity"] == "medium"


def test_failed_linked_payment_is_fraud_attempt():
    chat = extract(SCAM_CHAT)
    txn = InformationExtractor().extract(EvidenceIngestor().ingest(
        {"amount": 5000, "to": "kyc.help@ybl", "date": "2024-03-12 10:45:00", "status": "FAILED"}))
    events = build_timeline([chat, txn])["events"]
    assert events[-1]["event_type"] == "fraud_attempt"
    assert build_timeline([chat, txn])["summary"]["total_loss"] == {}


def test_statement_yields_event_per_transaction():
    stmt = extract("date,narration,debit,credit\n2024-03-12,UPI/kyc.help@ybl,5000,\n"
                   "2024-03-11,UPI/kyc.help@ybl,,1\n")
    events = build_timeline([extract(SCAM_CHAT), stmt])["events"]
    types = [e["event_type"] for e in events]
    # A ₹1 "test credit" from the scammer on the 11th comes first.
    assert types == ["scammer_credit", "suspicious_message", "fraudulent_payment"]


def test_empty_input():
    tl = build_timeline([])
    assert tl["events"] == [] and tl["summary"]["event_count"] == 0


# --------------------------------------------------------------- rendering

def test_renderers(scam_case):
    tl = build_timeline(scam_case, case_id="CASE-1")
    text = render_text(tl)
    assert "Attack chain: suspicious message → malicious URL" in text
    assert "(date only)" in text and "(no timestamp)" in text
    md = render_markdown(tl)
    assert md.startswith("# Fraud timeline — CASE-1")
    assert md.count("\n| ") == len(tl["events"]) + 1


def test_json_serializable(scam_case):
    json.dumps(build_timeline(scam_case), ensure_ascii=False)


def test_cli_reads_case_file(tmp_path, scam_case, capsys):
    case = tmp_path / "case.json"
    store = JsonEvidenceStore(case, case_id="CASE-9")
    store.add_many(scam_case)
    store.save()

    assert main([str(case)]) == 0
    tl = json.loads(capsys.readouterr().out)
    assert tl["case_id"] == "CASE-9" and len(tl["events"]) == 6

    out = tmp_path / "timeline.md"
    assert main([str(case), "--format", "markdown", "--out", str(out)]) == 0
    assert "fraudulent payment" in out.read_text()


def test_cli_reads_jsonl(tmp_path, scam_case, capsys):
    jsonl = tmp_path / "records.jsonl"
    jsonl.write_text("\n".join(json.dumps(r) for r in scam_case))
    assert main([str(jsonl), "--format", "text"]) == 0
    assert "Total loss: INR 5,000.00" in capsys.readouterr().out
