import json

import pytest

from fraud_evidence.consistency import check_timeline, render_markdown, render_text
from fraud_evidence.consistency.__main__ import main
from fraud_evidence.extraction import InformationExtractor, JsonEvidenceStore
from fraud_evidence.ingestion import EvidenceIngestor
from fraud_evidence.timeline import build_timeline

SCAM_SMS = ("VM-SBIINB: Dear customer your account will be blocked today. "
            "Update KYC at http://sbi-kyc.top/verify")
SCAM_CHAT = ("[12/03/24, 10:40:00 AM] SBI Support: Sir pay Rs 5000 verification fee to "
             "kyc.help@ybl immediately")
DEBIT_SMS = ("Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA kyc.help@ybl "
             "UPI Ref 412345678901")


def extract(item, **metadata):
    return InformationExtractor().extract(EvidenceIngestor().ingest(item, metadata=metadata))


def receipt(amount=5000, to="kyc.help@ybl", date="2024-03-12 10:45:00", ref="412345678901", **extra):
    return extract({"amount": amount, "to": to, "date": date, "transaction_id": ref, **extra})


def party(identifier=None, name=None, kind=None):
    return {"name": name, "identifier": identifier, "identifier_type": kind,
            "raw": identifier or name}


def event(seq, event_type="message", stage="communication", timestamp="2024-03-12T10:00:00+05:30",
          precision="datetime", evidence_id=None, sender=None, receiver=None, amount=None,
          details=None, linked=()):
    return {
        "sequence": seq, "event_type": event_type, "stage": stage, "title": f"event {seq}",
        "evidence_id": evidence_id or f"ev{seq}", "timestamp": timestamp,
        "time_precision": precision if timestamp else "unknown",
        "actors": {"from": sender, "to": receiver}, "amount": amount,
        "details": details or {}, "linked_evidence": list(linked),
    }


def debit(seq, value=5000.0, to="kyc.help@ybl", ref="UTR1", event_type="fraudulent_payment",
          stage="fraud", **kw):
    kw.setdefault("receiver", party(to, kind="upi_id") if to else None)
    return event(seq, event_type, stage, amount={"value": value, "currency": "INR", "direction": "debit"},
                 details={"transaction_id": ref, **kw.pop("details", {})}, **kw)


def types(report):
    return [i["issue_type"] for i in report["issues"]]


def by_type(report, issue_type):
    return next(i for i in report["issues"] if i["issue_type"] == issue_type)


@pytest.fixture
def clean_case():
    sms = extract(SCAM_SMS, timestamp="2024-03-12T10:15:00")
    chat = extract(SCAM_CHAT, sender="+91 99887 76655")
    return [sms, chat, receipt()]


# ------------------------------------------------------------ clean input

def test_consistent_case_has_no_issues(clean_case):
    report = check_timeline(build_timeline(clean_case, case_id="CASE-1"))
    assert report["issues"] == []
    assert report["case_id"] == "CASE-1"
    assert report["summary"]["issue_count"] == 0
    assert report["summary"]["highest_severity"] is None
    assert report["summary"]["events_checked"] == 4


def test_empty_timeline():
    report = check_timeline(build_timeline([]))
    assert report["issues"] == [] and report["summary"]["events_checked"] == 0


# ------------------------------------------------------------------- gaps

def test_missing_timestamp_reported_once_per_evidence():
    tl = build_timeline([extract("Your account is blocked, update KYC at http://sbi-kyc.top/x"),
                         extract({"amount": 700, "to": "a@ybl", "transaction_id": "U1"})])
    missing = [i for i in check_timeline(tl)["issues"] if i["issue_type"] == "missing_timestamp"]
    assert len(missing) == 2
    # The debit is missing its date: that blocks matching it to a statement.
    assert missing[0]["severity"] == "high" and len(missing[0]["events"]) == 1
    # The message and the URL it carries are one evidence item, one issue.
    assert missing[1]["severity"] == "medium" and len(missing[1]["events"]) == 2
    assert len(missing[1]["evidence_ids"]) == 1


def test_date_only_payment_is_low_severity_gap():
    report = check_timeline(build_timeline([extract(SCAM_CHAT, sender="+919988776655"),
                                            extract(DEBIT_SMS)]))
    issue = by_type(report, "date_only_timestamp")
    assert issue["severity"] == "low" and issue["category"] == "gap"


def test_incomplete_transaction_details():
    tl = {"events": [
        debit(1, value=None, to=None, ref=None),
        debit(2, event_type="transaction", stage="transaction", ref=None),
    ]}
    report = check_timeline(tl)
    assert sorted(types(report)) == ["missing_amount", "missing_counterparty",
                                     "missing_transaction_id", "missing_transaction_id"]
    assert by_type(report, "missing_amount")["severity"] == "high"
    ref_gaps = {i["events"][0]: i["severity"] for i in report["issues"]
                if i["issue_type"] == "missing_transaction_id"}
    assert ref_gaps == {1: "medium", 2: "low"}  # a UTR matters most for the fraudulent payment


def test_credit_without_payer_is_gap():
    tl = {"events": [event(1, "scammer_credit", "transaction",
                           amount={"value": 1.0, "currency": "INR", "direction": "credit"},
                           details={"transaction_id": "U9"})]}
    issue = by_type(check_timeline(tl), "missing_counterparty")
    assert issue["field"] == "actors.from.identifier" and "payer" in issue["title"]


def test_suspicious_sender_known_only_by_name():
    report = check_timeline(build_timeline([extract(SCAM_CHAT)]))
    issue = by_type(report, "missing_sender_id")
    assert '"SBI Support"' in issue["description"]
    # A benign message from an unknown sender is not flagged.
    benign = build_timeline([extract("[12/03/24, 10:00:00 AM] Mom: Dinner at 8?")])
    assert check_timeline(benign)["issues"] == []


def test_unlinked_debit_after_contact():
    records = [extract(SCAM_SMS, timestamp="2024-03-12T10:15:00"),
               receipt(amount=999, to="shop@okaxis", date="2024-03-12 11:00:00", ref="U2")]
    issue = by_type(check_timeline(build_timeline(records)), "unlinked_debit")
    assert issue["severity"] == "medium" and len(issue["events"]) == 1


def test_scam_contact_without_any_payment_evidence():
    report = check_timeline(build_timeline([extract(SCAM_SMS, timestamp="2024-03-12T10:15:00")]))
    assert types(report) == ["no_transaction_evidence"]
    assert report["issues"][0]["events"] == []


# --------------------------------------------------------- contradictions

def test_same_reference_with_different_amounts():
    records = [extract(SCAM_CHAT, sender="+919988776655"), extract(DEBIT_SMS), receipt(amount=4000)]
    report = check_timeline(build_timeline(records))
    issue = report["issues"][0]  # the highest-severity issue sorts first
    assert issue["issue_type"] == "amount_mismatch" and issue["severity"] == "high"
    assert issue["category"] == "contradiction"
    assert sorted(v["value"] for v in issue["values"]) == [4000.0, 5000.0]
    assert "₹4,000.00" in issue["description"] and "₹5,000.00" in issue["description"]
    assert report["issues"][0]["issue_id"] == "ISSUE-001"


def test_same_reference_with_conflicting_parties_status_and_time():
    tl = {"events": [
        debit(1, to="kyc.help@ybl", ref="utr 77", sender=party("XX1234", kind="account"),
              details={"status": "SUCCESS"}),
        debit(2, to="refund@paytm", ref="UTR77", sender=party("000000001234", kind="account"),
              details={"status": "FAILED"}, timestamp="2024-03-14T10:00:00+05:30"),
    ]}
    found = set(types(check_timeline(tl)))
    assert {"payee_mismatch", "status_mismatch", "timestamp_mismatch"} <= found
    # XX1234 and 000000001234 are the same masked account (last 4 digits).
    assert "payer_mismatch" not in found


def test_conflicting_payer_accounts():
    tl = {"events": [debit(1, sender=party("XX1234", kind="account")),
                     debit(2, sender=party("XX9876", kind="account"))]}
    assert by_type(check_timeline(tl), "payer_mismatch")["severity"] == "medium"


def test_times_within_tolerance_are_not_a_contradiction():
    tl = {"events": [debit(1, timestamp="2024-03-12T10:45:00+05:30"),
                     debit(2, timestamp="2024-03-12T10:47:00+05:30"),
                     debit(3, timestamp="2024-03-12", precision="date")]}
    assert "timestamp_mismatch" not in types(check_timeline(tl))


def test_agreeing_records_of_one_payment_are_a_duplicate():
    records = [extract(SCAM_CHAT, sender="+919988776655"), extract(DEBIT_SMS), receipt()]
    tl = build_timeline(records)
    assert tl["summary"]["total_loss"] == {"INR": 10000.0}  # counted twice by the timeline
    issue = by_type(check_timeline(tl), "duplicate_transaction")
    assert issue["category"] == "duplicate" and issue["severity"] == "medium"
    assert "counts it 2 times" in issue["description"]


def test_payment_differs_from_requested_amount():
    records = [extract(SCAM_CHAT, sender="+919988776655"), receipt(amount=4500)]
    issue = by_type(check_timeline(build_timeline(records)), "requested_amount_mismatch")
    assert "asked for ₹5,000.00" in issue["description"] and "₹4,500.00" in issue["description"]
    assert len(issue["evidence_ids"]) == 2


def test_matching_requested_amount_is_not_flagged(clean_case):
    assert "requested_amount_mismatch" not in types(check_timeline(build_timeline(clean_case)))


def test_one_name_with_several_sender_ids():
    records = [
        extract("[12/03/24, 10:00:00 AM] SBI Support: your KYC expired, share OTP",
                sender="SBI Support <+91 99887 76655>"),
        extract("[12/03/24, 11:00:00 AM] SBI Support: pay Rs 500 fee now",
                sender="SBI Support <+91 91234 56789>"),
    ]
    report = check_timeline(build_timeline(records))
    issue = by_type(report, "sender_id_conflict")
    assert issue["severity"] == "medium" and len(issue["events"]) == 2
    assert {v["value"] for v in issue["values"]} == {"+919988776655", "+919123456789"}


def test_same_phone_number_formatted_differently_is_not_a_conflict():
    tl = {"events": [event(1, sender=party("+91 99887 76655", "Ravi", "phone")),
                     event(2, sender=party("09988776655", "Ravi", "phone"))]}
    assert check_timeline(tl)["issues"] == []


def test_one_identifier_with_several_names():
    tl = {"events": [event(1, sender=party("+919988776655", "SBI Support", "phone")),
                     event(2, sender=party("+919988776655", "HDFC Care", "phone"))]}
    issue = by_type(check_timeline(tl), "identifier_name_conflict")
    assert issue["severity"] == "low"
    assert "HDFC Care, SBI Support" in issue["description"]


def test_payment_dated_before_linked_contact():
    records = [extract(SCAM_CHAT, sender="+919988776655"),
               receipt(date="2024-03-11 09:00:00")]
    issue = by_type(check_timeline(build_timeline(records)), "payment_before_contact")
    assert issue["severity"] == "medium" and len(issue["events"]) == 2


def test_date_only_payment_same_day_as_contact_is_not_before_it():
    tl = {"events": [
        event(1, "suspicious_message", "contact", sender=party("+919988776655", kind="phone"),
              timestamp="2024-03-12T10:40:00+05:30", evidence_id="msg"),
        debit(2, timestamp="2024-03-12", precision="date", linked=["msg"]),
    ]}
    assert "payment_before_contact" not in types(check_timeline(tl))


# -------------------------------------------------------- output and CLI

def test_issues_sorted_by_severity_then_category():
    records = [extract(SCAM_CHAT), extract(DEBIT_SMS), receipt(amount=4000),
               extract("hxxps://bit.ly/sbi-refund")]
    report = check_timeline(build_timeline(records))
    rank = {"high": 0, "medium": 1, "low": 2}
    keys = [rank[i["severity"]] for i in report["issues"]]
    assert keys == sorted(keys)
    assert [i["issue_id"] for i in report["issues"]] == [
        f"ISSUE-{n:03d}" for n in range(1, len(report["issues"]) + 1)]
    s = report["summary"]
    assert s["issue_count"] == len(report["issues"]) == sum(s["by_category"].values())
    assert s["highest_severity"] == "high"
    json.dumps(report, ensure_ascii=False)


def test_renderers():
    records = [extract(SCAM_CHAT), extract(DEBIT_SMS), receipt(amount=4000)]
    report = check_timeline(build_timeline(records, case_id="CASE-1"))
    text = render_text(report)
    assert "Gaps & contradictions — case CASE-1" in text
    assert "ISSUE-001 !! [contradiction] Conflicting amounts" in text
    md = render_markdown(report)
    assert md.startswith("# Gaps & contradictions — CASE-1")
    assert md.count("\n| ") == len(report["issues"]) + 1
    assert "No issues found" in render_text(check_timeline(build_timeline([])))


def test_cli_reads_timeline(tmp_path, capsys):
    records = [extract(SCAM_CHAT), extract(DEBIT_SMS), receipt(amount=4000)]
    path = tmp_path / "timeline.json"
    path.write_text(json.dumps(build_timeline(records, case_id="CASE-7")))
    assert main([str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["case_id"] == "CASE-7" and "amount_mismatch" in types(report)


def test_cli_builds_timeline_from_case_file(tmp_path, capsys):
    store = JsonEvidenceStore(tmp_path / "case.json", case_id="CASE-8")
    store.add_many([extract(SCAM_CHAT), receipt(amount=4500)])
    store.save()
    out = tmp_path / "issues.md"
    assert main([str(tmp_path / "case.json"), "--format", "markdown", "--out", str(out)]) == 0
    assert out.read_text().startswith("# Gaps & contradictions — CASE-8")

    jsonl = tmp_path / "records.jsonl"
    jsonl.write_text("\n".join(json.dumps(r) for r in [extract(SCAM_CHAT), receipt(amount=4500)]))
    assert main([str(jsonl), "--format", "text"]) == 0
    assert "Paid amount differs" in capsys.readouterr().out
