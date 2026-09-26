import json

import pytest

from fraud_evidence.consistency import check_timeline
from fraud_evidence.extraction import InformationExtractor, JsonEvidenceStore
from fraud_evidence.ingestion import EvidenceIngestor
from fraud_evidence.redaction import PLACEHOLDER, Redactor, redact
from fraud_evidence.redaction.__main__ import main
from fraud_evidence.timeline import build_timeline

SCAM_CHAT = ("[12/03/24, 10:40:00 AM] SBI Support: Sir pay Rs 5000 to kyc.help@ybl or call "
             "98765 43210, or mail agent.sbi@gmail.com")
DEBIT_SMS = ("Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA kyc.help@ybl "
             "UPI Ref 412345678901")

SENSITIVE = ["kyc.help@ybl", "98765 43210", "agent.sbi@gmail.com", "XX1234",
             "99887 76655", "9988776655"]


def extract(item, **metadata):
    return InformationExtractor().extract(EvidenceIngestor().ingest(item, metadata=metadata))


@pytest.fixture
def records():
    return [extract(SCAM_CHAT, sender="SBI Support <+91 99887 76655>"), extract(DEBIT_SMS)]


def leaks(document) -> list[str]:
    text = json.dumps(document, ensure_ascii=False)
    return [s for s in SENSITIVE if s in text]


# ---------------------------------------------------------- free-text patterns

@pytest.mark.parametrize("text, expected", [
    ("mail agent.sbi@gmail.com now", f"mail {PLACEHOLDER} now"),
    ("pay to kyc.help@ybl.", f"pay to {PLACEHOLDER}."),
    ("call +91 98765 43210 or 09876543210", f"call {PLACEHOLDER} or {PLACEHOLDER}"),
    ("call 9876543210", f"call {PLACEHOLDER}"),
    ("debited from A/c XX1234 today", f"debited from A/c {PLACEHOLDER} today"),
    ("Account No: 123456789012 frozen", f"Account No: {PLACEHOLDER} frozen"),
    ("acct ending in 4321", f"acct ending in {PLACEHOLDER}"),
    ("card **5678 was charged", f"card {PLACEHOLDER} was charged"),
    ("card 4111 1111 1111 1111 exp 12/27", f"card {PLACEHOLDER} exp 12/27"),
])
def test_patterns(text, expected):
    assert Redactor().redact_text(text) == expected


@pytest.mark.parametrize("text", [
    "UPI Ref 412345678901",           # reference numbers are kept
    "Rs 5,000 paid on 12-03-2024 at 10:40",
    "visit http://sbi-kyc.top/verify",
    "order 1234567890123",            # 13 digits but not a valid card number
    "SMS from VM-SBIINB",
])
def test_non_sensitive_text_is_kept(text):
    assert Redactor().redact_text(text) == text


def test_reference_number_that_looks_like_a_phone_is_kept():
    doc = {"transaction_id": "919876543210", "description": "UTR 919876543210 credited"}
    assert redact(doc) == doc


# ------------------------------------------------------------ structured data

def test_records_are_fully_redacted(records):
    assert leaks(records)  # sanity check: the fixture contains the values
    result = Redactor().redact(records)
    assert leaks(result.document) == []

    chat, sms = result.document
    assert chat["sender"] == {"name": "SBI Support", "identifier": PLACEHOLDER,
                              "identifier_type": "phone", "raw": f"SBI Support <{PLACEHOLDER}>"}
    assert chat["contacts"]["upi_ids"] == [PLACEHOLDER]
    assert chat["contacts"]["emails"] == [PLACEHOLDER]
    assert chat["contacts"]["phone_numbers"] == [PLACEHOLDER]
    assert chat["message"]["content"] == (f"SBI Support: Sir pay Rs 5000 to {PLACEHOLDER} or call "
                                          f"{PLACEHOLDER}, or mail {PLACEHOLDER}")
    txn = sms["transactions"][0]
    assert txn["sender"]["identifier"] == PLACEHOLDER and txn["receiver"]["raw"] == PLACEHOLDER
    assert txn["description"] == (f"Rs.5,000.00 debited from A/c {PLACEHOLDER} on 12-03-24 to VPA "
                                  f"{PLACEHOLDER} UPI Ref 412345678901")


def test_investigative_fields_are_kept(records):
    chat, sms = redact(records)
    for original, red in zip(records, (chat, sms)):
        for key in ("evidence_id", "content_hash", "timestamp", "field_sources", "urls"):
            assert red[key] == original[key]
    assert sms["transaction"] == records[1]["transaction"]
    assert sms["contacts"]["reference_numbers"] == ["412345678901"]
    assert chat["message"]["amounts_mentioned"] == records[0]["message"]["amounts_mentioned"]
    assert chat["sender"]["name"] == "SBI Support"


def test_input_is_not_modified(records):
    before = json.dumps(records)
    redact(records)
    assert json.dumps(records) == before


def test_identifier_found_in_a_field_is_removed_from_all_text():
    # "000012345678" matches no pattern on its own, but the statement names it as an account.
    doc = {
        "sender": {"name": None, "identifier": "000012345678", "identifier_type": "account",
                   "raw": "000012345678"},
        "description": "NEFT/000012345678/refund",
        "note": "same account 000012345678 again",
    }
    red = Redactor().redact(doc)
    assert "000012345678" not in json.dumps(red.document)
    assert red.document["description"] == f"NEFT/{PLACEHOLDER}/refund"
    assert red.counts == {"account": 4}


def test_non_sensitive_identifier_types_are_kept():
    party = {"name": None, "identifier": "VM-SBIINB", "identifier_type": "sms_sender_id",
             "raw": "VM-SBIINB"}
    assert redact({"sender": party}) == {"sender": party}


def test_counts_by_type(records):
    counts = Redactor().redact(records).counts
    assert set(counts) == {"phone", "email", "upi_id", "account"}
    assert all(n > 0 for n in counts.values())


def test_selected_types_only(records):
    chat, sms = redact(records, types=["email"])
    assert "agent.sbi@gmail.com" not in json.dumps(chat)
    assert "kyc.help@ybl" in json.dumps(chat) and "XX1234" in json.dumps(sms)
    assert chat["contacts"]["upi_ids"] == ["kyc.help@ybl"]


def test_custom_placeholder_and_unknown_type():
    assert Redactor(placeholder="***").redact_text("call 9876543210") == "call ***"
    with pytest.raises(ValueError):
        Redactor(types=["aadhaar"])


def test_later_module_outputs_are_redacted(records):
    timeline = build_timeline(records, case_id="CASE-1")
    report = check_timeline(timeline)
    for doc in (timeline, report):
        red = redact(doc)
        assert leaks(red) == []
        assert red["case_id"] == "CASE-1"
    red_tl = redact(timeline)
    assert [e["evidence_id"] for e in red_tl["events"]] == [e["evidence_id"] for e in timeline["events"]]
    assert red_tl["summary"]["suspect_identifiers"] == [PLACEHOLDER, PLACEHOLDER]


def test_non_string_values_untouched():
    doc = {"amount": 9876543210, "ok": True, "none": None, "items": [1, 2.5]}
    assert redact(doc) == doc


# ------------------------------------------------------------------------ CLI

def test_cli_case_file(tmp_path, records, capsys):
    store = JsonEvidenceStore(tmp_path / "case.json", case_id="CASE-2")
    store.add_many(records)
    store.save()
    out = tmp_path / "redacted.json"
    assert main([str(tmp_path / "case.json"), "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["case_id"] == "CASE-2" and len(doc["records"]) == 2
    assert leaks(doc) == []
    assert capsys.readouterr().err.startswith("redacted ")


def test_cli_jsonl_keeps_line_format(tmp_path, records, capsys):
    jsonl = tmp_path / "records.jsonl"
    jsonl.write_text("\n".join(json.dumps(r) for r in records))
    assert main([str(jsonl), "--types", "email,upi_id"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    docs = [json.loads(line) for line in lines]
    assert "kyc.help@ybl" not in json.dumps(docs) and "XX1234" in json.dumps(docs)


def test_cli_rejects_unknown_type(tmp_path):
    with pytest.raises(SystemExit):
        main(["--types", "aadhaar"])
