import json

import pytest

from fraud_evidence.extraction import (
    InformationExtractor,
    JsonEvidenceStore,
    ListProvider,
    URLReputationScorer,
    load_schema,
    make_party,
    parse_datetime,
)
from fraud_evidence.extraction.__main__ import main
from fraud_evidence.ingestion import EvidenceIngestor, OCRResult

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class FakeOCR:
    name = "fake"

    def __init__(self, text):
        self.text = text

    def extract_text(self, image_bytes):
        return OCRResult(text=self.text, engine=self.name, confidence=0.9)


def run(item, ocr_text="", **kwargs):
    ev = EvidenceIngestor(ocr_engine=FakeOCR(ocr_text)).ingest(item, **kwargs)
    return InformationExtractor().extract(ev)


def validate(record):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(record, load_schema())


# ----------------------------------------------------------------- parties

@pytest.mark.parametrize("raw, identifier, id_type", [
    ("scam.pay@ybl", "scam.pay@ybl", "upi_id"),
    ("Help Desk <help@sbi-care.com>", "help@sbi-care.com", "email"),
    ("98765 43210", "+919876543210", "phone"),
    ("+91-9876543210", "+919876543210", "phone"),
    ("XX1234", "XX1234", "account"),
    ("VM-SBIINB", "VM-SBIINB", "sms_sender_id"),
    ("Amazon Pay", None, None),
])
def test_make_party_classifies_identifiers(raw, identifier, id_type):
    party = make_party(raw)
    assert party["identifier"] == identifier
    assert party["identifier_type"] == id_type
    assert party["raw"] == raw


def test_make_party_keeps_display_names():
    assert make_party("Help Desk <help@x.com>")["name"] == "Help Desk"
    assert make_party("Amazon Pay")["name"] == "Amazon Pay"
    assert make_party(None) is None


@pytest.mark.parametrize("raw, expected", [
    ("12/03/24 10:15:02 AM", "2024-03-12T10:15:02"),
    ("12/03/2024, 9:05 pm", "2024-03-12T21:05:00"),
    ("Tue, 12 Mar 2024 10:15:00 +0530", "2024-03-12T10:15:00+05:30"),
    ("2024-03-12", "2024-03-12T00:00:00"),
    ("not a date", None),
])
def test_parse_datetime(raw, expected):
    assert parse_datetime(raw) == expected


# -------------------------------------------------------------- reputation

def test_reputation_flags_brand_impersonation_as_malicious():
    rep = URLReputationScorer().score("hxxps://sbi-kyc-update[.]xyz/login")
    names = {s.name for s in rep.signals}
    assert rep.verdict == "malicious" and rep.score >= 60
    assert {"brand_impersonation", "suspicious_tld", "phishing_keywords"} <= names


def test_reputation_trusts_official_domains():
    rep = URLReputationScorer().score("https://www.hdfcbank.com/personal")
    assert rep.verdict == "benign" and rep.score == 0
    assert rep.domain == "hdfcbank.com"


def test_reputation_handles_multi_part_suffix():
    rep = URLReputationScorer().score("https://retail.onlinesbi.sbi.co.in/login")
    assert rep.domain == "sbi.co.in"
    assert "brand_impersonation" not in {s.name for s in rep.signals}


def test_reputation_structural_signals():
    scorer = URLReputationScorer()
    assert "ip_address_host" in {s.name for s in scorer.score("http://103.21.4.9/pay").signals}
    assert scorer.score("bit.ly/x1").verdict == "suspicious"


def test_list_provider_overrides():
    scorer = URLReputationScorer([ListProvider(blocklist=["evil.com"], allowlist=["sbi-kyc.xyz"])])
    blocked = scorer.score("https://login.evil.com")
    assert blocked.verdict == "malicious" and "lists" in blocked.sources
    assert scorer.score("https://sbi-kyc.xyz/login").score == 0


# -------------------------------------------------------------- extraction

def test_extract_url_evidence():
    rec = run("hxxp://paytm-refund[.]online/claim")
    assert rec["evidence_type"] == "url"
    assert rec["urls"][0]["verdict"] == "malicious"
    assert rec["sender"] is None and rec["message"] is None
    validate(rec)


def test_extract_sms_with_sender_id():
    rec = run("VM-SBIINB: Your account is blocked. Update KYC at http://sbi-kyc.top/verify "
              "or call 9876543210")
    assert rec["sender"]["identifier"] == "VM-SBIINB"
    assert rec["sender"]["identifier_type"] == "sms_sender_id"
    assert rec["message"]["platform"] == "sms"
    assert rec["message"]["content"].startswith("Your account is blocked")
    assert rec["contacts"]["phone_numbers"] == ["+919876543210"]
    assert rec["urls"][0]["verdict"] == "malicious"
    assert rec["field_sources"]["sender"] == "sms_header"
    validate(rec)


def test_extract_whatsapp_export():
    chat = ("[12/03/24, 10:15:02 AM] Rahul Sharma: Sir send Rs 5000 to rahul.pay@ybl for refund\n"
            "[12/03/24, 10:16:40 AM] Me: ok")
    rec = run(chat)
    assert rec["sender"]["name"] == "Rahul Sharma"
    assert rec["receiver"]["name"] == "Me"
    assert rec["timestamp"] == "2024-03-12T10:15:02"
    assert rec["message"]["platform"] == "chat"
    assert rec["message"]["participants"] == ["Rahul Sharma", "Me"]
    assert rec["message"]["amounts_mentioned"][0]["value"] == 5000.0
    assert rec["contacts"]["upi_ids"] == ["rahul.pay@ybl"]
    assert rec["transaction"] is None
    validate(rec)


def test_extract_email_headers():
    email = ("From: SBI Alerts <alerts@sbi-secure.info>\nTo: victim@gmail.com\n"
             "Date: Tue, 12 Mar 2024 10:15:00 +0530\nSubject: KYC pending\n\n"
             "Click https://sbi-secure.info/kyc now")
    rec = run(email)
    assert rec["sender"] == {"name": "SBI Alerts", "identifier": "alerts@sbi-secure.info",
                             "identifier_type": "email", "raw": "SBI Alerts <alerts@sbi-secure.info>"}
    assert rec["receiver"]["identifier"] == "victim@gmail.com"
    assert rec["timestamp"] == "2024-03-12T10:15:00+05:30"
    assert rec["message"]["subject"] == "KYC pending"
    assert rec["message"]["content"] == "Click https://sbi-secure.info/kyc now"
    assert rec["urls"][0]["verdict"] == "malicious"
    validate(rec)


def test_extract_transaction_sms():
    rec = run("Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA scam.pay@ybl "
              "UPI Ref 412345678901")
    assert rec["sender"]["identifier_type"] == "account"
    assert rec["receiver"]["identifier"] == "scam.pay@ybl"
    assert rec["timestamp"] == "2024-03-12T00:00:00"
    assert rec["transaction"]["amount"] == 5000.0
    assert rec["transaction"]["transaction_id"] == "412345678901"
    assert rec["transaction"]["direction"] == "debit"
    validate(rec)


def test_extract_statement_aggregates_and_uses_narration():
    rec = run("date,narration,debit,credit\n2024-03-12,UPI/abc@ybl/pay,5000,\n"
              "2024-03-13,UPI/refund@ybl,,200\n2024-03-14,UPI/abc@ybl,1500,\n")
    t = rec["transaction"]
    assert t["record_count"] == 3
    assert t["total_debit"] == 6500.0 and t["total_credit"] == 200.0
    assert t["max_amount"] == 5000.0
    assert rec["receiver"]["identifier"] == "abc@ybl"
    assert rec["transactions"][1]["sender"]["identifier"] == "refund@ybl"
    validate(rec)


def test_extract_screenshot_receipt():
    rec = run(PNG_BYTES, ocr_text="₹ 25,000 debited from A/c XX4321\nUPI Ref 398765432109\n"
                                  "to lucky.draw@okicici")
    assert rec["evidence_type"] == "screenshot"
    assert rec["transaction"]["amount"] == 25000.0
    assert rec["receiver"]["identifier"] == "lucky.draw@okicici"
    assert rec["message"]["ocr_confidence"] == 0.9
    validate(rec)


def test_metadata_overrides_inferred_fields():
    rec = run("Pay now to avoid penalty", metadata={
        "sender": "+91 99887 76655", "timestamp": "2024-03-12T09:00:00"})
    assert rec["sender"]["identifier"] == "+919988776655"
    assert rec["field_sources"]["sender"] == "metadata"
    assert rec["timestamp"] == "2024-03-12T09:00:00"


def test_accepts_dict_form_of_evidence():
    ev = EvidenceIngestor().ingest("https://example.com").to_dict()
    rec = InformationExtractor().extract(json.loads(json.dumps(ev)))
    assert rec["evidence_id"] == ev["evidence_id"]


# ------------------------------------------------------------------- storage

def test_store_roundtrip_and_dedupes(tmp_path):
    path = tmp_path / "cases" / "case.json"
    rec = run("hello")
    store = JsonEvidenceStore(path, case_id="CASE-1")
    store.add(rec)
    store.add(rec)
    store.save()

    doc = json.loads(path.read_text())
    assert doc["case_id"] == "CASE-1" and doc["record_count"] == 1

    reopened = JsonEvidenceStore(path)
    reopened.add(run("another"))
    reopened.save()
    assert JsonEvidenceStore(path).get(rec["evidence_id"]) == rec
    assert json.loads(path.read_text())["record_count"] == 2
    assert not list(path.parent.glob("*.tmp"))


def test_cli_pipes_module1_output(tmp_path, monkeypatch, capsys):
    from fraud_evidence.ingestion.__main__ import main as ingest_main

    ingest_main(["--text", "https://bit.ly/x", "--text", "VM-HDFCBK: OTP is 1234"])
    jsonl = tmp_path / "evidence.jsonl"
    jsonl.write_text(capsys.readouterr().out)
    blocklist = tmp_path / "block.txt"
    blocklist.write_text("# feed\nbit.ly\n")

    out = tmp_path / "case.json"
    assert main([str(jsonl), "--out", str(out), "--case-id", "C1",
                 "--blocklist", str(blocklist)]) == 0
    doc = json.loads(out.read_text())
    assert doc["record_count"] == 2
    url_rec = next(r for r in doc["records"] if r["evidence_type"] == "url")
    assert url_rec["urls"][0]["verdict"] == "malicious"
