import json
from pathlib import Path

import pytest

from fraud_evidence.ingestion import (
    EvidenceIngestor,
    EvidenceType,
    OCRResult,
    OCRUnavailableError,
)
from fraud_evidence.ingestion.__main__ import main
from fraud_evidence.ingestion.text import extract_entities, normalize_text
from fraud_evidence.ingestion.urls import normalize_url

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class FakeOCR:
    name = "fake"

    def __init__(self, text="", confidence=0.95, error=None):
        self.text, self.confidence, self.error = text, confidence, error

    def extract_text(self, image_bytes):
        if self.error:
            raise self.error
        return OCRResult(text=self.text, engine=self.name, confidence=self.confidence)


@pytest.fixture
def ingestor():
    return EvidenceIngestor(ocr_engine=FakeOCR())


# ---------------------------------------------------------------- text helpers

def test_normalize_text_strips_invisible_chars_and_whitespace():
    raw = "Your  acc​ount is   blocked\r\n\r\n\r\n\r\nClick  now "
    assert normalize_text(raw) == "Your account is blocked\n\nClick now"


def test_normalize_text_folds_fullwidth_lookalikes():
    assert normalize_text("ＳＢＩ ＫＹＣ") == "SBI KYC"


def test_extract_entities_indicators():
    ent = extract_entities(
        "Call +91 98765 43210 or mail help@sbi-care.com. Pay ₹1,500.50 to refund.desk@ybl, "
        "UTR: 412345678901. Visit hxxp://evil[.]com/x"
    )
    assert ent.phone_numbers == ["+919876543210"]
    assert ent.emails == ["help@sbi-care.com"]
    assert ent.upi_ids == ["refund.desk@ybl"]
    assert ent.amounts[0]["value"] == 1500.5 and ent.amounts[0]["currency"] == "INR"
    assert ent.reference_numbers == ["412345678901"]
    assert ent.urls == ["http://evil.com/x"]


def test_emails_are_not_reported_as_upi_ids():
    ent = extract_entities("contact fraud@bank.co.in")
    assert ent.emails == ["fraud@bank.co.in"] and ent.upi_ids == []


# ----------------------------------------------------------------------- URLs

def test_normalize_url_canonicalizes_and_extracts_features():
    info = normalize_url("HXXPS://Login.SBI-KYC[.]XYZ:443/verify?utm_source=sms&id=7#top")
    assert info["canonical"] == "https://login.sbi-kyc.xyz/verify?id=7"
    assert info["registered_domain"] == "sbi-kyc.xyz"
    assert info["tld"] == "xyz"
    assert info["subdomain_depth"] == 1
    assert info["uses_https"]


def test_normalize_url_flags_risky_structures():
    assert normalize_url("http://192.168.1.5/pay")["is_ip_host"]
    assert normalize_url("bit.ly/abc")["is_shortener"]
    puny = normalize_url("https://xn--pypal-4ve.com")
    assert puny["is_punycode"] and puny["display_host"] != puny["host"]
    assert normalize_url("http://user@evil.com")["has_credentials"]


# ------------------------------------------------------------ type detection

@pytest.mark.parametrize("text, expected", [
    ("https://example.com/login", EvidenceType.URL),
    ("hxxp://phish[.]site/a", EvidenceType.URL),
    ("amazon-offer.xyz", EvidenceType.URL),
    ("Congrats! You won a lottery. Click https://win.xyz to claim", EvidenceType.MESSAGE),
    ("Hi mom, new number, send money", EvidenceType.MESSAGE),
    ("Rs.2,000 debited from A/c XX9876 via UPI Ref 312345678901", EvidenceType.TRANSACTION),
    ('{"amount": 100, "to": "a@ybl"}', EvidenceType.TRANSACTION),
    ("date,amount,payee\n2024-01-01,50,x@ybl", EvidenceType.TRANSACTION),
])
def test_detect_text_type(text, expected):
    assert EvidenceIngestor.detect_text_type(text) is expected


# ------------------------------------------------------------------ ingestion

def test_ingest_message(ingestor):
    ev = ingestor.ingest("Your KYC expired. Update at bit.ly/kyc1 or call 9123456789")
    assert ev.evidence_type is EvidenceType.MESSAGE
    assert ev.entities.phone_numbers == ["+919123456789"]
    assert ev.structured["linked_urls"][0]["is_shortener"]
    assert len(ev.content_hash) == 64


def test_ingest_url(ingestor):
    ev = ingestor.ingest("  https://Paytm-Refund.online/claim?gclid=1  ")
    assert ev.evidence_type is EvidenceType.URL
    assert ev.normalized_text == "https://paytm-refund.online/claim"


def test_ingest_transaction_sms(ingestor):
    ev = ingestor.ingest(
        "Rs.5,000.00 debited from A/c XX1234 on 12-03-24 to VPA scam.pay@ybl UPI Ref 412345678901"
    )
    rec = ev.structured["records"][0]
    assert ev.evidence_type is EvidenceType.TRANSACTION
    assert rec["amount"] == 5000.0 and rec["currency"] == "INR"
    assert rec["direction"] == "debit"
    assert rec["receiver"] == "scam.pay@ybl"
    assert rec["sender"] == "XX1234"
    assert rec["transaction_id"] == "412345678901"
    assert rec["timestamp"] == "2024-03-12T00:00:00"
    assert rec["payment_method"] == "UPI"


def test_ingest_transaction_dict_maps_aliases(ingestor):
    ev = ingestor.ingest({"txn_id": "T1", "amount": "₹1,999", "to": "x@paytm",
                          "mode": "upi", "date": "13/03/2024", "device": "android"})
    rec = ev.structured["records"][0]
    assert rec["transaction_id"] == "T1"
    assert rec["amount"] == 1999.0 and rec["currency"] == "INR"
    assert rec["receiver"] == "x@paytm"
    assert rec["payment_method"] == "UPI"
    assert rec["timestamp"] == "2024-03-13T00:00:00"
    assert rec["extra"] == {"device": "android"}
    assert ev.entities.upi_ids == ["x@paytm"]


def test_ingest_bank_statement_csv_infers_direction_from_columns(ingestor):
    csv_text = "Date,Narration,Debit,Credit\n2024-03-12,UPI/abc@ybl,5000,\n2024-03-13,Refund,,200\n"
    ev = ingestor.ingest(csv_text)
    records = ev.structured["records"]
    assert ev.structured["record_count"] == 2
    assert (records[0]["direction"], records[0]["amount"]) == ("debit", 5000.0)
    assert (records[1]["direction"], records[1]["amount"]) == ("credit", 200.0)
    assert "abc@ybl" in ev.entities.upi_ids


def test_ingest_transaction_warns_on_bad_fields(ingestor):
    ev = ingestor.ingest({"amount": "lots", "date": "someday"})
    assert any("amount" in w for w in ev.warnings)
    assert any("timestamp" in w for w in ev.warnings)


def test_ingest_screenshot_runs_ocr_and_classifies_content():
    ocr = FakeOCR("₹ 25,000 debited from A/c XX4321\nUPI Ref 398765432109\nto lucky.draw@okicici")
    ev = EvidenceIngestor(ocr_engine=ocr).ingest(PNG_BYTES)
    assert ev.evidence_type is EvidenceType.SCREENSHOT
    assert ev.metadata["mime_type"] == "image/png"
    assert ev.structured["ocr_engine"] == "fake"
    assert ev.structured["content_type"] == "transaction"
    assert ev.structured["transaction"]["amount"] == 25000.0
    assert ev.entities.upi_ids == ["lucky.draw@okicici"]


def test_screenshot_low_confidence_and_missing_ocr_warn():
    low = EvidenceIngestor(ocr_engine=FakeOCR("blurry", confidence=0.3)).ingest(PNG_BYTES)
    assert any("low OCR confidence" in w for w in low.warnings)

    missing = EvidenceIngestor(ocr_engine=FakeOCR(error=OCRUnavailableError("no tesseract")))
    ev = missing.ingest(PNG_BYTES)
    assert ev.evidence_type is EvidenceType.SCREENSHOT
    assert ev.normalized_text == ""
    assert any("OCR unavailable" in w for w in ev.warnings)


def test_ingest_path_detects_image_by_magic_bytes(tmp_path: Path):
    img = tmp_path / "chat.dat"  # misleading extension
    img.write_bytes(PNG_BYTES)
    ev = EvidenceIngestor(ocr_engine=FakeOCR("Send OTP now")).ingest(img)
    assert ev.evidence_type is EvidenceType.SCREENSHOT
    assert ev.metadata["filename"] == "chat.dat"
    assert ev.source.startswith("file:")


def test_ingest_path_text_file(ingestor, tmp_path: Path):
    f = tmp_path / "sms.txt"
    f.write_text("You won a prize! Claim at https://prize.xyz", encoding="utf-8")
    ev = ingestor.ingest(f)
    assert ev.evidence_type is EvidenceType.MESSAGE
    assert ev.entities.urls == ["https://prize.xyz"]


def test_forced_type_overrides_detection(ingestor):
    ev = ingestor.ingest("https://example.com", evidence_type="message")
    assert ev.evidence_type is EvidenceType.MESSAGE


def test_ingest_many_isolates_failures(ingestor):
    results = ingestor.ingest_many(["hello", 12345, "https://a.com"])
    assert [r.evidence_type for r in results] == [
        EvidenceType.MESSAGE, EvidenceType.MESSAGE, EvidenceType.URL
    ]
    assert results[1].warnings and "ingestion failed" in results[1].warnings[0]


def test_to_dict_is_json_serializable(ingestor):
    ev = ingestor.ingest("Pay Rs 500 to a@ybl")
    data = json.loads(json.dumps(ev.to_dict()))
    assert data["evidence_type"] == "message"
    assert data["entities"]["upi_ids"] == ["a@ybl"]


def test_cli_outputs_json_lines(capsys):
    assert main(["--text", "https://x.com", "--text", "hello"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line)["evidence_type"] for line in lines] == ["url", "message"]
