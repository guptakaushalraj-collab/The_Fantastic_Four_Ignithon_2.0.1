"""Printed bank statements and PDF evidence (all names and numbers are made up)."""

import json

import pytest

from fraud_evidence.extraction import InformationExtractor
from fraud_evidence.extraction.extractor import make_party
from fraud_evidence.ingestion import EvidenceIngestor, EvidenceType, OCRResult
from fraud_evidence.ingestion.pdf import PDFPage, is_pdf, read_pdf
from fraud_evidence.ingestion.statement import looks_like_statement, parse_statement_text
from fraud_evidence.report import IncidentReportBuilder, render_text

# OCR of a scanned statement (Tesseract --psm 6), with its usual noise: narration
# above and below the dates, a balance on a narration line, "2536. 62Cr" spacing,
# a Cr marker read as "C", and a row that wraps "BRAN" / "CH : ...".
OCR_PAGE = """\
STATEMENT OF ACCOUNT
Ravi Kumar Verma
Account No : 1234567890
Post Date Value Details Chq.No. Debit Credit Balance
Brought Forward 2776.61cr
YESBOYBLUPI/Jar Gold /XXXXX
/JARGOLDONLINE@ybl /UPI/6245217 2746.61C
02/09/26 02/09/26 64705/Subscription Debit N /BRANCH 30.00
: ATM SERVICE BRANCH
FDRL0001382/Mr SHOP KEEPER
02/09/26 02/09/26 /UPI/613321222747/Pay to BharatPe 210.00 2536. 61Cr
ANCH : ATM SERVICE BRANCH
Ravi Kumar Verma
02/09/26 02/09/26 /TRANSFER FROM 78935568 200000.00 202536.61Cr
66 BRANCH : Main Road CITY
| trf / TRANSFER TO 5024576364/SOME-COLLEGE
92/09/26 02/09/26 FEES /BRAN 425418 '86000.00 116536.61Cr
CH : Main Road CITY
BDBL0002604/SOME PERSON
02/09/26 02/09/26 /XXXXX62191/9835562191@axl /UPI/61 500.00 116036.61Cr
3332104413/Sent using Paytm UPI /BRANCH : ATM SERVICE BRANCH
Carried Forward 116036.61Cr
Statement Summary Dr. Count:4 Cr. Count:1 86740.00 200000.00
"""


def rows(statement):
    return [(r["direction"], r["amount"], r["balance"]) for r in statement.records]


# ------------------------------------------------------------------ parsing

def test_statement_rows_read_from_ocr():
    st = parse_statement_text(OCR_PAGE)
    assert st.account == "1234567890"
    assert st.opening_balance == 2776.61 and st.closing_balance == 116036.61
    assert rows(st) == [
        ("debit", 30.0, 2746.61),
        ("debit", 210.0, 2536.61),
        ("credit", 200000.0, 202536.61),
        ("debit", 86000.0, 116536.61),
        ("debit", 500.0, 116036.61),
    ]
    assert st.warnings == []  # the summary's counts and totals match
    assert st.summary == {"debit_count": 4, "credit_count": 1, "debit_total": 86740.0,
                          "credit_total": 200000.0}


def test_statement_row_details():
    records = parse_statement_text(OCR_PAGE).records
    upi, _, transfer_in, fees, _ = records
    assert upi["reference"] == "624521764705"  # wrapped over two lines
    assert upi["receiver"] == "jargoldonline@ybl" and upi["sender"] == "A/c 1234567890"
    assert upi["payment_method"] == "UPI"
    assert transfer_in["sender"] == "A/c 78935568" and transfer_in["receiver"] == "A/c 1234567890"
    assert "cheque_number" not in transfer_in  # the account number before the amount is not a cheque
    assert fees["date"] == "2026-09-02"  # "92/09/26" is OCR for 02/09/26
    assert fees["receiver"] == "A/c 5024576364"  # narration wrapped as BRAN / CH
    assert fees["cheque_number"] == "425418"
    assert "SOME-COLLEGE" in fees["narration"]


def test_missing_balance_is_solved_from_the_next_row():
    text = OCR_PAGE.replace("210.00 2536. 61Cr", "210.00")
    st = parse_statement_text(text)
    assert rows(st)[1] == ("debit", 210.0, 2536.61)
    assert st.warnings == []


def test_misread_balance_is_corrected_by_the_printed_amount():
    st = parse_statement_text(OCR_PAGE.replace("202536.61Cr", "202536.67Cr"))
    assert rows(st)[2] == ("credit", 200000.0, 202536.61)


def test_summary_mismatch_warns_about_missing_rows():
    text = OCR_PAGE.replace("Dr. Count:4", "Dr. Count:6").replace("86740.00", "99999.00")
    warnings = parse_statement_text(text).warnings
    assert any("summary lists 6 debits" in w and "missing" in w for w in warnings)


def test_unreadable_amount_warns():
    text = OCR_PAGE.replace("/UPI/613321222747/Pay to BharatPe 210.00", "/UPI/613321222747/Pay")
    st = parse_statement_text(text)
    assert any("row 2: amount 210.00 taken from the balance change" in w for w in st.warnings)
    assert rows(st)[1] == ("debit", 210.0, 2536.61)


def test_not_a_statement():
    assert parse_statement_text("Your account is blocked, share OTP") is None
    assert not looks_like_statement("Dinner at 8?")


# --------------------------------------------------------------- ingestion

class FakeOCR:
    name = "fake"

    def __init__(self, text, confidence=0.9, **details):
        self.text, self.confidence, self.details = text, confidence, details

    def extract_text(self, image_bytes):
        return OCRResult(self.text, self.name, self.confidence, dict(self.details))


def fake_pdf(monkeypatch, pages):
    monkeypatch.setattr("fraud_evidence.ingestion.pipeline.read_pdf", lambda data: pages)
    return b"%PDF-1.7\n%fake"


def test_scanned_pdf_statement_becomes_transaction(monkeypatch):
    data = fake_pdf(monkeypatch, [PDFPage(1, None, b"png")])
    # The first OCR pass garbles the table; the reading that reconciles is kept.
    garbled = FakeOCR(OCR_PAGE.replace("Brought Forward 2776.61cr", "Brought Forward"),
                      confidence=0.95)
    clean = FakeOCR(OCR_PAGE, confidence=0.8, psm=6)
    ev = EvidenceIngestor(document_ocr_engines=[garbled, clean]).ingest(data)
    assert ev.evidence_type is EvidenceType.TRANSACTION
    assert ev.metadata["mime_type"] == "application/pdf" and ev.metadata["format"] == "statement"
    assert ev.structured["record_count"] == 5
    page = ev.structured["pages"][0]
    assert page["method"] == "ocr" and page["ocr_options"] == {"psm": 6}
    assert page["statement"]["account"] == "1234567890"
    first = ev.structured["records"][0]
    assert first["timestamp"] == "2026-09-02T00:00:00" and first["amount"] == 30.0
    assert first["transaction_id"] == "624521764705"
    assert first["extra"]["balance"] == 2746.61 and first["extra"]["page"] == 1


def test_pdf_with_text_layer_that_is_not_a_statement(monkeypatch):
    data = fake_pdf(monkeypatch, [PDFPage(1, "From: a@evil.info\nPay the fee now", None)])
    ev = EvidenceIngestor(document_ocr_engines=[FakeOCR("unused")]).ingest(data)
    assert ev.evidence_type is EvidenceType.MESSAGE
    assert "Pay the fee now" in ev.normalized_text
    assert ev.structured["pages"] == [{"page": 1, "method": "text"}]


def test_pdf_is_never_read_as_text(monkeypatch):
    def unavailable(data):
        from fraud_evidence.ingestion.pdf import PDFUnavailableError
        raise PDFUnavailableError("PDF support requires 'pdfplumber'")
    monkeypatch.setattr("fraud_evidence.ingestion.pipeline.read_pdf", unavailable)
    ev = EvidenceIngestor().ingest(b"%PDF-1.7\n1 0 obj << >> endobj")
    assert ev.normalized_text == "" and ev.warnings == ["PDF support requires 'pdfplumber'"]


def test_real_pdf_text_layer():
    pytest.importorskip("pdfplumber")
    content = b"BT /F1 12 Tf 72 720 Td (Your account is blocked. Share the OTP to unblock it now.) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf, offsets = b"%PDF-1.4\n", []
    for n, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    pdf += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objects) + 1, xref)

    assert is_pdf(pdf)
    pages = read_pdf(pdf)
    assert len(pages) == 1 and "Share the OTP" in pages[0].text
    ev = EvidenceIngestor().ingest(pdf)
    assert ev.evidence_type is EvidenceType.MESSAGE and "Share the OTP" in ev.normalized_text


def test_statement_text_pasted_as_string():
    ev = EvidenceIngestor().ingest(OCR_PAGE)
    assert ev.evidence_type is EvidenceType.TRANSACTION
    assert ev.metadata["format"] == "statement" and ev.structured["record_count"] == 5


# ----------------------------------------------------- downstream modules

@pytest.mark.parametrize("raw, kind, identifier", [
    ("A/c 7210933889", "account", "7210933889"),       # 10 digits, but marked as an account
    ("50431698659", "account", "50431698659"),         # 11-digit account, not a phone
    ("9988776655", "phone", "+919988776655"),
    ("+91 99887 76655", "phone", "+919988776655"),
    ("09988776655", "phone", "+919988776655"),
    ("+44 20 7946 0958", "phone", "+442079460958"),
])
def test_party_classification(raw, kind, identifier):
    party = make_party(raw)
    assert (party["identifier_type"], party["identifier"]) == (kind, identifier)


def test_statement_report_redacts_account_numbers(monkeypatch):
    data = fake_pdf(monkeypatch, [PDFPage(1, None, b"png")])
    ev = EvidenceIngestor(document_ocr_engines=[FakeOCR(OCR_PAGE)]).ingest(data)
    record = InformationExtractor().extract(ev)
    report = IncidentReportBuilder().build_from_records([record], case_id="S-1")
    text = json.dumps(report, ensure_ascii=False) + render_text(report)
    for secret in ("1234567890", "78935568", "5024576364", "9835562191", "jargoldonline"):
        assert secret not in text
    assert "624521764705" in text  # UPI reference kept
    assert report["executive_summary"]["assessment"] == "No fraud indicators found"
    assert "attack followed" not in report["executive_summary"]["text"]
