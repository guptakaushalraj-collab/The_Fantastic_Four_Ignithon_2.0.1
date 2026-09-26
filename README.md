# The_Fantastic_Four_Ignithon_2.0.1
This description is concise, professional, and highlights the problem statement, workflow, and purpose.

## Module 1: Evidence Ingestion

`fraud_evidence.ingestion` turns raw fraud evidence into normalized, tagged `Evidence` records that later modules can consume uniformly.

| Input | Detected as | Normalization |
|---|---|---|
| Image bytes / image file (PNG, JPEG, GIF, BMP, TIFF, WebP; detected by magic bytes) | `screenshot` | OCR via Tesseract (grayscale, autocontrast, upscaling). The OCR text is sub-classified as `message` or `transaction`, and receipts are parsed. |
| A single URL, including defanged ones (`hxxps://evil[.]com`) | `url` | Refang, lowercase the scheme and host, strip default ports, fragments and tracking params (`utm_*`, `gclid`…). Adds host features: IP host, punycode, shortener, subdomain depth, TLD. |
| `dict` / `list[dict]`, JSON, CSV/TSV bank statements, bank/UPI alert SMS | `transaction` | Bank-specific column names map to canonical fields (`transaction_id`, `timestamp`, `amount`, `currency`, `direction`, `sender`, `receiver`, `payment_method`, `status`, `description`). Dates are parsed to ISO-8601. Direction is inferred from debit/credit columns. |
| Any other text (SMS, WhatsApp, email) | `message` | Unicode NFKC, removal of zero-width/bidi characters, whitespace cleanup. |

Every record also carries extracted **entities** (URLs, emails, Indian phone numbers, UPI IDs, amounts with currency, UTR/reference numbers), a SHA-256 `content_hash` for de-duplication and chain of custody, `metadata`, and `warnings` (for example, low OCR confidence or unparseable fields).

```python
from pathlib import Path
from fraud_evidence.ingestion import EvidenceIngestor

ingestor = EvidenceIngestor()
ev = ingestor.ingest("Rs.5,000 debited from A/c XX1234 to VPA scam@ybl UPI Ref 412345678901")
ev.evidence_type          # EvidenceType.TRANSACTION
ev.structured["records"]  # canonical transaction record(s)
ingestor.ingest(Path("chat.png"))                 # screenshot -> OCR
ingestor.ingest("https://x.com", evidence_type="message")  # force a type
```

CLI (outputs JSON Lines):

```bash
python -m fraud_evidence.ingestion screenshot.png statement.csv --text "hxxp://kyc-update[.]xyz" --pretty
```

The OCR backend is pluggable: pass any object with `name` and `extract_text(bytes) -> OCRResult` as `EvidenceIngestor(ocr_engine=...)`. If Tesseract isn't installed, screenshots are still ingested and tagged, with an `OCR unavailable` warning.

Run the tests with `pip install -r requirements.txt && python -m pytest`.
