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

## Module 2: Information Extraction

`fraud_evidence.extraction` takes Module 1 evidence (the `Evidence` objects or their JSON form) and extracts the key fields into one structured JSON record per item. The record format is defined in [`fraud_evidence/extraction/schema.json`](fraud_evidence/extraction/schema.json).

| Field | How it is extracted |
|---|---|
| `sender` / `receiver` | From email headers (`From:`/`To:`), WhatsApp export lines, SMS sender IDs (`VM-SBIINB`), or transaction records. For statements, it falls back to a UPI ID found in the narration. Each party is `{name, identifier, identifier_type, raw}`, where `identifier_type` is one of `phone`, `email`, `upi_id`, `account` or `sms_sender_id`. |
| `timestamp` | The time of the event (not of ingestion), as ISO-8601. Taken from the email `Date:` header, the chat line time, the transaction date or a date in the text. |
| `transaction` | Amount, currency, direction, transaction/UTR ID, method and status. For statements, it also gives `record_count`, `total_debit`, `total_credit` and `max_amount`; `transactions` lists every record. |
| `urls` | A reputation for each URL: a `score` from 0 to 100, a `verdict` (`benign`, `suspicious` or `malicious`) and the `signals` behind it. Signals cover brand impersonation, abused TLDs, IP hosts, punycode, shorteners, phishing keywords and known official domains. |
| `message` | The body with headers and chat timestamps removed, plus `subject`, `platform` (`email`/`sms`/`chat`), `participants`, `amounts_mentioned` and `ocr_confidence` for screenshots. |
| `contacts` | All phone numbers, emails, UPI IDs and reference numbers found. |
| `field_sources` | Where each field came from (`header`, `chat_export`, `transaction`, `text`, `metadata`…), for auditability. |

Values the reporter supplies when submitting (for example `metadata={"sender": "+91 99887 76655"}` in Module 1) override the inferred ones.

URL reputation works offline by default. You can plug in threat-intel feeds with `ListProvider(blocklist, allowlist)`, or add an online service (Safe Browsing, VirusTotal…) by implementing `ReputationProvider.lookup()`.

```python
from fraud_evidence.ingestion import EvidenceIngestor
from fraud_evidence.extraction import InformationExtractor, JsonEvidenceStore

record = InformationExtractor().extract(EvidenceIngestor().ingest(raw_item))
store = JsonEvidenceStore("cases/CASE-001.json", case_id="CASE-001")
store.add(record)
store.save()  # atomic write; records are de-duplicated by evidence_id
```

CLI, chained with Module 1:

```bash
python -m fraud_evidence.ingestion chat.png statement.csv --text "hxxp://kyc-update[.]xyz" \
  | python -m fraud_evidence.extraction --out cases/CASE-001.json --case-id CASE-001 --blocklist feeds/bad_domains.txt
```

## Module 3: Chronological Timeline

`fraud_evidence.timeline` takes Module 2's extracted records and builds an ordered list of timestamped events, each with a description, plus a case summary.

**How events are built**
- A suspicious message becomes a `suspicious_message` event, plus a `malicious_url`/`suspicious_url` event for each bad link it carries.
- A bank statement becomes one event per transaction.
- A message is suspicious if it has a bad URL, or contains scam language: a credential request (OTP/PIN/KYC), a payment request, an account threat, job/investment bait, or two weaker signals (urgency, reward bait).

**How events are linked**
- A debit to a UPI ID, phone or email that appeared in suspicious evidence becomes a `fraudulent_payment` (or a `fraud_attempt` if it failed). It lists `linked_evidence` IDs pointing back to the messages that named the account.
- A credit from a suspect becomes `scammer_credit`, for example a ₹1 "test" payment.
- A suspicious message after a loss becomes a `follow_up_message`.

**How events are sorted**
- Events are sorted by timestamp. Times without an offset are read as `Asia/Kolkata` by default; change this with `--tz`.
- Date-only entries, such as statement rows, go at the end of their day, so the scam message that caused a payment comes before it.
- Events at the same time follow the fraud sequence: contact → lure → transaction → fraud → follow-up.
- Undated evidence goes last.

**Summary:** attack chain (e.g. `suspicious message → malicious URL → fraudulent payment → follow-up message`), total loss per currency, time from first contact to first loss, suspect identifiers and highest severity.

```python
from fraud_evidence.timeline import build_timeline, render_text
timeline = build_timeline(records, case_id="CASE-001")   # records from Module 2
print(render_text(timeline))
```

```
Attack chain: suspicious message → malicious URL → fraudulent payment → follow-up message
Total loss: INR 5,000.00
  1. 2024-03-12 10:15:00  [contact] ! Suspicious SMS from VM-SBIINB
  2. 2024-03-12 10:15:00  (+0s)  [lure] !! Malicious URL shared by VM-SBIINB: sbi-kyc.top
  3. 2024-03-12 10:40:00  (+25m)  [contact] ! Suspicious chat message from SBI Support
  4. 2024-03-12 (date only)  [fraud] !!! Fraudulent payment: Debit of ₹5,000.00 to kyc.help@ybl
  5. 2024-03-13 09:00:00  (+22h 20m)  [follow_up] !! Follow-up chat message from SBI Support
```

CLI (reads a Module 2 case file, a JSON list or JSON Lines; outputs `json`, `text` or `markdown`):

```bash
python -m fraud_evidence.timeline cases/CASE-001.json --format markdown --out cases/CASE-001-timeline.md
```
