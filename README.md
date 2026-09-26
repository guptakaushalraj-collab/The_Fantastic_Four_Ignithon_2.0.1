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

## Module 4: Gap & Contradiction Detection

`fraud_evidence.consistency` takes a Module 3 timeline and returns a list of flagged issues. Each issue has an `issue_id`, a `category` (`gap`, `contradiction` or `duplicate`), an `issue_type`, a `severity` (`low`, `medium`, `high`), the timeline `events` (sequence numbers) and `evidence_ids` involved, the conflicting `values`, and a `suggestion` for what to collect or check next. Issues are sorted by severity.

**Gaps (missing or incomplete details)**

| Issue type | Flagged when |
|---|---|
| `missing_timestamp` | Evidence has no date (high for payments, medium otherwise; reported once per evidence item). |
| `date_only_timestamp` | A payment has a date but no time, so its order against same-day messages is inferred. |
| `missing_amount` | A transaction amount could not be read. |
| `missing_counterparty` | A debit has no payee UPI ID/account/phone, or a credit has no payer. |
| `missing_transaction_id` | A payment has no UTR/reference (medium for fraudulent payments). |
| `missing_sender_id` | A suspicious message's sender is unknown or known only by a display name. |
| `unlinked_debit` | A debit follows suspicious contact but its payee appears in no suspicious evidence. |
| `no_transaction_evidence` | The case has suspicious contact but no payment records at all. |

**Contradictions**

| Issue type | Flagged when |
|---|---|
| `amount_mismatch`, `currency_mismatch`, `direction_mismatch`, `payee_mismatch`, `payer_mismatch`, `status_mismatch`, `timestamp_mismatch` | Two records with the same transaction reference disagree (e.g. a receipt says ₹4,000 and the statement says ₹5,000). Masked accounts are compared by their last 4 digits, phones by their last 10, and times within 1 hour count as the same. |
| `requested_amount_mismatch` | A fraudulent payment's amount matches none of the amounts the linked scam messages asked for. |
| `sender_id_conflict` | One sender name appears with several phone numbers/emails/UPI IDs. |
| `identifier_name_conflict` | One identifier appears under several names (a common impersonation pattern). |
| `payment_before_contact` | A fraudulent payment is dated before every message that named its payee. |

Records with the same reference that agree are reported as a `duplicate_transaction`, because the timeline's total loss counts each of them.

```python
from fraud_evidence.consistency import check_timeline, render_text
report = check_timeline(timeline)   # timeline from Module 3
print(render_text(report))
```

```
Gaps & contradictions — case C1
6 issue(s) in 7 event(s): 2 contradiction, 4 gap

ISSUE-001 !! [contradiction] Conflicting amounts for transaction 412345678901  (events #4, #6)
     The same reference appears with different amounts: ₹4,000.00, ₹5,000.00.
     → Check which record is authentic against the bank's own statement.
ISSUE-002 !  [contradiction] Paid amount differs from the amount requested: Fraudulent payment: Debit of ₹4,000.00 to kyc.help@ybl  (events #3, #4)
     The linked message asked for ₹5,000.00, but the payment was ₹4,000.00.
```

CLI (reads a Module 3 timeline, or Module 2 output which it turns into a timeline first; outputs `json`, `text` or `markdown`):

```bash
python -m fraud_evidence.timeline cases/CASE-001.json | python -m fraud_evidence.consistency --format text
python -m fraud_evidence.consistency cases/CASE-001.json --format markdown --out cases/CASE-001-issues.md
```

## Module 5: Redaction

`fraud_evidence.redaction` finds sensitive data in structured evidence and replaces it with `[REDACTED]`. It works on the output of any module: Module 2 records or case files, a Module 3 timeline or a Module 4 report. The output keeps the same shape, so it can still be fed to the next module.

| Type | Found in |
|---|---|
| `account` | Parties with `identifier_type: account`, masked numbers (`XX1234`, `**5678`), and numbers after "A/c", "acct" or "account (no)". |
| `card` | 13–19 digit numbers that pass the Luhn check. |
| `phone` | Parties with `identifier_type: phone`, `contacts.phone_numbers`, and Indian mobile numbers in any text (`+91 98765 43210`, `09876543210`). |
| `email` | Parties, `contacts.emails`, and email addresses in any text. |
| `upi_id` | Parties, `contacts.upi_ids`, and UPI IDs in any text (`name@ybl`). |

Any value found in a structured field is also removed wherever it appears in free text, even when no pattern would recognize it (e.g. an unmasked account number in a statement narration).

What is kept: evidence IDs, content hashes, timestamps, amounts, URLs, display names, SMS sender IDs (`VM-SBIINB`) and transaction references (UTR/RRN), since those are needed to trace the money and do not identify a person. A number that matches a known transaction reference is never treated as a phone number.

```python
from fraud_evidence.redaction import Redactor, redact
safe = redact(records)                          # a redacted copy; the input is untouched
result = Redactor(types=["phone", "email"]).redact(case_document)
result.counts                                   # {"phone": 3, "email": 1}
```

CLI (JSON or JSON Lines in, same format out; the count of redacted values goes to stderr):

```bash
python -m fraud_evidence.redaction cases/CASE-001.json --out cases/CASE-001-redacted.json
python -m fraud_evidence.timeline cases/CASE-001.json | python -m fraud_evidence.redaction --types phone,email,upi_id
```

## Module 6: Incident Report Generation

`fraud_evidence.report` combines the timeline (Module 3), the redacted evidence (Module 5) and the flags (Module 4) into one structured incident report, as JSON, Markdown or text.

| Section | Contents |
|---|---|
| `executive_summary` | An assessment (`Fraud with financial loss`, `Attempted fraud, no confirmed loss`, `Suspicious contact, no payment found` or `No fraud indicators found`), a plain-language summary paragraph, and key facts: first contact, first loss, attack chain, contact channels, payment and attempt counts, total loss, suspect count and flag counts. |
| `timeline` | Every timeline event in order: time, stage, severity, title and description. |
| `evidence` | One row per evidence item: type, source, time, sender, receiver, a content summary, content hash and warnings, plus the timeline events and flags that refer to it. |
| `flags` | The Module 4 gaps, contradictions and duplicates, with the suggested next step for each. |
| `fraud_attempt_log` | Every fraud action in order (scam contact, phishing link, payment to suspect, failed attempt, follow-up demand), with channel, counterparty, amount, UTR/URL and outcome (`contacted`, `link sent`, `money lost`, `failed`…). |

A payment recorded in several documents (for example an SMS alert and a receipt with the same UTR) is counted once in the loss total.

The finished report goes through the redactor once more, so identifiers carried by the timeline or the flags never appear unredacted. Pass `redact=False` (or `--no-redact`) only for a report that stays inside the investigating team.

```python
from fraud_evidence.report import IncidentReportBuilder, build_report, render_markdown
report = build_report(timeline, redacted_records, flags)            # outputs of Modules 3, 5 and 4
report = IncidentReportBuilder().build_from_records(records, "CASE-001")  # or run Modules 3-5 from Module 2 records
print(render_markdown(report))
```

CLI:

```bash
# From a Module 2 case file (builds the timeline, flags and redaction itself):
python -m fraud_evidence.report cases/CASE-001.json --format markdown --out cases/CASE-001-report.md

# From the earlier modules' outputs (timeline and flags are computed if omitted):
python -m fraud_evidence.report --timeline timeline.json --evidence redacted.json --flags issues.json --format markdown
```
