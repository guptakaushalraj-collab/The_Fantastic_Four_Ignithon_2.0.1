# Running the pipeline for evaluation

This guide takes you from a fresh clone to a finished incident report. It uses a made-up fraud
case in `samples/case-001`, in which a fake "SBI KYC" scam leads to one lost UPI payment and one
failed payment. All names, numbers and accounts in the sample are invented.

## 1. Requirements

- Python 3.10 or newer
- Tesseract OCR 4 or newer, which reads the screenshot and the scanned PDF statement

## 2. Setup

```bash
git clone https://github.com/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1
cd The_Fantastic_Four_Ignithon_2.0.1
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Install Tesseract:

| System | Command |
|---|---|
| Ubuntu / Debian | `sudo apt install tesseract-ocr` |
| macOS | `brew install tesseract` |
| Windows | Install the UB Mannheim build from https://github.com/UB-Mannheim/tesseract/wiki and add its folder (for example `C:\Program Files\Tesseract-OCR`) to `PATH` |

Check the install:

```bash
tesseract --version
python -c "import pdfplumber, pytesseract; print('ok')"
```

## 3. Run the sample case

One command runs all six modules:

```bash
bash samples/run_sample.sh
```

On Windows without bash, run the same steps by hand (section 4).

### The sample evidence

| File | What it is | Read as |
|---|---|---|
| `01_scam_sms.txt` | SMS from `VM-SBIINB` threatening to block the account, with a phishing link | message |
| `02_whatsapp_chat.txt` | WhatsApp export: the scammer asks for a ₹4,999 fee, then a ₹15,000 deposit | message (chat) |
| `03_upi_debit_alert.txt` | Bank SMS for the ₹4,999 UPI debit | transaction |
| `04_payment_screenshot.png` | UPI app receipt for the same payment | screenshot (OCR) |
| `05_failed_payment.csv` | Bank export showing the failed ₹15,000 payment | transaction |
| `06_bank_statement.pdf` | Scanned bank statement with no text layer | transaction (OCR) |

## 4. The same run, step by step

```bash
mkdir -p out
# Module 1: ingest raw files into normalized evidence (JSON Lines)
python -m fraud_evidence.ingestion samples/case-001/* > out/evidence.jsonl
# Module 2: extract parties, amounts, dates and indicators into a case file
python -m fraud_evidence.extraction out/evidence.jsonl --out out/CASE-001.json --case-id CASE-001
# Module 3: chronological timeline
python -m fraud_evidence.timeline out/CASE-001.json --format text > out/timeline.txt
# Module 4: gaps and contradictions
python -m fraud_evidence.consistency out/CASE-001.json --format text > out/flags.txt
# Module 5: redaction of personal data
python -m fraud_evidence.redaction out/CASE-001.json --out out/redacted.json
# Module 6: incident report (JSON + human-readable text)
python -m fraud_evidence.report out/CASE-001.json --out out/report/CASE-001
```

Module 6 builds the timeline, flags and redaction itself, so the first two commands plus the last
one are enough to get the report. Steps 3 to 5 write each module's output for inspection.

## 5. Where the output lands

| File | Contents |
|---|---|
| `out/evidence.jsonl` | Module 1: one normalized evidence record per input file |
| `out/CASE-001.json` | Module 2: case file with the extracted fields (not redacted) |
| `out/timeline.txt` | Module 3: events in time order |
| `out/flags.txt` | Module 4: missing and contradictory information |
| `out/redacted.json` | Module 5: the case file with personal data replaced by `[REDACTED]` |
| `out/report/CASE-001.txt` | Module 6: the human-readable incident report |
| `out/report/CASE-001.json` | Module 6: the same report as JSON |

Add `--format json text markdown` to the report command for a Markdown copy as well.

### What the report should show

- Assessment: **Fraud with financial loss**
- First contact at 2026-09-12 10:40:12 (the chat), first loss at 10:44:00
- 1 fraudulent payment of ₹4,999.00, recorded in 3 documents (SMS alert, screenshot, statement)
  and counted once
- 1 failed payment attempt (₹15,000)
- The phishing link `sbi-kyc-update.top` scored as malicious
- Flags for the SMS with no timestamp and for statement rows with only a date
- No phone numbers, UPI IDs or account numbers anywhere in the report; UTR `625512345678` is kept
  so the bank can trace the payment

## 6. Run the tests

```bash
python -m pytest
```

All 175 tests should pass. `tests/test_sample_case.py` runs the sample case end to end and checks
the numbers above; it is skipped if Tesseract is not installed.

## 7. Run it on your own evidence

Put the files in a folder and use the same commands:

```bash
python -m fraud_evidence.ingestion my-case/* --text "hxxp://pasted-link[.]xyz" > evidence.jsonl
python -m fraud_evidence.extraction evidence.jsonl --out cases/MY-CASE.json --case-id MY-CASE
python -m fraud_evidence.report cases/MY-CASE.json --out reports/MY-CASE
```

Accepted inputs: screenshots (PNG, JPEG and others), PDFs (text or scanned), bank statement
CSV/JSON exports, bank alert SMS, WhatsApp chat exports, emails and plain text.

## Troubleshooting

- **`OCR unavailable` warning, or empty text from images:** Tesseract is not installed or not on
  `PATH`. Check with `tesseract --version`.
- **`pdfplumber` import fails with `No module named '_cffi_backend'`:** run `pip install cffi`.
- **`PDF support requires 'pdfplumber'`:** run `pip install -r requirements.txt` again inside the
  virtual environment.
