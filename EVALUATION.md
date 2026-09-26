# Running the pipeline for evaluation

This guide takes you from a fresh clone to a finished incident report. It uses a made-up fraud
case in `samples/case-001`, in which a fake "SBI KYC" scam leads to one lost UPI payment and one
failed payment. All names, numbers and accounts in the sample are invented.

The commands are the same on Windows, macOS and Linux. On Windows, type `py` instead of `python`
if `python` opens the Microsoft Store or is not found.

## 0. Run it online, with nothing to install

**Google Colab** (needs a Google account):
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1/blob/main/notebooks/run_on_colab.ipynb)
Open the link, click **Runtime → Run all**, and scroll down to the report. The notebook installs
Tesseract, runs the sample case, prints the report, and can also run the tests or your own files.

**GitHub Codespaces** (needs a GitHub account): on the repository page click
**Code → Codespaces → Create codespace on main**. Setup runs by itself (Tesseract and the Python
packages are installed from `.devcontainer/devcontainer.json`). When the terminal is ready, run
`python samples/run_sample.py` and open `out/report/CASE-001.txt`.

The rest of this guide is for running on your own computer.

## 1. Requirements

- Python 3.10 or newer
- Tesseract OCR 4 or newer, which reads the screenshot and the scanned PDF statement

## 2. Setup

```bash
git clone https://github.com/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1
cd The_Fantastic_Four_Ignithon_2.0.1
python -m venv .venv
```

Activate the virtual environment:

| System | Command |
|---|---|
| macOS / Linux | `source .venv/bin/activate` |
| Windows PowerShell | `.venv\Scripts\Activate.ps1` (if blocked, first run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`) |
| Windows cmd | `.venv\Scripts\activate.bat` |

Then install the Python packages:

```bash
python -m pip install -r requirements.txt
```

Install Tesseract:

| System | Command |
|---|---|
| Ubuntu / Debian | `sudo apt install tesseract-ocr` |
| macOS | `brew install tesseract` |
| Windows | Run the UB Mannheim installer from https://github.com/UB-Mannheim/tesseract/wiki with the default folder. It is found automatically there; otherwise set `TESSERACT_CMD` to the full path of `tesseract.exe`. |

Check the setup. Every line should say `[ok]`; a `[FAIL]` line says what to install:

```bash
python -m fraud_evidence.check
```

## 3. Run the sample case

One command runs the setup check and all six modules:

```bash
python samples/run_sample.py
```

If a step fails, the run stops and prints what to fix.

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

Each command writes its output with `--out`. Avoid `>` redirects: on Windows PowerShell they
save files in a different encoding.

```bash
# Module 1: ingest raw evidence (a folder means every file in it)
python -m fraud_evidence.ingestion samples/case-001 --out out/evidence.jsonl
# Module 2: extract parties, amounts, dates and indicators into a case file
python -m fraud_evidence.extraction out/evidence.jsonl --out out/CASE-001.json --case-id CASE-001
# Module 3: chronological timeline
python -m fraud_evidence.timeline out/CASE-001.json --format text --out out/timeline.txt
# Module 4: gaps and contradictions
python -m fraud_evidence.consistency out/CASE-001.json --format text --out out/flags.txt
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

Add `--format json text markdown` to the report command for a Markdown copy as well. All files
are UTF-8; open the `.txt` report in any editor (Notepad, VS Code) to see the ₹ signs correctly.

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

All 188 tests should pass. `tests/test_sample_case.py` runs the sample case end to end and checks
the numbers above; it is skipped if Tesseract is not installed. `tests/test_cli_robustness.py`
checks the commands on a Windows-style console and with PowerShell-encoded files.

## 7. Run it on your own evidence

Put the files in a folder and use the same commands:

```bash
python -m fraud_evidence.ingestion my-case --text "hxxp://pasted-link[.]xyz" --out work/evidence.jsonl
python -m fraud_evidence.extraction work/evidence.jsonl --out work/MY-CASE.json --case-id MY-CASE
python -m fraud_evidence.report work/MY-CASE.json --out reports/MY-CASE
```

Accepted inputs: screenshots (PNG, JPEG and others), PDFs (text or scanned), bank statement
CSV/JSON exports, bank alert SMS, WhatsApp chat exports, emails and plain text. Problems with an
input, such as unreadable OCR, are printed as `warning:` lines and recorded in the report.

## Troubleshooting

Run `python -m fraud_evidence.check` first; it names most problems and their fix.

| Message | Fix |
|---|---|
| `Tesseract OCR is not installed or not on PATH` | Install Tesseract (section 2), or set `TESSERACT_CMD` to the full path of `tesseract.exe` |
| `No module named 'fraud_evidence'` | Run the commands from the repository folder (the one containing `EVALUATION.md`) |
| `No module named 'PIL'` / `'pdfplumber'` / `'pytest'` | Activate the virtual environment, then `python -m pip install -r requirements.txt` |
| `pdfplumber failed to load` | `python -m pip install --upgrade cffi cryptography` |
| `fraud_evidence needs Python 3.10 or newer` | Install Python 3.10+ from python.org and recreate the virtual environment |
| `file not found: ...` | Check the path; run the earlier step that creates that file |
