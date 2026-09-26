# Running the pipeline for evaluation

This guide takes you from a fresh clone to a finished incident report. One command runs all six
modules:

```bash
python -m fraud_evidence samples/case-001
```

It uses a made-up fraud case in `samples/case-001`, in which a fake "SBI KYC" scam leads to one
lost UPI payment and one failed payment. All names, numbers and accounts in the sample are
invented.

## 0. Run it online, with nothing to install

**Google Colab** (needs a Google account):
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1/blob/main/notebooks/run_on_colab.ipynb)
Open the link, click **Runtime → Run all**, and scroll down to the report. The notebook installs
Tesseract, runs the sample case, prints the report, and can also run the tests or your own files.

**GitHub Codespaces** (needs a GitHub account): on the repository page click
**Code → Codespaces → Create codespace on main**. Setup runs by itself (Tesseract and the Python
packages are installed from `.devcontainer/devcontainer.json`). When the terminal is ready, run
`python -m fraud_evidence samples/case-001` and open `reports/CASE-001/report.txt`.

The rest of this guide is for running on your own computer.

## 1. Requirements

- Python 3.10 or newer
- Git
- Tesseract OCR 4 or newer, which reads screenshots and scanned PDFs

## 2. Setup

### Windows (PowerShell)

1. Install Python from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Install Git from https://git-scm.com/download/win.
3. Install Tesseract with the UB Mannheim installer from
   https://github.com/UB-Mannheim/tesseract/wiki, keeping the default folder.
4. Open a new PowerShell window and run:

```powershell
git clone https://github.com/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1
cd The_Fantastic_Four_Ignithon_2.0.1
py -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m fraud_evidence.check
```

In cmd instead of PowerShell, activate with `.venv\Scripts\activate.bat` and skip the
`Set-ExecutionPolicy` line.

### macOS / Linux

```bash
# Tesseract: macOS `brew install tesseract`; Ubuntu `sudo apt install tesseract-ocr`
git clone https://github.com/guptakaushalraj-collab/The_Fantastic_Four_Ignithon_2.0.1
cd The_Fantastic_Four_Ignithon_2.0.1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m fraud_evidence.check
```

`python -m fraud_evidence.check` should print `[ok]` on every line. A `[FAIL]` line says what to
install. If Tesseract is installed somewhere unusual, set `TESSERACT_CMD` to the full path of the
program.

## 3. Run the sample case

With the virtual environment active, from the repository folder:

```bash
python -m fraud_evidence samples/case-001
```

It prints each step and ends with the assessment, the total loss and where the report is:

```
Assessment:  Fraud with financial loss
Total loss:  ₹4,999.00
Flags:       15
Report:      reports/CASE-001/report.txt
JSON:        reports/CASE-001/report.json
```

Add `--print` to print the whole report too. `python samples/run_sample.py` does the same after
running the setup check.

### The sample evidence

| File | What it is | Read as |
|---|---|---|
| `01_scam_sms.txt` | SMS from `VM-SBIINB` threatening to block the account, with a phishing link | message |
| `02_whatsapp_chat.txt` | WhatsApp export: the scammer asks for a ₹4,999 fee, then a ₹15,000 deposit | message (chat) |
| `03_upi_debit_alert.txt` | Bank SMS for the ₹4,999 UPI debit | transaction |
| `04_payment_screenshot.png` | UPI app receipt for the same payment | screenshot (OCR) |
| `05_failed_payment.csv` | Bank export showing the failed ₹15,000 payment | transaction |
| `06_bank_statement.pdf` | Scanned bank statement with no text layer | transaction (OCR) |

## 4. Where the output lands

Everything goes in `reports/<case-id>/` (change the folder with `--out`, the case name with
`--case-id`):

| File | Module | Contents |
|---|---|---|
| `report.txt` | 6 | The human-readable incident report |
| `report.json` | 6 | The same report as JSON |
| `evidence.jsonl` | 1 | One normalized evidence record per input |
| `case.json` | 2 | Extracted fields (not redacted) |
| `timeline.txt` | 3 | Events in time order |
| `flags.txt` | 4 | Missing and contradictory information |
| `redacted.json` | 5 | The case file with personal data replaced by `[REDACTED]` |

All files are UTF-8; open them in any editor (Notepad, VS Code) to see the ₹ signs correctly.

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

## 5. Run it on your own evidence

Put the files in a folder (screenshots, PDFs, bank CSV/JSON exports, WhatsApp chat exports, SMS
saved as `.txt`) and run:

```bash
python -m fraud_evidence path/to/my-case --case-id MY-CASE
```

Text can be passed directly too, and files and folders can be mixed:

```bash
python -m fraud_evidence chat.txt statement.pdf --text "Rs.5,000 debited from A/c XX1234 to VPA abc@ybl UPI Ref 412345678901" --case-id MY-CASE
```

Problems with an input, such as unreadable OCR, are printed as `warning:` lines and recorded in
the report. Running again with the same case id replaces that case's results.

## 6. Run the tests

```bash
python -m pytest
```

All 194 tests should pass. `tests/test_sample_case.py` runs the sample case end to end and is
skipped if Tesseract is not installed. `tests/test_cli_robustness.py` checks the commands on a
Windows-style console and with PowerShell-encoded files.

## 7. Running the modules one at a time

Each module also has its own command, for inspecting the intermediate steps:

```bash
python -m fraud_evidence.ingestion samples/case-001 --out out/evidence.jsonl
python -m fraud_evidence.extraction out/evidence.jsonl --out out/CASE-001.json --case-id CASE-001
python -m fraud_evidence.timeline out/CASE-001.json --format text --out out/timeline.txt
python -m fraud_evidence.consistency out/CASE-001.json --format text --out out/flags.txt
python -m fraud_evidence.redaction out/CASE-001.json --out out/redacted.json
python -m fraud_evidence.report out/CASE-001.json --out out/report/CASE-001
```

Use `--out` rather than `>`: on Windows PowerShell, `>` saves files in a different encoding.

## Troubleshooting

Run `python -m fraud_evidence.check` first; it names most problems and their fix.

| Message | Fix |
|---|---|
| `python` opens the Microsoft Store, or is not found | Use `py` instead of `python` for the `venv` line, or reinstall Python with **Add python.exe to PATH** ticked |
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then activate again |
| `Tesseract OCR is not installed or not on PATH` | Install Tesseract (section 2), or set `TESSERACT_CMD` to the full path of `tesseract.exe` |
| `No module named 'fraud_evidence'` | Run the commands from the repository folder (the one containing `EVALUATION.md`) |
| `No module named 'PIL'` / `'pdfplumber'` / `'pytest'` | Activate the virtual environment, then `python -m pip install -r requirements.txt` |
| `pdfplumber failed to load` | `python -m pip install --upgrade cffi cryptography` |
| `unknown time zone` | `python -m pip install tzdata` |
| `fraud_evidence needs Python 3.10 or newer` | Install Python 3.10+ and recreate the virtual environment |
| `file not found: ...` | Check the path; paths are relative to the folder you are in |
