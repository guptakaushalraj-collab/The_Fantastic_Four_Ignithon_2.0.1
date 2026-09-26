"""The command-line tools on Windows-like setups: non-UTF-8 consoles, PowerShell files."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fraud_evidence.cli import decode
from fraud_evidence.ingestion.ocr import OCRUnavailableError, TesseractOCR

ROOT = Path(__file__).resolve().parent.parent
CASE = ROOT / "samples" / "case-001"
TEXT_FILES = [CASE / "01_scam_sms.txt", CASE / "02_whatsapp_chat.txt",
              CASE / "03_upi_debit_alert.txt", CASE / "05_failed_payment.csv"]


def run(*args, env=None, **kwargs):
    env = {**os.environ, **(env or {})}
    return subprocess.run([sys.executable, "-m", *map(str, args)], cwd=ROOT, env=env,
                          capture_output=True, **kwargs)


@pytest.fixture
def case_file(tmp_path):
    run("fraud_evidence.ingestion", *TEXT_FILES, "--out", tmp_path / "e.jsonl", check=True)
    run("fraud_evidence.extraction", tmp_path / "e.jsonl", "--out", tmp_path / "c.json", check=True)
    return tmp_path / "c.json"


@pytest.mark.parametrize("module", ["timeline", "consistency", "report"])
def test_text_output_on_a_windows_console(case_file, module):
    # A Windows console can't encode ₹ or →; the CLIs must not crash on it.
    result = run(f"fraud_evidence.{module}", case_file, "--format", "text",
                 env={"PYTHONIOENCODING": "cp1252"})
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert "₹" in result.stdout.decode("utf-8")


def test_powershell_utf16_redirect_is_read(tmp_path):
    # Windows PowerShell 5 saves "python -m ... > evidence.jsonl" as UTF-16 with a BOM.
    out = run("fraud_evidence.ingestion", *TEXT_FILES, check=True).stdout.decode("utf-8")
    (tmp_path / "e.jsonl").write_bytes(out.encode("utf-16"))
    run("fraud_evidence.extraction", tmp_path / "e.jsonl", "--out", tmp_path / "c.json", check=True)
    assert len(json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))["records"]) == 4


def test_decode():
    assert decode("₹5".encode("utf-8-sig")) == "₹5"
    assert decode("₹5".encode("utf-16")) == "₹5"
    assert decode("caf\xe9".encode("cp1252")) == "café"


def test_folder_input(tmp_path):
    folder = tmp_path / "case"
    folder.mkdir()
    for f in TEXT_FILES:
        (folder / f.name).write_bytes(f.read_bytes())
    run("fraud_evidence.ingestion", folder, "--out", tmp_path / "e.jsonl", check=True)
    lines = (tmp_path / "e.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(l)["metadata"]["filename"] for l in lines] == [f.name for f in TEXT_FILES]


@pytest.mark.parametrize("module", ["ingestion", "extraction", "timeline", "consistency",
                                    "redaction", "report"])
def test_missing_file_is_a_clear_error(module):
    result = run(f"fraud_evidence.{module}", "no-such-file.json")
    assert result.returncode == 2
    assert b"file not found: no-such-file.json" in result.stderr
    assert b"Traceback" not in result.stderr


def test_missing_tesseract_says_how_to_install(monkeypatch):
    monkeypatch.setenv("TESSERACT_CMD", "/no/such/tesseract")
    pytest.importorskip("pytesseract")
    with pytest.raises(OCRUnavailableError, match="TESSERACT_CMD"):
        TesseractOCR().extract_text(b"not an image")
