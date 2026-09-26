"""python -m fraud_evidence: all six modules in one command."""

import json
import zoneinfo
from pathlib import Path

import pytest

from fraud_evidence.__main__ import main
from fraud_evidence.timeline import builder

CASE = Path(__file__).resolve().parent.parent / "samples" / "case-001"
TEXT_FILES = ["01_scam_sms.txt", "02_whatsapp_chat.txt", "03_upi_debit_alert.txt",
              "05_failed_payment.csv"]


def run(tmp_path, *extra):
    args = [str(CASE / f) for f in TEXT_FILES] + ["--out", str(tmp_path), *extra]
    assert main(args) == 0
    return tmp_path / "CASE-001"


def test_writes_every_module_output(tmp_path, capsys):
    folder = run(tmp_path)
    assert sorted(p.name for p in folder.iterdir()) == [
        "case.json", "evidence.jsonl", "flags.txt", "redacted.json", "report.json",
        "report.txt", "timeline.txt"]
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    assert report["case_id"] == "CASE-001"
    assert report["executive_summary"]["assessment"] == "Fraud with financial loss"
    assert report["executive_summary"]["key_facts"]["total_loss"] == {"INR": 4999.0}
    text = (folder / "report.txt").read_text(encoding="utf-8")
    redacted = (folder / "redacted.json").read_text(encoding="utf-8")
    for secret in ("kyc.helpdesk@ybl", "98765 43210", "XX8659"):
        assert secret not in text and secret not in redacted
    err = capsys.readouterr().err
    assert "Assessment:  Fraud with financial loss" in err and "₹4,999.00" in err


def test_rerun_replaces_the_case(tmp_path):
    run(tmp_path)
    folder = run(tmp_path)
    case = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    assert case["record_count"] == len(TEXT_FILES)


def test_text_evidence_and_print(tmp_path, capsys):
    assert main(["--text", "Rs.500 debited from A/c XX1111 to VPA a@ybl UPI Ref 412345678901",
                 "--case-id", "T-1", "--out", str(tmp_path), "--print"]) == 0
    assert "INCIDENT REPORT — T-1" in capsys.readouterr().out


@pytest.mark.parametrize("args, message", [
    (["no-such-file.png"], "file not found: no-such-file.png"),
    ([], "give at least one evidence file"),
])
def test_bad_input_is_a_clear_error(tmp_path, capsys, args, message):
    with pytest.raises(SystemExit) as exc:
        main(args + ["--out", str(tmp_path)])
    assert exc.value.code == 2 and message in capsys.readouterr().err


def test_works_without_a_time_zone_database(tmp_path, monkeypatch):
    # Windows has no zone database unless the tzdata package is installed.
    def missing(name):
        raise zoneinfo.ZoneInfoNotFoundError(name)
    monkeypatch.setattr(builder, "ZoneInfo", missing)
    folder = run(tmp_path)
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    assert report["executive_summary"]["key_facts"]["first_contact_at"] == "2026-09-12T10:40:12+05:30"
    with pytest.raises(ValueError, match="pip install tzdata"):
        builder.get_zone("Europe/London")
