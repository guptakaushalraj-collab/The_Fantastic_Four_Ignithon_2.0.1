"""Parsing of printed bank statements (PDF text or OCR of a scan).

A printed statement is a table: post date, value date, a narration that
wraps over several lines, a cheque number, a debit or credit amount and the
running balance. OCR keeps each printed row on one line but loses the
columns, and the narration lines can sit above and below the dates.

So amounts are read from the running balance rather than from column
positions: the change in balance from one row to the next gives the amount
and whether it was a debit or a credit. A figure printed in the row that
matches that change is preferred, since the balance itself may be misread.
The statement summary (``Dr. Count:4 Cr. Count:1 200740.00 200000.00``) is
checked against the parsed rows, which catches missing rows and pages.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .text import extract_entities, parse_amount

_ROW_RE = re.compile(
    r"^[\W_]{0,3}(?P<post>\d{2}[/-]\d{2}[/-]\d{2,4})\s+[\W_]{0,2}"
    r"(?P<value>\d{2}[/-]\d{2}[/-]\d{2,4})\b(?P<rest>.*)$"
)
# 1,75,000.00 / 2746.61 / 2746.61Cr / 2536.620r (OCR for 2536.61Cr)
_AMOUNT_RE = re.compile(
    r"(?<![0-9A-Za-z/.])(?P<num>\d{1,3}(?:,\d{2,3})+|\d+)\.(?P<dec>\d{2})"
    r"(?P<suffix>\s?(?:[cC][A-Za-z]{0,2}|[dD][rR]|0[rR])\b)?"
)
_OPENING_RE = re.compile(r"(?i)\b(brought\s+forward|opening\s+balance|b/f)\b")
_CLOSING_RE = re.compile(
    r"(?i)\b(carried\s+forward|closing\s+balance|statement\s+summary|dr\.?\s*count|c/f)\b")
_HEADER_RE = re.compile(r"(?i)\bpost\s*date\b|\btxn\s*date\b")
# Rows end with the branch name: "/BRANCH : Jangi Road", also wrapped as "BRAN" / "CH : ...".
_ROW_END_RE = re.compile(r"(?i)(?:^|[\s/|])(?:BR)?(?:AN)?CH\s*[:;|]|^[:;]\s*\w")
_SUMMARY_RE = re.compile(
    r"(?i)dr\.?\s*count\s*[:;.]?\s*(?P<dr>\d+)\s*cr\.?\s*count\s*[:;.]?\s*(?P<cr>\d+)")
_ACCOUNT_RE = re.compile(r"(?i)\baccount\s*no\.?\s*[:.]?\s*(\d{6,18})\b")
_REF_RES = (
    re.compile(r"(?i)\bUP[IT1]\s*/\s*(\d{6,12})\s*(\d{0,6})(?=\D|$)"),  # UPI/6245217 64705 (wrapped)
    re.compile(r"\b([A-Z]{4}[NR]\d{10,})\b"),                          # NEFT/RTGS UTR
    re.compile(r"(?i)\b(?:utr|rrn|ref\.?\s*no)\s*[:.]?\s*([A-Z0-9]{8,22})\b"),
)
_TRANSFER_RE = re.compile(r"(?i)\b(?:transfer|trf)\s+(to|from)\s+(\d{6,18})\b")
# "ATM SERVICE BRANCH" is a branch name, not a cash withdrawal.
_METHOD_RE = re.compile(r"(?i)\b(UP[IT]|NEFT|IMPS|RTGS|ATM(?!\s+SERVICE)|POS|TRANSFER|TRF)\b")
# A cheque number is printed in its own column, just before the amount.
_CHEQUE_RE = re.compile(r"(?i)(?<![\w/])(?<!from )(?<!to )(\d{6,9})\s+[^\w\s]{0,2}(?=(?:\d{1,3}(?:,\d{2,3})+|\d+)\.\d{2})")


@dataclass
class ParsedStatement:
    records: list[dict[str, Any]]
    account: str | None = None
    opening_balance: float | None = None
    closing_balance: float | None = None
    summary: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)

    def info(self) -> dict[str, Any]:
        return {"account": self.account, "opening_balance": self.opening_balance,
                "closing_balance": self.closing_balance, "row_count": len(self.records),
                "summary": self.summary}


def _clean_numbers(line: str) -> str:
    """Undo OCR spacing inside numbers: "175018 ,00" -> "175018.00", "2536. 62" -> "2536.62"."""
    # A letter OCR'd in place of the leading digit of an amount: "B6000.00" -> "86000.00".
    line = re.sub(r"(?<![0-9A-Za-z])([BOSl])(?=\d{3,}(?:,\d{2,3})*\.\d{2}(?!\d))",
                  lambda m: {"B": "8", "O": "0", "S": "5", "l": "1"}[m.group(1)], line)
    line = re.sub(r"(\d)\s*,\s*\.\s*(\d)", r"\1.\2", line)
    line = re.sub(r"(\d)\s+[.,]\s*(\d{2})(?!\d)", r"\1.\2", line)
    return re.sub(r"(\d)\.\s+(\d{2})", r"\1.\2", line)


def _amounts(line: str) -> list[tuple[float, bool]]:
    """(value, looks_like_balance) for each money figure in a line."""
    out = []
    for m in _AMOUNT_RE.finditer(_clean_numbers(line)):
        value = parse_amount(f"{m.group('num')}.{m.group('dec')}")
        if value is not None:
            out.append((value, bool(m.group("suffix"))))
    return out


def _parse_date(value: str) -> str | None:
    parts = re.split(r"[/-]", value)
    try:
        day, month, year = (int(p) for p in parts)
    except ValueError:
        return None
    if day > 31 and parts[0].startswith("9"):  # OCR reads a leading 0 as 9
        day -= 90
    year += 2000 if year < 100 else 0
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def looks_like_statement(text: str) -> bool:
    rows = sum(bool(_ROW_RE.match(line.strip())) for line in text.splitlines())
    return rows >= 2 or (rows >= 1 and bool(_OPENING_RE.search(text) or _HEADER_RE.search(text)))


def parse_statement_text(text: str, currency: str = "INR") -> ParsedStatement | None:
    """Parse one statement (one page or account) into raw transaction dicts, or ``None``."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not looks_like_statement(text):
        return None
    account = next((m.group(1) for line in lines if (m := _ACCOUNT_RE.search(line))), None)

    # The table runs from the header / brought-forward line to the closing line.
    start = next((i for i, line in enumerate(lines) if _OPENING_RE.search(line)), None)
    if start is None:
        start = next((i for i, line in enumerate(lines) if _HEADER_RE.search(line)), -1)
    opening = None
    if start >= 0 and _OPENING_RE.search(lines[start]):
        found = _amounts(lines[start])
        opening = found[-1][0] if found else None
    end = next((i for i in range(start + 1, len(lines)) if _CLOSING_RE.search(lines[i])), len(lines))
    table = lines[start + 1:end]
    tail = lines[end:]

    row_idx = [i for i, line in enumerate(table) if _ROW_RE.match(line)]
    if not row_idx:
        return None
    blocks = _blocks(table, row_idx)

    statement = ParsedStatement(records=[], account=account, opening_balance=opening)
    rows = [_read_row(row_line, block, account, currency, n)
            for n, (row_line, block) in enumerate(blocks, start=1)]
    closing_line = next((line for line in tail if re.search(r"(?i)carried|closing", line)), None)
    closing = _amounts(closing_line)[-1][0] if closing_line and _amounts(closing_line) else None
    previous = _reconcile(rows, opening, closing, statement.warnings)
    statement.records = [_finish(row, account) for row in rows]

    if closing is not None:
        statement.closing_balance = closing
        if previous is not None and abs(closing - previous) > 0.01:
            statement.warnings.append(
                f"closing balance {closing:.2f} does not match the last row's balance "
                f"{previous:.2f}; a row may be missing or misread")
    _check_summary(statement, tail)
    return statement


def _blocks(table: list[str], row_idx: list[int]) -> list[tuple[str, list[str]]]:
    """Group narration lines with their row.

    Lines after a row's date line belong to it up to a line ending the row
    ("... /BRANCH : Jangi Road"); later lines lead into the next row.
    """
    bounds = []
    begin = 0
    for k, i in enumerate(row_idx):
        stop = row_idx[k + 1] if k + 1 < len(row_idx) else len(table)
        end = stop
        for j in range(i + 1, stop):
            if _ROW_END_RE.search(table[j]):
                end = j + 1
                break
        else:
            if k + 1 < len(row_idx) and any(_ROW_END_RE.search(t) for t in table[i:i + 1]):
                end = i + 1
        bounds.append((begin, end, i))
        begin = end
    return [(table[i], table[b:e]) for b, e, i in bounds]


def _read_row(row_line: str, block: list[str], account, currency, n) -> dict[str, Any]:
    """Read one row's text and figures; amounts and directions come from :func:`_reconcile`."""
    m = _ROW_RE.match(row_line)
    post, value = _parse_date(m.group("post")), _parse_date(m.group("value"))
    narration = " ".join((m.group("rest") if line is row_line else line) for line in block).strip()
    narration_text = re.sub(r"\s+", " ", _AMOUNT_RE.sub(" ", _clean_numbers(narration))).strip(" |—-")

    figures = [f for line in block for f in _amounts(line)]
    row_figures = _amounts(m.group("rest"))
    balances = [v for v, is_balance in figures if is_balance]
    if not balances and len(row_figures) >= 2:
        # Balance printed without its Cr/Dr marker: it is the rightmost column.
        balances = [row_figures[-1][0]]
        row_figures = row_figures[:-1]
    # Figures on the date line are the row's own columns; narration may quote others.
    candidates = [v for v, is_balance in row_figures if not is_balance]
    candidates += [v for v, is_balance in figures
                   if not is_balance and v not in candidates and v not in balances]

    record: dict[str, Any] = {
        "date": post or value, "value_date": value, "amount": None, "currency": currency,
        "direction": None, "narration": narration_text, "balance": None, "row": n,
    }
    if ref := _reference(narration_text):
        record["reference"] = ref
    if chq := _CHEQUE_RE.findall(_clean_numbers(m.group("rest"))):
        record["cheque_number"] = chq[-1]
    method = _METHOD_RE.search(narration)
    record["payment_method"] = (
        {"UPT": "UPI", "TRF": "TRANSFER"}.get(method.group(1).upper(), method.group(1).upper())
        if method else ("CHEQUE" if record.get("cheque_number") else None))
    return {"record": record, "balances": balances, "candidates": candidates,
            "counterparty": _counterparty(narration)}


def _reconcile(rows: list[dict], opening, closing, warnings) -> float | None:
    """Give each row its amount and direction from the running balance.

    Rows whose balance was not read are held back and solved together with the
    next row that has one (or with the closing balance): the signs of their
    amounts must add up to the change in balance.
    """
    previous = opening
    pending: list[dict] = []

    def settle(target: float | None, current: dict | None) -> bool:
        nonlocal previous
        group = pending + ([current] if current else [])
        if previous is None or target is None or not group:
            return False
        options = [row["candidates"][:3] or [None] for row in group]
        balances = current["balances"][::-1] if current else [target]
        for bal in balances:
            for amounts in itertools.product(*options):
                if None in amounts:
                    continue
                for signs in itertools.product((1, -1), repeat=len(group)):
                    if abs(previous + sum(s * a for s, a in zip(signs, amounts)) - bal) <= 1.0:
                        running = previous
                        for row, sign, amount in zip(group, signs, amounts):
                            running = round(running + sign * amount, 2)
                            row["record"].update(amount=amount, balance=running,
                                                 direction="credit" if sign > 0 else "debit")
                        previous = running
                        return True
        return False

    for row in rows:
        if not row["balances"]:
            pending.append(row)
            continue
        if not settle(None, row) and not settle(row["balances"][-1], row):
            balance = row["balances"][-1]
            record = row["record"]
            for held in pending:
                held["record"]["amount"] = (held["candidates"] or [None])[0]
                warnings.append(f"row {held['record']['row']}: debit/credit could not be determined")
            if previous is not None and not pending:
                diff = round(balance - previous, 2)
                record.update(amount=abs(diff), direction="credit" if diff > 0 else "debit")
                warnings.append(f"row {record['row']}: amount {abs(diff):.2f} taken from the balance "
                                "change; no matching figure was read in the row")
            else:
                record["amount"] = (row["candidates"] or [None])[0]
                warnings.append(f"row {record['row']}: debit/credit could not be determined")
            record["balance"] = balance
            previous = balance
        pending = []

    if pending and not settle(closing, None):
        for held in pending:
            held["record"]["amount"] = (held["candidates"] or [None])[0]
            warnings.append(f"row {held['record']['row']}: debit/credit could not be determined")
    return previous


def _finish(row: dict, account: str | None) -> dict[str, Any]:
    record = row["record"]
    account = f"A/c {account}" if account else None
    if record["direction"] == "credit":
        record["sender"], record["receiver"] = row["counterparty"], account
    else:
        record["sender"], record["receiver"] = account, row["counterparty"]
    return record


def _reference(narration: str) -> str | None:
    for pattern in _REF_RES:
        if m := pattern.search(narration):
            return "".join(g for g in m.groups() if g)
    return None


def _counterparty(narration: str) -> str | None:
    if m := _TRANSFER_RE.search(narration):
        return f"A/c {m.group(2)}"
    entities = extract_entities(narration)
    return (entities.upi_ids or entities.emails or [None])[0]


def _check_summary(statement: ParsedStatement, tail: list[str]) -> None:
    text = " ".join(tail)
    m = _SUMMARY_RE.search(text)
    if not m:
        return
    totals = [v for v, _ in _amounts(text[m.end():])][:2]
    summary = {"debit_count": int(m.group("dr")), "credit_count": int(m.group("cr"))}
    if len(totals) == 2:
        summary.update(debit_total=totals[0], credit_total=totals[1])
    statement.summary = summary

    for kind in ("debit", "credit"):
        rows = [r for r in statement.records if r["direction"] == kind]
        found = round(sum(r["amount"] or 0 for r in rows), 2)
        expected_count, expected_total = summary[f"{kind}_count"], summary.get(f"{kind}_total")
        if len(rows) != expected_count or (expected_total is not None
                                           and abs(found - expected_total) > 0.01):
            statement.warnings.append(
                f"statement summary lists {expected_count} {kind}s"
                + (f" totalling {expected_total:,.2f}" if expected_total is not None else "")
                + f", but {len(rows)} totalling {found:,.2f} were read; rows or pages may be missing")
