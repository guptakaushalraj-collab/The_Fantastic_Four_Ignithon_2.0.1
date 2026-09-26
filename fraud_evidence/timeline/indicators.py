"""Scam-language indicators used to decide whether a message is suspicious."""

from __future__ import annotations

import re

INDICATOR_PATTERNS: dict[str, re.Pattern] = {
    "urgency": re.compile(
        r"(?i)\b(urgent(ly)?|immediately|asap|right now|within \d+\s*(hours?|hrs?|minutes?|mins?)|"
        r"today only|last chance|expir(e|es|ed|ing)|deadline)\b"
    ),
    "account_threat": re.compile(
        r"(?i)\b(blocked|suspended|deactivated|frozen|locked|disconnected|penalty|legal action|"
        r"arrest|police|fir)\b"
    ),
    "credential_request": re.compile(
        r"(?i)\b(otp|one time password|pin|password|cvv|card number|kyc|aadhaar|pan card|"
        r"login details|verification code|screen ?share|anydesk|teamviewer)\b"
    ),
    "payment_request": re.compile(
        r"(?i)\b(send|pay|transfer|deposit|scan (the )?qr|processing fee|registration fee|"
        r"advance)\b.{0,40}?(₹|rs\.?|inr|rupees|\d{3,}|money|amount|fee)"
    ),
    "reward_bait": re.compile(
        r"(?i)\b(won|winner|lottery|prize|cashback|reward|bonus|gift|lucky draw|refund|"
        r"free|jackpot|selected)\b"
    ),
    "job_or_investment_bait": re.compile(
        r"(?i)\b(work from home|part[- ]time job|earn \S+ (per|a) day|daily income|guaranteed returns?|"
        r"double your money|crypto|trading tips?|investment plan|task based)\b"
    ),
}

# Indicators strong enough to mark a message suspicious on their own; the
# softer ones (urgency, reward bait) only count in combination.
_STRONG = {"credential_request", "payment_request", "account_threat", "job_or_investment_bait"}


# URLs, emails and UPI IDs are scored separately; words inside them
# ("kyc.help@ybl", "/verify-otp") must not count as scam language.
_IDENTIFIER_RE = re.compile(r"\S+@\S+|\b(?:https?://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)+/\S*")


def find_indicators(text: str) -> list[str]:
    text = _IDENTIFIER_RE.sub(" ", text or "")
    return [name for name, pattern in INDICATOR_PATTERNS.items() if pattern.search(text)]


def is_suspicious(indicators: list[str], has_bad_url: bool = False) -> bool:
    return has_bad_url or bool(_STRONG & set(indicators)) or len(indicators) >= 2
