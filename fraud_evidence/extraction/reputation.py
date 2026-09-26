"""URL reputation scoring.

The default scorer is fully offline: it combines the structural features
computed during ingestion with phishing heuristics (brand impersonation,
abused TLDs, credential-harvesting keywords, ...). Online lookups such as
Google Safe Browsing or VirusTotal can be added by implementing
:class:`ReputationProvider` and passing it to :class:`URLReputationScorer`.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, Protocol

from ..ingestion.urls import normalize_url

# Brands commonly impersonated in Indian payment/KYC fraud, mapped to the
# registered domains they legitimately use.
BRAND_DOMAINS: dict[str, set[str]] = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbicard.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com", "icici.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com", "google.com"},
    "googlepay": {"google.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "paypal": {"paypal.com"},
    "npci": {"npci.org.in"},
    "incometax": {"incometax.gov.in"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "irctc": {"irctc.co.in"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
}
# Multi-part public suffixes whose registered domain spans three labels.
_MULTI_SUFFIXES = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "co.uk", "com.au"}
SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "online", "site", "club", "icu", "live", "shop", "buzz", "click",
    "link", "rest", "fit", "cam", "monster", "sbs", "cfd", "tk", "ml", "ga", "cf", "gq",
})
PHISHING_KEYWORDS = (
    "login", "signin", "verify", "verification", "update", "kyc", "secure", "account",
    "bank", "wallet", "refund", "reward", "prize", "lottery", "claim", "otp", "bonus",
    "unlock", "suspend", "blocked", "confirm", "payment", "free", "gift",
)


@dataclass
class Signal:
    name: str
    weight: int
    detail: str = ""


@dataclass
class URLReputation:
    url: str
    domain: str
    score: int  # 0 (clean) .. 100 (almost certainly malicious)
    verdict: str  # "benign" | "suspicious" | "malicious"
    signals: list[Signal] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ReputationProvider(Protocol):
    """An external reputation source. Return ``None`` when the URL is unknown."""

    name: str

    def lookup(self, url: str, features: dict) -> list[Signal] | None: ...


class ListProvider:
    """Static allow/block lists, e.g. loaded from a threat-intel feed."""

    name = "lists"

    def __init__(self, blocklist: Iterable[str] = (), allowlist: Iterable[str] = ()):
        self.blocklist = {d.lower() for d in blocklist}
        self.allowlist = {d.lower() for d in allowlist}

    def lookup(self, url: str, features: dict) -> list[Signal] | None:
        hosts = {features["host"], registered_domain(features["host"])}
        if hosts & self.blocklist:
            return [Signal("blocklisted", 100, "domain is on the blocklist")]
        if hosts & self.allowlist:
            return [Signal("allowlisted", -100, "domain is on the allowlist")]
        return None


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _verdict(score: int) -> str:
    if score >= 60:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "benign"


class URLReputationScorer:
    def __init__(self, providers: Iterable[ReputationProvider] = ()):
        self.providers = list(providers)

    def score(self, url: str | dict) -> URLReputation:
        features = url if isinstance(url, dict) else normalize_url(url)
        host = features["host"]
        domain = registered_domain(host) if not features["is_ip_host"] else host
        signals = self._heuristics(features, domain)
        sources = ["heuristics"]

        for provider in self.providers:
            found = provider.lookup(features["canonical"], features)
            if found is not None:
                signals.extend(found)
                sources.append(provider.name)

        # An explicit allowlist hit overrides heuristics entirely.
        if any(s.name == "allowlisted" for s in signals):
            score = 0
        else:
            score = max(0, min(100, sum(s.weight for s in signals)))
        return URLReputation(
            url=features["canonical"], domain=domain, score=score,
            verdict=_verdict(score), signals=signals, sources=sources,
        )

    @staticmethod
    def _heuristics(f: dict, domain: str) -> list[Signal]:
        signals: list[Signal] = []
        host = f["host"]
        add = lambda name, weight, detail="": signals.append(Signal(name, weight, detail))  # noqa: E731

        if not host:
            add("no_host", 40, "URL has no resolvable host")
            return signals
        if f["is_ip_host"]:
            add("ip_address_host", 35, host)
        if f["is_punycode"]:
            add("punycode_domain", 30, f"displays as {f['display_host']}")
        if f["has_credentials"]:
            add("credentials_in_url", 30, "user@host trick hides the real destination")
        if f["is_shortener"]:
            add("url_shortener", 20, "real destination is hidden")
        if not f["uses_https"]:
            add("no_https", 10)
        if f["port"] and f["port"] not in (80, 443):
            add("non_standard_port", 10, str(f["port"]))

        tld = f["tld"]
        if tld in SUSPICIOUS_TLDS:
            add("suspicious_tld", 20, f".{tld}")

        name = domain.split(".")[0]
        if name.count("-") >= 2:
            add("many_hyphens", 10, name)
        if sum(ch.isdigit() for ch in name) >= 4:
            add("digit_heavy_domain", 10, name)
        if f["subdomain_depth"] >= 3:
            add("deep_subdomains", 15, host)
        if len(f["canonical"]) > 100:
            add("very_long_url", 5, f"{len(f['canonical'])} chars")

        # A brand name in a domain it doesn't own ("sbi-kyc-update.xyz").
        compact = re.sub(r"[^a-z0-9]", "", host)
        for brand, official in BRAND_DOMAINS.items():
            if brand in compact and not any(
                host == d or host.endswith("." + d) for d in official
            ):
                add("brand_impersonation", 45, f"mentions '{brand}' but is not {sorted(official)[0]}")
                break

        haystack = (host + f["path"]).lower()
        hits = sorted({k for k in PHISHING_KEYWORDS if k in haystack})
        if hits:
            add("phishing_keywords", min(8 * len(hits), 24), ", ".join(hits))

        if any(domain == d for official in BRAND_DOMAINS.values() for d in official):
            add("known_legitimate_domain", -40, domain)
        return signals
