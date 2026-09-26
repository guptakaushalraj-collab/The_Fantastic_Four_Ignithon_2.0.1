"""URL canonicalization and structural feature extraction."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .text import normalize_text, refang

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id",
})
_TRACKING_PARAMS = ("utm_", "fbclid", "gclid", "mc_eid", "igshid")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(raw: str) -> dict:
    """Return the canonical form of ``raw`` plus host features useful for later scoring.

    Canonicalization lowercases scheme and host, decodes punycode for display,
    drops default ports, fragments and tracking parameters, and refangs
    defanged indicators such as ``hxxps://evil[.]com``.
    """
    text = refang(normalize_text(raw)).strip("<>\"' ")
    if "://" not in text:
        text = "http://" + text

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None

    try:
        display_host = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        display_host = host

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    netloc = host
    if port and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"

    query = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING_PARAMS)
    ]
    canonical = urlunsplit((scheme, netloc, parts.path or "/", urlencode(query), ""))

    labels = host.split(".") if host and not is_ip else []
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host

    return {
        "original": raw.strip(),
        "canonical": canonical,
        "scheme": scheme,
        "host": host,
        "display_host": display_host,
        "registered_domain": registered_domain,
        "tld": labels[-1] if labels else "",
        "subdomain_depth": max(len(labels) - 2, 0),
        "port": port,
        "path": parts.path or "/",
        "query_params": dict(query),
        "is_ip_host": is_ip,
        "is_punycode": "xn--" in host,
        "is_shortener": host.removeprefix("www.") in URL_SHORTENERS,
        "has_credentials": bool(parts.username),
        "uses_https": scheme == "https",
    }
