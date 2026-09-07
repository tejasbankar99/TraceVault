"""
TraceVault — ioc_patterns.py
Compiled regex patterns and helper functions for extracting and normalising
Indicators of Compromise (IOCs) from raw email text and HTML.
"""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Standard IPv4 — four octets, each 0-255
IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\b"
)

# IPv6 — covers full, compressed (::), and mixed IPv4/IPv6 forms
IPV6_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:"
    # Full 8-group form
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|"
    # Compressed forms with ::
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    r"::(?:[fF]{4}(?::0{1,4})?:)?"
    r"(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:"
    r"(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r"|"
    r"::"
    r")\b",
    re.IGNORECASE,
)

# Comprehensive URL pattern — http / https / ftp in body text and HTML
URL_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)"
    r"\b(?:https?|ftp)://"                    # scheme
    r"(?:[a-z0-9\-._~%!$&'()*+,;=:@]+"        # userinfo or host chars
    r"|(?:\[(?:[0-9a-fA-F:]+)\]))"             # IPv6 literal
    r"(?::\d{1,5})?"                           # optional port
    r"(?:/[a-z0-9\-._~%!$&'()*+,;=:@/]*)?"   # path
    r"(?:\?[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?" # query
    r"(?:\#[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?" # fragment
    r"(?=[^\w]|$)",                            # boundary
)

# Email address — RFC 5321-ish, handles most real-world addresses
EMAIL_PATTERN: re.Pattern[str] = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Standalone domain (no scheme) — e.g. evil-domain.xyz
DOMAIN_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# ---------------------------------------------------------------------------
# Defang / refang patterns
# ---------------------------------------------------------------------------

# Used for defanging: patterns to neutralise URLs for safe sharing
DEFANG_PATTERNS: dict[str, str] = {
    "http://":  "hXXp://",
    "https://": "hXXps://",
    "ftp://":   "fXXp://",
}


def defang_url(url: str) -> str:
    """
    Defang a URL so it cannot be accidentally clicked or resolved.

    Transformations applied:
    - ``http://``  → ``hXXp://``
    - ``https://`` → ``hXXps://``
    - ``ftp://``   → ``fXXp://``
    - Literal ``.`` in the netloc portion → ``[.]``
    """
    result = url
    for original, defanged in DEFANG_PATTERNS.items():
        result = result.replace(original, defanged)

    # Replace dots in domain portion only (not in path/query)
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        netloc_defanged = parsed.netloc.replace(".", "[.]")
        result = result.replace(parsed.netloc, netloc_defanged, 1)
    except Exception:
        result = result.replace(".", "[.]", 1)

    return result


def refang_url(url: str) -> str:
    """
    Reverse a defanged URL back to its original form.

    Handles common defang conventions including hXXp, hxxp, [.], [:]
    """
    result = url
    result = re.sub(r"hXXps://", "https://", result)
    result = re.sub(r"hXXp://",  "http://",  result)
    result = re.sub(r"hxxps://", "https://", result, flags=re.IGNORECASE)
    result = re.sub(r"hxxp://",  "http://",  result, flags=re.IGNORECASE)
    result = re.sub(r"fXXp://",  "ftp://",   result)
    result = re.sub(r"fxxp://",  "ftp://",   result, flags=re.IGNORECASE)
    # Dot variants
    result = result.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    # Port colon variants
    result = result.replace("[:]", ":").replace("(:)", ":")
    return result


# ---------------------------------------------------------------------------
# IP address utilities
# ---------------------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    """
    Return ``True`` if *ip* is RFC 1918, loopback, link-local, or otherwise
    non-routable / special-purpose.

    Handles both IPv4 and IPv6.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

def extract_domain_from_url(url: str) -> str:
    """
    Extract and return the netloc (host, without port) from a URL string.

    Falls back to the raw input if parsing fails.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or parsed.netloc
        return host.lower().strip() if host else url.lower().strip()
    except Exception:
        return url.lower().strip()


# ---------------------------------------------------------------------------
# Text / HTML extraction helpers
# ---------------------------------------------------------------------------

def extract_emails_from_text(text: str) -> list[str]:
    """Return a deduplicated list of email addresses found in *text*."""
    return list(dict.fromkeys(m.lower() for m in EMAIL_PATTERN.findall(text)))


def extract_urls_from_text(text: str) -> list[str]:
    """Return a deduplicated list of URLs found in plain-text *text*."""
    return list(dict.fromkeys(URL_PATTERN.findall(text)))


class _HrefSrcExtractor(HTMLParser):
    """Minimal HTML parser that collects href, src, action, and data-url values."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr_name, attr_val in attrs:
            if attr_name in ("href", "src", "action", "data-url") and attr_val:
                self.links.append(attr_val.strip())


def extract_urls_from_html(html: str) -> list[str]:
    """
    Extract URLs from HTML content using two strategies:

    1. Parse ``href``, ``src``, ``action``, and ``data-url`` attributes.
    2. Apply the URL regex over the full HTML text (catches inline URLs in
       ``<script>`` blocks, ``style`` attributes, etc.).

    Returns a deduplicated list of URLs, filtering out fragment-only and
    ``javascript:`` pseudo-URLs.
    """
    # Strategy 1: attribute extraction
    parser = _HrefSrcExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    attr_urls = [
        u for u in parser.links
        if u
        and not u.startswith("#")
        and not u.lower().startswith("javascript:")
    ]

    # Strategy 2: regex over full HTML
    regex_urls = URL_PATTERN.findall(html)

    combined = attr_urls + regex_urls
    seen: set[str] = set()
    result: list[str] = []
    for url in combined:
        key = url.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


def extract_ips_from_text(text: str) -> list[str]:
    """
    Return a deduplicated list of IP addresses (v4 and v6) found in *text*.
    """
    ipv4s = IPV4_PATTERN.findall(text)
    ipv6s = IPV6_PATTERN.findall(text)
    return list(dict.fromkeys(ipv4s + ipv6s))
