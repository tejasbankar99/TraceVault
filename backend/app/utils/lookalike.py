"""
TraceVault — lookalike.py
Lookalike / typosquat domain detection using Levenshtein distance,
homoglyph substitution analysis, and composite scoring.
"""

from __future__ import annotations

import re
import unicodedata

try:
    import Levenshtein  # python-Levenshtein (C extension, fastest)
    _USE_LEVENSHTEIN_LIB = True
except ImportError:
    _USE_LEVENSHTEIN_LIB = False

try:
    import tldextract  # for reliable eTLD+1 splitting
    _USE_TLDEXTRACT = True
except ImportError:
    _USE_TLDEXTRACT = False


# ---------------------------------------------------------------------------
# Homoglyph / visual substitution mapping
# ---------------------------------------------------------------------------

HOMOGLYPH_MAP: dict[str, str] = {
    # Digit → letter
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "b",
    "7": "t",
    "8": "b",
    # Cyrillic lookalikes (common in IDN abuse)
    "\u0430": "a",   # CYRILLIC SMALL LETTER A
    "\u0435": "e",   # CYRILLIC SMALL LETTER IE
    "\u043e": "o",   # CYRILLIC SMALL LETTER O
    "\u0440": "p",   # CYRILLIC SMALL LETTER ER
    "\u0441": "c",   # CYRILLIC SMALL LETTER ES
    "\u0445": "x",   # CYRILLIC SMALL LETTER HA
    "\u0443": "y",   # CYRILLIC SMALL LETTER U
    "\u044c": "b",   # CYRILLIC SMALL LETTER SOFT SIGN
    "\u0456": "i",   # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0455": "s",   # CYRILLIC SMALL LETTER DZE
    # Greek
    "\u03b1": "a",   # GREEK SMALL LETTER ALPHA
    "\u03bf": "o",   # GREEK SMALL LETTER OMICRON
    "\u03c1": "p",   # GREEK SMALL LETTER RHO
    "\u03bd": "v",   # GREEK SMALL LETTER NU
}

# Multi-character substitution patterns (rn → m, vv → w, etc.)
_PAIR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"rn"), "m"),
    (re.compile(r"vv"), "w"),
    (re.compile(r"cl"), "d"),
    (re.compile(r"ri"), "n"),
    (re.compile(r"li"), "h"),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_sld(domain: str) -> str:
    """
    Extract the Second-Level Domain (SLD) — the registrable portion without
    the TLD, subdomains, or leading/trailing dots.

    E.g. ``secure-paypal.com`` → ``secure-paypal``
         ``mail.google.com``   → ``google``

    Uses *tldextract* when available for accurate eTLD handling; falls back
    to a simple split on the last two dot-parts.
    """
    domain = domain.lower().strip(".")
    if _USE_TLDEXTRACT:
        extracted = tldextract.extract(domain)
        return extracted.domain
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _normalise_for_comparison(label: str) -> str:
    """Apply Unicode NFKC normalisation and lower-case the label."""
    return unicodedata.normalize("NFKC", label).lower()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_edit_distance(s1: str, s2: str) -> int:
    """
    Return the Levenshtein edit distance between *s1* and *s2*.

    Uses the C extension (python-Levenshtein) when installed; falls back to
    a pure-Python Wagner–Fischer dynamic-programming implementation.
    """
    if _USE_LEVENSHTEIN_LIB:
        return Levenshtein.distance(s1, s2)

    # Pure-Python fallback
    m, n = len(s1), len(s2)
    dp: list[list[int]] = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,        # deletion
                dp[i][j - 1] + 1,        # insertion
                dp[i - 1][j - 1] + cost  # substitution
            )
    return dp[m][n]


def is_lookalike_domain(
    domain: str,
    brand_list: list[str],
    threshold: int = 3,
) -> tuple[bool, str | None]:
    """
    Determine whether *domain* is a lookalike of any brand in *brand_list*.

    Algorithm:
    1. Extract the SLD of *domain*.
    2. For each brand, compute the Levenshtein distance between SLD and brand.
    3. If distance ≤ *threshold*, classify as lookalike.
    4. Return the closest match (shortest distance).

    Returns:
        ``(True, brand_name)`` if lookalike detected, else ``(False, None)``.
        Returns ``(False, None)`` on exact match (legitimate sender).
    """
    sld = _extract_sld(domain)
    if not sld:
        return False, None

    sld_norm = _normalise_for_comparison(sld)

    best_distance = threshold + 1
    best_brand: str | None = None

    for brand in brand_list:
        brand_norm = brand.lower()

        # Skip exact match — this is a legitimate sender
        if sld_norm == brand_norm:
            return False, None

        dist = compute_edit_distance(sld_norm, brand_norm)
        if dist <= threshold and dist < best_distance:
            best_distance = dist
            best_brand = brand

    if best_brand is not None:
        return True, best_brand
    return False, None


def check_homoglyph_substitution(domain: str) -> bool:
    """
    Return ``True`` if *domain* contains characters or character sequences
    that are visual substitutes for legitimate ASCII characters.

    Checks:
    - Non-ASCII characters mapping to ASCII look-alikes (Cyrillic, Greek).
    - Digit substitutions in brand-like labels (0→o, 1→l, etc.).
    - Multi-char substitutions: ``rn``→m, ``vv``→w, ``cl``→d, etc.
    - Mixed-script labels (Latin + Cyrillic in same label).
    """
    label = _extract_sld(domain).lower()
    if not label:
        label = domain.lower()

    # Non-ASCII single-char homoglyphs
    for char in label:
        if char in HOMOGLYPH_MAP and char not in "01345678":
            return True

    # Digit substitutions (flag only in letter+digit labels)
    has_letters = any(c.isalpha() for c in label)
    has_suspicious_digits = any(c in "01345678" for c in label)
    if has_letters and has_suspicious_digits:
        normalised = label
        for digit, letter in {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"}.items():
            normalised = normalised.replace(digit, letter)
        if normalised != label:
            return True

    # Multi-char pair substitutions
    for pattern, _ in _PAIR_PATTERNS:
        if pattern.search(label):
            return True

    # Mixed-script detection
    scripts: set[str] = set()
    for char in label:
        if char.isalpha():
            try:
                script = unicodedata.name(char, "").split()[0]
                scripts.add(script)
            except Exception:
                pass
    if len(scripts) > 1:
        return True

    return False


def get_suspicious_domain_score(
    domain: str,
    brand_list: list[str],
    threshold: int = 3,
) -> dict:
    """
    Return a comprehensive analysis dict for *domain*.

    Keys returned:
    - ``domain``            — input domain string
    - ``sld``               — extracted second-level domain
    - ``is_lookalike``      — bool
    - ``lookalike_target``  — str | None (closest matching brand)
    - ``edit_distance``     — int | None
    - ``has_homoglyphs``    — bool
    - ``risk_score``        — 0-100 int
    - ``risk_factors``      — list[str] of human-readable findings
    - ``verdict``           — "LIKELY_MALICIOUS" | "SUSPICIOUS" | "CLEAN"
    """
    sld = _extract_sld(domain)
    is_lookalike, lookalike_target = is_lookalike_domain(domain, brand_list, threshold)
    has_homoglyphs = check_homoglyph_substitution(domain)

    edit_distance: int | None = None
    if is_lookalike and lookalike_target:
        edit_distance = compute_edit_distance(
            _normalise_for_comparison(sld),
            lookalike_target.lower(),
        )

    risk_factors: list[str] = []
    risk_score = 0

    if is_lookalike and lookalike_target:
        risk_factors.append(
            f"Domain SLD '{sld}' is a lookalike of brand '{lookalike_target}' "
            f"(edit distance: {edit_distance})"
        )
        if edit_distance == 1:
            risk_score += 70
        elif edit_distance == 2:
            risk_score += 55
        else:
            risk_score += 40

    if has_homoglyphs:
        risk_factors.append(
            f"Domain '{domain}' contains homoglyph/visual substitution characters"
        )
        risk_score += 30

    # Hyphen abuse: paypal-secure.com / secure-paypal.com
    if "-" in sld:
        parts = sld.split("-")
        for brand in brand_list:
            if brand.lower() in parts:
                risk_factors.append(
                    f"Brand name '{brand}' used as a hyphenated sub-label in domain"
                )
                risk_score += 25
                break

    # Brand used as subdomain label: paypal.evil-domain.com
    full_labels = domain.lower().strip(".").split(".")
    for brand in brand_list:
        if brand.lower() in full_labels[:-1]:
            risk_factors.append(
                f"Brand name '{brand}' appears as a subdomain label"
            )
            risk_score += 35
            break

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict = "LIKELY_MALICIOUS"
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "domain": domain,
        "sld": sld,
        "is_lookalike": is_lookalike,
        "lookalike_target": lookalike_target,
        "edit_distance": edit_distance,
        "has_homoglyphs": has_homoglyphs,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "verdict": verdict,
    }
