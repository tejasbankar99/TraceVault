"""
TraceVault — hashing.py
Cryptographic hashing utilities for evidence integrity, IOC fingerprinting,
and forensic case ID generation.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Core hash functions
# ---------------------------------------------------------------------------

def compute_sha256(data: bytes) -> str:
    """Return lowercase hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def compute_sha3_256(data: bytes) -> str:
    """Return lowercase hex-encoded SHA3-256 digest of *data*."""
    return hashlib.sha3_256(data).hexdigest()


def compute_md5(data: bytes) -> str:
    """
    Return lowercase hex-encoded MD5 digest of *data*.

    MD5 is retained for attachment correlation against legacy threat-intel
    feeds (e.g. VirusTotal) that still index by MD5.  It is **not** used
    for integrity proofs — use SHA-256 / SHA3-256 for that purpose.
    """
    return hashlib.md5(data).hexdigest()  # noqa: S324


# ---------------------------------------------------------------------------
# Deterministic dictionary hashing
# ---------------------------------------------------------------------------

def hash_dict(d: dict) -> str:
    """
    Produce a deterministic SHA-256 fingerprint of dictionary *d*.

    The dict is JSON-serialised with sorted keys and no extra whitespace so
    that two dicts with the same logical content always produce the same hash
    regardless of insertion order.
    """
    serialised = json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)
    return compute_sha256(serialised.encode("utf-8"))


# ---------------------------------------------------------------------------
# Case ID generation
# ---------------------------------------------------------------------------

def generate_case_id() -> str:
    """
    Generate a human-readable, globally-unique TraceVault case identifier.

    Format: ``TV-{YYYYMMDD}-{8-char uppercase hex}``

    Example: ``TV-20260906-3A7F1B2C``
    """
    today = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:8].upper()
    return f"TV-{today}-{suffix}"


# ---------------------------------------------------------------------------
# Hash verification
# ---------------------------------------------------------------------------

def verify_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify that *data* matches *expected_hash*.

    Auto-detects algorithm by digest length:
    - 32 chars  → MD5
    - 64 chars  → SHA-256 or SHA3-256 (both checked when length == 64)

    Args:
        data:          Raw bytes to verify.
        expected_hash: Lowercase hex digest (MD5, SHA-256, or SHA3-256).

    Returns:
        ``True`` if *data* matches *expected_hash*, ``False`` otherwise.
    """
    expected = expected_hash.strip().lower()
    length = len(expected)

    if length == 32:
        return compute_md5(data) == expected

    if length == 64:
        # Try SHA-256 first (most common), then SHA3-256
        if compute_sha256(data) == expected:
            return True
        if compute_sha3_256(data) == expected:
            return True
        return False

    # Unknown length — attempt all algorithms
    return (
        compute_md5(data) == expected
        or compute_sha256(data) == expected
        or compute_sha3_256(data) == expected
    )
