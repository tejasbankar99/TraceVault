"""
TraceVault — evidence_preservation.py
Immutable evidence preservation with dual-hash integrity checking and
an aiofiles-based async write pipeline for chain-of-custody compliance.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import aiofiles
import aiofiles.os

from app.utils.hashing import compute_sha256, compute_sha3_256, generate_case_id


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    """Immutable record created when evidence is first preserved."""
    case_id: str
    sha256: str
    sha3_256: str
    file_path: str
    file_size_bytes: int
    created_at: datetime
    created_by_id: str


@dataclass
class IntegrityResult:
    """Result of a post-preservation integrity verification."""
    is_intact: bool
    computed_hash: str
    stored_hash: str
    verified_at: datetime
    case_id: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class EvidencePreservationService:
    """
    Handles forensic-grade evidence preservation for email artefacts.

    Responsibilities:
    - Compute SHA-256 and SHA-3-256 immediately on ingest (before any writes).
    - Write the original .eml file to a case-specific directory.
    - Write an evidence_manifest.json alongside for chain-of-custody.
    - Provide async integrity verification against the stored manifest hash.

    Configuration:
    - Evidence store root is read from ``settings.EVIDENCE_STORE_PATH``.
    - Falls back to ``./evidence_store`` when settings are unavailable.
    """

    def __init__(self) -> None:
        try:
            from app.config import settings  # type: ignore[import]
            self._store_root = str(settings.EVIDENCE_STORE_PATH)
        except (ImportError, AttributeError):
            self._store_root = str(Path.cwd() / "evidence_store")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def preserve_email(
        self,
        raw_bytes: bytes,
        created_by_id: str,
    ) -> EvidenceRecord:
        """
        Persist raw email bytes as tamper-evident forensic evidence.

        Steps:
        1. Compute SHA-256 and SHA-3-256 of raw bytes *before* any I/O.
        2. Generate a unique case_id.
        3. Create the case evidence directory.
        4. Write ``original.eml`` using aiofiles (async, buffered).
        5. Write ``evidence_manifest.json`` with hashes, timestamps, size.
        6. Return an ``EvidenceRecord`` dataclass.

        Args:
            raw_bytes:      The complete raw .eml content.
            created_by_id:  User / API-key ID that submitted the email.

        Returns:
            An ``EvidenceRecord`` with case_id, hashes, path, and timestamp.
        """
        # Step 1 — hash immediately (before any writes)
        sha256_digest = compute_sha256(raw_bytes)
        sha3_digest = compute_sha3_256(raw_bytes)

        # Step 2 — unique case identifier
        case_id = generate_case_id()

        # Step 3 — create directory
        case_dir = self._get_evidence_path(case_id)
        await aiofiles.os.makedirs(case_dir, exist_ok=True)

        # Step 4 — write original .eml
        eml_path = self._get_eml_path(case_id)
        async with aiofiles.open(eml_path, "wb") as fh:
            await fh.write(raw_bytes)

        # Step 5 — write manifest
        now = datetime.now(tz=timezone.utc)
        manifest = {
            "case_id": case_id,
            "sha256": sha256_digest,
            "sha3_256": sha3_digest,
            "file_size_bytes": len(raw_bytes),
            "original_filename": "original.eml",
            "created_at": now.isoformat(),
            "created_by_id": created_by_id,
            "schema_version": "1.0",
        }
        manifest_path = os.path.join(case_dir, "evidence_manifest.json")
        async with aiofiles.open(manifest_path, "w", encoding="utf-8") as fh:
            await fh.write(json.dumps(manifest, indent=2))

        # Step 6 — return record
        return EvidenceRecord(
            case_id=case_id,
            sha256=sha256_digest,
            sha3_256=sha3_digest,
            file_path=eml_path,
            file_size_bytes=len(raw_bytes),
            created_at=now,
            created_by_id=created_by_id,
        )

    async def verify_evidence_integrity(
        self,
        case_id: str,
        stored_hash: str,
    ) -> IntegrityResult:
        """
        Verify that the stored .eml file has not been altered since preservation.

        Reads the .eml file, recomputes its SHA-256 digest, and compares it to
        *stored_hash* (which should come from the original ``EvidenceRecord`` or
        the ``evidence_manifest.json``).

        Args:
            case_id:     The case identifier returned by ``preserve_email``.
            stored_hash: The SHA-256 digest to compare against.

        Returns:
            An ``IntegrityResult`` with ``is_intact=True`` when hashes match.
        """
        verified_at = datetime.now(tz=timezone.utc)
        eml_path = self._get_eml_path(case_id)

        try:
            async with aiofiles.open(eml_path, "rb") as fh:
                raw_bytes = await fh.read()
        except FileNotFoundError:
            return IntegrityResult(
                is_intact=False,
                computed_hash="",
                stored_hash=stored_hash,
                verified_at=verified_at,
                case_id=case_id,
                error=f"Evidence file not found: {eml_path}",
            )
        except OSError as exc:
            return IntegrityResult(
                is_intact=False,
                computed_hash="",
                stored_hash=stored_hash,
                verified_at=verified_at,
                case_id=case_id,
                error=f"OS error reading evidence: {exc}",
            )

        computed = compute_sha256(raw_bytes)
        return IntegrityResult(
            is_intact=computed == stored_hash.lower(),
            computed_hash=computed,
            stored_hash=stored_hash.lower(),
            verified_at=verified_at,
            case_id=case_id,
            error=None,
        )

    async def load_manifest(self, case_id: str) -> dict | None:
        """
        Load and return the evidence_manifest.json for *case_id*, or None if
        the manifest does not exist.
        """
        manifest_path = os.path.join(self._get_evidence_path(case_id), "evidence_manifest.json")
        try:
            async with aiofiles.open(manifest_path, "r", encoding="utf-8") as fh:
                content = await fh.read()
            return json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    async def read_raw_eml(self, case_id: str) -> bytes | None:
        """
        Read and return the raw .eml bytes for *case_id*, or None if not found.
        """
        eml_path = self._get_eml_path(case_id)
        try:
            async with aiofiles.open(eml_path, "rb") as fh:
                return await fh.read()
        except FileNotFoundError:
            return None

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _get_evidence_path(self, case_id: str) -> str:
        """Return the directory path for a given case_id."""
        return os.path.join(self._store_root, case_id)

    def _get_eml_path(self, case_id: str) -> str:
        """Return the full path to the original.eml file for a case."""
        return os.path.join(self._get_evidence_path(case_id), "original.eml")
