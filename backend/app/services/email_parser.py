"""
TraceVault — email_parser.py
Parses raw .eml bytes (or pasted text) into a fully-structured ParsedEmailData
object using mail-parser (mailparser) as the primary engine with stdlib email
as a fallback.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes, message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

try:
    import mailparser  # mail-parser package
    _HAS_MAILPARSER = True
except ImportError:
    _HAS_MAILPARSER = False

from app.utils.hashing import compute_md5, compute_sha256


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AttachmentData:
    """Structured representation of an email attachment."""
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    content: bytes = field(repr=False)


@dataclass
class ParsedEmailData:
    """Complete structured data extracted from a raw email message."""

    # Sender information
    from_addr: str = ""
    from_name: str = ""
    from_domain: str = ""

    # Routing fields
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    message_id: str = ""

    # Display / metadata fields
    subject: str = ""
    date: datetime | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)

    # Body content
    body_text: str = ""
    body_html: str = ""

    # Header analysis fields
    headers: dict[str, Any] = field(default_factory=dict)
    raw_headers: dict[str, list[str]] = field(default_factory=dict)
    received_headers: list[str] = field(default_factory=list)

    # Extended / X- headers
    x_originating_ip: str | None = None
    x_mailer: str | None = None
    authentication_results: str | None = None
    dkim_signature: str | None = None

    # Attachments
    attachments: list[AttachmentData] = field(default_factory=list)

    # Validation
    rfc_violations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class EmailParserService:
    """
    Parses raw .eml bytes or text into a ``ParsedEmailData`` instance.

    Primary engine: mail-parser (``mailparser``).
    Fallback: Python stdlib ``email`` module when mail-parser is not installed.
    """

    # ------------------------------------------------------------------
    # Public async entry-points
    # ------------------------------------------------------------------

    async def parse_eml_bytes(self, raw_bytes: bytes) -> ParsedEmailData:
        """
        Parse raw .eml bytes into a ``ParsedEmailData`` instance.

        Args:
            raw_bytes: The complete raw email file content (RFC 5322 format).

        Returns:
            A fully-populated ``ParsedEmailData`` dataclass.
        """
        if _HAS_MAILPARSER:
            try:
                return self._parse_with_mailparser_bytes(raw_bytes)
            except Exception:
                pass  # Fall through to stdlib
        return self._parse_with_stdlib_bytes(raw_bytes)

    async def parse_raw_text(self, raw_text: str) -> ParsedEmailData:
        """
        Parse a raw email provided as a string (e.g. pasted into the UI).

        Args:
            raw_text: The raw email text in RFC 5322 format.

        Returns:
            A fully-populated ``ParsedEmailData`` dataclass.
        """
        if _HAS_MAILPARSER:
            try:
                return self._parse_with_mailparser_text(raw_text)
            except Exception:
                pass
        return self._parse_with_stdlib_text(raw_text)

    # ------------------------------------------------------------------
    # mail-parser paths
    # ------------------------------------------------------------------

    def _parse_with_mailparser_bytes(self, raw_bytes: bytes) -> ParsedEmailData:
        mail = mailparser.parse_from_bytes(raw_bytes)
        return self._build_from_mailparser(mail, raw_bytes)

    def _parse_with_mailparser_text(self, raw_text: str) -> ParsedEmailData:
        mail = mailparser.parse_from_string(raw_text)
        return self._build_from_mailparser(mail, raw_text.encode("utf-8", errors="replace"))

    def _build_from_mailparser(self, mail: Any, raw_bytes: bytes) -> ParsedEmailData:
        """Convert a mailparser result object to ``ParsedEmailData``."""
        # From
        from_list = mail.from_ or []
        from_name, from_addr = ("", "")
        if from_list:
            entry = from_list[0]
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                from_name, from_addr = str(entry[0]), str(entry[1])
            else:
                from_addr = str(entry)

        from_domain = self._extract_domain(from_addr)

        # Reply-To
        reply_to_raw = mail.reply_to or []
        reply_to: list[str] = []
        for entry in reply_to_raw:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                reply_to.append(str(entry[1]))
            else:
                reply_to.append(str(entry))

        # To / CC
        to_addrs = self._flatten_address_list(getattr(mail, "to", []))
        cc_addrs = self._flatten_address_list(getattr(mail, "cc", []))

        # Received headers — mailparser returns them oldest→newest; we reverse
        received_raw = getattr(mail, "received", []) or []
        received_strings = self._parse_received_headers(received_raw)

        # X- and auth headers (access raw headers dict)
        raw_headers_obj = getattr(mail, "headers", {}) or {}
        raw_headers = {k.lower(): [str(v)] for k, v in raw_headers_obj.items()}

        x_orig_ip = self._get_header(raw_headers, "x-originating-ip")
        x_mailer = self._get_header(raw_headers, "x-mailer")
        auth_results = self._get_header(raw_headers, "authentication-results")
        dkim_sig = self._get_header(raw_headers, "dkim-signature")
        return_path = self._get_header(raw_headers, "return-path") or ""
        message_id = getattr(mail, "message_id", "") or ""

        # Date
        date_obj: datetime | None = None
        try:
            date_val = getattr(mail, "date", None)
            if isinstance(date_val, datetime):
                date_obj = date_val
            elif date_val:
                date_obj = parsedate_to_datetime(str(date_val))
        except Exception:
            pass

        # Attachments
        attachments = self._extract_attachments_mailparser(mail)

        result = ParsedEmailData(
            from_addr=from_addr,
            from_name=from_name,
            from_domain=from_domain,
            reply_to=reply_to,
            return_path=self._clean_addr(return_path),
            message_id=message_id.strip("<>").strip(),
            subject=getattr(mail, "subject", "") or "",
            date=date_obj,
            to=to_addrs,
            cc=cc_addrs,
            body_text=getattr(mail, "body", "") or "",
            body_html=self._get_html_body_mailparser(mail),
            headers={k: v[0] if v else "" for k, v in raw_headers.items()},
            raw_headers=raw_headers,
            received_headers=received_strings,
            x_originating_ip=x_orig_ip,
            x_mailer=x_mailer,
            authentication_results=auth_results,
            dkim_signature=dkim_sig,
            attachments=attachments,
        )
        result.rfc_violations = self._detect_rfc_violations_data(result)
        return result

    def _get_html_body_mailparser(self, mail: Any) -> str:
        """Extract HTML body from mailparser object."""
        html_parts = getattr(mail, "text_html", []) or []
        if html_parts:
            return html_parts[0] if isinstance(html_parts[0], str) else ""
        return ""

    def _extract_attachments_mailparser(self, mail: Any) -> list[AttachmentData]:
        """Extract AttachmentData list from mailparser attachment objects."""
        result: list[AttachmentData] = []
        for att in (getattr(mail, "attachments", []) or []):
            content = att.get("payload", b"") or b""
            if isinstance(content, str):
                content = content.encode("latin-1", errors="replace")
            filename = att.get("filename", "") or "unnamed"
            content_type = att.get("mail_content_type", "application/octet-stream") or ""
            result.append(AttachmentData(
                filename=filename,
                content_type=content_type,
                size=len(content),
                sha256=compute_sha256(content),
                md5=compute_md5(content),
                content=content,
            ))
        return result

    # ------------------------------------------------------------------
    # stdlib fallback paths
    # ------------------------------------------------------------------

    def _parse_with_stdlib_bytes(self, raw_bytes: bytes) -> ParsedEmailData:
        msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)
        return self._build_from_stdlib(msg)

    def _parse_with_stdlib_text(self, raw_text: str) -> ParsedEmailData:
        msg = message_from_string(raw_text, policy=email.policy.compat32)
        return self._build_from_stdlib(msg)

    def _build_from_stdlib(self, msg: email.message.Message) -> ParsedEmailData:
        """Convert a stdlib email.message.Message to ParsedEmailData."""

        # Raw headers dict (multi-value)
        raw_headers: dict[str, list[str]] = {}
        for key in set(k.lower() for k in msg.keys()):
            raw_headers[key] = msg.get_all(key, [])

        # From
        from_raw = msg.get("From", "")
        from_name, from_addr = parseaddr(from_raw)
        from_domain = self._extract_domain(from_addr)

        # Reply-To
        reply_to_raw = msg.get("Reply-To", "")
        _, rt_addr = parseaddr(reply_to_raw)
        reply_to = [rt_addr] if rt_addr else []

        # Additional Reply-To values
        for rt in msg.get_all("Reply-To", [])[1:]:
            _, a = parseaddr(rt)
            if a:
                reply_to.append(a)

        # To / CC
        to_addrs = self._parse_addr_list(msg.get_all("To", []))
        cc_addrs = self._parse_addr_list(msg.get_all("Cc", []))

        # Return-Path / Message-ID
        return_path_raw = msg.get("Return-Path", "")
        _, return_path = parseaddr(return_path_raw)
        message_id = msg.get("Message-ID", "").strip("<>").strip()

        # Subject / Date
        subject = msg.get("Subject", "") or ""
        date_obj: datetime | None = None
        try:
            date_str = msg.get("Date")
            if date_str:
                date_obj = parsedate_to_datetime(date_str)
        except Exception:
            pass

        # Body
        body_text, body_html = self._extract_body_stdlib(msg)

        # Received headers — stdlib returns them in reverse (newest first)
        received_raw = msg.get_all("Received", []) or []
        received_strings = list(received_raw)  # already newest→oldest in stdlib

        # X- headers
        x_orig_ip = self._first(msg.get_all("X-Originating-IP", []))
        x_mailer = self._first(msg.get_all("X-Mailer", []))
        auth_results = self._first(msg.get_all("Authentication-Results", []))
        dkim_sig = self._first(msg.get_all("DKIM-Signature", []))

        # Attachments
        attachments = self._extract_attachments_stdlib(msg)

        result = ParsedEmailData(
            from_addr=from_addr,
            from_name=from_name,
            from_domain=from_domain,
            reply_to=reply_to,
            return_path=return_path,
            message_id=message_id,
            subject=subject,
            date=date_obj,
            to=to_addrs,
            cc=cc_addrs,
            body_text=body_text,
            body_html=body_html,
            headers={k: v[0] if v else "" for k, v in raw_headers.items()},
            raw_headers=raw_headers,
            received_headers=received_strings,
            x_originating_ip=x_orig_ip,
            x_mailer=x_mailer,
            authentication_results=auth_results,
            dkim_signature=dkim_sig,
            attachments=attachments,
        )
        result.rfc_violations = self._detect_rfc_violations_data(result)
        return result

    def _extract_body_stdlib(self, msg: email.message.Message) -> tuple[str, str]:
        """Walk the MIME tree and extract text/plain and text/html parts."""
        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in disposition:
                    continue
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                decoded = payload.decode(charset, errors="replace")
                if ct == "text/plain" and not body_text:
                    body_text = decoded
                elif ct == "text/html" and not body_html:
                    body_html = decoded
        else:
            ct = msg.get_content_type()
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(charset, errors="replace")
                if ct == "text/html":
                    body_html = decoded
                else:
                    body_text = decoded
        return body_text, body_html

    def _extract_attachments_stdlib(self, msg: email.message.Message) -> list[AttachmentData]:
        """Extract attachments from a stdlib email.message.Message."""
        attachments: list[AttachmentData] = []
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" not in disposition:
                continue
            filename = part.get_filename() or "unnamed"
            content_type = part.get_content_type() or "application/octet-stream"
            payload = part.get_payload(decode=True) or b""
            attachments.append(AttachmentData(
                filename=filename,
                content_type=content_type,
                size=len(payload),
                sha256=compute_sha256(payload),
                md5=compute_md5(payload),
                content=payload,
            ))
        return attachments

    # ------------------------------------------------------------------
    # Shared helper methods
    # ------------------------------------------------------------------

    def _extract_domain(self, email_addr: str) -> str:
        """Extract the domain portion from an email address string."""
        if not email_addr:
            return ""
        cleaned = self._clean_addr(email_addr)
        if "@" in cleaned:
            return cleaned.split("@", 1)[1].lower().strip()
        return ""

    def _clean_addr(self, addr: str) -> str:
        """Strip angle brackets and whitespace from an address string."""
        return addr.strip().strip("<>").strip()

    def _parse_received_headers(self, received_raw: list) -> list[str]:
        """
        Normalise received header values from mailparser into plain strings.

        mailparser may return dicts or strings. We always return strings,
        ordered newest → oldest (most recent hop first).
        """
        result: list[str] = []
        for item in received_raw:
            if isinstance(item, dict):
                result.append(item.get("src", str(item)))
            else:
                result.append(str(item))
        return result  # mailparser returns newest first already

    def _flatten_address_list(self, addr_list: list) -> list[str]:
        """Flatten mailparser address lists (which may be [name, email] pairs)."""
        result: list[str] = []
        for entry in (addr_list or []):
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                result.append(str(entry[1]))
            elif isinstance(entry, str):
                result.append(entry)
        return result

    def _parse_addr_list(self, header_values: list[str]) -> list[str]:
        """Parse a list of header values containing RFC 5322 address lists."""
        addrs: list[str] = []
        for val in header_values:
            # Each header value may contain comma-separated addresses
            for part in val.split(","):
                _, addr = parseaddr(part.strip())
                if addr:
                    addrs.append(addr.lower())
        return addrs

    def _get_header(self, raw_headers: dict[str, list[str]], name: str) -> str | None:
        """Return the first value of *name* from raw_headers, or None."""
        values = raw_headers.get(name.lower(), [])
        return values[0].strip() if values else None

    def _first(self, lst: list[str]) -> str | None:
        """Return the first element of a list or None if empty."""
        return lst[0].strip() if lst else None

    # ------------------------------------------------------------------
    # RFC violation detection
    # ------------------------------------------------------------------

    def _detect_rfc_violations(self, mail: Any) -> list[str]:
        """Detect RFC violations from a mailparser object (legacy interface)."""
        raw_headers = {k.lower(): [str(v)] for k, v in (getattr(mail, "headers", {}) or {}).items()}
        violations: list[str] = []
        if not self._get_header(raw_headers, "date"):
            violations.append("RFC5322: Missing required 'Date' header")
        if not self._get_header(raw_headers, "from"):
            violations.append("RFC5322: Missing required 'From' header")
        if not self._get_header(raw_headers, "message-id"):
            violations.append("RFC5322: Missing 'Message-ID' header (recommended)")
        froms = raw_headers.get("from", [])
        if len(froms) > 1:
            violations.append("RFC5322: Multiple 'From' headers detected")
        mid = self._get_header(raw_headers, "message-id") or ""
        if mid and not re.match(r"^[^@]+@[^@]+$", mid.strip("<>")):
            violations.append(f"RFC5322: Malformed Message-ID '{mid}'")
        return violations

    def _detect_rfc_violations_data(self, data: ParsedEmailData) -> list[str]:
        """Detect RFC violations from a ParsedEmailData object."""
        violations: list[str] = []

        if not data.date:
            violations.append("RFC5322: Missing or unparseable 'Date' header")

        if not data.from_addr:
            violations.append("RFC5322: Missing required 'From' header")

        if not data.message_id:
            violations.append("RFC5322: Missing 'Message-ID' header (recommended)")
        elif not re.match(r"^[^@\s]+@[^@\s]+$", data.message_id):
            violations.append(
                f"RFC5322: Malformed Message-ID format: '{data.message_id}'"
            )

        # Multiple From headers
        from_values = data.raw_headers.get("from", [])
        if len(from_values) > 1:
            violations.append("RFC5322: Multiple 'From' headers detected")

        # Missing Subject (not technically required but suspicious)
        if not data.subject:
            violations.append("RFC5322: Missing 'Subject' header")

        # Return-Path should be present in delivered email
        if not data.return_path:
            violations.append("RFC5321: Missing 'Return-Path' header (set by MTA on delivery)")

        # Received headers presence
        if not data.received_headers:
            violations.append("RFC5321: No 'Received' headers present (possibly direct injection)")

        return violations
