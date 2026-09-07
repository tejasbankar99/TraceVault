"""
TraceVault — ioc_extractor.py
Full IOC (Indicator of Compromise) extraction from parsed email data and
relay chain metadata.  Covers IPs, URLs, domains, email addresses, and
attachment file hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.utils.constants import (
    IOC_TYPES,
    SEVERITY_LEVELS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    WELL_KNOWN_BRANDS,
)
from app.utils.ioc_patterns import (
    defang_url,
    extract_domain_from_url,
    extract_emails_from_text,
    extract_ips_from_text,
    extract_urls_from_html,
    extract_urls_from_text,
    is_private_ip,
)
from app.utils.lookalike import get_suspicious_domain_score

if TYPE_CHECKING:
    from app.services.email_parser import ParsedEmailData
    from app.services.header_forensics import RelayHopData


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DomainAnalysis:
    """Result of a domain threat analysis."""
    domain: str
    is_lookalike: bool = False
    lookalike_target: str | None = None
    has_suspicious_tld: bool = False
    has_homoglyphs: bool = False
    is_url_shortener: bool = False
    risk_score: int = 0
    severity: str = "LOW"
    risk_factors: list[str] = field(default_factory=list)


@dataclass
class ExtractedIOC:
    """A single extracted Indicator of Compromise."""
    ioc_type: str                              # IOC_TYPES constant
    ioc_value: str                             # Raw (refanged) value
    defanged_value: str                        # Safe display value
    severity: str = "LOW"                      # LOW / MEDIUM / HIGH / CRITICAL
    context: str = ""                          # Where it was found
    is_lookalike: bool = False
    lookalike_target: str | None = None
    is_shortened_url: bool = False
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class IOCExtractorService:
    """
    Extracts and classifies all Indicators of Compromise from a parsed email.

    Usage::

        service = IOCExtractorService()
        iocs = service.extract_all_iocs(parsed_email, relay_chain)
    """

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    def extract_all_iocs(
        self,
        parsed_email: "ParsedEmailData",
        relay_chain: list["RelayHopData"],
    ) -> list[ExtractedIOC]:
        """
        Extract, classify, and deduplicate all IOCs from the email.

        Extraction order:
        1. IP addresses (relay chain + body text + X-Originating-IP)
        2. URLs (body text + HTML href/src attributes)
        3. Domain IOCs derived from extracted URLs
        4. Email addresses found in the body
        5. Attachment file hashes

        Returns:
            Deduplicated list of ``ExtractedIOC`` objects.
        """
        iocs: list[ExtractedIOC] = []
        iocs.extend(self.extract_ip_addresses(parsed_email, relay_chain))
        iocs.extend(self.extract_urls(parsed_email))
        iocs.extend(self.extract_email_addresses(parsed_email))
        iocs.extend(self.extract_attachment_hashes(parsed_email))
        return self.deduplicate_iocs(iocs)

    # ------------------------------------------------------------------
    # IP address extraction
    # ------------------------------------------------------------------

    def extract_ip_addresses(
        self,
        parsed_email: "ParsedEmailData",
        relay_chain: list["RelayHopData"],
    ) -> list[ExtractedIOC]:
        """
        Extract IP addresses from:
        - Each hop in the relay chain (already parsed).
        - X-Originating-IP header.
        - Plain-text body.
        """
        iocs: list[ExtractedIOC] = []
        seen: set[str] = set()

        def _add_ip(ip: str, context: str, hop_index: int | None = None) -> None:
            ip = ip.strip()
            if not ip or ip in seen:
                return
            seen.add(ip)
            severity = self.classify_ip_severity(ip, context)
            metadata: dict = {"context": context}
            if hop_index is not None:
                metadata["relay_hop_index"] = hop_index
            iocs.append(ExtractedIOC(
                ioc_type=IOC_TYPES.IP,
                ioc_value=ip,
                defanged_value=ip.replace(".", "[.]"),
                severity=severity,
                context=context,
                metadata=metadata,
            ))

        # From relay chain
        for hop in relay_chain:
            if hop.ip_address:
                _add_ip(
                    hop.ip_address,
                    f"Received header hop {hop.hop_index} (from: {hop.from_server})",
                    hop_index=hop.hop_index,
                )

        # X-Originating-IP
        if parsed_email.x_originating_ip:
            _add_ip(
                parsed_email.x_originating_ip.strip(),
                "X-Originating-IP header (webmail sender IP)",
            )

        # Body text
        body_text = (parsed_email.body_text or "") + " " + (parsed_email.body_html or "")
        for ip in extract_ips_from_text(body_text):
            _add_ip(ip, "Email body text")

        return iocs

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------

    def extract_urls(self, parsed_email: "ParsedEmailData") -> list[ExtractedIOC]:
        """
        Extract URLs from the email body (plain text and HTML).

        For each URL:
        - Defang for safe display.
        - Check if it's a URL shortener.
        - Check if its TLD is suspicious.
        - Extract the domain and add as a separate DOMAIN IOC.
        """
        iocs: list[ExtractedIOC] = []
        seen_urls: set[str] = set()
        seen_domains: set[str] = set()

        all_urls: list[tuple[str, str]] = []  # (url, context)

        # Plain text body
        for url in extract_urls_from_text(parsed_email.body_text or ""):
            all_urls.append((url, "email body plain text"))

        # HTML body
        for url in extract_urls_from_html(parsed_email.body_html or ""):
            all_urls.append((url, "email body HTML (href/src attribute)"))

        for url, context in all_urls:
            url_key = url.lower().rstrip("/")
            if url_key in seen_urls:
                continue
            seen_urls.add(url_key)

            domain = extract_domain_from_url(url)
            is_shortener = self._is_url_shortener(domain)
            has_suspicious_tld = self._has_suspicious_tld(domain)
            defanged = defang_url(url)

            # Determine URL severity
            url_severity = "LOW"
            url_metadata: dict = {
                "domain": domain,
                "is_url_shortener": is_shortener,
                "has_suspicious_tld": has_suspicious_tld,
            }

            domain_analysis: DomainAnalysis | None = None
            if domain:
                domain_analysis = self.analyze_domain(domain)
                url_metadata["domain_analysis"] = {
                    "is_lookalike": domain_analysis.is_lookalike,
                    "lookalike_target": domain_analysis.lookalike_target,
                    "risk_score": domain_analysis.risk_score,
                    "severity": domain_analysis.severity,
                }

                if domain_analysis.severity == "CRITICAL" or is_shortener:
                    url_severity = "HIGH"
                elif domain_analysis.severity in ("HIGH", "MEDIUM") or has_suspicious_tld:
                    url_severity = "MEDIUM"

            iocs.append(ExtractedIOC(
                ioc_type=IOC_TYPES.URL,
                ioc_value=url,
                defanged_value=defanged,
                severity=url_severity,
                context=context,
                is_lookalike=domain_analysis.is_lookalike if domain_analysis else False,
                lookalike_target=domain_analysis.lookalike_target if domain_analysis else None,
                is_shortened_url=is_shortener,
                metadata=url_metadata,
            ))

            # Add domain as separate IOC
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                da = domain_analysis or self.analyze_domain(domain)
                iocs.append(ExtractedIOC(
                    ioc_type=IOC_TYPES.DOMAIN,
                    ioc_value=domain,
                    defanged_value=domain.replace(".", "[.]"),
                    severity=da.severity,
                    context=f"Extracted from URL found in {context}",
                    is_lookalike=da.is_lookalike,
                    lookalike_target=da.lookalike_target,
                    is_shortened_url=da.is_url_shortener,
                    metadata={
                        "risk_score": da.risk_score,
                        "risk_factors": da.risk_factors,
                        "has_suspicious_tld": da.has_suspicious_tld,
                        "has_homoglyphs": da.has_homoglyphs,
                    },
                ))

        # Also add From domain, Reply-To domains, Return-Path domain as DOMAIN IOCs
        for domain_str, ctx in self._sender_domains(parsed_email):
            if domain_str and domain_str not in seen_domains:
                seen_domains.add(domain_str)
                da = self.analyze_domain(domain_str)
                iocs.append(ExtractedIOC(
                    ioc_type=IOC_TYPES.DOMAIN,
                    ioc_value=domain_str,
                    defanged_value=domain_str.replace(".", "[.]"),
                    severity=da.severity,
                    context=ctx,
                    is_lookalike=da.is_lookalike,
                    lookalike_target=da.lookalike_target,
                    metadata={
                        "risk_score": da.risk_score,
                        "risk_factors": da.risk_factors,
                    },
                ))

        return iocs

    # ------------------------------------------------------------------
    # Email address extraction
    # ------------------------------------------------------------------

    def extract_email_addresses(
        self,
        parsed_email: "ParsedEmailData",
    ) -> list[ExtractedIOC]:
        """
        Extract email addresses found in the body text (not just header fields).

        These may be drop-box addresses, impersonation targets, or exfiltration
        recipients embedded in malicious content.
        """
        iocs: list[ExtractedIOC] = []
        seen: set[str] = set()

        body = (parsed_email.body_text or "") + " " + (parsed_email.body_html or "")
        for addr in extract_emails_from_text(body):
            if addr in seen:
                continue
            seen.add(addr)
            domain = addr.split("@")[-1] if "@" in addr else ""
            da = self.analyze_domain(domain) if domain else None
            severity = da.severity if da and da.is_lookalike else "LOW"
            iocs.append(ExtractedIOC(
                ioc_type=IOC_TYPES.EMAIL,
                ioc_value=addr,
                defanged_value=addr.replace("@", "[@]"),
                severity=severity,
                context="Email body",
                is_lookalike=da.is_lookalike if da else False,
                lookalike_target=da.lookalike_target if da else None,
                metadata={"domain": domain},
            ))

        return iocs

    # ------------------------------------------------------------------
    # Attachment hash extraction
    # ------------------------------------------------------------------

    def extract_attachment_hashes(
        self,
        parsed_email: "ParsedEmailData",
    ) -> list[ExtractedIOC]:
        """
        Create a ``FILE_HASH`` IOC for each email attachment.

        Returns one IOC per attachment with SHA-256 as the primary value
        and MD5 stored in metadata (for legacy TI feed correlation).
        """
        iocs: list[ExtractedIOC] = []
        for att in parsed_email.attachments:
            # Decide severity based on content type
            severity = self._attachment_severity(att.content_type, att.filename)
            iocs.append(ExtractedIOC(
                ioc_type=IOC_TYPES.FILE_HASH,
                ioc_value=att.sha256,
                defanged_value=att.sha256,
                severity=severity,
                context=f"Email attachment: {att.filename}",
                metadata={
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size_bytes": att.size,
                    "sha256": att.sha256,
                    "md5": att.md5,
                },
            ))
            # Also add the MD5 as a separate IOC for legacy TI lookup
            iocs.append(ExtractedIOC(
                ioc_type=IOC_TYPES.FILE_HASH,
                ioc_value=att.md5,
                defanged_value=att.md5,
                severity=severity,
                context=f"Email attachment (MD5): {att.filename}",
                metadata={
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size_bytes": att.size,
                    "sha256": att.sha256,
                    "md5": att.md5,
                    "hash_algorithm": "MD5",
                },
            ))
        return iocs

    # ------------------------------------------------------------------
    # Domain analysis
    # ------------------------------------------------------------------

    def analyze_domain(self, domain: str) -> DomainAnalysis:
        """
        Analyse a domain for threat signals.

        Checks performed:
        1. Lookalike / typosquat detection via Levenshtein distance.
        2. Suspicious TLD membership.
        3. Homoglyph substitution.
        4. URL shortener membership.

        Returns:
            A ``DomainAnalysis`` with a risk score and severity classification.
        """
        domain = domain.lower().strip()
        da = DomainAnalysis(domain=domain)

        # URL shortener check (fast set lookup)
        da.is_url_shortener = domain in URL_SHORTENERS
        if da.is_url_shortener:
            da.risk_factors.append(f"'{domain}' is a known URL shortener service")
            da.risk_score += 20

        # Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                da.has_suspicious_tld = True
                da.risk_factors.append(f"Domain uses suspicious TLD '{tld}'")
                da.risk_score += 15
                break

        # Lookalike / homoglyph analysis via lookalike utility
        score_data = get_suspicious_domain_score(domain, WELL_KNOWN_BRANDS)
        da.is_lookalike = score_data["is_lookalike"]
        da.lookalike_target = score_data["lookalike_target"]
        da.has_homoglyphs = score_data["has_homoglyphs"]
        da.risk_score += score_data["risk_score"]
        da.risk_factors.extend(score_data["risk_factors"])

        da.risk_score = min(da.risk_score, 100)

        # Map risk score to severity
        if da.risk_score >= 80:
            da.severity = "CRITICAL"
        elif da.risk_score >= 60:
            da.severity = "HIGH"
        elif da.risk_score >= 40:
            da.severity = "MEDIUM"
        elif da.risk_score >= 20:
            da.severity = "LOW"
        else:
            da.severity = "LOW"

        return da

    # ------------------------------------------------------------------
    # IP severity classification
    # ------------------------------------------------------------------

    def classify_ip_severity(self, ip: str, context: str) -> str:
        """
        Assign a severity level to an extracted IP address.

        Logic:
        - Private / loopback IPs → "LOW" (internal noise).
        - Public IPs in relay chain → "MEDIUM" (infrastructure IOC).
        - Public IPs in body text → "MEDIUM" (may be C2 or exfil destination).
        - Everything else → "LOW".
        """
        if is_private_ip(ip):
            return "LOW"
        if "relay" in context.lower() or "received" in context.lower():
            return "MEDIUM"
        if "body" in context.lower():
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def deduplicate_iocs(self, iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
        """
        Remove duplicate IOCs by (ioc_type, ioc_value).

        When duplicates exist, we keep the one with the higher severity
        and merge context strings.
        """
        seen: dict[tuple[str, str], ExtractedIOC] = {}
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for ioc in iocs:
            key = (ioc.ioc_type, ioc.ioc_value.lower())
            if key not in seen:
                seen[key] = ioc
            else:
                existing = seen[key]
                # Keep higher severity
                if severity_order.get(ioc.severity, 0) > severity_order.get(existing.severity, 0):
                    seen[key] = ioc
                # Merge context
                if ioc.context and ioc.context not in existing.context:
                    seen[key].context = f"{existing.context}; {ioc.context}"

        return list(seen.values())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_url_shortener(self, domain: str) -> bool:
        """Return True if *domain* is a known URL shortener."""
        return domain.lower() in URL_SHORTENERS

    def _has_suspicious_tld(self, domain: str) -> bool:
        """Return True if *domain* ends with a suspicious TLD."""
        d = domain.lower()
        return any(d.endswith(tld) for tld in SUSPICIOUS_TLDS)

    def _sender_domains(self, parsed_email: "ParsedEmailData") -> list[tuple[str, str]]:
        """Return (domain, context) tuples for sender-related domains."""
        result: list[tuple[str, str]] = []
        if parsed_email.from_domain:
            result.append((parsed_email.from_domain, "From header domain"))
        for rt in parsed_email.reply_to:
            rt_domain = rt.split("@")[-1] if "@" in rt else ""
            if rt_domain:
                result.append((rt_domain, "Reply-To header domain"))
        rp = parsed_email.return_path
        if rp and "@" in rp:
            rp_domain = rp.split("@")[-1].strip("<> ")
            if rp_domain:
                result.append((rp_domain, "Return-Path domain"))
        return result

    def _attachment_severity(self, content_type: str, filename: str) -> str:
        """
        Assign severity to an attachment based on its content type and filename.

        High-risk types (executable, macro-enabled documents, scripts):
        → HIGH

        Medium-risk types (PDFs, archives that could contain malware):
        → MEDIUM

        Others → LOW
        """
        HIGH_RISK_TYPES = {
            "application/x-msdownload",
            "application/x-dosexec",
            "application/x-executable",
            "application/x-bat",
            "application/vnd.ms-excel.addin.macroEnabled.12",
            "application/vnd.ms-word.document.macroEnabled.12",
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            "text/x-python", "text/x-perl", "text/x-sh",
            "application/x-msdos-program",
        }
        HIGH_RISK_EXTENSIONS = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".hta", ".msi", ".com", ".scr", ".pif",
            ".xlsm", ".docm", ".pptm", ".xlam",
        }
        MEDIUM_RISK_TYPES = {
            "application/pdf",
            "application/zip",
            "application/x-rar-compressed",
            "application/x-7z-compressed",
            "application/gzip",
        }

        ct = content_type.lower()
        fn = filename.lower()
        ext = "." + fn.rsplit(".", 1)[-1] if "." in fn else ""

        if ct in HIGH_RISK_TYPES or ext in HIGH_RISK_EXTENSIONS:
            return "HIGH"
        if ct in MEDIUM_RISK_TYPES or ext in {".pdf", ".zip", ".rar", ".7z", ".gz"}:
            return "MEDIUM"
        return "LOW"
