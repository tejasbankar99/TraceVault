"""
geo_intelligence.py
===================
IP Geolocation and Infrastructure Intelligence service for TraceVault.

Data sources (in order of priority):
  1. ipinfo.io        — best for ASN / org data
  2. ip-api.com       — free fallback geo enrichment
  3. ipwhois (RDAP)   — ARIN/RIPE structured whois
  4. dnspython        — reverse PTR lookup

Domain intelligence:
  - python-whois for registration data
  - dnspython for A / MX / NS / TXT records
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.reversename
import httpx
import whois
from ipwhois import IPWhois


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class IPIntelligenceResult:
    """Full intelligence profile for a single IP address."""
    ip: str
    is_private: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    hostname: Optional[str] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    is_proxy: bool = False
    ptr_record: Optional[str] = None
    whois_data: dict = field(default_factory=dict)
    enrichment_source: Optional[str] = None


@dataclass
class DomainIntelligenceResult:
    """WHOIS and DNS profile for a single domain."""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[object] = None
    expiration_date: Optional[object] = None
    registrant_country: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_newly_registered: bool = False
    dns_records: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC-1918 private or loopback."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class GeoIntelligenceService:
    """
    Provides enriched geolocation and infrastructure intelligence for IP
    addresses and domain names found in email headers and IOCs.

    Usage::

        service = GeoIntelligenceService()
        ip_result     = await service.analyze_ip("185.220.101.1")
        domain_result = await service.analyze_domain("paypa1.com")
    """

    def __init__(self) -> None:
        self.ipinfo_token: str = os.getenv("IPINFO_TOKEN", "")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_ip(self, ip: str) -> IPIntelligenceResult:
        """
        Gather full intelligence on a single IP address using four data
        sources with graceful fallback between them.

        Private/loopback addresses are returned early with is_private=True.
        """
        if not ip or is_private_ip(ip):
            return IPIntelligenceResult(ip=ip, is_private=True)

        result = IPIntelligenceResult(ip=ip)

        # Layer 1 — ipinfo.io (best org/ASN coverage)
        await self._enrich_from_ipinfo(ip, result)

        # Layer 2 — ip-api.com (free fallback when ipinfo returns nothing)
        if not result.country:
            await self._enrich_from_ipapi(ip, result)

        # Layer 3 — ipwhois RDAP (structured registry data)
        await self._enrich_from_ipwhois(ip, result)

        # Layer 4 — Reverse DNS PTR
        await self._get_reverse_dns(ip, result)

        # Classify infrastructure type from enriched org/ISP strings
        result.is_vpn = self._check_is_vpn(result)
        result.is_hosting = self._check_is_hosting(result)
        result.is_tor = self._check_is_tor(ip, result)

        return result

    async def analyze_domain(self, domain: str) -> DomainIntelligenceResult:
        """
        Gather WHOIS registration data and DNS records for a domain.
        Flags domains registered fewer than 30 days ago as newly registered.
        """
        result = DomainIntelligenceResult(domain=domain)

        # WHOIS
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            result.registrar = str(w.registrar) if w.registrar else None

            raw_creation = w.creation_date
            result.creation_date = (
                raw_creation[0] if isinstance(raw_creation, list) else raw_creation
            )

            raw_expiry = w.expiration_date
            result.expiration_date = (
                raw_expiry[0] if isinstance(raw_expiry, list) else raw_expiry
            )

            result.registrant_country = getattr(w, "country", None)

            # Flag recently-registered domains (< 30 days) as suspicious.
            if result.creation_date:
                from datetime import datetime, timezone

                creation = result.creation_date
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation).days
                result.domain_age_days = age_days
                result.is_newly_registered = age_days < 30
        except Exception:
            pass

        # DNS records — A, MX, NS, TXT
        result.dns_records = {}
        for record_type in ("A", "MX", "NS", "TXT"):
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, dns.resolver.resolve, domain, record_type
                )
                result.dns_records[record_type] = [str(r) for r in answers]
            except Exception:
                result.dns_records[record_type] = []

        return result

    # ------------------------------------------------------------------
    # Private enrichment helpers
    # ------------------------------------------------------------------

    async def _enrich_from_ipinfo(self, ip: str, result: IPIntelligenceResult) -> None:
        """Enrich result using ipinfo.io (best ASN/org coverage)."""
        headers: dict[str, str] = {}
        token = self.ipinfo_token
        if token and token not in ("", "your-ipinfo-token-from-ipinfo.io"):
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://ipinfo.io/{ip}/json", headers=headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result.country = data.get("country")
                    result.country_code = data.get("country")
                    result.city = data.get("city")
                    result.region = data.get("region")
                    if "loc" in data:
                        lat, lon = data["loc"].split(",")
                        result.latitude = float(lat)
                        result.longitude = float(lon)
                    org_field = data.get("org", "")
                    if " " in org_field:
                        result.asn, result.isp = org_field.split(" ", 1)
                    else:
                        result.isp = org_field
                    result.hostname = data.get("hostname")
                    result.enrichment_source = "ipinfo.io"
        except Exception:
            pass

    async def _enrich_from_ipapi(self, ip: str, result: IPIntelligenceResult) -> None:
        """Enrich result using ip-api.com free tier (no key required)."""
        try:
            fields = "country,countryCode,city,regionName,lat,lon,isp,org,as"
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}?fields={fields}"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result.country = data.get("country")
                    result.country_code = data.get("countryCode")
                    result.city = data.get("city")
                    result.region = data.get("regionName")
                    result.latitude = data.get("lat")
                    result.longitude = data.get("lon")
                    result.isp = data.get("isp")
                    result.org = data.get("org")
                    as_field = data.get("as", "")
                    result.asn = as_field.split(" ")[0] if as_field else None
                    result.enrichment_source = result.enrichment_source or "ip-api.com"
        except Exception:
            pass

    async def _enrich_from_ipwhois(self, ip: str, result: IPIntelligenceResult) -> None:
        """Enrich result using ipwhois RDAP for structured registry data."""
        try:
            loop = asyncio.get_event_loop()
            obj = IPWhois(ip)
            rdap_data = await loop.run_in_executor(None, obj.lookup_rdap)
            network = rdap_data.get("network", {}) or {}
            result.whois_data = {
                "network_name": network.get("name"),
                "network_country": network.get("country"),
                "asn_description": rdap_data.get("asn_description"),
                "asn_country": rdap_data.get("asn_country_code"),
                "entities": [
                    e.get("handle")
                    for e in (rdap_data.get("entities") or [])[:3]
                ],
            }
            if not result.asn and rdap_data.get("asn"):
                result.asn = f"AS{rdap_data['asn']}"
        except Exception:
            result.whois_data = {}

    async def _get_reverse_dns(self, ip: str, result: IPIntelligenceResult) -> None:
        """Perform a PTR (reverse DNS) lookup for the IP address."""
        try:
            loop = asyncio.get_event_loop()
            rev = dns.reversename.from_address(ip)
            answers = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(rev, "PTR")
            )
            result.ptr_record = str(answers[0])
        except Exception:
            result.ptr_record = None

    # ------------------------------------------------------------------
    # Infrastructure type classifiers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_is_vpn(result: IPIntelligenceResult) -> bool:
        """Heuristic VPN detection from org/ISP strings."""
        vpn_keywords = {
            "vpn", "nordvpn", "expressvpn", "surfshark", "mullvad",
            "protonvpn", "pia", "private internet access", "cyberghost",
            "hidemyass", "ipvanish", "windscribe", "tunnelbear",
        }
        combined = ((result.org or "") + " " + (result.isp or "")).lower()
        return any(kw in combined for kw in vpn_keywords)

    @staticmethod
    def _check_is_hosting(result: IPIntelligenceResult) -> bool:
        """Heuristic hosting/cloud provider detection from org/ISP strings."""
        hosting_keywords = {
            "amazon", "aws", "azure", "google cloud", "digitalocean",
            "linode", "vultr", "hetzner", "ovh", "cloudflare", "fastly",
            "akamai", "hostinger", "bluehost", "godaddy", "contabo",
            "rackspace", "leaseweb", "serverius",
        }
        combined = ((result.org or "") + " " + (result.isp or "")).lower()
        return any(kw in combined for kw in hosting_keywords)

    @staticmethod
    def _check_is_tor(ip: str, result: IPIntelligenceResult) -> bool:
        """Heuristic Tor exit-node detection from org/PTR record strings."""
        tor_keywords = {"tor", "onion", "exit node", "tor exit", "torproject"}
        combined = (
            (result.org or "") + " " + (result.ptr_record or "")
        ).lower()
        return any(kw in combined for kw in tor_keywords)
