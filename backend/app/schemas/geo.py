"""
TraceVault - Geo Intelligence Pydantic Schema
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class GeoIntelligenceResponse(BaseModel):
    """Geo-IP enrichment record for a public IP found in a case."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    ip_address: str
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
    whois_data: Optional[Dict[str, Any]] = None
    dns_records: Optional[Dict[str, List[str]]] = None
    enrichment_source: Optional[str] = None
