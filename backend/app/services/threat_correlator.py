"""
threat_correlator.py
====================
Correlates IOCs across all TraceVault cases to detect phishing campaigns.

Strategy:
  - Build an IOC → cases mapping from the database.
  - Weight shared IOCs by type (file hashes > IPs > domains > URLs > emails).
  - Normalise to a similarity score in [0, 1].
  - Cases with similarity > 0.3 are considered related.
  - If ≥1 related case exists, assign or create a Campaign record.
  - Expose a Cytoscape.js-compatible threat graph for the frontend.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CaseCampaign
from app.models.ioc import IOC


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CorrelationResult:
    """Result of IOC-based case correlation."""
    related_cases: dict            # {case_id: {"shared_iocs": [...], "similarity_score": float}}
    campaign_id: Optional[str]
    is_part_of_campaign: bool


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ThreatCorrelatorService:
    """
    Correlates new IOCs against the existing database to detect campaign
    membership and related cases.

    Usage::

        correlator = ThreatCorrelatorService()
        result = await correlator.correlate_case(db, case_id, new_iocs)
        graph   = await correlator.build_threat_graph(db)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def correlate_case(
        self,
        db: AsyncSession,
        case_id: str,
        new_iocs: list,
    ) -> CorrelationResult:
        """
        Find cases related to *case_id* via shared IOCs, then assign or
        create a Campaign if significant overlap exists (score > 0.3).

        Similarity score
        ----------------
        Each shared IOC contributes its type weight (see _get_ioc_weight).
        The total is normalised by the number of new IOCs, capped at 1.0.
        """
        # Fetch all IOCs belonging to other cases.
        stmt = select(IOC).where(IOC.case_id != case_id)
        existing_iocs = (await db.execute(stmt)).scalars().all()

        # Build IOC key → set of case_ids mapping.
        ioc_to_cases: dict[str, set[str]] = {}
        for ioc in existing_iocs:
            key = f"{ioc.ioc_type}:{ioc.ioc_value.lower()}"
            ioc_to_cases.setdefault(key, set()).add(ioc.case_id)

        # Find cases sharing at least one IOC with the new case.
        related_cases: dict[str, dict] = {}
        for new_ioc in new_iocs:
            key = f"{getattr(new_ioc, 'ioc_type', '')}:{str(getattr(new_ioc, 'ioc_value', '')).lower()}"
            if key in ioc_to_cases:
                for related_case_id in ioc_to_cases[key]:
                    entry = related_cases.setdefault(
                        related_case_id, {"shared_iocs": [], "similarity_score": 0.0}
                    )
                    entry["shared_iocs"].append(
                        {
                            "type": getattr(new_ioc, "ioc_type", ""),
                            "value": getattr(new_ioc, "ioc_value", ""),
                            "weight": self._get_ioc_weight(
                                getattr(new_ioc, "ioc_type", "")
                            ),
                        }
                    )

        # Compute normalised similarity scores.
        n_new = max(len(new_iocs), 1)
        for data in related_cases.values():
            total_weight = sum(ioc["weight"] for ioc in data["shared_iocs"])
            data["similarity_score"] = min(total_weight / n_new, 1.0)

        # Keep only significant relationships.
        significant = {
            k: v
            for k, v in related_cases.items()
            if v["similarity_score"] > 0.3
        }

        # Assign or create a campaign for this cluster of related cases.
        campaign_id: Optional[str] = None
        if significant:
            campaign_id = await self._assign_or_create_campaign(
                db, case_id, significant
            )

        return CorrelationResult(
            related_cases=significant,
            campaign_id=campaign_id,
            is_part_of_campaign=campaign_id is not None,
        )

    async def build_threat_graph(self, db: AsyncSession) -> dict:
        """
        Build a Cytoscape.js-compatible graph of all IOC relationships.

        Nodes:
          - Case nodes  (type="case")
          - IOC nodes   (type=ioc_type.lower())

        Edges:
          - Case → IOC  (membership)
          - Case → Case (shared_ioc, when an IOC appears in multiple cases)

        Returns
        -------
        {"nodes": [...], "edges": [...]}  — ready for Cytoscape.js
        """
        stmt = select(IOC)
        all_iocs = (await db.execute(stmt)).scalars().all()

        nodes: list[dict] = []
        edges: list[dict] = []
        seen_nodes: set[str] = set()

        # Case nodes
        case_ids = list({ioc.case_id for ioc in all_iocs})
        for cid in case_ids:
            node_id = f"case_{cid}"
            if node_id not in seen_nodes:
                nodes.append(
                    {"data": {"id": node_id, "label": cid, "type": "case", "size": 30}}
                )
                seen_nodes.add(node_id)

        # IOC nodes + case→IOC edges
        ioc_to_cases: dict[str, list[str]] = {}
        for ioc in all_iocs:
            safe_value = (
                ioc.ioc_value[:30]
                .replace(".", "_")
                .replace("/", "_")
                .replace(":", "_")
            )
            node_id = f"{ioc.ioc_type}_{safe_value}"

            if node_id not in seen_nodes:
                nodes.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": ioc.ioc_value[:40],
                            "type": ioc.ioc_type.lower(),
                            "severity": ioc.severity,
                            "size": 20,
                        }
                    }
                )
                seen_nodes.add(node_id)

            edges.append(
                {
                    "data": {
                        "source": f"case_{ioc.case_id}",
                        "target": node_id,
                        "label": ioc.ioc_type,
                    }
                }
            )

            ioc_to_cases.setdefault(node_id, []).append(ioc.case_id)

        # Case↔Case edges for shared IOCs
        for node_id, case_list in ioc_to_cases.items():
            if len(case_list) > 1:
                for i in range(len(case_list)):
                    for j in range(i + 1, len(case_list)):
                        edges.append(
                            {
                                "data": {
                                    "source": f"case_{case_list[i]}",
                                    "target": f"case_{case_list[j]}",
                                    "label": "shared_ioc",
                                    "weight": 5,
                                }
                            }
                        )

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ioc_weight(ioc_type: str) -> float:
        """
        Weight each IOC type by how reliably it identifies a specific actor.
        File hashes and IPs are the most reliable; generic string matches less so.
        """
        weights = {
            "FILE_HASH": 0.95,
            "ATTACHMENT": 0.90,
            "IP": 0.90,
            "DOMAIN": 0.85,
            "URL": 0.80,
            "EMAIL": 0.70,
        }
        return weights.get(ioc_type.upper(), 0.50)

    async def _assign_or_create_campaign(
        self,
        db: AsyncSession,
        case_id: str,
        related: dict,
    ) -> str:
        """
        Look for an existing Campaign that already includes one of the related
        cases. If found, link the current case to it; otherwise create a new
        Campaign record.
        """
        related_case_ids = list(related.keys())

        # Check whether any related case already belongs to a campaign.
        stmt = select(CaseCampaign).where(
            CaseCampaign.case_id.in_(related_case_ids)
        )
        existing_links = (await db.execute(stmt)).scalars().all()

        if existing_links:
            campaign_id = existing_links[0].campaign_id
        else:
            # Create a new campaign with a deterministic, human-readable ID.
            date_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
            hash_tag = hashlib.md5(case_id.encode()).hexdigest()[:6].upper()
            campaign_id = f"CAMP-{date_tag}-{hash_tag}"

            all_shared_iocs: list[dict] = []
            for data in related.values():
                all_shared_iocs.extend(data["shared_iocs"])

            campaign = Campaign(
                id=uuid.uuid4(),
                campaign_id=campaign_id,
                name=f"Campaign {campaign_id}",
                case_count=len(related_case_ids) + 1,
                shared_indicators={"iocs": all_shared_iocs[:20]},
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(campaign)

        # Link the current case to the campaign.
        current_link = CaseCampaign(
            case_id=case_id,
            campaign_id=campaign_id,
            similarity_score=max(
                v["similarity_score"] for v in related.values()
            ),
            shared_ioc_count=sum(
                len(v["shared_iocs"]) for v in related.values()
            ),
        )
        db.add(current_link)

        # Link any related cases not already linked.
        linked_case_ids = {lnk.case_id for lnk in existing_links}
        for rel_case_id in related_case_ids:
            if rel_case_id not in linked_case_ids:
                link = CaseCampaign(
                    case_id=rel_case_id,
                    campaign_id=campaign_id,
                    similarity_score=related[rel_case_id]["similarity_score"],
                    shared_ioc_count=len(related[rel_case_id]["shared_iocs"]),
                )
                db.add(link)

        await db.commit()
        return campaign_id
