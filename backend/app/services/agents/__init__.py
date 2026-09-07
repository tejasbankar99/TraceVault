"""
TraceVault Multi-Agent Intelligence Services.
Specialist forensic analysis agents powered by Google Gemini.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentResult:
    """Standardized output produced by each specialist forensic agent."""
    agent_name: str
    score: int                  # Threat score between 0 (clean) and 100 (critical)
    confidence: float           # Confidence level between 0.0 and 1.0
    findings: list[str] = field(default_factory=list)  # Key forensic observations


from app.services.agents.header_agent import HeaderAgent
from app.services.agents.ioc_agent import IocAgent

__all__ = ["AgentResult", "HeaderAgent", "IocAgent"]
