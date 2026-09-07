"""Initial schema – create all TraceVault tables.

Revision ID: 001
Revises:
Create Date: 2024-09-15 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enums ─────────────────────────────────────────────────────────────────
    user_role_enum = postgresql.ENUM(
        "admin", "analyst", "viewer", name="user_role_enum", create_type=False
    )
    user_role_enum.create(op.get_bind(), checkfirst=True)

    case_status_enum = postgresql.ENUM(
        "PENDING", "ANALYZING", "COMPLETED", "FAILED",
        name="case_status_enum", create_type=False
    )
    case_status_enum.create(op.get_bind(), checkfirst=True)

    case_severity_enum = postgresql.ENUM(
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN",
        name="case_severity_enum", create_type=False
    )
    case_severity_enum.create(op.get_bind(), checkfirst=True)

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(320), unique=True, nullable=False),
        sa.Column("username", sa.String(64), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("full_name", sa.String(256), nullable=False, server_default=""),
        sa.Column(
            "role",
            sa.Enum("admin", "analyst", "viewer", name="user_role_enum"),
            nullable=False,
            server_default="analyst",
        ),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email_active", "users", ["email", "is_active"])
    op.create_index("ix_users_role", "users", ["role"])

    # ── cases ─────────────────────────────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.String(30), unique=True, nullable=False),
        sa.Column(
            "status",
            sa.Enum("PENDING", "ANALYZING", "COMPLETED", "FAILED", name="case_status_enum"),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("evidence_hash3", sa.String(64), nullable=False),
        sa.Column("raw_email_path", sa.String(512), nullable=False),
        sa.Column("file_size_bytes", sa.Integer, nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("threat_score", sa.Integer, nullable=True),
        sa.Column(
            "severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN", name="case_severity_enum"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_cases_case_id", "cases", ["case_id"])
    op.create_index("ix_cases_status", "cases", ["status"])
    op.create_index("ix_cases_severity", "cases", ["severity"])
    op.create_index("ix_cases_created_at", "cases", ["created_at"])
    op.create_index("ix_cases_threat_score", "cases", ["threat_score"])
    op.create_index("ix_cases_created_by", "cases", ["created_by"])

    # ── email_headers ─────────────────────────────────────────────────────────
    op.create_table(
        "email_headers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_addr", sa.Text, nullable=True),
        sa.Column("from_name", sa.Text, nullable=True),
        sa.Column("from_domain", sa.Text, nullable=True),
        sa.Column("reply_to", sa.Text, nullable=True),
        sa.Column("reply_to_domain", sa.Text, nullable=True),
        sa.Column("return_path", sa.Text, nullable=True),
        sa.Column("return_path_domain", sa.Text, nullable=True),
        sa.Column("message_id", sa.Text, nullable=True),
        sa.Column("subject", sa.Text, nullable=True),
        sa.Column("date_sent", sa.DateTime(timezone=True), nullable=True),
        sa.Column("x_originating_ip", sa.Text, nullable=True),
        sa.Column("x_mailer", sa.Text, nullable=True),
        sa.Column("content_type", sa.Text, nullable=True),
        sa.Column("raw_headers", postgresql.JSONB, nullable=True),
        sa.Column("rfc_violations", postgresql.JSONB, nullable=True),
        sa.Column("spoofing_indicators", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_email_headers_case_id", "email_headers", ["case_id"])

    # ── relay_hops ────────────────────────────────────────────────────────────
    op.create_table(
        "relay_hops",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hop_index", sa.Integer, nullable=False, server_default="0"),
        sa.Column("by_server", sa.Text, nullable=True),
        sa.Column("from_server", sa.Text, nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_public_ip", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("is_suspicious", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("raw_header", sa.Text, nullable=True),
    )
    op.create_index("ix_relay_hops_case_id", "relay_hops", ["case_id"])
    op.create_index("ix_relay_hops_case_hop", "relay_hops", ["case_id", "hop_index"])

    # ── auth_results ──────────────────────────────────────────────────────────
    op.create_table(
        "auth_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("spf_result", sa.String(20), nullable=True),
        sa.Column("spf_domain", sa.Text, nullable=True),
        sa.Column("spf_explanation", sa.Text, nullable=True),
        sa.Column("dkim_result", sa.String(20), nullable=True),
        sa.Column("dkim_domain", sa.Text, nullable=True),
        sa.Column("dkim_selector", sa.Text, nullable=True),
        sa.Column("dmarc_result", sa.String(20), nullable=True),
        sa.Column("dmarc_policy", sa.String(20), nullable=True),
        sa.Column("dmarc_subdomain_policy", sa.String(20), nullable=True),
        sa.Column("overall_verdict", sa.String(20), nullable=True),
        sa.Column("spoofing_risk", sa.String(20), nullable=True),
        sa.Column("raw_auth_header", sa.Text, nullable=True),
    )
    op.create_index("ix_auth_results_case_id", "auth_results", ["case_id"])

    # ── analysis_results ──────────────────────────────────────────────────────
    op.create_table(
        "analysis_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("threat_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("threat_categories", postgresql.JSONB, nullable=True),
        sa.Column("rule_score", sa.Integer, nullable=True),
        sa.Column("ml_score", sa.Float, nullable=True),
        sa.Column("gemini_score", sa.Integer, nullable=True),
        sa.Column("ai_explanation", sa.Text, nullable=True),
        sa.Column("urgency_phrases", postgresql.JSONB, nullable=True),
        sa.Column("impersonation_details", postgresql.JSONB, nullable=True),
        sa.Column("social_engineering_patterns", postgresql.JSONB, nullable=True),
        sa.Column("shap_features", postgresql.JSONB, nullable=True),
        sa.Column("recommended_actions", postgresql.JSONB, nullable=True),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("analysis_duration_ms", sa.Integer, nullable=True),
    )
    op.create_index("ix_analysis_results_case_id", "analysis_results", ["case_id"])

    # ── iocs ──────────────────────────────────────────────────────────────────
    op.create_table(
        "iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ioc_type", sa.String(30), nullable=False),
        sa.Column("ioc_value", sa.Text, nullable=False),
        sa.Column("defanged_value", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("context", sa.Text, nullable=True),
        sa.Column("is_lookalike", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("lookalike_target", sa.Text, nullable=True),
        sa.Column("is_shortened_url", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("redirect_target", sa.Text, nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_iocs_case_id", "iocs", ["case_id"])
    op.create_index("ix_iocs_type", "iocs", ["ioc_type"])
    op.create_index("ix_iocs_severity", "iocs", ["severity"])
    op.create_index("ix_iocs_value", "iocs", ["ioc_value"])

    # ── geo_intelligence ──────────────────────────────────────────────────────
    op.create_table(
        "geo_intelligence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip_address", sa.Text, nullable=False),
        sa.Column("country", sa.Text, nullable=True),
        sa.Column("country_code", sa.String(2), nullable=True),
        sa.Column("city", sa.Text, nullable=True),
        sa.Column("region", sa.Text, nullable=True),
        sa.Column("latitude", sa.Float, nullable=True),
        sa.Column("longitude", sa.Float, nullable=True),
        sa.Column("isp", sa.Text, nullable=True),
        sa.Column("org", sa.Text, nullable=True),
        sa.Column("asn", sa.Text, nullable=True),
        sa.Column("hostname", sa.Text, nullable=True),
        sa.Column("is_vpn", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_tor", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_hosting", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_proxy", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("ptr_record", sa.Text, nullable=True),
        sa.Column("whois_data", postgresql.JSONB, nullable=True),
        sa.Column("dns_records", postgresql.JSONB, nullable=True),
        sa.Column("enrichment_source", sa.Text, nullable=True),
    )
    op.create_index("ix_geo_case_id", "geo_intelligence", ["case_id"])
    op.create_index("ix_geo_ip_address", "geo_intelligence", ["ip_address"])
    op.create_index("ix_geo_country_code", "geo_intelligence", ["country_code"])

    # ── blockchain_ledger ─────────────────────────────────────────────────────
    op.create_table(
        "blockchain_ledger",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("block_index", sa.Integer, unique=True, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("actor", sa.Text, nullable=False, server_default="system"),
        sa.Column("data", postgresql.JSONB, nullable=True),
        sa.Column("data_hash", sa.String(64), nullable=False),
        sa.Column("block_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("polygon_tx_hash", sa.Text, nullable=True),
        sa.Column("is_anchored", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_blockchain_block_index", "blockchain_ledger", ["block_index"])
    op.create_index("ix_blockchain_case_id", "blockchain_ledger", ["case_id"])
    op.create_index("ix_blockchain_action", "blockchain_ledger", ["action"])

    # ── campaigns ─────────────────────────────────────────────────────────────
    op.create_table(
        "campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("campaign_id", sa.String(30), unique=True, nullable=False),
        sa.Column("name", sa.Text, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("case_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("shared_indicators", postgresql.JSONB, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("threat_actor_hypothesis", sa.Text, nullable=True),
    )
    op.create_index("ix_campaigns_campaign_id", "campaigns", ["campaign_id"])
    op.create_index("ix_campaigns_first_seen", "campaigns", ["first_seen"])
    op.create_index("ix_campaigns_last_seen", "campaigns", ["last_seen"])

    # ── case_campaigns ────────────────────────────────────────────────────────
    op.create_table(
        "case_campaigns",
        sa.Column(
            "case_id",
            sa.String(30),
            sa.ForeignKey("cases.case_id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "campaign_id",
            sa.String(30),
            sa.ForeignKey("campaigns.campaign_id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("similarity_score", sa.Float, nullable=True),
        sa.Column("shared_ioc_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("ix_case_campaigns_case_id", "case_campaigns", ["case_id"])
    op.create_index("ix_case_campaigns_campaign_id", "case_campaigns", ["campaign_id"])


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_table("case_campaigns")
    op.drop_table("campaigns")
    op.drop_table("blockchain_ledger")
    op.drop_table("geo_intelligence")
    op.drop_table("iocs")
    op.drop_table("analysis_results")
    op.drop_table("auth_results")
    op.drop_table("relay_hops")
    op.drop_table("email_headers")
    op.drop_table("cases")
    op.drop_table("users")

    # Drop enums
    sa.Enum(name="case_severity_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="case_status_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="user_role_enum").drop(op.get_bind(), checkfirst=True)
