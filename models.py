"""models.py — SQLAlchemy ORM models for Harvest Horizon."""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_name: Mapped[str] = mapped_column(String(200))
    org_type: Mapped[str] = mapped_column(String(100), default="")
    org_description: Mapped[str] = mapped_column(Text, default="")
    data_sensitivity: Mapped[str] = mapped_column(String(50), default="INTERNAL")
    data_retention_years: Mapped[int] = mapped_column(Integer, default=5)

    # Raw crypto footprint description (user-supplied)
    footprint_description: Mapped[str] = mapped_column(Text, default="")

    # JSON string — proposed inventory extracted by Claude; awaits human confirm
    extracted_items_json: Mapped[str] = mapped_column(Text, default="")

    # Status: DRAFT → EXTRACTED → CONFIRMED → ASSESSED → ROADMAP_READY
    status: Mapped[str] = mapped_column(String(30), default="DRAFT")

    # HNDL exposure scoring (set by exposure_engine after confirmation)
    hndl_score: Mapped[int] = mapped_column(Integer, default=0)
    hndl_tier: Mapped[str] = mapped_column(String(20), default="")
    hndl_rationale: Mapped[str] = mapped_column(Text, default="")

    # Migration roadmap (Claude-drafted)
    roadmap_text: Mapped[str] = mapped_column(Text, default="")
    roadmap_generated_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    items: Mapped[list[CryptoItem]] = relationship(
        "CryptoItem", back_populates="assessment", cascade="all, delete-orphan"
    )

    # ---------------------------------------------------------------------------
    # Computed properties for templates
    # ---------------------------------------------------------------------------

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.items if i.quantum_vulnerability == "CRITICAL")

    @property
    def non_compliant_count(self) -> int:
        return sum(1 for i in self.items if i.compliance_status in ("NON_COMPLIANT", "DEPRECATED"))

    @property
    def pqc_approved_count(self) -> int:
        return sum(1 for i in self.items if i.compliance_status == "PQC_APPROVED")

    @property
    def quantum_safe_count(self) -> int:
        return sum(1 for i in self.items if i.compliance_status == "QUANTUM_SAFE")

    @property
    def reduced_count(self) -> int:
        return sum(1 for i in self.items if i.compliance_status == "REDUCED_SECURITY")

    @property
    def hndl_tier_color(self) -> str:
        return {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "amber",
            "LOW": "green",
        }.get(self.hndl_tier, "grey")

    @property
    def compliance_tier(self) -> str:
        if not self.items:
            return "UNASSESSED"
        nc = self.non_compliant_count
        total = len(self.items)
        if nc == 0:
            return "COMPLIANT"
        if nc / total >= 0.5:
            return "CRITICAL_GAP"
        if nc / total >= 0.25:
            return "NON_COMPLIANT"
        return "TRANSITIONAL"


class CryptoItem(Base):
    __tablename__ = "crypto_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(Integer, ForeignKey("assessments.id"))

    component: Mapped[str] = mapped_column(String(200))   # "TLS 1.2", "Code Signing", etc.
    algorithm: Mapped[str] = mapped_column(String(100))   # raw name as extracted
    algorithm_key: Mapped[str] = mapped_column(String(100))  # normalized catalog key
    use_case: Mapped[str] = mapped_column(String(100))    # Key Exchange, Signature, etc.
    key_size: Mapped[str] = mapped_column(String(20), default="")

    # Set by assessment_engine
    quantum_vulnerability: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    compliance_status: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    pqc_replacements: Mapped[str] = mapped_column(Text, default="")  # comma-separated
    fips_citation: Mapped[str] = mapped_column(String(200), default="")
    engine_rationale: Mapped[str] = mapped_column(Text, default="")

    assessment: Mapped[Assessment] = relationship("Assessment", back_populates="items")

    @property
    def vulnerability_color(self) -> str:
        return {
            "CRITICAL": "red",
            "REDUCED": "amber",
            "NONE": "green",
            "DEPRECATED": "purple",
        }.get(self.quantum_vulnerability, "grey")

    @property
    def compliance_color(self) -> str:
        return {
            "PQC_APPROVED": "green",
            "QUANTUM_SAFE": "green",
            "REDUCED_SECURITY": "amber",
            "NON_COMPLIANT": "red",
            "DEPRECATED": "purple",
            "UNKNOWN": "grey",
        }.get(self.compliance_status, "grey")

    @property
    def replacements_list(self) -> list[str]:
        if not self.pqc_replacements:
            return []
        return [r.strip() for r in self.pqc_replacements.split(",") if r.strip()]
