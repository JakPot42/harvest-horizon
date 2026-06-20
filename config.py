"""config.py — Harvest Horizon configuration and regulatory parameters.

Every regulatory citation, threshold, and timeline lives here.
The assessment engine (assessment_engine.py) imports values; it never defines its own.

⚠ VERIFICATION NOTICE ⚠
FIPS 203, FIPS 204, and FIPS 205 finalization (August 2024) are high-confidence —
well-documented NIST publications. All other regulatory parameters (OMB memo numbers,
specific migration deadline years, CNSA 2.0 transition dates) are marked VERIFY and
must be confirmed against current official sources before any operational use.
This tool is a portfolio/planning aid, not compliance legal counsel.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# App identity
# ---------------------------------------------------------------------------
APP_TITLE = "Harvest Horizon"
APP_SUBTITLE = "Post-Quantum Cryptographic Migration Assessor"
DEMO_MODE = os.getenv("DEMO_MODE", "True").lower() in ("1", "true", "yes")
DEMO_BANNER = (
    "DEMO MODE — All organizations and cryptographic inventories are fictional. "
    "This is a portfolio demonstration, not compliance or legal advice."
)
SCOPE_NOTICE = (
    "This tool does NOT implement cryptography, does NOT break or analyze any real "
    "cryptosystem, and does NOT perform cryptanalysis. It is a compliance-inventory "
    "and migration-planning ASSESSMENT tool only."
)
VERIFICATION_DISCLAIMER = (
    "FIPS 203/204/205 finalization (August 2024) is verified. OMB memo numbers, "
    "specific migration deadlines, and CNSA 2.0 transition dates are flagged VERIFY — "
    "confirm against current official sources before operational use."
)

# ---------------------------------------------------------------------------
# API / model
# ---------------------------------------------------------------------------
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-haiku-4-5-20251001"
CLAUDE_MAX_TOKENS = 2000
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./harvest_horizon.db")

# ---------------------------------------------------------------------------
# Data sensitivity levels — used in HNDL exposure scoring
# ---------------------------------------------------------------------------
DATA_SENSITIVITY_LEVELS = {
    "PUBLIC": "Public — no sensitivity restriction",
    "INTERNAL": "Internal — business-sensitive, not legally restricted",
    "CONFIDENTIAL": "Confidential — legally protected (PII, PHI, CUI, proprietary)",
    "SECRET": "Secret/Classified — highest long-term secrecy requirement",
}

# ---------------------------------------------------------------------------
# HNDL scoring thresholds
# ---------------------------------------------------------------------------
HNDL_TIER_CRITICAL = 75
HNDL_TIER_HIGH = 50
HNDL_TIER_MEDIUM = 25

# Algorithm vulnerability scores used in HNDL calculation
HNDL_SCORE_CRITICAL_ALGORITHM = 20   # per CRITICAL vulnerability item
HNDL_SCORE_REDUCED_ALGORITHM = 5     # per REDUCED_SECURITY item
HNDL_ALGORITHM_CAP = 60              # max score from algorithm component

# Data sensitivity scores
HNDL_SENSITIVITY_SCORES = {
    "PUBLIC": 2,
    "INTERNAL": 8,
    "CONFIDENTIAL": 14,
    "SECRET": 20,
}

# ---------------------------------------------------------------------------
# Quantum timeline — explicitly uncertain, flagged as unverified
#
# ⚠ VERIFY: Cryptographically-Relevant Quantum Computer (CRQC) timeline
# estimates range widely in published literature (approximately 10–30 years
# as of 2024). No authoritative consensus exists. This tool presents a range
# rather than a specific year. Never hardcode a specific CRQC arrival year.
# ---------------------------------------------------------------------------
QUANTUM_TIMELINE_NOTE = (
    "CRQC timeline is disputed in published literature — estimates range from "
    "approximately 10 to 30 years as of 2024. No authoritative consensus exists. "
    "Data secrecy requirements that extend into this window carry harvest-now risk."
)
QUANTUM_TIMELINE_RANGE_LOW_YEARS = 10   # VERIFY: conservative estimate
QUANTUM_TIMELINE_RANGE_HIGH_YEARS = 30  # VERIFY: optimistic estimate

# ---------------------------------------------------------------------------
# NIST PQC standards — HIGH CONFIDENCE (finalized August 2024)
# ---------------------------------------------------------------------------
FIPS_203_NAME = "FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)"
FIPS_204_NAME = "FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm)"
FIPS_205_NAME = "FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)"
FIPS_FINALIZATION_DATE = "August 2024"

# ---------------------------------------------------------------------------
# NSA CNSA 2.0 — National Security Algorithm Suite 2.0
#
# ⚠ VERIFY: CNSA 2.0 was published by NSA in approximately 2022. Specific
# transition deadline years for different algorithm types vary by system
# category. Confirm current NSA guidance before citing specific years.
# ---------------------------------------------------------------------------
CNSA_20_NOTE = (
    "NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) — published "
    "approximately 2022. Specifies PQC algorithm requirements for National Security "
    "Systems (NSS). ⚠ VERIFY specific transition deadlines before citing to stakeholders."
)

# ---------------------------------------------------------------------------
# OMB Memoranda — ⚠ VERIFY before citing
#
# Federal agency cryptographic inventory requirements stem from OMB memoranda
# and related executive directives. Specific memo numbers and binding deadline
# dates must be verified against current OMB guidance — they were not independently
# confirmed during development of this tool.
# ---------------------------------------------------------------------------
OMB_PQC_MEMO_NOTE = (
    "⚠ VERIFY: OMB memo numbers and specific binding migration deadlines for federal "
    "agency PQC inventories must be confirmed against current OMB guidance before citing."
)

# ---------------------------------------------------------------------------
# Compliance status labels
# ---------------------------------------------------------------------------
COMPLIANCE_STATUSES = {
    "PQC_APPROVED": "PQC Approved",
    "QUANTUM_SAFE": "Quantum Safe",
    "REDUCED_SECURITY": "Reduced Security",
    "NON_COMPLIANT": "Non-Compliant (Quantum Vulnerable)",
    "DEPRECATED": "Deprecated",
    "UNKNOWN": "Unknown",
}

# Quantum vulnerability levels
VULNERABILITY_LEVELS = {
    "CRITICAL": "Critical — directly broken by Shor's algorithm",
    "HIGH": "High — significantly weakened by Grover's algorithm",
    "REDUCED": "Reduced — moderate weakening by Grover's algorithm",
    "NONE": "None — quantum-resistant",
    "DEPRECATED": "Deprecated — already removed from use",
    "UNKNOWN": "Unknown",
}
