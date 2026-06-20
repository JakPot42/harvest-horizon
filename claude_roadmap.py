"""claude_roadmap.py — Claude drafts the PQC migration roadmap narrative.

Claude's role here: given the deterministic assessment results (algorithm inventory,
compliance gaps, HNDL exposure score), draft a structured migration roadmap that:
  - Cites specific FIPS 203/204/205 standards for each recommendation
  - Acknowledges the CRQC timeline uncertainty explicitly
  - Never makes compliance determinations (those come from the engine)
  - Flags OMB memo numbers and specific deadline years as requiring verification

Claude is the narrator and explainer. The engine is the decision-maker.

In DEMO_MODE, returns pre-baked roadmap text without calling the API.
"""

from __future__ import annotations

import anthropic

from config import (
    ANTHROPIC_API_KEY,
    CLAUDE_MAX_TOKENS,
    CLAUDE_MODEL,
    DEMO_MODE,
    FIPS_203_NAME,
    FIPS_204_NAME,
    FIPS_205_NAME,
    QUANTUM_TIMELINE_NOTE,
)


class RoadmapError(Exception):
    pass


_SYSTEM_PROMPT = f"""You are a post-quantum cryptographic migration advisor writing a structured
migration roadmap for an organization's compliance assessment report.

Context you must always apply:
- NIST finalized three PQC standards in August 2024:
  * {FIPS_203_NAME}
  * {FIPS_204_NAME}
  * {FIPS_205_NAME}
- {QUANTUM_TIMELINE_NOTE}
- NSA CNSA 2.0 specifies PQC requirements for National Security Systems (VERIFY specific deadlines).
- OMB memoranda direct federal agencies to conduct cryptographic inventories (VERIFY specific memo numbers and deadlines before citing).

Rules you must follow:
1. Every recommendation must cite the specific FIPS standard (FIPS 203, 204, or 205) that provides the replacement.
2. You draft the roadmap — you NEVER make the compliance determination. The compliance determination was already made by a separate deterministic engine; you explain and contextualize it.
3. Flag any specific migration deadline years or OMB memo numbers with "⚠ VERIFY:" — you cannot confirm these from your training data and they may change.
4. Acknowledge CRQC timeline uncertainty explicitly — do not predict a specific year.
5. Organize by priority: CRITICAL vulnerabilities → HIGH → MEDIUM.
6. Be specific and actionable, not generic. Cite the actual algorithms found.

Format:
## Executive Summary
(2-3 sentences on overall posture)

## Immediate Actions (CRITICAL priority)
(Specific steps for CRITICAL-tier vulnerabilities)

## Near-Term Actions (HIGH priority)
(Steps for HIGH-tier items)

## Strategic Actions (MEDIUM/LOW priority)
(Longer-horizon planning)

## Regulatory Mandate
(Cite FIPS 203/204/205, CNSA 2.0, OMB memos with VERIFY flags where needed)

## Monitoring and Reassessment
(Cadence for keeping this current)"""


def draft_migration_roadmap(
    org_name: str,
    hndl_tier: str,
    hndl_score: int,
    critical_algorithms: list[str],
    non_compliant_algorithms: list[str],
    reduced_algorithms: list[str],
    data_sensitivity: str,
    data_retention_years: int,
    demo_key: str | None = None,
) -> str:
    """Draft a migration roadmap narrative.

    In DEMO_MODE, returns pre-baked roadmap text.
    In live mode, calls Claude Haiku.
    """
    if DEMO_MODE and demo_key is not None:
        from seed_data import DEMO_ROADMAPS
        text = DEMO_ROADMAPS.get(demo_key, "")
        if text:
            return text

    if not ANTHROPIC_API_KEY:
        raise RoadmapError(
            "ANTHROPIC_API_KEY is not set. Set it or enable DEMO_MODE."
        )

    prompt = _build_prompt(
        org_name, hndl_tier, hndl_score,
        critical_algorithms, non_compliant_algorithms, reduced_algorithms,
        data_sensitivity, data_retention_years,
    )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except RoadmapError:
        raise
    except Exception as exc:
        raise RoadmapError(f"Claude API error during roadmap drafting: {exc}") from exc


def _build_prompt(
    org_name: str,
    hndl_tier: str,
    hndl_score: int,
    critical_algorithms: list[str],
    non_compliant_algorithms: list[str],
    reduced_algorithms: list[str],
    data_sensitivity: str,
    data_retention_years: int,
) -> str:
    return f"""Draft a PQC migration roadmap for the following assessment:

Organization: {org_name}
HNDL Exposure Tier: {hndl_tier} (score: {hndl_score}/100)
Data Sensitivity: {data_sensitivity}
Data Retention Requirement: {data_retention_years} years

Quantum-CRITICAL algorithms found (Shor-breakable, must migrate):
{chr(10).join(f"  - {a}" for a in critical_algorithms) or "  None"}

Non-compliant algorithms (same as above plus DEPRECATED):
{chr(10).join(f"  - {a}" for a in non_compliant_algorithms) or "  None"}

Reduced-security algorithms (Grover-weakened, upgrade recommended):
{chr(10).join(f"  - {a}" for a in reduced_algorithms) or "  None"}

Draft the migration roadmap following the format in your instructions.
Cite specific FIPS 203/204/205 replacements for each vulnerable algorithm.
Flag any OMB memo numbers or specific deadline years with ⚠ VERIFY:"""
