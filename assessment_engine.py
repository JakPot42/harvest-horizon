"""assessment_engine.py — Deterministic algorithm classification engine.

This engine checks each algorithm against the crypto_catalog and assigns:
  - quantum_vulnerability: CRITICAL | REDUCED | NONE | DEPRECATED | UNKNOWN
  - compliance_status: PQC_APPROVED | QUANTUM_SAFE | REDUCED_SECURITY | NON_COMPLIANT | DEPRECATED | UNKNOWN
  - pqc_replacements: list of algorithms to migrate to
  - fips_citation: NIST standard governing this algorithm

Claude NEVER makes a compliance determination. The catalog is authoritative;
Claude only extracts the raw algorithm names from prose descriptions.
"""

from __future__ import annotations

from crypto_catalog import lookup, normalize_algorithm
from models import Assessment, CryptoItem


class EngineError(Exception):
    pass


def classify_algorithm(raw_algorithm: str) -> dict:
    """Return classification dict for a raw algorithm name."""
    entry = lookup(raw_algorithm)
    if entry is None:
        return {
            "algorithm_key": normalize_algorithm(raw_algorithm),
            "quantum_vulnerability": "UNKNOWN",
            "compliance_status": "UNKNOWN",
            "pqc_replacements": "",
            "fips_citation": "Unknown — not found in NIST PQC catalog",
            "engine_rationale": "Algorithm not recognized. Manual review required.",
        }
    return {
        "algorithm_key": normalize_algorithm(raw_algorithm),
        "quantum_vulnerability": entry["quantum_vulnerability"],
        "compliance_status": entry["compliance_status"],
        "pqc_replacements": ", ".join(entry.get("pqc_replacements", [])),
        "fips_citation": entry.get("fips_citation", ""),
        "engine_rationale": entry.get("rationale", ""),
    }


def assess_items(assessment: Assessment, proposed_items: list[dict]) -> list[CryptoItem]:
    """Create CryptoItem records from proposed extraction, running deterministic classification.

    proposed_items: list of dicts with keys: component, algorithm, use_case, key_size
    Returns: list of CryptoItem instances (not yet committed to DB)
    """
    items = []
    for raw in proposed_items:
        classification = classify_algorithm(raw.get("algorithm", ""))
        item = CryptoItem(
            assessment_id=assessment.id,
            component=raw.get("component", "Unknown"),
            algorithm=raw.get("algorithm", ""),
            algorithm_key=classification["algorithm_key"],
            use_case=raw.get("use_case", ""),
            key_size=str(raw.get("key_size", "")) if raw.get("key_size") else "",
            quantum_vulnerability=classification["quantum_vulnerability"],
            compliance_status=classification["compliance_status"],
            pqc_replacements=classification["pqc_replacements"],
            fips_citation=classification["fips_citation"],
            engine_rationale=classification["engine_rationale"],
        )
        items.append(item)
    return items


def compliance_summary(items: list[CryptoItem]) -> dict:
    """Compute compliance summary counts from a list of assessed items."""
    counts = {
        "total": len(items),
        "pqc_approved": 0,
        "quantum_safe": 0,
        "reduced_security": 0,
        "non_compliant": 0,
        "deprecated": 0,
        "unknown": 0,
        "critical_vulnerabilities": 0,
    }
    for item in items:
        status = item.compliance_status
        if status == "PQC_APPROVED":
            counts["pqc_approved"] += 1
        elif status == "QUANTUM_SAFE":
            counts["quantum_safe"] += 1
        elif status == "REDUCED_SECURITY":
            counts["reduced_security"] += 1
        elif status == "NON_COMPLIANT":
            counts["non_compliant"] += 1
        elif status == "DEPRECATED":
            counts["deprecated"] += 1
        else:
            counts["unknown"] += 1

        if item.quantum_vulnerability == "CRITICAL":
            counts["critical_vulnerabilities"] += 1

    return counts
