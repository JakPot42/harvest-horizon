"""exposure_engine.py — Harvest-now, decrypt-later (HNDL) exposure scoring engine.

This engine computes a separate HNDL exposure score, which is DISTINCT from compliance status.

Compliance status answers: "Does this algorithm match what NIST/NSA mandates?"
HNDL exposure answers: "How much encrypted data at risk from quantum-capable adversaries
                        harvesting ciphertext today for future decryption?"

The exposure score reflects three factors:
  1. Algorithm vulnerability — how many CRITICAL (Shor-breakable) algorithms are present
  2. Data sensitivity — how sensitive is the data being protected
  3. Data retention — how long must the data remain secret vs. CRQC timeline

⚠ CRQC TIMELINE NOTE: Estimates for when a cryptographically-relevant quantum computer
(CRQC) will exist range from approximately 10 to 30 years (as of 2024 published literature).
No authoritative consensus exists. This scoring uses retention years as a proxy for
quantum-window overlap risk — data that must remain secret for 15+ years is most exposed.

Deterministic engine — no Claude calls. Claude only drafts the roadmap narrative.
"""

from __future__ import annotations

from config import (
    HNDL_ALGORITHM_CAP,
    HNDL_SCORE_CRITICAL_ALGORITHM,
    HNDL_SCORE_REDUCED_ALGORITHM,
    HNDL_SENSITIVITY_SCORES,
    HNDL_TIER_CRITICAL,
    HNDL_TIER_HIGH,
    HNDL_TIER_MEDIUM,
    QUANTUM_TIMELINE_NOTE,
)
from models import CryptoItem


def compute_hndl_score(
    items: list[CryptoItem],
    data_sensitivity: str,
    data_retention_years: int,
) -> dict:
    """Compute HNDL exposure score and tier.

    Returns dict with: score (0-100), tier, critical_count, reduced_count, rationale
    """
    if not items:
        return {
            "score": 0, "tier": "LOW", "critical_count": 0, "reduced_count": 0,
            "alg_score": 0, "sens_score": 0, "ret_score": 0,
            "rationale": "No algorithm inventory available — run assessment first.",
            "quantum_timeline_note": QUANTUM_TIMELINE_NOTE,
        }

    critical_count = sum(1 for i in items if i.quantum_vulnerability == "CRITICAL")
    reduced_count = sum(1 for i in items if i.quantum_vulnerability == "REDUCED")

    # Algorithm component: CRITICAL items drive harvest risk; REDUCED items add marginal risk
    alg_score = min(
        HNDL_ALGORITHM_CAP,
        critical_count * HNDL_SCORE_CRITICAL_ALGORITHM + reduced_count * HNDL_SCORE_REDUCED_ALGORITHM,
    )

    # Sensitivity component: how much does exposure matter?
    sens_score = HNDL_SENSITIVITY_SCORES.get(data_sensitivity, HNDL_SENSITIVITY_SCORES["INTERNAL"])

    # Retention component: how long does data need to stay secret?
    if data_retention_years < 2:
        ret_score = 3
        ret_label = f"{data_retention_years} year(s) — likely stale before CRQC arrives"
    elif data_retention_years < 5:
        ret_score = 8
        ret_label = f"{data_retention_years} years — moderate overlap with estimated CRQC window"
    elif data_retention_years < 15:
        ret_score = 14
        ret_label = f"{data_retention_years} years — significant overlap with estimated CRQC window"
    else:
        ret_score = 20
        ret_label = f"{data_retention_years} years — high overlap with estimated CRQC window"

    # If no critical algorithms, cap total at MEDIUM regardless of sensitivity/retention
    if critical_count == 0:
        total = min(HNDL_TIER_HIGH - 1, alg_score + (sens_score // 3) + (ret_score // 3))
    else:
        total = min(100, alg_score + sens_score + ret_score)

    tier = _tier(total)

    rationale = _build_rationale(
        critical_count, reduced_count, alg_score,
        data_sensitivity, sens_score,
        data_retention_years, ret_label, ret_score,
        total, tier,
    )

    return {
        "score": total,
        "tier": tier,
        "critical_count": critical_count,
        "reduced_count": reduced_count,
        "alg_score": alg_score,
        "sens_score": sens_score,
        "ret_score": ret_score,
        "rationale": rationale,
        "quantum_timeline_note": QUANTUM_TIMELINE_NOTE,
    }


def _tier(score: int) -> str:
    if score >= HNDL_TIER_CRITICAL:
        return "CRITICAL"
    if score >= HNDL_TIER_HIGH:
        return "HIGH"
    if score >= HNDL_TIER_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _build_rationale(
    critical_count: int,
    reduced_count: int,
    alg_score: int,
    sensitivity: str,
    sens_score: int,
    retention_years: int,
    ret_label: str,
    ret_score: int,
    total: int,
    tier: str,
) -> str:
    parts = []

    if critical_count > 0:
        parts.append(
            f"{critical_count} quantum-CRITICAL algorithm(s) present (breakable by Shor's algorithm "
            f"on a CRQC) — contributing {alg_score} of {total} exposure points."
        )
    else:
        parts.append(
            "No quantum-CRITICAL algorithms detected. Primary harvest-now risk is eliminated "
            "by PQC migration or absence of asymmetric cryptography."
        )

    if reduced_count > 0:
        parts.append(
            f"{reduced_count} REDUCED-security algorithm(s) present (weakened by Grover's algorithm, "
            f"key-length upgrade recommended)."
        )

    parts.append(
        f"Data sensitivity ({sensitivity}) contributes {sens_score} exposure points — "
        f"higher sensitivity data is more valuable to adversaries harvesting now."
    )

    parts.append(
        f"Retention requirement ({ret_label}) contributes {ret_score} exposure points — "
        f"data requiring longer secrecy has more overlap with the estimated CRQC window."
    )

    tier_labels = {
        "CRITICAL": "Immediate migration action required. Quantum-vulnerable algorithms are "
                    "protecting high-value, long-lived data that adversaries are actively harvesting.",
        "HIGH": "Priority migration action required. Quantum-vulnerable algorithms present with "
                "significant sensitivity or retention exposure.",
        "MEDIUM": "Planned migration action required. Some quantum vulnerability present, "
                  "but sensitivity or retention limits immediate exposure.",
        "LOW": "Low harvest-now risk. Either quantum-safe algorithms are in use, data sensitivity "
               "is minimal, or retention requirements fall within near-term window.",
    }
    parts.append(tier_labels.get(tier, ""))

    return " ".join(parts)
