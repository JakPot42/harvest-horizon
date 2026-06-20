"""Tests for exposure_engine — HNDL scoring and tier determination."""

import pytest
from unittest.mock import MagicMock

from exposure_engine import _tier, compute_hndl_score


def _make_item(vulnerability: str, compliance: str = "NON_COMPLIANT"):
    item = MagicMock()
    item.quantum_vulnerability = vulnerability
    item.compliance_status = compliance
    return item


class TestTier:
    def test_critical_at_75(self):
        assert _tier(75) == "CRITICAL"

    def test_critical_at_100(self):
        assert _tier(100) == "CRITICAL"

    def test_high_at_50(self):
        assert _tier(50) == "HIGH"

    def test_high_at_74(self):
        assert _tier(74) == "HIGH"

    def test_medium_at_25(self):
        assert _tier(25) == "MEDIUM"

    def test_medium_at_49(self):
        assert _tier(49) == "MEDIUM"

    def test_low_at_0(self):
        assert _tier(0) == "LOW"

    def test_low_at_24(self):
        assert _tier(24) == "LOW"


class TestComputeHNDLScore:

    def test_no_algorithms_gives_low_score(self):
        result = compute_hndl_score([], "INTERNAL", 5)
        assert result["tier"] == "LOW"
        assert result["score"] == 0  # empty items early-exits with score 0

    def test_critical_secret_long_retention_gives_critical_tier(self):
        items = [
            _make_item("CRITICAL"),
            _make_item("CRITICAL"),
            _make_item("CRITICAL"),
        ]
        result = compute_hndl_score(items, "SECRET", 25)
        assert result["tier"] == "CRITICAL"
        assert result["score"] >= 75

    def test_single_critical_confidential_medium_retention_is_high(self):
        items = [_make_item("CRITICAL"), _make_item("REDUCED"), _make_item("REDUCED")]
        result = compute_hndl_score(items, "CONFIDENTIAL", 7)
        assert result["tier"] == "HIGH"
        assert result["score"] >= 50

    def test_one_critical_internal_short_retention_is_medium(self):
        items = [_make_item("CRITICAL")]
        result = compute_hndl_score(items, "INTERNAL", 2)
        assert result["tier"] in ("MEDIUM", "LOW")

    def test_no_critical_algorithms_caps_below_high(self):
        items = [_make_item("REDUCED"), _make_item("REDUCED")]
        result = compute_hndl_score(items, "SECRET", 25)
        assert result["tier"] != "CRITICAL"
        assert result["score"] < 50

    def test_pqc_only_gives_low(self):
        items = [
            _make_item("NONE", "PQC_APPROVED"),
            _make_item("NONE", "QUANTUM_SAFE"),
        ]
        result = compute_hndl_score(items, "SECRET", 25)
        assert result["tier"] == "LOW"
        assert result["score"] < 25

    def test_score_capped_at_100(self):
        items = [_make_item("CRITICAL")] * 10
        result = compute_hndl_score(items, "SECRET", 25)
        assert result["score"] <= 100

    def test_score_not_negative(self):
        result = compute_hndl_score([], "PUBLIC", 1)
        assert result["score"] >= 0

    def test_deprecated_algorithms_dont_add_to_alg_score(self):
        # DEPRECATED items (3DES, SHA-1, etc.) are broken classically — not a quantum harvest target.
        # They should contribute 0 to the algorithm vulnerability component.
        items_dep = [_make_item("DEPRECATED", "DEPRECATED")] * 5
        result_dep = compute_hndl_score(items_dep, "SECRET", 25)
        assert result_dep["alg_score"] == 0
        # With 0 critical algorithms, the formula caps exposure below HIGH tier
        assert result_dep["tier"] not in ("CRITICAL", "HIGH")

    def test_public_data_short_retention_low_score(self):
        items = [_make_item("CRITICAL")]
        result = compute_hndl_score(items, "PUBLIC", 1)
        assert result["score"] < 30

    def test_critical_count_returned(self):
        items = [_make_item("CRITICAL"), _make_item("CRITICAL"), _make_item("REDUCED")]
        result = compute_hndl_score(items, "INTERNAL", 5)
        assert result["critical_count"] == 2
        assert result["reduced_count"] == 1

    def test_rationale_mentions_critical_count(self):
        items = [_make_item("CRITICAL"), _make_item("CRITICAL")]
        result = compute_hndl_score(items, "CONFIDENTIAL", 10)
        assert "2" in result["rationale"]

    def test_rationale_present(self):
        items = [_make_item("CRITICAL")]
        result = compute_hndl_score(items, "INTERNAL", 5)
        assert len(result["rationale"]) > 50

    def test_aegis_scenario_is_critical(self):
        # 4 CRITICAL, CONFIDENTIAL, 25yr → should be CRITICAL
        items = [_make_item("CRITICAL")] * 4 + [_make_item("REDUCED")] * 2
        result = compute_hndl_score(items, "CONFIDENTIAL", 25)
        assert result["tier"] == "CRITICAL"

    def test_meridian_scenario_is_high(self):
        # 1 CRITICAL (RSA cert), 3 REDUCED, CONFIDENTIAL, 7yr → HIGH
        items = [_make_item("CRITICAL")] + [_make_item("REDUCED")] * 3
        result = compute_hndl_score(items, "CONFIDENTIAL", 7)
        assert result["tier"] == "HIGH"

    def test_apex_scenario_is_low(self):
        # 0 CRITICAL, 1 REDUCED, INTERNAL, 2yr → LOW
        items = [_make_item("REDUCED")]
        result = compute_hndl_score(items, "INTERNAL", 2)
        assert result["tier"] == "LOW"
