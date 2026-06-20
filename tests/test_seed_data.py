"""Tests for seed_data — seed scenarios and idempotency."""

import pytest
from models import Assessment, CryptoItem


class TestSeedScenarios:
    def test_all_three_scenarios_seeded(self, db_session):
        names = [a.org_name for a in db_session.query(Assessment).all()]
        assert "Aegis Defense Systems" in names
        assert "Meridian Health Systems" in names
        assert "Apex Technology Corp" in names

    def test_aegis_has_critical_tier(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        assert a.hndl_tier == "CRITICAL"

    def test_meridian_has_high_tier(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Meridian Health Systems").first()
        assert a.hndl_tier == "HIGH"

    def test_apex_has_low_tier(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Apex Technology Corp").first()
        assert a.hndl_tier == "LOW"

    def test_aegis_has_critical_algorithms(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        critical = [i for i in a.items if i.quantum_vulnerability == "CRITICAL"]
        assert len(critical) >= 3

    def test_apex_has_pqc_approved_items(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Apex Technology Corp").first()
        pqc = [i for i in a.items if i.compliance_status == "PQC_APPROVED"]
        assert len(pqc) >= 2

    def test_all_seed_scenarios_have_items(self, db_session):
        seed_names = ["Aegis Defense Systems", "Meridian Health Systems", "Apex Technology Corp"]
        for name in seed_names:
            a = db_session.query(Assessment).filter_by(org_name=name).first()
            assert a is not None, f"Seed scenario {name} not found"
            assert len(a.items) > 0, f"{name} has no items"

    def test_all_seed_scenarios_have_hndl_rationale(self, db_session):
        seed_names = ["Aegis Defense Systems", "Meridian Health Systems", "Apex Technology Corp"]
        for name in seed_names:
            a = db_session.query(Assessment).filter_by(org_name=name).first()
            assert a.hndl_rationale, f"{name} missing HNDL rationale"

    def test_all_seed_scenarios_have_roadmaps(self, db_session):
        seed_names = ["Aegis Defense Systems", "Meridian Health Systems", "Apex Technology Corp"]
        for name in seed_names:
            a = db_session.query(Assessment).filter_by(org_name=name).first()
            assert a.roadmap_text, f"{name} missing roadmap"

    def test_roadmaps_cite_fips(self, db_session):
        seed_names = ["Aegis Defense Systems", "Meridian Health Systems", "Apex Technology Corp"]
        for name in seed_names:
            a = db_session.query(Assessment).filter_by(org_name=name).first()
            assert "FIPS" in a.roadmap_text, f"{name} roadmap missing FIPS citation"

    def test_roadmaps_have_verify_flags(self, db_session):
        seed_names = ["Aegis Defense Systems", "Meridian Health Systems", "Apex Technology Corp"]
        for name in seed_names:
            a = db_session.query(Assessment).filter_by(org_name=name).first()
            assert "VERIFY" in a.roadmap_text, f"{name} roadmap missing VERIFY flags"

    def test_seed_is_idempotent(self, db_session):
        from seed_data import load_seed_data
        count_before = db_session.query(Assessment).count()
        load_seed_data(db_session)
        count_after = db_session.query(Assessment).count()
        assert count_before == count_after

    def test_aegis_score_above_75(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        assert a.hndl_score >= 75

    def test_apex_score_below_25(self, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Apex Technology Corp").first()
        assert a.hndl_score < 25

    def test_all_items_have_fips_citations(self, db_session):
        items = db_session.query(CryptoItem).all()
        for item in items:
            if item.compliance_status != "UNKNOWN":
                assert item.fips_citation, f"Item {item.algorithm} missing FIPS citation"

    def test_non_compliant_items_have_replacements(self, db_session):
        items = db_session.query(CryptoItem).filter_by(compliance_status="NON_COMPLIANT").all()
        for item in items:
            assert item.pqc_replacements, f"Non-compliant item {item.algorithm} missing PQC replacement"
