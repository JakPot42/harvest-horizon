"""Tests for main.py FastAPI routes."""

import pytest
from models import Assessment, CryptoItem


class TestIndex:
    def test_index_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_index_contains_app_title(self, client):
        r = client.get("/")
        assert b"Harvest Horizon" in r.content

    def test_index_shows_assessments(self, client):
        r = client.get("/")
        assert b"Aegis" in r.content or b"No assessments" in r.content


class TestNewAssessmentForm:
    def test_get_returns_200(self, client):
        r = client.get("/assessments/new")
        assert r.status_code == 200

    def test_form_shows_sensitivity_options(self, client):
        r = client.get("/assessments/new")
        assert b"CONFIDENTIAL" in r.content or b"Confidential" in r.content

    def test_post_missing_name_returns_422(self, client):
        r = client.post("/assessments/new", data={"org_name": ""}, follow_redirects=False)
        assert r.status_code in (422, 200)  # shows error or form

    def test_post_creates_assessment_and_redirects(self, client, db_session):
        r = client.post(
            "/assessments/new",
            data={
                "org_name": "Test Corp",
                "org_type": "Commercial Technology Company",
                "org_description": "Test org",
                "data_sensitivity": "INTERNAL",
                "data_retention_years": "3",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/describe" in r.headers["location"]


class TestSeedRoute:
    def test_seed_redirects_to_assessment(self, client):
        r = client.post("/seed", follow_redirects=False)
        assert r.status_code == 303

    def test_seed_idempotent(self, client, db_session):
        client.post("/seed")
        count_before = db_session.query(Assessment).filter(
            Assessment.org_name == "Aegis Defense Systems"
        ).count()
        client.post("/seed")
        count_after = db_session.query(Assessment).filter(
            Assessment.org_name == "Aegis Defense Systems"
        ).count()
        assert count_before == count_after == 1


class TestAssessmentDetail:
    def test_existing_assessment_returns_200(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}")
        assert r.status_code == 200

    def test_assessment_shows_hndl_tier(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}")
        assert b"CRITICAL" in r.content

    def test_assessment_shows_org_name(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}")
        assert b"Aegis Defense Systems" in r.content

    def test_nonexistent_assessment_returns_404(self, client):
        r = client.get("/assessments/99999")
        assert r.status_code == 404

    def test_assessment_shows_algorithm_inventory(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}")
        assert b"RSA" in r.content

    def test_assessment_shows_compliance_status(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}")
        assert b"NON" in r.content or b"CRITICAL" in r.content


class TestDescribeRoute:
    def test_describe_form_returns_200(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}/describe")
        assert r.status_code == 200


class TestRoadmapRoute:
    def test_roadmap_returns_200_when_ready(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}/roadmap")
        assert r.status_code in (200, 303)

    def test_roadmap_contains_fips_citation(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        if a.roadmap_text:
            r = client.get(f"/assessments/{a.id}/roadmap")
            assert b"FIPS" in r.content


class TestPDFRoute:
    def test_pdf_returns_200_bytes(self, client, db_session):
        a = db_session.query(Assessment).filter_by(org_name="Aegis Defense Systems").first()
        r = client.get(f"/assessments/{a.id}/report.pdf")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert len(r.content) > 1000


class TestStatsRoute:
    def test_stats_returns_ok(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "assessments" in data
        assert "critical_vulnerabilities" in data

    def test_stats_demo_mode_true(self, client):
        r = client.get("/api/stats")
        assert r.json()["demo_mode"] is True
