"""Tests for assessment_engine — algorithm classification and batch assessment."""

import pytest
from assessment_engine import assess_items, classify_algorithm, compliance_summary
from models import Assessment


class TestClassifyAlgorithm:

    # Quantum-CRITICAL algorithms (Shor-breakable)
    def test_rsa_is_critical(self):
        r = classify_algorithm("RSA-2048")
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_rsa_is_non_compliant(self):
        r = classify_algorithm("RSA-2048")
        assert r["compliance_status"] == "NON_COMPLIANT"

    def test_ecdh_is_critical(self):
        r = classify_algorithm("ECDH-P256")
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_ecdhe_is_non_compliant(self):
        r = classify_algorithm("ECDHE-P256")
        assert r["compliance_status"] == "NON_COMPLIANT"

    def test_dh_is_critical(self):
        r = classify_algorithm("DH")
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_ecdsa_is_critical(self):
        r = classify_algorithm("ECDSA-P256")
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_ed25519_is_critical(self):
        # Ed25519 is elliptic curve despite being a modern algorithm
        r = classify_algorithm("Ed25519")
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_dsa_is_deprecated(self):
        r = classify_algorithm("DSA")
        assert r["compliance_status"] == "DEPRECATED"
        assert r["quantum_vulnerability"] == "CRITICAL"

    def test_x25519_is_critical(self):
        r = classify_algorithm("X25519")
        assert r["quantum_vulnerability"] == "CRITICAL"

    # PQC-Approved (FIPS 203/204/205)
    def test_ml_kem_512_is_pqc_approved(self):
        r = classify_algorithm("ML-KEM-512")
        assert r["compliance_status"] == "PQC_APPROVED"
        assert r["quantum_vulnerability"] == "NONE"

    def test_ml_kem_768_is_pqc_approved(self):
        r = classify_algorithm("ML-KEM-768")
        assert r["compliance_status"] == "PQC_APPROVED"

    def test_ml_kem_1024_is_pqc_approved(self):
        r = classify_algorithm("ML-KEM-1024")
        assert r["compliance_status"] == "PQC_APPROVED"

    def test_ml_dsa_44_is_pqc_approved(self):
        r = classify_algorithm("ML-DSA-44")
        assert r["compliance_status"] == "PQC_APPROVED"

    def test_ml_dsa_65_is_pqc_approved(self):
        r = classify_algorithm("ML-DSA-65")
        assert r["compliance_status"] == "PQC_APPROVED"
        assert r["quantum_vulnerability"] == "NONE"

    def test_ml_dsa_87_is_pqc_approved(self):
        r = classify_algorithm("ML-DSA-87")
        assert r["compliance_status"] == "PQC_APPROVED"

    def test_slh_dsa_is_pqc_approved(self):
        r = classify_algorithm("SLH-DSA-SHA2-128s")
        assert r["compliance_status"] == "PQC_APPROVED"
        assert r["quantum_vulnerability"] == "NONE"

    # Quantum-safe symmetric
    def test_aes256_is_quantum_safe(self):
        r = classify_algorithm("AES-256-GCM")
        assert r["compliance_status"] == "QUANTUM_SAFE"
        assert r["quantum_vulnerability"] == "NONE"

    def test_aes256_gcm_is_quantum_safe(self):
        r = classify_algorithm("AES-256-CBC")
        assert r["compliance_status"] == "QUANTUM_SAFE"

    def test_chacha20_is_quantum_safe(self):
        r = classify_algorithm("ChaCha20-Poly1305")
        assert r["compliance_status"] == "QUANTUM_SAFE"

    # Reduced security
    def test_aes128_is_reduced_security(self):
        r = classify_algorithm("AES-128-GCM")
        assert r["compliance_status"] == "REDUCED_SECURITY"
        assert r["quantum_vulnerability"] == "REDUCED"

    def test_sha256_is_reduced_security(self):
        r = classify_algorithm("SHA-256")
        assert r["compliance_status"] == "REDUCED_SECURITY"

    def test_sha384_is_quantum_safe(self):
        r = classify_algorithm("SHA-384")
        assert r["compliance_status"] == "QUANTUM_SAFE"

    def test_sha512_is_quantum_safe(self):
        r = classify_algorithm("SHA-512")
        assert r["compliance_status"] == "QUANTUM_SAFE"

    # Deprecated
    def test_3des_is_deprecated(self):
        r = classify_algorithm("3DES")
        assert r["compliance_status"] == "DEPRECATED"

    def test_sha1_is_deprecated(self):
        r = classify_algorithm("SHA-1")
        assert r["compliance_status"] == "DEPRECATED"

    def test_md5_is_deprecated(self):
        r = classify_algorithm("MD5")
        assert r["compliance_status"] == "DEPRECATED"

    def test_rc4_is_deprecated(self):
        r = classify_algorithm("RC4")
        assert r["compliance_status"] == "DEPRECATED"

    # Unknown
    def test_unknown_algorithm(self):
        r = classify_algorithm("QUANTUM-SUPER-ALGO-9000")
        assert r["compliance_status"] == "UNKNOWN"
        assert r["quantum_vulnerability"] == "UNKNOWN"

    # PQC replacements
    def test_rsa_replacement_includes_ml_kem(self):
        r = classify_algorithm("RSA-2048")
        assert "ML-KEM-768" in r["pqc_replacements"] or "ML-KEM-1024" in r["pqc_replacements"]

    def test_ecdsa_replacement_includes_ml_dsa(self):
        r = classify_algorithm("ECDSA-P256")
        assert "ML-DSA-65" in r["pqc_replacements"]

    def test_pqc_approved_has_no_replacement(self):
        r = classify_algorithm("ML-KEM-768")
        assert r["pqc_replacements"] == ""

    # FIPS citations
    def test_ml_kem_cites_fips_203(self):
        r = classify_algorithm("ML-KEM-768")
        assert "FIPS 203" in r["fips_citation"]

    def test_ml_dsa_cites_fips_204(self):
        r = classify_algorithm("ML-DSA-65")
        assert "FIPS 204" in r["fips_citation"]

    def test_slh_dsa_cites_fips_205(self):
        r = classify_algorithm("SLH-DSA-SHA2-128s")
        assert "FIPS 205" in r["fips_citation"]


class TestAssessItems:
    def test_assess_batch_returns_correct_count(self, db_session):
        assessment = db_session.query(Assessment).first()
        proposed = [
            {"component": "TLS", "algorithm": "RSA-2048", "use_case": "Key Exchange", "key_size": 2048},
            {"component": "Storage", "algorithm": "AES-256-GCM", "use_case": "Symmetric Encryption", "key_size": 256},
        ]
        items = assess_items(assessment, proposed)
        assert len(items) == 2

    def test_assess_batch_classifies_correctly(self, db_session):
        assessment = db_session.query(Assessment).first()
        proposed = [
            {"component": "TLS", "algorithm": "ML-KEM-768", "use_case": "Key Encapsulation", "key_size": None},
        ]
        items = assess_items(assessment, proposed)
        assert items[0].compliance_status == "PQC_APPROVED"
        assert items[0].quantum_vulnerability == "NONE"


class TestComplianceSummary:
    def test_summary_counts_correctly(self, db_session):
        assessment = db_session.query(Assessment).first()
        summary = compliance_summary(assessment.items)
        assert summary["total"] == len(assessment.items)
        total_check = (
            summary["pqc_approved"] + summary["quantum_safe"] +
            summary["reduced_security"] + summary["non_compliant"] +
            summary["deprecated"] + summary["unknown"]
        )
        assert total_check == summary["total"]

    def test_summary_critical_count(self, db_session):
        assessment = db_session.query(Assessment).first()
        summary = compliance_summary(assessment.items)
        manual_critical = sum(1 for i in assessment.items if i.quantum_vulnerability == "CRITICAL")
        assert summary["critical_vulnerabilities"] == manual_critical
