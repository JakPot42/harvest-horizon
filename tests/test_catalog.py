"""Tests for crypto_catalog — normalization and lookup."""

import pytest
from crypto_catalog import CATALOG, lookup, normalize_algorithm


class TestNormalize:
    def test_lowercase_canonical_pass_through(self):
        assert normalize_algorithm("rsa") == "rsa"

    def test_case_insensitive(self):
        assert normalize_algorithm("RSA") == "rsa"
        assert normalize_algorithm("AES-256") == "aes-256"
        assert normalize_algorithm("SHA-256") == "sha-256"

    def test_rsa_with_key_size(self):
        assert normalize_algorithm("RSA-2048") == "rsa"
        assert normalize_algorithm("rsa-4096") == "rsa"

    def test_ecdhe_with_curve(self):
        assert normalize_algorithm("ECDHE-P256") == "ecdhe"
        assert normalize_algorithm("ecdhe-p384") == "ecdhe"

    def test_ecdsa_with_curve(self):
        assert normalize_algorithm("ECDSA-P256") == "ecdsa"

    def test_aes_mode_stripped(self):
        assert normalize_algorithm("AES-128-GCM") == "aes-128"
        assert normalize_algorithm("AES-256-GCM") == "aes-256"
        assert normalize_algorithm("AES-256-CBC") == "aes-256"

    def test_chacha20_poly1305(self):
        assert normalize_algorithm("ChaCha20-Poly1305") == "chacha20"

    def test_3des_variants(self):
        assert normalize_algorithm("3DES-EDE") == "3des"
        assert normalize_algorithm("Triple-DES") == "3des"

    def test_sha_shortforms(self):
        assert normalize_algorithm("SHA256") == "sha-256"
        assert normalize_algorithm("SHA384") == "sha-384"
        assert normalize_algorithm("SHA512") == "sha-512"

    def test_kyber_aliases(self):
        assert normalize_algorithm("KYBER768") == "ml-kem-768"
        assert normalize_algorithm("crystals-kyber") == "ml-kem-768"

    def test_dilithium_aliases(self):
        assert normalize_algorithm("DILITHIUM3") == "ml-dsa-65"
        assert normalize_algorithm("crystals-dilithium") == "ml-dsa-65"

    def test_unknown_returns_as_is(self):
        result = normalize_algorithm("SOME-UNKNOWN-ALGO")
        assert result == "some-unknown-algo"


class TestLookup:
    def test_rsa_lookup(self):
        entry = lookup("RSA-2048")
        assert entry is not None
        assert entry["quantum_vulnerability"] == "CRITICAL"
        assert entry["compliance_status"] == "NON_COMPLIANT"

    def test_ml_kem_768_lookup(self):
        entry = lookup("ML-KEM-768")
        assert entry is not None
        assert entry["quantum_vulnerability"] == "NONE"
        assert entry["compliance_status"] == "PQC_APPROVED"

    def test_unknown_returns_none(self):
        assert lookup("NOT-REAL-ALGO-XYZ") is None

    def test_aes256_quantum_safe(self):
        entry = lookup("AES-256-GCM")
        assert entry["compliance_status"] == "QUANTUM_SAFE"
        assert entry["quantum_vulnerability"] == "NONE"

    def test_sha256_reduced_security(self):
        entry = lookup("SHA-256")
        assert entry["compliance_status"] == "REDUCED_SECURITY"
        assert entry["quantum_vulnerability"] == "REDUCED"
