"""crypto_catalog.py — Algorithm taxonomy for post-quantum compliance assessment.

Each entry defines:
  category: functional category (KEM, Signature, Symmetric, Hash)
  quantum_vulnerability: CRITICAL | REDUCED | NONE | DEPRECATED
  compliance_status: PQC_APPROVED | QUANTUM_SAFE | REDUCED_SECURITY | NON_COMPLIANT | DEPRECATED
  pqc_replacements: list of FIPS 203/204/205 algorithms to migrate to
  fips_citation: NIST standard that governs this algorithm
  rationale: one-line explanation of the vulnerability or approval basis

Scope: asymmetric algorithms broken by Shor's algorithm are CRITICAL (harvest-now risk).
Symmetric algorithms weakened by Grover's algorithm are REDUCED (key-length concern only).
FIPS 203/204/205 algorithms are PQC_APPROVED.

Note: Ed25519 and Ed448 are elliptic-curve-based and quantum-CRITICAL despite being
modern algorithms — their security relies on ECDLP, which Shor's algorithm breaks.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical catalog — keyed by normalized algorithm identifier
# ---------------------------------------------------------------------------

CATALOG: dict[str, dict] = {

    # -----------------------------------------------------------------------
    # Key Encapsulation / Key Exchange — CRITICAL (Shor's algorithm breaks DLP/IFP)
    # -----------------------------------------------------------------------
    "rsa": {
        "category": "Key Exchange / KEM",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768", "ML-KEM-1024"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "RSA relies on integer factorization — directly solved by Shor's algorithm on a CRQC.",
    },
    "dh": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "Diffie-Hellman relies on discrete logarithm — solved by Shor's algorithm.",
    },
    "dhe": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "DHE relies on discrete logarithm — solved by Shor's algorithm.",
    },
    "ecdh": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "ECDH relies on elliptic curve discrete logarithm — solved by Shor's algorithm.",
    },
    "ecdhe": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "ECDHE relies on elliptic curve discrete logarithm — solved by Shor's algorithm.",
    },
    "x25519": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-768"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "X25519 is Curve25519 ECDH — elliptic curve, solved by Shor's algorithm.",
    },
    "x448": {
        "category": "Key Exchange",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-KEM-1024"],
        "fips_citation": "FIPS 203 (replacement)",
        "rationale": "X448 is Curve448 ECDH — elliptic curve, solved by Shor's algorithm.",
    },

    # -----------------------------------------------------------------------
    # Digital Signatures — CRITICAL (Shor's algorithm breaks DLP/IFP/ECDLP)
    # -----------------------------------------------------------------------
    "rsa-pss": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-DSA-65", "ML-DSA-87"],
        "fips_citation": "FIPS 204 (replacement)",
        "rationale": "RSA-PSS relies on integer factorization — solved by Shor's algorithm.",
    },
    "rsa-pkcs1": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-DSA-65", "ML-DSA-87"],
        "fips_citation": "FIPS 204 (replacement)",
        "rationale": "RSA PKCS#1 signature relies on integer factorization — solved by Shor's algorithm.",
    },
    "dsa": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["ML-DSA-65"],
        "fips_citation": "FIPS 204 (replacement); DSA already deprecated (NIST SP 800-186)",
        "rationale": "DSA relies on discrete logarithm — already deprecated classically and broken by Shor's algorithm.",
    },
    "ecdsa": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-DSA-65", "SLH-DSA-SHA2-128s"],
        "fips_citation": "FIPS 204, FIPS 205 (replacements)",
        "rationale": "ECDSA relies on elliptic curve discrete logarithm — solved by Shor's algorithm.",
    },
    "ed25519": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-DSA-65", "SLH-DSA-SHA2-128s"],
        "fips_citation": "FIPS 204 (replacement)",
        "rationale": "Ed25519 is EdDSA over Curve25519 — elliptic curve, solved by Shor's algorithm despite being a modern algorithm.",
    },
    "ed448": {
        "category": "Digital Signature",
        "quantum_vulnerability": "CRITICAL",
        "compliance_status": "NON_COMPLIANT",
        "pqc_replacements": ["ML-DSA-87", "SLH-DSA-SHA2-256s"],
        "fips_citation": "FIPS 204 (replacement)",
        "rationale": "Ed448 is EdDSA over Curve448 — elliptic curve, solved by Shor's algorithm.",
    },

    # -----------------------------------------------------------------------
    # PQC-Approved Key Encapsulation — FIPS 203 (August 2024)
    # -----------------------------------------------------------------------
    "ml-kem-512": {
        "category": "Key Encapsulation (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 203 (ML-KEM, August 2024)",
        "rationale": "Module-Lattice-Based KEM, NIST Level 1 security. Based on MLWE hardness problem.",
    },
    "ml-kem-768": {
        "category": "Key Encapsulation (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 203 (ML-KEM, August 2024)",
        "rationale": "Module-Lattice-Based KEM, NIST Level 3 security. Recommended general-purpose replacement for ECDH.",
    },
    "ml-kem-1024": {
        "category": "Key Encapsulation (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 203 (ML-KEM, August 2024)",
        "rationale": "Module-Lattice-Based KEM, NIST Level 5 security. Recommended for highest-assurance applications.",
    },

    # -----------------------------------------------------------------------
    # PQC-Approved Digital Signatures — FIPS 204 (August 2024)
    # -----------------------------------------------------------------------
    "ml-dsa-44": {
        "category": "Digital Signature (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 204 (ML-DSA, August 2024)",
        "rationale": "Module-Lattice-Based DSA, NIST Level 2 security. Based on MLWE/MSIS hardness.",
    },
    "ml-dsa-65": {
        "category": "Digital Signature (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 204 (ML-DSA, August 2024)",
        "rationale": "Module-Lattice-Based DSA, NIST Level 3 security. Recommended general-purpose PQC signature.",
    },
    "ml-dsa-87": {
        "category": "Digital Signature (PQC)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 204 (ML-DSA, August 2024)",
        "rationale": "Module-Lattice-Based DSA, NIST Level 5 security. Recommended for highest-assurance applications.",
    },

    # -----------------------------------------------------------------------
    # PQC-Approved Digital Signatures — FIPS 205 (August 2024)
    # -----------------------------------------------------------------------
    "slh-dsa-sha2-128s": {
        "category": "Digital Signature (PQC, Hash-Based)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 205 (SLH-DSA, August 2024)",
        "rationale": "Stateless Hash-Based DSA, small-signature variant. Security based solely on hash function properties.",
    },
    "slh-dsa-sha2-128f": {
        "category": "Digital Signature (PQC, Hash-Based)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 205 (SLH-DSA, August 2024)",
        "rationale": "Stateless Hash-Based DSA, fast-signature variant. Different security assumption from lattice-based schemes.",
    },
    "slh-dsa-sha2-256s": {
        "category": "Digital Signature (PQC, Hash-Based)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 205 (SLH-DSA, August 2024)",
        "rationale": "Stateless Hash-Based DSA, highest security variant. Conservative choice for long-lived signatures.",
    },
    "slh-dsa-shake-128s": {
        "category": "Digital Signature (PQC, Hash-Based)",
        "quantum_vulnerability": "NONE",
        "compliance_status": "PQC_APPROVED",
        "pqc_replacements": [],
        "fips_citation": "FIPS 205 (SLH-DSA, August 2024)",
        "rationale": "SLH-DSA SHAKE variant. Hash-based, quantum-resistant.",
    },

    # -----------------------------------------------------------------------
    # Symmetric Encryption — QUANTUM_SAFE (AES-256) or REDUCED_SECURITY (AES-128)
    # Grover's algorithm halves the effective key length in bits.
    # AES-128: 64-bit effective — marginal, recommend upgrade.
    # AES-256: 128-bit effective — remains secure.
    # -----------------------------------------------------------------------
    "des": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "DEPRECATED",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["AES-256"],
        "fips_citation": "Withdrawn by NIST (2005)",
        "rationale": "DES is classically broken (56-bit key). Deprecated regardless of quantum threat.",
    },
    "3des": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "DEPRECATED",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["AES-256"],
        "fips_citation": "NIST SP 800-131A Rev 2 — disallowed after 2023",
        "rationale": "Triple-DES disallowed by NIST after 2023. Vulnerable to Sweet32 attack classically.",
    },
    "aes-128": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "REDUCED",
        "compliance_status": "REDUCED_SECURITY",
        "pqc_replacements": ["AES-256"],
        "fips_citation": "FIPS 197 — upgrade to AES-256 recommended",
        "rationale": "Grover's algorithm halves AES-128's effective key length to ~64 bits. Recommend AES-256.",
    },
    "aes-192": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "REDUCED",
        "compliance_status": "REDUCED_SECURITY",
        "pqc_replacements": ["AES-256"],
        "fips_citation": "FIPS 197 — AES-256 preferred",
        "rationale": "Grover's reduces AES-192 to ~96-bit effective. Marginally acceptable; AES-256 preferred.",
    },
    "aes-256": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "FIPS 197",
        "rationale": "AES-256 remains secure under Grover's algorithm (128-bit effective key strength).",
    },
    "chacha20": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "RFC 8439 (non-FIPS); 256-bit key is quantum-safe",
        "rationale": "ChaCha20 uses a 256-bit key — Grover's leaves 128-bit effective strength. Quantum-safe.",
    },
    "rc4": {
        "category": "Symmetric Encryption",
        "quantum_vulnerability": "DEPRECATED",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["AES-256"],
        "fips_citation": "Prohibited by RFC 7465 and NIST guidance",
        "rationale": "RC4 is classically broken and prohibited. Must be removed immediately.",
    },

    # -----------------------------------------------------------------------
    # Hash Functions — Grover's algorithm provides quadratic speedup in search.
    # For collision resistance: Grover's halves the security margin.
    # SHA-256: 128-bit collision resistance → stays at 128-bit (Grover targets preimage).
    # More precisely: SHA-256 preimage resistance ~128 bits post-Grover.
    # SHA-384/SHA-512: remains 192/256-bit preimage resistance.
    # -----------------------------------------------------------------------
    "sha-1": {
        "category": "Hash Function",
        "quantum_vulnerability": "DEPRECATED",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["SHA-384", "SHA-512"],
        "fips_citation": "NIST SP 800-131A Rev 2 — disallowed for most uses after 2013",
        "rationale": "SHA-1 is classically broken for collision resistance. Disallowed by NIST.",
    },
    "md5": {
        "category": "Hash Function",
        "quantum_vulnerability": "DEPRECATED",
        "compliance_status": "DEPRECATED",
        "pqc_replacements": ["SHA-384"],
        "fips_citation": "NIST SP 800-131A — disallowed",
        "rationale": "MD5 is classically broken. Must be replaced immediately.",
    },
    "sha-256": {
        "category": "Hash Function",
        "quantum_vulnerability": "REDUCED",
        "compliance_status": "REDUCED_SECURITY",
        "pqc_replacements": ["SHA-384", "SHA-512"],
        "fips_citation": "FIPS 180-4 — SHA-384 or SHA-512 preferred for long-term use",
        "rationale": "Grover's reduces SHA-256 preimage resistance to ~128 bits. Acceptable now; SHA-384 preferred.",
    },
    "sha-384": {
        "category": "Hash Function",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "FIPS 180-4",
        "rationale": "SHA-384 retains ~192-bit preimage resistance post-Grover. Quantum-safe.",
    },
    "sha-512": {
        "category": "Hash Function",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "FIPS 180-4",
        "rationale": "SHA-512 retains ~256-bit preimage resistance post-Grover. Quantum-safe.",
    },
    "sha-3-256": {
        "category": "Hash Function",
        "quantum_vulnerability": "REDUCED",
        "compliance_status": "REDUCED_SECURITY",
        "pqc_replacements": ["SHA-3-384", "SHA-3-512"],
        "fips_citation": "FIPS 202 — SHA-3-384 preferred",
        "rationale": "SHA-3-256 preimage resistance reduced to ~128 bits by Grover's algorithm.",
    },
    "sha-3-384": {
        "category": "Hash Function",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "FIPS 202",
        "rationale": "SHA-3-384 retains ~192-bit preimage resistance post-Grover. Quantum-safe.",
    },
    "sha-3-512": {
        "category": "Hash Function",
        "quantum_vulnerability": "NONE",
        "compliance_status": "QUANTUM_SAFE",
        "pqc_replacements": [],
        "fips_citation": "FIPS 202",
        "rationale": "SHA-3-512 retains ~256-bit preimage resistance post-Grover. Quantum-safe.",
    },
}

# ---------------------------------------------------------------------------
# Normalization map — maps common variant names to canonical keys
# ---------------------------------------------------------------------------

NORMALIZE_MAP: dict[str, str] = {
    # RSA variants
    "rsa-2048": "rsa",
    "rsa-4096": "rsa",
    "rsa-1024": "rsa",
    "rsa2048": "rsa",
    "rsa4096": "rsa",
    "rsa 2048": "rsa",
    "rsa 4096": "rsa",
    # DH variants
    "diffie-hellman": "dh",
    "diffie hellman": "dh",
    # ECDH variants
    "ecdh-p256": "ecdh",
    "ecdh-p384": "ecdh",
    "ecdhe-p256": "ecdhe",
    "ecdhe-p384": "ecdhe",
    "ecdhe-rsa": "ecdhe",
    "ecdhe-ecdsa": "ecdhe",
    "ecdhe p256": "ecdhe",
    "ecdhe p384": "ecdhe",
    # ECDSA variants
    "ecdsa-p256": "ecdsa",
    "ecdsa-p384": "ecdsa",
    "ecdsa p256": "ecdsa",
    "ecdsa p384": "ecdsa",
    "ecdsa-sha256": "ecdsa",
    "ecdsa-sha384": "ecdsa",
    # RSA signature variants
    "rsa-pss-sha256": "rsa-pss",
    "rsa-pss-sha384": "rsa-pss",
    "rsassa-pkcs1-v1_5": "rsa-pkcs1",
    "rsa-pkcs1-sha256": "rsa-pkcs1",
    # Ed25519 / Ed448
    "eddsa": "ed25519",
    "ed25519-ph": "ed25519",
    # 3DES variants
    "triple-des": "3des",
    "tdea": "3des",
    "des3": "3des",
    "3des-ede": "3des",
    # AES variants (strip mode indicators)
    "aes-128-gcm": "aes-128",
    "aes-128-cbc": "aes-128",
    "aes-128-ctr": "aes-128",
    "aes128": "aes-128",
    "aes-192-gcm": "aes-192",
    "aes-256-gcm": "aes-256",
    "aes-256-cbc": "aes-256",
    "aes-256-ctr": "aes-256",
    "aes256": "aes-256",
    "aes256-gcm": "aes-256",
    # ChaCha20 variants
    "chacha20-poly1305": "chacha20",
    "chacha20poly1305": "chacha20",
    # Hash variants
    "sha1": "sha-1",
    "sha256": "sha-256",
    "sha384": "sha-384",
    "sha512": "sha-512",
    "sha2-256": "sha-256",
    "sha2-384": "sha-384",
    "sha2-512": "sha-512",
    # ML-KEM variants (CRYSTALS-Kyber was standardized as ML-KEM)
    "kyber512": "ml-kem-512",
    "kyber768": "ml-kem-768",
    "kyber1024": "ml-kem-1024",
    "kyber-512": "ml-kem-512",
    "kyber-768": "ml-kem-768",
    "crystals-kyber": "ml-kem-768",
    # ML-DSA variants (CRYSTALS-Dilithium was standardized as ML-DSA)
    "dilithium2": "ml-dsa-44",
    "dilithium3": "ml-dsa-65",
    "dilithium5": "ml-dsa-87",
    "crystals-dilithium": "ml-dsa-65",
    # SLH-DSA variants (SPHINCS+ was standardized as SLH-DSA)
    "sphincs+": "slh-dsa-sha2-128s",
    "sphincs+-sha2-128s": "slh-dsa-sha2-128s",
    "sphincs+-sha2-256s": "slh-dsa-sha2-256s",
}


def normalize_algorithm(raw: str) -> str:
    """Return the canonical catalog key for a raw algorithm name."""
    cleaned = raw.strip().lower()
    if cleaned in CATALOG:
        return cleaned
    if cleaned in NORMALIZE_MAP:
        return NORMALIZE_MAP[cleaned]
    # Partial match attempts
    for alias, key in NORMALIZE_MAP.items():
        if alias in cleaned:
            return key
    for key in CATALOG:
        if key in cleaned:
            return key
    return cleaned  # unknown — returned as-is


def lookup(algorithm: str) -> dict | None:
    """Return catalog entry for a raw or normalized algorithm name, or None."""
    key = normalize_algorithm(algorithm)
    return CATALOG.get(key)
