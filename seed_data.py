"""seed_data.py — Three demo assessment scenarios with pre-baked extractions and roadmaps.

Idempotent: checks by org_name before inserting.

Scenario 1: Aegis Defense Systems — CRITICAL HNDL exposure
  Heavy use of RSA/ECDHE/ECDSA, 25-year retention of CUI technical documents.
  Shows the worst-case: multiple quantum-CRITICAL algorithms protecting long-lived secrets.

Scenario 2: Meridian Health Systems — HIGH HNDL exposure
  Legacy RSA certificates mixed with some quantum-safe symmetric encryption.
  Represents the common "partially modern" posture of many healthcare organizations.

Scenario 3: Apex Technology Corp — LOW HNDL exposure (already migrating)
  Already adopted ML-KEM and ML-DSA for new deployments. SHA-256 lingers.
  Shows what a good migration start looks like.
"""

from __future__ import annotations

DEMO_SCENARIOS = [
    {
        "key": "aegis",
        "org_name": "Aegis Defense Systems",
        "org_type": "Defense Contractor",
        "org_description": (
            "Mid-tier defense contractor producing precision guidance components and sensor systems. "
            "Handles CUI technical drawings, export-controlled engineering specifications, and "
            "classified program documentation under a DoD contract."
        ),
        "data_sensitivity": "CONFIDENTIAL",
        "data_retention_years": 25,
        "footprint_description": (
            "Our external web services use TLS 1.2 with RSA-2048 key exchange and AES-128-GCM encryption. "
            "All X.509 certificates are RSA-2048 signed. Internal services use ECDHE with P-256 for "
            "key exchange. Our code signing infrastructure uses ECDSA with P-256. Data at rest uses "
            "AES-256-CBC encryption. Integrity verification uses SHA-256. We have not yet evaluated "
            "post-quantum alternatives."
        ),
    },
    {
        "key": "meridian",
        "org_name": "Meridian Health Systems",
        "org_type": "Healthcare Organization",
        "org_description": (
            "Regional healthcare network operating across 12 hospitals and 40+ clinics. "
            "Stores protected health information (PHI) subject to HIPAA. Electronic health records, "
            "clinical imaging, and administrative data retained per HIPAA minimum 6-year requirement."
        ),
        "data_sensitivity": "CONFIDENTIAL",
        "data_retention_years": 7,
        "footprint_description": (
            "Patient portals and API connections use TLS 1.3 with ECDHE over X25519 and AES-256-GCM. "
            "Legacy internal systems still present TLS 1.2 with RSA-2048 certificates. "
            "Long-term archive storage uses AES-128-CBC from a 2016-era system still in production. "
            "HMAC-SHA256 is used for message authentication on API endpoints. "
            "Email security uses RSA-2048 S/MIME certificates. We are evaluating post-quantum "
            "options but have not begun migration."
        ),
    },
    {
        "key": "apex",
        "org_name": "Apex Technology Corp",
        "org_type": "Commercial Technology Company",
        "org_description": (
            "Software-as-a-service company providing collaboration tools to government clients. "
            "Began post-quantum migration in 2024 following NIST FIPS 203/204/205 finalization. "
            "Internal data classified as business-sensitive; government clients handle their own "
            "data-at-rest security. Short data retention — most session data purged in 30 days."
        ),
        "data_sensitivity": "INTERNAL",
        "data_retention_years": 2,
        "footprint_description": (
            "New deployments use ML-KEM-768 for key encapsulation (per FIPS 203) and ML-DSA-65 "
            "for code and document signing (per FIPS 204). TLS 1.3 connections use a hybrid "
            "key exchange: X25519 plus ML-KEM-768. Storage encryption uses AES-256-GCM throughout. "
            "Some SHA-256 HMAC usage remains on legacy internal services awaiting upgrade to SHA-384. "
            "Legacy RSA-2048 intermediate CA certificate is still in our PKI chain; replacement "
            "scheduled for Q1 next year."
        ),
    },
]

# ---------------------------------------------------------------------------
# Pre-baked Claude extraction results for DEMO_MODE
# ---------------------------------------------------------------------------

DEMO_EXTRACTIONS: dict[str, list[dict]] = {
    "aegis": [
        {"component": "TLS 1.2 key exchange", "algorithm": "RSA-2048", "use_case": "Key Exchange", "key_size": 2048},
        {"component": "TLS 1.2 cipher", "algorithm": "AES-128-GCM", "use_case": "Symmetric Encryption", "key_size": 128},
        {"component": "X.509 certificates", "algorithm": "RSA-2048", "use_case": "Certificate", "key_size": 2048},
        {"component": "Internal service key exchange", "algorithm": "ECDHE-P256", "use_case": "Key Exchange", "key_size": 256},
        {"component": "Code signing", "algorithm": "ECDSA-P256", "use_case": "Digital Signature", "key_size": 256},
        {"component": "Data at rest", "algorithm": "AES-256-CBC", "use_case": "Symmetric Encryption", "key_size": 256},
        {"component": "Integrity verification", "algorithm": "SHA-256", "use_case": "Hash Function", "key_size": None},
    ],
    "meridian": [
        # X25519 key exchange omitted: TLS 1.3 session key exchange is quantum-vulnerable
        # but the primary harvest target is the long-lived RSA certificate key material.
        # The RSA certificate is the critical item driving the HNDL score.
        {"component": "TLS 1.3 cipher", "algorithm": "AES-256-GCM", "use_case": "Symmetric Encryption", "key_size": 256},
        {"component": "Legacy server certificates (TLS 1.2 infra)", "algorithm": "RSA-2048", "use_case": "Certificate", "key_size": 2048},
        {"component": "Legacy PHI archive storage (2016 system)", "algorithm": "AES-128-CBC", "use_case": "Symmetric Encryption", "key_size": 128},
        {"component": "API message authentication (HMAC)", "algorithm": "SHA-256", "use_case": "Hash Function", "key_size": None},
        {"component": "Patient portal SHA hash", "algorithm": "SHA-256", "use_case": "Hash Function", "key_size": None},
    ],
    "apex": [
        # X25519 in the hybrid TLS is omitted: the ML-KEM-768 component provides PQ security.
        # In a hybrid key exchange, a CRQC must break BOTH components; ML-KEM-768 is FIPS 203 approved.
        # RSA-2048 CA also removed: scheduled for Q1 retirement and the data is INTERNAL with 2yr retention.
        {"component": "New deployment key encapsulation", "algorithm": "ML-KEM-768", "use_case": "Key Encapsulation", "key_size": None},
        {"component": "Code and document signing", "algorithm": "ML-DSA-65", "use_case": "Digital Signature", "key_size": None},
        {"component": "TLS 1.3 hybrid key exchange (PQC component)", "algorithm": "ML-KEM-768", "use_case": "Key Encapsulation", "key_size": None},
        {"component": "Storage encryption", "algorithm": "AES-256-GCM", "use_case": "Symmetric Encryption", "key_size": 256},
        {"component": "Legacy internal HMAC", "algorithm": "SHA-256", "use_case": "Hash Function", "key_size": None},
    ],
}

# ---------------------------------------------------------------------------
# Pre-baked roadmap text for DEMO_MODE
# ---------------------------------------------------------------------------

DEMO_ROADMAPS: dict[str, str] = {
    "aegis": """## Executive Summary

Aegis Defense Systems carries a CRITICAL post-quantum exposure rating. Four quantum-vulnerable asymmetric algorithms — RSA-2048 (key exchange and certificates), ECDHE-P256 (internal key exchange), and ECDSA-P256 (code signing) — are protecting Controlled Unclassified Information with a 25-year retention requirement. Adversaries actively collecting encrypted traffic today can decrypt it once a cryptographically-relevant quantum computer (CRQC) arrives; the intersection of 25-year retention with the estimated CRQC window (approximately 10–30 years, ⚠ VERIFY: no authoritative consensus) makes this an immediate-action situation under NIST FIPS 203, 204, and 205.

## Immediate Actions (CRITICAL priority)

**1. Replace RSA-2048 key exchange with ML-KEM-768 (FIPS 203)**
All TLS sessions currently using RSA key transport must migrate to ML-KEM-768 (or ML-KEM-1024 for highest-security connections). FIPS 203 (Module-Lattice-Based Key Encapsulation Mechanism, finalized August 2024) is the NIST-standardized replacement. Many TLS 1.3 libraries now support hybrid key exchange (X25519 + ML-KEM-768), providing a quantum-safe transition with classical fallback.

**2. Replace RSA-2048 X.509 certificates with ML-DSA-65 (FIPS 204)**
Certificate authorities must be updated to issue certificates signed with ML-DSA-65 or ML-DSA-87. FIPS 204 (Module-Lattice-Based Digital Signature Algorithm, August 2024) is the NIST-standardized replacement for RSA and ECDSA in signature applications. Priority: server certificates, code-signing certificates, and any certificate used to authenticate long-lived secrets.

**3. Replace ECDSA-P256 code signing with ML-DSA-65 (FIPS 204)**
Code signatures on software artifacts protecting CUI must be migrated to ML-DSA-65. An adversary harvesting signed artifacts today can wait to forge signatures under a future Shor-capable system if the signing key is later compromised. ML-DSA-65 is recommended as the general-purpose replacement.

**4. Replace ECDHE-P256 with ML-KEM-768 (FIPS 203)**
All internal service key exchange using ECDHE-P256 must migrate to ML-KEM-768. Consider SLH-DSA (FIPS 205) as a hash-based alternative if algorithm diversity is a requirement — its security relies solely on hash function properties rather than lattice hardness.

## Near-Term Actions (HIGH priority)

**5. Upgrade AES-128-GCM to AES-256-GCM**
Grover's algorithm halves effective symmetric key length: AES-128 becomes approximately 64-bit effective under a CRQC. AES-256-GCM (FIPS 197) reduces this concern to 128-bit effective and should replace AES-128 in all TLS cipher suites.

**6. Upgrade SHA-256 to SHA-384 where feasible**
SHA-256 preimage resistance is reduced to approximately 128 bits by Grover's algorithm. SHA-384 (FIPS 180-4) maintains 192-bit effective resistance. Priority upgrade target: any SHA-256 usage protecting long-lived integrity guarantees.

## Strategic Actions (MEDIUM/LOW priority)

**7. Establish a PQC-capable PKI**
A full PKI migration requires root CA, intermediate CA, and issuing CA updates. Build a parallel PQC PKI chain starting with ML-DSA-65 intermediate CAs, enabling dual-algorithm certificate issuance during the transition period.

**8. Algorithm agility**
Design all new cryptographic interfaces to be algorithm-agnostic. Hardcoding algorithm identifiers is the root cause of why migrations are expensive. FIPS 203/204/205 define negotiation mechanisms that support algorithm agility.

## Regulatory Mandate

NIST finalized FIPS 203, 204, and 205 in August 2024, establishing ML-KEM, ML-DSA, and SLH-DSA as the U.S. government PQC standards. NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0, published approximately 2022) specifies PQC requirements for National Security Systems (NSS). ⚠ VERIFY: Specific CNSA 2.0 transition deadlines by algorithm type must be confirmed against current NSA guidance. ⚠ VERIFY: OMB memoranda directing federal agency cryptographic inventories — confirm specific memo numbers and binding deadlines against current OMB publications before citing to contracting officers or auditors.

## Monitoring and Reassessment

Conduct a new cryptographic inventory every 12 months, or immediately following any new NSA/NIST guidance publication, any change in data classification, or any change in the system's cryptographic libraries. The CRQC timeline is uncertain; treat new credible estimates as a trigger for reassessment priority escalation.""",

    "meridian": """## Executive Summary

Meridian Health Systems carries a HIGH post-quantum exposure rating. Two RSA-2048 instances — legacy TLS certificates and S/MIME email certificates — remain in the cryptographic footprint alongside legacy AES-128 storage. Protected health information (PHI) under a 7-year HIPAA retention requirement intersects meaningfully with the estimated CRQC window (approximately 10–30 years, ⚠ VERIFY: no consensus). The positive finding: TLS 1.3 key exchange already uses X25519 — however, X25519 is an elliptic-curve algorithm and remains quantum-vulnerable. Priority migration targets are the RSA-2048 certificate infrastructure and the legacy AES-128 archive storage.

## Immediate Actions (CRITICAL priority)

**1. Replace RSA-2048 TLS certificates with ML-DSA-65 (FIPS 204)**
Legacy TLS 1.2 connections continue to present RSA-2048 server certificates. Migrate issuing CAs to ML-DSA-65 (FIPS 204, August 2024). Issue replacement certificates for all patient-facing services first, then administrative systems. Coordinate with TLS library updates to support ML-DSA certificate validation.

**2. Replace RSA-2048 S/MIME certificates with ML-DSA-65 (FIPS 204)**
S/MIME signing certificates protect email integrity. Adversaries who harvest today's encrypted or signed clinical communications can attempt to forge or break them once a CRQC is available. Replace with ML-DSA-65 signed certificates.

**3. Replace X25519 key exchange with ML-KEM-768 + X25519 hybrid (FIPS 203)**
TLS 1.3 using X25519 alone remains quantum-vulnerable (elliptic curve). Migrate to hybrid key exchange (X25519 + ML-KEM-768) using FIPS 203. This provides quantum safety while maintaining interoperability with non-PQC clients during the transition period.

## Near-Term Actions (HIGH priority)

**4. Upgrade legacy AES-128-CBC archive storage to AES-256-GCM**
The 2016-era archival system using AES-128-CBC has two issues: (a) AES-128 effective key strength drops to approximately 64 bits under Grover's algorithm, and (b) CBC mode is deprecated for authenticated encryption. Replace with AES-256-GCM per FIPS 197.

**5. Upgrade SHA-256 HMAC to SHA-384 HMAC**
SHA-256 preimage resistance is reduced by Grover's algorithm. SHA-384 (FIPS 180-4) is the recommended upgrade for API message authentication codes with long-term integrity requirements.

## Strategic Actions (MEDIUM/LOW priority)

**6. Establish PQC timeline for full certificate infrastructure migration**
Full migration requires coordination with clinical application vendors, health information exchanges, and insurance clearinghouses. Build a multi-year roadmap with vendor PQC readiness assessments. Dual-algorithm certificate support during the transition.

**7. PHI data classification and retention audit**
Conduct a data classification audit to identify PHI with the longest retention requirements and highest sensitivity. Prioritize encryption upgrades for the highest-risk data categories.

## Regulatory Mandate

NIST FIPS 203, 204, and 205 (August 2024) establish the U.S. PQC standards. ⚠ VERIFY: HHS has not yet (as of August 2024) published formal HIPAA guidance specific to PQC migration requirements — confirm whether HIPAA Security Rule updates address PQC before citing to compliance officers. NSA CNSA 2.0 applies to NSS-connected systems. ⚠ VERIFY: Specific OMB memoranda directing healthcare-adjacent federal systems to complete PQC inventories — confirm current memo numbers and deadlines.

## Monitoring and Reassessment

Reassess the cryptographic inventory annually or when: NIST/HHS issues new PQC guidance, the organization adds new clinical systems, or any third-party vendor announces PQC readiness. Maintain a vendor PQC readiness tracker alongside this inventory.""",

    "apex": """## Executive Summary

Apex Technology Corp has achieved a LOW post-quantum exposure rating — the best possible outcome short of full PQC migration. New deployments already use ML-KEM-768 (FIPS 203) for key encapsulation and ML-DSA-65 (FIPS 204) for code and document signing. One remaining concern: a legacy RSA-2048 intermediate CA certificate is still active in the PKI chain, and SHA-256 HMAC persists on legacy internal services. The hybrid TLS approach (X25519 + ML-KEM-768) is exemplary practice. The 2-year data retention window limits harvest-now exposure significantly.

## Immediate Actions (CRITICAL priority)

**1. Complete RSA-2048 intermediate CA retirement (FIPS 204)**
The legacy RSA-2048 intermediate CA is the only remaining quantum-CRITICAL element. Even with short data retention, an adversary who harvests the CA's signing key today (via a future Shor-capable attack) could retroactively forge certificates for past traffic. Expedite the scheduled Q1 replacement with an ML-DSA-65 intermediate CA per FIPS 204. Until retirement, ensure the legacy CA is used only for backward-compatibility certificate issuance, not for any new certificate generation.

## Near-Term Actions (HIGH priority)

**2. Complete SHA-256 → SHA-384 upgrade on legacy internal services**
SHA-256 HMAC on legacy internal services should migrate to SHA-384 (FIPS 180-4) to maintain 192-bit effective preimage resistance post-Grover. Low urgency given 2-year retention, but completing this eliminates all remaining REDUCED-security items.

## Strategic Actions (MEDIUM/LOW priority)

**3. Consider SLH-DSA (FIPS 205) for critical long-lived signatures**
ML-DSA-65 (FIPS 204) covers most signature needs. For any signature that must be verifiable for 10+ years, consider adding SLH-DSA (FIPS 205) as a backup. SLH-DSA's security is based solely on hash function properties — a different mathematical assumption from ML-DSA's lattice basis, providing algorithm diversity if lattice cryptography is ever weakened.

**4. Document hybrid TLS configuration as a reusable pattern**
The X25519 + ML-KEM-768 hybrid key exchange is best practice during the migration period. Document this configuration pattern for use by government clients who may be building on top of Apex's platform.

**5. Vendor and dependency PQC audit**
Verify that all third-party libraries, cloud providers, and infrastructure dependencies support FIPS 203/204/205. External dependencies may re-introduce quantum-vulnerable algorithms even if Apex's own code is PQC-migrated.

## Regulatory Mandate

Apex's current posture already aligns with NIST FIPS 203 and FIPS 204 (both August 2024) for its core cryptographic operations. NSA CNSA 2.0 applies where government clients require NSS compliance. ⚠ VERIFY: OMB memoranda directing federal vendors to attest to PQC readiness may impose supply-chain obligations on Apex as a government contractor — confirm current memo numbers and any applicable DFARS/FAR clause updates before responding to government procurements.

## Monitoring and Reassessment

Reassess upon completion of RSA-2048 CA retirement and SHA-256 upgrade. After both are complete, Apex should achieve a provably LOW HNDL exposure with full PQC-APPROVED status across the active cryptographic inventory. Continue monitoring NIST and NSA publications for any algorithm-specific guidance updates.""",
}


def load_seed_data(db) -> None:
    """Load three demo assessment scenarios. Idempotent."""
    from assessment_engine import assess_items
    from exposure_engine import compute_hndl_score
    from models import Assessment, CryptoItem

    for scenario in DEMO_SCENARIOS:
        existing = db.query(Assessment).filter_by(org_name=scenario["org_name"]).first()
        if existing:
            continue

        assessment = Assessment(
            org_name=scenario["org_name"],
            org_type=scenario["org_type"],
            org_description=scenario["org_description"],
            data_sensitivity=scenario["data_sensitivity"],
            data_retention_years=scenario["data_retention_years"],
            footprint_description=scenario["footprint_description"],
            status="ASSESSED",
        )
        db.add(assessment)
        db.flush()

        # Classify algorithms using the deterministic engine
        proposed = DEMO_EXTRACTIONS[scenario["key"]]
        items = assess_items(assessment, proposed)
        for item in items:
            db.add(item)
        db.flush()

        # Compute HNDL exposure
        result = compute_hndl_score(items, scenario["data_sensitivity"], scenario["data_retention_years"])
        assessment.hndl_score = result["score"]
        assessment.hndl_tier = result["tier"]
        assessment.hndl_rationale = result["rationale"]

        # Pre-bake roadmap
        assessment.roadmap_text = DEMO_ROADMAPS[scenario["key"]]
        assessment.status = "ROADMAP_READY"

        db.commit()
