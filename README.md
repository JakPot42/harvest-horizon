# Harvest Horizon — Post-Quantum Cryptographic Migration Assessor

Cryptographic inventory and quantum-vulnerability assessment tool — describe your organization's encryption footprint, get an algorithm-by-algorithm assessment against NIST's finalized post-quantum standards, and receive a migration roadmap prioritized by harvest-now-decrypt-later exposure.

Built to make the PQC transition tractable for defense contractors and federal agencies who need to act now on data that must stay secret for years.

**Live demo:** https://harvest-horizon-lulp.onrender.com

---

## What It Does

NIST finalized three post-quantum cryptography standards in August 2024: FIPS 203 (ML-KEM, key encapsulation), FIPS 204 (ML-DSA, digital signatures), and FIPS 205 (SLH-DSA, stateless hash-based signatures). The threat driving urgency is "harvest now, decrypt later" — adversaries are collecting encrypted traffic today and will decrypt it retroactively once quantum computing capability arrives.

This tool automates the assessment workflow:

1. **Inventory** — Claude extracts your cryptographic footprint from a plain-language description: TLS configurations, key exchange protocols, signature schemes, certificate chains, data types, and retention periods
2. **Assess** — deterministic engine checks each algorithm against NIST FIPS 203/204/205 compliance and NSA CNSA 2.0 deprecation timelines
3. **Expose** — "harvest-now-decrypt-later" (HNDL) exposure rating computed per data type: how long does this data need to stay secret vs. the estimated quantum timeline?
4. **Roadmap** — Claude drafts a prioritized migration roadmap: which systems need post-quantum algorithms first, and why
5. **Export** — ReportLab PDF with DEMO watermark

---

## The HNDL Exposure Model

Compliance and exposure are different questions — this tool answers both.

A system that uses deprecated RSA-2048 but only handles data with a 1-year sensitivity window has low HNDL exposure (the data will be worthless before quantum arrives). The same RSA-2048 on a system handling clearance files, weapons designs, or diplomatic cables — data with 20-50 year sensitivity windows — has critical exposure.

| HNDL Exposure | Criteria | Priority |
|--------------|---------|---------|
| Critical | Long-retention sensitive data + deprecated algorithm | Migrate within 12 months |
| High | Medium-retention data + quantum-vulnerable algorithm | Migrate within 24 months |
| Medium | Short-retention data + deprecated algorithm | Plan migration |
| Low | Already post-quantum or expired data | Monitor |

---

## Algorithm Assessment

| Algorithm | Status | Replacement |
|-----------|--------|------------|
| RSA (all key sizes) | Deprecated — quantum-vulnerable (Shor's algorithm) | ML-KEM (FIPS 203) |
| ECDH / ECDSA | Deprecated — quantum-vulnerable (Shor's algorithm) | ML-KEM / ML-DSA (FIPS 203/204) |
| AES-256 | Compliant — quantum-resistant (Grover's halves security, AES-256 retains 128-bit post-quantum) | Retain |
| SHA-256/384/512 | Compliant — Grover resistance adequate | Retain |
| ML-KEM (CRYSTALS-Kyber) | FIPS 203 compliant | Native |
| ML-DSA (CRYSTALS-Dilithium) | FIPS 204 compliant | Native |
| SLH-DSA (SPHINCS+) | FIPS 205 compliant | Native |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI + Python |
| AI | Claude Haiku (cryptographic inventory extraction; migration roadmap drafting) |
| Compliance engine | Deterministic rules against NIST FIPS 203/204/205 (`assessment_engine.py`) |
| HNDL scoring | Deterministic exposure engine (`exposure_engine.py`) — data retention × algorithm vulnerability |
| Algorithm catalog | `crypto_catalog.py` — algorithm database with quantum vulnerability classification |
| PDF export | ReportLab (DEMO watermark) |
| Database | SQLite + SQLAlchemy 2.0 |
| Frontend | Jinja2 templates + vanilla CSS |
| Deploy | Render (DEMO_MODE=True) |

---

## Quick Start

```bash
git clone https://github.com/JakPot42/harvest-horizon.git
cd harvest-horizon
cp .env.example .env          # add ANTHROPIC_API_KEY=sk-ant-...
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\uvicorn main:app --reload
```

Open http://localhost:8000

---

## Pre-Seeded Demo Scenarios

Three organizations load automatically on startup:

**Aegis Defense Systems** — TLS 1.2 (ECDHE-RSA), RSA-2048 certificate signing, AES-256 symmetric. Handles weapons system design data with 30-year classification. HNDL: Critical.

**Meridian Analytics** — TLS 1.3 (X25519), ECDSA-384 signing, AES-256-GCM. Handles PII with 7-year retention. HNDL: High (ECDSA is still quantum-vulnerable).

**Apex Commercial** — TLS 1.3 with ML-KEM hybrid, ML-DSA signatures, AES-256. 2-year data retention. HNDL: Low (already migrated to hybrid post-quantum).

---

## Architecture

```
crypto_catalog.py       Algorithm database: classical vulnerabilities (Shor/Grover), FIPS status, CNSA 2.0 timeline
assessment_engine.py    Deterministic FIPS 203/204/205 compliance check per algorithm
exposure_engine.py      HNDL exposure rating: data retention period × quantum timeline × algorithm vulnerability
claude_extractor.py     Claude Haiku: plain-language system description → structured cryptographic inventory JSON
claude_roadmap.py       Claude Haiku: assessment results → prioritized migration roadmap
pdf_export.py           ReportLab PDF with DEMO watermark
seed_data.py            3 demo scenarios (Aegis, Meridian, Apex)
models.py               SQLAlchemy ORM (Organization, AlgorithmAssessment, HNDLScore, MigrationRoadmap)
main.py                 FastAPI routes, Jinja rendering, lifespan seed
```

---

## Key Architecture Decisions

**Why compliance and exposure are separate outputs:**
An organization can be "compliant" with current federal guidance while still having critical HNDL exposure — if they're using quantum-vulnerable algorithms on data that needs to stay secret for 20 years, they have a real problem even before the formal deprecation deadline. Same distinction CFIUS Screener makes between jurisdiction (legal question) and risk (security question).

**Natural sibling to ATO Accelerator:**
The ATO Accelerator (P4) helps organizations achieve NIST 800-53 compliance. Harvest Horizon does the same for the post-quantum transition. Same pattern: Claude extracts the inventory, deterministic rules against published standards run the assessment, Claude explains the results. Completely different technical content.

**What this tool does not do:**
- Does not implement any cryptography
- Does not break or analyze real cryptosystems
- Does not perform cryptanalysis
- Does not give legal compliance guidance

This is an inventory and planning assessment tool, the same way the ATO Accelerator helps plan a NIST 800-53 implementation without being a security system itself.

---

## Honest Limitations

- HNDL exposure ratings depend on quantum timeline estimates, which remain uncertain. The tool uses conservative estimates aligned with current NSA/NIST guidance.
- Migration roadmap is a starting point — actual migration requires cryptographic engineering expertise and testing.
- Claude extraction quality depends on the specificity of the system description; vague descriptions produce vague inventories.
- DEMO_MODE=True on Render; the three demo scenarios use pre-baked assessments.

---

## Tests

```bash
venv\Scripts\python.exe -m pytest tests/ -v
# 116 passed
```

Covers: algorithm classification (Shor/Grover vulnerability), FIPS 203/204/205 compliance logic, HNDL exposure scoring (retention × vulnerability matrix), migration priority ordering, Claude inventory parsing, PDF export structure, seed data integrity.

---

*DEMONSTRATION ONLY — cryptographic assessments are for planning purposes only. NIST FIPS 203/204/205 finalized August 2024. Verify current OMB memoranda and agency-specific migration deadlines before implementation.*
