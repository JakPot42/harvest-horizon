"""claude_extractor.py — Claude extracts structured crypto inventory from free text.

Claude's role here: parse natural-language descriptions of cryptographic configurations
into a structured list of algorithm entries. Claude does NOT classify algorithms
or make compliance determinations — that is the exclusive role of assessment_engine.py.

In DEMO_MODE, returns pre-baked extraction without calling the API.
"""

from __future__ import annotations

import json
import re

import anthropic

from config import ANTHROPIC_API_KEY, CLAUDE_MAX_TOKENS, CLAUDE_MODEL, DEMO_MODE


class ExtractorError(Exception):
    pass


_SYSTEM_PROMPT = """You are a cryptographic inventory extractor for a compliance assessment tool.

Your ONLY job is to extract structured algorithm entries from a natural-language description
of an organization's cryptographic footprint. You do NOT classify algorithms, assess compliance,
or provide recommendations — those tasks belong to a separate deterministic engine.

For each cryptographic algorithm or protocol mentioned, output one JSON object with:
  - component: the system or function using this algorithm (e.g., "TLS 1.2 connections", "Code signing", "X.509 certificates", "Storage encryption")
  - algorithm: the specific algorithm name as mentioned or implied (e.g., "RSA-2048", "ECDHE-P256", "AES-256-GCM", "ML-KEM-768")
  - use_case: one of: "Key Exchange", "Key Encapsulation", "Digital Signature", "Symmetric Encryption", "Hash Function", "MAC", "Certificate", "Other"
  - key_size: integer key size in bits if mentioned or implied, null otherwise

Output ONLY a JSON array. No explanation, no markdown, no commentary.
Example:
[
  {"component": "TLS 1.2", "algorithm": "RSA-2048", "use_case": "Key Exchange", "key_size": 2048},
  {"component": "TLS 1.2", "algorithm": "AES-128-GCM", "use_case": "Symmetric Encryption", "key_size": 128},
  {"component": "Code signing", "algorithm": "ECDSA-P256", "use_case": "Digital Signature", "key_size": 256}
]"""


def extract_crypto_inventory(footprint_description: str, demo_key: str | None = None) -> list[dict]:
    """Extract structured algorithm inventory from a crypto footprint description.

    In DEMO_MODE, uses pre-baked extraction keyed by demo_key.
    In live mode, calls Claude Haiku.

    Returns: list of dicts with keys: component, algorithm, use_case, key_size
    """
    if DEMO_MODE and demo_key is not None:
        from seed_data import DEMO_EXTRACTIONS
        items = DEMO_EXTRACTIONS.get(demo_key, [])
        if items:
            return items

    if not ANTHROPIC_API_KEY:
        raise ExtractorError(
            "ANTHROPIC_API_KEY is not set. Set it as an environment variable or "
            "enable DEMO_MODE to use pre-baked extraction results."
        )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Extract all cryptographic algorithms from this description:\n\n"
                        + footprint_description
                    ),
                }
            ],
        )
        raw = msg.content[0].text.strip()
        return _parse_json_response(raw)
    except ExtractorError:
        raise
    except Exception as exc:
        raise ExtractorError(f"Claude API error during extraction: {exc}") from exc


def _parse_json_response(raw: str) -> list[dict]:
    """Parse Claude's JSON response, stripping any accidental markdown."""
    text = raw.strip()
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExtractorError(f"Claude returned invalid JSON: {exc}\nRaw: {raw[:300]}") from exc

    if not isinstance(parsed, list):
        raise ExtractorError(f"Expected JSON array, got {type(parsed).__name__}")

    validated = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        validated.append({
            "component": str(item.get("component", "Unknown")),
            "algorithm": str(item.get("algorithm", "")),
            "use_case": str(item.get("use_case", "")),
            "key_size": item.get("key_size"),
        })
    return validated
