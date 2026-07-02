from collections import Counter
from presidio_analyzer import RecognizerResult
from app.detection.analyzer import get_analyzer, ALL_ENTITIES

# Map entity types to risk tiers - used by the scorer downstream
ENTITY_RISK_TIER = {
    "AADHAAR_NUMBER": "high",
    "PAN_NUMBER": "high",
    "CREDIT_CARD": "high",
    "API_KEY": "high",
    "PASSWORD": "high",
    "IBAN_CODE": "high",
    "BANK_ACCOUNT_NUMBER": "high",
    "IFSC_CODE": "medium",
    "EMAIL_ADDRESS": "medium",
    "PHONE_NUMBER": "medium",
    "EMPLOYEE_ID": "medium",
    "IP_ADDRESS": "medium",
    "PERSON": "low",
    "LOCATION": "low",
    "US_SSN": "high",
}

MIN_CONFIDENCE = 0.4  # drop low-confidence noise (e.g. bare 9-18 digit numbers without context)

def _truncate_at_newline(start: int, end: int, text: str) -> tuple[int, int]:
    """spaCy NER sometimes spans across newlines when there's no punctuation boundary.
    Truncate any finding's span at the first newline it contains."""
    raw = text[start:end]
    if "\n" in raw:
        end = start + raw.index("\n")
    return start, end

def mask_value(value: str, entity_type: str) -> str:
    """Produce a masked preview - never expose raw sensitive value in reports/API responses."""
    if len(value) <= 4:
        return "*" * len(value)
    if entity_type in ("EMAIL_ADDRESS",):
        local, _, domain = value.partition("@")
        return f"{local[:2]}{'*' * max(len(local) - 2, 1)}@{domain}"
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def detect_sensitive_data(text: str) -> dict:
    """Run Presidio analysis over text and return normalized, risk-tagged findings."""
    analyzer = get_analyzer()
    results: list[RecognizerResult] = analyzer.analyze(
        text=text, entities=ALL_ENTITIES, language="en"
    )

    findings = []
    for r in results:
        if r.score < MIN_CONFIDENCE:
            continue
        start, end = _truncate_at_newline(r.start, r.end, text)
        if end <= start:
            continue
        raw_value = text[start:end]
        findings.append({
            "entity_type": r.entity_type,
            "risk_tier": ENTITY_RISK_TIER.get(r.entity_type, "low"),
            "start": start,
            "end": end,
            "confidence": round(r.score, 2),
            "masked_value": mask_value(raw_value, r.entity_type),
        })

    # Dedup overlapping spans of the same entity type (Presidio can sometimes double-match)
    findings = _dedupe(findings)

    counts = Counter(f["entity_type"] for f in findings)
    tier_counts = Counter(f["risk_tier"] for f in findings)

    return {
        "findings": findings,
        "counts_by_type": dict(counts),
        "counts_by_tier": dict(tier_counts),
        "total_findings": len(findings),
    }


def _spans_overlap(a: dict, b: dict) -> bool:
    return not (a["end"] <= b["start"] or b["end"] <= a["start"])


def _dedupe(findings: list[dict]) -> list[dict]:
    """
    Keep the highest-confidence finding for any overlapping span (partial or full).
    This prevents corrupted redaction when two recognizers claim overlapping text
    (e.g. a generic BANK_ACCOUNT_NUMBER pattern matching inside a PHONE_NUMBER).
    """
    candidates = sorted(findings, key=lambda x: (-x["confidence"], x["start"]))
    kept: list[dict] = []
    for f in candidates:
        if not any(_spans_overlap(f, k) for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda x: x["start"])
    """
    Remove exact duplicate spans, then suppress lower-confidence findings
    whose span is fully contained within a higher-confidence finding's span
    (e.g. a generic BANK_ACCOUNT_NUMBER match sitting inside a PHONE_NUMBER match).
    """
    # Step 1: exact-span dedup (keep highest confidence per identical span)
    seen = {}
    for f in findings:
        key = (f["entity_type"], f["start"], f["end"])
        if key not in seen or f["confidence"] > seen[key]["confidence"]:
            seen[key] = f
    candidates = sorted(seen.values(), key=lambda x: (-x["confidence"], x["start"]))

    # Step 2: suppress spans contained within a higher-confidence span of a different type
    final = []
    for f in candidates:
        contained = any(
            other is not f
            and other["start"] <= f["start"]
            and other["end"] >= f["end"]
            and other["confidence"] >= f["confidence"]
            and not (other["start"] == f["start"] and other["end"] == f["end"])
            for other in final
        )
        if not contained:
            final.append(f)

    return sorted(final, key=lambda x: x["start"])