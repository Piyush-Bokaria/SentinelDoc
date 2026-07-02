TIER_WEIGHT = {"high": 3, "medium": 2, "low": 1}

# Thresholds - tune these after testing on real sample docs
HIGH_RISK_THRESHOLD = 15
MEDIUM_RISK_THRESHOLD = 5


def calculate_risk(detection_result: dict) -> dict:
    """
    Deterministic, explainable risk scoring - deliberately NOT LLM-judged,
    so the risk level is auditable and reproducible for compliance purposes.
    """
    tier_counts = detection_result["counts_by_tier"]

    score = sum(TIER_WEIGHT.get(tier, 1) * count for tier, count in tier_counts.items())

    if score >= HIGH_RISK_THRESHOLD:
        level = "High Risk"
    elif score >= MEDIUM_RISK_THRESHOLD:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return {
        "risk_score": score,
        "risk_level": level,
        "breakdown": {
            "high_risk_findings": tier_counts.get("high", 0),
            "medium_risk_findings": tier_counts.get("medium", 0),
            "low_risk_findings": tier_counts.get("low", 0),
        },
        "explanation": (
            f"Score = (high×3) + (medium×2) + (low×1) = "
            f"({tier_counts.get('high', 0)}×3) + ({tier_counts.get('medium', 0)}×2) + "
            f"({tier_counts.get('low', 0)}×1) = {score}"
        ),
    }