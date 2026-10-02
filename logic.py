"""Pure scoring logic (unit-testable, no framework)."""


def combine_scores(model_prob, rule_score, url_score=None):
    """Ensemble of three signals (each 0-100).
    1. Rules and links combine as a noisy-OR: any strong signal lifts the score, a clean link never dilutes.
    2. If the AI judgement is available it is blended in (55% AI, 45% rules+links).
    3. Strong deterministic evidence can't be talked down by the AI: >=80 floors at 60, >=50 floors at 30. A blocklisted URL forces >=90."""
    safe = 1.0
    for v in (rule_score, url_score):
        if v is not None:
            safe *= 1 - max(0.0, min(100.0, v)) / 100
    base = (1 - safe) * 100
    score = base if model_prob is None else 0.55 * model_prob + 0.45 * base
    if model_prob is not None:
        if base >= 80:
            score = max(score, 60.0)
        elif base >= 50:
            score = max(score, 30.0)  # moderate evidence is never shown as "low risk" just because the AI said so
    if url_score is not None and url_score >= 100:
        score = max(score, 90.0)
    return round(score, 1)


def risk_tier(score: float) -> str:
    return "danger" if score >= 60 else "warning" if score >= 30 else "safe"
