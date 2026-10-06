def severity_for(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"

def combine_scores(scores: list[int]) -> int:
    """Combine evidence without allowing risk to exceed 100."""
    return min(100, sum(scores))
