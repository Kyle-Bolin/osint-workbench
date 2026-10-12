"""A claim is one sourced fact: subject -predicate-> object, with a confidence.

Every module returns claims instead of raw output, so the UI, a future pivot
graph, and an AI agent all read the same shape.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Claim:
    subject: str
    predicate: str
    object: str
    source: str
    confidence: float
    rationale: str = ""
    evidence_url: str = ""
    found_by: str = "me"
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)


# Base confidence by kind of source. Scores come from these rules, never
# from a model guessing a number.
BASE_CONFIDENCE = {
    "authoritative": 0.95,  # DNS answers, registry data
    "log": 0.9,             # certificate transparency logs
    "weak": 0.4,            # correlations like a matching username
    "inference": 0.3,       # anything without a direct source
}


def combine(*scores: float) -> float:
    """Noisy-OR: independent sources that agree raise confidence."""
    remaining = 1.0
    for s in scores:
        remaining *= 1.0 - s
    return round(1.0 - remaining, 3)
