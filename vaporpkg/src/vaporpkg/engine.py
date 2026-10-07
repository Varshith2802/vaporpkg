"""Glue: candidates -> registry lookups -> assessments."""
from __future__ import annotations

from .models import Assessment, Candidate
from .popular import PopularIndex
from .registry import RegistryClient
from .scoring import Policy, assess


def check_candidates(candidates: list[Candidate], client: RegistryClient,
                     policy: Policy | None = None, popular: PopularIndex | None = None) -> list[Assessment]:
    popular = popular or client.popular
    groups: dict[tuple[str, str], list[Candidate]] = {}
    for c in candidates:
        groups.setdefault(c.key(), []).append(c)
    infos = client.lookup_many((cs[0].ecosystem, cs[0].name) for cs in groups.values())
    results: list[Assessment] = []
    for key, cs in groups.items():
        info = infos[key]
        low_only = all(c.confidence == "low" for c in cs)
        a = assess(info, popular, policy, low_confidence_only=low_only)
        a.name = cs[0].name
        a.candidates = cs
        results.append(a)
    results.sort(key=lambda a: (-a.verdict.rank, -a.score, a.name.lower()))
    return results
