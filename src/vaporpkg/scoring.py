"""Turns registry metadata into an explainable risk score and a verdict."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .models import CRITICAL, Assessment, Ecosystem, PackageInfo, Signal, Verdict
from .popular import PopularIndex

ECO_LABEL = {Ecosystem.PYPI: "PyPI", Ecosystem.NPM: "npm"}
#: Signals that are never softened by the popularity cap.
UNCAPPED = {"MALICIOUS_VERSIONS"}


@dataclass
class Policy:
    block_threshold: int = 70
    warn_threshold: int = 30
    very_new_days: int = 14
    new_days: int = 90
    popular_cap: int = 20  # max score for packages in the popular list (unless critical)


def assess(info: PackageInfo, popular: PopularIndex, policy: Policy | None = None,
           now: datetime | None = None, low_confidence_only: bool = False) -> Assessment:
    policy = policy or Policy()
    now = now or datetime.now(timezone.utc)
    eco, name = info.ecosystem, info.name
    reg = ECO_LABEL[eco]
    signals: list[Signal] = []
    look = popular.lookalike(eco, name)
    lookalike = look[0] if look else None

    if info.lookup_error:
        signals.append(Signal("LOOKUP_FAILED", 0, f"Could not query {reg}: {info.lookup_error}"))
        return Assessment(eco, name, Verdict.ERROR, 0, signals, info, lookalike)

    if not info.exists:
        if info.status == "quarantined":
            signals.append(Signal("QUARANTINED", CRITICAL,
                                  "PyPI administrators quarantined this project (suspected malware)."))
        if info.malicious_advisories:
            signals.append(Signal("KNOWN_MALICIOUS", CRITICAL,
                                  "Previously published as malware: " + ", ".join(info.malicious_advisories[:3])))
        if info.status == "no-releases":
            msg = (f"'{name}' is registered on {reg} but has no installable releases (deleted or "
                   f"placeholder); whoever owns the name can publish code under it at any time.")
        elif info.status == "unpublished":
            msg = f"'{name}' was unpublished from {reg}; the name may be re-registered by anyone."
        else:
            msg = (f"'{name}' does not exist on {reg}. AI assistants often invent package names; attackers "
                   f"register them with malware ('slopsquatting'). Check the library's official docs.")
        if lookalike:
            msg += f" Did you mean '{lookalike}'?"
        if low_confidence_only and not info.malicious_advisories and info.status != "quarantined":
            # Derived from an import statement: the distribution may simply have another name.
            signals.append(Signal("IMPORT_NOT_ON_REGISTRY", policy.warn_threshold,
                                  f"Module '{name}' is imported but no {reg} project has that name. "
                                  "The distribution may use a different name - verify before installing."))
        else:
            signals.append(Signal("NOT_FOUND", CRITICAL, msg))
        return _finish(eco, name, signals, info, lookalike, policy, popular_rank=None)

    if info.security_holding:
        signals.append(Signal("SECURITY_HOLDING", CRITICAL,
                              "npm replaced this package with a security placeholder (it was malicious)."))
    if info.status == "quarantined":
        signals.append(Signal("QUARANTINED", CRITICAL, "PyPI administrators quarantined this project."))
    rank = popular.rank(eco, name)
    if info.malicious_advisories:
        if rank is not None:
            signals.append(Signal("MALICIOUS_VERSIONS", 40,
                                  "Malicious versions were published (possible account takeover): "
                                  + ", ".join(info.malicious_advisories[:3]) + ". Pin a known-good version."))
        else:
            signals.append(Signal("KNOWN_MALICIOUS", CRITICAL,
                                  "Listed in the OpenSSF malicious-packages database: "
                                  + ", ".join(info.malicious_advisories[:3])))

    full = info.metadata_complete
    if info.created is None:
        if full:
            signals.append(Signal("AGE_UNKNOWN", 5, "Could not determine when the project was first published."))
    else:
        age = (now - info.created).days
        if age < policy.very_new_days:
            signals.append(Signal("VERY_NEW", 45, f"First published only {age} day(s) ago."))
        elif age < policy.new_days:
            signals.append(Signal("NEW", 25, f"First published {age} days ago."))

    if info.release_count == 1:
        signals.append(Signal("SINGLE_RELEASE", 15, "Only one release has ever been published."))
    elif info.release_count == 2:
        signals.append(Signal("FEW_RELEASES", 8, "Only two releases have been published."))

    if info.weekly_downloads is not None:
        if info.weekly_downloads < 50:
            signals.append(Signal("VERY_LOW_DOWNLOADS", 20, f"Only {info.weekly_downloads} downloads last week."))
        elif info.weekly_downloads < 1000:
            signals.append(Signal("LOW_DOWNLOADS", 10, f"{info.weekly_downloads} downloads last week."))

    if full and not info.repo_url:
        signals.append(Signal("NO_REPOSITORY", 12, "No source repository is linked."))
    if full and not info.summary:
        signals.append(Signal("NO_DESCRIPTION", 8, "No description."))
    if info.install_scripts:
        signals.append(Signal("INSTALL_SCRIPTS", 15,
                              "Runs code during installation (" + ", ".join(info.install_scripts) + ")."))
    if info.deprecated or info.status in ("deprecated", "archived"):
        signals.append(Signal("DEPRECATED", 10, f"Marked {info.status or 'deprecated'} by its maintainers."))
    if look:
        target, reason, pts = look
        signals.append(Signal("LOOKALIKE", pts, f"Name looks like a typo/variant: {reason}."))
    if info.organization:
        signals.append(Signal("VERIFIED_ORG", -10, f"Owned by PyPI organization '{info.organization}'."))
    if rank is not None:
        signals.append(Signal("POPULAR", 0, f"Among the most downloaded {reg} packages (rank #{rank})."))
    return _finish(eco, name, signals, info, lookalike, policy, popular_rank=rank)


def _finish(eco: Ecosystem, name: str, signals: list[Signal], info: PackageInfo, lookalike: str | None,
            policy: Policy, popular_rank: int | None) -> Assessment:
    critical = any(s.points >= CRITICAL for s in signals)
    heuristic = sum(s.points for s in signals if s.code not in UNCAPPED)
    hard = sum(s.points for s in signals if s.code in UNCAPPED)
    if popular_rank is not None and not critical:
        # Popular packages legitimately have install scripts, single maintainers, etc.
        heuristic = min(heuristic, policy.popular_cap)
    score = max(0, min(100, heuristic + hard))
    if critical:
        verdict, score = Verdict.BLOCK, 100
    elif score >= policy.block_threshold:
        verdict = Verdict.BLOCK
    elif score >= policy.warn_threshold:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.OK
    return Assessment(eco, name, verdict, score, signals, info, lookalike)
