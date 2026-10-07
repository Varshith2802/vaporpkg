"""Core data types shared across VaporPkg."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"


class Verdict(str, Enum):
    OK = "OK"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"

    @property
    def rank(self) -> int:
        return {"OK": 0, "WARN": 1, "ERROR": 1, "BLOCK": 2}[self.value]


#: Signals with this severity (or higher) block the install regardless of score.
CRITICAL = 100


@dataclass
class Signal:
    """One piece of evidence about a package, with the points it adds to the risk score."""

    code: str
    points: int
    message: str


@dataclass
class PackageInfo:
    """Registry metadata normalised across ecosystems."""

    ecosystem: Ecosystem
    name: str
    exists: bool
    created: datetime | None = None
    latest_release: datetime | None = None
    release_count: int = 0
    latest_version: str | None = None
    summary: str = ""
    repo_url: str | None = None
    homepage: str | None = None
    maintainers: list[str] = field(default_factory=list)
    organization: str | None = None
    weekly_downloads: int | None = None
    install_scripts: list[str] = field(default_factory=list)
    deprecated: bool = False
    status: str | None = None  # PyPI project status (PEP 792): active/archived/quarantined/deprecated
    security_holding: bool = False  # npm replaced the package because it was malicious
    malicious_advisories: list[str] = field(default_factory=list)
    lookup_error: str | None = None
    #: False when only abbreviated registry metadata was fetched (age/repo/description unknown).
    metadata_complete: bool = True


@dataclass
class Candidate:
    """A package name found in a file, a command line or LLM output."""

    ecosystem: Ecosystem
    name: str
    source: str = "cli"  # cli | requirements | pyproject | package.json | pip-command | npm-command | import | require
    location: str | None = None  # file path
    line: int | None = None
    context: str | None = None
    confidence: str = "high"  # high | low (low = derived from an import statement)

    def key(self) -> tuple[str, str]:
        return (self.ecosystem.value, normalize(self.ecosystem, self.name))


@dataclass
class Assessment:
    ecosystem: Ecosystem
    name: str
    verdict: Verdict
    score: int
    signals: list[Signal]
    info: PackageInfo | None = None
    lookalike: str | None = None
    candidates: list[Candidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ecosystem": self.ecosystem.value,
            "name": self.name,
            "verdict": self.verdict.value,
            "score": self.score,
            "signals": [asdict(s) for s in self.signals],
            "lookalike": self.lookalike,
        }
        if self.info is not None:
            info = asdict(self.info)
            info["ecosystem"] = self.info.ecosystem.value
            for k in ("created", "latest_release"):
                if info[k] is not None:
                    info[k] = info[k].isoformat()
            d["metadata"] = info
        if self.candidates:
            d["found_in"] = [
                {"source": c.source, "location": c.location, "line": c.line, "confidence": c.confidence}
                for c in self.candidates
            ]
        return d


_PEP503 = re.compile(r"[-_.]+")


def normalize(ecosystem: Ecosystem, name: str) -> str:
    """Canonical form used for comparisons and caching.

    PyPI names are normalised per PEP 503 (case-insensitive, runs of -_. are equivalent).
    npm names are case-sensitive in theory, but new names must be lowercase, so we lowercase.
    """
    name = name.strip()
    if ecosystem is Ecosystem.PYPI:
        return _PEP503.sub("-", name).lower()
    return name.lower()
