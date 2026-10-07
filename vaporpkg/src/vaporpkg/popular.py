"""Popular-package index used for typosquat / lookalike detection.

The bundled lists are snapshots (see the header line of each data file).  Refresh them with
``python -m vaporpkg.refresh_lists`` or point ``VAPORPKG_DATA_DIR`` at your own copies.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

from .models import Ecosystem, normalize

_SEP = re.compile(r"[-_.]+")

#: Prefixes/suffixes that LLMs (and typosquatters) like to bolt onto real package names.
AFFIX_PREFIXES = ("python-", "py-", "py", "node-", "js-")
AFFIX_SUFFIXES = ("-python", "-py", "py", "-js", "js", ".js", "-node", "-lib", "-sdk", "-api",
                  "-client", "-cli", "-tools", "-utils", "-helper", "-official", "2", "3")


def _data_path(filename: str) -> Path | None:
    override = os.environ.get("VAPORPKG_DATA_DIR")
    if override:
        p = Path(override) / filename
        if p.exists():
            return p
    return None


def _read_list(filename: str) -> list[str]:
    p = _data_path(filename)
    if p is not None:
        text = p.read_text(encoding="utf-8")
    else:
        text = resources.files("vaporpkg").joinpath("data", filename).read_text(encoding="utf-8")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


def osa_distance(a: str, b: str, max_dist: int = 2) -> int:
    """Optimal-string-alignment (restricted Damerau-Levenshtein) distance.

    Returns ``max_dist + 1`` as soon as the distance is known to exceed ``max_dist``.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    prev2: list[int] | None = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
            row_min = min(row_min, v)
        if row_min > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[lb] if prev[lb] <= max_dist else max_dist + 1


class PopularIndex:
    """Rank lookups plus lookalike search over the most-downloaded packages."""

    def __init__(self, lists: dict[Ecosystem, list[str]] | None = None,
                 typo_targets: int = 5000, affix_targets: int = 2000):
        self._lists = lists
        self.typo_targets = typo_targets
        self.affix_targets = affix_targets
        self._rank: dict[Ecosystem, dict[str, int]] = {}
        self._by_len: dict[Ecosystem, dict[int, list[str]]] = {}
        self._stripped: dict[Ecosystem, dict[str, str]] = {}

    def _load(self, eco: Ecosystem) -> None:
        if eco in self._rank:
            return
        if self._lists is not None and eco in self._lists:
            names = self._lists[eco]
        else:
            names = _read_list("top_pypi.txt" if eco is Ecosystem.PYPI else "top_npm.txt")
        ranks: dict[str, int] = {}
        for i, n in enumerate(names, start=1):
            ranks.setdefault(normalize(eco, n), i)
        self._rank[eco] = ranks
        by_len: dict[int, list[str]] = {}
        stripped: dict[str, str] = {}
        for n, r in ranks.items():
            if r > self.typo_targets:
                continue
            by_len.setdefault(len(n), []).append(n)
            stripped.setdefault(_SEP.sub("", n), n)
        self._by_len[eco] = by_len
        self._stripped[eco] = stripped

    def rank(self, eco: Ecosystem, name: str) -> int | None:
        self._load(eco)
        return self._rank[eco].get(normalize(eco, name))

    def is_popular(self, eco: Ecosystem, name: str) -> bool:
        return self.rank(eco, name) is not None

    def lookalike(self, eco: Ecosystem, name: str) -> tuple[str, str, int] | None:
        """Return ``(popular_name, reason, points)`` if *name* imitates a popular package."""
        self._load(eco)
        n = normalize(eco, name)
        if n in self._rank[eco]:
            return None
        # 1) Same letters, different separators: "python_dateutil" vs "python-dateutil" is fine on
        #    PyPI (normalised away) but "pythondateutil" or "date-util" are different projects.
        s = _SEP.sub("", n)
        target = self._stripped[eco].get(s)
        if target and target != n:
            return target, f"same letters as popular '{target}' with different separators", 35
        # 2) Small edit distance to a popular name.
        best: tuple[int, int, str] | None = None
        for length in range(len(n) - 2, len(n) + 3):
            for t in self._by_len[eco].get(length, ()):
                if len(t) < 5:  # very short names collide by chance ("mail" vs "nail")
                    continue
                limit = 1 if len(t) <= 7 else 2
                d = osa_distance(n, t, limit)
                if d <= limit:
                    cand = (d, self._rank[eco][t], t)
                    if best is None or cand < best:
                        best = cand
        if best is not None:
            d, _, t = best
            return t, f"{d} edit{'s' if d > 1 else ''} away from popular '{t}'", 35
        # 3) Popular name with a prefix/suffix bolted on ("requests-python", "py-numpy").
        for pre in AFFIX_PREFIXES:
            if n.startswith(pre):
                base = n[len(pre):]
                r = self._rank[eco].get(base)
                if r is not None and r <= self.affix_targets and len(base) >= 4:
                    return base, f"popular '{base}' with prefix '{pre}' added", 20
        for suf in AFFIX_SUFFIXES:
            if n.endswith(suf):
                base = n[: -len(suf)]
                r = self._rank[eco].get(base)
                if r is not None and r <= self.affix_targets and len(base) >= 4:
                    return base, f"popular '{base}' with suffix '{suf}' added", 20
        return None


@lru_cache(maxsize=1)
def default_index() -> PopularIndex:
    return PopularIndex()
