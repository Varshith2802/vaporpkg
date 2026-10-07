"""Human, JSON and SARIF output."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .models import Assessment, Verdict

_COLORS = {Verdict.BLOCK: "\033[1;31m", Verdict.WARN: "\033[1;33m", Verdict.ERROR: "\033[1;35m",
           Verdict.OK: "\033[32m"}
_RESET = "\033[0m"
_DIM = "\033[2m"


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def summary_counts(results: list[Assessment]) -> dict[str, int]:
    counts = {v.value: 0 for v in Verdict}
    for a in results:
        counts[a.verdict.value] += 1
    return counts


def format_table(results: list[Assessment], color: bool = False, verbose: bool = False) -> str:
    if not results:
        return "No packages found."
    name_w = min(40, max(len(a.name) for a in results))
    lines = []
    for a in results:
        v = a.verdict.value.ljust(5)
        if color:
            v = f"{_COLORS[a.verdict]}{v}{_RESET}"
        headline = _headline(a)
        low = " (from import)" if a.candidates and all(c.confidence == "low" for c in a.candidates) else ""
        lines.append(f"{v}  {a.ecosystem.value:<4}  {a.name:<{name_w}}  {a.score:>3}  {headline}{low}")
        if verbose:
            for s in a.signals:
                pts = f"{s.points:+d}" if s.points else " 0"
                row = f"        {pts:>4}  {s.code}: {s.message}"
                lines.append(f"{_DIM}{row}{_RESET}" if color else row)
            for c in a.candidates:
                if c.location:
                    where = f"{c.location}:{c.line}" if c.line else c.location
                    row = f"              found in {where}"
                    lines.append(f"{_DIM}{row}{_RESET}" if color else row)
    counts = summary_counts(results)
    lines.append("")
    lines.append(f"{len(results)} package(s) checked: {counts['BLOCK']} blocked, {counts['WARN']} warning(s), "
                 f"{counts['ERROR']} lookup error(s), {counts['OK']} ok")
    return "\n".join(lines)


def _headline(a: Assessment) -> str:
    if not a.signals:
        return "no risk signals"
    ranked = sorted(a.signals, key=lambda s: -s.points)
    top = [s for s in ranked if s.points > 0][:2] or ranked[:1]
    return " ".join(s.message for s in top)


def to_json(results: list[Assessment]) -> str:
    return json.dumps({"tool": "vaporpkg", "version": __version__, "summary": summary_counts(results),
                       "results": [a.to_dict() for a in results]}, indent=2)


def to_sarif(results: list[Assessment], base: Path | None = None) -> str:
    base = base or Path.cwd()
    rules: dict[str, dict[str, Any]] = {}
    sarif_results = []
    for a in results:
        if a.verdict not in (Verdict.BLOCK, Verdict.WARN):
            continue
        primary = max(a.signals, key=lambda s: s.points)
        rules.setdefault(primary.code, {
            "id": primary.code,
            "name": primary.code.title().replace("_", ""),
            "shortDescription": {"text": primary.code.replace("_", " ").lower()},
            "helpUri": "https://github.com/",
        })
        for c in a.candidates:
            if not c.location:
                continue
            try:
                uri = Path(c.location).resolve().relative_to(base.resolve()).as_posix()
            except ValueError:
                uri = Path(c.location).as_posix()
            loc: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if c.line:
                loc["region"] = {"startLine": c.line}
            sarif_results.append({
                "ruleId": primary.code,
                "level": "error" if a.verdict is Verdict.BLOCK else "warning",
                "message": {"text": f"[{a.ecosystem.value}] {a.name}: " + _headline(a)},
                "locations": [{"physicalLocation": loc}],
                "properties": {"score": a.score, "verdict": a.verdict.value},
            })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VaporPkg", "version": __version__, "informationUri": "https://github.com/",
                                "rules": list(rules.values())}},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)
