#!/usr/bin/env python3
"""Alert-rate (false-positive) evaluation on real, existing packages.

Cohorts
  popular-pypi / popular-npm : random sample from the bundled most-downloaded lists
  random-pypi                : uniform random sample of ALL PyPI project names (outside the top list)
  longtail-npm               : npm packages outside the top list (bench/data/npm_longtail.txt)

    python bench/fp_eval.py --popular 300 --random-pypi 300 --longtail-npm 300 --out bench/results/alerts

Real packages that get WARN/BLOCK are not necessarily false positives (the random PyPI cohort contains
abandoned, empty and even malicious projects), so the script also writes every flagged package with its
reasons for manual review.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vaporpkg.cache import FileCache  # noqa: E402
from vaporpkg.models import Ecosystem, Verdict  # noqa: E402
from vaporpkg.popular import _read_list, default_index  # noqa: E402
from vaporpkg.registry import RegistryClient  # noqa: E402
from vaporpkg.scoring import assess  # noqa: E402

SIMPLE_INDEX = "https://pypi.org/simple/"


def random_pypi_names(n: int, rng: random.Random, exclude: set[str]) -> list[str]:
    req = urllib.request.Request(SIMPLE_INDEX, headers={"Accept": "application/vnd.pypi.simple.v1+json",
                                                        "User-Agent": "vaporpkg-bench"})
    with urllib.request.urlopen(req, timeout=120) as r:
        projects = [p["name"] for p in json.load(r)["projects"]]
    pool = [p for p in projects if p.lower() not in exclude]
    return rng.sample(pool, n)


def run_cohort(name: str, eco: Ecosystem, names: list[str], client: RegistryClient) -> dict:
    popular = client.popular
    verdicts: Counter = Counter()
    signals: Counter = Counter()
    latencies: list[float] = []
    flagged = []
    for n in names:
        t0 = time.perf_counter()
        info = client.lookup(eco, n)
        latencies.append(time.perf_counter() - t0)
        a = assess(info, popular)
        verdicts[a.verdict.value] += 1
        for s in a.signals:
            if s.points > 0:
                signals[s.code] += 1
        if a.verdict in (Verdict.WARN, Verdict.BLOCK):
            flagged.append({"name": n, "verdict": a.verdict.value, "score": a.score,
                            "signals": [s.code for s in a.signals if s.points > 0]})
    total = len(names)
    return {
        "cohort": name, "ecosystem": eco.value, "n": total,
        "pct": {v: round(100 * verdicts.get(v, 0) / total, 1) for v in ("OK", "WARN", "BLOCK", "ERROR")},
        "top_signals": signals.most_common(8),
        "latency_ms": {"median": round(1000 * statistics.median(latencies), 1),
                       "p95": round(1000 * sorted(latencies)[int(0.95 * (total - 1))], 1)},
        "flagged": flagged,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--popular", type=int, default=200, help="sample size per ecosystem from the top lists")
    ap.add_argument("--random-pypi", type=int, default=200)
    ap.add_argument("--longtail-npm", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--no-downloads", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("bench/results/alerts"))
    a = ap.parse_args()

    rng = random.Random(a.seed)
    client = RegistryClient(cache=FileCache(enabled=False), use_osv=not a.no_osv,
                            use_downloads=not a.no_downloads)
    idx = default_index()
    top_pypi = _read_list("top_pypi.txt")
    top_npm = _read_list("top_npm.txt")
    results = []
    if a.popular:
        results.append(run_cohort("popular-pypi", Ecosystem.PYPI, rng.sample(top_pypi, a.popular), client))
        results.append(run_cohort("popular-npm", Ecosystem.NPM, rng.sample(top_npm, a.popular), client))
    if a.random_pypi:
        names = random_pypi_names(a.random_pypi, rng, {n.lower() for n in top_pypi})
        results.append(run_cohort("random-pypi", Ecosystem.PYPI, names, client))
    if a.longtail_npm:
        lt = [l.strip() for l in (ROOT / "bench" / "data" / "npm_longtail.txt").read_text().splitlines()
              if l.strip() and not l.startswith("#") and not idx.is_popular(Ecosystem.NPM, l.strip())]
        results.append(run_cohort("longtail-npm", Ecosystem.NPM, rng.sample(lt, min(a.longtail_npm, len(lt))),
                                  client))

    a.out.mkdir(parents=True, exist_ok=True)
    meta = {"seed": a.seed, "osv": not a.no_osv, "downloads": not a.no_downloads,
            "date": time.strftime("%Y-%m-%d")}
    (a.out / "alert_rates.json").write_text(json.dumps({"meta": meta, "cohorts": results}, indent=2))
    lines = ["| cohort | n | OK % | WARN % | BLOCK % | ERROR % | median ms | top signals |", "|---|---|---|---|---|---|---|---|"]
    for r in results:
        p = r["pct"]
        top = ", ".join(f"{c} ({k})" for c, k in r["top_signals"][:4])
        lines.append(f"| {r['cohort']} | {r['n']} | {p['OK']} | {p['WARN']} | {p['BLOCK']} | {p['ERROR']} | "
                     f"{r['latency_ms']['median']} | {top} |")
    (a.out / "alert_rates.md").write_text("\n".join(lines) + f"\n\nSettings: {meta}\n")
    print("\n".join(lines))
    print(f"\nSettings: {meta}\nwrote {a.out}/alert_rates.json and alert_rates.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
