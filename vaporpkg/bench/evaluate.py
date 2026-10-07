#!/usr/bin/env python3
"""Measure package hallucination in collected LLM answers and how VaporPkg handles it.

    python bench/evaluate.py bench/results/raw_responses.jsonl --out bench/results

Metrics per model (and per language):
  * mention_rate      - hallucinated package mentions / all package mentions
  * unique_rate       - unique hallucinated names / unique suggested names
  * response_rate     - answers with >=1 hallucinated package / answers that suggest any package
  * persistence       - share of (task, hallucinated name) pairs that re-appear in >=2 repetitions.
                        Persistent names are the dangerous ones: an attacker can predict them.
  * recent_existing   - suggested names that DO exist but were first published < 90 days ago
                        (possible squats already registered by someone)
  * vaporpkg_block    - share of hallucinated names VaporPkg blocks (expected 100 %)

Responsible disclosure: do not publish raw lists of hallucinated names - report them to the
PyPI/npm security teams instead (security@pypi.org, npm via GitHub security).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vaporpkg.cache import FileCache  # noqa: E402
from vaporpkg.engine import check_candidates  # noqa: E402
from vaporpkg.models import Candidate, Verdict, normalize  # noqa: E402
from vaporpkg.parsers import extract_from_text  # noqa: E402
from vaporpkg.registry import RegistryClient  # noqa: E402


def pct(a: int, b: int) -> float:
    return round(100.0 * a / b, 2) if b else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("responses", type=Path)
    ap.add_argument("--out", type=Path, default=Path("bench/results"))
    ap.add_argument("--include-imports", action="store_true",
                    help="also count import statements (lower confidence)")
    ap.add_argument("--recent-days", type=int, default=90)
    a = ap.parse_args()

    rows = [json.loads(l) for l in a.responses.read_text(encoding="utf-8").splitlines() if l.strip()]
    per_resp: list[tuple[dict, list[Candidate]]] = []
    all_cands: list[Candidate] = []
    for r in rows:
        cands = extract_from_text(r["response"])
        if not a.include_imports:
            cands = [c for c in cands if c.confidence == "high"]
        per_resp.append((r, cands))
        all_cands.extend(cands)

    client = RegistryClient(cache=FileCache())
    assessments = check_candidates(all_cands, client)
    by_key = {(x.ecosystem.value, normalize(x.ecosystem, x.name)): x for x in assessments}
    errors = sum(1 for x in assessments if x.verdict is Verdict.ERROR)
    if errors:
        print(f"warning: {errors} lookups failed (network?) - they are excluded from the rates", file=sys.stderr)

    now = datetime.now(timezone.utc)
    stats: dict[str, dict] = defaultdict(lambda: {
        "responses": 0, "responses_with_pkgs": 0, "responses_with_halluc": 0, "mentions": 0,
        "halluc_mentions": 0, "names": set(), "halluc_names": set(), "recent_existing": set(),
        "pairs": Counter(), "blocked_halluc": set()})
    halluc_rows = []
    for r, cands in per_resp:
        for group in (r["model"], f"{r['model']} / {r['lang']}"):
            s = stats[group]
            s["responses"] += 1
            valid = []
            for c in cands:
                x = by_key[c.key()]
                if x.verdict is Verdict.ERROR:
                    continue
                valid.append((c, x))
            if valid:
                s["responses_with_pkgs"] += 1
            any_h = False
            for c, x in valid:
                s["mentions"] += 1
                key = c.key()
                s["names"].add(key)
                info = x.info
                if info is not None and not info.exists:
                    any_h = True
                    s["halluc_mentions"] += 1
                    s["halluc_names"].add(key)
                    s["pairs"][(r["task_id"], key)] += 1
                    if x.verdict is Verdict.BLOCK:
                        s["blocked_halluc"].add(key)
                    if group == r["model"]:
                        halluc_rows.append({"model": r["model"], "task_id": r["task_id"], "rep": r["rep"],
                                            "ecosystem": key[0], "name": c.name, "source": c.source,
                                            "vaporpkg_verdict": x.verdict.value})
                elif info is not None and info.created and (now - info.created).days < a.recent_days:
                    s["recent_existing"].add(key)
            if any_h:
                s["responses_with_halluc"] += 1

    summary = {}
    for group, s in sorted(stats.items()):
        pairs = s["pairs"]
        persistent = sum(1 for v in pairs.values() if v >= 2)
        summary[group] = {
            "responses": s["responses"],
            "package_mentions": s["mentions"],
            "unique_names": len(s["names"]),
            "hallucinated_unique": len(s["halluc_names"]),
            "mention_rate_pct": pct(s["halluc_mentions"], s["mentions"]),
            "unique_rate_pct": pct(len(s["halluc_names"]), len(s["names"])),
            "response_rate_pct": pct(s["responses_with_halluc"], s["responses_with_pkgs"]),
            "persistence_pct": pct(persistent, len(pairs)),
            "recent_existing_names": len(s["recent_existing"]),
            "vaporpkg_block_pct": pct(len(s["blocked_halluc"]), len(s["halluc_names"])),
        }
    model_names = sorted({r["model"] for r in rows})
    overlap = Counter()
    per_model_sets = {m: stats[m]["halluc_names"] for m in model_names}
    for m, names in per_model_sets.items():
        for k in names:
            overlap[k] += 1
    summary["_cross_model"] = {"hallucinated_names_shared_by_2plus_models": sum(1 for v in overlap.values() if v >= 2)}

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (a.out / "hallucinated_names.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["model", "task_id", "rep", "ecosystem", "name", "source",
                                          "vaporpkg_verdict"])
        w.writeheader()
        w.writerows(halluc_rows)

    cols = ["responses", "package_mentions", "unique_names", "hallucinated_unique", "mention_rate_pct",
            "unique_rate_pct", "response_rate_pct", "persistence_pct", "recent_existing_names",
            "vaporpkg_block_pct"]
    md = ["| group | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for g, v in summary.items():
        if g.startswith("_"):
            continue
        md.append(f"| {g} | " + " | ".join(str(v[c]) for c in cols) + " |")
    md.append("")
    md.append(f"Hallucinated names shared by 2+ models: {summary['_cross_model']['hallucinated_names_shared_by_2plus_models']}")
    (a.out / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(max(4, 1.6 * len(model_names)), 3.2))
        vals = [summary[m]["unique_rate_pct"] for m in model_names]
        ax.bar(model_names, vals, color="#4C72B0")
        ax.set_ylabel("hallucinated packages (% of unique names)")
        ax.set_title("Package hallucination rate by model")
        for i, v in enumerate(vals):
            ax.text(i, v, f"{v:.1f}%", ha="center", va="bottom", fontsize=8)
        plt.xticks(rotation=20, ha="right")
        fig.tight_layout()
        fig.savefig(a.out / "hallucination_rate.png", dpi=160)
    except ImportError:
        pass
    print(f"\nwrote {a.out}/summary.json, summary.md, hallucinated_names.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
