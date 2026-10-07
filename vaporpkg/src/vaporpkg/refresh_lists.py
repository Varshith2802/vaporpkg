"""Refresh the popular-package lists used for lookalike detection.

    python -m vaporpkg.refresh_lists --out ~/.local/share/vaporpkg
    export VAPORPKG_DATA_DIR=~/.local/share/vaporpkg
"""
from __future__ import annotations

import argparse
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

TOP_PYPI = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search?"
NPM_KEYWORDS = (
    "react vue angular svelte cli test eslint babel webpack typescript http server express util string "
    "array date time json parser css color logger stream file fs path promise async crypto hash uuid "
    "validation schema database sql mongo redis aws cloud api graphql auth jwt oauth image svg chart "
    "markdown html dom browser polyfill jest mock lint format prettier build bundle rollup vite node npm "
    "config env debug error event queue cache fetch axios websocket socket email template i18n math "
    "object merge clone diff glob watch terminal ansi prompt progress args command yaml xml csv zip "
    "compress buffer types next nuxt rxjs redux state router form ui components icons animation ai "
    "openai llm postcss tailwind sass storybook prisma orm mysql postgres firebase google azure docker "
    "git semver regex url cookie session cors middleware proxy security pdf video audio").split()


def _get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "vaporpkg-refresh"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def refresh_pypi(out: Path, n: int) -> int:
    d = _get_json(TOP_PYPI)
    names = [re.sub(r"[-_.]+", "-", r["project"]).lower() for r in d["rows"][:n]]
    (out / "top_pypi.txt").write_text(
        f"# Top PyPI projects (hugovk/top-pypi-packages, {d.get('last_update', '')[:10]})\n" + "\n".join(names) + "\n",
        encoding="utf-8")
    return len(names)


def refresh_npm(out: Path, n: int) -> int:
    seen: dict[str, int] = {}
    for kw in NPM_KEYWORDS:
        q = urllib.parse.urlencode({"text": f"keywords:{kw}", "popularity": "1.0", "quality": "0.0",
                                    "maintenance": "0.0", "size": "250"})
        try:
            d = _get_json(NPM_SEARCH + q)
        except Exception as e:  # keep going on transient errors
            print(f"warning: {kw}: {e}")
            continue
        for o in d.get("objects", []):
            name = o["package"]["name"]
            weekly = (o.get("downloads") or {}).get("weekly", 0) or 0
            seen[name] = max(seen.get(name, 0), weekly)
        time.sleep(0.2)
    ranked = [k for k, _ in sorted(seen.items(), key=lambda kv: -kv[1])][:n]
    (out / "top_npm.txt").write_text(
        f"# Popular npm packages by weekly downloads (npm search API, {date.today()})\n" + "\n".join(ranked) + "\n",
        encoding="utf-8")
    return len(ranked)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path.home() / ".local" / "share" / "vaporpkg")
    ap.add_argument("-n", type=int, default=15000)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    print("pypi:", refresh_pypi(a.out, a.n))
    print("npm:", refresh_npm(a.out, a.n))
    print(f"done - now set VAPORPKG_DATA_DIR={a.out}")


if __name__ == "__main__":
    main()
