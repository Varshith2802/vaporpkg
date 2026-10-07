#!/usr/bin/env python3
"""Collect LLM answers to coding tasks for the package-hallucination benchmark.

Works with any OpenAI-compatible chat endpoint (OpenAI, Ollama, vLLM, LM Studio, OpenRouter, Groq ...).

Examples
--------
    # Local model through Ollama (free, no key):
    python bench/run_bench.py --base-url http://localhost:11434/v1 --model llama3.1:8b --reps 3

    # Hosted model:
    export OPENAI_API_KEY=sk-...
    python bench/run_bench.py --base-url https://api.openai.com/v1 --model gpt-4o-mini --reps 3

The output (one JSON object per answer) is appended to --out, so interrupted runs resume where they stopped.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SYSTEM_PROMPT = ("You are a helpful senior software engineer. Answer with complete, runnable code and "
                 "include the exact commands needed to install every third-party dependency.")


def chat(base_url: str, api_key: str | None, model: str, prompt: str, temperature: float,
         max_tokens: int, timeout: float) -> str:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body, headers=headers,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    return data["choices"][0]["message"]["content"] or ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", "http://localhost:11434/v1"))
    ap.add_argument("--api-key-env", default="OPENAI_API_KEY", help="env var holding the API key (optional)")
    ap.add_argument("--model", action="append", required=True, help="repeat to benchmark several models")
    ap.add_argument("--tasks", type=Path, default=Path(__file__).with_name("tasks.jsonl"))
    ap.add_argument("--reps", type=int, default=3, help="answers per task (needed for persistence metrics)")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--limit", type=int, default=0, help="only the first N tasks (0 = all)")
    ap.add_argument("--out", type=Path, default=Path("bench/results/raw_responses.jsonl"))
    a = ap.parse_args()

    tasks = [json.loads(l) for l in a.tasks.read_text().splitlines() if l.strip()]
    if a.limit:
        tasks = tasks[: a.limit]
    a.out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if a.out.exists():
        for line in a.out.read_text().splitlines():
            r = json.loads(line)
            done.add((r["model"], r["task_id"], r["rep"]))
    api_key = os.environ.get(a.api_key_env)
    total = len(a.model) * len(tasks) * a.reps
    n = 0
    with a.out.open("a", encoding="utf-8") as f:
        for model in a.model:
            for t in tasks:
                for rep in range(a.reps):
                    n += 1
                    if (model, t["id"], rep) in done:
                        continue
                    for attempt in range(4):
                        try:
                            t0 = time.time()
                            text = chat(a.base_url, api_key, model, t["prompt"], a.temperature, a.max_tokens,
                                        a.timeout)
                            break
                        except (urllib.error.URLError, TimeoutError, KeyError) as e:
                            wait = 2 ** attempt * 5
                            print(f"  error ({e}); retrying in {wait}s", file=sys.stderr)
                            time.sleep(wait)
                    else:
                        print(f"giving up on {model} {t['id']} rep {rep}", file=sys.stderr)
                        continue
                    f.write(json.dumps({"model": model, "task_id": t["id"], "lang": t["lang"], "rep": rep,
                                        "prompt": t["prompt"], "response": text,
                                        "latency_s": round(time.time() - t0, 2)}) + "\n")
                    f.flush()
                    print(f"[{n}/{total}] {model} {t['id']} rep={rep}")
    print(f"saved to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
