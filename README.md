# VaporPkg

**Catch AI-hallucinated ("slopsquatted"), typosquatted and known-malicious PyPI/npm packages *before* you install them.**

AI coding assistants regularly recommend packages that do not exist. Attackers watch for those names,
register them on PyPI or npm with malware inside, and wait for developers to copy-paste
`pip install <hallucinated-name>`. This attack is called **slopsquatting**. VaporPkg sits in front of
`pip`/`npm`/`uv`/`pnpm`/`yarn`/`bun`, checks every package an install command would fetch, and refuses to
run the install when a name is missing, freshly registered, a lookalike of a popular package, or listed as
malicious.

```text
$ vaporpkg pip install pandas garmin-fit-zones reqeusts
BLOCK  pypi  garmin-fit-zones  100  'garmin-fit-zones' does not exist on PyPI. AI assistants often invent package names; ...
BLOCK  pypi  reqeusts          100  'reqeusts' does not exist on PyPI. ... Did you mean 'requests'?
OK     pypi  pandas              0  Among the most downloaded PyPI packages (rank #40).

vaporpkg: refusing to run 'pip' - blocked: garmin-fit-zones, reqeusts
```

## Live demo

Try it in the browser: **https://varshith2802.github.io/vaporpkg/**

Paste an AI answer, a `requirements.txt`, a `package.json`, a `pyproject.toml` or an install command and see
which packages to block before installing. The page is [`docs/index.html`](docs/index.html), a single file with
no server: it runs the same parsers, popularity index and scoring as this Python package (ported to JavaScript
and tested against the Python output) and queries PyPI and npm directly from the browser. You can also open the
file locally by double-clicking it.

To publish it from your own copy of the repository: **Settings > Pages > Deploy from a branch > `main` / `docs`**.

---

## Quick start (how it runs)

Requirements: Python 3.10+ and internet access to `pypi.org` / `registry.npmjs.org`. No third-party
dependencies (standard library only).

```bash
# 1. get the code
unzip vaporpkg.zip && cd vaporpkg

# 2. install (a virtual environment is recommended)
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 3. run the tests (offline, ~1 s)
pytest -q

# 4. try it
vaporpkg check requests huggingface-cli npm:expresss
vaporpkg scan examples -v
vaporpkg extract examples/llm_answer.md
```

Exit codes: `0` nothing blocked, `1` warnings (only with `--fail-on warn`, or a declined prompt),
`2` something blocked, `3` usage/IO error.

## Usage

| Command | What it does |
|---|---|
| `vaporpkg check NAME...` | Check names. Prefix with `npm:`/`pypi:`; `@scope/x` is treated as npm; `--npm` makes npm the default. |
| `vaporpkg scan [PATH...] [-R]` | Scan `requirements*.txt`, `pyproject.toml`, `package.json` (files or directories, `-R` = recursive). |
| `vaporpkg extract FILE\|-` | Find every package mentioned in text (an LLM answer, README, notebook, .py/.js file) and check it. |
| `vaporpkg pip install ...` | **Guard mode**: check, then run the real command. Works for `pip`, `uv`, `uvx`, `poetry`, `pipenv`, `pdm`, `pipx`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`. |
| `vaporpkg guard [--yes] [--force] [--dry-run] -- CMD...` | Same as above with explicit options. |
| `vaporpkg cache clear` | Delete cached registry metadata (`~/.cache/vaporpkg`). |

Useful options: `--json`, `-v/--verbose` (every signal with its points), `--sarif FILE`,
`--fail-on warn`, `--block-threshold 70`, `--warn-threshold 30`, `--no-osv`, `--no-downloads`.

### Make it automatic

Bash/zsh (`~/.bashrc` or `~/.zshrc`):

```bash
pip()  { vaporpkg guard -- pip  "$@"; }
npm()  { vaporpkg guard -- npm  "$@"; }
npx()  { vaporpkg guard -- npx  "$@"; }
pnpm() { vaporpkg guard -- pnpm "$@"; }
```

Only install-type subcommands are checked (`pip install`, `npm install/i/add`, `npx <pkg>` ...);
everything else is passed straight through. Running `npm install`/`yarn` without arguments checks
`package.json` in the current directory.

### CI / pre-commit

GitHub Actions (with code-scanning annotations):

```yaml
- uses: actions/checkout@v4
- uses: your-user/vaporpkg@main        # this repository
  with:
    paths: "."
    fail-on: block                     # block | warn | never
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vaporpkg.sarif
```

pre-commit (`.pre-commit-config.yaml`):

```yaml
- repo: https://github.com/your-user/vaporpkg
  rev: v0.1.0
  hooks:
    - id: vaporpkg
```

## How it works

```
install command / dependency file / LLM answer
        │  parsers.py  (pip, uv, poetry, npm, pnpm, yarn, bun, npx ... + imports/requires)
        ▼
  candidate packages ──► registry.py ──► PyPI JSON + Simple API (PEP 691/792), npm registry,
        │                               OSV (OpenSSF malicious packages), download counts
        ▼
  scoring.py: explainable signals ──► score 0-100 ──► OK / WARN / BLOCK
```

| Signal | Points | Why it matters |
|---|---|---|
| `NOT_FOUND` | block | The name does not exist: the classic hallucination an attacker can claim. |
| `QUARANTINED` / `SECURITY_HOLDING` / `KNOWN_MALICIOUS` | block | PyPI quarantine (PEP 792), npm security placeholder, OpenSSF `MAL-*` advisory. |
| `VERY_NEW` (< 14 days) / `NEW` (< 90 days) | 45 / 25 | Slopsquats are registered shortly after the names start circulating. |
| `LOOKALIKE` | 35 / 20 | 1–2 edits from a top-5000 package, same letters with different separators, or a popular name with a prefix/suffix bolted on (`requests-python`). |
| `SINGLE_RELEASE` / `FEW_RELEASES` | 15 / 8 | Throw-away packages rarely have history. |
| `VERY_LOW_DOWNLOADS` / `LOW_DOWNLOADS` | 20 / 10 | Weekly downloads < 50 / < 1000. |
| `INSTALL_SCRIPTS` | 15 | npm `preinstall`/`install`/`postinstall` run code on your machine. |
| `NO_REPOSITORY` / `NO_DESCRIPTION` | 12 / 8 | Weak provenance. |
| `DEPRECATED` | 10 | Abandoned or archived. |
| `VERIFIED_ORG` | −10 | Owned by a PyPI organization account. |

The score is the sum of the points (0–100). Default policy: **BLOCK ≥ 70, WARN ≥ 30**. Packages in the
bundled top-15,000 lists are capped at 20 points unless a critical signal fires, so popular packages with
legitimate install scripts (e.g. `esbuild`) are not flagged. Names derived only from `import` statements
are WARN instead of BLOCK when missing, because import names often differ from distribution names
(`cv2` → `opencv-python`; ~90 common mappings are built in).

Registry lookups run in parallel and are cached for 24 h (missing names for 1 h, because an attacker could
register them at any time).

## Research benchmark: how often do LLMs hallucinate packages?

`bench/` contains a reproducible experiment with 70 coding tasks (40 Python, 30 JavaScript, mixing
mainstream and niche domains such as PLCs, GNSS, Swedish identity numbers and AIS ship data).

```bash
# 1) collect answers (any OpenAI-compatible endpoint; Ollama shown - free and local)
ollama pull llama3.1:8b
python bench/run_bench.py --base-url http://localhost:11434/v1 --model llama3.1:8b --reps 3

#    hosted model:
export OPENAI_API_KEY=...
python bench/run_bench.py --base-url https://api.openai.com/v1 --model gpt-4o-mini --reps 3

# 2) measure hallucination + how VaporPkg handles it
python bench/evaluate.py bench/results/raw_responses.jsonl --out bench/results
#    -> summary.md / summary.json / hallucinated_names.csv / hallucination_rate.png

# 3) alert-rate (false-positive) study on real packages
python bench/fp_eval.py --popular 300 --random-pypi 300 --longtail-npm 300

# Dry run of the pipeline without any LLM (hand-written synthetic answers, NOT real model output):
python bench/evaluate.py bench/sample_responses.jsonl --out /tmp/demo
```

Metrics: mention-level and unique-name hallucination rate, share of answers with at least one
hallucination, **persistence** (does the same fake name come back across repetitions? persistent names are
predictable and therefore exploitable), names that exist but were registered in the last 90 days (possible
squats), cross-model overlap, and the share of hallucinated names VaporPkg blocks.

### Measured alert rates (live registries, 2026-10-05, seed 7)

Run in a sandbox where the OSV and download-count APIs were not reachable, so those two signals were off
(`--no-osv --no-downloads`); all other signals were live.

| Cohort | n | OK % | WARN % | BLOCK % | Median lookup |
|---|---|---|---|---|---|
| Popular PyPI (top 15k sample) | 300 | 100.0 | 0.0 | 0.0 | 30 ms |
| Popular npm (top 15k sample) | 300 | 99.7* | 0.0 | 0.0 | 57 ms |
| Random PyPI projects (outside top 15k) | 300 | 91.3 | 6.0 | 2.7 | 29 ms |
| Long-tail npm (outside top 15k) | 300 | 90.7 | 9.3 | 0.0 | 90 ms |

\* one transient network error (0.3 %); a retry was added afterwards.
All 8 BLOCKs in the random PyPI cohort were names that are registered but have **no installable files**
(deleted/placeholder projects), so `pip install` would fail on them anyway. The WARNs are mostly
legitimate-but-new or single-release projects. That is the cost of the policy, and the reason WARN prompts
instead of blocking. Raw data: `bench/results/alerts/`.

## Limitations

* A determined attacker can age a package, add a fake repository link and inflate downloads; VaporPkg raises
  the cost of slopsquatting but is not a malware scanner (combine it with e.g. OSV-Scanner/GuardDog).
* Lookalike detection compares against snapshot lists (refresh with `python -m vaporpkg.refresh_lists`).
* Private indexes (`--index-url`) are not queried; the check is against public PyPI/npm.
* Brand-new legitimate packages will be warned about. That is intentional.

## Responsible disclosure

Do not publish raw lists of hallucinated package names from your benchmark runs. Report them to
`security@pypi.org` and to npm (via GitHub security) so the registries can reserve or monitor them.

## Project layout

```
src/vaporpkg/      cli.py  parsers.py  registry.py  scoring.py  popular.py  engine.py  report.py  cache.py
src/vaporpkg/data/ top_pypi.txt  top_npm.txt         (popular-name snapshots, 15k each)
bench/             tasks.jsonl  run_bench.py  evaluate.py  fp_eval.py  sample_responses.jsonl  results/
tests/             30 offline tests (fake registry transport)
examples/          requirements.txt  package.json  llm_answer.md
report/            report.tex (+ report.pdf)  - paper-style write-up
action.yml  .pre-commit-hooks.yaml  .github/workflows/ci.yml
```

## License

MIT © 2026 Varshith
