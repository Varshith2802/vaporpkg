"""Command-line interface.

    vaporpkg check requests flask-jwt-simple npm:expresss
    vaporpkg scan requirements.txt package.json --sarif out.sarif
    vaporpkg extract answer.md                     # check packages mentioned in LLM output
    vaporpkg pip install somepkg                   # guard: check first, then run pip
    vaporpkg npm install left-padd                 # same for npm / pnpm / yarn / bun / uv / poetry ...
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .cache import FileCache
from .engine import check_candidates
from .models import Assessment, Candidate, Ecosystem, Verdict
from .parsers import (extract_from_text, parse_file, parse_npm_args, parse_package_json, parse_pip_args,
                      parse_requirement, npm_spec_to_name)
from .registry import RegistryClient
from .report import format_table, to_json, to_sarif, use_color
from .scoring import Policy

EXIT_OK, EXIT_WARN, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2, 3

GUARDED_TOOLS = {"pip", "pip3", "uv", "uvx", "poetry", "pipenv", "pdm", "pipx", "npm", "npx", "pnpm",
                 "yarn", "bun", "bunx"}
NPM_INSTALL_ALIASES = {"install", "i", "add", "isntall", "in", "ins", "inst", "insta", "instal", "isnt",
                       "isnta", "isntal"}
DEP_FILES = ("requirements.txt", "requirements-dev.txt", "dev-requirements.txt", "requirements.in",
             "pyproject.toml", "package.json")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", ".tox", "dist", "build", ".mypy_cache"}

# Hook so tests can inject an offline client.
_client_factory = None


def _make_client(args: argparse.Namespace) -> RegistryClient:
    if _client_factory is not None:
        return _client_factory(args)
    return RegistryClient(cache=FileCache(enabled=not getattr(args, "no_cache", False)),
                          timeout=getattr(args, "timeout", 10.0),
                          use_osv=not getattr(args, "no_osv", False),
                          use_downloads=not getattr(args, "no_downloads", False))


def _policy(args: argparse.Namespace) -> Policy:
    return Policy(block_threshold=args.block_threshold, warn_threshold=args.warn_threshold)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("-v", "--verbose", action="store_true", help="show every risk signal")
    p.add_argument("--no-cache", action="store_true", help="ignore the local metadata cache")
    p.add_argument("--no-osv", action="store_true", help="skip the OSV malicious-package lookup")
    p.add_argument("--no-downloads", action="store_true", help="skip download-count lookups")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    p.add_argument("--block-threshold", type=int, default=70)
    p.add_argument("--warn-threshold", type=int, default=30)
    p.add_argument("--fail-on", choices=["block", "warn"], default="block",
                   help="exit non-zero on blocked packages only (default) or also on warnings")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vaporpkg", description="Catch hallucinated and suspicious packages "
                                 "before you install them.")
    ap.add_argument("--version", action="version", version=f"vaporpkg {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("check", help="check package names (prefix with npm: or pypi:)")
    p.add_argument("names", nargs="+")
    p.add_argument("--npm", action="store_true", help="treat unprefixed names as npm packages")
    _add_common(p)

    p = sub.add_parser("scan", help="scan dependency files or directories")
    p.add_argument("paths", nargs="*", default=["."])
    p.add_argument("-R", "--recursive", action="store_true")
    p.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 report (GitHub code scanning)")
    _add_common(p)

    p = sub.add_parser("extract", help="find and check packages mentioned in text (e.g. an LLM answer)")
    p.add_argument("file", nargs="?", default="-", help="file to read, or - for stdin")
    p.add_argument("--no-imports", action="store_true", help="ignore import/require statements")
    p.add_argument("--sarif", metavar="FILE")
    _add_common(p)

    p = sub.add_parser("guard", help="check the packages in an install command, then run it")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.add_argument("--yes", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    _add_common(p)

    p = sub.add_parser("cache", help="manage the metadata cache")
    p.add_argument("action", choices=["clear", "path"])
    return ap


def _exit_code(results: list[Assessment], fail_on: str) -> int:
    if any(a.verdict is Verdict.BLOCK for a in results):
        return EXIT_BLOCK
    if fail_on == "warn" and any(a.verdict in (Verdict.WARN, Verdict.ERROR) for a in results):
        return EXIT_WARN
    return EXIT_OK


def _emit(results: list[Assessment], args: argparse.Namespace, stream=None) -> None:
    stream = stream or sys.stdout
    if args.json:
        print(to_json(results), file=stream)
    else:
        print(format_table(results, color=use_color(stream), verbose=args.verbose), file=stream)


def _parse_name_arg(raw: str, default_npm: bool) -> Candidate | None:
    eco = Ecosystem.NPM if default_npm else Ecosystem.PYPI
    s = raw
    if raw.lower().startswith(("npm:", "pypi:")):
        prefix, s = raw.split(":", 1)
        eco = Ecosystem(prefix.lower())
    elif raw.startswith("@"):
        eco = Ecosystem.NPM
    name = parse_requirement(s) if eco is Ecosystem.PYPI else npm_spec_to_name(s)
    return Candidate(eco, name, "cli") if name else None


def cmd_check(args: argparse.Namespace) -> int:
    cands = []
    for raw in args.names:
        c = _parse_name_arg(raw, args.npm)
        if c is None:
            print(f"vaporpkg: skipping '{raw}' (not a registry package name)", file=sys.stderr)
            continue
        cands.append(c)
    results = check_candidates(cands, _make_client(args), _policy(args))
    _emit(results, args)
    return _exit_code(results, args.fail_on)


def _discover(paths: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            if recursive:
                for root, dirs, fnames in os.walk(p):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for f in fnames:
                        if f in DEP_FILES or (f.startswith("requirements") and f.endswith((".txt", ".in"))):
                            files.append(Path(root) / f)
            else:
                for f in sorted(p.iterdir()):
                    if f.is_file() and (f.name in DEP_FILES or (f.name.startswith("requirements")
                                                               and f.name.endswith((".txt", ".in")))):
                        files.append(f)
        else:
            raise FileNotFoundError(raw)
    return files


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        files = _discover(args.paths, args.recursive)
    except FileNotFoundError as e:
        print(f"vaporpkg: no such file or directory: {e}", file=sys.stderr)
        return EXIT_ERROR
    if not files:
        print("vaporpkg: no dependency files found", file=sys.stderr)
        return EXIT_OK
    cands: list[Candidate] = []
    for f in files:
        try:
            cands.extend(parse_file(f))
        except (ValueError, OSError) as e:
            print(f"vaporpkg: could not parse {f}: {e}", file=sys.stderr)
    results = check_candidates(cands, _make_client(args), _policy(args))
    _emit(results, args)
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(results), encoding="utf-8")
    return _exit_code(results, args.fail_on)


def cmd_extract(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")
    cands = extract_from_text(text)
    if args.file != "-":
        for c in cands:
            c.location = args.file
    if args.no_imports:
        cands = [c for c in cands if c.confidence == "high"]
    results = check_candidates(cands, _make_client(args), _policy(args))
    _emit(results, args)
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(results), encoding="utf-8")
    return _exit_code(results, args.fail_on)


# --------------------------------------------------------------------------- guard

def candidates_for_command(argv: list[str], cwd: Path | None = None) -> list[Candidate] | None:
    """Packages an install command would fetch.  None means 'not an install command'."""
    if not argv:
        return None
    cwd = cwd or Path.cwd()
    tool = Path(argv[0]).name.lower().removesuffix(".exe")
    rest = argv[1:]
    if tool.startswith("python") or tool == "py":
        if len(rest) >= 2 and rest[0] == "-m" and rest[1] in ("pip", "pip3"):
            tool, rest = "pip", rest[2:]
        else:
            return None
    if tool.startswith("pip") and tool != "pipx" and tool != "pipenv":
        if rest and rest[0] in ("install", "download", "wheel"):
            return parse_pip_args(rest[1:], base_dir=cwd)
        return None
    if tool == "uv":
        if rest[:2] == ["pip", "install"]:
            return parse_pip_args(rest[2:], base_dir=cwd)
        if rest and rest[0] == "add":
            return parse_pip_args(rest[1:], base_dir=cwd)
        if rest[:2] in (["tool", "install"], ["tool", "run"]):
            return _runner(rest[2:], Ecosystem.PYPI)
        return None
    if tool == "uvx":
        return _runner(rest, Ecosystem.PYPI)
    if tool in ("poetry", "pdm") and rest and rest[0] == "add":
        return parse_pip_args(rest[1:], base_dir=cwd)
    if tool == "pipenv" and rest and rest[0] == "install":
        return parse_pip_args(rest[1:], base_dir=cwd)
    if tool == "pipx" and rest and rest[0] in ("install", "run"):
        return _runner(rest[1:], Ecosystem.PYPI)
    if tool in ("npx", "bunx"):
        return _runner(rest, Ecosystem.NPM)
    if tool in ("npm", "pnpm", "bun", "yarn"):
        if tool in ("pnpm", "yarn") and rest and rest[0] == "dlx":
            return _runner(rest[1:], Ecosystem.NPM)
        if tool == "yarn" and (not rest or rest[0] == "install"):
            return _package_json(cwd)
        if tool == "yarn" and rest[:2] == ["global", "add"]:
            return parse_npm_args(rest[2:])
        if rest and rest[0] in NPM_INSTALL_ALIASES:
            pkgs = parse_npm_args(rest[1:])
            if pkgs:
                return pkgs
            return _package_json(cwd) if not [a for a in rest[1:] if not a.startswith("-")] else []
        return None
    return None


def _runner(tokens: list[str], eco: Ecosystem) -> list[Candidate]:
    from .parsers import _runner_first_package  # local import keeps the public API small
    out = []
    for t in _runner_first_package(tokens, ""):
        name = parse_requirement(t) if eco is Ecosystem.PYPI else npm_spec_to_name(t)
        if name:
            out.append(Candidate(eco, name, "run-command", None, None, t))
    return out


def _package_json(cwd: Path) -> list[Candidate]:
    pj = cwd / "package.json"
    return parse_package_json(pj) if pj.exists() else []


def cmd_guard(args: argparse.Namespace) -> int:
    argv = list(args.command)
    if not argv:
        print("vaporpkg guard: missing command", file=sys.stderr)
        return EXIT_ERROR
    cands = candidates_for_command(argv)
    if cands:
        results = check_candidates(cands, _make_client(args), _policy(args))
        _emit(results, args, stream=sys.stderr)
        blocked = [a for a in results if a.verdict is Verdict.BLOCK]
        warned = [a for a in results if a.verdict in (Verdict.WARN, Verdict.ERROR)]
        if blocked and not args.force:
            names = ", ".join(a.name for a in blocked)
            print(f"\nvaporpkg: refusing to run '{argv[0]}' - blocked: {names}\n"
                  f"          Fix the name, or re-run with --force if you are sure.", file=sys.stderr)
            return EXIT_BLOCK
        if blocked and args.force:
            print("\nvaporpkg: --force given, installing blocked packages anyway.", file=sys.stderr)
        if warned and not args.yes and not args.force:
            if sys.stdin.isatty():
                answer = input("\nvaporpkg: some packages look risky. Continue? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    return EXIT_WARN
            else:
                print("\nvaporpkg: warnings in non-interactive mode; aborting (use --yes to accept).",
                      file=sys.stderr)
                return EXIT_WARN
    if args.dry_run:
        print("vaporpkg: dry run - would execute: " + " ".join(argv), file=sys.stderr)
        return EXIT_OK
    exe = shutil.which(argv[0])
    if exe is None:
        print(f"vaporpkg: command not found: {argv[0]}", file=sys.stderr)
        return 127
    if os.name == "posix":
        os.execv(exe, [exe] + argv[1:])  # replaces this process; never returns
    return subprocess.call([exe] + argv[1:])  # pragma: no cover (Windows)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Shortcut: "vaporpkg pip install x" == "vaporpkg guard -- pip install x"
    if argv and argv[0] in GUARDED_TOOLS:
        argv = ["guard", "--"] + argv
    ap = build_parser()
    if argv[:1] == ["guard"]:
        # Split our own options from the wrapped command at the first non-option token / "--".
        ours, rest = [], argv[1:]
        while rest and rest[0] != "--" and rest[0].startswith("-"):
            opt = rest.pop(0)
            ours.append(opt)
            if opt in ("--timeout", "--block-threshold", "--warn-threshold", "--fail-on") and rest:
                ours.append(rest.pop(0))
        if rest and rest[0] == "--":
            rest = rest[1:]
        args = ap.parse_args(["guard"] + ours)
        args.command = rest
        return cmd_guard(args)
    args = ap.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "extract":
        return cmd_extract(args)
    if args.cmd == "cache":
        cache = FileCache()
        if args.action == "clear":
            print(f"removed {cache.clear()} cached entries from {cache.dir}")
        else:
            print(cache.dir)
        return EXIT_OK
    ap.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
