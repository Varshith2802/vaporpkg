"""Find package names in dependency files, install commands and free text (LLM output)."""
from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from .models import Candidate, Ecosystem

# --------------------------------------------------------------------------- shared tables

#: pip / uv / poetry / pipenv / pdm options that consume the following argument.
PY_VALUE_OPTS = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix",
    "--root", "--platform", "--python-version", "--implementation", "--abi", "--src",
    "--upgrade-strategy", "--progress-bar", "--log", "--log-file", "--cache-dir", "--trusted-host",
    "--proxy", "--retries", "--timeout", "--exists-action", "--cert", "--client-cert", "--report",
    "-C", "--config-settings", "--global-option", "--build-option", "--no-binary", "--only-binary",
    "--root-user-action", "--python", "--keyring-provider", "--use-feature", "--use-deprecated",
    "--resume-retries", "--group", "-G", "--source", "-E", "--extras", "--extra", "--markers",
    "--optional", "--index", "--default-index", "--tag", "--branch", "--rev", "-p", "--package",
    "--directory", "--project", "--spec", "--with", "--from",
}
PY_REQ_FILE_OPTS = {"-r", "--requirement", "--requirements"}
PY_SKIP_VALUE_OPTS = {"-c", "--constraint", "-e", "--editable", "-o", "--override"}

NPM_VALUE_OPTS = {
    "--registry", "--prefix", "--tag", "-w", "--workspace", "--omit", "--include", "--before",
    "--cache", "--userconfig", "--loglevel", "--install-strategy", "--scope", "--otp", "--cpu",
    "--os", "--libc", "--filter", "-F", "--dir", "--cwd", "--modules-folder", "--network-timeout",
    "--mutex", "--global-folder", "--link-dir", "--virtual-store-dir", "--call", "-c",
}

NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto",
    "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test", "sqlite", "sea",
}

#: Common import-name -> distribution-name mismatches on PyPI.
IMPORT_TO_DIST = {
    "cv2": "opencv-python", "PIL": "Pillow", "yaml": "PyYAML", "sklearn": "scikit-learn",
    "skimage": "scikit-image", "bs4": "beautifulsoup4", "dateutil": "python-dateutil",
    "dotenv": "python-dotenv", "jwt": "PyJWT", "Crypto": "pycryptodome", "Cryptodome": "pycryptodomex",
    "OpenSSL": "pyOpenSSL", "serial": "pyserial", "usb": "pyusb", "magic": "python-magic",
    "docx": "python-docx", "pptx": "python-pptx", "fitz": "PyMuPDF", "git": "GitPython",
    "telegram": "python-telegram-bot", "discord": "discord.py", "googleapiclient": "google-api-python-client",
    "attr": "attrs", "MySQLdb": "mysqlclient", "zmq": "pyzmq", "wx": "wxPython", "gi": "PyGObject",
    "kafka": "kafka-python", "jose": "python-jose", "multipart": "python-multipart",
    "slugify": "python-slugify", "ldap": "python-ldap", "win32api": "pywin32", "win32com": "pywin32",
    "win32con": "pywin32", "pythoncom": "pywin32", "OpenGL": "PyOpenGL", "socks": "PySocks",
    "nacl": "PyNaCl", "faiss": "faiss-cpu", "umap": "umap-learn", "Bio": "biopython",
    "cairo": "pycairo", "dns": "dnspython", "mpl_toolkits": "matplotlib", "pkg_resources": "setuptools",
    "google": None, "ruamel": "ruamel.yaml", "sentencepiece": "sentencepiece", "Levenshtein": "Levenshtein",
    "lxml": "lxml", "jinja2": "Jinja2", "markdown": "Markdown", "speech_recognition": "SpeechRecognition",
    "pyaudio": "PyAudio", "tensorflow_hub": "tensorflow-hub", "ffmpeg": "ffmpeg-python",
    "fake_useragent": "fake-useragent", "websocket": "websocket-client", "jsonschema": "jsonschema",
    "playwright": "playwright", "psycopg": "psycopg", "psycopg2": "psycopg2-binary",
    "pydantic_settings": "pydantic-settings", "llama_cpp": "llama-cpp-python", "whisper": "openai-whisper",
    "dash_bootstrap_components": "dash-bootstrap-components", "talib": "TA-Lib", "pymupdf": "PyMuPDF",
    "Xlib": "python-xlib", "bluetooth": "PyBluez", "RPi": "RPi.GPIO", "smbus2": "smbus2",
    "pygame": "pygame", "kivy": "Kivy", "cpuinfo": "py-cpuinfo", "vlc": "python-vlc",
}

_REQ = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$", re.S)
_NPM_NAME = re.compile(r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
_ARCHIVE = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".egg")


# --------------------------------------------------------------------------- requirement strings

def parse_requirement(spec: str) -> str | None:
    """Return the project name of a PEP 508 requirement, or None for paths/URLs/direct refs."""
    s = spec.strip().strip("'\"")
    if not s or s.startswith(("-", ".", "/", "~", "\\")) or "://" in s.split("@")[0]:
        return None
    if s.startswith(("git+", "hg+", "svn+", "bzr+", "file:")) or s.lower().endswith(_ARCHIVE):
        return None
    if re.match(r"^[A-Za-z]:[\\/]", s):  # Windows path
        return None
    m = _REQ.match(s)
    if not m:
        return None
    name, _extras, rest = m.groups()
    rest = rest.strip()
    if rest.startswith("@"):  # "pkg @ https://..." direct reference: not resolved from the index
        return None
    if rest and not re.match(r"^(===|==|>=|<=|!=|~=|>|<|;|,|\(|\*|$)", rest):
        return None
    return name


# --------------------------------------------------------------------------- dependency files

def _logical_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), start=1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        buf += raw
        out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def parse_requirements(path: str | Path, _seen: set[Path] | None = None) -> list[Candidate]:
    path = Path(path)
    seen = _seen if _seen is not None else set()
    rp = path.resolve()
    if rp in seen:
        return []
    seen.add(rp)
    out: list[Candidate] = []
    for lineno, line in _logical_lines(path.read_text(encoding="utf-8", errors="replace")):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        if line.startswith("-"):
            parts = line.split(None, 1)
            opt = parts[0]
            value = parts[1].strip() if len(parts) > 1 else ""
            if "=" in opt and opt.startswith("--"):
                opt, value = opt.split("=", 1)
            elif opt.startswith("-r") and len(opt) > 2:
                opt, value = "-r", opt[2:]
            if opt in PY_REQ_FILE_OPTS and value:
                out.extend(parse_requirements(path.parent / value, seen))
            continue
        spec = re.split(r"\s+--", line)[0]  # drop per-line options such as --hash=...
        name = parse_requirement(spec)
        if name:
            out.append(Candidate(Ecosystem.PYPI, name, "requirements", str(path), lineno, line))
    return out


def _find_line(text: str, needle: str) -> int | None:
    pat = re.compile(r"[\"'\s=,\[]" + re.escape(needle) + r"(?![A-Za-z0-9._-])", re.I)
    for i, ln in enumerate(text.splitlines(), start=1):
        if pat.search(" " + ln):
            return i
    return None


def parse_pyproject(path: str | Path) -> list[Candidate]:
    if tomllib is None:  # pragma: no cover
        raise RuntimeError("Reading pyproject.toml requires Python 3.11+")
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    specs: list[str] = []
    project = data.get("project", {})
    specs += project.get("dependencies", []) or []
    for group in (project.get("optional-dependencies") or {}).values():
        specs += group or []
    for group in (data.get("dependency-groups") or {}).values():
        specs += [g for g in group if isinstance(g, str)]
    specs += (data.get("build-system") or {}).get("requires", []) or []
    names: list[str] = [n for n in (parse_requirement(s) for s in specs) if n]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    for grp in (poetry.get("group") or {}).values():
        tables.append((grp or {}).get("dependencies") or {})
    for table in tables:
        for name, val in table.items():
            if name.lower() == "python":
                continue
            if isinstance(val, dict) and any(k in val for k in ("path", "git", "url", "file")):
                continue
            names.append(name)
    out, seen = [], set()
    for n in names:
        if n.lower() in seen:
            continue
        seen.add(n.lower())
        out.append(Candidate(Ecosystem.PYPI, n, "pyproject", str(path), _find_line(text, n), None))
    return out


def npm_spec_to_name(key: str, value: str | None = None) -> str | None:
    """Resolve a package.json entry (or a CLI spec when value is None) to a registry name."""
    if value is not None:
        v = value.strip()
        if v.startswith("npm:"):
            return npm_spec_to_name(v[4:])
        if v.startswith(("file:", "link:", "workspace:", "git+", "git:", "github:", "gitlab:",
                         "bitbucket:", "gist:", "http:", "https:", "portal:", "patch:", "exec:")):
            return None
        if "/" in v and not v.startswith("@") and re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", v):
            return None  # GitHub shorthand "user/repo"
        return key if _NPM_NAME.match(key.lower()) else None
    s = key.strip().strip("'\"")
    if not s or s.startswith(("file:", "link:", "workspace:", "git+", "git:", "github:", "gitlab:",
                              "bitbucket:", "gist:", "http:", "https:", ".", "/", "~")):
        return None
    if s.endswith((".tgz", ".tar.gz", ".tar")):
        return None
    if "@npm:" in s:  # alias@npm:real@version
        return npm_spec_to_name(s.split("@npm:", 1)[1])
    if s.startswith("@"):
        at = s.find("@", 1)
        name = s if at == -1 else s[:at]
    else:
        if "/" in s:
            return None  # GitHub shorthand
        name = s.split("@", 1)[0]
    return name if _NPM_NAME.match(name) else None


def parse_package_json(path: str | Path) -> list[Candidate]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    out: list[Candidate] = []
    seen: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for key, value in (data.get(section) or {}).items():
            name = npm_spec_to_name(key, str(value))
            if name and name not in seen:
                seen.add(name)
                out.append(Candidate(Ecosystem.NPM, name, "package.json", str(path),
                                     _find_line(text, f'"{key}"'.strip('"')), f"{key}: {value}"))
    return out


def parse_file(path: str | Path) -> list[Candidate]:
    p = Path(path)
    lname = p.name.lower()
    if lname == "package.json":
        return parse_package_json(p)
    if lname == "pyproject.toml":
        return parse_pyproject(p)
    if lname.endswith((".txt", ".in")) or "requirements" in lname:
        return parse_requirements(p)
    if lname.endswith((".md", ".markdown", ".rst", ".ipynb", ".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx")):
        text = p.read_text(encoding="utf-8", errors="replace")
        if lname.endswith(".ipynb"):
            try:
                nb = json.loads(text)
                text = "\n".join("".join(c.get("source", [])) for c in nb.get("cells", []))
            except ValueError:
                pass
        default_lang = "python" if lname.endswith((".py", ".ipynb")) else (
            "js" if lname.endswith((".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx")) else None)
        cands = extract_from_text(text, default_lang=default_lang)
        for c in cands:
            c.location = str(p)
        return cands
    raise ValueError(f"Unsupported file type: {p.name}")


# --------------------------------------------------------------------------- command lines

def parse_pip_args(args: list[str], base_dir: Path | None = None,
                   read_files: bool = True) -> list[Candidate]:
    """Package names from the arguments of ``pip install`` (also uv/poetry/pipenv/pdm add)."""
    out: list[Candidate] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in PY_REQ_FILE_OPTS or (a.startswith("-r") and len(a) > 2 and not a.startswith("--")) \
                or a.startswith(("--requirement=", "--requirements=")):
            if a in PY_REQ_FILE_OPTS:
                value = args[i + 1] if i + 1 < len(args) else ""
                i += 2
            else:
                value = a.split("=", 1)[1] if a.startswith("--") else a[2:]
                i += 1
            if read_files and value:
                p = Path(value) if base_dir is None else base_dir / value
                if p.exists():
                    out.extend(parse_requirements(p))
            continue
        if a in PY_SKIP_VALUE_OPTS or a in PY_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        name = parse_requirement(a)
        if name:
            out.append(Candidate(Ecosystem.PYPI, name, "pip-command", None, None, a))
        i += 1
    return out


def parse_npm_args(args: list[str]) -> list[Candidate]:
    out: list[Candidate] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in NPM_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        name = npm_spec_to_name(a)
        if name:
            out.append(Candidate(Ecosystem.NPM, name, "npm-command", None, None, a))
        i += 1
    return out


def _segments(line: str) -> list[str]:
    """Split a line into shell command segments at unquoted ; | & ` ( ) characters."""
    segs, buf, quote = [], [], None
    for ch in line:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in ";|&`()":
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def _cut_shell(rest: str) -> list[str]:
    """Tokenise the remainder of a shell line, stopping at control operators and comments."""
    buf, quote = [], None
    for i, ch in enumerate(rest):
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            continue
        if ch == "#" and (i == 0 or rest[i - 1].isspace()):
            break
        if ch in ";|&`)\n":
            break
        buf.append(ch)
    s = "".join(buf)
    try:
        tokens = shlex.split(s)
    except ValueError:
        tokens = s.split()
    out = []
    for t in tokens:
        if t in (">", ">>", "<", "2>", "1>", "2>&1") or t.startswith((">", "<", "2>")):
            break
        out.append(t.rstrip(",.;:"))
    return out


_PY_CMD = re.compile(
    r"(?:^|[\s;&|`(!%$])(?:sudo\s+)?(?:(?:python(?:3(?:\.\d+)?)?|py(?:\s+-3)?)\s+-m\s+)?"
    r"(?P<tool>pip3?(?:\.\d+)?\s+install|uv\s+pip\s+install|uv\s+add|poetry\s+add|pipenv\s+install|"
    r"pdm\s+add|rye\s+add|pipx\s+install|pipx\s+run|uvx|uv\s+tool\s+(?:install|run))\s+(?P<rest>.*)$",
    re.I)
_NPM_CMD = re.compile(
    r"(?:^|[\s;&|`(!$])(?:sudo\s+)?(?P<tool>npm\s+(?:install|i|add|isntall|in)|pnpm\s+(?:add|install|i|dlx)|"
    r"yarn\s+(?:global\s+)?(?:add|dlx)|bun\s+(?:add|install|i)|bunx|npx)\s+(?P<rest>.*)$", re.I)
_RUNNERS = ("pipx run", "uvx", "uv tool run", "npx", "bunx", "pnpm dlx", "yarn dlx")

_FENCE = re.compile(r"^\s*(```|~~~)\s*([\w.+-]*)")
_JS_LANGS = {"js", "javascript", "ts", "typescript", "jsx", "tsx", "mjs", "cjs", "node", "vue", "svelte"}
_PY_LANGS = {"py", "python", "python3", "ipython", "py3", "jupyter"}
_JS_SPEC = re.compile(r"""(?:\brequire\(\s*|\bimport\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"]+)['"]""")
_PY_IMPORT = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)\s*(?:#.*)?$")
_PY_FROM = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+")


def _runner_first_package(tokens: list[str], tool: str) -> list[str]:
    """For npx/uvx-style runners only the package being executed matters."""
    pkgs, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-p", "--package", "--from", "--spec", "--with"):
            if i + 1 < len(tokens):
                pkgs.append(tokens[i + 1])
            i += 2
            continue
        if t.startswith("--package="):
            pkgs.append(t.split("=", 1)[1])
            i += 1
            continue
        if t.startswith("-"):
            i += 1
            continue
        if not pkgs:
            pkgs.append(t)
        break
    return pkgs


def _js_spec_to_package(spec: str) -> str | None:
    if spec.startswith((".", "/", "node:", "bun:", "http:", "https:", "~/", "@/", "#", "virtual:", "data:")):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) < 2:
            return None
        name = "/".join(parts[:2])
    else:
        name = spec.split("/")[0]
    if name in NODE_BUILTINS:
        return None
    return name if _NPM_NAME.match(name) else None


def _py_module_to_dist(mod: str) -> tuple[str | None, str]:
    top = mod.split(".")[0]
    if not top or top.startswith("_") or top in sys.stdlib_module_names or top == "__future__":
        return None, "stdlib"
    if top in IMPORT_TO_DIST:
        return IMPORT_TO_DIST[top], "mapped"
    return top, "same-name"


def extract_from_text(text: str, default_lang: str | None = None) -> list[Candidate]:
    """Extract package candidates from free text such as an LLM answer or a README."""
    out: list[Candidate] = []
    seen: set[tuple[str, str, str]] = set()

    def add(eco: Ecosystem, name: str | None, source: str, lineno: int, ctx: str, conf: str = "high") -> None:
        if not name:
            return
        k = (eco.value, name.lower(), conf)
        if k in seen:
            return
        seen.add(k)
        out.append(Candidate(eco, name, source, None, lineno, ctx.strip()[:200], conf))

    lines = text.splitlines()
    fence_context = ""
    fence_lang: str | None = None
    in_fence = False
    block: list[tuple[int, str]] = []
    prev_text = ""
    for lineno, line in enumerate(lines, start=1):
        m = _FENCE.match(line)
        if m:
            if not in_fence:
                in_fence, fence_lang, block = True, (m.group(2) or "").lower(), []
                fence_context = prev_text
            else:
                _flush_block(fence_lang, block, fence_context, add)
                in_fence, fence_lang = False, None
            continue
        if in_fence:
            block.append((lineno, line))
        if line.strip():
            prev_text = line

        for seg in _segments(line):
            for rx, eco in ((_PY_CMD, Ecosystem.PYPI), (_NPM_CMD, Ecosystem.NPM)):
                cm = rx.search(seg)
                if not cm:
                    continue
                tool = " ".join(cm.group("tool").lower().split())
                tokens = _cut_shell(cm.group("rest"))
                if any(tool.startswith(r) for r in _RUNNERS):
                    for t in _runner_first_package(tokens, tool):
                        name = parse_requirement(t) if eco is Ecosystem.PYPI else npm_spec_to_name(t)
                        add(eco, name, "run-command", lineno, line)
                    continue
                cands = parse_pip_args(tokens, read_files=False) if eco is Ecosystem.PYPI else parse_npm_args(tokens)
                for c in cands:
                    add(eco, c.name, "pip-command" if eco is Ecosystem.PYPI else "npm-command", lineno, line)

        lang = fence_lang if in_fence and fence_lang else default_lang
        is_js = lang in _JS_LANGS if lang else None
        if is_js is not False:
            for spec in _JS_SPEC.findall(line):
                if is_js or ("require(" in line or re.search(r"\bfrom\s+['\"]", line)):
                    add(Ecosystem.NPM, _js_spec_to_package(spec), "import", lineno, line, "low")
        if is_js is not True and "'" not in line and '"' not in line:
            pm = _PY_IMPORT.match(line)
            mods: list[str] = []
            if pm:
                mods = [p.strip().split()[0] for p in pm.group(1).split(",")]
            else:
                fm = _PY_FROM.match(line)
                if fm and not fm.group(1).startswith("."):
                    mods = [fm.group(1)]
            if mods and (lang in _PY_LANGS or lang is None):
                for mod in mods:
                    dist, _how = _py_module_to_dist(mod)
                    add(Ecosystem.PYPI, dist, "import", lineno, line, "low")
    if in_fence:
        _flush_block(fence_lang, block, fence_context, add)
    # Prefer high-confidence evidence when the same package was found both ways.
    high = {(c.ecosystem.value, c.name.lower()) for c in out if c.confidence == "high"}
    return [c for c in out if c.confidence == "high" or (c.ecosystem.value, c.name.lower()) not in high]


def _flush_block(lang: str | None, block: list[tuple[int, str]], context: str, add) -> None:
    if not block:
        return
    body = "\n".join(l for _, l in block)
    if (lang and "requirements" in lang) or (lang in ("", "txt", "text", "plaintext", None)
                                            and "requirements" in (context or "").lower()):
        for lineno, l in block:
            s = re.sub(r"(^|\s)#.*$", "", l).strip()
            if s and not s.startswith("-"):
                add(Ecosystem.PYPI, parse_requirement(re.split(r"\s+--", s)[0]), "requirements", lineno, l)
    elif lang in ("json", "jsonc", "", None) and ('"dependencies"' in body or '"devDependencies"' in body):
        try:
            data = json.loads(body)
        except ValueError:
            return
        if isinstance(data, dict):
            first = block[0][0]
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for key, value in (data.get(section) or {}).items():
                    add(Ecosystem.NPM, npm_spec_to_name(key, str(value)), "package.json", first, f"{key}: {value}")
    elif lang in ("toml",) and "[project]" in body and tomllib is not None:
        try:
            data = tomllib.loads(body)
        except Exception:
            return
        for spec in (data.get("project") or {}).get("dependencies", []) or []:
            add(Ecosystem.PYPI, parse_requirement(spec), "pyproject", block[0][0], spec)
