"""Registry lookups for PyPI and npm (plus optional OSV and download counts).

Everything goes through a pluggable *transport* so the test-suite can run fully offline.
Only the standard library is used, so the tool can be installed anywhere.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from . import __version__
from .cache import FileCache
from .models import Ecosystem, PackageInfo, normalize
from .popular import PopularIndex, default_index

# (method, url, body, headers, timeout) -> (status, parsed JSON or None)
Transport = Callable[[str, str, "bytes | None", "dict[str, str]", float], "tuple[int, Any]"]

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_SIMPLE = "https://pypi.org/simple/{name}/"
PYPISTATS = "https://pypistats.org/api/packages/{name}/recent"
NPM_PACKUMENT = "https://registry.npmjs.org/{name}"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week/{name}"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search?{query}"
OSV_QUERY = "https://api.osv.dev/v1/query"

REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht", "git.sr.ht",
              "launchpad.net", "sourceforge.net", "gitee.com", "huggingface.co")

POSITIVE_TTL = 24 * 3600
NEGATIVE_TTL = 3600  # re-check missing names hourly: an attacker may register them at any time


def urllib_transport(method: str, url: str, body: bytes | None, headers: dict[str, str],
                     timeout: float) -> tuple[int, Any]:
    hdrs = {"User-Agent": f"vaporpkg/{__version__} (+https://github.com/)", "Accept": "application/json"}
    hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, None


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _looks_like_repo(url: str | None) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        host = urllib.parse.urlparse(url if "://" in url else "https://" + url).netloc.lower()
    except ValueError:
        return False
    host = host.split("@")[-1]
    return any(host == h or host.endswith("." + h) for h in REPO_HOSTS)


def info_to_json(info: PackageInfo) -> dict[str, Any]:
    d = asdict(info)
    d["ecosystem"] = info.ecosystem.value
    for k in ("created", "latest_release"):
        d[k] = d[k].isoformat() if d[k] else None
    return d


def info_from_json(d: dict[str, Any]) -> PackageInfo:
    d = dict(d)
    d["ecosystem"] = Ecosystem(d["ecosystem"])
    for k in ("created", "latest_release"):
        d[k] = _parse_time(d.get(k))
    return PackageInfo(**d)


class RegistryClient:
    def __init__(self, transport: Transport | None = None, cache: FileCache | None = None,
                 timeout: float = 10.0, use_osv: bool = True, use_downloads: bool = True,
                 popular: PopularIndex | None = None, max_workers: int = 8):
        self.transport = transport or urllib_transport
        self.cache = cache if cache is not None else FileCache()
        self.timeout = timeout
        self.use_osv = use_osv
        self.use_downloads = use_downloads
        self.popular = popular or default_index()
        self.max_workers = max_workers

    # ------------------------------------------------------------------ helpers
    def _get(self, url: str, headers: dict[str, str] | None = None, retries: int = 1) -> tuple[int, Any]:
        for attempt in range(retries + 1):
            try:
                status, data = self.transport("GET", url, None, headers or {}, self.timeout)
            except Exception:
                if attempt == retries:
                    raise
                time.sleep(0.5 * (attempt + 1))
                continue
            if status >= 500 and attempt < retries:  # transient registry/CDN error
                time.sleep(0.5 * (attempt + 1))
                continue
            return status, data
        raise RuntimeError("unreachable")  # pragma: no cover

    def _post(self, url: str, payload: Any) -> tuple[int, Any]:
        body = json.dumps(payload).encode("utf-8")
        return self.transport("POST", url, body, {"Content-Type": "application/json"}, self.timeout)

    # ------------------------------------------------------------------ public
    def lookup(self, eco: Ecosystem, name: str) -> PackageInfo:
        key = f"info:v1:{eco.value}:{normalize(eco, name)}"
        cached = self.cache.get(key)
        if cached is not None:
            return info_from_json(cached)
        try:
            info = self._lookup_pypi(name) if eco is Ecosystem.PYPI else self._lookup_npm(name)
        except Exception as e:  # network failure, bad JSON, timeout ...
            return PackageInfo(ecosystem=eco, name=name, exists=False,
                               lookup_error=f"{type(e).__name__}: {e}")
        if info.lookup_error is None:
            self.cache.set(key, info_to_json(info), POSITIVE_TTL if info.exists else NEGATIVE_TTL)
        return info

    def lookup_many(self, items: Iterable[tuple[Ecosystem, str]]) -> dict[tuple[str, str], PackageInfo]:
        unique: dict[tuple[str, str], tuple[Ecosystem, str]] = {}
        for eco, name in items:
            unique.setdefault((eco.value, normalize(eco, name)), (eco, name))
        out: dict[tuple[str, str], PackageInfo] = {}
        if not unique:
            return out
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(unique))) as pool:
            futures = {k: pool.submit(self.lookup, eco, name) for k, (eco, name) in unique.items()}
            for k, fut in futures.items():
                out[k] = fut.result()
        return out

    # ------------------------------------------------------------------ PyPI
    def _lookup_pypi(self, name: str) -> PackageInfo:
        norm = normalize(Ecosystem.PYPI, name)
        status, data = self._get(PYPI_JSON.format(name=urllib.parse.quote(norm)))
        if status == 404:
            info = PackageInfo(ecosystem=Ecosystem.PYPI, name=name, exists=False)
            info.status = self._pypi_project_status(norm)
            info.malicious_advisories = self._osv_malicious("PyPI", norm)
            return info
        if status != 200 or not isinstance(data, dict):
            return PackageInfo(ecosystem=Ecosystem.PYPI, name=name, exists=False,
                               lookup_error=f"PyPI returned HTTP {status}")
        meta = data.get("info") or {}
        releases: dict[str, list[dict[str, Any]]] = data.get("releases") or {}
        times: list[datetime] = []
        release_count = 0
        for files in releases.values():
            stamps = [_parse_time(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in files]
            stamps = [t for t in stamps if t]
            if stamps:
                release_count += 1
                times.extend(stamps)
        if not releases:  # the JSON API's "releases" key is deprecated; fall back to the simple API
            release_count, times = self._pypi_simple_times(norm)
        project_urls = meta.get("project_urls") or {}
        urls = [u for u in project_urls.values() if isinstance(u, str)]
        repo = next((u for u in urls if _looks_like_repo(u)), None)
        homepage = meta.get("home_page") or project_urls.get("Homepage") or project_urls.get("homepage")
        if not repo and _looks_like_repo(homepage):
            repo = homepage
        ownership = data.get("ownership") or {}
        maintainers = [r.get("user") for r in ownership.get("roles", []) if r.get("user")]
        summary = (meta.get("summary") or "").strip()
        if summary.upper() == "UNKNOWN":
            summary = ""
        if not summary:
            description = (meta.get("description") or "").strip()
            summary = "" if description.upper() == "UNKNOWN" else description[:200]
        info = PackageInfo(
            ecosystem=Ecosystem.PYPI,
            name=meta.get("name") or name,
            exists=True,
            created=min(times) if times else None,
            latest_release=max(times) if times else None,
            release_count=release_count,
            latest_version=meta.get("version"),
            summary=summary,
            repo_url=repo,
            homepage=homepage if isinstance(homepage, str) else None,
            maintainers=maintainers,
            organization=ownership.get("organization"),
        )
        info.malicious_advisories = self._osv_malicious("PyPI", norm)
        if self.use_downloads and not self.popular.is_popular(Ecosystem.PYPI, norm):
            info.weekly_downloads = self._pypistats_weekly(norm)
        return info

    def _pypi_simple_times(self, norm: str) -> tuple[int, list[datetime]]:
        status, data = self._get(PYPI_SIMPLE.format(name=norm),
                                 {"Accept": "application/vnd.pypi.simple.v1+json"})
        if status != 200 or not isinstance(data, dict):
            return 0, []
        times = [t for t in (_parse_time(f.get("upload-time")) for f in data.get("files", [])) if t]
        return len(data.get("versions") or []), times

    def _pypi_project_status(self, norm: str) -> str | None:
        """Status of a name the JSON API does not know.

        Returns the PEP 792 status (e.g. "quarantined"), "no-releases" when the name is registered
        but has nothing installable (all files deleted / placeholder), or None if it is unregistered.
        """
        try:
            status, data = self._get(PYPI_SIMPLE.format(name=norm),
                                     {"Accept": "application/vnd.pypi.simple.v1+json"})
        except Exception:
            return None
        if status == 200 and isinstance(data, dict):
            ps = (data.get("project-status") or {}).get("status")
            if ps and ps != "active":
                return ps
            return "no-releases"
        return None

    def _pypistats_weekly(self, norm: str) -> int | None:
        try:
            status, data = self._get(PYPISTATS.format(name=norm))
        except Exception:
            return None
        if status == 200 and isinstance(data, dict):
            v = (data.get("data") or {}).get("last_week")
            return int(v) if isinstance(v, (int, float)) else None
        return None

    # ------------------------------------------------------------------ npm
    def _lookup_npm(self, name: str) -> PackageInfo:
        enc = urllib.parse.quote(name, safe="@")  # "@scope/pkg" -> "@scope%2Fpkg"
        popular = self.popular.is_popular(Ecosystem.NPM, name)
        headers = {"Accept": "application/vnd.npm.install-v1+json"} if popular else {}
        status, data = self._get(NPM_PACKUMENT.format(name=enc), headers)
        if status == 404:
            info = PackageInfo(ecosystem=Ecosystem.NPM, name=name, exists=False)
            info.malicious_advisories = self._osv_malicious("npm", name)
            return info
        if status != 200 or not isinstance(data, dict):
            return PackageInfo(ecosystem=Ecosystem.NPM, name=name, exists=False,
                               lookup_error=f"npm registry returned HTTP {status}")
        versions: dict[str, Any] = data.get("versions") or {}
        time_map: dict[str, Any] = data.get("time") or {}
        if not versions:
            # Fully unpublished packages keep a stub document with time.unpublished.
            info = PackageInfo(ecosystem=Ecosystem.NPM, name=name, exists=False,
                               status="unpublished" if "unpublished" in time_map else None)
            info.malicious_advisories = self._osv_malicious("npm", name)
            return info
        latest = (data.get("dist-tags") or {}).get("latest")
        latest_doc = versions.get(latest) or versions[sorted(versions)[-1]]
        scripts = latest_doc.get("scripts") or {}
        install_scripts = [s for s in ("preinstall", "install", "postinstall") if s in scripts]
        if not install_scripts and latest_doc.get("hasInstallScript"):
            install_scripts = ["install-script"]
        stamps = [_parse_time(v) for k, v in time_map.items() if k not in ("created", "modified")]
        stamps = [t for t in stamps if t]
        created = _parse_time(time_map.get("created")) or (min(stamps) if stamps else None)
        repo = data.get("repository") or latest_doc.get("repository")
        repo_url = repo.get("url") if isinstance(repo, dict) else repo if isinstance(repo, str) else None
        homepage = data.get("homepage") or latest_doc.get("homepage")
        description = (data.get("description") or latest_doc.get("description") or "").strip()
        info = PackageInfo(
            ecosystem=Ecosystem.NPM,
            name=data.get("name") or name,
            exists=True,
            created=created,
            latest_release=max(stamps) if stamps else _parse_time(data.get("modified")),
            release_count=len(versions),
            latest_version=latest,
            summary=description,
            repo_url=repo_url if _looks_like_repo(repo_url) or (repo_url and "git" in repo_url) else None,
            homepage=homepage if isinstance(homepage, str) else None,
            maintainers=[m.get("name") for m in data.get("maintainers", []) if isinstance(m, dict) and m.get("name")],
            install_scripts=install_scripts,
            deprecated=bool(latest_doc.get("deprecated")),
            security_holding=(latest or "").endswith("-security")
            or "security holding package" in description.lower(),
        )
        if popular and "time" not in data:
            # Abbreviated metadata (used for popular packages to save bandwidth) has no creation
            # time, repository or description, so those signals must not be computed.
            info.created = None
            info.latest_release = _parse_time(data.get("modified"))
            info.metadata_complete = False
        info.malicious_advisories = self._osv_malicious("npm", name)
        if self.use_downloads and not popular:
            info.weekly_downloads = self._npm_weekly(name)
        return info

    def _npm_weekly(self, name: str) -> int | None:
        try:
            status, data = self._get(NPM_DOWNLOADS.format(name=urllib.parse.quote(name, safe="@/")))
            if status == 200 and isinstance(data, dict) and isinstance(data.get("downloads"), int):
                return data["downloads"]
        except Exception:
            pass
        # Fallback: the search endpoint lives on registry.npmjs.org and also reports downloads.
        try:
            q = urllib.parse.urlencode({"text": name, "size": "5"})
            status, data = self._get(NPM_SEARCH.format(query=q))
        except Exception:
            return None
        if status == 200 and isinstance(data, dict):
            for obj in data.get("objects", []):
                if (obj.get("package") or {}).get("name") == name:
                    w = (obj.get("downloads") or {}).get("weekly")
                    return int(w) if isinstance(w, (int, float)) else None
        return None

    # ------------------------------------------------------------------ OSV
    def _osv_malicious(self, osv_ecosystem: str, name: str) -> list[str]:
        """IDs of OpenSSF malicious-package advisories (``MAL-*``) for this package."""
        if not self.use_osv:
            return []
        try:
            status, data = self._post(OSV_QUERY, {"package": {"name": name, "ecosystem": osv_ecosystem}})
        except Exception:
            return []
        if status != 200 or not isinstance(data, dict):
            return []
        ids = []
        for v in data.get("vulns", []) or []:
            vid = v.get("id", "")
            aliases = v.get("aliases") or []
            if vid.startswith("MAL-") or any(str(a).startswith("MAL-") for a in aliases):
                ids.append(vid)
        return ids
