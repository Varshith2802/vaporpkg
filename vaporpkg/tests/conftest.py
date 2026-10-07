import json
from datetime import datetime, timedelta, timezone

import pytest

from vaporpkg.cache import FileCache
from vaporpkg.models import Ecosystem
from vaporpkg.popular import PopularIndex
from vaporpkg.registry import RegistryClient

NOW = datetime.now(timezone.utc)


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def pypi_doc(name, days_ago_first, n_releases=1, repo=True, summary="A package", org=None):
    releases = {}
    for i in range(n_releases):
        age = days_ago_first - i * (days_ago_first / max(n_releases, 1))
        releases[f"0.{i}.0"] = [{"upload_time_iso_8601": iso(age), "packagetype": "sdist"}]
    return {
        "info": {"name": name, "summary": summary, "description": "", "version": f"0.{n_releases - 1}.0",
                 "home_page": None,
                 "project_urls": {"Source": f"https://github.com/example/{name}"} if repo else {}},
        "releases": releases,
        "ownership": {"organization": org, "roles": [{"role": "Owner", "user": "someone"}]},
        "vulnerabilities": [],
    }


def npm_doc(name, days_ago_created, versions=("1.0.0",), scripts=None, repo=True, description="pkg",
            latest=None):
    vs = {v: {"name": name, "version": v, "scripts": scripts or {}} for v in versions}
    time_map = {"created": iso(days_ago_created), "modified": iso(1)}
    for i, v in enumerate(versions):
        time_map[v] = iso(days_ago_created - i)
    doc = {"name": name, "description": description, "dist-tags": {"latest": latest or versions[-1]},
           "versions": vs, "time": time_map, "maintainers": [{"name": "dev"}]}
    if repo:
        doc["repository"] = {"type": "git", "url": f"git+https://github.com/example/{name}.git"}
    return doc


class FakeTransport:
    def __init__(self):
        self.routes = {}
        self.osv = {}
        self.calls = []

    def add(self, url, status, data=None):
        self.routes[url] = (status, data)

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append((method, url))
        if method == "POST" and "osv.dev" in url:
            q = json.loads(body)
            key = (q["package"]["ecosystem"], q["package"]["name"])
            return 200, {"vulns": [{"id": i} for i in self.osv.get(key, [])]} if key in self.osv else {}
        if url in self.routes:
            return self.routes[url]
        return 404, None


@pytest.fixture
def popular():
    return PopularIndex(lists={
        Ecosystem.PYPI: ["requests", "numpy", "flask", "python-dateutil", "huggingface-hub", "pandas",
                         "beautifulsoup4", "scikit-learn"],
        Ecosystem.NPM: ["express", "react", "lodash", "esbuild", "left-pad", "@types/node"],
    })


@pytest.fixture
def transport():
    t = FakeTransport()
    t.add("https://pypi.org/pypi/requests/json", 200, pypi_doc("requests", 5000, 150, org=None))
    t.add("https://pypi.org/pypi/reqeusts/json", 200, pypi_doc("reqeusts", 3, 1, repo=False, summary=""))
    t.add("https://pypi.org/pypi/tiny-helper/json", 200, pypi_doc("tiny-helper", 400, 6))
    t.add("https://pypi.org/pypi/fresh-but-legit/json", 200, pypi_doc("fresh-but-legit", 40, 3, org="acme"))
    t.add("https://pypi.org/simple/evil-quarantined/", 200, {"project-status": {"status": "quarantined"}, "files": []})
    t.add("https://pypi.org/simple/empty-project/", 200, {"project-status": {"status": "active"}, "files": []})
    t.add("https://registry.npmjs.org/express", 200, npm_doc("express", 4000, ("4.18.0", "4.19.0", "5.0.0")))
    t.add("https://registry.npmjs.org/esbuild", 200,
          npm_doc("esbuild", 2000, ("0.20.0", "0.21.0"), scripts={"postinstall": "node install.js"}))
    t.add("https://registry.npmjs.org/evil-holding", 200,
          npm_doc("evil-holding", 100, ("0.0.1-security",), description="security holding package"))
    t.add("https://registry.npmjs.org/new-helper-lib", 200,
          npm_doc("new-helper-lib", 30, ("1.0.0",), scripts={"postinstall": "node x.js"}, repo=False))
    t.add("https://api.npmjs.org/downloads/point/last-week/new-helper-lib", 200, {"downloads": 5})
    t.add("https://registry.npmjs.org/@scope%2Fthing", 200, npm_doc("@scope/thing", 900, ("1.0.0", "1.1.0", "2.0.0")))
    t.add("https://api.npmjs.org/downloads/point/last-week/@scope/thing", 200, {"downloads": 50000})
    t.osv[("PyPI", "malware-pkg")] = ["MAL-2025-1234"]
    return t


@pytest.fixture
def client(transport, popular, tmp_path):
    return RegistryClient(transport=transport, cache=FileCache(tmp_path / "cache"), popular=popular)
