"""Tiny JSON file cache with per-entry TTL (no external dependencies)."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    base = os.environ.get("VAPORPKG_CACHE_DIR")
    if base:
        return Path(base)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "vaporpkg"
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "vaporpkg" / "cache"
    return Path.home() / ".cache" / "vaporpkg"


class FileCache:
    def __init__(self, directory: Path | None = None, enabled: bool = True):
        self.dir = directory or default_cache_dir()
        self.enabled = enabled

    def _path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.dir / h[:2] / f"{h}.json"

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        p = self._path(key)
        try:
            entry = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if entry.get("expires", 0) < time.time():
            return None
        return entry.get("value")

    def set(self, key: str, value: Any, ttl: float) -> None:
        if not self.enabled:
            return
        p = self._path(key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps({"expires": time.time() + ttl, "value": value}), encoding="utf-8")
            os.replace(tmp, p)
        except OSError:
            pass  # caching is best-effort

    def clear(self) -> int:
        n = 0
        if self.dir.exists():
            for p in self.dir.rglob("*.json"):
                try:
                    p.unlink()
                    n += 1
                except OSError:
                    pass
        return n
