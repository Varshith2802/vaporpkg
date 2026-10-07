from pathlib import Path

from vaporpkg.models import Ecosystem
from vaporpkg.parsers import (extract_from_text, npm_spec_to_name, parse_npm_args, parse_package_json,
                              parse_pip_args, parse_pyproject, parse_requirement, parse_requirements)


def test_parse_requirement_variants():
    assert parse_requirement("requests") == "requests"
    assert parse_requirement("requests[socks]>=2.0 ; python_version>'3.8'") == "requests"
    assert parse_requirement("Django==4.2") == "Django"
    assert parse_requirement("numpy~=1.26") == "numpy"
    assert parse_requirement("pkg @ https://example.com/pkg.whl") is None
    assert parse_requirement("./local/dir") is None
    assert parse_requirement("git+https://github.com/a/b") is None
    assert parse_requirement("dist/foo-1.0-py3-none-any.whl") is None
    assert parse_requirement("https://x.y/z.tar.gz") is None


def test_requirements_file_with_includes(tmp_path: Path):
    (tmp_path / "base.txt").write_text("flask>=2\n# comment\n")
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\n-c constraints.txt\n--index-url https://pypi.org/simple\n"
        "requests==2.31 --hash=sha256:abc \\\n    --hash=sha256:def\n-e ./mylib\nnumpy  # inline comment\n"
        "pkg @ https://example.com/p.whl\n")
    names = [c.name for c in parse_requirements(tmp_path / "requirements.txt")]
    assert names == ["flask", "requests", "numpy"]
    req = [c for c in parse_requirements(tmp_path / "requirements.txt") if c.name == "requests"][0]
    assert req.line == 4


def test_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('''
[build-system]
requires = ["setuptools>=68"]
[project]
name = "x"
dependencies = ["httpx>=0.27", "rich"]
[project.optional-dependencies]
dev = ["pytest"]
[dependency-groups]
lint = ["ruff", {include-group = "dev"}]
[tool.poetry.dependencies]
python = "^3.11"
localpkg = {path = "../localpkg"}
fastapi = "^0.110"
''')
    names = [c.name for c in parse_pyproject(tmp_path / "pyproject.toml")]
    assert names == ["httpx", "rich", "pytest", "ruff", "setuptools", "fastapi"]


def test_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text('''{
  "dependencies": {"express": "^4.18.0", "my-alias": "npm:lodash@^4", "local": "file:../local",
                   "gh": "user/repo#main", "@types/node": "^20"},
  "devDependencies": {"jest": "^29"}
}''')
    cands = parse_package_json(tmp_path / "package.json")
    assert [c.name for c in cands] == ["express", "lodash", "@types/node", "jest"]
    assert cands[0].line == 2


def test_npm_spec_to_name():
    assert npm_spec_to_name("lodash@4.17.21") == "lodash"
    assert npm_spec_to_name("@types/node@^20") == "@types/node"
    assert npm_spec_to_name("@types/node") == "@types/node"
    assert npm_spec_to_name("alias@npm:react@18") == "react"
    assert npm_spec_to_name("user/repo") is None
    assert npm_spec_to_name("./pkg.tgz") is None
    assert npm_spec_to_name("Bad_Upper") is None


def test_pip_and_npm_args(tmp_path: Path):
    (tmp_path / "r.txt").write_text("pandas\n")
    c = parse_pip_args(["-U", "--index-url", "https://x", "requests>=2", "-r", "r.txt", "-e", ".", "--user"],
                       base_dir=tmp_path)
    assert [x.name for x in c] == ["requests", "pandas"]
    c = parse_npm_args(["-D", "--registry", "https://r", "react@18", "@scope/pkg", "./local"])
    assert [x.name for x in c] == ["react", "@scope/pkg"]


LLM_ANSWER = '''
Sure! First install the dependencies:

```bash
pip install fastapi uvicorn "pydantic>=2" && python -m pip install --upgrade sklearn-utils-pro
npm install express-validator-plus@1.2 --save
npx create-shiny-app my-app
```

Then:

```python
import os, json
import numpy as np
from bs4 import BeautifulSoup
from mylocalhelpers.sub import thing
import cv2
```

```js
const express = require('express');
import fs from 'fs';
import { z } from "zod";
import x from './local.js';
```

requirements.txt:

```
flask==3.0
huggingface-cli
```

You can also run `pip3 install torchaudio-extra` if needed.
'''


def test_extract_from_llm_answer():
    cands = extract_from_text(LLM_ANSWER)
    got = {(c.ecosystem, c.name, c.confidence) for c in cands}
    for name in ("fastapi", "uvicorn", "pydantic", "sklearn-utils-pro", "flask", "huggingface-cli", "torchaudio-extra"):
        assert (Ecosystem.PYPI, name, "high") in got, name
    for name in ("express-validator-plus", "create-shiny-app"):
        assert (Ecosystem.NPM, name, "high") in got, name
    assert (Ecosystem.PYPI, "numpy", "low") in got
    assert (Ecosystem.PYPI, "beautifulsoup4", "low") in got  # import name mapped to distribution
    assert (Ecosystem.PYPI, "opencv-python", "low") in got
    assert (Ecosystem.PYPI, "mylocalhelpers", "low") in got
    assert (Ecosystem.NPM, "express", "low") in got
    assert (Ecosystem.NPM, "zod", "low") in got
    names = {c.name for c in cands}
    assert "os" not in names and "json" not in names and "fs" not in names  # stdlib / builtins skipped
    assert "my-app" not in names  # npx argument after the package is not a package
