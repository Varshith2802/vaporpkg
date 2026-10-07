from vaporpkg.engine import check_candidates
from vaporpkg.models import Candidate, Ecosystem, Verdict


def run(client, *items):
    cands = [Candidate(eco, name) for eco, name in items]
    return {a.name: a for a in check_candidates(cands, client)}


def test_not_found_is_blocked_with_suggestion(client):
    r = run(client, (Ecosystem.PYPI, "huggingface-cli"), (Ecosystem.NPM, "expresss"))
    assert r["huggingface-cli"].verdict is Verdict.BLOCK
    assert r["huggingface-cli"].signals[0].code == "NOT_FOUND"
    assert r["expresss"].verdict is Verdict.BLOCK
    assert "Did you mean 'express'" in r["expresss"].signals[0].message


def test_popular_package_ok(client):
    r = run(client, (Ecosystem.PYPI, "requests"), (Ecosystem.NPM, "express"), (Ecosystem.NPM, "esbuild"))
    assert all(a.verdict is Verdict.OK for a in r.values()), {k: (a.verdict, a.signals) for k, a in r.items()}
    assert any(s.code == "INSTALL_SCRIPTS" for s in r["esbuild"].signals)  # still reported, but capped


def test_fresh_typosquat_blocked(client):
    a = run(client, (Ecosystem.PYPI, "reqeusts"))["reqeusts"]
    codes = {s.code for s in a.signals}
    assert {"VERY_NEW", "SINGLE_RELEASE", "NO_REPOSITORY", "LOOKALIKE"} <= codes
    assert a.verdict is Verdict.BLOCK


def test_security_holding_and_quarantine_and_osv(client):
    r = run(client, (Ecosystem.NPM, "evil-holding"), (Ecosystem.PYPI, "evil-quarantined"),
            (Ecosystem.PYPI, "malware-pkg"))
    assert r["evil-holding"].verdict is Verdict.BLOCK
    assert any(s.code == "SECURITY_HOLDING" for s in r["evil-holding"].signals)
    assert any(s.code == "QUARANTINED" for s in r["evil-quarantined"].signals)
    assert any(s.code == "KNOWN_MALICIOUS" for s in r["malware-pkg"].signals)


def test_new_unknown_npm_with_postinstall_blocked(client):
    a = run(client, (Ecosystem.NPM, "new-helper-lib"))["new-helper-lib"]
    codes = {s.code for s in a.signals}
    assert {"NEW", "SINGLE_RELEASE", "VERY_LOW_DOWNLOADS", "NO_REPOSITORY", "INSTALL_SCRIPTS"} <= codes
    assert a.verdict is Verdict.BLOCK


def test_benign_small_package_ok_and_org_bonus(client):
    r = run(client, (Ecosystem.PYPI, "tiny-helper"), (Ecosystem.PYPI, "fresh-but-legit"),
            (Ecosystem.NPM, "@scope/thing"))
    assert r["tiny-helper"].verdict is Verdict.OK
    assert r["@scope/thing"].verdict is Verdict.OK
    legit = r["fresh-but-legit"]
    assert any(s.code == "VERIFIED_ORG" for s in legit.signals)
    assert legit.verdict is Verdict.OK  # NEW(25) - org(10) = 15


def test_import_only_candidates_warn_instead_of_block(client):
    cands = [Candidate(Ecosystem.PYPI, "mylocalhelpers", "import", confidence="low")]
    a = check_candidates(cands, client)[0]
    assert a.verdict is Verdict.WARN
    assert a.signals[0].code == "IMPORT_NOT_ON_REGISTRY"


def test_lookup_error_reported(popular, tmp_path):
    from vaporpkg.cache import FileCache
    from vaporpkg.registry import RegistryClient

    def broken(*_a):
        raise OSError("network down")

    c = RegistryClient(transport=broken, cache=FileCache(tmp_path / "c"), popular=popular)
    a = check_candidates([Candidate(Ecosystem.PYPI, "requests")], c)[0]
    assert a.verdict is Verdict.ERROR


def test_cache_avoids_second_request(client, transport):
    run(client, (Ecosystem.PYPI, "tiny-helper"))
    n = len(transport.calls)
    run(client, (Ecosystem.PYPI, "tiny-helper"))
    assert len(transport.calls) == n


def test_registered_name_without_releases(client):
    a = run(client, (Ecosystem.PYPI, "empty-project"))["empty-project"]
    assert a.verdict is Verdict.BLOCK
    assert "no installable releases" in a.signals[0].message
