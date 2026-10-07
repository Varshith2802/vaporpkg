from vaporpkg.models import Ecosystem
from vaporpkg.popular import PopularIndex, default_index, osa_distance


def test_osa_distance_basics():
    assert osa_distance("requests", "requests") == 0
    assert osa_distance("reqeusts", "requests") == 1  # transposition counts as one edit
    assert osa_distance("requets", "requests") == 1
    assert osa_distance("abc", "xyz", max_dist=2) == 3  # early exit returns max+1


def test_lookalike_rules(popular):
    assert popular.lookalike(Ecosystem.PYPI, "requests") is None  # popular itself
    t, reason, pts = popular.lookalike(Ecosystem.PYPI, "reqeusts")
    assert t == "requests" and pts == 35
    t, reason, _ = popular.lookalike(Ecosystem.PYPI, "pythondateutil")
    assert t == "python-dateutil" and "separators" in reason
    t, reason, pts = popular.lookalike(Ecosystem.PYPI, "pandas-python")
    assert t == "pandas" and pts == 20
    assert popular.lookalike(Ecosystem.NPM, "expresss")[0] == "express"
    assert popular.lookalike(Ecosystem.PYPI, "totally-unrelated-name") is None


def test_pep503_normalisation_counts_as_same(popular):
    assert popular.is_popular(Ecosystem.PYPI, "Python_DateUtil")
    assert popular.lookalike(Ecosystem.PYPI, "python.dateutil") is None


def test_bundled_lists_load():
    idx = default_index()
    assert idx.rank(Ecosystem.PYPI, "requests") is not None
    assert idx.rank(Ecosystem.NPM, "express") is not None
    assert idx.lookalike(Ecosystem.PYPI, "reqeusts")[0] == "requests"
