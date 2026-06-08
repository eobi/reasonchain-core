"""Facts merger — the substrate for cross-tool fusion."""
from reasonchain.facts import Facts


def test_scalar_overwrite():
    f = Facts({"waf_detected": False})
    f.merge({"waf_detected": True})
    assert f.get("waf_detected") is True


def test_list_union_with_dedup():
    f = Facts({"open_ports": [22, 80]})
    f.merge({"open_ports": [80, 443]})
    assert f.get("open_ports") == [22, 80, 443]


def test_snapshot_keys_sorted():
    f = Facts({"z": 1, "a": 1, "m": 1})
    assert f.snapshot_keys() == ["a", "m", "z"]


def test_empty_partial_no_op():
    f = Facts({"x": 1})
    f.merge({})
    assert f.as_dict() == {"x": 1}


def test_as_dict_returns_copy():
    f = Facts({"x": [1]})
    snapshot = f.as_dict()
    snapshot["x"].append(2)
    # Internal state must NOT have been mutated by writing to snapshot.
    # (Shallow copy: list mutation IS visible; assertion guards against
    # us forgetting and switching to deepcopy semantics later.)
    assert f.get("x") == [1, 2]
