"""Tests for RunOnceEx: a registry subtree that may not exist when FIM starts."""

import baseline
from baseline import TRUNCATED, UNREADABLE, Item, KeyContents, compare, read_key_tree
from targets import APPEARANCE_WATCHES, REGISTRY_TARGETS

ROOT_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"
SHOWN = "HKLM\\" + ROOT_KEY


def tree(value_name="1", data="C:\\Path\\x.dll", reg_type=1):
    return {
        ROOT_KEY: KeyContents(subkeys=("0001",)),
        ROOT_KEY + "\\0001": KeyContents(subkeys=("Depend",)),
        ROOT_KEY + "\\0001\\Depend": KeyContents(values=((value_name, data, reg_type),)),
    }


def read(contents, subtree=True):
    return read_key_tree(contents.get, SHOWN, ROOT_KEY, subtree)


def test_the_runonceex_targets_are_subtrees_that_may_be_missing():
    targets = [target for target in REGISTRY_TARGETS if target.name.endswith("RunOnceEx")]
    assert sorted(target.name for target in targets) == [
        SHOWN,
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    ]
    assert all(target.subtree and target.optional for target in targets)
    assert not any(target.subtree for target in REGISTRY_TARGETS if not target.name.endswith("RunOnceEx"))


def test_a_watch_on_each_parent_tells_fim_when_runonceex_appears():
    assert sorted(target.name for target in APPEARANCE_WATCHES) == [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion",
    ]
    watched = {target.name for target in REGISTRY_TARGETS}
    assert not any(target.name in watched for target in APPEARANCE_WATCHES)


def test_a_subtree_read_finds_values_in_numbered_subkeys():
    assert read(tree()) == {f"{SHOWN}\\0001\\Depend\\1": Item("registry", "C:\\Path\\x.dll", 1)}


def test_a_read_without_subtree_ignores_subkeys():
    assert read(tree(), subtree=False) == {}


def test_a_missing_key_reads_as_empty():
    assert read({}) == {}


def test_adding_then_removing_the_value_is_seen_as_added_then_removed():
    before = read({})
    during = read(tree())
    after = read(tree() | {ROOT_KEY + "\\0001\\Depend": KeyContents()})
    assert [change.change_kind for change in compare(before, during)] == ["added"]
    assert [change.change_kind for change in compare(during, after)] == ["removed"]


def test_an_unnamed_value_is_the_default_value():
    assert f"{SHOWN}\\0001\\Depend\\(Default)" in read(tree(value_name=""))


def test_registry_data_is_encoded_like_the_flat_keys():
    assert read(tree(data=b"\x01\xff", reg_type=3))[f"{SHOWN}\\0001\\Depend\\1"] == Item("registry", "01ff", 3)


def test_an_unreadable_subkey_is_reported_not_skipped():
    contents = tree() | {ROOT_KEY + "\\0001\\Depend": KeyContents(unreadable=True)}
    assert read(contents) == {f"{SHOWN}\\0001\\Depend\\({UNREADABLE})": Item("registry", UNREADABLE)}


def test_a_tree_that_is_too_deep_is_reported(monkeypatch):
    monkeypatch.setattr(baseline, "MAX_TREE_DEPTH", 1)
    items = read(tree())
    assert f"{SHOWN}\\0001\\({TRUNCATED})" in items
    assert not any(name.endswith("\\1") for name in items)


def test_a_tree_with_too_many_keys_is_reported(monkeypatch):
    monkeypatch.setattr(baseline, "MAX_TREE_KEYS", 3)
    contents = {ROOT_KEY: KeyContents(subkeys=tuple(f"k{index}" for index in range(10)))}
    for index in range(10):
        contents[f"{ROOT_KEY}\\k{index}"] = KeyContents(subkeys=("deeper",))
    assert any(name.endswith(f"({TRUNCATED})") for name in read(contents))
