"""T8: depths from synthetic CycloneDX documents (handoff T8 table and Section 7.4)."""
import pytest

from compiler.sbom import depths


def ref(name):
    return f"pkg:pypi/{name.lower()}@1.0?package-id={name}0f3a9c"


def purl(name):
    return f"pkg:pypi/{name.lower()}@1.0"


def bom(names, deps=None, extra=()):
    """names become components whose bom-ref carries ?package-id=, as syft writes them."""
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"bom-ref": ref(n), "type": "library", "name": n, "purl": purl(n)} for n in names]
                      + list(extra),
        "dependencies": [{"ref": ref(a), "dependsOn": [ref(b) for b in bs]} for a, bs in (deps or {}).items()],
    }


def depth_of(packages, name):
    return packages[purl(name)]["depth"]


# --- the T8 table ------------------------------------------------------------------------

def test_chain_with_package_id_bom_refs():
    packages, _ = depths(bom("ABC", {"A": "B", "B": "C"}))
    assert set(packages) == {purl("A"), purl("B"), purl("C")}     # keyed by purl, not bom-ref
    assert [depth_of(packages, n) for n in "ABC"] == [1, 2, 3]


def test_diamond_takes_the_minimum():
    packages, _ = depths(bom("ABC", {"A": "BC", "B": "C"}))
    assert depth_of(packages, "C") == 2


def test_component_in_no_edge_is_null():
    packages, _ = depths(bom("ABD", {"A": "B"}))
    assert depth_of(packages, "D") is None


def test_two_roots():
    packages, _ = depths(bom(["A1", "A2", "X", "Y"], {"A1": ["X"], "A2": ["Y"], "Y": ["X"]}))
    assert depth_of(packages, "X") == 2


def test_cycle_under_a_root_terminates():
    packages, _ = depths(bom("ABC", {"A": "B", "B": "C", "C": "B"}))
    assert (depth_of(packages, "B"), depth_of(packages, "C")) == (2, 3)


# --- more cases --------------------------------------------------------------------------------

def test_cycle_that_no_root_reaches_is_null():
    packages, _ = depths(bom("BC", {"B": "C", "C": "B"}))
    assert (depth_of(packages, "B"), depth_of(packages, "C")) == (None, None)


def test_components_without_a_purl_are_left_out(caplog):
    """As syft lists pip's Windows launchers: application, binary, no purl, in no edge."""
    launchers = [{"bom-ref": f"d60858f6579e7bb{i}", "type": "application", "name": name, "version": "1.1.0.14",
                  "properties": [{"name": "syft:package:type", "value": "binary"}]}
                 for i, name in enumerate(["Simple Launcher", "cli-64", "gui-32"])]
    caplog.set_level("INFO", logger="provbind.sbom")
    packages, unresolved = depths(bom("AB", {"A": "B"}, extra=launchers + [{"type": "library", "name": "no-ref"}]))
    assert set(packages) == {purl("A"), purl("B")}
    assert unresolved == 0.0                                     # not 4 of 6
    assert "4 SBOM components have no purl" in caplog.text and "cli-64" in caplog.text


def test_a_component_without_a_purl_still_carries_depth_through_its_edges():
    middle = {"bom-ref": "no-purl-middle", "type": "library", "name": "middle"}
    doc = bom("AC", extra=[middle])
    doc["dependencies"] = [{"ref": ref("A"), "dependsOn": ["no-purl-middle"]},
                           {"ref": "no-purl-middle", "dependsOn": [ref("C")]}]
    packages, _ = depths(doc)
    assert set(packages) == {purl("A"), purl("C")}
    assert (depth_of(packages, "A"), depth_of(packages, "C")) == (1, 3)


def test_duplicate_purls_keep_the_smallest_known_depth():
    dup = {"bom-ref": "pkg:pypi/c@1.0?package-id=second", "type": "library", "purl": purl("C")}
    packages, _ = depths(bom("ABC", {"A": "B", "B": "C"}, extra=[dup]))
    assert depth_of(packages, "C") == 3
    assert len(packages) == 3


def test_non_package_components_are_ignored():
    os_component = {"bom-ref": "os:debian@12", "type": "operating-system", "name": "debian"}
    packages, fraction = depths(bom("AB", {"A": "B"}, extra=[os_component]))
    assert set(packages) == {purl("A"), purl("B")}
    assert fraction == 0.0


def test_nested_components_count():
    parent = {"bom-ref": "p", "type": "application", "purl": "pkg:generic/p@1",
              "components": [{"bom-ref": ref("N"), "type": "library", "purl": purl("N")}]}
    packages, _ = depths(bom("A", {"A": "N"}, extra=[parent]))
    assert depth_of(packages, "N") == 2
    assert packages["pkg:generic/p@1"] == {"depth": None}


def test_edges_to_unknown_refs_do_not_break_anything():
    doc = bom("AB", {"A": "B"})
    doc["dependencies"].append({"ref": ref("B"), "dependsOn": ["not-a-component"]})
    doc["dependencies"].append({"dependsOn": ["no-ref-key"]})
    packages, _ = depths(doc)
    assert [depth_of(packages, n) for n in "AB"] == [1, 2]


@pytest.mark.parametrize("names,deps,expected", [
    ("ABCDE", {"A": "B", "B": "C"}, 0.4),           # D and E are in no edge
    ("AB", {"A": "B"}, 0.0),
    ("", {}, 0.0),                                  # no components at all
])
def test_unresolved_fraction(names, deps, expected):
    _, fraction = depths(bom(names, deps))
    assert fraction == pytest.approx(expected)


def test_missing_dependencies_section_leaves_everything_unresolved():
    doc = bom("AB")
    del doc["dependencies"]
    packages, fraction = depths(doc)
    assert all(v["depth"] is None for v in packages.values())
    assert fraction == 1.0
