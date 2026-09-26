"""T10: capabilities from the allowlist and the port rule."""
import pytest

from compiler.caps import capabilities, load_allowlist
from compiler.purls import identity, pep503


def caps(packages=(), ports=None, allowlist=None):
    return capabilities(packages, ports, allowlist)


def test_allowlist_hits_a_package():
    assert caps(["pkg:pypi/gunicorn@21.2.0"]) == [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]


def test_allowlist_ignores_version_and_qualifiers():
    purl = "pkg:deb/debian/iputils-ping@3:20221126-1?arch=amd64&distro=debian-12"
    assert caps([purl]) == [{"cap": "CAP_NET_RAW", "origin": "INFERRED"}]


def test_allowlist_matches_pypi_names_after_pep503():
    allow = {("pypi", None, "foo-bar"): ["CAP_SYS_TIME"]}
    assert caps(["pkg:pypi/Foo_Bar@1.0"], allowlist=allow) == [{"cap": "CAP_SYS_TIME", "origin": "INFERRED"}]


@pytest.mark.parametrize("port,fires", [("80/tcp", True), ("8080/tcp", False), ("53/udp", True),
                                        ("1023/tcp", True), ("1024/tcp", False)])
def test_port_rule(port, fires):
    expected = [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}] if fires else []
    assert caps(ports={port: {}}) == expected


def test_one_entry_per_capability():
    assert caps(["pkg:pypi/gunicorn@21.2.0", "pkg:pypi/uvicorn@0.30.0"], {"80/tcp": {}}) == \
        [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]


def test_nothing_matches():
    assert caps(["pkg:pypi/requests@2.32.3", "not a purl"], {"8080/tcp": {}, "junk": {}}) == []


def test_shipped_allowlist_skips_the_comment():
    allow = load_allowlist()
    assert ("pypi", None, "gunicorn") in allow
    assert all(isinstance(k, tuple) for k in allow)


def test_purl_helpers():
    assert pep503("Foo_Bar.baz--Qux") == "foo-bar-baz-qux"
    assert identity("pkg:deb/debian/libc6@2.36-9?arch=amd64") == ("deb", "debian", "libc6")
    assert identity("nonsense") is None
