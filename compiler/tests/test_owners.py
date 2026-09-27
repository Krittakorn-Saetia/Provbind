"""T9: ownership from synthetic dpkg and pip records."""
import pytest

from compiler.owners import Record, match, owners, read_metadata, read_record
from compiler.purls import pep503

SITE = "/usr/local/lib/python3.11/site-packages"
MERGED_USR = {"/bin": "usr/bin", "/lib": "usr/lib", "/usr/bin/sh": "dash"}

STATUS = b"""Package: coreutils
Essential: yes
Status: install ok installed
Priority: required
Architecture: amd64
Version: 9.1-1
Description: GNU core utilities
 This package contains the basic file, shell and text manipulation
 Version: 0.0-this-is-a-description-line

Package: libc6
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Version: 2.36-9+deb12u10

Package: dash
Status: install ok installed
Architecture: amd64
Version: 0.5.12-2

Package: removed-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: login
Status: install ok installed
Architecture: amd64
Version: 1:4.13+dfsg1-1
"""

SBOM_PURLS = [
    "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12",
    "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64&distro=debian-12",
    "pkg:deb/debian/dash@0.5.12-2?arch=amd64&distro=debian-12",
    "pkg:deb/debian/login@4.13%2Bdfsg1-1?arch=amd64&distro=debian-12",   # written without the epoch
    "pkg:pypi/requests@2.32.3",
    "pkg:pypi/charset-normalizer@3.3.2",
]


def image():
    """Canonical files with contents, on a merged-/usr link map."""
    files = {
        "/var/lib/dpkg/status": STATUS,
        "/var/lib/dpkg/info/coreutils.list": b"/.\n/bin\n/bin/ls\n/usr/share/doc/coreutils/README\n",
        "/var/lib/dpkg/info/libc6:amd64.list": b"/lib/x86_64-linux-gnu/libc.so.6\n",
        "/var/lib/dpkg/info/dash.list": b"/bin/dash\n",
        "/var/lib/dpkg/info/removed-thing.list": b"/usr/bin/removed\n",
        "/var/lib/dpkg/info/login.list": b"/bin/login\n",
        "/usr/bin/ls": b"ELF", "/usr/bin/dash": b"ELF", "/usr/bin/removed": b"x", "/usr/bin/login": b"ELF",
        "/usr/lib/x86_64-linux-gnu/libc.so.6": b"ELF",
        f"{SITE}/requests-2.32.3.dist-info/METADATA": b"Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\n",
        f"{SITE}/requests-2.32.3.dist-info/RECORD":
            b"requests/__init__.py,sha256=abc,4955\nrequests-2.32.3.dist-info/METADATA,,\n"
            b"requests-2.32.3.dist-info/RECORD,,\n",
        f"{SITE}/requests/__init__.py": b"",
        f"{SITE}/charset_normalizer-3.3.2.dist-info/METADATA":
            b"Name: Charset_Normalizer\nVersion: 3.3.2\n\nName: not-this-one\n",
        f"{SITE}/charset_normalizer-3.3.2.dist-info/RECORD":
            b'../../../bin/normalizer,sha256=xyz,250\n"charset_normalizer/odd,name.py",,\n',
        "/usr/local/bin/normalizer": b"#!/usr/local/bin/python3.11\n",
        f"{SITE}/charset_normalizer/odd,name.py": b"",
        "/app/app.py": b"import requests\n",
    }
    return files, dict(MERGED_USR)


def owned():
    files, links = image()
    return owners(files, links, files.get)


def test_dpkg_list_on_merged_usr_claims_the_real_path():
    own = owned()
    assert own["/usr/bin/ls"] == Record("deb", "coreutils", "9.1-1", "amd64")
    assert match(own, SBOM_PURLS)["/usr/bin/ls"] == "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12"


def test_multi_arch_list_file_name():
    own = owned()
    assert own["/usr/lib/x86_64-linux-gnu/libc.so.6"].name == "libc6"
    assert match(own, SBOM_PURLS)["/usr/lib/x86_64-linux-gnu/libc.so.6"].startswith("pkg:deb/debian/libc6@")


def test_only_installed_packages_and_present_files_count():
    own = owned()
    assert "/usr/bin/removed" not in own                         # deinstall ok config-files
    assert not {"/", "/usr/bin", "/usr/share/doc/coreutils/README"} & set(own)


def test_record_path_with_dotdot_resolves():
    own = owned()
    assert own["/usr/local/bin/normalizer"] == Record("pypi", "charset-normalizer", "3.3.2")


def test_record_csv_quoting():
    assert f"{SITE}/charset_normalizer/odd,name.py" in owned()
    assert read_record('a.py,sha256=x,1\n"b,c.py",,\n') == ["a.py", "b,c.py"]


def test_pep503():
    assert pep503("Foo_Bar") == "foo-bar"


def test_metadata_headers_stop_at_the_first_blank_line():
    assert read_metadata("Name: Foo_Bar\nVersion: 1.0\n\nName: body\n") == ("Foo_Bar", "1.0")
    assert read_metadata("Name: only-a-name\n") is None


def test_pypi_files_matched_to_purls_including_dist_info():
    m = match(owned(), SBOM_PURLS)
    assert m[f"{SITE}/requests/__init__.py"] == "pkg:pypi/requests@2.32.3"
    assert m[f"{SITE}/requests-2.32.3.dist-info/METADATA"] == "pkg:pypi/requests@2.32.3"
    assert m["/usr/local/bin/normalizer"] == "pkg:pypi/charset-normalizer@3.3.2"


def test_qualifiers_are_ignored_but_kept_in_the_result():
    m = match(owned(), SBOM_PURLS)
    assert m["/usr/bin/dash"] == "pkg:deb/debian/dash@0.5.12-2?arch=amd64&distro=debian-12"


def test_epoch_missing_from_the_sbom_still_matches():
    assert match(owned(), SBOM_PURLS)["/usr/bin/login"] == "pkg:deb/debian/login@4.13%2Bdfsg1-1?arch=amd64&distro=debian-12"


def test_unmatched_record_gives_none_and_a_log_line(caplog):
    m = match(owned(), [p for p in SBOM_PURLS if "coreutils" not in p])
    assert m["/usr/bin/ls"] is None
    assert "no SBOM component for deb coreutils 9.1-1" in caplog.text


def test_unowned_files_are_absent():
    assert "/app/app.py" not in owned()


def test_pip_wins_over_dpkg():
    files, links = image()
    files["/var/lib/dpkg/info/dash.list"] = b"/bin/dash\n/usr/local/bin/normalizer\n"
    assert owners(files, links, files.get)["/usr/local/bin/normalizer"].kind == "pypi"


def test_pep503_applies_to_the_sbom_side_too():
    # purl normalisation keeps the dot; PEP 503 turns it into a dash on both sides.
    files = {f"{SITE}/zope.interface-6.0.dist-info/METADATA": b"Name: zope.interface\nVersion: 6.0\n",
             f"{SITE}/zope.interface-6.0.dist-info/RECORD": b"zope/interface/__init__.py,,\n",
             f"{SITE}/zope/interface/__init__.py": b""}
    m = match(owners(files, {}, files.get), ["pkg:pypi/zope.interface@6.0"])
    assert m[f"{SITE}/zope/interface/__init__.py"] == "pkg:pypi/zope.interface@6.0"


def test_arch_breaks_ties_between_purls():
    own = {"/usr/lib/x86_64-linux-gnu/libc.so.6": Record("deb", "libc6", "2.36-9", "amd64")}
    purls = ["pkg:deb/debian/libc6@2.36-9?arch=i386", "pkg:deb/debian/libc6@2.36-9?arch=amd64"]
    assert match(own, purls)["/usr/lib/x86_64-linux-gnu/libc.so.6"] == "pkg:deb/debian/libc6@2.36-9?arch=amd64"


def test_no_dpkg_database_and_broken_dist_info(caplog):
    files = {f"{SITE}/broken-1.0.dist-info/RECORD": b"broken/x.py,,\n", f"{SITE}/broken/x.py": b""}
    assert owners(files, {}, files.get) == {}
    assert "broken-1.0.dist-info" in caplog.text


@pytest.mark.parametrize("listed", ["/bin/ls", "/usr/bin/ls", "/usr/bin/../bin/ls"])
def test_any_spelling_of_the_path_resolves(listed):
    files = {"/var/lib/dpkg/status": b"Package: coreutils\nStatus: install ok installed\nVersion: 9.1-1\n",
             "/var/lib/dpkg/info/coreutils.list": listed.encode() + b"\n", "/usr/bin/ls": b""}
    assert set(owners(files, {"/bin": "usr/bin"}, files.get)) == {"/usr/bin/ls"}
