"""T5: the layer union, on synthetic tars (handoff T5 table and Section 7.1)."""
import os

import pytest

from compiler.layers import LayerError, mode_string, normalise, union

from .helpers import Tar, make_layer, sha


@pytest.fixture
def build(tmp_path):
    """build(tar0, tar1, ...) -> Union of those layers, in order."""
    opened = []

    def _build(*tars, kind="gzip", media_type=""):
        blobs = [make_layer(tmp_path, i, t, kind, media_type) for i, t in enumerate(tars)]
        u = union(blobs)
        opened.append(u)
        return u

    yield _build
    for u in opened:
        u.close()


# --- the T5 table ------------------------------------------------------------------------

def test_overwrite(build):
    u = build(Tar().dir("a").file("a/f", b"x"), Tar().file("a/f", b"y"))
    assert u.files["/a/f"][:2] == (sha(b"y"), 1)


def test_file_whiteout(build):
    u = build(Tar().dir("a").file("a/f", b"x"), Tar().whiteout("a/.wh.f"))
    assert "/a/f" not in u.files
    assert "/a" in u.dirs


def test_directory_whiteout(build):
    u = build(Tar().dir("a").dir("a/b").file("a/b/c"), Tar().whiteout("a/.wh.b"))
    assert "/a/b/c" not in u.files
    assert "/a/b" not in u.dirs


@pytest.mark.parametrize("marker_first", [False, True], ids=["opaque-after-file", "opaque-before-file"])
def test_opaque_marker_hides_only_lower_children(build, marker_first):
    top = Tar().dir("d")
    if marker_first:
        top.whiteout("d/.wh..wh..opq").file("d/y", b"y")
    else:
        top.file("d/y", b"y").whiteout("d/.wh..wh..opq")
    u = build(Tar().dir("d").file("d/x", b"x"), top)
    assert "/d/y" in u.files
    assert "/d/x" not in u.files
    assert "/d" in u.dirs


@pytest.mark.parametrize("marker_first", [False, True], ids=["whiteout-after-file", "whiteout-before-file"])
def test_whiteout_never_hides_its_own_layer(build, marker_first):
    top = Tar().dir("e")
    if marker_first:
        top.whiteout("e/.wh.z").file("e/z", b"new")
    else:
        top.file("e/z", b"new").whiteout("e/.wh.z")
    u = build(Tar().dir("e").file("e/z", b"old"), top)
    assert u.files["/e/z"][:2] == (sha(b"new"), 1)


def test_hardlink(build):
    u = build(Tar().dir("usr").dir("usr/bin").file("usr/bin/a", b"A", 0o755).hardlink("usr/bin/b", "usr/bin/a"))
    assert u.files["/usr/bin/b"][:3] == (sha(b"A"), 0, "0755")
    assert u.read("/usr/bin/b") == b"A"


def test_hardlink_to_a_lower_layer(build):
    u = build(Tar().file("a", b"A"), Tar().hardlink("b", "a"))
    assert u.files["/b"][:2] == (sha(b"A"), 1)
    assert u.read("/b") == b"A"


def test_symlink(build):
    u = build(Tar().symlink("bin", "usr/bin"))
    assert u.links == {"/bin": "usr/bin"}
    assert "/bin" not in u.files
    assert u.link_layers == {"/bin": 0}


def test_symlink_replaces_file(build):
    u = build(Tar().file("x", b"x"), Tar().symlink("x", "/y"))
    assert u.links["/x"] == "/y"
    assert "/x" not in u.files


# --- the rows added with decision D1 ---------------------------------------------------------

def test_symlink_replaces_directory(build):
    u = build(Tar().dir("x").file("x/a"), Tar().symlink("x", "/y"))
    assert "/x/a" not in u.files
    assert "/x" not in u.dirs
    assert u.links["/x"] == "/y"


def test_file_replaces_directory(build):
    u = build(Tar().dir("x").file("x/a").symlink("x/l", "a").dir("x/sub"), Tar().file("x", b"f"))
    assert "/x/a" not in u.files
    assert "/x/l" not in u.links
    assert not {"/x", "/x/sub"} & u.dirs
    assert u.files["/x"].layer == 1


def test_directory_replaces_symlink(build):
    u = build(Tar().symlink("x", "/y").dir("y").file("y/c", b"c"), Tar().dir("x").file("x/b", b"b"))
    assert "/x" not in u.links
    assert "/x" in u.dirs
    assert "/x/b" in u.files
    assert "/y/c" in u.files


# --- compression and media types -------------------------------------------------------------

def _two_layers():
    return (Tar().dir("usr").dir("usr/bin").file("usr/bin/a", b"A", 0o755).symlink("bin", "usr/bin")
                .dir("d").file("d/x", b"x"),
            Tar().dir("d").whiteout("d/.wh..wh..opq").file("d/y", b"y").hardlink("usr/bin/b", "usr/bin/a"))


def _summary(u):
    return ({p: e[:3] for p, e in u.files.items()}, u.links, u.dirs)


@pytest.mark.parametrize("media_type", ["", None], ids=["by-media-type", "by-magic-bytes"])
def test_gzip_zstd_and_plain_tar_give_identical_output(build, media_type):
    results = [_summary(build(*_two_layers(), kind=kind, media_type=media_type))
               for kind in ("gzip", "zstd", "tar")]
    assert results[0] == results[1] == results[2]
    assert set(results[0][0]) == {"/usr/bin/a", "/usr/bin/b", "/d/y"}


def test_docker_media_type_is_gzip(build):
    u = build(Tar().file("f", b"1"), media_type="application/vnd.docker.image.rootfs.diff.tar.gzip")
    assert u.files["/f"].sha256 == sha(b"1")


def test_media_type_that_does_not_match_the_bytes_raises(build):
    with pytest.raises(LayerError):
        build(Tar().file("f", b"1"), kind="tar", media_type="application/vnd.oci.image.layer.v1.tar+gzip")


def test_empty_blob_is_an_empty_layer(build):
    u = build(Tar().file("f", b"1"), b"", kind="tar")
    assert set(u.files) == {"/f"}


# --- names, modes, reads ------------------------------------------------------------------------

def test_names_are_normalised(build):
    u = build(Tar().file("./a//b", b"1").file("/c", b"2").dir("d/").file("e/./f/../g", b"3").dir("./"))
    assert set(u.files) == {"/a/b", "/c", "/e/g"}
    assert "/d" in u.dirs


@pytest.mark.parametrize("name,expected", [
    ("./a", "/a"), ("a//b/", "/a/b"), ("/abs", "/abs"), ("//x", "/x"), ("a/../b", "/b"),
    ("../../etc/passwd", "/etc/passwd"), ("./", None), (".", None),
])
def test_normalise(name, expected):
    assert normalise(name) == expected


def test_mode_strings(build):
    u = build(Tar().file("su", b"s", 0o4755).file("passwd", b"p", 0o644).file("typed", b"t", 0o100755))
    assert u.files["/su"].mode == "04755"        # "%04o" would give "4755", which the schema rejects
    assert u.files["/passwd"].mode == "0644"
    assert u.files["/typed"].mode == "0755"      # file-type bits are dropped
    assert mode_string(0) == "0000"


def test_read_returns_the_effective_version(build):
    u = build(Tar().file("a", b"old"), Tar().file("a", b"hello world"))
    assert u.read("/a") == b"hello world"
    assert u.read("/a", 5) == b"hello"
    assert u.read("/missing") is None


# --- more replacement cases -----------------------------------------------------------------------

def test_whiteout_removes_a_lower_symlink(build):
    u = build(Tar().symlink("l", "t"), Tar().whiteout(".wh.l"))
    assert "/l" not in u.links and "/l" not in u.link_layers


def test_directory_whiteout_then_recreated_in_the_same_layer(build):
    u = build(Tar().dir("a").dir("a/b").file("a/b/old"), Tar().whiteout("a/.wh.b").dir("a/b").file("a/b/new"))
    assert "/a/b/old" not in u.files
    assert "/a/b/new" in u.files


def test_special_file_replaces_but_is_not_listed(build):
    u = build(Tar().file("p", b"x"), Tar().fifo("p"))
    assert "/p" not in u.files and "/p" not in u.links


def test_later_entry_for_a_path_wins_within_a_layer(build):
    u = build(Tar().file("x", b"first").symlink("x", "target"))
    assert "/x" not in u.files and u.links["/x"] == "target"


def test_hardlink_to_a_missing_target_is_skipped(build, caplog):
    u = build(Tar().hardlink("b", "nowhere"))
    assert "/b" not in u.files
    assert "target not found" in caplog.text


def test_close_removes_the_temporary_layers(tmp_path):
    u = union([make_layer(tmp_path, 0, Tar().file("f", b"1"))])
    workdir = u.store.dir
    with u:
        assert u.read("/f") == b"1"
    assert not os.path.exists(workdir)
