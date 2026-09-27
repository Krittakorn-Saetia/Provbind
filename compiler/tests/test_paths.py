"""T6: realpath (handoff T6 table and Section 7.2), canonical keys, symlink targets."""
import pytest

from compiler.layers import FileEntry
from compiler.paths import SymlinkLoop, all_dirs, canonicalise, realpath, resolve_links


def entry(layer, digest="0" * 64):
    return FileEntry(digest, layer, "0644", 0, layer, 0)


# --- the T6 table ------------------------------------------------------------------------

@pytest.mark.parametrize("path,links,expected", [
    ("/bin/ls", {"/bin": "usr/bin"}, "/usr/bin/ls"),
    ("/usr/local/bin/python",
     {"/usr/local/bin/python": "python3", "/usr/local/bin/python3": "python3.11"},
     "/usr/local/bin/python3.11"),
    ("/opt/app/lib/x", {"/opt/app/lib": "../shared"}, "/opt/shared/x"),
    ("/bin/sh", {"/bin": "usr/bin", "/usr/bin/sh": "dash"}, "/usr/bin/dash"),
], ids=["merged-usr", "python-chain", "relative-dotdot", "bin-sh"])
def test_realpath_table(path, links, expected):
    assert realpath(path, links) == expected


def test_loop_raises():
    with pytest.raises(SymlinkLoop):
        realpath("/loop", {"/loop": "/loop2", "/loop2": "/loop"})


# --- more realpath cases ----------------------------------------------------------------------

def test_merged_usr_dynamic_loader():
    links = {"/lib64": "usr/lib64",
             "/usr/lib64/ld-linux-x86-64.so.2": "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}
    assert realpath("/lib64/ld-linux-x86-64.so.2", links) == "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"


def test_absolute_target_restarts_at_root():
    assert realpath("/a/b/c", {"/a/b": "/x"}) == "/x/c"


def test_dotdot_is_physical_after_a_link():
    # /opt/app/lib is /opt/shared, so /opt/app/lib/.. is /opt, not /opt/app.
    assert realpath("/opt/app/lib/../y", {"/opt/app/lib": "../shared"}) == "/opt/y"


def test_dotdot_stops_at_root():
    assert realpath("/../../a/./b", {}) == "/a/b"


def test_forty_hops_resolve_and_forty_one_raise():
    chain40 = {f"/l{i}": f"/l{i + 1}" for i in range(40)}
    assert realpath("/l0", chain40) == "/l40"
    with pytest.raises(SymlinkLoop):
        realpath("/l0", {f"/l{i}": f"/l{i + 1}" for i in range(41)})


# --- canonical keys ----------------------------------------------------------------------------

def test_file_keys_move_under_the_real_parent():
    c = canonicalise({"/bin/foo": entry(1)}, {"/bin": "usr/bin"}, {"/usr", "/usr/bin"}, {"/bin": 0})
    assert set(c.files) == {"/usr/bin/foo"}
    assert c.links == {"/bin": "usr/bin"}


@pytest.mark.parametrize("bin_layer,usr_layer,winner", [(2, 0, "/bin/foo"), (0, 2, "/usr/bin/foo")])
def test_collision_keeps_the_higher_layer(bin_layer, usr_layer, winner):
    files = {"/bin/foo": entry(bin_layer, "a" * 64), "/usr/bin/foo": entry(usr_layer, "b" * 64)}
    c = canonicalise(files, {"/bin": "usr/bin"}, set(), {"/bin": 0})
    assert c.files["/usr/bin/foo"] is files[winner]


def test_file_and_link_collision_keeps_the_higher_layer():
    c = canonicalise({"/bin/sh": entry(3)}, {"/bin": "usr/bin", "/usr/bin/sh": "dash"}, set(),
                     {"/bin": 0, "/usr/bin/sh": 0})
    assert "/usr/bin/sh" in c.files and "/usr/bin/sh" not in c.links


def test_link_keys_move_under_the_real_parent():
    c = canonicalise({}, {"/bin": "usr/bin", "/bin/sh": "dash"}, set(), {"/bin": 0, "/bin/sh": 0})
    assert c.links == {"/bin": "usr/bin", "/usr/bin/sh": "dash"}
    assert c.link_layers == {"/bin": 0, "/usr/bin/sh": 0}


def test_file_under_a_looping_directory_is_dropped(caplog):
    c = canonicalise({"/loop/f": entry(0)}, {"/loop": "/loop2", "/loop2": "/loop"}, set(),
                     {"/loop": 0, "/loop2": 0})
    assert c.files == {}
    assert "symlink loop" in caplog.text


def test_dirs_are_canonical():
    c = canonicalise({}, {"/lib": "usr/lib"}, {"/lib/x86_64-linux-gnu", "/usr/lib"}, {"/lib": 0})
    assert c.dirs == {"/usr/lib/x86_64-linux-gnu", "/usr/lib"}


# --- symlink targets for the envelope ---------------------------------------------------------

def test_symlink_targets_resolve_or_dangle():
    links = {"/bin": "usr/bin", "/usr/bin/sh": "dash", "/usr/bin/gone": "nowhere",
             "/loop": "/loop2", "/loop2": "/loop", "/root-link": "/"}
    files = {"/usr/bin/dash": entry(0)}
    out = resolve_links(links, files, {"/usr", "/usr/bin"})
    assert out == {"/bin": "/usr/bin", "/usr/bin/sh": "/usr/bin/dash", "/usr/bin/gone": None,
                   "/loop": None, "/loop2": None, "/root-link": "/"}


def test_implicit_parent_directories_count_as_targets():
    # The layer lists no directory entries at all; /opt/shared exists because a file is in it.
    out = resolve_links({"/opt/app/lib": "../shared"}, {"/opt/shared/x": entry(0)}, set())
    assert out == {"/opt/app/lib": "/opt/shared"}


def test_all_dirs_includes_parents():
    assert all_dirs(["/a/b/c"], ["/l/m"], ["/d"]) == {"/", "/a", "/a/b", "/l", "/d"}
