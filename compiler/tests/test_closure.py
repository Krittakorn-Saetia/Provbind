"""T7: the entrypoint closure on synthetic images built from minimal ELF files."""
import pytest

from compiler.closure import closure, env_command, parse_shebang

from .helpers import EM_AARCH64, MemFS, config, make_elf

LOADER = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LIBM = "/usr/lib/x86_64-linux-gnu/libm.so.6"
PY = "/usr/local/bin/python3.11"
LIBPY = "/usr/local/lib/libpython3.11.so.1.0"
PYTHON_CLOSURE = sorted([LOADER, LIBC, LIBM, PY, LIBPY])
INTERP = "/lib64/ld-linux-x86-64.so.2"
PY_ENV = ["PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"]

MERGED_USR = {
    "/bin": "usr/bin", "/lib": "usr/lib", "/lib64": "usr/lib64",
    "/usr/lib64/ld-linux-x86-64.so.2": "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/bin/sh": "dash",
    "/usr/local/bin/python": "python3", "/usr/local/bin/python3": "python3.11",
}


def python_image(extra=None, modes=None):
    """A python:3.11-slim-shaped image: merged /usr, Python in /usr/local, ld.so.conf includes."""
    contents = {
        PY: make_elf(interp=INTERP, needed=["libpython3.11.so.1.0", "libc.so.6"]),
        LIBPY: make_elf(needed=["libm.so.6", "libc.so.6"]),
        LIBC: make_elf(needed=["ld-linux-x86-64.so.2"]),
        LIBM: make_elf(needed=["libc.so.6"]),
        LOADER: make_elf(),
        "/usr/bin/dash": make_elf(interp=INTERP, needed=["libc.so.6"]),
        "/usr/bin/ls": make_elf(interp=INTERP, needed=["libselinux.so.1", "libc.so.6"]),
        "/usr/bin/env": make_elf(interp=INTERP, needed=["libc.so.6"]),
        "/etc/ld.so.conf": b"include /etc/ld.so.conf.d/*.conf\n",
        "/etc/ld.so.conf.d/libc.conf": b"# libc default configuration\n/usr/local/lib\n",
        "/etc/ld.so.conf.d/x86_64-linux-gnu.conf":
            b"# Multiarch support\n/usr/local/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n",
        "/app/app.py": b"import requests\n",
    }
    contents.update(extra or {})
    return MemFS(contents, dict(MERGED_USR), modes={"/app/app.py": "0644", **(modes or {})})


# --- shebang parsing ------------------------------------------------------------------------------

@pytest.mark.parametrize("head,expected", [
    (b"#!/bin/sh\nexec python\n", ("/bin/sh", None)),
    (b"#!/usr/bin/env python3\n", ("/usr/bin/env", "python3")),
    (b"#!/usr/bin/env -S python3 -u\n", ("/usr/bin/env", "-S python3 -u")),
    (b"#! /usr/bin/python3\t-u  \r\n", ("/usr/bin/python3", "-u")),
    (b"#!\n", None),
    (b"\x7fELF\x02\x01", None),
])
def test_parse_shebang(head, expected):
    assert parse_shebang(head) == expected


@pytest.mark.parametrize("arg,expected", [
    ("python3", "python3"),
    ("-S python3 -u", "python3"),
    ("-Spython3 -u", "python3"),
    ("--split-string=python3 -u", "python3"),
    ("-S PYTHONPATH=/opt/x python3", "python3"),
    ("-u HOME -C /tmp python3", "python3"),
    ("-i -- python3", "python3"),
    ("-S", None),
    ("FOO=1", None),
])
def test_env_command(arg, expected):
    assert env_command(arg) == expected


# --- the stand-in's shape ------------------------------------------------------------------------

def test_python_entrypoint_closure():
    got = closure(config(cmd=["python", "app.py"], env=PY_ENV, working_dir="/app"), python_image())
    assert got == PYTHON_CLOSURE                   # libpython comes from ld.so.conf's include
    assert "/usr/bin/ls" not in got and "/usr/bin/dash" not in got and "/app/app.py" not in got


def test_shebang_script_adds_the_real_interpreter():
    fs = python_image({"/app/run.sh": b"#!/bin/sh\nexec python app.py\n"})
    got = closure(config(entrypoint=["/app/run.sh"], env=PY_ENV, working_dir="/app"), fs)
    assert got == sorted(["/app/run.sh", "/usr/bin/dash", LOADER, LIBC])      # the body is never parsed


def test_env_shebang_resolves_the_command_on_path():
    fs = python_image({"/app/tool.py": b"#!/usr/bin/env -S python3 -u\nprint()\n"})
    got = closure(config(entrypoint=["/app/tool.py"], env=PY_ENV), fs)
    assert got == sorted(["/app/tool.py", "/usr/bin/env", *PYTHON_CLOSURE])


def test_sh_c_entrypoint_covers_only_the_shell():
    got = closure(config(entrypoint=["sh", "-c", "python app.py"], env=PY_ENV), python_image())
    assert got == sorted(["/usr/bin/dash", LOADER, LIBC])


def test_relative_entrypoint_uses_working_dir():
    fs = python_image({"/app/start.sh": b"#!/bin/sh\n"})
    assert "/app/start.sh" in closure(config(entrypoint=["./start.sh"], env=PY_ENV, working_dir="/app"), fs)


def test_default_path_when_env_has_none():
    assert closure(config(cmd=["python"]), python_image()) == PYTHON_CLOSURE


def test_no_entrypoint_or_cmd_gives_an_empty_closure(caplog):
    assert closure(config(), python_image()) == []
    assert "neither Entrypoint nor Cmd" in caplog.text


# --- library search order --------------------------------------------------------------------------

def libx_image(binary, env=(), libs=("/opt/r", "/opt/p", "/opt/l")):
    contents = {"/opt/app/bin/tool": binary, **{f"{d}/libx.so": make_elf() for d in libs}}
    return MemFS(contents), config(entrypoint=["/opt/app/bin/tool"], env=list(env))


def test_runpath_origin():
    fs = MemFS({"/opt/app/bin/tool": make_elf(needed=["libtool.so"], runpath="$ORIGIN/../lib"),
                "/opt/app/lib/libtool.so": make_elf()})
    assert "/opt/app/lib/libtool.so" in closure(config(entrypoint=["/opt/app/bin/tool"]), fs)


def test_rpath_is_ignored_when_runpath_exists():
    fs, cfg = libx_image(make_elf(needed=["libx.so"], rpath="/opt/r", runpath="/opt/p"))
    assert "/opt/p/libx.so" in closure(cfg, fs) and "/opt/r/libx.so" not in closure(cfg, fs)


def test_rpath_comes_before_ld_library_path():
    fs, cfg = libx_image(make_elf(needed=["libx.so"], rpath="/opt/r"), env=["LD_LIBRARY_PATH=/opt/l"])
    assert "/opt/r/libx.so" in closure(cfg, fs)


def test_ld_library_path_comes_before_runpath():
    fs, cfg = libx_image(make_elf(needed=["libx.so"], runpath="/opt/p"), env=["LD_LIBRARY_PATH=/opt/l"])
    assert "/opt/l/libx.so" in closure(cfg, fs)


def test_library_for_another_machine_is_skipped():
    fs = MemFS({"/opt/tool": make_elf(needed=["libx.so"]),
                "/lib/libx.so": make_elf(machine=EM_AARCH64), "/usr/lib/libx.so": make_elf()})
    got = closure(config(entrypoint=["/opt/tool"]), fs)
    assert "/usr/lib/libx.so" in got and "/lib/libx.so" not in got


def test_missing_library_is_logged_and_skipped(caplog):
    fs = python_image({PY: make_elf(interp=INTERP, needed=["libmissing.so.1", "libc.so.6"])})
    got = closure(config(cmd=["python"], env=PY_ENV), fs)
    assert PY in got and LIBC in got
    assert "libmissing.so.1" in caplog.text


# --- odd inputs ---------------------------------------------------------------------------------

def test_path_search_skips_files_without_an_exec_bit():
    fs = python_image({"/usr/local/bin/tool": b"#!/bin/sh\n", "/usr/bin/tool": b"#!/bin/sh\n"},
                      modes={"/usr/local/bin/tool": "0644"})
    got = closure(config(cmd=["tool"], env=PY_ENV), fs)
    assert "/usr/bin/tool" in got and "/usr/local/bin/tool" not in got


def test_broken_elf_does_not_stop_compilation(caplog):
    fs = python_image({"/app/bad": b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 9 + b"garbage"})
    assert closure(config(entrypoint=["/app/bad"]), fs) == ["/app/bad"]
    assert "cannot parse ELF" in caplog.text


def test_missing_entrypoint_is_logged(caplog):
    assert closure(config(entrypoint=["/nope"]), python_image()) == []
    assert "/nope" in caplog.text
