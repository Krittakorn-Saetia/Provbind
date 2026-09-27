"""T7: the entrypoint's execution and load closure (handoff Section 7.3).

Start from Entrypoint[0] (or Cmd[0]) and follow what the kernel and ld.so would: shebang
interpreters, ELF PT_INTERP, and each DT_NEEDED library found by ld.so's search order.
Every path added is a real path in the union. A library that cannot be found is logged
and skipped; it never stops compilation.

Out of scope, by design: arguments are never parsed, so an entrypoint of
["sh", "-c", "..."] adds only the shell and its libraries; libraries opened with dlopen
at run time (Python's lib-dynload modules, for example) are not in the closure.
"""
from __future__ import annotations

import fnmatch
import logging
import posixpath
from dataclasses import dataclass
from typing import BinaryIO, Mapping, Protocol

from elftools.elf.elffile import ELFFile

from .paths import SymlinkLoop, realpath

log = logging.getLogger("provbind.closure")

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"   # the runtime's default
DEFAULT_LIB_DIRS = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")
LD_SO_CONF = "/etc/ld.so.conf"
HEAD_BYTES = 256
ENV_OPTIONS_WITH_VALUE = {"-u", "--unset", "-C", "--chdir"}


class ImageFS(Protocol):
    """What the closure needs from the union: canonical maps and file bytes."""
    files: Mapping
    links: Mapping[str, str]

    def read(self, path: str, n: int | None = None) -> bytes | None: ...
    def open(self, path: str) -> BinaryIO | None: ...


@dataclass
class ElfInfo:
    interp: str | None
    needed: list[str]
    rpath: list[str]
    runpath: list[str]


def parse_env(env: list[str] | None) -> dict[str, str]:
    out = {}
    for item in env or ():
        key, sep, value = item.partition("=")
        if sep:
            out[key] = value
    return out


def first_executable(config) -> str | None:
    """Entrypoint[0], or Cmd[0] when there is no entrypoint. The rest of argv is never
    parsed: ["sh", "-c", "..."] gives the shell only (the command string is out of scope)."""
    argv = config.entrypoint or config.cmd
    return argv[0] if argv else None


def parse_shebang(head: bytes) -> tuple[str, str | None] | None:
    """(interpreter, optional argument) from a "#!" line, split as Linux does: the
    interpreter runs to the first space or tab, and the rest is one argument."""
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").replace("\t", " ").strip()
    if not line:
        return None
    interp, _, arg = line.partition(" ")
    return interp, (arg.strip() or None)


def env_command(arg: str) -> str | None:
    """The command `env` runs, from a shebang argument such as "-S python3 -u": options
    and NAME=value assignments are skipped."""
    tokens = arg.split()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            return tokens[i + 1] if i + 1 < len(tokens) else None
        if t in ENV_OPTIONS_WITH_VALUE:
            i += 2
        elif t.startswith("-S") and len(t) > 2:          # -Spython3: the rest is the string
            tokens[i] = t[2:]
        elif t.startswith("--split-string="):
            tokens[i] = t.split("=", 1)[1]
        elif t.startswith("-") or "=" in t:
            i += 1
        else:
            return t
    return None


def parse_elf(f: BinaryIO) -> ElfInfo:
    elf = ELFFile(f)
    info = ElfInfo(None, [], [], [])
    for seg in elf.iter_segments():
        kind = seg["p_type"]
        if kind == "PT_INTERP":
            info.interp = seg.get_interp_name()
        elif kind == "PT_DYNAMIC":
            for tag in seg.iter_tags():
                d_tag = tag.entry.d_tag
                if d_tag == "DT_NEEDED":
                    info.needed.append(tag.needed)
                elif d_tag == "DT_RPATH":
                    info.rpath += [d for d in tag.rpath.split(":") if d]
                elif d_tag == "DT_RUNPATH":
                    info.runpath += [d for d in tag.runpath.split(":") if d]
    return info


def elf_ident(head: bytes) -> tuple[int, int] | None:
    """(EI_CLASS, e_machine) of an ELF header, or None if `head` is not one."""
    if len(head) < 20 or not head.startswith(b"\x7fELF"):
        return None
    return head[4], int.from_bytes(head[18:20], "little" if head[5] == 1 else "big")


def _real(path: str, fs: ImageFS) -> str | None:
    try:
        return realpath(path, fs.links)
    except SymlinkLoop:
        log.warning("closure: %s is a symlink loop; skipped", path)
        return None


def resolve_exe(name: str, fs: ImageFS, path_dirs: list[str], workdir: str) -> str | None:
    """The real path of `name`: a path if it contains "/" (relative to WorkingDir),
    else the first executable regular file on PATH, as execvp finds it."""
    if "/" in name:
        real = _real(name if name.startswith("/") else posixpath.join(workdir, name), fs)
        return real if real in fs.files else None
    for d in path_dirs:
        if not d.startswith("/"):
            continue
        real = _real(posixpath.join(d, name), fs)
        entry = fs.files.get(real) if real else None
        if entry is not None and int(entry.mode, 8) & 0o111:
            return real
    return None


def _glob(pattern: str, fs: ImageFS) -> list[str]:
    """Real paths of union files matching a glob in one directory (for ld.so.conf include)."""
    directory = _real(posixpath.dirname(pattern), fs)
    if directory is None:
        return []
    names = {p for p in list(fs.files) + list(fs.links) if posixpath.dirname(p) == directory}
    hits = [p for p in sorted(names) if fnmatch.fnmatchcase(posixpath.basename(p), posixpath.basename(pattern))]
    return [r for r in (_real(p, fs) for p in hits) if r in fs.files]


def ld_so_conf_dirs(fs: ImageFS) -> list[str]:
    """Directories from /etc/ld.so.conf and its include globs, in file order."""
    dirs: list[str] = []
    seen: set[str] = set()

    def parse(path: str, depth: int) -> None:
        real = _real(path, fs)
        if real is None or real in seen or depth > 10:
            return
        seen.add(real)
        data = fs.read(real)
        for raw in data.decode("utf-8", "replace").splitlines() if data is not None else ():
            line = raw.split("#", 1)[0].strip()
            if line.startswith("include") and line[7:8] in (" ", "\t"):
                for pattern in line[7:].split():
                    pattern = pattern if pattern.startswith("/") else posixpath.join(posixpath.dirname(real), pattern)
                    for conf in _glob(pattern, fs):
                        parse(conf, depth + 1)
            elif line and not line.startswith("hwcap"):
                dirs.extend(t.split("=", 1)[0] for t in line.split() if t.startswith("/"))

    parse(LD_SO_CONF, 0)
    return dirs


def find_library(soname: str, obj: str, info: ElfInfo, ident: tuple[int, int] | None,
                 env: Mapping[str, str], conf_dirs: list[str], fs: ImageFS) -> str | None:
    """ld.so's search for one DT_NEEDED entry (handoff T7): DT_RPATH (only without
    DT_RUNPATH), LD_LIBRARY_PATH, DT_RUNPATH, /etc/ld.so.conf, then the default
    directories. $ORIGIN is the directory of the object being examined. Like ld.so, skip
    candidates whose ELF class or machine differs from the object's."""
    if "/" in soname:
        real = _real(soname, fs)
        return real if real in fs.files else None
    origin = posixpath.dirname(obj)

    def expand(dirs):
        return [d.replace("${ORIGIN}", origin).replace("$ORIGIN", origin) for d in dirs]

    search = expand(info.rpath) if info.rpath and not info.runpath else []
    search += expand(d for d in env.get("LD_LIBRARY_PATH", "").split(":") if d)
    search += expand(info.runpath) + conf_dirs + list(DEFAULT_LIB_DIRS)
    for d in search:
        if not d.startswith("/"):
            continue
        real = _real(posixpath.join(d, soname), fs)
        if real in fs.files and (ident is None or elf_ident(fs.read(real, 20) or b"") == ident):
            return real
    return None


def closure(config, fs: ImageFS) -> list[str]:
    """The sorted real paths of every executable and library the entrypoint can reach."""
    env = parse_env(config.env)
    path_dirs = env.get("PATH", DEFAULT_PATH).split(":")
    workdir = config.working_dir or "/"
    first = first_executable(config)
    if first is None:
        log.warning("closure: the image has neither Entrypoint nor Cmd; the closure is empty")
        return []

    conf_dirs: list[str] | None = None
    work, seen = [first], set()
    while work:
        name = work.pop()
        p = resolve_exe(name, fs, path_dirs, workdir)
        if p is None:
            log.warning("closure: %s is not an executable file in the image; skipped", name)
            continue
        if p in seen:
            continue
        seen.add(p)
        head = fs.read(p, HEAD_BYTES) or b""
        shebang = parse_shebang(head)
        if shebang:
            interp, arg = shebang
            work.append(interp if "/" in interp else posixpath.join(workdir, interp))
            if posixpath.basename(interp) == "env" and arg:
                command = env_command(arg)
                if command:
                    work.append(command)
        elif head.startswith(b"\x7fELF"):
            try:
                with fs.open(p) as f:
                    info = parse_elf(f)
            except Exception as e:                          # a broken ELF must not stop compilation
                log.warning("closure: cannot parse ELF %s (%s); its dependencies are skipped", p, e)
                continue
            if info.interp:
                work.append(info.interp)
            if info.needed and conf_dirs is None:
                conf_dirs = ld_so_conf_dirs(fs)
            for soname in info.needed:
                lib = find_library(soname, p, info, elf_ident(head), env, conf_dirs, fs)
                if lib:
                    work.append(lib)
                else:
                    log.warning("closure: %s needs %s, which is not in the image; skipped", p, soname)
    return sorted(seen)
