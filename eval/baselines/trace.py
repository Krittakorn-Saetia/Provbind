"""Read a recorded system-call trace and the ELF imports of the image's binaries.

A trace is what `eval/baselines/record_trace.sh` writes on the demo VM: one line per system call,
tab-separated, `<time_ns>\\t<pid>\\t<comm>\\t<syscall_name>`. A blank line and a `#` comment line are
skipped, so a header is allowed. `read_trace` also accepts a bare list of syscall names, one per line,
for a quick check without the recorder.

ELF imports: `imported_functions` returns the undefined dynamic symbols of one ELF file (the libc
wrappers it calls); `imports_under` unions them over every ELF file in a directory. Confine-E and
DeSFAM-E turn those into a system-call set with `syscalls.syscalls_for`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Event:
    t_ns: int          # kernel timestamp in nanoseconds, or the line number when the trace has no time
    pid: int
    comm: str          # the process's command name (task comm), as the kernel reports it
    syscall: str       # the system-call name, without the sys_ prefix


def read_trace(path: str | os.PathLike) -> list[Event]:
    """Every system-call event in a trace file, in order."""
    events: list[Event] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                t, pid, comm, call = parts[0], parts[1], parts[2], parts[3].strip()
                events.append(Event(_int(t, n), _int(pid, 0), comm, _clean(call)))
            else:                                          # a bare syscall name per line
                events.append(Event(n, 0, "", _clean(line.strip())))
    return events


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean(call: str) -> str:
    for prefix in ("sys_enter_", "sys_exit_", "sys_", "__x64_sys_", "SYS_"):
        if call.startswith(prefix):
            call = call[len(prefix):]
    return call


def syscalls_in(events) -> set[str]:
    return {e.syscall for e in events if e.syscall}


def executed_in(events) -> set[str]:
    """The command names of processes that ran an exec in the trace (their post-exec comm)."""
    return {e.comm for e in events if e.syscall in ("execve", "execveat") and e.comm}


def windows(events, size: int = 15, stride: int = 3):
    """Sliding windows of syscall names (DeSFAM: length 15, stride 3)."""
    names = [e.syscall for e in events if e.syscall]
    if len(names) < size:
        if names:
            yield names
        return
    for start in range(0, len(names) - size + 1, stride):
        yield names[start:start + size]


# --- ELF imports ------------------------------------------------------------------------------------

def imported_functions(elf_path: str | os.PathLike) -> set[str]:
    """The undefined dynamic symbols of an ELF file: the functions it imports from shared libraries.
    Returns an empty set for a file that is not a readable ELF."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    out: set[str] = set()
    try:
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for section_name in (".dynsym", ".symtab"):
                section = elf.get_section_by_name(section_name)
                if section is None:
                    continue
                for sym in section.iter_symbols():
                    if sym.name and sym["st_shndx"] == "SHN_UNDEF" and sym["st_info"]["type"] == "STT_FUNC":
                        out.add(sym.name.split("@", 1)[0])   # drop a @GLIBC_2.x version suffix
    except (ELFError, OSError):
        return set()
    return out


def is_elf(path: str | os.PathLike) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def imports_under(directory: str | os.PathLike) -> tuple[set[str], int]:
    """(the union of imported functions over every ELF file under `directory`, number of ELF files)."""
    funcs: set[str] = set()
    count = 0
    for root, _dirs, files in os.walk(directory):
        for name in files:
            p = Path(root) / name
            if p.is_symlink() or not p.is_file():
                continue
            if is_elf(p):
                funcs |= imported_functions(p)
                count += 1
    return funcs, count
