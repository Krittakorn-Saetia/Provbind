"""Confine-E: an estimated function for Confine [14] (RAID 2020).

Confine builds a per-image seccomp allow list from static analysis of the binaries that run in the
container, then the kernel blocks any system call outside it. It does not detect, explain or re-check
trust; it only blocks. This estimate follows that design (Confine §5):

1. `static_set(binaries_dir)` reads the libc functions imported by every ELF file in a directory (the
   image's entrypoint closure plus any programs seen in the first 30 s of the startup trace, which
   Role 1 exports with `export_binaries.sh`) and maps them to system calls with `syscalls.syscalls_for`.
   That set is `S_static`, the allow list.
2. `evaluate(events, allow)` marks a scenario **blocked** when its trace contains a system call outside
   `S_static`, at the time of the first such call; otherwise not blocked.

This is an approximation, stated as such in the plan: the libc-function-to-syscall map is curated
(`syscalls.py`), not derived from glibc's source as Confine does, and direct `syscall()` instructions
in stripped binaries are not recovered. For an interpreted image (our Python demo) `S_static` is large,
because libpython imports most file, process and network wrappers, so few scenarios are blocked. That
is a real property of Confine for interpreted containers (its §6.3, §8), not an artefact of the estimate.

    python -m eval.baselines.confine_estimate --binaries DIR --trace run/traces/attack-1-1.txt ...

Capabilities are fixed by the design: runtime blocking only, no admission check, no alert text, no
attribution, no trust re-evaluation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .syscalls import LIBC_RUNTIME, syscalls_for
from .trace import imports_under, read_trace, syscalls_in

CAPABILITIES = {
    "admission_check": False,
    "runtime_detection": True,     # as blocking, not an alert
    "prevents": True,
    "alert_text": False,
    "attribution_level": 0,
    "trust_reevaluation": False,
}


def static_set(binaries_dir: str | os.PathLike, extra_calls=()) -> tuple[set[str], dict]:
    """(S_static, how it was built). S_static is the system calls reachable from the libc functions
    imported by the ELF files under `binaries_dir`, plus any `extra_calls` given."""
    functions, n_elf = imports_under(binaries_dir)
    allow = syscalls_for(functions) | set(extra_calls)
    if n_elf:
        allow |= LIBC_RUNTIME                              # libc's internal calls (see syscalls.py)
    return allow, {"elf_files": n_elf, "imported_functions": len(functions), "allow_size": len(allow)}


def evaluate(events, allow: set[str]) -> dict:
    """Confine's runtime decision for one scenario trace."""
    unlisted = []
    first_bad = None
    for e in events:
        if e.syscall and e.syscall not in allow:
            if first_bad is None:
                first_bad = {"syscall": e.syscall, "t_ns": e.t_ns, "pid": e.pid, "comm": e.comm}
            unlisted.append(e.syscall)
    return {
        "blocked": first_bad is not None,
        "stage": "runtime" if first_bad is not None else None,
        "first_blocked": first_bad,
        "unlisted_syscalls": sorted(set(unlisted)),
        "syscalls_seen": len(syscalls_in(events)),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.confine_estimate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binaries", required=True, help="directory of the image's closure/startup ELF files")
    ap.add_argument("--trace", action="append", default=[], metavar="FILE", help="a scenario trace (repeatable)")
    ap.add_argument("--extra-syscall", action="append", default=[], help="add a call to the allow list (repeatable)")
    ap.add_argument("--out", help="write the JSON result here as well as to stdout")
    args = ap.parse_args(argv)

    allow, how = static_set(args.binaries, args.extra_syscall)
    results = {}
    for path in args.trace:
        results[os.path.basename(path)] = evaluate(read_trace(path), allow)
    report = {"system": "Confine-E", "estimated": True, "capabilities": CAPABILITIES,
              "allow_list": how, "results": results}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
