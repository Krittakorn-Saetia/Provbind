"""System-call reference data for the estimated baselines.

Two tables, both approximations stated as such in the plan:

- `CATEGORY`: each system call's functional category (file, memory, process, network, ipc, signal,
  time, other), used by DeSFAM-E's per-window features (its §IV-D groups calls this way).
- `LIBC_SYSCALLS`: the system calls a libc wrapper function may reach. Confine analysed glibc's own
  call graph to build this; we approximate it: a wrapper reaches the same-named call, plus a curated
  table for the wrappers whose names differ from their calls (e.g. `fopen` -> `openat`). Confine-E
  and DeSFAM-E use it to turn a binary's imported libc functions into a system-call set.

`HIGH_RISK` seeds DeSFAM-E's `S_blocked` (the calls its paper names for the CVEs it tests).

The names are the Linux x86-64 syscall names. Where a wrapper has been implemented over different
calls across libc versions (`open` vs `openat`), both are listed, so the set is a superset, which is
the conservative direction for an allow list.
"""
from __future__ import annotations

# --- categories -------------------------------------------------------------------------------------

_CATEGORIES: dict[str, tuple[str, ...]] = {
    "file": (
        "open", "openat", "openat2", "creat", "close", "read", "pread64", "readv", "preadv",
        "write", "pwrite64", "writev", "pwritev", "lseek", "stat", "fstat", "lstat", "newfstatat",
        "statx", "access", "faccessat", "faccessat2", "getdents", "getdents64", "unlink", "unlinkat",
        "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "link", "linkat", "symlink",
        "symlinkat", "readlink", "readlinkat", "chmod", "fchmod", "fchmodat", "chown", "fchown",
        "lchown", "fchownat", "truncate", "ftruncate", "fallocate", "fsync", "fdatasync", "fadvise64",
        "dup", "dup2", "dup3", "fcntl", "flock", "chdir", "fchdir", "getcwd", "chroot", "umask",
        "utime", "utimes", "utimensat", "futimesat", "copy_file_range", "sendfile", "splice", "tee",
        "mount", "umount2", "statfs", "fstatfs", "sync", "syncfs", "inotify_add_watch",
    ),
    "memory": (
        "mmap", "munmap", "mremap", "mprotect", "msync", "madvise", "mlock", "munlock", "mlockall",
        "brk", "mincore", "memfd_create", "pkey_mprotect", "pkey_alloc",
    ),
    "process": (
        "fork", "vfork", "clone", "clone3", "execve", "execveat", "exit", "exit_group", "wait4",
        "waitid", "kill", "tkill", "tgkill", "getpid", "getppid", "gettid", "setpgid", "getpgid",
        "setsid", "prctl", "arch_prctl", "ptrace", "personality", "unshare", "setns", "capget",
        "capset", "seccomp", "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
        "setfsuid", "setfsgid", "setgroups", "getuid", "geteuid", "getgid", "getegid", "getgroups",
        "sched_setaffinity", "sched_getaffinity", "sched_yield", "setpriority", "getpriority",
        "getrlimit", "setrlimit", "prlimit64", "getrusage",
    ),
    "network": (
        "socket", "socketpair", "bind", "listen", "accept", "accept4", "connect", "getsockname",
        "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
        "shutdown", "setsockopt", "getsockopt",
    ),
    "ipc": (
        "pipe", "pipe2", "eventfd", "eventfd2", "signalfd", "signalfd4", "shmget", "shmat", "shmdt",
        "shmctl", "semget", "semop", "semctl", "msgget", "msgsnd", "msgrcv", "msgctl", "mq_open",
        "futex", "set_robust_list", "get_robust_list",
    ),
    "signal": (
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending", "rt_sigtimedwait",
        "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "pause",
    ),
    "time": (
        "nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres", "gettimeofday", "time",
        "times", "timer_create", "timerfd_create", "timerfd_settime", "getitimer", "setitimer",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "poll", "ppoll",
        "select", "pselect6",
    ),
    "other": (
        "ioctl", "uname", "sysinfo", "getrandom", "sethostname", "setdomainname", "reboot",
        "syslog", "acct", "quotactl", "sysfs", "ioprio_set", "ioprio_get", "add_key", "keyctl",
        "bpf", "perf_event_open", "kexec_load", "init_module", "finit_module", "delete_module",
        "io_uring_setup", "io_uring_enter", "landlock_create_ruleset",
    ),
}

CATEGORY: dict[str, str] = {name: cat for cat, names in _CATEGORIES.items() for name in names}
CATEGORIES: tuple[str, ...] = tuple(_CATEGORIES) + ("unknown",)


def categorize(name: str) -> str:
    """The functional category of a system call, or 'unknown' for one not in the table."""
    return CATEGORY.get(name, "unknown")


# --- high-risk calls (DeSFAM-E S_blocked seeds) -----------------------------------------------------
# The calls DeSFAM's paper names for the CVEs it blocks (Polkit, Dirty Pipe, waitid) plus the classic
# container-escape and privilege primitives. A container that never needs these is safer without them.

HIGH_RISK: frozenset[str] = frozenset({
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "waitid", "splice", "setuid",
    "setgid", "setresuid", "setresgid", "setreuid", "setregid", "clone", "clone3", "unshare",
    "setns", "mount", "umount2", "pivot_root", "chroot", "keyctl", "add_key", "request_key",
    "bpf", "perf_event_open", "init_module", "finit_module", "delete_module", "kexec_load",
    "reboot", "acct", "quotactl", "iopl", "ioperm", "modify_ldt",
})


# --- libc wrapper -> system calls (Confine's mapping, approximated) ----------------------------------
# A libc function reaches the same-named call by default (added below). This table is only for the
# wrappers whose reachable calls differ from, or extend, their own name. It is a documented
# approximation of Confine's glibc call-graph analysis, not a reproduction of it.

_LIBC_EXTRA: dict[str, tuple[str, ...]] = {
    # opening and reading files: the wrappers land on the *at variants on a modern glibc
    "open": ("open", "openat"), "open64": ("open", "openat"), "fopen": ("openat", "open"),
    "fopen64": ("openat", "open"), "freopen": ("openat", "open", "close"),
    "creat": ("creat", "openat"), "opendir": ("openat", "open", "getdents64", "fstat"),
    "readdir": ("getdents64",), "fread": ("read",), "fwrite": ("write",), "fgets": ("read",),
    "fputs": ("write",), "fprintf": ("write",), "printf": ("write",), "puts": ("write",),
    "perror": ("write",), "fclose": ("close",), "fflush": ("write",),
    "stat": ("stat", "newfstatat"), "stat64": ("stat", "newfstatat"),
    "lstat": ("lstat", "newfstatat"), "fstat": ("fstat", "newfstatat"),
    "access": ("access", "faccessat", "faccessat2"),
    "remove": ("unlink", "unlinkat", "rmdir"), "unlink": ("unlink", "unlinkat"),
    "rename": ("rename", "renameat", "renameat2"), "mkdir": ("mkdir", "mkdirat"),
    "rmdir": ("rmdir", "unlinkat"), "chmod": ("chmod", "fchmodat"),
    "chown": ("chown", "fchownat"), "symlink": ("symlink", "symlinkat"),
    "readlink": ("readlink", "readlinkat"), "realpath": ("readlink", "readlinkat", "newfstatat"),
    "truncate": ("truncate",), "getcwd": ("getcwd",),
    # memory
    "malloc": ("brk", "mmap"), "calloc": ("brk", "mmap"), "realloc": ("brk", "mmap", "mremap"),
    "free": ("brk", "munmap"), "mmap": ("mmap",), "posix_memalign": ("brk", "mmap"),
    # processes
    "system": ("clone", "clone3", "fork", "execve", "wait4"),
    "popen": ("clone", "clone3", "pipe2", "execve", "wait4"),
    "execl": ("execve",), "execlp": ("execve",), "execv": ("execve",), "execvp": ("execve",),
    "execvpe": ("execve",), "posix_spawn": ("clone", "clone3", "execve"),
    "posix_spawnp": ("clone", "clone3", "execve"),
    "fork": ("fork", "clone"), "vfork": ("vfork", "clone"),
    "pthread_create": ("clone", "clone3", "mmap", "rt_sigprocmask"),
    "wait": ("wait4",), "waitpid": ("wait4",), "waitid": ("waitid",),
    "abort": ("kill", "tgkill", "rt_sigprocmask"), "raise": ("tgkill",), "kill": ("kill",),
    "setuid": ("setuid",), "seteuid": ("setresuid",), "setgid": ("setgid",),
    "setgroups": ("setgroups",), "setresuid": ("setresuid",),
    "getpwnam": ("openat", "read", "close"), "getpwuid": ("openat", "read", "close"),
    # network name resolution and sockets
    "socket": ("socket",), "connect": ("connect",), "bind": ("bind",), "listen": ("listen",),
    "accept": ("accept", "accept4"),
    "getaddrinfo": ("socket", "connect", "sendto", "recvfrom", "openat", "read", "close"),
    "gethostbyname": ("socket", "connect", "sendto", "recvfrom", "openat", "read"),
    "getnameinfo": ("socket", "connect", "sendto", "recvfrom"),
    "send": ("sendto",), "recv": ("recvfrom",),
    # dynamic loading
    "dlopen": ("openat", "read", "mmap", "mprotect", "close", "newfstatat"),
    "dlsym": (), "dlclose": ("munmap",),
    # time and polling
    "sleep": ("clock_nanosleep", "nanosleep"), "usleep": ("clock_nanosleep", "nanosleep"),
    "nanosleep": ("clock_nanosleep", "nanosleep"), "time": ("clock_gettime", "time"),
    "gettimeofday": ("clock_gettime", "gettimeofday"),
    "select": ("select", "pselect6"), "poll": ("poll", "ppoll"),
    # syslog and misc
    "syslog": ("sendto", "socket", "connect"), "openlog": ("socket", "connect"),
    "getrandom": ("getrandom",), "rand": (), "srand": (),
}

# Every entry maps to at least the same-named call when one exists.
LIBC_SYSCALLS: dict[str, frozenset[str]] = {}
for _fn, _calls in _LIBC_EXTRA.items():
    LIBC_SYSCALLS[_fn] = frozenset(_calls) or frozenset()
for _name in CATEGORY:                                    # a wrapper named exactly like a call reaches it
    LIBC_SYSCALLS.setdefault(_name, frozenset({_name}))


# --- calls libc and the dynamic loader make on their own ---------------------------------------------
# Every dynamically linked program makes these whatever it imports: the loader maps libraries
# (mmap, mprotect, openat, read, fstat...), libc's start-up code sets up threads and signals
# (arch_prctl, set_tid_address, set_robust_list, rseq, prlimit64, rt_sigaction...), malloc grows the
# heap (brk), and exit() ends with exit_group. They never appear as imported symbols, because libc
# calls them internally, so an import-only analysis misses them. Confine's glibc call-graph analysis
# reaches them; Confine-E and DeSFAM-E add this set whenever there is at least one ELF file.

LIBC_RUNTIME: frozenset[str] = frozenset({
    "execve", "brk", "arch_prctl", "set_tid_address", "set_robust_list", "rseq", "prlimit64",
    "mmap", "munmap", "mprotect", "mremap", "madvise", "openat", "open", "read", "pread64",
    "close", "fstat", "newfstatat", "statx", "access", "faccessat", "faccessat2", "readlink",
    "readlinkat", "lseek", "getrandom", "futex", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "sigaltstack", "getpid", "gettid", "getuid", "geteuid", "getgid",
    "getegid", "uname", "sysinfo", "clock_gettime", "gettimeofday", "sched_getaffinity",
    "exit", "exit_group", "tgkill", "write", "writev", "ioctl", "fcntl", "getcwd",
})


def syscalls_for(functions) -> set[str]:
    """The system calls the given libc function names may reach (best-effort; unknown names ignored)."""
    out: set[str] = set()
    for fn in functions:
        out |= LIBC_SYSCALLS.get(fn, frozenset())
    return out
