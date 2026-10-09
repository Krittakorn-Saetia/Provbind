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

# Every x86-64 system-call name (from the kernel's asm/unistd_64.h), so a libc wrapper named like any
# call maps to it even when the call has no category above.
X86_64_SYSCALLS: frozenset[str] = frozenset((
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect",
    "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
    "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore",
    "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm",
    "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt",
    "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget",
    "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync",
    "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir",
    "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown",
    "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace",
    "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid",
    "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid",
    "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset",
    "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime",
    "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority",
    "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
    "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock",
    "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl",
    "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
    "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
    "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl",
    "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr",
    "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
    "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex",
    "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
    "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
    "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
    "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime",
    "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres",
    "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind",
    "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
    "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl",
    "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
    "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
    "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
    "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice",
    "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate",
    "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3",
    "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg",
    "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at",
    "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
    "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom",
    "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2",
    "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx",
    "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
    "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2", "process_madvise",
    "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule",
    "landlock_restrict_self", "memfd_secret", "process_mrelease", "futex_waitv",
    "set_mempolicy_home_node", "cachestat", "fchmodat2", "map_shadow_stack", "futex_wake",
    "futex_wait", "futex_requeue", "statmount", "listmount", "lsm_get_self_attr", "lsm_set_self_attr",
    "lsm_list_modules",
))
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
    # glibc's 64-bit-offset and convenience names for calls with other names
    "fstat64": ("fstat", "newfstatat"), "fstatat64": ("newfstatat",), "fstatat": ("newfstatat",),
    "lstat64": ("lstat", "newfstatat"), "statvfs": ("statfs",), "statvfs64": ("statfs",),
    "fstatvfs": ("fstatfs",), "fstatvfs64": ("fstatfs",), "posix_fadvise": ("fadvise64",),
    "posix_fadvise64": ("fadvise64",), "posix_fallocate": ("fallocate",),
    "posix_fallocate64": ("fallocate",), "futimens": ("utimensat",), "utimensat": ("utimensat",),
    "closefrom": ("close_range", "close"), "fexecve": ("execveat", "execve"),
    "eventfd_read": ("read",), "eventfd_write": ("write",), "fdopendir": ("getdents64", "fstat"),
    "readdir64": ("getdents64",), "pread": ("pread64",), "pwrite": ("pwrite64",),
    "preadv64": ("preadv",), "pwritev64": ("pwritev",), "prlimit": ("prlimit64",),
    "getrlimit": ("prlimit64", "getrlimit"), "setrlimit": ("prlimit64", "setrlimit"),
    "wait3": ("wait4",), "forkpty": ("clone", "openat", "ioctl"), "openpty": ("openat", "ioctl"),
    "sendfile64": ("sendfile",), "epoll_wait": ("epoll_wait", "epoll_pwait"),
}

# Every entry maps to at least the same-named call when one exists.
LIBC_SYSCALLS: dict[str, frozenset[str]] = {}
for _fn, _calls in _LIBC_EXTRA.items():
    LIBC_SYSCALLS[_fn] = frozenset(_calls) or frozenset()
for _name in X86_64_SYSCALLS | set(CATEGORY):            # a wrapper named exactly like a call reaches it
    LIBC_SYSCALLS.setdefault(_name, frozenset({_name}))
for _name in X86_64_SYSCALLS:                             # glibc's foo64 wrapper of call foo (fcntl64, lseek64)
    LIBC_SYSCALLS.setdefault(_name + "64", frozenset({_name}))


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
