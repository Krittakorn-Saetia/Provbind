#!/usr/bin/env bash
# Record the demo pod's system calls with bpftrace, for the estimated baselines (Confine-E, DeSFAM-E).
# Runs on the demo VM as root (bpftrace needs it). Role 1 runs this alongside each scenario and for the
# benign baseline; PROVBIND's own timing runs happen WITHOUT it (tracing every syscall slows the pod).
#
#   sudo eval/baselines/record_trace.sh --pid <host pid of a pod process> --out run/traces/attack-1-1.txt [--seconds 0]
#
# It writes one line per system call, tab-separated:  <nsecs>\t<pid>\t<comm>\t<syscall>
# so eval/baselines/trace.py reads it directly. --seconds 0 (default) records until Ctrl-C or the
# scenario script signals it (kill the recorded PID); a positive value records for that long.
#
# How the filter works: every process in the pod shares one PID namespace. We take the namespace inode
# of --pid and keep only tracepoint:syscalls:sys_enter_* events whose task is in that namespace, so
# children the scenario spawns are included and the rest of the node is not.
#
# VERIFY on the demo VM (kernel 7.0, bpftrace version): that the pidns field below resolves. If bpftrace
# rejects `curtask->nsproxy->pid_ns_for_children->ns.inum`, print it with `bpftrace -lv
# 'tracepoint:syscalls:sys_enter_openat'` is not enough; instead fall back to `--pids a,b,c` (a fixed
# PID list) using the alternate program shown by --dry-run.
set -euo pipefail

PID=""; OUT=""; SECONDS_LIMIT=0; DRY_RUN=0; PIDS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pid) PID="$2"; shift 2;;
    --pids) PIDS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --seconds) SECONDS_LIMIT="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    *) echo "record_trace: unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$OUT" ] || { echo "record_trace: --out FILE is required" >&2; exit 2; }
command -v bpftrace >/dev/null || { echo "record_trace: bpftrace is not installed (apt install bpftrace)" >&2; exit 3; }

mkdir -p "$(dirname "$OUT")"

if [ -n "$PIDS" ]; then
  # Fallback: a fixed PID list. Misses children spawned after the trace starts, so prefer --pid.
  cond=""
  IFS=',' read -ra arr <<< "$PIDS"
  for p in "${arr[@]}"; do cond="${cond:+$cond || }pid == $p"; done
  FILTER="/ $cond /"
elif [ "$DRY_RUN" = 1 ] && [ -z "$PID" ]; then
  FILTER="/ (uint64)curtask->nsproxy->pid_ns_for_children->ns.inum == <pidns-of-target> /"
else
  [ -n "$PID" ] || { echo "record_trace: give --pid <host pid in the pod> (or --pids a,b,c)" >&2; exit 2; }
  NS_INUM="$(stat -L -c %i "/proc/$PID/ns/pid")" || { echo "record_trace: cannot read /proc/$PID/ns/pid (run as root)" >&2; exit 3; }
  FILTER="/ (uint64)curtask->nsproxy->pid_ns_for_children->ns.inum == $NS_INUM /"
fi

PROG='tracepoint:syscalls:sys_enter_* '"$FILTER"' { printf("%lld\t%d\t%s\t%s\n", nsecs, pid, comm, probe); }'

if [ "$DRY_RUN" = 1 ]; then
  echo "# bpftrace program:"; echo "$PROG"; exit 0
fi

# bpftrace prints the full probe name (tracepoint:syscalls:sys_enter_openat); strip it to the call name.
run_bpftrace() {
  bpftrace -e "$PROG" 2>/dev/null | sed -u -E 's/\ttracepoint:syscalls:sys_enter_/\t/'
}

echo "record_trace: tracing into $OUT (Ctrl-C to stop)" >&2
if [ "$SECONDS_LIMIT" -gt 0 ] 2>/dev/null; then
  timeout "$SECONDS_LIMIT" bash -c "$(declare -f run_bpftrace); run_bpftrace" > "$OUT" || true
else
  run_bpftrace > "$OUT"
fi
echo "record_trace: $(wc -l < "$OUT") events written to $OUT" >&2
