#!/usr/bin/env bash
# Copy the demo image's entrypoint-closure ELF files out of the running pod, for Confine-E and
# DeSFAM-E's static analysis. Runs on the demo VM. The estimators read imported libc functions from
# these files; only their bytes are needed, so a read-only copy is enough.
#
#   eval/baselines/export_binaries.sh --run "$PROVBIND_RUN" --namespace demo --deploy demo-app \
#       --digest sha256:<hex> --out run/traces/binaries [--startup-trace run/traces/startup.txt]
#
# It reads the envelope's `closure` list (the executables and libraries reachable from the entrypoint,
# which is exactly Confine's static reachability for the app) and copies each file from the pod with
# `kubectl exec ... cat`. With --startup-trace it also copies any program executed in the first 30 s
# that is on disk in the pod (utilities like chown, find that run during init), matching Confine's
# "programs seen at startup" step. It also copies every file mapped into a running process of the pod
# (/proc/<pid>/maps): an interpreter such as Python loads most of its libc users at runtime as
# extension modules (_socket, select, _posixsubprocess...), which the closure does not list but
# Confine's analysis of the running image reaches. Files are stored flat, with '/' turned into '%'.
set -euo pipefail

RUN="${PROVBIND_RUN:-./run}"; NS=demo; DEPLOY=demo-app; DIGEST=""; OUT=""; STARTUP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --run) RUN="$2"; shift 2;;
    --namespace) NS="$2"; shift 2;;
    --deploy) DEPLOY="$2"; shift 2;;
    --digest) DIGEST="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --startup-trace) STARTUP="$2"; shift 2;;
    *) echo "export_binaries: unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$OUT" ] || { echo "export_binaries: --out DIR is required" >&2; exit 2; }
[ -n "$DIGEST" ] || { echo "export_binaries: --digest sha256:<hex> is required" >&2; exit 2; }
command -v kubectl >/dev/null || { echo "export_binaries: kubectl not found" >&2; exit 3; }

HEX="${DIGEST#sha256:}"
ENV="$RUN/envelopes/$HEX.json"
[ -f "$ENV" ] || { echo "export_binaries: no envelope at $ENV (compile the image first)" >&2; exit 3; }
mkdir -p "$OUT"

# The list of paths to copy: the closure, plus startup-executed programs that exist as files.
paths_file="$(mktemp)"
python3 - "$ENV" "${STARTUP:-}" > "$paths_file" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
paths = set(env.get("closure") or [])
startup = sys.argv[2] if len(sys.argv) > 2 else ""
files = env.get("files") or {}
if startup:
    # add any executed program (comm) whose declared path is in the image
    execed = set()
    try:
        for line in open(startup, encoding="utf-8", errors="replace"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 4 and p[3].strip().replace("tracepoint:syscalls:sys_enter_", "") in ("execve", "execveat"):
                execed.add(p[2])
    except OSError:
        pass
    for path, meta in files.items():
        if path.rsplit("/", 1)[-1] in execed:
            paths.add(path)
for p in sorted(paths):
    print(p)
PY

pod="$(kubectl get pods -n "$NS" -l "app=$DEPLOY" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$pod" ] || pod="$(kubectl -n "$NS" get pods -o jsonpath="{.items[?(@.metadata.name=~'^$DEPLOY')].metadata.name}" 2>/dev/null | awk '{print $1}')"
[ -n "$pod" ] || { echo "export_binaries: no pod for $DEPLOY in $NS" >&2; exit 3; }

# Add the files mapped into the pod's processes (shared libraries and extension modules).
kubectl exec -n "$NS" "$pod" -- sh -c 'cat /proc/[0-9]*/maps 2>/dev/null' 2>/dev/null \
  | awk '$6 ~ /^\// && $7 == "" {print $6}' >> "$paths_file" || true
sort -u -o "$paths_file" "$paths_file"

n=0; miss=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  dest="$OUT/${path//\//%}"
  if kubectl exec -n "$NS" "$pod" -- cat "$path" > "$dest" 2>/dev/null && [ -s "$dest" ]; then
    n=$((n + 1))
  else
    rm -f "$dest"; miss=$((miss + 1))
  fi
done < "$paths_file"
rm -f "$paths_file"
echo "export_binaries: copied $n files to $OUT ($miss not found in the pod)" >&2
