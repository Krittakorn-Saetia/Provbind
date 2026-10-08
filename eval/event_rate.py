"""Events per request: how many Tetragon events the demo app's pod caused, per hook, for the requests one
load-client run sent (scripts/event-rate.sh). The overhead test's cost is roughly events per request times
the cost of moving one event to PROVBIND, so this is the quick check before an overhead run. Counts only.

    python -m eval.event_rate <events.jsonl> <client.json> [--path /cache]
"""
import argparse
import collections
import json
import sys

KPROBE = {"security_file_permission": "write", "security_file_truncate": "truncate",
          "security_path_truncate": "truncate", "security_mmap_file": "library load",
          "cap_capable": "capability check", "tcp_connect": "connection"}


def category(kind: str, body: dict) -> str:
    if kind != "process_kprobe":
        return kind.replace("process_", "process ")
    cat = KPROBE.get(body.get("function_name"), str(body.get("function_name")))
    if cat == "write":
        path = next((a["file_arg"].get("path", "") for a in body.get("args") or []
                     if isinstance(a, dict) and isinstance(a.get("file_arg"), dict)), "")
        if not path.startswith("/"):
            cat = "write to a pipe or socket"
        elif path.startswith("/tmp/app-cache/"):
            cat = "write (cache file)"
        else:
            cat = "write (other file)"
    return cat


def count(lines, namespace="demo", pod_prefix="demo-app") -> collections.Counter:
    c = collections.Counter()
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        for kind, body in d.items():
            if not isinstance(body, dict) or not isinstance(body.get("process"), dict):
                continue
            pod = body["process"].get("pod") or {}
            if pod.get("namespace") == namespace and str(pod.get("name", "")).startswith(pod_prefix):
                c[category(kind, body)] += 1
    return c


def summary(counts, requests, path) -> str:
    total = sum(counts.values())
    per = f"{total / requests:.3f}" if requests else "—"
    parts = ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda x: -x[1])) or "none"
    return f"GET {path:<7} {requests:>7} requests; app events per request: {per}  ({parts})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("events")
    ap.add_argument("client")
    ap.add_argument("--path", default="/cache")
    ap.add_argument("--namespace", default="demo")
    ap.add_argument("--pod-prefix", default="demo-app")
    a = ap.parse_args(argv)
    lines = open(a.client).read().strip().splitlines()
    requests = int(json.loads(lines[-1]).get("requests") or 0) if lines else 0
    with open(a.events, encoding="utf-8", errors="replace") as f:
        counts = count(f, a.namespace, a.pod_prefix)
    print(summary(counts, requests, a.path))
    return 0 if requests else 1


if __name__ == "__main__":
    sys.exit(main())
