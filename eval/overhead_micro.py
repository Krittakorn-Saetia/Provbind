"""Micro-benchmark for the overhead test (scripts/overhead-run.sh): the worst case for an in-kernel
monitor, because every operation here is a hooked event. Runs INSIDE the demo container:

    kubectl -n demo exec -i deploy/demo-app -- python3 - <file_ops> <spawns> < eval/overhead_micro.py

- file ops: open, write, close a small file under /tmp, <file_ops> times (PROVBIND's write hook, Falco's
  file rules);
- spawns: start /usr/bin/true <spawns> times (exec and exit hooks on both systems).
The same style as Falco's own driver benchmark (per-syscall latency with and without the monitor).
Prints one JSON object: microseconds per file op and milliseconds per spawn. Harmless.
"""
import json
import os
import subprocess
import sys
import time


def main():
    file_ops = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    spawns = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    path = "/tmp/provbind-overhead.txt"
    t0 = time.perf_counter()
    for i in range(file_ops):
        with open(path, "w") as f:
            f.write("x%d\n" % i)
    t_file = time.perf_counter() - t0
    true = "/usr/bin/true" if os.path.exists("/usr/bin/true") else "/bin/true"
    t0 = time.perf_counter()
    for _ in range(spawns):
        subprocess.run([true], check=False)
    t_spawn = time.perf_counter() - t0
    try:
        os.remove(path)
    except OSError:
        pass
    print(json.dumps({"file_ops": file_ops, "file_op_us": round(t_file / file_ops * 1e6, 3),
                      "spawns": spawns, "spawn_ms": round(t_spawn / spawns * 1e3, 4)}))


if __name__ == "__main__":
    main()
