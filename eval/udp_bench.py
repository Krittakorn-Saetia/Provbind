"""Her et al.'s network micro-benchmark [F] (IEEE Access 2025, Section V-B2; udp.c in their public
ESST-eval repository), for the network test (scripts/overhead-run.sh with WORKLOADS=udp). Runs INSIDE
the demo container, like eval/overhead_micro.py:

    kubectl -n demo exec -i deploy/demo-app -- python3 - <packets> <iterations> < eval/udp_bench.py

As in udp.c: in each iteration, <packets> times, open a UDP socket and send one 4-byte datagram with
sendto(), timing the two calls together (the close is not timed); each iteration's total is reported.
Defaults are theirs: 100,000 packets, 10 iterations.

One difference, for safety: udp.c sends to 8.8.8.8:53, a public DNS server; this sends to a UDP socket
bound on 127.0.0.1 inside the same process, so no packet leaves the pod. That socket is never read; once
its buffer is full the kernel drops further datagrams, which costs the sender nothing extra. The program
is Python (the demo image has no compiler), so each packet also carries the interpreter's own cost; the
same program runs under every configuration, so the overheads compare, and our Falco run shows how far
this setup reproduces their Falco figure. Prints one JSON object. Harmless.
"""
import json
import socket
import statistics
import sys
import time


def main():
    packets = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    dest, payload = sink.getsockname(), b"test"
    clock, family, kind = time.perf_counter_ns, socket.AF_INET, socket.SOCK_DGRAM
    per_iteration, failed = [], 0
    for _ in range(iterations):
        total = 0
        for _ in range(packets):
            t0 = clock()
            s = socket.socket(family, kind)
            try:
                sent = s.sendto(payload, dest)
                t1 = clock()
            except OSError:
                sent, t1 = -1, 0
            s.close()
            if sent == len(payload):
                total += t1 - t0
            else:
                failed += 1
        per_iteration.append(total / 1e9)
    sink.close()
    us = [s / packets * 1e6 for s in per_iteration]
    print(json.dumps({"udp_packets": packets, "udp_iterations": iterations,
                      "udp_iteration_s": [round(s, 6) for s in per_iteration],
                      "udp_us": round(statistics.median(us), 4), "udp_failed": failed}))


if __name__ == "__main__":
    main()
