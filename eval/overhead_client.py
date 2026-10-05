"""Closed-loop HTTP load client for the overhead test (scripts/overhead-run.sh). Runs INSIDE the
cluster, in the load pod, so kubectl port-forward does not sit between the client and the app:

    kubectl -n provbind-load exec -i loadgen -- python3 - <url> <seconds> <concurrency> <mix> < eval/overhead_client.py

<mix> is `mix` (60% /, 25% /healthz, 15% /cache, the load generator's mix) or a single path such as
`/cache`. Prints one JSON object on stdout: requests, errors, throughput and latency percentiles in ms.
Standard library only (the load pod runs the demo image's Python).
"""
import json
import random
import sys
import threading
import time
import urllib.request


def pick(mix, rng):
    if mix != "mix":
        return mix
    r = rng.random()
    return "/" if r < 0.60 else ("/healthz" if r < 0.85 else "/cache")


def worker(base, mix, deadline, seed, out, errors):
    rng = random.Random(seed)
    while time.monotonic() < deadline:
        path = pick(mix, rng)
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(base + path, timeout=10) as r:
                r.read()
            out.append((time.perf_counter() - t0) * 1000.0)
        except Exception:                                   # noqa: BLE001 - count, keep going
            errors.append(1)


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(round(q / 100 * (len(v) - 1))))], 3)


def main():
    base, seconds, conc, mix = sys.argv[1].rstrip("/"), float(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    lat, errors = [], []
    deadline = time.monotonic() + seconds
    started = time.monotonic()
    threads = [threading.Thread(target=worker, args=(base, mix, deadline, i, lat, errors)) for i in range(conc)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.monotonic() - started
    print(json.dumps({"mix": mix, "seconds": round(took, 2), "concurrency": conc, "requests": len(lat),
                      "errors": len(errors), "rps": round(len(lat) / took, 2) if took else None,
                      "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
                      "mean_ms": round(sum(lat) / len(lat), 3) if lat else None}))


if __name__ == "__main__":
    main()
