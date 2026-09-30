"""PROVBIND demo app: a tiny HTTP server on port 8080 (Sprint Handoff §5). HARMLESS test code.

Endpoints drive the demo scenarios (Test Plan §7); all effects happen only inside the throwaway
demo container:
  GET /         -> "ok"
  GET /healthz  -> "ok"
  GET /cache    -> the app's own benign cache-file write (the load generator's traffic for ML-B's D2)
  GET /update   -> attack-1: requestz_helper.check_update() drops and runs the test payload
  GET /update2  -> attack-2: an in-envelope burst of new files under /tmp/.cache (declared binaries
                   only), which no deterministic rule flags but ML-B should (D_beh)
The Tier 2 comparison endpoints (TIER2 below) each drive one harmless behaviour in tier2.py, one per
comparison-plan scenario (R-K2, R-K3, R-U3, R-U4, R-U5, B4, B5, A-U2). Any other /update* path is a
P1 scenario not implemented in this prototype and returns 501.
"""
from __future__ import annotations

import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

CACHE_DIR = "/tmp/.cache"

# Tier 2 comparison endpoints -> the harmless behaviour in tier2.py (docs/COMPARISON-RUN.md §3).
TIER2 = {
    "/rk2": "kernel_cve_shape",      # R-K2: known kernel-CVE syscall shape (waitid, splice)
    "/rk3": "preload_injection",     # R-K3: LD_PRELOAD of an embedded harmless .so
    "/ru3": "exfil_connect",         # R-U3: connect to a never-routed test address (no data sent)
    "/ru4": "overwrite_binary",      # R-U4: overwrite the declared /usr/bin/ls, then run it
    "/ru5": "credential_read",       # R-U5: read the SA token; send only its digest to an allowed sink
    "/b4": "dns_lookups",            # B4: benign DNS lookups
    "/b5": "volume_write",           # B5: benign write under a mounted volume
    "/au2": "build_time_payload",    # A-U2: run a build-time program (Dockerfile.au2 variant only)
}


def cache_burst(base_dir: str = CACHE_DIR, n: int = 300, duration: float = 20.0) -> int:
    """Write n new files over about `duration` seconds and read them back (attack-2: 300 files in
    20 s, Test Plan §7). Pure Python file I/O inside the long-running server process (ML-B ignores
    processes younger than 10 s): no new executables, no writes to declared files. Returns the
    number of files written."""
    os.makedirs(base_dir, exist_ok=True)
    pause = duration / n if n else 0
    written = 0
    for i in range(n):
        if pause:
            time.sleep(pause)
        p = os.path.join(base_dir, f"c{i}.dat")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"payload-{i}\n")
        written += 1
    for i in range(n):                       # read them back
        with open(os.path.join(base_dir, f"c{i}.dat"), encoding="utf-8") as f:
            f.read()
    return written


APP_CACHE_DIR = "/tmp/app-cache"


def cache_entry(base_dir: str = APP_CACHE_DIR, slots: int = 50) -> str:
    """The app's own, benign cache-file write (GET /cache): rewrite one of `slots` small files and
    read it back. The load generator calls it at random, so ML-B's benign data (D2, Test Plan §5)
    contains ordinary file writes and attack-2's burst is judged against them."""
    os.makedirs(base_dir, exist_ok=True)
    path = os.path.join(base_dir, f"entry{int(time.time() * 1000) % slots}.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"cached_at": %d}\n' % int(time.time()))
    with open(path, encoding="utf-8") as f:
        f.read()
    return path


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = (body + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/healthz"):
            self._send(200, "ok")
        elif self.path == "/cache":
            cache_entry()
            self._send(200, "cached")
        elif self.path == "/update":
            from requestz_helper import check_update
            started = check_update()
            self._send(200, f"update triggered (payload started: {started})")
        elif self.path == "/update2":
            self._send(200, f"burst done ({cache_burst()} files)")
        elif self.path in TIER2:
            import tier2
            result = getattr(tier2, TIER2[self.path])()
            self._send(200, f"{self.path}: {result}")
        elif self.path.startswith("/update"):
            self._send(501, "scenario endpoint not implemented in this prototype")
        else:
            self._send(404, "not found")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
