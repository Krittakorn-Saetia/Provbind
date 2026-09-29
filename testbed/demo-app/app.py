"""PROVBIND demo app: a tiny HTTP server on port 8080 (Sprint Handoff §5). HARMLESS test code.

Endpoints drive the demo scenarios (Test Plan §7); all effects happen only inside the throwaway
demo container:
  GET /         -> "ok"
  GET /healthz  -> "ok"
  GET /update   -> attack-1: requestz_helper.check_update() drops and runs the test payload
  GET /update2  -> attack-2: an in-envelope burst of new files under /tmp/.cache (declared binaries
                   only), which no deterministic rule flags but ML-B should (D_beh)
The attack-3..8 endpoints (P1 scenarios) are not implemented in this prototype and return 501.
"""
from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, HTTPServer

CACHE_DIR = "/tmp/.cache"


def cache_burst(base_dir: str = CACHE_DIR, n: int = 300) -> int:
    """Write n new files and read them back (attack-2). Pure Python file I/O: no new executables,
    no writes to declared files. Returns the number of files written."""
    os.makedirs(base_dir, exist_ok=True)
    written = 0
    for i in range(n):
        p = os.path.join(base_dir, f"c{i}.dat")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"payload-{i}\n")
        written += 1
    for i in range(n):                       # read them back
        with open(os.path.join(base_dir, f"c{i}.dat"), encoding="utf-8") as f:
            f.read()
    return written


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
        elif self.path == "/update":
            from requestz_helper import check_update
            started = check_update()
            self._send(200, f"update triggered (payload started: {started})")
        elif self.path == "/update2":
            self._send(200, f"burst done ({cache_burst()} files)")
        elif self.path.startswith("/update"):
            self._send(501, "scenario endpoint not implemented in this prototype")
        else:
            self._send(404, "not found")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
