"""A small synthetic dataset D1 in ml/train.py's format, for testing before the real one exists.

Each image is drawn from an archetype (a web server that drops privileges, a Python app that runs
as a user, a ping utility, ...) with random extra packages, environment variables, missing ELF
imports and restricted pods. The real extractor (ml.features.extract) turns it into features.
Its labels come from a fixed rule per archetype, capped at the pod's allowed set, with some label
noise. The rules can be learned from the features, so a working pipeline beats the empty baseline.
The numbers say nothing about real images.
"""
from __future__ import annotations

import hashlib
import random

from ml.alg1 import effective_set
from ml.features import extract

LIBC = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/ld-linux-x86-64.so.2"]
SERVER_IMPORTS = ["socket", "bind", "listen", "setuid", "setgid", "setgroups", "chown"]

# name: (images, packages, closure, imports of the first closure file, ports, User, labels)
ARCHETYPES = {
    "webserver": (7, ["pkg:deb/debian/nginx@1.27.0", "pkg:deb/debian/libc6@2.36", "pkg:deb/debian/libssl3@3.0.15"],
                  ["/usr/sbin/nginx"] + LIBC, SERVER_IMPORTS, ["80/tcp"], "",
                  {"CAP_NET_BIND_SERVICE", "CAP_SETUID", "CAP_SETGID", "CAP_CHOWN", "CAP_DAC_OVERRIDE"}),
    "datastore": (5, ["pkg:deb/debian/postgresql-16@16.4", "pkg:deb/debian/libc6@2.36", "pkg:deb/debian/gosu@1.17"],
                  ["/usr/lib/postgresql/16/bin/postgres"] + LIBC, SERVER_IMPORTS, ["5432/tcp"], "",
                  {"CAP_SETUID", "CAP_SETGID", "CAP_CHOWN", "CAP_FOWNER", "CAP_DAC_OVERRIDE"}),
    "cache": (5, ["pkg:deb/debian/redis-server@7.0.15", "pkg:deb/debian/libc6@2.36", "pkg:deb/debian/gosu@1.17"],
              ["/usr/bin/redis-server"] + LIBC, ["socket", "bind", "listen", "setuid", "setgid"], ["6379/tcp"], "",
              {"CAP_SETUID", "CAP_SETGID"}),
    "python_app": (6, ["pkg:pypi/flask@3.0.3", "pkg:pypi/werkzeug@3.0.4", "pkg:deb/debian/libc6@2.36"],
                   ["/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0"] + LIBC,
                   ["socket", "bind", "listen", "connect"], ["8080/tcp"], "app", set()),
    "python_low_port": (3, ["pkg:pypi/gunicorn@22.0.0", "pkg:pypi/flask@3.0.3", "pkg:deb/debian/libc6@2.36"],
                        ["/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0"] + LIBC,
                        ["socket", "bind", "listen", "connect"], ["80/tcp"], "", {"CAP_NET_BIND_SERVICE"}),
    "node_app": (4, ["pkg:npm/express@4.19.2", "pkg:npm/lodash@4.17.21"], ["/usr/local/bin/node"] + LIBC,
                 ["socket", "bind", "listen", "connect"], ["3000/tcp"], "node", set()),
    "go_static": (3, ["pkg:golang/example.com/server@v1.2.0"], ["/app/server"], [], ["8080/tcp"], "65532", set()),
    "ping": (4, ["pkg:deb/debian/iputils-ping@20221126", "pkg:deb/debian/libc6@2.36"], ["/usr/bin/ping"] + LIBC,
             ["socket", "setuid"], [], "", {"CAP_NET_RAW"}),
    "shell_job": (1, ["pkg:apk/alpine/busybox@1.36.1"], ["/bin/busybox"], ["socket", "connect"], [], "", set()),
    "supervisor": (2, ["pkg:pypi/supervisor@4.2.5", "pkg:deb/debian/libc6@2.36"],
                   ["/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0"] + LIBC,
                   ["socket", "setuid", "setgid"], ["9001/tcp"], "", {"CAP_KILL", "CAP_SETUID", "CAP_SETGID"}),
}
EXTRA_PACKAGES = ["pkg:deb/debian/zlib1g@1.2.13", "pkg:deb/debian/ca-certificates@20230311", "pkg:pypi/requests@2.32.3",
                  "pkg:pypi/urllib3@2.2.3", "pkg:npm/debug@4.3.6", "pkg:deb/debian/tzdata@2024a"]
RESTRICTED_POD = {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}


def rows(seed: int = 0, noise: float = 0.1) -> list[dict]:
    """40 images; `noise` is the chance that an image's label set gains or loses one capability,
    like two profiling runs that disagree (§4.2)."""
    rng = random.Random(seed)
    out = []
    for name, (count, packages, closure, imports, ports, user, labels) in ARCHETYPES.items():
        for i in range(count):
            pkgs = sorted(set(packages) | set(rng.sample(EXTRA_PACKAGES, rng.randint(0, 3))))
            pod = RESTRICTED_POD if rng.random() < 0.15 else {}
            allowed = effective_set(pod.get("add", ()), pod.get("drop", ()))
            known = None if rng.random() < 0.1 else {closure[0]: imports}     # ELF imports not read
            config = {"User": user, "ExposedPorts": dict.fromkeys(ports, {}),
                      "Env": [f"VAR{j}=x" for j in range(rng.randint(1, 6))]}
            envelope = {"packages": dict.fromkeys(pkgs, {}), "closure": closure}
            used = set(labels)
            if rng.random() < noise:
                used ^= {rng.choice(sorted(allowed))}
            digest = "sha256:" + hashlib.sha256(f"synthetic/{seed}/{name}/{i}".encode()).hexdigest()
            out.append({"digest": digest, "image": f"synthetic/{name}:{i}",
                        "features": extract(envelope, config, imports=known, deployment=pod).to_json(),
                        "packages": pkgs, "labels": sorted(used & allowed), "allowed": sorted(allowed),
                        "exposed_ports": sorted(ports), "synthetic": True})
    return out
