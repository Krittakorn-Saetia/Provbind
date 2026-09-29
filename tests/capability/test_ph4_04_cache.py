"""PH4-04 (P1): one cached envelope per digest (Eq. 52), live on the demo PC (integration).

Scale the demo deployment to 5 replicas, then to 0, while Role 4's controller keeps
$PROVBIND_RUN/bindings.json up to date. After each step, a Store on the run folder must hold:
- at 5 replicas, one envelope for the image's digest, referenced by 5 verified containers;
- at 0, no envelope for the digest (evicted).

The deployment is PROVBIND_DEMO_DEPLOY (default demo-app) in namespace demo; its replica count is
restored at the end. If the controller keeps the bindings of deleted pods, the eviction never
happens and the test fails with that note. The logic itself is unit-tested in node/tests/test_store.py.
"""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from node.store import Store

RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
DEPLOY = os.environ.get("PROVBIND_DEMO_DEPLOY", "demo-app")


def kubectl(*args, timeout=60):
    proc = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        pytest.skip(f"kubectl {' '.join(args[:3])} failed: {proc.stderr.strip()[-300:]}")
    return proc.stdout


def ours():
    """Verified bindings of the deployment's pods: container ID -> digest."""
    try:
        doc = json.loads((RUN / "bindings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {cid: b.get("image_digest") for cid, b in doc.items()
            if (b.get("pod") or "").startswith(DEPLOY) and b.get("verified") is True}


def wait_for(predicate, timeout=180):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(2)
    return False


@pytest.mark.integration
def test_ph4_04_one_envelope_per_digest_live(record_result):
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl is not on PATH")
    before = int(kubectl("get", "deploy", DEPLOY, "-n", "demo", "-o", "jsonpath={.spec.replicas}") or 1)
    metrics, notes = {}, []
    try:
        kubectl("scale", "deploy", DEPLOY, "-n", "demo", "--replicas=5")
        up = wait_for(lambda: len(ours()) >= 5)
        digests = set(ours().values())
        store = Store(RUN)
        store.refresh()
        digest = next(iter(digests)) if len(digests) == 1 else None
        metrics.update({"bindings_at_5": len(ours()), "digests_at_5": len(digests),
                        "refs_at_5": store.refs[digest] if digest else None,
                        "envelopes_for_digest_at_5": int(digest in store.cache) if digest else 0})
        if not up:
            notes.append("fewer than 5 verified bindings appeared within 180 s")
        kubectl("scale", "deploy", DEPLOY, "-n", "demo", "--replicas=0")
        down = wait_for(lambda: not ours())
        store.refresh()
        metrics.update({"bindings_at_0": len(ours()), "evicted": int(bool(digest) and digest not in store.cache),
                        "evictions": store.stats["evictions"]})
        if not down:
            notes.append("the controller kept the bindings of deleted pods, so nothing could be evicted")
    finally:
        subprocess.run(["kubectl", "scale", "deploy", DEPLOY, "-n", "demo", f"--replicas={before}"],
                       capture_output=True, timeout=60)
    ok = (metrics.get("refs_at_5") or 0) >= 5 and metrics.get("envelopes_for_digest_at_5") == 1 \
        and metrics.get("evicted") == 1
    record_result("PH4-04", "pass" if ok else "fail", metrics=metrics,
                  notes="live scale 5 then 0: " + ("; ".join(notes) or "one envelope at 5 replicas, evicted at 0"))
    assert ok, (metrics, notes)
