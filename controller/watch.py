"""Phase 2: admission, verification and binding (Sprint Handoff §3.3, §4.2, §8 Day 1; Test Plan §3.2).

    python -m controller.watch --run $PROVBIND_RUN [--namespace demo] [--key pipeline/keys/cosign.pub] [--once]
    python -m controller.watch --run $PROVBIND_RUN --image REF@DIGEST [--pod NAME] [--container-id ID]

Watches pods in the namespace. For each started container it:

1. **Verifies the running digest**, taken from the container status's imageID, never a tag, so a
   moved tag cannot redirect the evidence (PH2-08). Verification is Role 2's `compiler.evidence`:
   `cosign verify` plus `verify-attestation` for CycloneDX and SLSA v1, with the public key. It
   requires an image-signature entry for the digest, because cosign v3's `verify` alone also passes
   an image that is attested but never signed. Two more checks follow (Eqs. 11-12):
   - **v_trans**: the signature's Rekor entry (its sign/v1 bundle) must carry an RFC 6962 inclusion
     proof that hashes to its root (PH2-04). Offline signing has no entry: not applicable.
   - **v_trust**: the key must not be revoked, disabled or compromised in `keystatus.json`, the
     stand-in for KMS key state that Phase 6 reads too (PH2-05). This one is checked on every
     admission, not cached, so a pod started after a revocation is not verified. A container already
     bound is not re-admitted when the watch re-lists it: a later revocation is the trust loop's.
   **Any failure, including a missing cosign, gives `verified: false`**: the controller fails closed.
2. **Stores the verification context** Γ_I (Eq. 22, PH2-09) in `contexts/<hex>.json`: the key and its
   id, the five checks, the builder, commit and Rekor log index, the signature bundle with its
   transparency entry, and t0, the verification time. Phase 6 (`alerts.trust`) reads it. The SBOM's
   dependency edges go beside it, in `contexts/<hex>.sbom.json`, for the dependency path (PH5-07).
3. **Writes the binding** in `bindings.json` (§4.2) as soon as the container ID is known: whole-file,
   temp file and rename. `mounts` are the container's volume mounts plus the files Kubernetes manages;
   `run_as_root` and `privileged` come from the container's securityContext, then the pod's.
4. **Runs Role 2's compiler** once per verified digest if `envelopes/<hex>.json` is missing, then sets
   `envelope_ready` only if that file exists.

A deleted pod's bindings are removed, and so are a restarted container's old IDs (Role 3's Q5).
Verification and compilation run once per digest per process.

`--image` binds one image without a cluster (a local check or a test): it verifies, stores the
context, compiles and writes one binding for container `--container-id`, then exits: 0 verified and
envelope ready; 2 not verified; 3 no envelope. With no Kubernetes client or cluster config, the
watcher exits 3; it never invents a binding. Logs go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from alerts.attribute import graph_path, sbom_graph
from alerts.common import atomic_write_json, envelope_path, hex_of, load_json, locked, logger, now_iso
from alerts.trust import key_check, key_id_of, verify_inclusion
from compiler import evidence, oci

log = logger("controller")

ROOT = Path(__file__).resolve().parents[1]
K8S_MANAGED = ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/termination-log",
               "/var/run/secrets/kubernetes.io/serviceaccount"]
COMPILE_TIMEOUT_S = 900


# --- image references -----------------------------------------------------------------------------------

def _strip_tag(image: str) -> str:
    repo = image.split("@", 1)[0]
    slash = repo.rfind("/")
    colon = repo.rfind(":")
    return repo[:colon] if colon > slash else repo


def digest_ref(image: str | None, image_id: str | None) -> str | None:
    """`repo@sha256:<hex>` for what the container runs, from the status's image and imageID."""
    image_id = (image_id or "").split("://", 1)[-1]          # docker-pullable://repo@sha256:...
    if "@sha256:" in image_id:
        return image_id
    if image_id.startswith("sha256:") and image:
        return f"{_strip_tag(image)}@{image_id}"
    if image and "@sha256:" in image:
        return image
    return None


# --- verification -------------------------------------------------------------------------------------------

def signature_bundle(bundles_output: str, hex_digest: str) -> dict | None:
    """The sign/v1 bundle bound to the digest (cosign v3), latest integratedTime first."""
    best, best_t = None, None
    for value in evidence.json_values(bundles_output):
        stmt = evidence.statement(value) if isinstance(value, dict) and "dsseEnvelope" in value else None
        if stmt is None or not evidence.binds(stmt, hex_digest, evidence.SIGN_V1):
            continue
        entries = (value.get("verificationMaterial") or {}).get("tlogEntries") or [{}]
        t = int(str((entries[0] or {}).get("integratedTime", "0") or 0))
        if best_t is None or t >= best_t:
            best, best_t = value, t
    return best


def transparency_check(bundle: dict | None) -> tuple[bool | None, str]:
    """v_trans (Eq. 11) on the signature's sign/v1 bundle: None when there is no entry to check."""
    entries = ((bundle or {}).get("verificationMaterial") or {}).get("tlogEntries") or []
    if not entries:
        return None, "no transparency entry in the signature bundle"
    return verify_inclusion(entries[0])


class Verifier:
    def __init__(self, key: str, offline: bool = False, registry_name: str | None = None, cosign=None,
                 run: str | Path | None = None):
        self.key, self.offline, self.registry_name = key, offline, registry_name
        self.cosign = cosign
        self.run = Path(run) if run is not None else None       # for keystatus.json (v_trust)
        self.cache: dict[str, dict] = {}
        self.graphs: dict[str, dict] = {}                       # digest -> the SBOM's edges
        try:
            self.key_id = key_id_of(key)
        except (OSError, ValueError) as e:
            log.error("cannot read the public key %s (%s): every image will be unverified", key, e)
            self.key_id = None

    def verify(self, ref: str) -> dict:
        """Γ_I for the image: verified or not, and why. The cosign checks and v_trans run once per
        digest; v_trust is checked on every call."""
        repo, digest = oci.parse_ref(ref)
        if digest not in self.cache:
            self.cache[digest] = self._evidence(repo, digest, ref)
        ctx = dict(self.cache[digest], checks=dict(self.cache[digest]["checks"]))
        if ctx["verified"]:
            ok, why = key_check(ctx, self._keystatus())
            ctx["checks"]["v_trust"] = ok
            if ok is False:
                ctx.update(verified=False, reason=f"key: {why}")
                log.warning("%s NOT verified: %s", hex_of(digest)[:12], ctx["reason"])
        return ctx

    def _keystatus(self) -> dict:
        doc = load_json(self.run / "keystatus.json", {}) if self.run is not None else {}
        return doc if isinstance(doc, dict) else {}

    def _evidence(self, repo: str, digest: str, ref: str) -> dict:
        fetch_ref = f"{oci.with_registry(repo, self.registry_name)}@{digest}"
        ctx = {"digest": digest, "ref": ref, "t0": now_iso(), "offline": self.offline,
               "key": {"path": str(self.key), "key_id": self.key_id},
               "verified": False, "reason": None,
               "checks": {"v_sig": False, "v_B": False, "v_P": False, "v_trans": None, "v_trust": None},
               "builder_id": None, "source_commit": None, "rekor_log_index": None, "signature_bundle": None}
        cosign = self.cosign or evidence.Cosign(self.key, offline=self.offline)
        started = time.perf_counter()
        try:
            if self.key_id is None:
                raise evidence.EvidenceError("v_sig: the public key cannot be read")
            ev = evidence.collect(fetch_ref, digest, cosign)
            ctx["checks"].update(ev.verification)
            ctx.update(verified=True, builder_id=ev.builder_id, source_commit=ev.source_commit,
                       rekor_log_index=ev.rekor_log_index, reason="signature and both attestations verified")
            self.graphs[digest] = sbom_graph(ev.sbom)
            if not self.offline:
                ctx["signature_bundle"] = signature_bundle(cosign.download_signature(fetch_ref), hex_of(digest))
                ok, why = transparency_check(ctx["signature_bundle"])
                ctx["checks"]["v_trans"] = ok
                if ok is False:
                    ctx.update(verified=False, reason=f"v_trans: {why}")
                elif ok:
                    ctx["reason"] += "; the Rekor inclusion proof verifies"
        except evidence.EvidenceError as e:          # collect stops at the first failed check
            order = ("v_sig", "v_B", "v_P")
            failed = str(e).split(":", 1)[0]
            if failed in order:
                ctx["checks"].update({k: i < order.index(failed) for i, k in enumerate(order)})
            ctx["reason"] = str(e)
        except Exception as e:                   # cosign missing, timeout, anything: fail closed
            ctx["reason"] = f"{type(e).__name__}: {e}"
        ctx["verify_ms"] = round((time.perf_counter() - started) * 1000, 1)
        (log.info if ctx["verified"] else log.warning)("%s %s: %s", hex_of(digest)[:12],
                                                       "verified" if ctx["verified"] else "NOT verified", ctx["reason"])
        return ctx


# --- pod specs ------------------------------------------------------------------------------------------------

def _get(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def container_spec(pod, name: str):
    for c in _get(_get(pod, "spec"), "containers") or []:
        if _get(c, "name") == name:
            return c
    return None


def security(pod, spec) -> tuple[bool, bool]:
    """(run_as_root, privileged): the container's securityContext first, then the pod's. With no
    user set anywhere the image's default is assumed to be root, as for the demo app."""
    csc, psc = _get(spec, "security_context"), _get(_get(pod, "spec"), "security_context")
    user = _get(csc, "run_as_user")
    if user is None:
        user = _get(psc, "run_as_user")
    non_root = _get(csc, "run_as_non_root")
    if non_root is None:
        non_root = _get(psc, "run_as_non_root")
    run_as_root = (user == 0) if user is not None else not bool(non_root)
    return run_as_root, bool(_get(csc, "privileged"))


def mounts_of(spec) -> list[str]:
    paths = set(K8S_MANAGED)
    for m in _get(spec, "volume_mounts") or []:
        p = _get(m, "mount_path")
        if p:
            paths.add(p.rstrip("/") or "/")
    return sorted(paths)


# --- the controller -----------------------------------------------------------------------------------------

class Controller:
    def __init__(self, run: str | Path, key: str, offline: bool = False, registry_name: str | None = None,
                 verifier: Verifier | None = None, compile_fn=None):
        self.run = Path(run).resolve()
        self.key = str(Path(key).resolve()) if not os.path.isabs(key) else key
        self.registry_name = registry_name
        self.verifier = verifier or Verifier(self.key, offline, registry_name, run=self.run)
        if getattr(self.verifier, "run", None) is None:
            self.verifier.run = self.run
        self.compile_fn = compile_fn or self._compile
        self.compiled: dict[str, bool] = {}
        self.bindings_path = self.run / "bindings.json"
        self.lock = self.run / ".bindings.lock"
        (self.run / "envelopes").mkdir(parents=True, exist_ok=True)

    def _compile(self, ref: str) -> bool:
        cmd = [sys.executable, "-m", "compiler.compile", ref, "--run", str(self.run), "--key", self.key]
        if self.registry_name:
            cmd += ["--registry-name", self.registry_name]
        log.info("compiling %s", ref)
        try:
            out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=COMPILE_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            log.error("compiler did not run: %s", e)
            return False
        if out.returncode != 0:
            log.error("compiler exit %d: %s", out.returncode, (out.stderr.strip().splitlines() or ["?"])[-1])
            return False
        return True

    def _update_bindings(self, change) -> None:
        with locked(self.lock):
            doc = load_json(self.bindings_path, {}) or {}
            if not isinstance(doc, dict):
                doc = {}
            if change(doc) is not False:
                atomic_write_json(self.bindings_path, doc)

    def bind(self, container_id: str, namespace: str, pod: str, container: str, ref: str,
             run_as_root: bool = True, privileged: bool = False, mounts: list[str] | None = None) -> dict:
        existing = (load_json(self.bindings_path, {}) or {}).get(container_id)
        if isinstance(existing, dict) and existing.get("image_digest") == oci.parse_ref(ref)[1]:
            # Already admitted. v_trust is an admission check (module docstring): the watch re-lists every
            # pod every 300 s and on each pod update, and must not re-admit a running container. On the
            # demo VM a re-list inside trust-2's 30 s revocation flipped the running pod to unverified, which
            # blinded the node and the trust loop for 5 minutes, since restoring the key re-verified nothing.
            # Key changes for running pods are the trust loop's (alerts.trust: trust/key).
            ready = envelope_path(self.run, existing["image_digest"]).exists()
            if ready != existing.get("envelope_ready"):
                existing = {**existing, "envelope_ready": ready}
                self._update_bindings(lambda d: d.__setitem__(container_id, existing) if container_id in d else False)
            return existing
        ctx = self.verifier.verify(ref)
        digest = ctx["digest"]
        ctx_path = self.run / "contexts" / f"{hex_of(digest)}.json"
        if load_json(ctx_path) != ctx:
            atomic_write_json(ctx_path, ctx)
        graph = getattr(self.verifier, "graphs", {}).get(digest)
        if graph is not None and load_json(graph_path(self.run, digest)) != {"digest": digest, **graph}:
            atomic_write_json(graph_path(self.run, digest), {"digest": digest, **graph})
        env = envelope_path(self.run, digest)
        binding = {"namespace": namespace, "pod": pod, "container": container, "image_digest": digest,
                   "verified": bool(ctx["verified"]), "run_as_root": bool(run_as_root), "privileged": bool(privileged),
                   "mounts": sorted(set(mounts or K8S_MANAGED)), "envelope_ready": env.exists(),
                   "ref": ref, "reason": ctx["reason"]}
        self._update_bindings(lambda d: d.__setitem__(container_id, binding))
        if ctx["verified"] and not env.exists() and digest not in self.compiled:
            self.compiled[digest] = self.compile_fn(ref)
            if env.exists():
                binding = {**binding, "envelope_ready": True}
                self._update_bindings(lambda d: d.__setitem__(container_id, binding) if container_id in d else False)
        log.info("bound %s -> %s (verified %s, envelope_ready %s)", container_id[-12:], hex_of(digest)[:12],
                 binding["verified"], binding["envelope_ready"])
        return binding

    def forget_pod(self, namespace: str, pod: str, keep: set[str] = frozenset()) -> list[str]:
        removed = []

        def change(doc):
            for cid in [c for c, b in doc.items() if isinstance(b, dict) and b.get("namespace") == namespace
                        and b.get("pod") == pod and c not in keep]:
                removed.append(cid)
                del doc[cid]
            return bool(removed)
        self._update_bindings(change)
        for cid in removed:
            log.info("removed binding %s (pod %s/%s)", cid[-12:], namespace, pod)
        return removed

    def handle_pod(self, event_type: str, pod) -> None:
        meta = _get(pod, "metadata")
        namespace, name = _get(meta, "namespace"), _get(meta, "name")
        if event_type == "DELETED":
            self.forget_pod(namespace, name)
            return
        current = set()
        for status in _get(_get(pod, "status"), "container_statuses") or []:
            cid = _get(status, "container_id")
            if not cid:
                continue                                 # not started yet; bound on a later event
            current.add(cid)
            ref = digest_ref(_get(status, "image"), _get(status, "image_id"))
            if ref is None:
                log.warning("%s/%s %s: no digest in the container status; not bound", namespace, name, _get(status, "name"))
                continue
            spec = container_spec(pod, _get(status, "name"))
            run_as_root, privileged = security(pod, spec)
            self.bind(cid, namespace, name, _get(status, "name"), ref, run_as_root, privileged, mounts_of(spec))
        self.forget_pod(namespace, name, keep=current)

    def watch(self, namespace: str, once: bool = False) -> int:
        try:
            from kubernetes import client, config, watch
        except ImportError:
            log.error("the kubernetes Python client is not installed (pip install -r requirements.txt)")
            return 3
        try:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
        except Exception as e:
            log.error("no Kubernetes configuration: %s", e)
            return 3
        v1 = client.CoreV1Api()
        if once:
            for pod in v1.list_namespaced_pod(namespace).items:
                self.handle_pod("ADDED", pod)
            return 0
        log.info("watching pods in namespace %s", namespace)
        while True:
            try:
                for event in watch.Watch().stream(v1.list_namespaced_pod, namespace=namespace, timeout_seconds=300):
                    self.handle_pod(event["type"], event["object"])
            except KeyboardInterrupt:
                return 0
            except Exception as e:                   # an expired watch, an API hiccup: resume
                log.warning("watch interrupted (%s); resuming", e)
                time.sleep(2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m controller.watch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--namespace", default="demo")
    ap.add_argument("--key", "--pubkey", dest="key", default="pipeline/keys/cosign.pub", help="cosign public key")
    ap.add_argument("--registry-name", help="registry host to fetch from, if the cluster's differs (compiler --registry-name)")
    ap.add_argument("--once", action="store_true", help="bind the pods that exist now, then exit")
    ap.add_argument("--image", help="bind one REF@DIGEST without a cluster, then exit")
    ap.add_argument("--pod", default="local", help="pod name for --image")
    ap.add_argument("--container", default="app", help="container name for --image")
    ap.add_argument("--container-id", help="container ID for --image (default containerd://local-<hex12>)")
    args = ap.parse_args(argv)
    offline = os.environ.get("PROVBIND_OFFLINE") == "1"
    ctl = Controller(args.run, args.key, offline, args.registry_name)
    if args.image:
        try:
            _, digest = oci.parse_ref(args.image)
        except oci.BadInput as e:
            log.error("%s", e)
            return 3
        cid = args.container_id or f"containerd://local-{hex_of(digest)[:12]}"
        binding = ctl.bind(cid, args.namespace, args.pod, args.container, args.image)
        print(json.dumps({cid: binding}))
        if not binding["verified"]:
            return 2
        return 0 if binding["envelope_ready"] else 3
    return ctl.watch(args.namespace, args.once)


if __name__ == "__main__":
    sys.exit(main())
