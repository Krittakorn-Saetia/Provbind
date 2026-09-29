"""Phase 6: trust re-evaluation (Explanation §9; Eqs. 81-96; Test Plan §3.9, scenarios trust-1/2).

    python -m alerts.trust --run $PROVBIND_RUN [--interval 300] [--poll 2] [--once]
    python -m alerts.trust key-id [--key pipeline/keys/cosign.pub]
    python -m alerts.trust set-key --run $PROVBIND_RUN --state revoked [--key ...] [--since TIME]

For every verified image in `bindings.json`, four checks decide whether its evidence can still be
trusted (Eq. 89: trusted = all four). The inputs are plain files in the run folder, so a scenario
changes trust by editing one:

| Check | Eq. | Input | Fails when |
|---|---|---|---|
| key | 85 | `keystatus.json` (stand-in for KMS key state) | the signing key is revoked, disabled or compromised; or rotated before the image was verified |
| trans | 86 | the Rekor entry stored at admission, `contexts/<hex>.json` | its inclusion proof no longer hashes to its root, or the checkpoint disagrees |
| builder | 87 | `builder_denylist.json` | the provenance's builder_id is listed |
| comp | 88 | `advisories/*.json` (OSV format) | a package in the envelope has a malicious-package advisory (`MAL-` ID) |

- **Alert once** (Eq. 90): a trust alert is written only when an image goes from trusted to not
  trusted. An admitted image starts trusted (Eq. 84), so a first evaluation that fails alerts too.
  The state is saved every cycle (Eq. 93) in `trust/<hex>.json`, so staying untrusted is silent.
- **Policy** (Explanation §9): an ordinary advisory (a CVE, not `MAL-`) never withdraws trust; it is
  reported in the state file (PH6-05). A key rotated after the image was verified keeps its trust.
- **trans** re-hashes the stored RFC 6962 inclusion proof to its root and compares the checkpoint's
  tree size and root. It does not verify Rekor's signature on the checkpoint, nor fetch a newer tree
  head for a consistency proof: both need the network. Without a stored entry (offline signing) the
  check is not applicable and does not withdraw trust.
- **Runtime and trust stay separate** (Eqs. 95-96): the alert says whether the image's containers
  are conforming or deviating at runtime, from the detection alerts in `alerts.jsonl`.
- **When**: every --interval seconds (ΔR, 300 by default), and within --poll seconds of any input
  file changing, so trust-1's advisory edit alerts within its 30 s window (E2E-11).

keystatus.json:        {"keys": {"<key id>": {"state": "active|rotated|disabled|revoked", "since": TIME}}}
builder_denylist.json: ["<builder id>", ...]  or  {"denied": ["<builder id>", ...]}
Key ids are "sha256:" + the SHA-256 of the public key's DER bytes (`key-id` prints it).

Trust alerts go to `alerts.jsonl` and the violation log like any alert, with class "trust",
subclass the failed checks joined by "+", and `trust_reason` listing them (Role 1's E2E-11).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import glob
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from compiler import purls

from .common import (atomic_write_json, container_label, hex_of, load_envelope, load_json, logger, now_iso,
                     parse_time)
from .log import ViolationLog

log = logger("trust")

CHECKS = ("key", "trans", "builder", "comp")
BAD_KEY_STATES = {"revoked", "disabled", "compromised", "destroyed"}
TRUST_SCORE = 70                     # proposal: the plan gives trust alerts no score; High
DEFAULT_KEY = "pipeline/keys/cosign.pub"
OSV_TYPES = {"pypi": "pypi", "npm": "npm", "debian": "deb", "ubuntu": "deb", "go": "golang",
             "crates.io": "cargo", "maven": "maven", "rubygems": "gem", "nuget": "nuget",
             "packagist": "composer", "alpine": "apk"}


# --- key ids ------------------------------------------------------------------------------------------

def key_id_of(path: str | Path) -> str:
    """'sha256:' + SHA-256 of the DER bytes inside a PEM public key (line endings don't matter)."""
    text = Path(path).read_text(encoding="ascii")
    body = "".join(ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("-----"))
    return "sha256:" + hashlib.sha256(base64.b64decode(body)).hexdigest()


# --- the four checks ----------------------------------------------------------------------------------

def key_check(context: dict | None, keystatus: dict) -> tuple[bool | None, str]:
    key = (context or {}).get("key") or {}
    kid = key.get("key_id")
    if not kid:
        return None, "no key id stored at admission"
    keys = keystatus.get("keys", keystatus) if isinstance(keystatus, dict) else {}
    entry = keys.get(kid) if isinstance(keys, dict) else None
    if not isinstance(entry, dict):
        return True, f"key {kid[:19]} has no recorded state change"
    state = str(entry.get("state", "active")).lower()
    since = entry.get("since")
    if state in BAD_KEY_STATES:
        return False, f"key {kid[:19]} is {state}" + (f" since {since}" if since else "")
    if state == "rotated":
        t0, ts = parse_time((context or {}).get("t0")), parse_time(since)
        if t0 is not None and ts is not None and t0 < ts:
            return True, f"key {kid[:19]} rotated at {since}, after this image was verified: signature kept"
        return False, f"key {kid[:19]} rotated at {since}, before this image was verified"
    return True, f"key {kid[:19]} is {state}"


def _b64_or_hex(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return bytes.fromhex(s)


def verify_inclusion(entry: dict) -> tuple[bool, str]:
    """RFC 6962 inclusion: the entry's leaf, folded with the proof's hashes, gives the proof's root,
    and the checkpoint names the same tree size and root (RFC 9162 §2.1.3.2)."""
    try:
        proof = entry["inclusionProof"]
        leaf = hashlib.sha256(b"\x00" + base64.b64decode(entry["canonicalizedBody"])).digest()
        index, size = int(proof["logIndex"]), int(proof["treeSize"])
        root = _b64_or_hex(proof["rootHash"])
        hashes = [_b64_or_hex(h) for h in proof["hashes"]]
    except (KeyError, TypeError, ValueError, binascii.Error) as e:
        return False, f"the stored inclusion proof is unreadable ({type(e).__name__})"
    if not 0 <= index < size:
        return False, "the stored inclusion proof's index is outside its tree"
    fn, sn, r = index, size - 1, leaf
    for p in hashes:
        if sn == 0:
            return False, "the stored inclusion proof has too many hashes"
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    if sn != 0 or r != root:
        return False, "the stored inclusion proof does not hash to its root"
    lines = str((proof.get("checkpoint") or {}).get("envelope", "")).split("\n")
    if len(lines) >= 3:
        try:
            if lines[1].strip() != str(size) or base64.b64decode(lines[2].strip()) != root:
                return False, "the checkpoint does not match the inclusion proof"
        except (binascii.Error, ValueError):
            return False, "the checkpoint is unreadable"
    return True, f"inclusion proof verifies (log index {entry.get('logIndex')}, tree size {size})"


def trans_check(context: dict | None) -> tuple[bool | None, str]:
    bundle = (context or {}).get("signature_bundle")
    entries = ((bundle or {}).get("verificationMaterial") or {}).get("tlogEntries") or []
    if not entries:
        return None, "no transparency record stored (offline signing, or verified without one)"
    return verify_inclusion(entries[0])


def builder_check(envelope: dict | None, denylist) -> tuple[bool | None, str]:
    if envelope is None:
        return None, "no envelope"
    builder = (envelope.get("image") or {}).get("builder_id")
    denied = denylist.get("denied", []) if isinstance(denylist, dict) else (denylist or [])
    if builder and builder in denied:
        return False, f"builder {builder} is on the denylist"
    return True, f"builder {builder} is not on the denylist"


def _advisory_packages(adv: dict):
    """(identity, versions or None for every version) for each affected package of an OSV advisory."""
    for aff in adv.get("affected") or []:
        pkg = aff.get("package") or {}
        purl = pkg.get("purl")
        if not purl and pkg.get("name"):
            eco = str(pkg.get("ecosystem", "")).split(":")[0].lower()
            kind = OSV_TYPES.get(eco)
            purl = f"pkg:{kind}/{pkg['name']}" if kind else None
        ident = purls.identity(purl) if purl else None
        if ident:
            versions = aff.get("versions")
            yield ident, (set(versions) if versions else None)


def _same_package(a, b) -> bool:
    return a[0] == b[0] and a[2] == b[2] and (a[1] is None or b[1] is None or a[1] == b[1])


def comp_check(envelope: dict | None, advisories: list[tuple[str, dict]]) -> tuple[bool | None, str, list, list]:
    """(ok, reason, malicious findings, other advisories reported). Each finding names the
    package, its depth and the layers that hold its files (Eq. 94)."""
    if envelope is None:
        return None, "no envelope", [], []
    packages = envelope.get("packages") or {}
    findings, reported = [], []
    for name, adv in advisories:
        aid = str(adv.get("id", name))
        for ident, versions in _advisory_packages(adv):
            for purl, info in packages.items():
                mine = purls.identity(purl)
                if not mine or not _same_package(ident, mine):
                    continue
                parsed = purls.parse(purl)
                version = parsed.version if parsed else None
                if versions is not None and version not in versions:
                    continue
                if aid.upper().startswith("MAL-"):
                    layers = sorted({m.get("layer") for m in (envelope.get("files") or {}).values()
                                     if m.get("package") == purl and m.get("layer") is not None})
                    by_index = {l.get("index"): l.get("digest") for l in envelope.get("layers") or []}
                    findings.append({"advisory": aid, "package": purl, "depth": (info or {}).get("depth"),
                                     "layers": [by_index.get(i) for i in layers], "layer_indices": layers})
                else:
                    reported.append({"advisory": aid, "package": purl})
    if findings:
        f = findings[0]
        return False, (f"{f['package']} is flagged malicious by {f['advisory']}"
                       + ("" if len(findings) == 1 else f" (and {len(findings) - 1} more)")), findings, reported
    return True, "no malicious-package advisory matches a package of the image", [], reported


# --- one evaluation -------------------------------------------------------------------------------------

def load_advisories(run: Path) -> list[tuple[str, dict]]:
    out = []
    for path in sorted(glob.glob(str(run / "advisories" / "*.json"))):
        doc = load_json(path)
        if isinstance(doc, dict):
            out.append((os.path.basename(path), doc))
        elif doc is None:
            log.warning("advisory %s is not JSON; ignored", path)
    return out


def runtime_state(run: Path, digest: str) -> str:
    """'deviating' if any detection alert above Low exists for the image, else 'conforming'."""
    try:
        with open(run / "alerts.jsonl", encoding="utf-8") as f:
            for line in f:
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                if (a.get("image_digest") == digest and a.get("class") != "trust"
                        and str(a.get("bucket", "low")).lower() != "low"):
                    return "deviating"
    except OSError:
        pass
    return "conforming"


def input_mtime(run: Path) -> float | None:
    paths = [run / "keystatus.json", run / "builder_denylist.json", *map(Path, glob.glob(str(run / "advisories" / "*.json")))]
    times = [p.stat().st_mtime for p in paths if p.exists()]
    return max(times) if times else None


def evaluate(run: Path, digest: str) -> dict:
    context = load_json(run / "contexts" / f"{hex_of(digest)}.json")
    envelope = load_envelope(run, digest)
    results = {"key": key_check(context, load_json(run / "keystatus.json", {}) or {}),
               "trans": trans_check(context),
               "builder": builder_check(envelope, load_json(run / "builder_denylist.json", []))}
    ok, why, findings, reported = comp_check(envelope, load_advisories(run))
    results["comp"] = (ok, why)
    checks = {k: v[0] for k, v in results.items()}
    return {"digest": digest, "trusted": all(v is not False for v in checks.values()), "checks": checks,
            "reasons": {k: v[1] for k, v in results.items()}, "failed": [k for k in CHECKS if checks[k] is False],
            "findings": findings, "advisories_reported": reported, "evaluated_at": now_iso(),
            "admitted_at": (context or {}).get("t0"), "envelope": envelope is not None}


def trust_alert(run: Path, state: dict, bindings: list[dict]) -> dict:
    envelope = load_envelope(run, state["digest"]) or {}
    image = envelope.get("image") or {}
    finding = state["findings"][0] if state["findings"] else {}
    first = bindings[0] if bindings else {}
    changed = input_mtime(run)
    now = time.time()
    return {
        "detection_id": None,
        "time": now_iso(),
        "image_digest": state["digest"],
        "container": container_label(first) if first else "",
        "class": "trust",
        "subclass": "+".join(state["failed"]),
        "violated_clause": "; ".join(f"{k}: {state['reasons'][k]}" for k in state["failed"]),
        "origin": "AUTHENTICATED",
        "score": TRUST_SCORE,
        "bucket": "high",
        "attribution": {"layer": (finding.get("layers") or [None])[0], "package": finding.get("package"),
                        "depth": finding.get("depth"), "process_chain": []},
        "signing_identity": {"builder_id": image.get("builder_id"), "source_commit": image.get("source_commit"),
                             "rekor_log_index": image.get("rekor_log_index")},
        "chain_id": None,
        "trust_reason": state["failed"],
        "trust": state["checks"],
        "findings": state["findings"],
        "runtime_state": runtime_state(run, state["digest"]),
        "namespace": first.get("namespace"), "pod": first.get("pod"),
        "containers": [container_label(b) for b in bindings],
        "input_changed_at": changed,
        "latency_s": round(now - changed, 3) if changed else None,
    }


def cycle(run: str | Path, violation_log: ViolationLog | None = None) -> list[dict]:
    """Evaluate every verified image once; write a trust alert for each 1 -> 0 flip."""
    run = Path(run)
    vlog = violation_log or ViolationLog(run)
    bindings = load_json(run / "bindings.json", {}) or {}
    by_digest: dict[str, list[dict]] = {}
    for cid, b in sorted(bindings.items(), key=lambda kv: (str(kv[1].get("pod")), kv[0])):
        if isinstance(b, dict) and b.get("verified") and b.get("image_digest"):
            by_digest.setdefault(b["image_digest"], []).append(b)
    alerts = []
    for digest, bound in by_digest.items():
        state_path = run / "trust" / f"{hex_of(digest)}.json"
        prev = load_json(state_path) or {}
        state = evaluate(run, digest)
        was_trusted = prev.get("trusted", True)                # Eq. (84): admitted means trusted
        same = bool(prev) and prev.get("trusted") == state["trusted"]
        state["since"] = prev.get("since", state["evaluated_at"]) if same else state["evaluated_at"]
        if not state["trusted"] and prev.get("alert_id"):
            state["alert_id"] = prev["alert_id"]
        if was_trusted and not state["trusted"]:
            alert = vlog.append(trust_alert(run, state, bound))
            state["alert_id"] = alert["alert_id"]
            alerts.append(alert)
            log.warning("%s trust withdrawn for %s: %s", alert["alert_id"], hex_of(digest)[:12], alert["violated_clause"])
        elif not was_trusted and state["trusted"]:
            log.info("trust restored for %s", hex_of(digest)[:12])
        for r in state["advisories_reported"]:
            if r not in (prev.get("advisories_reported") or []):
                log.info("advisory %s for %s reported; it does not withdraw trust", r["advisory"], r["package"])
        atomic_write_json(state_path, state)
    return alerts


# --- the loop and the helpers -----------------------------------------------------------------------------

def _stamp(run: Path):
    paths = [run / "bindings.json", run / "keystatus.json", run / "builder_denylist.json"]
    paths += [Path(p) for pattern in ("advisories/*.json", "contexts/*.json", "envelopes/*.json")
              for p in glob.glob(str(run / pattern))]
    out = []
    for p in sorted(paths):
        try:
            st = p.stat()
            out.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return tuple(out)


def loop(run: str | Path, interval: float = 300, poll: float = 2, once: bool = False) -> int:
    run = Path(run)
    vlog = ViolationLog(run)
    written = len(cycle(run, vlog))
    if once:
        return written
    last, stamp = time.time(), _stamp(run)
    while True:
        time.sleep(poll)
        now_stamp = _stamp(run)
        if now_stamp != stamp or time.time() - last >= interval:
            written += len(cycle(run, vlog))
            last, stamp = time.time(), _stamp(run)


def set_key(run: str | Path, key: str, state: str, since: str | None) -> dict:
    run = Path(run)
    doc = load_json(run / "keystatus.json", {}) or {}
    keys = doc.setdefault("keys", {})
    kid = key_id_of(key)
    keys[kid] = {"state": state, "since": since or now_iso(), "key": str(key)}
    atomic_write_json(run / "keystatus.json", doc)
    return {kid: keys[kid]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.trust", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    k = sub.add_parser("key-id", help="print a public key's id")
    k.add_argument("--key", default=DEFAULT_KEY)
    s = sub.add_parser("set-key", help="record a key state change in keystatus.json (scenario trust-2)")
    s.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    s.add_argument("--key", default=DEFAULT_KEY)
    s.add_argument("--state", required=True, choices=["active", "rotated", "disabled", "revoked", "compromised"])
    s.add_argument("--since", help="when the change happened (ISO 8601; default now)")
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--interval", type=float, default=300, help="ΔR in seconds (default 300)")
    ap.add_argument("--poll", type=float, default=2, help="seconds between checks for changed inputs (default 2)")
    ap.add_argument("--once", action="store_true", help="evaluate once and exit")
    args = ap.parse_args(argv)
    if args.cmd == "key-id":
        print(key_id_of(args.key))
        return 0
    if args.cmd == "set-key":
        print(json.dumps(set_key(args.run, args.key, args.state, args.since)))
        return 0
    try:
        written = loop(args.run, args.interval, args.poll, args.once)
    except KeyboardInterrupt:
        written = None
    if args.once:
        print(json.dumps({"trust_alerts_written": written}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
