"""Run folders and Role 3-shaped detections for Role 4's tests, built on Role 2's golden envelope."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
BUNDLE = Path(__file__).with_name("fixtures") / "standin-sign-v1-bundle.json"
STANDIN_HEX = "0a6bfbb07745da4c50e29e159cf426b05ff4481540a9894c746e1190961944a3"
CID = "containerd://" + "4b1c" * 16
PY = "/usr/local/bin/python3.11"


def golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def write_run(tmp: Path, envelope: dict | None = None, *, binding: dict | None = None, cid: str = CID) -> Path:
    """A run folder with one envelope (envelopes/<hex>.json) and one binding for it."""
    run = Path(tmp) / "run"
    (run / "envelopes").mkdir(parents=True, exist_ok=True)
    env = envelope if envelope is not None else golden()
    digest = env["image"]["digest"]
    (run / "envelopes" / f"{digest.split(':')[1]}.json").write_text(json.dumps(env), encoding="utf-8")
    b = {"namespace": "demo", "pod": "demo-app-7d9f", "container": "app", "image_digest": digest, "verified": True,
         "run_as_root": True, "privileged": False, "mounts": ["/etc/hosts"], "envelope_ready": True}
    b.update(binding or {})
    (run / "bindings.json").write_text(json.dumps({cid: b}), encoding="utf-8")
    return run


def context_for(env: dict, path: str) -> dict:
    """The context Role 3's node gives a file: declared, package, depth, layer index."""
    f = (env.get("files") or {}).get(path)
    if f is None:
        return {"declared": False, "package": None, "depth": None, "layer": None}
    pkg = f.get("package")
    return {"declared": True, "package": pkg,
            "depth": (env.get("packages") or {}).get(pkg, {}).get("depth") if pkg else None, "layer": f.get("layer")}


def detection(env: dict, n: int, cls: str, sub: str, path: str, *, exe: str | None = None, pid: int = 4471,
              ppid: int = 4402, time: str = "2026-09-29T10:05:00.000Z", origin: str = "AUTHENTICATED",
              kind: str = "file_set", detail: str = "path is in no layer of the attested image",
              context: dict | None = None, cid: str = CID) -> dict:
    return {"id": f"det-{n:04d}", "time": time, "container_id": cid, "namespace": "demo", "pod": "demo-app-7d9f",
            "container": "app", "image_digest": env["image"]["digest"], "pid": pid, "ppid": ppid,
            "exe": exe or path, "parent_exe": PY, "class": cls, "subclass": sub,
            "clause": {"kind": kind, "path": path, "detail": detail}, "origin": origin,
            "context": context if context is not None else context_for(env, path)}


def attack_and_benign(env: dict) -> list[dict]:
    """benign-1's two weak execs, then attack-1's undeclared exec and its write, as Role 3 emits them."""
    return [
        detection(env, 1, "D_exec", "outside_closure", "/usr/bin/dash", pid=900, ppid=880,
                  time="2026-09-29T10:00:00.000Z", kind="closure", detail="declared in layer 0, but not reachable"),
        detection(env, 2, "D_exec", "outside_closure", "/usr/bin/ls", pid=901, ppid=900,
                  time="2026-09-29T10:00:00.050Z", kind="closure", detail="declared in layer 0, but not reachable"),
        detection(env, 3, "D_exec", "undeclared", "/tmp/.x9", time="2026-09-29T10:05:00.000Z"),
        detection(env, 4, "D_write", "declared_file", "/etc/passwd", exe="/tmp/.x9", time="2026-09-29T10:05:00.020Z",
                  detail="write to a file declared in layer 0; not under a mount"),
    ]


def write_detections(run: Path, dets: list[dict], mode: str = "a") -> None:
    with open(run / "detections.jsonl", mode, encoding="utf-8") as f:
        for d in dets:
            f.write(json.dumps(d) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
