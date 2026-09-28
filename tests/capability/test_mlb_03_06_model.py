"""MLB-03 to MLB-06: the per-image model and what it catches (Test Plan §3.7 and §5).

Evidence, first found wins:
1. **Demo PC.** D2 in PROVBIND_MLB_DATA (default ml/data/mlb/): one folder per image digest (64
   hex) with train.jsonl, validation.jsonl and heldout.jsonl, built with `python -m node.mlb`
   (ml/data/mlb/README.md). The demo image is PROVBIND_MLB_DIGEST, or the only folder. MLB-05
   also needs PROVBIND_RECORDING, the run folder and a ground truth with an attack-2 row, as the
   PH4 tests do.
2. **Otherwise** synthetic D2 (four hours of synthetic benign load, an hour held out an hour
   later) and the synthetic scenario library. The checks run, and the result is not_run.

The tests:
- **MLB-03 (P0).** The model trains as in Eq. (49) and is stored beside the envelope with θ_A and
  g_I. On the demo PC it is written to $PROVBIND_RUN/envelopes/<hex>.mlb/model.json, where
  `node.run --mlb` uses it. A synthetic model goes to a temporary folder, never the run folder.
- **MLB-04 (P0).** The window false-positive rate on held-out benign windows is at most 1%.
- **MLB-05 (P0).** attack-2 gives at least one D_beh and no deterministic detection.
- **MLB-06 (P1).** A per-image model against a global model (C5), on 3 or more images.

MLB-04 and MLB-05 report the forest alone next to the forest with the range guard
(node/mlb.py), since Test Plan §0 rule 1 asks for a proposed fix to be run side by side. The
status is the model as it decides, guard included.
"""
from __future__ import annotations

import copy
import functools
import os
from pathlib import Path

import pytest

pytest.importorskip("numpy")          # training needs requirements.txt; skip cleanly without it,
pytest.importorskip("sklearn")        # as MLA-04/05 do (the report then shows these as not_run)

from node.mlb import (Behaviour, Model, compare_global, evaluate, model_path, read_windows, split, train,  # noqa: E402
                      write_model)
from node.scenarios import Row, read_ground_truth, replay, rows_of  # noqa: E402
from node.store import Store  # noqa: E402
from node.synth import DIGEST, benign_session, library  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
SYNTHETIC_NOTE = "; synthetic D2 and library, so not a project result: build ml/data/mlb/<hex>/ on the demo PC"


def synthetic_windows(lines, digest=DIGEST) -> list:
    lib = library()
    out = []
    replay(lines, Store.static([lib.envelope], lib.bindings), behaviour=Behaviour(on_window=out.append),
           keep=lambda e: False)
    for w in out:
        w["digest"] = digest
    return out


@functools.lru_cache(maxsize=1)
def d2() -> dict:
    root = Path(os.environ.get("PROVBIND_MLB_DATA", ROOT / "ml" / "data" / "mlb"))
    folders = sorted(p for p in root.glob("*") if p.is_dir() and (p / "train.jsonl").is_file()) if root.is_dir() else []
    if folders:
        data = {f"sha256:{p.name}": (read_windows(p / "train.jsonl"), read_windows(p / "validation.jsonl"),
                                     read_windows(p / "heldout.jsonl") if (p / "heldout.jsonl").is_file() else [])
                for p in folders}
        return {"real": True, "source": str(root), "data": data}
    train_w, validation_w = split(synthetic_windows(benign_session(4 * 3600, seed=0)))
    heldout = synthetic_windows(benign_session(3600, seed=100, start="2026-09-28T16:00:00Z"))
    return {"real": False, "source": "synthetic D2 (node/synth.py benign_session)",
            "data": {DIGEST: (train_w, validation_w, heldout)}}


def demo_digest(ev) -> str | None:
    given = os.environ.get("PROVBIND_MLB_DIGEST")
    if given:
        return given if given.startswith("sha256:") else "sha256:" + given
    return next(iter(ev["data"])) if len(ev["data"]) == 1 else None


@functools.lru_cache(maxsize=1)
def model_doc() -> dict | None:
    ev = d2()
    digest = demo_digest(ev)
    if digest is None or digest not in ev["data"]:
        return None
    tr, va, _ = ev["data"][digest]
    return train(tr, va, digest)


def status(ok: bool, real: bool) -> str:
    return ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")


def no_model(record_result, test_id):
    ev = d2()
    record_result(test_id, "not_run", notes=f"{ev['source']}: {len(ev['data'])} images in D2 and no "
                                            "PROVBIND_MLB_DIGEST to say which is the demo image")


def test_mlb_03_per_image_model_is_stored_beside_the_envelope(record_result, tmp_path):
    ev, doc = d2(), model_doc()
    if doc is None:
        return no_model(record_result, "MLB-03")
    digest = doc["digest"]
    target = RUN if ev["real"] else tmp_path
    path = write_model(target, doc)
    stored = Model.load(path)
    n_train, n_val = doc["windows"]["train"], doc["windows"]["validation"]
    ok = (path == model_path(target, digest) and stored.theta == doc["theta_a"]
          and len(stored.validation) == n_val and stored.guard_factor == 2.0)
    notes = (f"{ev['source']}: IF_I on {n_train} training windows; θ_A {doc['theta_a']:.4f} at the "
             f"{doc['percentile']}th percentile of {n_val} validation windows; g_I = their {n_val} scores; "
             f"stored at {path}")
    if doc["percentile_note"]:
        notes += f"; {doc['percentile_note']}"
    if n_train + n_val < 360:
        notes += f"; {n_train + n_val} windows, fewer than the 360 Test Plan §12.2 asks for"
    if ev["real"] and not (RUN / "envelopes" / f"{digest[7:]}.json").is_file():
        notes += "; the envelope itself is not in this run folder"
    if not ev["real"]:
        notes += SYNTHETIC_NOTE
    record_result("MLB-03", status(ok, ev["real"]),
                  metrics={"train_windows": n_train, "validation_windows": n_val, "theta_a": doc["theta_a"],
                           "percentile": doc["percentile"], "guard_factor": 2.0},
                  notes=notes, artifacts=[str(path)] if ev["real"] else [])
    assert ok, notes


def test_mlb_04_heldout_false_positive_rate(record_result):
    ev, doc = d2(), model_doc()
    if doc is None:
        return no_model(record_result, "MLB-04")
    heldout = ev["data"][doc["digest"]][2]
    if not heldout:
        record_result("MLB-04", "not_run", notes=f"{ev['source']}: no heldout.jsonl for {doc['digest']}")
        return
    r = evaluate(Model(doc), heldout)
    ok = r["fpr"] <= 0.01
    notes = (f"{ev['source']}: {r['windows']} held-out windows, FPR {r['fpr']:.4f} ({r['false_positives']}); "
             f"the forest alone {r['forest_fpr']:.4f}; the range guard added {r['guard_false_positives']}")
    if r["windows"] < 120:
        notes += f"; fewer than the ~120 windows of an hour-long run"
    if not ev["real"]:
        notes += SYNTHETIC_NOTE
    record_result("MLB-04", status(ok, ev["real"]), metrics=r, notes=notes)
    assert status(ok, ev["real"]) != "fail", notes


def attack_evidence():
    """(lines, store factory, rows, source, real) for attack-2."""
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        gt = os.environ.get("PROVBIND_GROUND_TRUTH") or RUN / "ground_truth.csv"
        rows = read_ground_truth(gt) if Path(gt).is_file() else []

        def store():
            s = Store(RUN)
            s.refresh()
            return s
        return Path(rec).read_text(encoding="utf-8", errors="replace").splitlines(), store, rows, rec, True
    lib = library()
    return lib.lines, lambda: Store.static([lib.envelope], lib.bindings), [Row.of(r) for r in lib.ground_truth], \
        "synthetic library", False


def test_mlb_05_in_envelope_attack_is_flagged(record_result):
    ev, doc = d2(), model_doc()
    if doc is None:
        return no_model(record_result, "MLB-05")
    lines, store, rows, source, real = attack_evidence()
    attack = rows_of(rows, "attack-2")
    if not attack:
        record_result("MLB-05", "not_run", notes=f"{source}: no attack-2 row in the ground truth")
        return
    forest_only = copy.deepcopy(doc)
    forest_only["guard"] = None
    found = {}
    for name, d in (("model", doc), ("forest_alone", forest_only)):
        m = Model(d)
        r = replay(lines, store(), behaviour=Behaviour(model_for=lambda digest, m=m: m if digest == d["digest"] else None))
        per_row = [r.within(row)[1] for row in attack]
        found[name] = {"d_beh": [sum(1 for x in dets if x["class"] == "D_beh") for dets in per_row],
                       "deterministic": [sum(1 for x in dets if x["class"] != "D_beh") for dets in per_row]}
    ok = all(found["model"]["d_beh"]) and not any(found["model"]["deterministic"])
    notes = (f"{source} with {'the demo PC' if ev['real'] else 'synthetic'} D2: D_beh per attack-2 run "
             f"{found['model']['d_beh']} (the forest alone {found['forest_alone']['d_beh']}); deterministic "
             f"detections {found['model']['deterministic']}")
    if not (real and ev["real"]):
        notes += SYNTHETIC_NOTE
    record_result("MLB-05", status(ok, real and ev["real"]), metrics=found, notes=notes)
    assert status(ok, real and ev["real"]) != "fail", notes


def synthetic_images() -> dict:
    """Three synthetic images: the demo app, a busier one and a quieter one."""
    out = {}
    for digest, seed, rate in ((DIGEST, 0, 0.2), ("sha256:" + "aa" * 32, 3, 0.5), ("sha256:" + "bb" * 32, 4, 0.08)):
        tr, va = split(synthetic_windows(benign_session(4 * 3600, seed=seed, rate=rate), digest))
        held = synthetic_windows(benign_session(3600, seed=seed + 100, rate=rate, start="2026-09-28T16:00:00Z"),
                                 digest)
        out[digest] = (tr, va, held)
    return out


def test_mlb_06_per_image_against_a_global_model(record_result):
    ev = d2()
    data = ev["data"] if ev["real"] else synthetic_images()
    usable = {d: v for d, v in data.items() if v[2]}
    if len(usable) < 3:
        record_result("MLB-06", "not_run",
                      notes=f"{ev['source']}: {len(usable)} images with held-out windows; MLB-06 needs 3")
        return
    lines, store, rows, source, real = attack_evidence()
    windows = []
    replay(lines, store(), behaviour=Behaviour(on_window=windows.append), keep=lambda e: False)
    attack = [w for w in windows if any(r.holds({"namespace": r.namespace, "pod": w["pod"], "time": w["end"]})
                                        and w["pod"].startswith(r.pod_prefix) for r in rows_of(rows, "attack-2"))]
    r = compare_global(usable, attack)
    per = {d[7:19]: (r["per_image"][d]["fpr"], r["global"][d]["fpr"]) for d in r["images"]}
    notes = (f"{ev['source']}: held-out FPR per image, per-image against global: {per}")
    if "attack" in r:
        notes += (f"; attack-2 windows flagged: per-image {r['attack']['per_image']['anomalous']}, global "
                  f"{r['attack']['global']['anomalous']} of {r['attack']['windows']}")
    if not ev["real"]:
        notes += SYNTHETIC_NOTE
    record_result("MLB-06", "pass" if ev["real"] else "not_run", metrics=r, notes=notes)
