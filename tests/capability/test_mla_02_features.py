"""MLA-02: the feature extractor Ω_I is deterministic (Eq. 32), and every feature is named in
ml/features.md (Test Plan §3.4).

z_I is extracted from the same envelope in this process and in six fresh Python processes with
fixed hash seeds 0-5, each from the inputs as given and from a copy with every dict and list
reordered. Fixed seeds make a dependence on set iteration order show up the same way on every
run, not by chance. Pass: all thirteen vectors are identical, and every feature is documented.

The envelope is PROVBIND_ENVELOPE when set (with PROVBIND_IMAGE_CONFIG, the image's config
JSON, if given), otherwise the synthetic golden envelope. Determinism is a property of the
extractor, so the result counts either way; the notes say which envelope was used.
"""
import json
import math
import os
import subprocess
import sys
from pathlib import Path

from ml.features import extract, package_ids
from tests.ml.features_doc import documented_names, undocumented

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
DEFAULT_CONFIG = {"User": "", "ExposedPorts": {"8080/tcp": {}}, "Env": ["PATH=/usr/local/bin:/usr/bin"]}

CHILD = """
import json, sys
from ml.features import extract
a = json.load(open(sys.argv[1]))
print(json.dumps([extract(a[e], a["config"], imports=a[i], vocabulary=a["vocabulary"]).to_json()
                  for e, i in (("envelope", "imports"), ("reordered", "reordered_imports"))]))
"""
SEEDS = ("0", "1", "2", "3", "4", "5")


def _inputs():
    path = os.environ.get("PROVBIND_ENVELOPE")
    source = path or str(GOLDEN.relative_to(ROOT))
    envelope = json.loads(Path(path or GOLDEN).read_text())
    config_path = os.environ.get("PROVBIND_IMAGE_CONFIG")
    config = json.loads(Path(config_path).read_text()) if config_path else DEFAULT_CONFIG
    return envelope, config, source


def _same(a: dict, b: dict) -> bool:
    return a.keys() == b.keys() and all(
        (x is None and y is None) or (x is not None and y is not None and (x == y or (math.isnan(x) and math.isnan(y))))
        for x, y in ((a[k], b[k]) for k in a))


def test_mla_02_extractor_is_deterministic(record_result, tmp_path):
    envelope, config, source = _inputs()
    closure = sorted(envelope.get("closure") or [])
    imports = {p: ["socket", "connect"] for p in closure[:1]}          # exercises the imp.* features
    vocabulary = sorted(package_ids(envelope))[:100]

    first = extract(envelope, config, imports=imports, vocabulary=vocabulary)

    reordered = dict(reversed(list(envelope.items())))
    reordered["packages"] = dict(reversed(list((envelope.get("packages") or {}).items())))
    reordered["closure"] = list(reversed(envelope.get("closure") or []))
    args = tmp_path / "inputs.json"
    args.write_text(json.dumps({"envelope": envelope, "reordered": reordered, "config": config,
                                "imports": imports,
                                "reordered_imports": {p: list(reversed(s)) for p, s in reversed(list(imports.items()))},
                                "vocabulary": vocabulary}))
    vectors, errors = [first.to_json()], []
    for seed in SEEDS:
        child = subprocess.run([sys.executable, "-c", CHILD, str(args)], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONHASHSEED": seed}, timeout=120)
        if child.returncode:
            errors.append(f"seed {seed}: {child.stderr.strip()[-200:]}")
        else:
            vectors += json.loads(child.stdout)

    identical = not errors and all(_same(vectors[0], v) for v in vectors[1:])
    missing = undocumented(first.names, documented_names())
    ok = identical and not missing
    notes = (f"envelope: {source}; {len(vectors)} extractions: this process, and hash seeds 0-5 "
             "each on the inputs as given and reordered")
    if not identical:
        notes += "; vectors differ" + (f"; {' | '.join(errors)}" if errors else "")
    if missing:
        notes += "; not in ml/features.md: " + ", ".join(missing)
    record_result("MLA-02", "pass" if ok else "fail",
                  metrics={"features": len(first.names), "vocabulary": len(vocabulary), "extractions": len(vectors),
                           "identical": identical, "undocumented": len(missing)},
                  notes=notes)
    assert ok, notes
