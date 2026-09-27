"""T10 and T13 step 6: the envelope's capabilities. Every entry is INFERRED.

With a trained ML-A model in ml/model/, the capabilities are Algorithm 1 (ml/alg1.py) over the
model's probabilities for this image's features, and each entry carries its probability as an
extra field (the contract allows extra fields; readers ignore them). Without a model, the
curated allowlist and the port rule decide. The ML libraries are imported only when a model
exists, so compiling without one needs nothing beyond the compiler's own requirements.

PROVBIND_CAPS_MODEL names another model directory; "none" always uses the allowlist (MLA-07
compiles both ways). A model that exists but cannot be used is bad input: the compiler never
falls back silently.

𝒞_K8s, the pod's allowed set (Eq. 34), is the `allowed` parameter. The compiler works per image
and cannot know the pod, so it passes None and caps nothing; who applies the cap is handoff §13
decision 4.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Iterable, Mapping

from . import purls
from .oci import BadInput

log = logging.getLogger("provbind.caps")

ALLOWLIST = Path(__file__).with_name("caps_allowlist.json")
MODEL_DIR = Path(__file__).resolve().parents[1] / "ml" / "model"
MODEL_FILE = "model.json"                        # ml.train.MODEL_FILE
MODEL_ENV = "PROVBIND_CAPS_MODEL"
NET_BIND_SERVICE = "CAP_NET_BIND_SERVICE"
PROBABILITY_DIGITS = 4


def load_allowlist(path: str | Path = ALLOWLIST) -> dict[tuple, list[str]]:
    """Package identity -> capabilities, from caps_allowlist.json ("_" keys are comments)."""
    out: dict[tuple, list[str]] = {}
    for key, caps in json.loads(Path(path).read_text(encoding="utf-8")).items():
        if key.startswith("_"):
            continue
        ident = purls.identity(key)
        if ident is None:
            log.warning("caps allowlist: %r is not a purl; ignored", key)
            continue
        out[ident] = list(caps)
    return out


def privileged_ports(exposed_ports: Iterable[str] | None) -> list[int]:
    """Ports below 1024 among the config's ExposedPorts keys, such as "80/tcp"."""
    ports = []
    for spec in exposed_ports or ():
        try:
            port = int(str(spec).split("/", 1)[0])
        except ValueError:
            log.warning("ExposedPorts entry %r is not a port; ignored", spec)
            continue
        if port < 1024:
            ports.append(port)
    return ports


def _bound(allowed: Iterable[str]) -> set[str]:
    from ml.alg1 import normalise                 # standard library only
    return {normalise(c) for c in allowed}


def capabilities(package_purls: Iterable[str], exposed_ports: Iterable[str] | None,
                 allowlist: Mapping[tuple, list[str]] | None = None,
                 allowed: Iterable[str] | None = None) -> list[dict]:
    """The allowlist's capabilities, sorted by name, one entry per capability, capped at
    `allowed` (𝒞_K8s) when it is given."""
    allow = load_allowlist() if allowlist is None else allowlist
    caps: set[str] = set()
    for purl in package_purls:
        caps.update(allow.get(purls.identity(purl), ()))
    if privileged_ports(exposed_ports):
        caps.add(NET_BIND_SERVICE)
    if allowed is not None:
        caps &= _bound(allowed)
    return [{"cap": c, "origin": "INFERRED"} for c in sorted(caps)]


# --- ML-A (handoff T13 step 6) -------------------------------------------------------------------

def model_dir() -> Path | None:
    """Where to look for the model: $PROVBIND_CAPS_MODEL, or ml/model/; None for "none"."""
    value = os.environ.get(MODEL_ENV, "").strip()
    if value.lower() == "none":
        return None
    return Path(value) if value else MODEL_DIR


def load_model(directory: str | Path | None):
    """The trained ml.train.CapabilityModel in `directory`, or None when it holds no model.json.
    Raises BadInput when the model is there but cannot be used."""
    if directory is None or not (Path(directory) / MODEL_FILE).is_file():
        log.info("caps: curated allowlist (no model%s)", "" if directory is None else f" in {directory}")
        return None
    try:
        from ml.train import CapabilityModel      # numpy and LightGBM: only when there is a model
    except ImportError as e:
        raise BadInput(f"the ML-A model in {directory} needs the ML libraries "
                       f"(pip install -r requirements.txt): {e}") from None
    try:
        model = CapabilityModel.load(directory)
    except Exception as e:                        # bad JSON, another features version, a broken booster
        raise BadInput(f"the ML-A model in {directory} cannot be used: {e}") from None
    log.info("caps: ML-A model in %s (%d labels, θ_C %.2f)", directory, len(model.labels), model.theta)
    return model


def image_features(packages: Mapping, config, closure: Iterable[str], fs, vocabulary: Iterable[str] = ()):
    """z_I for one image (ml.features.extract) with the default pod, since the compiler works per
    image. `fs` gives the closure binaries' imported symbols. With no vocabulary this is the row
    the training dataset stores (T13 step 3), so training and compilation see the same features."""
    from ml.features import closure_imports, extract
    closure = sorted(closure)
    return extract({"packages": packages, "closure": closure}, config,
                   imports=closure_imports(fs, closure), vocabulary=list(vocabulary))


def predicted(model, features: Mapping[str, float | None], allowed: Iterable[str] | None = None) -> list[dict]:
    """ML-A's capabilities: Algorithm 1 over the model's probabilities at its θ_C, nothing
    declared, capped at `allowed` when given. Each entry is INFERRED with its probability,
    rounded to 4 decimal places."""
    from ml.alg1 import infer
    return [{"cap": c.cap, "origin": c.origin, "probability": round(c.probability, PROBABILITY_DIGITS)}
            for c in infer(model.predict_proba(features), None if allowed is None else sorted(allowed),
                           theta=model.theta)]


def for_image(packages: Mapping, config, closure: Iterable[str], fs, model=None,
              allowed: Iterable[str] | None = None) -> list[dict]:
    """The envelope's `capabilities` for one image: ML-A when `model` is given (load_model),
    otherwise the allowlist and the port rule."""
    if model is None:
        return capabilities(packages, config.exposed_ports, allowed=allowed)
    return predicted(model, image_features(packages, config, closure, fs, model.vocabulary).as_dict(), allowed)
