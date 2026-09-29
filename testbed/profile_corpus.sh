#!/usr/bin/env bash
# Profile the ML-A corpus for capability labels (MLA-03, Test Plan §4.1-4.2). Runs on the demo PC.
#
# For each image in ml/corpus.yaml this:
#   1. pulls it, re-tags into localhost:5001 and (ATTEST=1) attests it, so the compiler can later
#      read verified evidence for the feature side, joined by digest (§4.1);
#   2. deploys it by digest in namespace `demo`, twice, and for each run captures `cap_capable`
#      events for 120 s while the workload runs, saving raw Tetragon JSON;
#   3. writes meta.json (image + digest) beside the two runs.
# Then `python -m testbed.profiling.run` assembles ml/data/labels.jsonl.
#
# Prerequisites: kind + registry (testbed/kind-with-registry.sh), Tetragon with Role 3's
# cap_capable TracingPolicy applied, cosign key at pipeline/keys/cosign.key, syft, crane, jq.
# Several values are marked VERIFY: check them against the demo PC (testbed/VERSIONS.md).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"
: "${NAMESPACE:=demo}"
: "${RAW:=ml/data/raw}"
: "${RUN_SECONDS:=120}"                 # §4.2: a 120 s run
: "${HELPER_IMAGE:=curlimages/curl:8.10.1}"   # DB workloads need a richer client image (e.g. netshoot)
: "${ATTEST:=1}"
: "${TETRAGON_CONTAINER:=export-stdout}"      # VERIFY: `kubectl logs -n kube-system ds/tetragon -c ...`
REG=localhost:5001

slug() { echo "$1" | tr '/:@' '___'; }

retag_and_attest() {   # image -> prints ref@digest in the local registry
  local image="$1" name ref digest out
  name="$(slug "$image")"
  docker pull -q "$image" >/dev/null
  docker tag "$image" "$REG/$name:latest"
  docker push -q "$REG/$name:latest" >/dev/null
  digest="$(crane digest --insecure "$REG/$name:latest")"
  ref="$REG/$name@$digest"
  if [ "$ATTEST" = "1" ]; then
    out="$PROVBIND_RUN/attest/$name"; mkdir -p "$out"
    syft "docker:$REG/$name:latest" -o cyclonedx-json > "$out/sbom.json" 2>/dev/null || true
    python3 pipeline/gen_provenance.py --subject "$ref" --commit "$(git rev-parse --short HEAD)" \
      > "$out/prov.json" 2>/dev/null || true
    local K="--yes --key pipeline/keys/cosign.key --allow-insecure-registry"
    cosign sign   $K "$ref"                                                   2>>"$out/cosign.log" || true
    cosign attest $K --type cyclonedx       --predicate "$out/sbom.json" "$ref" 2>>"$out/cosign.log" || true
    cosign attest $K --type slsaprovenance1 --predicate "$out/prov.json" "$ref" 2>>"$out/cosign.log" || true
  fi
  echo "$ref"
}

profile_one_run() {   # name ref workload run_no
  local name="$1" ref="$2" workload="$3" run_no="$4" pod="prof-$1" host="prof-$1"
  local dir="$RAW/$name"; mkdir -p "$dir"
  kubectl run "$pod" -n "$NAMESPACE" --image="$ref" --restart=Never \
    --labels="provbind-profile=1" >/dev/null 2>&1 || true
  kubectl wait -n "$NAMESPACE" --for=condition=Ready "pod/$pod" --timeout=90s >/dev/null 2>&1 || true
  kubectl expose pod "$pod" -n "$NAMESPACE" --name="$host" --port=80 >/dev/null 2>&1 || true

  # Capture cap_capable events for this namespace while the workload runs.
  kubectl logs -n kube-system "ds/tetragon" -c "$TETRAGON_CONTAINER" -f --tail=0 \
    | grep --line-buffered cap_capable > "$dir/run${run_no}.jsonl" &
  local cap_pid=$!
  if [ -n "$workload" ]; then
    kubectl run "wl-$name-$run_no" -n "$NAMESPACE" --image="$HELPER_IMAGE" --restart=Never --rm -i \
      --command -- sh -c "${workload//\{host\}/$host}" >/dev/null 2>&1 || true
  fi
  sleep "$RUN_SECONDS"
  kill "$cap_pid" 2>/dev/null || true
  kubectl delete pod "$pod" -n "$NAMESPACE" --now >/dev/null 2>&1 || true
  kubectl delete svc "$host" -n "$NAMESPACE" >/dev/null 2>&1 || true
}

# Emit "image<TAB>workload" per corpus entry (skip our own already-attested images if missing).
python3 - "$@" <<'PY' | while IFS=$'\t' read -r image workload; do
import sys, yaml
for e in yaml.safe_load(open("ml/corpus.yaml")):
    print(f"{e['image']}\t{e.get('workload','')}")
PY
  name="$(slug "$image")"
  echo ">> profiling $image" >&2
  ref="$(retag_and_attest "$image")" || { echo "  skip $image (attest failed)" >&2; continue; }
  digest="${ref##*@}"
  mkdir -p "$RAW/$name"
  printf '{"image": "%s", "digest": "%s"}\n' "$image" "$digest" > "$RAW/$name/meta.json"
  profile_one_run "$name" "$ref" "$workload" 1
  profile_one_run "$name" "$ref" "$workload" 2
done

python3 -m testbed.profiling.run --raw "$RAW" --out ml/data/labels.jsonl --namespace "$NAMESPACE"
