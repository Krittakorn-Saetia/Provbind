#!/usr/bin/env bash
# Profile the ML-A corpus for capability labels (MLA-03, Test Plan §4.1-4.2). Runs on the demo PC.
#
# For each image in ml/corpus.yaml this:
#   1. pulls it, re-tags it into localhost:5001, signs and attests it with the team key (SBOM plus a
#      re-tag provenance from gen_provenance.py), then verifies all three with cosign.pub, so the
#      compiler can later read verified evidence for the feature side, joined by digest (§4.1);
#   2. runs it twice in a DEFAULT pod in namespace `demo` (no securityContext: ML-A's features assume
#      the default pod, and ml.dataset refuses a label row with a pod of its own), capturing Tetragon's
#      cap_capable events from before the container starts until RUN_SECONDS after it started (§4.2);
#   3. writes meta.json (image, digest, pod) beside the two captures, only when both runs succeeded.
# Then `python -m testbed.profiling.run` assembles ml/data/labels.jsonl.
#
# Errors are reported, never hidden: each image's tool output goes to $PROVBIND_RUN/profile-logs/,
# an image that fails any step is skipped and listed at the end, and the script exits 1 if any image
# failed. STRICT=1 stops at the first failure instead.
#
# Run it with Role 4's controller and alerts, and Role 3's node, STOPPED: profiling pods run in `demo`,
# which they watch, so they would bind, compile and raise detections for every corpus image.
#
# Prerequisites: `make up` (kind + registry, Tetragon with Role 3's node/tetragon/cap.yaml applied),
# pipeline/keys/cosign.key (from Korn, privately), and COSIGN_PASSWORD exported:
#     read -rsp 'cosign key password: ' COSIGN_PASSWORD && echo && export COSIGN_PASSWORD
# Tools: docker, kubectl, crane, cosign, syft, python3 (with PyYAML).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"
: "${NAMESPACE:=demo}"
: "${RAW:=ml/data/raw}"
: "${RUN_SECONDS:=120}"                         # §4.2: a 120 s run after the workload starts
: "${READY_TIMEOUT:=180}"
: "${HELPER_IMAGE:=curlimages/curl:8.10.1}"     # default workload client; corpus entries may set `helper`
: "${ATTEST:=1}"                                # 0 skips signing (labels only; the compiler will refuse such images)
: "${STRICT:=0}"
: "${TETRAGON_NAMESPACE:=kube-system}"
: "${TETRAGON_CONTAINER:=export-stdout}"        # VERIFY on the demo PC (Role 3 handoff §3)
REG="${PROVBIND_REGISTRY:-localhost:5001}"
KEY="${COSIGN_KEY:-pipeline/keys/cosign.key}"
PUB="${KEY%.key}.pub"
LOGS="$PROVBIND_RUN/profile-logs"
mkdir -p "$LOGS" "$RAW"

say() { echo "[profile] $*" >&2; }
die() { say "ERROR: $*"; exit 1; }

# Registry path and raw folder name: Role 2's §6.3 loop compiles localhost:5001/<slug>@<digest>.
slug() { echo "$1" | tr '/:@' '___'; }
# Kubernetes object names must be DNS-1123/1035 labels: lowercase letters, digits and '-'.
kname() { echo "$1" | tr 'A-Z' 'a-z' | sed -e 's/[^a-z0-9-]/-/g' -e 's/--*/-/g' | cut -c1-40 | sed -e 's/-$//'; }

# Signing flags exactly as pipeline/build-and-attest.sh builds them (offline mode, cosign v3).
SIGN_FLAGS=(); VERIFY_FLAGS=()
if [ "${PROVBIND_OFFLINE:-}" = "1" ]; then
  SIGN_FLAGS=(--tlog-upload=false); VERIFY_FLAGS=(--insecure-ignore-tlog=true)
  SIGN_HELP="$(cosign sign --help 2>&1 || true)"
  case "$SIGN_HELP" in
    *--use-signing-config*) SIGN_FLAGS=(--use-signing-config=false "${SIGN_FLAGS[@]}") ;;
  esac
  say "PROVBIND_OFFLINE=1: signing without Rekor"
fi

preflight() {
  local t
  for t in docker kubectl crane python3; do command -v "$t" >/dev/null || die "missing tool: $t"; done
  python3 -c 'import yaml' 2>/dev/null || die "python3 needs PyYAML (pip install -r requirements.txt)"
  if [ "$ATTEST" = "1" ]; then
    for t in cosign syft; do command -v "$t" >/dev/null || die "missing tool: $t"; done
    [ -f "$KEY" ] || die "$KEY is missing: get cosign.key from Korn privately (never commit it)"
    [ -f "$PUB" ] || die "$PUB is missing"
    [ -n "${COSIGN_PASSWORD:-}" ] || die "COSIGN_PASSWORD is not exported; without it cosign waits at a hidden prompt. Run: read -rsp 'cosign key password: ' COSIGN_PASSWORD && echo && export COSIGN_PASSWORD"
  else
    say "WARNING: ATTEST=0: images are not signed, so the compiler will refuse them and they cannot join D1"
  fi
  kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || die "namespace $NAMESPACE does not exist (run make up)"
  if ! kubectl get tracingpoliciesnamespaced -n "$NAMESPACE" -o name 2>/dev/null | grep -q .; then
    say "WARNING: no TracingPolicy in namespace $NAMESPACE; apply Role 3's node/tetragon/cap.yaml or no labels will be captured"
  fi
}

FAILED=()
WHY=""
REF=""

summary() {
  local ok="$1"
  say "done: $ok image(s) profiled, ${#FAILED[@]} failed"
  local f
  for f in ${FAILED[@]+"${FAILED[@]}"}; do say "  FAILED $f"; done
}

fail_image() {   # image reason
  FAILED+=("$1: $2 (log: $LOGS/$(slug "$1").log)")
  say "FAILED $1: $2"
  if [ "$STRICT" = "1" ]; then summary "$OK"; exit 1; fi
}

retag_and_attest() {   # image -> sets REF, or WHY and returns 1
  local image="$1" name log out digest
  name="$(slug "$image")"; log="$LOGS/$name.log"; out="$PROVBIND_RUN/attest/$name"
  docker pull "$image" >>"$log" 2>&1                          || { WHY="docker pull failed"; return 1; }
  docker tag "$image" "$REG/$name:latest" >>"$log" 2>&1       || { WHY="docker tag failed"; return 1; }
  docker push "$REG/$name:latest" >>"$log" 2>&1               || { WHY="docker push failed"; return 1; }
  digest="$(crane digest "$REG/$name:latest" 2>>"$log")"      || { WHY="crane digest failed"; return 1; }
  REF="$REG/$name@$digest"
  [ "$ATTEST" = "1" ] || return 0

  mkdir -p "$out"
  syft "docker:$REG/$name:latest" -o cyclonedx-json > "$out/sbom.json" 2>>"$log" || { WHY="syft failed"; return 1; }
  [ -s "$out/sbom.json" ]                                     || { WHY="syft wrote an empty SBOM"; return 1; }
  python3 pipeline/gen_provenance.py --subject "$REF" --commit "$(git rev-parse --short HEAD)" \
    --source "$image" > "$out/prov.json" 2>>"$log"            || { WHY="gen_provenance.py failed"; return 1; }
  [ -s "$out/prov.json" ]                                     || { WHY="gen_provenance.py wrote an empty provenance"; return 1; }
  cosign sign --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} "$REF" >>"$log" 2>&1 \
                                                              || { WHY="cosign sign failed"; return 1; }
  cosign attest --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} --type cyclonedx \
    --predicate "$out/sbom.json" "$REF" >>"$log" 2>&1         || { WHY="cosign attest (cyclonedx) failed"; return 1; }
  cosign attest --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} --type slsaprovenance1 \
    --predicate "$out/prov.json" "$REF" >>"$log" 2>&1         || { WHY="cosign attest (slsaprovenance1) failed"; return 1; }
  # Verify now, as the compiler will: a failure here would otherwise surface only as a compile exit 2.
  cosign verify --key "$PUB" ${VERIFY_FLAGS[@]+"${VERIFY_FLAGS[@]}"} "$REF" >>"$log" 2>&1 \
                                                              || { WHY="cosign verify failed after signing"; return 1; }
  local t
  for t in cyclonedx slsaprovenance1; do
    cosign verify-attestation --key "$PUB" ${VERIFY_FLAGS[@]+"${VERIFY_FLAGS[@]}"} --type "$t" "$REF" >>"$log" 2>&1 \
                                                              || { WHY="cosign verify-attestation ($t) failed"; return 1; }
  done
}

cleanup_pod() {   # pod svc
  kubectl delete pod "$1" -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  [ -n "$2" ] && kubectl delete svc "$2" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
}

profile_one_run() {   # image ref pod port env cmd helper workload run_no -> WHY on failure
  local image="$1" ref="$2" pod="$3" port="$4" env="$5" cmd="$6" helper="$7" workload="$8" n="$9"
  local name log dir raw cap_pid started svc="" args=() kv arg envs=() cmds=()
  name="$(slug "$image")"; log="$LOGS/$name.log"; dir="$RAW/$name"; raw="$dir/.raw$n.jsonl"
  [ -n "$port" ] && svc="$pod"
  cleanup_pod "$pod" "$svc"

  # Capture first, so the capabilities used while the container starts are in the label (§4.2).
  kubectl logs -n "$TETRAGON_NAMESPACE" ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 > "$raw" 2>>"$log" &
  cap_pid=$!
  sleep 3

  args=(run "$pod" -n "$NAMESPACE" --image="$ref" --restart=Never --labels=provbind-profile=1)
  if [ -n "$env" ]; then IFS=$'\x1e' read -r -a envs <<<"$env"; for kv in "${envs[@]}"; do args+=(--env "$kv"); done; fi
  if [ -n "$cmd" ]; then IFS=$'\x1e' read -r -a cmds <<<"$cmd"; args+=(--command --); for arg in "${cmds[@]}"; do args+=("$arg"); done; fi
  started=$(date +%s)
  if ! kubectl "${args[@]}" >>"$log" 2>&1; then
    kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true
    WHY="kubectl run failed (run $n)"; return 1
  fi
  if ! kubectl wait -n "$NAMESPACE" --for=condition=Ready "pod/$pod" --timeout="${READY_TIMEOUT}s" >>"$log" 2>&1; then
    kubectl describe pod "$pod" -n "$NAMESPACE" >>"$log" 2>&1 || true
    kubectl logs "$pod" -n "$NAMESPACE" --tail=50 >>"$log" 2>&1 || true
    kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true
    cleanup_pod "$pod" "$svc"
    WHY="pod never became Ready in a default pod (run $n); see the log, or drop it from the corpus and tell Korn"; return 1
  fi
  if [ -n "$svc" ] && ! kubectl expose pod "$pod" -n "$NAMESPACE" --name="$svc" --port="$port" --target-port="$port" >>"$log" 2>&1; then
    kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true
    cleanup_pod "$pod" "$svc"
    WHY="kubectl expose failed (run $n)"; return 1
  fi

  if [ -n "$workload" ]; then
    # A separate helper pod (its events are filtered out by pod name at assembly). stdin is closed so
    # it cannot swallow the corpus list this loop reads on fd 3.
    if ! kubectl run "wl-$pod-$n" -n "$NAMESPACE" --image="$helper" --restart=Never --rm -i --quiet \
         --command -- sh -c "${workload//\{host\}/$svc}" </dev/null >>"$log" 2>&1; then
      say "WARNING $image run $n: workload exited non-zero (labels may miss workload-driven capabilities; see the log)"
    fi
  fi

  local left=$(( started + RUN_SECONDS - $(date +%s) ))
  [ "$left" -gt 0 ] && sleep "$left"
  kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true
  cleanup_pod "$pod" "$svc"

  grep cap_capable "$raw" > "$dir/run$n.jsonl" || true
  rm -f "$raw"
  if [ ! -s "$dir/run$n.jsonl" ]; then
    WHY="no cap_capable events captured in namespace $NAMESPACE (run $n): is node/tetragon/cap.yaml applied, and is $TETRAGON_CONTAINER the export container?"
    return 1
  fi
}

preflight
OK=0
trap 'say "interrupted"; summary "$OK"; exit 130' INT TERM

# One line per corpus entry, fields separated by \x1f, lists by \x1e (never in the values).
while IFS=$'\x1f' read -r -u 3 image port env cmd helper workload; do
  name="$(slug "$image")"; pod="prof-$(kname "$image")"; : > "$LOGS/$name.log"
  mkdir -p "$RAW/$name"; rm -f "$RAW/$name/meta.json" "$RAW/$name"/run*.jsonl
  say "profiling $image (pod $pod)"
  if ! retag_and_attest "$image"; then fail_image "$image" "$WHY"; continue; fi
  good=1
  for n in 1 2; do
    if ! profile_one_run "$image" "$REF" "$pod" "$port" "$env" "$cmd" "${helper:-$HELPER_IMAGE}" "$workload" "$n"; then
      fail_image "$image" "$WHY"; good=0; break
    fi
  done
  [ "$good" = "1" ] || continue
  python3 - "$RAW/$name/meta.json" "$image" "${REF##*@}" "$pod" "$workload" <<'PY'
import json, sys
path, image, digest, pod, workload = sys.argv[1:]
json.dump({"image": image, "digest": digest, "pod": pod, "workload": workload}, open(path, "w"))
PY
  OK=$((OK + 1))
  say "ok $image ${REF##*@}"
done 3< <(python3 - <<'PY'
import yaml
for e in yaml.safe_load(open("ml/corpus.yaml")):
    env = "\x1e".join(f"{k}={v}" for k, v in (e.get("env") or {}).items())
    cmd = "\x1e".join(str(a) for a in (e.get("command") or []))
    fields = [e["image"], str(e.get("port") or ""), env, cmd, e.get("helper") or "", e.get("workload") or ""]
    print("\x1f".join(f.replace("\n", " ") for f in fields))
PY
)

summary "$OK"
python3 -m testbed.profiling.run --raw "$RAW" --out ml/data/labels.jsonl --namespace "$NAMESPACE" || true
[ "${#FAILED[@]}" -eq 0 ] || exit 1
