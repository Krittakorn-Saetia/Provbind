#!/usr/bin/env bash
# The live demo for an audience (docs/LIVE-DEMO.md): six short acts, each paused so the presenter can
# talk, while a second screen shows the alerts as they arrive:
#     python3 -m eval.demo_view --run "$PROVBIND_RUN" --follow
#
#   scripts/live-demo.sh check     is everything ready? (reads only)
#   scripts/live-demo.sh prep      fresh run folder, sensor policies, PROVBIND's services, the unsigned image
#   scripts/live-demo.sh run       the six acts, Enter between them (AUTO=1 runs straight through)
#   scripts/live-demo.sh act N     one act again (1-6), for example after a hiccup
#   scripts/live-demo.sh reset     undo the acts (advisory, log edit, test deployment); services keep running
#   scripts/live-demo.sh stop      stop PROVBIND's services
#
# On the demo PC after `make up` and `make demo-app`, with DEMO_REF=<the ref@digest make demo-app printed>.
#   1. the signed demo app is deployed by digest: verified at admission, envelope compiled in seconds
#   2. an operator opens a shell in it: PROVBIND logs it (Low, not an alert); Falco raises an alert
#   3. the compromised dependency (requestz-helper) drops and runs a program that edits /etc/passwd
#   4. a malicious-package advisory names requestz-helper while it runs: a trust alert, behaviour unchanged
#   5. an unsigned copy of the image is deployed: it fails verification (prep builds it)
#   6. the violation log verifies; one character changes; verification fails at that record
# SKIP="2 5" leaves acts out. DRY_RUN=1 prints the commands instead of running them (no cluster needed).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run-demo}"; export PROVBIND_RUN
: "${NAMESPACE:=demo}"; export NAMESPACE
: "${DEPLOY:=demo-app}"; export DEPLOY
: "${POD_PREFIX:=demo-app}"; export POD_PREFIX
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${PROVBIND_REGISTRY:=localhost:5001}"; export PROVBIND_REGISTRY
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICY_SET:=opt}"        # opt = the rate-limited policies of the final runs (node/tetragon/opt/); orig = node/tetragon/
: "${EVENT_SOURCE:=kubectl}"  # kubectl = kubectl logs; file = Tetragon's export file in the kind node (docker exec)
: "${KIND_NODE:=kind-control-plane}"
: "${TETRAGON_LOG:=/var/run/cilium/tetragon/tetragon.log}"
: "${EGRESS:=testbed/egress.json}"
: "${WAIT_S:=90}"
: "${AUTO:=0}"
: "${DRY_RUN:=0}"
: "${SKIP:=}"
: "${DEMO_REF:=}"
UNSIGNED=demo-app-unsigned
source testbed/scenarios/deploy_lib.sh        # now(), app_curl, deploy_temp, teardown_temp (and lib.sh)

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'
else B=; D=; G=; R=; Y=; N=; fi

# --- small helpers -------------------------------------------------------------------------------
x() {                      # run a command, or print it in a dry run
  if [ "$DRY_RUN" = 1 ]; then printf '%s  + %s%s\n' "$D" "$*" "$N"; return 0; fi
  "$@"
}
xs() {                     # the same for a shell pipeline written as one string
  if [ "$DRY_RUN" = 1 ]; then printf '%s  + %s%s\n' "$D" "$1" "$N"; return 0; fi
  bash -c "$1"
}
py() { python3 -m eval.live_demo "$@" --run "$PROVBIND_RUN"; }
sleep_s() { [ "$DRY_RUN" = 1 ] || sleep "$1"; }
act_header() { echo; echo "${B}=== ACT $1  ·  $2${N}"; }
tell() { local line; for line in "$@"; do printf '    %s\n' "$line"; done; }
watch_for() { printf '    %swatch:%s %s\n' "$Y" "$N" "$*"; }
ok() { printf '    %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '    %s!%s %s\n' "$R" "$N" "$*"; }
result() { local line; while IFS= read -r line; do printf '      %s\n' "$line"; done; }
skipped() { case " $SKIP " in *" $1 "*) return 0 ;; esac; return 1; }
need_ref() { [ -n "${DEMO_REF:-}" ] || { echo "set DEMO_REF to the ref@digest that make demo-app printed" >&2; exit 2; }; }

pause() {                  # wait for the presenter (not in AUTO or without a terminal)
  [ "$AUTO" = 1 ] && return 0
  [ -t 0 ] || return 0
  read -r -p "    ${D}[Enter] ${1:-go}${N} " _ || true
}

wait_until() {             # SECONDS WHAT -- COMMAND...: poll COMMAND (twice a second) until it succeeds
  local secs=$1 what=$2 spin="|/-\\" i=0 deadline
  shift 3
  if [ "$DRY_RUN" = 1 ]; then printf '%s  (waits up to %s s for %s)%s\n' "$D" "$secs" "$what" "$N"; return 0; fi
  deadline=$(( $(date +%s) + secs ))
  while ! "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then printf '\r%60s\r' ''; warn "no $what after ${secs} s"; return 1; fi
    printf '\r    %s waiting for %s ' "${spin:i++%4:1}" "$what"
    sleep 0.5
  done
  printf '\r%60s\r' ''
}

more_than() { local n=$1; shift; [ "$(py count "$@")" -gt "$n" ]; }   # N COUNT-ARGS...
envelope_ready() { [[ "$(py envelope)" == *"envelope compiled"* ]]; }
has_binding() { [[ "$(py binding --pod-prefix "$1")" != "no binding yet"* ]]; }
attack_seen() { more_than "$1" --cls D_exec --sub undeclared && more_than "$2" --cls D_write; }

service_alive() {          # NAME: is that background service of prep still running?
  local name pid
  [ -f "$PROVBIND_RUN/demo.pids" ] || return 1
  while read -r name pid; do [ "$name" = "$1" ] && kill -0 "$pid" 2>/dev/null && return 0; done < "$PROVBIND_RUN/demo.pids"
  return 1
}

PROBE_PID=""
cleanup() { [ -z "$PROBE_PID" ] || kill "$PROBE_PID" 2>/dev/null || true; stop_port_forward; }
trap cleanup EXIT
curl_app() { app_curl "$1"; trap cleanup EXIT; }    # lib.sh's port-forward sets its own EXIT trap

probe_start() {            # does the sensor see the app's own process? (about 30 s, raises no alert)
  if [ "$DRY_RUN" = 1 ]; then x scripts/probe-events.sh; return 0; fi
  scripts/probe-events.sh > "$PROVBIND_RUN/logs/probe.log" 2>&1 & PROBE_PID=$!
  tell "${D}(checking in the background that the sensor sees the app: about 30 s, no alerts)${N}"
}
probe_result() {
  [ -n "$PROBE_PID" ] || return 0
  if wait "$PROBE_PID"; then ok "the sensor sees the app's own process"
  else
    warn "the sensor does NOT see the app: run 'kubectl -n $NAMESPACE rollout restart deploy/$DEPLOY',"
    warn "then 'scripts/live-demo.sh act 1' again ($PROVBIND_RUN/logs/probe.log has the counts)"
  fi
  PROBE_PID=""
}

# --- the six acts ----------------------------------------------------------------------------------
act1() {
  act_header 1 "A signed image arrives: verified, then compiled into its envelope"
  tell "We deploy the demo app by its digest. PROVBIND checks the signature, the SBOM and the build" \
       "provenance, then compiles them into the envelope: every file, layer, package and program the" \
       "signed evidence allows. No training and no observation period."
  watch_for "this terminal: the admission checks, then the envelope, compiled in a few seconds"
  pause "deploy"
  xs "kubectl -n '$NAMESPACE' create deployment '$DEPLOY' --image='$DEMO_REF' --port=8080 --dry-run=client -o yaml | kubectl apply -f - >/dev/null"
  x kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout="${WAIT_S}s"
  if ! wait_until "$WAIT_S" "the envelope" -- envelope_ready; then
    warn "no envelope: see $PROVBIND_RUN/logs/controller.log, then run 'scripts/live-demo.sh act 1' again"
    return 1
  fi
  py envelope | result
  probe_start
}

act2() {
  act_header 2 "An operator opens a shell in the running container"
  tell "Legitimate, but unusual: someone on the team runs 'ls /' inside the container." \
       "A learned detector has never seen it; a rule-based monitor has a rule for it."
  watch_for "alert screen: dim lines only, logged but NOT alerts (sh and ls are in the signed image)"
  probe_result
  pause "open the shell"
  local falco_mark low_before alerts_before tty=-i
  [ -t 0 ] && tty=-it                     # Falco's shell rule needs a terminal
  falco_mark=$(py lines); low_before=$(py count --low); alerts_before=$(py count --alerts)
  x kubectl exec "$tty" -n "$NAMESPACE" "deploy/$DEPLOY" -- sh -c 'ls /; cat /etc/hostname' || true
  wait_until 30 "the Low record" -- more_than "$low_before" --low || true
  sleep_s 5                               # Falco's output trails by a few seconds
  ok "PROVBIND: $(( $(py count --alerts) - alerts_before )) new alerts; the shell was logged as Low, not raised"
  if [ "$DRY_RUN" = 1 ] || service_alive falco; then py falco --since "$falco_mark" | result
  else tell "${D}(Falco is not running in this demo)${N}"; fi
}

act3() {
  act_header 3 "The compromised dependency strikes"
  tell "requestz-helper is a dependency of the app: signed, listed in the SBOM, admitted." \
       "One request makes it drop a program in /tmp, run it, and append a line to /etc/passwd."
  watch_for "alert screen: CRITICAL (a program in no layer of the signed image) and HIGH (a signed"
  watch_for "file changed) in one incident; the /etc/passwd card names the image layer it came from"
  pause "send the request"
  local ex_before wr_before falco_mark
  ex_before=$(py count --cls D_exec --sub undeclared); wr_before=$(py count --cls D_write); falco_mark=$(py lines)
  x curl_app /update
  wait_until "$WAIT_S" "the attack alerts" -- attack_seen "$ex_before" "$wr_before" || true
  py incident | result
  sleep_s 3
  if [ "$DRY_RUN" = 1 ] || service_alive falco; then
    py falco --since "$falco_mark" | result
    tell "${D}(Falco names the process and the file, but not the package or layer they came from)${N}"
  fi
}

act4() {
  act_header 4 "Later: an advisory names that dependency, while the app is running"
  tell "Nothing in the container changes. A malicious-package advisory (OSV format, a MAL- id)" \
       "is published for requestz-helper 0.1.0. PROVBIND's trust loop re-checks the running image."
  watch_for "alert screen: TRUST withdrawn within about 2 s, while the pod still behaves as signed"
  pause "publish the advisory"
  local before
  before=$(py count --cls trust)
  xs "TRUST_SETTLE=0 bash testbed/scenarios/trust.sh >/dev/null"
  wait_until 30 "the trust alert" -- more_than "$before" --cls trust || true
  py trust | result
  tell "${D}(a runtime monitor sees no event here, so it cannot raise anything)${N}"
}

act5() {
  act_header 5 "Someone deploys an image that was never signed"
  tell "The same app, built outside the pipeline: no signature, no SBOM or provenance attestations."
  watch_for "this terminal: NOT VERIFIED, no envelope; alert screen: HIGH 'Image failed verification'"
  local ref before
  ref=$(cat "$PROVBIND_RUN/demo-unsigned.ref" 2>/dev/null || true)
  if [ -z "$ref" ] && [ "$DRY_RUN" != 1 ]; then
    warn "skipped: prep did not build the unsigned image ($PROVBIND_RUN/logs/unsigned-build.log)"
    return 0
  fi
  pause "deploy the unsigned image"
  before=$(py count --cls binding)
  x deploy_temp "$UNSIGNED" "${ref:-$PROVBIND_REGISTRY/$UNSIGNED@sha256:(built by prep)}"
  wait_until "$WAIT_S" "the admission decision" -- has_binding "$UNSIGNED" || true
  py binding --pod-prefix "$UNSIGNED" | result
  wait_until 30 "the alert" -- more_than "$before" --cls binding || true
  x teardown_temp "$UNSIGNED"
}

act6() {
  act_header 6 "Can an intruder erase the evidence?"
  tell "Every alert is appended to a hash-chained log. We verify it, change ONE character in one" \
       "record, as someone covering their tracks would, and verify again."
  watch_for "this terminal: OK with N records, then BROKEN at the record that was changed"
  pause "verify, tamper, verify"
  verify_log
  xs "bash testbed/scenarios/tamper.sh | tail -1"
  verify_log
  restore_log
}

verify_log() {             # verify_log prints its verdict on stderr and JSON on stdout
  if [ "$DRY_RUN" = 1 ]; then x python3 -m alerts.verify_log --run "$PROVBIND_RUN"; return 0; fi
  { python3 -m alerts.verify_log --run "$PROVBIND_RUN" 2>&1 >/dev/null || true; } | result
}

restore_log() {
  local log=$PROVBIND_RUN/log/violations.jsonl
  if [ "$DRY_RUN" = 1 ]; then x cp "$log.orig" "$log"; return 0; fi
  if [ -f "$log.orig" ]; then
    cp "$log.orig" "$log" && rm -f "$log.orig"
    tell "${D}(the original log is back, so the next run starts clean)${N}"
  fi
}

finale() {
  echo; echo "${B}=== That was PROVBIND${N}"
  tell "Signed evidence in, runtime verification out: quiet on the operator's shell, precise on the" \
       "attack, trust withdrawn without any change in behaviour, and a log that shows tampering."
  ok "$(py count --alerts) alerts in this run; 'scripts/live-demo.sh reset' undoes the acts"
}

# --- check, prep, reset, stop ----------------------------------------------------------------------
check_ready() {            # prints one line per item; returns 1 if something required is missing
  local bad=0
  item() {                 # required|optional LABEL -- COMMAND...
    local kind=$1 label=$2; shift 3
    if [ "$DRY_RUN" = 1 ]; then x "$@"; return 0; fi
    if "$@" >/dev/null 2>&1; then ok "$label"
    elif [ "$kind" = required ]; then warn "$label"; bad=1
    else printf '    %s-%s %s (optional)\n' "$Y" "$N" "$label"; fi
  }
  echo "${B}check${N}"
  item required "kubectl, curl and python3 are installed" -- command -v kubectl curl python3
  item required "DEMO_REF is a ref@digest ($DEMO_REF)" -- test "${DEMO_REF#*@sha256:}" != "${DEMO_REF:-}"
  item required "the cluster answers" -- kubectl get nodes
  item required "namespace $NAMESPACE exists" -- kubectl get namespace "$NAMESPACE"
  item required "Tetragon is running" -- kubectl -n kube-system rollout status ds/tetragon --timeout=10s
  item required "the local registry answers ($PROVBIND_REGISTRY)" -- curl -sf "http://$PROVBIND_REGISTRY/v2/"
  item required "the public key exists ($PROVBIND_KEY)" -- test -s "$PROVBIND_KEY"
  item required "PROVBIND's modules import" -- python3 -c \
    'import controller.watch, node.run, alerts.run, alerts.trust, alerts.verify_log, eval.demo_view, eval.live_demo'
  item optional "the demo image is in the registry" -- crane digest "$DEMO_REF"
  item optional "Falco is running (act 2 and 3 compare with it)" -- falco_running
  item optional "docker and crane, to build the unsigned image of act 5" -- command -v docker crane
  item optional "Neo4j answers (without it, attribution uses the envelope's layer field)" -- curl -sf http://localhost:7474
  return "$bad"
}
falco_running() { kubectl -n falco get pods -l app.kubernetes.io/name=falco --no-headers | grep -q Running; }

events() {
  if [ "$EVENT_SOURCE" = file ]; then echo "docker exec $KIND_NODE tail -n 0 -F $TETRAGON_LOG"
  else echo "kubectl logs -n kube-system ds/tetragon -c $TETRAGON_CONTAINER -f --tail=0"; fi
}

start_service() {          # NAME COMMAND...: in its own session, so stop can end the whole pipeline
  local name=$1; shift
  if [ "$DRY_RUN" = 1 ]; then printf '%s  + %s &%s\n' "$D" "$*" "$N"; return 0; fi
  setsid "$@" > "$PROVBIND_RUN/logs/$name.out" 2> "$PROVBIND_RUN/logs/$name.log" < /dev/null &
  echo "$name $!" >> "$PROVBIND_RUN/demo.pids"
}

stop_services() {
  local name pid f=$PROVBIND_RUN/demo.pids
  [ -f "$f" ] || return 0
  while read -r name pid; do
    x kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done < "$f"
  [ "$DRY_RUN" = 1 ] || rm -f "$f"
}

build_unsigned() {         # an unsigned copy of the demo app, with a new digest, for act 5
  local img=$PROVBIND_REGISTRY/$UNSIGNED:latest log=$PROVBIND_RUN/logs/unsigned-build.log
  echo "${B}prep: an unsigned copy of the demo app for act 5 (about a minute)${N}"
  if [ "$DRY_RUN" = 1 ]; then x docker build -t "$img" testbed/demo-app; x docker push "$img"; return 0; fi
  if docker build --platform linux/amd64 --provenance=false --sbom=false \
       --label "provbind.test=unsigned-$(date +%s)" -t "$img" testbed/demo-app > "$log" 2>&1 \
     && docker push "$img" >> "$log" 2>&1; then
    echo "$PROVBIND_REGISTRY/$UNSIGNED@$(crane digest "$img")" > "$PROVBIND_RUN/demo-unsigned.ref"
    ok "pushed without a signature: $(cat "$PROVBIND_RUN/demo-unsigned.ref")"
  else
    warn "could not build it, so act 5 will be skipped ($log)"
  fi
}

prep() {
  check_ready || { warn "fix the items marked ! first"; exit 1; }
  stop_services
  if [ -e "$PROVBIND_RUN" ] && [ "$DRY_RUN" != 1 ]; then
    mv "$PROVBIND_RUN" "$PROVBIND_RUN.$(date +%Y%m%d-%H%M%S)"     # keeps the rehearsal for a replay
  fi
  x mkdir -p "$PROVBIND_RUN/logs"
  echo "${B}prep: the cluster (a fresh deployment comes in act 1)${N}"
  x kubectl -n "$NAMESPACE" delete deployment "$DEPLOY" "$UNSIGNED" --ignore-not-found --wait=true
  local pdir=node/tetragon other=node/tetragon/opt f
  [ "$POLICY_SET" = opt ] && { pdir=node/tetragon/opt; other=node/tetragon; }
  for f in write truncate cap load connect; do
    xs "kubectl delete -f $other/$f.yaml --ignore-not-found >/dev/null 2>&1 || true"
    x kubectl apply -f "$pdir/$f.yaml"
  done
  echo "${B}prep: PROVBIND's services (logs in $PROVBIND_RUN/logs)${N}"
  start_service controller python3 -m controller.watch --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY"
  # shellcheck disable=SC2016  # the quotes are for the inner shell; $EGRESS expands here
  start_service node bash -c "$(events) | tee '$PROVBIND_RUN/rec.jsonl' | python3 -m node.run --run '$PROVBIND_RUN' ${EGRESS:+--egress '$EGRESS'}"
  start_service alerts python3 -m alerts.run --run "$PROVBIND_RUN"
  start_service trust python3 -m alerts.trust --run "$PROVBIND_RUN" --poll 2
  if [ "$DRY_RUN" = 1 ] || falco_running >/dev/null 2>&1; then start_service falco ./eval/capture_falco.sh
  else tell "${D}(Falco is not running: acts 2 and 3 show PROVBIND only)${N}"; fi
  sleep_s 3
  if [ "$DRY_RUN" != 1 ]; then
    local name pid dead=0
    while read -r name pid; do
      if kill -0 "$pid" 2>/dev/null; then ok "$name is running"
      else warn "$name stopped: see $PROVBIND_RUN/logs/$name.log"; dead=1; fi
    done < "$PROVBIND_RUN/demo.pids"
    [ "$dead" = 0 ] || exit 1
  fi
  skipped 5 || build_unsigned
  echo
  echo "${B}READY.${N} On the audience screen:  python3 -m eval.demo_view --run $PROVBIND_RUN --follow"
  echo "       Then here:                 scripts/live-demo.sh run"
}

reset_demo() {
  echo "${B}reset${N}"
  xs "RESTORE=1 bash testbed/scenarios/trust.sh >/dev/null"
  restore_log
  x teardown_temp "$UNSIGNED"
  ok "advisory removed, log restored, test deployment removed; the services keep running"
  tell "for a clean alert screen as well, run prep again (a fresh run folder)"
}

case "${1:-help}" in
  check) check_ready ;;
  prep) need_ref; prep ;;
  run)
    need_ref
    for n in 1 2 3 4 5 6; do skipped "$n" || "act$n"; done
    finale ;;
  act)
    case "${2:-}" in
      [1-6]) need_ref; "act$2" ;;
      *) echo "usage: scripts/live-demo.sh act 1-6" >&2; exit 2 ;;
    esac ;;
  reset) reset_demo ;;
  stop) stop_services; ok "PROVBIND's services stopped" ;;
  help|-h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) echo "unknown command: $1 (try: check, prep, run, act N, reset, stop)" >&2; exit 2 ;;
esac
