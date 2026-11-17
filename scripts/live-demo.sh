#!/usr/bin/env bash
# The live demo (docs/LIVE-DEMO.md): about a minute, hands-free, the same every time. The settings are in
# testbed/live-demo.conf; a setting given on the command line or in the environment wins for that run:
#     make live-demo ATTACK=overwrite PAUSE=enter
#
#   scripts/live-demo.sh             the demo: PROVBIND restarts on a fresh run folder, then the acts
#   scripts/live-demo.sh act NAME    one act, on the running services (envelope shell attack trust log unsigned)
#   scripts/live-demo.sh check       is everything ready? (reads only)
#   scripts/live-demo.sh setup       once: check, deploy the app, build the unsigned copy if ACTS has it
#   scripts/live-demo.sh settings    the settings in use, and where each one comes from
#   scripts/live-demo.sh reset       undo the acts when FRESH=0 (advisory, key, log edit, test deployment)
#   scripts/live-demo.sh stop        stop PROVBIND's services
#   scripts/live-demo.sh diagnose    what the last run saw, for an act that showed no alert (reads only)
#
# The audience screen, in a second terminal, starts over by itself at every run:
#     python3 -m eval.demo_view --run ./run-demo --follow          (make live-demo-view)
# Runs on the demo PC (kind, Tetragon, the local registry). AUTO=1 skips every pause; DRY_RUN=1 prints
# the commands instead of running them (no cluster needed).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# --- settings: built-in defaults < testbed/live-demo.conf < the command line and the environment ------
SETTINGS="ACTS PAUSE CAPTIONS ATTACK TRUST ADVISORY_PACKAGE ADVISORY_VERSION ADVISORY_ECOSYSTEM ADVISORY_ID
SHELL_CMD FRESH REDEPLOY WAIT_S KEEP_RUNS FALCO NEO4J POLICY_SET DEMO_REF NAMESPACE DEPLOY"
CONF=${DEMO_CONF:-testbed/live-demo.conf}
declare -A GIVEN=() FROM=()
for k in $SETTINGS; do
  if [ -n "${!k+x}" ]; then GIVEN[$k]=${!k}; unset "$k"; fi
done
if [ -f "$CONF" ]; then
  # shellcheck source=/dev/null
  source "$CONF"
elif [ -n "${DEMO_CONF:-}" ]; then
  echo "live-demo: no settings file at $CONF" >&2
  exit 2
fi
for k in $SETTINGS; do [ -z "${!k+x}" ] || FROM[$k]=conf; done
for k in "${!GIVEN[@]}"; do printf -v "$k" '%s' "${GIVEN[$k]}"; FROM[$k]="command line"; done
: "${ACTS:=envelope shell trust attack log}"
: "${PAUSE:=3}"
: "${CAPTIONS:=short}"
: "${ATTACK:=update}"
: "${TRUST:=advisory}"
: "${ADVISORY_PACKAGE:=requestz-helper}"
: "${ADVISORY_VERSION=0.1.0}"           # empty means every version, so no colon
: "${ADVISORY_ECOSYSTEM:=PyPI}"
: "${ADVISORY_ID:=MAL-2026-9001}"
: "${SHELL_CMD:=ls /; cat /etc/hostname}"
: "${FRESH:=1}"
: "${REDEPLOY:=0}"
: "${WAIT_S:=30}"
: "${KEEP_RUNS:=3}"
: "${FALCO:=auto}"
: "${NEO4J:=off}"
: "${POLICY_SET:=opt}"
: "${DEMO_REF:=}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${PROVBIND_RUN:=./run-demo}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${PROVBIND_REGISTRY:=localhost:5001}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${EVENT_SOURCE:=kubectl}"            # kubectl = kubectl logs; file = Tetragon's export file in the kind node
: "${KIND_NODE:=kind-control-plane}"
: "${TETRAGON_LOG:=/var/run/cilium/tetragon/tetragon.log}"
: "${EGRESS:=testbed/egress.json}"
: "${AUTO:=0}"
: "${DRY_RUN:=0}"
ACTS=$(tr -s '[:space:]' ' ' <<< "$ACTS" | sed 's/^ //; s/ $//')
export PROVBIND_RUN NAMESPACE DEPLOY PROVBIND_REGISTRY
export POD_PREFIX=$DEPLOY
ALL_ACTS="envelope shell attack trust log unsigned"
UNSIGNED=$DEPLOY-unsigned
source testbed/scenarios/deploy_lib.sh      # app_curl, deploy_temp, teardown_temp (and lib.sh)

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'
else B=; D=; G=; R=; Y=; N=; fi

validate() {               # stop before anything runs when a setting has a value the demo cannot use
  local bad=() n
  for n in $ACTS; do
    case " $ALL_ACTS " in *" $n "*) ;; *) bad+=("ACTS: no act named '$n' (acts: $ALL_ACTS)") ;; esac
  done
  [ -n "${ACTS// /}" ] || bad+=("ACTS is empty (acts: $ALL_ACTS)")
  case "$ATTACK" in update|overwrite|inject|egress) ;; *) bad+=("ATTACK=$ATTACK: use update, overwrite, inject or egress") ;; esac
  case "$TRUST" in advisory|key) ;; *) bad+=("TRUST=$TRUST: use advisory or key") ;; esac
  case "$PAUSE" in enter) ;; ''|*[!0-9.]*) bad+=("PAUSE=$PAUSE: use a number of seconds, or enter") ;; esac
  case "$CAPTIONS" in short|long) ;; *) bad+=("CAPTIONS=$CAPTIONS: use short or long") ;; esac
  case "$FRESH" in 0|1) ;; *) bad+=("FRESH=$FRESH: use 0 or 1") ;; esac
  case "$REDEPLOY" in 0|1) ;; *) bad+=("REDEPLOY=$REDEPLOY: use 0 or 1") ;; esac
  case "$WAIT_S" in ''|*[!0-9]*) bad+=("WAIT_S=$WAIT_S: use a whole number of seconds") ;; esac
  case "$KEEP_RUNS" in ''|*[!0-9]*) bad+=("KEEP_RUNS=$KEEP_RUNS: use a whole number") ;; esac
  case "$FALCO" in auto|off) ;; *) bad+=("FALCO=$FALCO: use auto or off") ;; esac
  case "$NEO4J" in on|off) ;; *) bad+=("NEO4J=$NEO4J: use off or on") ;; esac
  case "$POLICY_SET" in opt|orig) ;; *) bad+=("POLICY_SET=$POLICY_SET: use opt or orig") ;; esac
  [ -n "$ADVISORY_PACKAGE" ] && [ -n "$ADVISORY_ID" ] || bad+=("ADVISORY_PACKAGE and ADVISORY_ID must not be empty")
  local eco=${ADVISORY_ECOSYSTEM%%:*}       # the trust loop reads "Debian:12" as Debian
  case "${eco,,}" in
    pypi|npm|debian|ubuntu|go|crates.io|maven|rubygems|nuget|packagist|alpine) ;;
    *) bad+=("ADVISORY_ECOSYSTEM=$ADVISORY_ECOSYSTEM: use PyPI, npm, Debian, Ubuntu, Go, crates.io, Maven, RubyGems, NuGet, Packagist or Alpine") ;;
  esac
  [ -n "$SHELL_CMD" ] || bad+=("SHELL_CMD must not be empty")
  [ "${#bad[@]}" -eq 0 ] && return 0
  printf 'live-demo: %s\n' "${bad[@]}" >&2
  echo "live-demo: fix them in $CONF or on the command line" >&2
  exit 2
}

# --- small helpers -------------------------------------------------------------------------------
x() {                      # run a command, or print it in a dry run
  if [ "$DRY_RUN" = 1 ]; then printf '%s    + %s%s\n' "$D" "$*" "$N"; return 0; fi
  "$@"
}
xq() {                     # the same, with the command's own output discarded
  if [ "$DRY_RUN" = 1 ]; then x "$@"; return 0; fi
  "$@" >/dev/null
}
xs() {                     # the same for a shell pipeline written as one string
  if [ "$DRY_RUN" = 1 ]; then printf '%s    + %s%s\n' "$D" "$1" "$N"; return 0; fi
  bash -c "$1"
}
py() { python3 -m eval.live_demo "$@" --run "$PROVBIND_RUN"; }
sleep_s() { [ "$DRY_RUN" = 1 ] || sleep "$1"; }
tell() { local line; for line in "$@"; do printf '      %s\n' "$line"; done; }
ok() { printf '      %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '      %s!%s %s\n' "$R" "$N" "$*"; }
result() { local line; while IFS= read -r line; do printf '      %s\n' "$line"; done; }
has_act() { case " $ACTS " in *" $1 "*) return 0 ;; esac; return 1; }

ACT_N=0; ACT_TOTAL=0; ACT_NAME=""
intro() {                  # SHORT [LONG_LINE...] [-- WATCH]: one line, or with CAPTIONS=long what to say and watch
  local short=$1; shift
  printf '\n%s[%s/%s] %-9s%s %s\n' "$B" "$ACT_N" "$ACT_TOTAL" "$ACT_NAME" "$N" "$short"
  [ "$CAPTIONS" = long ] || return 0
  while [ $# -gt 0 ] && [ "$1" != -- ]; do tell "$1"; shift; done
  if [ "${1:-}" = -- ]; then shift; printf '      %swatch:%s %s\n' "$Y" "$N" "$*"; fi
}
go() {                     # PAUSE=enter: wait for the presenter before the act does anything
  [ "$PAUSE" = enter ] && [ "$AUTO" != 1 ] && [ -t 0 ] || return 0
  read -r -p "      ${D}[Enter]${N} " _ || true
}
between() {                # PAUSE=N: N seconds between two acts
  [ "$AUTO" = 1 ] && return 0
  case "$PAUSE" in enter|0) ;; *) sleep_s "$PAUSE" ;; esac
}

wait_until() {             # SECONDS WHAT -- COMMAND...: poll COMMAND twice a second until it succeeds
  local secs=$1 what=$2 spin="|/-\\" i=0 deadline
  shift 3
  if [ "$DRY_RUN" = 1 ]; then printf '%s    (waits up to %s s for %s)%s\n' "$D" "$secs" "$what" "$N"; return 0; fi
  deadline=$(( $(date +%s) + secs ))
  while ! "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then printf '\r%60s\r' ''; warn "$what did not arrive within ${secs} s"; return 1; fi
    printf '\r      %s waiting for %s ' "${spin:i++%4:1}" "$what"
    sleep 0.5
  done
  printf '\r%60s\r' ''
}
more_than() { local n=$1; shift; [ "$(py count "$@")" -gt "$n" ]; }   # N COUNT-ARGS...
envelope_state() { py envelope --pod-prefix "$DEPLOY"; }
envelope_ready() { [[ "$(envelope_state)" == *"envelope compiled"* ]]; }
envelope_decided() { local s; s=$(envelope_state); [[ "$s" == *"envelope compiled"* || "$s" == *"not verified"* ]]; }
has_binding() { [[ "$(py binding --pod-prefix "$1")" != "no binding yet"* ]]; }

PIDS_FILE=$PROVBIND_RUN/demo.pids
is_ours() {                # NAME PID: is PID still that service? After a reboot a saved PID can be any program
  local cmd marker
  case "$1" in
    controller) marker=controller.watch ;; node) marker=node.run ;; alerts) marker=alerts.run ;;
    trust) marker=alerts.trust ;; falco) marker=capture_falco ;; *) return 1 ;;
  esac
  cmd=$(tr '\0' ' ' < "/proc/$2/cmdline" 2>/dev/null) || return 1
  [[ "$cmd" == *"$marker"* ]]
}
service_alive() {          # NAME: is that service of this run folder running?
  local name pid
  [ -f "$PIDS_FILE" ] || return 1
  while read -r name pid; do [ "$name" = "$1" ] && is_ours "$name" "$pid" && return 0; done < "$PIDS_FILE"
  return 1
}
services_running() { local s; for s in controller node alerts trust; do service_alive "$s" || return 1; done; }
falco_running() { kubectl -n falco get pods -l app.kubernetes.io/name=falco --no-headers 2>/dev/null | grep -q Running; }
falco_on() { [ "$FALCO" != off ] && { [ "$DRY_RUN" = 1 ] || service_alive falco; }; }
falco_app() { py falco --since "$1" --namespace "$NAMESPACE" --pod-prefix "$DEPLOY"; }   # MARK: the app's only
falco_saw() { [[ "$(falco_app "$1")" != "Falco: no alert" ]]; }      # Falco also reports the VM's own programs
show_falco() { if falco_on; then falco_app "$1" | result; fi; }
falco_settle() {           # MARK: Falco's alerts come through kubectl logs: wait up to 4 s for the app's first, then 1 s
  falco_on && [ "$DRY_RUN" != 1 ] || return 0
  local end=$(( SECONDS + 4 ))
  while [ "$SECONDS" -lt "$end" ] && ! falco_saw "$1"; do sleep 0.5; done
  if falco_saw "$1"; then sleep 1; fi
}

cleanup() { stop_port_forward; }
trap cleanup EXIT
curl_app() { app_curl "$1"; trap cleanup EXIT; }    # lib.sh's port-forward sets its own EXIT trap

# --- the image and the app -----------------------------------------------------------------------
resolve_ref() {            # DEMO_REF: as set, else the running deployment's image, else <registry>/demo-app:latest
  [ -z "$DEMO_REF" ] || return 0
  if [ "$DRY_RUN" = 1 ]; then DEMO_REF="$PROVBIND_REGISTRY/demo-app@sha256:(found at run time)"; return 0; fi
  local img digest
  img=$(kubectl -n "$NAMESPACE" get deployment "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)
  case "$img" in *@sha256:*) DEMO_REF=$img; return 0 ;; esac
  digest=$(crane digest "$PROVBIND_REGISTRY/demo-app:latest" 2>/dev/null || true)
  if [ -n "$digest" ]; then DEMO_REF="$PROVBIND_REGISTRY/demo-app@$digest"; return 0; fi
  warn "no signed image found: run 'make demo-app', or set DEMO_REF in $CONF"
  return 1
}

deploy_app() {
  xs "kubectl -n '$NAMESPACE' create deployment '$DEPLOY' --image='$DEMO_REF' --port=8080 --dry-run=client -o yaml | kubectl apply -f - >/dev/null"
  xq kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=120s
}

app_older_than_sensor() {  # true when the app started before Tetragon was ready, so its checks may miss the app
  python3 - "$NAMESPACE" "$DEPLOY" <<'PY'
import json, subprocess, sys
ns, deploy = sys.argv[1:3]
def pods(args):
    out = subprocess.run(["kubectl", *args, "-o", "json"], capture_output=True, text=True, check=True).stdout
    return json.loads(out)["items"]
def started(items):
    return [cs["state"]["running"]["startedAt"] for p in items
            for cs in (p.get("status") or {}).get("containerStatuses") or []
            if ((cs.get("state") or {}).get("running") or {}).get("startedAt")]
def ready(items):
    return [c["lastTransitionTime"] for p in items for c in (p.get("status") or {}).get("conditions") or []
            if c.get("type") == "Ready" and c.get("status") == "True" and c.get("lastTransitionTime")]
app = started([p for p in pods(["-n", ns, "get", "pods", "-l", f"app={deploy}"])
               if not (p.get("metadata") or {}).get("deletionTimestamp")])
sensor = pods(["-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/name=tetragon"])
since = ready(sensor) or started(sensor)         # Tetragon needs seconds after its start to apply its policies
sys.exit(0 if app and since and min(app) <= max(since) else 1)
PY
}

restart_app() {            # WHY
  tell "${D}$1: restarting the app (about 20 s)${N}"
  kubectl -n "$NAMESPACE" rollout restart "deploy/$DEPLOY" >/dev/null
  kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=120s >/dev/null
}

app_key() {                # the newest app pod and its start: the sensor check is done once per app start
  kubectl -n "$NAMESPACE" get pods -l "app=$DEPLOY" --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1:].metadata.name}/{.items[-1:].status.containerStatuses[0].state.running.startedAt}' 2>/dev/null
}

sensor_output() {          # the sensor's recent raw events
  if [ "$EVENT_SOURCE" = file ]; then docker exec "$KIND_NODE" tail -n 5000 "$TETRAGON_LOG" 2>/dev/null
  else kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" --since=90s 2>/dev/null; fi
}

sensor_sees_app() {        # a write inside the app's container must reach the sensor (its namespaced policies)
  local mark i
  mark=.provbind-probe-$(date +%s)
  kubectl -n "$NAMESPACE" exec "deploy/$DEPLOY" -- sh -c \
    "for i in 1 2 3; do echo probe >> /tmp/$mark; sleep 1; done; rm -f /tmp/$mark" >/dev/null 2>&1 || return 1
  for ((i = 0; i < ${PROBE_TRIES:-5}; i++)); do
    [ "$i" = 0 ] || sleep 1
    if sensor_output | grep -q -- "$mark"; then return 0; fi
  done
  return 1
}

check_sensor_sees_app() {  # once per app start: restart the app if the sensor does not see its writes
  local stamp=$PROVBIND_RUN.probe key
  key=$(app_key)
  if [ -n "$key" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$key" ]; then return 0; fi
  tell "${D}checking that the sensor sees the app (once after each start)${N}"
  if ! sensor_sees_app; then
    restart_app "the sensor does not see the app's writes"
    sensor_sees_app || warn "the sensor still does not see writes in the app: the attack act shows only its first alert (docs/LIVE-DEMO.md, section 5)"
    key=$(app_key)
  fi
  echo "$key" > "$stamp"
}

ensure_app() {             # the app runs, started after the sensor was ready, and the sensor sees its writes
  [ "$REDEPLOY" = 1 ] && return 0          # the envelope act deploys it
  if [ "$DRY_RUN" = 1 ]; then
    x kubectl -n "$NAMESPACE" get deployment "$DEPLOY"
    printf '%s    (checks once after each app start that the sensor sees writes in the app)%s\n' "$D" "$N"
    return 0
  fi
  if ! kubectl -n "$NAMESPACE" get deployment "$DEPLOY" >/dev/null 2>&1; then
    tell "${D}deploying the signed app ($DEMO_REF), once${N}"
    deploy_app
  elif app_older_than_sensor; then
    restart_app "the app started before the sensor was ready"
  fi
  check_sensor_sees_app
}

# --- PROVBIND's services -----------------------------------------------------------------------------
events() {
  if [ "$EVENT_SOURCE" = file ]; then echo "docker exec $KIND_NODE tail -n 0 -F $TETRAGON_LOG"
  else echo "kubectl logs -n kube-system ds/tetragon -c $TETRAGON_CONTAINER -f --tail=0"; fi
}

start_service() {          # NAME COMMAND...: in its own session, so stop ends the whole pipeline
  local name=$1; shift
  if [ "$DRY_RUN" = 1 ]; then printf '%s    + %s &%s\n' "$D" "$*" "$N"; return 0; fi
  setsid "$@" > "$PROVBIND_RUN/logs/$name.out" 2> "$PROVBIND_RUN/logs/$name.log" < /dev/null &
  echo "$name $!" >> "$PIDS_FILE"
}

stop_services() {
  local name pid
  [ -f "$PIDS_FILE" ] || return 0
  while read -r name pid; do
    is_ours "$name" "$pid" || continue          # already gone, or the PID now belongs to another program
    x kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done < "$PIDS_FILE"
  [ "$DRY_RUN" = 1 ] || rm -f "$PIDS_FILE"
}

apply_policies() {         # one policy set: both at once would report every event twice
  local use=node/tetragon drop=node/tetragon/opt f on=() off=()
  if [ "$POLICY_SET" = opt ]; then use=node/tetragon/opt; drop=node/tetragon; fi
  for f in write truncate cap load connect; do on+=(-f "$use/$f.yaml"); off+=(-f "$drop/$f.yaml"); done
  xq kubectl delete --ignore-not-found "${off[@]}" 2>/dev/null || true
  xq kubectl apply "${on[@]}"
}

new_run_folder() {         # move the last run aside (plan B replays it) and keep KEEP_RUNS of them
  local stamp old
  if [ "$DRY_RUN" = 1 ]; then x mv "$PROVBIND_RUN" "$PROVBIND_RUN.<date-time>"; x mkdir -p "$PROVBIND_RUN/logs"; return 0; fi
  if [ -e "$PROVBIND_RUN" ]; then
    stamp="$PROVBIND_RUN.$(date +%Y%m%d-%H%M%S)"
    [ -e "$stamp" ] && stamp="$stamp-$$"
    mv "$PROVBIND_RUN" "$stamp"
  fi
  while IFS= read -r old; do rm -rf -- "$old"; done < <(
    find "$(dirname "$PROVBIND_RUN")" -maxdepth 1 -type d -name "$(basename "$PROVBIND_RUN").2*" | sort -r | tail -n +"$((KEEP_RUNS + 1))")
  mkdir -p "$PROVBIND_RUN/logs"
}

start_services() {
  [ "$DRY_RUN" = 1 ] || mkdir -p "$PROVBIND_RUN/logs"
  start_service controller python3 -m controller.watch --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY"
  # shellcheck disable=SC2016  # the quotes are for the inner shell; $EGRESS expands here
  start_service node bash -c "$(events) | tee '$PROVBIND_RUN/rec.jsonl' | python3 -m node.run --run '$PROVBIND_RUN' ${EGRESS:+--egress '$EGRESS'}"
  # NEO4J=off: attribution straight from the envelope (alerts/attribute.py: the same answer), so the
  # alert engine never stops to load a fresh run's graph into Neo4j while alerts wait
  start_service alerts env "PROVBIND_NEO4J=$NEO4J" python3 -m alerts.run --run "$PROVBIND_RUN"
  start_service trust python3 -m alerts.trust --run "$PROVBIND_RUN" --poll 2
  if [ "$FALCO" != off ] && { [ "$DRY_RUN" = 1 ] || falco_running; }; then start_service falco ./eval/capture_falco.sh; fi
  sleep_s 2
  if [ "$DRY_RUN" != 1 ]; then
    local name pid
    while read -r name pid; do
      kill -0 "$pid" 2>/dev/null || { warn "$name stopped at once: see $PROVBIND_RUN/logs/$name.log"; exit 1; }
    done < "$PIDS_FILE"
  fi
}

prepare() {                # FRESH=1, or nothing running: PROVBIND restarts on a fresh run folder
  resolve_ref || exit 1    # before a redeploy deletes the deployment
  if [ "$FRESH" = 1 ] || ! services_running; then
    stop_services
    if [ "$REDEPLOY" = 1 ]; then
      xq kubectl -n "$NAMESPACE" delete deployment "$DEPLOY" --ignore-not-found --wait=true
    fi
    apply_policies         # before the sensor check, which needs them
    ensure_app             # before PROVBIND starts, so the check leaves nothing in the run
    if [ "$FRESH" = 1 ] || [ ! -d "$PROVBIND_RUN" ]; then new_run_folder; fi
    start_services
  else
    ensure_app
  fi
}

wait_envelope() {          # show|quiet: wait for the app's envelope; 1 if the image did not verify or nothing came
  if ! wait_until "$((WAIT_S + 60))" "the app's envelope" -- envelope_decided; then
    warn "see $PROVBIND_RUN/logs/controller.log"
    return 1
  fi
  [ "$1" = quiet ] || envelope_state | result
  [ "$DRY_RUN" = 1 ] || envelope_ready || { [ "$1" != quiet ] || envelope_state | result; return 1; }
}

# --- the acts -------------------------------------------------------------------------------------
act_envelope() {
  if [ "$REDEPLOY" = 1 ]; then
    intro "the signed app is deployed by its digest: verified, then compiled into its runtime envelope" \
      "We deploy the demo app by its digest. PROVBIND checks the signature, the SBOM and the build" \
      "provenance, then compiles the envelope: every file, layer, package and program they allow." \
      -- "the admission checks, then the envelope, compiled in a few seconds"
    go
    deploy_app
  else
    intro "PROVBIND checks the app's signed evidence and compiles its runtime envelope" \
      "PROVBIND has just started. It checks the running app's signature, SBOM and build provenance," \
      "then compiles the envelope: every file, layer, package and program the evidence allows." \
      -- "the admission checks, then the envelope, compiled in a few seconds, with no training"
    go
  fi
  wait_envelope show || { warn "the app has no envelope: see $PROVBIND_RUN/logs/controller.log"; return 1; }
}

act_shell() {
  intro "an operator runs '$SHELL_CMD' in the container: legitimate, but unusual" \
    "Someone on the team opens a shell in the running container. A learned detector has never seen" \
    "it; a rule-based monitor has a rule for it." \
    -- "alert screen: dim lines only, logged but NOT alerts (the programs are in the signed image)"
  go
  local falco_mark low_before alerts_before tty=-i
  [ -t 0 ] && tty=-it                     # Falco's shell rule needs a terminal
  falco_mark=$(py lines); low_before=$(py count --low); alerts_before=$(py count --alerts)
  xq kubectl exec "$tty" -n "$NAMESPACE" "deploy/$DEPLOY" -- sh -c "$SHELL_CMD" 2>/dev/null || true
  wait_until 15 "the Low record" -- more_than "$low_before" --low || true
  falco_settle "$falco_mark"
  ok "PROVBIND: $(( $(py count --alerts) - alerts_before )) alerts; $(( $(py count --low) - low_before )) Low records, logged"
  show_falco "$falco_mark"
}

attack_plan() {            # ENDPOINT, CAPTION and the class (and subclass) the attack must raise
  case "$ATTACK" in
    update)    ENDPOINT=/update; CLS=D_exec; SUB=undeclared
               CAPTION="the dependency requestz-helper drops a program in /tmp and runs it; it edits /etc/passwd" ;;
    overwrite) ENDPOINT=/ru4; CLS=D_write; SUB=
               CAPTION="the app overwrites the signed /usr/bin/ls, runs it, then restores it" ;;
    inject)    ENDPOINT=/rk3; CLS=D_load; SUB=undeclared
               CAPTION="a library written at runtime is preloaded into a new process" ;;
    egress)    ENDPOINT=/ru3; CLS=D_net; SUB=
               CAPTION="the app connects to an address outside its egress allow list (nothing is sent)" ;;
  esac
}

rate_limit_wait() {        # POLICY_SET=opt reports an identical write or library load once a minute
  [ "$POLICY_SET" = opt ] || return 0
  case "$ATTACK" in overwrite|inject) ;; *) return 0 ;; esac
  local last left
  last=$(cat "$PROVBIND_RUN.$ATTACK.at" 2>/dev/null || echo 0)
  left=$(( last + 62 - $(date +%s) ))
  [ "$left" -gt 0 ] || return 0
  tell "${D}(waiting ${left} s: the sensor reports an identical event once a minute)${N}"
  sleep_s "$left"
}

act_attack() {
  attack_plan
  intro "$CAPTION" \
    "requestz-helper stands in for a compromised dependency: it is signed, in the SBOM, and was" \
    "admitted. Now its payload runs: one request to the app sets it off." \
    -- "alert screen: what the action contradicts in the signed evidence, with the layer and package"
  go
  rate_limit_wait
  local mark falco_mark before writes seen=1
  mark=$(py count); falco_mark=$(py lines); writes=$(py count --cls D_write)
  before=$(py count --cls "$CLS" ${SUB:+--sub "$SUB"})
  x curl_app "$ENDPOINT" || warn "the request to $ENDPOINT failed (see above)"
  [ "$DRY_RUN" = 1 ] || date +%s > "$PROVBIND_RUN.$ATTACK.at"
  wait_until "$WAIT_S" "the alert" -- more_than "$before" --cls "$CLS" ${SUB:+--sub "$SUB"} || seen=0
  if [ "$ATTACK" = update ] && [ "$seen" = 1 ]; then
    wait_until 10 "the /etc/passwd alert" -- more_than "$writes" --cls D_write || true
  fi
  py since --since "$mark" | result
  [ "$seen" = 1 ] || warn "if the app started before the sensor: 'kubectl -n $NAMESPACE rollout restart deploy/$DEPLOY', then run again"
  falco_settle "$falco_mark"
  show_falco "$falco_mark"
}

undo_trust() {             # FRESH=0: undo an earlier trust change first, so the loop sees a new one
  [ "$FRESH" = 1 ] && return 0
  local changed=0
  if compgen -G "$PROVBIND_RUN/advisories/*.json" >/dev/null; then x rm -f "$PROVBIND_RUN"/advisories/*.json; changed=1; fi
  if grep -q revoked "$PROVBIND_RUN/keystatus.json" 2>/dev/null; then
    xq python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --key "$PROVBIND_KEY" --state active; changed=1
  fi
  [ "$changed" = 0 ] || sleep_s 4
}

act_trust() {
  if [ "$TRUST" = key ]; then
    intro "the key that signed the image is revoked, while the app runs" \
      "Nothing in the container changes. The key that signed the image is revoked." \
      -- "alert screen: TRUST withdrawn within about 2 s, while the pod still behaves as signed"
  else
    intro "advisory $ADVISORY_ID names $ADVISORY_PACKAGE ${ADVISORY_VERSION:-(every version)}, while the app runs" \
      "Before anything happens in the pod, an advisory for one of the image's packages appears in" \
      "the feed. Nothing in the container changes; PROVBIND's trust loop checks the image again." \
      -- "alert screen: TRUST withdrawn within about 2 s, while the pod still behaves as signed"
  fi
  go
  undo_trust
  local before
  before=$(py count --cls trust)
  if [ "$TRUST" = key ]; then
    xq python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --key "$PROVBIND_KEY" --state revoked
  else
    xq python3 -m eval.live_demo advisory --run "$PROVBIND_RUN" --id "$ADVISORY_ID" --ecosystem "$ADVISORY_ECOSYSTEM" \
      --package "$ADVISORY_PACKAGE" --pkg-version "$ADVISORY_VERSION"
  fi
  if [ "$TRUST" = advisory ] && [[ "$ADVISORY_ID" != [Mm][Aa][Ll]-* ]]; then
    sleep_s 5                # 2 s polling and a margin: a non-MAL advisory must NOT withdraw trust
    if more_than "$before" --cls trust; then py trust | result
    else ok "no trust alert: $ADVISORY_ID is not a malicious-package advisory, so it is reported and trust stays"; fi
    return 0
  fi
  if wait_until "$WAIT_S" "the trust alert" -- more_than "$before" --cls trust; then py trust | result
  elif [ "$TRUST" = advisory ]; then warn "is $ADVISORY_PACKAGE ($ADVISORY_ECOSYSTEM ${ADVISORY_VERSION:-any version}) in the image's SBOM? see $PROVBIND_RUN/logs/trust.log"
  else warn "see $PROVBIND_RUN/logs/trust.log"; fi
}

verify_log() {             # verify_log prints its verdict on stderr and JSON on stdout
  if [ "$DRY_RUN" = 1 ]; then x python3 -m alerts.verify_log --run "$PROVBIND_RUN"; return 0; fi
  { python3 -m alerts.verify_log --run "$PROVBIND_RUN" 2>&1 >/dev/null || true; } \
    | sed 's/^\[verify_log\] /log check: /' | result
}

restore_log() {
  local log=$PROVBIND_RUN/log/violations.jsonl
  if [ "$DRY_RUN" = 1 ]; then x cp "$log.orig" "$log"; return 0; fi
  if [ -f "$log.orig" ]; then cp "$log.orig" "$log" && rm -f "$log.orig"; tell "${D}(the original log is back)${N}"; fi
}

act_log() {
  intro "the alert log verifies; one character changes; verification fails at that record" \
    "Every alert is appended to a hash-chained log. We change ONE character in one record, as" \
    "someone covering their tracks would, and verify again." \
    -- "this terminal: OK with N records, then BROKEN at the record that was changed"
  go
  local out k
  if [ "$DRY_RUN" != 1 ] && [ ! -s "$PROVBIND_RUN/log/violations.jsonl" ]; then
    warn "the log is empty: put an act that alerts (shell, attack or trust) before log in ACTS"
    return 0
  fi
  verify_log
  if [ "$DRY_RUN" = 1 ]; then x bash testbed/scenarios/tamper.sh
  else
    out=$(bash testbed/scenarios/tamper.sh 2>&1 | tail -1 || true)
    k=$(sed -n 's/.*edited record k=\([0-9][0-9]*\).*/\1/p' <<< "$out")
    if [ -n "$k" ]; then tell "one character changed in record k=$k"; else warn "${out:-tamper.sh printed nothing}"; fi
  fi
  verify_log
  restore_log
}

build_unsigned() {         # an unsigned copy of the app, with a digest of its own
  local img=$PROVBIND_REGISTRY/$UNSIGNED:latest log=$PROVBIND_RUN/logs/unsigned-build.log
  if [ "$DRY_RUN" = 1 ]; then x docker build -t "$img" testbed/demo-app; x docker push "$img"; return 0; fi
  mkdir -p "$PROVBIND_RUN/logs"
  tell "${D}building an unsigned copy of the app (about a minute, once)${N}"
  if docker build --platform linux/amd64 --provenance=false --sbom=false \
       --label "provbind.test=unsigned-$(date +%s)" -t "$img" testbed/demo-app > "$log" 2>&1 \
     && docker push "$img" >> "$log" 2>&1; then
    echo "$PROVBIND_REGISTRY/$UNSIGNED@$(crane digest "$img")" > "$PROVBIND_RUN.unsigned.ref"
  else
    warn "could not build it ($log)"
    return 1
  fi
}

act_unsigned() {
  intro "an unsigned copy of the app is deployed: it fails verification" \
    "The same app, built outside the pipeline: no signature, no SBOM or provenance attestations." \
    -- "this terminal: NOT VERIFIED, no envelope; alert screen: HIGH 'Image failed verification'"
  go
  if [ ! -s "$PROVBIND_RUN.unsigned.ref" ]; then build_unsigned || return 0; fi
  local ref before
  ref=$(cat "$PROVBIND_RUN.unsigned.ref" 2>/dev/null || echo "$PROVBIND_REGISTRY/$UNSIGNED@sha256:(built once)")
  before=$(py count --cls binding)
  x deploy_temp "$UNSIGNED" "$ref"
  wait_until "$WAIT_S" "the admission decision" -- has_binding "$UNSIGNED" || true
  py binding --pod-prefix "$UNSIGNED" | result
  wait_until 20 "the alert" -- more_than "$before" --cls binding || true
  x teardown_temp "$UNSIGNED"
}

# --- commands -------------------------------------------------------------------------------------
run_demo() {
  local start=$SECONDS n acts
  validate
  read -r -a acts <<< "$ACTS"
  echo "${B}PROVBIND live demo${N} · ${acts[*]} · attack $ATTACK · trust $TRUST · pause $PAUSE"
  echo "${D}  settings: $CONF (make live-demo-settings) · run folder $PROVBIND_RUN · audience screen: make live-demo-view${N}"
  prepare
  if ! has_act envelope; then
    [ "$REDEPLOY" != 1 ] || deploy_app     # REDEPLOY=1 deleted it; no envelope act will deploy it
    wait_envelope quiet || { warn "the app has no envelope"; exit 1; }
  fi
  ACT_TOTAL=${#acts[@]}; ACT_N=0
  for n in "${acts[@]}"; do
    ACT_N=$((ACT_N + 1)); ACT_NAME=$n
    if ! "act_$n" && [ "$n" = envelope ]; then exit 1; fi
    [ "$ACT_N" -ge "$ACT_TOTAL" ] || between
  done
  echo; echo "${B}done in $(( SECONDS - start )) s${N} ${D}· again: make live-demo · change it: $CONF${N}"
}

run_one() {                # NAME: one act, on the running services (started if none are running)
  case " $ALL_ACTS " in *" ${1:-none} "*) ;; *) echo "usage: scripts/live-demo.sh act {${ALL_ACTS// /|}}" >&2; exit 2 ;; esac
  validate
  FRESH=0                  # keep the services and the folder; undo an earlier trust change
  [ "$1" = envelope ] || REDEPLOY=0        # only the envelope act deploys the app
  prepare
  ACT_TOTAL=1; ACT_N=1; ACT_NAME=$1
  if [ "$1" != envelope ]; then wait_envelope quiet || { warn "the app has no envelope"; exit 1; }; fi
  "act_$1"
}

check_ready() {            # one line per item; returns 1 if something required is missing
  local missing=0
  item() {                 # required|optional LABEL -- COMMAND...
    local kind=$1 label=$2; shift 3
    if [ "$DRY_RUN" = 1 ]; then x "$@"; return 0; fi
    if "$@" >/dev/null 2>&1; then ok "$label"
    elif [ "$kind" = required ]; then warn "$label"; missing=1
    else printf '      %s-%s %s (optional)\n' "$Y" "$N" "$label"; fi
  }
  validate
  echo "${B}check${N}"
  item required "kubectl, curl and python3 are installed" -- command -v kubectl curl python3
  item required "the cluster answers" -- kubectl get nodes
  item required "namespace $NAMESPACE exists" -- kubectl get namespace "$NAMESPACE"
  item required "Tetragon is running" -- kubectl -n kube-system rollout status ds/tetragon --timeout=10s
  item required "the local registry answers ($PROVBIND_REGISTRY)" -- curl -sf "http://$PROVBIND_REGISTRY/v2/"
  item required "a signed image is known (DEMO_REF, the deployment, or demo-app:latest)" -- resolve_ref
  item required "the public key exists ($PROVBIND_KEY)" -- test -s "$PROVBIND_KEY"
  item required "PROVBIND's modules import" -- python3 -c \
    'import controller.watch, node.run, alerts.run, alerts.trust, alerts.verify_log, eval.demo_view, eval.live_demo'
  if [ "$FALCO" != off ]; then
    item optional "Falco is running (the shell and attack acts compare with it)" -- falco_running
  fi
  if has_act unsigned; then
    item required "docker and crane are installed (the unsigned act)" -- command -v docker crane
  fi
  if [ "$NEO4J" = on ]; then
    item optional "Neo4j answers (NEO4J=on loads each run's graph into it)" -- curl -sf http://localhost:7474
  fi
  return "$missing"
}

setup() {
  check_ready || { warn "fix the items marked ! first"; exit 1; }
  echo "${B}setup${N}"
  ensure_app
  if has_act unsigned && [ ! -s "$PROVBIND_RUN.unsigned.ref" ]; then build_unsigned || true; fi
  ok "ready: make live-demo-view in one terminal, make live-demo in the other"
}

show_settings() {
  local k
  validate
  echo "${B}settings${N} ${D}(command line or environment > $CONF > default)${N}"
  for k in $SETTINGS; do printf '  %-19s %-36s %s%s%s\n' "$k" "${!k}" "$D" "${FROM[$k]:-default}" "$N"; done
  printf '  %-19s %s\n' PROVBIND_RUN "$PROVBIND_RUN"
}

diagnose() {               # what the last run saw: for an act that showed no alert (reads only)
  echo "${B}diagnose${N} ${D}($PROVBIND_RUN)${N}"
  echo "  start times (the app must start after the sensor):"
  kubectl -n "$NAMESPACE" get pods -l "app=$DEPLOY" -o jsonpath='{range .items[*]}    app     {.metadata.name}  {.status.containerStatuses[0].state.running.startedAt}{"\n"}{end}' 2>&1 || true
  kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o jsonpath='{range .items[*]}    sensor  {.metadata.name}  {.status.containerStatuses[0].state.running.startedAt}  ready {.status.conditions[?(@.type=="Ready")].lastTransitionTime}{"\n"}{end}' 2>&1 || true
  if app_older_than_sensor 2>/dev/null; then echo "    -> the app started BEFORE the sensor was ready"; else echo "    -> order ok"; fi
  echo "  last sensor check passed for: $(cat "$PROVBIND_RUN.probe" 2>/dev/null || echo 'none yet')"
  echo "  sensor policies in $NAMESPACE: $(kubectl get tracingpoliciesnamespaced -n "$NAMESPACE" -o name 2>/dev/null | tr '\n' ' ')"
  python3 - "$PROVBIND_RUN" <<'PY'
import collections, json, sys
from pathlib import Path
run = Path(sys.argv[1])
def lines(name):
    try:
        return (run / name).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
def classes(name):
    c = collections.Counter()
    for line in lines(name):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict):
            c[f"{d.get('class')}/{d.get('subclass')}"] += 1
    return ", ".join(f"{k} x{v}" for k, v in sorted(c.items())) or "none"
rec = lines("rec.jsonl")
writes = [l for l in rec if "security_file_permission" in l]
print(f"  sensor events: {len(rec)}; writes: {len(writes)}; writes to /etc/passwd: {sum('/etc/passwd' in l for l in writes)}")
for line in writes[:8]:
    try:
        k = json.loads(line).get("process_kprobe") or {}
        path = next((a["file_arg"].get("path") for a in k.get("args") or [] if "file_arg" in a), "?")
        print(f"    write  {(k.get('process') or {}).get('binary', '?')} -> {path}")
    except (ValueError, AttributeError, TypeError):
        continue
print(f"  detections: {classes('detections.jsonl')}")
print(f"  alerts: {classes('alerts.jsonl')}")
neo = [l.strip()[:150] for l in lines("logs/alerts.log") if "neo4j" in l.lower()]
print("  alert engine and Neo4j:" + ("".join(f"\n    {l}" for l in neo[:4]) or " no Neo4j lines"))
PY
}

reset_demo() {
  echo "${B}reset${N}"
  x rm -f "$PROVBIND_RUN"/advisories/*.json
  xq python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --key "$PROVBIND_KEY" --state active 2>/dev/null || true
  restore_log
  x teardown_temp "$UNSIGNED"
  ok "advisories removed, key active, log restored, test deployment removed"
}

[ "${BASH_SOURCE[0]}" = "$0" ] || return 0     # sourced (the tests): the functions only

case "${1:-run}" in
  run) run_demo ;;
  act) run_one "${2:-}" ;;
  check) check_ready ;;
  setup) setup ;;
  settings) show_settings ;;
  reset) reset_demo ;;
  stop) stop_services; ok "PROVBIND's services stopped" ;;
  diagnose) diagnose ;;
  help|-h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" ;;
  *) echo "unknown command: $1 (try: run, act NAME, check, setup, settings, reset, stop, diagnose, help)" >&2; exit 2 ;;
esac
