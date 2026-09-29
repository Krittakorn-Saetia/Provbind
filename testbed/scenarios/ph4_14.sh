#!/usr/bin/env bash
# ph4-14 (Role 3's PH4-14; Role 3 handoff §4): write a NEW file, /tmp/new.txt, in the demo pod, inside a
# ground-truth row named `ph4-14`. Expected: no write detection, because a file that is in no image
# layer is conforming. Role 3's replay judges only the events inside this row.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
START="$(now)"
kubectl exec -n "$NAMESPACE" "deploy/$DEPLOY" -- sh -c 'echo x > /tmp/new.txt'
sleep 10
END="$(now)"

record_gt ph4-14 benign "$START" "$END" "no write detection: /tmp/new.txt is a new file"
echo "ph4-14 recorded: $START .. $END"
