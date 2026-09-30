# PROVBIND Makefile. Role 1 owns the testbed and evaluation targets below (Sprint Handoff §3.3).
# Role 4 extends this file with the controller, alerts and `make demo` targets; Roles 2 and 3
# drive their steps through the commands documented in the handoff.
#
# All parts talk through $(PROVBIND_RUN) (default ./run). Cluster targets (up/down, scenarios,
# profiling, Falco capture) need the demo PC (Docker, kind, Tetragon, Falco). The `test`,
# `compare`, `report` and `corpus-check` targets run anywhere.

PROVBIND_RUN ?= ./run
export PROVBIND_RUN

# Role 3's Tetragon values (export filter, enablePolicyFilter for the namespaced write and truncate
# policies), once node/ is merged. Without them the chart's defaults may drop every write event.
TETRAGON_VALUES := $(if $(wildcard node/tetragon/values.yaml),-f node/tetragon/values.yaml,)

.PHONY: help up down demo-app benign attack attack2 trust tamper falco-capture \
        profile assemble-labels compare report corpus-check test

help:  ## list the targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

## --- cluster (demo PC) ---------------------------------------------------------------------

up:  ## start kind + registry, Tetragon, Falco, Neo4j, and the demo namespace (Sprint Handoff §10)
	./testbed/kind-with-registry.sh
	helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
	helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
	helm repo update >/dev/null
	helm upgrade --install tetragon cilium/tetragon -n kube-system $(TETRAGON_VALUES)
	kubectl rollout status -n kube-system ds/tetragon
	kubectl rollout status -n kube-system deploy/tetragon-operator --timeout=300s
	until kubectl get crd tracingpoliciesnamespaced.cilium.io >/dev/null 2>&1; do sleep 2; done
	kubectl wait --for condition=established --timeout=120s crd/tracingpoliciesnamespaced.cilium.io
	helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
	  --set driver.kind=modern_ebpf --set falco.json_output=true
	docker rm -f neo4j >/dev/null 2>&1 || true
	docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/provbind-demo neo4j:5
	kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
	$(if $(wildcard node/tetragon/cap.yaml),kubectl apply -f node/tetragon/write.yaml -f node/tetragon/truncate.yaml -f node/tetragon/cap.yaml,@echo "make up: node/tetragon/ is not merged yet; apply Role 3's policies once it is")

down:  ## tear the cluster and the registry down
	kind delete cluster || true
	docker rm -f kind-registry neo4j >/dev/null 2>&1 || true

demo-app:  ## build, push, sign and attest the demo app into the local registry (needs Role 2's pipeline)
	pipeline/build-and-attest.sh testbed/demo-app demo-app

benign:  ## run the benign-1 scenario and append its ground-truth row
	./testbed/scenarios/benign.sh

attack:  ## run the attack-1 scenario (undeclared exec + declared write)
	./testbed/scenarios/attack.sh

attack2:  ## run the attack-2 scenario (in-envelope burst, expects D_beh)
	./testbed/scenarios/attack2.sh

trust:  ## run the trust-1 scenario (mark requestz-helper malicious in the local advisory)
	./testbed/scenarios/trust.sh

tamper:  ## run the tamper-1 scenario (edit one character in the violation log)
	./testbed/scenarios/tamper.sh

.PHONY: trust2 ph4-14

trust2:  ## run the trust-2 scenario (our key revoked in keystatus.json); RESTORE=1 undoes it
	./testbed/scenarios/trust2.sh

.PHONY: benign-traffic

benign-traffic:  ## ordinary app requests and cache writes, no kubectl exec (balances trust-2 in make scored)
	./testbed/scenarios/benign_traffic.sh

ph4-14:  ## write the new file /tmp/new.txt in the demo pod inside a ph4-14 row (Role 3's PH4-14)
	./testbed/scenarios/ph4_14.sh

.PHONY: loadgen

loadgen:  ## benign load for ML-B's dataset D2: 4 h by default, DURATION=3600 for the held-out hour
	./testbed/loadgen.sh

falco-capture:  ## stream Falco JSON into $(PROVBIND_RUN)/falco.jsonl (run in the background)
	./eval/capture_falco.sh

profile:  ## profile the ML-A corpus for capability labels (MLA-03); writes ml/data/labels.jsonl
	./testbed/profile_corpus.sh

## --- runs anywhere -------------------------------------------------------------------------

assemble-labels:  ## rebuild ml/data/labels.jsonl from captured events under ml/data/raw
	python3 -m testbed.profiling.run --raw ml/data/raw --out ml/data/labels.jsonl

compare:  ## the PROVBIND vs Falco table and scoring matrix (EV-01); writes results/SCORING.md
	python3 -m eval.compare --run $(PROVBIND_RUN) --write

report:  ## write $(PROVBIND_RUN)/results/REPORT.md from the recorded results
	python3 -m eval.report --run $(PROVBIND_RUN)

corpus-check:  ## sanity-check ml/corpus.yaml
	python3 -m pytest -q tests/testbed/test_corpus.py

test:  ## run the unit and capability tests that run anywhere
	python3 -m pytest -q -m "not integration"

## --- Role 4: controller, alerts, trust loop, demo (Sprint Handoff §3.3, §8) -------------------------

PROVBIND_KEY ?= pipeline/keys/cosign.pub

.PHONY: controller alerts graph trust-loop show verify-log check-contracts demo

controller:  ## watch pods in namespace demo: verify, store the context, bind, compile
	python3 -m controller.watch --run $(PROVBIND_RUN) --key $(PROVBIND_KEY)

alerts:  ## tail detections.jsonl into alerts.jsonl and the violation log
	python3 -m alerts.run --run $(PROVBIND_RUN)

graph:  ## load every envelope (and its SBOM edges) into Neo4j; alerts also loads new ones
	python3 -m alerts.attribute --run $(PROVBIND_RUN)

trust-loop:  ## re-evaluate trust every 300 s and on any change to keystatus.json or advisories/
	python3 -m alerts.trust --run $(PROVBIND_RUN)

show:  ## print the alerts, one line each
	python3 -m alerts.show --run $(PROVBIND_RUN)

verify-log:  ## recompute the violation log's hash chain; exit 1 at the first broken record
	python3 -m alerts.verify_log --run $(PROVBIND_RUN)

check-contracts:  ## check the run folder against the Sprint Handoff §4 contracts
	python3 contracts/check_contracts.py --run $(PROVBIND_RUN)

## --- comparison Tier 2 scenarios (demo PC; comparison test plan §3) ------------------------------

.PHONY: rk2 rk3 ru3 ru4 ru5 benign-dns benign-vol au2 ak1 ak2 ak3 au2-deploy comparison

rk2:  ## R-K2: replay a known kernel-CVE syscall shape (waitid, splice), no exploit
	./testbed/scenarios/rk2.sh

rk3:  ## R-K3: LD_PRELOAD an embedded harmless .so (library injection); expects D_load
	./testbed/scenarios/rk3.sh

ru3:  ## R-U3: connect to a never-routed test address, no data sent; expects D_net
	./testbed/scenarios/ru3.sh

ru4:  ## R-U4: overwrite the declared /usr/bin/ls then restore it; expects D_write
	./testbed/scenarios/ru4.sh

ru5:  ## R-U5: read the SA token, send only its digest to an allowed sink (PROVBIND blind spot)
	./testbed/scenarios/ru5.sh

benign-dns:  ## B4: benign DNS lookups; expects nothing above Low
	./testbed/scenarios/benign_dns.sh

benign-vol:  ## B5: benign writes under a mounted volume; expects nothing above Low
	./testbed/scenarios/benign_vol.sh

au2:  ## A-U2 trigger only: run the build-time program (needs the au-2 variant pod; see au2-deploy)
	./testbed/scenarios/au2.sh

ak1:  ## A-K1: a MAL- advisory exists before deploy; expects a trust alert at admission (needs DEMO_REF)
	./testbed/scenarios/deploy-advisory-first.sh

ak2:  ## A-K2: deploy an unsigned image copy; expects a binding failure
	./testbed/scenarios/deploy-unsigned.sh

ak3:  ## A-K3: key revoked before deploy; expects rejection at admission (needs DEMO_REF)
	./testbed/scenarios/deploy-revoked-key.sh

au2-deploy:  ## A-U2: build+sign the au-2 variant, deploy it, run the build-time program
	./testbed/scenarios/deploy-au2.sh

comparison:  ## the full four-system comparison run: traces every scenario, runs the estimators + aggregator (needs DEMO_REF)
	./scripts/comparison-run.sh

.PHONY: scored

scored:  ## Role 1's balanced scored run: ROUNDS x (benign, attack, trust, ph4-14, trust2, benign-traffic), tamper, compare (needs DEMO_REF)
	./scripts/scored-run.sh

demo:  ## the Sprint Handoff §1.1 demo, after make up and make demo-app (needs DEMO_REF=<ref@digest>)
	./scripts/demo.sh
