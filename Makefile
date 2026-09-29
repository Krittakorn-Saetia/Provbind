# PROVBIND Makefile. Role 1 owns the testbed and evaluation targets below (Sprint Handoff §3.3).
# Role 4 extends this file with the controller, alerts and `make demo` targets; Roles 2 and 3
# drive their steps through the commands documented in the handoff.
#
# All parts talk through $(PROVBIND_RUN) (default ./run). Cluster targets (up/down, scenarios,
# profiling, Falco capture) need the demo PC (Docker, kind, Tetragon, Falco). The `test`,
# `compare`, `report` and `corpus-check` targets run anywhere.

PROVBIND_RUN ?= ./run
export PROVBIND_RUN

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
	helm upgrade --install tetragon cilium/tetragon -n kube-system
	kubectl rollout status -n kube-system ds/tetragon
	helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
	  --set driver.kind=modern_ebpf --set falco.json_output=true
	docker rm -f neo4j >/dev/null 2>&1 || true
	docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/provbind-demo neo4j:5
	kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -

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

falco-capture:  ## stream Falco JSON into $(PROVBIND_RUN)/falco.jsonl (run in the background)
	./eval/capture_falco.sh

profile:  ## profile the ML-A corpus for capability labels (MLA-03); writes ml/data/labels.jsonl
	./testbed/profile_corpus.sh

## --- runs anywhere -------------------------------------------------------------------------

assemble-labels:  ## rebuild ml/data/labels.jsonl from captured events under ml/data/raw
	python3 -m testbed.profiling.run --raw ml/data/raw --out ml/data/labels.jsonl

compare:  ## print the PROVBIND vs Falco vs ground-truth table (EV-01)
	python3 -m eval.compare --run $(PROVBIND_RUN)

report:  ## write $(PROVBIND_RUN)/results/REPORT.md from the recorded results
	python3 -m eval.report --run $(PROVBIND_RUN)

corpus-check:  ## sanity-check ml/corpus.yaml
	python3 -m pytest -q tests/testbed/test_corpus.py

test:  ## run the unit and capability tests that run anywhere
	python3 -m pytest -q -m "not integration"

## --- Role 4: controller, alerts, trust loop, demo (Sprint Handoff §3.3, §8) -------------------------

PROVBIND_KEY ?= pipeline/keys/cosign.pub

.PHONY: controller alerts trust-loop show verify-log check-contracts demo

controller:  ## watch pods in namespace demo: verify, store the context, bind, compile
	python3 -m controller.watch --run $(PROVBIND_RUN) --key $(PROVBIND_KEY)

alerts:  ## tail detections.jsonl into alerts.jsonl and the violation log
	python3 -m alerts.run --run $(PROVBIND_RUN)

trust-loop:  ## re-evaluate trust every 300 s and on any change to keystatus.json or advisories/
	python3 -m alerts.trust --run $(PROVBIND_RUN)

show:  ## print the alerts, one line each
	python3 -m alerts.show --run $(PROVBIND_RUN)

verify-log:  ## recompute the violation log's hash chain; exit 1 at the first broken record
	python3 -m alerts.verify_log --run $(PROVBIND_RUN)

check-contracts:  ## check the run folder against the Sprint Handoff §4 contracts
	python3 contracts/check_contracts.py --run $(PROVBIND_RUN)

demo:  ## the Sprint Handoff §1.1 demo, after make up and make demo-app (needs DEMO_REF=<ref@digest>)
	./scripts/demo.sh
