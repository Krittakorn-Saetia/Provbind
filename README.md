# PROVBIND

Continuous provenance-bound runtime integrity verification for cloud-native containers. SF9-26 senior project, SIIT, Thammasat University; advisor Aj Ohm.

PROVBIND signs an image's SBOM and provenance, compiles them into an **envelope** (files and hashes, owning packages, dependency depth, the entrypoint's executable closure, expected capabilities), and checks every runtime exec and write event seen by Tetragon against it.

**Status, 27 September 2026:** 4-day prototype sprint plus capability testing. Aj Ohm's draft (`docs/reference/PROVBIND_AjOhmdraft.pdf`) is the reference version of the paper, and his instruction is to understand, check and update it.

**Evaluation, 9 October 2026:** finished. The results are in `docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md`;
the paper figures and the numbers behind them are in `docs/FIGURES-HOWTO.md`.

## Start here

| Read | Why |
|---|---|
| `docs/PROVBIND-Sprint-Handoff.md` (v1.1) | The team plan: roles, run folder, contracts, schedule |
| `docs/PROVBIND-Capability-Test-Plan.md` (v1.2) | All 113 tests, the datasets (Section 12) and the update log, with a proposed Results section (Section 10.1) |
| `docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md` | The evaluation's final results: accuracy, runtime cost, the zero-day method, preparation time |
| `docs/FIGURES-HOWTO.md` | How to draw the paper figures from the repository, and where the final numbers are |
| `docs/ROLE2-HANDOFF.md` (v0.2) | Role 2 spec: evidence pipeline, envelope compiler, ML-A |
| `docs/PROVBIND-Explanation-and-Review.md` | The design behind every phase, and the 31 fail points in the draft |
| `docs/PROVBIND-Source-Answers.md` | Project questions answered from the documents, with sources |
| `docs/PROMPTS.md` | Prompts for Claude Code, in order |
| `docs/reference/` | Aj Ohm's draft and our DS2 and DS1 drafts, read-only |

## Layout

```
contracts/   envelope schema and sample (team contract)
pipeline/    Phase 1: build-and-attest.sh, gen_provenance.py        (Role 2)
compiler/    Phase 3: envelope compiler                             (Role 2)
ml/          ML-A and ML-B data and training                        (Roles 2, 3)
node/        Phase 4: verifier; reference cuckoo filter             (Role 3)
eval/        test report; baselines                                 (Role 1)
tests/       capability tests; registry of all 113 tests
testbed/     stand-in app; tool versions                            (Role 1)
docs/        plans, specs, reference papers
scripts/     cloud-setup.sh for Claude Code on the web
```

Role 4's `controller/` and `alerts/` folders and Role 1's `testbed/demo-app/` are added by those teammates.

## Working with Claude Code on the web

- **Cloud sessions can** write code, run the unit tests (`pytest -m "not integration"`) and edit the docs.
- **Only the demo PC can** run kind, Tetragon, Falco, Neo4j and every test marked `integration`. Loading eBPF programs needs kernel privileges that a cloud sandbox is not expected to provide.
- **Environment:** set the environment's setup script to `bash scripts/cloud-setup.sh`. It installs the Python packages and, where network access allows, syft, cosign and crane.
- **First prompt:** prompt 0 in `docs/PROMPTS.md`.

## Rules

- **Contracts:** files in `contracts/` are frozen; change them only with the team (Sprint Handoff §4).
- **Keys:** never commit keys (`pipeline/keys/*.key`) or the run folder.
- **Malware:** never commit real malicious samples (Test Plan §12.4).
- **Reference files:** `docs/reference/` is read-only. Proposed changes to Aj Ohm's draft go into the update log (Test Plan §10).
- **Privacy:** keep this repository **private**; `docs/reference/` holds an unpublished paper draft.

## Commands

| Command | Does |
|---|---|
| `pip install -r requirements.txt` | Install every Python dependency |
| `pytest -m "not integration"` | Unit tests; runs anywhere |
| `pytest -m integration` | Tests that need the cluster, Tetragon or the registry; demo PC only |
| `pipeline/build-and-attest.sh <dir> <name>` | Phase 1 for one image: build, push, sign, attest the SBOM and the provenance |
| `python -m compiler.compile <ref@digest> --run $PROVBIND_RUN` | Phase 3: verify the evidence, then write `envelopes/<hex>.json` |
| `python -m compiler.compile <ref@digest> --run $PROVBIND_RUN --features-out ml/data/features.jsonl` | The same, and append the image's ML-A features (the feature side of dataset D1) |
| `python -m ml.dataset` | Join Role 1's `ml/data/labels.jsonl` (MLA-03) to the features by digest, into `ml/data/dataset.jsonl` |
| `python -m ml.train --out ml/model` | Train ML-A on D1 (cross-validated by image). The compiler uses `ml/model/` when it exists; `PROVBIND_CAPS_MODEL=none` forces the allowlist |
| `python -m eval.report --run $PROVBIND_RUN` | Capability test report, `run/results/REPORT.md` |
| `python -m eval.baselines.plot_contributions --data docs/figures/data/final-2026-10-09 --out figures` | Draw the eight paper figures from the final results (`docs/FIGURES-HOWTO.md`) |
