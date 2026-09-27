# PROVBIND Sprint Handoff: 4-Day Prototype

**Version 1.1, 27 September 2026.** For the SF9-26 team: Takorn, Korn, Sirasit and Panachai.

One shared plan for the next four days. Each person picks a role and builds against the shared contracts, all four in parallel. At the end, everything merges into one demo that runs on one PC.

**How to read this.** Everyone reads Sections 1–4 and Section 9. Then read your own role section in full, and skim the other three so you know what your teammates are building and what they need from you. Tick the boxes as you go.

**One version only.** When anyone changes this file, they bump the version number at the top and add a line to the changelog at the end. A contract (Section 4) changes only under the rules in Section 4.

The design behind every step is in the companion doc, *PROVBIND: Project Explanation and Review of Aj Ohm's Draft*. This handoff cites it as "Explanation §N".

---

## 1. Goal

By the end of Day 4, we show one working slice of PROVBIND. A signed image with a malicious dependency is caught at runtime, and the alert names the signed claim it broke. Falco watches the same actions for comparison.

**Version 1.1 widens the sprint.** Aj Ohm asked us to understand, check and update his draft, so every capability it claims is now tested, including ML-A, ML-B, the Cuckoo filter, all five event hooks and the trust loop. The *PROVBIND Capability Test Plan* lists the 113 tests, their owners and priorities. The 47 P0 tests are due at the Day 3 noon freeze.

### 1.1 The demo script

1. **Deploy.** Deploy the signed demo app by digest. The controller verifies its signature and attestations and records the binding. The compiler then writes `envelopes/<digest>.json`. Show the envelope and the image's layer graph in Neo4j.
2. **Benign action.** Run `kubectl exec -it … -- sh -c 'ls /'`.
   - PROVBIND records two Low observations: `sh` and `ls` are declared files, but they are outside the entrypoint closure.
   - Falco is expected to fire its "terminal shell in container" rule. Record what it actually does.
3. **Attack.** Call the app's `/update` endpoint. The malicious package writes an embedded payload to `/tmp/.x9` and runs it, and the payload appends a line to `/etc/passwd`.
   - PROVBIND raises two alerts in one chain: **D_exec undeclared (Critical, 90)** and **D_write on `/etc/passwd` (High, 72)**. Both carry the builder and commit from the signed provenance.
   - Record what Falco reports, honestly.
4. **In-envelope attack.** Call `/update2`. The package writes 300 new files under `/tmp/.cache` and reads them back, using only declared binaries.
   - No deterministic detection fires; ML-B raises one behavioural alert (Test Plan MLB-05).
5. **Trust withdrawal.** Mark `requestz-helper` malicious in the local advisory file. One trust alert appears while the pod still conforms at runtime (PH6-04, E2E-11).
6. **Tamper.** Change one character in the violation log. `verify_log` reports the first broken record.
7. **Compare.** Show the table (scenario, ground truth, PROVBIND, Falco) and the capability test report (`run/results/REPORT.md`).

### 1.2 In scope

| Phase | What we build in four days |
|---|---|
| 1 | Build, SBOM, provenance; sign and attest with a cosign key file |
| 2 | Controller verifies signatures and attestations, records container → digest |
| 3 | Files and layers, closure, SBOM depth, ownership for pip and dpkg; ML-A (LightGBM) trained on a profiled corpus, with the curated capability list as its baseline |
| 4 | Tetragon exec, write, executable-mmap, capability and connect events; the deterministic verifier with its decision order; the Cuckoo filter, measured against a plain index; ML-B (Isolation Forest) |
| 5 | Scoring, layer attribution through Neo4j, alerts, hash-chained log, chains by process ancestry |
| 6 | Trust re-evaluation, with key state emulated in `run/keystatus.json` and a local advisory file |
| Evaluation | The scenarios in Test Plan §7, PROVBIND against Falco (and ML-C when ready): P0 qualitative, P1 counts |

### 1.3 Out of scope

Say so plainly in the talk:

- Kyverno enforcement and a real KMS; key state is emulated in `run/keystatus.json`.
- Overhead numbers on bare metal. Laptop numbers are indicative only.
- The full SynthChain reconstruction and the low-and-slow mimicry attack.
- ML-A accuracy beyond a feasibility result on 20–40 images.

### 1.4 How to present it

- **Call it a proof of concept** of the core verification loop. Show which capabilities passed their tests, from `REPORT.md`, and say which results are P0 demonstrations and which are measurements.
- **Each person presents their own part,** in pipeline order. The panel then sees that each of us knows how our piece connects to the next one.
- **Record the demo on Day 4 as a backup video.** Live demos fail.

---

## 2. Pick a role

Write your name in the last column at the kickoff.

| Role | You build | Phases | You need from | You hand over | Good fit if you know | Taken by |
|---|---|---|---|---|---|---|
| **1. Testbed and evaluation** | Demo PC, demo app and malicious package, scenarios, Falco capture, comparison, backup video | Eval | Nobody; you start first | Running cluster, demo-app source, ground truth, results table | Docker, Kubernetes basics, bash, a little C | |
| **2. Evidence and compiler** | Build-and-attest script, envelope compiler | 1, 3 | Role 1: demo-app source | Signed image, `envelopes/<digest>.json` | Python, Linux file systems and packaging | |
| **3. Node runtime** | Tetragon policies, event normaliser, verifier | 4 | Role 2: envelopes; Role 4: bindings (use samples until then) | `detections.jsonl` | Linux internals, Python | |
| **4. Alerts and integration** | Repo, controller, scoring, attribution, log, `make demo` | 2, 5 | Role 3: detections; Role 2: envelopes | `bindings.json`, alerts, log, the demo | Python, Kubernetes API, Neo4j | |

Role 2 carries the most code. Role 1 is the lightest after Day 2 and backs up anyone who falls behind. Because every role is written out in full below, anyone can pick up another person's tasks.

---

## 3. How the pieces fit

### 3.1 Data flow

```
Role 1  demo-app source ----> Role 2  build-and-attest.sh ----> signed image (localhost:5001)
                                                                   | kubectl apply, by digest
Role 4  controller: cosign verify --> bindings.json                v
        and calls ------------------> Role 2  compiler ----> envelopes/<digest>.json
                                                                   |
Tetragon (kind) --JSON--> Role 3  normalize -> verify <------------+
                                                 |
                                          detections.jsonl
                                                 v
Role 4  alerts: score -> attribute (Neo4j) -> chain -> alerts.jsonl + log/violations.jsonl
                                                 v
Role 1  compare: PROVBIND vs Falco vs ground_truth.csv -> results table
```

### 3.2 The run folder

All parts talk through one folder, `$PROVBIND_RUN` (default `./run`), using plain files. Nobody runs a server for another part, so each part can be tested alone and any run can be replayed.

| Path | Written by | Read by |
|---|---|---|
| `attest/<name>/` (SBOM, provenance, cosign output) | Role 2 | Role 2 |
| `envelopes/<digest>.json` | Role 2 | Roles 3, 4 |
| `bindings.json` | Role 4 | Roles 1, 3 |
| `events.jsonl` (normalised copy, for replay) | Role 3 | Roles 3, 1 |
| `detections.jsonl` | Role 3 | Role 4 |
| `alerts.jsonl` | Role 4 | Role 1 |
| `log/violations.jsonl` | Role 4 | Anyone (`verify_log`) |
| `falco.jsonl` | Role 1 | Role 1 |
| `ground_truth.csv` | Role 1 | Role 1 |
| `results/<ID>.json`, `results/REPORT.md` | Every role (one file per test) | Everyone |

JSONL files are append-only, one JSON object per line. `bindings.json` is always rewritten whole: write a temporary file, then rename it, so readers never see half a file.

### 3.3 Commands each part must provide

These commands are contracts too. `make demo` calls them in this form.

| Command | Owner | What it does |
|---|---|---|
| `make up` / `make down` | 1 | Start or stop cluster, registry, Tetragon, Falco, Neo4j |
| `pipeline/build-and-attest.sh <dir> <name>` | 2 | Build, push, SBOM, provenance, sign, attest; prints `ref@digest` |
| `python -m compiler.compile <ref@digest> --run $RUN` | 2 | Writes `envelopes/<digest>.json`; exit code 0 on success |
| `python -m controller.watch --run $RUN` | 4 | Watches pods in `demo`, verifies, writes bindings, runs the compiler for new digests |
| `python -m node.run --run $RUN` | 3 | Reads Tetragon JSON on stdin; appends events and detections |
| `python -m alerts.run --run $RUN` | 4 | Tails detections; writes alerts and the log |
| `python -m alerts.show --run $RUN` | 4 | Readable alert view for the demo screen |
| `python -m alerts.verify_log --run $RUN` | 4 | Recomputes the chain; prints the first broken record |
| `make benign` / `make attack` | 1 | Runs a scenario and appends its ground-truth row |
| `python -m eval.compare --run $RUN` | 1 | Prints the PROVBIND vs Falco vs ground-truth table |
| `python -m eval.report --run $RUN` | 1 | Writes the capability test report, `results/REPORT.md` |
| `make demo` | 4 | Runs the Section 1.1 script in order |

### 3.4 Repository

- **Branches.** One Git repo, one branch per role, merged into `main` at each merge point (Section 9). From the Day 2 merge on, `main` must always run.
- **Python.** Use Python 3.11 everywhere, with one shared `requirements.txt`.
- **Keys.** Never commit `cosign.key`; share it privately.

```
provbind/
  contracts/   Section 4 samples + check_contracts.py                (all; Role 4 keeps it)
  testbed/     kind + registry script, helm values, demo-app/, scenarios/   (Role 1)
  eval/        falco capture, compare.py                                (Role 1)
  pipeline/    build-and-attest.sh, gen_provenance.py, keys/cosign.pub (Role 2)
  compiler/    compile.py, layers.py, sbom.py, owners.py, closure.py,
               caps_allowlist.json                                      (Role 2)
  node/        tetragon/*.yaml, normalize.py, verify.py, run.py, testdata/  (Role 3)
  controller/  watch.py                                                 (Role 4)
  alerts/      run.py, score.py, attribute.py, log.py, show.py, verify_log.py  (Role 4)
  Makefile
```

---

## 4. The contracts

The contracts are frozen at the end of the Day 1 kickoff.

- **Changing one.** A change needs the producer and every consumer to agree, a bump of the `schema` field, and updated samples in `contracts/`.
- **Adding and renaming fields.** Readers ignore fields they don't know, so adding a field is cheap. Renaming or removing a field after Day 1 is not allowed.
- **Paths.** All paths are **real absolute paths inside the container**, with every symlink resolved. Debian-based images have `/bin → usr/bin`, so `ls` is `/usr/bin/ls` and `sh` is `/usr/bin/dash`. Tetragon also reports resolved paths.
- **Formats.** Times are UTC ISO 8601. Digests are `sha256:<64 hex>`.

Every value below is illustrative.

### 4.1 `envelopes/<digest>.json` (Role 2 → Roles 3, 4)

```json
{
  "schema": "provbind.envelope/v0",
  "image": {
    "ref": "localhost:5001/demo-app@sha256:1111…",
    "digest": "sha256:1111…",
    "builder_id": "sf9-26/local-build",
    "source_commit": "9f31ab2",
    "rekor_log_index": 123456789
  },
  "layers": [
    { "index": 0, "digest": "sha256:aaaa…" },
    { "index": 5, "digest": "sha256:ffff…" }
  ],
  "files": {
    "/usr/local/bin/python3.11": { "sha256": "5e8f…", "layer": 2, "package": null, "mode": "0755" },
    "/usr/bin/ls":   { "sha256": "c0ff…", "layer": 0, "package": "pkg:deb/debian/coreutils@9.1-1", "mode": "0755" },
    "/usr/bin/dash": { "sha256": "d4a5…", "layer": 0, "package": "pkg:deb/debian/dash@0.5.12-2", "mode": "0755" },
    "/etc/passwd":   { "sha256": "ab12…", "layer": 0, "package": null, "mode": "0644" },
    "/app/app.py":   { "sha256": "77aa…", "layer": 5, "package": null, "mode": "0644" }
  },
  "symlinks": {
    "/bin": "/usr/bin",
    "/usr/local/bin/python": "/usr/local/bin/python3",
    "/usr/local/bin/python3": "/usr/local/bin/python3.11"
  },
  "closure": [
    "/usr/local/bin/python3.11",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/local/lib/libpython3.11.so.1.0"
  ],
  "packages": {
    "pkg:pypi/requestz-helper@0.1.0": { "depth": 1 },
    "pkg:deb/debian/coreutils@9.1-1": { "depth": null }
  },
  "capabilities": [ { "cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED" } ],
  "unresolved_fraction": 0.62,
  "compiled_at": "2026-09-28T09:00:00Z"
}
```

- `files` holds regular files only, after whiteouts, keyed by real path. `layer` is an index into `layers`.
- `closure` holds the real paths reachable from the entrypoint.
- `package: null` means no package record owns the file; `depth: null` means the depth is unresolved.
- `capabilities` comes from the curated list for now, so every entry is `INFERRED`.

### 4.2 `bindings.json` (Role 4 → Roles 1, 3)

```json
{
  "containerd://4b1c…": {
    "namespace": "demo", "pod": "demo-app-7d9f", "container": "app",
    "image_digest": "sha256:1111…",
    "verified": true,
    "run_as_root": true, "privileged": false,
    "mounts": ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
               "/dev/termination-log", "/var/run/secrets/kubernetes.io/serviceaccount"],
    "envelope_ready": true
  }
}
```

- `mounts` lists the container's volume mount paths plus the files Kubernetes manages. Role 3 never reports writes under them.
- `envelope_ready` becomes true once the envelope file exists. Role 1's attack script waits for it.

### 4.3 `events.jsonl` (Role 3, also used for replay)

One object per line:

```json
{"time":"2026-09-28T10:14:22.123Z","kind":"exec","container_id":"containerd://4b1c…","namespace":"demo","pod":"demo-app-7d9f","container":"app","pid":4471,"ppid":4402,"exe":"/tmp/.x9","parent_exe":"/usr/local/bin/python3.11","hash":null}
{"time":"2026-09-28T10:14:22.140Z","kind":"write","container_id":"containerd://4b1c…","namespace":"demo","pod":"demo-app-7d9f","container":"app","pid":4471,"ppid":4402,"exe":"/tmp/.x9","parent_exe":"/usr/local/bin/python3.11","path":"/etc/passwd"}
```

### 4.4 `detections.jsonl` (Role 3 → Role 4)

Shown across several lines here; in the file it is one line.

```json
{
  "id": "det-0001",
  "time": "2026-09-28T10:14:22.123Z",
  "container_id": "containerd://4b1c…",
  "namespace": "demo", "pod": "demo-app-7d9f", "container": "app",
  "image_digest": "sha256:1111…",
  "pid": 4471, "ppid": 4402,
  "exe": "/tmp/.x9", "parent_exe": "/usr/local/bin/python3.11",
  "class": "D_exec", "subclass": "undeclared",
  "clause": { "kind": "file_set", "path": "/tmp/.x9",
              "detail": "path is in no layer of the attested image" },
  "origin": "AUTHENTICATED",
  "context": { "declared": false, "package": null, "depth": null, "layer": null }
}
```

| `class` | `subclass` | Meaning |
|---|---|---|
| `D_exec` | `undeclared` | The executed file is in no layer |
| `D_exec` | `outside_closure` | A declared file, not reachable from the entrypoint |
| `D_write` | `declared_file` | A write to a file that is in the image and not under a mount |
| `D_hash` | `modified` | Declared path, different content (needs runtime hashing; stretch) |
| `D_hash` | `relocated` | Declared content at a new path (stretch) |
| `binding` | `unknown_container` | An event from a container with no binding |

### 4.5 `alerts.jsonl` (Role 4 → Role 1)

```json
{
  "alert_id": "alr-0001",
  "detection_id": "det-0001",
  "time": "2026-09-28T10:14:22.123Z",
  "image_digest": "sha256:1111…",
  "container": "demo/demo-app-7d9f/app",
  "class": "D_exec", "subclass": "undeclared",
  "violated_clause": "file_set: /tmp/.x9 is in no layer of the attested image",
  "origin": "AUTHENTICATED",
  "score": 90, "bucket": "critical",
  "attribution": {
    "layer": null, "package": null, "depth": null,
    "process_chain": ["/usr/local/bin/python3.11", "/tmp/.x9"]
  },
  "signing_identity": {
    "builder_id": "sf9-26/local-build", "source_commit": "9f31ab2",
    "rekor_log_index": 123456789
  },
  "chain_id": "chain-0001",
  "log_k": 1
}
```

### 4.6 `log/violations.jsonl` (Role 4)

```json
{"k": 1, "prev": "0000…0000", "hash": "3a7f…", "record": {"...": "the alert object"}}
```

The hash rule, exactly. Anyone must be able to recompute it.

```python
canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
h = hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canon).digest()).hexdigest()
# prev for k = 1 is 64 zeros; prev for k > 1 is the hash of record k - 1
```

### 4.7 `ground_truth.csv` (Role 1)

```
scenario,label,namespace,pod_prefix,start,end,expected
benign-1,benign,demo,demo-app,2026-09-28T10:20:00Z,2026-09-28T10:21:00Z,nothing above Low
attack-1,malicious,demo,demo-app,2026-09-28T10:14:00Z,2026-09-28T10:15:00Z,D_exec undeclared + D_write
```

---

## 5. Role 1: Testbed and evaluation

**You own:** the demo PC, the demo app and its malicious dependency, the two scenarios, Falco's output, the comparison table and the backup video.

**Your tests** (Capability Test Plan, owner R1). P0: MLA-03 (profiling the ML-A corpus with Role 3's capability policy), E2E-01 to 03, E2E-11, E2E-12, EV-01. Your P1 and P2 tests are in `registry.json`.

**You start first,** because everyone else deploys onto your PC.

### Day 1

- [ ] Set up the PC as in Section 10 until every smoke test passes. Give the team SSH access.
- [ ] Write `testbed/demo-app/`:
  - `app.py`: a small HTTP server on port 8080 with `/` (returns `ok`) and `/update` (calls `requestz_helper.check_update()`).
  - `Dockerfile`: `FROM python:3.11-slim@sha256:…`, pinned by digest.
  - `requirements.txt`: names `requestz-helper==0.1.0`, installed from a local wheel in the build context.
- [ ] Write `testbed/demo-app/requestz_helper/`, the test "malicious" package. `check_update()` decodes a base64 payload stored inside the package, writes it to `/tmp/.x9`, sets mode 755 and starts it in the background.
- [ ] Write the payload, `x9.c`. It appends `provbind-test:x:0:0::/:/bin/false` to `/etc/passwd`, then sleeps 600 s.
  - Build it static so it runs on any base image: `gcc -static -Os -s -o x9 x9.c`, then `base64 -w0 x9`.
- [ ] Hand the `demo-app/` folder to Role 2 by the end of the day.

The payload never exists as a file in the image; it sits inside a `.py` file as base64, so its hash is new. Real droppers work the same way, and it is why PROVBIND reports `/tmp/.x9` as undeclared rather than relocated.

### Day 2

- [ ] Write `testbed/scenarios/benign.sh`:
  - three `curl` calls to `/`;
  - then `kubectl exec -it -n demo deploy/demo-app -- sh -c 'ls /; cat /etc/hostname'`;
  - then append a `benign-1` row with start and end times to `ground_truth.csv`.
- [ ] Write `testbed/scenarios/attack.sh`:
  - wait until the pod's binding shows `envelope_ready: true`;
  - `curl /update`, then wait 30 s;
  - append an `attack-1` row.
- [ ] Capture Falco: `kubectl logs -n falco -l app.kubernetes.io/name=falco -f`, keep the JSON lines, write them to `run/falco.jsonl`.
- [ ] Run both scenarios with only Falco watching. Write down exactly which Falco rules fired, if any.
- [ ] Wire up `make benign` and `make attack`.

### Day 3

- [ ] Write `eval/compare.py`. It matches alerts and Falco lines to ground-truth rows by pod and time window, and prints one row per scenario: the truth, PROVBIND's alerts with their highest bucket, and Falco's rules with their priority.
- [ ] Run the full integrated demo twice. Report each failure to the owner of the failing step, with the exact command and output.

### Day 4

- [ ] Put the final comparison table into the slides.
- [ ] Record the backup video: the whole Section 1.1 script, with the terminal large enough to read.

**Done when** `make benign` and `make attack` repeat cleanly after a fresh `make up`, and `compare.py` prints the table.

**Pitfalls**

- Pin the base image by digest, or the envelope changes between runs.
- Trigger the attack only after the envelope exists. Otherwise its events land in the cold-start window.
- Keep the `-it` in `kubectl exec`: Falco's shell rule looks for a terminal.
- The payload must stay harmless and run only inside the throwaway demo container.

---

## 6. Role 2: Evidence and compiler

**You own:** every signed artifact and the envelope.

**Your tests** (owner R2). P0: PH1-01, PH1-04, PH3-01, PH3-02, PH3-04, PH3-06 to 09, MLA-01, MLA-02, MLA-04, MLA-06. ML-A is yours; the Role 2 handoff v0.2 adds it as task T13.

The compiler is the core research contribution in code. Its correctness decides whether Role 3's verdicts are right.

### Day 1

- [ ] Run `cosign generate-key-pair` in `pipeline/keys/`. Commit `cosign.pub`, never `cosign.key`. Set `COSIGN_PASSWORD` so the scripts run without prompts.
- [ ] Write `pipeline/gen_provenance.py`. It prints a SLSA v1 provenance predicate with:
  - `buildDefinition.buildType`;
  - `externalParameters`: the repo and the Dockerfile path;
  - `resolvedDependencies`: the git commit and the base image digest;
  - `runDetails.builder.id = "sf9-26/local-build"`.
- [ ] Get `pipeline/build-and-attest.sh` (below) working on any small image, with `cosign verify` and `cosign verify-attestation` both succeeding.
- [ ] Compiler input: `crane pull --insecure --format=oci <ref> <dir>`, then read `index.json` → manifest → config → layers.

```bash
#!/usr/bin/env bash
# usage: pipeline/build-and-attest.sh <context-dir> <name>    -> prints ref@digest
set -euo pipefail
REG=localhost:5001
IMG="$REG/$2:latest"
OUT="run/attest/$2"; mkdir -p "$OUT"

docker build -t "$IMG" "$1"
docker push "$IMG"
DIGEST=$(crane digest --insecure "$IMG")
REF="$REG/$2@$DIGEST"

syft "docker:$IMG" -o cyclonedx-json > "$OUT/sbom.json"
python pipeline/gen_provenance.py --subject "$REF" \
  --commit "$(git rev-parse --short HEAD)" > "$OUT/prov.json"

K="--yes --key pipeline/keys/cosign.key --allow-insecure-registry"   # VERIFY: flag for an HTTP registry
cosign sign   $K "$REF"                                                2>> "$OUT/cosign.log"
cosign attest $K --type cyclonedx       --predicate "$OUT/sbom.json" "$REF" 2>> "$OUT/cosign.log"
cosign attest $K --type slsaprovenance1 --predicate "$OUT/prov.json" "$REF" 2>> "$OUT/cosign.log"  # VERIFY: type name
echo "$REF"
```

### Day 2

- [ ] **Files and layers:** implement the two-pass whiteout rule from Explanation §6, Step 1. Branch on each layer's `mediaType` for gzip or zstd.
- [ ] **Symlinks:** record every symlink, and resolve file and directory links whenever you turn a path into a key. `/bin → usr/bin` must work.
- [ ] **Closure:**
  1. Start from `Entrypoint[0]`, or `Cmd[0]` if there is no entrypoint, and look it up on the image's `PATH`.
  2. Resolve links.
  3. Follow shebangs, and follow ELF `PT_INTERP` and `DT_NEEDED` entries with pyelftools.
  4. Search for libraries in `DT_RUNPATH`, `DT_RPATH`, the directories in `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*`, then the default directories.
- [ ] **SBOM:**
  - Read the verified CycloneDX attestation (`cosign verify-attestation --type cyclonedx`) and decode its payload.
  - Build the dependency graph and compute depth with a multi-source BFS.
  - Write `depth: null` for unresolved packages, and record `unresolved_fraction`.
- [ ] **Ownership:**
  - map `/var/lib/dpkg/info/*.list` to `pkg:deb/…`;
  - map `site-packages/*.dist-info/RECORD` to `pkg:pypi/…`;
  - match both to the SBOM's purls by name and version.
- [ ] **Capabilities:** `compiler/caps_allowlist.json` maps package names to capabilities; every entry is `INFERRED`.
- [ ] **Signing identity:** take the builder and commit from the verified provenance attestation. Take the Rekor log index from `cosign verify --output json` (VERIFY the field path).
- [ ] Write the envelope exactly as in Section 4.1 and check that it passes `check_contracts.py`.

### Day 3

- [ ] Build and attest Role 1's demo app, compile it, and post the digest to the team.
- [ ] Fix what integration finds. It is usually path normalisation.

### Day 4

- [ ] Slides: what is signed, what the envelope holds, and one screenshot of a real envelope.

**Done when** the demo image's envelope has:

- `python3.11`, `libpython3.11` and libc in `closure`;
- `/usr/bin/ls` and `/usr/bin/dash` in `files` but not in `closure`;
- no entry for `/tmp/.x9`;
- the `requestz_helper` files owned by `pkg:pypi/requestz-helper@0.1.0`.

**Pitfalls**

- Use the manifest's layer digests, never the config's `diff_ids`.
- A whiteout you skip silently widens the envelope.
- Read only evidence that `cosign verify-attestation` accepted, never the unverified files in `run/attest/`.
- If syft emits no dependency edges, depth is `null` everywhere. That is acceptable for the demo; report it.

---

## 7. Role 3: Node runtime

**You own:** everything between the kernel and `detections.jsonl`.

**Your tests** (owner R3). P0: PH4-01, PH4-02a, PH4-05, PH4-06, PH4-12, PH4-14, PH4-17, CF-01, MLB-01 to 05. ML-B and the Cuckoo filter are yours; the write hook must cover all paths for ML-B.

For the demo, your code runs as a normal process on the PC, fed by Tetragon's JSON stream. Packaging it as a DaemonSet can wait until after the presentation.

### Day 1

- [ ] Confirm that exec events stream: run `kubectl logs -n kube-system ds/tetragon -c export-stdout -f` (VERIFY the container name) while you run a command in a test pod.
- [ ] Save 5 minutes of real Tetragon output to `node/testdata/raw.jsonl`. Everything else today runs on this file.
- [ ] Write `node/normalize.py`. It turns a Tetragon `process_exec` into the Section 4.3 event:
  - `exe` from `process.binary` and `parent_exe` from `parent.binary`;
  - pod, container, container ID, pid and ppid;
  - drop every namespace except `demo`.
- [ ] Write the `node/verify.py` skeleton. It loads the envelopes and `bindings.json` from the run folder and reloads them when they change. For each envelope it prepares a `closure_set` and a `hash_index`.

### Day 2

- [ ] **Write events:** adapt a TracingPolicy from Tetragon's documented file-monitoring example (VERIFY: it hooks `security_file_permission` with a write mask). Limit it to paths under `/etc`, `/usr`, `/app`, `/lib` and `/bin`, and normalise the output to `kind: write`.
- [ ] Implement the decision order below, including the mount exclusion and binding failures.
- [ ] Test on replayed events:

| Replayed event | Expected result |
|---|---|
| exec `/tmp/.x9` | D_exec undeclared |
| exec `/usr/bin/ls` | D_exec outside_closure |
| exec `/usr/local/bin/python3.11` | nothing |
| write `/etc/passwd` | D_write |
| write `/etc/hosts` | nothing (it is a mount) |
| write `/tmp/cache.json` | nothing (not captured, or a new file) |

```python
def verify(ev, env, binding):
    if binding is None:
        return det(ev, "binding", "unknown_container")
    if env is None:
        return BUFFER                                   # envelope not ready yet
    files, closure = env["files"], env["closure_set"]
    if ev["kind"] == "exec":
        rec = files.get(ev["exe"])
        if rec is None:                                 # file is in no layer
            if ev.get("hash") and ev["hash"] in env["hash_index"]:
                return det(ev, "D_hash", "relocated")
            return det(ev, "D_exec", "undeclared")
        if ev.get("hash") and ev["hash"] != rec["sha256"]:
            return det(ev, "D_hash", "modified")
        if ev["exe"] not in closure:
            return det(ev, "D_exec", "outside_closure")
        return None                                     # conforming
    if ev["kind"] == "write":
        p = ev["path"]
        under_mount = any(p == m or p.startswith(m.rstrip("/") + "/")
                          for m in binding["mounts"])
        if p in files and not under_mount:
            return det(ev, "D_write", "declared_file")
        return None                                     # new files are fine
```

### Day 3

- [ ] Run live: `kubectl logs … -f | python -m node.run --run $RUN` writes `events.jsonl` and `detections.jsonl`.
- [ ] Buffer the events of a container whose envelope is not ready yet, and verify them when it arrives.
- [ ] Stretch: runtime hashing for the relocated-binary case. First check which PID namespace Tetragon's `pid` belongs to: in kind, the node is itself a container.

### Day 4

- [ ] Slides: the hooks, the decision order, and one real detection.

**Done when** replaying the recorded attack gives exactly D_exec undeclared plus D_write, and replaying the benign scenario gives only `outside_closure` detections.

**Pitfalls**

- Compare real paths only. `sh` runs as `/usr/bin/dash`.
- Filter by namespace as early as possible. The cluster itself produces many events.
- For a script started through a shebang, the reported binary may be the script or the interpreter. The static payload avoids that question in the demo.

---

## 8. Role 4: Alerts and integration

**You own:** the repo, the controller, everything after a detection, and `make demo`.

**Your tests** (owner R4). P0: PH2-01, PH2-09, PH5-01 to 03, PH5-06, PH5-08 to 11, PH6-01, PH6-02, PH6-04, PH6-06. The trust loop is yours, with `run/keystatus.json` and the local advisory file.

You run the merge points, so you need to know every contract.

### Day 1

- [ ] Before the kickoff ends:
  - create the repo layout (Section 3.4);
  - put the Section 4 samples in `contracts/`;
  - write `check_contracts.py`, which checks the required keys for each file type.
- [ ] Write `controller/watch.py`. It watches pods in namespace `demo` with the Kubernetes Python client, and for each container whose image is `…@sha256:…`:
  1. Runs `cosign verify`, then `cosign verify-attestation` for `cyclonedx` and for `slsaprovenance1`, all with `cosign.pub`.
  2. Writes the container's entry in `bindings.json`, with `run_as_root`, `privileged` and `mounts` taken from the pod spec, plus the Kubernetes-managed files in Section 4.2.
  3. Runs Role 2's compiler if `envelopes/<digest>.json` is missing, then sets `envelope_ready`.

  The container ID appears in `status.containerStatuses` only after the container starts, so update the entry at that point.
- [ ] Write `alerts/score.py` with the rules below, and unit tests for the three expected scores.

### Day 2

- [ ] Write `alerts/log.py`, which appends records using the exact rule in Section 4.6. Write `alerts/verify_log.py`, which recomputes the chain and prints the first bad `k`.
- [ ] Write `alerts/attribute.py`. It loads each new envelope into Neo4j and queries the layer path (below). If Neo4j is down, it uses the envelope's `layer` field instead.
- [ ] Write `alerts/run.py`: tail detections → score → attribute → chain → alert → log.
- [ ] Evening: lead the mock integration on the sample files.

### Day 3

- [ ] Write `make demo`, with waits between steps: until the envelope is ready, and until an alert is present.
- [ ] Write `alerts/show.py`: one line per alert, coloured by bucket, with its clause and attribution.
- [ ] Lead the noon integration and call the freeze.

### Day 4

- [ ] Slides: scoring, attribution and the log. Run the rehearsal.

**Done when** `make demo`, after a fresh `make up`, produces:

- two alerts scoring 90 and 72 in one chain;
- two benign Lows;
- a `verify_log` run that passes, then fails after a one-character edit.

### Scoring rules for the demo

Simplified from Explanation §8:

```
S = 0.4*s_type + 0.2*s_origin + 0.4*(0.5*rho + 0.5*kappa)       score = round(100*S)

s_type    D_exec undeclared 1.00   D_hash modified 1.00   D_write 0.80
          D_hash relocated 0.70    D_exec outside_closure 0.25 (then cap the score at 34)
s_origin  AUTHENTICATED 1.0        INFERRED 0.5
rho       1.0 if the file is in no layer
          0.5 if declared but owned by no package, or depth unknown
          depth/(1+depth) otherwise
kappa     privileged pod 1.0       root 0.5       non-root 0.2   (demo stand-in for capability class)
buckets   Critical >= 80   High 60-79   Medium 35-59   Low < 35
binding   fixed score 60 (High)
```

Expected scores for a root, non-privileged pod. These are your unit tests:

| Detection | s_type | s_origin | rho | kappa | Score |
|---|---|---|---|---|---|
| `/tmp/.x9` executed | 1.00 | 1.0 | 1.0 | 0.5 | 90, Critical |
| `/etc/passwd` written | 0.80 | 1.0 | 0.5 | 0.5 | 72, High |
| `/usr/bin/ls` executed | 0.25 | 1.0 | 0.5 | 0.5 | 50, capped to 34, Low |

**Chains.** A detection joins an open chain if its `pid` or `ppid` matches a pid already in that chain, and it arrives within 60 s of the chain's last detection. Otherwise it starts a new chain.

### Neo4j load and layer query

```cypher
MERGE (i:Image {digest: $digest})
  SET i.builder_id = $builder_id, i.source_commit = $source_commit
WITH i
UNWIND $layers AS l
  MERGE (x:Layer {digest: l.digest})
  MERGE (i)-[c:CONTAINS]->(x) SET c.index = l.index;

UNWIND $files AS f
  MATCH (x:Layer {digest: f.layer_digest})
  MERGE (fl:File {path: f.path, sha256: f.sha256})
  MERGE (x)-[:INTRODUCES]->(fl);

// Layer path for a detection; no row means the file came from no layer
MATCH (:Image {digest: $digest})-[c:CONTAINS]->(l:Layer)-[:INTRODUCES]->(:File {path: $path})
RETURN l.digest AS layer, c.index AS idx ORDER BY idx DESC LIMIT 1;
```

The layer index is stored on the CONTAINS edge, not on the Layer node, because images share layers.

---

## 9. Schedule and merge points

### 9.1 Day 1 kickoff (first hour, everyone)

1. Pick roles (Section 2) and write the names in.
2. Walk through Sections 3 and 4 together. Change any sample now; after this hour the contracts are frozen.
3. Role 4 pushes the repo skeleton and `contracts/`, and everyone clones it.

### 9.2 Day by day

| | Role 1 | Role 2 | Role 3 | Role 4 |
|---|---|---|---|---|
| **Day 1** | PC up; demo app, malicious package, payload | Keys, provenance script, build-and-attest, OCI reading | Tetragon stream, raw sample, normaliser, verifier skeleton | Repo, contracts, controller, scoring with tests |
| **Day 2** | Scenarios, Falco capture, Falco-only run | Layers, symlinks, closure, SBOM depth, ownership, envelope | Write policy, decision order, replay tests | Log and `verify_log`, Neo4j attribution, alert pipeline |
| **Day 3** | `compare.py`, two full test runs | Real demo image attested and compiled; fixes | Live mode, buffering; hashing if ahead | `make demo`, `show.py`, lead integration |
| **Day 4** | Results table, backup video | Slides | Slides | Slides, rehearsal |

### 9.3 Merge points

| When | Must be true | Checked by |
|---|---|---|
| Day 1, end of kickoff | Roles taken, contracts frozen, repo cloned by all | Role 4 |
| Day 1, evening | `make up` passes the smoke tests; key pair exists; Tetragon events visible; controller writes a binding | Everyone, 15-minute call |
| Day 2, evening | Every command in Section 3.3 runs on the sample files; `main` works | Role 4 |
| Day 3, noon | The real demo image goes through the whole pipeline on the PC. **Feature freeze.** | Role 4 |
| Day 3, evening | `make demo` passes twice in a row from a fresh `make up` | Role 1 |
| Day 4, noon | Slides merged; backup video recorded | Role 1 |
| Day 4, afternoon | Full rehearsal, timed | Everyone |

After the freeze, only bug fixes go in. Hold a 15-minute call each evening covering what works, what is blocked, and any contract change request.

---

## 10. Setting up the demo PC

**Machine:**

- **Operating system:** native Ubuntu 24.04, not WSL or a virtual machine, where eBPF may not work.
- **Memory:** 16 GB RAM minimum; 32 GB is comfortable.
- **CPU and disk:** 8 cores and 100 GB of free disk.
- **Network:** internet access for image pulls and Rekor.

**Install:** Docker Engine, kind, kubectl, helm, crane, cosign, syft, Python 3.11 with venv, gcc, git and jq. Follow each tool's official install instructions. Record the installed versions in `testbed/VERSIONS.md`, so the flags marked VERIFY are checked against the right documentation.

```bash
# 1. kind cluster wired to a local registry at localhost:5001.
#    Copy the "local registry" script from the kind documentation into
#    testbed/kind-with-registry.sh, then run it.
./testbed/kind-with-registry.sh

# 2. Tetragon
helm repo add cilium https://helm.cilium.io && helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon

# 3. Falco with the modern eBPF driver                         (VERIFY value names)
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set falco.json_output=true

# 4. Neo4j
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/provbind-demo neo4j:5

# 5. Namespace for the demo
kubectl create namespace demo
```

**Smoke tests** (Day 1 evening):

- [ ] `kubectl get nodes` shows every node Ready.
- [ ] `docker pull busybox && docker tag busybox localhost:5001/busybox && docker push localhost:5001/busybox` works, and then `kubectl run t -n demo --image=localhost:5001/busybox -- sleep 60` starts.
- [ ] `kubectl logs -n kube-system ds/tetragon -c export-stdout --tail=5` prints JSON events.
- [ ] `kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20` shows Falco running.
- [ ] Neo4j opens at `http://localhost:7474`.
- [ ] `cosign version`, `syft version`, `crane version` and `python3.11 --version` all work.

---

## 11. Risks, fallbacks and stretch goals

| Risk | Fallback | Owner |
|---|---|---|
| Tetragon gives no pod-labelled events in kind by Day 1 noon | Run Tetragon as a Docker container on the host and the demo app as a plain Docker container; bind by Docker container ID. The demo makes the same point without Kubernetes. | Roles 3, 1 |
| cosign or syft refuse the HTTP registry | Try the flags marked VERIFY; otherwise push to GitHub Container Registry | Role 2 |
| Rekor upload fails (no internet) | Sign with `--tlog-upload=false`, and say in the talk that the demo skips the transparency step | Role 2 |
| syft emits no dependency edges | Depth shows as unknown; the demo still works; mention it | Role 2 |
| Neo4j is down or slow | Attribution uses the envelope's `layer` field; show a screenshot of the graph instead | Role 4 |
| Falco's driver fails in kind | Run Falco on the host with the modern eBPF driver | Role 1 |
| Integration is not done by Day 3 noon | Cut chains and Neo4j; keep exec detection, scoring and the log | Role 4 |
| A teammate is out | Role 1 takes over that role's section of this handoff | Everyone |

**Stretch goals.** Three of the four original stretch goals are now tests in the Capability Test Plan:

- relocated binary → attack-3 (PH4-07, P1);
- signed log checkpoints → PH5-12 (P1);
- Phase 6 preview → trust-1 (PH6-04, P0).

The remaining stretch goal, only after the Day 3 evening check passes: a Kyverno `verifyImages` policy that rejects an unsigned image, shown live as an extra demo step (Role 4).

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 1.0 | 26 Sep 2026 | First version |
| 1.1 | 27 Sep 2026 | Scope widened to test every capability in Aj Ohm's draft (Capability Test Plan v1.0): ML-A, ML-B, the Cuckoo filter, five hooks, the trust loop. Demo steps 4–5 added; test ownership per role; results files in the run folder |
