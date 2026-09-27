# PROVBIND: Project Explanation and Review of Aj Ohm's Draft

2026-09-26 · @Krittakorn Saetia

## 1. What Aj Ohm's draft changed

Aj Ohm kept our title, abstract, keywords and evaluation plan, and rewrote everything between them. The system section went from a tool-by-tool pipeline to a formal model: seven entities, a threat model, six phases, 96 numbered equations and two algorithms. The comparison below is against `main_DS2_revised.tex`, our last revised DS2.

### At a glance

| Area | Our revised DS2 | Aj Ohm's draft |
|---|---|---|
| Title and abstract | Title with manual line breaks | Title wraps naturally; abstract unchanged |
| Introduction | xz-utils case, then "every runtime tool learns from observation" | Kubernetes-centred problem, a compromised transitive package as the example, four named challenges |
| Contributions | C1–C3 | Four contributions; attribution is now its own contribution |
| Related work | One section, 25 references, including FuseChain, GoLeash, SynthChain | Three subsections, 30 references; FuseChain and GoLeash removed; 10 new IEEE papers from 2023–2026 |
| System section | Five-part overview, tools table, 7 algorithms | Seven entities (SP, SCR, AEM, EPGS, KWN, RIV, TR), threat model, six phases, Eqs. (1)–(96), 2 algorithms |
| Admission | Existing controller, untouched; our watcher fetches attestations and compares layer digests | The AEM checks signature, transparency record and signer/key policy, then binds manifest, config, SBOM and provenance to the digest; rejects on failure |
| Envelope | F, P, Φ, Q, K | E = (F, G^P, δ, Φ, Q, C, N̂), every entry labelled AUTHENTICATED or INFERRED; adds a package index |
| Capability model | LightGBM predicts per package | LightGBM predicts per image from one feature vector, capped by the Kubernetes capability set (Algorithm 1) |
| Graph schema | Image, Layer, File, Package, Container, Deviation | Image, Layer, File, Package, Container, Process; adds OWNS, RUNS, EXECUTES, LOADS; drops Deviation and CHAINED_TO |
| Verification classes | 5 types, plus modified binary, relocated binary and a low-weight "unexpected process" | Six classes (D_exec, D_load, D_write, D_cap, D_net, D_hash) plus binding failure; any exec outside the closure is a contradiction |
| Residual screen | One Isolation Forest per node on conforming windows, always Low severity | Per-process windows, a behavioural model stored per image, its own score formula |
| Scoring | S = 0.4τ + 0.4ρ(δ) + 0.2κ with ρ(δ) = δ/(1+δ), two tables, buckets, two worked examples | S_det = w_τ s_τ + w_π s_π + w_c s_c and S_beh = w_A s̄_A + w_c s_c, with no values given |
| Attribution | Layer-index lookup; deviations grouped into chains by process ancestry | Two graph traces: dependency path and image-layer path; no chains |
| Violation log | Merkle tree, KMS-signed roots, anchored in Rekor | Hash chain H_k = H(H_k−1 ∥ H(A_D)), protected by trusting the RIV and EPGS |
| Trust re-evaluation | Algorithm 7 with concrete checks | Four policy-controlled predicates; alert only when trust flips from 1 to 0; runtime and trust states kept separate |
| Evaluation plan | As written | Unchanged, except the SynthChain citation now prints as [?] |

### What got better

- **A threat model now exists.** It names the adversary, the trusted components and what is out of scope. Reviewers look for this first, and our version had none.
- **Admission is formalised.** Authentication (Eqs. 10–13) is separate from cross-evidence binding (Eqs. 14–18), so an SBOM or provenance file belonging to another image cannot be reused. We only compared layer digests.
- **Declared versus inferred now changes the score.** Eq. (66) makes s_π(AUTHENTICATED) > s_π(INFERRED), so breaking a signed claim outranks breaking a prediction. Algorithm 1 also caps predicted capabilities at what the pod is allowed.
- **The behavioural path has clean semantics.** It runs per process, only on events that already passed verification, and its findings are never called contradictions. The draft states that the novelty is the gating, not the Isolation Forest.
- **Attribution has two independent views.** A package and an image layer are different axes, so tracing them separately (Eqs. 69–74) is more correct than one chain.
- **Trust re-evaluation is better specified.** It alerts once per trust loss (Eq. 90), leaves "is this advisory enough?" to policy, and keeps runtime state and trust state orthogonal (Eq. 96). This also removes the key-state bug in our Algorithm 7.
- **The graph is richer.** OWNS makes file-to-package ownership an edge, Process nodes allow process-level attribution, and depth now handles several root components (Eq. 29).
- **The references lean on peer-reviewed IEEE work**, which is what he asked for in the earlier round.

### What got weaker

- **No numbers in the scoring.** τ, κ, ρ(δ), the weights, the buckets and the worked examples are gone. The abstract still promises ranking by dependency distance.
- **No tools.** Tetragon, cosign, syft, Neo4j and Kyverno are never named, and the tools table is gone.
- **No decision order.** Five of seven algorithms became equations, so nothing says which class wins when an event fits two.
- **Weaker log.** A bare hash chain can be recomputed by anyone who can write to the log.
- **Lost context.** Chain grouping, the xz-utils example, and the closest related work (GoLeash, FuseChain) are gone.
- **More false positives.** Eq. (55) makes any exec outside the entrypoint closure a contradiction. We scored that case low on purpose.

Section 14 has the fix for each of these.

### The old defects

| Defect from the handoff | Status in Aj Ohm's draft |
|---|---|
| Algorithm 4 had no check that a runtime hash exists | Algorithm removed, but Eq. (55) still needs H(f) at runtime: same gap |
| Fig. 1 caption said hash-chained, body said Merkle | Resolved: the design is now a hash chain |
| Broken opening sentence of §III-A | Resolved: section rewritten |
| Cuckoo filter against our "measure first" decision | Still present (Phase 4, Step 2) |
| Title manual line breaks | Resolved |
| Invented or placeholder authors (GoLeash, FuseChain, SynthChain) | References deleted; SynthChain is still cited, so it prints [?] |
| Algorithm 7 key-state logic | Resolved by the predicate model |
| Evaluation plan without ablations or adversarial test | Unchanged |
| No conclusion section | Still none |
| Diagram typos I flagged last time | Not in his figure: "Dependency Manifest" and "(node cache)" are correct there; only the old copy in our project had them wrong |

## 2. The project in one page

PROVBIND checks a running container against the signed record of what was built into it, and raises an alert when the two disagree.

**The problem.** A supply chain attack reaches its target through something the target already trusts: a dependency, a base image or a build step. The payload is signed by the right identities and passes the same admission checks as legitimate software. The 2024 xz-utils backdoor was correctly signed and built from the real repository, and it was found by accident. A signature proves where an artifact came from, not that it is benign.

**The gap.** Build-time evidence (provenance, SBOM, layer digests) is checked once at admission and then ignored for the rest of the container's life. Runtime monitors such as Falco, provenance-based IDS and profiling tools learn "normal" from observation. They can say an event is unusual, but not which signed claim it breaks. Aj Ohm's introduction puts it as build-time trust and runtime trust being disconnected.

**The idea.** Keep the evidence after admission and compile it into an **envelope**:

- the declared files, with their hashes and the layers that introduced them;
- the package graph, with each package's dependency depth;
- the binaries and libraries reachable from the entrypoint.

Where signed evidence is silent (capabilities, network egress), a LightGBM model fills in expectations labelled INFERRED. Every kernel event is checked against the envelope. The question changes from "is this unusual?" to "does this contradict what was signed?"

**What comes with it.** Alerts name the clause they contradict and trace the offending file to its package path and image layer. An Isolation Forest screens behaviour that already passed verification, to catch attackers who stay inside the envelope. A timer loop withdraws trust when a key, builder or component goes bad after admission.

**The claim to test.** At the same detection rate, verifying against a signed specification should give fewer false positives than learned anomaly detection. No experiment has run yet, and the claim can fail; Section 14 says how.

**What it cannot catch.** Malicious code that is declared in the SBOM, stays inside the envelope and behaves like the application. The draft's threat model puts this out of scope.

**The minimum result that is still a paper:**

1. File and package layers working.
2. Detection on the reconstructed containerised attack scenarios.
3. A lower false-positive rate than Falco at matched detection.
4. Alerts that cite the violated clause.

## 3. Where it starts and when each part runs

The pipeline starts in CI, when a developer's commit is built into a signed image. PROVBIND's own code starts at Phase 2, when Kubernetes receives a pod that uses that image. Each phase runs on a different clock, and the clock decides what the phase may do: the per-event check may touch only memory, while the timer loop may call the network.

| Phase | Draft entity | Starts when | How often | Runs where | Allowed cost |
|---|---|---|---|---|---|
| 1. Build and evidence | SP → SCR | A commit or tag is built | Once per build | CI runner, registry, KMS, Rekor (outside the cluster) | Minutes; existing tools |
| 2. Admission and verification | AEM | A pod is created | Once per pod; cached per digest | Cluster: admission controller plus our controller | Milliseconds on the admission path |
| 3. Envelope compilation | AEM → EPGS | A digest is seen for the first time | Once per image digest | Cluster Deployment, Neo4j | Seconds; network, disk and database allowed |
| 4a. Deterministic check | KWN, RIV | Every kernel event | Thousands per second per node | Node DaemonSet | Microseconds; memory only, no I/O |
| 4b. Behavioural check | RIV | A process window fills | Per window (proposal: 30 s or 200 events) | Node DaemonSet | Milliseconds |
| 5. Scoring and attribution | RIV, EPGS | A detection is raised | Rare | Node (score), cluster (graph trace, log) | Graph queries allowed |
| 6. Trust re-evaluation | TR | A timer fires | Every ΔR (proposal: 300 s; the draft gives no value) | Cluster Deployment or CronJob | Network and database allowed |

Three placement rules hold everywhere:

- **Nothing runs inside a monitored container.** A monitor that shares a trust domain with the workload can be switched off by whoever compromises the workload. This is a security rule, not a performance one.
- **Inference goes where the data is; training goes where the aggregate data is.** Models are trained offline at cluster level and loaded as files.
- **The graph database is never on the per-event path.** It is read after a detection, for attribution only.

The draft's seven entities are logical roles. This is what each one is when we build it (component names are our proposal):

| Entity | In practice |
|---|---|
| SP, Software Producer | The CI pipeline: BuildKit, syft, cosign, a KMS key |
| SCR, Supply-Chain Repository | OCI registry, Rekor transparency log, KMS |
| AEM, Admission and Envelope Manager | Kyverno makes the admit/reject decision; our `provbind-controller` fetches evidence, checks bindings and compiles the envelope |
| EPGS, Envelope and Provenance Graph Store | Neo4j for the graph, plus a blob store for compiled envelopes and indices keyed by digest |
| KWN, Kubernetes Worker Node | The node, with Tetragon running as a DaemonSet |
| RIV, Runtime Integrity Verifier | Our `provbind-node` DaemonSet (cache, verifier, Isolation Forest), plus a cluster-side attribution step |
| TR, Trust Re-evaluator | Our `provbind-trust` Deployment |

## 4. Phase 1: Build and supply-chain evidence (SP → SCR)

Phase 1 produces a signed image plus a signed SBOM and signed provenance, all bound to one image digest. We write no code here. We run existing tools to make the attested test images the rest of the system needs.

**In the draft:** Eqs. (1)–(6). Image I is built from source S, Dockerfile F_D, dependency manifest M and base image I_B. Its digest d_I is the key for every later phase.

|  | What | Example |
|---|---|---|
| Inputs | Source repo at a commit, Dockerfile, dependency manifest, base image | `requirements.txt`, `package-lock.json`, `go.mod`; `python:3.11-slim@sha256:…` |
| Outputs | Manifest M_I, config C_I, layer blobs, digest d_I; SBOM B_I; provenance P_I; signatures; Rekor entry τ_I | CycloneDX JSON SBOM; in-toto Statement v1 carrying a SLSA v1 provenance predicate |

**Tools:** Docker BuildKit (or Kaniko) to build; crane for digests; syft for the SBOM; BuildKit's provenance output; cosign to sign; HashiCorp Vault transit for development or a cloud KMS; a local `registry:2`; the public Rekor log.

**Algorithms:** SHA-256 content addressing; ECDSA P-256 signatures over the DSSE pre-authentication encoding (PAE); Rekor's Merkle tree, whose inclusion proofs verify in O(log n).

**How we run it.** One script per test image. The flags marked VERIFY must be checked against the versions we pin.

```bash
# 1. Build and push; the digest is what every later phase keys on
docker buildx build --provenance=mode=max --sbom=true -t "$IMG" --push .
DIGEST=$(crane digest "$IMG")

# 2. SBOM with dependency edges
syft "$IMG@$DIGEST" -o cyclonedx-json > sbom.json
jq '.dependencies | length' sbom.json          # must be > 0

# 3. Provenance produced by BuildKit                      (VERIFY format path)
docker buildx imagetools inspect "$IMG" --format '{{ json .Provenance.SLSA }}' > provenance.json

# 4. Sign the image and attest both documents with the KMS key
cosign sign   --key hashivault://provbind "$IMG@$DIGEST"
cosign attest --key hashivault://provbind --type cyclonedx       --predicate sbom.json       "$IMG@$DIGEST"
cosign attest --key hashivault://provbind --type slsaprovenance1 --predicate provenance.json "$IMG@$DIGEST"  # VERIFY type name
```

**Pitfalls:**

- Pin the base image by digest. A tag can move after signing.
- Check that syft emitted dependency edges. Without them, dependency depth means nothing.
- cosign stores signatures in two ways: tag-style `sha256-<hex>.sig` / `.att`, and the OCI referrers API. The retriever must read both.
- The draft's Eq. (5) signs only d_I. In practice `cosign attest` signs each document as a DSSE envelope, and the paper should say so (fail point C1).
- We sign with a KMS-held key instead of Fulcio keyless signing, so a key can be disabled later and Phase 6 has something to check. Vault versus cloud KMS is still undecided (OD4).
- A compromise made before or during the build is declared honestly in the SBOM and passes every check here. PROVBIND sees it only if it behaves differently at runtime.

## 5. Phase 2: Admission and evidence verification (AEM)

Phase 2 decides whether a pod may run and records the verified evidence the envelope will be built from. In the draft the AEM makes the admit/reject decision itself. We build it as two parts: Kyverno enforces the decision, and our controller does the evidence work beside it.

**In the draft:** Eqs. (7)–(23). The digest is resolved, then authenticated (v_auth = v_sig ∧ v_trans ∧ v_trust), then bound (v_bind = v_M ∧ v_C ∧ v_B ∧ v_P). The pod is admitted only if both hold. The verified state 𝒱_I goes to the compiler; the context Γ_I is kept for Phase 6.

| Check | Eq. | Confirms | How we implement it |
|---|---|---|---|
| Resolve | (7) | Tag → immutable digest | Kyverno rewrites tags to digests in the pod spec (`mutateDigest`); the controller reads the digest from the spec |
| v_sig | (10) | Signatures verify against the producer's key | cosign verification with the KMS public key (Kyverno attestor) |
| v_trans | (11) | The Rekor entry exists and matches the signature | cosign checks the Rekor bundle and inclusion proof |
| v_trust | (12) | Key enabled and signer allowed at time t | KMS key-state query plus an allowlist of builder IDs; same function as Phase 6's T_key |
| v_M | (15) | sha256(manifest) = d_I | Recompute the manifest digest |
| v_C | (16) | Manifest's config digest = sha256(config) | Recompute the config digest |
| v_B | (17) | SBOM statement subject = d_I | Parse the in-toto statement subject |
| v_P | (18) | Provenance subject = d_I | Same, on the provenance statement |

**Tools:** Kyverno `verifyImages` rule (or the Sigstore policy-controller) for the decision; Python with the Kubernetes client (watch API), cosign and crane for our controller.

**How we build it.** We do not write our own webhook. Kyverno enforces signatures and required attestations, and its exact policy YAML is written against the version we pin. Our controller watches pod events and repeats the cheap checks, so our records do not depend on Kyverno's logs:

```python
def on_pod_event(pod):                        # provbind-controller, watch-based
    for c in pod.spec.containers:
        d = digest_of(c.image)                # image@sha256:… after mutateDigest
        bind(pod.uid, c.name, d)              # container → digest, used by BindCheck
        if d in compiled or d in in_progress:
            continue                          # one compile per digest
        A = fetch_evidence(d)                 # manifest, config, SBOM, provenance, sigs, Rekor bundle
        v_auth = verify_sigs(A, kms_pubkey) and verify_rekor(A) and trust_check(A.key, now())
        v_bind = (sha256(A.manifest) == d
                  and A.manifest.config.digest == sha256(A.config)
                  and subject(A.sbom) == d and subject(A.provenance) == d)
        if not (v_auth and v_bind):
            report_binding_failure(d); continue
        store_context(d, key=A.key, sigs=A.sigs, rekor=A.rekor, t0=now())   # Γ_I for Phase 6
        enqueue_compile(d, A)                 # 𝒱_I for Phase 3
```

**The cold-start window.** Admission returns in milliseconds; compilation takes seconds. The pod is already running in between, and the draft does not say what happens to its events. The options, in order of preference:

1. **Buffer and verify late.** The node keeps each new container's events until its envelope arrives, then checks them. Recommended default.
2. **Hold the first pod.** A Kubernetes scheduling gate keeps a pod of a never-seen digest unscheduled until the envelope exists; cached digests pass at once. Scheduling gates are stable in recent Kubernetes versions (VERIFY on our cluster).
3. **Compile at registry push.** No window at all, but it needs a registry hook. Future work.

Either way, report how long the window lasts.

**Pitfalls:**

- Never key anything on a tag.
- The admission webhook must never wait for compilation, or every deployment in the cluster pays the delay.
- Decide what an image without evidence gets: rejected by Kyverno, or admitted and reported as a binding failure.
- Rekor proves a signature existed at a time. It is not a revocation source.

## 6. Phase 3: Envelope compilation and the provenance graph (AEM → EPGS)

Phase 3 turns the verified evidence into the envelope and its lookup indices, once per image digest. The envelope says which files may exist and with which hashes, which package owns each file and how deep it sits, what may execute or load, and which capabilities and network access to expect. This is the core research contribution (contribution 1).

**In the draft:** Eqs. (24)–(49) and Algorithm 1. **Runs:** cluster-level compiler worker, triggered by Phase 2 for each new digest. **Input:** 𝒱_I = (d_I, M_I, C_I, B_I, P_I) plus the layer blobs, which must be downloaded because the manifest lists only their digests.

### Step 1: Files and layers (Eqs. 24–26)

The compiler rebuilds the filesystem the container will see and records each file's hash and the layer that introduced it. The algorithm is an ordered layered union with whiteouts, the same rule overlay filesystems use. Tools: crane to pull blobs, Python `tarfile` for gzip layers, `zstandard` for zstd layers, `hashlib`.

```python
def file_layer(manifest, blobs):                   # Eqs. (24)-(26)
    F = {}
    for i, layer in enumerate(manifest.layers):    # manifest order is load-bearing
        new, gone, opaque = {}, set(), set()
        for e in iter_tar(blobs[layer.digest], layer.mediaType):   # gzip or zstd
            d, base = dirname(e.name), basename(e.name)
            if base == ".wh..wh..opq":     opaque.add(d)              # hide lower layers under d
            elif base.startswith(".wh."):  gone.add(join(d, base[4:]))  # delete path and subtree
            elif e.isfile(): new[e.name] = Rec(sha256_stream(e), layer.digest, i, e.mode, e.uid, e.gid)
            elif e.islnk():  new[e.name] = Link(e.linkname, layer.digest, i)  # resolved below
            elif e.issym():  new[e.name] = Sym(e.linkname, layer.digest, i)   # record, never follow
        F = {p: r for p, r in F.items()               # 1) this layer's deletions hit lower layers only
             if not under_any(p, opaque) and not is_or_under_any(p, gone)}
        F.update(resolve_hardlinks(new, F))           # 2) then add this layer's own entries
    return F
```

The two-pass form matters. Our Section-Spec deleted files at the moment it met an opaque marker, which also removes files the *same* layer added earlier in the tar. Traps: keep manifest order; never skip whiteouts (deleted files would silently widen the envelope); use the manifest layer digest, never `rootfs.diff_ids`; branch on `mediaType` for zstd. A `python:3.11-slim` image holds roughly 15,000 files, so this step takes seconds, not minutes (approximate, from the design log).

### Step 2: Package graph, depth and ownership (Eqs. 27–30)

The compiler turns the SBOM into a dependency graph and gives every package its shortest distance from a root component. Eq. (29) takes the minimum over several roots, which is exactly a multi-source breadth-first search, O(V + E).

```python
def depths(sbom):                                  # Eqs. (27)-(29)
    roots = sbom.root_components()                 # normally metadata.component
    depth, q = {r: 0 for r in roots}, deque(roots)
    while q:
        u = q.popleft()
        for v in sbom.depends_on.get(u, ()):
            if v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)
    unresolved = set(sbom.components) - set(depth) # the draft marks these unresolved
    return depth, unresolved                       # report len(unresolved) / len(components)
```

Packages do not execute; files do. The ownership map Φ (Eq. 30) links each file to the package that installed it, using the package manager's own records inside the image:

| Ecosystem | Record read inside the image |
|---|---|
| Debian, Ubuntu | `/var/lib/dpkg/info/*.list` |
| Alpine | `/lib/apk/db/installed` |
| RHEL, Fedora | the rpm database under `/var/lib/rpm` |
| Python | `site-packages/*.dist-info/RECORD` |
| Node.js | the package's own `node_modules/<pkg>/` directory |
| Go | the module list embedded in each binary (`go version -m`) |

Package names from these records must be normalised to the SBOM's purls before matching. A file no record claims gets no package, which later scores as ⊥ (no declared component).

### Step 3: Execution and load closure (Eq. 31)

The compiler walks from the entrypoint to everything it statically needs: shebang lines give an interpreter, ELF files give their loader (`PT_INTERP`) and `DT_NEEDED` libraries, resolved through `DT_RPATH`, `DT_RUNPATH` and the default library paths. Tools: pyelftools or LIEF. It is a worklist reachability search, O(V + E).

```python
def closure(config, F):                            # Eq. (31)
    work, Q = [first_executable(config)], set()    # Entrypoint[0], else Cmd[0]
    while work:
        p = resolve_in_path(work.pop(), config.Env, F)
        if p is None or p in Q:
            continue
        Q.add(p)
        head = read_head(F, p)
        if head.startswith(b"#!"):
            work.append(shebang_interpreter(head))
        elif head.startswith(b"\x7fELF"):
            elf = parse_elf(F, p)
            if elf.interp:
                work.append(elf.interp)
            work += [resolve_so(n, elf.rpath, elf.runpath) for n in elf.needed]
    return Q                                       # a static Go binary adds only itself
```

This closure **under-approximates** normal behaviour. It cannot see what a shell script launches (`ls`, `grep`, `curl`), what `dlopen` loads at runtime (Python and Node native extensions, glibc's DNS modules), or what an interpreter imports. That is why fail point C2 matters.

### Step 4: Capability and egress inference (Eqs. 32–34, Algorithm 1)

No attestation format states which Linux capabilities or network access a container needs, so a LightGBM multi-label model predicts them. The prediction is capped by what the pod's Kubernetes security settings allow, and every predicted entry is labelled INFERRED.

- **Labels:** Linux capabilities (e.g. `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`), plus egress classes such as "outbound TCP 443" or "DNS".
- **Features z_I:** image config (runs as root, exposed ports, environment), package indicators (ecosystem, known network, crypto or subprocess libraries), ELF imported symbols (`socket`, `bind`, `setuid`, `mount`, `ptrace`), closure size, and deployment attributes.
- **Model:** one LightGBM classifier per label (`MultiOutputClassifier(LGBMClassifier())`), threshold θ_C per label.
- **Training data:** run a corpus of images in a sandbox cluster under Tetragon and record which capabilities they use and where they connect. This dataset is the largest hidden task in the project.
- **Baseline to beat:** a curated allowlist for common packages plus a conservative default, reported as an ablation.

Two gaps in the draft: N̂_I (egress) appears in Eq. (35) but is never defined, and Algorithm 1's "declared capabilities" have no stated source (fail points M8 and M9).

### Step 5: Envelope and runtime indices (Eqs. 35–37)

Every envelope entry carries its origin label, AUTHENTICATED or INFERRED (Eq. 36). The indices are what the node reads per event, so each is a plain Python dictionary with O(1) lookups:

| Index | Maps | Used for |
|---|---|---|
| J_path | path → (sha256, layer) | Is this file declared, and is its content unchanged? |
| J_hash | sha256 → {paths} | Relocated binary: declared content at an undeclared path |
| J_layer | path → layer digest | Layer attribution without a graph query |
| J_pkg | path → package (Φ) | Owning package |
| J_depth | package → δ | Dependency position for scoring |

If memory becomes a problem, store paths as 64-bit hashes (8 bytes instead of about 60). The draft also puts a Cuckoo filter in front of these; see fail point M15.

### Step 6: Provenance graph and storage (Eqs. 38–49)

The graph follows the draft's Fig. 2: six node types and eight edge types.

| Node | Properties |
|---|---|
| Image | digest, builder_id, source_commit, registry |
| Layer | digest, index, size, created_at |
| File | path, sha256, mode, size |
| Package | purl, name, version, type, depth |
| Container | id, name, namespace, node |
| Process | pid, name, cmdline, start_time, uid/gid |

Edges: Image →CONTAINS→ Layer, Layer →INTRODUCES→ File, Package →DEPENDS_ON→ Package, Package →OWNS→ File, Container →INSTANCE_OF→ Image, Container →RUNS→ Process, Process →EXECUTES→ File, Process →LOADS→ File. The first four are written at compile time. The runtime four should be written only for processes involved in a detection (fail point M3).

```cypher
CREATE INDEX file_key IF NOT EXISTS FOR (f:File) ON (f.path, f.sha256);
CREATE INDEX layer_key IF NOT EXISTS FOR (l:Layer) ON (l.digest);

// batched load: 100,000 single CREATE statements take minutes
UNWIND $files AS f
MATCH (l:Layer {digest: f.layer})
MERGE (x:File {path: f.path, sha256: f.sha256})
MERGE (l)-[:INTRODUCES]->(x);
```

Keying File nodes by (path, sha256) lets images that share a base layer share nodes, so the graph grows with distinct layers rather than images. Neo4j is the store; Kuzu is the embedded fallback with the same Cypher. The compiled envelope and indices are serialised as one blob keyed by d_I, which is what nodes download. Package depth and DEPENDS_ON edges need image scope (fail point M4).

## 7. Phase 4: Runtime observation and dual-path verification (KWN, RIV)

Phase 4 checks every kernel event against the envelope in memory, then screens the events that passed for odd behaviour, one process at a time. It runs on every node as a DaemonSet, outside the monitored containers. This is contribution 2.

**In the draft:** Eqs. (50)–(61) and Algorithm 2. Path 1 is deterministic: does the event contradict the envelope? Path 2 is statistical: is a conforming process behaving oddly?

### Step 1: Collect and bind events (Eqs. 50–51)

Tetragon collects five kinds of event, and most filtering happens inside the kernel so that uninteresting events never reach our code. Hook names come from our design notes and must be checked against the Tetragon version we pin.

| Event | Draft class | Tetragon source (VERIFY) | Filtered in the kernel |
|---|---|---|---|
| Process execution | D_exec, D_hash | built-in `process_exec` events | Monitored pods only |
| File opened for writing | D_write | kprobe on `security_file_open` | Write intent only: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC |
| Executable mapping (library load) | D_load, D_hash | kprobe on `security_mmap_file` with PROT_EXEC | Executable mappings only |
| Capability use | D_cap | kprobe on `cap_capable` | Monitored pods only |
| Outbound connection | D_net | kprobe on `tcp_connect`; UDP needs its own hook | Monitored pods only |

Our earlier design specified only exec, file-open and `tcp_connect`. Library loads and capability use had no event source (fail point M11).

Tetragon labels each event with its pod and container. The node looks up the container's digest, recorded by the controller in Phase 2; this is BindCheck (Eq. 51). An unknown container is a binding failure.

**Where H(f) comes from.** Eq. (55) compares the executed file's hash with the declared one, but Tetragon reports paths, not hashes. The options, best first:

1. Kernel IMA measuring each exec (`measure func=BPRM_CHECK`), read by Tetragon if our version supports it (VERIFY).
2. Hash `/proc/<pid>/exe` in userspace at exec time, cached by (device, inode, mtime). Very short-lived processes may exit before hashing.
3. Path-only mode. The hash checks are then off, and the paper must say so.

### Step 2: Resolve the envelope from the cache (Eq. 52)

The node keeps two maps: container → envelope, and digest → (envelope, reference count). A container start increments the count, or downloads the envelope blob from the EPGS on a miss; a container exit decrements it; the envelope is evicted at zero. A 200-replica deployment therefore holds one envelope per node. While a download or compilation is pending, that container's events are buffered.

### Step 3: Deterministic verification (Eqs. 53–56)

The draft defines one rule per class but not the order in which they are tried. The order matters: an exec at a new path whose content matches a declared file fits both D_exec and D_hash. Our proposed order gives every event exactly one outcome:

```python
def verify(ev, E, J):                        # one outcome per event
    if ev.kind in (EXEC, LOAD):
        rec = J.path.get(ev.path)
        if rec is not None:                   # declared file
            if ev.hash is not None and ev.hash != rec.sha256:
                return Det("D_hash", "modified")          # declared path, new content
            if ev.path not in E.Q:
                return Det(kind_class(ev), "outside_closure")  # weak, see Section 8
            return CONFORMING
        if ev.hash is not None and ev.hash in J.hash:
            return Det("D_hash", "relocated", declared_at=J.hash[ev.hash])
        return Det(kind_class(ev), "undeclared")          # in no layer at all
    if ev.kind == WRITE and ev.path in J.path and not under_mount(ev):
        return Det("D_write")                 # creating a new file is conforming
    if ev.kind == CAP and ev.cap not in E.C:
        return Det("D_cap", origin=E.origin(ev.cap))
    if ev.kind == CONNECT and not E.N.allows(ev.daddr, ev.dport):
        return Det("D_net", origin=E.origin_net)
    return CONFORMING                         # continues to the behavioural path
```

Three details in this code are fixes to the draft. The `ev.hash is not None` test is the hash guard our old Algorithm 4 was missing. The `outside_closure` case keeps a script's `ls` from being scored like a dropped binary. The `under_mount` test stops writes to a volume mounted over an image directory being reported as tampering. The draft's rule for runtime-created files (conforming unless they modify a protected object or break another clause) is the `WRITE` line.

### Step 4: Behavioural path (Eqs. 57–59, Algorithm 2)

Events that passed Step 3 are grouped per process into windows and scored by an Isolation Forest. The aim is an attacker who uses only declared binaries and destinations, the mimicry case. The draft leaves the window, features and threshold open; these are our proposals:

- **Monitored processes (𝒬_beh):** long-lived processes in the container's process tree, for example alive longer than 10 s.
- **Window W:** 30 s or 200 events, whichever comes first.
- **Features Ψ:** counts per event kind, child-process spawn rate, distinct files written and their path classes (`/tmp`, `/etc`, data directories), distinct destination addresses and ports, connection rate.
- **Model:** scikit-learn `IsolationForest`, 100 trees, 256 samples each; report `contamination` and never tune it on the test set.
- **Score:** the negated `score_samples` value, mapped to [0, 1] by its percentile among benign validation windows (the draft's g_I).
- **Threshold θ_A:** the 99th percentile of benign validation windows.

The draft says plainly that the novelty is the gating, not the model: only envelope-conforming events reach the forest. A behavioural finding D_beh never claims a contradiction.

### Step 5: Detection records (Eqs. 60–61)

A deterministic detection records the digest, event, class, violated clause and that clause's origin label. A behavioural detection records the digest, process, window, score and features. Both go to Phase 5.

**Pitfalls:**

- The kernel ring buffer drops events under bursts. Report the drop rate next to CPU use.
- A script dropped after build and imported by a declared interpreter produces no exec and no library load. Only the behavioural path can see it.
- Just-in-time compilers create executable memory from data. Our earlier draft constrained this through writable-executable mappings; Aj Ohm's draft does not mention it.
- `pip install` at runtime produces new files (conforming) and then executes or loads them (D_exec or D_load, undeclared). This is by design; report it by cause.
- Capability checks are very frequent. Measure the `cap_capable` event rate before relying on it.
- eBPF with CO-RE needs Linux kernel 5.8 or later (VERIFY).

## 8. Phase 5: Scoring, attribution, alerts and the violation log (RIV)

Phase 5 turns each detection into an alert a person can act on: a priority score, the dependency path and image layer it traces to, the clause it broke, and a tamper-evident log entry. It runs only when a detection happens, so graph queries are allowed here. This is contribution 3.

**In the draft:** Eqs. (62)–(80).

### Step 1: Context (Eqs. 62–64)

For each detection the RIV builds 𝒞_D = (o_D, f_D, p_D, δ_D, ℓ_D): the object involved, its file, the owning package, that package's depth and the layer. All five come straight from the cached indices (J_pkg, J_depth, J_layer), so the node can compute them without touching the graph. For a behavioural detection, the object is the process and f_D is its executable.

### Step 2: Score (Eqs. 65–68)

The draft gives the shape of the score but no functions or weights. This proposal fills them in, reusing the values from our revised DS2 and adding the draft's origin term s_π:

```latex
S_{\mathrm{det}} = w_\tau\, s_\tau(\tau_D) + w_\pi\, s_\pi(\pi(x_D)) + w_c\, s_c(\mathcal{C}_D), \qquad s_c = \tfrac{1}{2}\,\rho(\delta_D) + \tfrac{1}{2}\,\kappa, \qquad \rho(\delta) = \begin{cases} 1 & \delta = \bot \\ \dfrac{\delta}{1+\delta} & \delta \in \mathbb{N} \\ 0.5 & \delta \text{ unresolved} \end{cases}
```

| Detection | s_τ |
|---|---|
| D_exec, undeclared (file in no layer) | 1.00 |
| D_hash, modified (declared path, new content) | 1.00 |
| D_load, undeclared (library in no layer) | 0.85 |
| D_write (declared file modified) | 0.80 |
| D_hash, relocated (declared content, new path) | 0.70 |
| D_cap | 0.60 |
| D_net | 0.55 |
| D_exec or D_load outside the closure (declared file) | 0.25, and the total is capped at Low |

| Term | Proposed values |
|---|---|
| s_π (origin of the broken clause) | AUTHENTICATED 1.0, INFERRED 0.5 |
| κ (capability class) | privileged 1.0, network 0.7, filesystem 0.5, none 0.2 |
| Weights | w_τ = 0.4, w_π = 0.2, w_c = 0.4, to be fixed by ablation on benign workloads |
| Buckets on 100·S | Critical ≥ 80, High 60–79, Medium 35–59, Low < 35 |
| Behavioural score S_beh | w_A = 0.6, w_c = 0.4, capped at 59 (Medium) |

ρ(δ) = δ/(1+δ) is the function Aj Ohm asked for in the earlier round. It rises with depth because deep transitive dependencies get the least review, and it stays below 1 for every declared package, so no declared package can outrank a file that came from nowhere. "Unresolved" depth is not ⊥: a base-image file whose package has no SBOM edges should not score like a dropped binary.

Two worked examples under this proposal:

1. `/tmp/.x9` is executed with `CAP_SYS_ADMIN` and belongs to no package: s_τ = 1.00, s_π = 1.0, ρ = 1, κ = 1.0, so s_c = 1.0 and S = 0.4 + 0.2 + 0.4 = **1.00 → 100, Critical**.
2. A file owned by a depth-2 dependency uses `CAP_CHOWN`, which the model did not predict: s_τ = 0.60, s_π = 0.5, ρ = 0.67, κ = 0.5, so s_c = 0.58 and S = 0.24 + 0.10 + 0.23 = **0.57 → 57, Medium**.

The two caps keep weak evidence from outranking signed contradictions. A declared file running outside the closure is weak evidence, and a behavioural score is a statistical hint.

### Step 3: Attribution (Eqs. 69–74)

The RIV traces two independent paths through the graph: the dependency path (root package → … → owning package → file) and the layer path (image → layer → file).

```cypher
// Layer path (Eqs. 71-72): which layer of this image introduced the file?
// The node already knows the effective layer from J_layer; this query is for display.
MATCH (i:Image {digest: $d})-[:CONTAINS]->(l:Layer)-[:INTRODUCES]->(f:File {path: $path})
RETURN l.digest, l.index ORDER BY l.index DESC LIMIT 1;   // no row: the file came from no layer

// Dependency path (Eqs. 69-70). Needs image scope on DEPENDS_ON, see fail point M4.
MATCH (pk:Package)-[:OWNS]->(:File {path: $path, sha256: $h})
MATCH p = shortestPath((root:Package {root: true})-[:DEPENDS_ON*0..8]->(pk))
RETURN p;
```

An empty layer path is itself the finding: nothing signed ever claimed that file exists.

### Step 4: The alert (Eqs. 75–78)

We propose adding the signing identity from the provenance to the draft's attribution record, so every field of the alert traces to signed evidence. Values below are illustrative.

```json
{
  "id": "det-0192",
  "time": "2026-09-26T10:14:22Z",
  "image_digest": "sha256:4a2c…",
  "container": "prod/web-7d9f",
  "process": { "pid": 4471, "exe": "/tmp/.x9" },
  "class": "D_exec", "subclass": "undeclared",
  "violated_clause": { "kind": "file_set", "detail": "path in no layer of the attested image", "origin": "AUTHENTICATED" },
  "context": { "package": null, "depth": null, "layer": null },
  "score": { "value": 100, "bucket": "critical" },
  "signing_identity": { "builder_id": "…", "source_commit": "9f31ab…", "rekor_log_index": 84213771 },
  "chain_id": "chain-0031"
}
```

The draft dropped chain grouping. We propose restoring it: detections whose processes share an ancestor within a window Δ_w (e.g. 60 s) get one `chain_id`, so a multi-stage attack is one incident rather than many unrelated alerts.

### Step 5: The violation log (Eqs. 79–80)

The draft uses a hash chain, H_k = H(H_k−1 ∥ H(A_D)), and relies on the RIV and EPGS being trusted. The weakness: whoever can write the log storage can recompute the whole chain. A signed checkpoint closes that at small cost and keeps his design:

```python
def append(record):                               # Eqs. (79)-(80)
    global head, k
    k += 1
    h = sha256(head + sha256(canonical_json(record)))   # sorted keys, no whitespace
    store(k, record, h)
    head = h
    if k % CHECKPOINT_EVERY == 0:                 # our addition
        sig = kms_sign(LOG_KEY, f"{k}:{h.hex()}")  # dedicated log key, never the build key
        store_checkpoint(k, h, sig)               # optionally publish to Rekor
```

A verifier recomputes the chain and checks it against the last signed checkpoint. Records written since that checkpoint remain unprotected; a shorter interval shrinks that gap.

## 9. Phase 6: Continuous trust re-evaluation (TR)

Phase 6 re-checks, every ΔR, whether the evidence behind each running image can still be trusted, and alerts once when it cannot. It never looks at runtime behaviour, so an image can lose trust while it behaves perfectly. This is contribution 4.

**In the draft:** Eqs. (81)–(96). **Runs:** a cluster-level Deployment on a timer. The draft gives no value for ΔR; we propose 300 s, plus an immediate run when a feed updates.

| Predicate | Eq. | Question | Data source | Tool |
|---|---|---|---|---|
| T_key | (85) | Is the signing key still acceptable? | KMS key state and its timeline (created, rotated, disabled) | AWS `DescribeKey` → `KeyState`; GCP key-version state; Vault transit has no simple "disabled" flag (OD4) |
| T_trans | (86) | Does the transparency evidence still verify? | Stored inclusion proof against the current signed tree head, plus a consistency proof between old and new tree heads | Rekor client or sigstore-python |
| T_builder | (87) | Is the builder still trusted? | `builder_id` from the provenance against an organisational denylist | A ConfigMap or JSON file |
| T_comp | (88) | Has a declared component been flagged? | SBOM package URLs against OSV advisories and VEX statements | OSV batch query API |

Trust is the AND of the four (Eq. 89). The TR alerts only when trust flips from 1 to 0 (Eq. 90), names the predicates that failed (Eq. 91), and for a component failure traces the package's dependency path and layer through the graph. The EPGS stores the new state either way (Eq. 93), so an image that stays untrusted produces no repeat alerts.

```python
def re_evaluate(d, ctx, prev):                   # every ΔR, for each running digest d
    T = {"key":     key_check(ctx.key, now()),
         "trans":   transparency_check(d, ctx.sigs, ctx.rekor),
         "builder": builder_check(ctx.builder_id),
         "comp":    component_check(ctx.purls)}
    trusted = all(T.values())                     # Eq. (89)
    if prev.trusted and not trusted:              # Eq. (90): alert on the flip only
        failed = [x for x, ok in T.items() if not ok]           # Eq. (91)
        emit_trust_alert(d, failed, context_for(d, failed))     # Eqs. (92), (94)
    save_state(d, T, trusted, now())              # Eq. (93)
```

The draft makes each predicate "policy controlled" without giving a policy. A starting policy:

| Event | Proposed policy |
|---|---|
| Key disabled after suspected compromise | Withdraw trust from every image signed with it |
| Key rotated for routine reasons | Keep signatures made before the rotation; record that this rule applied |
| Builder added to the denylist | Withdraw trust |
| A declared package gets an OSV malicious-package advisory (ID starting `MAL-`) | Withdraw trust |
| A declared package gets an ordinary CVE | Report only; withdraw if a VEX statement says "affected" and severity meets the threshold |
| An inclusion or consistency proof fails | Withdraw trust; the log itself may have been altered |

Runtime state and trust state stay separate (Eqs. 95–96). A container can be conforming but untrusted, or deviating but trusted, and the alert says which.

**Pitfalls:**

- Rekor supplies the timestamp, never the revocation signal. Revocation comes from the KMS and the advisory feeds.
- If we use Vault transit, confirm what it returns for a retired key before building T_key on it (OD4).
- Query OSV in batches and cache results; one call per package every 5 minutes will hit rate limits.
- The draft handles 1 → 0 only. Decide what a 0 → 1 recovery does; we suggest a state update and a log entry, no alert.
- Trust withdrawal raises an alert and nothing else. Stopping pods is out of scope.

## 10. The three ML models

The running system has two learned models, and the evaluation has a third. They must never share code, training data or model files. The draft now specifies both in-system models (Algorithms 1 and 2), which answers the old question of which model the advisor required: both are in scope.

|  | ML-A: capability model | ML-B: behavioural model | ML-C: evaluation baseline |
|---|---|---|---|
| Where in the draft | Phase 3, Step 3; Algorithm 1 | Phase 4, Step 4; Algorithm 2 | Evaluation plan ("independently trained learned-anomaly detector") |
| Algorithm | LightGBM, multi-label | Isolation Forest | Isolation Forest, a separate instance |
| Runs | Once per image digest, cluster | Per process window, node | Every event, node, experiments only |
| Input | Feature vector z_I (config, packages, closure, deployment) | Features of conforming-event windows | Features of all events |
| Output | Predicted capabilities and egress, labelled INFERRED | Anomaly score s̄_A in [0, 1] | The anomaly baseline PROVBIND is compared against |
| Trained on | Images profiled in a sandbox (capabilities used, destinations contacted) | Benign conforming traces | All benign traffic |

**ML-A** is the one place the design derives policy from observation, which is what the paper criticises in other systems. That is why its outputs are labelled INFERRED and why s_π weights a broken prediction below a broken signed claim. Its training set is the largest hidden task in the project. The curated allowlist is the baseline ML-A must beat, so build it first and report ML-A against it.

**ML-B** has an unanswered question. The draft stores a behavioural model per image, ℳ_I^beh, in the EPGS at compile time (Eq. 49). No step says where its training data comes from, and at compile time the image has never run. Three ways out:

1. **One global model** with features that do not depend on the image. Simplest; recommended for the prototype.
2. **Per-image models trained in CI**, by running the image's own tests in a sandbox under Tetragon. It fits the "evidence produced at build time" story but costs a sandbox run per image.
3. **A burn-in period in production.** Avoid it: behaviour that is already malicious during burn-in is learned as normal, the exact weakness the paper criticises.

**ML-C** shares ML-B's algorithm but not its role. The baseline sees every event and sits outside the system; ML-B sees only events that passed verification. If they shared a script, model file or training data, the evaluation would compare PROVBIND with one of its own parts.

## 11. Tools and algorithms at a glance

Every tool and algorithm the build needs, by phase. The tool choices are ours; the draft names only LightGBM, Isolation Forest, eBPF and the Cuckoo filter.

| Phase and component | Tools | Algorithm | Cost |
|---|---|---|---|
| 1. Build the image | BuildKit (`docker buildx`) or Kaniko; crane | SHA-256 content addressing | Once per build |
| 1. SBOM | syft, CycloneDX JSON | Package-database enumeration | Once per build |
| 1. Provenance | BuildKit provenance; in-toto Statement v1, SLSA v1 predicate | — | Once per build |
| 1. Signing | cosign with a KMS key (Vault transit or cloud KMS) | ECDSA P-256 over DSSE PAE | Once per build |
| 1. Transparency | Rekor | Merkle inclusion and consistency proofs | O(log n) per proof |
| 2. Admission decision | Kyverno `verifyImages`, or Sigstore policy-controller | Signature and attestation checks | Per pod, milliseconds |
| 2. Evidence retrieval and binding | Python, Kubernetes client (watch), cosign, crane | Digest recomputation, subject matching | Once per new digest |
| 3. Files and layers | crane, `tarfile`, `zstandard`, `hashlib` | Ordered layered union with whiteouts, two passes per layer | O(tar entries) |
| 3. Dependency depth | Python | Multi-source breadth-first search | O(V + E) |
| 3. Ownership Φ | Readers for dpkg, apk, rpm, dist-info, npm, Go build info | Record parsing and purl matching | O(files) |
| 3. Execution and load closure | pyelftools or LIEF | Worklist reachability over shebangs, PT_INTERP, DT_NEEDED | O(V + E) |
| 3. Capability and egress inference (ML-A) | LightGBM, scikit-learn | Multi-label gradient-boosted trees | Milliseconds per image |
| 3. Runtime indices | Python `dict` and `set`; Cuckoo filter optional | Hash tables | O(1) per lookup |
| 3, 5. Provenance graph | Neo4j (Kuzu fallback), Python driver | Batched MERGE; bounded traversals | Per digest; per detection |
| 4. Event collection | Tetragon (eBPF), TracingPolicy | In-kernel selectors | Per event |
| 4. Deterministic check | Python in the node DaemonSet | Set membership in a fixed decision order | O(1) per event |
| 4. Behavioural check (ML-B) | scikit-learn `IsolationForest` | Average isolation path length over t trees | O(t log ψ) per window, ψ = 256 |
| 5. Scoring | Python | Weighted sum with caps | Per detection |
| 5. Attribution | Cypher | Shortest dependency path; layer lookup | Per detection |
| 5. Violation log | `hashlib`; KMS log key and Rekor if checkpoints are adopted | Hash chain, plus signed checkpoints | O(1) per append |
| 6. Trust re-evaluation | KMS SDK, Rekor client, OSV API, VEX documents | Predicate evaluation, transition detection | Every ΔR |
| Evaluation | Falco, ML-C (Isolation Forest), pandas or DuckDB | Precision, recall, F1, FPR | Offline |

**Environment:** Linux kernel 5.8 or later for CO-RE eBPF (VERIFY), Python 3.11, kind or minikube on a 16 GB laptop for development, and one bare-metal Ubuntu machine for the overhead numbers. A virtual machine inflates eBPF overhead measurements.

## 12. Evaluation plan

The draft's evaluation plan is ours, unchanged, and it does not yet test anything Aj Ohm added: the behavioural path, trust transitions or binding failures. It also has no ablations and no adversarial case, which our DS1 plan had. This is the plan with those gaps filled.

**The claim under test.** At matched recall, PROVBIND has a lower false-positive rate than Falco and than a learned anomaly detector. Report FPR next to F1, never folded into it.

**Metrics:** precision, recall, F1, false-positive rate and accuracy, with "supply chain violation" as the positive class; for multi-stage scenarios, the fraction of attack stages detected.

**Dataset.** SynthChain's attack scenarios ship without signed provenance or SBOMs, and most are not containerised. We re-create their attack semantics inside an attested container testbed and report that reconstruction as part of the method. The paper's citation for it currently prints as [?] (fail point M14).

**Baselines:**

1. Falco with its default rules (rule-based runtime monitor).
2. ML-C, an Isolation Forest trained on all events (learned anomaly detector).
3. Admission-time signature verification alone.

**Ablations,** one switched off at a time:

- each envelope layer: files, packages, closure, capabilities, egress;
- the origin term s_π;
- strict closure as in Eq. (55) against the split classes proposed in Section 7;
- the behavioural path;
- ML-A against the curated allowlist.

**Adversarial case.** Run one attack that stays entirely inside the envelope, the mimicry pattern of Goyal et al. [19]. Report whether the behavioural path catches it. If nothing catches it, report the miss; that is the honest boundary of the method.

**Benign workloads that must not alert.** These keep the false-positive number honest: `pip install` at runtime, `kubectl exec` sessions, cron jobs, JIT compilers writing to `/tmp`, log rotation, injected sidecars, DNS lookups (which load glibc NSS modules), and writes to mounted volumes.

**New items for the draft's additions:**

- binding failures: how often, and why;
- trust-alert latency: time from a key being disabled, or an advisory being published, to the alert;
- duplicate suppression: one alert per trust loss, as Eq. (90) promises.

**Cost.** Measure per-event verification latency, node CPU and memory, ring-buffer drop rate under burst load, compile and index time per image, resident index memory, cache hit rate at realistic replica counts, and the cold-start window length. Report overhead relative to Tetragon or Falco already running, since the kernel collection cost is inherited, not introduced by PROVBIND.

## 13. Build plan: where the team starts

Build the thinnest version of every phase first. The first hard gate is one image, one attack and one clause-citing alert, end to end, by week 6. This 14-week plan is our proposal; Aj Ohm has not approved it, and week 1 has no fixed date yet.

| Weeks | Deliverable | Phases |
|---|---|---|
| 1–2 | kind cluster with Tetragon and Falco; ML-C baseline trained on the reconstructed scenarios | 4, evaluation |
| 3–4 | Attestation pipeline: every test image signed, with SBOM and provenance; Vault or cloud KMS decided | 1, 2 |
| 5–7 | Compiler: files and layers, packages, depth and Φ, indices, Neo4j load | 3 |
| 6 | **Gate:** one image, one attack, one alert that cites its clause | 1–5 |
| 8–9 | All five Tetragon event kinds, binding, cache, runtime hashing | 4 |
| 10–11 | Deterministic verifier with the decision order, scoring, attribution, hash-chain log | 4, 5 |
| 11–12 | Trust re-evaluator; ML-A against the allowlist; ML-B | 6, 3, 4 |
| 12 | Full evaluation, ablations and overhead | Evaluation |
| 13 | The adversarial in-envelope attack | Evaluation |
| 14 | Write-up | — |

The baselines come first on purpose. Falco and ML-C need no PROVBIND code, and they give the numbers PROVBIND must beat before anyone knows whether it does.

**Day one, concretely:** install kind, Tetragon and Falco on a Linux machine with a recent kernel, then run the Phase 1 script from Section 4 on one small image and confirm that `cosign verify-attestation` succeeds against the KMS key. Everything later depends on that one working image.

The work splits into four streams. Roles are still unassigned; one way to divide them:

1. **Data and evaluation:** scenario reconstruction, benign workloads, baselines, metrics.
2. **Evidence and compiler:** Phases 1–3, including ML-A.
3. **Node side:** Tetragon policies, binding, cache, verifier, ML-B.
4. **Alerts and trust:** scoring, attribution, the log, Phase 6, and the paper.

## 14. Fail points and fixes

Thirty-one fail points: five critical, seventeen major, nine minor. The critical ones can break the security argument or the central claim; the major ones are what a reviewer or Aj Ohm will ask about; the minor ones are writing and layout. Equation numbers refer to Aj Ohm's draft.

### Critical

- **C1. The SBOM and provenance are never signed in the model (Eq. 5).** σ_I signs only d_I, and Eq. (10) checks only that. Anyone who can write to the registry could swap the SBOM or provenance, and every later phase would trust it. Fix: sign each evidence object (what `cosign attest` does), or sign H(𝓑_I), and make v_sig check every signature.
- **C2. The closure is treated as complete (Eq. 55 and D_load).** 𝒬_I cannot see what a shell script launches or what `dlopen` loads, such as Python native extensions or glibc's `libnss_dns` during a DNS lookup. Under Eq. (55), `sh -c ls` and every DNS lookup become contradictions, which can push the false-positive rate above Falco's and sink the central claim. Fix: split each class into "file in no layer" (strong) and "declared file outside the closure" (weak, capped at Low), as in Section 7.
- **C3. The runtime hash H(f) has no source.** Eq. (55) and D_hash need the executed file's hash, but Tetragon reports paths. Without a source, D_hash never fires and a declared binary overwritten in place goes unseen. Fix: name the source (IMA or hashing `/proc/<pid>/exe`), guard every hash test, and state the path-only fallback.
- **C4. Admission and compilation timing is undefined (Phases 2–3).** The pod starts at admission; the envelope takes seconds; the draft is silent on the events in between. If the AEM is a webhook that waits for compilation, every deployment pays that delay. Fix: a standard controller enforces admission, compilation runs asynchronously, early events are buffered or new pods held by a scheduling gate, and the window is reported.
- **C5. The per-image behavioural model has no training source (Eq. 49, Algorithm 2).** ℳ_I^beh is stored at compile time, before the image has ever run. Fix: a global model for the prototype, or per-image models trained from CI sandbox runs, plus a stated fallback for new images.

### Major

- **M1. The scoring functions have no values (Eqs. 65–68).** s_τ, s_π, s_c, the weights and the buckets are undefined, with no worked example. The abstract and contribution 3 promise ranking by dependency depth, which the formula no longer shows. Fix: Section 8's tables, with ρ(δ) written inside s_c.
- **M2. A behavioural hint can outrank a signed contradiction.** S_det and S_beh share the [0, 1] range. Fix: cap S_beh at Medium, or give behavioural findings their own queue.
- **M3. The graph may end up on the event path.** Eqs. (45)–(48) create Container, Process, EXECUTES and LOADS "as the workload executes", yet Phase 4 Step 2 keeps the graph off the per-event path. Fix: write runtime nodes asynchronously, only for processes involved in a detection.
- **M4. Depth is per image, but Package nodes are shared.** Fig. 2 stores depth on the Package node and DEPENDS_ON carries no image, so two SBOMs merge and a traced path can cross images. Fig. 2 also draws an Image–Package "declared in SBOM" edge that Eq. (40) omits. Fix: add DECLARES (Image → Package) with depth on the edge, and tag DEPENDS_ON with the digest.
- **M5. Where detections live is inconsistent.** The abstract says a graph database stores them, the EPGS description says the graph links violations, Eq. (39) has no detection vertex, and Phase 5 writes them to the hash-chained log. Fix: make the log authoritative, optionally mirror detections into the graph off the hot path, and align the abstract.
- **M6. The hash chain has no anchor (Eq. 79).** Anyone who can write the log storage can rebuild the chain. Fix: signed checkpoints with a separate KMS log key, optionally published to Rekor (Section 8).
- **M7. Chain grouping was removed.** A multi-stage attack now yields many unrelated alerts, while SynthChain's ground truth is per chain. Fix: group detections by process ancestry within Δ_w; a SPAWNED edge between Process nodes can hold this.
- **M8. Egress is undefined.** N̂_I appears only in Eq. (35), D_net has no rule, and the LightGBM step covers only capabilities. Kernel events also carry IP addresses, not hostnames. Fix: define N̂_I as predicted ports and protocols plus an operator allowlist of destinations, matched via recorded DNS answers or CIDR ranges.
- **M9. "Declared capabilities" have no source.** Algorithm 1 labels 𝒞_I^decl AUTHENTICATED, but no attestation format carries capabilities. If they come from the pod's securityContext, that is operator configuration, not signed evidence. Eq. (34) and Algorithm 1 line 6 also define 𝒞_I differently. Fix: name the source; label pod-spec values CONFIGURED.
- **M10. Writes under mounted volumes look like tampering.** A volume mounted over an image directory (such as `/var/lib/mysql`) and Kubernetes-managed files (`/etc/hosts`, `/etc/resolv.conf`) turn normal writes into D_write. Fix: remove each container's mount points from the protected set when it starts.
- **M11. D_load and D_cap had no event source.** Our design gave hooks only for exec, file-open and `tcp_connect`. Fix: add the executable-mapping and capability hooks from Section 7, verify them on our Tetragon version, and measure their event rates first.
- **M12. No decision order across classes.** An exec at a new path whose content matches a declared file is both D_exec and D_hash. Fix: state the order, as in Section 7.
- **M13. The evaluation plan does not test the draft's additions** and has no ablations or adversarial case. Fix: Section 12.
- **M14. The dataset citation is broken and the closest work is gone.** SynthChain prints as [?]. GoLeash and FuseChain, the nearest systems, were removed, so the novelty claim loses its closest comparison. Fix: restore SynthChain, which is the dataset, and ask whether one sentence on GoLeash and FuseChain can return.
- **M15. The Cuckoo filter is still on the hot path.** Most events conform, so most lookups are hits that need the full index anyway; the filter adds a step and memory. Fix: plain `dict` and `set`, with the filter kept only if measured memory pressure justifies it.
- **M16. "Unresolved" depth could score like "no package".** Scored as ⊥, a base-image file looks as bad as a dropped binary. Fix: score unresolved as neutral (ρ = 0.5) and report the unresolved fraction per image.
- **M17. Our own compiler spec had a whiteout bug.** It deleted files on meeting an opaque marker, including files the same layer added earlier. Fix: the two-pass version in Section 6. This one is in our notes, not in the draft.

### Minor

- **m1. Eq. (40) overflows its column and prints over Eq. (50);** both are unreadable in the PDF. Split the edge set over two lines.
- **m2. Heading glitches:** "textbfPhase 3" is a missing backslash; phase headings end in ".:"; Phase 6 is styled differently from the others.
- **m3. Notation:** Eq. (32) uses three different C symbols (𝒞^cfg, 𝒞, C_I) and different arguments from Algorithm 1 line 1. τ means transparency evidence (Eq. 5), event type (Eq. 50) and deviation class (Eq. 60). 𝒟 means both dependency edges and detection classes. N̂_I and 𝒞^cfg are never defined, and Eq. (35) calls an envelope with inferred parts "deterministic".
- **m4. Two consecutive paragraphs open with "Thus,"** in Phase 4, Step 4. Merge them.
- **m5. References:** [18], [26], [28] and [29] are never cited. [28] (RFID authentication for physical supply chains) is off-topic, and [29] (attacks on botnet builders) is tangential. Numbering does not follow first citation. "IEEE Security Privacy" and "Computers, Materials Continua" lost their "&", and [17] still lacks volume and pages.
- **m6. The abstract no longer matches the body.** It never mentions the threat model, the dual-path design or the separate trust state.
- **m7. Fig. 1 does not show the seven entities.** Label its regions SP, SCR, AEM, EPGS, KWN, RIV and TR; rename "Database" to EPGS; replace "No/Yes" with "conforms/contradicts"; make the LightGBM arrow one-way, since training is offline.
- **m8. There is still no conclusion section.**
- **m9. Phase 1 reads as if PROVBIND runs the CI.** Say it is existing tooling that PROVBIND consumes unchanged.

## 15. Questions to settle with Aj Ohm

Eight decisions only he can make; each one changes either the paper or the build. The first three matter most before the presentation.

- [ ] **Is the AEM the admission controller itself, or a manager beside a standard one?** If it is the webhook, compilation cannot wait inside it (C4).
- [ ] **May we add signed checkpoints to the hash chain?** It is a small change that removes the need to trust the log's storage (M6).
- [ ] **Should concrete scoring values return,** as a table of s_τ, s_π, ρ(δ) and κ with one worked example (M1)?
- [ ] **Is one global behavioural model acceptable for the prototype,** instead of a model per image (C5)?
- [ ] **May SynthChain stay as the dataset reference, and may GoLeash and FuseChain return in one sentence** despite being arXiv papers (M14)?
- [ ] **Should executing a declared file outside the closure be a full contradiction** as in Eq. (55), or a separate weak class (C2)?
- [ ] **What must the DS2 "Requirements Specification and Mockup" contain,** and does it belong in this paper or in separate documents?
- [ ] **Should [18], [26], [28] and [29] be cited somewhere or dropped** (m5)?
