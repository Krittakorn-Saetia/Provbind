**SENIOR PROJECT SF9-26**

**PROVBIND: Continuous Provenance-Bound Runtime Integrity**

**Verification for Detecting Software Supply Chain Attacks**

**in Cloud-Native Containers**

**Project Concept**

Submitted to

School of Information, Computer and Communication Technology

Sirindhorn International Institute of Technology

Thammasat University

August 2026

By

Takorn Sripetcharakul          6622771283

Krittakorn Saetia          6622770475

Sirasit Wongtawewat          6622770426

Panachai Buddharaksa          6622780664

Advisor: Dr. Somchart Fugkeaw

**Project Overview**

**Abstract**

Container images have become a primary distribution channel for software, and supply chain attacks that reach production through them are among the most severe threats to modern systems. Existing defences establish trust before execution: build frameworks emit signed provenance attestations and software bills of materials (SBOMs), and admission controllers verify these signatures before a workload is permitted to run. Such mechanisms prove where an artifact originated but not whether it is benign, and they establish trust only at a single instant. Runtime monitors observe behaviour thereafter, but derive their notion of correct behaviour from observed execution — operator-authored rules, dynamic profiling of test workloads, or unsupervised learning over benign traces — and remain blind to the signed declaration that already describes what the container was supposed to contain. Consequently, no deployed system asks whether a running container remains consistent with what was cryptographically signed for it.

This project proposes PROVBIND, a continuous provenance-bound runtime integrity verification framework. Rather than discarding the attestation after admission, PROVBIND retains it and treats it as an authoritative specification against which observed execution is verified throughout the container lifetime, reframing runtime detection from a statistical problem into a verification problem grounded in cryptographic evidence.

The framework introduces three key mechanisms. First, a baseline compiler derives an expected behavioural envelope from the signed provenance and SBOM, combining deterministic extraction of declared files and package closures with static binary analysis and a learned multi-label classifier that predicts required capabilities where the declaration is semantically silent; the envelope is indexed by path, content hash, layer, and dependency depth at admission, so that subsequent verification reduces to constant-time lookups. Second, a binding verifier continuously compares kernel-level observations against that envelope and produces clause-citing alerts that name the specific signed claim contradicted, ranked by distance from the declared dependency set and attributed to the image layer that introduced the violation. Third, a trust re-evaluation loop periodically re-examines signing key state and external revocation intelligence against the transparency log timestamp, allowing trust in an already-running container to be withdrawn after admission.

PROVBIND is evaluated on containerised supply chain attack scenarios reconstructed with build-time attestations, against rule-based and learned-anomaly runtime baselines, with mechanism ablations. Detection effectiveness is evaluated jointly with operational cost through classification metrics, per-event verification latency, kernel event drop rate, and envelope cache amortisation. The resulting framework aims to provide explainable, cryptographically grounded runtime detection of post-deployment supply chain compromise, and to demonstrate that specification-based verification reduces false positives relative to learned-anomaly detection at matched detection rate.

**Introduction**

Software supply chain attacks have become one of the most severe threats to modern software systems. Rather than attacking a target directly, adversaries compromise an upstream component that the target already trusts, so that malicious code reaches production through legitimate and fully authorised channels. Because contemporary applications are assembled largely from third-party open-source dependencies and distributed as container images, a single compromised component can propagate simultaneously to thousands of downstream organisations [1], [2]. In response, the software industry has converged on build-time attestation as the primary defence: frameworks such as SLSA generate signed provenance recording how an artifact was produced, a Software Bill of Materials (SBOM) enumerates the components it contains, and tools such as cosign cryptographically sign the resulting image and bind these declarations to its content digest [3], [4], [5].

A fundamental limitation of this defence is that it establishes trust at a single instant and proves the wrong property. Admission controllers verify signatures and attestations immediately before a container is permitted to start, and admit only artifacts satisfying the configured policy. This is effective against artifact substitution and unauthorised builds, but a signature demonstrates the origin of an artifact rather than its benignity. The xz-utils backdoor of 2024 illustrates the distinction precisely: a contributor spent approximately two years establishing maintainer trust in a compression library present on essentially every Linux system before inserting a backdoor, and the resulting artifact was correctly signed, built from the genuine repository by the legitimate maintainer, through the authentic release process. It would have satisfied every attestation-based admission policy deployed today, and was ultimately discovered by accident rather than by any automated control. Vulnerability scanning offers no remedy, since it detects only previously catalogued weaknesses and cannot identify an intentionally introduced backdoor [7].

Runtime observation is therefore the remaining line of defence, and recent work has advanced it considerably. Provenance-based intrusion detection systems reconstruct attack behaviour from system-level event graphs [10], [11], supply-chain-specific systems fuse multiple runtime telemetry sources to reconstruct attack stages [16], and policy-enforcement systems constrain container behaviour to a profile derived from prior execution [6]. These approaches differ in mechanism but share a common characteristic: each derives its notion of correct behaviour from observation, whether by static analysis of code, dynamic profiling of execution, or statistical learning of a behavioural baseline. Consequently, behaviour that was already malicious during the learning window is absorbed into the model as normal, while behaviour that is legitimate but infrequent is reported as anomalous, contributing to the alert fatigue that burdens security operations teams [12]. GoLeash states the limitation explicitly, observing that rarely executed paths missed during profiling are subsequently flagged at runtime as false positives [6]. Critically, all of these systems are provenance-blind: although a signed attestation and SBOM describing precisely what the container was declared to contain already exist, they are discarded after admission and never consulted thereafter. The question of whether a running container remains consistent with what was cryptographically signed for it is therefore never asked.

Treating the attestation as a runtime specification, however, is not merely a matter of retaining it. A signed declaration describes an artifact’s composition — its files, its layers, its package closure — whereas runtime observation yields events, and the two are expressed in different vocabularies. Bridging this semantic gap requires deriving, from component-level declarations, a concrete envelope of behaviour those components are capable of exhibiting. Some of this derivation is deterministic: the declared file set and layer digests follow directly from the image, and the package dependency closure follows directly from the SBOM. Other parts are not. An SBOM records that a container contains a particular HTTP client library, but not that the library requires outbound network access, because capability and egress requirements are not expressed in any current attestation format. The declaration is complete with respect to composition and silent with respect to consequence.

A further challenge concerns the temporal scope of trust. A container is a duration rather than a moment, and may execute for weeks or months after admission. During that interval, the evidence underpinning the original admission decision may cease to hold: a signing key may be disabled, a builder identity may be found compromised, or a vulnerability advisory may be published against a component the image declares. Withdrawing trust from an already-running workload requires a revocation signal, and the transparency log that anchors the original signature cannot supply one, being append-only by construction and capable of proving only that a signature existed at a given time. Continuous verification therefore requires an explicit and separate source of revocation intelligence.

Finally, evaluating attestation-grounded verification introduces a methodological difficulty absent from behaviour-learning approaches. Published supply chain attack corpora provide runtime telemetry and ground-truth annotations, but were assembled to evaluate detectors that consume telemetry alone, and consequently ship without the signed provenance and SBOM documents that an attestation-grounded system requires as input; the majority of their scenarios are additionally not containerised [17]. Credible evaluation therefore requires reconstructing the build-time evidence for each scenario within an attested container testbed, and reporting this reconstruction explicitly as part of the methodology rather than presenting the corpus as though it were consumed unmodified.

To address these challenges, we propose PROVBIND, a framework for continuous provenance-bound runtime integrity verification. PROVBIND retains the attestation verified at admission rather than discarding it, and compiles the signed provenance and SBOM into an expected behavioural envelope comprising the declared file set with per-layer attribution, the package dependency closure annotated by depth, and the process and library set implied by the declared entrypoint; a learned capability model supplies expectations for permissions and network egress, where the declaration is silent. An eBPF collector observes process execution, file access, and network connection events at kernel level, and a binding verifier determines, for each event, whether it contradicts the declared envelope. Detection is thereby reframed from an unsupervised statistical problem into a verification problem grounded in cryptographic evidence: a violation constitutes a contradiction of a signed claim rather than an estimate of improbability. Because every alert references the specific attestation clause it contradicts, PROVBIND produces explanations that behaviour-learning detectors cannot structurally provide; deviations are ranked by the offending component’s distance from the declared dependency closure, attributed to the image layer that introduced them, and committed to a Merkle-anchored append-only log so that detection output is itself tamper-evident [21]. A separate re-validation loop periodically re-evaluates whether each running image remains trustworthy, querying signing key state and external revocation intelligence, with the transparency log providing the immutable timestamp anchor.

PROVBIND is evaluated on containerised supply chain attack scenarios reconstructed with build-time attestations, against a rule-based runtime monitor and an independently trained learned-anomaly detector, with ablations isolating the contribution of each envelope layer, of severity scoring, and of the residual screening stage. Detection effectiveness is assessed jointly with deployment cost through detection rate, false positive rate, detection latency, and runtime overhead measured relative to existing runtime collection rather than to an unmonitored host, together with an explicit analysis of adaptive adversaries that constrain their behaviour to remain within the declared envelope [18]. Overall, PROVBIND investigates whether verification against a cryptographically signed specification can detect post-deployment supply chain compromise with fewer false positives than learned-anomaly detection at matched detection rate, while producing alerts whose justification is traceable to signed evidence.

**Literature review**

**Build-time provenance and signing. **A mature line of work establishes verifiable statements about how software artifacts are produced. The in-toto framework defines an attestation model providing end-to-end guarantees over the steps of a software supply chain [3], and SLSA formalises build-integrity levels with requirements culminating in non-falsifiable provenance from a hardened build platform [4]. Sigstore supplies the signing and transparency infrastructure that made these attestations practical at ecosystem scale [5]. Empirical work nevertheless finds substantial obstacles to deployment [7], and a study of SBOM practice reports that the gap between specification and tool implementation is wide enough to undermine interoperability claims [8]. These systems supply the signed evidence PROVBIND consumes, and their limitation is temporal rather than cryptographic: verification occurs once, before execution.

**Container runtime monitoring. **eBPF has become the standard mechanism for observing container behaviour with acceptable overhead, and production monitors apply rule sets to kernel event streams. Recent work combines flow-based network metadata with host-based system call traces for malicious container detection, reporting that single-source approaches encounter limits that hybrid analysis overcomes [9]. Such systems are effective at expressing operator intent but possess no knowledge of the build-time declaration, and their rules are authored rather than derived.

**Provenance-based intrusion detection. **A parallel line reconstructs intrusions from system-level provenance graphs. NodLink performs online fine-grained detection and investigation of multi-stage attacks [10], and ORTHRUS addresses the quality-of-attribution problem that has limited the operational value of this family, namely that detection alone does not localise the responsible entity [11]. A comprehensive comparison of state-of-the-art systems finds that simpler configurations frequently match elaborate ones [12], and an evaluation-realism critique argues that reported performance often does not survive industrial conditions [13]. This work motivates the emphasis PROVBIND places on attribution and on honest evaluation, but its ground truth remains a learned model of observed behaviour. Note that provenance in this literature denotes graphs of runtime system events, whereas the present work uses the term for signed build provenance.

**Runtime policy derivation. **Closest to the present work are systems that derive an execution policy and enforce it at runtime. Confine generates system call policies by static analysis of container images to reduce attack surface [14]. A Node.js framework infers package capabilities and enforces them at require-time across a large registry sample, incurring policy generation cost once per software version [15]. GoLeash profiles package behaviour dynamically and enforces per-package least privilege at package-level granularity, remaining effective under obfuscation where static analysis fails [6]. Critically, its authors state that code paths not exercised during profiling are reported as violations at runtime, a limitation intrinsic to dynamic analysis. These systems differ from PROVBIND in the origin of the policy: all three derive it from the code, whether statically or dynamically, whereas PROVBIND derives it from signed build metadata that is complete by construction with respect to the declared file and package sets.

**Runtime supply chain detection and evaluation. **Very recent work targets supply chain attacks specifically at runtime, fusing multiple telemetry sources into temporal provenance graphs to reconstruct attack stages, with representations learned from benign execution traces [16]. A companion benchmark provides a multi-source runtime dataset spanning representative exploit scenarios across several ecosystems with chain-level ground truth, and reports that no single telemetry source is chain-complete [17]. That corpus supplies the attack semantics adopted here, although it is composed predominantly of non-containerised scenarios and ships without the signed build evidence this framework consumes, and is therefore reconstructed rather than used directly. Finally, mimicry attacks against provenance-graph intrusion detection demonstrate that adversaries able to constrain their behaviour within expected patterns can evade specification- and model-based detection alike [18], which motivates both the residual screening stage and the adversarial analysis in the evaluation plan.

**Learning components. **Where the signed declaration is semantically incomplete, the framework relies on established statistical methods rather than novel models. Multi-label classification supplies the mapping from declared components to required capabilities, and isolation-based anomaly detection provides both the residual screening stage and the comparison baseline, isolating outliers through recursive random partitioning with logarithmic-time inference suitable for per-event evaluation [19].

**Problem statement**

Despite mature build-time attestation and capable runtime monitoring, detecting supply chain compromise that manifests only after deployment remains unresolved. PROVBIND addresses the following key problems:

- **Signed Evidence Discarded at Admission: **Provenance attestations and SBOMs are generated, signed, and verified before execution, then discarded. No mechanism carries this evidence forward, so a container that has been running for weeks is never re-examined against the declaration under which it was admitted. Trust is established at a single instant although the workload persists for an extended period.

- **Provenance-Blind Runtime Verification: **Runtime monitors determine correct behaviour from observed execution rather than from any declared specification. Behaviour already malicious during the learning window is absorbed as normal, while legitimate but infrequent behaviour is reported as anomalous, contributing to the alert volume that burdens security operations. The signed document describing what the container should contain is available but unused.

- **Unexplainable Detection Output: **Because anomaly-based detectors possess no specification, they can report only that behaviour was improbable, not which claim it violated. Analysts therefore receive a score rather than a statement of contradiction, and violations cannot be attributed to the base image or build step that introduced them.

- **Semantic Gap Between Declaration and Behaviour: **An SBOM enumerates components, not permissions. No attestation format expresses the capabilities, system calls, or network destinations a declared dependency legitimately requires. Any framework binding behaviour to attestation must close this gap explicitly, and a framework that closes it by observation reintroduces the coverage limitation it set out to avoid.

- **Trust That Cannot Be Withdrawn: **Admission control is a one-way gate. If a signing key is subsequently disabled, or a builder identity is later found to be compromised, containers already running under that key continue executing without re-evaluation. There is no mechanism by which trust granted at admission can be revoked during execution.

**Impact and benefits**

PROVBIND targets organisations operating containerised workloads at scale, including platform engineering teams, cloud service providers, and security operations centres responsible for runtime defence.

- **Security analysts. **Every alert names the specific signed claim it contradicts and the image layer that introduced the offending artifact, replacing an unexplained anomaly score with a statement of contradiction and a partial root cause. This reduces the investigation time consumed by ambiguous runtime alerts.

- **Platform operators. **The framework consumes attestations that many organisations already generate for regulatory compliance, and requires no modification to application images or build pipelines. Envelope compilation is amortised per image digest rather than per container, so cost scales with the number of distinct images rather than the number of running workloads.

- **Compliance and audit functions. **Because verification is continuous, the system can assert positively that a workload has remained consistent with its signed build throughout its lifetime, and records violations in a tamper-evident log with an independently verifiable chain of custody. Existing tooling can attest only that a workload was consistent at the moment of admission.

- **Incident responders. **Layer attribution localises a compromise to a specific base image or build step, which identifies every other workload derived from the same layer and converts detection into the beginning of a scoped investigation.

- **The research community. **The framework establishes signed build metadata as a fourth source of runtime policy, alongside static analysis, dynamic profiling, and learned baselines, and the accompanying evaluation quantifies the precision consequences of that choice against both rule-based and learned alternatives.

**Framework**

PROVBIND is organised as a build-time evidence stage consumed unchanged, an envelope compilation stage, a kernel-level observation stage, and a verification and attribution stage, together with an independent trust re-evaluation loop. Figure 1 illustrates the procedure.

**Figure 1. **The PROVBIND verification pipeline. Signed provenance and SBOM documents produced by existing build infrastructure are retained at admission and compiled into a behavioural envelope; an eBPF collector observes runtime events, and the binding verifier classifies contradictions of the envelope, which are scored, attributed to an image layer, and committed to a tamper-evident log. A separate timer loop re-evaluates image trust independently of the event path.

**Procedure**

- **Build-time evidence. **The image is built by existing continuous integration infrastructure, which emits an SBOM enumerating the package closure and a SLSA provenance statement recording source commit, builder identity, and build parameters. Both documents are signed with a key held in a key management service and bound by digest to the image, and a record of each signature is submitted to a transparency log. PROVBIND consumes this stage unchanged and contributes no component to it; the build pipeline is a dependency of the framework rather than part of it.

- **Attestation retention. **An admission controller performs the conventional signature check and admits or rejects the pod. Independently, PROVBIND observes pod creation through the Kubernetes API and retrieves the corresponding attestations by content digest, verifying the signature chain and the transparency log inclusion proof. Retrieval is performed asynchronously rather than within an admission webhook, because envelope compilation requires downloading and expanding image layers and would otherwise add latency to every admission in the cluster. This retention is the point of departure from standard practice, in which the attestation is discarded once verified.

- **Digest verification. **The layer digests enumerated in the image manifest are compared against those recorded in the attestation subject. This check is inexpensive, runs once per image, and detects substitution of a layer between signing and deployment. It establishes that the artifact about to be compiled is the artifact that was signed, and is a precondition for treating the remaining declarations as authoritative.

- **Envelope compilation. **The retained documents are compiled into an expected behavioural envelope in four layers of decreasing determinism. The file layer expands each image layer in manifest order, honouring whiteout markers so that files deleted during the build do not widen the envelope, and records for every path both its content hash and the layer that introduced it. The package layer parses the SBOM dependency graph and assigns each component a depth by breadth-first traversal from the root component. The process layer resolves the declared entrypoint and derives its dynamic library closure; statically linked binaries expose no such closure and are covered instead by the file and package layers, a limitation reported explicitly in the evaluation. The capability layer is supplied by a learned model, since no current attestation format expresses permission or egress requirements. Compilation is performed once per image digest and is therefore amortised across every container instantiated from that image.

- **Index construction. **Because per-event verification must complete in constant time, the structures supporting it are derived once during compilation rather than at query time. A path index maps each declared path to its content hash and originating layer; a reverse content index maps each hash to the paths that declare it, distinguishing a binary relocated within the image from one absent from it entirely; a layer index resolves attribution by lookup rather than by graph traversal; and a depth index supplies the severity weighting derived from the package closure. The graph database is separately indexed on image digest, file path, content hash, layer digest, and package identifier, so that post-violation attribution does not scan. Indexing is keyed by image digest and is therefore performed once per distinct image, irrespective of how many containers are subsequently instantiated from it.

- **Envelope distribution. **The compiled envelope is persisted to a graph database recording images, layers, packages, and their relationships, and is additionally pushed to a node-local in-memory cache with an approximate membership filter fronting the file set. The filter admits negative answers definitively and positive answers probabilistically, so a membership assertion is confirmed against the authoritative set before an event is cleared. The graph database is queried only after a violation has been raised; no database access occurs on the per-event path.

- **Runtime observation. **An eBPF collector captures process execution, file access, and network connection events at kernel level, filtering by control group within the kernel so that events belonging to unmonitored workloads never cross into userspace. Events are enriched with pod and container identity at the point of capture. Where the kernel integrity subsystem is available, the content hash of an executed binary is obtained at execution rather than derived from its path, so that in-place replacement of a declared binary does not evade verification.

- **Binding verification. **For each event, the collector’s container identity resolves to an image digest and thence to the resident envelope in constant time, and the event is tested for membership against the relevant envelope layer. Contradictions are classified into five deviation types: undeclared execution, undeclared library load, write to a path declared immutable by the image, capability use beyond the declared profile, and undeclared network egress. Conforming events are discarded without further processing, which is the common case. Deviations are grouped by process ancestry within a sliding window so that a multi-stage compromise is reported as a single chain rather than as a sequence of unrelated alerts.

- **Residual screening. **Events cleared by verification are additionally examined by an anomaly model that screens the interior of the envelope for behaviour that is declared but atypical. This stage addresses the adaptive adversary who confines activity to declared components in order to avoid contradiction, and is explicitly a supplementary rather than a primary mechanism; it is trained on cleared events only, and is distinct in both data and instantiation from the learned-anomaly configuration used as an evaluation baseline.

- **Severity scoring and layer attribution. **Each deviation is weighted by its type and by the depth assigned to the responsible component during compilation. A binary absent from the SBOM entirely is treated as maximally distant and ranked above an anomalous operation attributable to a declared transitive dependency, on the basis that the former contradicts the declaration while the latter merely strains it. The violating path is then reverse-resolved through the layer index constructed during compilation, localising the deviation to the image layer that introduced it and thereby to the base image or build step responsible.

- **Alert assembly and tamper-evident recording. **The framework emits the observed event together with the specific attestation clause it contradicts, the assigned severity and provenance distance, the attributed layer, and the signing identity recorded in the provenance. Every field derives from signed evidence, which is the property that distinguishes clause-citing verification from anomaly scoring: the alert states not that behaviour was improbable but which signed claim it violated. Each record is committed to a Merkle-anchored append-only log, so that the detection output carries an independently verifiable chain of custody suitable for forensic use.

- **Trust re-evaluation. **Independently of the event path and on a fixed interval, the framework re-evaluates whether each running image should still be trusted. It confirms that the stored inclusion proof remains consistent with the current log tree head, that the signing key remains in an enabled state and that the recorded signing time precedes any rotation or disablement of that key, and that neither the image digest nor the builder identity has since appeared in a revocation source, whether an organisational denylist, a vulnerability advisory feed, or a subsequently published exploitability statement. The transparency log supplies the immutable timestamp anchor for these checks but not the revocation signal itself, which originates from the key management service and from external intelligence. A change in status raises a deviation on the same alert path, permitting trust to be withdrawn from a workload that was legitimately admitted.

**Evaluation**

Detection quality is assessed against ground-truth labels using standard classification measures, with a supply chain violation as the positive class. TP and TN denote correctly classified violating and conforming events, and FP and FN denote conforming events classified as violations and violations classified as conforming.

*Precision = TP / (TP + FP)*

*Recall (TPR) = TP / (TP + FN)*

*F1 = 2 × Precision × Recall / (Precision + Recall)*

*FPR = FP / (FP + TN)*

*Accuracy = (TP + TN) / (TP + TN + FP + FN)*

False positive rate is reported alongside the F-measure rather than folded into it, because the central claim of the framework concerns precision specifically: verification against a signed specification is expected to eliminate the class of false alarms that arises when a learned baseline encounters legitimate but infrequent behaviour. Detection is additionally reported as stage coverage per attack scenario, since a supply chain compromise proceeds through multiple stages and partial detection carries different operational value from complete reconstruction.

Because the framework must operate on the kernel event path, computational cost is measured on equal footing with accuracy: per-event verification latency, node-level CPU and memory overhead, kernel ring buffer event drop rate under burst load, and envelope compilation and index construction time per image. The resident memory of the index structures is reported separately, since it determines how many distinct images a single node can cache concurrently. Compilation and indexing cost is reported against the number of distinct image digests rather than the number of containers, since both are performed once per digest and shared across replicas; cache hit rate at realistic replica counts quantifies this amortisation. Overhead is reported relative to an existing runtime monitor rather than to an unmonitored baseline, because the kernel collection cost is inherited rather than introduced.

Evaluation uses containerised supply chain attack scenarios reconstructed with build-time attestations. Published corpora supply runtime telemetry and chain-level ground truth but were assembled to evaluate detectors consuming telemetry alone, and consequently ship without the signed provenance and SBOM documents this framework requires; the majority of their scenarios are additionally not containerised [17]. The attack semantics are therefore extracted from the published corpus and re-instantiated within an attested container testbed, and this reconstruction is reported explicitly as part of the methodology rather than presenting the corpus as though consumed unmodified. The full framework is compared against a rule-based runtime monitor, against an unsupervised anomaly detector trained on benign traces, and against admission-time signature verification alone; the anomaly detector is instantiated separately from the residual screening component so that the system is not compared against one of its own parts. Ablations isolate the contribution of each envelope layer, of severity scoring, and of residual screening. A final adversarial evaluation constructs an attack that deliberately remains within the declared envelope and reports the resulting miss, characterising the boundary of specification-based verification rather than asserting its absence [18].

**References**

[1] P. Ladisa, H. Plate, M. Martinez, and O. Barais, "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains," in Proc. IEEE Symposium on Security and Privacy (S&P), 2023.

[2] C. Okafor, T. R. Schorlemmer, S. Torres-Arias, and J. C. Davis, "SoK: Analysis of Software Supply Chain Security by Establishing Secure Design Properties," in Proc. ACM Workshop on Software Supply Chain Offensive Research and Ecosystem Defenses (SCORED), 2022.

[3] S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola, and J. Cappos, "in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes," in Proc. 28th USENIX Security Symposium, 2019.

[4] Open Source Security Foundation, "Supply-chain Levels for Software Artifacts (SLSA), Version 1.0 Specification," OpenSSF, 2023.

[5] Z. Newman, J. S. Meyers, and S. Torres-Arias, "Sigstore: Software Signing for Everybody," in Proc. ACM SIGSAC Conference on Computer and Communications Security (CCS), 2022, pp. 2353-2367.

[6] "GoLeash: Mitigating Golang Software Supply Chain Attacks with Runtime Policy Enforcement," arXiv preprint arXiv:2505.11016, 2025.

[7] M. R. Rahman et al., "Analyzing Challenges in Deployment of the SLSA Framework for Software Supply Chain Security," arXiv preprint arXiv:2409.05014, 2024.

[8] B. Xia, T. Bi, Z. Xing, Q. Lu, and L. Zhu, "An Empirical Study on Software Bill of Materials: Where We Stand and the Road Ahead," in Proc. IEEE/ACM International Conference on Software Engineering (ICSE), 2023.

[9] S. Ryu et al., "Hybrid Runtime Detection of Malicious Containers Using eBPF," Computers, Materials & Continua, 2026.

[10] S. Li et al., "NodLink: An Online System for Fine-Grained APT Attack Detection and Investigation," in Proc. Network and Distributed System Security Symposium (NDSS), 2024.

[11] B. Jiang et al., "ORTHRUS: Achieving High Quality of Attribution in Provenance-based Intrusion Detection Systems," in Proc. 34th USENIX Security Symposium, 2025.

[12] T. Bilot, B. Jiang, Z. Li, N. El Madhoun, K. Al Agha, A. Zouaoui, and T. Pasquier, "Sometimes Simpler is Better: A Comprehensive Analysis of State-of-the-Art Provenance-Based Intrusion Detection Systems," in Proc. 34th USENIX Security Symposium, 2025.

[13] "How Far Should We Need to Go: Evaluate Provenance-based Intrusion Detection Systems in Industrial Scenarios," arXiv preprint arXiv:2603.22982, 2026.

[14] S. Ghavamnia, T. Palit, A. Mishra, and M. Polychronakis, "Confine: Automated System Call Policy Generation for Container Attack Surface Reduction," in Proc. International Symposium on Research in Attacks, Intrusions and Defenses (RAID), 2020.

[15] "You Can Run But You Can’t Hide: Runtime Protection Against Malicious Package Updates For Node.js," arXiv preprint arXiv:2305.19760, 2023.

[16] "FuseChain: Runtime Evidence Reconstruction for Software Supply-Chain Attacks," University of Glasgow, arXiv preprint arXiv:2606.15811, 2026.

[17] "SynthChain: A Synthetic Benchmark and Forensic Analysis of Advanced and Stealthy Software Supply Chain Attacks," University of Glasgow, arXiv preprint arXiv:2603.16694, 2026.

[18] A. Goyal, X. Han, G. Wang, and A. Bates, "Sometimes, You Aren’t What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems," in Proc. Network and Distributed System Security Symposium (NDSS), 2023.

[19] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in Proc. IEEE International Conference on Data Mining (ICDM), 2008, pp. 413-422.

[20] M. A. Inam et al., "SoK: History is a Vast Early Warning System: Auditing the Provenance of System Intrusions," in Proc. IEEE Symposium on Security and Privacy (S&P), 2023.

[21] R. C. Merkle, "A Digital Signature Based on a Conventional Encryption Function," in Advances in Cryptology (CRYPTO), 1987, pp. 369-378.

[22] B. Laurie, A. Langley, and E. Kasper, "Certificate Transparency," RFC 6962, Internet Engineering Task Force, 2013.

[23] G. Ke, Q. Meng, T. Finley, T. Wang, W. Chen, W. Ma, Q. Ye, and T.-Y. Liu, "LightGBM: A Highly Efficient Gradient Boosting Decision Tree," in Advances in Neural Information Processing Systems 30 (NeurIPS), 2017.