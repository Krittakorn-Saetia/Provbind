# The live demo

One command, about a minute, the same every time. It runs on the demo PC (kind, Tetragon, Falco, the
local registry), and everything the audience sees is real: the cluster, the sensor and PROVBIND's
services. The only exception is plan B, a replay of an earlier run, and the screen says so.

The settings are in `testbed/live-demo.conf`. Any setting can also be given for one run on the command
line, which wins: `make live-demo ATTACK=overwrite`.

The demo was checked without a cluster (unit tests and dry runs of every act and setting). **Rehearse it on
the demo PC before the talk** (Section 4).

## 1. Step by step

### Once, on the demo PC

Do this where there is internet: `make up` downloads charts and images, and signing writes to the public
Rekor log.

1. Get the code and the Python packages:
   ```bash
   cd ~/Provbind && git checkout claude/zen-hypatia-pyrg25 && git pull origin claude/zen-hypatia-pyrg25
   source .venv/bin/activate && pip install -r requirements.txt
   ```
2. Put the team's signing key at `pipeline/keys/cosign.key`. Never commit it; `cosign.pub` is already in the
   repository. Then `export COSIGN_PASSWORD=…` (an empty string if the key has no password).
3. Start the cluster and sign the app. Skip either one if it is already done:
   ```bash
   make up          # kind with the local registry, Tetragon, Falco, Neo4j, namespace demo
   make demo-app    # builds, signs and attests the demo app, and prints its ref@digest
   ```
4. Run `make live-demo-setup`. Every required line should show ✓. It deploys the signed app.

### Every time you show it

1. Open two terminals in `~/Provbind` and run `source .venv/bin/activate` in both.
2. Terminal 1: `make live-demo-view`. Leave it open the whole time.
3. Terminal 2: `make live-demo`. It takes about a minute and ends with `done in N s`.
4. To show it again, run `make live-demo` again. There is nothing to reset in between.
5. When you are finished: `make live-demo-stop`.

Each `make live-demo`:
1. Restarts PROVBIND on a fresh run folder. The previous run is kept as `run-demo.<date-time>` for plan B.
2. Clears the audience screen, which starts over by itself.
3. Runs five acts with 10 s between them, so the audience can read each result.

Nothing needs undoing between runs: the advisory, the key state and the log edit all stay in the old folder.

### If the venue has no internet

The signature check also checks the image's entry in the public Rekor log. If the envelope act fails there,
run `make live-demo PROVBIND_OFFLINE=1`. The signature and both attestations are still checked against
the key; only the Rekor check is skipped, and the admission line no longer lists it. An image signed with
`PROVBIND_OFFLINE=1 make demo-app` has no Rekor entry, so always run its demo with `PROVBIND_OFFLINE=1`.

### After the PC restarts

1. In a terminal: `cd ~/Provbind && source .venv/bin/activate`, then `make live-demo-check`.
2. If the cluster or Tetragon shows !, wait a minute or two, because Kubernetes is still starting, then check
   again.
3. If it still shows !, start the cluster's container with `docker start kind-control-plane`, wait a minute
   and check again. If the registry shows !, run `docker start kind-registry`.
4. Run one practice `make live-demo`. The first run after a restart checks that the sensor sees the app,
   and restarts the app if it does not (about 20 s more, once).

Do not run `make up` while the cluster exists: `kind create cluster` stops with an error. `make up` is only
for a machine with no cluster, where `kind get clusters` prints nothing.

## 2. Change the demo

Edit `testbed/live-demo.conf`, or give the setting for one run:

| Goal | Command | About |
|---|---|---|
| The default | `make live-demo` | 1 min |
| You set the pace; the script shows what to say | `make live-demo PAUSE=enter CAPTIONS=long` | as long as you talk |
| The short version | `make live-demo ACTS="envelope trust attack" PAUSE=3` | 20 s |
| Admission live: the app is deployed during the first act | `make live-demo REDEPLOY=1` | 1.5 min |
| Add an unsigned image | `make live-demo ACTS="envelope shell trust attack log unsigned"` | 1.5–2 min |
| Another attack | `make live-demo ATTACK=egress` (or `overwrite`, `inject`) | 1 min |
| Revoke the signing key instead of an advisory | `make live-demo TRUST=key` | 1 min |
| An ordinary CVE: reported, trust stays | `make live-demo ADVISORY_ID=CVE-2026-0001` | 1 min |
| See what is in use, and where it comes from | `make live-demo-settings` | |

The times come from runs on the demo VM (17 November): the five default acts took about 20 s, plus the
pauses. The script prints the real total at the end.

| Setting | Default | Values | What it changes |
|---|---|---|---|
| `ACTS` | `envelope shell trust attack log` | any of `envelope shell trust attack log unsigned`, in any order | which acts run, in that order |
| `PAUSE` | `10` | seconds, or `enter` | the gap between acts; `enter` waits for you before each act. The acts take about 20 s in all, so 10 gives about a minute and 3 about 30 s |
| `CAPTIONS` | `short` | `short`, `long` | one line per act, or also what to say and what to watch |
| `ATTACK` | `update` | `update`, `overwrite`, `inject`, `egress` | the attack act (table in Section 3) |
| `TRUST` | `advisory` | `advisory`, `key` | an advisory appears, or the signing key is revoked |
| `ADVISORY_PACKAGE` | `requestz-helper` | a package in the image's SBOM | the package the advisory names |
| `ADVISORY_VERSION` | `0.1.0` | a version; empty means every version | |
| `ADVISORY_ECOSYSTEM` | `PyPI` | PyPI, npm, Debian, Ubuntu, Go, crates.io, Maven, RubyGems, NuGet, Packagist, Alpine | |
| `ADVISORY_ID` | `MAL-2026-9001` | `MAL-…` withdraws trust; any other id (`CVE-…`) is only reported | |
| `SHELL_CMD` | `ls /; cat /etc/hostname` | a shell command | what the operator runs in the shell act |
| `FRESH` | `1` | `1`, `0` | 1: a fresh run folder and fresh services every run. 0: keep both (then `make live-demo-reset` undoes the acts) |
| `REDEPLOY` | `0` | `0`, `1` | 1: the envelope act deploys the app, so admission happens live |
| `WAIT_S` | `30` | seconds | how long an act waits for its alert |
| `KEEP_RUNS` | `3` | a number | earlier run folders kept for plan B |
| `FALCO` | `auto` | `auto`, `off` | Falco's alerts beside PROVBIND's, when Falco runs |
| `NEO4J` | `off` | `off`, `on` | off: the cards take layer and package straight from the envelope, the same answer at once. on: each run's graph is first loaded into Neo4j, and alerts wait while it loads |
| `POLICY_SET` | `opt` | `opt`, `orig` | the sensor policies: the rate-limited set of the final runs, or the unfiltered set |
| `DEMO_REF` | empty | `ref@digest` | the signed image; empty: the running deployment's image, else `demo-app:latest` in the local registry |
| `NAMESPACE`, `DEPLOY` | `demo`, `demo-app` | | where the app runs |

These are given on the command line only:

| Setting | What it does |
|---|---|
| `AUTO=1` | skips every pause (a quick rehearsal) |
| `DRY_RUN=1` | prints the commands instead of running them; needs no cluster |
| `PROVBIND_OFFLINE=1` | checks signatures without the public Rekor log (Section 1) |
| `DEMO_CONF=FILE` | reads another settings file, so you can keep variants: `cp testbed/live-demo.conf testbed/talk.conf`, edit it, then `make live-demo DEMO_CONF=testbed/talk.conf` |
| `DEMO_RUN=DIR` | another run folder (default `./run-demo`); give the same one to `make live-demo-view` |

A setting with a value the demo cannot use stops the run before anything starts, with a message naming
the setting and its allowed values.

## 3. The acts

Each act prints one caption line on the presenter's terminal, runs, then prints what happened. With
`CAPTIONS=long` it also prints what to say and what to watch.

| Act | The audience sees | About |
|---|---|---|
| (start) | PROVBIND restarts on a fresh folder | 5 s |
| `envelope` | the admission checks, then the envelope card | 5–10 s |
| `shell` | dim lines only on the alert screen; Falco alerts | 6 s |
| `trust` | a TRUST card within about 2 s, while the pod still behaves | 3 s |
| `attack` | the attack's alerts, with layer and package; Falco's | 8 s |
| `log` | the log verifies, one character changes, then it fails at that record | 2 s |
| `unsigned` | NOT VERIFIED, and a HIGH card | 30–40 s, plus about a minute once to build the image |

### envelope: the signed evidence becomes an envelope (contribution 1)

- **Say:** "Our pipeline signed this image and attested its SBOM and build provenance. PROVBIND checks
  them and compiles the envelope: every file, layer, package and program the evidence allows."
- **Presenter terminal:** the admission checks, then "envelope compiled in … s, from the signed evidence
  alone", the counts of layers, files, packages and programs in the execution closure, the builder, the
  commit and the Rekor entry.
- **Point at:** the compile time: seconds, with no training and no observation period. Say the number on
  the screen; it was about 4 s in our measurements and can be slower on the first run after a restart.
  DeSFAM needs about 30 minutes of profiling and Confine about 33 s (report, Fig. 3).
- With the default `REDEPLOY=0`, PROVBIND compiles the envelope of the app that is already running. With
  `REDEPLOY=1`, the app is deployed by its digest during the act.

### shell: an operator opens a shell (precision, contribution 2)

- **Say:** "Something legitimate but unusual: a team member opens a shell in the container."
- **Alert screen:** only dim lines such as `logged, not an alert (Low …): /usr/bin/ls …`. The programs are
  in the signed image but outside the entrypoint's closure, so PROVBIND records them and stays quiet.
- **Presenter terminal:** `PROVBIND: 0 alerts; N Low records, logged`, then Falco's alert.
- **Point at:** in our evaluation both learned detectors flagged this in all five runs, and so did Falco.
  PROVBIND flagged none of the 30 benign runs.

### trust: an advisory, while the app still behaves (contribution 4)

- **Say:** "Before anything happens in the pod, a malicious-package advisory is published for
  requestz-helper, one of the app's dependencies. Nothing in the container changes."
- **Alert screen:** a `TRUST` card, `Trust withdrawn: component advisory`, with the package, its dependency
  depth and layer, then `raised … s after the change · the pod still runs as CONFORMING`.
- **Point at:** the delay: under 2 s, because the trust loop checks every 2 s, so anything from 0.1 s to 2 s
  is normal (median 1.7 s in our runs). No runtime monitor can see this, because no behaviour changed:
  PROVBIND distrusts the image before its payload ever runs.
- `TRUST=key` revokes the signing key instead. An `ADVISORY_ID` that is not `MAL-…` is reported and trust
  stays; the terminal says so. That is the trust policy, and it is worth showing.
- Keep `trust` before `attack` in `ACTS`. After the attack, the pod is no longer CONFORMING, and the
  card says so.

### attack: the compromised dependency strikes (contributions 2 and 3)

- **Say:** "requestz-helper is signed, in the SBOM, and was admitted. Now its payload runs: one request to
  the app sets it off."

| `ATTACK` | The request | The alert screen |
|---|---|---|
| `update` | `GET /update`: requestz-helper writes `/tmp/.x9` and runs it; it appends a line to `/etc/passwd` | One incident, three cards: **CRITICAL 84** `Undeclared code loaded` and **CRITICAL 90** `Undeclared program executed` for `/tmp/.x9`, from nothing in the signed image; then **HIGH 72** `Signed image file modified` for `/etc/passwd`, with its layer |
| `overwrite` | `GET /ru4`: the app overwrites `/usr/bin/ls` with `/bin/cat`'s bytes, runs it, then restores it | `Signed image file modified` for `/usr/bin/ls` |
| `inject` | `GET /rk3`: an embedded harmless library is preloaded into `python3 -c pass` | `Undeclared code loaded` |
| `egress` | `GET /ru3`: a connection to 203.0.113.9:4444 (TEST-NET-3, never routed); nothing is sent | `Connection to an undeclared address` |

- **Point at:** the alert is a fact about the signed evidence, not a statistical guess, and it names the
  layer and package. Falco also catches the attack, but names no package or layer.
- With `POLICY_SET=opt`, the sensor reports an identical write or library load once a minute. When
  `overwrite` or `inject` runs again within a minute, the script waits out the rest of that minute and
  says so.

### log: can someone erase the evidence?

- **Say:** "Every alert goes into a hash-chained log. We change one character in one record, as someone
  covering their tracks would."
- **Presenter terminal:** `log check: OK: N records`, `one character changed in record k=…`, then
  `log check: BROKEN at record k=…`. The original log is then restored.
- The log needs an alert first, so put `log` after `shell`, `attack` or `trust` in `ACTS`.

### unsigned: an image built outside the pipeline (admission)

- **Say:** "Someone deploys a copy of the app built outside the pipeline: no signature, no attestations."
- **Presenter terminal:** `demo-app-unsigned-…: NOT VERIFIED: …` and `envelope: none`.
- **Alert screen:** `HIGH 60 Image failed verification`, once the pod's first event arrives.
- **Say it accurately:** the prototype verifies and flags; it does not stop the pod, since there is no
  admission webhook. Say "fails verification", not "is blocked".
- `make live-demo-setup` builds the unsigned copy when `ACTS` has `unsigned`; otherwise the act builds it
  the first time, which takes about a minute.

### Closing

Move to the slides for the numbers:
- **Detection:** 50 of 65 attack runs with no false alarm; F1 0.87 against 0.58.
- **Trust:** all 25 trust problems caught.
- **Cost:** within 10% of an unmonitored app.

One live run is a demonstration, not a measurement.

## 4. Before the talk

| When | What |
|---|---|
| Once on the demo PC | Section 1, *Once, on the demo PC* |
| The day before | `make live-demo-view` in one terminal, then `make live-demo` twice in the other: the second run proves it repeats. Note the `done in N s`, and try the settings you plan to use |
| 30 minutes before | `make live-demo-check`, then one `make live-demo`, which also gives plan B a fresh recording |
| 5 minutes before | Open both terminals side by side, about 100 columns each, font about 20 pt; mute notifications |

`make live-demo-check` only reads. It lists what is ready (✓) and what is missing (!). Optional items (-)
only limit what an act can show, such as Falco's side of the comparison.

## 5. If something goes wrong

| Symptom | On stage | Afterwards |
|---|---|---|
| `live-demo: ATTACK=…` or another setting named | Fix it on the command line and run again | The message lists the allowed values |
| `no signed image found` | Plan B | `make demo-app`, or set `DEMO_REF` in the settings file |
| No envelope after 90 s, or the app is NOT VERIFIED | Run `make live-demo` again; if it fails twice, plan B | `run-demo/logs/controller.log`. If it names Rekor or the network: `make live-demo PROVBIND_OFFLINE=1` |
| An act shows no alert, or a wait says `… did not arrive` | Run again, or plan B for that act | `make live-demo-diagnose` before the next run: start order of the app and the sensor, the writes the sensor saw, the detections and the alerts. The script restarts the app when it started before the sensor |
| `(waiting N s: …once a minute)` | Talk over it | Normal when `overwrite` or `inject` runs twice within a minute |
| `the sensor still does not see writes in the app` | Go on: the attack act still shows its CRITICAL alert, but not the `/etc/passwd` one | Tetragon's namespace-scoped policies do not match the app's pod. Role 3 saw this on their VM; their workaround is cluster-wide copies of the policies (`node/handoff/ROLE3-VM-TO-ROLE1.md`, §5.2) |
| No Falco alert in the shell act | Say that Falco flagged it in all five recorded runs | Falco's shell rule needs a real terminal; `AUTO=1` has none |
| No trust alert | Plan B for that act | The package must be in the image's SBOM, in the right ecosystem; see `run-demo/logs/trust.log` |
| `the log is empty` | Skip it in one sentence | Put an act that alerts before `log` |
| One act needs repeating | `make live-demo-act ACT=attack` | It runs on the services that are already running |
| The cluster or the VM is gone | Plan B | `make up`, `make demo-app`, `make live-demo-setup` |

## 6. Plan B: replay an earlier run

Every run keeps the one before it as `run-demo.<date-time>`, up to `KEEP_RUNS`. On the alert screen, stop
the live view (Ctrl-C) and replay a good run, one act per Enter:

```bash
python3 -m eval.demo_view --replay run-demo.<date-time>/alerts.jsonl --step
```

The header says `REPLAY of a recorded run, not live`; tell the audience too. `--speed 2` replays with the
recorded timing instead, twice as fast.

As a last resort, record a rehearsal's screen (OBS, or `asciinema rec`) and keep the video on the laptop.

## 7. After the talk

`make live-demo-stop` stops PROVBIND's services; they keep running between runs until then. With `FRESH=0`,
`make live-demo-reset` undoes the acts: it removes the advisory, makes the key active, restores the log and
deletes the unsigned deployment.

The demo deployment stays. The `update` attack appends one line to `/etc/passwd` in that container on each
run. `kubectl -n demo rollout restart deploy/demo-app` gives a clean container, and the next run notices
the restart by itself.

## 8. What the demo does not show

- **Building and signing (Phase 1):** `make demo-app` did it beforehand; it takes minutes and needs the
  internet. The builder, commit and Rekor entry on the envelope card are its evidence.
- **The behavioural path (ML-B):** it needs a model trained on 7 hours of traffic. The report gives its
  result: it catches the in-envelope burst.
- **Measurements:** the numbers come from 95 recorded runs (report, Section VI), not from this run.
- **Blocking at admission:** the prototype verifies and flags; it does not reject pods.
- **What PROVBIND misses** (the 15 of 65 attack runs it did not catch, `docs/COMPARISON-RUN.md`): ru-5, a
  program that only reads a credential file, since nothing it does contradicts the envelope; rk-2, the
  system-call shape of a kernel exploit, which a system-call detector complements; au-2, a build step
  that adds an undeclared program before signing, which PROVBIND only logs as Low when it runs.

## 9. How it works

| File | Role |
|---|---|
| `testbed/live-demo.conf` | The settings, with a comment on each |
| `scripts/live-demo.sh` | `run` (the default), `act NAME`, `check`, `setup`, `settings`, `reset`, `stop`, `diagnose`, `help`. `AUTO=1` skips every pause; `DRY_RUN=1` prints the commands without a cluster |
| `eval/demo_view.py` | The alert screen: `--follow` live (it starts over when the run folder is replaced), `--replay FILE` for plan B |
| `eval/live_demo.py` | The presenter terminal's counts and summaries, and the trust act's OSV advisory |
| `testbed/scenarios/` | The scenario pieces the acts reuse: `lib.sh`, `deploy_lib.sh`, `tamper.sh` |

With `FRESH=1`, each run:
1. Stops the previous run's services.
2. Moves `run-demo` aside and applies one sensor policy set.
3. Starts the controller, the node, the alert engine, the trust loop and the Falco capture. Their logs go
   to `run-demo/logs/`.

The controller lists the running pods when it starts, so it verifies the running app and compiles its
envelope without a redeploy.

Tetragon applies its write, library, capability and network checks only to pods it saw start. After a
reboot, the app and Tetragon can start in the same second, and then the app's new programs are still
reported but its writes are not. So before PROVBIND starts, the script:
1. Restarts the app if it started before Tetragon was ready.
2. Once after each app start, writes a test file inside the app and checks that Tetragon reports it.
3. Restarts the app if it does not.
