# The live demo

For whoever presents PROVBIND live, in about 10 minutes. It runs on the demo PC (kind, Tetragon, Falco,
the local registry), and everything the audience sees is real: the cluster, the sensor and PROVBIND's
services. The only exception is plan B, a replay of the rehearsal, and the screen says so.

The demo was checked without a cluster (unit tests and a dry run of every act). **Rehearse it once on the
demo PC before the talk.**

## 1. What the audience sees

Two terminals side by side, large font (about 20 pt), each about 100 columns wide:

| Terminal | Command | Shows |
|---|---|---|
| Alert screen | `make live-demo-view` | One card per alert as it arrives: what happened, which layer and package of the signed image it concerns, where it ran. A dim line is logged but is not an alert. |
| Presenter | `make live-demo` | The six acts. Each act prints a caption, waits for Enter, runs, then prints what happened. |

The captions are written so they can be on screen; read them or say them in your own words.

## 2. Before the talk

`DEMO_REF` is the `ref@digest` that `make demo-app` printed (for example
`localhost:5001/demo-app@sha256:…`). Keep it in a note; every command below needs it.

| When | What | Commands |
|---|---|---|
| The day before | A full rehearsal | `make up` and `make demo-app` if the cluster is down; `export DEMO_REF=…`; `make live-demo-check`; `make live-demo-prep`; `make live-demo-view` in a second terminal; `AUTO=1 make live-demo`; `make live-demo-stop` |
| 30 minutes before | Check, then prepare | `make live-demo-check`, then `make live-demo-prep` (about 2 minutes) |
| 5 minutes before | Open both terminals, set the font size, mute notifications | `make live-demo-view` in one, `make live-demo` ready in the other |

`make live-demo-check` only reads. It lists what is ready (✓) and what is missing (!); optional items (-)
only limit acts 2, 3 and 5.

`make live-demo-prep`:
- moves the previous `run-demo` folder aside as `run-demo.<date-time>`, which plan B can replay;
- deletes the demo deployment, so act 1 deploys a fresh pod while Tetragon is running;
- applies one sensor policy set: `opt`, the rate-limited set of the final runs;
- starts the controller, the node, the alert engine, the trust loop and the Falco capture (logs in `run-demo/logs/`);
- builds an unsigned copy of the app for act 5.

It ends with `READY.`

The alert screen picks up the fresh folder by itself, so it can stay open through prep.

## 3. The six acts

Times include a sentence or two of talk. Press Enter when the caption says `[Enter]`.

| Act | About | Time |
|---|---|---|
| 1 | A signed image is verified and compiled into its envelope | 1 min |
| 2 | An operator opens a shell: logged, not an alert | 1 min |
| 3 | The compromised dependency drops and runs a program | 1 min |
| 4 | An advisory names that dependency while it runs | 1 min |
| 5 | An unsigned image is deployed | 1 min |
| 6 | Someone edits the violation log | 1 min |

### Act 1: a signed image arrives (contribution 1)

- **Say:** "This is our demo app. Our pipeline signed its image and attested an SBOM and the build
  provenance. We deploy it by its digest."
- **Presenter terminal:** the rollout, then a card: the admission checks (signature, SBOM, provenance,
  transparency log), "envelope compiled in … s", and the counts of layers, files, packages and programs in the
  execution closure, with the builder, commit and Rekor entry.
- **Point at:** the compile time, about 4 s in our measurements, with no training and no observation period.
  DeSFAM needs about 30 minutes of profiling and Confine about 33 s (report, Fig. 3).
- **Meanwhile:** a 30-second check that the sensor sees the app runs in the background. It raises no alert,
  and its result prints at the start of act 2.

### Act 2: an operator opens a shell (precision, contribution 2)

- **Say:** "Something legitimate but unusual: a team member opens a shell in the container."
- **Alert screen:** only dim lines such as `logged, not an alert (Low …): /usr/bin/ls …`. The programs are in
  the signed image, outside the entrypoint's closure, so PROVBIND records them and stays quiet.
- **Presenter terminal:** `PROVBIND: 0 new alerts` and Falco's alert (its rule for a terminal shell in a container).
- **Point at:** in our evaluation both learned detectors flagged this in all five runs, and so did Falco.
  PROVBIND flagged none of the 30 benign runs.

### Act 3: the compromised dependency strikes (contributions 2 and 3)

- **Say:** "requestz-helper is a dependency of the app: signed, in the SBOM, admitted. One request now
  triggers its payload."
- **Alert screen:**
  - **CRITICAL 90:** `Undeclared program executed`, for `/tmp/.x9`, from nothing in the signed image.
  - **HIGH 72:** `Signed image file modified`, for `/etc/passwd`, with the image layer it came from and the
    marker `(same incident)`.
- **Presenter terminal:** the same two alerts in short form, then Falco's rules.
- **Point at:** the first alert is a fact about the signed evidence, not a statistical guess; both alerts are
  one incident. Falco also catches it, but names no package or layer. `/etc/passwd` is created at install
  time, so the SBOM may name no package for it; act 4 shows a package and its depth.

### Act 4: an advisory, while the app runs (contribution 4)

- **Say:** "Later that day, a malicious-package advisory is published for requestz-helper. Nothing in the
  container changes."
- **Alert screen:** a `TRUST` card saying `Trust withdrawn: component advisory`, with the package
  `requestz-helper 0.1.0`, its dependency depth and layer, then `raised … s after the change · the pod still
  runs as CONFORMING`.
- **Point at:** the delay, 1 to 2 s (median 1.7 s in our runs), and that no runtime monitor can see this,
  because no behaviour changed.

### Act 5: an unsigned image (admission)

- **Say:** "Someone deploys a copy of the app that was built outside the pipeline: no signature, no attestations."
- **Presenter terminal:** `demo-app-unsigned-…: NOT VERIFIED: …` and `envelope: none`.
- **Alert screen:** `HIGH 60 Image failed verification`, once the pod's first event arrives.
- **Say it accurately:** the prototype verifies and flags; it does not stop the pod, since there is no
  admission webhook. Say "fails verification", not "is blocked".

### Act 6: can someone erase the evidence?

- **Say:** "Every alert goes into a hash-chained log. We change one character in one record, as someone
  covering their tracks would."
- **Presenter terminal:** `[verify_log] OK: N records`, then `edited record k=…`, then
  `[verify_log] BROKEN at record k=…`. The original log is then restored.

### Closing

The script prints a one-paragraph summary. Then move to the slides for the numbers:
- **Detection:** 50 of 65 attack runs with no false alarm, F1 0.87 against 0.58.
- **Trust:** all 25 trust problems caught.
- **Cost:** within 10% of an unmonitored app.

One live run is a demonstration, not a measurement.

## 4. If something goes wrong

To repeat one act: `PROVBIND_RUN=./run-demo scripts/live-demo.sh act N` (with `DEMO_REF` set).

| Symptom | On stage | Afterwards |
|---|---|---|
| Act 1 times out waiting for the envelope | Run act 1 again; if it fails twice, plan B | `run-demo/logs/controller.log` |
| Act 2 says the sensor does NOT see the app | `kubectl -n demo rollout restart deploy/demo-app`, then act 1 again | `run-demo/logs/probe.log` (happens when Tetragon restarted after the app) |
| Act 3 shows no alert after 90 s | Plan B for the rest | `run-demo/logs/node.log`, `alerts.log` |
| Act 2 shows no Falco alert | Say Falco flagged the shell in all five recorded runs | Falco's shell rule needs a real terminal: none in `AUTO=1` |
| Act 5 says skipped | Skip it in one sentence | `run-demo/logs/unsigned-build.log` (needs docker and crane) |
| The cluster or VM is gone | Plan B | `make up`, `make demo-app`, `make live-demo-prep` |

## 5. Plan B: replay the rehearsal

`make live-demo-prep` keeps each earlier run as `run-demo.<date-time>`. On the alert screen, stop the live
view (Ctrl-C) and replay the rehearsal, one act per Enter:

```bash
python3 -m eval.demo_view --replay run-demo.<date-time>/alerts.jsonl --step
```

The header says `REPLAY of a recorded run, not live`; say so to the audience too. `--speed 2` replays with
the recorded timing instead, twice as fast.

As a last resort, record the rehearsal's screen (OBS, or `asciinema rec`) and keep the video on the laptop.

## 6. After the talk

`make live-demo-stop` stops PROVBIND's services. `make live-demo-reset` undoes the acts: it removes the
advisory, restores the log and deletes the unsigned deployment. The demo deployment stays; remove it with
`kubectl -n demo delete deployment demo-app`.

## 7. What the demo does not show

- **The behavioural path (ML-B):** it needs a model trained on 7 hours of traffic. The report gives its
  result: it catches the in-envelope burst.
- **Measurements:** the numbers come from 95 recorded runs (report, Section VI), not from this run.
- **Blocking at admission:** the prototype verifies and flags; it does not reject pods.
- **Key revocation:** it can replace act 4. `make trust2` revokes the key and `RESTORE=1 make trust2` undoes
  it, with `PROVBIND_RUN=./run-demo`.

## 8. The pieces

| File | Role |
|---|---|
| `scripts/live-demo.sh` | `check`, `prep`, `run`, `act N`, `reset`, `stop`; `AUTO=1` without pauses, `SKIP="2 5"` to leave acts out, `DRY_RUN=1` to print the commands without a cluster |
| `eval/demo_view.py` | The alert screen: `--follow` live, `--replay FILE` for plan B |
| `eval/live_demo.py` | The presenter terminal's counts and summaries |
| `testbed/scenarios/` | The scenario steps the acts reuse: `lib.sh`, `deploy_lib.sh`, `trust.sh`, `tamper.sh` |
