# PROVBIND live demo: foolproof guide

Open this page on the VM with `less docs/LIVE-DEMO-CHEATSHEET.md` (q to quit). The full runbook is
`docs/LIVE-DEMO.md`.

## The short version (a normal day)

```bash
cd ~/Provbind && source .venv/bin/activate && make live-demo-check   # terminal 1: every line ✓
cd ~/Provbind && source .venv/bin/activate && make live-demo-view    # terminal 2: the audience screen
make live-demo                                                       # terminal 1: the demo
make live-demo-stop                                                  # terminal 1: at the very end
```

---

## Part 1: Settings

### 1.1 The two ways to change a setting

**Way A: permanent.** The change stays until you change it back.

1. In a terminal, go to the project with `cd ~/Provbind`.
2. Open the settings file with `nano testbed/live-demo.conf`.
3. Use the arrow keys to move to the line, for example `PAUSE=10`. Lines starting with `#` are only
   explanations.
4. Delete the old value after the `=` and type the new one, for example `PAUSE=enter`.
5. Save with **Ctrl+O**, then **Enter**. Exit with **Ctrl+X**.
6. Check it with `make live-demo-settings`. Your line shows the new value and the word `conf`.

**Way B: one run only.** The file is not changed.

```bash
make live-demo PAUSE=enter                        # one setting
make live-demo PAUSE=enter CAPTIONS=long          # several settings, separated by spaces
make live-demo ACTS="envelope trust attack"       # a value with spaces goes in double quotes
```

To check without running the demo, type `make live-demo-settings PAUSE=enter`. The line shows the word
`command line`. The next plain `make live-demo` uses the file again.

### 1.2 Rules that prevent mistakes

| Rule | Right | Wrong |
|---|---|---|
| The name in capitals, spelled exactly | `PAUSE=enter` | `pause=enter`, `PAUSES=enter` |
| No spaces around `=` | `PAUSE=enter` | `PAUSE = enter` |
| A value with spaces in double quotes | `ACTS="envelope attack"` | `ACTS=envelope attack` |
| The value spelled exactly as listed, in small letters | `CAPTIONS=long` | `CAPTIONS=Long` |

- If you use both ways, the command line wins for that run.
- A change in the file applies from the next run.
- A wrong value is safe: the demo refuses to start and prints the allowed values.
- To put the whole file back as it was: `git checkout testbed/live-demo.conf`.

### 1.3 The settings you may change

Each block shows the options, then exactly what to type in each way.

**ACTS**: which acts run, and in what order.
- `envelope`: the signed evidence becomes the rulebook (about 10 s).
- `shell`: an operator's shell raises no false alarm; Falco raises one (about 6 s).
- `trust`: an advisory withdraws trust while the app behaves (about 3 s).
- `attack`: the attack chosen by `ATTACK` is caught and traced (about 8 s).
- `log`: one character in the alert log changes, and the check finds it (about 2 s).
- `unsigned`: an unsigned image fails verification (about 40 s; the first time, about a minute more).

Keep `trust` before `attack`, and keep `log` after an act that raises an alert.
```
Default:  ACTS="envelope shell trust attack log"
File:     ACTS="envelope trust attack"
One run:  make live-demo ACTS="envelope trust attack"
```

**ATTACK**: which attack is shown.
- `update`: a dropped program runs and edits `/etc/passwd`. Three alerts in one incident; the best story.
- `overwrite`: the app overwrites `/usr/bin/ls`.
- `inject`: hidden code is loaded into a program.
- `egress`: the app connects to an address it is not allowed to; nothing is sent.
```
Default:  ATTACK=update
File:     ATTACK=egress
One run:  make live-demo ATTACK=egress
```

**TRUST**: what happens in the trust act.
- `advisory`: an advisory names one of the image's packages.
- `key`: the signing key is revoked. This is simulated, so say so.
```
Default:  TRUST=advisory
File:     TRUST=key
One run:  make live-demo TRUST=key
```

**ADVISORY_ID**: the advisory's id.
- `MAL-2026-9001`: a malicious package, so trust is withdrawn.
- `CVE-2026-0001`: an ordinary bug, so it is only reported and trust stays.
```
Default:  ADVISORY_ID=MAL-2026-9001
File:     ADVISORY_ID=CVE-2026-0001
One run:  make live-demo ADVISORY_ID=CVE-2026-0001
```

**PAUSE**: the gap between acts.
- A number of seconds: `0` means none, `3` gives about 30 s in all, `10` about 1 minute.
- `enter`: the demo waits for you to press Enter before each act.
```
Default:  PAUSE=10
File:     PAUSE=enter
One run:  make live-demo PAUSE=enter
```

**CAPTIONS**: the text on your screen.
- `short`: one line per act.
- `long`: also what to say and what to point at.
```
Default:  CAPTIONS=short
File:     CAPTIONS=long
One run:  make live-demo CAPTIONS=long
```

**SHELL_CMD**: what the operator types in the shell act. Any short, harmless command, in quotes.
```
Default:  SHELL_CMD="ls /; cat /etc/hostname"
File:     SHELL_CMD="id; ls /tmp"
One run:  make live-demo SHELL_CMD="id; ls /tmp"
```

**REDEPLOY**: `0` uses the app that is already running. `1` deploys the app during the first act, so the
audience sees it checked on arrival (about 20 s more).
```
Default:  REDEPLOY=0
File:     REDEPLOY=1
One run:  make live-demo REDEPLOY=1
```

**FALCO**: `auto` shows Falco's alerts beside PROVBIND's. `off` hides them.
```
Default:  FALCO=auto
File:     FALCO=off
One run:  make live-demo FALCO=off
```

**KEEP_RUNS**: how many earlier runs are kept for the backup replay.
```
Default:  KEEP_RUNS=3
File:     KEEP_RUNS=5
One run:  make live-demo KEEP_RUNS=5
```

### 1.4 Settings to leave alone

They work the same two ways, but the defaults are right for your VM.

| Setting | Default | Options |
|---|---|---|
| `ADVISORY_PACKAGE` | `requestz-helper` | a package in the image's SBOM |
| `ADVISORY_VERSION` | `0.1.0` | a version; empty means every version |
| `ADVISORY_ECOSYSTEM` | `PyPI` | `PyPI` `npm` `Debian` `Ubuntu` `Go` `crates.io` `Maven` `RubyGems` `NuGet` `Packagist` `Alpine` |
| `WAIT_S` | `30` | seconds each act waits for its alert |
| `FRESH` | `1` | `1`: a clean start every run. `0`: continue on the running services |
| `NEO4J` | `off` | `off`: alerts at once. `on`: alerts wait while each run's graph loads |
| `POLICY_SET` | `opt` | `opt`: the sensor setup of the final runs. `orig`: the unfiltered set |
| `DEMO_REF` | empty | the signed image as `ref@digest`; empty means found automatically |
| `NAMESPACE` | `demo` | the Kubernetes namespace |
| `DEPLOY` | `demo-app` | the app's deployment name |

### 1.5 Command line only (not in the file)

| Setting | What it does | Example |
|---|---|---|
| `AUTO=1` | skips every pause | `make live-demo AUTO=1` |
| `DRY_RUN=1` | prints the commands without running them | `make live-demo DRY_RUN=1` |
| `PROVBIND_OFFLINE=1` | for a venue without internet: skips the Rekor check | `make live-demo PROVBIND_OFFLINE=1` |
| `DEMO_CONF=FILE` | uses another settings file | `make live-demo DEMO_CONF=testbed/talk.conf` |
| `DEMO_RUN=DIR` | another run folder; give the same one to the audience screen | `make live-demo DEMO_RUN=./run-demo2` |
| `ACT=NAME` | the act to repeat, with `make live-demo-act` | `make live-demo-act ACT=attack` |

### 1.6 Ready-made versions

| You want | Type |
|---|---|
| Hands-free, about 1 minute | `make live-demo` |
| You set the pace, with talking points on screen | `make live-demo PAUSE=enter CAPTIONS=long` |
| A short version, about 20 s | `make live-demo ACTS="envelope trust attack" PAUSE=3` |
| The full show, about 2 minutes | `make live-demo ACTS="envelope shell trust attack log unsigned" REDEPLOY=1` |
| A different attack | `make live-demo ATTACK=egress` |
| A revoked key | `make live-demo TRUST=key` |
| A CVE that does not withdraw trust | `make live-demo ADVISORY_ID=CVE-2026-0001` |

---

## Part 2: Step by step, start to finish

### Step 1: start the VM
1. Start the VM in VirtualBox and log in.
2. Open a terminal with **Ctrl+Alt+T**. This is **terminal 1**.

### Step 2: go to the project and get the latest version
In terminal 1:
```bash
cd ~/Provbind
source .venv/bin/activate
git pull origin claude/zen-hypatia-pyrg25
```
- **You should see:** `(.venv)` at the start of the line, and `Already up to date.` or a list of files.
- **If git says "Your local changes … would be overwritten":** stop, and send me the message.

### Step 3: check that everything is ready
In terminal 1:
```bash
make live-demo-check
```
- **You should see:** ✓ on every line. Just after a power-on, the Falco line may show `-` for a minute,
  which is fine.
- **If a line shows `!`:** see Problems P1 to P3 below.

### Step 4: choose your settings (only if you want to change something)
Use Part 1 (Way A), then check with `make live-demo-settings`. For a talk, I recommend `PAUSE=enter` and
`CAPTIONS=long`.

### Step 5: open the audience screen
1. Open a second terminal with **Ctrl+Alt+T**. This is **terminal 2**.
2. In terminal 2:
   ```bash
   cd ~/Provbind
   source .venv/bin/activate
   make live-demo-view
   ```
- **You should see:** the header `PROVBIND · live alerts`, and then it waits.
- Leave terminal 2 open the whole time, and do not type in it. It clears itself at every run.

### Step 6: practice run (before the audience arrives)
In terminal 1:
```bash
make live-demo
```
- **You should see:** `[1/5] envelope` through `[5/5] log`, then `done in N s`, while alert cards appear in
  terminal 2.
- **The first run after a power-on** may say `restarting the app (about 20 s)`. That is normal.
- **You should not see** a line starting with `!`. If you do, see P5.

### Step 7: arrange the screen
1. Put terminal 2 (the audience screen) and terminal 1 side by side.
2. In each terminal, press **Ctrl and +** a few times to enlarge the font.
3. Turn notifications off.

### Step 8: the demo
1. Say the opening line: *"PROVBIND builds a rulebook from the image's signed evidence before anything
   runs, then checks every action in the container against it."*
2. In terminal 1, type `make live-demo`, or the one-run version you chose.
3. Follow the acts:

| Act | You will see | Say |
|---|---|---|
| envelope | all checks `ok`, then `envelope compiled in N s` | "From the signed evidence alone, before anything happens." |
| shell | `PROVBIND: 0 alerts; 3 Low records`, then a Falco alert | "Inside the container: allowed, so no alarm. Falco raises a false alarm." |
| trust | `trust withdrawn`, the pod still `CONFORMING` | "Nothing changed in the container, but trust is gone." |
| attack | `CRITICAL 84`, `CRITICAL 90`, `HIGH 72`, `(same incident)` | "Caught, traced to the image layer, one incident." |
| log | `OK: N records`, then `BROKEN at record k=…` | "The evidence cannot be quietly edited." |

4. Close: *"The numbers are on the slides: one live run is a demonstration, not a measurement."*
5. To show it again, type `make live-demo`.

### Step 9: finish
1. In terminal 1:
   ```bash
   make live-demo-stop
   ```
2. In terminal 2, press **Ctrl+C**.
3. Shut down from **Ubuntu's menu → Power Off**, or close the VM window and choose **"Save the machine
   state"**. Never choose "Power off the machine": it is like pulling the plug.

---

## Problems and what to do

| # | You see | Do this |
|---|---|---|
| P1 | `!` on "the cluster answers" or "Tetragon is running" | Wait 2 minutes and run `make live-demo-check` again. Still `!`: run `docker start kind-control-plane`, wait 1 minute, check again |
| P2 | `!` on "the local registry answers" | `docker start kind-registry`, then check again |
| P3 | `!` on "a signed image is known" | `export COSIGN_PASSWORD='…'` (your key's password), then `make demo-app`, then check again |
| P4 | Still broken after P1 to P3 | **Do not run `make up`** (it fails while the cluster exists). Send me the output of `make live-demo-check` |
| P5 | A line starting with `!` during the demo | Keep going; the other acts still run. Afterwards, run `make live-demo-diagnose` and send me the output |
| P6 | The demo refuses to start: `live-demo: SETTING=…` | A setting is misspelled. The message lists the allowed values; fix it and run again |
| P7 | No `(.venv)` at the start of the line, or `No module named …` | You skipped `source .venv/bin/activate` in that terminal; run it |
| P8 | One act needs repeating | `make live-demo-act ACT=attack` (or `envelope`, `shell`, `trust`, `log`) |
| P9 | Lines like `/proc/…/cmdline: No such file or directory` at the start | Harmless (after a hard power-off). `git pull origin claude/zen-hypatia-pyrg25` removes them |
| P10 | Nothing works in front of the audience | Backup replay: in terminal 2 press Ctrl+C, type `ls -d run-demo.2*`, then `python3 -m eval.demo_view --replay run-demo.<one of those names>/alerts.jsonl --step` and press Enter for each act. Say it is a recording |
