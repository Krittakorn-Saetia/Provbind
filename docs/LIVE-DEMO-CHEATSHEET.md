# Live demo: one-page cheat sheet

The full runbook is `docs/LIVE-DEMO.md`. Open this page on the VM with `less docs/LIVE-DEMO-CHEATSHEET.md`
(q to quit).

## Settings: two ways, the same names and options

| Way | How | Lasts |
|---|---|---|
| Permanent | `nano testbed/live-demo.conf`, change the value after `=`, save with Ctrl+O and Enter, exit with Ctrl+X | every run from now on |
| One run | `make live-demo NAME=value NAME=value`; quotes around a value with spaces: `ACTS="envelope attack"` | that run only |

- The command line wins over the file.
- `make live-demo-settings` shows what will be used and where each value comes from. Add `NAME=value` to
  preview a one-run setting.
- To undo every edit to the file: `git checkout testbed/live-demo.conf`.
- No spaces around `=`.
- A wrong value stops the demo before it starts and lists the allowed values.

### Every setting

**What the audience sees**

| Setting | Options | Default |
|---|---|---|
| `ACTS` | any of `envelope` `shell` `trust` `attack` `log` `unsigned`, in any order, in quotes. Keep `trust` before `attack`, and `log` after an act that alerts | `"envelope shell trust attack log"` |
| `ATTACK` | `update`: a dropped program runs and edits `/etc/passwd`, 3 alerts. `overwrite`: `/usr/bin/ls` is overwritten. `inject`: hidden code is loaded. `egress`: a forbidden connection | `update` |
| `TRUST` | `advisory`: an advisory names a package. `key`: the signing key is revoked (simulated) | `advisory` |
| `ADVISORY_ID` | `MAL-…` withdraws trust. Any other id, such as `CVE-2026-0001`, is only reported and trust stays | `MAL-2026-9001` |
| `ADVISORY_PACKAGE` | a package in the image's SBOM | `requestz-helper` |
| `ADVISORY_VERSION` | a version; empty (`ADVISORY_VERSION=`) means every version | `0.1.0` |
| `ADVISORY_ECOSYSTEM` | `PyPI` `npm` `Debian` `Ubuntu` `Go` `crates.io` `Maven` `RubyGems` `NuGet` `Packagist` `Alpine` | `PyPI` |
| `SHELL_CMD` | any harmless shell command, in quotes | `"ls /; cat /etc/hostname"` |

**Pace and text**

| Setting | Options | Default |
|---|---|---|
| `PAUSE` | seconds between acts (`0` none, `3` gives about 30 s in all, `10` about 1 minute), or `enter`: waits for you before each act | `10` |
| `CAPTIONS` | `short`: one line per act. `long`: adds what to say and what to point at | `short` |
| `WAIT_S` | seconds each act waits for its alert | `30` |

**How each run behaves**

| Setting | Options | Default |
|---|---|---|
| `FRESH` | `1`: a clean start every run. `0`: continue on the running services | `1` |
| `REDEPLOY` | `0`: use the running app. `1`: deploy it live in the first act (about 20 s more) | `0` |
| `KEEP_RUNS` | how many old runs are kept for the backup replay | `3` |
| `FALCO` | `auto`: Falco's alerts beside PROVBIND's. `off`: hide them | `auto` |
| `NEO4J` | `off`: alerts at once. `on`: alerts wait while each run's graph loads | `off` |
| `POLICY_SET` | `opt`: the sensor setup of the final runs. `orig`: no wait when an attack repeats, but noisier | `opt` |

**Where the app is** (leave as is)

| Setting | Options | Default |
|---|---|---|
| `DEMO_REF` | the signed image as `ref@digest`; empty means found automatically | empty |
| `NAMESPACE` | the Kubernetes namespace | `demo` |
| `DEPLOY` | the deployment's name | `demo-app` |

**Command line only**

| Setting | What it does |
|---|---|
| `AUTO=1` | skips every pause |
| `DRY_RUN=1` | prints the commands without running them; needs no cluster |
| `PROVBIND_OFFLINE=1` | checks signatures without the internet (the Rekor check is skipped) |
| `DEMO_CONF=FILE` | uses another settings file, such as `testbed/talk.conf` |
| `DEMO_RUN=DIR` | another run folder; give the same one to `make live-demo-view` |
| `ACT=NAME` | with `make live-demo-act`: the act to repeat |

### Ready-made versions

| You want | Command |
|---|---|
| Hands-free, about 1 minute | `make live-demo` |
| You set the pace, talking points on screen | `make live-demo PAUSE=enter CAPTIONS=long` |
| A short version, about 20 s | `make live-demo ACTS="envelope trust attack" PAUSE=3` |
| The full show, about 2 minutes | `make live-demo ACTS="envelope shell trust attack log unsigned" REDEPLOY=1` |
| Another attack | `make live-demo ATTACK=egress` |
| A revoked key | `make live-demo TRUST=key` |
| A CVE that does not withdraw trust | `make live-demo ADVISORY_ID=CVE-2026-0001` |

## Start to finish

### A. Power on and check (about 3 minutes)

1. Start the VM, log in, and open a terminal with Ctrl+Alt+T.
2. Run these commands:
   ```bash
   cd ~/Provbind
   source .venv/bin/activate
   git pull origin claude/zen-hypatia-pyrg25
   make live-demo-check
   ```
3. If every required line shows ✓, go to B. Otherwise:
   - **"the cluster answers" or "Tetragon is running" shows `!`:** wait 2 minutes and check again. If it is still `!`, run `docker start kind-control-plane`, wait a minute, and check again.
   - **"the local registry answers" shows `!`:** run `docker start kind-registry`.
   - **"a signed image is known" shows `!`:** run `export COSIGN_PASSWORD=…`, then `make demo-app`.
   - **The Falco line shows `-`:** it is still starting. Wait a minute; it is optional.
   - **Never run `make up` while the cluster exists.**

### B. Choose the settings (once)

Edit `testbed/live-demo.conf` (Way 1 above), then check with `make live-demo-settings`. For a talk:
`PAUSE=enter` and `CAPTIONS=long`.

### C. Practice run (before the audience arrives)

1. Open a second terminal and start the audience screen. Leave it open the whole time:
   ```bash
   cd ~/Provbind && source .venv/bin/activate && make live-demo-view
   ```
2. In the first terminal, run `make live-demo`. The first run after a power-on may restart the app once
   (about 20 s); that is normal. It ends with `done in N s` and no line starting with `!`.
3. Put the two terminals side by side and enlarge the font with Ctrl and +.

### D. The demo

1. Opening line: *"PROVBIND builds a rulebook from the image's signed evidence before anything runs, then
   checks every action in the container against it."*
2. In the first terminal, run `make live-demo`.
3. Say one sentence per act:
   - **envelope:** "From the signed evidence alone, before anything happens."
   - **shell:** "Inside the container: allowed, so no alarm. Falco raises a false alarm."
   - **trust:** "Nothing changed in the container, but trust is gone."
   - **attack:** "Caught, traced to the image layer, one incident."
   - **log:** "The evidence cannot be quietly edited."
4. Close: the numbers are on the slides, because one live run is a demonstration, not a measurement.
5. To show it again: `make live-demo`.

### E. Afterwards

1. Run `make live-demo-stop`.
2. Shut down from Ubuntu's menu (Power Off), or close the VM window with "Save the machine state". Never
   use VirtualBox's "Power off the machine".

### F. If something goes wrong

| What happens | What to do |
|---|---|
| A line starts with `!` during an act | Keep going; the other acts still run. Afterwards, run `make live-demo-diagnose` |
| One act needs repeating | `make live-demo-act ACT=attack` (or `envelope`, `shell`, `trust`, `log`) |
| Nothing works | Backup replay in the second terminal: Ctrl+C, then `ls -d run-demo.2*` and `python3 -m eval.demo_view --replay run-demo.<date-time>/alerts.jsonl --step`. Say it is a recording |
