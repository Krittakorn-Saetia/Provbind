# Behaviours our scenarios re-create (Test Plan §12.4)

Our scenarios are **harmless re-creations** of behaviours seen in real malicious packages. This file
names, for each scenario, the behaviour it stands for and the real package(s) it was modelled on, so
the paper can say where each test comes from. The team's source is the **Datadog malicious software
packages dataset** (D6; `github.com/DataDog/malicious-software-packages-dataset`, Apache-2.0), with
Backstabber's Knife Collection (D7) optional.

## Handling rules (Test Plan §12.4: follow them exactly)

1. **Never install, import or run a sample.** `pip install` / `npm install` run install scripts, which
   is how many of these packages attack.
2. **Read samples only in a dedicated virtual machine** with no personal accounts, SSH keys or cloud
   credentials. Snapshot it first; disable networking while samples are extracted.
3. **Read, don't run:** extract into a folder mounted `noexec`, open files as text, delete them after.
   Don't clone the whole repository onto a laptop; download single files or use a sparse checkout.
4. **Never put a real sample** in an image, the registry, the demo PC or this repository. Tell Aj Ohm
   and follow SIIT policy before downloading.
5. **What goes in this file:** the package name and version, the ecosystem, and the behaviour in plain
   words. No code, no payload hosts or URLs, no copied strings from the sample.
6. **The safe part, usable anywhere:** each ecosystem's `manifest.json` lists only package names and
   affected versions (`null` means every version is malicious). It can feed the trust tests
   (ComponentCheck, PH6-04/05) as a list of known-malicious packages.

**Caveat for the paper:** the Datadog dataset was found mostly by one ruleset (GuardDog), so it may not
represent all supply-chain malware.

## Behaviour → scenario map

Fill in "Modelled on" after reading samples in the VM (5–10 samples cover these behaviours, §12.4).

| Behaviour (§12.4) | Scenario | PROVBIND detection expected | Our harmless re-creation | Status | Modelled on (ecosystem / package / version) |
|---|---|---|---|---|---|
| Run-time drop-and-execute | attack-1 | D_exec undeclared + D_write | `requestz_helper.check_update()` drops `/tmp/.x9` (inert marker write to `/etc/passwd`) | ready | _to fill_ |
| Library injection | attack-5 | D_load undeclared | `LD_PRELOAD` of an embedded `.so` into `python3 -c pass` | P1, endpoint not implemented | _to fill_ |
| Exfiltration to an out-of-band endpoint (the most common in the Datadog analysis) | attack-7 | D_net | connect to an address outside the egress list | P1, endpoint not implemented | _to fill_ |
| Install-time execution (npm pre-install; the second most common) | attack-8 | only a weak outside-closure detection: the documented build-time boundary | a build step writes `/usr/local/bin/helperd`, run later | P1, not implemented | _to fill_ |
| Credential-file reads | — | **none deterministic**: PROVBIND hooks exec, write, exec-mmap, capability and connect, not reads | — | gap (see below) | _to fill_ |
| In-envelope volumetric activity | attack-2 | D_beh only (ML-B) | 300 new files under `/tmp/.cache` in 20 s, read back | ready | not from a sample: the plan's in-envelope adversary |

**Gap to report:** credential-file reads have no deterministic hook in the draft's design (§8 lists
exec, write, mmap, capability and connect). Either add a read hook for protected paths (for example
`security_file_permission` with MAY_READ, filtered in the kernel to a few paths) as an update item, or
state the limit in the paper.
