# Tool versions

Fill this in on Day 1 so every flag can be checked against the right documentation. The demo PC column is the one that counts on the day. Korn-PC is where Role 2 built, signed and compiled the stand-in.

| Tool | Command | Demo PC | Korn-PC (Role 2, WSL2) |
|---|---|---|---|
| OS | `lsb_release -ds` | Ubuntu 24.04 (VirtualBox VM on a Windows host) | Ubuntu 22.04 on WSL2 (Windows host) |
| Docker | `docker version --format '{{.Server.Version}}'` | 29.8.1 (`docker --version`) | 29.5.3 (Docker Desktop, WSL integration) |
| buildx | `docker buildx version` | | |
| crane | `crane version` | | 0.22.1 |
| cosign | `cosign version` | v3.1.3 | v3.1.3 |
| syft | `syft version` | | 1.52.0 |
| jq | `jq --version` | | |
| Python | `python3.11 --version` | | 3.11.16 (deadsnakes PPA) |
| kind | `kind version` | v0.33.0 (go1.26.7) | not used by Role 2 |
| Tetragon | `helm list -n kube-system` | 1.7.1 (chart tetragon-1.7.1) | not used by Role 2 |
| Falco | `helm list -n falco` | 0.45.0 (chart falco-9.2.0) | not used by Role 2 |
| Kernel | `uname -r` | 7.0.0-34-generic | |
| kubectl | `kubectl version --client` | v1.37.1 | |
| bpftrace | `bpftrace --version` | v0.20.2 (Confine-E / DeSFAM-E traces) | |

Notes:

- **Demo PC column** (Role 1, 2 October 2026): the VM that ran the 30 September scored runs and the 1 and 2 October comparison runs. buildx, crane, syft, jq and the exact Python 3.11 patch release were not recorded.

- **Python.** 3.11 is the team standard. Ubuntu 22.04 ships 3.10.12, so install 3.11 from the deadsnakes PPA. The unit tests also pass on 3.10, 3.12 and 3.13, but the integration run used 3.11.16.
- **Signing.** The stand-in was signed online (Rekor upload on) with cosign v3.1.3, and the compiler read cosign v3's output without changes.
- **Windows.** The compiler's unit tests pass on Windows too, but `pipeline/build-and-attest.sh` needs bash, so run the pipeline in WSL2. Keep the clone and `$PROVBIND_RUN` out of OneDrive, which would sync the blob cache and can lock files.
