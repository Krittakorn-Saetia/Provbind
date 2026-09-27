# Tool versions

Fill this in on Day 1 so every flag can be checked against the right documentation. The demo PC column is the one that counts on the day. Korn-PC is where Role 2 built, signed and compiled the stand-in.

| Tool | Command | Demo PC | Korn-PC (Role 2, WSL2) |
|---|---|---|---|
| OS | `lsb_release -ds` | | Ubuntu 22.04 on WSL2 (Windows host) |
| Docker | `docker version --format '{{.Server.Version}}'` | | 29.5.3 (Docker Desktop, WSL integration) |
| buildx | `docker buildx version` | | |
| crane | `crane version` | | 0.22.1 |
| cosign | `cosign version` | | v3.1.3 |
| syft | `syft version` | | 1.52.0 |
| jq | `jq --version` | | |
| Python | `python3.11 --version` | | 3.11.16 (deadsnakes PPA) |
| kind | `kind version` | | not used by Role 2 |
| Tetragon | `helm list -n kube-system` | | not used by Role 2 |
| Falco | `helm list -n falco` | | not used by Role 2 |

Notes:

- **Python.** 3.11 is the team standard. Ubuntu 22.04 ships 3.10.12, so install 3.11 from the deadsnakes PPA. The unit tests also pass on 3.10, 3.12 and 3.13, but the integration run used 3.11.16.
- **Signing.** The stand-in was signed online (Rekor upload on) with cosign v3.1.3, and the compiler read cosign v3's output without changes.
- **Windows.** The compiler's unit tests pass on Windows too, but `pipeline/build-and-attest.sh` needs bash, so run the pipeline in WSL2. Keep the clone and `$PROVBIND_RUN` out of OneDrive, which would sync the blob cache and can lock files.
