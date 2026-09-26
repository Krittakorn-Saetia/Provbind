# Tool versions on the demo PC

Fill this in on Day 1 so every flag can be checked against the right documentation.

| Tool | Command | Version |
|---|---|---|
| Docker | `docker version --format '{{.Server.Version}}'` | |
| buildx | `docker buildx version` | |
| crane | `crane version` | |
| cosign | `cosign version` | |
| syft | `syft version` | |
| Python | `python3.11 --version` | |
| kind | `kind version` | |
| Tetragon | `helm list -n kube-system` | |
| Falco | `helm list -n falco` | |
