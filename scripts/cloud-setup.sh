#!/bin/bash
# Setup script for the PROVBIND repo in Claude Code on the web (or any fresh Linux machine).
# Python packages are required; the CLI tools are best-effort and depend on the
# environment's network access. Nothing here needs Docker or a cluster.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null || true

python3 -m pip install --quiet -r requirements.txt \
  || echo "WARN: pip install failed; check the environment's network access"

BIN=/usr/local/bin
[ -w "$BIN" ] || BIN="$HOME/.local/bin"; mkdir -p "$BIN"

command -v syft >/dev/null || curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b "$BIN" || echo "WARN: syft not installed"
command -v cosign >/dev/null || { curl -sSfL -o "$BIN/cosign" \
  https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x "$BIN/cosign"; } \
  || echo "WARN: cosign not installed"
command -v crane >/dev/null || curl -sSfL \
  https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz \
  | tar -xz -C "$BIN" crane || echo "WARN: crane not installed"

echo "cloud-setup: done (tools in $BIN)"
