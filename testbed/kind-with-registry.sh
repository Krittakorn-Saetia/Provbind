#!/usr/bin/env bash
# kind cluster wired to a local registry at localhost:5001 (Sprint Handoff §10, Role 1).
# Adapted from the kind "Local Registry" guide (kind.sigs.k8s.io/docs/user/local-registry/).
# Runs on the demo PC; needs docker, kind and kubectl. Re-running it is safe.
set -euo pipefail

REG_NAME='kind-registry'
REG_PORT='5001'

# 1. Create the registry container unless it already exists.
if [ "$(docker inspect -f '{{.State.Running}}' "${REG_NAME}" 2>/dev/null || true)" != 'true' ]; then
  docker run -d --restart=always -p "127.0.0.1:${REG_PORT}:5000" --network bridge --name "${REG_NAME}" \
    registry:2
fi

# 2. Create the kind cluster with containerd told to use the registry.
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
nodes:
- role: control-plane
EOF

# 3. Point the nodes at the registry (containerd certs.d hosts.toml).
REGISTRY_DIR="/etc/containerd/certs.d/localhost:${REG_PORT}"
for node in $(kind get nodes); do
  docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
  cat <<EOF | docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${REG_NAME}:5000"]
EOF
done

# 4. Connect the registry to the kind network so nodes can reach it by name.
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${REG_NAME}")" = 'null' ]; then
  docker network connect "kind" "${REG_NAME}"
fi

# 5. Document the registry in the cluster (kind convention).
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REG_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

echo "kind + registry ready: push to localhost:${REG_PORT}/<name>"
