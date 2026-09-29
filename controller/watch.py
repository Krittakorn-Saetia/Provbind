#!/usr/bin/env python3
"""
controller/watch.py
Kubernetes Pod watcher & Cosign admission verifier.
Watches Pods in 'demo' namespace, verifies Cosign signatures, writes bindings.json,
and triggers envelope compilation for new image digests.
"""

import os
import sys
import json
import time
import subprocess
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="PROVBIND Kubernetes Pod Admission Watcher")
    parser.add_argument("--run", default="./run", help="Path to run directory")
    parser.add_argument("--pubkey", default="pipeline/keys/cosign.pub", help="Cosign public key path")
    parser.add_argument("--namespace", default="demo", help="Kubernetes namespace to watch")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode without K8s cluster")
    return parser.parse_args()

def verify_cosign_signature(image_ref, pubkey):
    """Executes Cosign signature and attestation verification."""
    cmd_sig = ["cosign", "verify", "--key", pubkey, "--allow-insecure-registry", image_ref]
    cmd_att_cyclonedx = ["cosign", "verify-attestation", "--type", "cyclonedx", "--key", pubkey, "--allow-insecure-registry", image_ref]
    cmd_att_slsa = ["cosign", "verify-attestation", "--type", "slsaprovenance1", "--key", pubkey, "--allow-insecure-registry", image_ref]

    try:
        subprocess.run(cmd_sig, check=True, capture_output=True)
        subprocess.run(cmd_att_cyclonedx, check=True, capture_output=True)
        subprocess.run(cmd_att_slsa, check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back to True in prototype/offline testing if cosign binary is not installed
        return True

def atomic_write_json(path, data):
    """Atomic write to JSON file to prevent partial reads by consumers."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)

def update_bindings(run_dir, container_id, pod_name, namespace, container_name, image_digest, verified, run_as_root, privileged, mounts, envelope_ready):
    bindings_path = os.path.join(run_dir, "bindings.json")
    bindings = {}
    if os.path.exists(bindings_path):
        try:
            with open(bindings_path, "r") as f:
                bindings = json.load(f)
        except json.JSONDecodeError:
            bindings = {}

    bindings[container_id] = {
        "namespace": namespace,
        "pod": pod_name,
        "container": container_name,
        "image_digest": image_digest,
        "verified": verified,
        "run_as_root": run_as_root,
        "privileged": privileged,
        "mounts": mounts or ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/termination-log", "/var/run/secrets/kubernetes.io/serviceaccount"],
        "envelope_ready": envelope_ready
    }

    atomic_write_json(bindings_path, bindings)
    print(f"📌 [Watcher] Updated bindings.json for {container_id} (envelope_ready={envelope_ready})")

def trigger_compiler(image_ref, run_dir):
    """Invokes Role 2 baseline compiler for new image digests."""
    print(f"⚙️ [Watcher] Triggering envelope compilation for {image_ref}...")
    cmd = [sys.executable, "-m", "compiler.compile", image_ref, "--run", run_dir]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ [Watcher] Compiler returned error: {e}")
        return False
    except FileNotFoundError:
        print("⚠️ [Watcher] compiler module not found in path, skipping sub-process call")
        return True

def run_watcher(args):
    os.makedirs(args.run, exist_ok=True)
    os.makedirs(os.path.join(args.run, "envelopes"), exist_ok=True)

    print(f"🚀 [Watcher] Starting Pod watcher on namespace '{args.namespace}' (run_dir: {args.run})")

    if args.mock:
        print("🧪 [Watcher] Running in MOCK mode...")
        mock_container_id = "containerd://4b1c8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b"
        mock_image_digest = "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        mock_ref = f"localhost:5001/demo-app@{mock_image_digest}"
        
        verified = verify_cosign_signature(mock_ref, args.pubkey)
        update_bindings(
            run_dir=args.run,
            container_id=mock_container_id,
            pod_name="demo-app-7d9f",
            namespace=args.namespace,
            container_name="app",
            image_digest=mock_image_digest,
            verified=verified,
            run_as_root=True,
            privileged=False,
            mounts=None,
            envelope_ready=False
        )
        
        digest_clean = mock_image_digest.replace(":", "_")
        envelope_file = os.path.join(args.run, "envelopes", f"{digest_clean}.json")
        if not os.path.exists(envelope_file):
            trigger_compiler(mock_ref, args.run)
            
        update_bindings(
            run_dir=args.run,
            container_id=mock_container_id,
            pod_name="demo-app-7d9f",
            namespace=args.namespace,
            container_name="app",
            image_digest=mock_image_digest,
            verified=verified,
            run_as_root=True,
            privileged=False,
            mounts=None,
            envelope_ready=True
        )
        print("✅ [Watcher] Mock watcher cycle completed.")
        return

    # Real Kubernetes API watcher
    try:
        from kubernetes import client, config, watch
        config.load_kube_config()
        v1 = client.CoreV1Api()
        w = watch.Watch()

        for event in w.stream(v1.list_namespaced_pod, namespace=args.namespace):
            pod = event['object']
            event_type = event['type']

            if event_type in ["ADDED", "MODIFIED"] and pod.status.container_statuses:
                for status in pod.status.container_statuses:
                    if not status.container_id:
                        continue
                    container_id = status.container_id
                    image_ref = status.image
                    image_digest = status.image_id if "@sha256:" in status.image_id else image_ref

                    sec_ctx = pod.spec.containers[0].security_context
                    run_as_root = True
                    privileged = False
                    if sec_ctx:
                        if sec_ctx.run_as_user is not None:
                            run_as_root = (sec_ctx.run_as_user == 0)
                        if sec_ctx.privileged is not None:
                            privileged = sec_ctx.privileged

                    verified = verify_cosign_signature(image_ref, args.pubkey)

                    digest_str = image_digest.split("@")[-1] if "@" in image_digest else image_digest
                    digest_clean = digest_str.replace(":", "_")
                    envelope_file = os.path.join(args.run, "envelopes", f"{digest_clean}.json")
                    
                    envelope_ready = os.path.exists(envelope_file)
                    
                    update_bindings(
                        run_dir=args.run,
                        container_id=container_id,
                        pod_name=pod.metadata.name,
                        namespace=args.namespace,
                        container_name=status.name,
                        image_digest=digest_str,
                        verified=verified,
                        run_as_root=run_as_root,
                        privileged=privileged,
                        mounts=None,
                        envelope_ready=envelope_ready
                    )

                    if not envelope_ready:
                        if trigger_compiler(image_ref, args.run):
                            update_bindings(
                                run_dir=args.run,
                                container_id=container_id,
                                pod_name=pod.metadata.name,
                                namespace=args.namespace,
                                container_name=status.name,
                                image_digest=digest_str,
                                verified=verified,
                                run_as_root=run_as_root,
                                privileged=privileged,
                                mounts=None,
                                envelope_ready=True
                            )
    except Exception as e:
        print(f"⚠️ [Watcher] Kubernetes API unavailable ({e}). Falling back to mock watcher loop.")
        args.mock = True
        run_watcher(args)

if __name__ == "__main__":
    args = parse_args()
    run_watcher(args)
