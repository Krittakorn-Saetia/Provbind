#!/usr/bin/env python3
"""
contracts/check_contracts.py
Schema validator for PROVBIND data contract files.
Validates bindings.json, envelopes/*.json, detections.jsonl, and alerts.jsonl.
"""

import json
import sys
import os

def validate_json_schema(obj, required_keys, file_name):
    missing = [k for k in required_keys if k not in obj]
    if missing:
        print(f"❌ [Contract Error] {file_name} missing required keys: {missing}")
        return False
    return True

def check_bindings(path):
    if not os.path.exists(path):
        print(f"⚠️ {path} does not exist yet (skipping check)")
        return True
    with open(path, "r") as f:
        data = json.load(f)
    required = ["namespace", "pod", "container", "image_digest", "verified", "run_as_root", "privileged", "mounts", "envelope_ready"]
    valid = True
    for container_id, binding in data.items():
        if not validate_json_schema(binding, required, f"bindings.json ({container_id})"):
            valid = False
    if valid:
        print(f"✅ bindings.json contract valid ({len(data)} entries)")
    return valid

def check_envelope(path):
    if not os.path.exists(path):
        print(f"⚠️ {path} does not exist yet (skipping check)")
        return True
    with open(path, "r") as f:
        data = json.load(f)
    required = ["schema", "image", "layers", "files", "symlinks", "closure", "packages", "capabilities", "unresolved_fraction", "compiled_at"]
    if not validate_json_schema(data, required, path):
        return False
    print(f"✅ {os.path.basename(path)} contract valid")
    return True

def check_jsonl(path, required_keys, schema_name):
    if not os.path.exists(path):
        print(f"⚠️ {path} does not exist yet (skipping check)")
        return True
    valid = True
    count = 0
    with open(path, "r") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            count += 1
            record = json.loads(line)
            if not validate_json_schema(record, required_keys, f"{schema_name} line {i}"):
                valid = False
    if valid:
        print(f"✅ {os.path.basename(path)} contract valid ({count} records)")
    return valid

def main():
    run_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"🔍 Validating PROVBIND data contracts in: {run_dir}\n" + "-"*50)
    
    b_ok = check_bindings(os.path.join(run_dir, "bindings.json"))
    
    env_dir = os.path.join(run_dir, "envelopes")
    e_ok = True
    if os.path.exists(env_dir):
        for fname in os.listdir(env_dir):
            if fname.endswith(".json"):
                if not check_envelope(os.path.join(env_dir, fname)):
                    e_ok = False

    det_keys = ["id", "time", "container_id", "namespace", "pod", "container", "image_digest", "pid", "ppid", "exe", "parent_exe", "class", "subclass", "clause", "origin", "context"]
    d_ok = check_jsonl(os.path.join(run_dir, "detections.jsonl"), det_keys, "detections.jsonl")

    alt_keys = ["alert_id", "detection_id", "time", "image_digest", "container", "class", "subclass", "violated_clause", "origin", "score", "bucket", "attribution", "signing_identity", "chain_id", "log_k"]
    a_ok = check_jsonl(os.path.join(run_dir, "alerts.jsonl"), alt_keys, "alerts.jsonl")

    if b_ok and e_ok and d_ok and a_ok:
        print("-" * 50 + "\n🎉 All data contracts passed validation successfully!")
        sys.exit(0)
    else:
        print("-" * 50 + "\n❌ Data contract validation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
