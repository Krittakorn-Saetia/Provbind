"""Build run/results/REPORT.md from the test registry and the result files.

usage: python -m eval.report [--run RUN_DIR] [--registry tests/capability/registry.json]
Every registry entry gets one row; a test without a result file is reported as not_run.
"""
import argparse, json, os, sys
from collections import Counter

ORDER = {"fail": 0, "blocked": 1, "not_run": 2, "pass": 3}


def load_results(results_dir):
    out = {}
    if not os.path.isdir(results_dir):
        return out
    for name in os.listdir(results_dir):
        if name.endswith(".json"):
            path = os.path.join(results_dir, name)
            try:
                with open(path, encoding="utf-8") as f:
                    r = json.load(f)
                out[r["id"]] = r
            except (OSError, ValueError, KeyError) as e:
                print(f"report: skipping unreadable {path}: {e}", file=sys.stderr)
    return out


def fmt_metrics(m):
    if not m:
        return ""
    return "; ".join(f"{k}={v}" for k, v in list(m.items())[:4])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--registry", default="tests/capability/registry.json")
    args = ap.parse_args()

    with open(args.registry, encoding="utf-8") as f:
        tests = json.load(f)["tests"]
    results_dir = os.path.join(args.run, "results")
    results = load_results(results_dir)
    unknown = sorted(set(results) - {t["id"] for t in tests})

    lines = ["# PROVBIND capability test report", ""]
    for prio in ("P0", "P1", "P2"):
        subset = [t for t in tests if t["priority"] == prio]
        counts = Counter(results.get(t["id"], {}).get("status", "not_run") for t in subset)
        lines.append(f"**{prio}:** " + ", ".join(f"{k} {counts.get(k, 0)}" for k in ("pass", "fail", "blocked", "not_run"))
                     + f" (of {len(subset)})")
    lines += ["", "| ID | P | Owner | Status | Checks | Metrics | Notes |", "|---|---|---|---|---|---|---|"]
    rows = []
    for t in tests:
        r = results.get(t["id"], {})
        status = r.get("status", "not_run")
        rows.append((t["priority"], ORDER.get(status, 9), t["id"],
                     f"| {t['id']} | {t['priority']} | {t['owner']} | {status} | {t['checks']} | "
                     f"{fmt_metrics(r.get('metrics'))} | {r.get('notes', '')} |"))
    lines += [row[-1] for row in sorted(rows)]
    if unknown:
        lines += ["", "Result files with IDs not in the registry: " + ", ".join(unknown)]
    os.makedirs(results_dir, exist_ok=True)
    out = os.path.join(results_dir, "REPORT.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(out)


if __name__ == "__main__":
    main()
