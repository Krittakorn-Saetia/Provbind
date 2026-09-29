# ml/data/mlb/: dataset D2, ML-B's benign windows

Test Plan §5 and §12.2. One folder per image, named by the 64 hex digits of its digest:

| File | What it holds |
|---|---|
| `<hex>/train.jsonl` | The first 70% of the first benign run's windows, in time order |
| `<hex>/validation.jsonl` | The last 30%. θ_A and g_I come from these |
| `<hex>/heldout.jsonl` | A second benign run, starting at least an hour after the first (MLB-04) |

Each line is one closed window, written by `node/mlb.py`: digest, container, pod, pid, exe, start, end, events, `closed_by` (`time` or `count`), the process's age, and the 20 features Ψ_I. The windows are built after verification, so only conforming events are in them (MLB-01).

## Building it on the demo PC

1. **Apply the same Tetragon policies you will use for attack-2**: at least `write.yaml`, `truncate.yaml` and `cap.yaml`, plus `connect.yaml` if you use it. The features count every kind of event, so a model trained without a hook sees that hook's events as new.
2. **First benign run, at least 4 hours** (see "How long"). Record Tetragon while Role 1's load generator runs:
   ```bash
   kubectl logs -n kube-system ds/tetragon -c export-stdout -f | tee benign-1.jsonl | python -m node.run --run $PROVBIND_RUN
   ```
3. **Windows, then the split:**
   ```bash
   python -m node.mlb windows --run $PROVBIND_RUN --replay benign-1.jsonl --digest <digest> --out benign-1.windows.jsonl
   python -m node.mlb split --windows benign-1.windows.jsonl --out-dir ml/data/mlb/<hex>
   ```
4. **Second benign run.** At least an hour later, record at least another hour. Make its windows the same way, with `--out ml/data/mlb/<hex>/heldout.jsonl`.
5. **Train and check:**
   ```bash
   python -m node.mlb train --data ml/data/mlb/<hex> --run $PROVBIND_RUN      # model beside the envelope
   python -m node.mlb evaluate --data ml/data/mlb/<hex> --run $PROVBIND_RUN   # MLB-04's false-positive rate
   ```
6. **Record the results.** `pytest -q tests/capability/test_mlb_*.py` records MLB-03 to 06. For MLB-05, also set `PROVBIND_RECORDING` to a recording with an attack-2 row in `ground_truth.csv`.
7. **For MLB-06, repeat for two or more corpus images.** With several folders here, set `PROVBIND_MLB_DIGEST` to the demo image's digest.

The model goes to `$PROVBIND_RUN/envelopes/<hex>.mlb/model.json`. That is JSON, not a pickle. `python -m node.run --mlb` scores windows with it.

## How long

A window starts at a process's first event, so a process that is quiet between requests gives fewer windows than one per 30 seconds.

- **3 hours:** with the synthetic load of the unit tests (one request every 5 s), this gave about 290 windows. That leaves fewer than 100 for validation, so θ_A falls back to the 95th percentile, as Test Plan §5 says, and a 1% false-positive rate is out of reach.
- **4 hours:** this gave about 390 windows (119 for validation) and the 99th percentile.

Record at least 4 hours, and check the validation count that `train` prints.

## Rules (Test Plan §12.2)

- **Keep ML-C apart.** Never read from or write to ML-C's folder (`eval/mlc/data/`), and never use these files for ML-C (EV-07).
- **Commit windows only.** Raw Tetragon recordings are large and hold host details, so they don't belong here.
- **No real malware.** Any payload is harmless test code (§12.4).
