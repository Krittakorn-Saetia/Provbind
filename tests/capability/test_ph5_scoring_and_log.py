"""PH5-01 to PH5-05 (scoring) and PH5-10, PH5-11 (the log): Role 4, Test Plan §3.8.

The plan's "how" for these is unit and property tests (the Sprint Handoff §8 examples, random
inputs, 100 appended records, a one-character edit), so they record pass or fail anywhere.
"""
import random
import re

from alerts import verify_log
from alerts.log import ViolationLog
from alerts.score import bucket_of, score_detection

ROOT_POD = {"run_as_root": True, "privileged": False}


def det(cls, sub, origin="AUTHENTICATED", **ctx):
    return {"class": cls, "subclass": sub, "origin": origin,
            "context": {"declared": True, "package": None, "depth": None, **ctx}}


def test_ph5_01_the_sprint_handoff_scores(record_result):
    got = {"x9": score_detection(det("D_exec", "undeclared", declared=False), ROOT_POD)[:2],
           "passwd": score_detection(det("D_write", "declared_file"), ROOT_POD)[:2],
           "ls": score_detection(det("D_exec", "outside_closure", package="pkg:deb/debian/coreutils@9.1-1", depth=1), ROOT_POD)[:2]}
    ok = got == {"x9": (90, "critical"), "passwd": (72, "high"), "ls": (34, "low")}
    record_result("PH5-01", "pass" if ok else "fail", metrics={k: v[0] for k, v in got.items()},
                  notes=f"root, non-privileged pod: /tmp/.x9 {got['x9']}, /etc/passwd {got['passwd']}, /usr/bin/ls {got['ls']}")
    assert ok


def test_ph5_02_authenticated_outranks_inferred(record_result):
    pairs = {f"{c}/{s}": (score_detection(det(c, s), ROOT_POD)[0], score_detection(det(c, s, "INFERRED"), ROOT_POD)[0])
             for c, s in [("D_exec", "undeclared"), ("D_write", "declared_file"), ("D_hash", "modified"),
                          ("D_load", "undeclared"), ("D_cap", "not_in_envelope"), ("D_net", "not_allowed")]}
    ok = all(a > i for a, i in pairs.values())
    record_result("PH5-02", "pass" if ok else "fail", metrics={k: {"authenticated": a, "inferred": i} for k, (a, i) in pairs.items()},
                  notes=f"same detection with the origin flipped, {len(pairs)} classes: AUTHENTICATED scores higher in every one")
    assert ok


def test_ph5_03_scores_stay_in_range(record_result):
    rng = random.Random(2026)
    classes = [("D_exec", "undeclared"), ("D_exec", "outside_closure"), ("D_write", "declared_file"), ("D_hash", "modified"),
               ("D_hash", "relocated"), ("D_load", "undeclared"), ("D_load", "outside_closure"), ("D_cap", "not_in_envelope"),
               ("D_net", "not_allowed"), ("D_beh", "anomalous_window"), ("binding", "unverified"), ("D_future", "x")]
    dets = [{"class": c, "subclass": s, "origin": rng.choice(["AUTHENTICATED", "INFERRED", "CONFIGURED"]),
             "clause": {"detail": f"g_I {rng.random():.3f}"},
             "context": {"declared": rng.choice([True, False, None]), "package": rng.choice([None, "pkg:pypi/x@1"]),
                         "depth": rng.choice([None, 0, 1, 2, 7, 60])}}
            for c, s in (rng.choice(classes) for _ in range(5000))]
    before = [dict(d) for d in dets]
    scores = [score_detection(d, {"privileged": rng.random() < .3, "run_as_root": rng.random() < .6}) for d in dets]
    ok = len(scores) == len(dets) and dets == before and all(0 <= s <= 100 and b == bucket_of(s) for s, b, _ in scores)
    record_result("PH5-03", "pass" if ok else "fail", metrics={"detections": len(dets), "min": min(s for s, _, _ in scores),
                                                              "max": max(s for s, _, _ in scores)},
                  notes="5,000 random detections over every class Role 3 emits, plus an unknown one: every score in [0, 100] "
                        "(S in [0, 1]), one score per detection, detections unchanged")
    assert ok


def test_ph5_04_undeclared_outranks_declared(record_result):
    """Judged on S, the score Eq. (65) defines; the whole-number score is only its display. For
    every type, origin and pod, and every depth 0-199: S is lower for the declared file, its
    rounded score is never higher, and ranking (alerts.show --rank) puts the undeclared file first."""
    from alerts.show import rank
    types = [("D_exec", "undeclared"), ("D_load", "undeclared"), ("D_write", "declared_file"), ("D_hash", "relocated"),
             ("D_cap", "not_in_envelope"), ("D_net", "not_allowed")]
    pods = [{"privileged": True}, {"run_as_root": True}, {"run_as_root": False}]
    combos = s_lower = never_higher = ranked_first = 0
    first_ties = set()
    for cls, sub in types:
        for origin in ("AUTHENTICATED", "INFERRED"):
            for pod in pods:
                u_score, _, u = score_detection(det(cls, sub, origin, declared=False), pod)
                for d in range(200):
                    combos += 1
                    score, _, p = score_detection(det(cls, sub, origin, package="pkg:pypi/x@1", depth=d), pod)
                    s_lower += p["S"] < u["S"]
                    never_higher += score <= u_score
                    order = rank([{"alert_id": "declared", "score": score, "score_parts": p, "time": "t"},
                                  {"alert_id": "undeclared", "score": u_score, "score_parts": u, "time": "t"}])
                    ranked_first += order[0]["alert_id"] == "undeclared"
                    if score == u_score:
                        first_ties.add(d)
    ok = s_lower == never_higher == ranked_first == combos
    first_tie = min(first_ties) if first_ties else None
    record_result("PH5-04", "pass" if ok else "fail",
                  metrics={"cases": combos, "S_lower": s_lower, "score_never_higher": never_higher,
                           "ranked_first": ranked_first, "display_tie_from_depth": first_tie},
                  notes=(f"{combos} cases (6 types x 2 origins x 3 pods x depths up to 199): S is lower for the declared "
                         f"file in every case, its rounded score is never higher, and ranking by S puts the undeclared "
                         f"file first. The whole-number display score ties from depth {first_tie} "
                         f"(for a root pod 100*S = 70 + 20*d/(1+d), which rounds to 90 there); ranking uses S"))
    assert ok


def test_ph5_05_unresolved_depth_is_not_bottom(record_result):
    parts = score_detection(det("D_write", "declared_file", package="pkg:deb/debian/login@1", depth=None), ROOT_POD)[2]
    ok = parts["rho"] == 0.5
    record_result("PH5-05", "pass" if ok else "fail", metrics={"rho": parts["rho"]},
                  notes="a base-image file whose package has a null depth: rho = 0.5, not 1 (M16)")
    assert ok


def test_ph5_10_and_11_the_hash_chain(tmp_path, record_result):
    log = ViolationLog(tmp_path)
    for i in range(1, 101):
        log.append({"detection_id": f"det-{i:04d}", "class": "D_exec", "subclass": "undeclared", "score": 90})
    clean = verify_log.verify(tmp_path)
    ok10 = clean.ok and clean.records == 100
    record_result("PH5-10", "pass" if ok10 else "fail", metrics={"records": clean.records},
                  notes=f"100 records appended with the §4.6 rule, then verify_log: {clean.reason}")

    path = tmp_path / "log" / "violations.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    reported = {}
    for k in (1, 42, 100):
        edited = list(lines)
        edited[k - 1] = edited[k - 1].replace('"score": 90', '"score": 91', 1)
        path.write_text("\n".join(edited) + "\n", encoding="utf-8")
        reported[k] = verify_log.verify(tmp_path).first_bad
    target = len(lines) // 2                          # Role 1's tamper-1 edit: the first lowercase letter
    i = re.search(r"[a-z]", lines[target]).start()
    edited = list(lines)
    edited[target] = edited[target][:i] + "b" + edited[target][i + 1:]
    path.write_text("\n".join(edited) + "\n", encoding="utf-8")
    reported[f"tamper-1 at {target + 1}"] = verify_log.verify(tmp_path).first_bad
    ok11 = reported == {1: 1, 42: 42, 100: 100, f"tamper-1 at {target + 1}": target + 1}
    record_result("PH5-11", "pass" if ok11 else "fail", metrics={"reported": {str(k): v for k, v in reported.items()}},
                  notes="one character changed in record k: verify_log reports k, for k = 1, 42, 100 and for "
                        "testbed/scenarios/tamper.sh's own edit")
    assert ok10 and ok11
