"""The audience screen for the live demo (docs/LIVE-DEMO.md).

    python -m eval.demo_view --run $PROVBIND_RUN --follow           # live, beside scripts/live-demo.sh
    python -m eval.demo_view --replay <run>/alerts.jsonl --step     # plan B: a recorded run, one burst per Enter
    python -m eval.demo_view --replay <run>/alerts.jsonl --speed 2  # plan B: recorded timing, twice as fast

One card per alert in plain words, coloured by severity: what happened, which layer, package and
dependency depth of the signed image it concerns, and where it ran. Alerts with the same chain id are
one incident. A Low record (a declared program outside the execution closure, such as an operator's
shell) is logged but is not an alert (Phase 5), so it shows as one dim line. A trust alert says how
long after the change it came and that the pod still behaves as signed.

A replay is a recorded run, not a live one, and its header says so. Reads alerts.jsonl (and the
envelopes beside it, for layer numbers) only; writes nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

COLOURS = {"critical": "\033[1;91m", "high": "\033[1;93m", "medium": "\033[1;94m",
           "low": "\033[2m", "trust": "\033[1;95m", "head": "\033[1m", "dim": "\033[2m"}
RESET = "\033[0m"
INDENT = " " * 10

TITLES = {
    ("D_exec", "undeclared"): "Undeclared program executed",
    ("D_load", "undeclared"): "Undeclared library loaded",
    ("D_exec", "outside_closure"): "Program outside the execution closure",
    ("D_load", "outside_closure"): "Library outside the execution closure",
    ("D_write", None): "Signed image file modified",
    ("D_hash", "modified"): "Signed program changed on disk",
    ("D_hash", "relocated"): "Signed program copied to a new path",
    ("D_cap", None): "Capability outside the envelope",
    ("D_net", None): "Connection to an undeclared address",
    ("D_beh", None): "Unusual behaviour inside the envelope",
    ("binding", "unverified"): "Image failed verification",
    ("binding", "unknown_container"): "Container from an unknown image",
    ("binding", "no_envelope"): "No envelope for this image",
}
TRUST_REASONS = {"key": "signing key revoked", "comp": "component advisory",
                 "builder": "builder denied", "trans": "transparency record broken"}


def paint(text: str, style: str, colour: bool) -> str:
    return f"{COLOURS[style]}{text}{RESET}" if colour and style in COLOURS else text


def clock(value) -> str:
    """HH:MM:SS in local time, from the alert's ISO time."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return "--:--:--"


def title_of(a: dict) -> str:
    cls, sub = a.get("class"), a.get("subclass")
    return TITLES.get((cls, sub)) or TITLES.get((cls, None)) or f"{cls}/{sub}"


def clause_parts(a: dict) -> tuple[str, str]:
    """(path, detail) from the alert's "kind: path: detail" clause."""
    parts = str(a.get("violated_clause") or "").split(": ", 2)
    if len(parts) == 3:
        return parts[1], parts[2]
    return "", str(a.get("violated_clause") or "")


def package_name(purl) -> str | None:
    """pkg:pypi/requests@2.32.3 -> requests 2.32.3."""
    if not purl:
        return None
    s = str(purl).split("?", 1)[0]
    s = s.split("/", 1)[1] if s.startswith("pkg:") and "/" in s else s
    name, _, version = s.rpartition("@") if "@" in s else (s, "", "")
    return f"{name.rsplit('/', 1)[-1]} {version}".strip()


class Layers:
    """Layer digest -> (index, count) from the envelopes in a run folder, read once per image."""

    def __init__(self, run: Path | None):
        self.run, self.cache = run, {}

    def lookup(self, image_digest, layer_digest) -> tuple[int, int] | None:
        if not (self.run and image_digest and layer_digest):
            return None
        hexd = str(image_digest).split(":", 1)[-1]
        if hexd not in self.cache:
            try:
                env = json.loads((self.run / "envelopes" / f"{hexd}.json").read_text(encoding="utf-8"))
                layers = env.get("layers") or []
                self.cache[hexd] = ({l.get("digest"): l.get("index") for l in layers}, len(layers))
            except (OSError, ValueError, AttributeError):
                self.cache[hexd] = ({}, 0)
        index, count = self.cache[hexd][0].get(layer_digest), self.cache[hexd][1]
        return (index, count) if index is not None else None


def provenance(a: dict, layers: Layers) -> str:
    attr = a.get("attribution") or {}
    bits = []
    layer = attr.get("layer")
    if layer:
        where = layers.lookup(a.get("image_digest"), layer)
        short = str(layer).split(":", 1)[-1][:12]
        bits.append(f"layer {where[0]} of {where[1]} ({short})" if where else f"layer {short}")
    pkg = package_name(attr.get("package"))
    if pkg:
        bits.append(f"package {pkg}")
    if attr.get("depth") is not None:
        bits.append(f"dependency depth {attr['depth']}")
    path = attr.get("dependency_path") or []
    if len(path) > 1:
        bits.append("via " + " > ".join(package_name(p) or str(p) for p in path))
    if bits:
        return "from: " + " · ".join(bits)
    if a.get("subclass") == "undeclared":
        return "from: nothing in the signed image (in no layer, owned by no package)"
    return ""


def place(a: dict) -> str:
    bits = []
    pod = a.get("pod") or a.get("container")
    if pod:
        bits.append(f"pod {pod}")
    chain = [x for x in ((a.get("attribution") or {}).get("process_chain") or []) if x]
    if chain:
        bits.append("process " + " > ".join(os.path.basename(str(x)) for x in chain))
    if a.get("chain_id"):
        bits.append(f"incident {a['chain_id']}")
    return "where: " + " · ".join(bits) if bits else ""


def wrap(text: str, width: int) -> list[str]:
    return textwrap.wrap(text, width=max(40, width - len(INDENT)), subsequent_indent="  ") or [""]


def card(a: dict, layers: Layers, colour: bool = False, width: int = 100, same_incident: bool = False) -> list[str]:
    """The lines shown for one alert (Low records: see low_line)."""
    when = clock(a.get("time"))
    if a.get("class") == "trust":
        reasons = ", ".join(TRUST_REASONS.get(r, r) for r in (a.get("trust_reason") or [])) or "trust check failed"
        lines = [f"{when}  " + paint(f"{'TRUST':<8}    ", "trust", colour) + f"Trust withdrawn: {reasons}"]
        body = [str(a.get("violated_clause") or ""), provenance(a, layers)]
        latency, state = a.get("latency_s"), str(a.get("runtime_state") or "").upper()
        tail = []
        if isinstance(latency, (int, float)):
            tail.append(f"raised {latency:.1f} s after the change")
        if state:
            tail.append(f"the pod still runs as {state}" if state == "CONFORMING" else f"runtime state {state}")
        body.append(" · ".join(tail))
    else:
        bucket = str(a.get("bucket") or "low").lower()
        lines = [f"{when}  " + paint(f"{bucket.upper():<8} {a.get('score', ''):>3}", bucket, colour)
                 + f"  {title_of(a)}" + ("   (same incident)" if same_incident else "")]
        path, detail = clause_parts(a)
        body = [f"{path}: {detail}" if path else detail, provenance(a, layers), place(a)]
    for text in body:
        if text:
            lines += [INDENT + line for line in wrap(text, width)]
    return lines


def low_line(a: dict, colour: bool = False) -> str:
    path, detail = clause_parts(a)
    what = f"{path}: {detail}" if path else detail
    return paint(f"{clock(a.get('time'))}  · logged, not an alert (Low {a.get('score', '')}): {what}", "low", colour)


def header(source: str, replay: bool, colour: bool, width: int) -> list[str]:
    if replay:
        top = paint("PROVBIND · REPLAY of a recorded run, not live", "trust", colour) + f" · {source}"
    else:
        top = paint("PROVBIND · live alerts", "head", colour) + f" · {source}"
    key = "Critical / High / Medium are alerts · a dim line is logged, not an alert · same incident = same chain"
    return [top, paint(key, "dim", colour), "-" * min(width, 100)]


class Screen:
    """Prints alerts as they arrive, marking alerts that continue the previous alert's incident."""

    def __init__(self, layers: Layers, colour: bool, width: int, show_low: bool, out=None):
        self.layers, self.colour, self.width, self.show_low, self._out = layers, colour, width, show_low, out
        self.last_chain = None

    @property
    def out(self):
        return self._out or sys.stdout

    def show(self, a: dict) -> None:
        if not isinstance(a, dict):
            return
        if a.get("class") != "trust" and str(a.get("bucket") or "low").lower() == "low":
            if self.show_low:
                print(low_line(a, self.colour), file=self.out, flush=True)
            return
        chain = a.get("chain_id")
        same = bool(chain) and chain == self.last_chain
        self.last_chain = chain
        print("", file=self.out)
        for line in card(a, self.layers, self.colour, self.width, same):
            print(line, file=self.out, flush=True)


def parse(line: str) -> dict | None:
    try:
        a = json.loads(line)
    except ValueError:
        return None
    return a if isinstance(a, dict) else None


def read_alerts(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [a for a in map(parse, lines) if a]


def seconds(a: dict) -> float | None:
    try:
        return datetime.fromisoformat(str(a.get("time")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def bursts(alerts: list[dict], gap_s: float = 8.0) -> list[list[dict]]:
    """Split a recorded run where more than gap_s seconds pass between two alerts (one scenario each)."""
    groups: list[list[dict]] = []
    prev = None
    for a in alerts:
        t = seconds(a)
        if not groups or (t is not None and prev is not None and t - prev > gap_s):
            groups.append([])
        groups[-1].append(a)
        prev = t if t is not None else prev
    return groups


def replaced(path: Path, inode: int) -> bool:
    """True when the file at path is gone or is another file (each live-demo.sh run starts a fresh run folder)."""
    try:
        return os.stat(path).st_ino != inode
    except OSError:
        return True


def follow(run: Path, screen: Screen, keep_going: bool, poll: float = 0.5, on_new_run=None) -> None:
    """Show run/alerts.jsonl as it grows. When the run folder is replaced (each `make live-demo` starts
    a fresh one), call on_new_run() and go on with the new folder's alerts."""
    path = run / "alerts.jsonl"
    first = True
    while True:
        while not run.exists():
            if not keep_going:
                print(f"no alerts yet ({path})", file=sys.stderr)
                return
            time.sleep(poll)
        run_inode = os.stat(run).st_ino
        if not first:
            screen.last_chain = None
            if on_new_run:
                on_new_run()
        first = False
        new_folder = False
        while not path.exists():
            if not keep_going:
                print(f"no alerts yet ({path})", file=sys.stderr)
                return
            if replaced(run, run_inode):
                new_folder = True
                break
            time.sleep(poll)
        if new_folder:
            continue
        buf = ""
        with open(path, encoding="utf-8") as f:
            inode = os.fstat(f.fileno()).st_ino
            while True:
                chunk = f.read(65536)
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for line in lines:
                        a = parse(line) if line.strip() else None
                        if a:
                            screen.show(a)
                    continue
                if not keep_going:
                    return
                if replaced(path, inode) or replaced(run, run_inode):
                    break
                time.sleep(poll)


def replay(alerts: list[dict], screen: Screen, step: bool, speed: float, max_gap: float,
           burst_gap: float, colour: bool) -> None:
    groups = bursts(alerts, burst_gap)
    for i, group in enumerate(groups):
        if step:
            try:
                input(paint(f"[replay] Enter: next scenario ({i + 1} of {len(groups)})", "dim", colour))
            except EOFError:
                pass
        prev = None
        for a in group:
            t = seconds(a)
            if not step and prev is not None and t is not None:
                time.sleep(min(max(t - prev, 0.0), max_gap) / max(speed, 0.01))
            elif step and prev is not None:
                time.sleep(0.4)
            prev = t if t is not None else prev
            screen.show(a)
        if not step and i + 1 < len(groups):
            time.sleep(min(burst_gap, max_gap) / max(speed, 0.01))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.demo_view", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"),
                    help="run folder to show (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--follow", action="store_true", help="keep showing new alerts (the live screen)")
    ap.add_argument("--replay", metavar="ALERTS_JSONL", help="show a recorded alerts.jsonl instead (plan B)")
    ap.add_argument("--step", action="store_true", help="replay: one scenario per Enter")
    ap.add_argument("--speed", type=float, default=1.0, help="replay: speed-up of the recorded timing (default 1)")
    ap.add_argument("--max-gap", type=float, default=3.0, help="replay: longest pause between alerts, in seconds")
    ap.add_argument("--burst-gap", type=float, default=8.0, help="replay: a gap longer than this starts a new scenario")
    ap.add_argument("--hide-low", action="store_true", help="leave out the dim 'logged, not an alert' lines")
    ap.add_argument("--no-color", action="store_true", help="plain text")
    args = ap.parse_args(argv)
    colour = sys.stdout.isatty() and not args.no_color
    width = shutil.get_terminal_size((100, 30)).columns
    if args.replay:
        path = Path(args.replay)
        screen = Screen(Layers(path.parent), colour, width, not args.hide_low)
        for line in header(str(path), True, colour, width):
            print(line)
        replay(read_alerts(path), screen, args.step, args.speed, args.max_gap, args.burst_gap, colour)
        return 0
    run = Path(args.run)
    screen = Screen(Layers(run), colour, width, not args.hide_low)

    def start(clear: bool) -> None:
        if clear and colour:
            print("\033[2J\033[H", end="")            # a fresh screen for a fresh run
        elif clear:
            print("\n" + "=" * min(width, 100))
        for line in header(f"run {run}", False, colour, width):
            print(line, flush=True)
        screen.layers = Layers(run)                      # the new folder's envelopes

    start(False)
    follow(run, screen, args.follow, on_new_run=lambda: start(True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
