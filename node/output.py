"""Append-only JSONL output: events.jsonl and detections.jsonl (Sprint Handoff §3.2).

One JSON object per line, written with a single call and flushed, so a reader tailing the file
sees whole lines as soon as possible. Readers must still wait for the newline of the last line.
Detection IDs continue from the highest `det-N` already in the file, so a restarted node never
reuses one.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_DET_ID = re.compile(rb'"id"\s*:\s*"det-(\d+)"')


def dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class JsonlWriter:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(self.path, "a", encoding="utf-8", newline="\n")
        self.written = 0

    def write(self, obj) -> None:
        self._f.write(dumps(obj) + "\n")
        self._f.flush()
        self.written += 1

    def close(self) -> None:
        self._f.close()


class EventWriter(JsonlWriter):
    """events.jsonl: each event's §4.3 record. Kinds without contract fields (cap, connect) are skipped."""

    def __call__(self, ev) -> None:
        rec = ev.record()
        if rec is not None:
            self.write(rec)


class DetectionWriter(JsonlWriter):
    """detections.jsonl: sets each detection's `id` (det-0001, det-0002, …) and appends it."""

    def __init__(self, path: str | os.PathLike):
        self.next_id = 1 + last_detection_number(path)
        super().__init__(path)

    def __call__(self, det: dict) -> None:
        det["id"] = f"det-{self.next_id:04d}"
        self.next_id += 1
        self.write(det)


def last_detection_number(path: str | os.PathLike) -> int:
    """The highest N of any det-N in an existing detections.jsonl, or 0."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return 0
    return max((int(m) for m in _DET_ID.findall(data)), default=0)


class Collector:
    """An in-memory sink with the same IDs as DetectionWriter, for replays and tests."""

    def __init__(self):
        self.items: list = []

    def __call__(self, item) -> None:
        if isinstance(item, dict) and "id" in item and item["id"] is None:
            item["id"] = f"det-{len(self.items) + 1:04d}"
        self.items.append(item)
