#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 flxk1
"""Check an implementation against the published conformance vectors.

The vectors in ``vectors.json`` are the specification; this runner is one
implementation's gate against it. Any implementation, in any language, conforms
if it reproduces every ``expect`` from the corresponding ``input``.

Usage:
    python3 conformance/check_vectors.py [path-to-vectors.json]

Exit 0 = conformant · 1 = a vector failed · 2 = the suite could not be run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from enforcement_posture import (  # noqa: E402
    Control, Posture, EvidenceWindow, compare, coverage,
)


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _posture(d: dict) -> Posture:
    return Posture(
        d["engine"],
        tuple(Control(c["name"], c["enabled"], c.get("mode"), c.get("quantity")) for c in d["controls"]),
        d["effective_from"],
        d.get("effective_to"),
    )


def _run(call: str, inp: dict) -> str:
    if call == "compare":
        return compare(_posture(inp["before"]), _posture(inp["after"]),
                       mode_order=inp.get("mode_order"),
                       quantity_order=inp.get("quantity_order")).value
    if call == "coverage":
        w = inp["window"]
        return coverage(EvidenceWindow(w["log_id"], w["start"], w["end"], w["digest"]),
                        [_posture(p) for p in inp["postures"]],
                        canonicalize=_canon).status.value
    raise KeyError(f"unknown call {call!r}")


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "vectors.json"
    try:
        doc = json.loads(path.read_text())
    except Exception as exc:
        print(f"cannot read vectors: {exc}", file=sys.stderr)
        return 2
    vectors = doc.get("vectors") or []
    if not vectors:
        # A suite that runs zero vectors and exits 0 is the silent-skip failure.
        print("no vectors found — refusing to report conformance", file=sys.stderr)
        return 2

    failed = 0
    for v in vectors:
        try:
            got = _run(v["call"], v["input"])
        except Exception as exc:
            got = f"<raised {type(exc).__name__}: {exc}>"
        if got != v["expect"]:
            failed += 1
            print(f"FAIL {v['id']}\n     expected {v['expect']!r}, got {got!r}\n     {v['note']}")

    print(f"{len(vectors) - failed}/{len(vectors)} vectors conformant"
          f"{'' if not failed else f' — {failed} FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
