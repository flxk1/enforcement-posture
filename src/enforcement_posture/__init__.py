# SPDX-License-Identifier: MIT
# Copyright 2026 flxk1
"""enforcement-posture — bind a body of evidence to the controls that were in force.

An audit log, an evidence pack or a conformity report is uninterpretable unless you
know *which controls were actually enforcing* while it was recorded. Enforcement
engines ship escape hatches — a permissive flag, an advisory-instead-of-hard mode,
an opt-in strict tier — and the effective posture is the product of all of them.
That posture is typically unsigned, unjournalled and unreported, so evidence
arrives with no statement of the regime that produced it.

This package is the missing statement. It computes and checks; it does not judge.

Three semantics carry the design, and each is a refusal rather than a guess:

* :func:`compare` returns :attr:`Change.INCOMPARABLE` — for a different engine, a
  different control set, a mode change with no caller-supplied order, or a change
  that both hardens and weakens. Posture is a **partial order**, not a score, and
  a tool that returned a number here would be inventing one.
* :func:`coverage` returns :attr:`Cover.SPLIT` when a window spans more than one
  posture, and hands back the segments **instead of** collapsing them. A
  projection over a window whose regime changed mid-way must say so.
* :func:`coverage` returns :attr:`Cover.UNCOVERED`, fail-closed, when any
  sub-interval of the window has no attested posture. Silence is not consent, and
  UNCOVERED outranks SPLIT.

Closed I/O: canonical bytes and signatures are **injected**, never bundled — pass
``rfc8785.dumps`` and an Ed25519 ``sign`` / ``verify_sig``. The core is stdlib-only.

Grounded in EU AI Act (Reg. 2024/1689) Art. 12 — record-keeping whose records are
required to be *interpretable*, which is precisely what an unstated posture denies.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

__version__ = "0.1.0"

#: in-toto predicate type minted by this package
PREDICATE_TYPE = "https://flxk1.github.io/enforcement-posture/v0.1"
#: in-toto Statement envelope type this package emits
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
#: DSSE payload type for an in-toto statement
PAYLOAD_TYPE = "application/vnd.in-toto+json"

Canonicalize = Callable[[Any], bytes]
Sign = Callable[[bytes], bytes]
VerifySig = Callable[[bytes, bytes], bool]

__all__ = [
    "Control",
    "Posture",
    "EvidenceWindow",
    "Change",
    "Cover",
    "Segment",
    "Coverage",
    "Finding",
    "Report",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "PAYLOAD_TYPE",
    "posture_id",
    "compare",
    "coverage",
    "attest",
    "verify",
]


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #

def _ts(value: str) -> datetime:
    """Parse an RFC 3339 / ISO 8601 timestamp; naive input is read as UTC."""
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


# --------------------------------------------------------------------------- #
# the record
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Control:
    """One named enforcement control and the state it was in.

    ``mode`` carries a graded setting where a control is not merely on/off (say
    ``"advisory"`` vs ``"hard-fail"``). Modes are compared only against an order
    the caller supplies; otherwise a mode change is INCOMPARABLE, by design.
    """

    name: str
    enabled: bool
    mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "enabled": self.enabled}
        if self.mode is not None:
            out["mode"] = self.mode
        return out


@dataclass(frozen=True)
class Posture:
    """The effective enforcement configuration of one engine over one interval.

    ``effective_to`` of ``None`` means open-ended — still in force.
    """

    engine: str
    controls: tuple[Control, ...]
    effective_from: str
    effective_to: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "engine": self.engine,
            "controls": [c.to_dict() for c in sorted(self.controls, key=lambda c: c.name)],
            "effective_from": self.effective_from,
        }
        if self.effective_to is not None:
            out["effective_to"] = self.effective_to
        return out

    def control(self, name: str) -> Control | None:
        for c in self.controls:
            if c.name == name:
                return c
        return None


@dataclass(frozen=True)
class EvidenceWindow:
    """The body of evidence being bound: what it is, when it covers, its digest."""

    log_id: str
    start: str
    end: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"log_id": self.log_id, "start": self.start, "end": self.end}


def posture_id(posture: Posture, *, canonicalize: Canonicalize) -> str:
    """Content address of a posture: ``sha256:<hex>`` over its canonical form.

    Interval bounds are excluded — the identity of a posture is *what was
    enforcing*, so the same configuration in two disjoint periods shares an id and
    :func:`coverage` can recognise a window as un-SPLIT across a re-attestation.
    """
    body = {"engine": posture.engine, "controls": [c.to_dict() for c in sorted(posture.controls, key=lambda c: c.name)]}
    return "sha256:" + hashlib.sha256(canonicalize(body)).hexdigest()


# --------------------------------------------------------------------------- #
# the partial order
# --------------------------------------------------------------------------- #

class Change(str, Enum):
    """How one posture relates to another. Not a scale — a partial order."""

    UNCHANGED = "unchanged"
    HARDENED = "hardened"
    WEAKENED = "weakened"
    INCOMPARABLE = "incomparable"


def compare(
    before: Posture,
    after: Posture,
    *,
    mode_order: Mapping[str, Sequence[str]] | None = None,
) -> Change:
    """Relate two postures, refusing to invent an ordering that does not exist.

    INCOMPARABLE is returned for a different engine, a differing control set, a
    mode change with no supplied order (or a mode outside it), and — the case a
    scoring tool would paper over — a change that both hardens and weakens.

    ``mode_order`` maps a control name to its modes weakest-first, e.g.
    ``{"host_divergence": ["off", "advisory", "hard-fail"]}``.
    """
    if before.engine != after.engine:
        return Change.INCOMPARABLE
    if {c.name for c in before.controls} != {c.name for c in after.controls}:
        return Change.INCOMPARABLE

    hardened = weakened = False
    for old in before.controls:
        new = after.control(old.name)
        assert new is not None  # guarded by the set equality above

        if old.enabled != new.enabled:
            if new.enabled:
                hardened = True
            else:
                weakened = True

        if old.mode != new.mode:
            order = (mode_order or {}).get(old.name)
            if order is None or old.mode not in order or new.mode not in order:
                return Change.INCOMPARABLE
            if order.index(new.mode) > order.index(old.mode):
                hardened = True
            else:
                weakened = True

    if hardened and weakened:
        return Change.INCOMPARABLE
    if weakened:
        return Change.WEAKENED
    if hardened:
        return Change.HARDENED
    return Change.UNCHANGED


# --------------------------------------------------------------------------- #
# coverage of a window
# --------------------------------------------------------------------------- #

class Cover(str, Enum):
    """Whether a window's regime is known. UNCOVERED outranks SPLIT (fail-closed)."""

    COVERED = "covered"
    SPLIT = "split"
    UNCOVERED = "uncovered"


@dataclass(frozen=True)
class Segment:
    """A sub-interval of the window and the posture in force across it."""

    start: str
    end: str
    posture_id: str | None


@dataclass(frozen=True)
class Coverage:
    """The verdict over a window, with the segments that produced it.

    On SPLIT, ``segments`` is the answer — this type deliberately offers no
    "effective posture" for a window whose regime changed.
    """

    status: Cover
    segments: tuple[Segment, ...]
    gaps: tuple[Segment, ...]
    transitions: tuple[Change, ...]

    @property
    def ok(self) -> bool:
        return self.status is Cover.COVERED


def coverage(
    window: EvidenceWindow,
    postures: Iterable[Posture],
    *,
    canonicalize: Canonicalize,
    mode_order: Mapping[str, Sequence[str]] | None = None,
) -> Coverage:
    """Decide whether ``window`` sits under a single known posture.

    Overlapping attestations are an operator error the caller must see rather than
    have silently resolved, so an overlap is reported as INCOMPARABLE in
    ``transitions`` and never merged.
    """
    w_start, w_end = _ts(window.start), _ts(window.end)
    if w_end < w_start:
        return Coverage(Cover.UNCOVERED, (), (Segment(window.start, window.end, None),), ())

    clipped: list[tuple[datetime, datetime, Posture]] = []
    for p in postures:
        p_start = _ts(p.effective_from)
        p_end = _ts(p.effective_to) if p.effective_to is not None else None
        lo = max(p_start, w_start)
        hi = w_end if p_end is None else min(p_end, w_end)
        if lo < hi:
            clipped.append((lo, hi, p))
    clipped.sort(key=lambda t: (t[0], t[1]))

    segments: list[Segment] = []
    gaps: list[Segment] = []
    transitions: list[Change] = []
    cursor = w_start
    previous: Posture | None = None

    for lo, hi, p in clipped:
        if lo > cursor:
            gaps.append(Segment(_iso(cursor), _iso(lo), None))
        elif lo < cursor and previous is not None:
            transitions.append(Change.INCOMPARABLE)  # overlapping attestations
            previous = None
        if previous is not None:
            transitions.append(compare(previous, p, mode_order=mode_order))
        segments.append(Segment(_iso(max(lo, cursor)), _iso(hi), posture_id(p, canonicalize=canonicalize)))
        previous = p
        cursor = max(cursor, hi)

    if cursor < w_end:
        gaps.append(Segment(_iso(cursor), _iso(w_end), None))

    distinct = {s.posture_id for s in segments}
    if gaps:
        status = Cover.UNCOVERED
    elif len(distinct) > 1 or Change.INCOMPARABLE in transitions:
        status = Cover.SPLIT
    else:
        status = Cover.COVERED
    return Coverage(status, tuple(segments), tuple(gaps), tuple(transitions))


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# the attestation
# --------------------------------------------------------------------------- #

def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (in-toto DSSE v1)."""
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def attest(
    posture: Posture,
    window: EvidenceWindow,
    *,
    canonicalize: Canonicalize,
    sign: Sign,
    keyid: str = "",
) -> dict[str, Any]:
    """Emit a DSSE-wrapped in-toto Statement binding ``window`` to ``posture``."""
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": window.log_id, "digest": {"sha256": window.digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"posture": posture.to_dict(), "window": window.to_dict()},
    }
    payload = canonicalize(statement)
    signature = sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(signature).decode()}],
    }


@dataclass(frozen=True)
class Finding:
    """A located defect. ``code`` is stable; ``detail`` is for humans."""

    code: str
    detail: str = ""


@dataclass(frozen=True)
class Report:
    """The result of re-checking an attestation offline."""

    ok: bool
    findings: tuple[Finding, ...]
    posture: Posture | None = None
    window: EvidenceWindow | None = None


def verify(
    envelope: Mapping[str, Any],
    *,
    canonicalize: Canonicalize,
    verify_sig: VerifySig,
) -> Report:
    """Re-check an attestation from the envelope and a public key alone.

    Locates structural and cryptographic defects. Whether the attested posture was
    *adequate* is the auditor's call, not this function's.
    """
    findings: list[Finding] = []

    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return Report(False, (Finding("bad-envelope", f"payloadType {envelope.get('payloadType')!r}"),))
    signatures = envelope.get("signatures") or []
    if not signatures:
        return Report(False, (Finding("bad-envelope", "no signatures"),))
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        raw_sig = base64.b64decode(signatures[0]["sig"], validate=True)
    except Exception as exc:  # malformed base64 / missing key
        return Report(False, (Finding("bad-envelope", str(exc)),))

    if not verify_sig(_pae(PAYLOAD_TYPE, payload), raw_sig):
        findings.append(Finding("bad-signature", "signature does not verify over the PAE"))

    import json  # local: the core reads back only what it wrote

    try:
        statement = json.loads(payload)
    except Exception as exc:
        return Report(False, tuple(findings) + (Finding("malformed-predicate", str(exc)),))

    if statement.get("predicateType") != PREDICATE_TYPE:
        findings.append(Finding("unknown-predicate-type", str(statement.get("predicateType"))))
        return Report(False, tuple(findings))

    try:
        raw_posture = statement["predicate"]["posture"]
        raw_window = statement["predicate"]["window"]
        subject = statement["subject"][0]
        posture = Posture(
            engine=raw_posture["engine"],
            controls=tuple(
                Control(c["name"], bool(c["enabled"]), c.get("mode")) for c in raw_posture["controls"]
            ),
            effective_from=raw_posture["effective_from"],
            effective_to=raw_posture.get("effective_to"),
        )
        window = EvidenceWindow(
            log_id=raw_window["log_id"],
            start=raw_window["start"],
            end=raw_window["end"],
            digest=subject["digest"]["sha256"],
        )
    except Exception as exc:
        return Report(False, tuple(findings) + (Finding("malformed-predicate", str(exc)),))

    if not posture.controls:
        findings.append(Finding("empty-posture", "a posture asserting no controls attests nothing"))
    if canonicalize(statement) != payload:
        findings.append(Finding("non-canonical-payload", "payload is not the canonical form of its statement"))
    try:
        if _ts(posture.effective_to or window.end) < _ts(posture.effective_from):
            findings.append(Finding("interval-inverted", "effective_to precedes effective_from"))
        if _ts(window.end) < _ts(window.start):
            findings.append(Finding("interval-inverted", "window end precedes window start"))
    except ValueError as exc:
        findings.append(Finding("malformed-predicate", f"unparseable timestamp: {exc}"))

    return Report(not findings, tuple(findings), posture, window)
