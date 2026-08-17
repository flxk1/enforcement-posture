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

Four semantics carry the design, and each is a refusal rather than a guess:

* :attr:`Control.weakens_when_enabled` marks an **exemption** — a policy
  exception, override or break-glass grant, whose presence weakens rather than
  strengthens. Without it the package assumed enabling always hardens, and a newly
  granted exception read as a hardening.
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
* :func:`exposure` books time it cannot rank against the baseline as
  **indeterminate** rather than clean — including time with no attestation at
  all. Only provably at-or-above-baseline time counts as enforcing.

Closed I/O: canonical bytes and signatures are **injected**, never bundled — pass
``rfc8785.dumps`` and an Ed25519 ``sign`` / ``verify_sig``. The core is stdlib-only.

Grounded in EU AI Act (Reg. 2024/1689) Art. 12 — record-keeping whose records are
required to be *interpretable*, which is precisely what an unstated posture denies.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

__version__ = "0.5.1"

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
    "Episode",
    "Exposure",
    "Finding",
    "Report",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "PAYLOAD_TYPE",
    "posture_id",
    "compare",
    "coverage",
    "exposure",
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
    #: A numeric setting — a poll interval, a timeout, a rate limit, a threshold.
    #: Quantities are compared only against a caller-supplied direction, because
    #: which way is stronger is domain knowledge: a *lower* bundle-poll delay is
    #: stronger, a *higher* key length is. Absent a direction, a change is
    #: INCOMPARABLE rather than silently unchanged.
    quantity: float | None = None
    #: Whether the control is an *exemption*: something whose presence WEAKENS
    #: enforcement rather than strengthening it — a policy exception, an override,
    #: a break-glass grant, a bypass allowlist. The package otherwise assumes
    #: enabling a control hardens, which is false for this whole family and made a
    #: newly added exception read as a HARDENING.
    #:
    #: Unlike ``mode_order`` and ``quantity_order``, which are orderings a
    #: deployment defines over its own value vocabulary, polarity is a fact about
    #: what the control *is*. It therefore travels inside the signed attestation,
    #: so two readers cannot disagree about whether a change was a weakening.
    weakens_when_enabled: bool = False
    # NOTE: appended, never inserted. Positional construction is part of the
    # public surface — adding a field mid-dataclass silently rebinds every
    # positional caller's arguments, which is how this was caught.

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "enabled": self.enabled}
        if self.mode is not None:
            out["mode"] = self.mode
        if self.quantity is not None:
            out["quantity"] = self.quantity
        if self.weakens_when_enabled:
            out["weakens_when_enabled"] = True
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
    quantity_order: Mapping[str, str] | None = None,
) -> Change:
    """Relate two postures, refusing to invent an ordering that does not exist.

    INCOMPARABLE is returned for a different engine, a differing control set, a
    mode change with no supplied order (or a mode outside it), a **quantity change
    with no supplied direction**, and — the case a scoring tool would paper over —
    a change that both hardens and weakens.

    ``mode_order`` maps a control name to its modes weakest-first, e.g.
    ``{"host_divergence": ["off", "advisory", "hard-fail"]}``.

    A control marked :attr:`Control.weakens_when_enabled` inverts the on/off
    reading. If the two postures disagree about that flag they are INCOMPARABLE —
    they are not describing the same control.

    ``quantity_order`` maps a control name to ``"lower-is-stronger"`` or
    ``"higher-is-stronger"``, e.g. ``{"bundle.authz.polling": "lower-is-stronger"}``
    — a longer poll interval means a staler policy. Without an entry a quantity
    change is INCOMPARABLE; it is never reported as unchanged.
    """
    if before.engine != after.engine:
        return Change.INCOMPARABLE
    if {c.name for c in before.controls} != {c.name for c in after.controls}:
        return Change.INCOMPARABLE

    hardened = weakened = False
    for old in before.controls:
        new = after.control(old.name)
        assert new is not None  # guarded by the set equality above

        if old.weakens_when_enabled != new.weakens_when_enabled:
            # The two records assert different things about what this control IS.
            # That is the same class of conflict as a differing control set, and
            # ranking it would mean picking one record's claim over the other's.
            return Change.INCOMPARABLE

        if old.enabled != new.enabled:
            # An exemption inverts the usual reading: switching one ON weakens.
            turning_on = new.enabled
            stronger = (not turning_on) if old.weakens_when_enabled else turning_on
            if stronger:
                hardened = True
            else:
                weakened = True

        if old.quantity != new.quantity:
            direction = (quantity_order or {}).get(old.name)
            if direction is None or old.quantity is None or new.quantity is None:
                return Change.INCOMPARABLE
            if direction == "higher-is-stronger":
                stronger = new.quantity > old.quantity
            elif direction == "lower-is-stronger":
                stronger = new.quantity < old.quantity
            else:
                return Change.INCOMPARABLE
            if stronger:
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
    quantity_order: Mapping[str, str] | None = None,
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
            transitions.append(compare(previous, p, mode_order=mode_order, quantity_order=quantity_order))
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
# exposure — how long enforcement ran below what was intended
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Episode:
    """A contiguous period spent below the baseline, and which controls were off.

    ``end`` of ``None`` never occurs — :func:`exposure` closes every episode at
    the explicit horizon rather than leaving one open, so a duration is always
    computable.
    """

    start: str
    end: str
    posture_id: str
    controls_off: tuple[str, ...]

    @property
    def seconds(self) -> float:
        return (_ts(self.end) - _ts(self.start)).total_seconds()


@dataclass(frozen=True)
class Exposure:
    """Time split three ways against an intended baseline.

    The third bucket is the honest one. Time under a posture that is
    :attr:`Change.INCOMPARABLE` to the baseline is **indeterminate**, not clean —
    and so is time with no attested posture at all. Fail-closed: only time
    provably at-or-above the baseline counts as clean.
    """

    at_or_above: float
    weakened: float
    indeterminate: float
    episodes: tuple[Episode, ...]

    @property
    def total(self) -> float:
        return self.at_or_above + self.weakened + self.indeterminate

    @property
    def clean_fraction(self) -> float:
        """Share of observed time provably at or above baseline. ``0.0`` if no time."""
        return self.at_or_above / self.total if self.total else 0.0


def exposure(
    baseline: Posture,
    timeline: Iterable[Posture],
    *,
    since: str,
    until: str,
    canonicalize: Canonicalize,
    mode_order: Mapping[str, Sequence[str]] | None = None,
    quantity_order: Mapping[str, str] | None = None,
) -> Exposure:
    """Measure time spent below an intended enforcement baseline.

    The question governance never answers — *what fraction of the time did this
    actually run with enforcement fully on?* — computed from the same attestations
    :func:`attest` produces. A posture change is an escape hatch being opened or
    closed, so a timeline of postures is a record of exactly that.

    ``since``/``until`` are explicit because this package reads no clock: an
    open-ended posture is closed at ``until``, and any part of the interval with
    no posture counts as indeterminate, never as clean.
    """
    lo, hi = _ts(since), _ts(until)
    if hi <= lo:
        return Exposure(0.0, 0.0, 0.0, ())

    clipped: list[tuple[datetime, datetime, Posture]] = []
    for p in timeline:
        p_start = _ts(p.effective_from)
        p_end = _ts(p.effective_to) if p.effective_to is not None else hi
        start, end = max(p_start, lo), min(p_end, hi)
        if start < end:
            clipped.append((start, end, p))
    clipped.sort(key=lambda t: (t[0], t[1]))

    at_or_above = weakened = indeterminate = 0.0
    episodes: list[Episode] = []
    cursor = lo

    for start, end, p in clipped:
        if start > cursor:  # unattested time is never clean
            indeterminate += (start - cursor).total_seconds()
        effective_start = max(start, cursor)
        if effective_start >= end:  # fully swallowed by an overlapping earlier posture
            continue
        span = (end - effective_start).total_seconds()

        verdict = compare(baseline, p, mode_order=mode_order, quantity_order=quantity_order)
        if verdict in (Change.UNCHANGED, Change.HARDENED):
            at_or_above += span
        elif verdict is Change.WEAKENED:
            weakened += span
            off = tuple(
                sorted(
                    c.name
                    for c in baseline.controls
                    if c.enabled and (p.control(c.name) is None or not p.control(c.name).enabled)
                )
            )
            episodes.append(Episode(_iso(effective_start), _iso(end), posture_id(p, canonicalize=canonicalize), off))
        else:  # INCOMPARABLE — not clean, not a weakening we can name
            indeterminate += span
        cursor = max(cursor, end)

    if cursor < hi:
        indeterminate += (hi - cursor).total_seconds()

    return Exposure(at_or_above, weakened, indeterminate, tuple(episodes))


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
    algorithm: str = "",
) -> dict[str, Any]:
    """Emit a DSSE-wrapped in-toto Statement binding ``window`` to ``posture``.

    ``algorithm`` names the signature scheme (``"ed25519"``, ``"ml-dsa-65"``, …)
    and is recorded **inside the signed payload**, not beside ``keyid`` in the
    signature object. That placement is deliberate: DSSE's PAE covers only the
    payload type and the payload, so an algorithm noted in the signature object
    is unauthenticated and can be stripped or altered without breaking
    verification. Evidence that must be re-checked years later, under a scheme
    that may by then be broken, needs an *authentic* record of what signed it.

    Omitting it is permitted and back-compatible — the envelope stays valid and
    :attr:`Report.algorithm` is then ``None``, meaning a future verifier has to
    learn the scheme out-of-band.
    """
    predicate: dict[str, Any] = {"posture": posture.to_dict(), "window": window.to_dict()}
    if algorithm:
        predicate["signing"] = {"algorithm": algorithm}
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": window.log_id, "digest": {"sha256": window.digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
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
    algorithm: str | None = None

    @property
    def algorithm_stated(self) -> bool:
        """Whether the envelope authentically records what signed it.

        An envelope without it is **valid, and less durable** — the same shape as
        an ungrounded rule: it makes no false claim, but a verifier re-checking it
        after a scheme migration must learn the algorithm from somewhere else.
        Reported, never a finding.
        """
        return self.algorithm is not None


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

    signing = statement["predicate"].get("signing") or {}
    algorithm = signing.get("algorithm") or None

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

    return Report(not findings, tuple(findings), posture, window, algorithm)
