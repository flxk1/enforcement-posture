# enforcement-posture

An audit log, an evidence pack, a conformity report — none of it is interpretable unless you know
**which controls were actually enforcing while it was recorded.** Every real enforcement engine
ships escape hatches: a permissive flag for the awkward case, an advisory-instead-of-hard mode, an
opt-in strict tier nobody opted into. The effective posture is the product of all of them, and it
is typically unsigned, unjournalled and unreported. So evidence arrives with no statement of the
regime that produced it, and *"we had controls"* is exactly as unfalsifiable as *"a human approved
it."*

This is the missing statement: a signed, portable attestation binding **a body of evidence** to
**the enforcement configuration in force across it**, re-checkable offline by a third party from
the attestation and a public key alone.

It **computes and checks; it does not judge.** Whether a posture was *adequate* is the auditor's
call. What this settles is the prior question — what was on.

## The three refusals

Each of these is a place where a tool that returned a tidy answer would be inventing one.

| | |
|---|---|
| `compare` → **INCOMPARABLE** | Posture is a **partial order, not a score.** A different control set, a mode change with no caller-supplied order, or a change that both hardens *and* weakens returns INCOMPARABLE. There is no security number here to report. |
| `coverage` → **SPLIT** | A window spanning more than one posture hands back **the segments instead of collapsing them.** The type deliberately offers no single "effective posture" for a window whose regime changed mid-way. |
| `coverage` → **UNCOVERED** | Any sub-interval with no attested posture makes the whole window uncovered, **fail-closed** — and UNCOVERED outranks SPLIT. Silence is not consent. |

## Install

```bash
pip install .
```

Stdlib-only core — you inject the FOSS primitives (closed I/O): the test suite needs `pytest`
(`pip install ".[test]"`); the usage example needs `pip install ".[recommended]"` (`cryptography`
for Ed25519, `rfc8785` for canonical bytes).

## Usage

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rfc8785 import dumps  # RFC 8785 canonical JSON — the composed FOSS primitive
from enforcement_posture import (
    Control, Posture, EvidenceWindow, attest, verify, coverage, compare,
)

key = Ed25519PrivateKey.from_private_bytes(bytes(32))   # fixed seed for a reproducible demo
pub = key.public_key()
sign = lambda b: key.sign(b)
def verify_sig(b, s):
    try: pub.verify(s, b); return True
    except Exception: return False

# What was enforcing in the first half of March, and what changed on the 15th.
strict = Posture(
    engine="rvnd",
    controls=(Control("folder_allowlist", True), Control("host_divergence", True, "hard-fail")),
    effective_from="2026-03-01T00:00:00Z", effective_to="2026-03-15T00:00:00Z",
)
relaxed = Posture(
    engine="rvnd",
    controls=(Control("folder_allowlist", False), Control("host_divergence", True, "hard-fail")),
    effective_from="2026-03-15T00:00:00Z",
)
window = EvidenceWindow("chain:ws-1", "2026-03-01T00:00:00Z", "2026-03-31T00:00:00Z", "a" * 64)

# A third party re-checks the attestation offline, from the envelope + public key alone:
envelope = attest(strict, window, canonicalize=dumps, sign=sign)
print("attestation valid:", verify(envelope, canonicalize=dumps, verify_sig=verify_sig).ok)

# The control that got switched off is named, and its direction is not a guess:
print("march 15 change:", compare(strict, relaxed).value)

# And the month as a whole refuses to be reported as one regime:
result = coverage(window, [strict, relaxed], canonicalize=dumps)
print("window:", result.status.value, "in", len(result.segments), "segments")

# The same evidence, asked for only the first fortnight, is answerable:
fortnight = EvidenceWindow("chain:ws-1", "2026-03-01T00:00:00Z", "2026-03-14T00:00:00Z", "a" * 64)
print("fortnight:", coverage(fortnight, [strict, relaxed], canonicalize=dumps).status.value)
```

Output (behaviour proven by the test suite; the printed values are canonicaliser-independent):

```
attestation valid: True
march 15 change: weakened
window: split in 2 segments
fortnight: covered
```

The third line is the distinctive rule. A conformity projection over March cannot honestly be
rendered under one posture, so this refuses to produce one — while the fourth line shows the
evidence is not lost: **narrow the window to a period with one regime and it answers.** That is the
difference between an evidence pack that averages over a change in enforcement and one that
declines to.

## Exposure — the number nobody publishes

A posture change *is* an escape hatch being opened or closed, so a timeline of attestations is
already a record of how often enforcement ran below what was intended. `exposure` reads it out:

```python
from enforcement_posture import Control, Posture, exposure

intended = Posture(
    engine="rvnd",
    controls=(Control("folder_allowlist", True), Control("host_divergence", True, "hard-fail")),
    effective_from="2026-03-01T00:00:00Z",
)
def at(frm, to=None, allowlist=True):
    return Posture("rvnd",
                   (Control("folder_allowlist", allowlist), Control("host_divergence", True, "hard-fail")),
                   frm, to)

timeline = [                                          # what actually ran
    at("2026-03-01T00:00:00Z", "2026-03-11T00:00:00Z"),
    at("2026-03-11T00:00:00Z", "2026-03-21T00:00:00Z", allowlist=False),   # switched off for a sprint
    at("2026-03-21T00:00:00Z"),
]

result = exposure(intended, timeline,
                  since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=dumps)

print("ran fully enforcing:", round(result.clean_fraction, 3))
print("weakened for:", result.weakened / 86400, "days")
for episode in result.episodes:
    print("  ", episode.start, "→", episode.end, "off:", episode.controls_off)
```

```
ran fully enforcing: 0.667
weakened for: 10.0 days
   2026-03-11T00:00:00Z → 2026-03-21T00:00:00Z off: ('folder_allowlist',)
```

Time splits three ways, and **the third bucket is the honest one**: time under a posture
`INCOMPARABLE` to the baseline — and time with no attestation at all — is `indeterminate`, never
clean. Only time *provably* at or above baseline counts. An unranked mode downgrade lands in
`indeterminate` until you supply a `mode_order`, at which point the same timeline reports it as a
weakening; the tests pin both readings of the identical data.

No clock is read: `since` and `until` are explicit, so an open-ended posture is closed at the
horizon you name and the result is reproducible.

## What you attest

A `Posture` is the engine, its named `Control`s (`enabled`, plus an optional graded `mode`), and
the interval it was in force. `posture_id` content-addresses *what was enforcing* and deliberately
excludes the interval — so re-attesting an unchanged posture after a restart reads as `covered`,
not as a split.

The envelope is a DSSE-wrapped **in-toto Statement**: the subject is the evidence body and its
digest, the `predicateType` is `https://flxk1.github.io/enforcement-posture/v0.1`. It travels
through any DSSE/Sigstore-aware pipeline unchanged.

## Limitations

- **Single signature.** One DSSE signature per envelope in this version; threshold/multi-sig is
  not modelled.
- **You supply canonicalisation and the key.** Pass an RFC 8785 canonicaliser (`rfc8785.dumps`)
  and an Ed25519 `sign`/`verify_sig`; the library bundles neither, by design (closed I/O).
- **It attests a claim, it does not observe the engine.** The posture recorded is the one the
  attesting process asserts. This makes an operator's enforcement claims *checkable and
  non-repudiable*; it does not independently measure what the engine did. Pairing it with a second
  observation plane is the caller's job.
- **Mode orders are per-caller.** There is no built-in ranking of mode names, because there is no
  universal one. Supply `mode_order` or accept INCOMPARABLE.
- **It does not judge adequacy.** `verify` locates structural and cryptographic defects; whether
  the attested posture satisfied a legal duty is the auditor's call.

## Origin & prior art

Composed, not reinvented. Signing envelope = the in-toto **DSSE** standard (its PAE encoding);
statement shape = **in-toto Statement v1**; canonical bytes = **RFC 8785**; signatures =
**`cryptography`** (Ed25519). It interoperates with the DSSE/Sigstore ecosystem.

The incumbents attest *artifacts* (in-toto/SLSA provenance: what was built, from what) or
*distributed policy* (OPA bundle signing, which addresses bundle drift). Neither attests the
**effective runtime enforcement posture of a running engine, bound to the evidence window it
produced** — what was switched on while this log was being written. That is the layer this package
owns, together with the partial order that makes a weakening detectable without inventing a score,
and the coverage verdict that refuses to collapse a split window.

Grounded in EU AI Act (Reg. 2024/1689) Art. 12 — record-keeping obliged to yield records that are
*interpretable*, which an unstated posture denies.

```
PRIOR-ART:
  incumbent(s):      in-toto/SLSA (artifact + build provenance) · DSSE (signing envelope) ·
                     OPA bundle signing (policy-distribution drift) · RFC 8785 · cryptography ·
                     Sigstore/Rekor (transparency)
  distinctive layer: the runtime-posture semantic — effective enforcement configuration bound to
                     the evidence window it produced; posture as a partial order with
                     INCOMPARABLE first-class; fail-closed coverage that returns SPLIT/UNCOVERED
                     rather than one collapsed answer; offline re-verifiable
  decision:          build-distinctive (composes on the above; owns the enforcement-posture predicate)
```

## License

MIT. See `LICENSE`. Copyright 2026 flxk1.
