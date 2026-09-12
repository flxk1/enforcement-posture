# Usage and API


Binds a body of evidence to the enforcement controls that were in force while it was recorded, as
a DSSE-wrapped in-toto Statement verifiable offline. Also measures time spent below an intended
baseline.

Enforcement engines ship escape hatches — permissive flags, advisory-instead-of-hard modes, opt-in
strict tiers. The effective posture is the product of all of them and is usually unsigned and
unreported, so an audit log arrives with no statement of the regime that produced it.

## Install

```bash
pip install "enforcement-posture[recommended] @ git+https://github.com/flxk1/enforcement-posture"
```

Stdlib-only core; FOSS primitives are injected, not bundled. The `recommended` extra pulls
`cryptography` and `rfc8785`, which the examples use — the core needs neither.

Distributed from this repository; there is no package-index release. Tests:
`pip install ".[test]"` from a clone.

## Usage

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rfc8785 import dumps
from enforcement_posture import Control, Posture, EvidenceWindow, attest, verify, coverage, compare

key = Ed25519PrivateKey.from_private_bytes(bytes(32))
pub = key.public_key()
sign = lambda b: key.sign(b)
def verify_sig(b, s):
    try: pub.verify(s, b); return True
    except Exception: return False

strict = Posture("engine",
    (Control("folder_allowlist", True), Control("host_divergence", True, "hard-fail")),
    "2026-03-01T00:00:00Z", "2026-03-15T00:00:00Z")
relaxed = Posture("engine",
    (Control("folder_allowlist", False), Control("host_divergence", True, "hard-fail")),
    "2026-03-15T00:00:00Z")
window = EvidenceWindow("chain:ws-1", "2026-03-01T00:00:00Z", "2026-03-31T00:00:00Z", "a" * 64)

envelope = attest(strict, window, canonicalize=dumps, sign=sign, algorithm="ed25519")
print(verify(envelope, canonicalize=dumps, verify_sig=verify_sig).ok)
print(compare(strict, relaxed).value)
print(coverage(window, [strict, relaxed], canonicalize=dumps).status.value)
```

```
True
weakened
split
```

A conformity projection over March cannot be rendered under one posture, so `coverage` returns
`split` and hands back the segments. Narrow the window to a single regime and it returns `covered`.

### Exposure

```python
from enforcement_posture import exposure

def at(frm, to=None, allowlist=True):
    return Posture("engine",
        (Control("folder_allowlist", allowlist), Control("host_divergence", True, "hard-fail")),
        frm, to)

intended = at("2026-03-01T00:00:00Z")          # what should have been enforcing
timeline = [                                    # what actually ran
    at("2026-03-01T00:00:00Z", "2026-03-11T00:00:00Z"),
    at("2026-03-11T00:00:00Z", "2026-03-21T00:00:00Z", allowlist=False),
    at("2026-03-21T00:00:00Z"),
]

result = exposure(intended, timeline,
                  since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=dumps)
print(round(result.clean_fraction, 3), result.weakened / 86400)
for e in result.episodes:
    print(e.start, e.end, e.controls_off)
```

```
0.667 10.0
2026-03-11T00:00:00Z 2026-03-21T00:00:00Z ('folder_allowlist',)
```

Time splits three ways: at-or-above baseline, weakened, and indeterminate. A posture that is
`INCOMPARABLE` to the baseline, and any interval with no attestation, counts as indeterminate.

## API

| call | returns |
|---|---|
| `Control(name, enabled, mode=None, weakens_when_enabled=False, quantity=None)` | one control; set the flag for exemptions |
| `attest(posture, window, …)` | DSSE envelope wrapping an in-toto Statement |
| `verify(envelope, …)` | `Report(ok, findings, posture, window, algorithm)` |
| `compare(a, b, mode_order=None, quantity_order=None)` | `UNCHANGED` · `HARDENED` · `WEAKENED` · `INCOMPARABLE` |
| `coverage(window, postures, …)` | `COVERED` · `SPLIT` · `UNCOVERED`, plus segments and gaps |
| `exposure(baseline, timeline, since=, until=, …)` | at-or-above / weakened / indeterminate seconds, plus episodes |
| `posture_id(posture, …)` | `sha256:…` over the controls, excluding the interval |
