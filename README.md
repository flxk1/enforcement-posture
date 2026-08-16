# enforcement-posture

Binds a body of evidence to the enforcement controls that were in force while it was recorded, as
a DSSE-wrapped in-toto Statement verifiable offline. Also measures time spent below an intended
baseline.

Enforcement engines ship escape hatches — permissive flags, advisory-instead-of-hard modes, opt-in
strict tiers. The effective posture is the product of all of them and is usually unsigned and
unreported, so an audit log arrives with no statement of the regime that produced it.

## Install

```bash
pip install .
```

Stdlib-only core; FOSS primitives are injected, not bundled. The example needs
`pip install ".[recommended]"` (`cryptography`, `rfc8785`). Tests: `pip install ".[test]"`.

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

strict = Posture("rvnd",
    (Control("folder_allowlist", True), Control("host_divergence", True, "hard-fail")),
    "2026-03-01T00:00:00Z", "2026-03-15T00:00:00Z")
relaxed = Posture("rvnd",
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
    return Posture("rvnd",
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
| `attest(posture, window, …)` | DSSE envelope wrapping an in-toto Statement |
| `verify(envelope, …)` | `Report(ok, findings, posture, window, algorithm)` |
| `compare(a, b, mode_order=None)` | `UNCHANGED` · `HARDENED` · `WEAKENED` · `INCOMPARABLE` |
| `coverage(window, postures, …)` | `COVERED` · `SPLIT` · `UNCOVERED`, plus segments and gaps |
| `exposure(baseline, timeline, since=, until=, …)` | at-or-above / weakened / indeterminate seconds, plus episodes |
| `posture_id(posture, …)` | `sha256:…` over the controls, excluding the interval |

## Semantics

- **`compare` is a partial order, not a score.** A different engine, a differing control set, a
  mode change with no supplied `mode_order`, or a change that both hardens and weakens returns
  `INCOMPARABLE`.
- **`coverage` returns `SPLIT` with segments** rather than collapsing a window whose regime
  changed. There is no single "effective posture" for such a window.
- **`UNCOVERED` outranks `SPLIT`.** Any sub-interval without an attested posture makes the whole
  window uncovered.
- **`posture_id` excludes the interval**, so re-attesting an unchanged posture after a restart
  reads as `covered`, not as a split.
- **`algorithm` is recorded inside the signed payload** (`predicate.signing.algorithm`), not beside
  `keyid`. DSSE's PAE covers only payload type and payload, so an algorithm in the signature object
  is unauthenticated and strippable. Omitting it is back-compatible; `Report.algorithm_stated` is
  then `False`.
- No clock: `since` / `until` are explicit, so an open-ended posture closes at a named horizon.

## Limitations

- **Single signature** per envelope; threshold and multi-sig are not modelled.
- **You supply canonicalisation and keys.** Pass `rfc8785.dumps` and an Ed25519 `sign`/`verify_sig`.
  Migrating to a post-quantum scheme is a caller change.
- **It attests a claim; it does not observe the engine.** The posture recorded is the one the
  attesting process asserts. It makes an operator's claims checkable and non-repudiable — it does
  not independently measure what the engine did.
- **Mode orders are per-caller.** There is no universal ranking of mode names.
- It does not judge adequacy. `verify` locates structural and cryptographic defects only.

## Prior art

Composed on the in-toto **DSSE** envelope and Statement v1, **RFC 8785** canonical JSON and
**Ed25519**; interoperates with the DSSE/Sigstore ecosystem. Incumbents attest *artifacts*
(in-toto/SLSA provenance) or *distributed policy* (OPA bundle signing). Neither attests the
effective runtime posture of a running engine bound to the evidence window it produced.

```
PRIOR-ART:
  incumbent(s):      in-toto/SLSA · DSSE · OPA bundle signing · RFC 8785 · cryptography · Sigstore
  distinctive layer: runtime enforcement posture bound to an evidence window; posture as a partial
                     order with INCOMPARABLE; fail-closed coverage returning SPLIT/UNCOVERED
  decision:          build-distinctive (composes on the above; owns the posture predicate)
```

Relevant to EU AI Act (Reg. 2024/1689) Art. 12.

## License

MIT. See `LICENSE`. Copyright 2026 flxk1.
