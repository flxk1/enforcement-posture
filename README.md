# enforcement-posture

Binds evidence to the enforcement controls in force while it was recorded, as a DSSE-wrapped in-toto Statement; measures time below a baseline posture.

## Problem

Evidence is recorded, but not which controls were active at the time. Binds evidence to the enforcement controls in force, measures time below baseline.

## Install

`pip install "enforcement-posture[recommended] @ git+https://github.com/flxk1/enforcement-posture"`

## Usage

```python
envelope = attest(strict, window, canonicalize=dumps, sign=sign, algorithm="ed25519")
coverage(window, [strict, relaxed], canonicalize=dumps).status.value
```

## Example

```
in : compare(Posture("opa", (Control("deny-egress", True),), "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z"),
             Posture("opa", (Control("deny-egress", False),), "2026-03-02T00:00:00Z"))
out: Change.WEAKENED
```

## Interface

- `Posture(engine, controls, effective_from, effective_to=None)`, `Control(name, enabled, mode=None, weakens_when_enabled=False, quantity=None)`, `EvidenceWindow(log_id, start, end, digest)`
- `attest(posture, window, …)` -> DSSE envelope; `verify(envelope, …)` -> `Report(ok, findings, posture, window, algorithm)`
- `compare(a, b, …)` -> UNCHANGED, HARDENED, WEAKENED, INCOMPARABLE (partial order)
- `coverage(window, postures, …)` -> COVERED, SPLIT, UNCOVERED
- `exposure(baseline, timeline, …)` -> at-or-above/weakened/indeterminate seconds, episodes

## Family

Assurance artifact, pillar "enforcement state" of [governance-certification](https://github.com/flxk1/governance-certification). Consumes: DSSE, in-toto Statement v1, RFC 8785, Ed25519 (injected). `examples/`: OPA, Kyverno. Docs: [docs/](docs/).

## Status

0.5.1 · 63 tests · 22 conformance vectors · Python ≥ 3.10

## License

MIT — [LICENSES/MIT.txt](LICENSES/MIT.txt)
