# Changelog

## 0.3.0 — 2026-08-15

Record the signature scheme **inside the signed payload** (`predicate.signing.algorithm`) rather
than beside `keyid`, where DSSE's PAE would leave it unauthenticated and strippable. Evidence held
under AI Act Art. 12's ten-year provider retention may be re-checked after the signing scheme has
been broken, and retroactive forgeability makes an authentic record of *what signed it* load-bearing.
`Report.algorithm` / `.algorithm_stated` surface it. Fully back-compatible: an envelope without it
verifies as before and is simply reported as less durable — never a finding.

## 0.2.0 — 2026-08-15

`exposure` — measure time spent below an intended enforcement baseline, computed from the same
attestations `attest` produces (a posture change *is* an escape hatch opening or closing). Time
splits three ways and the third is the honest one: time under a posture INCOMPARABLE to the
baseline, and time with no attestation at all, is **indeterminate** — never clean. Weakening
episodes name the controls that were off. No clock is read; `since`/`until` are explicit.

## 0.1.0 — 2026-08-15

Initial draft. The enforcement-posture predicate: a DSSE-wrapped in-toto Statement binding an
evidence window to the enforcement configuration in force across it, with a partial order over
postures (`compare` → unchanged / hardened / weakened / **incomparable**) and a fail-closed
coverage verdict (`coverage` → covered / **split** / **uncovered**) that hands back segments
rather than collapsing a window whose regime changed. Composes on the in-toto DSSE envelope,
RFC 8785 and Ed25519 — all injected, none bundled.
