# Changelog

## 0.1.0 — 2026-08-15

Initial draft. The enforcement-posture predicate: a DSSE-wrapped in-toto Statement binding an
evidence window to the enforcement configuration in force across it, with a partial order over
postures (`compare` → unchanged / hardened / weakened / **incomparable**) and a fail-closed
coverage verdict (`coverage` → covered / **split** / **uncovered**) that hands back segments
rather than collapsing a window whose regime changed. Composes on the in-toto DSSE envelope,
RFC 8785 and Ed25519 — all injected, none bundled.
