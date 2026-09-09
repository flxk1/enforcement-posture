# Describing an engine that is not ours

## Describing an engine that is not ours

`examples/opa_posture.py` maps an Open Policy Agent runtime configuration — the response shape of
OPA's `GET /v1/config` — onto a `Posture`, and compares two of them.

This exists because until now the package had described exactly one engine, and that engine and
the package share an author. The test found a real defect: OPA's controls include **quantities** (bundle
poll intervals, decision-log report delays), which `Control` could not express, and a poll interval
moving from 120 s to 86400 s — a day-stale policy, unambiguously a weakening — compared as
`UNCHANGED`. `Control.quantity` and `quantity_order` exist because of that run.

The whole OPA configuration now maps with no further change to the package.

`examples/kyverno_posture.py` does the same for Kyverno, chosen because it is structurally
unlike OPA: its posture is a *set of policy objects* of changing cardinality rather than one
config document. Two findings. Modelling one control per policy makes every routine policy
addition `INCOMPARABLE` — aggregate to a fixed control set whose values summarise the fleet
instead. And a `PolicyException` exposed the polarity gap above: granting an escape hatch was
read as a hardening.
