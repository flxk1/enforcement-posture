# SPDX-License-Identifier: MIT
"""Describe an Open Policy Agent deployment's enforcement posture.

A universality test, not a convenience. Until now this package had described exactly
one engine, written by the same author. OPA is foreign, widely
deployed, and exposes its effective runtime configuration at ``GET /v1/config`` —
which is exactly the thing `Posture` claims to model.

The rule of the test: if the package must change to describe OPA, its abstraction
is wrong. Run this file to see what fitted and what did not.
"""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from enforcement_posture import Control, Posture, compare, Change

# A realistic /v1/config response (shape per OPA's configuration reference).
OPA_CONFIG = {
    "labels": {"id": "opa-prod-1", "version": "1.4.0"},
    "bundles": {
        "authz": {
            "service": "control-plane",
            "persist": True,
            "polling": {"min_delay_seconds": 60, "max_delay_seconds": 120},
            "signing": {"keyid": "global_key", "scope": "write"},
        }
    },
    "keys": {"global_key": {"algorithm": "RS256"}},
    "decision_logs": {"service": "control-plane", "reporting": {"min_delay_seconds": 5}},
    "status": {"service": "control-plane"},
    "server": {"encoding": {"gzip": {"min_length": 1024}}},
}


def posture_from_opa_config(cfg: dict, *, effective_from: str) -> tuple[Posture, list[str]]:
    """Map an OPA runtime config onto a Posture. Returns the posture and the
    controls that could NOT be expressed."""
    controls: list[Control] = []
    unmapped: list[str] = []

    for name, b in cfg.get("bundles", {}).items():
        # on/off — fits Control.enabled exactly
        controls.append(Control(f"bundle.{name}.persist", bool(b.get("persist"))))
        # presence + a graded attribute — fits enabled + mode
        signing = b.get("signing") or {}
        alg = (cfg.get("keys", {}).get(signing.get("keyid"), {}) or {}).get("algorithm")
        controls.append(Control(f"bundle.{name}.signing", bool(signing), alg))
        # a QUANTITY — Control.quantity, added in 0.4.0 because of this test
        polling = b.get("polling") or {}
        if "max_delay_seconds" in polling:
            controls.append(Control(f"bundle.{name}.polling", True,
                                    quantity=float(polling["max_delay_seconds"])))

    controls.append(Control("decision_logs", bool(cfg.get("decision_logs"))))
    controls.append(Control("status_reporting", bool(cfg.get("status"))))
    delay = (cfg.get("decision_logs") or {}).get("reporting", {}).get("min_delay_seconds")
    if delay is not None:
        controls.append(Control("decision_logs.reporting", True, quantity=float(delay)))

    return Posture("opa", tuple(controls), effective_from), unmapped


p, unmapped = posture_from_opa_config(OPA_CONFIG, effective_from="2026-03-01T00:00:00Z")
print("controls expressed:")
for c in sorted(p.controls, key=lambda c: c.name):
    print(f"   {c.name:32} enabled={str(c.enabled):5} mode={c.mode}")

print("\nNOT expressible as a Control:", unmapped or "nothing — the whole config mapped")

# Does compare() see the weakenings an operator would care about?
relaxed = json.loads(json.dumps(OPA_CONFIG))
relaxed["bundles"]["authz"]["persist"] = False
q, _ = posture_from_opa_config(relaxed, effective_from="2026-03-02T00:00:00Z")
print("\npersist true -> false :", compare(p, q).value)

slower = json.loads(json.dumps(OPA_CONFIG))
slower["bundles"]["authz"]["polling"]["max_delay_seconds"] = 86400   # a day-stale bundle
r, _ = posture_from_opa_config(slower, effective_from="2026-03-02T00:00:00Z")
# Which way is stronger is domain knowledge, so the caller supplies it.
DIRECTIONS = {"bundle.authz.polling": "lower-is-stronger",      # a longer poll = staler policy
              "decision_logs.reporting": "lower-is-stronger"}
print("polling 120s -> 86400s, no direction given:", compare(p, r).value)
print("polling 120s -> 86400s, direction given   :",
      compare(p, r, quantity_order=DIRECTIONS).value)
