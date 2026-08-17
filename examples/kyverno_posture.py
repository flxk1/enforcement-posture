# SPDX-License-Identifier: MIT
"""Describe a Kyverno deployment's enforcement posture.

The second foreign engine, chosen because it is structurally unlike OPA. OPA's
posture is one configuration document. Kyverno's is a *set of policy objects*,
each carrying its own enforcement settings, whose cardinality changes as policies
are added and removed. If `Posture` only fits engines shaped like a config file,
this is where it shows.

Fields per Kyverno's documented ClusterPolicy settings:
    validationFailureAction   Enforce | Audit   (block, or record in a report)
    failurePolicy             Fail | Ignore     (API-server behaviour if the webhook fails)
    webhookTimeoutSeconds     1..30, default 10
    background                scan existing resources
    PolicyException           a carve-out object; escape hatches as first-class objects
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from enforcement_posture import Control, Posture, compare, Change

CLUSTER = {
    "policies": [
        {"name": "require-labels", "validationFailureAction": "Enforce",
         "failurePolicy": "Fail", "webhookTimeoutSeconds": 10, "background": True},
        {"name": "disallow-latest-tag", "validationFailureAction": "Enforce",
         "failurePolicy": "Fail", "webhookTimeoutSeconds": 10, "background": True},
    ],
    "exceptions": [],
}

ACTION_ORDER = {"validationFailureAction": ["Audit", "Enforce"]}      # Audit records; Enforce blocks
FAILURE_ORDER = {"failurePolicy": ["Ignore", "Fail"]}                 # Ignore admits on webhook failure
DIRECTIONS = {"webhookTimeoutSeconds": "higher-is-stronger"}          # more time = fewer timeouts admitted


def posture_of(cluster, *, effective_from="2026-03-01T00:00:00Z", per_policy=False):
    """Two ways to model the same cluster.

    per_policy=True names a control per policy — faithful, and the control SET
    changes whenever a policy is added or removed. per_policy=False aggregates to
    a fixed set of controls whose values summarise the fleet.
    """
    pol = cluster["policies"]
    if per_policy:
        controls = []
        for p in pol:
            controls.append(Control(f"policy.{p['name']}.action", True, p["validationFailureAction"]))
            controls.append(Control(f"policy.{p['name']}.failurePolicy", True, p["failurePolicy"]))
        controls.append(Control("policy_exceptions", bool(cluster["exceptions"]),
                                weakens_when_enabled=True))
        return Posture("kyverno", tuple(controls), effective_from)

    weakest_action = "Audit" if any(p["validationFailureAction"] == "Audit" for p in pol) else "Enforce"
    weakest_failure = "Ignore" if any(p["failurePolicy"] == "Ignore" for p in pol) else "Fail"
    return Posture("kyverno", (
        Control("validationFailureAction", True, weakest_action),   # strictest-wins reported as weakest-present
        Control("failurePolicy", True, weakest_failure),
        Control("background", all(p["background"] for p in pol)),
        Control("webhookTimeoutSeconds", True,
                quantity=float(min(p["webhookTimeoutSeconds"] for p in pol))),
        # An exception is an EXEMPTION: its presence weakens. Without the flag the
        # package read a newly granted exception as a hardening.
        Control("policy_exceptions", bool(cluster["exceptions"]), weakens_when_enabled=True),
    ), effective_from)


import copy
ORDERS = dict(mode_order={**ACTION_ORDER, **FAILURE_ORDER}, quantity_order=DIRECTIONS)

print("A. one policy switched Enforce -> Audit  (a real weakening)")
relaxed = copy.deepcopy(CLUSTER); relaxed["policies"][0]["validationFailureAction"] = "Audit"
for label, per in (("per-policy controls", True), ("aggregated controls", False)):
    a, b = posture_of(CLUSTER, per_policy=per), posture_of(relaxed, per_policy=per)
    print(f"   {label:22} {compare(a, b, **({} if per else ORDERS)).value}")
print("   per-policy needs its own mode_order keyed by every policy name; aggregated does not.\n")

print("B. a THIRD policy added, nothing else changed")
added = copy.deepcopy(CLUSTER)
added["policies"].append({"name": "restrict-caps", "validationFailureAction": "Enforce",
                          "failurePolicy": "Fail", "webhookTimeoutSeconds": 10, "background": True})
for label, per in (("per-policy controls", True), ("aggregated controls", False)):
    a, b = posture_of(CLUSTER, per_policy=per), posture_of(added, per_policy=per)
    print(f"   {label:22} {compare(a, b, **({} if per else ORDERS)).value}")
print("   Per-policy modelling makes every routine policy addition INCOMPARABLE.\n")

print("C. a PolicyException added  (an escape hatch, aggregated)")
excepted = copy.deepcopy(CLUSTER); excepted["exceptions"] = [{"name": "allow-legacy-ns"}]
print("   ", compare(posture_of(CLUSTER, per_policy=False),
                     posture_of(excepted, per_policy=False), **ORDERS).value,
      "<- correct once the control is marked weakens_when_enabled (added in 0.5.0)")
