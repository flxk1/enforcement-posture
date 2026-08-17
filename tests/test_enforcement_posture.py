# SPDX-License-Identifier: MIT
# Copyright 2026 flxk1
"""Tests for enforcement_posture. Runs under both `pytest` and
`python -m unittest discover -s tests`. Signatures use a real Ed25519 key via
`cryptography`; canonicalisation uses a deterministic in-test stub (production
passes `rfc8785.dumps`) — deliberately a *different* canonicaliser from the one
the README example uses, which is what makes the claim that behaviour is
canonicaliser-independent a tested one rather than an assertion.

Every refusal semantic (INCOMPARABLE / SPLIT / UNCOVERED) is pinned here."""

from __future__ import annotations

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from enforcement_posture import (  # noqa: E402
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    Change,
    Control,
    Cover,
    EvidenceWindow,
    Posture,
    attest,
    compare,
    coverage,
    exposure,
    posture_id,
    verify,
)


def canon(obj) -> bytes:
    """A deterministic canonicaliser. Production callers pass ``rfc8785.dumps``."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def posture(*, engine="rvnd", allowlist=True, divergence="advisory",
            frm="2026-01-01T00:00:00Z", to=None) -> Posture:
    return Posture(
        engine=engine,
        controls=(Control("folder_allowlist", allowlist), Control("host_divergence", True, divergence)),
        effective_from=frm,
        effective_to=to,
    )


WINDOW = EvidenceWindow("chain:ws-1", "2026-03-01T00:00:00Z", "2026-03-31T00:00:00Z", "a" * 64)
MODES = {"host_divergence": ["off", "advisory", "hard-fail"]}


class KeyMixin(unittest.TestCase):
    def setUp(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(bytes(32))
        pub = key.public_key()
        self.sign = key.sign

        def verify_sig(blob: bytes, sig: bytes) -> bool:
            try:
                pub.verify(sig, blob)
                return True
            except Exception:
                return False

        self.verify_sig = verify_sig

    def restate(self, envelope: dict, mutate) -> dict:
        """Decode a statement, apply ``mutate``, re-encode it into the envelope."""
        statement = json.loads(base64.b64decode(envelope["payload"]))
        mutate(statement)
        envelope["payload"] = base64.b64encode(canon(statement)).decode()
        return envelope


class TestPostureIdentity(unittest.TestCase):
    def test_stable_under_control_order(self):
        a = Posture("rvnd", (Control("x", True), Control("y", False)), "2026-01-01T00:00:00Z")
        b = Posture("rvnd", (Control("y", False), Control("x", True)), "2026-01-01T00:00:00Z")
        self.assertEqual(posture_id(a, canonicalize=canon), posture_id(b, canonicalize=canon))

    def test_ignores_interval_so_a_reattestation_is_not_a_split(self):
        early = posture(frm="2026-01-01T00:00:00Z", to="2026-02-01T00:00:00Z")
        later = posture(frm="2026-02-01T00:00:00Z")
        self.assertEqual(posture_id(early, canonicalize=canon), posture_id(later, canonicalize=canon))

    def test_changes_when_a_control_changes(self):
        self.assertNotEqual(
            posture_id(posture(), canonicalize=canon),
            posture_id(posture(allowlist=False), canonicalize=canon),
        )


class TestPartialOrder(unittest.TestCase):
    """The refusals are the point: posture is a partial order, not a score."""

    def test_disabling_a_control_is_a_weakening(self):
        self.assertIs(compare(posture(), posture(allowlist=False)), Change.WEAKENED)

    def test_enabling_a_control_is_a_hardening(self):
        self.assertIs(compare(posture(allowlist=False), posture()), Change.HARDENED)

    def test_identical_postures_are_unchanged(self):
        self.assertIs(compare(posture(), posture()), Change.UNCHANGED)

    def test_a_change_that_both_hardens_and_weakens_is_incomparable_not_a_score(self):
        before = posture(allowlist=True, divergence="off")
        after = posture(allowlist=False, divergence="hard-fail")
        self.assertIs(compare(before, after, mode_order=MODES), Change.INCOMPARABLE)

    def test_mode_change_without_a_supplied_order_is_incomparable(self):
        self.assertIs(
            compare(posture(divergence="advisory"), posture(divergence="hard-fail")),
            Change.INCOMPARABLE,
        )

    def test_mode_change_with_a_supplied_order_is_ranked(self):
        for new_mode, expected in (("hard-fail", Change.HARDENED), ("off", Change.WEAKENED)):
            with self.subTest(mode=new_mode):
                self.assertIs(
                    compare(posture(divergence="advisory"), posture(divergence=new_mode), mode_order=MODES),
                    expected,
                )

    def test_mode_outside_the_supplied_order_is_incomparable(self):
        self.assertIs(
            compare(posture(divergence="advisory"), posture(divergence="lenient"), mode_order=MODES),
            Change.INCOMPARABLE,
        )

    def test_differing_control_sets_are_incomparable(self):
        fewer = Posture("rvnd", (Control("folder_allowlist", True),), "2026-01-01T00:00:00Z")
        self.assertIs(compare(fewer, posture()), Change.INCOMPARABLE)

    def test_different_engines_are_incomparable(self):
        self.assertIs(compare(posture(), posture(engine="other")), Change.INCOMPARABLE)


class TestQuantities(unittest.TestCase):
    """Added in 0.4.0 after pointing the package at OPA — a foreign engine.

    The one engine described until now has boolean-and-mode controls, and the same
    author wrote both sides, so the abstraction fitted. OPA has quantities (poll intervals, report delays), and a bundle
    poll moving from 120s to 86400s means a day-stale policy — a real weakening
    that `compare` previously reported as UNCHANGED."""

    def q(self, value, name="poll"):
        return Posture("e", (Control(name, True, quantity=value),), "2026-01-01T00:00:00Z")

    def test_a_quantity_change_is_never_silently_unchanged(self):
        """The defect this fixes: silence reading as benign, in the package built
        to prevent exactly that."""
        result = compare(self.q(120), self.q(86400))
        self.assertIsNot(result, Change.UNCHANGED)
        self.assertIs(result, Change.INCOMPARABLE)

    def test_direction_is_caller_supplied_because_it_is_domain_knowledge(self):
        lower = {"poll": "lower-is-stronger"}    # a longer poll interval = staler policy
        higher = {"poll": "higher-is-stronger"}  # a longer key = stronger
        self.assertIs(compare(self.q(120), self.q(86400), quantity_order=lower), Change.WEAKENED)
        self.assertIs(compare(self.q(120), self.q(86400), quantity_order=higher), Change.HARDENED)

    def test_an_unrecognised_direction_is_incomparable(self):
        self.assertIs(compare(self.q(1), self.q(2), quantity_order={"poll": "bigger"}), Change.INCOMPARABLE)

    def test_a_quantity_appearing_or_vanishing_is_incomparable(self):
        none = Posture("e", (Control("poll", True),), "2026-01-01T00:00:00Z")
        self.assertIs(compare(none, self.q(60), quantity_order={"poll": "lower-is-stronger"}),
                      Change.INCOMPARABLE)

    def test_an_equal_quantity_is_unchanged(self):
        self.assertIs(compare(self.q(60), self.q(60)), Change.UNCHANGED)

    def test_quantity_participates_in_posture_identity(self):
        self.assertNotEqual(posture_id(self.q(60), canonicalize=canon),
                            posture_id(self.q(61), canonicalize=canon))

    def test_a_control_without_a_quantity_serialises_unchanged(self):
        """Back-compat: the field is omitted when absent, so 0.3.0 signatures hold."""
        self.assertEqual(Control("c", True).to_dict(), {"name": "c", "enabled": True})
        self.assertEqual(Control("c", True, quantity=5.0).to_dict(),
                         {"name": "c", "enabled": True, "quantity": 5.0})

    def test_quantity_and_enabled_moving_opposite_ways_is_incomparable(self):
        before = Posture("e", (Control("c", True, quantity=10),), "2026-01-01T00:00:00Z")
        after = Posture("e", (Control("c", False, quantity=5),), "2026-01-01T00:00:00Z")
        self.assertIs(compare(before, after, quantity_order={"c": "lower-is-stronger"}),
                      Change.INCOMPARABLE)


class TestExemptions(unittest.TestCase):
    """Added in 0.5.0 after describing Kyverno, whose escape hatches are objects.

    The package assumed enabling a control hardens. That is false for the whole
    exemption family — policy exceptions, overrides, break-glass grants, bypass
    allowlists — where presence weakens. A newly granted exception read as a
    HARDENING."""

    def p(self, on, exempt=True):
        return Posture("k", (Control("exceptions", on, weakens_when_enabled=exempt),),
                       "2026-01-01T00:00:00Z")

    def test_granting_an_exemption_weakens(self):
        self.assertIs(compare(self.p(False), self.p(True)), Change.WEAKENED)

    def test_revoking_an_exemption_hardens(self):
        self.assertIs(compare(self.p(True), self.p(False)), Change.HARDENED)

    def test_an_ordinary_control_is_unaffected(self):
        self.assertIs(compare(self.p(False, exempt=False), self.p(True, exempt=False)), Change.HARDENED)

    def test_polarity_travels_in_the_signed_record(self):
        """It is a fact about the control, not a reader's opinion, so two verifiers
        cannot disagree about whether a change was a weakening."""
        self.assertEqual(Control("c", True, weakens_when_enabled=True).to_dict(),
                         {"name": "c", "enabled": True, "weakens_when_enabled": True})

    def test_an_ordinary_control_serialises_unchanged(self):
        """Back-compat: the flag is omitted when false, so 0.4.0 signatures hold."""
        self.assertEqual(Control("c", True).to_dict(), {"name": "c", "enabled": True})

    def test_positional_field_order_is_part_of_the_contract(self):
        """weakens_when_enabled was first inserted BEFORE quantity, silently
        rebinding every positional caller's fourth argument. The keyword-using
        tests all passed; the conformance vectors, which construct positionally,
        caught it. New fields are appended, never inserted."""
        import inspect
        self.assertEqual(list(inspect.signature(Control).parameters),
                         ["name", "enabled", "mode", "quantity", "weakens_when_enabled"])
        c = Control("n", True, "m", 1.0)
        self.assertEqual((c.mode, c.quantity, c.weakens_when_enabled), ("m", 1.0, False))

    def test_polarity_participates_in_posture_identity(self):
        self.assertNotEqual(posture_id(self.p(True), canonicalize=canon),
                            posture_id(self.p(True, exempt=False), canonicalize=canon))


class TestPartialOrderProperties(unittest.TestCase):
    """Properties over the whole space, not examples.

    Example tests encode the author's assumptions and pass whenever the code
    matches them — every real defect in this package was found by something else.
    A polarity conflict made compare(a,b) and compare(b,a) BOTH return HARDENED,
    with 56 example tests green. These check the algebra instead."""

    MODES = {"c": ["off", "on", "strict"]}
    QTY = {"c": "lower-is-stronger"}
    INVERSE = {Change.HARDENED: Change.WEAKENED, Change.WEAKENED: Change.HARDENED,
               Change.UNCHANGED: Change.UNCHANGED, Change.INCOMPARABLE: Change.INCOMPARABLE}

    def controls(self):
        return [Control("c", en, md, q, w)
                for en in (True, False)
                for md in (None, "off", "on", "strict")
                for q in (None, 1.0, 2.0)
                for w in (False, True)]

    def posture(self, c):
        return Posture("e", (c,), "2026-01-01T00:00:00Z")

    def cmp(self, a, b):
        return compare(self.posture(a), self.posture(b),
                       mode_order=self.MODES, quantity_order=self.QTY)

    def test_antisymmetry_over_the_whole_space(self):
        """Reversing the arguments must reverse the direction. Exhaustive over
        every ordered pair of controls the type can express."""
        for a in self.controls():
            for b in self.controls():
                forward, reverse = self.cmp(a, b), self.cmp(b, a)
                if reverse is not self.INVERSE[forward]:
                    self.fail(f"antisymmetry broken: {a} -> {b} gave {forward.value}, "
                              f"reverse gave {reverse.value}")

    def test_reflexivity_over_the_whole_space(self):
        """Every control compared with itself is UNCHANGED — no exceptions."""
        for c in self.controls():
            self.assertIs(self.cmp(c, c), Change.UNCHANGED, f"{c} not unchanged against itself")

    def test_a_polarity_conflict_is_incomparable(self):
        """Two records asserting different things about what a control IS cannot be
        ranked; picking one record's claim over the other's is not a comparison."""
        exemption = Control("c", True, weakens_when_enabled=True)
        ordinary = Control("c", True, weakens_when_enabled=False)
        self.assertIs(self.cmp(exemption, ordinary), Change.INCOMPARABLE)

    def test_identity_is_at_least_as_strict_as_comparison(self):
        """If two postures share a posture_id they must compare UNCHANGED. The
        converse need not hold, but this direction must."""
        for a in self.controls():
            for b in self.controls():
                if posture_id(self.posture(a), canonicalize=canon) == \
                   posture_id(self.posture(b), canonicalize=canon):
                    self.assertIs(self.cmp(a, b), Change.UNCHANGED,
                                  f"same posture_id but {a} vs {b} did not compare unchanged")


class TestCoverage(unittest.TestCase):
    """UNCOVERED outranks SPLIT; both are fail-closed."""

    def test_a_window_under_one_posture_is_covered(self):
        result = coverage(WINDOW, [posture()], canonicalize=canon)
        self.assertIs(result.status, Cover.COVERED)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.segments), 1)
        self.assertFalse(result.gaps)

    def test_a_window_spanning_two_postures_is_split_and_hands_back_segments(self):
        first = posture(to="2026-03-15T00:00:00Z")
        second = posture(allowlist=False, frm="2026-03-15T00:00:00Z")
        result = coverage(WINDOW, [first, second], canonicalize=canon)
        self.assertIs(result.status, Cover.SPLIT)
        self.assertFalse(result.ok)
        self.assertEqual(len(result.segments), 2)
        self.assertEqual(result.transitions, (Change.WEAKENED,))

    def test_split_refuses_to_offer_one_effective_posture(self):
        result = coverage(
            WINDOW,
            [posture(to="2026-03-15T00:00:00Z"), posture(allowlist=False, frm="2026-03-15T00:00:00Z")],
            canonicalize=canon,
        )
        self.assertFalse(hasattr(result, "posture"))
        self.assertEqual(
            {s.posture_id for s in result.segments},
            {
                posture_id(posture(), canonicalize=canon),
                posture_id(posture(allowlist=False), canonicalize=canon),
            },
        )

    def test_a_gap_makes_the_window_uncovered_even_though_a_posture_exists(self):
        result = coverage(WINDOW, [posture(frm="2026-03-10T00:00:00Z")], canonicalize=canon)
        self.assertIs(result.status, Cover.UNCOVERED)
        self.assertEqual(result.gaps[0].start, "2026-03-01T00:00:00Z")
        self.assertEqual(result.gaps[0].end, "2026-03-10T00:00:00Z")

    def test_no_postures_at_all_is_uncovered_not_covered(self):
        result = coverage(WINDOW, [], canonicalize=canon)
        self.assertIs(result.status, Cover.UNCOVERED)
        self.assertTrue(result.gaps)

    def test_uncovered_outranks_split(self):
        first = posture(to="2026-03-10T00:00:00Z")
        third = posture(allowlist=False, frm="2026-03-20T00:00:00Z")
        self.assertIs(coverage(WINDOW, [first, third], canonicalize=canon).status, Cover.UNCOVERED)

    def test_re_attesting_the_same_posture_is_covered_not_split(self):
        first = posture(to="2026-03-15T00:00:00Z")
        same_again = posture(frm="2026-03-15T00:00:00Z")
        self.assertIs(coverage(WINDOW, [first, same_again], canonicalize=canon).status, Cover.COVERED)

    def test_overlapping_attestations_are_surfaced_never_merged(self):
        first = posture(to="2026-03-20T00:00:00Z")
        second = posture(allowlist=False, frm="2026-03-10T00:00:00Z")
        result = coverage(WINDOW, [first, second], canonicalize=canon)
        self.assertIs(result.status, Cover.SPLIT)
        self.assertIn(Change.INCOMPARABLE, result.transitions)

    def test_a_posture_entirely_outside_the_window_does_not_cover_it(self):
        stale = posture(frm="2025-01-01T00:00:00Z", to="2025-02-01T00:00:00Z")
        self.assertIs(coverage(WINDOW, [stale], canonicalize=canon).status, Cover.UNCOVERED)

    def test_inverted_window_is_uncovered(self):
        backwards = EvidenceWindow("chain:ws-1", "2026-03-31T00:00:00Z", "2026-03-01T00:00:00Z", "a" * 64)
        self.assertIs(coverage(backwards, [posture()], canonicalize=canon).status, Cover.UNCOVERED)


class TestExposure(unittest.TestCase):
    """How long did enforcement actually run below what was intended?

    The question governance never answers, computed from posture attestations.
    """

    DAY = 86400.0

    def test_a_month_fully_at_baseline_is_clean(self):
        result = exposure(
            posture(),
            [posture()],
            since="2026-03-01T00:00:00Z",
            until="2026-03-31T00:00:00Z",
            canonicalize=canon,
        )
        self.assertEqual(result.clean_fraction, 1.0)
        self.assertEqual(result.weakened, 0.0)
        self.assertEqual(result.episodes, ())

    def test_a_weakened_stretch_is_measured_and_the_controls_are_named(self):
        strict = posture(to="2026-03-11T00:00:00Z")
        relaxed = posture(allowlist=False, frm="2026-03-11T00:00:00Z", to="2026-03-21T00:00:00Z")
        restored = posture(frm="2026-03-21T00:00:00Z")
        result = exposure(
            posture(),
            [strict, relaxed, restored],
            since="2026-03-01T00:00:00Z",
            until="2026-03-31T00:00:00Z",
            canonicalize=canon,
        )
        self.assertEqual(result.weakened, 10 * self.DAY)
        self.assertEqual(result.at_or_above, 20 * self.DAY)
        self.assertEqual(result.indeterminate, 0.0)
        self.assertAlmostEqual(result.clean_fraction, 2 / 3)
        self.assertEqual(len(result.episodes), 1)
        self.assertEqual(result.episodes[0].controls_off, ("folder_allowlist",))
        self.assertEqual(result.episodes[0].seconds, 10 * self.DAY)

    def test_a_hardened_posture_counts_as_at_or_above(self):
        hardened = Posture(
            "rvnd",
            (Control("folder_allowlist", True), Control("host_divergence", True, "advisory"), Control("extra", True)),
            "2026-03-01T00:00:00Z",
        )
        # Same control set as the baseline is required for comparability, so compare
        # against a baseline that has the extra control switched off.
        base = Posture(
            "rvnd",
            (Control("folder_allowlist", True), Control("host_divergence", True, "advisory"), Control("extra", False)),
            "2026-03-01T00:00:00Z",
        )
        result = exposure(
            base, [hardened],
            since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon,
        )
        self.assertEqual(result.clean_fraction, 1.0)

    def test_unattested_time_is_indeterminate_never_clean(self):
        late = posture(frm="2026-03-11T00:00:00Z")
        result = exposure(
            posture(), [late],
            since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon,
        )
        self.assertEqual(result.indeterminate, 10 * self.DAY)
        self.assertAlmostEqual(result.clean_fraction, 2 / 3)

    def test_no_attestations_at_all_is_wholly_indeterminate(self):
        result = exposure(
            posture(), [],
            since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon,
        )
        self.assertEqual(result.clean_fraction, 0.0)
        self.assertEqual(result.indeterminate, 30 * self.DAY)

    def test_an_incomparable_posture_is_indeterminate_not_weakened(self):
        """A different control set cannot be scored against the baseline either way."""
        different = Posture("rvnd", (Control("something_else", True),), "2026-03-01T00:00:00Z")
        result = exposure(
            posture(), [different],
            since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon,
        )
        self.assertEqual(result.weakened, 0.0)
        self.assertEqual(result.indeterminate, 30 * self.DAY)
        self.assertEqual(result.episodes, ())

    def test_an_unranked_mode_downgrade_is_indeterminate_but_a_ranked_one_is_weakened(self):
        downgraded = posture(divergence="off")
        args = dict(since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon)
        blind = exposure(posture(), [downgraded], **args)
        informed = exposure(posture(), [downgraded], mode_order=MODES, **args)
        self.assertEqual(blind.indeterminate, 30 * self.DAY)
        self.assertEqual(informed.weakened, 30 * self.DAY)
        self.assertEqual(informed.episodes[0].controls_off, ())  # a mode drop, not a disable

    def test_an_open_ended_posture_is_closed_at_the_explicit_horizon(self):
        """No clock is read; `until` is the horizon, so a duration is always computable."""
        result = exposure(
            posture(), [posture(allowlist=False)],
            since="2026-03-01T00:00:00Z", until="2026-03-31T00:00:00Z", canonicalize=canon,
        )
        self.assertEqual(result.weakened, 30 * self.DAY)
        self.assertEqual(result.episodes[0].end, "2026-03-31T00:00:00Z")

    def test_an_inverted_or_empty_horizon_yields_no_time(self):
        for since, until in (("2026-03-31T00:00:00Z", "2026-03-01T00:00:00Z"),
                             ("2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z")):
            with self.subTest(since=since, until=until):
                result = exposure(posture(), [posture()], since=since, until=until, canonicalize=canon)
                self.assertEqual(result.total, 0.0)
                self.assertEqual(result.clean_fraction, 0.0)


class TestAttestVerify(KeyMixin):
    def test_round_trip_verifies_and_recovers_the_record(self):
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign)
        report = verify(envelope, canonicalize=canon, verify_sig=self.verify_sig)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(report.posture, posture())
        self.assertEqual(report.window, WINDOW)

    def test_envelope_is_a_dsse_wrapped_in_toto_statement(self):
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign, keyid="k1")
        self.assertEqual(envelope["payloadType"], PAYLOAD_TYPE)
        self.assertEqual(envelope["signatures"][0]["keyid"], "k1")
        statement = json.loads(base64.b64decode(envelope["payload"]))
        self.assertEqual(statement["predicateType"], PREDICATE_TYPE)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], WINDOW.digest)

    def test_a_tampered_payload_fails_the_signature(self):
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign)

        def flip_the_allowlist_off(statement):
            statement["predicate"]["posture"]["controls"][0]["enabled"] = False

        report = verify(
            self.restate(envelope, flip_the_allowlist_off),
            canonicalize=canon,
            verify_sig=self.verify_sig,
        )
        self.assertFalse(report.ok)
        self.assertIn("bad-signature", {f.code for f in report.findings})

    def test_a_foreign_predicate_type_is_refused(self):
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign)

        def retype(statement):
            statement["predicateType"] = "https://example.com/other/v1"

        report = verify(self.restate(envelope, retype), canonicalize=canon, verify_sig=self.verify_sig)
        self.assertIn("unknown-predicate-type", {f.code for f in report.findings})

    def test_the_signing_algorithm_is_recorded_and_recovered(self):
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign, algorithm="ed25519")
        report = verify(envelope, canonicalize=canon, verify_sig=self.verify_sig)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(report.algorithm, "ed25519")
        self.assertTrue(report.algorithm_stated)

    def test_the_algorithm_lives_inside_the_signed_payload_not_beside_keyid(self):
        """DSSE's PAE does not cover the signature object, so an algorithm noted
        there would be unauthenticated and strippable. Tampering with it must
        break verification — that is the whole point of the placement."""
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign, algorithm="ml-dsa-65")
        self.assertNotIn("alg", envelope["signatures"][0])

        statement = json.loads(base64.b64decode(envelope["payload"]))
        self.assertEqual(statement["predicate"]["signing"]["algorithm"], "ml-dsa-65")

        def downgrade(st):
            st["predicate"]["signing"]["algorithm"] = "ed25519"

        report = verify(self.restate(envelope, downgrade), canonicalize=canon, verify_sig=self.verify_sig)
        self.assertFalse(report.ok)
        self.assertIn("bad-signature", {f.code for f in report.findings})

    def test_an_envelope_without_an_algorithm_stays_valid_and_says_so(self):
        """Back-compatible: 0.2.0-shaped envelopes verify; they are just less durable."""
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign)
        statement = json.loads(base64.b64decode(envelope["payload"]))
        self.assertNotIn("signing", statement["predicate"])

        report = verify(envelope, canonicalize=canon, verify_sig=self.verify_sig)
        self.assertTrue(report.ok, "an unstated algorithm is not a defect")
        self.assertIsNone(report.algorithm)
        self.assertFalse(report.algorithm_stated)

    def test_a_posture_asserting_no_controls_attests_nothing(self):
        empty = Posture("rvnd", (), "2026-01-01T00:00:00Z")
        report = verify(
            attest(empty, WINDOW, canonicalize=canon, sign=self.sign),
            canonicalize=canon,
            verify_sig=self.verify_sig,
        )
        self.assertIn("empty-posture", {f.code for f in report.findings})

    def test_a_non_canonical_payload_is_located(self):
        """A re-serialised payload that verifies must still be flagged non-canonical."""
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=self.sign)
        statement = json.loads(base64.b64decode(envelope["payload"]))
        loose = json.dumps(statement, sort_keys=True, indent=2).encode()  # same content, padded bytes
        envelope["payload"] = base64.b64encode(loose).decode()

        report = verify(envelope, canonicalize=canon, verify_sig=lambda b, s: True)
        self.assertIn("non-canonical-payload", {f.code for f in report.findings})

    def test_an_inverted_effective_interval_is_located(self):
        bad = posture(frm="2026-06-01T00:00:00Z", to="2026-01-01T00:00:00Z")
        report = verify(
            attest(bad, WINDOW, canonicalize=canon, sign=self.sign),
            canonicalize=canon,
            verify_sig=self.verify_sig,
        )
        self.assertIn("interval-inverted", {f.code for f in report.findings})

    def test_malformed_envelopes_are_refused_never_raise(self):
        for envelope in (
            {},
            {"payloadType": "application/json", "payload": "e30=", "signatures": [{"sig": "AA=="}]},
            {"payloadType": PAYLOAD_TYPE, "payload": "e30=", "signatures": []},
            {"payloadType": PAYLOAD_TYPE, "payload": "!!not-base64!!", "signatures": [{"sig": "AA=="}]},
            {"payloadType": PAYLOAD_TYPE, "payload": "e30=", "signatures": [{"sig": "AA=="}]},
        ):
            with self.subTest(envelope=envelope):
                report = verify(envelope, canonicalize=canon, verify_sig=lambda b, s: True)
                self.assertFalse(report.ok)
                self.assertTrue(report.findings)



class TestDSSEInterop(unittest.TestCase):
    """The README claims interoperability with the DSSE ecosystem. This checks it
    against securesystemslib — the in-toto/TUF reference implementation — rather
    than against our own verifier, which would prove nothing.

    Skips when the library is absent so the core suite stays dependency-free."""

    def setUp(self):
        try:
            from securesystemslib.dsse import Envelope  # noqa: F401
        except ImportError:
            self.skipTest("securesystemslib not installed")

    def test_a_third_party_implementation_parses_our_envelope(self):
        from securesystemslib.dsse import Envelope

        key = Ed25519PrivateKey.from_private_bytes(bytes(32))
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=key.sign, algorithm="ed25519")

        theirs = Envelope.from_dict(envelope)
        self.assertEqual(theirs.payload_type, PAYLOAD_TYPE)

        statement = json.loads(theirs.payload)
        self.assertEqual(statement["_type"], STATEMENT_TYPE)
        self.assertEqual(statement["predicateType"], PREDICATE_TYPE)

    def test_their_pae_is_byte_identical_to_ours(self):
        """The load-bearing check: PAE is what gets signed. If their
        pre-authentication encoding differs from ours by one byte, every
        signature we produce is unverifiable to the ecosystem."""
        from securesystemslib.dsse import Envelope
        from enforcement_posture import _pae

        key = Ed25519PrivateKey.from_private_bytes(bytes(32))
        envelope = attest(posture(), WINDOW, canonicalize=canon, sign=key.sign)
        payload = base64.b64decode(envelope["payload"])

        self.assertEqual(Envelope.from_dict(envelope).pae(), _pae(PAYLOAD_TYPE, payload))


if __name__ == "__main__":
    unittest.main()
