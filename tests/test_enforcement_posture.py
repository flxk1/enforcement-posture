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
    Change,
    Control,
    Cover,
    EvidenceWindow,
    Posture,
    attest,
    compare,
    coverage,
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


if __name__ == "__main__":
    unittest.main()
