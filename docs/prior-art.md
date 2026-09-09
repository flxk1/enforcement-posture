# Prior art and related

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

## Related

One of four narrow governance primitives, each usable alone:

- [`enforcement-posture`](https://github.com/flxk1/enforcement-posture) — binds evidence to the
  controls that were in force while it was recorded
- [`norm-freshness`](https://github.com/flxk1/norm-freshness) — whether the rule a gate applies
  still matches the text it was compiled from
- [`effect-reconciliation`](https://github.com/flxk1/effect-reconciliation) — permissions granted
  against effects observed
- [`oversight-certificate`](https://github.com/flxk1/oversight-certificate) — re-checkable proof
  that a qualified human decided

They answer different questions about the same decision: *who decided* (oversight-certificate),
*under what regime* (enforcement-posture), *against which version of the rule* (norm-freshness),
and *did the permission produce the effect* (effect-reconciliation).
