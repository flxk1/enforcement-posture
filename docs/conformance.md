# Conformance

## Conformance

`conformance/vectors.json` is the specification: 18 language-agnostic vectors, each an input and
the result any implementation must produce. `conformance/check_vectors.py` checks this one.

```bash
python3 conformance/check_vectors.py
```

The refusal cases are most of the suite, because they are what a reimplementation gets wrong —
`incomparable` for an unranked mode or quantity change, `split` for a window whose regime changed,
`uncovered` outranking `split`. Getting any of them wrong converts a refusal into a false
assurance, which is worse than the missing feature. An empty suite exits 2 rather than reporting
success.
