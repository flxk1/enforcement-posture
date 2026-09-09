# Semantics and limitations

## Semantics

- **`compare` is a partial order, not a score.** A different engine, a differing control set, a
  mode change with no supplied `mode_order`, a quantity change with no supplied `quantity_order`,
  or a change that both hardens and weakens returns `INCOMPARABLE`.
- **An exemption inverts the on/off reading.** `Control(..., weakens_when_enabled=True)` marks a
  control whose *presence* weakens — a policy exception, an override, a break-glass grant, a bypass
  allowlist. Without it, granting an exception reads as a hardening. Unlike the orderings below,
  polarity is a fact about the control rather than a reader's choice, so it travels **inside the
  signed record**: two verifiers cannot disagree about whether a change was a weakening.
- **Quantities carry a caller-supplied direction.** `Control.quantity` holds a poll interval,
  timeout, rate limit or threshold. Which way is stronger is domain knowledge — a *lower* bundle
  poll delay is stronger, a *higher* key length is — so `quantity_order` maps a control name to
  `"lower-is-stronger"` or `"higher-is-stronger"`. Without an entry the change is `INCOMPARABLE`,
  **never `UNCHANGED`**.
- **`coverage` returns `SPLIT` with segments** rather than collapsing a window whose regime
  changed. There is no single "effective posture" for such a window.
- **`UNCOVERED` outranks `SPLIT`.** Any sub-interval without an attested posture makes the whole
  window uncovered.
- **`posture_id` excludes the interval**, so re-attesting an unchanged posture after a restart
  reads as `covered`, not as a split.
- **`algorithm` is recorded inside the signed payload** (`predicate.signing.algorithm`), not beside
  `keyid`. DSSE's PAE covers only payload type and payload, so an algorithm in the signature object
  is unauthenticated and strippable. Omitting it is back-compatible; `Report.algorithm_stated` is
  then `False`.
- No clock: `since` / `until` are explicit, so an open-ended posture closes at a named horizon.

## Limitations

- **Single signature** per envelope; threshold and multi-sig are not modelled.
- **You supply canonicalisation and keys.** Pass `rfc8785.dumps` and an Ed25519 `sign`/`verify_sig`.
  Migrating to a post-quantum scheme is a caller change.
- **It attests a claim; it does not observe the engine.** The posture recorded is the one the
  attesting process asserts. It makes an operator's claims checkable and non-repudiable — it does
  not independently measure what the engine did.
- **Mode orders and quantity directions are per-caller.** There is no universal ranking of mode
  names, and no universal answer to whether higher is stronger.
- It does not judge adequacy. `verify` locates structural and cryptographic defects only.
