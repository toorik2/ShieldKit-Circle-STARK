# Goal — local-word v15 Circle STARK

## Named end

Only the human declares the named end complete. It is one Chipnet-mined
envelope-B transaction satisfying [`RULES.md`](RULES.md): Circle FRI,
SHA-256, QM31 security arithmetic, at least 100 classical bits under the named
assumptions, every numbered relation check miner-run, and no private note data
recoverable from the complete transaction view.

V1 permits one deposit, one full withdrawal, or one withdrawal with at most one
private change note. It deliberately has no transfer, merge, split, batching,
administration, escape path, or non-miner fee. Any N-note batch is a future
relation and new family.

## Current candidate

The offline-qualified proof-format-15 construction is:

```text
8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133
```

Its fresh exact proof, 168-input VM-accepted transaction, observer ledger,
mutations, and skipped checks are in
[`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/).
It is not the named end until Chipnet landing is separately authorized, mined,
verified byte-for-byte, and accepted by the human.

## Scientific objective

Maintain the smallest intelligible BCH-native organization of the complete
sealed verifier:

```text
private relation traces -> secret ZK seal -> one transcript
                        -> canonical proof bytes -> byte-only carriers
```

The construction must remain complete, private under its precisely stated
model, above the soundness floor, and inside one BCH consensus transaction.
Optimization is allowed only when it removes or unifies a mechanism; it may not
weaken the relation, add a witness-to-transaction path, or manufacture size
with padding or duplicate bytes.

The governing implementation prompt is [`PROMPT.md`](PROMPT.md). The exact
construction identity binds the constitution, completeness list, membrane,
parameters, codecs, verifier keys, and carrier roles. Any identity-bound edit
requires a new family ID and complete requalification.

Historical FRI11 and batch-exit work remain evidence only. They are not renamed
as this product and are not reachable from the v15 product path.
