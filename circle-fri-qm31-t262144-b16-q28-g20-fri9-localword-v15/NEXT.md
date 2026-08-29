# Next — v15 chain authority gate

The offline construction is frozen and qualified under:

```text
8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133
```

The exact fresh artifact, all-role VM meters, privacy ledger, mutation matrix,
and skipped checks are recorded in
[`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/).

## Offline sequence completed

1. The Rust/TypeScript worst-profile preflight agreed on the relation and
   construction descriptor.
2. A fresh profile-2 proof was generated under the frozen ID.
3. The independent reference verifier accepted its exact 327,674 bytes.
4. The exact 168-input withdrawal-with-change transaction was constructed.
5. All 168 inputs accepted under `createVirtualMachineBch2026(false)` with
   per-input bytes and meters recorded.
6. The complete observer ledger was extracted from the serialized transaction;
   carrier union was exact and protected-trace recovery was false.
7. Root, opening, mask, fold, false-statement, and carrier-placement mutations
   rejected at both reference and VM boundaries.
8. Every PROMPT gate was audited and broader skipped checks were recorded.

## Only remaining action

Chipnet mining is a chain mutation and requires a separate explicit request.
When authorized, land this exact candidate through the BCHN RPC workflow,
verify the mined transaction byte-for-byte and input-by-input, and update the
evidence with the resulting txid/block data. Never target mainnet.

No further construction change is implied by this gate. Any identity-bound edit
requires a new family ID, new bank digests, a fresh proof, and complete
requalification. Only the human user declares the named end complete.
