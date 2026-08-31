# Next — preserve, assure, then make smaller

V17 has one fresh identity-bound offline qualification, indexed by
`evidence/v17-offline-qualification-receipt.json`, for construction:

```text
c434ed36bf04d8265ec6d0e447f69cd7a437baf91bcc6eab6eb0ff5f9cbe62e1
```

Do not casually tune this identity. Any normative, graph, verifier-bank, ROM,
allocation, or proof-codec change requires new IDs and fresh all-profile
qualification.

## Immediate assurance

1. Independently reproduce the compact receipt from source on a clean machine,
   including fresh Rust proofs, TypeScript replay, final observers, closure
   replay, and BCHN 29.0.0 input assays.
2. Review the static-to-runtime promotion seam: the runtime certificate must
   bind exactly the proof set, construction, linker, final infrastructure,
   BCHN evidence, privacy ledger, and adversarial evidence.
3. Mechanize or independently formalize L1-L9, especially the custom lookup
   and copy reductions, quotient degree correspondence, grouped binary FRI,
   and mixed-Merkle partial-decommitment argument.
4. Fuzz the strict proof codec, terminal opening directory, affine reader,
   monotone closure trace, occurrence-anchor ROM IDs, bank identity, carrier
   order, and exact infrastructure recreation.
5. Tighten privacy theory: compute the exact bad-denominator distance for this
   relation. Do not promote opening non-uniqueness into a complete
   honest-verifier, statistical, or computational ZK theorem. Either supply a
   QROM zero-knowledge reduction or continue to state QROM ZK as a nonclaim.
6. Add a separate offline transaction-context harness if full
   `CheckTransaction`/`CheckTxInputs`, UTXO maturity, and relative-locktime
   evidence is desired. Do not silently relabel per-input `VerifyScript`
   evidence as that stronger result.

## Later construction

Only after assurance is stable should a separate successor target standard
sub-100,000-byte relay. Start by removing proof material and verifier work at
their mathematical source. Recursion, accumulation, different commitment
geometry, or BCH-specific lookup arguments must delete more machinery than
they add and preserve the V17 constitution.

## Authorization boundary

No RPC, funding, spending, broadcast, mining, or chain mutation belongs to
this plan without a separate explicit request. Mainnet remains out of scope.
Only the human user declares the named end complete.
