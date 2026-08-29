# Status — local-word v15

**Construction ID:**
`8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133`

**State:** offline-qualified sealed successor candidate. The exact evidence is
[`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/).
It is not Chipnet-mined and not the human-declared named end.

## What exists

- A minimal constitution consistent with the v1 product: one deposit or one
  withdrawal consuming one note and creating at most one private change note;
  no transfer, merge, split, batching, administration, escape, or protocol fee.
- One 243,015-active-row worst-profile word machine containing SHA-256 amount
  commitment, leaf, membership/append, nullifier ownership, conservation,
  same-owner positive change, and fresh change rho.
- Public sparse-nullifier absence/insertion and exact settlement executed by
  production VM roles.
- Independently sealed original and interaction columns, one unsplit quotient,
  and one independent degree-`2^20` QM31 FRI isolator.
- One proof-format-15 transcript, 28-orbit query schedule, strict codec, and
  168-role byte-only carrier allocation.
- Three deterministic standing verifier banks tied to the construction ID.
- A 14-component manifest binding constitution, membrane, completeness,
  construction, parameters, transcript, codecs, keys, soundness, and carriers.

The v15 product import graph reaches 50 files and none of the historical FRI11
SHA-bit, booleanity, note-auth, witness-mask, or observer paths.

## Exact fresh artifact

| Item | Value |
|---|---:|
| construction rules SHA-256 | `49542e5f5fc9a13a16a3e205fe1408b1cfca49311c1f4e2613527d530fed9db5` |
| proof bytes / upper bound | 327,674 / 340,490 |
| proof SHA-256 | `a786071c0839e5dbcaf235d477c2441268abbc2f5538bb793971110874668d90` |
| quotient degree bound | 786,433 (< `2^20`) |
| transaction bytes / remaining | 967,476 / 32,524 |
| transaction SHA-256 | `8b7200b5a76ecc0e9ae038a5698d2d33ec884ea54548ccb347dd0d62390aef53` |
| inputs accepted | 168 / 168 |
| maximum verifier / redeem / unlocking | 9,383 / 9,435 / 9,699 bytes |
| maximum operation cost | 7,321,148 at `merkle:preprocessed:0` |
| tightest operation-cost slack | 19,905 at `merkle:interactionGlobal:2` |

All root, opening, FRI-mask, fold, false-statement, and carrier-placement
mutations rejected in both the relevant reference layer and a production VM
role. The serialized-transaction observer reassembled the exact carrier union
and reported no protected-trace recovery.

## Claim boundaries

- Classical soundness is above the 100-bit floor; the conservative named-event
  union is above 101.37 bits and the 104-bit FRI row is conjectural.
- Algebraic openings are perfect HVZK conditioned on nonzero denominators;
  bad-denominator distance is below `2^-102.61`.
- Merkle and Fiat–Shamir privacy are computational in the classical
  programmable random-oracle model.
- QROM zero knowledge is unresolved.
- The quantum stance is “no known polynomial-time quantum break”; no 100-bit
  post-quantum SHA-256 collision claim is made.
- FRI11 remains privacy- and completeness-defective historical evidence.

## Checks deliberately not promoted into evidence

- The complete historical `npm test` suite was skipped in favor of focused v15
  falsifiers and the exact end-to-end artifact.
- The full Cargo test suite was skipped; the release worker preflight, fresh
  proof, reference verification, and exact product run exercised the required
  Rust paths.
- The focused v15 suite passes 81/81 tests and release Cargo checking passes.
  Full source-lane TypeScript checking still reports 10 inherited errors in
  seven excluded historical files; none point to the exported v15 system. The
  minimal self-contained export typechecks cleanly.
- No RPC, mempool, funding, broadcast, or chain mutation was performed.

## Remaining authority gate

Only Chipnet landing and mined-artifact verification remain. They require an
explicit chain-mutation request. Never target mainnet. Only the human declares
the named end complete.
