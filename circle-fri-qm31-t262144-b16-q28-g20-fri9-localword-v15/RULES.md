# NONSTANDARD IDEAL CIRCLE STARK — CONSTITUTION V1

This file fixes the relation, privacy boundary, settlement invariants, security
floor, and product boundary. It deliberately does not specify query geometry,
AIR layout, proof encoding, carrier allocation, or other construction choices;
those belong in a separately versioned construction document.

Changing any rule below creates a new family and requires a new construction
identifier. No implementation or artifact may silently reinterpret this file.

## 1. Foundation

1. The proof family is a Circle FRI STARK.
2. SHA-256 is the native hash used by the relation and BCH verifier.
3. Private computation is represented over M31 and security-critical
   challenges, composition, quotient, and FRI arithmetic use QM31.
4. The classical security floor is at least 100 bits under every assumption
   actually counted. The quantum stance is only: **no known polynomial-time
   quantum break under the stated assumptions**.

Any different proof family, native hash, or security field is a new
constitution—not an optimization of v1.

## 2. Relation

V1 permits exactly one of these transitions:

1. **Deposit:** create exactly one private note.
2. **Full withdrawal:** consume exactly one private note and create no note.
3. **Withdrawal with change:** consume exactly one private note and create
   exactly one positive private change note.

The relation proves note ownership and identity, SHA-256 message construction,
membership or append as applicable, nullifier ownership, amount authenticity,
conservation, and change allocation. Change keeps the spent owner and uses a
fresh rho.

V1 has no private transfer, merge, split, batching, administration, emergency
escape, or alternate settlement path. A future N-note construction is a new
relation and a new family; historical batch-exit work is evidence only.

[`COMPLETENESS.md`](COMPLETENESS.md) is the versioned numbered lowering of this
relation. Every security-critical row in that list must be executed by miners;
a JavaScript-only assertion is not part of the proof.

## 3. Privacy boundary

The final transaction protects:

- note ownership and owner secret;
- note identity and note preimages;
- input-note and change-note amounts;
- private note-tree paths and directions; and
- change-note identity and allocation.

The following are public by design:

- the selected action and public state transition;
- net deposits and reserve increases;
- reserve decreases, withdrawal payouts, and BCH miner fees;
- the public nullifier and its sparse anti-replay update; and
- pool TVL.

Privacy is judged over every byte of the serialized transaction and everything
efficiently derivable from the union of all inputs, outputs, scripts, openings,
paths, indices, roots, folds, and final coefficients. Absence of a contiguous
secret substring is not evidence of privacy. Changing an amount tag is not a
proof-privacy repair.

The exact statistical, computational, ROM, QROM, and unresolved claim
boundaries must be stated separately. No stronger label may be inferred from a
weaker experiment.

## 4. Settlement invariants

Each transition may pay one explicit public BCH miner fee and no other fee.
Protocol, developer, operator, treasury, and relayer fees are forbidden.

1. A deposit creates a note equal to the reserve increase. Transparent funding
   inputs supply that deposit and the deposit transaction's miner fee.
2. A withdrawal requires the spent note to equal the public payout, private
   change if any, and that transaction's miner fee. The pool reserve decreases
   by the payout plus the miner fee.
3. Every auxiliary verifier-carrier input is recreated exactly: same lock,
   value, token state, and canonical position. Verifier infrastructure is value
   neutral and may neither subsidize nor receive settlement value.
4. Pool identity, token authority, state sequence, counters, roots, and the
   selected verifier bank roll forward exactly once.

## 5. Security floor

The exact worksheet must charge field-size, algebraic and Schwartz–Zippel
events, FRI/query/grind soundness, and SHA-256 random-oracle assumptions. The
minimum and the conservative named-event union must both remain at or above
100 classical bits.

Every conjectural step and model assumption is named. A query worksheet is not
a theorem; base-field representation does not reduce QM31 challenge security;
and no 100-bit post-quantum SHA-256 collision or QROM zero-knowledge claim is
made unless separately proved.

## 6. Product boundary

The product is one envelope-B May-2026 BCH consensus transaction:

- serialized transaction size at most 1,000,000 bytes (`MAX_TX_SIZE`);
- each unlocking and redeem script at most 10,000 bytes
  (`MAX_SCRIPT_SIZE`);
- every input accepts under `createVirtualMachineBch2026(false)`; and
- every required relation, transcript, authentication, quotient, batching,
  FRI, encoding, carrier-placement, and settlement check is miner-run.

The 100,000-byte standard relay policy is not this product boundary. Multiple
transactions, trusted host verification, dummy padding, duplicated proof bytes,
filler openings, or density ballast cannot be used to satisfy it. Proof and
transaction size must come from the argument.

Chipnet is the only permitted network. Never target mainnet.

## 7. Construction and evidence

Private data has one route to consensus:

```text
private relation traces -> secret ZK seal -> one transcript
                        -> canonical proof bytes -> byte-only carriers
```

The versioned construction identifier binds this constitution, the complete
relation, privacy membrane, parameters, transcript, codecs, verifier keys, and
carrier roles. A construction change requires a new identifier and fresh exact
evidence. Historical FRI11 artifacts retain their original mismatched metadata
and remain defective evidence; they are never renamed as v1.

Claims remain separated:

- **proven:** follows from the checked lock plus its stated correspondence;
- **measured:** exact serialized bytes, VM meters, or mined transaction data;
- **speculative:** named conjecture or unproved model step; and
- **unresolved:** no claim.

Chain mutation requires explicit authorization. Only the human user declares
the named end complete.
