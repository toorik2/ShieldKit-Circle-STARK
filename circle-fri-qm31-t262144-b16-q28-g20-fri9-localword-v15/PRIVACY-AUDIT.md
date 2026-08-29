# Amount-trace privacy audit

Date: 2026-08-27

Imported upstream: `4c43e0f37d36f6e4005db9555ca5365afcd9c574`

Status: **frozen blocking defect in historical FRI11**. Proof-format v15 is a
separate successor and does not revise this result.

## FRI11 judgment

Historical FRI11 does **not** serialize the complete 64 x 72-byte packed SHA trace in
`encodeFriProof`. It therefore does not have the identical proof-only defect
found in the LABS `sha-in-occupancy-c` lane.

It has a related cross-carrier defect:

1. `encodeFriProof` publishes 32 evaluations of each of the 96
   `amountCommit` SHA trace columns through `shaBit.shards`.
2. Consensus envelope B publishes another 36 evaluations of those same
   columns through its three booleanity unlocking shards.
3. The columns are evaluations of polynomials interpolated from a 64-row trace.
4. The two public opening sets contain 68 distinct points and have evaluation
   rank 64 for the tested honest proof.
5. A public observer can therefore interpolate every original trace column.
6. SHA message-schedule words `W[0..13]` then recover the complete 56-byte first
   compression message:

   `tag16 || amount_i64le || rho32`

The focused reproduction recovered the exact amount and all 32 bytes of `rho`.
The owner secret is not in this first compression and was not recovered by this
route.

## Additional direct privacy-boundary failures

The machine-readable follow-up in [`OBSERVER-LEDGER.md`](OBSERVER-LEDGER.md)
found direct disclosure beyond the interpolation attack:

- `encodeAuth` serializes the spent leaf, index, and full 16-node membership
  path, exposing note identity and its path;
- it also serializes the created leaf, index, and path, exposing change
  allocation; and
- note-auth transaction construction walks those public paths again.

These are independent failures under the lane's current privacy boundary. A
trace mask for amount/rho alone would not qualify the successor. Membership and
change relations must also move behind the sealed proof boundary.

## Public data flow

- `src/chain/sha-bit-air.ts` takes the first 96 `a/e/w` columns from
  `buildHashBitTrace`, interpolates each from the 64-row trace, and opens 32
  points in `openShaBit`.
- `src/backends/circle/fri.ts` serializes the six `shaBit.shards` in
  `encodeFriProof`.
- `src/chain/booleanity-kernel.ts` opens the same 96 column polynomials at all
  36 occupancy query indices.
- `src/chain/covenant-spend.ts` places those booleanity shards in consensus-B
  input unlockings while also placing the `shaBit` shards in fold unlockings.

Neither carrier alone supplies the complete interpolation budget. Their union
does. Privacy must therefore be judged over the complete transaction transcript,
not one proof object or input at a time.

## Focused reproduction

The audit used a deterministic note with:

- amount: `123456789`
- `rho`: 32 bytes of `0x52`
- owner: 32 bytes of `0x4f`

It generated one honest proof, decoded only its published `shaBit` shards,
combined them with the bytes published by the booleanity shards, constructed
the 64-dimensional evaluation matrix using the lane's Circle interpolation,
and performed M31 Gaussian elimination.

Observed result:

```json
{
  "serializedProofBytes": 90394,
  "uniqueProofOpenings": 32,
  "uniqueTransactionOpenings": 36,
  "combinedUniquePoints": 68,
  "publicEvaluationRank": 64,
  "recoveredTraceBitsAreBoolean": true,
  "recoveredAmount": "123456789",
  "amountMatches": true,
  "rhoMatches": true,
  "recoveredRhoPrefix": "5252525252525252"
}
```

The check completed in about 4.4 seconds. No broad test suite or chain action was
used.

## Consequence

RULES section 6 and the named privacy goal are not satisfied by consensus B.
The absence of contiguous `amount`, `rho`, or owner bytes in an unlocking is not
sufficient: the published evaluation representation is reversibly equivalent
to the amount and `rho`.

Do not describe FRI11 as shielded, confidential, statistically
zero-knowledge, or amount-hiding until this transcript-level recovery fails for
the exact final transaction.

## Safety gate for the redesign

A replacement must:

1. inventory every evaluation of every witness-dependent polynomial across the
   proof and all carrier inputs;
2. keep the combined public evaluation rank below witness recovery, or use a
   formally justified secret randomization that remains hidden in the complete
   transcript;
3. prevent SHA message-schedule reconstruction, not merely byte-substring
   matches;
4. test the adversary view extracted from the final serialized transaction; and
5. state separately what is computationally hidden, statistically hidden,
   public by design, and still unresolved.

This audit identifies the historical leak; it does not qualify its successor.

## v15 successor disposition

Proof-format v15 removes every path used above instead of sharing or hiding the
old openings:

- original and interaction traces cross independent secret `w + Z_H r` seals;
- membership, note identity, and change allocation remain inside that sealed
  relation;
- there is one unsplit quotient and one independent QM31 FRI isolator;
- one transcript owns all 28 openings and FRI folds; and
- 168 byte-only carriers partition one canonical proof without note-aware
  recomputation; public value/sequence coordinates only locate those bytes.

The exact simulator and current observation ledger are now
[`ZK-MEMBRANE.md`](ZK-MEMBRANE.md) and
[`OBSERVER-LEDGER.md`](OBSERVER-LEDGER.md). Targeted masking-ablation and
observer tests are green. The fresh worst-profile proof and exact 967,476-byte
transaction were audited under construction
`8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133`:
the parser reconstructed the exact 168-input carrier union, observed 28 openings
per original column against 262,144 fresh mask dimensions, and reported no
protected-trace recovery. Root, opening, mask, fold, statement, and placement
mutations rejected. This is evidence for the stated classical-ROM simulator
boundary; QROM zero knowledge remains unresolved. None of it changes FRI11's
blocking result.
