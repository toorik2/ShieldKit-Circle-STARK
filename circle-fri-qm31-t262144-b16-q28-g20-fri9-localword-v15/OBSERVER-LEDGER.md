# Complete observer ledger

**Status:** exact fresh profile-2 transaction ledger recorded for construction
`8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133`.
FRI11 remains the frozen failing control.

The observer receives the complete serialized transaction, not a convenient
single input. The authoritative parser is
`analyzeLocalWordObserverTransaction`. It reconstructs the canonical proof
from all carrier inputs and refuses a missing, duplicated, moved, or malformed
slice.

## v15 public view

| ID | Public object | Witness dependency | Exact exposure | Privacy treatment |
|---|---|---|---:|---|
| P | action, old/new public state, reserve delta, payout, miner fee, TVL | public by constitution | transaction | intentionally public |
| N | nullifier and 256-node sparse insertion path | public anti-replay state | one data output | intentionally public |
| K | construction/profile header, three authorized standing banks, preprocessed root | no private witness | selected 168 locks plus proof header | integrity only |
| O | sealed original oracle | private relation trace | 34 M31 at 28 points | 262,144 fresh M31 mask dimensions per column |
| I | sealed current interaction oracle | witness-derived LogUp trace | 56 M31 at 28 points | independently sealed, 262,144 dimensions per column |
| G | sealed global interaction oracle | witness-derived accumulators | 12 M31 at 56 current/predecessor points | independently sealed, 262,144 dimensions per column |
| Q | unsplit quotient | deterministic function of opened O/I/G and public AIR | 28 QM31 values | no extra witness form |
| R | independent FRI isolator | fresh randomness only | 28 direct QM31 values | uniform degree-`2^20` polynomial |
| F | batch, folds, final polynomial | function of O/I/G/Q plus R | 952 layer QM31 values and 8 final coefficients | decoupled by R |
| A | roots and authentication | committed oracle bytes | 5 matrix roots, 9 FRI roots, all canonical paths/frontiers | computational SHA-256 ROM |
| C | carrier union and address ledger | canonical proof plus public coordinates only | 168 contiguous slices, cumulative values, disabled sequences | byte-for-byte reassembly |

Derived totals fixed by the parameters:

```text
current query points                 28
global current/predecessor points    56
original opened M31 values          952
current interaction M31 values    1,568
global interaction M31 values       672
quotient QM31 values                 28
FRI-mask QM31 values                 28
FRI layer QM31 values               952
final QM31 coefficients               8
relation/auxiliary roots               5
FRI roots                              9
carrier inputs                        168
```

The exact fresh proof is 327,674 bytes and contains 7,741 authentication nodes,
including 3,215 FRI nodes. The complete 967,476-byte transaction has 168 inputs,
170 outputs, and one public 256-node sparse-nullifier path. The canonical
combinatorial maximum for every profile-2 schedule remains 340,490 proof bytes.
Machine-readable counts are in
[`survey/artifacts/local-word-v15-offline/meters.json`](survey/artifacts/local-word-v15-offline/meters.json).

## Privacy accounting

For O and I, 28 direct base-field forms are exposed against a
262,144-dimensional independent mask space per column. G exposes 56 forms
against the same dimension. Circle-code MDS makes each corresponding evaluation
map full rank.

Q is not treated as a separately hidden polynomial: at every revealed point it
is fixed by the already simulated sealed AIR frame and `Z_H`. There is no
quotient split.

R is a uniform 1,048,576-dimensional QM31 polynomial committed before the batch
challenge and added with coefficient one. Conditional on its 28 direct
openings, it isolates the downstream FRI transcript from O/I/G/Q. See
[`ZK-MEMBRANE.md`](ZK-MEMBRANE.md) for the simulator and model boundary.

| Layer | Status |
|---|---|
| algebraic openings, conditioned on nonzero denominators | perfect honest-verifier simulation |
| bad-denominator abort | conservative distance below `2^-102.61` |
| Merkle and Fiat–Shamir | computational, classical programmable ROM |
| QROM | unresolved |
| exact fresh transaction | carrier union exact; protected-trace recovery false |

## Adversarial extraction control

The transaction parser is intentionally hostile:

1. decode only serialized transaction inputs;
2. take the first pushed item from each of exactly 168 inputs;
3. concatenate in transaction order;
4. independently recompute the canonical weighted partition and its public
   value/sequence coordinates;
5. strictly decode proof version, length, field elements, directories, and
   schedules; and
6. run the protected-trace recovery analysis over the resulting union.

The masking ablation is the positive control: removing the secret seal restores
the expected interpolation recovery. With v15 sealing enabled, the same
observer does not recover the protected trace. This result supports the data
flow; it does not replace the privacy proof.

## FRI11 failing control

| ID | Historical public object | Exposure | Judgment |
|---|---|---|---|
| A0 | spent leaf, index, and 16-node path | direct `encodeAuth` bytes and note-auth walk | exposed note identity/path |
| A1 | created leaf, index, and path | direct bytes and note-auth walk | exposed change allocation |
| S | 96 amount-SHA columns | 32 opening points | unmasked witness evaluations |
| B | the same 96 columns | 36 booleanity-carrier points | second unmasked opening path |
| S+B | 64-row SHA trace | rank 64 | recovered amount and rho |
| F | old folds/final | no complete simulator | unresolved |
| C | note-aware carriers | multiple witness-to-transaction paths | failed membrane |

The deterministic reproduction measured a 90,394-byte FRI11 proof and recovered
`amount = 123456789` plus all 32 bytes of rho. This remains historical
evidence in [`PRIVACY-AUDIT.md`](PRIVACY-AUDIT.md); it is not a measurement of
v15.

## Deletion check

The v15 product path contains no `FriAuth`, witness OTP, `openShaBit`,
`occupancyBoolShardsFromNote`, carrier-side interpolation, public privacy
randomizer, or transaction builder that accepts a note. Historical source may
remain for reproducing FRI11, but it must be unreachable from the v15 proof and
transaction builders.
