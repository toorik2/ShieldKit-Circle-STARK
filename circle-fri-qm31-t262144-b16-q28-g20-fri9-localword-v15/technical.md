# v15 1MB — technical ledger

> **Status:** non-normative technical index, recorded 2026-08-29. The frozen
> construction remains identified by its canonical construction ID. This file
> consolidates the constitution, construction, implementation, and measured
> evidence; it does not silently amend them.

“Fixed” means construction-bound; “measured” means exact artifact evidence.
Conjectural and unresolved claims are intentionally not promoted.

## Identity and scope

| Category | Parameter | v15 1MB value | Status |
|---|---|---|---|
| Name | Human name | **v15 1MB** | Non-normative name |
| Constitution | Relation family | Constitution v1 | Fixed |
| Construction | Proof/relation version | 15 / 15 | Fixed |
| Family identifier | Internal family | `circle-stark-qm31-sha256-localword-v15` | Fixed |
| Construction ID | Canonical identity | `8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133` | Fixed |
| Constitution hash | `RULES.md` SHA-256 | `49542e5f5fc9a13a16a3e205fe1408b1cfca49311c1f4e2613527d530fed9db5` | Fixed |
| Proof magic | Header magic | `SKLW` | Fixed |
| Proof version | Header version | `15` | Fixed |
| Profiles | Header profile byte | `0` deposit, `1` full withdrawal, `2` withdrawal with change | Fixed |
| Proof family | Polynomial argument | Circle FRI STARK | Fixed |
| Native hash | Relation, Merkle, transcript | SHA-256 | Fixed |
| Trace field | Private computation | M31 | Fixed |
| Security field | Challenges, quotient, composition, FRI | QM31, approximately 124-bit cardinality | Fixed |
| Product | Settlement envelope | One BCH consensus transaction | Fixed |
| Network | Permitted target | Chipnet only; never mainnet | Fixed |
| VM | Consensus evaluator | `createVirtualMachineBch2026(false)` | Fixed |
| Current state | Qualification | Offline-qualified sealed successor candidate | Measured |
| Chain state | Mining | Not Chipnet-mined | Remaining gate |

## Supported relation

| Profile | Inputs to relation | Result | Note-root behavior |
|---|---|---|---|
| Deposit | One new private note | Creates exactly one note | Appends new leaf |
| Full withdrawal | One owned existing note | Consumes note, creates no note | Root remains unchanged |
| Withdrawal with change | One owned existing note | Public payout plus one positive private change note | Appends change leaf |

## Explicitly excluded behavior

| Feature | v15 1MB |
|---|---|
| Private transfer | Forbidden |
| Merge multiple notes | Forbidden |
| Split into multiple notes | Forbidden |
| Batch deposits/withdrawals | Forbidden |
| Multiple private change notes | Forbidden |
| Administration path | Forbidden |
| Emergency escape | Forbidden |
| Trusted host verification | Forbidden |
| Developer/protocol/operator fee | Forbidden |
| Relayer fee | Forbidden |
| Multiple settlement transactions | Forbidden |
| Mainnet operation | Forbidden |

## Note construction

| Component | Exact rule | Visibility |
|---|---|---|
| Amount commitment | `SHA256(tag16 \|\| amount_i64le \|\| rho32)` | Private preimage |
| Note leaf | `SHA256(amountCommit \|\| rho \|\| owner)` | Private preimage |
| Nullifier | `SHA256(poolInstanceId \|\| owner \|\| rho)` | Digest public; preimage private |
| Note-tree depth | 16 levels | Path private |
| Nullifier tree | 256-level sparse SHA-256 tree | Nullifier and update path public |
| Deposit amount | Equals public reserve increase | Publicly implied |
| Full-withdraw amount | Equals payout plus miner fee | Publicly implied |
| Change amount | `spent − payout − miner fee` | Private |
| Change validity | Strictly positive | Proved |
| Change owner | Same owner as spent note | Proved privately |
| Change rho | Fresh and different | Proved privately |
| Arithmetic | Signed amount relation without overflow | Proved |

## Privacy boundary

| Information | Status |
|---|---|
| Owner secret | Private |
| Note identity and preimages | Private |
| Rho | Private |
| Membership path and directions | Private |
| Deposit append path | Private |
| Change amount | Private |
| Change identity and allocation | Private |
| Link between spent note and change note | Private |
| Selected action | Public |
| Pool state transition | Public |
| Deposit/reserve increase | Public |
| Withdrawal reserve decrease | Public |
| Payout and payout locking digest | Public |
| BCH miner fee | Public |
| Nullifier | Public |
| Sparse-nullifier path | Public |
| Pool TVL | Public |

Privacy means no leakage beyond what the public settlement logically implies.
It does not mean that a public deposit or full withdrawal hides its amount.

## Pool state

| State field | Transition rule |
|---|---|
| Pool instance ID | Unchanged |
| CashToken category | Unchanged |
| CashToken capability | Unchanged |
| Token amount | Unchanged |
| State version/prefix | `PAA1`, version 1 |
| Sequence | Increments exactly once |
| Reserve | Changes by public deposit or withdrawal delta |
| Deposit counter | Increments only for deposit |
| Withdrawal counter | Increments only for withdrawal |
| Note root | Appended for deposit/change; unchanged for full withdrawal |
| Nullifier root | Unchanged for deposit; absence-to-used update for withdrawal |
| Pool-covenant authorization | Three deterministic verifier-bank digests |
| Pool position | Input and output index zero |

## Settlement accounting

| Action | Exact value rule |
|---|---|
| Deposit | Funding input supplies `reserve increase + miner fee` |
| Created deposit note | Equals reserve increase |
| Withdrawal | Reserve decrease equals `payout + miner fee` |
| Withdrawal with change | `spent note = payout + miner fee + private change` |
| Full withdrawal | `spent note = payout + miner fee` |
| Protocol fees | Zero; forbidden |
| Carrier subsidy | Forbidden |
| Carrier revenue | Forbidden |
| Carrier rollover | Same lock, value, token state, and position |

## Local-word machine

| Parameter | Exact value |
|---|---:|
| Instruction set | `input`, `private-mask`, `constant`, `rotate-right`, `xor`, `and`, `add`, `nonzero` |
| Operations | 8 |
| Word size | 32 bits |
| Limbs per word | 8 |
| Limb size | 4 bits |
| Fixed ALU table | 1,841 rows |
| Deposit SHA-256 compressions | 68 |
| Full-withdraw SHA-256 compressions | 38 |
| Change-withdraw SHA-256 compressions | 106 |
| Worst-profile active rows | 243,015 |
| Relation rows | 262,144 |
| Private input words | 316 |
| Public input words | 34 |
| Original trace columns | 34 M31 |
| Public preprocessed columns | 67 M31 |
| Logical interaction columns | 17 QM31 |
| Current interaction commitment | 56 M31 columns |
| Predecessor interaction commitment | 12 M31 columns |
| AIR residuals | 25 |
| AIR degree | Quadratic |
| Lookup mechanism | One ALU LogUp |
| Copy mechanism | One word-compressed permutation |
| Public boundary | One public-boundary LogUp |
| Memory argument | None |
| SHA side proof | None |
| Path/message bus | None |

## Computations inside the machine

| Relation component | Enforcement |
|---|---|
| SHA-256 message padding | Word-machine rows |
| SHA-256 schedule | Word-machine rows |
| All 64 SHA-256 rounds | Word-machine rows |
| Digest chaining | Copy classes |
| Amount commitment | SHA rows and copy classes |
| Note leaf | SHA rows and copy classes |
| Deposit append | Private path plus SHA rows |
| Withdrawal membership | Private path plus SHA rows |
| Nullifier ownership | SHA rows |
| Full-withdraw equality | Word relation |
| Change conservation | Word relation |
| Positive change | Nonzero/range relation |
| Same-owner change | Copy classes |
| Fresh change rho | Inequality/nonzero relation |
| Public statement binding | Public-boundary LogUp |

## Domains and degree bounds

| Parameter | Value | Status |
|---|---:|---|
| Relation log | 18 | Fixed |
| Relation domain | `2^18 = 262,144` | Fixed |
| Sealed-degree log | 19 | Fixed |
| Sealed bucket | `2^19 = 524,288` | Fixed |
| Quotient-degree log | 20 | Fixed |
| Quotient bucket | `2^20 = 1,048,576` | Fixed |
| Evaluation-domain log | 24 | Fixed |
| Evaluation rows | `2^24 = 16,777,216` | Fixed |
| Effective blowup | 16 | Fixed |
| Fresh quotient degree | 786,433 | Measured; below `2^20` |
| Domain separation | `Z_H` nonzero over complete LDE domain | Checked by prover |

## ZK sealing

| Oracle | Seal or treatment | Opened locations | Fresh secret dimensions |
|---|---|---:|---:|
| Original trace | `w + Z_H r` per M31 column | 28 current points | 262,144 M31 per column |
| Current interaction | Independently sealed | 28 current points | 262,144 M31 per column |
| Global interaction | Independently sealed | 28 current + 28 predecessor | 262,144 M31 per column |
| Quotient | Whole, determined by sealed AIR frame | 28 | No independent quotient mask |
| FRI isolator | Uniform QM31 polynomial `R` | 28, then complete FRI view | 1,048,576 QM31 coefficients |
| Public preprocessing | Deterministic | Public | None |

| Sealing property | v15 1MB rule |
|---|---|
| Randomness source | Fresh `getrandom` entropy |
| Reuse between proofs | Forbidden |
| Reuse between columns | Forbidden |
| Original/interaction reuse | Forbidden |
| Public-derived privacy masks | Forbidden |
| Seal input | Raw private trace |
| Seal output | Sealed oracle |
| Quotient input | Sealed oracles only |
| Transaction-builder input | Canonical proof bytes and public settlement only |

## Quotient and batching

| Parameter | Rule |
|---|---|
| Composition | One QM31 mixture of 25 AIR residuals |
| Quotient | One unsplit QM31 quotient |
| Quotient equation | `composition = quotient × Z_H` |
| Quotient decomposition | None |
| Quotient padding | None |
| Independent batch mask | Uniform degree-`2^20` QM31 polynomial |
| Mask coefficient | Exactly one |
| FRI layer zero | Horner batch of 9 packed original values, 17 packed interaction values, quotient, then `+ R` |
| Oracle-batch challenge | Transcript-derived QM31 |
| Alternate batch schedule | Forbidden |

## FRI geometry

| Parameter | Value |
|---|---:|
| Query orbits | 28 |
| Query collision policy | Collision-free |
| Grinding | 20 bits |
| FRI layers | 9 |
| Radix-4 folds | 8 |
| Binary folds | 1 |
| Final-degree log | 3 |
| Final polynomial degree | Less than 8 |
| Final coefficients | 8 QM31 |
| Merkle arity | Radix 4 |
| Independent query schedules | None |
| DEEP sample/oracle | None in v15 |
| Filler openings | Forbidden |
| Dummy padding | Forbidden |

## Transcript order

| Stage | Transcript material |
|---:|---|
| 1 | Public statement and construction ID |
| 2 | Construction descriptor, preprocessed root, sealed-original root |
| 3 | Lookup, copy, and public-boundary challenges |
| 4 | Verifier-checked public-boundary inverses |
| 5 | Sealed interaction roots and AIR mixing challenge |
| 6 | Quotient/FRI-mask root and batching challenge |
| 7 | Nine FRI roots and fold challenges |
| 8 | Eight final coefficients |
| 9 | Grind-20 nonce |
| 10 | Twenty-eight collision-free query orbits |

Every stage is SHA-256 domain-separated and re-derived by consensus roles.

## Authenticated proof objects

| Opening family | Contents |
|---|---|
| Matrix 1 | Public preprocessed matrix |
| Matrix 2 | Sealed original matrix |
| Matrix 3 | Sealed current interaction |
| Matrix 4 | Sealed current/predecessor interaction |
| Matrix 5 | Quotient plus FRI mask |
| FRI openings | Nine committed FRI layers |
| Authentication | Canonical radix-4 multiproofs |
| Index ownership | Derived from one transcript schedule |
| Intermediate Merkle work | Derived; not independently chosen |
| Roots | Serialized once |
| Opened rows | Serialized once |
| Alternate encoding | Rejected |
| Trailing bytes | Rejected |

## Canonical proof encoding

| Field | Rule |
|---|---|
| Magic | `SKLW` |
| Version | 15 |
| Profile | One byte |
| Geometry | Supplied by verifier key |
| Proof length | Canonical big-endian header length |
| Construction descriptor | Bound in header |
| Construction ID | Bound in transcript |
| Preprocessed root | Bound by verifier key |
| Opening directory | Compact and canonical |
| Ownership directory | Compact and canonical |
| Proof partition | Exactly once, contiguous and ordered |
| Maximum profile-2 proof | 340,490 bytes |
| Fresh qualified proof | 327,674 bytes |

## Verifier-role allocation

| Role family | Inputs |
|---|---:|
| Pool settlement/control plane | 1 |
| Per-query AIR evaluation | 28 |
| Public-boundary inverse batches | 3 |
| Proof header | 1 |
| Sparse-nullifier segments | 4 |
| Public-boundary sum | 1 |
| Transcript manifests | 6 |
| Query schedule | 1 |
| Opening schedules | 13 |
| Per-query quotient/batch algebra | 28 |
| Per-query FRI fold | 28 |
| Matrix/FRI Merkle stages | 54 |
| **Total core verifier-bearing inputs** | **168** |

### Merkle-role breakdown

| Merkle family | Roles |
|---|---:|
| Preprocessed matrix | 3 |
| Original matrix | 3 |
| Interaction matrix | 5 |
| Quotient and FRI mask | 3 |
| Global interaction | 7 |
| Nine FRI layers | 33 |
| **Total** | **54** |

### Opening-schedule breakdown

| Schedule | Roles |
|---|---:|
| Current matrix | 1 |
| Global current/previous/shape | 3 |
| FRI layers | 9 |
| **Total** | **13** |

## Verifier-bank structure

| Parameter | Value |
|---|---|
| Standing banks | 3 |
| Bank profiles | Deposit, full withdrawal, change withdrawal |
| UTXOs per bank | 167 |
| Bank selected per transaction | Exactly 1 |
| Other banks | Remain untouched |
| Pool UTXO | Separate from banks |
| Carrier slice | One contiguous proof range |
| Carrier proof interpretation | Forbidden beyond assigned verifier |
| Carrier value flow | Exactly neutral |
| Carrier lock rollover | Exact |
| Carrier token rollover | Exact |
| Bank authorization | SHA-256 digest of ordered locks, values, sequences, positions |
| Addressing values | Cumulative allocation-weight prefixes |
| Input sequences | Proof-length commitment or direct jump index |
| Proof duplication | None |

## Exact transaction shapes

| Action | Inputs | Outputs |
|---|---:|---:|
| Deposit | 169 | 168 |
| Full withdrawal | 168 | 170 |
| Withdrawal with change | 168 | 170 |

### Deposit positions

| Position | Purpose |
|---|---|
| Input 0 | Old pool and settlement role |
| Inputs 1–167 | Selected verifier bank |
| Input 168 | Transparent depositor funding |
| Output 0 | New enlarged pool |
| Outputs 1–167 | Recreated verifier bank |

### Withdrawal positions

| Position | Purpose |
|---|---|
| Input 0 | Old pool and settlement role |
| Inputs 1–167 | Selected verifier bank |
| Output 0 | New reduced pool |
| Outputs 1–167 | Recreated verifier bank |
| Output 168 | Public BCH payout |
| Output 169 | Zero-value nullifier and 256-level path data |

The common “168 inputs” description refers to the core verifier inventory and
exact withdrawal artifact. A deposit has an additional transparent funding
input.

## BCH boundaries

| BCH parameter | Current value | Classification |
|---|---:|---|
| Consensus transaction limit | 1,000,000 bytes | Consensus |
| Standard relay transaction limit | 100,000 bytes | Policy |
| Script/unlocking limit | 10,000 bytes | Consensus and policy |
| Intended boundary | 1 MB consensus | Product choice |
| Standard relay target | No | Explicitly excluded |
| Constants source | BCHN commit `864c53ee34924cca6c6b6d96607ff2cedcdccf02` | Source-derived |

## Worst-case construction bounds

| Measurement | Upper-bound value |
|---|---:|
| Canonical proof | 340,490 bytes |
| Verifier bytecode total | 606,863 bytes |
| Redeem bytecode total | 615,663 bytes |
| Unlocking bytecode total | 957,161 bytes |
| Maximum verifier | 9,383 bytes |
| Maximum redeem | 9,435 bytes |
| Maximum unlocking | 9,710 bytes |
| Full script-bearing transaction | 980,292 bytes |
| Remaining consensus space | 19,708 bytes |
| Core verifier roles | 168 |

## Exact qualified artifact

| Measurement | Exact value |
|---|---:|
| Profile | Withdrawal with change, profile 2 |
| Proof bytes | 327,674 |
| Proof SHA-256 | `a786071c0839e5dbcaf235d477c2441268abbc2f5538bb793971110874668d90` |
| Transaction bytes | 967,476 |
| Transaction SHA-256 | `8b7200b5a76ecc0e9ae038a5698d2d33ec884ea54548ccb347dd0d62390aef53` |
| Remaining consensus space | 32,524 bytes |
| Inputs accepted | 168 / 168 |
| Maximum verifier | 9,383 bytes |
| Maximum redeem | 9,435 bytes |
| Maximum unlocking | 9,699 bytes |
| Maximum operation cost | 7,321,148 at `merkle:preprocessed:0` |
| Tightest operation-cost slack | 19,905 at `merkle:interactionGlobal:2` |
| Quotient degree | 786,433 |
| Observer carrier union | Exact |
| Protected-trace recovery | False with seal |
| Masking ablation recovery | True when seal removed |

## Soundness worksheet

| Event | Count or degree | Estimated bits | Status |
|---|---:|---:|---|
| QM31 cardinality | Approximately `2^124` | ~124 | Field fact |
| False word permutation | Degree 728,097 | 104.52 | Algebraic bound |
| Word-product zero denominator | At most 786,432 terms | 104.41 | Algebraic bound |
| False lookup identity | At most 1,945,961 terms | 103.10 | Algebraic bound |
| Lookup zero denominator | At most 1,945,961 terms | 103.10 | Charged separately |
| Public-boundary identity | 34 terms | 118.91 | Algebraic bound |
| Public-boundary denominator | 34 terms | 118.91 | Algebraic bound |
| AIR Horner cancellation | Degree at most 24 | 119.41 | Algebraic bound |
| Oracle-batch cancellation | Degree at most 26 | 119.29 | Algebraic bound |
| FRI/query/grind | `28 × (4−1) + 20` | 104 | **Conjectural** |
| SHA-256 collision | Classical ROM | 128 | Model assumption |
| Conservative named-event union | Sum of named probabilities | Above 101.37 | Classical ROM; includes conjectural FRI row |
| Constitutional floor | At least 100 classical bits | Cleared conditionally | Construction requirement |

## Zero-knowledge claims

| Layer | Exact claim |
|---|---|
| Algebraic opening view | Perfect honest-verifier zero knowledge conditioned on nonzero denominators |
| Bad-denominator event | Statistical distance below `2^-102.61` |
| SHA-256 Merkle commitments | Computational hiding/binding in classical random-oracle model |
| Fiat–Shamir artifact | Computational ZK in classical programmable ROM |
| QROM Fiat–Shamir | Unresolved |
| Post-quantum collision security | Not claimed |
| Quantum statement | No known polynomial-time quantum break under stated assumptions |
| Observer test | Evidence for data flow, not substitute for simulator theorem |

## Adversarial qualification

| Mutation or attack | Result |
|---|---|
| False public statement | Rejected |
| Altered original opening | Rejected |
| Altered interaction opening | Rejected |
| Altered quotient/FRI-mask row | Rejected |
| Altered AIR composition | Rejected |
| Altered FRI root | Rejected |
| Altered FRI fold | Rejected |
| Altered final coefficients | Rejected |
| Altered transcript stage | Rejected |
| Altered query schedule | Rejected |
| Altered public-boundary inverse | Rejected |
| Sparse-nullifier replay | Rejected |
| Sparse-nullifier path mutation | Rejected |
| Changed carrier position | Rejected |
| Changed carrier role | Rejected |
| Changed slice length | Rejected |
| Changed proof byte | Rejected |
| Non-canonical proof encoding | Rejected |
| Raw protected trace recovery | Not found in sealed artifact |
| Recovery after seal removal | Successful, confirming the ablation |

## Mechanisms deleted from v15

| Removed mechanism | Status |
|---|---|
| Raw `openShaBit` openings | Deleted from product path |
| `occupancyBoolShardsFromNote` | Deleted |
| `FriAuth` note/path serialization | Deleted |
| Witness OTP in consensus proof | Deleted |
| Public-derived privacy masks | Deleted |
| Duplicate trace roots | Deleted |
| Note-aware carrier builder | Deleted |
| Quotient decomposition | Deleted |
| Quotient padding | Deleted |
| Independent query schedules | Deleted |
| Density ballast | Deleted |
| Dummy size bytes | Deleted |
| Historical FRI11 imports | Forbidden by product import audit |

## Implementation pins

| Component | Version or pin |
|---|---|
| Node.js | `>=20.10` |
| TypeScript | `5.8.3` |
| `tsx` | `4.20.3` |
| `@bitauth/libauth` | `3.1.0-next.8` |
| `cashc` | `0.14.0-next.4` |
| `nostr-tools` | `2.15.0` |
| Rust toolchain | `nightly-2026-01-15` |
| STWO | Commit `826591c6c371376810ca8213b5812d5daf6d5092` |
| STWO use | Circle-domain/FFT prover APIs only |
| Default STWO hash/transcript | Not adopted |
| Prover implementation | Rust |
| Reference/VM implementation | TypeScript and libauth |
| Artifact network | Offline Chipnet configuration |

## Published self-contained export

| Parameter | Value |
|---|---|
| Folder | `circle-fri-qm31-t262144-b16-q28-g20-fri9-localword-v15` |
| Manifest schema | `shieldkit.local-word-v15.export/v1` |
| Exported files | 115 |
| Exported source bytes | 1,467,754 |
| Product import graph | 50 reachable files |
| Forbidden historical imports | 0 |
| Git commit | `3d86ec80cbe683aa3d5ec2284b2aea7010fd0eb4` |
| Export typecheck | Passes |
| Export focused tests | 76 / 76 |
| Source-focused v15 suite | 81 / 81 recorded |
| Cargo release check | Passes |
| Dependencies/build output | Excluded |
| Wallet/RPC/broadcast code | Excluded |
| Raw proof/transaction binaries | Excluded; hashes and meters retained |
| Secrets/WIF/RPC credentials | Excluded |

## Remaining limitations and gates

| Item | State |
|---|---|
| Chipnet mining | Not performed |
| Mined byte-for-byte verification | Pending |
| Reusable verifier-bank lifecycle | Not demonstrated on-chain |
| FRI 104-bit row | Conjectural |
| QROM zero knowledge | Unresolved |
| Standard P2P relay | Not supported |
| Mainnet | Forbidden |
| Deposit input count documentation | Must clarify 169 versus 168 core verifier inputs |
| Full historical test suite | Deliberately skipped |
| Full source TypeScript check | Ten inherited errors in seven excluded historical files |
| Construction-changing edits | Require new ID, keys, proof, transaction, and complete requalification |
| Completion authority | Human user only |

## Canonical sources

- [`RULES.md`](RULES.md): constitution and product boundary.
- [`COMPLETENESS.md`](COMPLETENESS.md): numbered relation and consensus checks.
- [`ZK-MEMBRANE.md`](ZK-MEMBRANE.md): exact privacy experiment and simulator boundary.
- [`SUCCESSOR-CONSTRUCTION.md`](SUCCESSOR-CONSTRUCTION.md): frozen v15 construction.
- [`ARGUMENT.md`](ARGUMENT.md): construction identity and security worksheet.
- [`STATUS.md`](STATUS.md): measured qualification status.
- [`src/chain/local-word-role-manifest.ts`](src/chain/local-word-role-manifest.ts): ordered verifier roles.
- [`src/chain/local-word-carrier-allocation.ts`](src/chain/local-word-carrier-allocation.ts): canonical proof-byte weights.
- [`src/chain/local-word-envelope.ts`](src/chain/local-word-envelope.ts): transaction-shape reference semantics.
- [`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/): exact artifact hashes and meters.
