# What the shielded pool actually is

Jason / BCR 1476: **covenant first**, no `OP_CHECKZKP`.
BCR 1724: state cell + `proofBlob` slot.
BCR 1570: Pedersen/Bulletproofs when EC ops exist; hash STARKs do the same job without a CHIP.

The pool is **not a P2PKH address**. It is a self-replicating **covenant UTXO**. P2PKH is only how users fund, take payouts, and pay fees.

## Locks

| Coin | Lock | Why |
| --- | --- | --- |
| **Pool state UTXO** | **P2S** on 2026 Chipnet (program *is* the lock). ShieldKit P1 measured **P2SH32** shells — same covenant, hashed redeem. | Self-replicating. Validates. Does not “call.” |
| **User funding / payout / fee** | **P2PKH** today | Addresses later: Quantumroot (LM-OTS + lock NFT). Not the mixer. |

Cauldron is P2S. Wrap is P2SH. We are the Cauldron *shape* (same-index successor) with a **shielded** statement, not an AMM.

Chipnet lab default for the first broadcast is **P2SH32** (P1-measured shell). P2S compiles and measures in the same tree; swap the lock kind when we want the raw program as the lock.

CashTokens genesis is only legal from a parent **vout = 0**. A change output cannot mint a new category (`bad-txns-token-invalid-category`). The CLI self-sends a single-output prep tx when the lab UTXO is not vout 0.

`OP_SIZE` leaves the commitment on the stack. The redeem must `OP_DROP` it or a successor fails with “Extra items left on stack” (first Chipnet cell `0adce2ca…`).

## Five-point successor (every pool spend)

Output 0 must keep:

1. locking bytecode (P2S / P2SH32 redeem)
2. token category
3. satoshis = `STATE_BASE` + outstanding reserve (dust NFT carrier + public TVL; PAA1 reserve bytes stay zero)
4. fungible token amount `0`
5. new 128-byte commitment (`PAA1` any-amount, or `PAF1` Fv1 ticket)

Layla (2026-05-15) made NFT commitments **128 bytes**. That is why `PAA1` is 128 bytes, not a 40-byte hash of the state.

The continuing lock is five-point **plus** required kernel inputs. Standard
4-slot path (100 KB, R on-chain): inputs 1..10 SHA-256 paired-Merkle FRI at FRI_N path depth,
input 11 bind-T, grind, algebraicC, input fold (1 query), then 4 slot kernels
`(q−R)·Z = N` from T. Consensus 36-slot path: same prefix, then
**36** fold kernels (one per FS query) and **36** R-slot kernels. Prior Chipnet 10-fold land was 59 inputs / 301279 B. Unlocking of the pool input is the packed AIR
(FS digest + public PAA1) plus redeem — not spent-leaf/rho/owner/`publicAmountSats`.
A spend that is only `OP_RETURN PAA1PROF || SHA-256(proof)` **fails**. Recursion
is not used. The pool UTXO value is `STATE_BASE` + reserve (public TVL, not Maxwell/Orchard). CHIP 2025-05 EC ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is a later Pedersen/BP profile if it lands.

## Why not OP_RETURN (authoring)

`OP_RETURN` is not a covenant and cannot verify. State lives in the **128-byte mutable NFT commitment** (`PAA1`). The readable contract is CashScript (`contracts/PoolCovenant.cash`). The executed redeem is **libauth CashAssembly** (`src/chain/covenant-p2s.ts`, `fri-kernel.ts`, `air-cqz.ts`) because CashScript cannot emit the fused `OP_BEGIN`/`OP_UNTIL` Merkle/FRI/`C=Q·Z` loop. Tx assembly, P2SH32, CashTokens, and `createVirtualMachineBch2026` are libauth. FS query indices are decoded as unsigned BE16 (`OP_BIN2NUM` on a lone high bit is signed).

## Plugins (do not flatten)

| Plugin | Job | Not |
| --- | --- | --- |
| **Circle FRI (internal hash knob)** | Membership, nullifier, transition. Default SHA-256 (CashVM). BLAKE2s and Poseidon2-M31 (prover-side) alternates. Hash STARK. PQ family. | Addresses; Poseidon2 is not a lock opcode |
| **Tagged SHA-256 amount** | Production confidential *note* amounts. Circle FRI binds the commit. | Delivery |
| **Pedersen / Bulletproofs** | Comparison-only (BCR 1570). Discrete-log; not production. | Delivery |
| **ML-KEM-768** | Plane B *who* / note packets (BCR 1724). | The covenant |
| **Quantumroot** | PQ *keys* after ECDSA dies. | The pool set |
| **Nostr 44/59/17** | Event bus (CashFusion-style listener). | State |

`Verify(family, vk, statement, proof)` stays the only covenant hook.

## Profiles

- **Fv1** (joint, sealed): 0.1 ticket, public amount, PAF1. Size gate with toorik. Do not widen it on `main`.
- **any-amount** (this workspace): type the number. Note amounts are a tagged SHA-256 commit; the public net and reserve are hiding tagged hashes in `encodeStatement`. Pool UTXO sats = `STATE_BASE` + reserve (public TVL).
- **hidden-amount UTXO**: same covenant + hidden pool output value (later CHIP). Not this increment.

P2PKH is **not** the shielded pool. The pool is the **covenant UTXO**.

## Circle FRI parameters (shipped)

| Item | Value |
| --- | --- |
| Family | `circle-fri-m31` |
| Field | M31 (`2^31-1`) |
| Domain | circle group `x²+y²=1`, generator `(2, 1268011823)`, trace 64, LDE 1024 (`g = [2^21]G`) |
| Queries | 36 + 20-bit grind |
| Blowup / rate | 16 / `2/B` (quotient of the residual interpolant) |
| Fold | Circle FRI fold (2024/278) with `x=0` fallback to `y`; partners are Merkle siblings |
| Binding | **Off-chain** `publicCells`: reserves, delta, action, digest, roots. **On-chain** `onChainCells`: action, digest, roots, seq only (no reserve/delta). |
| `sound` | Worksheet **128 conjectural bits**. Not a Lean theorem. On-chain foldPair is **1** query per kernel (standard 1; consensus **36**). |

An honest deposit or withdraw verifies in TypeScript `verifyFri`. A false reserve, false note commitment, or false nullifier is rejected there. The off-chain FRI target is the residual quotient \(Q=C/Z\). The on-chain lock binds the new `PAA1` cell, walks packed Merkle openings (pair blob = merklized `left||right`), binds Newton `T` to `onChainCells`, foldPairs **1** query per fold kernel through remaining layers (standard: 1 kernel; consensus: **36**), and checks `(qTable−R)·Z` against AIR N from T per R-slot kernel (default **4** slots so A stays under **100 KB**; **36** on B). Unlocking and redeem are **10 KB** after Velma (chunk kernels across inputs; the 1 MB B envelope is headroom). Grind and algebraicC point-checks run as extra kernels. Slot kernels evaluate \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\). Envelope B adds a note-auth kernel (Merkle + nullifier + amount/auth). Envelope A does not. Never mainnet. Amount conservation is algebraicC + UTXO values, not the NFT reserve field (that field is zero). Dummy OP_DROP cargo is not the verifier (`packTo` default 0).

## Confidential amounts

`amountCommitIn` / `amountCommitOut` are 32-byte tagged internal-hash commits (`H(PAA1-HASH-AMT-v1 || amount_i64le || rho)`). Production `H` is SHA-256; BLAKE2s and Poseidon2-M31 are selectable prover-side alternates. `checkAuthRelation` requires them to match the opened note. `encodeStatement` writes hiding commits of the public net (`H(PAA1-HASH-NET-v1 || i64le || payout || blind32)`) and of old/new reserve (`PAA1-HASH-RSV-v1`); the blind is not in the encoding; public PAA1 cells zero the reserve field. That is still a tagged hash, not Bulletproofs or Orchard. `encodeFriProof` one-time-pads rho/owner/amount. FRI openings and packed Q/N add \(R_{\mathrm{on}}(i)+Z(i)R_{\mathrm{off}}(i)\) (SHA-256 coeffs; off-domain \(Z_H\cdot R\) as in ePrint 2024/1037). Not a Lean HVZK theorem. Packed nTable is N+R(i)Z. Slot kernels evaluate \(R\) and check `(qTable−R)·Z` against AIR N from T. Script cannot hide `STATE_BASE` or the miner-fee UTXO (those need a value-hiding CHIP). Packed Newton T is not the AIR interpolant. Pool UTXO sats stay `STATE_BASE`. CashVM Merkle/FS is `OP_SHA256`; Poseidon2-M31 is a table id on the prover, not a lock opcode. The old Pedersen module remains a comparison plugin only. The Poseidon2 four-predicate AIR stays on `@toorik2` (`poseidon2-air.mjs`) — TRACE-64 cannot hold that S-box budget.

**Fast withdraw is the default** (no wait). Public payouts snap to buckets (1 BCH … 1000 sats); leftover stays a **change note** in the same Merkle set. Each slice is a new BIP32 child `m/44'/145'/0'/0/i` (XO P2PKH; address reuse is rejected). `--to` is only for a single-bucket dest. Opt-in **batch exit** (`--batch-exit`) is a **shared round**: the first waiter samples a CSPRNG-uniform length in `[--batch-min, --batch-max]` seconds (default **30..180**). `--batch-window N` pins a fixed length. Later opt-ins wait the **remaining** time on that same clock. At close, one successor pays each waiter to **that waiter's** fresh P2PKH. It is not CashFusion. **Withdraw has no user P2PKH fee input** (no relayer); miner fee is surplus on the FRI kernel carriers. Deposits still need a funder for the net. CashVM on B walks the opened note and nullifier; batch-exit extra notes stay in `verifyFri`. A has no note-auth kernel.

Partial withdraw mints a **new change note**: leftover amount, same `ownerSecret`, **fresh `rho`**, new Merkle index. Reusing `rho` would make `nullifierOf(change) == nullifierOf(spent)` and the next spend dies (`nullifier already used`).

## Chipnet path

1. Lab wallet is P2PKH (`bchtest:q…`).
2. `lab demo --wallets 100` rehearses deposit+withdraw prove/verify locally.
3. `pool measure-tx` compiles P2S genesis, P2SH32 genesis, and a P2SH32 successor; prints byte counts.
4. `pool chipnet-covenant` signs a P2SH32 five-point genesis with a 128-byte `PAA1` NFT (no OP_RETURN). Pool unlocking is packed AIR + redeem. Envelope B adds a note-auth kernel whose unlocking carries the note preimage. Lab `evaluateOnChainVerify` requires both the 2026 lock and `verifyFri`.

## 100-wallet scale

The CLI walks K wallets through deposit, **partial withdraw** (fresh change `rho` + new index), then spend-change, each with Circle FRI prove+verify. One hundred **funded** on-chain wallets is not required while the faucet is captcha-gated.

## What is closed

- DEEP-ALI + 128-bit algebraic membership hash inside the AIR.
- Hidden amounts as EC points on-chain (CHIP 2025-05). Pool UTXO sats stay public.
- Rust worker on the new wire format.
- OPTN addon wired into OPTN upstream.
- ML-KEM Plane B and Quantumroot addresses.

## FAQ

### Packed Newton T vs the AIR interpolant

We still arithmetize with an **AIR** (trace + constraints + residual \(Q=N/Z\) + Circle FRI). The live interpolant of `onChainCells` is **circle-domain** (`interpolateCircle`, ePrint 2024/278): \(f(P)=E(x)+y\cdot O(x)\) on \(x^2+y^2=1\). That is not a switch to classical multiplicative-subgroup Lagrange on \(X^N-1\).

The **packed** Newton even/odd blob in the unlocking is **not** that interpolant (zero coeffs; seq-only cells). Zeroing it is a published-blob choice so evaluating T cannot recover the opening mask. The prover still interpolates the AIR on the circle. Newton divided differences inside `interpolateCircle` are an implementation of the even/odd univariate pieces, not “the AIR is Newton form.”

### Is this sounder than Aztec / Zcash / Monero?

No. SHA-256 as the internal hash does **not** make this lab better-than-XMR or Zcash. No published theorem says that, and a demo accept does not prove it. What we can say honestly:

- Circle FRI is a **hash STARK**: no trusted setup, no pairing curve, PQ *family* (SHA-256 + M31). Aztec (Honk/Plonk-ish) and Zcash (Halo2 / Groth16 history) sit on pairing or discrete-log assumptions. Monero is ring signatures + Bulletproofs, not a membership STARK.
- The **shipped** worksheet is 128 conjectural bits. That is an ethSTARK-style count, not a proof those systems are weaker.
- Pool UTXO sats are public `STATE_BASE` + reserve (TVL). Note amounts are hash-committed; that is not Monero Bulletproofs or Zcash Orchard hiding of output value. CHIP 2025-05 ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is later-if-lands.
- See `COMPARISON.md` for the checkable axes. Do not quote a “better-than theorem.”

### Why Rust?

Toorik’s ShieldKit-SDK `designs/fri` splits **Rust `fri-prover` / `fri-worker`** (heavy prove) from TS CLI/chain. This workspace does the same: TypeScript is the shipped plugin; `crates/circle-fri-worker` is an optional prove worker that emits the same proof bytes so TS `verifyFri` can consume them. n=32 is fast in TS; Rust is there for later larger domains and for a cross-check, not because TS is blocked.

### Why not Fv1 0.1?

Fv1 is the joint **size gate** with toorik (fixed ticket, smaller AIR). It is a better first *measurement*, not the product. The product is one set, any amount (Nova / Zcash / Aztec amounts). Note amounts are hash-committed; the public net and reserve are hiding tagged hashes in the statement (not Bulletproofs/Orchard). Do not widen sealed `PoolActionFv1` on `main`.

### Why a fresh rho on change?

`nullifier = SHA-256(poolInstance || ownerSecret || rho)`. Reusing `rho` on the leftover note makes the change spend the same nullifier as the note you just burned. The machine then throws `nullifier already used` (or `note not in tree` if you also keep the old index). Change keeps the owner, mints a new `rho`, and returns the new Merkle index.

### What is still closed?

On-chain fold of all 36 FS queries (density: 1 query per fold redeem; consensus lands 10). `algebraicC` / reserve conservation on-chain without publishing reserves. Hidden-amount EC on the UTXO. OPTN upstream wiring, Quantumroot addresses, ML-KEM delivery. See `STATUS.md`.

### P2S or P2SH?

Both. Same five-point program. **P2S**: the program *is* the lock (2026). **P2SH32**: `OP_HASH256 <redeem> OP_EQUAL` (ShieldKit P1 shells). P2PKH never holds the pool set.

### Are ML-KEM and Quantumroot the mixer?

No. ML-KEM is Plane B note delivery. Quantumroot is a PQ key vault. Neither is on the covenant `Verify` hook.
