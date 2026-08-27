# Status (inherited parent log — not this lane’s product)

**This lane’s constitution is [`RULES.md`](RULES.md). No vk yet.** See [`ARGUMENT.md`](ARGUMENT.md), [`GOAL.md`](GOAL.md), [`START.md`](START.md).

This lane (`glm-occupancy-c`) was copied from `research-lanes/sha-in-occupancy-c` at **`e0b0de3`** on 2026-08-27. The live lock state at the fork: fused N = leftover L0 C(z) + 36 leftover-z `C_SHA` evals (144 B, grind-bound `hashBitRoot`); honest accepts; mixed occupancy leftover + occupancy packed VM-rejects fused input 12; six-query fold density miss recorded; 100 kB off (packing suspended until gates 1–6 green). See [`START.md`](START.md).

The text below is the **parent freeze tree’s** status as copied on 2026-08-23 (and inherited through `sha-in-occupancy-c`). It describes vk `circle-fri-m31-t64-b16-q36-g20-fri9` (M31, preimage-in-unlocking). That freeze is evidence. It is **not** B under RULES.md.

---

# Status (2026-08-21, parent)

**Parent argument freeze (evidence):** `survey/artifacts/argument-freeze/` (`circle-fri-m31-t64-b16-q36-g20-fri9`). Pre-patch Chipnet `56be9ac0…` is not that freeze.

**Pre-release.** Off-chain TypeScript prover/verifier + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
Merkle-walk packed openings. Default spend **A** is **100 KB relay** with **4**
R-slots (`(q−R)·Z = C(z)`, honest C = 0). Envelope **B** is one consensus tx ≤ **1 MB**
(unlockings still ≤ 10 KB) with **36** unique-orbit folds + **36** R-slots,
grind, algebraicC, remaining FRI layers, pair-blob Merkle bind, note-auth kernel. Envelope **C**
is that work **chunked to stay standard**: 19 txs, every hop ≤ 100 KB, so the chain
relays on public Electrum with no JSON-RPC. Tape hops are real fold/R-slot slices
(18×2 queries, 82814–87572 B each), not dummy cargo and not a cross-tx accumulator;
the pay hop is standard (4 R-slots, 89338 B), **not** the 36-slot consensus spend it
used to be. The pay hop still carries **B's completeness kernels** — bind-T, grind,
algebraicC, and the **note-auth kernel** (note Merkle + nullifier + amount/auth);
`landC` funds it with `forceNoteAuth` and threads the opened note, so note/nullifier
completeness is **not** back in `verifyFri` for C. What differs from B is binding,
not completeness: B runs 36 R-slots in one tx, C runs 4 on the pay hop with 32 orbits
across tape hops, so C has no 36 **same-tx** binds. Skip-tape still rejects the pay tx. `packTo` defaults to **0**. 99 KB packing is not the verifier.
Density pad on high-index FS kernels is the 2026 VM meter, not leftover-fill.
BCHN still takes one tx at a time (no Core 1p1c blob). CLI: `--envelope a|b|c`.

**Milestones:** see [`MILESTONE.md`](MILESTONE.md). Compile size (not a land):
A **87611 B**, B **498398 B**, headroom **501602 B** unused; C 19 hops, max
**89338 B**, total **1659128 B**. On `FRI_VERSION` 9: **A** `614b7077…` (**87470 B**, Electrum) and **B**
`81bb2cef…` (**498398 B**, JSON-RPC into the Start9 BCHN mempool; public
Electrum does not carry it) both landed 2026-08-21. **C** landed the same day: 19 chunked standard txs (18 tape + pay
`06a6078a…`), total 1662420 B, all on public Electrum, with every hop bound to
`hash256(proof)` by the counted tip covenant. Older-kernel lands stay as they are: **A** `05f17bf1…`
(82365 B), **B** `b6818bd2…` (479356 B, JSON-RPC), **C** tape `6d242fee…`/
`ec4cd5b3…` + pay `6f9fd1d0…`. Do not relabel `b6818bd2`. Standard `--envelope a`;
consensus `--envelope b`; chained `--envelope c`.

Published note preimage is one-time-padded **in the proof**. It is NOT hidden on chain: the note-auth kernel's unlocking pushes amount, rho and owner in the clear, so anyone can recompute `leaf = SHA256(amountCommit||rho||owner)` and match it to the deposit that published that leaf. **Any note walked on chain has anonymity set 1.** That applies to B and C's pay hop as landed, and an on-chain batch multiplies it by N. Envelope A avoids it only by not walking notes. Verified in `test/onchain-privacy.test.ts`. **Not** a Lean theorem, **not** mainnet, **not** better-than-XMR, Zcash, Voidify, Tornado Cash, or StarkWare-as-theorem. CashVM pays **one `OP_SHA256`**; Poseidon2-M31 is a prover-side InternalHash table entry (Grain t=16 RF=8 RP=14); Monolith is not shipped. Neither is a lock opcode. **Fast withdraw is the default.** Public payouts snap to buckets (1e8…1e3 sats); leftover is a change note in the same set. Each slice is a new HD P2PKH (`m/44'/145'/0'/0/i`); address reuse is rejected. Opt-in **batch-exit** is a shared round: first waiter samples CSPRNG-uniform seconds in `[--batch-min, --batch-max]` (default 30..180); `--batch-window` pins a fixed length. Later opt-ins wait the remaining time on that clock. At close, one successor pays each waiter to that waiter's P2PKH. CLI countdown. CashFusion-shaped multi-P2PKH. The redeem HASH256-binds every payout lock+value (output 1 alone when N=1). Fee change is dust to a fresh P2PKH; leftover treasury is split off the fee coin. CashVM on **B and C's pay hop** walks note Merkle + nullifier + amount/auth (preimage in that kernel’s unlocking). **A** still does not. Batch-exit extra notes stay in `verifyFri`. Lab `evaluateOnChainVerify` requires both the lock and JS `verifyFri`. Fiat–Shamir rejection-samples **36 unique first-fold orbits** on FRI_N=1024 (`FRI_VERSION` 9); the query seed binds Newton even/odd so recooking T changes the query index; colliding indices or `i`/`i+N/2` partners are discarded. Consensus fold/slot kernels with index ≥ 4 prepend a dummy unlocking so 2026 density (41+unlocking)×800 covers that unique-orbit loop; unlocking stays ≤ 10 KB. Standard A is **4** R-slots. The shipped lock **requires**
Circle fold kernels that foldPair **1** FS query **each** (2026 VM density: 2+
queries in one redeem exceed ~800×script-length). Standard 100 KB: **1** fold + **4** R-slots.
Consensus 1 MB: **36** folds + **36** R-slots.
On-chain redeem is still Circle fold/C=QZ (plugin switch is off-chain + registry;
`hash-lab-v0` is not private/sound). Language: TypeScript / CashScript / Rust.

## Three resume questions (honest)

| Ask | Shipped bar |
| --- | --- |
| On-chain Circle STARK verifier? | **Yes**, 2026 VM: Merkle (`OP_SHA256`) + foldPair + `C=Q·Z`. Honest successor accepts; false statement / digest-only / dummy membership reject. Not a pairing SNARK. |
| Statistical ZK openings? | **On-chain R, not a Lean HVZK theorem.** Prove/verify and the slot lock use \(R_{\mathrm{on}}(i)+Z(i)R_{\mathrm{off}}(i)\) (SHA-256 coeffs; Z FS-bound; off-domain \(Z_H\cdot R\) as in ePrint 2024/1037). Slot check is `(qTable−R)·Z` against `C(z)`, the algebraicC residual interpolant (`FRI_VERSION` 9); honest C is the zero polynomial, not masked nTable. Not a Lean HVZK theorem. |
| Confidential TX + aggregated pool? | **Notes + OTP + unlinked fee + one set + paying UTXO.** Withdraw is a distinct payout output; `feeUtxo−change` is not the withdraw. Pool sats = `STATE_BASE` dust + outstanding reserve (public TVL, same class as a mixer treasury). PAA1 reserve *bytes* stay zero. Public net/reserve in `encodeStatement` are hiding tagged hashes (`PAA1-HASH-NET-v1` / `PAA1-HASH-RSV-v1` + 32-byte blind). Not Maxwell / not Orchard. CHIP 2025-05 native EC ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is a later Pedersen/Bulletproofs amount-hiding profile **if it lands**; this increment does not wait for it and does not implement EC ops. Not better-than-Voidify or Tornado Cash. Two honest amounts share one Merkle set; spent-nullifier reuse rejects. |

## Script vs consensus: what we can hide

BCH script cannot Maxwell-hide a UTXO value or a miner fee, and it cannot hide
that a covenant UTXO was spent. Those are consensus fields. What we *can* do
inside 10 KB / 100 KB / 1 MB is already (or now) done:

| Observer fact | In-script / in-consensus? |
| --- | --- |
| Pool output = `STATE_BASE` + reserve (public TVL) | **Cannot hide.** Output value is a consensus field. `STATE_BASE` is dust for the NFT carrier, not a substitute for the pot. Needs a value-hiding CHIP (Maxwell / Orchard / Pedersen+BP). CHIP 2025-05 EC arithmetic ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is later **if it lands**. |
| That a successor happened (roots + seq change) | **Cannot hide.** Spending a UTXO is public. Observer sees a pool move, not whose note or how many sats moved *inside* the set. |
| Miner / covenant fee as a BCH amount | **Cannot hide** `sum(in)−sum(out)`. **Withdraw has no user P2PKH fee input** (no relayer). Miner fee is surplus on the FRI kernel carriers. Deposits still need a funder for the net. |
| Public net as Bulletproofs / Orchard ciphertext | **Cannot** (no BP/Halo2 in CashVM; pairing SNARK is the wrong default). **Can** (shipped): hiding tagged hash `H(net \|\| payout \|\| blind32)` plus hiding reserve commits; raw i64 is not a successor field. Not a range-proof ciphertext. |
| Opened FRI view | **Can raise, not a theorem.** Slot kernels evaluate \(R_{\mathrm{on}}(i)+Z(i)R_{\mathrm{off}}(i)\) (SHA-256 coeffs, deg 7 / 35, ePrint 2024/1037-style off-domain, Z FS-bound) and check `(qTable−R)·Z` against `C(z)` (honest C = 0). Opened diffs are not plaintext \(Q\) diffs. Not a Lean HVZK theorem. |

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs \(Q=N/Z\) of the `onChainCells` interpolant (action/digest/roots/seq). Honest \(N\) vanishes on-trace so off-trace \(Q\) is not the zero polynomial. In-memory `verifyFri` (or `viewingKey`) checks the note preimage so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Public `plugin.verify` of the encoded proof checks membership + FRI without the preimage. Amount conservation is `algebraicC(publicCells)` inside `verifyFri`, not in packed T.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): packed T/N/Q interpolate `onChainCells` (action, digest, roots, seq only). Reserves/delta/note limbs are not in that interpolant. On-chain grind, algebraicC, and (on B and C's pay hop) note-auth kernels run on the successor. Envelope A still leaves note/nullifier in `verifyFri`. The other query folds are the 36 consensus fold kernels (standard still has 1). Pool unlocking is packed AIR + redeem (no rho/owner). B’s note-auth input carries the preimage. Inputs 1..10 Merkle-walk packed `layerRoots` at **FRI_N path depth** (8-leaf dummy paths fail), require ≥1 layer-0 opening whose felt is in `qTable`. Input 11 binds Newton `T` to AIR cells and those cells to the statement. Next input(s) foldPair **1** query each (standard: 1 fold; consensus: **36** folds, one kernel per FS query). Remaining inputs run distinct R-slot kernels (slots 0–3 standard, 0–35 consensus) at recomputed Fiat–Shamir indices: `(qTable−R)·Z` equals `C(z)` (honest C = 0). Digest-only, dummy-short-path, dummy-no-L0, dummy-unbound, dummy-consistent, wrong-fold-index (including query 10), and cross-statement packed all fail. Shipped test: 36× slot-0 op-cost exceeds the 10KB density budget. Conservation stays in `verifyFri` — on-chain PAA1 zeros the reserve field. Published `encodeFriProof` one-time-pads rho/owner/amount under an 80-byte viewing key that is not in the encoding. FRI openings and packed Q/N use \(R_{\mathrm{on}}(i)+Z(i)R_{\mathrm{off}}(i)\) (SHA-256 coeffs; off-domain \(Z_H\cdot R\) as in ePrint 2024/1037). Opened diffs are not plaintext Q diffs. Packed nTable is N+R(i)Z. The slot lock evaluates R and checks `(qTable−R)·Z` against `C(z)` (honest C = 0). Not a Lean HVZK theorem. Script cannot hide pool TVL (`STATE_BASE`+reserve) or the miner-fee UTXO. Packed Newton T is not the AIR interpolant (zero coeffs); packed cells carry seq only. That is a published-blob choice, not a drop of AIR: the prover still interpolates `onChainCells` on the circle (\(x^2+y^2=1\)), not classical Lagrange on \(X^N-1\). T-cell and T(action)-1|2 are not c. The slot lock subtracts on-chain R. Not a theorem that FRI openings hide the statement. Not better-than-XMR or Zcash.
- Proof 64310 B, **10 shards**, 252 Merkle openings. Standard successor compile stays ≤ **100000 B**; consensus ≤ **1000000 B**; every unlocking+redeem ≤ **10000 B**. Density stays 1 FRI query per fold redeem. Unique-orbit compile (`pool measure-tx`, `FRI_VERSION` 9, leftover-fill stripped): standard **87611 B**, consensus **498398 B**, chained max hop **89338 B**. Lands on these kernels (2026-08-21): standard `614b7077…` (**87470 B**, Electrum), consensus `81bb2cef…` (**498398 B**, JSON-RPC into the lab BCHN), chained `06a6078a…` pay hop + 18 tape hops (**1662420 B** total, Electrum, tape bound by the counted tip covenant). Prior lands were standard `23fd1b7d…` (**79525 B**) and consensus `9362df54…` (**283992 B**, JSON-RPC). Earlier `f14bff7b…` / `c40f4948…` / `617b1022…` / `b3ea8a75…` / `2acb1196…` / `b1415faf…` / `18c74b49…` / `356630bd…` are not relabeled.
- Any-amount one set; production note amounts are a tagged internal-hash commit (`PAA1-HASH-AMT-v1`, bound in `checkAuthRelation` / `verifyFri`). Internal hash is a drop-in knob: default SHA-256, alternates BLAKE2s and Poseidon2-M31 (same-hash accept, mixed-hash reject). Poseidon2-M31 is the public Grain permutation from [`poseidon2-m31.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/poseidon2-m31.mjs) (ePrint 2023/323), ported to TypeScript `digest()`. It is **not** the four-predicate AIR in [`poseidon2-air.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/poseidon2-air.mjs) / [`algebraic-hash-air.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/algebraic-hash-air.mjs) (TRACE-64 cannot hold ~5112 S-boxes; LDE-only bind). Monolith is not shipped. A later swap (Poseidon2 → Monolith) is a table entry + `digest()`, not a Merkle/FS/note rewrite. On-chain `OP_SHA256` remains the SHA-256 backend of the default knob (not a second tree). CLI `pool withdraw --batch-exit` is a shared round: first waiter samples CSPRNG-uniform seconds in `[--batch-min, --batch-max]` (default 30..180); `--batch-window` pins. Joiners wait the **remaining** time, then one successor pays each waiter to that waiter's P2PKH. The lock HASH256-binds every payout lock+value. Fee change is dust to a fresh address. Pedersen `C=vG+rH` is a comparison plugin only (not PQ, not production). `encodeStatement` writes hiding commits of the public net (`PAA1-HASH-NET-v1`) and of old/new reserve (`PAA1-HASH-RSV-v1`); the 32-byte blind is not in the encoding; public PAA1 cells zero the reserve field. Successor hex does not contain those note amounts, spent rho, or owner. On-chain PAA1 zeros the reserve field and requires seq+1. Reserve **value** conservation (`algebraicC` r0/r2/r3/r6) stays in `verifyFri` — publishing raw reserves would leak. Pool UTXO sats = `STATE_BASE` + outstanding reserve (public TVL). The lock requires output value = input value + public net; withdraw pays a distinct output bound to `HASH256` of its locking bytecode. Successor miner/covenant fee is paid from a **separate funder input** (`feeUtxo − change` ≠ withdraw). `runMixSuccessor` still updates machine reserve, noteRoot, and nullifierRoot.
- ZKP plugin hook: `zkpPlugins` = `circle-fri-m31` (default, sound) + `hash-lab-v0` (lab digest). Plugin switch is off-chain + registry. `hash-lab-v0` is not private and not sound. Same `PoolStatement` for both; cross-family verify rejects. CLI `pool deposit` / `pool withdraw` call the selected plugin. Notes/nullifiers/reserve do not change with family id. On-chain redeem is still Circle fold/C=QZ — not a pairing SNARK, not family-agnostic bytecode in this increment.
- Comparison table in `COMPARISON.md` (checkable axes only).

Batch-exit note walks: `circle-fri-m31-batch` is registered alongside FRI9
(**not** a `FRI_VERSION` bump, so these claims and the 2026-08-21 lands stay
valid). Its published proof carries every spent note's auth, so a verifier without
the witness can run the membership/nullifier/sum checks. On-chain batch note walks
are **built and tested, not shipped**: one transaction can make one nullifier
insertion, so **option A'** spreads N kernels across envelope C's tape hops and
binds the running root into the pool (pre-minted sibling roots, root-pinned tip
chain, `finalNfRoot` covenant pin), wired through `landC(hops, scratch, batchNotes)`
and VM-verified as a 3-note batch with all 18 tape hops passing. FRI9 stays
byte-identical. **No N-note batch has been broadcast** - the claims here are about
compiled and VM-verified transactions, not confirmed ones.
A second kernel, `note-auth-step-kernel.ts`, is built beside the audited one (never
an edit to it): it bakes (R_in, R_out) into the redeem instead of reading them at
index 0, so N coexist in one transaction. That gives **envelope B on-chain batching**
- 3 and 8 note batches verified on the 2026 VM in consensus mode, the covenant
pinning each step by index so none can be dropped or reordered. Room by bytes:
A 14 notes, B 602, C pay hop 12. Not adopted; `FRI_VERSION` stays 9 and FRI9 is
byte-identical. See [`FRI10-BATCH-EXIT.md`](FRI10-BATCH-EXIT.md).

## Not done (honest)

- Full DEEP-ALI / 128-bit algebraic note-tree hash inside the AIR (note tree uses the internal-hash knob, default SHA-256; Poseidon2-M31 is a prover-side table id). Poseidon2 four-predicate AIR **in the lock** is not shipped (TRACE-64 / ~5112 S-box wall; LDE-only bind on `@toorik2`). Monolith is not shipped.
- N-payout lock is shipped (sum + HASH256 of every lock+value; withdrawalCount delta = payout count). Envelope B and C's pay hop walk one opened note + nullifier on-chain; batch-exit extra notes and envelope A still stay in `verifyFri`. Encoded `plugin.verify` sees one auth (OTP-masked amounts).
- A CashAssembly interpreter for non-SHA-256 knob ids. Shipped redeem walks `OP_SHA256`. A blake2s-packed proof will not verify on the current lock.
- More than one FS query folded per redeem (density). Viewing-key delivery / wallet UX. Lean ePrint 2024/1037 HVZK theorem. Slot kernels **do** evaluate \(R\). algebraicC **is** the FRI interpolant now (`FRI_VERSION` 9): C = interpolant(algebraicC residuals), Q = C/Z.
- On-chain **value** hiding of the pool UTXO (now dust+reserve TVL), of the fact a successor happened, or of the miner fee as a BCH amount. Those need a value-hiding CHIP / are public UTXO facts. CHIP 2025-05 native EC ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is a later Pedersen/Bulletproofs profile **if it lands** — not this increment. Public net is a hiding tagged hash, not Bulletproofs/Orchard. Not better-than-Voidify or Tornado Cash.
- 100 faucet-funded Chipnet wallets. VM eval of the same bytecode is the on-chain bar.
- Formal paper proof. Rust worker still speaks the old n=32 wire (optional; TS is shipped).
- On-chain redeem that dispatches `Verify(family, …)` without a Circle-shaped kernel. Groth16 / Goldilocks / WHIR as a second production on-chain verifier.
- OPTN upstream. Merge to `upstream/main` only if both sides agree.

## Chipnet

Lab address stays in gitignored `.local/lab-wallet.json`.

**6-slot 100 KB lock** (Velma 10 KB script+input), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Self-send vout-0 prep | `9a67bb1caf1f52d67d3529c7223582a45800b23b858c9f363bee6df9dc948567` |
| Genesis P2SH32 PAA1 | `1234194d719291b31e9bcfec3cf80885954a8946f8e00fdb0a72438c0048e2f6` |
| 17 verifier-kernel carriers (10 FRI + bind-T + 6 slots) | `5c3d6102eebe58ce8217c1328b2326a24a0b53bc0eabb05293fbe95f614567ca` |
| Mix successor (95172 B, unlocking 2437, 6× C=Q·Z) | `b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f` |

Second 6-slot land (same lock, new mix), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Self-send vout-0 prep | `e42d0adaae8ec89690b90857f7a0ce07c41c3a8d6b4ff1ba372b043dee347826` |
| Genesis P2SH32 PAA1 | `b92f1a952c0a44582bd6b23db557b8b4e300ab78d18705eee4badf676eb6bf03` |
| 17 verifier-kernel carriers | `d65f679cc177fe223fda78f83cfc0cb6eee218403513e5f7ff9a32c9518d8ccb` |
| Mix successor (95172 B, unlocking 2437) | `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1` |

Previous 1-slot lock, Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Genesis P2SH32 PAA1 | `f8d363c0bc0b85e2d41cd76e12abcf1d8f58b06d767f3aa755089cd392273134` |
| 12 verifier-kernel carriers | `f2bd9454598f565ad4e623d5b40e119d0eabd77200fc85ed17af4b7daca6d47b` |
| Mix successor (66555 B, unlocking 2240) | `333701976ed045e778a69b8a11c798ed070c773701aec8093714097426c94be2` |

`b4d66312…` / `8ccad3b8…` still interpolated full `publicCells` into Newton T. `52b46dab…` published the spent preimage.

**36-slot consensus spend landed on Chipnet** after Start9 BCHN `acceptnonstdtxn=1` + local mine. Public Electrum has the raw 270251 B tx:

| Step | txid |
| --- | --- |
| Genesis | `006186da1d496abace49e1f1d8712c3c18d9bf522910aa8fb60b553be374cab5` |
| Kernels | `7a4e685d3bbfc39eb59f0f29ab11e05135eb76111e1c58a4f84ee2d13e32b8ba` |
| Successor (270251 B, 36× C=Q·Z) | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |

Block (3+ conf on local BCHN): `000000001abbed79d00f1d2d3e47c16a62114c40da6f559b6d24b438703636b7`

Public miners will not *relay* a 270 KB tx. This one got in because it was submitted to the lab BCHN mempool and mined. ASICSeer solo is pointed at that BCHN (`bitcoincashd.startos:48332`). Stratum for more hash: `start9oslinux.local:3333` (or `192.168.0.55:3333`), user `bchtest:qrzq5f9ltv70u4su7d40agd4nlnp8qlgqcma6x2tvp`.

**36-fold consensus successor landed on Chipnet** via BCHN JSON-RPC `sendrawtransaction` (not Electrum, not P2P `inv`). Size **382203**, 1+ conf:

| Step | txid |
| --- | --- |
| Prep vout-0 | `ea53c0e26a1cf3800199713c01ff5005c8c2e286df69f9234519a2517d1211ac` |
| Genesis | `169df22d347cfa7d7e2fb42152b83a764a4126a7b04ac05de078575ea4e86714` |
| Kernels | `7ea959b2d976b400f29640c7a218ee4c69c16c40b7ad81fa5d5ca80cbbd9296a` |
| Successor (382203 B, 36× C=Q·Z + **36** folds) | `b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29` |

Block (1+ conf): `0000000000000e4df903b409aee4e31f33210fb13ee75afe6d77691ddfd6c421` height **319402**.

**Prior 10-fold consensus successor** (not the 36-fold land). Local BCHN size **301279**, 59 inputs:

| Step | txid |
| --- | --- |
| Genesis | `2469f87208114473733aee0e02d163901318e760fc8b6973c4cc76b1d475bfab` |
| Kernels | `ef334c4a8d7309cc898031c61a476d9d9b39a3c9e8b99fd79df1c15f077502f0` |
| Successor (301279 B, 36× C=Q·Z + **10** folds) | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |

Block (2+ conf): `0000000026955667a7e7468d40043e66e0d8890bc21f7162a5d8595d02aaceca` height **319278**. Do not relabel `356630bd…` as this fold land.

**Fold-executing standard successor** (1 query fold + 6× C=QZ, 98831 B), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Prep vout-0 | `2a1a0c48e1a9128a466ca08e6e83e813b6002b5c2840736a97f3b34fc654a776` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |
| Successor (98831 B, fold on lock) | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`

Older txs `1973c065…` / `23ec0c8d…` / `86bd413f…` are a previous lock.
