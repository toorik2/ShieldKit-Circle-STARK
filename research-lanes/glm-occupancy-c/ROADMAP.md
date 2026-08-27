# Roadmap: four increments after the 10-fold Chipnet land

Scoreboard: [`STATUS.md`](STATUS.md). Lands: [`MILESTONE.md`](MILESTONE.md).

## Now

Chipnet Circle-FRI shielded covenant. ZKP plugin hook is **off-chain + registry**: default `circle-fri-m31`, second family `hash-lab-v0` on the same statement (`hash-lab-v0` is not private or sound). On-chain redeem is still Circle fold/C=QZ. Internal hash is a drop-in knob (default SHA-256, BLAKE2s and Poseidon2-M31 alternates). Poseidon2-M31 is prover-side only (toorik Grain t=16; ePrint 2023/323). Monolith is not shipped. On-chain `OP_SHA256` is the SHA-256 backend of the default knob, not a second tree. Opt-in batch-exit: shared round; first waiter samples CSPRNG-uniform seconds in [30, 180] (knobs `--batch-min`/`--batch-max`; `--batch-window` pins); CLI countdown; N-payout successor (every lock+value HASH256-bound). Fee coin sized to the fee; leftover treasury is not the successor change. CashVM on B walks note Merkle + nullifier + amount/auth; A does not. Batch-exit extra notes stay in `verifyFri`. Latest lands: standard `23fd1b7d…` (**79525 B**) and consensus `9362df54…` (**283992 B**). Pool UTXO sats = `STATE_BASE` dust + outstanding reserve (public TVL). CHIP 2025-05 EC ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) is later-if-lands for Pedersen/BP; this lab does not wait on it. Not better-than-XMR, Zcash, Voidify, or Tornado Cash. SHA-256 as the internal hash does not change that.

## Next, in order

1. **36 on-chain folds** — lock+VM+measure done (382203 B). Chipnet land `b1415faf…` height 319402. `18c74b49…` remains the 10-fold land.
2. **Conservation on chain** — done (`4414ff3`). seq+1 and reserve-field=0 on the lock; leak test on successor hex. Hidden reserve **value** residuals stay in `verifyFri`.
3. **Replace Pedersen** — done. Production path is tagged SHA-256 (`hash-commit.ts`), bound in `checkAuthRelation`. `encodeStatement` hiding-commits the public net and reserve (`PAA1-HASH-NET-v1` / `PAA1-HASH-RSV-v1` + blind32). Pedersen remains a comparison plugin. Not Bulletproofs/Orchard.
4. **Statistical ZK** — published preimage OTP; slot kernels evaluate \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) (SHA-256; Z FS-bound; off-domain as 2024/1037; deg 7 / 35) and check `(qTable−R)·Z` against AIR N from T. Fiat–Shamir rejection-samples 36 unique first-fold orbits (`FRI_VERSION` 8). Consensus high-index kernels density-pad unlocking; standard A is 4 R-slots. Pool TVL is public (`STATE_BASE`+reserve). CHIP 2025-05 ([BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)) Pedersen/BP is later **if it lands**. Not a Lean HVZK theorem.

Each increment: tests + measure + honest docs + commit + push `@ABLalgorithm` (origin and upstream), then stop and start the next.

Envelopes: **A** 100 KB (1 fold + 4 R-slots), **B** 1 MB 36-query R + grind + algebraicC + remaining folds + pair-blob bind + note-auth, **C** extra fold/R slices (18×2) + pay hop = B. Dummy cargo is not the verifier (`packTo` 0). Density pad is the VM meter. Chunk across 10 KB inputs. CLI `--envelope a|b|c`. Chipnet only. JSON-RPC for B. C is sequential parent-then-child, not Core 1p1c.
