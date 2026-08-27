# Checkable comparison (not a cryptanalysis theorem)

Axes we can measure or cite. This is **not** a proof that Circle FRI is “more sound”
than XMR / Zcash / Aztec / Voidify / Tornado.

| Axis | This lab (any-amount) | Monero | Zcash | Aztec | Voidify | Tornado Cash |
| --- | --- | --- | --- | --- | --- | --- |
| Trusted setup | None (hash STARK / Circle FRI) | None (rings + BP) | Historic Groth16; Orchard Halo2 | Honk / Plonk-ish setup | Groth16 + ceremony | Groth16 + ceremony |
| On-chain verify | BCH 2026 VM: packed AIR + 10 Merkle + bind-T + **1** fold + **6** C=QZ (≤100 KB) or **36** folds + **36** C=QZ (≤1 MB, measured 382203 B). Digest / dummy / wrong-fold-index (incl. query 10) fail. Chipnet 36-fold land `b1415faf…`. Prior 10-fold `18c74b49…`. | Consensus ring/BP | Consensus SNARK | L2 rollup circuits | Solana Groth16 verifier ELF | Ethereum Groth16 verifier |
| Any-amount | Yes (one set) | Yes | Yes | Yes | Nova-style amounts | Classic fixed tickets |
| Amount hiding | **Note** amounts: tagged SHA-256 commit (AIR-bound). **Public net / reserve**: hiding tagged hashes in `encodeStatement` (blind stays off the encoding), not a raw successor i64. **Not** Bulletproofs/Orchard. **Pool UTXO**: public `STATE_BASE`+reserve TVL (same class as a mixer treasury; not Zcash/Monero hidden output value). Withdraw is a distinct payout output. Unlocking does not publish spent leaf / rho / owner / amount preimage. CHIP 2025-05 EC / BCR 1570 is later-if-lands. | Yes (BP) | Yes | Yes | Yes (Nova/Groth16) | No (ticket size public) |
| Anon-set growth | Incremental Merkle (depth 16); mix successor updates noteRoot + nullifierRoot + reserve | Ring size (not a growing set) | Note commitment tree | Note tree | Pool tree | Pool tree per ticket |
| On-chain prover | No (off-chain prove, StarkWare split) | N/A | N/A | N/A | Off-chain | Off-chain |
| Conjectural FRI bits | 128 (`q=36`, `B=16`, grind 20, rate 2/B) | N/A | N/A | N/A | N/A | N/A |

## What we do **not** claim

- A theorem that those systems are less sound.
- Hidden individual note amounts on the UTXO (pool output is public `STATE_BASE`+reserve TVL; PAA1 reserve bytes stay zero). The public net is a hiding tagged hash in `encodeStatement`, not Bulletproofs/Orchard. CHIP 2025-05 / BCR 1570 Pedersen/BP is later **if it lands**.
- 128-bit collision resistance of the 4-limb algebraic mixer used inside the AIR (FRI bits are the worksheet; the note tree is still SHA-256).
- A theorem that the whole STARK is statistically ZK, or better-than-XMR or Zcash (including because the hash is SHA-256). Published note preimage is one-time-padded; unlocking cannot recover rho/owner.
