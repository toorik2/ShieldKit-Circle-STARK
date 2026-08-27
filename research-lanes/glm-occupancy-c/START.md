# Starting artifact (evidence, not the product)

Copied from `research-lanes/sha-in-occupancy-c` at `e0b0de3` (`feat: leftover L0 C(z) fused N plus independent leftover-z C_SHA`).

## The lock state this lane starts from

The equation at leftover z:

\[
C_{\mathrm{occ}}(z)+\gamma\cdot C_{\mathrm{SHA}}(\mathrm{TRACE}(z),\;\mathrm{leaf},\;\mathrm{nf},\;\mathrm{amountCommit})\;=\;Q(z)\cdot Z(z)
\]

- Fused N = **leftover L0 C(z)** of occupancy+SHA leftover FRI **plus 36 leftover-z `C_SHA` evals (144 B**, γ Fiat–Shamir, grind-bound `hashBitRoot` — merkle of the `C_SHA` column, query-independent). Not parked `<0>`.
- Folds bind **leftover-only pairs** (no unlocking pair copies): `bindFoldPairsLeftoverAsm` rebuilds query-major pairs from input 0 leftover. FRI kernels 1–7 merkle-walk.
- Honest path: both terms zero ⇒ N = 0, accepts. `test/r-onchain.test.ts` 12/12 at the pin, including “fused leftover L0 C(z) is N — not parked `<0>`”.
- Mixed occupancy leftover + occupancy packed (victim leaf + attacker nf + garbage amountCommit): JS-fail **and** VM-reject on fused **input 12 `OP_VERIFY`** — the SHA equation, not density, not note-auth 11, not algebraicC 10.
- Recook the 144 B to zeros **without** the zeros-column `hashBitRoot`: dies on **algebraicC grind-bind (input 10)**. Recook the root: grind.
- Six-query fold density miss (~24 over with fused R) is recorded, not golfed.
- **100 kB still off.** That lane’s phase suspended sub-100 kB packing until holes 1–6 are green and the asserting suite passes; this lane inherits that order of work.

| | |
|---|---|
| Occupancy pack | [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) |
| Occupancy Chipnet | `60d186de…` / 99043 B (evidence) |
| HASH_BIT host Chipnet | `5de68272…` / 99144 B / Electrum / padSum 0 / leftover-binds 0–6 (evidence) |
| Parent 91 KB freeze | `survey/artifacts/argument-freeze/` / `58b7df7f…` / 91598 B (evidence) |
| Pins | TRACE 64, blowup 16, q 36, grind 20, FRI 10, B=M31, F_fri=QM31 (~124), H=SHA-256 |
| Lock | 40 B hash-commit trampoline (`DUP HASH256 <digest> EQUALVERIFY` / `DEFINE 0` / `INVOKE 0`) |
| Extra-input SHA AIR meter | 36 × (41 + 576×4 + 9×32) = **94788 B**; occupancy+AIR ≈ 194 kB (wall on that geometry) |

The parent’s evidence ledger (fused-N lineage: leftover-vanish `d0554390…`, shaPubsAcc-N `0b2324fc…`, interpolant-EQUAL-zeros `f2e92ba4…`, dual packed interp+opening 99739 B, algebraicC merkle cargo 100245–101372 B) is inherited as evidence. None of it is B under RULES.md.

## Suite at the fork (measured 2026-08-27, this lane, full log in `.local/suite-full.log`)

- **294 tests / 238 pass / 56 fail — all 56 inherited from `e0b0de3`.** Verified three ways: every non-doc file is byte-identical to the `e0b0de3` archive; the three doc-pin failures (`qm31-artifact`, `qm31-occupancy`, `correspondence-oracle`) were already failing on the parent’s own `e0b0de3` content (live RULES sha `acc9a44a…` ≠ pack pin `de1f4dcf…`; parent ARGUMENT.md lacks the frozen-vk phrases; `FRI_VERSION 9` assertions vs src 10); and the parent lane reproduces `unique-queries` ×2 and `vm-onchain` ×1 identically.
- **`r-onchain.test.ts` 12/12 green** — the fused-N gates the parent shipped (honest `(q−R)·Z==C(z)` accepts; cooked viewing-commit / recooked qTable reject) hold in this lane.
- **Dominant honest wall:** fold **input 12** operation-cost density over by **~17–83 ops** (max 5,402,400; density control length 6753) on the full-successor honest path — the parent’s recorded density miss. Recorded, not golfed.
- The remaining failures are FRI9-era tests asserting superseded behavior (parent’s follow-up `aec5dfa` — “density recorded” — began hardening those in its own tree; this lane’s gate 1–6 suite work subsumes that).

This lane’s first compile carries that fused-N lock toward gates 1–6 green, then sub-100 kB packing of **this** lock. Do not relabel `e0b0de3` as that compile.
