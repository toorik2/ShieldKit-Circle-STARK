# Lane: GLM occupancy C

**Work only here.** Parent lane `research-lanes/sha-in-occupancy-c` (`e0b0de3`, fused N = leftover L0 C(z) + 144 B leftover-z `C_SHA`) is this lane’s starting lock state. Sibling 100 KB HASH_BIT leftover walks live in `research-lanes/ideal-bch-shielded-pool-stark` (`5de68272…` evidence). Sibling 1 MB SHA-AIR-on-own-inputs lives in `research-lanes/nonstandard-ideal-circle-stark`. Parent freeze in `research-lanes/envelope-b-standard` is evidence.

## Named end (only the human declares done)

One Chipnet Electrum transaction that is **B** under [`RULES.md`](RULES.md): one standard May-2026 tx, soundness min(FRI-query, field, SZ, hash-RO) ≥ 100, miner runs every numbered check, Circle FRI + SHA-256, on-chain money relation, leaf↔nf↔amount in occupancy composition C (same 36 queries), unlocking silent (no rho/owner/amount preimage), encoding ≡ spec.

That object does not exist yet. Do not say shielded until §6 holds in script.

## Construction (this lane)

SHA residuals live in occupancy composition C. The miner already FRIs that polynomial at 36 queries; the fused redeem is `(q−R)·Z==C(z)` with N = leftover L0 C(z) plus the independent 144 B leftover-z `C_SHA` evals. Close gates 1–6 on that lock, then pack **this** lock under 100 kB. Do not add 36 extra SHA-AIR inputs (meter **94788 B**). Do not drop q/grind/TRACE. Do not drop the 100 kB box.

A wall is a number (bytes, density, TRACE width), then the next packing. Only the human declares done.

## Starting artifact

Copy of the parent lane at `e0b0de3`: fused-N lock state, honest accepts, mixed VM-reject fused input 12, 100 kB off. Occupancy pack: [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) / `60d186de…` / 99043 B. See [`START.md`](START.md).

## Why this lane exists

The parent lane carried SHA-in-occupancy-C from the HASH_BIT sticker-matching host to the fused-N lock. This lane is the GLM agent’s own tree to carry that same equation the rest of the way: gates 1–6 green, then sub-100 kB packing of this lock, then Electrum — without 36 extra SHA-AIR inputs and without a second machine next to the occupancy verifier.

## vk

No vk string until a construction satisfies every RULES line. Then the vk **includes** the SHA-256 of `RULES.md`. Editing RULES is a new family.

Sibling occupancy vk `circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22` stays that sibling’s name. Do not reuse it here.

## Out of scope as product (controls stay in-tree)

- HASH_BIT leftover merkle/prefix as the money relation
- 36 extra SHA-AIR inputs
- The 1 MB consensus fork
- Relabeling `e0b0de3`, `5de68272…`, `60d186de…`, or the 91 KB freeze as this named end
