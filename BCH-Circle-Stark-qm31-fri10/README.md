# BCH Circle STARK — QM31 FRI10

One family. One standard May-2026 BCH transaction.

```
vk = circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
```

`RULES.md` is hashed into that string. Edit the rules, it is a different family.

Occupancy: **B = M31** (circle, Merkle, qTable, layer-0). **F_fri = QM31** (λ, layers 1–6, final). **H = SHA-256**.

Chipnet Electrum: [`60d186de…`](https://chipnet.imaginary.cash/tx/60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4) — 99 043 B, 18 in / 2 out, leftover bind layers 0–6, padSum 0.

This folder is the product. Field ~124 bits; query worksheet 128 is speculative. RULES §6 / §7 are not this object.

## Run

```bash
npm ci
npx tsx src/cli.ts vk
npx tsx src/cli.ts prove
npx tsx src/cli.ts measure
npx tsx src/cli.ts inspect artifact/chipnet-successor.hex
npm test
```

`land` needs a funded Chipnet wallet in `.local/` (`cli.ts wallet new`). Never mainnet.
