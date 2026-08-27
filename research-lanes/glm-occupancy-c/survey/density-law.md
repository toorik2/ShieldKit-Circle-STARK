# Density law (fold / R-slot at 0, 4, 18, 35)

Same compiled unlocking as B. Two meters: `createVirtualMachineBch2026(true)` = **standard** (0.5 hash-iter/byte, 192 cost/iter) and `(false)` = **consensus/nonstandard** (3.5 iter/byte, 64 cost/iter). Op-cost budget is always `800 × (41 + unlocking)`.

Isolated one-input evaluation **does not** have sibling packed-AIR / FRI pair-blob inputs, so `accepted` is not the B-successor bar. **Budgets** (opMax, hashMax, densityControlLength) are exact. `operationCost` / `hashDigestIterations` are ops that ran before the script failed on missing context — a lower bound on a full honest run, not the honest total.

Full B successor on this proof:

| meter | accepted | error |
|---|---|---|
| standard=true | false | Unable to verify standard transaction: transaction exceeds maximum standard byte length. This transaction is 498398 bytes, but the maximum standard transaction size is 100000 bytes. |
| standard=false | true |  |

vmMs (both full verifies) = 194097.05

## Isolated (budgets exact; opCost is a fail-path lower bound)

| kernel | idx | unlocking | redeem | std opCost | std opMax | std hashIter | std hashMax | nonstd opCost | nonstd opMax | nonstd hashIter | nonstd hashMax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fold | 0 | 3084 | 3079 | 25564 | 2500000 | 50 | 1562 | 19164 | 2500000 | 50 | 10937 |
| fold | 4 | 6002 | 3171 | 37426 | 4834400 | 51 | 3021 | 30898 | 4834400 | 51 | 21150 |
| fold | 18 | 6002 | 3173 | 37426 | 4834400 | 51 | 3021 | 30898 | 4834400 | 51 | 21150 |
| fold | 35 | 6002 | 3174 | 37426 | 4834400 | 51 | 3021 | 30898 | 4834400 | 51 | 21150 |
| slot | 0 | 5036 | 5030 | 52620 | 4061600 | 80 | 2538 | 42380 | 4061600 | 80 | 17769 |
| slot | 4 | 6002 | 5122 | 59765 | 4834400 | 82 | 3021 | 49269 | 4834400 | 82 | 21150 |
| slot | 18 | 6002 | 5123 | 59764 | 4834400 | 82 | 3021 | 49268 | 4834400 | 82 | 21150 |
| slot | 35 | 6002 | 5123 | 59764 | 4834400 | 82 | 3021 | 49268 | 4834400 | 82 | 21150 |

## In the real B successor (this is the density law)

| kernel | idx | input | accepted std | accepted nonstd | unlocking | std opCost/max | std hashIter/max | nonstd opCost/max | nonstd hashIter/max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fold | 0 | 15 | true | true | 3084 | 1728494/2500000 | 75/1562 | 1718894/2500000 | 75/10937 |
| slot | 0 | 51 | true | true | 5036 | 595910/4061600 | 179/2538 | 572998/4061600 | 179/17769 |
| fold | 4 | 19 | true | true | 6002 | 1884541/4834400 | 80/3021 | 1874301/4834400 | 80/21150 |
| slot | 4 | 55 | true | true | 6002 | 680064/4834400 | 185/3021 | 656384/4834400 | 185/21150 |
| fold | 18 | 33 | true | true | 6002 | 2610818/4834400 | 95/3021 | 2598658/4834400 | 95/21150 |
| slot | 18 | 69 | true | true | 6002 | 1400237/4834400 | 200/3021 | 1374637/4834400 | 200/21150 |
| fold | 35 | 50 | true | true | 6002 | 4391318/4834400 | 112/3021 | 4376982/4834400 | 112/21150 |
| slot | 35 | 86 | true | true | 6002 | 3230976/4834400 | 217/3021 | 3203200/4834400 | 217/21150 |


Redeem sizes: fold0=3079 fold35=3174 slot0=5030 slot35=5123.
