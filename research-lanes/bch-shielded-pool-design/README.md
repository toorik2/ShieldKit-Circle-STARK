# BCH shielded-pool design research lane

**Status:** source-mapped; product, proof family, and P0 backend-neutral relation
semantics content-pinned after root/SOL review; P1 semantic machinery complete;
P2 neutral M31 base control measured; four direct-construction certificates,
nonexecutable descriptors, source-set-v1, cohort-freeze-v2, R runtime-binding,
K runner-core, F frozen-inputs, P policy-authority static envelopes, and sealed
cohort-live-executor-v2 are content-bound. The sealed cohort-live-executor-v2
package remains a static, non-authorizing, and unqualified bounded transition
model. The sealed cohort-authority-binding-model-v1 package is a static, non-authorizing, unqualified requirements catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant remains false, retry remains empty/BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. The sealed cohort-external-origin-contract-v1 package is a static, non-authorizing, unqualified external-origin contract catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant and admission remains false, retry remains BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. The sealed cohort-upstream-origin-provider-contract-v1 package is a static, non-authorizing, unqualified provider-requirements catalog only. It authenticates only pinned static bytes and type/catalog relationships; no instances are represented, and every provider, owner, ownerBindingRoot, origin, fact, root, order, projection, and private byte remains unavailable. J remains ownerless and non-authorizing; retry and D remain BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. sealed cohort-upstream-provider-source-map-v1 is a static non-authorizing unqualified source-coverage catalog that classifies all sixteen UOPC interfaces against sixteen pinned source references as exact authoritative type fragments, shape-only references, requirement-only references, or explicitly missing upstream sources; it resolves or instantiates no provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, private byte, authority, admission, guard, runtime, or execution surface. The lane remains unqualified and nonranking.

The sealed gate-b0-execution-admission-contract-v1 integration closes only the static pre-execution prerequisite-catalog stage. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authorities satisfy every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validation prerequisite represented by the closed 30-row catalog and exact 37+7 causal edges. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The sealed gate-b0-static-source-authority-v1 integration closes only the static source-contract-language prerequisite stage beneath the sealed gate-b0-execution-admission-contract-v1. It authenticates 17 source-kind contracts and 2 supplemental contracts, but all 30 EAC provider requirements remain false/zero, unavailable, and uninstantiated. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authority contracts govern and bind the future authorized creation or satisfaction of every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validator prerequisite under the closed EAC grammar; no provider, owner, state, artifact, or runtime instance may be created before that authorization, and static source-contract resolution alone is insufficient. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, result-validator implementation or evaluation, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.
**Scope:** Circle-domain FRI; fixed-ticket deposit/withdrawal; unilateral
spends; one user action per transaction; no user batching
**Non-claim:** the diagram is not a complete or qualified shielded pool

## Bottom line

Telegram photo 7 is fully mapped at the label and connector level. It depicts
an Aztec-inspired private-note state carrier:

```text
private note -> membership/transition witness -> current roots -> next roots
                                                       |
mutable CashToken state UTXO + CEv1 commitment --------+
                                                       |
12 immutable 128-byte packet outputs -> recipient delivery
```

The image is strongest as a **state-carrier and encrypted-delivery prototype**.
It does not draw deposit/import, withdrawal/export, value conservation, range
constraints, batching, a sequencer, lanes, or cross-lane transitions. Those
appear later in the chat and are competing proposals, not properties of the
image.

The Chipnet transaction behind the image is independently resolved as:

```text
be8b9832a2a95bf9b09838cb085bc667e9eedacd2c71ae842289816ca93737b0
```

BCHN confirms its visible transaction shape. Output 0 remains unspent at the
recorded observation, so no proof-bearing transition spend has been
demonstrated by this artifact.

## Lane structure

```text
lane.json                                      lane boundary and promotion gate
sources/telegram-2026-07-29/source-manifest.json
                                               hashes, attribution, selection
sources/telegram-2026-07-29/diagram-transcription.schema.json
                                               literal diagram data contract
sources/telegram-2026-07-29/diagram-11174.transcription.json
                                               boxes, text, connectors, review
sources/telegram-2026-07-29/chain-observation-2026-08-08.json
                                               BCHN/Fulcrum reality check
sources/telegram-2026-07-29/review.md           human-readable triple check
analysis/claim-ledger.json                     claim/evidence separation
analysis/design-options.md                     design conversation frame
analysis/backend-evidence-2026-08-08.md         backend papers/chat/chain triage
spec/pool-config-fv1.json                       immutable deployment requirements
spec/p0-freeze-manifest.json                    root/SOL-reviewed P0 content pin
spec/pool-state-fv1.md                          exact 128-byte state codec
spec/pool-action-fv1.json                       frozen backend-neutral relation
spec/tx-binding-fv1.md                          canonical non-circular tx context
spec/responsibility-map-fv1.json                enforcer and mutation coverage
security/threat-model-fv1.json                  assets, adversaries, gates, PQ boundary
research/circle-fri-candidate-matrix.v1.json    unselected axes and cheap kill gates
research/circle-fri-candidate-matrix.v2.json    typed prequalification field registry
research/field-frontier-contract.md             frozen field experiment representation
security/soundness-worksheet.v2.schema.json     prequalification event-DAG bound contract
p2/field-cert/                                  independent generic certificate replayers
p2/gate-b/equal-relation-experiment.v1.json     blocked equal-kernel experiment contract
p2/lowering-arm-ir-freeze/                     14-arm SSA and 42-plan pre-source authority
p2/source-set-v1/                              canonical source, bytecode, and strict maps
p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1/
                                               CPSB future control-plane grammar package
p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json
                                               outside CPSB review anchor
evidence/cpsb-exact29-sealed-validation-v1/     retained exact29 receipt and checksums
evidence/poolactionfv1-contradiction-capture-v1/
                                               four open PoolAction blocker records
spec/poolaction-relation-disposition-refreeze-v2/
                                               blocked relation-disposition source contract
evidence/measurement-admission-v2/               sealed zero-count admission boundary
evidence/poolactionfv1-refreeze-falsifiers-v1/   inert synthetic regression subset
spec/poolactionfv1-refreeze-falsifier-contract-v2/
                                               blocked v2 source-contract closure
spec/poolactionfv1-refreeze-falsifier-contract-v2-review-anchor.v1.json
                                               outside v2 review-anchor raw pin
research/source-pin-review-2026-08-08.md        exact paper pins and blockers
research/phase-plan.md                          phased model routing and stop gates
bench/primitive-microbench-plan.md              measured BCH experiment order
vectors/pool-action-fv1/index.json              planned valid/adversarial corpus
profiles/*.json                                 current BCH and desktop pins
validate.mjs                                   deterministic lane checks
```

The full `Telegram_export/` is local-only because it contains unrelated
personal material. The lane records only hashes, technical message locators,
forwarding attribution, and scoped paraphrases. Do not copy or publish the raw
export as part of this lane.

## Validation

```bash
node research-lanes/bch-shielded-pool-design/validate.mjs
npm run check
```

## Frozen scope

The selected relation is the existing
`profile:fixed-ticket-serial-pool`:

```text
transparent fixed-ticket deposit
        -> one serial public-state transition
        -> later unilateral withdrawal to ordinary BCH
```

Each action is one complete standard BCH transaction for one ticket and one
user. A proof verifier may be partitioned across several inputs in that same
transaction; that is verifier execution topology, not user batching. A relayer
may broadcast a wallet-built transaction, but cannot be required for proving,
state recovery, or withdrawal.

The selected proof family is **Circle-domain FRI**. No prover stack, field, hash
channel, or verifier implementation is inherited. Stwo and other systems are
prior art only. The research target is a direct custom `PoolActionFv1` AIR and
proof protocol co-designed with BCH, including zero knowledge from the outset;
generic Cairo proving is outside the active design.

The frozen product envelope is:

- one 0.1 BCH (10,000,000 satoshi) ticket;
- an exact 0.1 BCH withdrawal and reserve reduction, with the transaction fee
  funded by a separate transparent input; fee privacy is out of scope;
- 128-bit soundness as the target and 100 bits as the hard floor. If a derived
  128-bit configuration cannot fit one complete 100,000-byte standard
  transaction after measured optimization, research selects the strongest
  fitting configuration at or above 100 bits;
- a local desktop CLI with unilateral proving under 60 seconds on the pinned
  ordinary desktop; mobile, browser, GUI, and required remote proving are out
  of scope; and
- a PQ-oriented proof and private spend path, subject to a component-level
  assumption audit. PQ substitutions may not casually weaken classical
  security, privacy, transaction binding, standardness, or implementation
  assurance, and the project will not call the whole system post-quantum while
  the BCH settlement path retains classical dependencies.

Transferable private notes, multi-user aggregation, K lanes/epochs,
seal-bound JoinSplit, and client-enforced conservation remain preserved as
source history. They are not candidates under the active profile.

P1 canonical codecs, a proof-free semantic oracle, JSON-to-transcript
projection, and deterministic Libauth transaction shells are now implemented
and cross-tested. Their first exact topology result is that, under documented
35-byte P2SH32 fixture-lock assumptions, the per-input 10,000-byte ceiling
scales through eight persistent carriers and the 100,000-byte transaction
ceiling begins binding at nine. This does not select a carrier count or estimate
a Circle-FRI proof. See [P1 evidence boundaries](p1/README.md).

The independent P1 audit passed after its findings were corrected. The current
ZK note is content-pinned; the algebraic-hash source track remains blocked on
the exact current merged XHash-family PDF. P2's neutral M31 fixed-width codec
and base-arithmetic suite passed 3,724 cases across standard Libauth, the real
BCHN Script leg, and LeanBCH. That result selects no extension or proof
component.

The field-role registry is deliberately prequalification-only: it cannot encode
a tuple, and the soundness v2 language cannot encode a qualification pass.
Independent repository replayers and a separately pinned Python/SymPy 1.14
review now pass for the exact M89-d2, M61-d3, M31-d5, and M31-d6 direct
constructions. This establishes each base prime and defining polynomial's
irreducibility only; it is not BCH cost or protocol-selection evidence.

Four additive Gate-B0 v2 descriptors now freeze the direct quotient algebra,
canonical fixed-width codec, parser boundary, arithmetic relations, exact
construction certificate, independent review, and every applicable frozen
formula arm. Lowering-freeze v1 binds the fourteen-arm policy; the validated
content-addressed lowering-arm IR package now realizes it as 28 typed SSA
programs, 19 parser/wrapper modules, and 42 relation-specific symbolic stack
plans. Its complete regenerated authority has 4,806 typed nodes/range rows and
25,098 symbolic instructions/trace rows. Source-set v1 now mechanically emits
the corresponding 42 canonical BCH Script sources, exact bytecode artifacts,
and strict source maps. The source totals 788,958 bytes and the bytecode totals
123,079 bytes across the comparison population; these are descriptive component
artifact sizes, not BCH-VM or transaction measurements. The cohort-freeze-v2
package now binds campaign-v2, canonical-corpus-v2, the fixture roster, one
shared execution-epoch-v2, the normative work-item roster, and four engine
artifact pins. Its exact entrypoints are listed in `lane.json`; its
`MANIFEST.json`, `SHA256SUMS`, schemas, and `COMMAND.txt` provide the
content/raw/schema provenance and deterministic checks. The package contains no
VM results, measurements, selection, ranking, Circle/query work, or prover
evidence. The legacy additive campaign separately freezes
counts, generator semantics, the
M31-d5/M31-d6/M61-d3/M89-d2 cohort, two implementation tracks, four engines,
and artifact-bound run records.

The M89 canonical-schoolbook shakedown is now materialized as component-only
evidence: 266 frozen cases (206 valid, 60 intentional rejects) produced exact
verdict agreement across the native model, standard Libauth VM, real BCHN
Script leg, and LeanBCH. The isolated one-input P2SH32 fixtures were 430--735
bytes; accepted BCHN operation cost peaked at 43,070 with at least 320,069
operation-cost headroom. These are arithmetic-kernel fixtures, not proof-size,
Circle-domain, soundness, prover, or complete pool-transaction measurements.
The run explicitly selects nothing. See the
[content-addressed run](p2/gate-b/runs/m89-d2-schoolbook-shakedown-v1/run.json).

Source-set-v1 and cohort-freeze-v2 remain frozen. R runtime-binding, K
runner-core, F frozen-inputs, and P policy-authority form the complete static,
content-bound prerequisite set. The sealed cohort-live-executor-v2 package is a
static, non-authorizing, and unqualified bounded transition model; it has no
authority to instantiate state inputs, authenticated origins, or ownership.
The sealed cohort-authority-binding-model-v1 package is a static, non-authorizing, unqualified requirements catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant remains false, retry remains empty/BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.
The sealed cohort-external-origin-contract-v1 package is a static, non-authorizing, unqualified external-origin contract catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant and admission remains false, retry remains BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.
The sealed cohort-upstream-origin-provider-contract-v1 package is a static, non-authorizing, unqualified provider-requirements catalog only. It authenticates only pinned static bytes and type/catalog relationships; no instances are represented, and every provider, owner, ownerBindingRoot, origin, fact, root, order, projection, and private byte remains unavailable. J remains ownerless and non-authorizing; retry and D remain BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. sealed cohort-upstream-provider-source-map-v1 is a static non-authorizing unqualified source-coverage catalog that classifies all sixteen UOPC interfaces against sixteen pinned source references as exact authoritative type fragments, shape-only references, requirement-only references, or explicitly missing upstream sources; it resolves or instantiates no provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, private byte, authority, admission, guard, runtime, or execution surface.

The sealed gate-b0-evidence-plan-v1 package is a static, non-authorizing, unqualified evidence-obligation plan bound by an outside-package review anchor; it authenticates only the reviewed 15-file authored closure, its two mechanical envelope files, 35 source pins, and false/zero admission boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider instance, measurement, execution, qualification, ranking, selection, or fallback authority.

The sealed gate-b0-execution-admission-contract-v1 package is a static, non-authorizing, non-admitting, unqualified pre-execution prerequisite catalog bound by an outside-package review anchor; it authenticates only the reviewed 18-file authored closure, its two mechanical envelope files, 64 raw-pinned source leaves with native semantic joins, 30 zero-instance external-requirement rows, 37 retry-prerequisite edges, 7 artifact/result edges, and the exact false/zero boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider, owner, fact, nonce, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution authority.

The sealed gate-b0-static-source-authority-v1 package is a static, non-authorizing, non-admitting, unqualified source-contract-language authority bound by an outside-package review anchor; it authenticates only the reviewed 24-file authored closure, its two mechanical envelope files, 64 raw-pinned transitive source leaves with native semantic joins, 17 closed source-contract records, 2 supplemental source contracts, 30 false/zero requirement-resolution rows, 15 raw-pinned schemas, and the exact false/zero non-authority boundary, and it creates no provider, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

Attempt-001 remains closed. Gate B1, Circle, DEEP, sampler, FRI, and query
implementation remain closed.

No field role, Circle domain, hash, masking scheme, AIR layout, FRI schedule,
carrier count, or final architecture is selected yet. The complete
qualification program is described in
[design-options.md](analysis/design-options.md) and
[phase-plan.md](research/phase-plan.md).

The sealed gate-b0-external-authority-prerequisite-policy-v1 package is a static, non-authorizing, non-admitting, unqualified prerequisite-policy language bound by an outside-package review anchor; it authenticates only the reviewed 21-file authored closure, its two mechanical envelope files, 12 raw-pinned schemas, 15 component digests, 10 policy groups, 2 supplemental policies, 30 false/zero requirement-authority rows, one unresolved UOPC/EAC source collision with selectedDag null, 31 prerequisite-DAG edges, a 6-state/5-edge transition policy with zero authorized transitions, and the exact false/zero non-authority boundary, and it creates no governance authorization, external authority contract, provider binding, principal, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

The sealed gate-b0-external-authority-prerequisite-policy-v1 integration closes only the static external-authority prerequisite-policy-language stage beneath B0_EXECUTION_AUTHORIZATION. The package's current state is AUTHORITY_POLICY_FROZEN_NO_AUTHORITY: its represented SOURCE_LANGUAGE_RESOLVED→AUTHORITY_POLICY_FROZEN_NO_AUTHORITY transition is static policy representation only, all four later transitions are BLOCKED_EXTERNAL, authorizedTransitions is empty, and selectedDag is null. The next B0-R phase-DAG node remains B0_EXECUTION_AUTHORIZATION, but it remains closed. Before it may open, separately authorized external principals must provide independently pinned external authority contracts; an independently reviewed provider-binding catalog; an explicit root/SOL governance authorization that resolves the UOPC/EAC precedence collision; and satisfaction of every closed EAC prerequisite, including the raw-artifact-map and independent-result-validator requirements. This package and this lane integration may not infer, issue, bind, instantiate, or satisfy any of those prerequisites. Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, Gate B1, admission, execution, evidence, qualification, ranking, and selection remain closed.

The CPSB exact29 authenticated sealed static validation authenticates only future control-plane grammar and content-hash ordering for the pinned 27-entry source closure, 29-file sealed package, 18 schema bindings, and 11 future-record schemas, all with zero records. The retained 8,147-byte receipt is `AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY` with authorization `NONE`; it is unsigned and replayable, depends on the external caller and host TCB, is not independent attestation or runtime-readiness evidence, and creates no principal, decision, contract, binding, authorization, instance, admission, attempt, execution, evidence admission, measurement, qualification, ranking, selection, candidate tuple, parameter, field/domain, AIR/FRI/proof/prover progress, or PoolActionFv1 amendment. B0_EXECUTION_AUTHORIZATION, Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The retained PoolActionFv1 contradiction capsule records four open qualification blockers with authority `none` and status `observed-open-blockers-not-a-relation-amendment`: network schema/codec drift, injected context-digest facts, carrier-lock anchor erasure, and proof-session context erasure. They keep Hard Gates 1 and 5 blocked under `cannot-qualify-select-or-begin-full-prover`; the capsule executes nothing and is not a relation amendment or complete transaction witness.

The quiescent `poolaction-relation-disposition-refreeze-v2`, `measurement-admission-v2`, inert v1 synthetic subset, and v2 falsifier source-contract/16-file review anchor form one `BLOCKED_VERSION_PIVOT_NO_REFREEZE` transition only: v2 preserves source-contract integrity while the supervisory-matrix raw file remains absent; it grants no authority, admission, execution, measurement, qualification, ranking, selection, candidate, tuple, role, parameter, or refreeze credit. Hard Gates 1 and 5 and `B0_EXECUTION_AUTHORIZATION` remain closed.
