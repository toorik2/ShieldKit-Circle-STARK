import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hash256 } from "@bitauth/libauth";
import { compileCovenantSuccessor, measureGenesisAndSuccessor } from "../src/chain/covenant-spend.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { decodeFriProof, encodeFriProof, proveFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import {
  compilePoolCovenant,
  p2sh32Unlocking,
  poolLockP2sh32,
} from "../src/chain/covenant-p2s.ts";
import { compileNoteMerkleWalk } from "../src/chain/note-merkle.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodeAirPacked, SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { FOLD_KERNEL_COUNT_CONSENSUS, FOLD_QUERIES_PER_KERNEL, foldKernelCount } from "../src/chain/fold-kernel.ts";
import { evaluateBch2026, evaluatePoolSuccessorVm, evaluateWrongFoldIndex } from "../src/chain/vm-verifier.ts";

describe("covenant five-point compile", () => {
  it("signs P2S and P2SH32 genesis plus a P2SH32 successor under envelope limits", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const proof = encodeFriProof(proveFri(d.statement, wDeposit(note, d.index, d.path)));
    const sizes = measureGenesisAndSuccessor(d.machine.state, w.machine.state, proof);
    assert.ok(sizes.genesisP2sh32.txBytes <= 100_000);
    assert.ok(sizes.genesisP2s.txBytes <= 100_000);
    assert.ok(sizes.successorP2sh32.txBytes <= 100_000);
    assert.ok(sizes.genesisP2sh32.unlockingBytes <= 10_000);
    assert.ok(sizes.successorP2sh32.unlockingBytes <= 10_000);
    assert.notEqual(sizes.genesisP2sh32.lockP2sh32Bytes, sizes.genesisP2sh32.lockP2sBytes);
    assert.equal(sizes.genesisP2sh32.lockKind, "p2sh32");
    assert.equal(sizes.genesisP2s.lockKind, "p2s");
    assert.ok(proof.length > 100);
    assert.equal(sizes.successorP2sh32.proofSlotBytes, 0);
    assert.ok(sizes.successorP2sh32.txBytes > 10_000, "successor must carry sharded FRI, not a 1 KB stub");
    assert.ok(sizes.successorP2sh32.txBytes <= 100_000);
    assert.equal(SLOT_KERNEL_COUNT, 4, "standard path pins 4 R-slot kernels to stay ≤ 100 KB");
    const redeem = compilePoolCovenant();
    assert.ok(redeem.length > 40);
    assert.notEqual(redeem[0], 0x6a, "pool redeem is not an OP_RETURN stub");
    assert.ok(compileNoteMerkleWalk().length > 10);
  });

  it("successor unlocking carries packed PAA1STMT when given the statement", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const measured = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(w.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      lockKind: "p2sh32",
    });
    assert.ok(Buffer.from(measured.raw).toString("hex").includes("50414131"), "successor must embed public PAA1");
    assert.equal(Buffer.from(measured.raw).toString("hex").includes("5041413153544d54"), false, "full PAA1STMT preimage stays off the unlocking");
    const rawHex = Buffer.from(measured.raw).toString("hex");
    assert.equal(rawHex.includes(Buffer.from(note.rho).toString("hex")), false, "spent rho must not appear in successor");
    assert.equal(
      rawHex.includes(Buffer.from(note.ownerSecret).toString("hex")),
      false,
      "owner secret must not appear in successor",
    );
    assert.ok(measured.txBytes <= 100_000);
    assert.ok(measured.unlockingBytes <= 10_000);
  });

  it("consensus envelope: 36 slot kernels stay under 1 MB and each unlocking ≤ 10 KB", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const measured = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 1_000_000 },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(w.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      note,
      change: w.created?.note,
    });
    assert.ok(measured.txBytes <= 1_000_000, `consensus tx ${measured.txBytes}`);
    assert.ok(measured.unlockingBytes <= 10_000);
    assert.ok(measured.txBytes > 10_000);

    const redeemStd = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT });
    const redeem36 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.notDeepEqual(redeemStd, redeem36, "36-slot redeem must differ from the standard-path redeem");
    const lock36 = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.deepEqual(lock36.subarray(2, 34), hash256(redeem36), "P2SH32 lock must commit the 36-slot redeem");
    const packed = encodeAirPacked(w.statement, decodeFriProof(raw));
    const unlockStd = p2sh32Unlocking(undefined, packed, { slotKernels: SLOT_KERNEL_COUNT });
    const unlock36 = p2sh32Unlocking(undefined, packed, { slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.notDeepEqual(unlockStd, unlock36);
    const hashFail = evaluateBch2026(lock36, unlockStd);
    assert.equal(hashFail.accepted, false, "standard-path redeem must fail HASH256 against the 36-slot lock");
    const rawHex = Buffer.from(measured.raw).toString("hex");
    assert.ok(rawHex.includes(Buffer.from(redeem36).toString("hex")), "consensus successor must push the 36-slot redeem");
    assert.equal(
      rawHex.includes(Buffer.from(redeemStd).toString("hex")),
      false,
      "consensus successor must not push the standard-path redeem",
    );
  });

  it("honest 36-slot consensus successor VM-accepts against the 36-slot lock", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const vm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change: w.created?.note,
    });
    assert.equal(vm.accepted, true, vm.error ?? "honest 36-slot successor must VM-accept");
    assert.ok(vm.unlockingBytes <= 10_000);
    assert.equal(foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS), FOLD_KERNEL_COUNT_CONSENSUS);
    assert.equal(FOLD_KERNEL_COUNT_CONSENSUS * FOLD_QUERIES_PER_KERNEL, 36);
  });

  it("wrong FS index on folded query 10 is rejected on the 36-fold lock", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const bad = evaluateWrongFoldIndex({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      queryIndex: 10,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change: w.created?.note,
    });
    assert.equal(bad.accepted, false, "query-10 wrong index must fail on 36-fold lock");
  });
});
