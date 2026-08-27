import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_INTERNAL_HASH_ID,
  INTERNAL_HASH_IDS,
  defaultInternalHash,
  internalHash,
  resolveInternalHash,
  type InternalHash,
  type InternalHashId,
} from "../src/backends/circle/internal-hash.ts";
import { decodeFriProof, encodeFriProof, proveFri, verifyFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, nullifierOf, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { commitAmount } from "../src/amounts/hash-commit.ts";
import { MerkleTree } from "../src/backends/circle/merkle.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function machine(hash = defaultInternalHash()) {
  return {
    state: emptyState(rnd32(), hash),
    notes: new IncrementalMerkle(undefined, hash),
    nullifiers: new NullifierSet(hash),
  };
}

describe("internal hash knob", () => {
  it("default is CashVM SHA-256; blake2s and poseidon2-m31 are real alternates", () => {
    assert.equal(DEFAULT_INTERNAL_HASH_ID, "sha256");
    assert.deepEqual([...INTERNAL_HASH_IDS], ["sha256", "blake2s", "poseidon2-m31"]);
    const msg = new TextEncoder().encode("paa1-hash-knob");
    const sha = internalHash("sha256").digest(msg);
    const blake = internalHash("blake2s").digest(msg);
    const poseidon = internalHash("poseidon2-m31").digest(msg);
    assert.deepEqual(sha, sha256(msg));
    assert.equal(sha.length, 32);
    assert.equal(blake.length, 32);
    assert.equal(poseidon.length, 32);
    assert.notDeepEqual(sha, blake);
    assert.notDeepEqual(sha, poseidon);
    assert.notDeepEqual(blake, poseidon);
    assert.equal(defaultInternalHash().id, "sha256");
  });

  it("same-hash prove/verify accepts; mixed-hash rejects", () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const friIds = INTERNAL_HASH_IDS.filter((id) => id !== "poseidon2-m31");
    for (const id of friIds) {
      const hash = internalHash(id);
      const d = applyDeposit(machine(hash), note);
      const proof = proveFri(d.statement, wDeposit(note, d.index, d.path), { hash });
      const ok = verifyFri(d.statement, proof, wDeposit(note, d.index, d.path), { hash });
      assert.equal(ok.ok, true, `${id} same-hash: ${ok.ok ? "" : ok.reason}`);
      const encoded = encodeFriProof(proof);
      const decoded = decodeFriProof(encoded);
      const pub = verifyFri(d.statement, decoded, {}, { hash });
      assert.equal(pub.ok, true, `${id} encoded same-hash: ${pub.ok ? "" : pub.reason}`);
    }

    const hashA = internalHash("sha256");
    const hashB = internalHash("blake2s");
    const hashC = internalHash("poseidon2-m31");
    const d = applyDeposit(machine(hashA), note);
    const proofA = proveFri(d.statement, wDeposit(note, d.index, d.path), { hash: hashA });
    const mixed = verifyFri(d.statement, proofA, wDeposit(note, d.index, d.path), { hash: hashB });
    assert.equal(mixed.ok, false, "sha256 proof must not verify under blake2s");
    const mixedP = verifyFri(d.statement, proofA, wDeposit(note, d.index, d.path), { hash: hashC });
    assert.equal(mixedP.ok, false, "sha256 proof must not verify under poseidon2-m31");

    const dB = applyDeposit(machine(hashB), note);
    const proofB = proveFri(dB.statement, wDeposit(note, dB.index, dB.path), { hash: hashB });
    const mixed2 = verifyFri(dB.statement, proofB, {}, { hash: hashA });
    assert.equal(mixed2.ok, false, "blake2s proof must not verify under sha256");
  });

  it("selecting the hash changes merkle, note, nullifier, and amount commit together", () => {
    const sha = internalHash("sha256");
    const blake = internalHash("blake2s");
    const poseidon = internalHash("poseidon2-m31");
    const note: Note = { amountSats: 9_000n, rho: rnd32(), ownerSecret: rnd32() };
    assert.notDeepEqual(commitNote(note, sha), commitNote(note, blake));
    assert.notDeepEqual(commitNote(note, sha), commitNote(note, poseidon));
    assert.notDeepEqual(commitAmount(note.amountSats, note.rho, sha), commitAmount(note.amountSats, note.rho, blake));
    assert.notDeepEqual(commitAmount(note.amountSats, note.rho, sha), commitAmount(note.amountSats, note.rho, poseidon));
    const treeSha = new MerkleTree([1n, 2n, 3n, 4n], sha);
    const treeBlake = new MerkleTree([1n, 2n, 3n, 4n], blake);
    const treeP = new MerkleTree([1n, 2n, 3n, 4n], poseidon);
    assert.notDeepEqual(treeSha.root, treeBlake.root);
    assert.notDeepEqual(treeSha.root, treeP.root);
    assert.equal(MerkleTree.verify(1n, 0, treeSha.path(0), treeSha.root, sha), true);
    assert.equal(MerkleTree.verify(1n, 0, treeSha.path(0), treeSha.root, blake), false);
    assert.equal(MerkleTree.verify(1n, 0, treeP.path(0), treeP.root, poseidon), true);
    assert.equal(MerkleTree.verify(1n, 0, treeP.path(0), treeP.root, sha), false);
  });

  it("a third digest object is a table pass-through, not a site rewrite", () => {
    const third = {
      id: "lab-third",
      digest(data: Uint8Array) {
        return sha256(concatBytes(new TextEncoder().encode("PAA1-LAB-THIRD"), data));
      },
    } as unknown as InternalHash;
    assert.equal(resolveInternalHash(third), third);
    assert.throws(() => internalHash("lab-third" as InternalHashId), /unknown internal hash/);

    const note: Note = { amountSats: 7_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(third), note);
    const wit = wDeposit(note, d.index, d.path);
    const proof = proveFri(d.statement, wit, { hash: third });
    assert.equal(verifyFri(d.statement, proof, wit, { hash: third }).ok, true);
    const mixed = verifyFri(d.statement, proof, wit, { hash: internalHash("sha256") });
    assert.equal(mixed.ok, false, "unregistered digest must not verify under sha256");

    const sha = internalHash("sha256");
    assert.notDeepEqual(commitNote(note, third), commitNote(note, sha));
    assert.notDeepEqual(
      nullifierOf(note, d.statement.oldState.poolInstanceId, third),
      nullifierOf(note, d.statement.oldState.poolInstanceId, sha),
    );
    assert.notDeepEqual(commitAmount(note.amountSats, note.rho, third), commitAmount(note.amountSats, note.rho, sha));
    const treeThird = new MerkleTree([1n, 2n, 3n, 4n], third);
    const treeSha = new MerkleTree([1n, 2n, 3n, 4n], sha);
    assert.notDeepEqual(treeThird.root, treeSha.root);
    assert.equal(MerkleTree.verify(1n, 0, treeThird.path(0), treeThird.root, third), true);
    assert.equal(MerkleTree.verify(1n, 0, treeThird.path(0), treeThird.root, sha), false);
  });

  it("shipped src default is SHA-256; poseidon2-m31 is a table entry, not a lock opcode", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const src = join(here, "..", "src");
    const files = [
      readFileSync(join(src, "backends", "circle", "internal-hash.ts"), "utf8"),
      readFileSync(join(src, "backends", "circle", "merkle.ts"), "utf8"),
      readFileSync(join(src, "backends", "circle", "fri.ts"), "utf8"),
      readFileSync(join(src, "pool", "notes.ts"), "utf8"),
      readFileSync(join(src, "amounts", "hash-commit.ts"), "utf8"),
      readFileSync(join(src, "chain", "covenant-p2s.ts"), "utf8"),
    ];
    const body = files.join("\n");
    assert.match(files[0]!, /DEFAULT_INTERNAL_HASH_ID: InternalHashId = "sha256"/);
    assert.match(files[0]!, /id: "blake2s"/);
    assert.match(files[0]!, /id: "poseidon2-m31"/);
    assert.match(files[0]!, /createHash\("blake2s256"\)/);
    assert.match(files[0]!, /digestPoseidon2M31Bytes/);
    assert.equal(/groth16|pairing.?snark|bn254/i.test(body), false);
    assert.match(files[5]!, /OP_HASH256/);
    assert.equal(/OP_POSEIDON/i.test(files[5]!), false);
    assert.match(files[1]!, /InternalHash/);
    assert.match(files[2]!, /resolveInternalHash/);
    assert.match(files[3]!, /InternalHash/);
    assert.match(files[4]!, /InternalHash/);
  });

  it("default prove/verify path stays SHA-256", () => {
    const note: Note = { amountSats: 4_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const w = applyWithdraw(d.machine, note, d.index, rnd32(), 1_000n);
    assert.ok(w.change);
    const inner = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
    assert.equal(verifyFri(w.statement, inner).ok, true);
  });
});
