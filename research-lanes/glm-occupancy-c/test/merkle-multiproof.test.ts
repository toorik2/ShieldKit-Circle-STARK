import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import {
  buildLayerProofs,
  layerProofBytes,
  walkCompact,
} from "../src/chain/merkle-multiproof.ts";

describe("unique-sibling Merkle multiproof", () => {
  it("JS walk of compact paths matches every opening root", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const openings = collectFriOpenings(proof);
    const layers = buildLayerProofs(openings);
    assert.equal(layers.length, 7);
    let payload = 0;
    for (const layer of layers) {
      const root = proof.layerRoots[layer.layer]!;
      assert.ok(layer.openings.length >= 3);
      for (const o of layer.openings) {
        assert.equal(
          walkCompact(o.left, o.right, o.compactPath, layer.table, root),
          true,
          `layer ${layer.layer} slot ${o.slot}`,
        );
      }
      payload += layerProofBytes(layer).totalPayload;
    }
    const naive = openings.reduce((n, o) => n + 8 + o.parentPath.length * 33, 0);
    assert.ok(payload < naive, `compact ${payload} >= naive ${naive}`);
    console.log(`merkle payload compact=${payload} naive=${naive} save=${naive - payload}`);
  });
});
