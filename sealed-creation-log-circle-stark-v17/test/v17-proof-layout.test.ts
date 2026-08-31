import assert from "node:assert/strict";
import test from "node:test";
import {
  V17_PROOF_FIXED_PREFIX_BYTES,
  V17_PROOF_OPENING_BODIES_OFFSET,
  V17_PROOF_PROTOCOL_ID,
  assertV17GeneratedProofLayout,
  v17ProofFrame,
  v17ProofFrameEnd,
  v17ProofFrameOffset,
} from "../src/backends/circle/v17-proof-layout.ts";
import { V17_CONSTRUCTION_GRAPH } from "../src/construction/v17-graph.ts";

test("the production proof layout is exactly the graph-generated layout", () => {
  assert.doesNotThrow(assertV17GeneratedProofLayout);
  assert.equal(V17_PROOF_PROTOCOL_ID.length, 32);
  assert.equal(v17ProofFrameOffset("oodValues"), 858);
  assert.equal(v17ProofFrame("oodValues").itemCount, 98);
  assert.equal(v17ProofFrame("queries").itemCount, 44);
  assert.equal(v17ProofFrameEnd("openingDirectory"), V17_PROOF_OPENING_BODIES_OFFSET);
  assert.equal(V17_PROOF_FIXED_PREFIX_BYTES, V17_CONSTRUCTION_GRAPH.proof.dynamicTail.offsetBytes);
});
