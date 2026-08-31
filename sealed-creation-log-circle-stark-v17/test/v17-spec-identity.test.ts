import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_NORMATIVE_DOCUMENT_LAYOUT,
  type V17ConstructionGraph,
  v17ProtocolIdHex,
  validateV17ConstructionGraph,
} from "../src/construction/v17-graph.ts";
import {
  assertV17NormativeSpecFiles,
  inspectV17NormativeSpecFiles,
  v17NormativeDocumentSha256Hex,
} from "../src/construction/v17-spec-identity.ts";

const laneRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots: string[] = [];

function temporarySpecRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "shieldkit-v17-spec-"));
  temporaryRoots.push(root);
  for (const document of V17_CONSTRUCTION_GRAPH.normativeSpec.documents) {
    writeFileSync(resolve(root, document.path), readFileSync(resolve(laneRoot, document.path)));
  }
  return root;
}

function withDocumentHash(index: number, sha256Hex: string): V17ConstructionGraph {
  const graph = structuredClone(V17_CONSTRUCTION_GRAPH);
  const documents = graph.normativeSpec.documents.map((document, documentIndex) =>
    documentIndex === index ? { ...document, sha256Hex } : document);
  return {
    ...graph,
    normativeSpec: { ...graph.normativeSpec, documents },
  };
}

function swapFirstTwoDocuments(graph: V17ConstructionGraph): boolean {
  const first = graph.normativeSpec.documents[0]!;
  const second = graph.normativeSpec.documents[1]!;
  return Reflect.set(graph.normativeSpec.documents, "0", second) &&
    Reflect.set(graph.normativeSpec.documents, "1", first);
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("v17 normative specification identity", () => {
  it("binds exactly three ordered opaque UTF-8/LF documents", () => {
    const receipt = assertV17NormativeSpecFiles({ laneRoot });
    assert.deepEqual(
      receipt.documents.map(({ id, path }) => ({ id, path })),
      V17_NORMATIVE_DOCUMENT_LAYOUT,
    );
    assert.equal(receipt.protocolIdHex, v17ProtocolIdHex());
    for (const document of receipt.documents) {
      assert.equal(document.actualSha256Hex, document.expectedSha256Hex, document.id);
      assert.ok(document.bytes > 0, document.id);
    }
  });

  it("forces a new protocol identity for a valid byte mutation of every document", () => {
    const protocolIdHex = v17ProtocolIdHex();
    for (const [index, descriptor] of V17_CONSTRUCTION_GRAPH.normativeSpec.documents.entries()) {
      const root = temporarySpecRoot();
      const path = resolve(root, descriptor.path);
      const original = readFileSync(path);
      const marker = new TextEncoder().encode(`\n<!-- v17 identity mutation: ${descriptor.id} -->\n`);
      const mutated = Uint8Array.from([...original, ...marker]);
      writeFileSync(path, mutated);

      assert.throws(
        () => assertV17NormativeSpecFiles({ laneRoot: root }),
        new RegExp(`hash drift ${descriptor.id}`),
      );

      const changedGraph = withDocumentHash(index, v17NormativeDocumentSha256Hex(mutated));
      assert.equal(validateV17ConstructionGraph(changedGraph), changedGraph);
      assert.notEqual(v17ProtocolIdHex(changedGraph), protocolIdHex, descriptor.id);
      assert.doesNotThrow(() => assertV17NormativeSpecFiles({
        laneRoot: root,
        graph: changedGraph,
      }));
    }
  });

  it("rejects descriptor ID, path, order, hash shape, and byte-policy drift", () => {
    for (const mutate of [
      (graph: V17ConstructionGraph) => Reflect.set(graph.normativeSpec.documents[0]!, "id", "rules"),
      (graph: V17ConstructionGraph) => Reflect.set(graph.normativeSpec.documents[0]!, "path", "CONSTRUCTION.md"),
      (graph: V17ConstructionGraph) => swapFirstTwoDocuments(graph),
      (graph: V17ConstructionGraph) => Reflect.set(graph.normativeSpec.documents[0]!, "sha256Hex", "AA".repeat(32)),
      (graph: V17ConstructionGraph) => Reflect.set(graph.normativeSpec.bytePolicy, "interpretation", "markdown-ast"),
    ]) {
      const graph = structuredClone(V17_CONSTRUCTION_GRAPH);
      mutate(graph);
      assert.throws(() => validateV17ConstructionGraph(graph), /v17 normative document/);
    }
  });

  it("enforces UTF-8 without BOM, LF-only lines, and one terminal LF policy", () => {
    const root = temporarySpecRoot();
    const descriptor = V17_CONSTRUCTION_GRAPH.normativeSpec.documents[0]!;
    const path = resolve(root, descriptor.path);
    const original = readFileSync(path);
    const assertPolicyRejects = (bytes: Uint8Array, pattern: RegExp): void => {
      writeFileSync(path, bytes);
      assert.throws(() => inspectV17NormativeSpecFiles({ laneRoot: root }), pattern);
      writeFileSync(path, original);
    };

    assertPolicyRejects(Uint8Array.of(0xef, 0xbb, 0xbf, ...original), /UTF-8 BOM/);
    const firstLf = original.indexOf(0x0a);
    assert.ok(firstLf >= 0);
    assertPolicyRejects(Uint8Array.of(
      ...original.subarray(0, firstLf), 0x0d, 0x0a, ...original.subarray(firstLf + 1),
    ), /non-LF line ending/);
    assertPolicyRejects(Uint8Array.of(...original.subarray(0, -1), 0xff, 0x0a), /invalid UTF-8/);
    assertPolicyRejects(original.subarray(0, -1), /missing terminal LF/);
  });
});
