import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import {
  V17_CONSTRUCTION_GRAPH,
  type V17ConstructionGraph,
  type V17NormativeDocumentId,
  validateV17ConstructionGraph,
  v17ProtocolIdHex,
} from "./v17-graph.ts";

export type V17NormativeDocumentObservation = {
  readonly id: V17NormativeDocumentId;
  readonly path: string;
  readonly bytes: number;
  readonly expectedSha256Hex: string;
  readonly actualSha256Hex: string;
};

export type V17NormativeSpecFilesystemReceipt = {
  readonly schema: "ShieldKit/V17NormativeSpecFilesystemReceipt/v1";
  readonly protocolIdHex: string;
  readonly documents: readonly V17NormativeDocumentObservation[];
};

export function v17NormativeDocumentSha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertOpaqueUtf8LfBytes(
  id: V17NormativeDocumentId,
  path: string,
  bytes: Uint8Array,
): void {
  if (bytes.length === 0) throw new Error(`v17 normative document empty ${id} ${path}`);
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error(`v17 normative document UTF-8 BOM ${id} ${path}`);
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new Error(`v17 normative document invalid UTF-8 ${id} ${path}`, { cause });
  }
  if (bytes.includes(0x0d)) {
    throw new Error(`v17 normative document non-LF line ending ${id} ${path}`);
  }
  if (bytes.at(-1) !== 0x0a) {
    throw new Error(`v17 normative document missing terminal LF ${id} ${path}`);
  }
}

/**
 * Read and hash the exact identity-bound specification bytes.
 *
 * This is an offline build/qualification guard. Consensus consumes only the
 * graph-derived protocol ID; neither miners nor verifiers parse Markdown.
 */
export function inspectV17NormativeSpecFiles(args: {
  readonly laneRoot: string;
  readonly graph?: V17ConstructionGraph;
}): V17NormativeSpecFilesystemReceipt {
  const graph = args.graph ?? V17_CONSTRUCTION_GRAPH;
  validateV17ConstructionGraph(graph);
  const laneRoot = resolve(args.laneRoot);
  const documents = graph.normativeSpec.documents.map((descriptor) => {
    const absolutePath = resolve(laneRoot, descriptor.path);
    const relativePath = relative(laneRoot, absolutePath);
    if (relativePath === "" || relativePath.startsWith("..") || isAbsolute(relativePath)) {
      throw new Error(`v17 normative document escapes lane ${descriptor.id} ${descriptor.path}`);
    }
    let bytes: Uint8Array;
    try {
      bytes = readFileSync(absolutePath);
    } catch (cause) {
      throw new Error(`v17 normative document unreadable ${descriptor.id} ${descriptor.path}`, {
        cause,
      });
    }
    assertOpaqueUtf8LfBytes(descriptor.id, descriptor.path, bytes);
    return {
      id: descriptor.id,
      path: descriptor.path,
      bytes: bytes.length,
      expectedSha256Hex: descriptor.sha256Hex,
      actualSha256Hex: v17NormativeDocumentSha256Hex(bytes),
    };
  });
  return {
    schema: "ShieldKit/V17NormativeSpecFilesystemReceipt/v1",
    protocolIdHex: v17ProtocolIdHex(graph),
    documents,
  };
}

export function assertV17NormativeSpecFiles(args: {
  readonly laneRoot: string;
  readonly graph?: V17ConstructionGraph;
}): V17NormativeSpecFilesystemReceipt {
  const receipt = inspectV17NormativeSpecFiles(args);
  for (const document of receipt.documents) {
    if (document.actualSha256Hex !== document.expectedSha256Hex) {
      throw new Error(
        `v17 normative document hash drift ${document.id} ${document.path}: ` +
        `${document.actualSha256Hex} != ${document.expectedSha256Hex}`,
      );
    }
  }
  return receipt;
}
