import type { PoolStatement } from "../../pool/statement.ts";
import type { PoolLocalShaGraph } from "../../chain/pool-relation-local-word-machine.ts";
import {
  encodeLocalShaProgram,
  encodePoolLocalShaConstruction,
} from "../../chain/sha256-local-word-codec.ts";
import { localWordProfile, localWordTranscriptInitial } from "./local-word-public-statement.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from "./local-word-successor-params.ts";

const MAGIC = new TextEncoder().encode("SKLB");
const VERSION = 2;
const PROFILE: Readonly<Record<PoolLocalShaGraph["profile"], number>> = {
  deposit: 0,
  "withdraw-full": 1,
  "withdraw-change": 2,
};

export type LocalWordProverInputs = {
  readonly statement: PoolStatement;
  readonly constructionId: Uint8Array;
  readonly graph: PoolLocalShaGraph;
  /** Public transaction miner fee; external on deposit, pool-funded on withdrawal. */
  readonly minerFeeSats?: bigint;
};

function expectedProfile(statement: PoolStatement): PoolLocalShaGraph["profile"] {
  return localWordProfile(statement);
}

/**
 * Private prover handoff. Rust reconstructs every relation column from this
 * canonical program plus inputs; no host-built trace matrix crosses languages.
 */
export function encodeLocalWordProverBundle(inputs: LocalWordProverInputs): Uint8Array {
  const { statement, constructionId, graph } = inputs;
  const minerFeeSats = inputs.minerFeeSats ?? 0n;
  if (graph.profile !== expectedProfile(statement)) throw new Error("local-word prover profile");
  if (graph.minerFeeSats !== minerFeeSats) throw new Error("local-word prover fee");
  const transcriptInitial = localWordTranscriptInitial(statement, constructionId, minerFeeSats);
  const descriptor = encodePoolLocalShaConstruction(graph);
  const program = encodeLocalShaProgram(graph.program);
  const publicWords = graph.inputLayout.filter((input) => input.visibility === "public");
  if (publicWords.length < 1 || publicWords.length > 0xffff ||
    publicWords.some((input) => input.publicField === undefined || input.word === undefined)) {
    throw new Error("local-word prover public words");
  }
  const relationRows = graph.relationRows;
  if (relationRows !== 2 ** LOCAL_WORD_PRODUCTION_PARAMETERS.relationLog) {
    throw new Error("local-word prover frozen relation rows");
  }
  const total = 4 + 1 + 1 + 4 + 4 + transcriptInitial.length + 4 + descriptor.length +
    4 + program.length + 4 + graph.inputs.length * 4 + 2 + publicWords.length * 10;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  let offset = 0;
  out.set(MAGIC, offset); offset += 4;
  out[offset++] = VERSION;
  out[offset++] = PROFILE[graph.profile];
  view.setUint32(offset, relationRows, false); offset += 4;
  view.setUint32(offset, transcriptInitial.length, false); offset += 4;
  out.set(transcriptInitial, offset); offset += transcriptInitial.length;
  view.setUint32(offset, descriptor.length, false); offset += 4;
  out.set(descriptor, offset); offset += descriptor.length;
  view.setUint32(offset, program.length, false); offset += 4;
  out.set(program, offset); offset += program.length;
  view.setUint32(offset, graph.inputs.length, false); offset += 4;
  for (const value of graph.inputs) {
    view.setUint32(offset, value, true); offset += 4;
  }
  view.setUint16(offset, publicWords.length, false); offset += 2;
  for (const [index, word] of publicWords.entries()) {
    view.setUint16(offset, index + 1, false); offset += 2;
    view.setUint32(offset, word.wire, false); offset += 4;
    view.setUint32(offset, word.value, true); offset += 4;
  }
  if (offset !== out.length) throw new Error("local-word prover bundle length");
  return out;
}
