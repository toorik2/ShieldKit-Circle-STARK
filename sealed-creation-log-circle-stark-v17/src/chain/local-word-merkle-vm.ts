import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_MATRIX_NAMES,
  localWordProofStaticOffsets,
  localWordV17MerkleCuts,
  localWordV17FriMerkleDescriptor,
  localWordV17MatrixMerkleDescriptor,
  type LocalWordMatrixName,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriLayerLogs,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { concatBytes } from "../pool/bytes.ts";
import { writeU32BE } from "../pool/bytes.ts";
import {
  v17MerkleSchedule,
  v17MerkleLevels,
  v17MerkleTreeKey,
  type V17MerkleDescriptor,
} from "../backends/circle/v17-merkle.ts";
import {
  localWordProofLengthAssembly,
  localWordReadDynamicAssembly,
  localWordReadWideAssembly,
  type LocalWordProofReader,
} from "./local-word-balanced-vm.ts";

function push(bytes: Uint8Array): string {
  return `<0x${binToHex(bytes)}>`;
}

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function sliceElementAssembly(depth: number, offset: number, length: number): string {
  return `<${depth}> OP_PICK <${offset}> OP_SPLIT OP_NIP <${length}> OP_SPLIT OP_DROP`;
}

/**
 * Executable BCH oracle for the strict v17 opening language. The schedule is
 * verifier-key data, so this deliberately specializes one fixture/KAT rather
 * than reintroducing proof-selected arities or an instruction stream. The
 * production stateless roles use the same hash prefixes but must additionally
 * reconstruct transcript-derived indices from the rank manifests.
 */
export function compileV17MerkleOpeningFixtureGate(args: {
  readonly descriptor: V17MerkleDescriptor;
  readonly indices: readonly number[];
  readonly cutBits?: readonly number[];
  readonly expectedRoot: Uint8Array;
  readonly stage?: { readonly startLevel: number; readonly endLevel: number };
}): Uint8Array {
  if (args.expectedRoot.length !== 32) throw new Error("v17 fixture Merkle root");
  const cutBits = args.cutBits ?? [];
  const schedule = v17MerkleSchedule(args.descriptor, args.indices);
  const treeKey = v17MerkleTreeKey(args.descriptor);
  const rowOffsets = new Map(args.indices.map((index, position) => [
    index,
    position * args.descriptor.rowWidth,
  ]));
  const siblingOffsets = new Map<string, number>();
  let siblingCursor = args.indices.length * args.descriptor.rowWidth;
  schedule.levels.forEach((level, boundary) => {
    level.siblingIndices.forEach((index) => {
      siblingOffsets.set(`${boundary}:${index}`, siblingCursor);
      siblingCursor += 32;
    });
  });
  const frontierSets: readonly ReadonlySet<number>[] = [
    new Set(schedule.indices),
    ...schedule.levels.map(({ parentIndices }) => new Set(parentIndices)),
  ];
  const byBits = new Map<number, { readonly boundary: number; readonly indices: readonly number[] }>([
    [0, { boundary: 0, indices: schedule.indices }],
  ]);
  schedule.levels.forEach((level, boundary) =>
    byBits.set(level.nextConsumedBits, { boundary: boundary + 1, indices: level.parentIndices }));
  let cutCursor = siblingCursor;
  const cutOffsets = new Map<string, number>();
  for (const bits of cutBits) {
    const frontier = byBits.get(bits);
    if (frontier === undefined || bits >= args.descriptor.logRows) {
      throw new Error("v17 fixture cut schedule");
    }
    for (const index of frontier.indices) {
      cutOffsets.set(`${frontier.boundary}:${index}`, cutCursor);
      cutCursor += 36;
    }
  }
  const levelCount = schedule.levels.length;
  const startLevel = args.stage?.startLevel ?? 0;
  const endLevel = args.stage?.endLevel ?? levelCount;
  if (!Number.isInteger(startLevel) || !Number.isInteger(endLevel) || startLevel < 0 ||
    startLevel >= endLevel || endLevel > levelCount ||
    (startLevel > 0 && ![...byBits.values()].some(({ boundary }) => boundary === startLevel)) ||
    (endLevel < levelCount && ![...byBits.values()].some(({ boundary }) => boundary === endLevel))) {
    throw new Error("v17 fixture stage");
  }
  const boundaryBits = [0, ...schedule.levels.map(({ nextConsumedBits }) => nextConsumedBits)];
  if ((startLevel > 0 && !cutBits.includes(boundaryBits[startLevel]!)) ||
    (endLevel < levelCount && !cutBits.includes(boundaryBits[endLevel]!))) {
    throw new Error("v17 fixture stage cuts");
  }
  const emitNode = (
    boundary: number,
    index: number,
    openingDepth: number,
    stopBoundary: number,
  ): string => {
    if (boundary === stopBoundary && stopBoundary > 0) {
      const offset = cutOffsets.get(`${boundary}:${index}`);
      if (offset === undefined) throw new Error("v17 fixture input frontier");
      return sliceElementAssembly(openingDepth, offset + 4, 32);
    }
    if (!frontierSets[boundary]!.has(index)) {
      const offset = siblingOffsets.get(`${boundary}:${index}`);
      if (offset === undefined) throw new Error("v17 fixture sibling schedule");
      return sliceElementAssembly(openingDepth, offset, 32);
    }
    if (boundary === 0) {
      const offset = rowOffsets.get(index);
      if (offset === undefined) throw new Error("v17 fixture leaf schedule");
      const prefix = concatBytes(Uint8Array.of(0), treeKey, writeU32BE(index));
      return `${sliceElementAssembly(openingDepth, offset, args.descriptor.rowWidth)}
${push(prefix)} OP_SWAP OP_CAT OP_SHA256`;
    }
    const level = schedule.levels[boundary - 1]!;
    const children = Array.from({ length: level.arity }, (_, child) =>
      emitNode(boundary - 1, index * level.arity + child, openingDepth + child, stopBoundary));
    const prefix = concatBytes(
      Uint8Array.of(level.arity === 2 ? 1 : 2),
      treeKey,
      Uint8Array.of(level.consumedBits),
    );
    return `${children.join("\n")}
${Array.from({ length: level.arity - 1 }, () => "OP_CAT").join("\n")}
${push(prefix)} OP_SWAP OP_CAT OP_SHA256`;
  };
  const expectedLength = cutCursor;
  const input = frontierSets[startLevel]!;
  const output = frontierSets[endLevel]!;
  const indexChecks = [...new Set([
    ...(startLevel > 0 ? input : []),
    ...(endLevel < levelCount ? output : []),
  ].map((index) => `${startLevel > 0 && input.has(index) ? startLevel : endLevel}:${index}`))]
    .map((key) => {
      const [boundaryText, indexText] = key.split(":");
      const boundary = Number(boundaryText);
      const index = Number(indexText);
      const offset = cutOffsets.get(`${boundary}:${index}`);
      if (offset === undefined) throw new Error("v17 fixture frontier index");
      return `${sliceElementAssembly(0, offset, 4)} ${push(writeU32BE(index))} OP_EQUALVERIFY`;
    });
  const outputChecks = [...output].map((index) => {
    const computed = emitNode(endLevel, index, 0, startLevel);
    if (endLevel === levelCount) {
      return `${computed}\n${push(args.expectedRoot)} OP_EQUALVERIFY`;
    }
    const offset = cutOffsets.get(`${endLevel}:${index}`);
    if (offset === undefined) throw new Error("v17 fixture output frontier");
    return `${computed}\n${sliceElementAssembly(1, offset + 4, 32)} OP_EQUALVERIFY`;
  });
  const canonicalCutChecks = args.stage === undefined
    ? cutBits.flatMap((bits) => {
      const frontier = byBits.get(bits)!;
      return frontier.indices.flatMap((index) => {
        const offset = cutOffsets.get(`${frontier.boundary}:${index}`)!;
        return [
          `${sliceElementAssembly(0, offset, 4)} ${push(writeU32BE(index))} OP_EQUALVERIFY`,
          `${emitNode(frontier.boundary, index, 0, 0)}\n` +
            `${sliceElementAssembly(1, offset + 4, 32)} OP_EQUALVERIFY`,
        ];
      });
    })
    : [];
  return compile(`OP_DUP OP_SIZE OP_NIP <${expectedLength}> OP_NUMEQUALVERIFY
${indexChecks.join("\n")}
${canonicalCutChecks.join("\n")}
${outputChecks.join("\n")}
OP_DROP OP_1`, "v17 strict Merkle opening fixture");
}

function insertBelow(depth: number): string {
  // Use the native fixed-depth permutations when they are exact. Besides
  // being the clearest description of these two stack moves, this avoids the
  // operand pushes and general OP_ROLL machinery in the parent hot loop.
  if (depth === 1) return "OP_SWAP";
  if (depth === 2) return "OP_ROT OP_ROT";
  return Array.from({ length: depth }, () => `<${depth}> OP_ROLL`).join("\n");
}

function updateState(depth: number, operation: string): string {
  return `<${depth}> OP_PICK ${operation}
<${depth + 1}> OP_ROLL OP_DROP
${insertBelow(depth)}`;
}

function mutateState(depth: number, operation: string): string {
  return `<${depth}> OP_ROLL ${operation}
${insertBelow(depth)}`;
}

/** Consume one row copy and batch-reject negative limbs and the sole value p. */
function canonicalM31RowAssembly(rowWidth: number): string {
  if (!Number.isInteger(rowWidth) || rowWidth < 4 || rowWidth % 4 !== 0) {
    throw new Error("local-word canonical M31 row width");
  }
  const signMask = new Uint8Array(rowWidth);
  const onePerLimb = new Uint8Array(rowWidth);
  for (let offset = 0; offset < rowWidth; offset += 4) {
    signMask[offset + 3] = 0x80;
    onePerLimb[offset] = 1;
  }
  const postAddMask = concatBytes(signMask, Uint8Array.of(0));
  return `OP_DUP ${push(signMask)} OP_AND
OP_0 <${rowWidth}> OP_NUM2BIN OP_EQUALVERIFY
<0x00> OP_CAT OP_BIN2NUM
${push(onePerLimb)} OP_BIN2NUM OP_ADD
<${rowWidth + 1}> OP_NUM2BIN
${push(postAddMask)} OP_AND
OP_0 <${rowWidth + 1}> OP_NUM2BIN OP_EQUALVERIFY`;
}

/**
 * Verify one current-row radix-4 matrix multiproof from the sole canonical byte string.
 * A separately checked sorted schedule names each row exactly once; the level
 * machine consumes every row and sibling exactly once. Its merge schedule is
 * derived from the checked sorted indices, so no instruction stream exists.
 */
function compileLocalWordOpeningMerkleGate(args: {
  readonly matrix?: LocalWordMatrixName;
  readonly friLayer?: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly stage?: "complete" | number;
  /** Measurement-only span over descriptor schedule levels. */
  readonly measurementSpan?: { readonly startLevel: number; readonly endLevel: number };
  /** Measurement-only complete cut inventory, including mandatory level zero. */
  readonly measurementCutBits?: readonly number[];
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 ||
    args.publicWordCount > 1024) {
    throw new Error("local-word Merkle verifier key");
  }
  const fri = args.friLayer !== undefined;
  if ((args.matrix === undefined) === (args.friLayer === undefined)) {
    throw new Error("local-word Merkle opening kind");
  }
  const matrix = args.matrix === undefined ? -1 : LOCAL_WORD_MATRIX_NAMES.indexOf(args.matrix);
  const friLayerLogs = localWordFriLayerLogs(parameters);
  if ((!fri && matrix < 0) || (fri && (!Number.isInteger(args.friLayer) ||
    args.friLayer! < 0 || args.friLayer! >= friLayerLogs.length))) {
    throw new Error("local-word Merkle opening");
  }
  const offsets = localWordProofStaticOffsets(args.publicWordCount, parameters);
  const descriptor = fri
    ? localWordV17FriMerkleDescriptor(args.friLayer!, parameters)
    : localWordV17MatrixMerkleDescriptor(args.matrix!, parameters);
  const canonicalCuts = fri
    ? localWordV17MerkleCuts({ friLayer: args.friLayer!, parameters })
    : localWordV17MerkleCuts({ matrix: args.matrix!, parameters });
  const selectedBoundaries = [...canonicalCuts, descriptor.logRows];
  const selectedStages = selectedBoundaries.slice(0, -1).map((startBits, item) => ({
    startBits,
    endBits: selectedBoundaries[item + 1]!,
  }));
  const queryCount = parameters.fri.queries;
  const global = args.matrix === "interactionGlobal";
  const openingMax = queryCount * (fri
    ? descriptor.shape === "quartet-first" ? 4 : 2
    : global ? 2 : 1);
  if (args.measurementSpan !== undefined && args.stage !== undefined) {
    throw new Error("local-word Merkle stage mode");
  }
  const stage = args.stage ?? "complete";
  const frontierLevels = args.measurementCutBits ?? canonicalCuts;
  if (frontierLevels[0] !== 0 || frontierLevels.some((bits, index) =>
    !Number.isInteger(bits) || bits < 0 || bits >= descriptor.logRows ||
    (index > 0 && frontierLevels[index - 1]! >= bits))) {
    throw new Error("local-word v17 Merkle cut inventory");
  }
  if (stage !== "complete" && (!Number.isInteger(stage) || stage < 0 ||
    stage >= selectedStages.length)) {
    throw new Error("local-word current Merkle stage geometry");
  }
  const stageNumber = stage === "complete" ? undefined : stage;
  const scheduleLevels = v17MerkleLevels(descriptor);
  const boundaryBits = [0, ...scheduleLevels.map(({ nextConsumedBits }) => nextConsumedBits)];
  const measured = args.measurementSpan;
  if (measured !== undefined && (!Number.isInteger(measured.startLevel) ||
    !Number.isInteger(measured.endLevel) || measured.startLevel < 0 ||
    measured.startLevel >= measured.endLevel || measured.endLevel > scheduleLevels.length)) {
    throw new Error("local-word measured Merkle span");
  }
  const selectedStage = measured !== undefined
    ? {
      startBits: boundaryBits[measured.startLevel]!,
      endBits: boundaryBits[measured.endLevel]!,
    }
    : stageNumber === undefined
      ? { startBits: 0, endBits: descriptor.logRows }
      : selectedStages[stageNumber]!;
  const stageStart = selectedStage.startBits;
  const stageEnd = selectedStage.endBits;
  const finalStage = stageEnd === descriptor.logRows;
  const spanLevels = scheduleLevels.filter(({ consumedBits }) =>
    consumedBits >= stageStart && consumedBits < stageEnd);
  if (spanLevels.length < 1 || spanLevels.some(({ arity }) => arity !== spanLevels[0]!.arity)) {
    throw new Error("v17 mixed Merkle span crosses an arity boundary");
  }
  const stageArity = spanLevels[0]!.arity;
  const levelStep = stageArity === 4 ? 2 : 1;
  const stageMetadataBytes = frontierLevels.length * 12;
  const rootOffset = fri
    ? offsets.friRoots + args.friLayer! * 32
    : offsets.matrixRoots + matrix * 32;
  const openingIndex = fri ? LOCAL_WORD_MATRIX_NAMES.length + args.friLayer! : matrix;
  const directoryOffset = offsets.openingDirectory + openingIndex * 20;
  const label = descriptor.label;
  const treeKey = v17MerkleTreeKey(descriptor);

  const reader = compile(
    localWordReadWideAssembly(args.reader),
    "local-word Merkle reader function",
  );
  // Buffer one binary level's worst-case sibling demand (one per query), capped
  // at the largest whole-node frame below BCH's 10,000-byte element ceiling.
  // For production q44 this is 44 siblings / 1,408 bytes; exact measurement
  // shows larger frames lose more in wide-read cost than they save in reloads.
  const siblingBufferItems = Math.min(queryCount, Math.floor(10_000 / 32));
  const frontierEnd = "<0xffffffff>";

  // Compact state: proofLength, frontierTail, nextFrontier, level,
  // frontierHead. End, cursor, and the transient sibling buffer live on the
  // alternate stack; keeping duplicate counters or buffers in the shuffled
  // main state only obscures the machine and wastes operation cost.
  const reloadSiblingBuffer = compile(`OP_FROMALTSTACK OP_FROMALTSTACK
OP_2DUP OP_SWAP OP_SUB <32> OP_DIV <${siblingBufferItems}> OP_MIN <32> OP_MUL
OP_ROT OP_ROT OP_TOALTSTACK OP_TOALTSTACK
<7> OP_PICK
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
OP_ROT <0> OP_INVOKE OP_NIP
OP_DUP OP_SIZE OP_NIP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
`, "local-word Merkle sibling buffer reload");
  const queueChild = compile(`<3> OP_ROLL <4> OP_SPLIT OP_TOALTSTACK
OP_REVERSEBYTES OP_BIN2NUM OP_NUMEQUALVERIFY
<4> OP_PICK OP_SIZE OP_NIP OP_0 OP_GREATERTHAN
OP_IF
  <4> OP_ROLL <36> OP_SPLIT ${insertBelow(5)}
OP_ELSE
  ${frontierEnd}
OP_ENDIF
${insertBelow(2)} OP_FROMALTSTACK`, "local-word Merkle queue child");
  const proofChild = compile(`OP_DROP OP_FROMALTSTACK
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP
  <4> OP_INVOKE
OP_ENDIF
<32> OP_SPLIT OP_TOALTSTACK`, "local-word Merkle proof child");
  const child = compile(`<3> OP_PICK <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK OP_NUMEQUAL
OP_IF <1> OP_ELSE <2> OP_ENDIF OP_INVOKE
OP_CAT`, "local-word Merkle child");
  const takeChild = (position: number): string => `<1> OP_PICK <${stageArity}> OP_MUL
${position === 0 ? "" : `<${position}> OP_ADD`}
<3> OP_INVOKE`;
  const parent = `OP_DUP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM <${stageArity}> OP_DIV
OP_0
${Array.from({ length: stageArity }, (_, childIndex) => takeChild(childIndex)).join("\n")}
<3> OP_PICK <1> OP_NUM2BIN
${push(concatBytes(Uint8Array.of(stageArity === 2 ? 1 : 2), treeKey))} OP_SWAP OP_CAT
OP_SWAP OP_CAT OP_SHA256
OP_SWAP <4> OP_NUM2BIN OP_REVERSEBYTES OP_SWAP OP_CAT
<3> OP_ROLL OP_SWAP OP_CAT ${insertBelow(2)}`;
  const levelTransition = `OP_DROP
<2> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
<1> OP_ROLL <36> OP_SPLIT
${insertBelow(2)}
OP_0 ${insertBelow(2)}
${mutateState(1, levelStep === 1 ? "OP_1ADD" : "<2> OP_ADD")}`;

  const metaWord = (depth: number, byteOffset: number): string => `<${depth}> OP_PICK
<${byteOffset}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM`;
  const startRecord = frontierLevels.indexOf(stageStart);
  const endRecord = finalStage ? -1 : frontierLevels.indexOf(stageEnd);
  if (startRecord < 0 || (!finalStage && endRecord < 0)) {
    throw new Error("local-word v17 Merkle stage frontier");
  }
  const endCut = finalStage ? "OP_FROMALTSTACK" : metaWord(1, endRecord * 12);
  // Every stage retains the graph-owned directory pointer read at setup.
  // Non-final stages reuse it for their output frontier; the final stage uses
  // the same pointer as the end of the contiguous sibling frame. Neither case
  // searches the proof carriers for an identical four-byte word twice.
  const retainStageDirectory = "OP_DUP OP_TOALTSTACK";
  const stagedSetup = `
OP_DUP <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
${retainStageDirectory}
<1> OP_PICK OP_SWAP <${stageMetadataBytes}> <0> OP_INVOKE OP_NIP
${metaWord(0, startRecord * 12)}
${endCut}
${metaWord(2, startRecord * 12 + 4)}
${metaWord(3, startRecord * 12 + 8)}
<4> OP_ROLL OP_DROP
OP_OVER OP_SUB
OP_DUP <36> OP_MOD OP_0 OP_NUMEQUALVERIFY
OP_DUP <36> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${openingMax * 36}> OP_LESSTHANOREQUAL OP_VERIFY
<4> OP_PICK OP_ROT OP_ROT <0> OP_INVOKE OP_NIP
<1> OP_ROLL OP_TOALTSTACK
<1> OP_ROLL OP_TOALTSTACK
<36> OP_SPLIT OP_SWAP
OP_0 <${stageStart}> <2> OP_ROLL
OP_0 OP_TOALTSTACK`;
  const completeFinish = `OP_TOALTSTACK
OP_DUP <${stageEnd}> OP_NUMEQUALVERIFY OP_DROP
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK
OP_FROMALTSTACK OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_NUMEQUALVERIFY
<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_0 OP_NUMEQUALVERIFY
<1> OP_PICK <${rootOffset}> <32> <0> OP_INVOKE OP_NIP OP_EQUAL OP_NIP`;
  const stagedFinish = `OP_TOALTSTACK
OP_DUP <${stageEnd}> OP_NUMEQUALVERIFY OP_DROP
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK OP_SWAP OP_CAT
OP_FROMALTSTACK OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_NUMEQUALVERIFY
OP_FROMALTSTACK
<2> OP_PICK <1> OP_PICK <${endRecord * 12}> OP_ADD <12> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <8> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
OP_2DUP OP_SWAP OP_SUB OP_TOALTSTACK OP_DROP OP_TOALTSTACK OP_2DROP
OP_FROMALTSTACK OP_FROMALTSTACK
<3> OP_PICK OP_ROT OP_ROT
<0> OP_INVOKE OP_NIP
OP_EQUAL
OP_NIP`;

  const assembly = `OP_DROP
<0x${binToHex(reader)}> <0> OP_DEFINE
<0x${binToHex(queueChild)}> <1> OP_DEFINE
<0x${binToHex(proofChild)}> <2> OP_DEFINE
<0x${binToHex(child)}> <3> OP_DEFINE
<0x${binToHex(reloadSiblingBuffer)}> <4> OP_DEFINE
${localWordProofLengthAssembly()}
${stagedSetup}
OP_BEGIN
  OP_BEGIN
    ${parent}
    OP_DUP <4> OP_SPLIT OP_DROP ${frontierEnd} OP_EQUAL
  OP_UNTIL
  ${levelTransition}
  <1> OP_PICK <${stageEnd}> OP_NUMEQUAL
OP_UNTIL
${finalStage ? completeFinish : stagedFinish}`;
  return compile(assembly, `local-word ${label} Merkle ${stage}`);
}

export function compileLocalWordCurrentMatrixMerkleGate(args: {
  readonly matrix: LocalWordMatrixName;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly stage?: "complete" | number;
  readonly measurementSpan?: { readonly startLevel: number; readonly endLevel: number };
  readonly measurementCutBits?: readonly number[];
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  return compileLocalWordOpeningMerkleGate(args);
}

export const LOCAL_WORD_INTERACTION_LEAF_SHARDS = 2;

/**
 * Bind one disjoint shard of raw rows to the mandatory level-zero frontier.
 * Current-matrix indices are also tied to the fixed current-index manifest;
 * global and FRI indices are tied to their transcript-derived schedules by
 * `compileLocalWordOpeningScheduleGate`. Parent roles consume this exact same
 * frontier slice, making it checked shared evidence rather than hidden state.
 */
export function compileLocalWordMerkleLeafGate(args: {
  readonly matrix?: LocalWordMatrixName;
  readonly friLayer?: number;
  readonly shard: number;
  readonly shards: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 ||
    args.publicWordCount > 1024 || !Number.isInteger(args.shard) || args.shard < 0 ||
    !Number.isInteger(args.shards) || args.shards < 1 || args.shard >= args.shards ||
    ((args.matrix === undefined) === (args.friLayer === undefined))) {
    throw new Error("local-word Merkle leaf verifier key");
  }
  const fri = args.friLayer !== undefined;
  const matrix = args.matrix === undefined ? -1 : LOCAL_WORD_MATRIX_NAMES.indexOf(args.matrix);
  const friLogs = localWordFriLayerLogs(parameters);
  if ((!fri && matrix < 0) || (fri && (!Number.isInteger(args.friLayer) ||
    args.friLayer! < 0 || args.friLayer! >= friLogs.length))) {
    throw new Error("local-word Merkle leaf opening");
  }
  const descriptor = fri
    ? localWordV17FriMerkleDescriptor(args.friLayer!, parameters)
    : localWordV17MatrixMerkleDescriptor(args.matrix!, parameters);
  const cuts = fri
    ? localWordV17MerkleCuts({ friLayer: args.friLayer!, parameters })
    : localWordV17MerkleCuts({ matrix: args.matrix!, parameters });
  if (cuts[0] !== 0) throw new Error("local-word Merkle leaf frontier");
  const rowWidth = descriptor.rowWidth;
  const queryCount = parameters.fri.queries;
  const indexCount = fri
    ? queryCount * (descriptor.shape === "quartet-first" ? 4 : 2)
    : args.matrix === "interactionGlobal" ? queryCount * 2 : queryCount;
  const first = Math.floor(args.shard * indexCount / args.shards);
  const end = Math.floor((args.shard + 1) * indexCount / args.shards);
  if (first === end) throw new Error("local-word empty Merkle leaf shard");
  const offsets = localWordProofStaticOffsets(args.publicWordCount, parameters);
  const openingIndex = fri ? LOCAL_WORD_MATRIX_NAMES.length + args.friLayer! : matrix;
  const directoryOffset = offsets.openingDirectory + openingIndex * 20;
  const reader = compile(
    localWordReadDynamicAssembly(args.reader),
    "local-word Merkle leaf reader",
  );
  const canonicalRow = compile(canonicalM31RowAssembly(rowWidth), "local-word canonical leaf row");
  const treeKey = v17MerkleTreeKey(descriptor);
  const leafPrefix = concatBytes(Uint8Array.of(0), treeKey);
  const current = !fri && args.matrix !== "interactionGlobal";
  /**
   * Consume one row and one level-zero record from graph-fixed frames. Current
   * matrices additionally consume the corresponding transcript-derived index.
   * Reading each contiguous frame once avoids repeating the carrier search for
   * every leaf while preserving the exact serialized proof language.
   */
  const leafBodyAssembly = current
    ? `<4> OP_SPLIT OP_SWAP OP_TOALTSTACK
OP_SWAP <36> OP_SPLIT OP_SWAP <4> OP_SPLIT
OP_TOALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
<2> OP_PICK OP_EQUALVERIFY
<4> OP_ROLL <${rowWidth}> OP_SPLIT OP_SWAP
OP_DUP <1> OP_INVOKE
<3> OP_PICK OP_SWAP OP_CAT ${push(leafPrefix)} OP_SWAP OP_CAT OP_SHA256
<2> OP_ROLL OP_EQUALVERIFY
OP_SWAP OP_DROP OP_SWAP OP_ROT`
    : `<36> OP_SPLIT OP_SWAP <4> OP_SPLIT
<3> OP_ROLL <${rowWidth}> OP_SPLIT OP_SWAP
OP_DUP <1> OP_INVOKE
<3> OP_PICK OP_SWAP OP_CAT ${push(leafPrefix)} OP_SWAP OP_CAT OP_SHA256
<2> OP_ROLL OP_EQUALVERIFY
OP_SWAP OP_DROP OP_SWAP`;
  const leaf = compile(leafBodyAssembly, `local-word ${descriptor.label} leaf body`);
  const count = end - first;
  const preload = `<2> OP_PICK <2> OP_PICK <${first * rowWidth}> OP_ADD
<${count * rowWidth}> <0> OP_INVOKE OP_NIP
<3> OP_PICK <2> OP_PICK <${first * 36}> OP_ADD
<${count * 36}> <0> OP_INVOKE OP_NIP
${current
    ? `<4> OP_PICK <${offsets.currentIndices + first * 4}> <${count * 4}> ` +
      `<0> OP_INVOKE OP_NIP
<3> OP_ROLL OP_DROP <3> OP_ROLL OP_DROP`
    : `<2> OP_ROLL OP_DROP <2> OP_ROLL OP_DROP`}`;
  const finish = current
    ? "OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_DROP OP_1"
    : "OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_DROP OP_1";
  const directoryWord = (depth: number, byteOffset: number): string => `<${depth}> OP_PICK
<${byteOffset}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM`;
  return compile(`OP_DROP
<0x${binToHex(reader)}> <0> OP_DEFINE
<0x${binToHex(canonicalRow)}> <1> OP_DEFINE
<0x${binToHex(leaf)}> <2> OP_DEFINE
${localWordProofLengthAssembly()}
OP_DUP <${directoryOffset}> <20> <0> OP_INVOKE OP_NIP
${directoryWord(0, 0)}
${directoryWord(1, 4)}
OP_2DUP OP_NUMEQUALVERIFY OP_NIP
${directoryWord(1, 8)}
OP_2DUP OP_SWAP OP_SUB <${indexCount * rowWidth}> OP_NUMEQUALVERIFY
${directoryWord(2, 12)}
<3> OP_ROLL OP_DROP
<3> OP_PICK <1> OP_PICK <12> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<3> OP_PICK OP_NUMEQUALVERIFY
OP_DUP <4> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <8> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
OP_2DUP OP_SWAP OP_SUB <${indexCount * 36}> OP_NUMEQUALVERIFY OP_DROP
OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK
${preload}
${Array.from({ length: count }, () => "<2> OP_INVOKE").join("\n")}
${finish}`, `local-word ${descriptor.label} leaf ${args.shard}/${args.shards}`);
}

export function compileLocalWordInteractionLeafGate(args: {
  readonly shard: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  return compileLocalWordMerkleLeafGate({
    matrix: "interaction",
    shard: args.shard,
    shards: LOCAL_WORD_INTERACTION_LEAF_SHARDS,
    publicWordCount: args.publicWordCount,
    parameters: args.parameters,
    reader: args.reader,
  });
}

export function compileLocalWordFriMerkleGate(args: {
  readonly layer: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly stage?: "complete" | number;
  readonly measurementSpan?: { readonly startLevel: number; readonly endLevel: number };
  readonly measurementCutBits?: readonly number[];
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  return compileLocalWordOpeningMerkleGate({
    friLayer: args.layer,
    publicWordCount: args.publicWordCount,
    parameters: args.parameters,
    stage: args.stage,
    measurementSpan: args.measurementSpan,
    measurementCutBits: args.measurementCutBits,
    reader: args.reader,
  });
}
