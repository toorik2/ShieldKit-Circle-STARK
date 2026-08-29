import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
  localWordMatrixMerkleStageGeometry,
  localWordMerkleFrontierLevels,
  localWordProofStaticOffsets,
  type LocalWordMatrixName,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriLayerLogs,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { concatBytes, sha256 } from "../pool/bytes.ts";
import {
  localWordProofLengthAssembly,
  localWordReadDynamicAssembly,
  localWordReadWideAssembly,
} from "./local-word-balanced-vm.ts";

const TREE_DOMAIN = new TextEncoder().encode("ShieldKit/CanonicalMerkle/v1");

const MATRIX_LABELS: Readonly<Record<LocalWordMatrixName, string>> = {
  preprocessed: "local-word:preprocessed",
  original: "local-word:original",
  interaction: "local-word:interaction",
  interactionGlobal: "local-word:interaction-global",
  quotientAndFriMask: "local-word:quotient-and-fri-mask",
};

function push(bytes: Uint8Array): string {
  return `<0x${binToHex(bytes)}>`;
}

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function insertBelow(depth: number): string {
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
  const rowWidth = fri ? 16 : LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix]!;
  const queryCount = parameters.fri.queries;
  const global = args.matrix === "interactionGlobal";
  const serializedIndices = fri || global;
  const openingMax = queryCount * (fri ? 4 : global ? 2 : 1);
  const treeLevels = (fri ? friLayerLogs[args.friLayer!]! : parameters.evalLog) / 2;
  const geometry = fri
    ? LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY
    : localWordMatrixMerkleStageGeometry(args.matrix!);
  const stage = args.stage ?? "complete";
  const frontierLevels = localWordMerkleFrontierLevels(treeLevels, geometry);
  if (stage !== "complete" && (stage < 0 || stage > frontierLevels.length)) {
    throw new Error("local-word current Merkle stage geometry");
  }
  if (!fri && args.matrix === "interaction" && stage === 0) {
    throw new Error("local-word interaction leaf stage owns stage zero");
  }
  const stageNumber = stage === "complete" ? undefined : stage;
  const stageStart = stageNumber === undefined || stageNumber === 0
    ? 0
    : frontierLevels[stageNumber - 1]!;
  const stageEnd = stageNumber === undefined || stageNumber === frontierLevels.length
    ? treeLevels
    : frontierLevels[stageNumber]!;
  const finalStage = stageNumber === undefined || stageNumber === frontierLevels.length;
  const stageMetadataBytes = frontierLevels.length * 12;
  const rootOffset = fri
    ? offsets.friRoots + args.friLayer! * 32
    : offsets.matrixRoots + matrix * 32;
  const openingIndex = fri ? LOCAL_WORD_MATRIX_NAMES.length + args.friLayer! : matrix;
  const directoryOffset = offsets.openingDirectory + openingIndex * 20;
  const label = fri ? `fri:layer:${args.friLayer}` : MATRIX_LABELS[args.matrix!];
  const treeKey = sha256(concatBytes(
    TREE_DOMAIN,
    new TextEncoder().encode(label),
  ));

  /*
   * Higher current-matrix stages need only three streams: the sorted input
   * frontier, the canonical sibling slice, and the next frontier. A sentinel
   * makes an empty queue safe to inspect, deleting the older head/tail and
   * refill-buffer state machine. Current stages contain at most 28 * 3 * 3
   * sibling hashes, so their complete sibling slice remains one VM element.
   */
  if (!serializedIndices && args.matrix !== "interaction" &&
    stageNumber !== undefined && stageNumber > 0) {
    const stagedReader = compile(localWordReadWideAssembly(), "local-word staged Merkle reader");
    const takeChild = compile(`<3> OP_PICK <4> OP_SPLIT OP_DROP OP_BIN2NUM
OP_OVER OP_NUMEQUAL
OP_IF
  OP_DROP <2> OP_ROLL <36> OP_SPLIT OP_TOALTSTACK
  <4> OP_SPLIT OP_NIP OP_CAT
  OP_FROMALTSTACK OP_ROT OP_ROT
OP_ELSE
  OP_DROP
  <1> OP_PICK OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
  OP_IF
    OP_SWAP OP_DROP
    OP_FROMALTSTACK OP_FROMALTSTACK
    OP_2DUP OP_SWAP OP_SUB <1024> OP_MIN
    <1> OP_PICK OP_TOALTSTACK
    <2> OP_PICK OP_OVER OP_ADD OP_TOALTSTACK
    OP_SWAP OP_DROP
    <7> OP_PICK <2> OP_ROLL <2> OP_ROLL <0> OP_INVOKE OP_NIP
    OP_SWAP
  OP_ENDIF
  <1> OP_ROLL <32> OP_SPLIT OP_TOALTSTACK
  OP_CAT OP_FROMALTSTACK OP_SWAP
OP_ENDIF`, "local-word staged Merkle child");
    const previousRecord = stageNumber - 1;
    const siblingEnd = finalStage
      ? "<4> OP_PICK"
      : `<4> OP_PICK <${stageNumber * 12}> OP_ADD
<6> OP_PICK OP_SWAP <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM`;
    const setup = `OP_DUP <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <1> OP_PICK <${previousRecord * 12}> OP_ADD <12> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <4> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<2> OP_PICK <8> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
${siblingEnd}
<6> OP_PICK <3> OP_PICK <3> OP_PICK <1> OP_PICK OP_SUB <0> OP_INVOKE OP_NIP
<1> OP_PICK OP_TOALTSTACK <4> OP_PICK OP_TOALTSTACK OP_TOALTSTACK
OP_2DROP OP_2DROP OP_2DROP
OP_FROMALTSTACK <0xffffffff> OP_CAT
OP_0
OP_0
<${stageStart}>`;
    const child = (position: number): string => `<3> OP_PICK <4> OP_MUL
${position === 0 ? "" : `<${position}> OP_ADD`}
<1> OP_INVOKE`;
    const parent = `<3> OP_PICK <4> OP_SPLIT OP_DROP OP_BIN2NUM <4> OP_DIV
<4> OP_ROLL <3> OP_ROLL OP_0
${[0, 1, 2, 3].map(child).join("\n")}
<4> OP_PICK <1> OP_NUM2BIN
${push(concatBytes(Uint8Array.of(2), treeKey))} OP_SWAP OP_CAT
OP_SWAP OP_CAT OP_SHA256
<3> OP_PICK <4> OP_NUM2BIN OP_SWAP OP_CAT
<5> OP_ROLL OP_SWAP OP_CAT
<3> OP_ROLL OP_DROP
<3> OP_ROLL OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
<3> OP_PICK <0xffffffff> OP_EQUAL`;
    const transition = `<3> OP_ROLL OP_DROP OP_1ADD
OP_TOALTSTACK OP_TOALTSTACK
<0xffffffff> OP_CAT OP_0
OP_FROMALTSTACK OP_FROMALTSTACK`;
    const finish = finalStage
      ? `OP_DUP OP_SIZE OP_NIP <36> OP_NUMEQUALVERIFY
<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_0 OP_NUMEQUALVERIFY
<1> OP_PICK <${rootOffset}> <32> <0> OP_INVOKE OP_NIP OP_EQUAL OP_NIP`
      : `<1> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<2> OP_PICK <1> OP_PICK <${stageNumber * 12}> OP_ADD <12> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <8> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
<5> OP_PICK <2> OP_PICK <2> OP_PICK <1> OP_PICK OP_SUB <0> OP_INVOKE OP_NIP
<5> OP_ROLL OP_EQUAL OP_TOALTSTACK
OP_2DROP OP_2DROP OP_DROP OP_FROMALTSTACK`;
    return compile(`OP_DROP
<0x${binToHex(stagedReader)}> <0> OP_DEFINE
<0x${binToHex(takeChild)}> <1> OP_DEFINE
${localWordProofLengthAssembly()}
${setup}
OP_BEGIN
  OP_BEGIN
    ${parent}
  OP_UNTIL
  ${transition}
  OP_DUP <${stageEnd}> OP_NUMEQUAL
OP_UNTIL
OP_DUP <${stageEnd}> OP_NUMEQUALVERIFY OP_DROP
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_NUMEQUALVERIFY
OP_DUP OP_SIZE OP_NIP <4> OP_SUB OP_SPLIT <0xffffffff> OP_EQUALVERIFY
${finish}`, `local-word ${label} compact Merkle ${stage}`);
  }
  const reader = compile(localWordReadWideAssembly(), "local-word Merkle reader function");
  const canonicalRows = serializedIndices ? 1
    : queryCount % 4 === 0 ? 4
      : queryCount % 2 === 0 ? 2 : 1;
  const canonicalWidth = canonicalRows * rowWidth;
  const canonicalRow = compile(
    canonicalM31RowAssembly(canonicalWidth),
    `local-word canonical M31 ${canonicalRows}-row batch`,
  );
  const canonicalDefinition = stageNumber === undefined || stageNumber === 0
    ? `<0x${binToHex(canonicalRow)}> <4> OP_DEFINE`
    : "";

  const leaf = `OP_TOALTSTACK
<2> OP_ROLL <4> OP_SPLIT OP_TOALTSTACK
OP_DUP OP_REVERSEBYTES OP_TOALTSTACK
OP_SWAP OP_CAT
${push(concatBytes(Uint8Array.of(0), treeKey))} OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK OP_SWAP OP_CAT OP_CAT
OP_FROMALTSTACK OP_SWAP
OP_FROMALTSTACK`;
  const rowsPerBatch = Math.max(
    canonicalRows,
    Math.floor(2_048 / (canonicalRows * rowWidth)) * canonicalRows,
  );
  const rowBatchBytes = rowsPerBatch * rowWidth;
  const siblingBufferItems = 32;
  const frontierEnd = "<0xffffffff>";
  const rowBatches: string[] = [];
  for (let start = 0; start < (serializedIndices ? 0 : queryCount);
    start += rowsPerBatch) {
    const count = Math.min(rowsPerBatch, queryCount - start);
    const width = count * rowWidth;
    rowBatches.push(`<6> OP_PICK <6> OP_PICK <${start * rowWidth}> OP_ADD <${width}>
${localWordReadWideAssembly()} OP_NIP
${Array.from({ length: count / canonicalRows }, () => `OP_DUP <${canonicalWidth}> OP_SPLIT
OP_DROP <4> OP_INVOKE
${Array.from({ length: canonicalRows }, () => `<${rowWidth}> OP_SPLIT
${leaf}`).join("\n")}`).join("\n")}
OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP`);
  }

  // Compact state: proofLength, frontierTail, nextFrontier, level,
  // frontierHead. End, cursor, and the transient sibling buffer live on the
  // alternate stack; keeping duplicate counters or buffers in the shuffled
  // main state only obscures the machine and wastes operation cost.
  const reloadSiblingBuffer = `OP_FROMALTSTACK OP_FROMALTSTACK
OP_2DUP OP_SWAP OP_SUB <32> OP_DIV <${siblingBufferItems}> OP_MIN <32> OP_MUL
OP_ROT OP_ROT OP_TOALTSTACK OP_TOALTSTACK
<7> OP_PICK
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
OP_ROT <0> OP_INVOKE OP_NIP
OP_DUP OP_SIZE OP_NIP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
`;
  const queueChild = compile(`<3> OP_ROLL <4> OP_SPLIT OP_TOALTSTACK
OP_BIN2NUM OP_NUMEQUALVERIFY
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
  ${reloadSiblingBuffer}
OP_ENDIF
<32> OP_SPLIT OP_TOALTSTACK`, "local-word Merkle proof child");
  const child = compile(`<3> OP_PICK <4> OP_SPLIT OP_DROP OP_BIN2NUM
<1> OP_PICK OP_NUMEQUAL
OP_IF <1> OP_INVOKE OP_ELSE <2> OP_INVOKE OP_ENDIF
OP_CAT`, "local-word Merkle child");
  const takeChild = (position: number): string => `<1> OP_PICK <4> OP_MUL
${position === 0 ? "" : `<${position}> OP_ADD`}
<3> OP_INVOKE`;
  const parent = `OP_DUP <4> OP_SPLIT OP_DROP OP_BIN2NUM <4> OP_DIV
OP_0
${[0, 1, 2, 3].map(takeChild).join("\n")}
<3> OP_PICK <1> OP_NUM2BIN
${push(concatBytes(Uint8Array.of(2), treeKey))} OP_SWAP OP_CAT
OP_SWAP OP_CAT OP_SHA256
OP_SWAP <4> OP_NUM2BIN OP_SWAP OP_CAT
<3> OP_ROLL OP_SWAP OP_CAT ${insertBelow(2)}`;
  const levelTransition = `OP_DROP
<2> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
<1> OP_ROLL <36> OP_SPLIT
${insertBelow(2)}
OP_0 ${insertBelow(2)}
${mutateState(1, "OP_1ADD")}`;

  const leafSiblingEnd = stageNumber === undefined || frontierLevels.length === 0
    ? `<2> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM`
    : `<2> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<3> OP_PICK OP_SWAP <${stageMetadataBytes}> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM OP_NIP`;
  const leafStageSetup = `
OP_DUP <${directoryOffset + 4}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <${directoryOffset + 8}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
${leafSiblingEnd}
<1> OP_PICK <3> OP_PICK OP_SUB <${queryCount * rowWidth}> OP_NUMEQUALVERIFY
OP_DUP <2> OP_PICK OP_SUB
OP_DUP <32> OP_MOD OP_0 OP_NUMEQUALVERIFY <32> OP_DIV
<1> OP_PICK <5> OP_PICK OP_LESSTHANOREQUAL OP_VERIFY
<4> OP_PICK <${offsets.currentIndices}> <${queryCount * 4}> <0> OP_INVOKE OP_NIP
OP_0
${rowBatches.join("\n")}
<1> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
<4> OP_ROLL OP_DROP
<2> OP_ROLL OP_TOALTSTACK
<2> OP_ROLL OP_TOALTSTACK
<1> OP_ROLL OP_DROP
OP_0 OP_TOALTSTACK
OP_0 OP_0
<2> OP_ROLL <36> OP_SPLIT ${insertBelow(3)}`;
  const globalSiblingEnd = stageNumber === undefined || frontierLevels.length === 0
    ? `<3> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM`
    : `<3> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<4> OP_PICK OP_SWAP <${stageMetadataBytes}> <0> OP_INVOKE OP_NIP
OP_DUP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM OP_NIP`;
  const globalLeafStageSetup = `
OP_DUP <${directoryOffset}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <${directoryOffset + 4}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<2> OP_PICK <${directoryOffset + 8}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
${globalSiblingEnd}
<2> OP_PICK <4> OP_PICK OP_SUB
OP_DUP <4> OP_MOD OP_0 OP_NUMEQUALVERIFY <4> OP_DIV
<2> OP_PICK <4> OP_PICK OP_SUB
<1> OP_PICK <${rowWidth}> OP_MUL OP_NUMEQUALVERIFY
OP_DUP <${queryCount}> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${openingMax}> OP_LESSTHANOREQUAL OP_VERIFY
<5> OP_PICK <5> OP_PICK <2> OP_PICK <4> OP_MUL <0> OP_INVOKE OP_NIP
<6> OP_PICK <5> OP_PICK <3> OP_PICK <${rowWidth}> OP_MUL <0> OP_INVOKE OP_NIP
<2> OP_ROLL OP_DROP <4> OP_ROLL OP_DROP <4> OP_ROLL OP_DROP
OP_0
OP_BEGIN
  <2> OP_ROLL <4> OP_SPLIT ${insertBelow(3)}
  OP_DUP OP_REVERSEBYTES OP_TOALTSTACK
  <2> OP_ROLL <${rowWidth}> OP_SPLIT
  OP_SWAP OP_DUP <4> OP_INVOKE OP_SWAP ${insertBelow(3)}
  OP_CAT ${push(concatBytes(Uint8Array.of(0), treeKey))} OP_SWAP OP_CAT OP_SHA256
  OP_FROMALTSTACK OP_SWAP OP_CAT OP_CAT
  <2> OP_PICK OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
OP_UNTIL
<1> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
<1> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
<1> OP_ROLL OP_TOALTSTACK <1> OP_ROLL OP_TOALTSTACK
OP_0 OP_TOALTSTACK
<36> OP_SPLIT OP_SWAP OP_0 OP_0 <2> OP_ROLL`;
  const metaWord = (depth: number, byteOffset: number): string => `<${depth}> OP_PICK
<${byteOffset}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM`;
  const startRecord = Math.max(0, (stageNumber ?? 1) - 1);
  const endCut = stageNumber === frontierLevels.length
    ? `<2> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM`
    : metaWord(1, (stageNumber ?? 0) * 12);
  const stagedSetup = `
OP_DUP <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
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
OP_DUP OP_SIZE OP_NIP OP_TOALTSTACK
<1> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP OP_REVERSEBYTES OP_BIN2NUM
<2> OP_PICK OP_SWAP <${stageMetadataBytes}> <0> OP_INVOKE OP_NIP
${metaWord(0, (stageNumber ?? 0) * 12 + 4)} OP_NIP
<2> OP_PICK OP_SWAP OP_FROMALTSTACK <0> OP_INVOKE OP_NIP
OP_EQUAL
OP_FROMALTSTACK OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_NUMEQUALVERIFY
OP_NIP`;

  const assembly = `OP_DROP
<0x${binToHex(reader)}> <0> OP_DEFINE
<0x${binToHex(queueChild)}> <1> OP_DEFINE
<0x${binToHex(proofChild)}> <2> OP_DEFINE
<0x${binToHex(child)}> <3> OP_DEFINE
${canonicalDefinition}
${localWordProofLengthAssembly()}
${stageNumber !== undefined && stageNumber > 0
    ? stagedSetup
    : serializedIndices ? globalLeafStageSetup : leafStageSetup}
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
}): Uint8Array {
  return compileLocalWordOpeningMerkleGate(args);
}

export const LOCAL_WORD_INTERACTION_LEAF_SHARDS = 2;

/**
 * Bind one disjoint shard of the wide interaction rows to the canonical
 * level-zero Merkle frontier. Higher stages consume only these checked leaf
 * nodes; every raw row and every frontier node is owned exactly once here.
 */
export function compileLocalWordInteractionLeafGate(args: {
  readonly shard: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 ||
    args.publicWordCount > 1024 || !Number.isInteger(args.shard) || args.shard < 0 ||
    args.shard >= LOCAL_WORD_INTERACTION_LEAF_SHARDS) {
    throw new Error("local-word interaction leaf verifier key");
  }
  const matrix = LOCAL_WORD_MATRIX_NAMES.indexOf("interaction");
  const rowWidth = LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix]!;
  const queryCount = parameters.fri.queries;
  const first = Math.floor(args.shard * queryCount / LOCAL_WORD_INTERACTION_LEAF_SHARDS);
  const end = Math.floor((args.shard + 1) * queryCount / LOCAL_WORD_INTERACTION_LEAF_SHARDS);
  const offsets = localWordProofStaticOffsets(args.publicWordCount, parameters);
  const directoryOffset = offsets.openingDirectory + matrix * 20;
  const reader = compile(localWordReadDynamicAssembly(), "local-word interaction leaf reader");
  const canonicalRow = compile(canonicalM31RowAssembly(rowWidth), "local-word interaction canonical row");
  const treeKey = sha256(concatBytes(
    TREE_DOMAIN,
    new TextEncoder().encode(MATRIX_LABELS.interaction),
  ));
  const leafPrefix = concatBytes(Uint8Array.of(0), treeKey);
  const bind = (item: number): string => `<2> OP_PICK
<${offsets.currentIndices + item * 4}> <4> <0> OP_INVOKE OP_NIP
OP_DUP OP_REVERSEBYTES OP_TOALTSTACK
<3> OP_PICK <3> OP_PICK <${item * rowWidth}> OP_ADD <${rowWidth}> <0> OP_INVOKE OP_NIP
OP_DUP <1> OP_INVOKE
OP_CAT ${push(leafPrefix)} OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK OP_SWAP OP_CAT
<3> OP_PICK <2> OP_PICK <${item * 36}> OP_ADD <36> <0> OP_INVOKE OP_NIP
OP_EQUALVERIFY`;
  return compile(`OP_DROP
<0x${binToHex(reader)}> <0> OP_DEFINE
<0x${binToHex(canonicalRow)}> <1> OP_DEFINE
${localWordProofLengthAssembly()}
OP_DUP <${directoryOffset + 4}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK <${directoryOffset + 12}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<2> OP_PICK <1> OP_PICK <4> OP_ADD <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<1> OP_ROLL OP_DROP
${Array.from({ length: end - first }, (_, local) => bind(first + local)).join("\n")}
OP_2DROP OP_DROP OP_1`, `local-word interaction leaf shard ${args.shard}`);
}

export function compileLocalWordFriMerkleGate(args: {
  readonly layer: number;
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly stage?: "complete" | number;
}): Uint8Array {
  return compileLocalWordOpeningMerkleGate({
    friLayer: args.layer,
    publicWordCount: args.publicWordCount,
    parameters: args.parameters,
    stage: args.stage,
  });
}
