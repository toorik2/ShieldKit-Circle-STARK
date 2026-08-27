import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { COMMITTED_LAYERS, FRI_LOG_N, FRI_QUERIES, FRI_VERSION, VK_ID } from "../backends/circle/params.ts";
import { sha256 } from "../pool/bytes.ts";
import { AIR_OFF_QTABLE, LOAD_AIR_PACKED } from "./air-cqz.ts";

/** One layer-major compact Merkle kernel per committed FRI layer. */
export const FRI_KERNEL_INPUTS = COMMITTED_LAYERS;
/** Compact path: bit || u16le unique-table index. */
export const COMPACT_PATH_STRIDE = 3;
/** Layer 0 is 8 B (2×M31). Layers 1–6 are 32 B (2×QM31). */
export const FRI_PAIR_BYTES_L0 = 8;
export const FRI_PAIR_BYTES_QM = 32;
export const FRI_PAIR_GROUP_BYTES = FRI_PAIR_BYTES_L0 + FRI_PAIR_BYTES_QM * (COMMITTED_LAYERS - 1);
export const FRI_PAIR_BYTES = FRI_PAIR_GROUP_BYTES;
/** One layer's leftover: 36 × 8 (L0) or 36 × 32 (later). */
export const FRI_LEFTOVER_L0_BYTES = FRI_QUERIES * FRI_PAIR_BYTES_L0;
export const FRI_LEFTOVER_LATER_BYTES = FRI_QUERIES * FRI_PAIR_BYTES_QM;
/** Input-0 leftover: [L6][L5]…[L1][L0], LIFO from the end per kernel copy. */
export const FRI_LEFTOVER_BYTES =
  FRI_LEFTOVER_LATER_BYTES * (COMMITTED_LAYERS - 1) + FRI_LEFTOVER_L0_BYTES;

/**
 * One paired-Merkle opening.
 * Stack: left right steps layerIndex
 * layerIndex 0..6 → layerRoots[i].
 * layerIndex 16..22 → layerRoots[i-16] (extra honest Q queries).
 * Actual layer 0 (0 or 16): opened felt must equal some packed qTable entry.
 * Steps length must be (FRI_LOG_N-1-layer)*33 so an 8-leaf dummy cannot walk.
 */
export const FRI_LAYER_UNBOUND = 16;

/** First unlocking push body (pair blob when present). Stack: unlocking → body. */
export const FIRST_PUSH_BODY = `
<1> OP_SPLIT
OP_OVER
<0x4c>
OP_NUMEQUAL
OP_IF
  OP_NIP
  <1> OP_SPLIT
  OP_SWAP
  <0x00>
  OP_CAT
  OP_BIN2NUM
  OP_SPLIT
  OP_DROP
OP_ELSE
  OP_OVER
  <0x4d>
  OP_NUMEQUAL
  OP_IF
    OP_NIP
    <2> OP_SPLIT
    OP_SWAP
    <0x00>
    OP_CAT
    OP_BIN2NUM
    OP_SPLIT
    OP_DROP
  OP_ELSE
    OP_SWAP
    OP_BIN2NUM
    OP_SPLIT
    OP_DROP
  OP_ENDIF
OP_ENDIF
`;

/** Stack: unlocking → body rest. */
export const PUSH_BODY_KEEP_REST = `
<1> OP_SPLIT
OP_OVER
<0x4c>
OP_NUMEQUAL
OP_IF
  OP_NIP
  <1> OP_SPLIT
  OP_SWAP
  <0x00>
  OP_CAT
  OP_BIN2NUM
  OP_SPLIT
OP_ELSE
  OP_OVER
  <0x4d>
  OP_NUMEQUAL
  OP_IF
    OP_NIP
    <2> OP_SPLIT
    OP_SWAP
    <0x00>
    OP_CAT
    OP_BIN2NUM
    OP_SPLIT
  OP_ELSE
    OP_SWAP
    OP_BIN2NUM
    OP_SPLIT
  OP_ENDIF
OP_ENDIF
`;

const PAIR_BYTES = FRI_PAIR_BYTES;

/** Stack: L R slot → L R. Slot copied to alt. */
function pairBlobBindAsm(layer: number): string {
  return `
OP_DUP
OP_TOALTSTACK
<${PAIR_BYTES}>
OP_MUL
<${layer * 8}>
OP_ADD
OP_TOALTSTACK
OP_OVER
OP_OVER
OP_CAT
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_FROMALTSTACK
OP_SPLIT
OP_NIP
<8>
OP_SPLIT
OP_DROP
OP_EQUALVERIFY
`;
}

/**
 * Pair-blob leftover bind is skipped: QM31 later-layer pairs live on fold
 * unlocking, not a leftover group on this kernel. Merkle still hashes L||R.
 */
const PAIR_BLOB_BIND = `
OP_NOP
`;

const PAIR_BLOB_BIND_UNUSED = `
OP_TOALTSTACK
OP_3 OP_PICK
OP_3 OP_PICK
OP_CAT
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
<8>
OP_MUL
OP_TOALTSTACK
OP_INPUTINDEX
OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_DUP
OP_SIZE
OP_NIP
OP_DUP
<8>
OP_MOD
OP_0
OP_NUMEQUAL
OP_IF
  OP_DUP
  <8>
  OP_GREATERTHANOREQUAL
  OP_IF
    OP_DROP
    OP_FROMALTSTACK
    OP_DUP
    <8>
    OP_ADD
    OP_2 OP_PICK
    OP_SIZE
    OP_NIP
    OP_SWAP
    OP_GREATERTHANOREQUAL
    OP_IF
      OP_SPLIT
      OP_NIP
      <8>
      OP_SPLIT
      OP_DROP
      OP_EQUALVERIFY
    OP_ELSE
      OP_DROP
      OP_DROP
      OP_DROP
    OP_ENDIF
  OP_ELSE
    OP_DROP
    OP_DROP
    OP_DROP
    OP_FROMALTSTACK
    OP_DROP
  OP_ENDIF
OP_ELSE
  OP_DROP
  OP_DROP
  OP_DROP
  OP_FROMALTSTACK
  OP_DROP
OP_ENDIF
`;

export const FRI_ONE_OPENING = `
${PAIR_BLOB_BIND}
OP_DUP
<${FRI_LAYER_UNBOUND}>
OP_GREATERTHANOREQUAL
OP_IF
  <${FRI_LAYER_UNBOUND}>
  OP_SUB
OP_ENDIF
OP_DUP
OP_0
OP_EQUAL
OP_TOALTSTACK
OP_DUP
<${FRI_LOG_N - 1}>
OP_SWAP
OP_SUB
<33>
OP_MUL
OP_2 OP_PICK
OP_SIZE
OP_NIP
OP_NUMEQUALVERIFY
OP_DUP
OP_TOALTSTACK
<32> OP_MUL
<0> OP_INPUTBYTECODE
<1> OP_SPLIT
OP_NIP
<2> OP_SPLIT
OP_NIP
OP_SWAP
OP_SPLIT
OP_NIP
<32> OP_SPLIT
OP_DROP
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DUP
OP_SHA256
OP_SWAP
OP_SHA256
OP_SWAP
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <33> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    OP_ROT
    OP_SWAP
    OP_ROT
    OP_IF
      OP_SWAP
    OP_ENDIF
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DROP
OP_FROMALTSTACK
OP_IF
  OP_FROMALTSTACK
  <4>
  OP_MUL
  <${AIR_OFF_QTABLE}>
  OP_ADD
  <0> OP_INPUTBYTECODE
  <1> OP_SPLIT OP_NIP
  <2> OP_SPLIT OP_NIP
  OP_SWAP
  OP_SPLIT OP_NIP
  <4> OP_SPLIT OP_DROP
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_TOALTSTACK
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_SWAP
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_FROMALTSTACK
  OP_DUP
  OP_3 OP_PICK
  OP_NUMEQUAL
  OP_SWAP
  OP_2 OP_PICK
  OP_NUMEQUAL
  OP_BOOLOR
  OP_VERIFY
  OP_2DROP
  OP_1
OP_ELSE
  OP_FROMALTSTACK
  OP_DROP
  OP_2DROP
  OP_0
OP_ENDIF
`;

/**
 * Batch kernel: stack is (left right steps layerIndex)×N then N.
 * At least one opening must be actual layer 0 (index 0 or 16) so a spend
 * that only uses 17–22 cannot skip the Q bind.
 */
export const FRI_QUERY_KERNEL = `
OP_0
OP_SWAP
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    ${FRI_ONE_OPENING}
    OP_FROMALTSTACK
    OP_BOOLOR
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_VERIFY
    OP_DEPTH
    OP_IF
      OP_DROP
    OP_ENDIF
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;

export const FRI_MERKLE_ONLY_KERNEL = FRI_QUERY_KERNEL;

function compactOpeningAsm(layer: number): string {
  const pathBytes = (FRI_LOG_N - 1 - layer) * 3;
  const qBind = layer === 0 ? `
<4>
OP_MUL
<${AIR_OFF_QTABLE}>
OP_ADD
<0> OP_INPUTBYTECODE
${PUSH_BODY_KEEP_REST}
OP_DROP
OP_SWAP
OP_SPLIT
OP_NIP
<4> OP_SPLIT
OP_DROP
<0x00> OP_CAT
OP_BIN2NUM
OP_TOALTSTACK
<0x00> OP_CAT
OP_BIN2NUM
OP_SWAP
<0x00> OP_CAT
OP_BIN2NUM
OP_FROMALTSTACK
OP_DUP
OP_3 OP_PICK
OP_NUMEQUAL
OP_SWAP
OP_2 OP_PICK
OP_NUMEQUAL
OP_BOOLOR
OP_VERIFY
OP_2DROP
` : "OP_DROP\nOP_2DROP\n";
  return `
OP_TOALTSTACK
OP_SIZE
<${pathBytes}>
OP_NUMEQUALVERIFY
OP_TOALTSTACK
OP_2DUP
OP_SHA256
OP_SWAP
OP_SHA256
OP_SWAP
OP_CAT
OP_SHA256
<${layer * 32}>
<0> OP_INPUTBYTECODE
${PUSH_BODY_KEEP_REST}
OP_DROP
OP_SWAP
OP_SPLIT
OP_NIP
<32> OP_SPLIT
OP_DROP
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <3> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    <0x00> OP_CAT
    OP_BIN2NUM
    OP_DEPTH
    <2> OP_SUB
    OP_SWAP
    OP_SUB
    OP_PICK
    OP_ROT
    OP_SWAP
    OP_ROT
    OP_IF
      OP_SWAP
    OP_ENDIF
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DROP
OP_2DROP
`;
}

export function compactFriQueryKernelAsm(layer = 0): string {
  const stride = 8;
  const opening = `
OP_DUP
<${FRI_LAYER_UNBOUND}>
OP_GREATERTHANOREQUAL
OP_IF
  <${FRI_LAYER_UNBOUND}>
  OP_SUB
OP_ENDIF
OP_DUP
OP_0
OP_EQUAL
OP_TOALTSTACK
OP_DUP
<${FRI_LOG_N - 1}>
OP_SWAP
OP_SUB
<${stride}>
OP_MUL
OP_2 OP_PICK
OP_SIZE
OP_NIP
OP_NUMEQUALVERIFY
OP_DUP
OP_TOALTSTACK
<32> OP_MUL
<0> OP_INPUTBYTECODE
<1> OP_SPLIT
OP_NIP
<2> OP_SPLIT
OP_NIP
OP_SWAP
OP_SPLIT
OP_NIP
<32> OP_SPLIT
OP_DROP
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DUP
OP_SHA256
OP_SWAP
OP_SHA256
OP_SWAP
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <${stride}> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    <2> OP_SPLIT
    OP_DROP
    <0x00> OP_CAT
    OP_BIN2NUM
    OP_DEPTH
    <2> OP_SUB
    OP_SWAP
    OP_SUB
    OP_PICK
    OP_ROT
    OP_SWAP
    OP_ROT
    OP_IF
      OP_SWAP
    OP_ENDIF
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DROP
OP_FROMALTSTACK
OP_DROP
OP_2DROP
`;
  return `
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    ${opening}
    OP_FROMALTSTACK
    OP_DROP
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_BEGIN
      OP_DEPTH
      OP_IF
        OP_DROP
        OP_0
      OP_ELSE
        OP_1
      OP_ENDIF
    OP_UNTIL
    OP_1
  OP_ENDIF
OP_UNTIL
<${FRI_VERSION}>
OP_DUP
OP_EQUALVERIFY
<0x${Buffer.concat([Buffer.from(VK_ID), Buffer.alloc(128)]).subarray(0, 128).toString("hex")}>
OP_SIZE
<128>
OP_NUMEQUALVERIFY
OP_DROP
OP_1
`;
}

/** Copy packed from under `above` alt workspace items. Alt is [pairs, packed, ...ws]. */
function altExposePacked(above: number): string {
  const fromWs = Array.from({ length: above }, () => "OP_FROMALTSTACK").join("\n");
  const restore = Array.from({ length: above }, () => "OP_SWAP\nOP_TOALTSTACK").join("\n");
  return `
${fromWs}
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
${restore}
`;
}

function compactQBindAsm(): string {
  return `
OP_FROMALTSTACK
<4>
OP_MUL
<${AIR_OFF_QTABLE}>
OP_ADD
${altExposePacked(1)}
OP_SWAP
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
<0x00>
OP_CAT
OP_BIN2NUM
OP_TOALTSTACK
<0x00>
OP_CAT
OP_BIN2NUM
OP_SWAP
<0x00>
OP_CAT
OP_BIN2NUM
OP_FROMALTSTACK
OP_DUP
OP_3 OP_PICK
OP_NUMEQUAL
OP_SWAP
OP_2 OP_PICK
OP_NUMEQUAL
OP_BOOLOR
OP_VERIFY
OP_2DROP
`;
}

/** Move remaining pairs off alt, split the last query group, park the prefix. OP_SIZE does not consume. */
function altConsumeLastGroup(workspace: number, parkPacked: boolean, stride: number): string {
  const fromWs = Array.from({ length: workspace }, () => "OP_FROMALTSTACK").join("\n");
  const restore = Array.from({ length: workspace }, () => "OP_SWAP\nOP_TOALTSTACK").join("\n");
  const consume = `
OP_SIZE
OP_DUP
<${stride}>
OP_GREATERTHANOREQUAL
OP_IF
  <${stride}>
  OP_SUB
  OP_SPLIT
OP_ELSE
  OP_DROP
OP_ENDIF
`;
  const packedPark = parkPacked
    ? `
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
${consume}
OP_SWAP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
`
    : `
OP_FROMALTSTACK
OP_FROMALTSTACK
${consume}
OP_SWAP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
`;
  return `
${fromWs}
${packedPark}
${restore}
`;
}

function altExposeRoot(workspace: number, parkPacked: boolean): string {
  const fromWs = Array.from({ length: workspace }, () => "OP_FROMALTSTACK").join("\n");
  const restore = Array.from({ length: workspace }, () => "OP_SWAP\nOP_TOALTSTACK").join("\n");
  const root = parkPacked
    ? `
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
`
    : `
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
`;
  return `
${fromWs}
${root}
${restore}
`;
}

function compactPairBindAsm(layer: number): string {
  const stride = layer === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM;
  if (layer === 0) {
    return `
OP_TOALTSTACK
OP_2DUP
OP_CAT
${altConsumeLastGroup(3, true, stride)}
<0>
OP_SPLIT
OP_NIP
<${stride}>
OP_SPLIT
OP_DROP
OP_EQUALVERIFY
`;
  }
  return `
OP_TOALTSTACK
OP_2DUP
OP_CAT
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SIZE
OP_DUP
<${stride}>
OP_GREATERTHANOREQUAL
OP_IF
  <${stride}>
  OP_SUB
  OP_SPLIT
OP_ELSE
  OP_DROP
OP_ENDIF
OP_SWAP
OP_TOALTSTACK
OP_5 OP_ROLL
OP_SWAP
OP_EQUALVERIFY
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
`;
}

function compactRootBindAsm(layer: number): string {
  return `
${altExposeRoot(2, layer === 0)}
OP_EQUALVERIFY
`;
}

function compactItemLookupAsm(): string {
  return `
<${COMPACT_PATH_STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
<0x00>
OP_CAT
OP_BIN2NUM
OP_DEPTH
<2>
OP_SUB
OP_SWAP
OP_SUB
OP_DUP
<0>
OP_GREATERTHANOREQUAL
OP_VERIFY
OP_DUP
OP_DEPTH
OP_1SUB
OP_LESSTHAN
OP_VERIFY
OP_PICK
OP_ROT
OP_SWAP
OP_ROT
OP_IF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_FROMALTSTACK
`;
}

function leftoverSkipFromEnd(layer: number): number {
  if (layer === 0) return 0;
  return FRI_LEFTOVER_L0_BYTES + FRI_LEFTOVER_LATER_BYTES * (layer - 1);
}

function leftoverKeepBytes(layer: number): number {
  return FRI_LEFTOVER_BYTES - leftoverSkipFromEnd(layer);
}

function leftoverRemainingAfter(layer: number): number {
  const stride = layer === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM;
  return leftoverKeepBytes(layer) - FRI_QUERIES * stride;
}

/** Drop the suffix belonging to layers this kernel does not consume (fresh copy from input 0). */
function trimLeftoverAsm(layer: number): string {
  const skip = leftoverSkipFromEnd(layer);
  if (skip === 0) return "";
  return `
OP_FROMALTSTACK
<${leftoverKeepBytes(layer)}>
OP_SPLIT
OP_DROP
OP_TOALTSTACK
`;
}

/** Layer-baked compact unique-table walker. packed||pairs is fetched once. L0 parks packed for qTable; later layers keep only pairs+root. */
export function compactLayerKernelAsm(layer = 0): string {
  const pathBytes = (FRI_LOG_N - 1 - layer) * COMPACT_PATH_STRIDE;
  const qBind = layer === 0 ? compactQBindAsm() : "OP_FROMALTSTACK\nOP_DROP\n";
  const leafHash = layer === 0
    ? `OP_2DUP
    OP_SHA256
    OP_SWAP
    OP_SHA256
    OP_SWAP
    OP_CAT
    OP_SHA256`
    : `OP_SHA256
    OP_SWAP
    OP_SHA256
    OP_SWAP
    OP_CAT
    OP_SHA256`;
  const rootExtract = layer === 0
    ? `OP_DUP
<32>
OP_SPLIT
OP_DROP
OP_TOALTSTACK
OP_TOALTSTACK`
    : `<${layer * 32}>
OP_SPLIT
OP_NIP
<32>
OP_SPLIT
OP_DROP
OP_TOALTSTACK`;
  const altCleanup = layer === 0
    ? `OP_FROMALTSTACK
    OP_DROP
    OP_FROMALTSTACK
    OP_DROP
    OP_FROMALTSTACK
    OP_SIZE
    <${leftoverRemainingAfter(0)}>
    OP_NUMEQUALVERIFY
    OP_DROP`
    : `OP_FROMALTSTACK
    OP_DROP
    OP_FROMALTSTACK
    OP_SIZE
    <${leftoverRemainingAfter(layer)}>
    OP_NUMEQUALVERIFY
    OP_DROP`;
  return `
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_TOALTSTACK
${LOAD_AIR_PACKED}
${trimLeftoverAsm(layer)}
${rootExtract}
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_SIZE
    <${pathBytes}>
    OP_NUMEQUALVERIFY
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    ${compactPairBindAsm(layer)}
    ${leafHash}
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    OP_BEGIN
      OP_SIZE
      OP_0 OP_GREATERTHAN
      OP_IF
        ${compactItemLookupAsm()}
        OP_0
      OP_ELSE
        OP_DROP
        OP_1
      OP_ENDIF
    OP_UNTIL
    ${compactRootBindAsm(layer)}
    ${qBind}
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_BEGIN
      OP_DEPTH
      OP_IF
        OP_DROP
        OP_0
      OP_ELSE
        OP_1
      OP_ENDIF
    OP_UNTIL
    ${altCleanup}
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;
}

export function compileFriQueryKernel(layer = 0): Uint8Array {
  const bin = cashAssemblyToBin(compactLayerKernelAsm(layer));
  if (typeof bin === "string") throw new Error(`fri kernel layer ${layer}: ${bin}`);
  return bin;
}

export function compileFriQueryLockP2sh32(layer = 0): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFriQueryKernel(layer)));
}

export function compileFriMerkleOnlyKernel(layer = 0): Uint8Array {
  return compileFriQueryKernel(layer);
}

export function compileFriMerkleOnlyLockP2sh32(layer = 0): Uint8Array {
  return compileFriQueryLockP2sh32(layer);
}
