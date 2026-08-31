/** Stack: digest32 -> M31 Script Number, interpreting the digest little-endian. */
export const SUCCESSOR_DIGEST_TO_M31_ASM = `OP_0 OP_SWAP
${Array.from({ length: 8 }, (_, limb) => `<4> OP_SPLIT OP_SWAP
OP_DUP <0xffffff7f> OP_AND OP_BIN2NUM
OP_SWAP <0x00000080> OP_AND <0x00000000> OP_EQUAL OP_NOT
OP_ADD <${1 << limb}> OP_MUL
OP_ROT OP_ADD <2147483647> OP_MOD OP_SWAP`).join("\n")}
OP_DROP`;
