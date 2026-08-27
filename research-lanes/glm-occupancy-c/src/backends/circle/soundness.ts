import {
  assertSoundParams,
  BLOWUP,
  COMMITTED_LAYERS,
  CONJECTURAL_BITS,
  conjecturalBits,
  FRI_FINAL,
  FRI_N,
  FRI_QUERIES,
  GRIND_BITS,
  RATE,
  SOUNDNESS_FLOOR,
  SOUNDNESS_TARGET,
  SECURE_FIELD_BIT_LENGTH,
  TRACE_LEN,
  VK_ID,
  RULES_SHA256,
} from "./params.ts";

export type SoundnessWorksheet = {
  family: "circle-fri-m31-qm31";
  field: "QM31";
  baseField: "M31";
  domain: "circle x^2+y^2=1";
  traceLen: number;
  blowup: number;
  friN: number;
  queries: number;
  grind: number;
  finalLayer: number;
  committedLayers: number;
  rate: "1/B" | "2/B";
  conjecturalBits: number;
  floor: number;
  target: number;
  sound: boolean;
  vkId: string;
  rulesSha256: string;
  fieldBits: number;
  queryConjectureBits: number;
  minBits: number;
  note: string;
};

export function soundnessWorksheet(): SoundnessWorksheet {
  assertSoundParams();
  const bits = conjecturalBits({
    queries: FRI_QUERIES,
    blowup: BLOWUP,
    grind: GRIND_BITS,
    rate: RATE,
  });
  const queryBits = bits;
  const fieldBits = SECURE_FIELD_BIT_LENGTH;
  const minBits = Math.min(queryBits, fieldBits);
  return {
    family: "circle-fri-m31-qm31",
    field: "QM31",
    baseField: "M31",
    domain: "circle x^2+y^2=1",
    traceLen: TRACE_LEN,
    blowup: BLOWUP,
    friN: FRI_N,
    queries: FRI_QUERIES,
    grind: GRIND_BITS,
    finalLayer: FRI_FINAL,
    committedLayers: COMMITTED_LAYERS,
    rate: RATE,
    conjecturalBits: queryBits,
    floor: SOUNDNESS_FLOOR,
    target: SOUNDNESS_TARGET,
    sound: minBits >= SOUNDNESS_FLOOR,
    vkId: VK_ID,
    rulesSha256: RULES_SHA256,
    fieldBits,
    queryConjectureBits: queryBits,
    minBits,
    note:
      "Query worksheet 36×3+20=128 at rate 2/B is ethSTARK-style speculative (not Stwo-128). " +
      "Field is QM31 (~124). SZ on TRACE 64 over QM31 is not tens of bits. " +
      "min(query, field, SZ, hash-RO) ≥ 100. qTable/layer-0 stay M31.",
  };
}

export { CONJECTURAL_BITS, assertSoundParams };
