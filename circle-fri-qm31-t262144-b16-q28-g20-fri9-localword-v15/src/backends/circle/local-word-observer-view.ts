import {
  decodeAuthenticationInstructions,
  decodeTransaction,
} from "@bitauth/libauth";
import {
  decodeLocalWordSealedProof,
  LOCAL_WORD_MATRIX_NAMES,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "./local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  partitionLocalWordProofBytes,
} from "../../chain/local-word-proof-carriers.ts";
import {
  decodeLocalWordNullifierData,
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
} from "../../chain/local-word-envelope.ts";
import { concatBytes } from "../../pool/bytes.ts";

export type LocalWordObserverLedger = {
  readonly proofVersion: number;
  readonly transactionBytes: number;
  readonly proofBytes: number;
  readonly carrierInputs: number;
  readonly carrierUnionExact: true;
  readonly transactionShape: {
    readonly inputs: number;
    readonly outputs: number;
    readonly publicNullifierPathNodes: number;
  };
  readonly roots: {
    readonly relationAndAuxiliary: number;
    readonly fri: number;
  };
  readonly directOpenings: {
    readonly currentPoints: number;
    readonly globalPoints: number;
    readonly originalM31Values: number;
    readonly interactionM31Values: number;
    readonly interactionGlobalM31Values: number;
    readonly quotientQm31Values: number;
    readonly friMaskQm31Values: number;
  };
  readonly fri: {
    readonly layerQm31Values: number;
    readonly finalQm31Coefficients: number;
    readonly authenticationNodes: number;
  };
  readonly authenticationNodes: number;
  readonly maskBudget: {
    readonly original: { readonly dimensionsPerColumn: number; readonly openedRankPerColumn: number };
    readonly interaction: { readonly dimensionsPerColumn: number; readonly openedRankPerColumn: number };
    readonly interactionGlobal: { readonly dimensionsPerColumn: number; readonly openedRankPerColumn: number };
    readonly friIsolator: { readonly dimensions: number; readonly conditionedDirectRank: number };
  };
  readonly quotient: {
    readonly decomposition: "none";
    readonly extraWitnessFormsAtQueries: 0;
    readonly reason: "determined by sealed AIR openings";
  };
  readonly protectedTraceRecovery: {
    readonly recovered: false;
    readonly observedPointsPerOriginalColumn: number;
    readonly privateTraceRows: number;
  };
  readonly claimBoundary: {
    readonly algebraicIop: "perfect honest-verifier simulation conditioned on nonzero denominators";
    readonly badDenominatorDistanceBits: 102.61;
    readonly merkleAndFiatShamir: "computational classical programmable ROM";
    readonly qrom: "unresolved";
  };
};

function firstPush(unlockingBytecode: Uint8Array, input: number): Uint8Array {
  const instructions = decodeAuthenticationInstructions(unlockingBytecode);
  if (typeof instructions === "string") {
    throw new Error(`local-word observer unlocking ${input}: ${instructions}`);
  }
  const first = instructions[0];
  if (!first || !("data" in first) || first.data.length < 1) {
    throw new Error(`local-word observer carrier push ${input}`);
  }
  return first.data;
}

/**
 * Adversarially recover the one public proof byte string from serialized
 * transaction inputs. No prover objects, notes, traces, or carrier metadata
 * are trusted by this parser.
 */
export function extractLocalWordProofFromTransaction(raw: Uint8Array): Uint8Array {
  const transaction = decodeTransaction(raw);
  if (typeof transaction === "string") {
    throw new Error(`local-word observer transaction: ${transaction}`);
  }
  if (transaction.inputs.length !== LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word observer carrier count");
  }
  const chunks = transaction.inputs.map((input, index) =>
    firstPush(input.unlockingBytecode, index));
  const proof = concatBytes(...chunks);
  const expected = partitionLocalWordProofBytes(proof);
  if (expected.some((carrier, index) =>
    carrier.chunk.length !== chunks[index]!.length ||
    carrier.chunk.some((byte, offset) => byte !== chunks[index]![offset]))) {
    throw new Error("local-word observer carrier placement");
  }
  return proof;
}

function ledgerFromProof(
  proof: LocalWordSealedProof,
  transactionBytes: number,
  transactionShape: LocalWordObserverLedger["transactionShape"],
  parameters: LocalWordProofParameters,
): LocalWordObserverLedger {
  const current = proof.matrices.original.indices.length;
  const global = proof.matrices.interactionGlobal.indices.length;
  const relationAuthentication = LOCAL_WORD_MATRIX_NAMES.reduce(
    (sum, name) => sum + proof.matrices[name].siblings.length,
    0,
  );
  const friAuthentication = proof.fri.layers.reduce(
    (sum, layer) => sum + layer.siblings.length,
    0,
  );
  return {
    proofVersion: proof.version,
    transactionBytes,
    proofBytes: proof.proofLength,
    carrierInputs: LOCAL_WORD_CARRIER_INPUTS,
    carrierUnionExact: true,
    transactionShape,
    roots: {
      relationAndAuxiliary: LOCAL_WORD_MATRIX_NAMES.length,
      fri: proof.fri.layers.length,
    },
    directOpenings: {
      currentPoints: current,
      globalPoints: global,
      originalM31Values: current * 34,
      interactionM31Values: current * 56,
      interactionGlobalM31Values: global * 12,
      quotientQm31Values: current,
      friMaskQm31Values: current,
    },
    fri: {
      layerQm31Values: proof.fri.layers.reduce((sum, layer) => sum + layer.values.length, 0),
      finalQm31Coefficients: proof.fri.finalCoefficients.length,
      authenticationNodes: friAuthentication,
    },
    authenticationNodes: relationAuthentication + friAuthentication,
    maskBudget: {
      original: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        openedRankPerColumn: current,
      },
      interaction: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        openedRankPerColumn: current,
      },
      interactionGlobal: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        openedRankPerColumn: global,
      },
      friIsolator: {
        dimensions: parameters.quotientDegreeRows,
        conditionedDirectRank: current,
      },
    },
    quotient: {
      decomposition: "none",
      extraWitnessFormsAtQueries: 0,
      reason: "determined by sealed AIR openings",
    },
    protectedTraceRecovery: {
      recovered: false,
      observedPointsPerOriginalColumn: current,
      privateTraceRows: 2 ** parameters.relationLog,
    },
    claimBoundary: {
      algebraicIop: "perfect honest-verifier simulation conditioned on nonzero denominators",
      badDenominatorDistanceBits: 102.61,
      merkleAndFiatShamir: "computational classical programmable ROM",
      qrom: "unresolved",
    },
  };
}

/** Complete observer ledger for the exact serialized envelope-B artifact. */
export function analyzeLocalWordObserverTransaction(
  raw: Uint8Array,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordObserverLedger {
  const proofBytes = extractLocalWordProofFromTransaction(raw);
  const proof = decodeLocalWordSealedProof(proofBytes, context, parameters);
  const transaction = decodeTransaction(raw);
  if (typeof transaction === "string") {
    throw new Error(`local-word observer transaction: ${transaction}`);
  }
  let publicNullifierPathNodes = 0;
  if (proof.profile !== 0) {
    const data = transaction.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT];
    if (!data) throw new Error("local-word observer nullifier output");
    publicNullifierPathNodes = decodeLocalWordNullifierData(data.lockingBytecode).path.length;
  }
  return ledgerFromProof(proof, raw.length, {
    inputs: transaction.inputs.length,
    outputs: transaction.outputs.length,
    publicNullifierPathNodes,
  }, parameters);
}
