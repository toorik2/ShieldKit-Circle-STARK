/** Versioned parameter target for the local-word successor construction. */
export const LOCAL_WORD_TRACE_LOG = 18;
export const LOCAL_WORD_SEALED_DEGREE_LOG = 19;
export const LOCAL_WORD_QUOTIENT_DEGREE_LOG = 20;

/**
 * Quadratic LogUp point: 28 * (4 - 1) + grind20 = 104. One accumulator per
 * fraction costs columns but deletes cubic products and thirteen query frames.
 */
export const LOCAL_WORD_LDE_LOG = 24;
export const LOCAL_WORD_FRI_LOG_BLOWUP = LOCAL_WORD_LDE_LOG - LOCAL_WORD_QUOTIENT_DEGREE_LOG;
export const LOCAL_WORD_QUERIES = 28;
export const LOCAL_WORD_GRIND_BITS = 20;
export const LOCAL_WORD_QUERY_CONJECTURE_BITS =
  LOCAL_WORD_QUERIES * (LOCAL_WORD_FRI_LOG_BLOWUP - 1) + LOCAL_WORD_GRIND_BITS;

export type LocalWordProofParameters = {
  readonly relationLog: number;
  readonly evalLog: number;
  readonly quotientDegreeRows: number;
  readonly fri: {
    readonly logBlowup: number;
    readonly finalLogDegree: number;
    /** Two binary folds per committed FRI layer; the last may use one. */
    readonly foldLog: 1 | 2;
    /** One collision-free orbit covers every fold before the final polynomial. */
    readonly queryOrbitLog: number;
    readonly queries: number;
    readonly grindBits: number;
  };
};

/** Verifier-key geometry. None of these values are repeated in proof bytes. */
export const LOCAL_WORD_PRODUCTION_PARAMETERS: LocalWordProofParameters = {
  relationLog: LOCAL_WORD_TRACE_LOG,
  evalLog: LOCAL_WORD_LDE_LOG,
  quotientDegreeRows: 2 ** LOCAL_WORD_QUOTIENT_DEGREE_LOG,
  fri: {
    logBlowup: LOCAL_WORD_FRI_LOG_BLOWUP,
    finalLogDegree: 3,
    foldLog: 2,
    queryOrbitLog: LOCAL_WORD_LDE_LOG - LOCAL_WORD_FRI_LOG_BLOWUP - 3,
    queries: LOCAL_WORD_QUERIES,
    grindBits: LOCAL_WORD_GRIND_BITS,
  },
};

export function validateLocalWordProofParameters(
  parameters: LocalWordProofParameters,
): LocalWordProofParameters {
  const { relationLog, evalLog, quotientDegreeRows, fri } = parameters;
  const sealBlowup = evalLog - relationLog - 1;
  const finalLog = fri.finalLogDegree + fri.logBlowup;
  if (!Number.isInteger(relationLog) || relationLog < 1 ||
    !Number.isInteger(evalLog) || evalLog > 30 || sealBlowup < 0 || sealBlowup > 16 ||
    !Number.isSafeInteger(quotientDegreeRows) || quotientDegreeRows < 2 ||
    (quotientDegreeRows & (quotientDegreeRows - 1)) !== 0 ||
    quotientDegreeRows > 2 ** evalLog || quotientDegreeRows > 2 ** (evalLog - fri.logBlowup) ||
    !Number.isInteger(fri.logBlowup) || fri.logBlowup < 0 ||
    !Number.isInteger(fri.finalLogDegree) || fri.finalLogDegree < 0 || finalLog >= evalLog ||
    fri.foldLog !== 2 || evalLog % 2 !== 0 ||
    !Number.isInteger(fri.queryOrbitLog) || fri.queryOrbitLog < 1 ||
    fri.queryOrbitLog !== evalLog - fri.logBlowup - fri.finalLogDegree ||
    !Number.isInteger(fri.queries) || fri.queries < 1 || fri.queries > 2 ** (evalLog - 1) ||
    !Number.isInteger(fri.grindBits) || fri.grindBits < 0 || fri.grindBits > 32) {
    throw new Error("local-word proof parameters");
  }
  return parameters;
}

export function localWordFriFoldCounts(parameters: LocalWordProofParameters): readonly number[] {
  validateLocalWordProofParameters(parameters);
  let remaining = parameters.evalLog - parameters.fri.logBlowup - parameters.fri.finalLogDegree;
  const counts: number[] = [];
  while (remaining > 0) {
    const count = Math.min(parameters.fri.foldLog, remaining);
    counts.push(count);
    remaining -= count;
  }
  return counts;
}

/** Input-domain log for each committed FRI layer. */
export function localWordFriLayerLogs(parameters: LocalWordProofParameters): readonly number[] {
  let log = parameters.evalLog;
  return localWordFriFoldCounts(parameters).map((folds) => {
    const layerLog = log;
    log -= folds;
    return layerLog;
  });
}

if (LOCAL_WORD_FRI_LOG_BLOWUP !== 4 || LOCAL_WORD_QUERY_CONJECTURE_BITS !== 104) {
  throw new Error("local-word successor parameters");
}

validateLocalWordProofParameters(LOCAL_WORD_PRODUCTION_PARAMETERS);
