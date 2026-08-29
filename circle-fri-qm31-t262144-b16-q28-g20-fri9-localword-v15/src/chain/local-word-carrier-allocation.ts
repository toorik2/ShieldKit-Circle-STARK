/**
 * Canonical proof-byte allocation in semantic verifier order.
 *
 * These are construction data, not padding: each number is the largest exact
 * chunk requirement observed for that role in the v15 product and spread-
 * orbit fixtures. The one canonical proof is partitioned in this proportion.
 */

const QUERY_ALGEBRA = [
  1011, 976, 999, 1023, 977, 1082, 1015, 979, 984, 973, 972, 1025, 976, 984,
  1069, 983, 980, 1003, 985, 984, 982, 993, 975, 977, 1024, 976, 982, 994,
] as const;

const QUERY_FRI = [
  2205, 2128, 2169, 2183, 2138, 2168, 2192, 2203, 2139, 2238, 2199, 2240,
  2163, 2168, 2188, 2201, 2156, 2178, 2214, 2158, 2147, 2133, 2135, 2146,
  2101, 2168, 2176, 2103,
] as const;

const OPENING_FRI = [845, 840, 887, 831, 833, 836, 823, 830, 1348] as const;

const MERKLE: Readonly<Record<string, number>> = {
  "merkle:preprocessed:0": 3552,
  "merkle:preprocessed:1": 8005,
  "merkle:preprocessed:2": 2882,
  "merkle:original:0": 2714,
  "merkle:original:1": 8017,
  "merkle:original:2": 2867,
  "merkle:interaction:leaf:0": 1598,
  "merkle:interaction:leaf:1": 1588,
  "merkle:interaction:1": 8194,
  "merkle:interaction:2": 7060,
  "merkle:interaction:3": 256,
  "merkle:quotientAndFriMask:0": 4613,
  "merkle:quotientAndFriMask:1": 8406,
  "merkle:quotientAndFriMask:2": 2879,
  "merkle:interactionGlobal:0": 4480,
  "merkle:interactionGlobal:1": 6838,
  "merkle:interactionGlobal:2": 6688,
  "merkle:interactionGlobal:3": 6583,
  "merkle:interactionGlobal:4": 6261,
  "merkle:interactionGlobal:5": 720,
  "merkle:interactionGlobal:6": 256,
  "merkle:fri:0:0": 4323,
  "merkle:fri:0:1": 4818,
  "merkle:fri:0:2": 4837,
  "merkle:fri:0:3": 3753,
  "merkle:fri:0:4": 256,
  "merkle:fri:1:0": 4351,
  "merkle:fri:1:1": 4895,
  "merkle:fri:1:2": 4970,
  "merkle:fri:1:3": 2414,
  "merkle:fri:1:4": 256,
  "merkle:fri:2:0": 4384,
  "merkle:fri:2:1": 4956,
  "merkle:fri:2:2": 4933,
  "merkle:fri:2:3": 709,
  "merkle:fri:3:0": 4481,
  "merkle:fri:3:1": 5170,
  "merkle:fri:3:2": 4053,
  "merkle:fri:3:3": 256,
  "merkle:fri:4:0": 4560,
  "merkle:fri:4:1": 5452,
  "merkle:fri:4:2": 2633,
  "merkle:fri:4:3": 256,
  "merkle:fri:5:0": 4533,
  "merkle:fri:5:1": 5289,
  "merkle:fri:5:2": 781,
  "merkle:fri:6:0": 4502,
  "merkle:fri:6:1": 4230,
  "merkle:fri:6:2": 256,
  "merkle:fri:7:0": 4510,
  "merkle:fri:7:1": 2746,
  "merkle:fri:7:2": 256,
  "merkle:fri:8:0": 2643,
  "merkle:fri:8:1": 752,
};

function numbered(name: string, expression: RegExp, values: readonly number[]): number | undefined {
  const match = expression.exec(name);
  if (match === null) return undefined;
  const value = values[Number(match[1])];
  if (value === undefined) throw new Error(`local-word role budget ${name}`);
  return value;
}

/** Exact measured budget for one semantic verifier role. */
export function localWordVerifierRoleBudget(name: string): number {
  if (/^query:\d+:air$/.test(name) || name === "header" || name === "boundary:sum" ||
    name === "query-schedule") return 256;

  const boundary = /^boundary:(\d+)-(\d+)$/.exec(name);
  if (boundary !== null) {
    const start = Number(boundary[1]);
    const width = Number(boundary[2]) - start + 1;
    return start === 0 ? 760 : start === width ? 736 : 384;
  }

  const fixed: Readonly<Record<string, number>> = {
    "nullifier:absence:0": 1728,
    "nullifier:absence:1": 1752,
    "nullifier:used:0": 1736,
    "nullifier:used:1": 1752,
    "transcript:interaction": 424,
    "transcript:composition": 256,
    "transcript:batch": 256,
    "transcript:fri-first": 256,
    "transcript:fri-second": 256,
    "transcript:final": 256,
    "opening:current": 1880,
    "opening:global-current": 256,
    "opening:global-previous": 924,
    "opening:global-shape": 690,
  };
  const exact = fixed[name] ?? MERKLE[name];
  if (exact !== undefined) return exact;

  const openingFri = numbered(name, /^opening:fri:(\d+)$/, OPENING_FRI);
  if (openingFri !== undefined) return openingFri;
  const algebra = numbered(name, /^query:(\d+):algebra$/, QUERY_ALGEBRA);
  if (algebra !== undefined) return algebra;
  const fri = numbered(name, /^query:(\d+):fri$/, QUERY_FRI);
  if (fri !== undefined) return fri;
  throw new Error(`local-word role budget ${name}`);
}

/**
 * Input zero is settlement; inputs 1..167 follow the semantic order in
 * compileLocalWordVerifierBank. Keeping this short builder next to the budget
 * evidence makes accidental role insertion or reordering fail immediately.
 */
export function localWordCanonicalCarrierBudgets(roleNames: readonly string[]): readonly number[] {
  // Input zero owns the complete fixed control-plane prefix (through the
  // opening directory); oracle bodies begin at input one.
  const budgets = [4192, ...roleNames.map(localWordVerifierRoleBudget)];
  if (budgets.length !== 168 || budgets.some((budget) => !Number.isInteger(budget) || budget < 256)) {
    throw new Error("local-word canonical carrier budgets");
  }
  return budgets;
}

const CANONICAL_ROLE_NAMES = [
  ...Array.from({ length: 28 }, (_, query) => `query:${query}:air`),
  "boundary:0-11",
  "boundary:12-23",
  "boundary:24-33",
  "header",
  "nullifier:absence:0",
  "nullifier:absence:1",
  "nullifier:used:0",
  "nullifier:used:1",
  "boundary:sum",
  "transcript:interaction",
  "transcript:composition",
  "transcript:batch",
  "transcript:fri-first",
  "transcript:fri-second",
  "transcript:final",
  "query-schedule",
  "opening:current",
  "opening:global-current",
  "opening:global-previous",
  "opening:global-shape",
  ...Array.from({ length: 9 }, (_, layer) => `opening:fri:${layer}`),
  ...Array.from({ length: 28 }, (_, query) => [
    `query:${query}:algebra`,
    `query:${query}:fri`,
  ]).flat(),
  ...Object.keys(MERKLE),
] as const;

/** Canonical semantic input order shared by the partitioner and VM bank. */
export const LOCAL_WORD_CANONICAL_ROLE_NAMES: readonly string[] = CANONICAL_ROLE_NAMES;
export const LOCAL_WORD_CARRIER_BUDGETS = localWordCanonicalCarrierBudgets(
  LOCAL_WORD_CANONICAL_ROLE_NAMES,
);
