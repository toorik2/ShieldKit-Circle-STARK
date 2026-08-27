/**
 * Opt-in batch exit is a **shared round**.
 *
 * First waiter opens one clock. Length is CSPRNG-uniform in
 * [`--batch-min`, `--batch-max`] seconds (default 30..180), unless
 * `--batch-window` pins a fixed length. Later opt-ins wait the **remaining**
 * time — they do not roll their own timer (that would miss the group).
 * At close, one successor pays each waiter to **that waiter's** P2PKH.
 * A late arriver after close opens the next round (new entropy sample).
 *
 * Outputs are CashFusion-*shaped* shuffled multi-P2PKH. Not CashFusion
 * (no OP_RETURN FUSE, no Pedersen / blind Schnorr). The lock HASH256-binds
 * every payout lock+value. Fee change is a dust coin to a fresh address.
 */

/** Default range the first waiter samples when `--batch-window` is omitted. */
export const BATCH_EXIT_WINDOW_MIN_SECONDS_DEFAULT = 30;
export const BATCH_EXIT_WINDOW_MAX_SECONDS_DEFAULT = 180;
/** Pinned `--batch-window` default (also the default max of the sample range). */
export const BATCH_EXIT_WINDOW_SECONDS_DEFAULT = BATCH_EXIT_WINDOW_MAX_SECONDS_DEFAULT;
export const BATCH_EXIT_KNOB_FLOOR_SECONDS = 1;
export const BATCH_EXIT_KNOB_CEILING_SECONDS = 86_400;

export type BatchExitClaim = {
  id: string;
  sats: bigint;
  lockingBytecode: Uint8Array;
  enqueuedAtMs: number;
  /** Local notebook index so a flush can pay this note, not someone else's. */
  noteIndex?: number;
  /** CashAddr this claim pays. Distinct per waiter. */
  address?: string;
};

export type BatchRound = {
  windowSeconds: number;
  openedAtMs: number;
  closesAtMs: number;
  claims: BatchExitClaim[];
};

export type FusionPayout = {
  sats: bigint;
  lockingBytecode: Uint8Array;
};

export type FusionBatchSketch = {
  version: 2;
  outputCount: number;
  totalSats: string;
  shuffled: true;
  shape: "cashfusion-like-multi-p2pkh";
  protocol: "not-cashfusion-fuse";
};

export function parseBatchWindowSeconds(seconds: number): number {
  if (!Number.isInteger(seconds)) throw new Error("batch-window must be an integer number of seconds");
  if (seconds < BATCH_EXIT_KNOB_FLOOR_SECONDS || seconds > BATCH_EXIT_KNOB_CEILING_SECONDS) {
    throw new Error(
      `batch-window must be in [${BATCH_EXIT_KNOB_FLOOR_SECONDS}, ${BATCH_EXIT_KNOB_CEILING_SECONDS}] seconds`,
    );
  }
  return seconds;
}

export function defaultBatchWindowSeconds(): number {
  return BATCH_EXIT_WINDOW_SECONDS_DEFAULT;
}

/**
 * CSPRNG uniform integer in [min, max] inclusive. First waiter uses this as
 * the shared round length. Not a per-person wait.
 */
export function sampleBatchWindowSeconds(args?: {
  minSeconds?: number;
  maxSeconds?: number;
  entropy?: Uint8Array;
}): number {
  const min = parseBatchWindowSeconds(args?.minSeconds ?? BATCH_EXIT_WINDOW_MIN_SECONDS_DEFAULT);
  const max = parseBatchWindowSeconds(args?.maxSeconds ?? BATCH_EXIT_WINDOW_MAX_SECONDS_DEFAULT);
  if (min > max) throw new Error("batch-min must be <= batch-max");
  return uniformInt(min, max, args?.entropy ?? crypto.getRandomValues(new Uint8Array(16)));
}

export function roundIsOpen(round: BatchRound, nowMs: number): boolean {
  return nowMs < round.closesAtMs;
}

/** Seconds left until the shared close. 0 if the round already closed (flush now). */
export function remainingSeconds(round: BatchRound, nowMs: number): number {
  if (nowMs >= round.closesAtMs) return 0;
  return Math.max(0, Math.ceil((round.closesAtMs - nowMs) / 1000));
}

export function randomClaimId(entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(16))): string {
  return Buffer.from(entropy).toString("hex");
}

export function makeBatchExitClaim(args: {
  sats: bigint;
  lockingBytecode: Uint8Array;
  nowMs?: number;
  id?: string;
  noteIndex?: number;
  address?: string;
}): BatchExitClaim {
  if (args.sats <= 0n) throw new Error("batch-exit claim sats must be positive");
  if (args.lockingBytecode.length === 0) throw new Error("batch-exit claim needs a locking bytecode");
  return {
    id: args.id ?? randomClaimId(),
    sats: args.sats,
    lockingBytecode: args.lockingBytecode,
    enqueuedAtMs: args.nowMs ?? Date.now(),
    noteIndex: args.noteIndex,
    address: args.address,
  };
}

function openRound(windowSeconds: number, first: BatchExitClaim, nowMs: number): BatchRound {
  const window = parseBatchWindowSeconds(windowSeconds);
  return {
    windowSeconds: window,
    openedAtMs: nowMs,
    closesAtMs: nowMs + window * 1000,
    claims: [first],
  };
}

/**
 * Join an open round, or open a new one if none exists / the previous already closed.
 * Does **not** restart the clock for a late-but-still-in-window joiner.
 */
export function joinRound(args: {
  round: BatchRound | null;
  sats: bigint;
  lockingBytecode: Uint8Array;
  nowMs?: number;
  /** Pin the shared length. Omit to sample uniform in [min, max]. */
  windowSeconds?: number;
  windowMinSeconds?: number;
  windowMaxSeconds?: number;
  windowEntropy?: Uint8Array;
  id?: string;
  noteIndex?: number;
  address?: string;
}): { round: BatchRound; remainingSeconds: number; openedNew: boolean; claim: BatchExitClaim } {
  const nowMs = args.nowMs ?? Date.now();
  const claim = makeBatchExitClaim({
    sats: args.sats,
    lockingBytecode: args.lockingBytecode,
    nowMs,
    id: args.id,
    noteIndex: args.noteIndex,
    address: args.address,
  });
  if (args.round && roundIsOpen(args.round, nowMs)) {
    const round: BatchRound = {
      ...args.round,
      claims: [...args.round.claims, claim],
    };
    return { round, remainingSeconds: remainingSeconds(round, nowMs), openedNew: false, claim };
  }
  const windowSeconds =
    args.windowSeconds ??
    sampleBatchWindowSeconds({
      minSeconds: args.windowMinSeconds,
      maxSeconds: args.windowMaxSeconds,
      entropy: args.windowEntropy,
    });
  const round = openRound(windowSeconds, claim, nowMs);
  return { round, remainingSeconds: remainingSeconds(round, nowMs), openedNew: true, claim };
}

/** Map CSPRNG bytes onto [min, max] inclusive. Shared round length and output shuffle. */
export function uniformInt(min: number, max: number, entropy: Uint8Array): number {
  if (!Number.isInteger(min) || !Number.isInteger(max)) throw new Error("uniformInt bounds must be integers");
  if (min > max) throw new Error("uniformInt min > max");
  if (entropy.length === 0) throw new Error("uniformInt needs entropy");
  const span = max - min + 1;
  if (span === 1) return min;
  let acc = 0n;
  for (const b of entropy) acc = (acc << 8n) | BigInt(b);
  return min + Number(acc % BigInt(span));
}

function entropyAt(entropy: Uint8Array, offset: number, width: number): Uint8Array {
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i += 1) out[i] = entropy[(offset + i) % entropy.length]!;
  return out;
}

export function shuffleInPlace<T>(items: T[], entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32))): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = uniformInt(0, i, entropyAt(entropy, i * 8, 8));
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
  }
  return items;
}

export function shapeFusionOutputs(
  claims: readonly BatchExitClaim[],
  entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): FusionPayout[] {
  const out: FusionPayout[] = claims.map((c) => ({
    sats: c.sats,
    lockingBytecode: c.lockingBytecode,
  }));
  shuffleInPlace(out, entropy);
  return out;
}

export function fusionBatchSketch(outputs: readonly FusionPayout[]): FusionBatchSketch {
  const total = outputs.reduce((n, o) => n + o.sats, 0n);
  return {
    version: 2,
    outputCount: outputs.length,
    totalSats: total.toString(),
    shuffled: true,
    shape: "cashfusion-like-multi-p2pkh",
    protocol: "not-cashfusion-fuse",
  };
}

export type CountdownIo = {
  sleep?: (ms: number) => Promise<void>;
  write?: (text: string) => void;
};

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function runBatchExitCountdown(seconds: number, io: CountdownIo = {}): Promise<void> {
  if (!Number.isInteger(seconds) || seconds < 0) throw new Error("countdown seconds must be a non-negative integer");
  const write = io.write ?? ((text: string) => process.stderr.write(text));
  const sleep = io.sleep ?? defaultSleep;
  if (seconds === 0) {
    write("batch-exit round closing 0s remaining\n");
    return;
  }
  for (let left = seconds; left > 0; left -= 1) {
    write(`\rbatch-exit round closing in ${left}s   `);
    await sleep(1000);
  }
  write("\rbatch-exit round closing in 0s   \n");
}

export type BatchExitPlan = {
  windowSeconds: number;
  remainingSeconds: number;
  openedNew: boolean;
  round: BatchRound;
  claim: BatchExitClaim;
  outputs: FusionPayout[];
  sketch: FusionBatchSketch;
};

export function planBatchExit(args: {
  sats: bigint;
  lockingBytecode: Uint8Array;
  round?: BatchRound | null;
  windowSeconds?: number;
  windowMinSeconds?: number;
  windowMaxSeconds?: number;
  windowEntropy?: Uint8Array;
  entropy?: Uint8Array;
  nowMs?: number;
  id?: string;
  noteIndex?: number;
  address?: string;
}): BatchExitPlan {
  const joined = joinRound({
    round: args.round ?? null,
    sats: args.sats,
    lockingBytecode: args.lockingBytecode,
    nowMs: args.nowMs,
    windowSeconds: args.windowSeconds,
    windowMinSeconds: args.windowMinSeconds,
    windowMaxSeconds: args.windowMaxSeconds,
    windowEntropy: args.windowEntropy,
    id: args.id,
    noteIndex: args.noteIndex,
    address: args.address,
  });
  const entropy = args.entropy ?? crypto.getRandomValues(new Uint8Array(32));
  const outputs = shapeFusionOutputs(joined.round.claims, entropy);
  return {
    windowSeconds: joined.round.windowSeconds,
    remainingSeconds: joined.remainingSeconds,
    openedNew: joined.openedNew,
    round: joined.round,
    claim: joined.claim,
    outputs,
    sketch: fusionBatchSketch(outputs),
  };
}

export type StoredBatchRound = {
  version: 1;
  windowSeconds: number;
  openedAtMs: number;
  closesAtMs: number;
  claims: Array<{
    id: string;
    sats: string;
    lockingHex: string;
    enqueuedAtMs: number;
    noteIndex?: number;
    address?: string;
  }>;
};

export function encodeRound(round: BatchRound): StoredBatchRound {
  return {
    version: 1,
    windowSeconds: round.windowSeconds,
    openedAtMs: round.openedAtMs,
    closesAtMs: round.closesAtMs,
    claims: round.claims.map((c) => ({
      id: c.id,
      sats: c.sats.toString(),
      lockingHex: Buffer.from(c.lockingBytecode).toString("hex"),
      enqueuedAtMs: c.enqueuedAtMs,
      noteIndex: c.noteIndex,
      address: c.address,
    })),
  };
}

export function decodeRound(stored: StoredBatchRound): BatchRound {
  if (stored.version !== 1) throw new Error("unknown batch-exit round version");
  return {
    windowSeconds: stored.windowSeconds,
    openedAtMs: stored.openedAtMs,
    closesAtMs: stored.closesAtMs,
    claims: stored.claims.map((c) => ({
      id: c.id,
      sats: BigInt(c.sats),
      lockingBytecode: Uint8Array.from(Buffer.from(c.lockingHex, "hex")),
      enqueuedAtMs: c.enqueuedAtMs,
      noteIndex: c.noteIndex,
      address: c.address,
    })),
  };
}
