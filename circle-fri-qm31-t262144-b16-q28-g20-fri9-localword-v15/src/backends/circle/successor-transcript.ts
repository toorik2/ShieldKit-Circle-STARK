import {
  concatBytes,
  sha256,
  writeU32LE,
} from "../../pool/bytes.ts";
import { M31 } from "./m31.ts";
import { encodeQm31, type QM31El } from "./qm31.ts";

export const SUCCESSOR_TRANSCRIPT_DOMAIN = new TextEncoder().encode("ShieldKit/SuccessorTranscript/v2");
const ABSORB_TAG = Uint8Array.of(0);
const CHALLENGE_TAG = Uint8Array.of(1);
const CHALLENGE_COMMIT_TAG = Uint8Array.of(2);
const POW_TAG = Uint8Array.of(3);
const QUERY_TAG = Uint8Array.of(4);

function labelBytes(label: string): Uint8Array {
  const bytes = new TextEncoder().encode(label);
  if (bytes.length < 1 || bytes.length > 96) throw new Error("transcript label");
  return bytes;
}

function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

/** Little-endian 256-bit digest reduced modulo the Mersenne prime. */
export function successorDigestToM31(digest: Uint8Array): bigint {
  if (digest.length !== 32) throw new Error("successor transcript digest width");
  let value = 0n;
  for (let index = digest.length - 1; index >= 0; index -= 1) {
    value = (value * 256n + BigInt(digest[index]!)) % M31;
  }
  return value;
}

/** One fixed-cost SHA-256 Fiat-Shamir state machine for the whole proof. */
export class SuccessorTranscript {
  private current: Uint8Array;

  constructor(initial: Uint8Array) {
    if (initial.length < 1 || initial.length > 0xffff) throw new Error("successor transcript initial");
    this.current = sha256(concatBytes(SUCCESSOR_TRANSCRIPT_DOMAIN, writeU32LE(initial.length), initial));
  }

  get digest(): Uint8Array {
    return new Uint8Array(this.current);
  }

  /** Independent verifier cursor over the same logical transcript state. */
  fork(): SuccessorTranscript {
    const fork = Object.create(SuccessorTranscript.prototype) as SuccessorTranscript;
    fork.current = new Uint8Array(this.current);
    return fork;
  }

  absorb(label: string, data: Uint8Array): void {
    const labelRaw = labelBytes(label);
    this.current = sha256(concatBytes(
      ABSORB_TAG,
      this.current,
      Uint8Array.of(labelRaw.length),
      labelRaw,
      writeU32LE(data.length),
      data,
    ));
  }

  /** Four fixed SHA-256 reductions; the construction accounts for modulo bias. */
  challengeQm31(label: string): QM31El {
    const labelRaw = labelBytes(label);
    const challenge = Array.from({ length: 4 }, (_, coordinate) => successorDigestToM31(sha256(concatBytes(
      CHALLENGE_TAG,
      this.current,
      Uint8Array.of(labelRaw.length),
      labelRaw,
      Uint8Array.of(coordinate),
    )))) as unknown as QM31El;
    this.current = sha256(concatBytes(
      CHALLENGE_COMMIT_TAG,
      this.current,
      Uint8Array.of(labelRaw.length),
      labelRaw,
      encodeQm31(challenge),
    ));
    return challenge;
  }

  grind(bits: number): number {
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error("grind bits");
    for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
      if (this.grindAccepts(bits, nonce)) {
        this.absorb("pow", concatBytes(Uint8Array.of(bits), writeU32LE(nonce)));
        return nonce;
      }
    }
    throw new Error("grind exhausted");
  }

  /** Grind once for PoW and a collision-free fixed query schedule. */
  grindForQueries(
    bits: number,
    rowCount: number,
    count: number,
    orbitLog = 1,
    acceptSchedule: (indices: readonly number[]) => boolean = () => true,
  ): number {
    for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
      if (!this.grindAccepts(bits, nonce)) continue;
      const before = this.current;
      this.absorb("pow", concatBytes(Uint8Array.of(bits), writeU32LE(nonce)));
      try {
        const indices = this.queryIndices(rowCount, count, orbitLog);
        if (!acceptSchedule(indices)) throw new Error("successor query schedule predicate");
        return nonce;
      } catch {
        this.current = before;
      }
    }
    throw new Error("successor conditioned grind exhausted");
  }

  acceptGrind(bits: number, nonce: number): boolean {
    if (!this.grindAccepts(bits, nonce)) return false;
    this.absorb("pow", concatBytes(Uint8Array.of(bits), writeU32LE(nonce)));
    return true;
  }

  private grindAccepts(bits: number, nonce: number): boolean {
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) return false;
    const candidate = sha256(concatBytes(POW_TAG, this.current, Uint8Array.of(bits), writeU32LE(nonce)));
    return leadingZeroBits(candidate) >= bits;
  }

  /**
   * Unique fixed-size bit-reversed orbits. Historical adjacent-pair callers
   * retain fixed counters; deep-orbit successors sample without replacement.
   */
  queryIndices(rowCount: number, count: number, orbitLog = 1): number[] {
    if (!Number.isInteger(rowCount) || rowCount < 2 || (rowCount & (rowCount - 1)) !== 0) {
      throw new Error("query domain");
    }
    const rowLog = Math.log2(rowCount);
    if (!Number.isInteger(orbitLog) || orbitLog < 1 || orbitLog >= rowLog ||
      !Number.isInteger(count) || count < 1 || count > rowCount / 2 ** orbitLog) {
      throw new Error("query count");
    }
    const indices: number[] = [];
    const orbits = new Set<number>();
    for (let counter = 0; indices.length < count; counter += 1) {
      if (counter > 0xffff_ffff) throw new Error("successor query counter exhausted");
      const block = sha256(concatBytes(QUERY_TAG, this.current, writeU32LE(counter)));
      const index = ((block[0]! | (block[1]! << 8) | (block[2]! << 16) |
        (block[3]! << 24)) >>> 0) & (rowCount - 1);
      const orbit = Math.floor(index / 2 ** orbitLog);
      if (orbits.has(orbit)) {
        if (orbitLog === 1) throw new Error("successor query orbit collision");
        continue;
      }
      orbits.add(orbit);
      indices.push(index);
    }
    return indices;
  }
}
