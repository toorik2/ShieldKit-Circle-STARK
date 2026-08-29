import { concatBytes, sha256, writeU32BE } from "../../pool/bytes.ts";

export const LOCAL_WORD_CONSTRUCTION_VERSION = 15;

export type LocalWordConstructionComponent = {
  readonly role:
    | "rules"
    | "membrane"
    | "completeness"
    | "construction-document"
    | "parameters"
    | "transcript"
    | "proof-codec"
    | "prover-codec"
    | "verifier-keys"
    | "relation-codec"
    | "soundness"
    | "carrier-codec"
    | "carrier-allocation"
    | "verifier-manifest";
  readonly path: string;
  readonly sha256Hex: string;
};

/**
 * Frozen normative inputs for construction v15. This file is deliberately not
 * one of its own components: the identifier has no self-reference. A test
 * hashes each current file and fails on any unversioned change.
 */
export const LOCAL_WORD_V15_COMPONENTS: readonly LocalWordConstructionComponent[] = [
  {
    role: "rules",
    path: "RULES.md",
    sha256Hex: "49542e5f5fc9a13a16a3e205fe1408b1cfca49311c1f4e2613527d530fed9db5",
  },
  {
    role: "membrane",
    path: "ZK-MEMBRANE.md",
    sha256Hex: "b2d8d9fa5bc2cfb3dff0bb3fc405a0c8169ef1de7a81a95fce6fa752cd551afc",
  },
  {
    role: "completeness",
    path: "COMPLETENESS.md",
    sha256Hex: "2a80a0f11e6aeb2e7d769b316d104f509ac84f48312a3b29d45e11bbcacb2f65",
  },
  {
    role: "construction-document",
    path: "SUCCESSOR-CONSTRUCTION.md",
    sha256Hex: "58c7df639c83248051dbb06963e3d7dcbe3f93022ef1e202b9c412389ec83c5c",
  },
  {
    role: "parameters",
    path: "src/backends/circle/local-word-successor-params.ts",
    sha256Hex: "9b50e94cf682162b89cc80c6789b3e5f0dc1488fdd877ff9b3940b4c5f8fea9f",
  },
  {
    role: "transcript",
    path: "src/backends/circle/local-word-transcript.ts",
    sha256Hex: "4c26bbbf40fb22dcde16afef4c6adcc884500bd77fc235eeb8fc10c26c5387b6",
  },
  {
    role: "proof-codec",
    path: "src/backends/circle/local-word-sealed-proof.ts",
    sha256Hex: "6e8f75e279673311bfacdc378895ff3edca15e3b344c3a082654ea7bdc3ec6f8",
  },
  {
    role: "prover-codec",
    path: "src/backends/circle/local-word-prover-bundle.ts",
    sha256Hex: "8970425846321687a3501b73e0354baf513d5dda5acc692bc0c7af1c2aff601b",
  },
  {
    role: "verifier-keys",
    path: "src/backends/circle/local-word-verifier-keys-v15.ts",
    sha256Hex: "57b80ef0c4aec0ced962b8bdf02e1ba789905fa95a8824d8f0875e3da0b2fe19",
  },
  {
    role: "relation-codec",
    path: "src/chain/sha256-local-word-codec.ts",
    sha256Hex: "24aacfcc1d15e3fa7ca45a1978afc1d7a5c103b96aa4076d371ef35882f12c2d",
  },
  {
    role: "soundness",
    path: "src/chain/sha256-local-word-permutation.ts",
    sha256Hex: "27208fec4b0a3e4db94ce2ff2bffc21026a1c2d4668a854b5c6f62755a927092",
  },
  {
    role: "carrier-codec",
    path: "src/chain/local-word-proof-carriers.ts",
    sha256Hex: "59223110f49a241818ea905ed103ddc1fc0c12bdad6d5bb5323cd9a40683556d",
  },
  {
    role: "carrier-allocation",
    path: "src/chain/local-word-carrier-allocation.ts",
    sha256Hex: "22d10d5fc33ae56f309ec5bdbc1bb18238d28be7f628ad0fa9083bcea17a58c4",
  },
  {
    role: "verifier-manifest",
    path: "src/chain/local-word-role-manifest.ts",
    sha256Hex: "d80cfc8cbdcd42b510296ff9c69f86245c0bf8e96e7af6b8fd9d66eb6ae74cfc",
  },
] as const;

const DOMAIN = new TextEncoder().encode("ShieldKit/LocalWordConstructionManifest/v15");

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word construction component hash");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

/** Canonical bytes hashed to obtain the family identifier. */
export function encodeLocalWordV15ConstructionManifest(): Uint8Array {
  const roles = new Set<string>();
  const paths = new Set<string>();
  const parts: Uint8Array[] = [
    DOMAIN,
    Uint8Array.of(LOCAL_WORD_CONSTRUCTION_VERSION),
    writeU32BE(LOCAL_WORD_V15_COMPONENTS.length),
  ];
  for (const component of LOCAL_WORD_V15_COMPONENTS) {
    if (roles.has(component.role) || paths.has(component.path)) {
      throw new Error("local-word construction component uniqueness");
    }
    roles.add(component.role);
    paths.add(component.path);
    const role = new TextEncoder().encode(component.role);
    const path = new TextEncoder().encode(component.path);
    parts.push(writeU32BE(role.length), role, writeU32BE(path.length), path, fromHex(component.sha256Hex));
  }
  return concatBytes(...parts);
}

export const LOCAL_WORD_V15_CONSTRUCTION_ID = sha256(
  encodeLocalWordV15ConstructionManifest(),
);

export const LOCAL_WORD_V15_CONSTRUCTION_ID_HEX = Array.from(
  LOCAL_WORD_V15_CONSTRUCTION_ID,
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");
