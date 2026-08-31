import { concatBytes, sha256, writeU32BE } from "../../pool/bytes.ts";

export const LOCAL_WORD_CONSTRUCTION_VERSION = 16;

export type LocalWordV16ConstructionComponent = {
  readonly name: string;
  readonly path: string;
  readonly sha256Hex: string;
};

/**
 * Frozen normative v16 inputs: stable specifications, package graph, every
 * product-reachable implementation module, and the pinned Rust worker.
 *
 * This manifest, its tests and reports, derivation helpers, and generated bank
 * digests are deliberately excluded. Bank scripts embed the resulting ID, so
 * including their digests would create a hash cycle.
 */
export const LOCAL_WORD_V16_COMPONENTS: readonly LocalWordV16ConstructionComponent[] = [
  {
    name: "01:RULES.md",
    path: "RULES.md",
    sha256Hex: "9b3bb9889f88260c12205171aed8a79e27fe31a24d4528d2b53a90cee57f3b08",
  },
  {
    name: "02:CONSTRUCTION.md",
    path: "CONSTRUCTION.md",
    sha256Hex: "cd027875e3e1ecf5501e6c2e7782ae121cb29c54d7a0c5fb785d313a74825458",
  },
  {
    name: "03:ZK-MEMBRANE.md",
    path: "ZK-MEMBRANE.md",
    sha256Hex: "15237948fe6b601f8d9ef6c2829508bd111e84921b80cc610fa91e72f8952c27",
  },
  {
    name: "04:COMPLETENESS.md",
    path: "COMPLETENESS.md",
    sha256Hex: "20e3feea75848563b3f074fcea9807d80e15f8a053cb36288c0e1283abfc2c36",
  },
  {
    name: "05:package.json",
    path: "package.json",
    sha256Hex: "59f5f5430f9a7ee85ddb0f34776d0d1fccef6cbce1f12f581c06b0b389864d93",
  },
  {
    name: "06:package-lock.json",
    path: "package-lock.json",
    sha256Hex: "b836906fabe65696dffa0f699cc657a19b61216f67bde69fc8cf9546a73b08a8",
  },
  {
    name: "07:scripts:prove-local-word-product.ts",
    path: "scripts/prove-local-word-product.ts",
    sha256Hex: "958d2dd4b5972a6cd502804d26885cd3030a8c77aecf23d2303c78245a202cf2",
  },
  {
    name: "08:src:amounts:hash-commit.ts",
    path: "src/amounts/hash-commit.ts",
    sha256Hex: "b71bb740a09cda47b7b4e4eb22691006c1b435c5a1755b0137a12846e0aeac2a",
  },
  {
    name: "09:src:backends:circle:canonical-merkle.ts",
    path: "src/backends/circle/canonical-merkle.ts",
    sha256Hex: "169860a4a6524d9e5b2bb606327191cb48296ef400f7f5df241cb501ea8b90b4",
  },
  {
    name: "10:src:backends:circle:group.ts",
    path: "src/backends/circle/group.ts",
    sha256Hex: "f5e817dfe943efe5cc9a0512e56fea5078202c2706ead3963b315bbfaaeae86b",
  },
  {
    name: "11:src:backends:circle:internal-hash.ts",
    path: "src/backends/circle/internal-hash.ts",
    sha256Hex: "6428606257cd72e0b9ddc7439d322cb5398ef7effde34c35e206a04225c579ed",
  },
  {
    name: "12:src:backends:circle:local-word-air.ts",
    path: "src/backends/circle/local-word-air.ts",
    sha256Hex: "c4272b06e4705fe280143fabadc490977695271e3e1c0c5762cab4c0a190cd9a",
  },
  {
    name: "13:src:backends:circle:local-word-observer-view.ts",
    path: "src/backends/circle/local-word-observer-view.ts",
    sha256Hex: "50ecdbe51e5749814f25c7e827bca60c355bfb298f4a61b2c418c768bb47da23",
  },
  {
    name: "14:src:backends:circle:local-word-oracle-layout.ts",
    path: "src/backends/circle/local-word-oracle-layout.ts",
    sha256Hex: "a877b4898664f22ca1ca4bee6253a6a602dd9523fba3593ce25bdd631179776b",
  },
  {
    name: "15:src:backends:circle:local-word-prover-bundle.ts",
    path: "src/backends/circle/local-word-prover-bundle.ts",
    sha256Hex: "45c1875a8a09633c2fe46e321e3e9748c6e5b182367c0c951a5cbce1772e5afe",
  },
  {
    name: "16:src:backends:circle:local-word-public-statement.ts",
    path: "src/backends/circle/local-word-public-statement.ts",
    sha256Hex: "9f8e9a7718bdac3a7c19601f9d09a6fbd4eb58c0fd60bbbafd9316a0a8265912",
  },
  {
    name: "17:src:backends:circle:local-word-sealed-proof.ts",
    path: "src/backends/circle/local-word-sealed-proof.ts",
    sha256Hex: "8c403b17072ce2668ab62b1a51c1dbe628142193fcddb88b4a6097c710f1d193",
  },
  {
    name: "18:src:backends:circle:local-word-successor-params.ts",
    path: "src/backends/circle/local-word-successor-params.ts",
    sha256Hex: "3bf4f6ff1bfa77bd04434b821718040e08083346c3eff763a580469e5d39396b",
  },
  {
    name: "19:src:backends:circle:local-word-transcript.ts",
    path: "src/backends/circle/local-word-transcript.ts",
    sha256Hex: "2f9a80802a15cf82a80286fc4fa61fab531494f87bfd196c9edf26ba36c132a3",
  },
  {
    name: "20:src:backends:circle:local-word-verifier-keys-v16.ts",
    path: "src/backends/circle/local-word-verifier-keys-v16.ts",
    sha256Hex: "ac546d6673941287022fdbe938c7b724b5974113ac69b5ab28312e22a6309643",
  },
  {
    name: "21:src:backends:circle:local-word-verifier.ts",
    path: "src/backends/circle/local-word-verifier.ts",
    sha256Hex: "614d5f7dca5faf8a51c93662fa62e22fa97d8ba8f656ef3d740955717fecb3a1",
  },
  {
    name: "22:src:backends:circle:m31.ts",
    path: "src/backends/circle/m31.ts",
    sha256Hex: "707b9a5cf3b029d486d8503f91e657155dbb0d3b542d644e82cd16df9b3dcd9c",
  },
  {
    name: "23:src:backends:circle:poseidon2-m31.ts",
    path: "src/backends/circle/poseidon2-m31.ts",
    sha256Hex: "b2699f5fc1d45c27f77676ab2f877511c0ba4afa277acbeb6f40a68017276420",
  },
  {
    name: "24:src:backends:circle:qm31.ts",
    path: "src/backends/circle/qm31.ts",
    sha256Hex: "e83a00ec211c318ae23077b870560ed2d1f9c104cda74a509510f176c2b71a0a",
  },
  {
    name: "25:src:backends:circle:successor-domain.ts",
    path: "src/backends/circle/successor-domain.ts",
    sha256Hex: "6d7386a63abd8dab4a80720014c7e5b37d8d41b36d5fed1149db159dc2be2546",
  },
  {
    name: "26:src:backends:circle:successor-fri.ts",
    path: "src/backends/circle/successor-fri.ts",
    sha256Hex: "37f94b9ccde095dae783ea5fa95db6448f2700f274cbfe1073a186ec0b110823",
  },
  {
    name: "27:src:backends:circle:successor-transcript.ts",
    path: "src/backends/circle/successor-transcript.ts",
    sha256Hex: "d656b36417f1fc3ce5a862544fefc616f23cb205d454dd16aa84d90329348e87",
  },
  {
    name: "28:src:chain:envelope.ts",
    path: "src/chain/envelope.ts",
    sha256Hex: "4fb0030dba1aa746efbe897715922831ed1ad40639efb3ebdf11dd39671c995c",
  },
  {
    name: "29:src:chain:local-word-algebra-vm.ts",
    path: "src/chain/local-word-algebra-vm.ts",
    sha256Hex: "c8d420e77f2d017317c30a430c13403a9b781bb9901248b1ab4c686d2e5f236a",
  },
  {
    name: "30:src:chain:local-word-balanced-vm.ts",
    path: "src/chain/local-word-balanced-vm.ts",
    sha256Hex: "cd181fde653d18bef856c871accf6cfb19cc8c464d420446ed338e2e18f7fdd0",
  },
  {
    name: "31:src:chain:local-word-carrier-allocation.ts",
    path: "src/chain/local-word-carrier-allocation.ts",
    sha256Hex: "49b10f8bac08ef10635816bead7a18cb8cb26568e0e0fc1887c77af0b68ff44f",
  },
  {
    name: "32:src:chain:local-word-envelope.ts",
    path: "src/chain/local-word-envelope.ts",
    sha256Hex: "634b221b57a3e12238d2a23a87730da98277209dd7536bbf7026d5908d8cd69f",
  },
  {
    name: "33:src:chain:local-word-merkle-vm.ts",
    path: "src/chain/local-word-merkle-vm.ts",
    sha256Hex: "19fd1c7868d8bea5b150aed60d0c184787f508102b39e427284c93cd0db4f826",
  },
  {
    name: "34:src:chain:local-word-proof-carriers.ts",
    path: "src/chain/local-word-proof-carriers.ts",
    sha256Hex: "af306865575526acd3d07aa4cb3ef73305ddc872cd939842998b6ee31acc4f32",
  },
  {
    name: "35:src:chain:local-word-role-manifest.ts",
    path: "src/chain/local-word-role-manifest.ts",
    sha256Hex: "a484999d57a3d82131a48843eaf9cf09eb11d30e2d11d36a5828631836adb740",
  },
  {
    name: "36:src:chain:m31-asm.ts",
    path: "src/chain/m31-asm.ts",
    sha256Hex: "43c89f0f0fc9cfeeb3ae2ecbbb912297b2b9e58a24f2eccdc5e4e2e8a14e1916",
  },
  {
    name: "37:src:chain:payout.ts",
    path: "src/chain/payout.ts",
    sha256Hex: "949a199a1078b89f7af1c8a28e8e81fb67282dd55cc9abf9e75c6ef50c815355",
  },
  {
    name: "38:src:chain:pool-relation-local-word-boundary.ts",
    path: "src/chain/pool-relation-local-word-boundary.ts",
    sha256Hex: "2e04d39a0efe11043390eac08a135eb855acf36451bd14808d4d618ecaefcf82",
  },
  {
    name: "39:src:chain:pool-relation-local-word-machine.ts",
    path: "src/chain/pool-relation-local-word-machine.ts",
    sha256Hex: "8744357684ca144ef8513bc6762ecc25a1b7da4e253eb6cab53ddac2ee718722",
  },
  {
    name: "40:src:chain:qm31-asm.ts",
    path: "src/chain/qm31-asm.ts",
    sha256Hex: "221acb8f746a8b0141da0ef7cf87277310d666b2361672888c5002f2623a62ea",
  },
  {
    name: "41:src:chain:sha256-local-word-codec.ts",
    path: "src/chain/sha256-local-word-codec.ts",
    sha256Hex: "c25c856428dc0abd37645856513b1f40a752582cd74924356df9081d8d447f36",
  },
  {
    name: "42:src:chain:sha256-local-word-machine.ts",
    path: "src/chain/sha256-local-word-machine.ts",
    sha256Hex: "2c1ad57ce0ccc515a260662774aa55b3e96068ec7b179f67b4619d946d9275a6",
  },
  {
    name: "43:src:chain:sha256-local-word-permutation.ts",
    path: "src/chain/sha256-local-word-permutation.ts",
    sha256Hex: "4a1b6b7d90d9802d93fdad96205791e787867af1206ca463d2cdf56b3c957ade",
  },
  {
    name: "44:src:chain:sha256-local-word-vm.ts",
    path: "src/chain/sha256-local-word-vm.ts",
    sha256Hex: "54cf1c6740a490379bf2b5d0f45c123b709023532bf62acaf3d79bc4f30e2cf3",
  },
  {
    name: "45:src:chain:sha256-primitives.ts",
    path: "src/chain/sha256-primitives.ts",
    sha256Hex: "6c3e22a14b6809562789514397447ffe396cd1d434f48213348c7ca724444bcc",
  },
  {
    name: "46:src:chain:transcript-vm-primitives.ts",
    path: "src/chain/transcript-vm-primitives.ts",
    sha256Hex: "b0a7b5059d8749c77fabfc6a99bf73b79d023c19a336df7f1ddc6ec55d19cfe1",
  },
  {
    name: "47:src:pool:bytes.ts",
    path: "src/pool/bytes.ts",
    sha256Hex: "c443338237ef906925adafbfa9aa5baba30b9b1b54dade058323dfa45a4612af",
  },
  {
    name: "48:src:pool:edge-history.ts",
    path: "src/pool/edge-history.ts",
    sha256Hex: "e3f69ff840814e98cbe8fb334f0665348d050b15aed2bbd0db182ad67d1833f2",
  },
  {
    name: "49:src:pool:notes.ts",
    path: "src/pool/notes.ts",
    sha256Hex: "532ab5bf40600d832d04eb6c94b1d5ce752451ebf88bdbce98ce5df3cde5da68",
  },
  {
    name: "50:src:pool:payout-buckets.ts",
    path: "src/pool/payout-buckets.ts",
    sha256Hex: "e4593ef3cdd41e831618a5a8303b9d10c1176d7b09c51da49c09d761c138dbb8",
  },
  {
    name: "51:src:pool:relation-witness.ts",
    path: "src/pool/relation-witness.ts",
    sha256Hex: "5099b05e4a53f45d43595a1731491dc8e201318654d3437513cd4c75e24285a6",
  },
  {
    name: "52:src:pool:sparse-nullifiers.ts",
    path: "src/pool/sparse-nullifiers.ts",
    sha256Hex: "e8e8a94c4b31ed970e8628b453e3b6c171683d86c6fa749c4e153418418e5193",
  },
  {
    name: "53:src:pool:state.ts",
    path: "src/pool/state.ts",
    sha256Hex: "693ccbffa9fba2a301fbdb2cba925ad76a91d8fa133745cf1194f75eab04e161",
  },
  {
    name: "54:src:pool:statement.ts",
    path: "src/pool/statement.ts",
    sha256Hex: "829c2028d181aee14e2f598bd5a303c7c5e92d0dd0d797c65d453ecd3354ab20",
  },
  {
    name: "55:src:pool:transition.ts",
    path: "src/pool/transition.ts",
    sha256Hex: "669351ec19d296595ac9fc29e01083585b8cb69c28dd7dac585c48c2133f45e1",
  },
  {
    name: "56:crates:circle-fri-worker:Cargo.lock",
    path: "crates/circle-fri-worker/Cargo.lock",
    sha256Hex: "0a0f2df2e7f94d1bb68c406f7734922c8a7b10fe013e2b88fa1321381b3d2430",
  },
  {
    name: "57:crates:circle-fri-worker:Cargo.toml",
    path: "crates/circle-fri-worker/Cargo.toml",
    sha256Hex: "e32d67658d4bd6679bf465230e48ffbff664827c83a5be883ced56eff6c82f10",
  },
  {
    name: "58:crates:circle-fri-worker:rust-toolchain.toml",
    path: "crates/circle-fri-worker/rust-toolchain.toml",
    sha256Hex: "c36b1ef796f5957939939956bfcfc16c72886ad062aabb3d3c40587d65f25ca7",
  },
  {
    name: "59:crates:circle-fri-worker:src:lib.rs",
    path: "crates/circle-fri-worker/src/lib.rs",
    sha256Hex: "51983845ba1b833fd79bd4b0d9a5e547d0e8f06bb36ef77db893a4d59644ebe8",
  },
  {
    name: "60:crates:circle-fri-worker:src:local_word_disk_oracle.rs",
    path: "crates/circle-fri-worker/src/local_word_disk_oracle.rs",
    sha256Hex: "218f4500b8ccdb1ccdf57cfab3c8a6b573232907302da63000684b488d1ab0bf",
  },
  {
    name: "61:crates:circle-fri-worker:src:main.rs",
    path: "crates/circle-fri-worker/src/main.rs",
    sha256Hex: "2f71cb674d4f136927212e874d3d275507a50963b8bf69e5d5e7e953e89f4206",
  },
] as const;

const DOMAIN = new TextEncoder().encode("ShieldKit/LocalWordConstructionManifest/v16");

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word v16 component hash");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

export function encodeLocalWordV16ConstructionManifest(): Uint8Array {
  const names = new Set<string>();
  const paths = new Set<string>();
  const parts: Uint8Array[] = [
    DOMAIN,
    Uint8Array.of(LOCAL_WORD_CONSTRUCTION_VERSION),
    writeU32BE(LOCAL_WORD_V16_COMPONENTS.length),
  ];
  for (const component of LOCAL_WORD_V16_COMPONENTS) {
    if (names.has(component.name) || paths.has(component.path)) {
      throw new Error("local-word v16 component uniqueness");
    }
    names.add(component.name);
    paths.add(component.path);
    const name = new TextEncoder().encode(component.name);
    const path = new TextEncoder().encode(component.path);
    parts.push(writeU32BE(name.length), name, writeU32BE(path.length), path,
      fromHex(component.sha256Hex));
  }
  return concatBytes(...parts);
}

export const LOCAL_WORD_V16_CONSTRUCTION_ID = sha256(
  encodeLocalWordV16ConstructionManifest(),
);

export const LOCAL_WORD_V16_CONSTRUCTION_ID_HEX = Array.from(
  LOCAL_WORD_V16_CONSTRUCTION_ID,
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");
