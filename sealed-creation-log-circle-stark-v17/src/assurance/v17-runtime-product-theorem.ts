import { createHash } from "node:crypto";
import type { LocalWordProofContext } from
  "../backends/circle/local-word-sealed-proof.ts";
import type { LocalWordObserverLedger } from
  "../backends/circle/local-word-observer-view.ts";
import { verifyLocalWordSealedProofBytes } from
  "../backends/circle/local-word-verifier.ts";
import {
  V17_PROFILES,
  canonicalV17Json,
  v17ProtocolIdHex,
  type V17Profile,
} from "../construction/v17-graph.ts";
import type {
  V17LinkerCertificate,
} from "../construction/v17-linker.ts";
import type { V17ProfileProofMaterial } from
  "../construction/v17-product-link.ts";
import {
  assertV17BchnProductEvidence,
  type V17BchnProductEvidence,
} from "./v17-bchn-product-gate.ts";
import {
  assertV17FinalInfrastructureIdentity,
  type V17FinalInfrastructureIdentity,
} from "./v17-final-infrastructure-identity.ts";
import {
  V17_PRODUCTION_ASSURANCE_ROWS,
  evaluateV17ProductionTheorem,
  type V17ProductionAssuranceRow,
  type V17RuntimeProductionTheoremInstantiation,
} from "./v17-production-theorem.ts";

export const V17_RUNTIME_PRODUCT_THEOREM_SCHEMA =
  "ShieldKit/V17RuntimeProductTheorem/v1" as const;

const REQUIRED_ADVERSARIAL_MUTATIONS = [
  "matrix-root-byte",
  "opening-body-byte",
  "truncated-proof",
  "false-public-transcript",
] as const;

export type V17FreshProofAttestation = {
  readonly profile: V17Profile;
  readonly source: "fresh-rust-worker-current-run-no-cache";
  readonly proofBytes: number;
  readonly proofSha256Hex: string;
  readonly quotientDegreeBound: number;
};

export type V17ReferenceAdversarialRejection = {
  readonly profile: V17Profile;
  readonly mutation: typeof REQUIRED_ADVERSARIAL_MUTATIONS[number];
  readonly rejected: true;
  readonly reason: string;
};

export type V17RuntimeProductTheoremEvidenceBody = {
  readonly schema: typeof V17_RUNTIME_PRODUCT_THEOREM_SCHEMA;
  readonly status: "offline-theorem-qualified-candidate";
  readonly protocolIdHex: string;
  readonly constructionIdHex: string;
  readonly linkerCertificateIdHex: string;
  readonly finalInfrastructureIdentitySha256Hex: string;
  readonly bchnProductEvidenceSha256Hex: string;
  readonly proofSetSha256Hex: string;
  readonly adversarialEvidenceSha256Hex: string;
  readonly privacyEvidenceSha256Hex: string;
  readonly promotedRows: readonly {
    readonly id:
      | "product-first-reduction-transcript"
      | "product-ood-air-role"
      | "product-batch-link-roles"
      | "product-grouped-fri-transcript"
      | "product-mixed-merkle-codec";
    readonly status: "proved";
    readonly evidence: string;
  }[];
  readonly theorem: {
    readonly assuranceRows: number;
    readonly randomizedRounds: number;
    readonly allTEndpointsPassed: true;
    readonly classicalFloor: "epsilon(T)/T <= 2^-100 for every integer 1 <= T < 2^128";
  };
  readonly privacyClaim: {
    readonly algebraicOpeningRecovery: "not-unique-with-executable-witness";
    readonly classicalFiatShamir:
      "classical-programmable-ROM-transcript-and-soundness-model-no-complete-ZK-claim";
    readonly qromZeroKnowledge: "unresolved-nonclaim";
  };
  readonly quantumClaim:
    "no known polynomial-time quantum break under the stated assumptions";
  readonly excluded: readonly [
    "BCHN transaction-level CheckTransaction and CheckTxInputs",
    "UTXO existence maturity and relative-locktime context",
    "standardness mempool block acceptance mining and broadcast",
    "QROM zero knowledge",
  ];
};

export type V17RuntimeProductTheoremEvidence =
  V17RuntimeProductTheoremEvidenceBody & {
    readonly evidenceSha256Hex: string;
  };

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function hex32(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 runtime theorem ${label}`);
}

function orderedThree<T extends { readonly profile: V17Profile }>(
  values: readonly T[],
  label: string,
): readonly [T, T, T] {
  if (values.length !== V17_PROFILES.length ||
    values.some((value, index) => value.profile !== V17_PROFILES[index])) {
    throw new Error(`v17 runtime theorem ${label}`);
  }
  return values as unknown as readonly [T, T, T];
}

function proofSetDigest(attestations: readonly V17FreshProofAttestation[]): string {
  return sha256Hex(canonicalV17Json({
    source: "fresh-rust-worker-current-run-no-cache",
    profiles: attestations,
  }));
}

function validatePrivacyAudit(observer: LocalWordObserverLedger, profile: V17Profile): unknown {
  const recovery = observer.protectedTraceRecovery;
  if (observer.proofVersion !== 17 || observer.carrierUnionExact !== true ||
    observer.carrierAllocation.status !== "measured" ||
    observer.carrierAllocation.exactOwnershipReplay !== true ||
    recovery.recovered !== false ||
    recovery.result !== "not-uniquely-recoverable-from-algebraic-opening-view" ||
    recovery.schedule.source !== "strict-decoded-proof-and-transcript-replay" ||
    recovery.linearSystem.field !== "M31" ||
    recovery.linearSystem.certifiedRankPerColumn !==
      recovery.linearSystem.equationsPerColumn ||
    recovery.linearSystem.conditionedMaskNullityPerColumn < 1 ||
    recovery.linearSystem.jointTraceAndMaskNullityPerColumn < 1 ||
    recovery.compensatingWitness.allOpeningResidualsZero !== true ||
    recovery.compensatingWitness.changesProtectedTrace !== true ||
    recovery.compensatingWitness.nonzeroMaskCoefficients < 1) {
    throw new Error(`v17 runtime theorem privacy audit ${profile}`);
  }
  [recovery.schedule.sha256Hex, recovery.observedValues.sha256Hex,
    recovery.compensatingWitness.maskCoefficientsSha256Hex].forEach((value) =>
    hex32(value, `privacy digest ${profile}`));
  return {
    profile,
    transactionBytes: observer.transactionBytes,
    proofBytes: observer.proofBytes,
    scheduleSha256Hex: recovery.schedule.sha256Hex,
    observedValuesSha256Hex: recovery.observedValues.sha256Hex,
    equationsPerColumn: recovery.linearSystem.equationsPerColumn,
    rankPerColumn: recovery.linearSystem.certifiedRankPerColumn,
    conditionedMaskNullityPerColumn: recovery.linearSystem.conditionedMaskNullityPerColumn,
    jointTraceAndMaskNullityPerColumn: recovery.linearSystem.jointTraceAndMaskNullityPerColumn,
    maskCoefficientsSha256Hex: recovery.compensatingWitness.maskCoefficientsSha256Hex,
  };
}

function promotedRows(evidence: {
  readonly bchn: V17BchnProductEvidence;
  readonly identity: V17FinalInfrastructureIdentity;
  readonly proofSetSha256Hex: string;
  readonly adversarialEvidenceSha256Hex: string;
  readonly privacyEvidenceSha256Hex: string;
}): readonly V17RuntimeProductTheoremEvidenceBody["promotedRows"][number][] {
  const common = `protocol=${evidence.bchn.protocolIdHex};construction=${evidence.bchn.constructionIdHex};` +
    `linker=${evidence.bchn.linkerCertificateIdHex};infrastructure=${evidence.identity.identitySha256Hex};` +
    `bchn=${evidence.bchn.evidenceSha256Hex};proofs=${evidence.proofSetSha256Hex}`;
  return [
    {
      id: "product-first-reduction-transcript",
      status: "proved",
      evidence: `${common};adversarial=${evidence.adversarialEvidenceSha256Hex};` +
        "fresh Rust proofs strict-replayed by TS and every exact transcript-bound CashVM input accepted",
    },
    {
      id: "product-ood-air-role",
      status: "proved",
      evidence: `${common};one graph-owned OOD/AIR role accepted in every exact profile envelope`,
    },
    {
      id: "product-batch-link-roles",
      status: "proved",
      evidence: `${common};all 44 graph-owned batch-link workers accepted and are final-infrastructure-bound`,
    },
    {
      id: "product-grouped-fri-transcript",
      status: "proved",
      evidence: `${common};strict proof replay consumed 17 independent alphas in nine graph-owned FRI rounds`,
    },
    {
      id: "product-mixed-merkle-codec",
      status: "proved",
      evidence: `${common};privacy=${evidence.privacyEvidenceSha256Hex};` +
        "strict TS codec and every final graph-owned mixed-Merkle CashVM role accepted byte-exact artifacts",
    },
  ];
}

export function certifyV17RuntimeProductTheorem(args: {
  readonly proofs: readonly V17ProfileProofMaterial[];
  readonly contexts: readonly { readonly profile: V17Profile; readonly context: LocalWordProofContext }[];
  readonly attestations: readonly V17FreshProofAttestation[];
  readonly adversarialRejections: readonly V17ReferenceAdversarialRejection[];
  readonly observers: readonly { readonly profile: V17Profile; readonly observer: LocalWordObserverLedger }[];
  readonly bchnEvidence: V17BchnProductEvidence;
  readonly finalIdentity: V17FinalInfrastructureIdentity;
  readonly linkerCertificate: V17LinkerCertificate;
}): {
  readonly evidence: V17RuntimeProductTheoremEvidence;
  readonly theorem: V17RuntimeProductionTheoremInstantiation & { readonly qualified: true };
} {
  const proofs = orderedThree(args.proofs, "proof order");
  const contexts = orderedThree(args.contexts, "context order");
  const attestations = orderedThree(args.attestations, "attestation order");
  const observers = orderedThree(args.observers, "observer order");
  assertV17BchnProductEvidence(args.bchnEvidence);
  assertV17FinalInfrastructureIdentity(args.finalIdentity);
  const certificate = args.linkerCertificate;
  if (args.bchnEvidence.protocolIdHex !== v17ProtocolIdHex() ||
    args.finalIdentity.protocolIdHex !== v17ProtocolIdHex() ||
    certificate.protocolIdHex !== v17ProtocolIdHex() ||
    args.bchnEvidence.constructionIdHex !== args.finalIdentity.constructionIdHex ||
    args.bchnEvidence.constructionIdHex !== certificate.constructionIdHex ||
    args.bchnEvidence.linkerCertificateIdHex !== args.finalIdentity.linkerCertificateIdHex ||
    args.bchnEvidence.linkerCertificateIdHex !== certificate.certificateIdHex ||
    args.bchnEvidence.finalInfrastructureIdentitySha256Hex !==
      args.finalIdentity.identitySha256Hex ||
    certificate.qualification !== "construction-only-not-qualified") {
    throw new Error("v17 runtime theorem product identity");
  }

  for (const profile of V17_PROFILES) {
    const proof = proofs[profile]!;
    const context = contexts[profile]!;
    const attestation = attestations[profile]!;
    const productProfile = args.bchnEvidence.profiles[profile]!;
    const identityProfile = args.finalIdentity.profiles[profile]!;
    const proofSha256Hex = sha256Hex(proof.proofBytes);
    const verification = verifyLocalWordSealedProofBytes(proof.proofBytes, context.context);
    if (!verification.ok || context.profile !== profile || attestation.profile !== profile ||
      attestation.source !== "fresh-rust-worker-current-run-no-cache" ||
      attestation.proofBytes !== proof.proofBytes.length ||
      attestation.proofSha256Hex !== proofSha256Hex ||
      !Number.isSafeInteger(attestation.quotientDegreeBound) ||
      attestation.quotientDegreeBound < 1 ||
      productProfile.proofBytes !== proof.proofBytes.length ||
      productProfile.proofSha256Hex !== proofSha256Hex ||
      identityProfile.proofBytes !== proof.proofBytes.length ||
      identityProfile.proofSha256Hex !== proofSha256Hex) {
      throw new Error(`v17 runtime theorem exact proof ${profile}${
        verification.ok ? "" : `: ${verification.reason}`}`);
    }
    const rejected = args.adversarialRejections.filter((item) => item.profile === profile);
    if (rejected.length !== REQUIRED_ADVERSARIAL_MUTATIONS.length ||
      REQUIRED_ADVERSARIAL_MUTATIONS.some((mutation) =>
        !rejected.some((item) => item.mutation === mutation && item.rejected === true &&
          item.reason.length > 0))) {
      throw new Error(`v17 runtime theorem adversarial coverage ${profile}`);
    }
  }

  const proofSetSha256Hex = proofSetDigest(attestations);
  const adversarialEvidenceSha256Hex = sha256Hex(canonicalV17Json(
    args.adversarialRejections.map(({ profile, mutation, rejected, reason }) => ({
      profile, mutation, rejected, reason,
    })),
  ));
  const privacyEvidenceSha256Hex = sha256Hex(canonicalV17Json(
    observers.map(({ profile, observer }) => validatePrivacyAudit(observer, profile)),
  ));
  const promoted = promotedRows({
    bchn: args.bchnEvidence,
    identity: args.finalIdentity,
    proofSetSha256Hex,
    adversarialEvidenceSha256Hex,
    privacyEvidenceSha256Hex,
  });
  const rows = V17_PRODUCTION_ASSURANCE_ROWS.map((row): V17ProductionAssuranceRow => {
    const product = promoted.find(({ id }) => id === row.id);
    return product === undefined
      ? row
      : { ...row, status: "proved", evidence: product.evidence };
  });
  const theorem = evaluateV17ProductionTheorem(rows);
  if (!theorem.qualified || theorem.reasons.length !== 0 ||
    theorem.theoremMap.certificate.endpoints.length !== 2 ||
    !theorem.theoremMap.certificate.endpoints.every(({ passes }) => passes)) {
    throw new Error(`v17 runtime theorem unresolved: ${theorem.reasons.join(",")}`);
  }
  const body: V17RuntimeProductTheoremEvidenceBody = {
    schema: V17_RUNTIME_PRODUCT_THEOREM_SCHEMA,
    status: "offline-theorem-qualified-candidate",
    protocolIdHex: args.bchnEvidence.protocolIdHex,
    constructionIdHex: args.bchnEvidence.constructionIdHex,
    linkerCertificateIdHex: args.bchnEvidence.linkerCertificateIdHex,
    finalInfrastructureIdentitySha256Hex: args.finalIdentity.identitySha256Hex,
    bchnProductEvidenceSha256Hex: args.bchnEvidence.evidenceSha256Hex,
    proofSetSha256Hex,
    adversarialEvidenceSha256Hex,
    privacyEvidenceSha256Hex,
    promotedRows: promoted,
    theorem: {
      assuranceRows: theorem.assurance.rows.length,
      randomizedRounds: theorem.theoremMap.rounds.length,
      allTEndpointsPassed: true,
      classicalFloor: "epsilon(T)/T <= 2^-100 for every integer 1 <= T < 2^128",
    },
    privacyClaim: {
      algebraicOpeningRecovery: "not-unique-with-executable-witness",
      classicalFiatShamir:
        "classical-programmable-ROM-transcript-and-soundness-model-no-complete-ZK-claim",
      qromZeroKnowledge: "unresolved-nonclaim",
    },
    quantumClaim: "no known polynomial-time quantum break under the stated assumptions",
    excluded: [
      "BCHN transaction-level CheckTransaction and CheckTxInputs",
      "UTXO existence maturity and relative-locktime context",
      "standardness mempool block acceptance mining and broadcast",
      "QROM zero knowledge",
    ],
  };
  return {
    evidence: { ...body, evidenceSha256Hex: sha256Hex(canonicalV17Json(body)) },
    theorem: theorem as V17RuntimeProductionTheoremInstantiation & { readonly qualified: true },
  };
}

export function assertV17RuntimeProductTheoremEvidence(
  evidence: V17RuntimeProductTheoremEvidence,
): void {
  const { evidenceSha256Hex, ...body } = evidence;
  if (body.schema !== V17_RUNTIME_PRODUCT_THEOREM_SCHEMA ||
    body.status !== "offline-theorem-qualified-candidate" ||
    body.protocolIdHex !== v17ProtocolIdHex() ||
    body.promotedRows.length !== 5 ||
    body.promotedRows.some(({ status }) => status !== "proved") ||
    body.theorem.assuranceRows !== 16 || body.theorem.randomizedRounds !== 14 ||
    body.theorem.allTEndpointsPassed !== true ||
    body.privacyClaim.algebraicOpeningRecovery !== "not-unique-with-executable-witness" ||
    body.privacyClaim.classicalFiatShamir !==
      "classical-programmable-ROM-transcript-and-soundness-model-no-complete-ZK-claim" ||
    body.privacyClaim.qromZeroKnowledge !== "unresolved-nonclaim" ||
    evidenceSha256Hex !== sha256Hex(canonicalV17Json(body))) {
    throw new Error("v17 runtime theorem evidence integrity");
  }
  [body.protocolIdHex, body.constructionIdHex, body.linkerCertificateIdHex,
    body.finalInfrastructureIdentitySha256Hex, body.bchnProductEvidenceSha256Hex,
    body.proofSetSha256Hex, body.adversarialEvidenceSha256Hex,
    body.privacyEvidenceSha256Hex, evidenceSha256Hex].forEach((value) =>
    hex32(value, "evidence digest"));
}
