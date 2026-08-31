import {
  V17_TRANSCRIPT_ROLE_PARTS,
  buildV17VerifierPlan,
  type V17ExpandedRole,
  type V17RoleSemantic,
} from "../construction/v17-graph.ts";

export { V17_TRANSCRIPT_ROLE_PARTS };

export type V17ProductionRoleLayout = Omit<
  V17ExpandedRole,
  "kind" | "semantic"
> & {
  readonly familyKind: V17ExpandedRole["kind"];
} & V17RoleSemantic;

function flattenGraphRole(role: V17ExpandedRole): V17ProductionRoleLayout {
  const { kind: familyKind, semantic, ...base } = role;
  // validateV17ConstructionGraph has already checked every discriminated
  // semantic instance against the family and its source geometry.
  return { ...base, familyKind, ...semantic } as V17ProductionRoleLayout;
}

/**
 * Thin compatibility view over the graph-generated verifier plan. There is no
 * second role inventory or semantic expansion in this module.
 */
export const V17_PRODUCTION_ROLE_LAYOUT: readonly V17ProductionRoleLayout[] =
  Object.freeze(buildV17VerifierPlan().roles.map(flattenGraphRole));
