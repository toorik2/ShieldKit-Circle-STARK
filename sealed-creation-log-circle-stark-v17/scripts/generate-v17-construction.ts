import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  V17_GENERATED_ARTIFACT_PATHS,
  generateV17ConstructionArtifacts,
} from "../src/construction/v17-artifacts.ts";
import {
  assertV17NormativeSpecFiles,
} from "../src/construction/v17-spec-identity.ts";

const lane = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const modes = ["--check", "--write", "--print"].filter((mode) => process.argv.includes(mode));
if (modes.length > 1) throw new Error("choose one v17 construction generation mode");
const mode = modes[0] ?? "--check";
assertV17NormativeSpecFiles({ laneRoot: lane });
const artifacts = generateV17ConstructionArtifacts();

if (mode === "--print") {
  console.log(JSON.stringify(artifacts));
} else if (mode === "--write") {
  for (const relativePath of V17_GENERATED_ARTIFACT_PATHS) {
    const path = resolve(lane, relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, artifacts[relativePath]);
  }
  console.log("v17-construction-generated", JSON.stringify({
    files: V17_GENERATED_ARTIFACT_PATHS.length,
  }));
} else {
  const stale = V17_GENERATED_ARTIFACT_PATHS.filter((relativePath) => {
    const path = resolve(lane, relativePath);
    return !existsSync(path) || readFileSync(path, "utf8") !== artifacts[relativePath];
  });
  if (stale.length > 0) {
    throw new Error(`stale v17 construction artifacts: ${stale.join(", ")}`);
  }
  console.log("v17-construction-checked", JSON.stringify({
    files: V17_GENERATED_ARTIFACT_PATHS.length,
  }));
}
