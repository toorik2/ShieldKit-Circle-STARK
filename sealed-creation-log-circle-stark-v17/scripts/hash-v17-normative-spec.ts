import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  inspectV17NormativeSpecFiles,
} from "../src/construction/v17-spec-identity.ts";

const laneRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const receipt = inspectV17NormativeSpecFiles({ laneRoot });

console.log(JSON.stringify({
  bytePolicy: "utf-8, no BOM, LF-only, terminal LF, SHA-256 over exact opaque bytes",
  protocolIdHex: receipt.protocolIdHex,
  documents: receipt.documents.map(({ id, path, bytes, actualSha256Hex }) => ({
    id,
    path,
    bytes,
    sha256Hex: actualSha256Hex,
  })),
}, null, 2));
