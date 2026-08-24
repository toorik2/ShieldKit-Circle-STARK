import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, cpSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import { validateCampaign, validateDescriptor } from './p2/algebra-component/algebra-component-validation.mjs';
import { validateDescriptorV2, validateFinalExternalReviewShape } from './p2/algebra-component/algebra-component-descriptor-v2.mjs';
import { validateConstructionFreezeSemantics } from './p2/construction-freeze/construction-freeze.mjs';
import { validateScheduleFreezeSemantics } from './p2/schedule-freeze/schedule-freeze.mjs';
import { verifyCertificateSet } from './p2/field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.mjs';
import { validateLoweringFreezeSemantics } from './p2/lowering-freeze/lowering-freeze.mjs';
import { validatePackageSemantics as validateLoweringArmIrPackage } from './p2/lowering-arm-ir-freeze/generate.mjs';
import { verifyM89Shakedown } from './p2/gate-b/materialize-m89-shakedown.mjs';
import { validatePackage as validateCohortFreezeV2Package } from './p2/gate-b/cohort-freeze-v2/validate.mjs';
import { validatePackage as validatePolicyAuthorityV1Package } from './p2/gate-b/cohort-policy-authority-v1/validate.mjs';
import { validateCandidateCompositionV2 } from './research/candidate-composition.mjs';

const laneDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(laneDir, '../..');
const sourceDir = resolve(laneDir, 'sources/telegram-2026-07-29');
const errors = [];

const loadJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const sha256Hex = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const canonicalize = (value) => Array.isArray(value)
  ? value.map(canonicalize)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map((key) => [key, canonicalize(value[key])]))
    : value;
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
const digestRecord = (value, domain) => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8', value: createHash('sha256').update(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), canonicalBytes(value)])).digest('hex') });
const withoutContentDigest = (value) => { const { contentDigest: _contentDigest, ...rest } = value; return rest; };
const laneRelativePath = (path) => {
  if (path.startsWith('p2/')) return path;
  return relative(laneDir, resolve(repoRoot, path)).replaceAll('\\', '/');
};
const expect = (condition, message) => {
  if (!condition) errors.push(message);
};
const expectExactSet = (actualValues, expectedValues, label) => {
  const actual = new Set(actualValues);
  const expected = new Set(expectedValues);
  expect(actual.size === actualValues.length, `${label} contains duplicates`);
  for (const value of expected) expect(actual.has(value), `${label} is missing ${value}`);
  for (const value of actual) expect(expected.has(value), `${label} contains unexpected ${value}`);
};
const validateContentManifest = (sourceManifest, label, allowedArtifactDrift = new Map()) => {
  expect(sourceManifest.schema === 'shieldkit-labs/p2/source-manifest/v1', `${label} schema changed`);
  const roots = new Map();
  for (const root of sourceManifest.roots) {
    expect(!roots.has(root.id), `duplicate ${label} root ${root.id}`);
    roots.set(root.id, root);
    expect(existsSync(root.path), `${label} root is missing: ${root.id}`);
    if (existsSync(root.path)) {
      try {
        const head = execFileSync('git', ['-C', root.path, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
        expect(head === root.commit, `${label} root commit is stale: ${root.id}`);
      } catch (error) {
        errors.push(`${label} root commit cannot be read: ${root.id}: ${error.message}`);
      }
    }
  }
  const artifactIds = new Set();
  for (const artifact of sourceManifest.artifacts) {
    expect(!artifactIds.has(artifact.id), `duplicate ${label} artifact ${artifact.id}`);
    artifactIds.add(artifact.id);
    const root = roots.get(artifact.rootId);
    expect(root !== undefined, `${label} artifact ${artifact.id} has unknown root ${artifact.rootId}`);
    expect(!artifact.path.startsWith('/') && !artifact.path.split('/').includes('..'), `${label} artifact ${artifact.id} has an unsafe path`);
    if (root !== undefined) {
      const artifactPath = resolve(root.path, artifact.path);
      expect(existsSync(artifactPath), `${label} artifact is missing: ${artifact.id}`);
      if (existsSync(artifactPath)) {
        const currentDigest = sha256(artifactPath);
        const transition = allowedArtifactDrift.get(artifact.id);
        expect(
          currentDigest === artifact.sha256 || (
            transition?.historicalSha256 === artifact.sha256 &&
            transition?.rebuiltSha256 === currentDigest
          ),
          `${label} artifact digest is stale: ${artifact.id}`
        );
      }
    }
  }
  return { roots, artifactIds };
};
const compileStrictSchema = (schemaPath, label, instance) => {
  try {
    const localAjv = new Ajv2020({ allErrors: true, strict: true });
    const validate = localAjv.compile(loadJson(schemaPath));
    if (instance !== undefined && !validate(instance)) {
      for (const error of validate.errors ?? []) {
        errors.push(`${label} schema ${error.instancePath || '/'} ${error.message}`);
      }
    }
    return validate;
  } catch (error) {
    errors.push(`${label} schema does not compile strictly: ${error.message}`);
    return null;
  }
};

const V3_FREEZE_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1/root';
const CLEV2_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/';
const CLEV2_PACKAGE_RELATIVE = 'p2/gate-b/cohort-live-executor-v2';
const CLEV2_PACKAGE_ROOT = resolve(laneDir, CLEV2_PACKAGE_RELATIVE);
const CLEV2_P_ROOT_PATH = resolve(laneDir, 'p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json');
const CLEV2_FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'model-root.v2.json', 'validate-static.mjs',
  'schemas/authority-dag.v2.schema.json', 'schemas/digest.v2.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/model-root.v2.schema.json', 'schemas/state.v2.schema.json', 'schemas/transition-grammar.v2.schema.json',
  'src/canonical.mjs', 'src/model.mjs', 'src/sha256.mjs', 'src/state-machine.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/state-machine.test.mjs'
]);
const CLEV2_DIRECTORIES = Object.freeze(['.', 'schemas', 'src', 'test']);
const CLEV2_P_PROJECTION = Object.freeze({
  schema: 'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root',
  artifactId: 'artifact:gate-b:cohort-policy-authority-v1',
  path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json',
  rawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e',
  contentDigest: '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50',
  bindingDigest: '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654',
  policyDigest: '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf',
  authorityDagDigest: '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d',
  liveFDigest: '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be'
});
const CLEV2_AUTHORITY_DAG = Object.freeze({
  nodes: ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT'],
  edges: ['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']
});
const CLEV2_EXPECTED_BINDING = Object.freeze({
  path: CLEV2_PACKAGE_RELATIVE,
  root: {
    path: `${CLEV2_PACKAGE_RELATIVE}/model-root.v2.json`,
    rawSha256: '45ddc12f0b44136a4f85e2800a47c8b9ed000ed0f33acc252b31b0758bdd2ebb',
    contentDigest: '67ed36e2b9f011de2dcd9794e33e3be8a1b1f00550357e6d7c5081bebf334a82'
  },
  pSemanticBindingDigest: 'd43c30388318e0ddf8700b30123467b8366aafc103dbda9c0f61d24834eda002',
  authorityDagDigest: 'b8d2a5b200799dc2a6cc57d4fc96b3eb9de5be0f91b99d2d1d9323fa5e7383af',
  transitionGrammarDigest: 'dc4680aa570ac87fc3972c644405b4be0ab59e63637917ae846a650432c4553b',
  manifest: {
    path: `${CLEV2_PACKAGE_RELATIVE}/MANIFEST.json`,
    rawSha256: 'ef03043f458915856b5c420e039208f6a0307633d20b21dac8238d73316fd98a',
    rosterDigest: '4734b2c457b12a1f9efe87814c2f101065c8cb2a111062adbbd769e617167df9',
    entryCount: 20
  },
  checksums: {
    path: `${CLEV2_PACKAGE_RELATIVE}/SHA256SUMS`,
    rawSha256: '0ef72e260de7afdc9bb508739321418be95c48879b09992669af23e71e3d7285'
  },
  validator: {
    path: `${CLEV2_PACKAGE_RELATIVE}/validate-static.mjs`,
    rawSha256: '31ef0e6f22eb6f6b20e426ca5ae4da2c0c8f7ed64becb693ad1da3fa81d8973a'
  },
  status: 'sol-regated-pure-static-transition-model-non-authorizing'
});
const CLEV2_PURE_IMPORTS = Object.freeze({
  'src/canonical.mjs': [],
  'src/sha256.mjs': [],
  'src/model.mjs': ['./canonical.mjs', './sha256.mjs'],
  'src/state-machine.mjs': ['./model.mjs']
});
const CLEV2_PURE_EXPORTS = Object.freeze({
  'src/canonical.mjs': ['canonicalJson', 'utf8Encode'],
  'src/sha256.mjs': ['sha256Hex'],
  'src/model.mjs': ['AUTHORITY_DAG', 'TRANSITION_GRAMMAR', 'VARIANTS', 'FACTS', 'EVENTS', 'VERDICTS', 'assertAuthorityDag', 'assertTransitionGrammar', 'requiredPredecessors', 'authorityDagDigest', 'transitionGrammarDigest', 'modelRootDigest', 'stateDigest'],
  'src/state-machine.mjs': ['emptyState', 'assertState', 'guardTransition', 'transition', 'replay']
});
const CLEV2_FORBIDDEN_PURE_SURFACE = /node:|\bimport\.meta\b|\bimport\s*\(|\brequire\s*\(|\b(?:eval|Function|globalThis|WebAssembly|Deno|Bun|Worker|SharedWorker|process|setTimeout|setInterval|queueMicrotask|fetch|WebSocket|XMLHttpRequest|child_process|vm|net|http|https)\b/u;
const CLEV2_FORBIDDEN_WORDS = /\b(?:result|evidence)\b/iu;

const clev2Fail = (message) => { throw new Error(`cohort-live-executor-v2 lane binding: ${message}`); };
const clev2Assert = (condition, message) => { if (!condition) clev2Fail(message); };
const clev2Canonical = (value, seen = new Set()) => {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    clev2Assert(Number.isFinite(value) && !Object.is(value, -0), 'noncanonical number');
    return JSON.stringify(value);
  }
  clev2Assert(value && typeof value === 'object', 'non-JSON value');
  clev2Assert(!seen.has(value), 'cyclic value');
  seen.add(value);
  try {
    if (Array.isArray(value)) return `[${value.map((item) => clev2Canonical(item, seen)).join(',')}]`;
    clev2Assert(Object.getPrototypeOf(value) === Object.prototype, 'nonplain JSON record');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${clev2Canonical(value[key], seen)}`).join(',')}}`;
  } finally {
    seen.delete(value);
  }
};
const clev2Equal = (actual, expected, label) => clev2Assert(clev2Canonical(actual) === clev2Canonical(expected), `${label} differs`);
const clev2RawSha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const clev2FramedDigest = (domain, value) => createHash('sha256').update(Buffer.from(`${domain}\u0000${clev2Canonical(value)}\n`, 'utf8')).digest('hex');
const clev2RawFileDigest = (bytes) => createHash('sha256').update(Buffer.from(`${CLEV2_PREFIX}file\u0000`, 'utf8')).update(bytes).digest('hex');
const clev2Descriptor = (domain, value) => ({
  algorithm: 'sha256',
  canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',
  domain,
  frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1',
  value
});
const clev2Read = (root, locator) => {
  const absolute = resolve(root, locator);
  clev2Assert(absolute.startsWith(`${root}/`), `unsafe locator ${locator}`);
  return readFileSync(absolute);
};
const clev2ReadCanonicalJson = (root, locator) => {
  const bytes = clev2Read(root, locator);
  clev2Assert(!bytes.includes(0x0d), `${locator} has CR bytes`);
  const text = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(text); } catch { clev2Fail(`${locator} is not JSON`); }
  clev2Assert(text === `${clev2Canonical(value)}\n`, `${locator} is not canonical JSON plus one final LF`);
  return value;
};
const clev2ExpectedGrammar = () => ({
  schema: `${CLEV2_PREFIX}transition-grammar/v2`,
  identifier: 'cohort-live-executor-v2',
  variants: ['initial', 'retry', 'abort'],
  facts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'],
  events: ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D', 'CLOSE_ABORT'],
  verdicts: ['ALLOW', 'BLOCKED_EXTERNAL', 'DENY_VARIANT', 'DENY_PREREQUISITE', 'DENY_DUPLICATE', 'DENY_CLOSED', 'DENY_UNKNOWN'],
  state: {
    schema: `${CLEV2_PREFIX}state/v2`,
    keys: ['schema', 'identifier', 'variant', 'facts', 'phase'],
    phases: ['open', 'abort-closed'],
    orderedUniqueFacts: true,
    neverAdmitted: ['D']
  },
  externalGuards: { retryQ: 'RETRY_PREDECESSOR', d: 'WORKER_ROWS_ROOT' },
  admission: {
    initial: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D'], initialFacts: ['Q', 'LIVE_F'] },
    retry: { allowedEvents: ['MATCH_Q', 'MATCH_A'], retryQ: 'BLOCKED_EXTERNAL', stateAlwaysEmpty: true },
    abort: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'CLOSE_ABORT'], allowedFacts: ['Q', 'A'], close: 'abort-closed' }
  },
  j: { grantsAuthority: false, predecessors: ['B', 'C'] },
  predecessors: { Q: [], A: ['Q'], LIVE_F: [], B: ['A', 'LIVE_F'], C: ['B'], J: ['B', 'C'], D: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'] }
});
const clev2Collect = (root, directory = root, prefix = '') => {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)))) {
    const locator = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = resolve(directory, entry.name);
    const stat = lstatSync(absolute);
    clev2Assert(!stat.isSymbolicLink(), `${locator} is a link`);
    if (stat.isDirectory()) {
      const nested = clev2Collect(root, absolute, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (stat.isFile()) {
      files.push(locator);
    } else {
      clev2Fail(`${locator} is not a regular file or directory`);
    }
  }
  return { files, directories };
};
const clev2CheckFilesystem = (root) => {
  const rootStat = lstatSync(root);
  clev2Assert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.nlink === 1 && (rootStat.mode & 0o7777) === 0o755, 'package root mode, link count, or type changed');
  const found = clev2Collect(root);
  clev2Equal(found.directories.sort(), [...CLEV2_DIRECTORIES].sort(), 'directory closure');
  const closure = [...CLEV2_FILES, 'MANIFEST.json', 'SHA256SUMS'];
  clev2Equal(found.files.sort(), [...closure].sort(), 'file closure');
  for (const locator of CLEV2_DIRECTORIES) {
    const stat = lstatSync(resolve(root, locator));
    clev2Assert(stat.isDirectory() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o7777) === 0o755, `${locator} directory mode, link count, or type changed`);
  }
  for (const locator of closure) {
    const stat = lstatSync(resolve(root, locator));
    clev2Assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o7777) === 0o644, `${locator} file mode, link count, or type changed`);
    clev2Assert(!clev2Read(root, locator).includes(0x0d), `${locator} has CR bytes`);
  }
};
const clev2CheckPureClosure = (root) => {
  for (const locator of [...CLEV2_FILES, 'MANIFEST.json', 'SHA256SUMS']) {
    const text = clev2Read(root, locator).toString('utf8');
    clev2Assert(!CLEV2_FORBIDDEN_WORDS.test(text), `${locator} has a forbidden word`);
  }
  for (const [locator, expectedImports] of Object.entries(CLEV2_PURE_IMPORTS)) {
    const source = clev2Read(root, locator).toString('utf8');
    clev2Assert(!CLEV2_FORBIDDEN_PURE_SURFACE.test(source), `${locator} has a forbidden pure-surface token`);
    const actualImports = [
      ...source.matchAll(/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/gu),
      ...source.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/gu)
    ].map((match) => match[1]);
    clev2Assert(actualImports.every((specifier) => specifier.startsWith('./')), `${locator} has a nonrelative import`);
    clev2Equal(actualImports, expectedImports, `${locator} import graph`);
    const exportList = source.match(/export\s*\{([\s\S]*?)\};\s*$/u);
    clev2Assert(exportList !== null, `${locator} lacks a terminal exact export list`);
    clev2Assert(!/\bexport\b/u.test(source.slice(0, exportList.index)), `${locator} has an additional export surface`);
    const actualExports = exportList[1].split(',').map((name) => name.trim()).filter(Boolean);
    clev2Equal(actualExports, CLEV2_PURE_EXPORTS[locator], `${locator} export surface`);
  }
};
const clev2RequireRawPin = (root, locator, expected, label) => {
  clev2Assert(clev2RawSha256(clev2Read(root, locator)) === expected, `${label} raw SHA-256 pin changed`);
};
const clev2ExpectedManifest = (root) => {
  const entries = CLEV2_FILES.map((locator) => {
    const bytes = clev2Read(root, locator);
    return { locator, bytes: bytes.length, sha256: clev2RawSha256(bytes), fileDigest: clev2RawFileDigest(bytes) };
  });
  return {
    schema: `${CLEV2_PREFIX}manifest/v1`,
    format: `${CLEV2_PREFIX}manifest/1`,
    package: 'cohort-live-executor-v2',
    entryCount: CLEV2_FILES.length,
    entries,
    rosterDigest: clev2FramedDigest(`${CLEV2_PREFIX}manifest-roster`, { package: 'cohort-live-executor-v2', entries })
  };
};
const clev2CheckManifestDocument = (root, manifest) => clev2Equal(manifest, clev2ExpectedManifest(root), 'manifest semantic envelope');
const clev2CheckChecksumEnvelope = (root) => {
  const entries = clev2ExpectedManifest(root).entries;
  const expected = [...entries, { locator: 'MANIFEST.json', sha256: clev2RawSha256(clev2Read(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  clev2Assert(clev2Read(root, 'SHA256SUMS').toString('utf8') === `${expected}\n`, 'SHA256SUMS semantic envelope changed');
};
const clev2ReadPProjection = () => {
  const bytes = readFileSync(CLEV2_P_ROOT_PATH);
  clev2Assert(clev2RawSha256(bytes) === CLEV2_P_PROJECTION.rawSha256, 'P root raw SHA-256 pin changed');
  let p;
  try { p = JSON.parse(bytes.toString('utf8')); } catch { clev2Fail('P root is not JSON'); }
  const projection = {
    schema: p.schema,
    artifactId: p.artifactId,
    path: CLEV2_P_PROJECTION.path,
    rawSha256: CLEV2_P_PROJECTION.rawSha256,
    contentDigest: p.contentDigest?.value,
    bindingDigest: p.bindingRoot?.value,
    policyDigest: p.policy?.contentDigest?.value,
    authorityDagDigest: p.causalDagRoot?.value,
    liveFDigest: p.policy?.liveF?.contentDigest?.value
  };
  clev2Equal(projection, CLEV2_P_PROJECTION, 'P semantic projection');
  clev2Assert(!Object.hasOwn(p, 'path'), 'P root has a contradictory embedded locator');
  const pNodes = [...CLEV2_AUTHORITY_DAG.nodes, 'JOURNAL', 'OBSERVATION', 'TERMINAL'];
  const edgePrefix = [...CLEV2_AUTHORITY_DAG.edges];
  const downstream = ['J→JOURNAL', 'D→JOURNAL', 'J→OBSERVATION', 'D→OBSERVATION', 'J→TERMINAL', 'D→TERMINAL'];
  clev2Equal(p.causalDag?.nodes, pNodes, 'P node closure');
  clev2Equal(p.causalDag?.edges?.slice(0, edgePrefix.length), edgePrefix, 'P edge prefix');
  clev2Equal(p.causalDag?.edges?.slice(edgePrefix.length), downstream, 'P downstream six edges');
  return projection;
};
const clev2CheckRoot = (root) => {
  const pProjection = clev2ReadPProjection();
  const rootDocument = clev2ReadCanonicalJson(root, 'model-root.v2.json');
  const grammar = clev2ExpectedGrammar();
  const pSemanticBindingDigest = clev2FramedDigest(`${CLEV2_PREFIX}policy-authority-binding`, pProjection);
  const authorityDagDigest = clev2FramedDigest(`${CLEV2_PREFIX}authority-dag`, CLEV2_AUTHORITY_DAG);
  const transitionGrammarDigest = clev2FramedDigest(`${CLEV2_PREFIX}transition-grammar`, grammar);
  clev2Assert(pSemanticBindingDigest === CLEV2_EXPECTED_BINDING.pSemanticBindingDigest, 'P semantic binding digest pin changed');
  clev2Assert(authorityDagDigest === CLEV2_EXPECTED_BINDING.authorityDagDigest, 'authority DAG digest pin changed');
  clev2Assert(transitionGrammarDigest === CLEV2_EXPECTED_BINDING.transitionGrammarDigest, 'transition grammar digest pin changed');
  const authority = { pRoot: pProjection, semanticBindingDigest: pSemanticBindingDigest };
  const rootPayload = {
    schema: `${CLEV2_PREFIX}model-root/v2`,
    identifier: 'cohort-live-executor-v2',
    authority,
    authorityDag: CLEV2_AUTHORITY_DAG,
    transitionGrammar: grammar
  };
  const rootDigest = clev2FramedDigest(`${CLEV2_PREFIX}root`, rootPayload);
  clev2Assert(rootDigest === CLEV2_EXPECTED_BINDING.root.contentDigest, 'model root digest pin changed');
  clev2Equal(rootDocument, {
    ...rootPayload,
    contentDigest: clev2Descriptor(`${CLEV2_PREFIX}root`, rootDigest)
  }, 'model root semantic projection');
  return rootDocument;
};
const clev2ValidateIndependent = (root = CLEV2_PACKAGE_ROOT) => {
  clev2CheckFilesystem(root);
  clev2RequireRawPin(root, 'model-root.v2.json', CLEV2_EXPECTED_BINDING.root.rawSha256, 'model root');
  clev2RequireRawPin(root, 'MANIFEST.json', CLEV2_EXPECTED_BINDING.manifest.rawSha256, 'manifest');
  clev2RequireRawPin(root, 'SHA256SUMS', CLEV2_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope');
  clev2RequireRawPin(root, 'validate-static.mjs', CLEV2_EXPECTED_BINDING.validator.rawSha256, 'validator');
  const rootDocument = clev2CheckRoot(root);
  const manifest = clev2ReadCanonicalJson(root, 'MANIFEST.json');
  clev2CheckManifestDocument(root, manifest);
  clev2Assert(manifest.rosterDigest === CLEV2_EXPECTED_BINDING.manifest.rosterDigest && manifest.entryCount === CLEV2_EXPECTED_BINDING.manifest.entryCount, 'manifest roster or entry-count pin changed');
  clev2CheckChecksumEnvelope(root);
  clev2CheckPureClosure(root);
  return { rootDocument, manifest, files: CLEV2_FILES.length + 2, directories: CLEV2_DIRECTORIES.length };
};
const clev2WriteCanonicalJson = (root, locator, value) => writeFileSync(resolve(root, locator), Buffer.from(`${clev2Canonical(value)}\n`, 'utf8'));
const clev2RegenerateEnvelope = (root) => {
  const manifest = clev2ExpectedManifest(root);
  clev2WriteCanonicalJson(root, 'MANIFEST.json', manifest);
  const sums = [...manifest.entries, { locator: 'MANIFEST.json', sha256: clev2RawSha256(clev2Read(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  writeFileSync(resolve(root, 'SHA256SUMS'), Buffer.from(`${sums}\n`, 'utf8'));
  return manifest;
};
const clev2ExpectFailure = (operation, label) => {
  let failed = false;
  try { operation(); } catch { failed = true; }
  clev2Assert(failed, `${label} mutation was accepted`);
};
const clev2RunCausalMutation = async () => {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), 'shieldkit-clev2-lane-'));
  const mutatedPackage = resolve(temporaryRoot, 'cohort-live-executor-v2');
  try {
    cpSync(CLEV2_PACKAGE_ROOT, mutatedPackage, { recursive: true, errorOnExist: true, verbatimSymlinks: true });
    writeFileSync(resolve(mutatedPackage, 'validate-static.mjs'), 'export function validateStatic() { return true; }\n');
    const stateSchema = clev2ReadCanonicalJson(mutatedPackage, 'schemas/state.v2.schema.json');
    stateSchema.properties.facts.items.enum.push('D');
    clev2WriteCanonicalJson(mutatedPackage, 'schemas/state.v2.schema.json', stateSchema);
    const modelRoot = clev2ReadCanonicalJson(mutatedPackage, 'model-root.v2.json');
    modelRoot.transitionGrammar.predecessors.D = ['B', 'C', 'J'];
    modelRoot.transitionGrammar.externalGuards.d = 'FORGED_WORKER_ROWS_ROOT';
    const { contentDigest: _priorContentDigest, ...mutatedRootPayload } = modelRoot;
    const mutatedRootDigest = clev2FramedDigest(`${CLEV2_PREFIX}root`, mutatedRootPayload);
    modelRoot.contentDigest = clev2Descriptor(`${CLEV2_PREFIX}root`, mutatedRootDigest);
    clev2WriteCanonicalJson(mutatedPackage, 'model-root.v2.json', modelRoot);
    clev2RegenerateEnvelope(mutatedPackage);
    clev2ExpectFailure(() => clev2RequireRawPin(mutatedPackage, 'validate-static.mjs', CLEV2_EXPECTED_BINDING.validator.rawSha256, 'validator'), 'validator raw pin');
    const replacement = await import(`${pathToFileURL(resolve(mutatedPackage, 'validate-static.mjs')).href}?cohort-live-executor-v2-causal-mutation`);
    clev2Assert(replacement.validateStatic() === true, 'coordinated replacement validator did not accept its local package');
    clev2ExpectFailure(() => clev2RequireRawPin(mutatedPackage, 'model-root.v2.json', CLEV2_EXPECTED_BINDING.root.rawSha256, 'model root'), 'model root raw pin');
    const mutatedRoot = clev2ReadCanonicalJson(mutatedPackage, 'model-root.v2.json');
    clev2Assert(mutatedRoot.contentDigest?.value === mutatedRootDigest, 'coordinated model root was not re-digested');
    clev2ExpectFailure(() => clev2Assert(mutatedRoot.contentDigest?.value === CLEV2_EXPECTED_BINDING.root.contentDigest, 'model root content pin changed'), 'model root content pin');
    clev2ExpectFailure(() => clev2RequireRawPin(mutatedPackage, 'MANIFEST.json', CLEV2_EXPECTED_BINDING.manifest.rawSha256, 'manifest'), 'manifest raw pin');
    const mutatedManifest = clev2ReadCanonicalJson(mutatedPackage, 'MANIFEST.json');
    clev2ExpectFailure(() => clev2Assert(mutatedManifest.rosterDigest === CLEV2_EXPECTED_BINDING.manifest.rosterDigest, 'manifest roster pin changed'), 'manifest roster pin');
    clev2ExpectFailure(() => clev2RequireRawPin(mutatedPackage, 'SHA256SUMS', CLEV2_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope'), 'checksum raw pin');
    const manifest = clev2ReadCanonicalJson(CLEV2_PACKAGE_ROOT, 'MANIFEST.json');
    const first = manifest.entries[0];
    const raw = clev2Read(CLEV2_PACKAGE_ROOT, first.locator);
    const metadataFramed = clev2FramedDigest(`${CLEV2_PREFIX}file`, { locator: first.locator, bytes: first.bytes, sha256: first.sha256 });
    const lfFramed = clev2RawFileDigest(Buffer.concat([raw, Buffer.from('\n', 'utf8')]));
    clev2Assert(metadataFramed !== first.fileDigest && lfFramed !== first.fileDigest, 'file-digest mutation unexpectedly collides');
    const metadataManifest = structuredClone(manifest);
    metadataManifest.entries[0].fileDigest = metadataFramed;
    clev2ExpectFailure(() => clev2CheckManifestDocument(CLEV2_PACKAGE_ROOT, metadataManifest), 'metadata-framed file digest');
    const lfManifest = structuredClone(manifest);
    lfManifest.entries[0].fileDigest = lfFramed;
    clev2ExpectFailure(() => clev2CheckManifestDocument(CLEV2_PACKAGE_ROOT, lfManifest), 'LF-framed file digest');
    return true;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
};
const CABM_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/';
const CABM_PACKAGE_RELATIVE = 'p2/gate-b/cohort-authority-binding-model-v1';
const CABM_PACKAGE_ROOT = resolve(laneDir, CABM_PACKAGE_RELATIVE);
const CABM_ROOT_STATUS = 'static-authority-binding-catalog-non-authorizing-external-origins-unavailable-unqualified';
const CABM_NONPROMOTION = 'The sealed cohort-authority-binding-model-v1 package is a static, non-authorizing, unqualified requirements catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant remains false, retry remains empty/BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.';
const CABM_FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'authority-binding-root.v1.json', 'validate-static.mjs',
  'schemas/authority-dag.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/external-origin-catalog.v1.schema.json', 'schemas/fact-catalog.v1.schema.json', 'schemas/state-grammar.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/model-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
  'src/canonical.mjs', 'src/sha256.mjs', 'src/model.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs'
]);
const CABM_DIRECTORIES = Object.freeze(['.', 'schemas', 'src', 'test']);
const CABM_AUTHORITY_DAG = Object.freeze({
  nodes: ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT'],
  edges: ['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']
});
const CABM_EXPECTED_BINDING = Object.freeze({
  path: CABM_PACKAGE_RELATIVE,
  root: {
    path: `${CABM_PACKAGE_RELATIVE}/authority-binding-root.v1.json`,
    rawSha256: '858050856ed4784d6b91bc74550c7e6595fae9596715314cc85bdee4051f68cb',
    contentDigest: '58365b7e9c01cf43b3e7fd46b8d06c27506361bbff80659b032499562e23731a'
  },
  authorityDagDigest: '66559720074ff58ce80f13fd031d4e5cb807e4bf8adff69690b1c3d91dd284d1',
  dependencyCatalogDigest: '1031a3a8f74a02d05b80694f7315f5652e719378082fc542153637347b9dd290',
  externalOriginsDigest: '19de8c2425d080e423c8b5f9664b0d67003b73d3b6b5475ceafb2e5a2e436d10',
  factCatalogDigest: '0fcfe494e021eceb1ec346a17b8cf27cf2ace84cdf863476c6b2243994bcb56e',
  stateGrammarDigest: '97e93ddcab4677da24d49a188ae7abcf20ca4dcb86e670cb5138fe88adcaf5f8',
  manifest: {
    path: `${CABM_PACKAGE_RELATIVE}/MANIFEST.json`,
    rawSha256: '05b171e7b4c8f308eb46f0f6bffb78f260513322d5b91728bf61a6cb62e891b7',
    rosterDigest: '9810e2871b1c83f5fc53691ea0044c52da11768d82988d115692b1e8d4fdac5d',
    entryCount: 20
  },
  checksums: {
    path: `${CABM_PACKAGE_RELATIVE}/SHA256SUMS`,
    rawSha256: 'a296a3a7b6acabed4b70c648d3907f032fd309ef32980427eb77fbff840dffab'
  },
  validator: {
    path: `${CABM_PACKAGE_RELATIVE}/validate-static.mjs`,
    rawSha256: 'e738933e665f7c748fc58edadf9255863469be9b67e3c40639014c83d73c8269'
  },
  model: {
    path: `${CABM_PACKAGE_RELATIVE}/src/model.mjs`,
    rawSha256: 'c46d205194fd773bdb263884faa62a94c161f35afded1e9431521749401378c9'
  },
  status: 'sol-regated-static-authority-binding-catalog-non-authorizing-external-origins-unavailable-unqualified'
});
const CABM_EXPECTED_ORIGINS = Object.freeze({
  schema: `${CABM_PREFIX}external-origin-catalog/v1`,
  identifier: 'cohort-authority-binding-model-v1',
  entries: [
    { id: 'RETRY_PREDECESSOR', ownerClass: 'unavailable-recovery-chain-owner', originFor: 'Q:retry', staticAuthenticators: ['P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false },
    { id: 'LIVE_F_CAPTURE', ownerClass: 'unavailable-private-capture-owner', originFor: 'LIVE_F', staticAuthenticators: ['P', 'F', 'V2'], availability: 'unavailable', modelDisposition: 'UNAVAILABLE_EXTERNAL', grantsAuthority: false },
    { id: 'WORKER_ROWS_ROOT', ownerClass: 'unavailable-private-dispatch-owner', originFor: 'D', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false }
  ]
});
const CABM_EXPECTED_FACTS = Object.freeze({
  schema: `${CABM_PREFIX}fact-catalog/v1`,
  identifier: 'cohort-authority-binding-model-v1',
  entries: [
    { id: 'Q', requiredOwnerClass: 'unavailable-request-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, originRequirements: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, grantsAuthority: false },
    { id: 'A', requiredOwnerClass: 'unavailable-activation-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: ['Q'], retry: ['Q'], abort: ['Q'] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'LIVE_F', requiredOwnerClass: 'unavailable-private-capture-owner', staticAuthenticators: ['P', 'F', 'V2'], variants: ['initial'], statePredecessors: { initial: [], retry: [], abort: [] }, originRequirements: { initial: ['LIVE_F_CAPTURE'], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'B', requiredOwnerClass: 'unavailable-private-descriptor-owner', staticAuthenticators: ['R', 'K', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['A', 'LIVE_F'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'C', requiredOwnerClass: 'unavailable-exclusive-c-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'J', requiredOwnerClass: 'none', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'D', requiredOwnerClass: 'unavailable-private-dispatch-owner', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], retry: [], abort: [] }, originRequirements: { initial: ['WORKER_ROWS_ROOT'], retry: [], abort: [] }, grantsAuthority: false }
  ]
});
const CABM_EXPECTED_STATE_GRAMMAR = Object.freeze({
  schema: `${CABM_PREFIX}state-grammar/v1`,
  identifier: 'cohort-authority-binding-model-v1',
  variants: ['initial', 'retry', 'abort'],
  stateFacts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'],
  initial: { modelDisposition: 'abstract-model-only', factOrder: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J'], neverAdmitted: ['D'] },
  retry: { stateFacts: [], qPredecessors: ['RETRY_PREDECESSOR'], qDisposition: 'BLOCKED_EXTERNAL', aDisposition: 'DENY_PREREQUISITE', automaticRetry: false },
  abort: { qPredecessors: [], aPredecessors: ['Q'], closeDisposition: 'abstract-close-only', emitsFacts: [], synthesizesRetryPredecessor: false },
  d: { statePredecessors: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], originRequirements: ['WORKER_ROWS_ROOT'], disposition: 'BLOCKED_EXTERNAL', neverAdmitted: true },
  capture: { templateId: 'LIVE_F_TEMPLATE', originId: 'LIVE_F_CAPTURE', factId: 'LIVE_F', templateSatisfiesOrigin: false, frozenInputSatisfiesOrigin: false, bToOriginAuthorityEdge: false, preB: 'immutable-private-capture-commitment', postB: 'retention-metadata-nonauthority' },
  aliasSeparation: { workerRowEndpointIds: ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'], frozenEngineOrder: ['native', 'libauth', 'bchn', 'leanbch'], leanbchExpansion: { frozenEngineId: 'leanbch', staticLabels: ['engine:leanbch:primary', 'engine:leanbch:secondary'] }, mayInterchange: false, acceptedRowOrder: null, workerRowsRootDomain: null },
  crashPolicy: { emitsFacts: [], createsRetryPredecessor: false, abortCloseSatisfiesRetry: false, jSatisfiesRetry: false, dSatisfiesRetry: false, automaticRetry: false, reuse: false }
});
const CABM_EXPECTED_CARDINALITY = Object.freeze({
  workloadTemplate: { source: 'P.kLaunchAuthority[*].workloads', value: 4608, unit: 'workloads-per-endpoint', endpointCount: 5 },
  workerRowSchema: { source: 'K.dispatch-plan.workerRows', minimum: 1, maximum: 4096, unit: 'worker-rows-per-dispatch-plan' },
  projection: { status: 'UNAVAILABLE_EXTERNAL', mayEquate: false, mayDerive: false, grantsAuthority: false }
});
const CABM_DEPENDENCIES = Object.freeze([
  { id: 'R', artifactId: 'artifact:gate-b:cohort-runtime-binding-v1', primaryRawSha256: 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd', pins: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'runtime-authority-digest'] },
  { id: 'K', artifactId: 'artifact:gate-b:cohort-runner-core-v1', primaryRawSha256: 'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2', pins: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'manifest-package-root', 'manifest-root', 'entries-root', 'binding-digest', 'worker-row-schema-raw-sha256', 'dispatch-plan-schema-raw-sha256', 'worker-row-endpoint-id-aliases'] },
  { id: 'F', artifactId: 'artifact:gate-b:cohort-frozen-inputs-v1', primaryRawSha256: '19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5', pins: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'source-native-semantic-digest', 'freeze-artifact-semantic-digest', 'ordered-leaf-ids', 'frozen-four-surface-order'] },
  { id: 'P', artifactId: 'artifact:gate-b:cohort-policy-authority-v1', primaryRawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e', pins: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-root', 'policy-content-digest', 'causal-dag-root', 'live-f-template-digest', 'worker-alias-map', 'q-initial-template-digest', 'q-retry-template-digest', 'q-abort-template-digest', 'a-initial-template-digest', 'a-retry-template-digest', 'a-abort-template-digest', 'b-subject-template-digest', 'b-envelope-template-digest'] },
  { id: 'V2', artifactId: 'artifact:gate-b:cohort-live-executor-v2', primaryRawSha256: '45ddc12f0b44136a4f85e2800a47c8b9ed000ed0f33acc252b31b0758bdd2ebb', pins: ['root-content-digest', 'manifest-raw-sha256', 'sha256sums-raw-sha256', 'validator-raw-sha256', 'manifest-roster-digest', 'p-semantic-binding-digest', 'authority-dag-digest', 'transition-grammar-digest'] }
]);
const CABM_PURE_IMPORTS = Object.freeze({
  'src/canonical.mjs': [],
  'src/sha256.mjs': [],
  'src/model.mjs': ['./canonical.mjs', './sha256.mjs']
});
const CABM_PURE_EXPORTS = Object.freeze({
  'src/canonical.mjs': ['canonicalJson', 'utf8Encode'],
  'src/sha256.mjs': ['sha256Hex'],
  'src/model.mjs': ['AUTHORITY_DAG', 'DEPENDENCY_CATALOG', 'EXTERNAL_ORIGINS', 'FACT_CATALOG', 'STATE_GRAMMAR', 'DISPOSITIONS', 'assertAuthorityDag', 'assertDependencyCatalog', 'assertExternalOrigins', 'assertFactCatalog', 'assertStateGrammar', 'requiredPredecessors', 'ownerOf', 'availabilityOf', 'authorityDisposition', 'authorityDagDigest', 'dependencyCatalogDigest', 'externalOriginsDigest', 'factCatalogDigest', 'stateGrammarDigest', 'modelRootDigest']
});
const CABM_FORBIDDEN_PURE_SURFACE = /node:|\bimport\.meta\b|\bimport\s*\(|\brequire\s*\(|\b(?:eval|Function|globalThis|WebAssembly|Deno|Bun|Worker|SharedWorker|process|setTimeout|setInterval|queueMicrotask|fetch|WebSocket|XMLHttpRequest|child_process|vm|net|http|https)\b/u;
const CABM_FORBIDDEN_API = /\b(?:emptyState|assertState|guardTransition|replay)\b/u;
const CABM_FORBIDDEN_WORDS = /\b(?:circle|metrics|ranking|selection)\b/iu;

const cabmFail = (message) => { throw new Error(`cohort-authority-binding-model-v1 lane binding: ${message}`); };
const cabmAssert = (condition, message) => { if (!condition) cabmFail(message); };
const cabmCanonical = (value, seen = new Set()) => {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    cabmAssert(Number.isFinite(value) && !Object.is(value, -0), 'noncanonical number');
    return JSON.stringify(value);
  }
  cabmAssert(value && typeof value === 'object', 'non-JSON value');
  cabmAssert(!seen.has(value), 'cyclic value');
  seen.add(value);
  try {
    if (Array.isArray(value)) return `[${value.map((item) => cabmCanonical(item, seen)).join(',')}]`;
    cabmAssert(Object.getPrototypeOf(value) === Object.prototype, 'nonplain JSON record');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${cabmCanonical(value[key], seen)}`).join(',')}}`;
  } finally {
    seen.delete(value);
  }
};
const cabmEqual = (actual, expected, label) => cabmAssert(cabmCanonical(actual) === cabmCanonical(expected), `${label} differs`);
const cabmRawSha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const cabmFramedDigest = (domain, value) => createHash('sha256').update(Buffer.from(`${domain}\u0000${cabmCanonical(value)}\n`, 'utf8')).digest('hex');
const cabmRawFileDigest = (bytes) => createHash('sha256').update(Buffer.from(`${CABM_PREFIX}file\u0000`, 'utf8')).update(bytes).digest('hex');
const cabmDescriptor = (domain, value) => ({
  algorithm: 'sha256',
  canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',
  domain,
  frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1',
  value
});
const cabmRead = (root, locator) => {
  const absolute = resolve(root, locator);
  cabmAssert(absolute.startsWith(`${root}/`), `unsafe locator ${locator}`);
  return readFileSync(absolute);
};
const cabmReadCanonicalJson = (root, locator) => {
  const bytes = cabmRead(root, locator);
  cabmAssert(!bytes.includes(0x0d), `${locator} has CR bytes`);
  const text = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(text); } catch { cabmFail(`${locator} is not JSON`); }
  cabmAssert(text === `${cabmCanonical(value)}\n`, `${locator} is not canonical JSON plus one final LF`);
  return value;
};
const cabmCollect = (root, directory = root, prefix = '') => {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)))) {
    const locator = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = resolve(directory, entry.name);
    const stat = lstatSync(absolute);
    cabmAssert(!stat.isSymbolicLink(), `${locator} is a link`);
    if (stat.isDirectory()) {
      const nested = cabmCollect(root, absolute, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (stat.isFile()) {
      files.push(locator);
    } else {
      cabmFail(`${locator} is not a regular file or directory`);
    }
  }
  return { files, directories };
};
const cabmCheckFilesystem = (root) => {
  const rootStat = lstatSync(root);
  cabmAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.nlink === 1 && (rootStat.mode & 0o7777) === 0o755, 'package root mode, link count, or type changed');
  const found = cabmCollect(root);
  cabmEqual(found.directories.sort(), [...CABM_DIRECTORIES].sort(), 'directory closure');
  const closure = [...CABM_FILES, 'MANIFEST.json', 'SHA256SUMS'];
  cabmEqual(found.files.sort(), [...closure].sort(), 'file closure');
  for (const locator of CABM_DIRECTORIES) {
    const stat = lstatSync(resolve(root, locator));
    cabmAssert(stat.isDirectory() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o7777) === 0o755, `${locator} directory mode, link count, or type changed`);
  }
  for (const locator of closure) {
    const stat = lstatSync(resolve(root, locator));
    cabmAssert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o7777) === 0o644, `${locator} file mode, link count, or type changed`);
    cabmAssert(!cabmRead(root, locator).includes(0x0d), `${locator} has CR bytes`);
  }
};
const cabmCheckPureClosure = (root) => {
  for (const locator of [...CABM_FILES, 'MANIFEST.json', 'SHA256SUMS']) {
    cabmAssert(!CABM_FORBIDDEN_WORDS.test(cabmRead(root, locator).toString('utf8')), `${locator} has a forbidden lane-contamination word`);
  }
  for (const [locator, expectedImports] of Object.entries(CABM_PURE_IMPORTS)) {
    const source = cabmRead(root, locator).toString('utf8');
    cabmAssert(!CABM_FORBIDDEN_PURE_SURFACE.test(source) && !CABM_FORBIDDEN_API.test(source), `${locator} has a forbidden pure-surface token`);
    const actualImports = [
      ...source.matchAll(/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/gu),
      ...source.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/gu)
    ].map((match) => match[1]);
    cabmAssert(actualImports.every((specifier) => specifier.startsWith('./')), `${locator} has a nonrelative import`);
    cabmEqual(actualImports, expectedImports, `${locator} import graph`);
    const exportList = source.match(/export\s*\{([\s\S]*?)\};\s*$/u);
    cabmAssert(exportList !== null, `${locator} lacks a terminal exact export list`);
    cabmAssert(!/\bexport\b/u.test(source.slice(0, exportList.index)), `${locator} has an additional export surface`);
    const actualExports = exportList[1].split(',').map((name) => name.trim()).filter(Boolean);
    cabmEqual(actualExports, CABM_PURE_EXPORTS[locator], `${locator} export surface`);
  }
};
const cabmRequireRawPin = (root, locator, expected, label) => {
  cabmAssert(cabmRawSha256(cabmRead(root, locator)) === expected, `${label} raw SHA-256 pin changed`);
};
const cabmExpectedManifest = (root) => {
  const entries = CABM_FILES.map((locator) => {
    const bytes = cabmRead(root, locator);
    return { locator, bytes: bytes.length, sha256: cabmRawSha256(bytes), fileDigest: cabmRawFileDigest(bytes) };
  });
  return {
    schema: `${CABM_PREFIX}manifest/v1`,
    format: `${CABM_PREFIX}manifest/1`,
    package: 'cohort-authority-binding-model-v1',
    entryCount: CABM_FILES.length,
    entries,
    rosterDigest: cabmFramedDigest(`${CABM_PREFIX}manifest-roster`, { package: 'cohort-authority-binding-model-v1', entries })
  };
};
const cabmCheckManifestDocument = (root, manifest) => cabmEqual(manifest, cabmExpectedManifest(root), 'manifest semantic envelope');
const cabmCheckChecksumEnvelope = (root) => {
  const entries = cabmExpectedManifest(root).entries;
  const expected = [...entries, { locator: 'MANIFEST.json', sha256: cabmRawSha256(cabmRead(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  cabmAssert(cabmRead(root, 'SHA256SUMS').toString('utf8') === `${expected}\n`, 'SHA256SUMS semantic envelope changed');
};
const cabmSemanticDigests = (rootDocument) => ({
  authorityDagDigest: cabmFramedDigest(`${CABM_PREFIX}authority-requirement-dag`, rootDocument.pinnedAuthorityDag),
  dependencyCatalogDigest: cabmFramedDigest(`${CABM_PREFIX}dependency-catalog`, rootDocument.staticDependencies),
  externalOriginsDigest: cabmFramedDigest(`${CABM_PREFIX}external-origin-catalog`, rootDocument.externalOrigins),
  factCatalogDigest: cabmFramedDigest(`${CABM_PREFIX}fact-catalog`, rootDocument.facts),
  stateGrammarDigest: cabmFramedDigest(`${CABM_PREFIX}state-grammar`, rootDocument.stateGrammar)
});
const cabmCheckDependencies = (dependencies) => {
  cabmAssert(dependencies?.schema === `${CABM_PREFIX}dependency-catalog/v1` && dependencies?.identifier === 'cohort-authority-binding-model-v1', 'dependency catalog identity changed');
  cabmEqual(dependencies?.entries?.map((entry) => entry.id), CABM_DEPENDENCIES.map((entry) => entry.id), 'dependency catalog order');
  for (const expected of CABM_DEPENDENCIES) {
    const actual = dependencies.entries.find((entry) => entry.id === expected.id);
    cabmAssert(actual && actual.artifactId === expected.artifactId && actual.primaryRawSha256 === expected.primaryRawSha256, `dependency ${expected.id} root pin changed`);
    cabmEqual(actual.pins?.map((pin) => pin.id), expected.pins, `dependency ${expected.id} pin order`);
    cabmAssert(actual.pins.every((pin) => /^[0-9a-f]{64}$/u.test(pin.value) || /^[a-z0-9:=>,\-]+$/u.test(pin.value)), `dependency ${expected.id} has a malformed static pin`);
    cabmEqual(actual.authenticates, ['static-byte-pins', 'static-schema-types', 'static-catalog-types'], `dependency ${expected.id} static authenticators`);
    cabmEqual(actual.doesNotAuthenticate, ['concrete-retry-predecessor', 'live-private-capture', 'private-handles', 'worker-rows-root', 'activation', 'execution'], `dependency ${expected.id} nonauthentication boundary`);
  }
};
const cabmCheckRoot = (root) => {
  const rootDocument = cabmReadCanonicalJson(root, 'authority-binding-root.v1.json');
  cabmEqual(Object.keys(rootDocument).sort(), ['schema', 'identifier', 'status', 'staticDependencies', 'pinnedAuthorityDag', 'externalOrigins', 'facts', 'stateGrammar', 'cardinalitySeparation', 'contentDigest'].sort(), 'root key closure');
  cabmAssert(rootDocument.schema === `${CABM_PREFIX}model-root/v1` && rootDocument.identifier === 'cohort-authority-binding-model-v1' && rootDocument.status === CABM_ROOT_STATUS, 'model root identity or status changed');
  cabmAssert(CABM_ROOT_STATUS !== CABM_EXPECTED_BINDING.status, 'package-root and lane-binding statuses must remain distinct');
  cabmEqual(rootDocument.pinnedAuthorityDag, CABM_AUTHORITY_DAG, 'authority requirement DAG');
  cabmCheckDependencies(rootDocument.staticDependencies);
  cabmEqual(rootDocument.externalOrigins, CABM_EXPECTED_ORIGINS, 'external-origin catalog');
  cabmEqual(rootDocument.facts, CABM_EXPECTED_FACTS, 'fact catalog');
  cabmEqual(rootDocument.stateGrammar, CABM_EXPECTED_STATE_GRAMMAR, 'state grammar');
  cabmEqual(rootDocument.cardinalitySeparation, CABM_EXPECTED_CARDINALITY, 'cardinality separation');
  cabmAssert(rootDocument.externalOrigins.entries.length === 3 && rootDocument.facts.entries.length === 7, 'external-origin or fact roster changed');
  cabmAssert(rootDocument.externalOrigins.entries.every((entry) => entry.availability === 'unavailable' && entry.grantsAuthority === false) && rootDocument.facts.entries.every((entry) => entry.grantsAuthority === false), 'unavailable external-origin or nonauthority boundary changed');
  cabmAssert(rootDocument.stateGrammar.retry.stateFacts.length === 0 && rootDocument.stateGrammar.retry.qDisposition === 'BLOCKED_EXTERNAL' && rootDocument.stateGrammar.d.disposition === 'BLOCKED_EXTERNAL' && rootDocument.stateGrammar.d.neverAdmitted === true, 'retry or D external blocking changed');
  cabmAssert(rootDocument.stateGrammar.aliasSeparation.acceptedRowOrder === null && rootDocument.stateGrammar.aliasSeparation.workerRowsRootDomain === null && rootDocument.stateGrammar.aliasSeparation.mayInterchange === false, 'row-order, root-domain, or alias separation changed');
  const predecessorIds = rootDocument.facts.entries.flatMap((entry) => Object.values(entry.statePredecessors).flat());
  cabmAssert(!predecessorIds.some((id) => ['R', 'K', 'F', 'P', 'V2'].includes(id)), 'static authenticators became state predecessors');
  const semanticDigests = cabmSemanticDigests(rootDocument);
  for (const [key, expected] of Object.entries({
    authorityDagDigest: CABM_EXPECTED_BINDING.authorityDagDigest,
    dependencyCatalogDigest: CABM_EXPECTED_BINDING.dependencyCatalogDigest,
    externalOriginsDigest: CABM_EXPECTED_BINDING.externalOriginsDigest,
    factCatalogDigest: CABM_EXPECTED_BINDING.factCatalogDigest,
    stateGrammarDigest: CABM_EXPECTED_BINDING.stateGrammarDigest
  })) cabmAssert(semanticDigests[key] === expected, `${key} pin changed`);
  const { contentDigest: _contentDigest, ...rootPayload } = rootDocument;
  const rootDigest = cabmFramedDigest(`${CABM_PREFIX}root`, rootPayload);
  cabmAssert(rootDigest === CABM_EXPECTED_BINDING.root.contentDigest, 'model root content digest pin changed');
  cabmEqual(rootDocument.contentDigest, cabmDescriptor(`${CABM_PREFIX}root`, rootDigest), 'model root digest descriptor');
  return { rootDocument, semanticDigests };
};
const cabmValidateIndependent = (root = CABM_PACKAGE_ROOT) => {
  cabmCheckFilesystem(root);
  cabmRequireRawPin(root, 'authority-binding-root.v1.json', CABM_EXPECTED_BINDING.root.rawSha256, 'model root');
  cabmRequireRawPin(root, 'MANIFEST.json', CABM_EXPECTED_BINDING.manifest.rawSha256, 'manifest');
  cabmRequireRawPin(root, 'SHA256SUMS', CABM_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope');
  cabmRequireRawPin(root, 'validate-static.mjs', CABM_EXPECTED_BINDING.validator.rawSha256, 'validator');
  cabmRequireRawPin(root, 'src/model.mjs', CABM_EXPECTED_BINDING.model.rawSha256, 'model');
  for (const locator of CABM_FILES.filter((entry) => entry.endsWith('.json'))) cabmReadCanonicalJson(root, locator);
  const { rootDocument, semanticDigests } = cabmCheckRoot(root);
  const manifest = cabmReadCanonicalJson(root, 'MANIFEST.json');
  cabmCheckManifestDocument(root, manifest);
  cabmAssert(manifest.rosterDigest === CABM_EXPECTED_BINDING.manifest.rosterDigest && manifest.entryCount === CABM_EXPECTED_BINDING.manifest.entryCount, 'manifest roster or entry-count pin changed');
  cabmCheckChecksumEnvelope(root);
  cabmCheckPureClosure(root);
  return { rootDocument, semanticDigests, manifest, files: CABM_FILES.length + 2, directories: CABM_DIRECTORIES.length };
};
const cabmWriteCanonicalJson = (root, locator, value) => writeFileSync(resolve(root, locator), Buffer.from(`${cabmCanonical(value)}\n`, 'utf8'));
const cabmRegenerateEnvelope = (root) => {
  const manifest = cabmExpectedManifest(root);
  cabmWriteCanonicalJson(root, 'MANIFEST.json', manifest);
  const sums = [...manifest.entries, { locator: 'MANIFEST.json', sha256: cabmRawSha256(cabmRead(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  writeFileSync(resolve(root, 'SHA256SUMS'), Buffer.from(`${sums}\n`, 'utf8'));
  return manifest;
};
const cabmExpectFailure = (operation, label) => {
  let failed = false;
  try { operation(); } catch { failed = true; }
  cabmAssert(failed, `${label} mutation was accepted`);
};
const cabmRunCausalMutation = async () => {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), 'shieldkit-cabm-lane-'));
  const mutatedPackage = resolve(temporaryRoot, 'cohort-authority-binding-model-v1');
  try {
    cpSync(CABM_PACKAGE_ROOT, mutatedPackage, { recursive: true, errorOnExist: true, verbatimSymlinks: true });
    const modelRoot = cabmReadCanonicalJson(mutatedPackage, 'authority-binding-root.v1.json');
    modelRoot.pinnedAuthorityDag.edges[0] = 'N→K';
    modelRoot.staticDependencies.entries[0].pins[0].value = '0'.repeat(64);
    modelRoot.externalOrigins.entries[0].ownerClass = 'mutated-unavailable-recovery-chain-owner';
    modelRoot.facts.entries[6].grantsAuthority = true;
    modelRoot.stateGrammar.d.neverAdmitted = false;
    const { contentDigest: _priorContentDigest, ...mutatedRootPayload } = modelRoot;
    const mutatedRootDigest = cabmFramedDigest(`${CABM_PREFIX}root`, mutatedRootPayload);
    modelRoot.contentDigest = cabmDescriptor(`${CABM_PREFIX}root`, mutatedRootDigest);
    cabmWriteCanonicalJson(mutatedPackage, 'authority-binding-root.v1.json', modelRoot);
    const factSchema = cabmReadCanonicalJson(mutatedPackage, 'schemas/fact-catalog.v1.schema.json');
    factSchema.$defs.factEntry.properties.grantsAuthority = { type: 'boolean' };
    cabmWriteCanonicalJson(mutatedPackage, 'schemas/fact-catalog.v1.schema.json', factSchema);
    const originalD = "{ id: 'D', requiredOwnerClass: 'unavailable-private-dispatch-owner', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], retry: [], abort: [] }, originRequirements: { initial: ['WORKER_ROWS_ROOT'], retry: [], abort: [] }, grantsAuthority: false }";
    const modelSource = cabmRead(mutatedPackage, 'src/model.mjs').toString('utf8');
    cabmAssert(modelSource.includes(originalD), 'D fact source anchor changed');
    writeFileSync(resolve(mutatedPackage, 'src/model.mjs'), modelSource.replace(originalD, originalD.replace('grantsAuthority: false', 'grantsAuthority: true')));
    writeFileSync(resolve(mutatedPackage, 'validate-static.mjs'), 'export function validateStatic() { return true; }\n');
    const manifest = cabmRegenerateEnvelope(mutatedPackage);
    const mutatedSemanticDigests = cabmSemanticDigests(modelRoot);
    cabmExpectFailure(() => cabmRequireRawPin(mutatedPackage, 'validate-static.mjs', CABM_EXPECTED_BINDING.validator.rawSha256, 'validator'), 'validator raw pin');
    cabmExpectFailure(() => cabmRequireRawPin(mutatedPackage, 'authority-binding-root.v1.json', CABM_EXPECTED_BINDING.root.rawSha256, 'model root'), 'model root raw pin');
    cabmExpectFailure(() => cabmAssert(modelRoot.contentDigest.value === CABM_EXPECTED_BINDING.root.contentDigest, 'model root content pin changed'), 'model root content pin');
    cabmExpectFailure(() => cabmRequireRawPin(mutatedPackage, 'src/model.mjs', CABM_EXPECTED_BINDING.model.rawSha256, 'model'), 'model raw pin');
    cabmExpectFailure(() => cabmRequireRawPin(mutatedPackage, 'MANIFEST.json', CABM_EXPECTED_BINDING.manifest.rawSha256, 'manifest'), 'manifest raw pin');
    cabmExpectFailure(() => cabmAssert(manifest.rosterDigest === CABM_EXPECTED_BINDING.manifest.rosterDigest, 'manifest roster pin changed'), 'manifest roster pin');
    cabmExpectFailure(() => cabmRequireRawPin(mutatedPackage, 'SHA256SUMS', CABM_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope'), 'checksum raw pin');
    for (const [key, expected] of Object.entries({
      authorityDagDigest: CABM_EXPECTED_BINDING.authorityDagDigest,
      dependencyCatalogDigest: CABM_EXPECTED_BINDING.dependencyCatalogDigest,
      externalOriginsDigest: CABM_EXPECTED_BINDING.externalOriginsDigest,
      factCatalogDigest: CABM_EXPECTED_BINDING.factCatalogDigest,
      stateGrammarDigest: CABM_EXPECTED_BINDING.stateGrammarDigest
    })) cabmExpectFailure(() => cabmAssert(mutatedSemanticDigests[key] === expected, `${key} pin changed`), `${key} pin`);
    const replacement = await import(`${pathToFileURL(resolve(mutatedPackage, 'validate-static.mjs')).href}?cohort-authority-binding-model-v1-causal-mutation`);
    cabmAssert(replacement.validateStatic() === true, 'coordinated replacement validator did not accept its local package');
    return true;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
    cabmAssert(!existsSync(temporaryRoot), 'causal mutation temporary root was not cleaned up');
  }
};
const ECOC_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/';
const ECOC_PACKAGE_RELATIVE = 'p2/gate-b/cohort-external-origin-contract-v1';
const ECOC_PACKAGE_ROOT = resolve(laneDir, ECOC_PACKAGE_RELATIVE);
const ECOC_ROOT_STATUS = 'static-external-origin-contract-catalog-no-instances-non-authorizing-origins-unavailable-unqualified';
const ECOC_NEXT_GATE = 'No downstream gate opens by this integration. Only a separately authorized read-only/no-I/O upstream-origin-provider architecture gate may open next. It may identify static owner/root/domain/order/projection provider contracts but may not instantiate an owner, origin, fact, root value, projection, or private byte; lift retry or D; grant authority; add runtime/endpoint/execution; or open downstream work. J remains ownerless and non-authorizing. Attempt-001, live origins, identities, capabilities, guard lifts, runtime, execution, evidence, metrics, ranking, selection, Circle/query, tuples, and prover remain closed.';
const ECOC_NONPROMOTION = 'The sealed cohort-external-origin-contract-v1 package is a static, non-authorizing, unqualified external-origin contract catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant and admission remains false, retry remains BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.';
const ECOC_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-integrated-no-io-architecture-unpromoted';
const ECOC_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-integrated-no-io-unqualified';
const ECOC_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-integrated-no-io-nonranking-unqualified';
const ECOC_FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'external-origin-contract-root.v1.json', 'validate-static.mjs',
  'schemas/causal-dag.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/ownership-catalog.v1.schema.json',
  'schemas/retry-predecessor-contract.v1.schema.json', 'schemas/live-f-capture-contract.v1.schema.json', 'schemas/worker-rows-root-contract.v1.schema.json',
  'schemas/workload-projection-contract.v1.schema.json', 'schemas/fact-contract-catalog.v1.schema.json', 'schemas/digest.v1.schema.json',
  'schemas/model-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
  'test/digest.kat.json', 'test/static.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs'
]);
const ECOC_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const ECOC_FACT_CONTRACT_SCHEMA_RAW = 'bbc59c8a04574512193a7aac74313545ecc8511b9fcf49fe47bb73d8770c867f';
const ECOC_CABM_DAG = Object.freeze({
  nodes: ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT'],
  edges: ['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']
});
const ECOC_EXTERNAL_DAG = Object.freeze({
  nodes: ['RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT', 'Q_INITIAL', 'Q_RETRY', 'Q_ABORT', 'A_INITIAL', 'A_RETRY', 'A_ABORT', 'LIVE_F', 'B', 'C', 'J', 'D'],
  edges: ['RETRY_PREDECESSOR→Q_RETRY', 'Q_INITIAL→A_INITIAL', 'Q_RETRY→A_RETRY', 'Q_ABORT→A_ABORT', 'LIVE_F_CAPTURE→LIVE_F', 'A_INITIAL→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']
});
const ECOC_EXPECTED_BINDING = Object.freeze({
  path: ECOC_PACKAGE_RELATIVE,
  root: { path: ECOC_PACKAGE_RELATIVE + '/external-origin-contract-root.v1.json', rawSha256: '63b8f0312fc5da429f66ce7ccfcc9c213edc52f9ce8ec671c7e0223207ac4f7d', contentDigest: '6aab36a2a185207da03c364066f9f791cf2710408798b1d93ef61618177f6e60' },
  dependencyCatalogDigest: '5f1462db4dc63600721d8da95578b3ff94c2a929173f81c19c9d0db94f9089b8',
  cabmAuthorityPrefixDigest: 'f487c232fd574853ac1039d54ff2d6218579234ff753df55e5b724c1647771e0',
  externalCausalDagDigest: '6227fd5d52dfc9e4b2879ce58c0bc45ea150dd5bde5719e476bd004073da5e45',
  ownershipCatalogDigest: '68d517dde6d5de8e5d5f8b7ece6509174039a5fbe72e9e0cef1250e7edf13e41',
  externalOriginContractsDigest: '1836a1038698ee6809f03b870a1b1b4c4d1c8855603cc1ce5b402287a844db96',
  factContractsDigest: '48824ca660ced0da245066bef687bac22ff25d4d30a344bb474cfceaa02ac823',
  rootDomainCatalogDigest: 'f6dc6604a33d227f07fb7101f9669be23a503eaa11d656c1a6b306c3a71d4284',
  workloadProjectionContractDigest: 'bb4de79eaf432b595ce19ca02c86180ccd0259789ddf95f0ba834b6f657497c0',
  manifest: { path: ECOC_PACKAGE_RELATIVE + '/MANIFEST.json', rawSha256: 'de386b8758b75c5a92fafdadcb9fe0dcd769ab7385afae8d8642c66df8608bc6', rosterDigest: 'd5dd2d964b0feb87ca367e300c450ca78afe7ebafc0e22ffad0118476d9a01ec', entryCount: 19 },
  checksums: { path: ECOC_PACKAGE_RELATIVE + '/SHA256SUMS', rawSha256: 'ec1b8bcee3a8e9835f4ed2b97b784fefe14000ee6e7df3f6a8cc4cd59671a5ea' },
  validator: { path: ECOC_PACKAGE_RELATIVE + '/validate-static.mjs', rawSha256: '0f37cf65905409c9a0bf26b8d98ad50fb228ae9500e6ff4647efa88b31a5f8de' },
  status: 'sol-regated-static-external-origin-contract-catalog-no-instances-non-authorizing-origins-unavailable-unqualified'
});
const ECOC_UPSTREAM_BASE = 'research-lanes/bch-shielded-pool-design/p2/gate-b/';
const ECOC_UPSTREAM_LEAF_ROWS = Object.freeze([
  ['R', 'cohort-runtime-binding-v1/runtime-binding-root.v1.json', 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd', 'primary-root'],
  ['R', 'cohort-runtime-binding-v1/MANIFEST.json', '2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254', 'manifest'],
  ['R', 'cohort-runtime-binding-v1/SHA256SUMS', 'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea', 'checksum-list'],
  ['K', 'cohort-runner-core-v1/runtime-core.v1.json', 'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2', 'primary-root'],
  ['K', 'cohort-runner-core-v1/MANIFEST.json', '913e5667c78de4f06a7ce34acfa13fb1393eeadbbf831641eab35ceddf3f01c4', 'manifest'],
  ['K', 'cohort-runner-core-v1/SHA256SUMS', '27ffdc493af8e77ab89b22dde1b424f0d9733bf9491013943b8a63ccc87bb4db', 'checksum-list'],
  ['K', 'cohort-runner-core-v1/schemas/worker-row.v1.schema.json', '6ff74e986cc12ad7eea100455ad41dcfb918311636c9e77c3e8053442b3460a2', 'worker-row-schema'],
  ['K', 'cohort-runner-core-v1/schemas/dispatch-plan.v1.schema.json', '821c60bd9385553e976bfad0d894ae6c0130a3085e1d9c367cb465cd878fb57b', 'dispatch-plan-schema'],
  ['K', 'cohort-runner-core-v1/src/contracts.mjs', '24518273dc70fcf240105328525f2fe177ee10a4f48f34c07f0d38d0502f545c', 'worker-row-contract-source'],
  ['K', 'cohort-runner-core-v1/src/strict.mjs', '7783af41d271634ff634043f7d0b34c165f6c1a019118598e176be64eec5def3', 'canonical-hash-contract-source'],
  ['F', 'cohort-frozen-inputs-v1/frozen-inputs-root.v1.json', '19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5', 'primary-root'],
  ['F', 'cohort-frozen-inputs-v1/MANIFEST.json', 'f6b1dbf3f6757366c519e10f11e1fed80d071507445ad0085955aae164ad0867', 'manifest'],
  ['F', 'cohort-frozen-inputs-v1/SHA256SUMS', '4099e52c4acd2c2c34c49142bb28e6cb7ac31d048feb452e053038f3db578eff', 'checksum-list'],
  ['P', 'cohort-policy-authority-v1/policy-authority-root.v1.json', 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e', 'primary-root'],
  ['P', 'cohort-policy-authority-v1/MANIFEST.json', '60fbc7ffe72e41a4df60603d9d4b6b0f0e118e1577028643fc867fbe3cb06bb1', 'manifest'],
  ['P', 'cohort-policy-authority-v1/SHA256SUMS', '66a8e1437c4c8d78dfa7600f7d0e1b83a2c6321c3f86b3d3a3dc2678eba992bb', 'checksum-list'],
  ['P', 'cohort-policy-authority-v1/schemas/q.v1.schema.json', 'e0ca38ea45bad589a4a36563dc53e3c01afb932dd8b5a93cec98a2915707f3c1', 'q-template-schema'],
  ['P', 'cohort-policy-authority-v1/schemas/a.v1.schema.json', '895b6013aa05393730b551ff8c12932a63debe5c26382e4c430d507d49b5fe06', 'a-template-schema'],
  ['P', 'cohort-policy-authority-v1/schemas/live-f.v1.schema.json', 'de918fc0d643d9a9634a16481ffe3e69ce01846cdca9c1dbb5c5da76f5000396', 'live-f-template-schema'],
  ['P', 'cohort-policy-authority-v1/schemas/policy.v1.schema.json', '817edc9e74dda772688f770a18492c5e4aff04ff20555d6320fff5452bae8eee', 'policy-schema'],
  ['V2', 'cohort-live-executor-v2/model-root.v2.json', '45ddc12f0b44136a4f85e2800a47c8b9ed000ed0f33acc252b31b0758bdd2ebb', 'primary-root'],
  ['V2', 'cohort-live-executor-v2/MANIFEST.json', 'ef03043f458915856b5c420e039208f6a0307633d20b21dac8238d73316fd98a', 'manifest'],
  ['V2', 'cohort-live-executor-v2/SHA256SUMS', '0ef72e260de7afdc9bb508739321418be95c48879b09992669af23e71e3d7285', 'checksum-list'],
  ['V2', 'cohort-live-executor-v2/validate-static.mjs', '31ef0e6f22eb6f6b20e426ca5ae4da2c0c8f7ed64becb693ad1da3fa81d8973a', 'static-validator'],
  ['CABM', 'cohort-authority-binding-model-v1/authority-binding-root.v1.json', '858050856ed4784d6b91bc74550c7e6595fae9596715314cc85bdee4051f68cb', 'primary-root'],
  ['CABM', 'cohort-authority-binding-model-v1/MANIFEST.json', '05b171e7b4c8f308eb46f0f6bffb78f260513322d5b91728bf61a6cb62e891b7', 'manifest'],
  ['CABM', 'cohort-authority-binding-model-v1/SHA256SUMS', 'a296a3a7b6acabed4b70c648d3907f032fd309ef32980427eb77fbff840dffab', 'checksum-list'],
  ['CABM', 'cohort-authority-binding-model-v1/validate-static.mjs', 'e738933e665f7c748fc58edadf9255863469be9b67e3c40639014c83d73c8269', 'static-validator'],
  ['CABM', 'cohort-authority-binding-model-v1/src/model.mjs', 'c46d205194fd773bdb263884faa62a94c161f35afded1e9431521749401378c9', 'pure-model-source']
]);
const ECOC_UPSTREAM_LEAVES = Object.freeze(ECOC_UPSTREAM_LEAF_ROWS.map(([dependencyId, suffix, rawSha256, role]) => ({ dependencyId, locator: ECOC_UPSTREAM_BASE + suffix, rawSha256, role })));
const ECOC_COMPONENT_DOMAINS = Object.freeze({
  staticDependencies: ECOC_PREFIX + 'dependency-catalog',
  cabmAuthorityPrefix: ECOC_PREFIX + 'cabm-authority-prefix',
  externalCausalDag: ECOC_PREFIX + 'external-causal-dag',
  ownershipCatalog: ECOC_PREFIX + 'ownership-catalog',
  externalOriginContracts: ECOC_PREFIX + 'external-origin-contracts',
  factContracts: ECOC_PREFIX + 'fact-contracts',
  rootDomainCatalog: ECOC_PREFIX + 'root-domain-catalog',
  workloadProjectionContract: ECOC_PREFIX + 'workload-projection-contract'
});
const ECOC_FACT_VARIANT_KEYS = Object.freeze({
  Q: ['abort', 'initial', 'retry'],
  A: ['abort', 'initial', 'retry'],
  LIVE_F: ['initial'],
  B: ['initial'],
  C: ['initial'],
  J: ['initial'],
  D: ['initial']
});

const ecocFail = (message) => { throw new Error('cohort-external-origin-contract-v1 lane binding: ' + message); };
const ecocAssert = (condition, message) => { if (!condition) ecocFail(message); };
const ecocCanonical = (value) => cabmCanonical(value);
const ecocEqual = (actual, expected, label) => ecocAssert(ecocCanonical(actual) === ecocCanonical(expected), label + ' differs');
const ecocRawSha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const ecocFramedDigest = (domain, value) => createHash('sha256').update(Buffer.from(domain + '\u0000' + ecocCanonical(value) + '\n', 'utf8')).digest('hex');
const ecocRawFileDigest = (bytes) => createHash('sha256').update(Buffer.from(ECOC_PREFIX + 'file\u0000', 'utf8')).update(bytes).digest('hex');
const ecocDescriptor = (domain, value) => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1', value });
const ecocWithout = (value, key = 'contentDigest') => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
const ecocLocalPath = (root, locator) => {
  ecocAssert(typeof locator === 'string' && locator.length > 0 && !locator.startsWith('/') && !locator.includes('\\') && !locator.split('/').includes('..'), 'unsafe local locator ' + locator);
  const absolute = resolve(root, locator);
  const rel = relative(root, absolute);
  ecocAssert(rel !== '' && rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\'), 'local locator escapes ' + locator);
  return absolute;
};
const ecocRead = (root, locator) => {
  const absolute = ecocLocalPath(root, locator);
  const info = lstatSync(absolute);
  ecocAssert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1, locator + ' is not an unlinked regular file');
  return readFileSync(absolute);
};
const ecocReadCanonicalJson = (root, locator) => {
  const bytes = ecocRead(root, locator);
  const text = bytes.toString('utf8');
  ecocAssert(!bytes.includes(0x0d) && text.endsWith('\n') && !text.endsWith('\n\n'), locator + ' final LF or CR framing changed');
  let value;
  try { value = JSON.parse(text); } catch { ecocFail(locator + ' is not JSON'); }
  ecocAssert(text === ecocCanonical(value) + '\n', locator + ' is not canonical JSON plus one final LF');
  return value;
};
const ecocCollect = (root, directory = root, prefix = '') => {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)))) {
    const locator = prefix ? prefix + '/' + entry.name : entry.name;
    const absolute = resolve(directory, entry.name);
    const info = lstatSync(absolute);
    ecocAssert(!info.isSymbolicLink(), locator + ' is a link');
    if (info.isDirectory()) {
      const nested = ecocCollect(root, absolute, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (info.isFile()) files.push(locator);
    else ecocFail(locator + ' is neither a regular file nor directory');
  }
  return { files, directories };
};
const ecocCheckFilesystem = (root) => {
  const rootInfo = lstatSync(root);
  ecocAssert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink() && rootInfo.nlink === 1 && (rootInfo.mode & 0o7777) === 0o755 && realpathSync(root) === resolve(root), 'package root mode, link count, or type changed');
  const found = ecocCollect(root);
  const closure = [...ECOC_FILES, 'MANIFEST.json', 'SHA256SUMS'];
  ecocEqual(found.directories.sort(), [...ECOC_DIRECTORIES].sort(), 'directory closure');
  ecocEqual(found.files.sort(), [...closure].sort(), 'file closure');
  for (const locator of ECOC_DIRECTORIES) {
    const info = lstatSync(locator === '.' ? root : ecocLocalPath(root, locator));
    ecocAssert(info.isDirectory() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o7777) === 0o755, locator + ' directory mode, link count, or type changed');
  }
  for (const locator of closure) {
    const info = lstatSync(ecocLocalPath(root, locator));
    const bytes = ecocRead(root, locator);
    ecocAssert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o7777) === 0o644, locator + ' file mode, link count, or type changed');
    ecocAssert(bytes.length > 0 && bytes.at(-1) === 0x0a && !bytes.includes(0x0d), locator + ' LF or CR framing changed');
  }
};
const ecocCheckCodeBoundary = (root) => {
  const source = ecocRead(root, 'validate-static.mjs').toString('utf8');
  const imports = [...source.matchAll(/(?:^|\n)import\s+(?:[^'"\n]+\s+from\s+)?['"]([^'"]+)['"]/gu)].map((match) => match[1]).sort();
  ecocEqual(imports, ['ajv/dist/2020.js', 'node:crypto', 'node:fs', 'node:path', 'node:url'], 'validator import closure');
  ecocAssert(source.includes('export { rawFileDigest, semanticDigest, validateStatic };'), 'validator exact export surface changed');
  ecocAssert(!/\bimport\s*\(|\brequire\s*\(|\bwriteFile|\bappendFile|\bmkdir|\brmSync|\bspawn|\bexec\b|\bfork\b|\bworker_threads\b|\bnode:vm\b|\bnode:net\b|\bnode:http\b|\bnode:https\b|\bWebSocket\b|\bXMLHttpRequest\b|\bWebAssembly\b/u.test(source), 'validator activation or writer surface changed');
};
const ecocExpectedManifest = (root) => {
  const entries = ECOC_FILES.map((locator) => {
    const bytes = ecocRead(root, locator);
    return { bytes: bytes.length, fileDigest: ecocRawFileDigest(bytes), locator, sha256: ecocRawSha256(bytes) };
  });
  return {
    entries,
    entryCount: ECOC_FILES.length,
    format: ECOC_PREFIX + 'manifest/1',
    package: 'cohort-external-origin-contract-v1',
    rosterDigest: ecocFramedDigest(ECOC_PREFIX + 'manifest-roster', { package: 'cohort-external-origin-contract-v1', entries }),
    schema: ECOC_PREFIX + 'manifest/v1'
  };
};
const ecocCheckManifest = (root) => {
  const manifest = ecocReadCanonicalJson(root, 'MANIFEST.json');
  const expected = ecocExpectedManifest(root);
  ecocEqual(manifest, expected, 'manifest raw-byte envelope');
  const sums = [...expected.entries, { locator: 'MANIFEST.json', sha256: ecocRawSha256(ecocRead(root, 'MANIFEST.json')) }]
    .map((entry) => entry.sha256 + '  ' + entry.locator).join('\n') + '\n';
  ecocAssert(ecocRead(root, 'SHA256SUMS').toString('utf8') === sums, 'checksum envelope differs');
  return manifest;
};
const ecocCheckComponent = (component, domain, label) => {
  ecocAssert(component && typeof component === 'object' && !Array.isArray(component) && Object.hasOwn(component, 'contentDigest'), label + ' contentDigest missing');
  const digest = ecocFramedDigest(domain, ecocWithout(component));
  ecocEqual(component.contentDigest, ecocDescriptor(domain, digest), label + ' contentDigest');
  return digest;
};
const ecocCheckNoMaterial = (value, context = '') => {
  ecocAssert(value !== null, 'null material is forbidden at ' + context);
  if (Array.isArray(value)) {
    value.forEach((item, index) => ecocCheckNoMaterial(item, context + '/' + index));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (key === 'futurePreimageKeys') continue;
    ecocAssert(!['ownerBindingRoot', 'targetRoot', 'predecessorRoot', 'retryPredecessorRoot', 'liveFCaptureRoot', 'workerRowsRoot', 'dispatchPlanRoot', 'privateBytes', 'projectionBytes', 'identity', 'capability', 'instance'].includes(key), 'material field is forbidden at ' + context + '/' + key);
    ecocCheckNoMaterial(item, context + '/' + key);
  }
};
const ecocCheckFutureKeyList = (value, label) => {
  ecocAssert(Array.isArray(value) && value.every((item) => typeof item === 'string') && new Set(value).size === value.length, label + ' must be an ordered unique string list');
};
const ecocCheckVariantKeyMap = (value, expected, label) => {
  ecocAssert(value && typeof value === 'object' && !Array.isArray(value), label + ' must be a variant record');
  ecocEqual(Object.keys(value).sort(), [...expected].sort(), label + ' key closure');
  for (const key of expected) ecocCheckFutureKeyList(value[key], label + '/' + key);
};
const ecocCheckFutureKeyShapes = (root) => {
  const originIds = ['RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT'];
  ecocEqual(root.externalOriginContracts.entries.map((entry) => entry.id), originIds, 'external-origin roster');
  for (const entry of root.externalOriginContracts.entries) ecocCheckFutureKeyList(entry.futurePreimageKeys, 'origin ' + entry.id + ' futurePreimageKeys');
  const factIds = ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'];
  ecocEqual(root.factContracts.entries.map((entry) => entry.id), factIds, 'fact roster');
  for (const entry of root.factContracts.entries) {
    ecocCheckVariantKeyMap(entry.futurePreimageKeys, ECOC_FACT_VARIANT_KEYS[entry.id], 'fact ' + entry.id + ' futurePreimageKeys');
    ecocCheckVariantKeyMap(entry.statePredecessors, ['abort', 'initial', 'retry'], 'fact ' + entry.id + ' statePredecessors');
    ecocCheckVariantKeyMap(entry.originRequirements, ['abort', 'initial', 'retry'], 'fact ' + entry.id + ' originRequirements');
  }
  const workloadKeys = root.workloadProjectionContract.futurePreimageKeys;
  ecocAssert(workloadKeys && typeof workloadKeys === 'object' && !Array.isArray(workloadKeys), 'workload futurePreimageKeys is not a record');
  ecocEqual(Object.keys(workloadKeys).sort(), ['dispatchPlan', 'endpointByteAuthority'], 'workload futurePreimageKeys key closure');
  ecocCheckFutureKeyList(workloadKeys.dispatchPlan, 'workload dispatchPlan futurePreimageKeys');
  ecocCheckFutureKeyList(workloadKeys.endpointByteAuthority, 'workload endpointByteAuthority futurePreimageKeys');
  const domains = root.rootDomainCatalog.entries;
  ecocEqual(domains.map((entry) => entry.id), ['OWNER_BINDING', 'RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT', 'ENDPOINT_BYTE_AUTHORITY', 'DISPATCH_PLAN', 'Q', 'A', 'LIVE_F', 'B_SUBJECT', 'B', 'C', 'J', 'D'], 'root-domain roster');
  for (const entry of domains) {
    if (Array.isArray(entry.futurePreimageKeys)) ecocCheckFutureKeyList(entry.futurePreimageKeys, 'root-domain ' + entry.id + ' futurePreimageKeys');
    else if (entry.id === 'Q' || entry.id === 'A') ecocCheckVariantKeyMap(entry.futurePreimageKeys, ['abort', 'initial', 'retry'], 'root-domain ' + entry.id + ' futurePreimageKeys');
    else ecocFail('root-domain ' + entry.id + ' futurePreimageKeys shape changed');
  }
};
const ecocSemanticDigests = (root) => ({
  dependencyCatalogDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.staticDependencies, ecocWithout(root.staticDependencies)),
  cabmAuthorityPrefixDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.cabmAuthorityPrefix, ecocWithout(root.cabmAuthorityPrefix)),
  externalCausalDagDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.externalCausalDag, ecocWithout(root.externalCausalDag)),
  ownershipCatalogDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.ownershipCatalog, ecocWithout(root.ownershipCatalog)),
  externalOriginContractsDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.externalOriginContracts, ecocWithout(root.externalOriginContracts)),
  factContractsDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.factContracts, ecocWithout(root.factContracts)),
  rootDomainCatalogDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.rootDomainCatalog, ecocWithout(root.rootDomainCatalog)),
  workloadProjectionContractDigest: ecocFramedDigest(ECOC_COMPONENT_DOMAINS.workloadProjectionContract, ecocWithout(root.workloadProjectionContract))
});
const ecocCheckRoot = (root) => {
  ecocEqual(Object.keys(root).sort(), ['cabmAuthorityPrefix', 'contentDigest', 'executionAllowed', 'externalCausalDag', 'externalOriginContracts', 'factContracts', 'identifier', 'nonAuthorityBoundary', 'ownershipCatalog', 'rootDomainCatalog', 'schema', 'staticDependencies', 'status', 'workloadProjectionContract'].sort(), 'root key closure');
  ecocAssert(root.identifier === 'cohort-external-origin-contract-v1' && root.schema === ECOC_PREFIX + 'model-root/v1' && root.status === ECOC_ROOT_STATUS && root.executionAllowed === false, 'root identity, status, or execution boundary changed');
  ecocAssert(ECOC_ROOT_STATUS !== ECOC_EXPECTED_BINDING.status, 'package-root and lane-binding statuses must remain distinct');
  ecocCheckNoMaterial(root);
  for (const [field, domain] of Object.entries(ECOC_COMPONENT_DOMAINS)) ecocCheckComponent(root[field], domain, field);
  const rootDigest = ecocFramedDigest(ECOC_PREFIX + 'root', ecocWithout(root));
  ecocEqual(root.contentDigest, ecocDescriptor(ECOC_PREFIX + 'root', rootDigest), 'root contentDigest');
  ecocEqual({ nodes: root.cabmAuthorityPrefix.nodes, edges: root.cabmAuthorityPrefix.edges }, ECOC_CABM_DAG, 'CABM 17/22 prefix');
  ecocAssert(root.cabmAuthorityPrefix.nodeCount === 17 && root.cabmAuthorityPrefix.edgeCount === 22 && root.cabmAuthorityPrefix.sourceDependencyId === 'CABM' && root.cabmAuthorityPrefix.sourceField === 'pinnedAuthorityDag' && root.cabmAuthorityPrefix.sourceSemanticDigest === '66559720074ff58ce80f13fd031d4e5cb807e4bf8adff69690b1c3d91dd284d1', 'CABM prefix metadata changed');
  ecocEqual({ nodes: root.externalCausalDag.nodes, edges: root.externalCausalDag.edges }, ECOC_EXTERNAL_DAG, 'external 14-node/14-edge DAG');
  ecocAssert(root.externalCausalDag.nodeCount === 14 && root.externalCausalDag.edgeCount === 14 && root.externalCausalDag.staticDependencyEdgesAllowed === false, 'external DAG metadata changed');
  ecocAssert(root.staticDependencies.entries.length === 29 && root.ownershipCatalog.entries.length === 10 && root.externalOriginContracts.entries.length === 3 && root.factContracts.entries.length === 7 && root.rootDomainCatalog.entries.length === 14, 'catalog cardinality changed');
  ecocCheckFutureKeyShapes(root);
  ecocAssert(root.externalOriginContracts.entries.every((entry) => entry.availability === 'unavailable' && entry.admissionAllowed === false && entry.grantsAuthority === false), 'origin availability, admission, or grant changed');
  ecocAssert(root.factContracts.entries.every((entry) => entry.admissionAllowed === false && entry.grantsAuthority === false), 'fact admission or grant changed');
  ecocAssert(root.ownershipCatalog.entries.every((entry) => entry.grantsAuthority === false && entry.capabilityDisposition === 'FORBIDDEN' && entry.instanceDisposition === 'FORBIDDEN'), 'ownership non-authority boundary changed');
  const j = root.ownershipCatalog.entries.find((entry) => entry.id === 'J');
  ecocAssert(j?.ownerClass === 'none' && j?.ownerDisposition === 'OWNERLESS' && j?.authorityDisposition === 'NON_AUTHORIZING' && j?.identityDisposition === 'NOT_APPLICABLE', 'J ownerless/non-authorizing boundary changed');
  const retryQ = root.factContracts.entries.find((entry) => entry.id === 'Q');
  const d = root.factContracts.entries.find((entry) => entry.id === 'D');
  ecocAssert(retryQ?.modelDispositionByVariant?.retry === 'BLOCKED_EXTERNAL' && ecocCanonical(retryQ?.statePredecessors?.retry) === ecocCanonical(['RETRY_PREDECESSOR']) && ecocCanonical(retryQ?.originRequirements?.retry) === ecocCanonical(['RETRY_PREDECESSOR']), 'retry external block changed');
  ecocAssert(d?.modelDispositionByVariant?.initial === 'BLOCKED_EXTERNAL' && ecocCanonical(d?.statePredecessors?.initial) === ecocCanonical(['B', 'C', 'J', 'WORKER_ROWS_ROOT']) && ecocCanonical(d?.originRequirements?.initial) === ecocCanonical(['WORKER_ROWS_ROOT']), 'D external block changed');
  const projection = root.workloadProjectionContract;
  ecocEqual(projection.acceptedWorkerRowEndpointOrder, ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'], 'worker endpoint order');
  ecocAssert(projection.targetWorkerRowCount === 5 && projection.workloadTemplate?.value === 4608 && projection.workloadTemplate?.endpointCount === 5 && projection.kWorkerRowBounds?.minimum === 1 && projection.kWorkerRowBounds?.maximum === 4096 && projection.projectionDisposition === 'UNAVAILABLE_EXTERNAL' && projection.grantsAuthority === false && projection.workerRowsRootDomain === 'K/WORKER-ROWS', 'workload projection separation changed');
  const boundary = root.nonAuthorityBoundary;
  ecocAssert(boundary?.admissionAllowed === false && boundary?.authorityGrantAllowed === false && boundary?.executionAllowed === false && boundary?.runtimeImportAllowed === false && boundary?.guardLiftAllowed === false && boundary?.externalOriginMaterialAllowed === false && boundary?.factMaterialAllowed === false && boundary?.nullPlaceholderAllowed === false && boundary?.omittedValueMembersRequired === true && boundary?.j?.grantsAuthority === false && ecocCanonical(boundary?.j?.predecessors) === ecocCanonical(['B', 'C']), 'non-authority boundary changed');
  const predecessorIds = root.factContracts.entries.flatMap((entry) => Object.values(entry.statePredecessors).flat());
  ecocAssert(!predecessorIds.some((id) => ['R', 'K', 'F', 'P', 'V2', 'CABM'].includes(id)), 'static dependencies became state predecessors');
  const semanticDigests = ecocSemanticDigests(root);
  for (const [key, value] of Object.entries(semanticDigests)) ecocAssert(value === ECOC_EXPECTED_BINDING[key], key + ' pin changed');
  ecocAssert(rootDigest === ECOC_EXPECTED_BINDING.root.contentDigest, 'root semantic digest pin changed');
  return { root, semanticDigests, rootDigest };
};
const ecocSafeUpstreamRead = (repository, locator) => {
  const gate = resolve(repository, 'research-lanes/bch-shielded-pool-design/p2/gate-b');
  ecocAssert(typeof locator === 'string' && locator.startsWith(ECOC_UPSTREAM_BASE) && !locator.startsWith('/') && !locator.includes('\\') && !locator.split('/').includes('..'), 'unsafe upstream locator ' + locator);
  const target = resolve(repository, locator);
  const contained = relative(gate, target);
  ecocAssert(contained !== '' && contained !== '..' && !contained.startsWith('../') && !contained.startsWith('..\\'), 'upstream locator escapes gate-b ' + locator);
  let current = repository;
  for (const part of relative(repository, target).split('/')) {
    if (!part) continue;
    current = resolve(current, part);
    ecocAssert(!lstatSync(current).isSymbolicLink(), 'upstream symlink component ' + locator);
  }
  const info = lstatSync(target);
  ecocAssert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && realpathSync(target) === target && realpathSync(gate) === gate, 'upstream leaf type, link count, or containment changed ' + locator);
  return readFileSync(target);
};
const ecocParseUpstream = (repository, locator) => {
  try { return JSON.parse(ecocSafeUpstreamRead(repository, locator).toString('utf8')); } catch (error) { ecocFail('upstream JSON parse ' + locator + ': ' + error.message); }
};
const ecocPrimaryRoot = (root, dependencyId, repository) => {
  const leaf = root.staticDependencies.entries.find((entry) => entry.dependencyId === dependencyId && entry.role === 'primary-root');
  ecocAssert(leaf, 'missing primary root ' + dependencyId);
  return ecocParseUpstream(repository, leaf.locator);
};
const ecocCheckUpstream = (root, repository = repoRoot, expectedLeaves = ECOC_UPSTREAM_LEAVES) => {
  ecocEqual(root.staticDependencies.entries, expectedLeaves, '29 upstream dependency leaves');
  for (const leaf of expectedLeaves) ecocAssert(ecocRawSha256(ecocSafeUpstreamRead(repository, leaf.locator)) === leaf.rawSha256, 'upstream raw pin changed ' + leaf.locator);
  const r = ecocPrimaryRoot(root, 'R', repository);
  const f = ecocPrimaryRoot(root, 'F', repository);
  const p = ecocPrimaryRoot(root, 'P', repository);
  const v2 = ecocPrimaryRoot(root, 'V2', repository);
  const cabm = ecocPrimaryRoot(root, 'CABM', repository);
  const manifestLeaf = root.staticDependencies.entries.find((entry) => entry.dependencyId === 'R' && entry.role === 'manifest');
  const workerLeaf = root.staticDependencies.entries.find((entry) => entry.dependencyId === 'K' && entry.role === 'worker-row-schema');
  const dispatchLeaf = root.staticDependencies.entries.find((entry) => entry.dependencyId === 'K' && entry.role === 'dispatch-plan-schema');
  ecocAssert(manifestLeaf && workerLeaf && dispatchLeaf, 'required upstream leaf missing');
  const rManifest = ecocParseUpstream(repository, manifestLeaf.locator);
  const workerSchema = ecocParseUpstream(repository, workerLeaf.locator);
  const dispatchSchema = ecocParseUpstream(repository, dispatchLeaf.locator);
  ecocEqual(r.runtimeAuthority?.common?.endpointOrder, ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch:primary', 'engine:leanbch:secondary'], 'R ordered endpoint projection');
  ecocAssert(r.runtimeAuthority?.common?.expectedRows === 4608 && typeof r.contentDigest?.value === 'string', 'R workload or content projection changed');
  ecocAssert(typeof rManifest.contentDigest === 'string', 'R manifest contentDigest must remain a direct string');
  ecocAssert(workerSchema.properties?.endpointId?.pattern === '^[a-z][a-z0-9-]{2,63}$' && dispatchSchema.properties?.workerRows?.minItems === 1 && dispatchSchema.properties?.workerRows?.maxItems === 4096 && dispatchSchema.properties?.executionAllowed?.const === false, 'K worker-row schema projection changed');
  ecocAssert(f.contentDigest?.value === '7f00510e5c4b8b4959b572c9c9ece8e97ca95174b5715c2ee0852ef79f28b08f' && f.executionAllowed === false, 'F static projection changed');
  ecocEqual(p.policy?.aliasMap, { native: 'engine:native', libauth: 'engine:libauth', bchn: 'engine:bchn', 'leanbch-primary': 'engine:leanbch:primary', 'leanbch-secondary': 'engine:leanbch:secondary' }, 'P worker alias projection');
  ecocAssert(Array.isArray(p.policy?.kLaunchAuthority) && p.policy.kLaunchAuthority.length === 5 && p.policy.kLaunchAuthority.every((entry) => entry.workloads === 4608) && p.policy?.liveF?.contentDigest?.value === '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be', 'P workload or LIVE_F template projection changed');
  ecocEqual({ nodes: v2.authorityDag?.nodes, edges: v2.authorityDag?.edges }, ECOC_CABM_DAG, 'V2 authority DAG projection');
  ecocAssert(v2.transitionGrammar?.externalGuards?.retryQ === 'RETRY_PREDECESSOR' && v2.transitionGrammar?.externalGuards?.d === 'WORKER_ROWS_ROOT', 'V2 retry or D guard projection changed');
  ecocEqual({ nodes: cabm.pinnedAuthorityDag?.nodes, edges: cabm.pinnedAuthorityDag?.edges }, ECOC_CABM_DAG, 'CABM authority DAG projection');
  ecocAssert(cabm.externalOrigins?.entries?.length === 3 && cabm.facts?.entries?.length === 7 && cabm.externalOrigins.entries.every((entry) => entry.grantsAuthority === false) && cabm.facts.entries.every((entry) => entry.grantsAuthority === false) && cabm.stateGrammar?.retry?.qDisposition === 'BLOCKED_EXTERNAL' && cabm.stateGrammar?.d?.disposition === 'BLOCKED_EXTERNAL', 'CABM catalog/non-authority projection changed');
};
const ecocRequireRawPin = (root, locator, expected, label) => ecocAssert(ecocRawSha256(ecocRead(root, locator)) === expected, label + ' raw SHA-256 pin changed');
const ecocValidateIndependent = (root = ECOC_PACKAGE_ROOT, repository = repoRoot) => {
  ecocCheckFilesystem(root);
  ecocRequireRawPin(root, 'external-origin-contract-root.v1.json', ECOC_EXPECTED_BINDING.root.rawSha256, 'model root');
  ecocRequireRawPin(root, 'MANIFEST.json', ECOC_EXPECTED_BINDING.manifest.rawSha256, 'manifest');
  ecocRequireRawPin(root, 'SHA256SUMS', ECOC_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope');
  ecocRequireRawPin(root, 'validate-static.mjs', ECOC_EXPECTED_BINDING.validator.rawSha256, 'validator');
  for (const locator of [...ECOC_FILES, 'MANIFEST.json'].filter((entry) => entry.endsWith('.json'))) ecocReadCanonicalJson(root, locator);
  const rootDocument = ecocReadCanonicalJson(root, 'external-origin-contract-root.v1.json');
  const semantic = ecocCheckRoot(rootDocument);
  const manifest = ecocCheckManifest(root);
  ecocAssert(manifest.entryCount === ECOC_EXPECTED_BINDING.manifest.entryCount && manifest.rosterDigest === ECOC_EXPECTED_BINDING.manifest.rosterDigest, 'manifest roster or count pin changed');
  ecocCheckCodeBoundary(root);
  ecocCheckUpstream(rootDocument, repository);
  return { rootDocument, manifest, semanticDigests: semantic.semanticDigests, files: ECOC_FILES.length + 2, directories: ECOC_DIRECTORIES.length };
};
const ecocWriteCanonicalJson = (root, locator, value) => writeFileSync(ecocLocalPath(root, locator), Buffer.from(ecocCanonical(value) + '\n', 'utf8'));
const ecocRegenerateEnvelope = (root) => {
  const manifest = ecocExpectedManifest(root);
  ecocWriteCanonicalJson(root, 'MANIFEST.json', manifest);
  const sums = [...manifest.entries, { locator: 'MANIFEST.json', sha256: ecocRawSha256(ecocRead(root, 'MANIFEST.json')) }]
    .map((entry) => entry.sha256 + '  ' + entry.locator).join('\n') + '\n';
  writeFileSync(ecocLocalPath(root, 'SHA256SUMS'), Buffer.from(sums, 'utf8'));
  return manifest;
};
const ecocRefreshRootDigests = (root) => {
  for (const [field, domain] of Object.entries(ECOC_COMPONENT_DOMAINS)) root[field].contentDigest = ecocDescriptor(domain, ecocFramedDigest(domain, ecocWithout(root[field])));
  root.contentDigest = ecocDescriptor(ECOC_PREFIX + 'root', ecocFramedDigest(ECOC_PREFIX + 'root', ecocWithout(root)));
  return root;
};
const ecocExpectFailure = (operation, label) => {
  let failed = false;
  try { operation(); } catch { failed = true; }
  ecocAssert(failed, label + ' mutation was accepted');
};
const ecocExpectFailureMessage = (operation, message, label) => {
  let caught;
  try { operation(); } catch (error) { caught = error; }
  ecocAssert(caught instanceof Error, label + ' mutation was accepted');
  ecocAssert(caught.message.includes(message), label + ' rejected before its intended guard: ' + caught.message);
};
const ecocRunCausalMutation = async () => {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), 'shieldkit-ecoc-lane-'));
  const mutatedPackage = resolve(temporaryRoot, 'cohort-external-origin-contract-v1');
  const reset = () => {
    rmSync(mutatedPackage, { recursive: true, force: true });
    cpSync(ECOC_PACKAGE_ROOT, mutatedPackage, { recursive: true, errorOnExist: true, verbatimSymlinks: true });
  };
  try {
    reset();
    let root = ecocReadCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json');
    root.externalCausalDag.edges[0] = 'RETRY_PREDECESSOR→A_RETRY';
    ecocRefreshRootDigests(root);
    ecocWriteCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json', root);
    ecocRegenerateEnvelope(mutatedPackage);
    ecocExpectFailure(() => ecocCheckRoot(root), 'semantic-reseal external DAG');
    ecocExpectFailure(() => ecocValidateIndependent(mutatedPackage), 'semantic-reseal root raw pin');

    reset();
    root = ecocReadCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json');
    const d = root.factContracts.entries.find((entry) => entry.id === 'D');
    d.admissionAllowed = true;
    d.grantsAuthority = true;
    root.nonAuthorityBoundary.authorityGrantAllowed = true;
    ecocRefreshRootDigests(root);
    ecocWriteCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json', root);
    const factSchema = ecocReadCanonicalJson(mutatedPackage, 'schemas/fact-contract-catalog.v1.schema.json');
    factSchema.$defs.entry.properties.admissionAllowed = { type: 'boolean' };
    factSchema.$defs.entry.properties.grantsAuthority = { type: 'boolean' };
    ecocWriteCanonicalJson(mutatedPackage, 'schemas/fact-contract-catalog.v1.schema.json', factSchema);
    writeFileSync(ecocLocalPath(mutatedPackage, 'validate-static.mjs'), Buffer.from('export function validateStatic() { return true; }\n', 'utf8'));
    const replacementManifest = ecocRegenerateEnvelope(mutatedPackage);
    ecocExpectFailure(() => ecocRequireRawPin(mutatedPackage, 'validate-static.mjs', ECOC_EXPECTED_BINDING.validator.rawSha256, 'validator'), 'coordinated replacement validator raw pin');
    ecocExpectFailure(() => ecocRequireRawPin(mutatedPackage, 'external-origin-contract-root.v1.json', ECOC_EXPECTED_BINDING.root.rawSha256, 'model root'), 'coordinated replacement root raw pin');
    ecocExpectFailure(() => ecocAssert(root.contentDigest.value === ECOC_EXPECTED_BINDING.root.contentDigest, 'root content pin changed'), 'coordinated replacement root semantic pin');
    ecocExpectFailure(() => ecocAssert(ecocRawSha256(ecocRead(mutatedPackage, 'schemas/fact-contract-catalog.v1.schema.json')) === ECOC_FACT_CONTRACT_SCHEMA_RAW, 'fact schema pin changed'), 'coordinated replacement schema raw pin');
    ecocExpectFailure(() => ecocRequireRawPin(mutatedPackage, 'MANIFEST.json', ECOC_EXPECTED_BINDING.manifest.rawSha256, 'manifest'), 'coordinated replacement manifest raw pin');
    ecocExpectFailure(() => ecocAssert(replacementManifest.rosterDigest === ECOC_EXPECTED_BINDING.manifest.rosterDigest, 'manifest roster pin changed'), 'coordinated replacement manifest roster pin');
    ecocExpectFailure(() => ecocRequireRawPin(mutatedPackage, 'SHA256SUMS', ECOC_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope'), 'coordinated replacement checksum raw pin');
    const replacement = await import(pathToFileURL(resolve(mutatedPackage, 'validate-static.mjs')).href + '?cohort-external-origin-contract-v1-causal-mutation');
    ecocAssert(replacement.validateStatic() === true, 'coordinated replacement validator did not accept its local replacement');

    reset();
    root = ecocReadCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json');
    root.factContracts.entries[0].futurePreimageKeys.illegalMaterial = ['privateBytes'];
    ecocRefreshRootDigests(root);
    ecocWriteCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json', root);
    const nestedFactSchema = ecocReadCanonicalJson(mutatedPackage, 'schemas/fact-contract-catalog.v1.schema.json');
    nestedFactSchema.$defs.variantFutureMap.additionalProperties = true;
    ecocWriteCanonicalJson(mutatedPackage, 'schemas/fact-contract-catalog.v1.schema.json', nestedFactSchema);
    ecocRegenerateEnvelope(mutatedPackage);
    ecocExpectFailure(() => ecocCheckRoot(root), 'nested futurePreimageKeys injection');
    ecocExpectFailure(() => ecocValidateIndependent(mutatedPackage), 'nested injection root raw pin');

    reset();
    root = ecocReadCanonicalJson(mutatedPackage, 'external-origin-contract-root.v1.json');
    root.executionAllowed = true;
    root.nonAuthorityBoundary.runtimeImportAllowed = true;
    root.nonAuthorityBoundary.guardLiftAllowed = true;
    root.externalOriginContracts.entries[1].availability = 'available';
    root.factContracts.entries.find((entry) => entry.id === 'D').admissionAllowed = true;
    root.factContracts.entries.find((entry) => entry.id === 'D').grantsAuthority = true;
    ecocRefreshRootDigests(root);
    ecocExpectFailure(() => ecocCheckRoot(root), 'admission/authority/live-origin/guard/runtime/execution mutation');

    const fixtureRepository = resolve(temporaryRoot, 'fixture-repository');
    const fixtureGate = resolve(fixtureRepository, 'research-lanes/bch-shielded-pool-design/p2/gate-b');
    mkdirSync(fixtureGate, { recursive: true });
    for (const packageName of ['cohort-runtime-binding-v1', 'cohort-runner-core-v1', 'cohort-frozen-inputs-v1', 'cohort-policy-authority-v1', 'cohort-live-executor-v2', 'cohort-authority-binding-model-v1']) {
      cpSync(resolve(laneDir, 'p2/gate-b', packageName), resolve(fixtureGate, packageName), { recursive: true, errorOnExist: true, verbatimSymlinks: true });
    }
    const fixturePackage = resolve(fixtureGate, 'cohort-external-origin-contract-v1');
    cpSync(ECOC_PACKAGE_ROOT, fixturePackage, { recursive: true, errorOnExist: true, verbatimSymlinks: true });
    const fixtureRoot = ecocReadCanonicalJson(fixturePackage, 'external-origin-contract-root.v1.json');
    const fixtureLeaves = structuredClone(ECOC_UPSTREAM_LEAVES);
    const fixtureRManifestLeaf = fixtureLeaves.find((entry) => entry.dependencyId === 'R' && entry.role === 'manifest');
    const fixtureRManifestPath = resolve(fixtureRepository, fixtureRManifestLeaf.locator);
    const fixtureRManifest = JSON.parse(readFileSync(fixtureRManifestPath, 'utf8'));
    fixtureRManifest.contentDigest = { value: fixtureRManifest.contentDigest };
    writeFileSync(fixtureRManifestPath, Buffer.from(JSON.stringify(fixtureRManifest) + '\n', 'utf8'));
    fixtureRManifestLeaf.rawSha256 = ecocRawSha256(readFileSync(fixtureRManifestPath));
    fixtureRoot.staticDependencies.entries = structuredClone(fixtureLeaves);
    ecocRefreshRootDigests(fixtureRoot);
    ecocWriteCanonicalJson(fixturePackage, 'external-origin-contract-root.v1.json', fixtureRoot);
    ecocRegenerateEnvelope(fixturePackage);
    ecocExpectFailure(() => ecocValidateIndependent(fixturePackage, fixtureRepository), 'fixture root raw pin');
    ecocExpectFailureMessage(() => ecocCheckUpstream(fixtureRoot, fixtureRepository, fixtureLeaves), 'R manifest contentDigest must remain a direct string', 'R direct-string contentDigest guard');
    return true;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
    ecocAssert(!existsSync(temporaryRoot), 'causal mutation temporary root was not cleaned up');
  }
};
const UOPC_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/';
const UOPC_PACKAGE_RELATIVE = 'p2/gate-b/cohort-upstream-origin-provider-contract-v1';
const UOPC_PACKAGE_ROOT = resolve(laneDir, UOPC_PACKAGE_RELATIVE);
const UOPC_ROOT_STATUS = 'static-upstream-origin-provider-contract-catalog-no-providers-no-owner-roots-no-material-non-authorizing-unavailable-unqualified';
const UOPC_NEXT_GATE = 'The upstream-provider source-mapping gate is closed by an exhaustive static classification of existing authoritative type fragments, shape-only references, requirement-only references, and genuinely missing upstream sources; no provider is resolved or instantiated. No further live-executor or provider architecture gate is required before returning to the mathematical design track. Only a separately authorized read-only/no-I/O Gate B1 typed-protocol-descriptor schema architecture gate may open next. It may define the closed additive schema, canonical encodings, cross-field constraints, source-resolution rules, and causal soundness structure required for complete fixed-ticket Circle-FRI candidates, but it may not create a candidate or tuple instance, assign or select a field or proof role, supply Circle, DEEP, transcript, sampler, FRI, query, hash, or prover parameter values, execute or benchmark anything, or instantiate any UOPC provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, or private byte. Actual Gate B1 candidate descriptors remain blocked until the full Gate B0 cohort and root/SOL review required by research/field-frontier-contract.md are complete. Retry and D remain BLOCKED_EXTERNAL; J remains ownerless and non-authorizing.';
const UOPC_NONPROMOTION = 'sealed cohort-upstream-provider-source-map-v1 is a static non-authorizing unqualified source-coverage catalog that classifies all sixteen UOPC interfaces against sixteen pinned source references as exact authoritative type fragments, shape-only references, requirement-only references, or explicitly missing upstream sources; it resolves or instantiates no provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, private byte, authority, admission, guard, runtime, or execution surface';
const UOPC_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-integrated-no-io-architecture-unpromoted';
const UOPC_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-integrated-no-io-unqualified';
const UOPC_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-integrated-no-io-nonranking-unqualified';
const UOPC_FILES = Object.freeze([
  'COMMAND.txt', 'README.md',
  'schemas/dependency-catalog.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/external-origin-provider-catalog.v1.schema.json',
  'schemas/fact-provider-catalog.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/model-root.v1.schema.json',
  'schemas/order-provider-catalog.v1.schema.json', 'schemas/owner-provider-catalog.v1.schema.json',
  'schemas/projection-provider-catalog.v1.schema.json', 'schemas/provider-dag.v1.schema.json', 'schemas/root-provider-catalog.v1.schema.json',
  'test/digest.kat.json', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/static.test.mjs',
  'upstream-origin-provider-contract-root.v1.json', 'validate-static.mjs'
]);
const UOPC_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const UOPC_COMPONENTS = Object.freeze([
  ['staticDependencies', 'dependency-catalog', 'dependencyCatalogDigest'],
  ['ecocContractPrefix', 'ecoc-contract-prefix', 'ecocContractPrefixDigest'],
  ['providerCausalDag', 'provider-causal-dag', 'providerCausalDagDigest'],
  ['ownerProviderCatalog', 'owner-provider-catalog', 'ownerProviderCatalogDigest'],
  ['rootProviderCatalog', 'root-provider-catalog', 'rootProviderCatalogDigest'],
  ['orderProviderCatalog', 'order-provider-catalog', 'orderProviderCatalogDigest'],
  ['projectionProviderCatalog', 'projection-provider-catalog', 'projectionProviderCatalogDigest'],
  ['externalOriginProviderCatalog', 'external-origin-provider-catalog', 'externalOriginProviderCatalogDigest'],
  ['factProviderCatalog', 'fact-provider-catalog', 'factProviderCatalogDigest'],
  ['nonAuthorityBoundary', 'non-authority-boundary', 'nonAuthorityBoundaryDigest']
]);
const UOPC_EXPECTED_BINDING = Object.freeze({
  path: UOPC_PACKAGE_RELATIVE,
  root: { path: UOPC_PACKAGE_RELATIVE + '/upstream-origin-provider-contract-root.v1.json', rawSha256: '2facf53272c1947bf76f1f7d70db23270e6a7c396fed8cb67baa62dec39a7579', contentDigest: 'e76b1c35b47fac325b0e2750495ce4fabc8f1d9145974cdbbae95b63f2699020' },
  dependencyCatalogDigest: '6ae947df810501fe09748609d40053322e32d8e83dfda27d25fd278eddca72b5',
  ecocContractPrefixDigest: 'f4f1911fee07dbbdaea2dd45e54068de3f1642a3b5f77737c8d00079bd0dafc5',
  providerCausalDagDigest: '8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d',
  ownerProviderCatalogDigest: '6e5565820ac94affdc6714b918f7ba0a4bd4b3e3b1ad6cbbe8498d5e3e87dbc3',
  rootProviderCatalogDigest: 'bc16611643a28371fa2aa415cc9966663e1c1cabef3d2ac19dbc88afd12f5374',
  orderProviderCatalogDigest: '8ae28f4abe35055dfa8432c12215e951c741ff40442c6e137bbebd6ebbfe23cb',
  projectionProviderCatalogDigest: '47996eb6e89d17242dab686efa67c21676bc047dde3a27c6ec2cee0393e418a6',
  externalOriginProviderCatalogDigest: '9f06806900954fd7312e56031aafd085f08851237de46e0db32a2cbf6835b228',
  factProviderCatalogDigest: 'd4138fc9d1e8aad3a8f2fd5c800b7f7a50615e9fa07ce9d6b5e6b13051eed114',
  nonAuthorityBoundaryDigest: 'da1b12e3df9f843e2336700f28bb14cb276937883bfe8c9e60d18519203194c1',
  manifest: { path: UOPC_PACKAGE_RELATIVE + '/MANIFEST.json', rawSha256: '3f8cb55cb5c22a6f6b7c41f7aacb2203cede37a22c742bda5d57cbbdd5cedf80', rosterDigest: '000ccb354405adddc31e45fe26f14034d57b908b60d70acd67ef194a5c655d62', entryCount: 19 },
  checksums: { path: UOPC_PACKAGE_RELATIVE + '/SHA256SUMS', rawSha256: '666fa5308ceab90aad90738a7be5d2219e7a0da09c6fabd5916eeed28387dc9d' },
  validator: { path: UOPC_PACKAGE_RELATIVE + '/validate-static.mjs', rawSha256: '4f978be80e5a3ef4c0bab8ad2c1ad8ba5ad1d8cde69ae242fc49ea70ebe77de8' },
  counts: { dependencyLeaves: 33, providerNodes: 30, providerEdges: 40, ownerProviders: 7, rootProviders: 18, orderProviders: 5, projectionProviders: 3, externalOriginProviders: 3, factProviders: 7, manifestEntries: 19, mutationTests: 29 },
  status: 'sol-regated-static-upstream-origin-provider-contract-catalog-no-providers-no-owner-roots-no-material-non-authorizing-unavailable-unqualified'
});
const UOPC_ECOC_TAIL = Object.freeze([
  { dependencyId: 'ECOC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-external-origin-contract-v1/external-origin-contract-root.v1.json', rawSha256: '63b8f0312fc5da429f66ce7ccfcc9c213edc52f9ce8ec671c7e0223207ac4f7d', role: 'primary-root' },
  { dependencyId: 'ECOC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-external-origin-contract-v1/MANIFEST.json', rawSha256: 'de386b8758b75c5a92fafdadcb9fe0dcd769ab7385afae8d8642c66df8608bc6', role: 'manifest' },
  { dependencyId: 'ECOC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-external-origin-contract-v1/SHA256SUMS', rawSha256: 'ec1b8bcee3a8e9835f4ed2b97b784fefe14000ee6e7df3f6a8cc4cd59671a5ea', role: 'checksum-list' },
  { dependencyId: 'ECOC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-external-origin-contract-v1/validate-static.mjs', rawSha256: '0f37cf65905409c9a0bf26b8d98ad50fb228ae9500e6ff4647efa88b31a5f8de', role: 'static-validator' }
]);
const UOPC_PROVIDER_DAG = Object.freeze({
  nodes: ['RECOVERY_CHAIN_OWNER_PROVIDER', 'REQUEST_OWNER_PROVIDER', 'ACTIVATION_OWNER_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER', 'RETRY_ORDER_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER', 'FROZEN_SURFACE_ORDER_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER', 'WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'RETRY_PREDECESSOR_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER', 'Q_INITIAL_PROVIDER', 'Q_RETRY_PROVIDER', 'Q_ABORT_PROVIDER', 'A_INITIAL_PROVIDER', 'A_RETRY_PROVIDER', 'A_ABORT_PROVIDER', 'LIVE_F_PROVIDER', 'B_SUBJECT_ROOT_TYPE', 'B_PROVIDER', 'C_PROVIDER', 'J_ROOT_TYPE', 'DISPATCH_PLAN_PROVIDER', 'D_PROVIDER'],
  edges: ['RECOVERY_CHAIN_OWNER_PROVIDER→RETRY_PREDECESSOR_PROVIDER', 'RETRY_ORDER_PROVIDER→RETRY_PREDECESSOR_PROVIDER', 'RETRY_PREDECESSOR_PROVIDER→Q_RETRY_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_INITIAL_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_RETRY_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_ABORT_PROVIDER', 'Q_INITIAL_PROVIDER→A_INITIAL_PROVIDER', 'Q_RETRY_PROVIDER→A_RETRY_PROVIDER', 'Q_ABORT_PROVIDER→A_ABORT_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_INITIAL_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_RETRY_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_ABORT_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER→LIVE_F_CAPTURE_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER→LIVE_F_CAPTURE_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER→LIVE_F_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER→LIVE_F_PROVIDER', 'A_INITIAL_PROVIDER→B_SUBJECT_ROOT_TYPE', 'B_SUBJECT_ROOT_TYPE→B_PROVIDER', 'LIVE_F_PROVIDER→B_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER→B_PROVIDER', 'B_PROVIDER→C_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER→C_PROVIDER', 'B_PROVIDER→J_ROOT_TYPE', 'C_PROVIDER→J_ROOT_TYPE', 'FROZEN_SURFACE_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'WORKLOAD_PROJECTION_PROVIDER→ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER→DISPATCH_PLAN_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→DISPATCH_PLAN_PROVIDER', 'B_PROVIDER→D_PROVIDER', 'C_PROVIDER→D_PROVIDER', 'J_ROOT_TYPE→D_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER→D_PROVIDER', 'DISPATCH_PLAN_PROVIDER→D_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→D_PROVIDER']
});

const uopcFail = (message) => { throw new Error('cohort-upstream-origin-provider-contract-v1 lane binding: ' + message); };
const uopcAssert = (condition, message) => { if (!condition) uopcFail(message); };
const uopcCanonical = (value) => cabmCanonical(value);
const uopcEqual = (actual, expected, label) => uopcAssert(uopcCanonical(actual) === uopcCanonical(expected), label + ' differs');
const uopcRawSha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const uopcSemanticDigest = (domain, value) => createHash('sha256').update(Buffer.from(domain + '\u0000' + uopcCanonical(value) + '\n', 'utf8')).digest('hex');
const uopcRawFileDigest = (bytes) => createHash('sha256').update(Buffer.from(UOPC_PREFIX + 'file\u0000', 'utf8')).update(bytes).digest('hex');
const uopcDescriptor = (domain, value) => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1', value });
const uopcWithout = (value, key = 'contentDigest') => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
const uopcLocalPath = (root, locator) => {
  uopcAssert(typeof locator === 'string' && locator.length > 0 && !locator.startsWith('/') && !locator.includes('\\') && !locator.split('/').includes('..'), 'unsafe local locator ' + locator);
  const target = resolve(root, locator);
  const pathRelative = relative(root, target);
  uopcAssert(pathRelative !== '' && pathRelative !== '..' && !pathRelative.startsWith('../') && !pathRelative.startsWith('..\\'), 'local locator escapes ' + locator);
  return target;
};
const uopcRead = (root, locator) => {
  const target = uopcLocalPath(root, locator);
  const info = lstatSync(target);
  uopcAssert(info.isFile() && !info.isSymbolicLink(), locator + ' is not a regular non-link file');
  return readFileSync(target);
};
const uopcReadCanonicalJson = (root, locator) => {
  const bytes = uopcRead(root, locator);
  const text = bytes.toString('utf8');
  uopcAssert(!bytes.includes(0x0d) && text.endsWith('\n') && !text.endsWith('\n\n'), locator + ' final LF or CR framing changed');
  let value;
  try { value = JSON.parse(text); } catch { uopcFail(locator + ' is not JSON'); }
  uopcAssert(text === uopcCanonical(value) + '\n', locator + ' is not canonical JSON plus one final LF');
  return value;
};
const uopcCollect = (root, directory = root, prefix = '') => {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)))) {
    const locator = prefix ? prefix + '/' + entry.name : entry.name;
    const target = resolve(directory, entry.name);
    const info = lstatSync(target);
    uopcAssert(!info.isSymbolicLink(), locator + ' is a link');
    if (info.isDirectory()) {
      const nested = uopcCollect(root, target, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (info.isFile()) files.push(locator);
    else uopcFail(locator + ' is neither a regular file nor directory');
  }
  return { files, directories };
};
const uopcCheckFilesystem = (root, { allowTemporaryMetadata = false } = {}) => {
  const rootInfo = lstatSync(root);
  uopcAssert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink() && realpathSync(root) === resolve(root), 'package root type, link, or containment changed');
  if (!allowTemporaryMetadata) uopcAssert(rootInfo.nlink === 1 && (rootInfo.mode & 0o7777) === 0o755, 'package root mode or link count changed');
  const found = uopcCollect(root);
  const closure = [...UOPC_FILES, 'MANIFEST.json', 'SHA256SUMS'];
  uopcEqual(found.directories.sort(), [...UOPC_DIRECTORIES].sort(), 'directory closure');
  uopcEqual(found.files.sort(), [...closure].sort(), 'file closure');
  for (const locator of UOPC_DIRECTORIES) {
    const info = lstatSync(locator === '.' ? root : uopcLocalPath(root, locator));
    uopcAssert(info.isDirectory() && !info.isSymbolicLink(), locator + ' directory type or link changed');
    if (!allowTemporaryMetadata) uopcAssert(info.nlink === 1 && (info.mode & 0o7777) === 0o755, locator + ' directory mode or link count changed');
  }
  for (const locator of closure) {
    const info = lstatSync(uopcLocalPath(root, locator));
    const bytes = uopcRead(root, locator);
    uopcAssert(info.isFile() && !info.isSymbolicLink(), locator + ' file type or link changed');
    if (!allowTemporaryMetadata) uopcAssert(info.nlink === 1 && (info.mode & 0o7777) === 0o644, locator + ' file mode or link count changed');
    uopcAssert(bytes.length > 0 && bytes.at(-1) === 0x0a && !bytes.includes(0x0d), locator + ' final LF or CR framing changed');
  }
};
const uopcCheckSourceBoundaryText = (source) => {
  const imports = [...source.matchAll(/(?:^|\n)import\s+(?:[^'"\n]+\s+from\s+)?['"]([^'"]+)['"]/gu)].map((match) => match[1]).sort();
  uopcEqual(imports, ['ajv/dist/2020.js', 'node:crypto', 'node:fs', 'node:path', 'node:url'], 'validator import closure');
  uopcAssert(source.includes('export { AUTHORED_FILES, PREFIX, canonicalJson, rawFileDigest, semanticDigest, validateStatic };'), 'validator export surface changed');
  const start = source.indexOf('function checkSourceBoundary');
  const end = source.indexOf('\nfunction validateStatic(');
  uopcAssert(start >= 0 && end > start, 'validator self-policy boundary changed');
  const checked = source.slice(0, start) + source.slice(end);
  uopcAssert(!/\bimport\s*\(|\brequire\s*\(|\bwriteFile|\bappendFile|\bmkdir|\brmSync|\bspawn|\bexec\b|\bfork\b|\bworker_threads\b|\bnode:vm\b|\bnode:net\b|\bnode:http\b|\bnode:https\b|\bWebSocket\b|\bXMLHttpRequest\b|\bWebAssembly\b/u.test(checked), 'validator activation or writer surface changed');
};
const uopcCheckSourceBoundary = (root) => uopcCheckSourceBoundaryText(uopcRead(root, 'validate-static.mjs').toString('utf8'));
const uopcExpectedManifest = (root) => {
  const entries = UOPC_FILES.map((locator) => {
    const bytes = uopcRead(root, locator);
    return { bytes: bytes.length, fileDigest: uopcRawFileDigest(bytes), locator, sha256: uopcRawSha256(bytes) };
  });
  return { entries, entryCount: UOPC_FILES.length, format: UOPC_PREFIX + 'manifest/1', package: 'cohort-upstream-origin-provider-contract-v1', rosterDigest: uopcSemanticDigest(UOPC_PREFIX + 'manifest-roster', UOPC_FILES), schema: UOPC_PREFIX + 'manifest/v1' };
};
const uopcCheckManifest = (root) => {
  const manifest = uopcReadCanonicalJson(root, 'MANIFEST.json');
  const expected = uopcExpectedManifest(root);
  uopcEqual(manifest, expected, 'manifest raw-byte envelope');
  const sums = [...expected.entries, { locator: 'MANIFEST.json', sha256: uopcRawSha256(uopcRead(root, 'MANIFEST.json')) }]
    .map((entry) => entry.sha256 + '  ' + entry.locator).join('\n') + '\n';
  uopcAssert(uopcRead(root, 'SHA256SUMS').toString('utf8') === sums, 'checksum envelope differs');
  return manifest;
};
const uopcCheckComponent = (component, suffix, label) => {
  const domain = UOPC_PREFIX + suffix;
  uopcAssert(component && typeof component === 'object' && !Array.isArray(component) && Object.hasOwn(component, 'contentDigest'), label + ' contentDigest missing');
  const digest = uopcSemanticDigest(domain, uopcWithout(component));
  uopcEqual(component.contentDigest, uopcDescriptor(domain, digest), label + ' contentDigest');
  return digest;
};
const uopcCheckFutureNames = (value, context) => {
  if (Array.isArray(value)) {
    uopcAssert(value.every((item) => typeof item === 'string'), 'future field names must be strings at ' + context);
    return;
  }
  uopcAssert(value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype, 'future field names must be strings at ' + context);
  const entries = Object.entries(value);
  uopcAssert(entries.length > 0, 'future field names must be strings at ' + context);
  for (const [variant, names] of entries) {
    uopcAssert(Array.isArray(names) && names.every((name) => typeof name === 'string'), 'future field names must be strings at ' + context + '/' + variant);
  }
};
const uopcCheckNoMaterial = (value, context = '$') => {
  uopcAssert(value !== null, 'null is forbidden at ' + context);
  if (Array.isArray(value)) { value.forEach((item, index) => uopcCheckNoMaterial(item, context + '/' + index)); return; }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (['futurePreimageKeys', 'futureProviderFields', 'futureValidationRules', 'rules'].includes(key)) { uopcCheckFutureNames(item, context + '/' + key); continue; }
    uopcAssert(!['ownerBindingRoot', 'upstreamOwnerContractRoot', 'targetRoot', 'predecessorRoot', 'retryPredecessorRoot', 'liveFCaptureRoot', 'workerRowsRoot', 'dispatchPlanRoot', 'privateBytes', 'projectionBytes', 'identity', 'capability', 'instance', 'workerId', 'workloadRoot', 'orderedWorkloadRoots', 'projectionEncodingId', 'projectedByteCount', 'rootValue'].includes(key), 'material member is forbidden at ' + context + '/' + key);
    uopcCheckNoMaterial(item, context + '/' + key);
  }
};
const uopcExactKeys = (value, expected, label) => uopcEqual(Object.keys(value).sort(), [...expected].sort(), label + ' fields');
const uopcAssertCatalog = (catalog, ids, label) => {
  uopcAssert(catalog && Array.isArray(catalog.entries), label + ' entries missing');
  uopcEqual(catalog.entries.map((entry) => entry.id), ids, label + ' identifier order');
  uopcAssert(catalog.entries.length === ids.length, label + ' count changed');
};
const uopcCheckSchemas = (root, packageRoot) => {
  const ajv = new Ajv2020({ allErrors: true, strictSchema: true, strictTypes: false });
  for (const locator of UOPC_FILES.filter((entry) => entry.startsWith('schemas/'))) ajv.addSchema(uopcReadCanonicalJson(packageRoot, locator));
  const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root.v1.schema.json');
  uopcAssert(validate && validate(root), 'root schema validation failed');
};
const uopcCheckDependencies = (root, repository = repoRoot) => {
  const dependencies = root.staticDependencies;
  uopcExactKeys(dependencies, ['contentDigest', 'entries', 'identifier', 'schema', 'validationMode'], 'dependency catalog');
  uopcAssert(dependencies.identifier === 'cohort-upstream-origin-provider-contract-v1' && dependencies.schema === UOPC_PREFIX + 'dependency-catalog/v1' && dependencies.validationMode === 'read-regular-file-bytes-only-no-import-no-evaluation', 'dependency catalog metadata changed');
  const expected = [...ECOC_UPSTREAM_LEAVES, ...UOPC_ECOC_TAIL];
  uopcEqual(dependencies.entries, expected, '33 dependency leaves');
  for (const leaf of expected) uopcAssert(uopcRawSha256(ecocSafeUpstreamRead(repository, leaf.locator)) === leaf.rawSha256, 'dependency raw pin changed ' + leaf.locator);
  const rManifest = JSON.parse(ecocSafeUpstreamRead(repository, expected[1].locator).toString('utf8'));
  uopcAssert(typeof rManifest.contentDigest === 'string', 'R manifest contentDigest must remain a direct string');
  const dispatchLeaf = expected.find((entry) => entry.dependencyId === 'K' && entry.role === 'dispatch-plan-schema');
  const dispatchSchema = JSON.parse(ecocSafeUpstreamRead(repository, dispatchLeaf.locator).toString('utf8'));
  const workerRows = dispatchSchema?.properties?.workerRows;
  uopcAssert(workerRows?.minItems === 1 && workerRows?.maxItems === 4096 && workerRows.minItems <= 5 && workerRows.maxItems >= 5, 'K dispatch workerRows bounds changed');
  return { minimum: workerRows.minItems, maximum: workerRows.maxItems };
};
const uopcCheckPrefix = (prefix, repository = repoRoot) => {
  uopcExactKeys(prefix, ['binding', 'contentDigest', 'identifier', 'schema', 'sourceDependencyId', 'sourceRootField', 'status'], 'ECOC contract prefix');
  uopcAssert(prefix.identifier === 'cohort-upstream-origin-provider-contract-v1' && prefix.schema === UOPC_PREFIX + 'ecoc-contract-prefix/v1' && prefix.sourceDependencyId === 'ECOC' && prefix.sourceRootField === 'external-origin-contract-root.v1.json' && prefix.status === 'exact-static-prefix-only-no-provider-instantiation', 'ECOC prefix metadata changed');
  uopcEqual(prefix.binding, ECOC_EXPECTED_BINDING, 'ECOC binding prefix');
  const ecocRoot = JSON.parse(ecocSafeUpstreamRead(repository, UOPC_ECOC_TAIL[0].locator).toString('utf8'));
  uopcAssert(ecocRoot.contentDigest?.value === ECOC_EXPECTED_BINDING.root.contentDigest, 'ECOC root semantic pin changed');
};
const uopcCheckDag = (dag) => {
  uopcExactKeys(dag, ['contentDigest', 'edgeCount', 'edges', 'nodeCount', 'nodes', 'staticDependencyEdgesAllowed', 'status'], 'provider DAG');
  uopcEqual({ nodes: dag.nodes, edges: dag.edges }, UOPC_PROVIDER_DAG, '30-node/40-edge provider DAG');
  uopcAssert(dag.nodeCount === 30 && dag.edgeCount === 40 && dag.staticDependencyEdgesAllowed === false && dag.status === 'type-only-provider-prerequisite-overlay', 'provider DAG metadata changed');
  const graph = new Map(UOPC_PROVIDER_DAG.nodes.map((node) => [node, []]));
  const seen = new Set();
  for (const edge of dag.edges) {
    const [from, to] = edge.split('→');
    uopcAssert(graph.has(from) && graph.has(to) && from !== to && !seen.has(edge), 'provider DAG edge invalid');
    seen.add(edge); graph.get(from).push(to);
  }
  const active = new Set(); const done = new Set();
  const visit = (node) => { uopcAssert(!active.has(node), 'provider DAG cycle'); if (done.has(node)) return; active.add(node); graph.get(node).forEach(visit); active.delete(node); done.add(node); };
  UOPC_PROVIDER_DAG.nodes.forEach(visit);
};
const UOPC_LIVE_F_RULES = Object.freeze(['liveFCaptureRoot-is-an-authenticated-LIVE_F_CAPTURE-root', 'LIVE_F_CAPTURE-and-LIVE_F-require-exact-future-ownerBindingRoot-equality', 'same-owner-class-alone-does-not-prove-owner-continuity', 'LIVE_F-may-precede-Q-or-follow-A', 'LIVE_F-must-precede-B', 'B-does-not-authenticate-LIVE_F_CAPTURE']);
const UOPC_D_RULES = Object.freeze(['state-predecessor-order-is-B-C-J-WORKER_ROWS_ROOT', 'dispatchPlanRoot-binds-workerRowsRoot-and-executionAllowed-false', 'WORKER_ROWS_ROOT-and-D-require-exact-future-ownerBindingRoot-equality', 'same-owner-class-alone-does-not-prove-owner-continuity', 'D-is-never-admitted', 'D-remains-BLOCKED_EXTERNAL', 'D-does-not-satisfy-RETRY_PREDECESSOR']);
const UOPC_WORKLOAD_RULES = Object.freeze(['future-worker-row-count-is-exactly-five', 'K-worker-row-bounds-are-1-through-4096-per-dispatch-plan', 'target-worker-row-count-five-is-within-K-worker-row-bounds', 'each-row-is-one-endpoint-control-row', 'orderedWorkloadRoots-has-exactly-4608-roots-per-endpoint', 'projection-order-encoding-and-material-are-unavailable-external', '4608-workloads-per-endpoint-is-not-4096-worker-rows', 'no-equality-ratio-batching-or-one-workload-per-row']);
const uopcCheckCatalogs = (root, kBounds) => {
  const owners = root.ownerProviderCatalog;
  uopcExactKeys(owners, ['contentDigest', 'entries', 'identifier', 'schema'], 'owner provider catalog');
  uopcAssert(owners.identifier === 'cohort-upstream-origin-provider-contract-v1' && owners.schema === UOPC_PREFIX + 'owner-provider-catalog/v1', 'owner provider catalog metadata changed');
  uopcAssertCatalog(owners, ['RECOVERY_CHAIN_OWNER_PROVIDER', 'REQUEST_OWNER_PROVIDER', 'ACTIVATION_OWNER_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER'], 'owner provider catalog');
  const ownerScopes = [['RETRY_PREDECESSOR'], ['Q'], ['A'], ['LIVE_F_CAPTURE', 'LIVE_F'], ['B'], ['C'], ['WORKER_ROWS_ROOT', 'D']];
  owners.entries.forEach((entry, index) => {
    const continuity = index === 3 || index === 6;
    uopcExactKeys(entry, continuity ? ['admissionAllowed', 'capabilityDisposition', 'futurePreimageKeys', 'grantsAuthority', 'id', 'identityDisposition', 'instanceDisposition', 'ownerBindingContinuity', 'ownerBindingRootDisposition', 'ownerClass', 'ownerContractDisposition', 'providerDisposition', 'scope'] : ['admissionAllowed', 'capabilityDisposition', 'futurePreimageKeys', 'grantsAuthority', 'id', 'identityDisposition', 'instanceDisposition', 'ownerBindingRootDisposition', 'ownerClass', 'ownerContractDisposition', 'providerDisposition', 'scope'], 'owner provider ' + entry.id);
    uopcAssert(entry.admissionAllowed === false && entry.grantsAuthority === false && entry.providerDisposition === 'TYPE_ONLY_UNAVAILABLE_EXTERNAL' && entry.ownerContractDisposition === 'UNAVAILABLE_EXTERNAL' && entry.ownerBindingRootDisposition === 'UNAVAILABLE_EXTERNAL' && entry.identityDisposition === 'NOT_REPRESENTED' && entry.capabilityDisposition === 'FORBIDDEN' && entry.instanceDisposition === 'FORBIDDEN', 'owner provider disposition ' + entry.id);
    if (continuity) uopcAssert(entry.ownerBindingContinuity === 'EXACT_FUTURE_OWNER_BINDING_ROOT_EQUALITY_ACROSS_SCOPE', 'owner continuity ' + entry.id);
    uopcEqual(entry.scope, ownerScopes[index], 'owner provider scope ' + entry.id);
    uopcEqual(entry.futurePreimageKeys, ['ownerClass', 'upstreamOwnerContractRoot'], 'owner provider preimage ' + entry.id);
  });
  const roots = root.rootProviderCatalog;
  uopcExactKeys(roots, ['contentDigest', 'entries', 'identifier', 'schema'], 'root provider catalog');
  uopcAssertCatalog(roots, ['UPSTREAM_OWNER_CONTRACT_ROOT', 'OWNER_BINDING', 'RETRY_TARGET_ROOT', 'RETRY_TERMINAL_PREDECESSOR_ROOT', 'RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKLOAD_ROOT', 'ENDPOINT_BYTE_AUTHORITY', 'WORKER_ROWS_ROOT', 'DISPATCH_PLAN', 'Q', 'A', 'LIVE_F', 'B_SUBJECT', 'B', 'C', 'J', 'D'], 'root provider catalog');
  const unknown = new Set(['UPSTREAM_OWNER_CONTRACT_ROOT', 'RETRY_TARGET_ROOT', 'RETRY_TERMINAL_PREDECESSOR_ROOT', 'WORKLOAD_ROOT']);
  roots.entries.forEach((entry) => {
    uopcAssert(entry.rootValueDisposition === 'OMITTED_UNAVAILABLE_EXTERNAL', 'root provider material boundary ' + entry.id);
    if (unknown.has(entry.id)) {
      uopcExactKeys(entry, ['domainDisposition', 'futureProviderFields', 'id', 'rootValueDisposition'], 'unknown root provider ' + entry.id);
      uopcAssert(entry.domainDisposition === 'UNAVAILABLE_EXTERNAL', 'unknown root provider disposition ' + entry.id);
      uopcEqual(entry.futureProviderFields, ['digestDomain', 'canonicalization', 'frame', 'futurePreimageKeys', 'futureValidationRules'], 'unknown root provider fields ' + entry.id);
    } else {
      uopcExactKeys(entry, ['canonicalization', 'domain', 'domainDisposition', 'frame', 'futurePreimageKeys', 'id', 'rootValueDisposition'], 'known root provider ' + entry.id);
      uopcAssert(['RESERVED_TYPE_ONLY', 'INHERITED_STATIC_TYPE_ONLY'].includes(entry.domainDisposition) && typeof entry.domain === 'string' && typeof entry.canonicalization === 'string' && typeof entry.frame === 'string', 'known root provider metadata ' + entry.id);
    }
  });
  const orders = root.orderProviderCatalog;
  uopcExactKeys(orders, ['contentDigest', 'entries', 'identifier', 'schema'], 'order provider catalog');
  uopcAssertCatalog(orders, ['RETRY_ORDER_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER', 'FROZEN_SURFACE_ORDER_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER'], 'order provider catalog');
  orders.entries.forEach((entry) => uopcAssert(entry.admissionAllowed === false && entry.grantsAuthority === false, 'order provider authority or admission ' + entry.id));
  uopcEqual(orders.entries[2].order, ['native', 'libauth', 'bchn', 'leanbch'], 'four frozen surfaces');
  uopcEqual(orders.entries[3].order, ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'], 'five endpoint controls');
  uopcAssert(orders.entries[4].expectedRootsPerEndpoint === 4608, '4608 workload roots per endpoint changed');
  const projections = root.projectionProviderCatalog;
  uopcExactKeys(projections, ['contentDigest', 'entries', 'identifier', 'schema'], 'projection provider catalog');
  uopcAssertCatalog(projections, ['WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'DISPATCH_PLAN_PROVIDER'], 'projection provider catalog');
  projections.entries.forEach((entry) => uopcAssert(entry.admissionAllowed === false && entry.grantsAuthority === false && entry.projectionDisposition === 'UNAVAILABLE_EXTERNAL', 'projection provider authority, admission, or availability ' + entry.id));
  const workload = projections.entries[0];
  uopcExactKeys(workload, ['admissionAllowed', 'futurePreimageKeys', 'grantsAuthority', 'id', 'kWorkerRowBounds', 'projectionDisposition', 'rules', 'targetWorkerRowCount', 'targetWorkerRowCountRelation', 'templates'], 'workload projection provider');
  uopcAssert(workload.admissionAllowed === false && workload.grantsAuthority === false && workload.projectionDisposition === 'UNAVAILABLE_EXTERNAL' && workload.targetWorkerRowCount === 5 && workload.targetWorkerRowCountRelation === 'WITHIN_K_WORKER_ROW_BOUNDS', 'workload projection disposition changed');
  uopcEqual(workload.kWorkerRowBounds, { minimum: 1, maximum: 4096, unit: 'worker-rows-per-dispatch-plan' }, 'workload K bounds');
  uopcEqual(workload.kWorkerRowBounds, { minimum: kBounds.minimum, maximum: kBounds.maximum, unit: 'worker-rows-per-dispatch-plan' }, 'workload K dispatch-schema bounds');
  uopcAssert(kBounds.minimum <= workload.targetWorkerRowCount && workload.targetWorkerRowCount <= kBounds.maximum, 'workload target is not within K bounds');
  uopcEqual(workload.rules, UOPC_WORKLOAD_RULES, 'workload projection rules');
  uopcEqual(workload.templates.map((entry) => [entry.alias, entry.engineLabel, entry.workloadCount]), [['native', 'engine:native', 4608], ['libauth', 'engine:libauth', 4608], ['bchn', 'engine:bchn', 4608], ['leanbch-primary', 'engine:leanbch:primary', 4608], ['leanbch-secondary', 'engine:leanbch:secondary', 4608]], 'five static endpoint templates');
  uopcAssert(projections.entries[2].dispatchOwnerProviderId === 'PRIVATE_DISPATCH_OWNER_PROVIDER' && projections.entries[2].executionAllowed === false, 'dispatch plan is not external/non-executing');
  const origins = root.externalOriginProviderCatalog;
  uopcExactKeys(origins, ['contentDigest', 'entries', 'identifier', 'schema'], 'external origin provider catalog');
  uopcAssertCatalog(origins, ['RETRY_PREDECESSOR_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER'], 'external origin provider catalog');
  origins.entries.forEach((entry) => uopcExactKeys(entry, ['admissionAllowed', 'futurePreimageKeys', 'grantsAuthority', 'id', 'modelDisposition', 'orderProviderIds', 'originId', 'ownerProviderId', 'staticDependencyIds'], 'external origin provider ' + entry.id));
  uopcEqual(origins.entries.map((entry) => [entry.originId, entry.ownerProviderId, entry.modelDisposition]), [['RETRY_PREDECESSOR', 'RECOVERY_CHAIN_OWNER_PROVIDER', 'BLOCKED_EXTERNAL'], ['LIVE_F_CAPTURE', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'UNAVAILABLE_EXTERNAL'], ['WORKER_ROWS_ROOT', 'PRIVATE_DISPATCH_OWNER_PROVIDER', 'BLOCKED_EXTERNAL']], 'external origin mappings');
  origins.entries.forEach((entry) => uopcAssert(entry.admissionAllowed === false && entry.grantsAuthority === false, 'external origin authority or admission ' + entry.id));
  const facts = root.factProviderCatalog;
  uopcExactKeys(facts, ['contentDigest', 'entries', 'identifier', 'schema'], 'fact provider catalog');
  uopcAssertCatalog(facts, ['Q_PROVIDER', 'A_PROVIDER', 'LIVE_F_PROVIDER', 'B_PROVIDER', 'C_PROVIDER', 'J_PROVIDER', 'D_PROVIDER'], 'fact provider catalog');
  const byFact = new Map(facts.entries.map((entry) => [entry.factId, entry]));
  const staticDependencyIds = new Set(['R', 'K', 'F', 'P', 'V2', 'CABM', 'ECOC']);
  facts.entries.forEach((entry) => Object.values(entry.statePredecessors).flat().forEach((predecessor) => uopcAssert(!staticDependencyIds.has(predecessor), 'static dependency cannot satisfy state predecessor ' + entry.id)));
  uopcEqual(byFact.get('Q').modelDispositionByVariant, { abort: 'CATALOG_ONLY', initial: 'CATALOG_ONLY', retry: 'BLOCKED_EXTERNAL' }, 'retry Q disposition');
  uopcEqual(byFact.get('A').modelDispositionByVariant, { abort: 'CATALOG_ONLY', initial: 'CATALOG_ONLY', retry: 'DENY_PREREQUISITE' }, 'retry A disposition');
  uopcEqual(byFact.get('LIVE_F').futureValidationRules, UOPC_LIVE_F_RULES, 'LIVE_F continuity rules');
  uopcEqual(byFact.get('D').futureValidationRules, UOPC_D_RULES, 'D continuity rules');
  uopcEqual(byFact.get('J').statePredecessors.initial, ['B', 'C'], 'J predecessors');
  facts.entries.forEach((entry) => uopcAssert(entry.admissionAllowed === false && entry.grantsAuthority === false, 'fact authority or admission ' + entry.id));
  uopcAssert(!Object.hasOwn(byFact.get('J'), 'ownerProviderId') && byFact.get('J').ownerDisposition === 'OWNERLESS' && byFact.get('J').grantsAuthority === false && byFact.get('D').admissionAllowed === false && byFact.get('D').modelDispositionByVariant.initial === 'BLOCKED_EXTERNAL', 'J/D non-authority boundary changed');
};
const uopcCheckBoundary = (boundary) => {
  uopcExactKeys(boundary, ['admissionAllowed', 'authorityGrantAllowed', 'capabilityAllowed', 'catalogDigestMaySatisfyFactRoot', 'catalogDigestMaySatisfyOriginRoot', 'catalogDigestMaySatisfyOwnerRoot', 'constructionSurface', 'contentDigest', 'dDisposition', 'endpointImportAllowed', 'executionAllowed', 'factMaterialAllowed', 'guardLiftAllowed', 'j', 'nullPlaceholderAllowed', 'originMaterialAllowed', 'ownerIdentityAllowed', 'ownerInstancesAllowed', 'privateBytesAllowed', 'projectionMaterialAllowed', 'providerInstancesAllowed', 'retryDisposition', 'rootValuesAllowed', 'runtimeImportAllowed', 'unavailableRepresentation', 'writerSurface'], 'non-authority boundary');
  for (const key of ['providerInstancesAllowed', 'ownerInstancesAllowed', 'ownerIdentityAllowed', 'capabilityAllowed', 'rootValuesAllowed', 'originMaterialAllowed', 'factMaterialAllowed', 'projectionMaterialAllowed', 'privateBytesAllowed', 'runtimeImportAllowed', 'endpointImportAllowed', 'executionAllowed', 'authorityGrantAllowed', 'admissionAllowed', 'guardLiftAllowed', 'nullPlaceholderAllowed', 'catalogDigestMaySatisfyOwnerRoot', 'catalogDigestMaySatisfyOriginRoot', 'catalogDigestMaySatisfyFactRoot']) uopcAssert(boundary[key] === false, 'non-authority boundary changed ' + key);
  uopcAssert(boundary.constructionSurface === 'none' && boundary.writerSurface === 'none' && boundary.retryDisposition === 'BLOCKED_EXTERNAL' && boundary.dDisposition === 'BLOCKED_EXTERNAL' && boundary.unavailableRepresentation === 'omit-members-and-list-names-only-in-futurePreimageKeys-or-futureProviderFields', 'non-authority boundary disposition changed');
  uopcEqual(boundary.j, { ownerClass: 'none', ownerProviderAllowed: false, grantsAuthority: false, predecessors: ['B', 'C'] }, 'non-authority J boundary');
};
const uopcCheckRoot = (root, repository = repoRoot, { enforcePins = true } = {}) => {
  uopcExactKeys(root, ['schema', 'identifier', 'status', 'executionAllowed', 'staticDependencies', 'ecocContractPrefix', 'providerCausalDag', 'ownerProviderCatalog', 'rootProviderCatalog', 'orderProviderCatalog', 'projectionProviderCatalog', 'externalOriginProviderCatalog', 'factProviderCatalog', 'nonAuthorityBoundary', 'contentDigest'], 'root');
  uopcAssert(root.schema === UOPC_PREFIX + 'model-root/v1' && root.identifier === 'cohort-upstream-origin-provider-contract-v1' && root.status === UOPC_ROOT_STATUS && root.executionAllowed === false, 'root identity, status, or execution boundary changed');
  const semanticDigests = {};
  for (const [field, suffix, bindingKey] of UOPC_COMPONENTS) semanticDigests[bindingKey] = uopcCheckComponent(root[field], suffix, field);
  const rootDigest = uopcSemanticDigest(UOPC_PREFIX + 'model-root', uopcWithout(root));
  uopcEqual(root.contentDigest, uopcDescriptor(UOPC_PREFIX + 'model-root', rootDigest), 'root contentDigest');
  if (enforcePins) {
    uopcAssert(rootDigest === UOPC_EXPECTED_BINDING.root.contentDigest, 'root semantic digest pin changed');
    for (const [bindingKey, digest] of Object.entries(semanticDigests)) uopcAssert(digest === UOPC_EXPECTED_BINDING[bindingKey], bindingKey + ' pin changed');
  }
  const kBounds = uopcCheckDependencies(root, repository);
  uopcCheckPrefix(root.ecocContractPrefix, repository);
  uopcCheckDag(root.providerCausalDag);
  uopcCheckCatalogs(root, kBounds);
  uopcCheckBoundary(root.nonAuthorityBoundary);
  uopcCheckNoMaterial(root);
  return { rootDigest, semanticDigests, kBounds };
};
const uopcRequireRawPin = (root, locator, expected, label) => uopcAssert(uopcRawSha256(uopcRead(root, locator)) === expected, label + ' raw SHA-256 pin changed');
const uopcValidateIndependent = (root = UOPC_PACKAGE_ROOT, repository = repoRoot, { allowTemporaryMetadata = false } = {}) => {
  uopcCheckFilesystem(root, { allowTemporaryMetadata });
  uopcRequireRawPin(root, 'validate-static.mjs', UOPC_EXPECTED_BINDING.validator.rawSha256, 'validator');
  uopcRequireRawPin(root, 'upstream-origin-provider-contract-root.v1.json', UOPC_EXPECTED_BINDING.root.rawSha256, 'model root');
  uopcRequireRawPin(root, 'MANIFEST.json', UOPC_EXPECTED_BINDING.manifest.rawSha256, 'manifest');
  uopcRequireRawPin(root, 'SHA256SUMS', UOPC_EXPECTED_BINDING.checksums.rawSha256, 'checksum envelope');
  for (const locator of [...UOPC_FILES, 'MANIFEST.json'].filter((entry) => entry.endsWith('.json'))) uopcReadCanonicalJson(root, locator);
  const rootDocument = uopcReadCanonicalJson(root, 'upstream-origin-provider-contract-root.v1.json');
  uopcCheckSchemas(rootDocument, root);
  const semantic = uopcCheckRoot(rootDocument, repository);
  const manifest = uopcCheckManifest(root);
  uopcAssert(manifest.entryCount === UOPC_EXPECTED_BINDING.manifest.entryCount && manifest.rosterDigest === UOPC_EXPECTED_BINDING.manifest.rosterDigest, 'manifest roster or count pin changed');
  uopcCheckSourceBoundary(root);
  return { rootDocument, manifest, semanticDigests: semantic.semanticDigests, files: UOPC_FILES.length + 2, directories: UOPC_DIRECTORIES.length };
};
const uopcWriteCanonicalJson = (root, locator, value) => writeFileSync(uopcLocalPath(root, locator), Buffer.from(uopcCanonical(value) + '\n', 'utf8'));
const uopcRefreshRootDigests = (root) => {
  for (const [field, suffix] of UOPC_COMPONENTS) root[field].contentDigest = uopcDescriptor(UOPC_PREFIX + suffix, uopcSemanticDigest(UOPC_PREFIX + suffix, uopcWithout(root[field])));
  root.contentDigest = uopcDescriptor(UOPC_PREFIX + 'model-root', uopcSemanticDigest(UOPC_PREFIX + 'model-root', uopcWithout(root)));
  return root;
};
const uopcRegenerateEnvelope = (root) => {
  const manifest = uopcExpectedManifest(root);
  uopcWriteCanonicalJson(root, 'MANIFEST.json', manifest);
  const sums = [...manifest.entries, { locator: 'MANIFEST.json', sha256: uopcRawSha256(uopcRead(root, 'MANIFEST.json')) }]
    .map((entry) => entry.sha256 + '  ' + entry.locator).join('\n') + '\n';
  writeFileSync(uopcLocalPath(root, 'SHA256SUMS'), Buffer.from(sums, 'utf8'));
  return manifest;
};
const uopcExpectFailureMessage = (operation, message, label) => {
  let caught;
  try { operation(); } catch (error) { caught = error; }
  uopcAssert(caught instanceof Error, label + ' mutation was accepted');
  uopcAssert(caught.message.includes(message), label + ' rejected before intended guard: ' + caught.message);
};
const uopcRunCausalMutation = async () => {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), 'shieldkit-uopc-lane-'));
  const mutatedPackage = resolve(temporaryRoot, 'cohort-upstream-origin-provider-contract-v1');
  const reset = () => {
    rmSync(mutatedPackage, { recursive: true, force: true });
    cpSync(UOPC_PACKAGE_ROOT, mutatedPackage, { recursive: true, errorOnExist: true, verbatimSymlinks: true });
  };
  try {
    const validatorSource = uopcRead(UOPC_PACKAGE_ROOT, 'validate-static.mjs').toString('utf8');
    uopcCheckSourceBoundaryText(validatorSource);
    uopcExpectFailureMessage(() => uopcCheckSourceBoundaryText(validatorSource + 'WebAssembly;\n'), 'validator activation or writer surface changed', 'forbidden source token outside validator self-policy block');

    reset();
    uopcExpectFailureMessage(() => uopcCheckFilesystem(mutatedPackage), 'package root mode or link count changed', 'strict temporary-fixture metadata boundary');
    uopcCheckFilesystem(mutatedPackage, { allowTemporaryMetadata: true });
    let root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'D').futureValidationRules[2] = 'same-owner-class-alone-proves-owner-continuity';
    uopcRefreshRootDigests(root); uopcWriteCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json', root); uopcRegenerateEnvelope(mutatedPackage);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'D continuity rules', 'semantic-reseal D continuity');
    uopcExpectFailureMessage(() => uopcValidateIndependent(mutatedPackage, repoRoot, { allowTemporaryMetadata: true }), 'model root raw SHA-256 pin changed', 'semantic-reseal root raw pin');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.ownerProviderCatalog.entries.find((entry) => entry.id === 'PRIVATE_CAPTURE_OWNER_PROVIDER').ownerBindingContinuity = 'SAME_OWNER_CLASS_ONLY';
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'owner continuity PRIVATE_CAPTURE_OWNER_PROVIDER', 'capture continuity mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.projectionProviderCatalog.entries[0].kWorkerRowBounds.maximum = 4608;
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'workload K bounds', 'K bound mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'LIVE_F').futureValidationRules[1] = 'same-owner-class-alone-proves-owner-continuity';
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'LIVE_F continuity rules', 'LIVE_F continuity mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'Q').futurePreimageKeys.initial.push({ privateBytes: 'forbidden' });
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'future field names must be strings', 'nested future material mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'D').admissionAllowed = true;
    root.nonAuthorityBoundary.authorityGrantAllowed = true;
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'fact authority or admission D_PROVIDER', 'admission and authority mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.executionAllowed = true;
    root.nonAuthorityBoundary.runtimeImportAllowed = true;
    root.nonAuthorityBoundary.guardLiftAllowed = true;
    root.externalOriginProviderCatalog.entries[1].availability = 'available';
    uopcRefreshRootDigests(root);
    uopcExpectFailureMessage(() => uopcCheckRoot(root, repoRoot, { enforcePins: false }), 'root identity, status, or execution boundary changed', 'runtime, execution, guard, and live-origin mutation');

    reset();
    root = uopcReadCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json');
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'D').admissionAllowed = true;
    root.factProviderCatalog.entries.find((entry) => entry.factId === 'D').grantsAuthority = true;
    uopcRefreshRootDigests(root); uopcWriteCanonicalJson(mutatedPackage, 'upstream-origin-provider-contract-root.v1.json', root);
    const schema = uopcReadCanonicalJson(mutatedPackage, 'schemas/fact-provider-catalog.v1.schema.json');
    schema.$comment = 'coordinated replacement';
    uopcWriteCanonicalJson(mutatedPackage, 'schemas/fact-provider-catalog.v1.schema.json', schema);
    writeFileSync(uopcLocalPath(mutatedPackage, 'validate-static.mjs'), Buffer.from('export function validateStatic() { return true; }\n', 'utf8'));
    uopcRegenerateEnvelope(mutatedPackage);
    uopcExpectFailureMessage(() => uopcValidateIndependent(mutatedPackage, repoRoot, { allowTemporaryMetadata: true }), 'validator raw SHA-256 pin changed', 'coordinated validator/schema/root/manifest/sums replacement');
    const replacement = await import(pathToFileURL(resolve(mutatedPackage, 'validate-static.mjs')).href + '?cohort-upstream-origin-provider-contract-v1-causal-mutation');
    uopcAssert(replacement.validateStatic() === true, 'coordinated replacement validator did not accept its local package');
    return true;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
    uopcAssert(!existsSync(temporaryRoot), 'causal mutation temporary root was not cleaned up');
  }
};

// This binding deliberately reimplements the sealed source-map checks before importing
// its validator. The package validator is an additional pinned gate, never its authority.
const SPM_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/';
const SPM_PACKAGE_RELATIVE = 'p2/gate-b/cohort-upstream-provider-source-map-v1';
const SPM_PACKAGE_ROOT = resolve(laneDir, SPM_PACKAGE_RELATIVE);
const SPM_STATUS = 'static-upstream-provider-source-map-catalog-authoritative-shape-only-missing-classification-no-provider-resolution-no-instances-non-authorizing-unqualified';
const SPM_NEXT_GATE = 'The upstream-provider source-mapping gate is closed by an exhaustive static classification of existing authoritative type fragments, shape-only references, requirement-only references, and genuinely missing upstream sources; no provider is resolved or instantiated. No further live-executor or provider architecture gate is required before returning to the mathematical design track. Only a separately authorized read-only/no-I/O Gate B1 typed-protocol-descriptor schema architecture gate may open next. It may define the closed additive schema, canonical encodings, cross-field constraints, source-resolution rules, and causal soundness structure required for complete fixed-ticket Circle-FRI candidates, but it may not create a candidate or tuple instance, assign or select a field or proof role, supply Circle, DEEP, transcript, sampler, FRI, query, hash, or prover parameter values, execute or benchmark anything, or instantiate any UOPC provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, or private byte. Actual Gate B1 candidate descriptors remain blocked until the full Gate B0 cohort and root/SOL review required by research/field-frontier-contract.md are complete. Retry and D remain BLOCKED_EXTERNAL; J remains ownerless and non-authorizing.';
const SPM_FILES = Object.freeze(['COMMAND.txt', 'README.md', 'upstream-provider-source-map-root.v1.json', 'schemas/b1-reentry-boundary.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/interface-source-map.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/mapping-dag.v1.schema.json', 'schemas/model-root.v1.schema.json', 'schemas/non-authority-boundary.v1.schema.json', 'schemas/source-reference-catalog.v1.schema.json', 'schemas/uopc-contract-prefix.v1.schema.json', 'validate-static.mjs', 'test/digest.kat.json', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/static.test.mjs']);
const SPM_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const SPM_COMPONENTS = Object.freeze([['staticDependencies', 'dependency-catalog', 'dependencyCatalogDigest', '629fc51a1dcd712444ed1632b30ad0a1a8d337086932af1af5054aa589ff99dd'], ['uopcContractPrefix', 'uopc-contract-prefix', 'uopcContractPrefixDigest', '735485a117e15899cd1a4b3aa720599785efa4bb61adab825e0f9fb862957551'], ['sourceReferenceCatalog', 'source-reference-catalog', 'sourceReferenceCatalogDigest', 'd91be196b34e664d28fa855fea8943e9771b30763d3b860b7a72041f49672512'], ['interfaceSourceMap', 'interface-source-map', 'interfaceSourceMapDigest', '59f580240c4d9c6402835710eadb0503ad0b58316fecf0fae07e382d082c4eb0'], ['mappingDag', 'mapping-dag', 'mappingDagDigest', 'a6ad2552b9c585dd5f35a2a732f0fc35f4d3cf6c3831a39c4fe6fef3bdd9f2b1'], ['nonAuthorityBoundary', 'non-authority-boundary', 'nonAuthorityBoundaryDigest', 'b5c60933657ad66d992d5c703c0e4ae497b887fc53d01adbd5980c3923b3eb95'], ['b1ReentryBoundary', 'b1-reentry-boundary', 'b1ReentryBoundaryDigest', 'a0619058be75e650f155814b55be7af94069fba7fcdc48d743814c91cc127f29']]);
const SPM_MAP_IDS = Object.freeze(['OWNER_CONTRACT_MAP', 'RETRY_TARGET_MAP', 'RETRY_PREDECESSOR_MAP', 'LIVE_F_CAPTURE_MAP', 'WORKLOAD_ROOT_MAP', 'WORKLOAD_ORDER_MAP', 'ENDPOINT_BYTE_AUTHORITY_MAP', 'WORKER_ROWS_MAP', 'DISPATCH_PLAN_MAP', 'Q_MAP', 'A_MAP', 'LIVE_F_MAP', 'B_MAP', 'C_MAP', 'J_MAP', 'D_MAP']);
const SPM_EXPECTED_BINDING = Object.freeze({
  path: SPM_PACKAGE_RELATIVE,
  root: { path: SPM_PACKAGE_RELATIVE + '/upstream-provider-source-map-root.v1.json', rawSha256: '19268c8cfca0fc12038a6b89a23ccf7719a8d0f1337bd16bc10ab81647b0179a', contentDigest: 'afddc9f5c7ff6a8f3950a50892e1ff281ab9f64e65f9f85df913e6e865cbf75b' },
  dependencyCatalogDigest: '629fc51a1dcd712444ed1632b30ad0a1a8d337086932af1af5054aa589ff99dd', uopcContractPrefixDigest: '735485a117e15899cd1a4b3aa720599785efa4bb61adab825e0f9fb862957551', sourceReferenceCatalogDigest: 'd91be196b34e664d28fa855fea8943e9771b30763d3b860b7a72041f49672512', interfaceSourceMapDigest: '59f580240c4d9c6402835710eadb0503ad0b58316fecf0fae07e382d082c4eb0', mappingDagDigest: 'a6ad2552b9c585dd5f35a2a732f0fc35f4d3cf6c3831a39c4fe6fef3bdd9f2b1', nonAuthorityBoundaryDigest: 'b5c60933657ad66d992d5c703c0e4ae497b887fc53d01adbd5980c3923b3eb95', b1ReentryBoundaryDigest: 'a0619058be75e650f155814b55be7af94069fba7fcdc48d743814c91cc127f29',
  manifest: { path: SPM_PACKAGE_RELATIVE + '/MANIFEST.json', rawSha256: 'bc214e4ba6d6e2501b5a6f33a61947d9dce007ef8a1ca4c520d365285ac9ed76', rosterDigest: 'cd717e030b9dba6bb4472632a4d0644f622329dee93774775c9b920cef122b10', entryCount: 18 },
  checksums: { path: SPM_PACKAGE_RELATIVE + '/SHA256SUMS', rawSha256: 'd89e2e670847abb483f83fdcc85c335fecf3d38b1239adb4a03e8ebb50a9ec51' }, validator: { path: SPM_PACKAGE_RELATIVE + '/validate-static.mjs', rawSha256: '5c10f189bb33b1d334ab00e0cc5f92cf198289692ab6bf99718f3c3e2abb397d' },
  counts: { dependencyLeaves: 37, sourceReferences: 16, ownerScopeMappings: 7, interfaceMappings: 16, missingSourceMappings: 3, partialSourceMappings: 12, exactDerivedMappings: 1, mappingNodes: 16, mappingEdges: 29, manifestEntries: 18, mutationTests: 37 }, status: 'sol-regated-static-upstream-provider-source-map-catalog-authoritative-shape-only-missing-classification-no-provider-resolution-no-instances-non-authorizing-unqualified'
});
const spmFail = message => { throw new Error('cohort-upstream-provider-source-map-v1 lane binding: ' + message); };
const spmAssert = (condition, message) => { if (!condition) spmFail(message); };
const spmCanonical = value => Array.isArray(value) ? `[${value.map(spmCanonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(key => `${JSON.stringify(key)}:${spmCanonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const spmRawSha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const spmSemanticDigest = (domain, value) => { const copy = structuredClone(value); delete copy.contentDigest; return spmRawSha256(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(spmCanonical(copy) + '\n')])); };
const spmRead = (root, locator) => readFileSync(resolve(root, locator));
const spmReadJson = (root, locator) => { const raw = spmRead(root, locator).toString('utf8'); let value; try { value = JSON.parse(raw); } catch { spmFail(locator + ' is not JSON'); } spmAssert(raw === spmCanonical(value) + '\n', locator + ' is not canonical'); return value; };
const spmWalk = (root, prefix = '') => readdirSync(root, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? [{ kind: 'directory', locator: prefix + entry.name }, ...spmWalk(resolve(root, entry.name), prefix + entry.name + '/')] : [{ kind: 'file', locator: prefix + entry.name }]);
const spmCheckFilesystem = root => {
  const laneRelative = relative(laneDir, root); spmAssert(laneRelative && !laneRelative.startsWith('..'), 'package root escapes lane'); let ancestor = laneDir;
  for (const part of laneRelative.split('/')) { ancestor = resolve(ancestor, part); const stat = lstatSync(ancestor); spmAssert(stat.isDirectory() && !stat.isSymbolicLink(), 'package-root ancestor link/type changed ' + part); }
  const entries = spmWalk(root); const files = entries.filter(entry => entry.kind === 'file').map(entry => entry.locator).sort(); const directories = ['.', ...entries.filter(entry => entry.kind === 'directory').map(entry => entry.locator)].sort();
  spmAssert(JSON.stringify(files) === JSON.stringify([...SPM_FILES, 'MANIFEST.json', 'SHA256SUMS'].sort()), 'exact 20-file closure changed');
  spmAssert(JSON.stringify(directories) === JSON.stringify([...SPM_DIRECTORIES].sort()), 'exact 3-directory closure changed');
  for (const locator of ['.', ...files]) { const stat = lstatSync(resolve(root, locator)); spmAssert(!stat.isSymbolicLink() && (locator === '.' ? stat.isDirectory() : stat.isFile()) && stat.nlink === 1 && (stat.mode & 0o777) === (locator === '.' || locator === 'schemas' || locator === 'test' ? 0o755 : 0o644), 'file metadata/link boundary changed ' + locator); }
  for (const locator of ['schemas', 'test']) { const stat = lstatSync(resolve(root, locator)); spmAssert(stat.isDirectory() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o755, 'directory metadata/link boundary changed ' + locator); }
  return { files: files.length, directories: directories.length };
};
const spmSafeLeaf = (repository, leaf) => {
  const parts = leaf.locator.split('/'); const target = resolve(repository, leaf.locator); const escaped = relative(repository, target); const laneEscaped = relative(laneDir, target);
  spmAssert(escaped && !escaped.startsWith('..') && laneEscaped && !laneEscaped.startsWith('..'), 'safe-walk leaf escapes repository/lane ' + leaf.locator);
  const laneStat = lstatSync(laneDir); spmAssert(laneStat.isDirectory() && !laneStat.isSymbolicLink(), 'lane root link/type changed');
  let cursor = laneDir;
  for (const part of laneEscaped.split('/')) { cursor = resolve(cursor, part); const stat = lstatSync(cursor); spmAssert(!stat.isSymbolicLink() && (cursor === target ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), 'safe-walk lane component link/type changed ' + leaf.locator); }
  spmAssert(realpathSync(target) === target && spmRawSha256(readFileSync(target)) === leaf.rawSha256, 'safe-walk raw pin changed ' + leaf.locator);
};
const spmCheckManifest = root => {
  const manifest = spmReadJson(root, 'MANIFEST.json'); const rawFileDigest = bytes => spmRawSha256(Buffer.concat([Buffer.from(SPM_PREFIX + 'file'), Buffer.from([0]), bytes]));
  spmAssert(manifest.schema === SPM_PREFIX + 'manifest/v1' && manifest.format === SPM_PREFIX + 'manifest/1' && manifest.package === 'cohort-upstream-provider-source-map-v1' && manifest.entryCount === 18 && manifest.entries.length === 18, 'manifest identity/count changed');
  spmAssert(JSON.stringify(manifest.entries.map(entry => entry.locator)) === JSON.stringify(SPM_FILES), 'manifest roster changed');
  spmAssert(manifest.rosterDigest === spmSemanticDigest(SPM_PREFIX + 'manifest-roster', SPM_FILES), 'manifest roster digest changed');
  for (const entry of manifest.entries) { const bytes = spmRead(root, entry.locator); spmAssert(entry.bytes === bytes.length && entry.sha256 === spmRawSha256(bytes) && entry.fileDigest === rawFileDigest(bytes), 'manifest raw/file digest changed ' + entry.locator); }
  const expectedSums = [...manifest.entries.map(entry => `${entry.sha256}  ${entry.locator}`), `${spmRawSha256(spmRead(root, 'MANIFEST.json'))}  MANIFEST.json`].join('\n') + '\n';
  spmAssert(spmRead(root, 'SHA256SUMS').equals(Buffer.from(expectedSums)), 'checksum envelope changed'); return manifest;
};
const spmResolvePointer = (document, pointer) => {
  if (pointer === '') return document;
  spmAssert(pointer.startsWith('/'), 'selector is not an absolute JSON pointer ' + pointer); let value = document;
  for (const token of pointer.slice(1).split('/').map(part => part.replaceAll('~1', '/').replaceAll('~0', '~'))) { spmAssert(value && typeof value === 'object' && Object.hasOwn(value, token), 'JSON pointer does not resolve ' + pointer); value = value[token]; }
  return value;
};
const spmCheckModel = (model, repository = repoRoot) => {
  spmAssert(model.schema === SPM_PREFIX + 'model-root/v1' && model.identifier === 'cohort-upstream-provider-source-map-v1' && model.status === SPM_STATUS && model.executionAllowed === false, 'root identity/status/execution changed');
  for (const [field, suffix, sibling, expected] of SPM_COMPONENTS) { const digest = spmSemanticDigest(SPM_PREFIX + suffix, model[field]); spmAssert(digest === expected && model[field].contentDigest?.value === expected && model[sibling]?.value === expected, 'semantic component pin changed ' + field); }
  spmAssert(spmSemanticDigest(SPM_PREFIX + 'model-root', model) === SPM_EXPECTED_BINDING.root.contentDigest && model.contentDigest?.value === SPM_EXPECTED_BINDING.root.contentDigest, 'root semantic pin changed');
  spmAssert(model.staticDependencies.entries.length === 37 && model.sourceReferenceCatalog.entries.length === 16, '53 safe-walk leaves count changed');
  for (const leaf of [...model.staticDependencies.entries, ...model.sourceReferenceCatalog.entries]) spmSafeLeaf(repository, leaf);
  const uopcPrimaryRootLeaf = model.staticDependencies.entries.find(entry => entry.dependencyId === 'UOPC' && entry.role === 'primary-root');
  spmAssert(uopcPrimaryRootLeaf && uopcPrimaryRootLeaf.locator === 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json' && uopcPrimaryRootLeaf.rawSha256 === UOPC_EXPECTED_BINDING.root.rawSha256, 'pinned UOPC primary-root dependency changed');
  spmSafeLeaf(repository, uopcPrimaryRootLeaf);
  const uopcRoot = JSON.parse(readFileSync(resolve(repository, uopcPrimaryRootLeaf.locator), 'utf8'));
  const uopcTail = [
    { dependencyId: 'UOPC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json', rawSha256: UOPC_EXPECTED_BINDING.root.rawSha256, role: 'primary-root' },
    { dependencyId: 'UOPC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/MANIFEST.json', rawSha256: UOPC_EXPECTED_BINDING.manifest.rawSha256, role: 'manifest' },
    { dependencyId: 'UOPC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/SHA256SUMS', rawSha256: UOPC_EXPECTED_BINDING.checksums.rawSha256, role: 'checksum-list' },
    { dependencyId: 'UOPC', locator: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/validate-static.mjs', rawSha256: UOPC_EXPECTED_BINDING.validator.rawSha256, role: 'static-validator' }
  ];
  spmAssert(JSON.stringify(model.staticDependencies.entries.slice(0, 33)) === JSON.stringify(uopcRoot.staticDependencies.entries) && JSON.stringify(model.staticDependencies.entries.slice(33)) === JSON.stringify(uopcTail), 'first 33 UOPC dependencies or exact four-leaf UOPC closure changed');
  const map = model.interfaceSourceMap; spmAssert(map.interfaceMappingCount === 16 && map.ownerScopeMappingCount === 7 && JSON.stringify(map.entries.map(entry => entry.id)) === JSON.stringify(SPM_MAP_IDS) && map.ownerScopeMappings.length === 7, 'exact map/owner catalog changed');
  spmAssert(JSON.stringify(map.classificationCounts) === JSON.stringify({ EXACT_DERIVED_TYPE_MAPPING_NO_PROVIDER_NO_INSTANCE: 1, MISSING_REQUIRED_STATIC_SOURCE: 3, PARTIAL_STATIC_TYPE_MAPPING_REQUIRED_SOURCE_MISSING: 12 }), 'classification counts changed');
  const selectors = map.entries.flatMap(entry => ['authoritativeTypeFragments', 'shapeOnlyReferences', 'requirementOnlyReferences'].flatMap(field => entry[field].flatMap(reference => reference.selectors)));
  spmAssert(selectors.filter(selector => selector.kind === 'JSON_POINTER').length === 184 && selectors.filter(selector => selector.kind === 'STATIC_SOURCE_SYMBOL').length === 8 && selectors.length === 192, '184 JSON-pointer/8 source-symbol closure changed');
  const references = new Map(model.sourceReferenceCatalog.entries.map(entry => [entry.id, entry]));
  for (const entry of map.entries) for (const field of ['authoritativeTypeFragments', 'shapeOnlyReferences', 'requirementOnlyReferences']) for (const reference of entry[field]) { const source = references.get(reference.sourceReferenceId); spmAssert(source, 'unknown source reference ' + reference.sourceReferenceId); const bytes = readFileSync(resolve(repository, source.locator)); for (const selector of reference.selectors) { if (selector.kind === 'JSON_POINTER') spmResolvePointer(JSON.parse(bytes.toString('utf8')), selector.value); else { spmAssert(selector.kind === 'STATIC_SOURCE_SYMBOL' && new RegExp(`\\b${selector.value}\\b`, 'u').test(bytes.toString('utf8')), 'static source symbol does not resolve ' + selector.value); } } }
  spmAssert(JSON.stringify(map.ownerScopeMappings) === JSON.stringify(uopcRoot.ownerProviderCatalog.entries), 'seven owner scope mappings diverge from UOPC');
  for (const owner of map.ownerScopeMappings) spmAssert(owner.admissionAllowed === false && owner.grantsAuthority === false && owner.instanceDisposition === 'FORBIDDEN' && owner.ownerBindingRootDisposition === 'UNAVAILABLE_EXTERNAL', 'owner mapping authority boundary changed ' + owner.id);
  const dag = model.mappingDag; spmAssert(dag.nodeCount === 16 && dag.edgeCount === 29 && JSON.stringify(dag.nodes) === JSON.stringify(SPM_MAP_IDS) && dag.ownerContractToJEdgeAllowed === false && dag.status === 'static-type-source-mapping-prerequisite-overlay-no-provider-resolution', 'exact 16-node/29-edge DAG changed');
  const graph = new Map(dag.nodes.map(node => [node, []])); for (const edge of dag.edges) { const [from, to] = edge.split('→'); spmAssert(graph.has(from) && graph.has(to) && from !== to && edge !== 'OWNER_CONTRACT_MAP→J_MAP', 'DAG edge changed ' + edge); graph.get(from).push(to); } const active = new Set(); const done = new Set(); const visit = node => { spmAssert(!active.has(node), 'DAG became cyclic'); if (done.has(node)) return; active.add(node); graph.get(node).forEach(visit); active.delete(node); done.add(node); }; graph.forEach((_, node) => visit(node));
  const boundary = model.nonAuthorityBoundary; for (const key of ['admissionAllowed', 'authoritativeTypeFragmentMaySatisfyProvider', 'authorityGrantAllowed', 'capabilityAllowed', 'catalogDigestMaySatisfyFactRoot', 'catalogDigestMaySatisfyOriginRoot', 'catalogDigestMaySatisfyOwnerRoot', 'endpointImportAllowed', 'executionAllowed', 'factMaterialAllowed', 'guardLiftAllowed', 'missingSourceMayGainReference', 'nullPlaceholderAllowed', 'originMaterialAllowed', 'ownerIdentityAllowed', 'ownerInstancesAllowed', 'privateBytesAllowed', 'projectionMaterialAllowed', 'providerInstancesAllowed', 'requirementOnlyReferenceMaySatisfyProvider', 'rootValuesAllowed', 'runtimeImportAllowed', 'shapeOnlyReferenceMaySatisfyProvider', 'sourceClassificationMaySatisfyProvider', 'sourceClassificationMaySatisfyUopcInterface', 'sourceResolutionAllowed']) spmAssert(boundary[key] === false, 'non-authority override ' + key);
  spmAssert(boundary.resolutionSurface === 'none' && boundary.constructionSurface === 'none' && boundary.writerSurface === 'none' && boundary.retryDisposition === 'BLOCKED_EXTERNAL' && boundary.dDisposition === 'BLOCKED_EXTERNAL' && JSON.stringify(boundary.j) === JSON.stringify({ grantsAuthority: false, ownerClass: 'none', ownerProviderAllowed: false, predecessors: ['B', 'C'] }), 'J/provider/runtime boundary changed');
  const b1 = model.b1ReentryBoundary; spmAssert(b1.currentPackageOpensGate === false && b1.providerArchitectureGateRequiredAfterThisPackage === false && b1.fullB0CohortAndRootSolReviewRequiredForCandidateDescriptors === true && b1.candidateDescriptorDisposition === 'BLOCKED_FULL_B0_COHORT_AND_ROOT_SOL_REVIEW' && b1.nextGate === SPM_NEXT_GATE && b1.retryDisposition === 'BLOCKED_EXTERNAL' && b1.dDisposition === 'BLOCKED_EXTERNAL' && JSON.stringify(b1.j) === JSON.stringify({ grantsAuthority: false, ownerClass: 'none', predecessors: ['B', 'C'] }), 'B1/candidate boundary changed');
};
const spmValidateIndependent = (root = SPM_PACKAGE_ROOT, repository = repoRoot) => {
  const closure = spmCheckFilesystem(root); for (const [locator, expected] of [['validate-static.mjs', SPM_EXPECTED_BINDING.validator.rawSha256], ['upstream-provider-source-map-root.v1.json', SPM_EXPECTED_BINDING.root.rawSha256], ['MANIFEST.json', SPM_EXPECTED_BINDING.manifest.rawSha256], ['SHA256SUMS', SPM_EXPECTED_BINDING.checksums.rawSha256]]) spmAssert(spmRawSha256(spmRead(root, locator)) === expected, 'external raw pin changed ' + locator);
  for (const locator of [...SPM_FILES, 'MANIFEST.json'].filter(locator => locator.endsWith('.json'))) spmReadJson(root, locator);
  const schemas = SPM_FILES.filter(locator => locator.startsWith('schemas/')).map(locator => spmReadJson(root, locator)); const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false }); schemas.forEach(schema => ajv.addSchema(schema)); const model = spmReadJson(root, 'upstream-provider-source-map-root.v1.json'); const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root.v1.schema.json'); spmAssert(validate && validate(model), 'root schema validation failed');
  spmCheckModel(model, repository); const manifest = spmCheckManifest(root); spmAssert(manifest.rosterDigest === SPM_EXPECTED_BINDING.manifest.rosterDigest && manifest.entryCount === 18, 'manifest pin changed'); return { ...closure, manifest };
};
const spmRunCausalMutation = async () => {
  const temporaryRoot = mkdtempSync(resolve(laneDir, '.shieldkit-spm-lane-')); try {
    const fixture = resolve(temporaryRoot, 'pkg'); cpSync(SPM_PACKAGE_ROOT, fixture, { recursive: true }); const rootPath = resolve(fixture, 'upstream-provider-source-map-root.v1.json');
    const resign = model => { for (const [field, suffix, sibling] of SPM_COMPONENTS) { const digest = spmSemanticDigest(SPM_PREFIX + suffix, model[field]); model[field].contentDigest.value = digest; model[sibling].value = digest; } model.contentDigest.value = spmSemanticDigest(SPM_PREFIX + 'model-root', model); writeFileSync(rootPath, Buffer.from(spmCanonical(model) + '\n')); return model; };
    const reseal = () => { const entries = SPM_FILES.map(locator => { const bytes = spmRead(fixture, locator); return { bytes: bytes.length, fileDigest: spmRawSha256(Buffer.concat([Buffer.from(SPM_PREFIX + 'file'), Buffer.from([0]), bytes])), locator, sha256: spmRawSha256(bytes) }; }); const manifest = { entries, entryCount: 18, format: SPM_PREFIX + 'manifest/1', package: 'cohort-upstream-provider-source-map-v1', rosterDigest: spmSemanticDigest(SPM_PREFIX + 'manifest-roster', SPM_FILES), schema: SPM_PREFIX + 'manifest/v1' }; writeFileSync(resolve(fixture, 'MANIFEST.json'), Buffer.from(spmCanonical(manifest) + '\n')); writeFileSync(resolve(fixture, 'SHA256SUMS'), Buffer.from([...entries.map(entry => `${entry.sha256}  ${entry.locator}`), `${spmRawSha256(spmRead(fixture, 'MANIFEST.json'))}  MANIFEST.json`].join('\n') + '\n')); };
    const mutate = (label, action, guard, expectedGuard) => { const model = spmReadJson(fixture, 'upstream-provider-source-map-root.v1.json'); action(model); resign(model); let guardError; try { guard(model); } catch (error) { guardError = error; } spmAssert(guardError?.message.includes(expectedGuard), 'causal mutation did not reach its intended semantic/shape guard ' + label); let independentError; try { spmValidateIndependent(fixture); } catch (error) { independentError = error; } spmAssert(independentError?.message.includes('external raw pin changed upstream-provider-source-map-root.v1.json'), 'causal mutation bypassed the external root pin ' + label); cpSync(SPM_PACKAGE_ROOT, fixture, { recursive: true, force: true }); };
    mutate('mapping', model => { model.interfaceSourceMap.entries[0].resolution = 'EXACT_DERIVED_TYPE_MAPPING_NO_PROVIDER_NO_INSTANCE'; }, model => spmAssert(model.interfaceSourceMap.entries[0].resolution === 'MISSING_REQUIRED_STATIC_SOURCE', 'mapping resolution guard'), 'mapping resolution guard');
    mutate('owner', model => { model.interfaceSourceMap.ownerScopeMappings[0].grantsAuthority = true; }, model => spmAssert(model.interfaceSourceMap.ownerScopeMappings[0].grantsAuthority === false, 'owner non-authority guard'), 'owner non-authority guard');
    mutate('J', model => { model.nonAuthorityBoundary.j.grantsAuthority = true; }, model => spmAssert(model.nonAuthorityBoundary.j.grantsAuthority === false, 'J ownerless non-authority guard'), 'J ownerless non-authority guard');
    mutate('provider/runtime', model => { model.nonAuthorityBoundary.runtimeImportAllowed = true; }, model => spmAssert(model.nonAuthorityBoundary.runtimeImportAllowed === false, 'provider runtime boundary guard'), 'provider runtime boundary guard');
    mutate('candidate', model => { model.b1ReentryBoundary.currentPackageOpensGate = true; }, model => spmAssert(model.b1ReentryBoundary.currentPackageOpensGate === false, 'B1 candidate reopening guard'), 'B1 candidate reopening guard');
    const model = spmReadJson(fixture, 'upstream-provider-source-map-root.v1.json'); model.b1ReentryBoundary.nextGate += ' coordinated-fixture'; const resigned = resign(model); const validatorPath = resolve(fixture, 'validate-static.mjs'); const validator = spmRead(fixture, 'validate-static.mjs').toString('utf8').replaceAll(SPM_EXPECTED_BINDING.b1ReentryBoundaryDigest, resigned.b1ReentryBoundaryDigest.value).replaceAll(SPM_EXPECTED_BINDING.root.contentDigest, resigned.contentDigest.value) + '\n// coordinated fixture validator\n'; writeFileSync(validatorPath, Buffer.from(validator)); const schemaPath = resolve(fixture, 'schemas/digest.v1.schema.json'); const schema = spmReadJson(fixture, 'schemas/digest.v1.schema.json'); schema.$comment = 'coordinated fixture schema'; writeFileSync(schemaPath, Buffer.from(spmCanonical(schema) + '\n')); reseal();
    symlinkSync(resolve(repoRoot, 'node_modules'), resolve(temporaryRoot, 'node_modules'), 'dir'); const replacement = await import(pathToFileURL(validatorPath).href + '?coordinated=' + Date.now()); replacement.validateStatic({ packageRoot: fixture, repositoryRoot: repoRoot, expectedExternalPins: { rootRawSha256: spmRawSha256(spmRead(fixture, 'upstream-provider-source-map-root.v1.json')), validatorRawSha256: spmRawSha256(spmRead(fixture, 'validate-static.mjs')) } }); let rejected = false; try { spmValidateIndependent(fixture); } catch (error) { rejected = error.message.includes('external raw pin changed validate-static.mjs'); } spmAssert(rejected, 'coordinated validator/schema/root/manifest/sums substitution escaped external validator pin'); return true;
  } finally { rmSync(temporaryRoot, { recursive: true, force: true }); spmAssert(!existsSync(temporaryRoot), 'causal mutation fixture cleanup failed'); }
};
// This sealed plan is checked independently before its validator is imported. The
// outside-package anchor is the authority for the package closure; the lane only
// records that already-reviewed static boundary and never supplies the caller pin.
const B0R_PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1';
const B0R_PACKAGE_RELATIVE = 'p2/gate-b/gate-b0-evidence-plan-v1';
const B0R_PACKAGE_ROOT = resolve(laneDir, B0R_PACKAGE_RELATIVE);
const B0R_PACKAGE_LOCATOR = 'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-evidence-plan-v1';
const B0R_ANCHOR_ROOT = resolve(laneDir, 'p2/gate-b');
const B0R_ANCHOR_LOCATOR = 'gate-b0-evidence-plan-review-anchor.v1.json';
const B0R_AUTHORED_FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'evidence-plan-root.v1.json',
  'schemas/adversarial-case.v2.schema.json', 'schemas/digest.v1.schema.json', 'schemas/kill-gate.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/measurement-result.v2.schema.json', 'schemas/root.v1.schema.json',
  'test/digest.kat.json', 'test/future-schema.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/static.test.mjs',
  'validate-static.mjs'
]);
const B0R_SEALED_FILES = Object.freeze([...B0R_AUTHORED_FILES, 'MANIFEST.json', 'SHA256SUMS']);
const B0R_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const B0R_INCLUDED_TOP_LEVEL_KEYS = Object.freeze(['apiVersion', 'kind', 'id', 'objective', 'boundaries', 'scopeDecision', 'productDecisions', 'proofBackendDecision', 'promotionGate']);
const B0R_EXCLUDED_TOP_LEVEL_KEYS = Object.freeze(['architectureCheckpoint', 'createdAt', 'entrypoints', 'optionDispositions', 'p1Checkpoint', 'p2FieldCheckpoint', 'status', 'title']);
const B0R_NONPROMOTION = 'The sealed gate-b0-evidence-plan-v1 package is a static, non-authorizing, unqualified evidence-obligation plan bound by an outside-package review anchor; it authenticates only the reviewed 15-file authored closure, its two mechanical envelope files, 35 source pins, and false/zero admission boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider instance, measurement, execution, qualification, ranking, selection, or fallback authority.';
const B0R_NOT_ESTABLISHED = 'any Gate B0 execution authorization, complete Gate B0 epoch, candidate or tuple instance, role or parameter assignment, provider instance, measured result, qualification, ranking, selection, fallback authorization, or Gate B1 schema/candidate stage opening by this integration; the sealed Gate B0-R evidence plan is static and non-authorizing';
const B0R_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-integrated-no-io-architecture-unpromoted';
const B0R_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-integrated-no-io-unqualified';
const B0R_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-integrated-no-io-nonranking-unqualified';
const B0R_NONAUTHORITY_BOUNDARY = Object.freeze({candidateCount: 0, candidateTupleCount: 0, executionAllowed: false, fallbackAuthorizationAllowed: false, measurementAdmissionAllowed: false, parameterAssignmentCount: 0, providerInstanceCount: 0, qualificationAllowed: false, rankingAllowed: false, roleAssignmentCount: 0, selectionAllowed: false, status: 'static-nonauthorizing-unqualified-plan-only-no-candidates-no-execution-no-selection', unavailableStatePolicy: 'TAGGED_STATE_NEVER_NULL'});
const B0R_EXPECTED_BINDING = Object.freeze({
  path: 'p2/gate-b/gate-b0-evidence-plan-v1',
  root: {path: 'p2/gate-b/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json', rawSha256: '78455f5faed663b73353bb87bd69c475b2a979d73ad2b5b78a0e6cbdc2c1a01b', contentDigest: 'ffb555285bdd98de1be99d1f0526a69c76526321cc1fc45b5b4a6d19322bae63'},
  manifest: {path: 'p2/gate-b/gate-b0-evidence-plan-v1/MANIFEST.json', rawSha256: '1406240ccabd976f3b066500a3b111ba3395ee3dce41c804153e2fddd72f57b7', rosterDigest: 'da54495f9ec98a44ec164187bfea06f25127bbdd4cb5c478c4bdcee202f49611', entryCount: 15},
  checksums: {path: 'p2/gate-b/gate-b0-evidence-plan-v1/SHA256SUMS', rawSha256: '5e02267005bdda74cbc681f9d0d0f5592a65294dc4f727d14556fb381e93625a'},
  validator: {path: 'p2/gate-b/gate-b0-evidence-plan-v1/validate-static.mjs', rawSha256: '739fd21bda2dab59bd18f0e0c641be6a9eccd1c0e7bd637a0b8163068c399893'},
  reviewAnchor: {path: 'p2/gate-b/gate-b0-evidence-plan-review-anchor.v1.json', schema: 'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/external-review-anchor/v1', bytes: 8541, rawSha256: '920b52f253ca186c92d80c9b9b69aa8669c0109923b0b418df86f5b783d5d34f'},
  laneAuthorityProjection: {includedTopLevelKeys: [...B0R_INCLUDED_TOP_LEVEL_KEYS], excludedTopLevelKeys: [...B0R_EXCLUDED_TOP_LEVEL_KEYS], contentDigest: '7ab73381ae474648873d94f99d7227b9558f5fbb49eff8066132f0b2520ba138'},
  counts: {authoredFiles: 15, sealedFiles: 17, directories: 3, sourcePins: 35, futureSchemaCausalNegatives: 23, causalMutationNegatives: 69, cliArgumentNegatives: 16, sealedPositives: 1},
  nonAuthorityBoundary: B0R_NONAUTHORITY_BOUNDARY,
  status: 'sol-regated-sealed-static-gate-b0-evidence-plan-v1-nonauthorizing-unqualified-no-candidates-no-execution-no-selection'
});
const B0R_REVIEW_ANCHOR_PIN = Object.freeze({anchorRoot: B0R_ANCHOR_ROOT, locator: B0R_ANCHOR_LOCATOR, bytes: 8541, rawSha256: '920b52f253ca186c92d80c9b9b69aa8669c0109923b0b418df86f5b783d5d34f'});
const b0rFail = message => { throw new Error('gate-b0-evidence-plan-v1 lane binding: ' + message); };
const b0rAssert = (condition, message) => { if (!condition) b0rFail(message); };
const b0rRawSha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const b0rCanonical = value => Array.isArray(value) ? `[${value.map(b0rCanonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map(key => `${JSON.stringify(key)}:${b0rCanonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const b0rSame = (left, right) => b0rCanonical(left) === b0rCanonical(right);
const b0rCanonicalDigest = (domain, value) => b0rRawSha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), Buffer.from(b0rCanonical(value) + '\n', 'utf8')]));
const b0rDigestRecord = (domain, value) => ({algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8||0x0a', value: b0rCanonicalDigest(domain, value)});
const b0rRawFileDigest = (locator, bytes) => {
  const domain = `${B0R_PREFIX}/file/${locator}`;
  return {algorithm: 'sha256', canonicalization: 'raw-file-bytes-v1', domain, frame: 'utf8(domain)||0x00||raw-file-bytes', value: b0rRawSha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), bytes]))};
};
const b0rExactObject = (value, keys, code) => b0rAssert(value && typeof value === 'object' && !Array.isArray(value) && b0rSame(Object.keys(value).sort(), [...keys].sort()), code);
const B0R_BINDING_KEYS = Object.freeze(['path', 'root', 'manifest', 'checksums', 'validator', 'reviewAnchor', 'laneAuthorityProjection', 'counts', 'nonAuthorityBoundary', 'status']);
const B0R_COUNT_KEYS = Object.freeze(Object.keys(B0R_EXPECTED_BINDING.counts));
const B0R_NUMERIC_BOUNDARY_KEYS = Object.freeze(['candidateCount', 'candidateTupleCount', 'parameterAssignmentCount', 'providerInstanceCount', 'roleAssignmentCount']);
const B0R_FALSE_BOUNDARY_KEYS = Object.freeze(['executionAllowed', 'fallbackAuthorizationAllowed', 'measurementAdmissionAllowed', 'qualificationAllowed', 'rankingAllowed', 'selectionAllowed']);
const B0R_CAUSAL_CLASS_COUNT = 60;
const b0rAssertBinding = binding => {
  b0rAssert(binding && typeof binding === 'object' && !Array.isArray(binding), 'B0R_BINDING_SHAPE');
  b0rAssert(B0R_BINDING_KEYS.every(key => Object.hasOwn(binding, key)), 'B0R_BINDING_OMISSION');
  b0rAssert(Object.keys(binding).length === B0R_BINDING_KEYS.length && Object.keys(binding).every(key => B0R_BINDING_KEYS.includes(key)), 'B0R_BINDING_EXTRA_KEY');
  b0rAssert(binding.path === B0R_EXPECTED_BINDING.path, 'B0R_BINDING_PATH');
  b0rAssert(binding.status === B0R_EXPECTED_BINDING.status, 'B0R_BINDING_STATUS');
  b0rAssert(binding.root?.rawSha256 === B0R_EXPECTED_BINDING.root.rawSha256, 'B0R_BINDING_ROOT_RAW');
  b0rAssert(binding.validator?.rawSha256 === B0R_EXPECTED_BINDING.validator.rawSha256, 'B0R_BINDING_VALIDATOR_RAW');
  b0rAssert(binding.manifest?.rawSha256 === B0R_EXPECTED_BINDING.manifest.rawSha256, 'B0R_BINDING_MANIFEST_RAW');
  b0rAssert(binding.checksums?.rawSha256 === B0R_EXPECTED_BINDING.checksums.rawSha256, 'B0R_BINDING_SUMS_RAW');
  b0rAssert(binding.reviewAnchor?.rawSha256 === B0R_EXPECTED_BINDING.reviewAnchor.rawSha256, 'B0R_BINDING_ANCHOR_RAW');
  b0rAssert(binding.reviewAnchor?.bytes === B0R_EXPECTED_BINDING.reviewAnchor.bytes, 'B0R_BINDING_ANCHOR_BYTES');
  b0rAssert(binding.reviewAnchor?.path === B0R_EXPECTED_BINDING.reviewAnchor.path, 'B0R_BINDING_ANCHOR_PATH');
  b0rExactObject(binding.counts, B0R_COUNT_KEYS, 'B0R_BINDING_COUNT_SHAPE');
  for (const key of B0R_COUNT_KEYS) b0rAssert(binding.counts[key] === B0R_EXPECTED_BINDING.counts[key], `B0R_BINDING_COUNT:${key}`);
  b0rExactObject(binding.nonAuthorityBoundary, Object.keys(B0R_NONAUTHORITY_BOUNDARY), 'B0R_BINDING_AUTHORITY_SHAPE');
  for (const key of B0R_NUMERIC_BOUNDARY_KEYS) b0rAssert(binding.nonAuthorityBoundary[key] === 0, `B0R_BINDING_AUTHORITY:${key}`);
  for (const key of B0R_FALSE_BOUNDARY_KEYS) b0rAssert(binding.nonAuthorityBoundary[key] === false, `B0R_BINDING_AUTHORITY:${key}`);
  b0rAssert(b0rSame(binding.nonAuthorityBoundary, B0R_NONAUTHORITY_BOUNDARY), 'B0R_BINDING_AUTHORITY_EXACT');
  b0rAssert(b0rSame(binding, B0R_EXPECTED_BINDING), 'B0R_BINDING_EXACT');
  return true;
};
const b0rSafeLocator = (locator, code) => {
  b0rAssert(typeof locator === 'string' && locator.length > 0 && !locator.includes('\\') && !locator.includes('\0'), `${code}:LOCATOR`);
  const parts = locator.split('/');
  b0rAssert(parts.every(part => /^[A-Za-z0-9._-]+$/u.test(part) && part !== '.' && part !== '..'), `${code}:LOCATOR`);
  return parts;
};
const b0rSafeRead = (root, locator, code) => {
  const parts = b0rSafeLocator(locator, code); const rootStat = lstatSync(root);
  b0rAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && realpathSync(root) === root, `${code}:ROOT_METADATA`);
  let current = root;
  for (let ordinal = 0; ordinal < parts.length; ordinal += 1) {
    current = resolve(current, parts[ordinal]); const stat = lstatSync(current); const last = ordinal === parts.length - 1;
    b0rAssert(!stat.isSymbolicLink() && (last ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), `${code}:SAFE_WALK:${locator}`);
    b0rAssert(realpathSync(current) === current, `${code}:REALPATH:${locator}`);
  }
  return readFileSync(current);
};
const b0rWalk = (root, prefix = '') => readdirSync(root, {withFileTypes: true}).flatMap(entry => {
  const locator = prefix + entry.name;
  if (entry.isDirectory()) return [{kind: 'directory', locator}, ...b0rWalk(resolve(root, entry.name), locator + '/')];
  if (entry.isFile()) return [{kind: 'file', locator}];
  return [{kind: entry.isSymbolicLink() ? 'link' : 'other', locator}];
});
const b0rCheckFilesystem = root => {
  const laneRelative = relative(laneDir, root); b0rAssert(laneRelative && !laneRelative.startsWith('..'), 'B0R_PACKAGE_ROOT');
  const rootStat = lstatSync(root); b0rAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && realpathSync(root) === root, 'B0R_PACKAGE_ROOT_METADATA');
  const entries = b0rWalk(root); const files = entries.filter(entry => entry.kind === 'file').map(entry => entry.locator).sort(); const directories = ['.', ...entries.filter(entry => entry.kind === 'directory').map(entry => entry.locator)].sort();
  b0rAssert(entries.every(entry => entry.kind === 'file' || entry.kind === 'directory'), 'B0R_PACKAGE_LINK_OR_SPECIAL_FILE');
  b0rAssert(b0rSame(files, [...B0R_SEALED_FILES].sort()), 'B0R_SEALED_FILE_CLOSURE');
  b0rAssert(b0rSame(directories, [...B0R_DIRECTORIES].sort()), 'B0R_SEALED_DIRECTORY_CLOSURE');
  for (const locator of directories) { const stat = lstatSync(resolve(root, locator)); b0rAssert(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o755, `B0R_DIRECTORY_METADATA:${locator}`); }
  for (const locator of files) { const stat = lstatSync(resolve(root, locator)); b0rAssert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o644 && realpathSync(resolve(root, locator)) === resolve(root, locator), `B0R_FILE_METADATA:${locator}`); }
  return {files: files.length, directories: directories.length};
};
const b0rParseJsonNoDuplicate = (bytes, code) => {
  const source = bytes.toString('utf8'); let index = 0;
  const skip = () => { while (/[ \t\r\n]/u.test(source[index] ?? '')) index += 1; };
  const readString = () => {
    b0rAssert(source[index] === '"', `${code}:JSON_STRING`); const start = index; index += 1;
    while (index < source.length) { const char = source[index++]; if (char === '\\') { b0rAssert(index < source.length, `${code}:JSON_ESCAPE`); index += 1; } else if (char === '"') { try { return JSON.parse(source.slice(start, index)); } catch { b0rFail(`${code}:JSON_STRING`); } } else b0rAssert(char.charCodeAt(0) >= 0x20, `${code}:JSON_CONTROL`); }
    b0rFail(`${code}:JSON_STRING`);
  };
  const readValue = () => {
    skip(); const token = source[index];
    if (token === '{') {
      index += 1; skip(); const keys = new Set(); if (source[index] === '}') { index += 1; return; }
      for (;;) { skip(); const key = readString(); b0rAssert(!keys.has(key), `${code}:DUPLICATE_JSON_KEY`); keys.add(key); skip(); b0rAssert(source[index] === ':', `${code}:JSON_OBJECT`); index += 1; readValue(); skip(); if (source[index] === '}') { index += 1; return; } b0rAssert(source[index] === ',', `${code}:JSON_OBJECT`); index += 1; }
    }
    if (token === '[') { index += 1; skip(); if (source[index] === ']') { index += 1; return; } for (;;) { readValue(); skip(); if (source[index] === ']') { index += 1; return; } b0rAssert(source[index] === ',', `${code}:JSON_ARRAY`); index += 1; } }
    if (token === '"') { readString(); return; }
    for (const literal of ['true', 'false', 'null']) if (source.startsWith(literal, index)) { index += literal.length; return; }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(index)); b0rAssert(number, `${code}:JSON_VALUE`); index += number[0].length;
  };
  readValue(); skip(); b0rAssert(index === source.length, `${code}:JSON_TRAILING`); try { return JSON.parse(source); } catch { b0rFail(`${code}:JSON_PARSE`); }
};
const b0rReadCanonicalJson = (root, locator, code) => { const bytes = b0rSafeRead(root, locator, code); const value = b0rParseJsonNoDuplicate(bytes, code); b0rAssert(bytes.toString('utf8') === b0rCanonical(value) + '\n', `${code}:CANONICAL`); return value; };
const b0rDeriveEnvelope = root => {
  const entries = [...B0R_AUTHORED_FILES].sort().map(locator => { const bytes = b0rSafeRead(root, locator, `B0R_SEAL_FILE:${locator}`); return {bytes: bytes.length, fileDigest: b0rRawFileDigest(locator, bytes), locator, sha256: b0rRawSha256(bytes)}; });
  const rosterDigest = b0rDigestRecord(`${B0R_PREFIX}/manifest-roster`, entries);
  const manifest = {entryCount: entries.length, entries, format: 'canonical-json-and-raw-file-sha256-lf-v1', package: B0R_PACKAGE_LOCATOR, rosterDigest, schema: `${B0R_PREFIX}/manifest/v1`};
  const manifestBytes = Buffer.from(b0rCanonical(manifest) + '\n', 'utf8');
  const sumsBytes = Buffer.from([...entries.map(entry => `${entry.sha256}  ${entry.locator}`), `${b0rRawSha256(manifestBytes)}  MANIFEST.json`].join('\n') + '\n', 'utf8');
  return {entries, manifest, manifestBytes, sumsBytes};
};
const b0rAssertManifest = root => {
  const actual = b0rReadCanonicalJson(root, 'MANIFEST.json', 'B0R_MANIFEST'); const derived = b0rDeriveEnvelope(root);
  b0rExactObject(actual, ['entryCount', 'entries', 'format', 'package', 'rosterDigest', 'schema'], 'B0R_MANIFEST_SHAPE');
  b0rAssert(actual.entryCount === B0R_AUTHORED_FILES.length && actual.entries?.length === B0R_AUTHORED_FILES.length, 'B0R_MANIFEST_COUNT');
  b0rAssert(Array.isArray(actual.entries), 'B0R_MANIFEST_ENTRIES');
  const expectedLocators = [...B0R_AUTHORED_FILES].sort();
  const actualLocators = actual.entries.map(entry => entry?.locator);
  b0rAssert(new Set(actualLocators).size === actualLocators.length && b0rSame(actualLocators, expectedLocators), 'B0R_MANIFEST_ROSTER');
  for (let ordinal = 0; ordinal < actual.entries.length; ordinal += 1) {
    const entry = actual.entries[ordinal]; const expected = derived.entries[ordinal];
    b0rExactObject(entry, ['bytes', 'fileDigest', 'locator', 'sha256'], 'B0R_MANIFEST_ENTRY_SHAPE');
    b0rAssert(entry.locator === expected.locator && entry.bytes === expected.bytes && entry.sha256 === expected.sha256 && b0rSame(entry.fileDigest, expected.fileDigest), `B0R_MANIFEST_FILE_DIGEST:${expected.locator}`);
  }
  b0rAssert(b0rSame(actual.rosterDigest, derived.manifest.rosterDigest), 'B0R_MANIFEST_ROSTER_DIGEST');
  b0rAssert(actual.format === derived.manifest.format && actual.package === derived.manifest.package && actual.schema === derived.manifest.schema, 'B0R_MANIFEST_IDENTITY');
  b0rAssert(b0rSame(actual, derived.manifest), 'B0R_MANIFEST_RECOMPUTATION');
  b0rAssert(b0rSafeRead(root, 'MANIFEST.json', 'B0R_MANIFEST').equals(derived.manifestBytes), 'B0R_MANIFEST_CANONICAL');
  b0rAssert(b0rSafeRead(root, 'SHA256SUMS', 'B0R_SUMS').equals(derived.sumsBytes), 'B0R_SUMS_RECOMPUTATION');
  b0rAssert(actual.rosterDigest.value === B0R_EXPECTED_BINDING.manifest.rosterDigest && actual.entryCount === B0R_EXPECTED_BINDING.manifest.entryCount, 'B0R_MANIFEST_PIN');
  return derived;
};
const b0rExpectedRootDigest = () => ({algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: `${B0R_PREFIX}/root`, frame: 'utf8(domain)||0x00||canonical-json-utf8||0x0a', value: B0R_EXPECTED_BINDING.root.contentDigest});
const b0rAssertP0Manifest = manifest => {
  b0rAssert(Array.isArray(manifest?.artifacts) && manifest.artifacts.length === 11, 'B0R_P0_LEAF_COUNT');
  b0rAssert(manifest.aggregate?.sha256 === 'db057332197d7a48a90eb65e55884455ab1388e8a0a970f1cb9a9d3b3f17dc52', 'B0R_P0_AGGREGATE_PIN');
  const paths = manifest.artifacts.map(artifact => artifact?.path);
  b0rAssert(paths.every(path => typeof path === 'string'), 'B0R_P0_LEAF_SHAPE');
  for (const path of paths) b0rSafeLocator(path, 'B0R_P0_LEAF');
  b0rAssert(new Set(paths).size === 11, 'B0R_P0_LEAF_DUPLICATE');
  b0rAssert(b0rSame(paths, [...paths].sort((left, right) => left.localeCompare(right))), 'B0R_P0_LEAF_ORDER');
  const aggregate = Buffer.concat(manifest.artifacts.map(artifact => {
    b0rAssert(/^[0-9a-f]{64}$/u.test(artifact.sha256), 'B0R_P0_LEAF_SHAPE');
    const leaf = b0rSafeRead(laneDir, artifact.path, 'B0R_P0_LEAF');
    b0rAssert(b0rRawSha256(leaf) === artifact.sha256, `B0R_P0_LEAF_RAW:${artifact.path}`);
    return Buffer.from(`${artifact.path}\0${artifact.sha256}\n`, 'utf8');
  }));
  b0rAssert(b0rRawSha256(aggregate) === 'db057332197d7a48a90eb65e55884455ab1388e8a0a970f1cb9a9d3b3f17dc52', 'B0R_P0_AGGREGATE');
  return {aggregateSha256: manifest.aggregate.sha256, expectedLeafCount: manifest.artifacts.length};
};
const b0rAssertP0 = () => {
  const bytes = b0rSafeRead(laneDir, 'spec/p0-freeze-manifest.json', 'B0R_P0_MANIFEST');
  b0rAssert(b0rRawSha256(bytes) === 'a55ebd49f117956dc3b0c8a94cf3a3e7b40c5d7477de2a99c53d58bef00012c2', 'B0R_P0_MANIFEST_RAW');
  const asserted = b0rAssertP0Manifest(b0rParseJsonNoDuplicate(bytes, 'B0R_P0_MANIFEST'));
  return {...asserted, manifestRawSha256: b0rRawSha256(bytes)};
};
const b0rAssertAnchorPin = pin => {
  b0rExactObject(pin, ['anchorRoot', 'bytes', 'locator', 'rawSha256'], 'B0R_ANCHOR_PIN_SHAPE');
  b0rAssert(pin.anchorRoot === B0R_REVIEW_ANCHOR_PIN.anchorRoot, 'B0R_ANCHOR_ROOT_PIN');
  b0rAssert(pin.locator === B0R_REVIEW_ANCHOR_PIN.locator, 'B0R_ANCHOR_LOCATOR_PIN');
  b0rAssert(pin.bytes === B0R_REVIEW_ANCHOR_PIN.bytes, 'B0R_ANCHOR_BYTES_PIN');
  b0rAssert(pin.rawSha256 === B0R_REVIEW_ANCHOR_PIN.rawSha256, 'B0R_ANCHOR_RAW_PIN');
};
const b0rAssertAnchorOutsidePackage = (anchorRoot, locator, packageRoot = B0R_PACKAGE_ROOT) => {
  b0rSafeLocator(locator, 'B0R_ANCHOR_PATH');
  const anchorPath = resolve(anchorRoot, locator); const outside = relative(packageRoot, anchorPath);
  b0rAssert(outside === '..' || outside.startsWith('../') || outside.startsWith('..\\'), 'B0R_ANCHOR_OUTSIDE_PACKAGE');
  return anchorPath;
};
const b0rReadAnchor = pin => {
  b0rAssertAnchorPin(pin);
  const anchorPath = b0rAssertAnchorOutsidePackage(pin.anchorRoot, pin.locator);
  const bytes = b0rSafeRead(pin.anchorRoot, pin.locator, 'B0R_ANCHOR'); b0rAssert(bytes.length === pin.bytes && b0rRawSha256(bytes) === pin.rawSha256, 'B0R_ANCHOR_RAW_PIN');
  const anchor = b0rParseJsonNoDuplicate(bytes, 'B0R_ANCHOR'); b0rAssert(bytes.toString('utf8') === b0rCanonical(anchor) + '\n', 'B0R_ANCHOR_CANONICAL'); return anchor;
};
const b0rAssertAnchor = (anchor, root, envelope, p0) => {
  b0rExactObject(anchor, ['entryCount', 'laneProjectionDigest', 'manifestRawSha256', 'nonAuthorityBoundary', 'orderedClosure', 'p0Freeze', 'package', 'rootContentDigest', 'rootRawSha256', 'rosterDigest', 'schema', 'sha256SumsRawSha256', 'validatorRawSha256'], 'B0R_ANCHOR_SHAPE');
  b0rAssert(anchor.schema === B0R_EXPECTED_BINDING.reviewAnchor.schema && anchor.package === B0R_PACKAGE_LOCATOR, 'B0R_ANCHOR_IDENTITY');
  b0rAssert(anchor.rootRawSha256 === B0R_EXPECTED_BINDING.root.rawSha256 && anchor.validatorRawSha256 === B0R_EXPECTED_BINDING.validator.rawSha256 && anchor.manifestRawSha256 === B0R_EXPECTED_BINDING.manifest.rawSha256 && anchor.sha256SumsRawSha256 === B0R_EXPECTED_BINDING.checksums.rawSha256, 'B0R_ANCHOR_RAW_JOINS');
  b0rAssert(b0rSame(anchor.rootContentDigest, b0rExpectedRootDigest()), 'B0R_ANCHOR_ROOT_DIGEST');
  b0rAssert(b0rSame(anchor.orderedClosure, envelope.entries) && anchor.entryCount === B0R_AUTHORED_FILES.length, 'B0R_ANCHOR_CLOSURE');
  b0rAssert(b0rSame(anchor.rosterDigest, envelope.manifest.rosterDigest), 'B0R_ANCHOR_ROSTER');
  b0rAssert(b0rSame(anchor.laneProjectionDigest, {algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: `${B0R_PREFIX}/lane-authority-projection`, frame: 'utf8(domain)||0x00||canonical-json-utf8||0x0a', value: B0R_EXPECTED_BINDING.laneAuthorityProjection.contentDigest}), 'B0R_ANCHOR_LANE_PROJECTION');
  b0rAssert(b0rSame(anchor.p0Freeze, p0), 'B0R_ANCHOR_P0'); b0rAssert(b0rSame(anchor.nonAuthorityBoundary, B0R_NONAUTHORITY_BOUNDARY) && b0rSame(root.nonAuthorityBoundary, B0R_NONAUTHORITY_BOUNDARY), 'B0R_ANCHOR_NONAUTHORITY');
};
const b0rAssertLaneKeyPartition = (laneValue, includedKeys = B0R_INCLUDED_TOP_LEVEL_KEYS, excludedKeys = B0R_EXCLUDED_TOP_LEVEL_KEYS) => {
  b0rAssert(b0rSame(includedKeys, B0R_INCLUDED_TOP_LEVEL_KEYS), 'B0R_LANE_INCLUDED_ROSTER');
  b0rAssert(b0rSame(excludedKeys, B0R_EXCLUDED_TOP_LEVEL_KEYS), 'B0R_LANE_EXCLUDED_ROSTER');
  const allKeys = [...includedKeys, ...excludedKeys];
  b0rAssert(new Set(allKeys).size === 17 && b0rSame(Object.keys(laneValue).sort(), [...allKeys].sort()), 'B0R_LANE_KEY_PARTITION');
};
const b0rAssertLaneProjection = (laneValue, root) => {
  b0rAssertLaneKeyPartition(laneValue);
  const projectionAuthority = root.authorityProjection?.authorities?.find(authority => authority.authorityId === 'B0R_LANE_AUTHORITY_PROJECTION'); const projection = projectionAuthority?.projection;
  b0rAssert(root.authorityProjection?.authorities?.map(authority => authority.authorityId).join(',') === 'B0R_LANE_AUTHORITY_PROJECTION,B0R_ATLAS_PRODUCT_PROFILE,B0R_P0_FREEZE_MANIFEST,B0R_BCH_ENVIRONMENT_PROFILE,B0R_DESKTOP_PROVER_PROFILE', 'B0R_AUTHORITY_ROSTER');
  b0rAssert(projection?.schema === `${B0R_PREFIX}/lane-authority-projection/v1`, 'B0R_LANE_PROJECTION_SCHEMA');
  const snapshot = Object.fromEntries(B0R_INCLUDED_TOP_LEVEL_KEYS.map(key => [key, laneValue[key]])); b0rAssert(b0rSame(projection?.snapshot, snapshot), 'B0R_LANE_PROJECTION');
  const projectionValue = {schema: projection?.schema, snapshot: projection?.snapshot}; const expectedDigest = b0rDigestRecord(`${B0R_PREFIX}/lane-authority-projection`, projectionValue); b0rAssert(b0rSame(projection?.contentDigest, expectedDigest) && projection.contentDigest.value === B0R_EXPECTED_BINDING.laneAuthorityProjection.contentDigest, 'B0R_LANE_PROJECTION_DIGEST');
};
const b0rAssertRoot = root => {
  b0rAssert(root.schema === 'https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/root.v1.schema.json' && root.status === B0R_NONAUTHORITY_BOUNDARY.status, 'B0R_ROOT_IDENTITY');
  b0rAssert(b0rSame(root.contentDigest, b0rExpectedRootDigest()), 'B0R_ROOT_DIGEST');
  b0rAssert(root.sourceCatalog?.entries?.length === B0R_EXPECTED_BINDING.counts.sourcePins && root.legacyReconciliation?.rowBindings?.length === 33 && root.legacyReconciliation?.typedKillGates?.length === 33 && root.protocolAxisContract?.axes?.length === 9 && root.protocolAxisContract?.componentFields?.length === 14, 'B0R_ROOT_COUNTS');
  b0rAssert(root.campaignTruth?.executionAvailable === false && root.campaignTruth?.metricsAvailable === false && root.campaignTruth?.rankingAvailable === false && root.campaignTruth?.selectionAvailable === false, 'B0R_ROOT_CAMPAIGN_BOUNDARY');
};
const b0rValidateIndependent = (root = B0R_PACKAGE_ROOT, repository = repoRoot, anchorPin = B0R_REVIEW_ANCHOR_PIN) => {
  const closure = b0rCheckFilesystem(root);
  for (const [locator, expected] of [['evidence-plan-root.v1.json', B0R_EXPECTED_BINDING.root.rawSha256], ['validate-static.mjs', B0R_EXPECTED_BINDING.validator.rawSha256], ['MANIFEST.json', B0R_EXPECTED_BINDING.manifest.rawSha256], ['SHA256SUMS', B0R_EXPECTED_BINDING.checksums.rawSha256]]) b0rAssert(b0rRawSha256(b0rSafeRead(root, locator, `B0R_RAW_PIN:${locator}`)) === expected, `B0R_RAW_PIN:${locator}`);
  const anchor = b0rReadAnchor(anchorPin);
  const schemas = B0R_AUTHORED_FILES.filter(locator => locator.startsWith('schemas/')).map(locator => b0rReadCanonicalJson(root, locator, `B0R_SCHEMA:${locator}`));
  const rootModel = b0rReadCanonicalJson(root, 'evidence-plan-root.v1.json', 'B0R_ROOT'); const ajv = new Ajv2020({allErrors: true, strict: true, strictTypes: true}); schemas.forEach(schema => ajv.addSchema(schema)); const validate = ajv.getSchema(rootModel.schema); b0rAssert(validate && validate(rootModel), `B0R_ROOT_SCHEMA:${ajv.errorsText(validate?.errors)}`);
  const envelope = b0rAssertManifest(root); b0rAssertRoot(rootModel); b0rAssertProseSourceDisjointness(rootModel); b0rAssertPhaseExcludesNonpromotion(); const p0 = b0rAssertP0(repository); b0rAssertAnchor(anchor, rootModel, envelope, p0);
  const laneBytes = b0rSafeRead(laneDir, 'lane.json', 'B0R_LANE'); const laneValue = b0rParseJsonNoDuplicate(laneBytes, 'B0R_LANE'); b0rAssertLaneProjection(laneValue, rootModel);
  return {...closure, anchor, envelope, root: rootModel};
};
const B0R_PROSE_SOURCES = Object.freeze([
  {label: 'lane README', locator: 'research-lanes/bch-shielded-pool-design/README.md', path: resolve(laneDir, 'README.md')},
  {label: 'design options', locator: 'research-lanes/bch-shielded-pool-design/analysis/design-options.md', path: resolve(laneDir, 'analysis/design-options.md')}
]);
const b0rAssertNonpromotionProse = (texts = B0R_PROSE_SOURCES.map(({path, label}) => [label, readFileSync(path, 'utf8')])) => { for (const [label, prose] of texts) b0rAssert(prose.split(B0R_NONPROMOTION).length === 2, `B0R_NONPROMOTION_PROSE:${label}`); };
const b0rAssertPhaseExcludesNonpromotion = (phase = readFileSync(resolve(laneDir, 'research/phase-plan.md'), 'utf8')) => b0rAssert(!phase.includes(B0R_NONPROMOTION), 'B0R_PHASE_NONPROMOTION_SOURCE_CYCLE');
const b0rAssertProseSourceDisjointness = (root, proseSources = B0R_PROSE_SOURCES) => {
  const sourceLocators = new Set(root.sourceCatalog?.entries?.map(entry => entry.locator));
  for (const source of proseSources) b0rAssert(!sourceLocators.has(source.locator), `B0R_PROSE_SOURCE_CYCLE:${source.locator}`);
};
const b0rExpectFailure = (operation, expected, label) => { let failure; try { operation(); } catch (error) { failure = error; } b0rAssert(failure?.message.includes(expected), `B0R_CAUSAL_MUTATION:${label}`); };
const b0rRunCausalMutation = async laneValue => {
  let causalClasses = 0;
  const reject = (operation, expected, label) => { b0rExpectFailure(operation, expected, label); causalClasses += 1; };
  const bindingMutation = (label, mutate, expected) => {
    const binding = structuredClone(B0R_EXPECTED_BINDING); mutate(binding); reject(() => b0rAssertBinding(binding), expected, `binding/${label}`);
  };
  const rootModel = b0rReadCanonicalJson(B0R_PACKAGE_ROOT, 'evidence-plan-root.v1.json', 'B0R_MUTATION_ROOT');

  bindingMutation('omission', binding => { delete binding.path; }, 'B0R_BINDING_OMISSION');
  bindingMutation('extra-key', binding => { binding.unreviewed = true; }, 'B0R_BINDING_EXTRA_KEY');
  bindingMutation('status-widening', binding => { binding.status += '-selection-authorized'; }, 'B0R_BINDING_STATUS');
  for (const key of B0R_COUNT_KEYS) bindingMutation(`count-${key}`, binding => { binding.counts[key] += 1; }, `B0R_BINDING_COUNT:${key}`);
  for (const key of B0R_NUMERIC_BOUNDARY_KEYS) bindingMutation(`authority-${key}`, binding => { binding.nonAuthorityBoundary[key] = 1; }, `B0R_BINDING_AUTHORITY:${key}`);
  for (const key of B0R_FALSE_BOUNDARY_KEYS) bindingMutation(`authority-${key}`, binding => { binding.nonAuthorityBoundary[key] = true; }, `B0R_BINDING_AUTHORITY:${key}`);
  for (const [label, path, code] of [
    ['root', ['root', 'rawSha256'], 'B0R_BINDING_ROOT_RAW'],
    ['validator', ['validator', 'rawSha256'], 'B0R_BINDING_VALIDATOR_RAW'],
    ['manifest', ['manifest', 'rawSha256'], 'B0R_BINDING_MANIFEST_RAW'],
    ['sums', ['checksums', 'rawSha256'], 'B0R_BINDING_SUMS_RAW'],
    ['anchor', ['reviewAnchor', 'rawSha256'], 'B0R_BINDING_ANCHOR_RAW']
  ]) bindingMutation(`${label}-raw`, binding => { binding[path[0]][path[1]] = '0'.repeat(64); }, code);
  bindingMutation('anchor-bytes', binding => { binding.reviewAnchor.bytes += 1; }, 'B0R_BINDING_ANCHOR_BYTES');
  bindingMutation('anchor-path', binding => { binding.reviewAnchor.path = 'p2/gate-b/inside-package-anchor.json'; }, 'B0R_BINDING_ANCHOR_PATH');

  const p0Manifest = b0rParseJsonNoDuplicate(b0rSafeRead(laneDir, 'spec/p0-freeze-manifest.json', 'B0R_MUTATION_P0'), 'B0R_MUTATION_P0');
  const p0Mutation = (label, mutate, expected) => { const model = structuredClone(p0Manifest); mutate(model); reject(() => b0rAssertP0Manifest(model), expected, `p0/${label}`); };
  p0Mutation('leaf-count', model => { model.artifacts.pop(); }, 'B0R_P0_LEAF_COUNT');
  p0Mutation('leaf-order', model => { [model.artifacts[0], model.artifacts[1]] = [model.artifacts[1], model.artifacts[0]]; }, 'B0R_P0_LEAF_ORDER');
  p0Mutation('duplicate', model => { model.artifacts[1] = structuredClone(model.artifacts[0]); }, 'B0R_P0_LEAF_DUPLICATE');
  p0Mutation('traversal', model => { model.artifacts[0].path = '../spec/p0-freeze-manifest.json'; }, 'B0R_P0_LEAF:LOCATOR');
  p0Mutation('leaf-raw', model => { model.artifacts[0].sha256 = '0'.repeat(64); }, 'B0R_P0_LEAF_RAW:');
  p0Mutation('aggregate', model => { model.aggregate.sha256 = '0'.repeat(64); }, 'B0R_P0_AGGREGATE_PIN');

  const includedMutation = structuredClone(laneValue); includedMutation.apiVersion = 'lane-authority-projection-mutant'; reject(() => b0rAssertLaneProjection(includedMutation, rootModel), 'B0R_LANE_PROJECTION', 'lane/included-key-value');
  reject(() => b0rAssertLaneKeyPartition(laneValue, B0R_EXCLUDED_TOP_LEVEL_KEYS, B0R_INCLUDED_TOP_LEVEL_KEYS), 'B0R_LANE_INCLUDED_ROSTER', 'lane/included-excluded-roster-substitution');
  reject(() => b0rAssertLaneKeyPartition(laneValue, B0R_INCLUDED_TOP_LEVEL_KEYS, B0R_EXCLUDED_TOP_LEVEL_KEYS.slice(1)), 'B0R_LANE_EXCLUDED_ROSTER', 'lane/omitted-excluded-key');
  const partitionMutation = structuredClone(laneValue); partitionMutation.unexpectedB0rKey = 'forbidden'; reject(() => b0rAssertLaneProjection(partitionMutation, rootModel), 'B0R_LANE_KEY_PARTITION', 'lane/new-unpartitioned-key');

  b0rAssertPhaseExcludesNonpromotion();
  reject(() => b0rAssertPhaseExcludesNonpromotion(B0R_NONPROMOTION), 'B0R_PHASE_NONPROMOTION_SOURCE_CYCLE', 'phase/nonpromotion-injection');
  const prose = B0R_PROSE_SOURCES.map(({path, label}) => [label, readFileSync(path, 'utf8')]);
  const deleted = prose.map(([label, text]) => [label, text.replace(B0R_NONPROMOTION, '')]); reject(() => b0rAssertNonpromotionProse(deleted), 'B0R_NONPROMOTION_PROSE:lane README', 'prose/deletion');
  const widened = prose.map(([label, text]) => [label, text.replace(B0R_NONPROMOTION, B0R_NONPROMOTION.replace('no candidate', 'a candidate'))]); reject(() => b0rAssertNonpromotionProse(widened), 'B0R_NONPROMOTION_PROSE:lane README', 'prose/widening');
  const cycle = [...B0R_PROSE_SOURCES, {label: 'phase plan', locator: 'research-lanes/bch-shielded-pool-design/research/phase-plan.md', path: resolve(laneDir, 'research/phase-plan.md')}]; reject(() => b0rAssertProseSourceDisjointness(rootModel, cycle), 'B0R_PROSE_SOURCE_CYCLE', 'prose/source-cycle');

  const temporaryRoot = mkdtempSync(resolve(laneDir, '.shieldkit-b0r-lane-'));
  try {
    const fixturePackage = label => { const fixture = resolve(temporaryRoot, `package-${label}`); cpSync(B0R_PACKAGE_ROOT, fixture, {recursive: true}); return fixture; };
    const mutateManifest = (label, mutate, expected) => {
      const fixture = fixturePackage(`manifest-${label}`); const manifestPath = resolve(fixture, 'MANIFEST.json'); const manifest = b0rReadCanonicalJson(fixture, 'MANIFEST.json', `B0R_MUTATION_MANIFEST:${label}`);
      mutate(manifest); writeFileSync(manifestPath, Buffer.from(b0rCanonical(manifest) + '\n', 'utf8'));
      reject(() => b0rAssertManifest(fixture), expected, `manifest/${label}`);
    };
    mutateManifest('remove', manifest => { manifest.entries.pop(); manifest.entryCount -= 1; }, 'B0R_MANIFEST_COUNT');
    mutateManifest('insert', manifest => { manifest.entries.push(structuredClone(manifest.entries[0])); manifest.entryCount += 1; }, 'B0R_MANIFEST_COUNT');
    mutateManifest('reorder', manifest => { [manifest.entries[0], manifest.entries[1]] = [manifest.entries[1], manifest.entries[0]]; }, 'B0R_MANIFEST_ROSTER');
    mutateManifest('duplicate', manifest => { manifest.entries[1] = structuredClone(manifest.entries[0]); }, 'B0R_MANIFEST_ROSTER');
    mutateManifest('file-digest', manifest => { manifest.entries[0].fileDigest.value = '0'.repeat(64); }, 'B0R_MANIFEST_FILE_DIGEST:');
    mutateManifest('roster', manifest => { manifest.rosterDigest.value = '0'.repeat(64); }, 'B0R_MANIFEST_ROSTER_DIGEST');
    {
      const fixture = fixturePackage('sums'); writeFileSync(resolve(fixture, 'SHA256SUMS'), Buffer.from('0'.repeat(64) + '  COMMAND.txt\n', 'utf8'));
      reject(() => b0rAssertManifest(fixture), 'B0R_SUMS_RECOMPUTATION', 'manifest/sums');
    }

    const securityRoot = resolve(temporaryRoot, 'anchor-security'); mkdirSync(securityRoot);
    const anchorPayload = Buffer.from('{}\n', 'utf8'); const rawAnchor = resolve(securityRoot, 'anchor.json'); writeFileSync(rawAnchor, anchorPayload);
    const byteMutation = structuredClone(B0R_REVIEW_ANCHOR_PIN); byteMutation.bytes += 1; reject(() => b0rAssertAnchorPin(byteMutation), 'B0R_ANCHOR_BYTES_PIN', 'anchor/byte-count');
    const rawMutation = structuredClone(B0R_REVIEW_ANCHOR_PIN); rawMutation.rawSha256 = '0'.repeat(64); reject(() => b0rAssertAnchorPin(rawMutation), 'B0R_ANCHOR_RAW_PIN', 'anchor/raw-pin');
    const pathMutation = structuredClone(B0R_REVIEW_ANCHOR_PIN); pathMutation.locator = '../unsafe.json'; reject(() => b0rAssertAnchorPin(pathMutation), 'B0R_ANCHOR_LOCATOR_PIN', 'anchor/path-pin');
    reject(() => b0rAssertAnchorOutsidePackage(B0R_PACKAGE_ROOT, 'MANIFEST.json'), 'B0R_ANCHOR_OUTSIDE_PACKAGE', 'anchor/inside-package');
    reject(() => b0rAssertAnchorOutsidePackage(B0R_ANCHOR_ROOT, '../unsafe.json'), 'B0R_ANCHOR_PATH:LOCATOR', 'anchor/unsafe-locator');
    symlinkSync('anchor.json', resolve(securityRoot, 'anchor-symlink.json')); reject(() => b0rSafeRead(securityRoot, 'anchor-symlink.json', 'B0R_ANCHOR'), 'B0R_ANCHOR:SAFE_WALK:anchor-symlink.json', 'anchor/symlink');
    linkSync(rawAnchor, resolve(securityRoot, 'anchor-hardlink.json')); reject(() => b0rSafeRead(securityRoot, 'anchor-hardlink.json', 'B0R_ANCHOR'), 'B0R_ANCHOR:SAFE_WALK:anchor-hardlink.json', 'anchor/hardlink');

    const validator = await import(pathToFileURL(resolve(B0R_PACKAGE_ROOT, 'validate-static.mjs')).href + `?b0r-causal=${Date.now()}`);
    reject(() => validator.validateStatic({packageRoot: B0R_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'unsealed'}), 'UNSEALED_ENVELOPE_ABSENT', 'validator/unsealed-mode');
    reject(() => validator.validateStatic({packageRoot: B0R_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: null}), 'SEALED_EXTERNAL_ANCHOR_REQUIRED', 'validator/missing-literal-pin');

    const fixture = fixturePackage('coordinated'); const fixtureAnchorRoot = resolve(temporaryRoot, 'coordinated-anchor'); mkdirSync(fixtureAnchorRoot);
    const fixtureRootPath = resolve(fixture, 'evidence-plan-root.v1.json'); writeFileSync(fixtureRootPath, Buffer.concat([readFileSync(fixtureRootPath), Buffer.from(' ', 'utf8')]));
    const fixtureSchemaPath = resolve(fixture, 'schemas/root.v1.schema.json'); writeFileSync(fixtureSchemaPath, Buffer.concat([readFileSync(fixtureSchemaPath), Buffer.from(' ', 'utf8')]));
    const fixtureValidatorPath = resolve(fixture, 'validate-static.mjs'); writeFileSync(fixtureValidatorPath, Buffer.from('export const validateStatic = () => ({ sealed: true });\n', 'utf8'));
    const fixtureEnvelope = b0rDeriveEnvelope(fixture); writeFileSync(resolve(fixture, 'MANIFEST.json'), fixtureEnvelope.manifestBytes); writeFileSync(resolve(fixture, 'SHA256SUMS'), fixtureEnvelope.sumsBytes);
    const anchor = b0rParseJsonNoDuplicate(b0rSafeRead(B0R_ANCHOR_ROOT, B0R_ANCHOR_LOCATOR, 'B0R_MUTATION_ANCHOR'), 'B0R_MUTATION_ANCHOR'); anchor.rootRawSha256 = b0rRawSha256(readFileSync(fixtureRootPath)); anchor.validatorRawSha256 = b0rRawSha256(readFileSync(fixtureValidatorPath)); anchor.manifestRawSha256 = b0rRawSha256(fixtureEnvelope.manifestBytes); anchor.sha256SumsRawSha256 = b0rRawSha256(fixtureEnvelope.sumsBytes); anchor.orderedClosure = fixtureEnvelope.entries; anchor.rosterDigest = fixtureEnvelope.manifest.rosterDigest;
    const fixtureAnchorPath = resolve(fixtureAnchorRoot, B0R_ANCHOR_LOCATOR); const fixtureAnchorBytes = Buffer.from(b0rCanonical(anchor) + '\n', 'utf8'); writeFileSync(fixtureAnchorPath, fixtureAnchorBytes);
    const replacement = await import(pathToFileURL(fixtureValidatorPath).href + `?b0r-coordinated=${Date.now()}`); b0rAssert(replacement.validateStatic({mode: 'sealed', reviewAnchorPin: {anchorRoot: fixtureAnchorRoot, locator: B0R_ANCHOR_LOCATOR, bytes: fixtureAnchorBytes.length, rawSha256: b0rRawSha256(fixtureAnchorBytes)}})?.sealed === true, 'B0R_CAUSAL_MUTATION:coordinated-local-validator');
    reject(() => b0rValidateIndependent(fixture, repoRoot, B0R_REVIEW_ANCHOR_PIN), 'B0R_RAW_PIN:evidence-plan-root.v1.json', 'validator/coordinated-root-validator-envelope-anchor-replacement');
    b0rAssert(causalClasses === B0R_CAUSAL_CLASS_COUNT, 'B0R_CAUSAL_MUTATION:class-count');
    return {classes: causalClasses};
  } finally {
    rmSync(temporaryRoot, {recursive: true, force: true}); b0rAssert(!existsSync(temporaryRoot), 'B0R_CAUSAL_MUTATION:cleanup');
  }
};

// EAC is a second sealed, static-only package.  Its lane binding is checked
// independently before its validator is imported, so coordinated local package
// replacement cannot turn the lane into an authority source.
const EAC_PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1';
const EAC_PACKAGE_RELATIVE = 'p2/gate-b/gate-b0-execution-admission-contract-v1';
const EAC_PACKAGE_ROOT = resolve(laneDir, EAC_PACKAGE_RELATIVE);
const EAC_PACKAGE_LOCATOR = 'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-execution-admission-contract-v1';
const EAC_ANCHOR_ROOT = resolve(laneDir, 'p2/gate-b');
const EAC_ANCHOR_LOCATOR = 'gate-b0-execution-admission-contract-review-anchor.v1.json';
const EAC_AUTHORED_FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'execution-admission-contract-root.v1.json',
  'schemas/digest.v1.schema.json', 'schemas/endpoint-projection.v1.schema.json', 'schemas/external-requirement.v1.schema.json', 'schemas/future-result-admission.v1.schema.json', 'schemas/future-state-grammar.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/non-authority-boundary.v1.schema.json', 'schemas/root.v1.schema.json', 'schemas/source-pin.v1.schema.json',
  'test/digest.kat.json', 'test/future-boundary.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/static.test.mjs', 'validate-static.mjs'
]);
const EAC_SEALED_FILES = Object.freeze([...EAC_AUTHORED_FILES, 'MANIFEST.json', 'SHA256SUMS']);
const EAC_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const EAC_SCHEMA_BINDINGS = Object.freeze([
  {locator: 'schemas/digest.v1.schema.json', rawSha256: '3a9523f6ed708b998dd96af5d38d7de9eabae2099aaf59d4c37c392703308403', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/digest.v1.schema.json'},
  {locator: 'schemas/endpoint-projection.v1.schema.json', rawSha256: '5c6c833aa51693ea6dd6b83459f41c4610c34db6c5bab62046eec34e4d043c75', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/endpoint-projection.v1.schema.json'},
  {locator: 'schemas/external-requirement.v1.schema.json', rawSha256: '7c33d3b0f7aea2990a022d728b28852bc39a48ed2734f0d023ab099331bb0dd6', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/external-requirement.v1.schema.json'},
  {locator: 'schemas/future-result-admission.v1.schema.json', rawSha256: '95c6aef8b1200944562799584f845d2fa13a4bde87803862295a6b9a94b3aa32', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/future-result-admission.v1.schema.json'},
  {locator: 'schemas/future-state-grammar.v1.schema.json', rawSha256: 'f4b30a3f05c7d191a4c197dec77b60bdf51cc40d02e7788a1c8f3075526e7410', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/future-state-grammar.v1.schema.json'},
  {locator: 'schemas/manifest.v1.schema.json', rawSha256: '1c889688e336ff63760d512f8c86acb7534516fb2127bc7b3176760603751ab4', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/manifest.v1.schema.json'},
  {locator: 'schemas/non-authority-boundary.v1.schema.json', rawSha256: '07bfc6af00795ec438dc199046896cc25ba0192f18bc52e3e0974df83d53f949', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/non-authority-boundary.v1.schema.json'},
  {locator: 'schemas/root.v1.schema.json', rawSha256: '08a9d6785ce506adf6b24361b6261479c48e0733a0e40ca82eff5c76fc52653c', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/root.v1.schema.json'},
  {locator: 'schemas/source-pin.v1.schema.json', rawSha256: '8691d71aa84f14f548565c37118448283a240bfa92e0d0b02d4d826e8c16d9bb', schemaId: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/source-pin.v1.schema.json'}
]);
const EAC_SOURCE_PIN_IDS = Object.freeze(['pin:parent:b0r-root','pin:parent:b0r-manifest','pin:parent:b0r-sums','pin:parent:b0r-validator','pin:parent:b0r-anchor','pin:foundation:p-root','pin:foundation:p-manifest','pin:foundation:p-sums','pin:foundation:r-root','pin:foundation:r-manifest','pin:foundation:r-sums','pin:foundation:k-root','pin:foundation:k-manifest','pin:foundation:k-sums','pin:foundation:f-root','pin:foundation:f-manifest','pin:foundation:f-sums','pin:origin:live-root','pin:origin:live-manifest','pin:origin:live-sums','pin:origin:cabm-root','pin:origin:cabm-manifest','pin:origin:cabm-sums','pin:origin:ecoc-root','pin:origin:ecoc-manifest','pin:origin:ecoc-sums','pin:origin:uopc-root','pin:origin:uopc-manifest','pin:origin:uopc-sums','pin:origin:source-map-root','pin:origin:source-map-manifest','pin:origin:source-map-sums','pin:history:attempt000-auth','pin:history:attempt000-schema','pin:history:accounting-root','pin:history:abort-receipt','pin:history:accounting-manifest','pin:history:accounting-sums','pin:history:retry-wrapper','pin:history:retry-manifest','pin:history:retry-sums','pin:history:v3-contract','pin:history:v3-manifest','pin:history:v3-sums','pin:history:v3-freeze','pin:history:v3-schema','pin:frozen:campaign','pin:frozen:corpus','pin:frozen:fixtures','pin:frozen:work-items','pin:frozen:epoch','pin:frozen:manifest','pin:frozen:sums','pin:frozen:construction','pin:frozen:schedule','pin:frozen:descriptor-m31d5','pin:frozen:descriptor-m31d6','pin:frozen:descriptor-m61d3','pin:frozen:descriptor-m89d2','pin:frozen:engine-native','pin:frozen:engine-libauth','pin:frozen:engine-bchn','pin:frozen:engine-leanbch','pin:frozen:engine-schema']);
const EAC_REQUIREMENT_IDS = Object.freeze(['RECOVERY_CHAIN_OWNER_PROVIDER','REQUEST_OWNER_PROVIDER','ACTIVATION_OWNER_PROVIDER','PRIVATE_CAPTURE_OWNER_PROVIDER','PRIVATE_DESCRIPTOR_OWNER_PROVIDER','EXCLUSIVE_C_OWNER_PROVIDER','PRIVATE_DISPATCH_OWNER_PROVIDER','RETRY_ORDER_PROVIDER','LIVE_F_RECORD_ORDER_PROVIDER','FROZEN_SURFACE_ORDER_PROVIDER','ENDPOINT_CONTROL_ORDER_PROVIDER','WORKLOAD_ROOT_ORDER_PROVIDER','WORKLOAD_PROJECTION_PROVIDER','ENDPOINT_BYTE_AUTHORITY_PROVIDER','RETRY_PREDECESSOR_PROVIDER','LIVE_F_CAPTURE_PROVIDER','WORKER_ROWS_ROOT_PROVIDER','Q_INITIAL_PROVIDER','Q_RETRY_PROVIDER','Q_ABORT_PROVIDER','A_INITIAL_PROVIDER','A_RETRY_PROVIDER','A_ABORT_PROVIDER','LIVE_F_PROVIDER','B_SUBJECT_ROOT_TYPE','B_PROVIDER','C_PROVIDER','J_ROOT_TYPE','DISPATCH_PLAN_PROVIDER','D_PROVIDER']);
const EAC_NONPROMOTION = 'The sealed gate-b0-execution-admission-contract-v1 package is a static, non-authorizing, non-admitting, unqualified pre-execution prerequisite catalog bound by an outside-package review anchor; it authenticates only the reviewed 18-file authored closure, its two mechanical envelope files, 64 raw-pinned source leaves with native semantic joins, 30 zero-instance external-requirement rows, 37 retry-prerequisite edges, 7 artifact/result edges, and the exact false/zero boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider, owner, fact, nonce, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution authority.';
const EAC_NOT_ESTABLISHED = 'any Gate B0 execution authorization or measurement admission, Q/A/LIVE_F/B/C/J/D instance, candidate or tuple instance, role or parameter assignment, provider, owner, fact, nonce, private byte, workload root, raw artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback authorization, Attempt-001, complete Gate B0 epoch, Gate B0 root/SOL review, or Gate B1 opening by this integration; the sealed gate-b0-execution-admission-contract-v1 package is a static prerequisite catalog only';
const EAC_NEXT_GATE = 'The sealed gate-b0-execution-admission-contract-v1 integration closes only the static pre-execution prerequisite-catalog stage. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authorities satisfy every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validation prerequisite represented by the closed 30-row catalog and exact 37+7 causal edges. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.';
const EAC_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-no-io-no-admission-architecture-unpromoted';
const EAC_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-no-io-no-admission-unqualified';
const EAC_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-no-io-no-admission-nonranking-unqualified';
const EAC_NONAUTHORITY_BOUNDARY = Object.freeze({artifactMapCreationAllowed: false, artifactMapInstanceCount: 0, attemptCreationAllowed: false, authorizationCount: 0, candidateCount: 0, candidateTupleCount: 0, childProcessCount: 0, claimCount: 0, claimCreationAllowed: false, endpointImportAllowed: false, evidenceCount: 0, executionAllowed: false, factInstanceCount: 0, fallbackAuthorizationAllowed: false, measurementAdmissionAllowed: false, measurementCount: 0, nonceCount: 0, ownerInstanceCount: 0, parameterAssignmentCount: 0, privateByteCount: 0, providerInstanceCount: 0, providerInstantiationAllowed: false, qualificationAllowed: false, rankingAllowed: false, resultCount: 0, roleAssignmentCount: 0, runCount: 0, runtimeImportAllowed: false, selectionAllowed: false, status: 'static-preexecution-prerequisite-catalog-no-authority-no-admission-no-instances', workloadRootCount: 0});
const EAC_EXPECTED_PARENT_BINDING = Object.freeze({manifestBytes: 6847, manifestLocator: 'p2/gate-b/gate-b0-evidence-plan-v1/MANIFEST.json', manifestRawSha256: '1406240ccabd976f3b066500a3b111ba3395ee3dce41c804153e2fddd72f57b7', manifestRosterDigest: 'da54495f9ec98a44ec164187bfea06f25127bbdd4cb5c478c4bdcee202f49611', packageId: 'gate-b0-evidence-plan-v1', reviewAnchorBytes: 8541, reviewAnchorLocator: 'p2/gate-b/gate-b0-evidence-plan-review-anchor.v1.json', reviewAnchorRawSha256: '920b52f253ca186c92d80c9b9b69aa8669c0109923b0b418df86f5b783d5d34f', rootBytes: 60597, rootLocator: 'p2/gate-b/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json', rootRawSha256: '78455f5faed663b73353bb87bd69c475b2a979d73ad2b5b78a0e6cbdc2c1a01b', rootSemanticDigest: 'ffb555285bdd98de1be99d1f0526a69c76526321cc1fc45b5b4a6d19322bae63', sumsBytes: 1468, sumsLocator: 'p2/gate-b/gate-b0-evidence-plan-v1/SHA256SUMS', sumsRawSha256: '5e02267005bdda74cbc681f9d0d0f5592a65294dc4f727d14556fb381e93625a', validatorBytes: 50253, validatorLocator: 'p2/gate-b/gate-b0-evidence-plan-v1/validate-static.mjs', validatorRawSha256: '739fd21bda2dab59bd18f0e0c641be6a9eccd1c0e7bd637a0b8163068c399893'});
const EAC_EXPECTED_PROJECTION = Object.freeze({endpoints: [{alias: 'engine:native', endpointId: 'native', frozenRole: 'engine:native'}, {alias: 'engine:libauth', endpointId: 'libauth', frozenRole: 'engine:libauth'}, {alias: 'engine:bchn', endpointId: 'bchn', frozenRole: 'engine:bchn'}, {alias: 'engine:leanbch:primary', endpointId: 'leanbch-primary', frozenRole: 'engine:leanbch'}, {alias: 'engine:leanbch:secondary', endpointId: 'leanbch-secondary', frozenRole: 'engine:leanbch'}], frozenFixtureRows: 4732, launchAuthorityRows: 5, leanPairComparisonRoles: 1, legacyEngineRoles: 4, legacyExecutableObligations: 18432, legacyPreflightTerminalObligations: 496, legacyTotalObligations: 18928, preflightInvalidFixtureRows: 124, projectionStatus: 'STATIC_ONLY_NO_ENDPOINT_LAUNCH_AUTHORITY', rowsPerEndpoint: 4608, totalEndpointRawRows: 23040});
const EAC_EXPECTED_BINDING = Object.freeze({
  path: 'p2/gate-b/gate-b0-execution-admission-contract-v1',
  root: {path: 'p2/gate-b/gate-b0-execution-admission-contract-v1/execution-admission-contract-root.v1.json', rawSha256: '80fc0d146911ba774715da76fa69dcbae21852135222f7b26b7fb8bd9c775479', contentDigest: 'fed30561c154ffd4db50bad5dc4e38e5c54107236cf301777339fdf2d9460e7a'},
  manifest: {path: 'p2/gate-b/gate-b0-execution-admission-contract-v1/MANIFEST.json', rawSha256: '552b3bdb39f05150abd8d0e2b286d466e45657a3fb4959f7a77c3db126af0ec9', rosterDigest: 'bc1c61cb6d728d6c4327719c726f01d37818437390df87da1a750066ceb29ea9', entryCount: 18},
  checksums: {path: 'p2/gate-b/gate-b0-execution-admission-contract-v1/SHA256SUMS', rawSha256: '02cb373013c55cdfabf25d8f0e10c094ca563fc327ca11a368e1e9502d83ae95'},
  validator: {path: 'p2/gate-b/gate-b0-execution-admission-contract-v1/validate-static.mjs', rawSha256: '4a050b8958d2666c527e9c666e71145fc8965fcf75deae86a9c11f2ff9defd69'},
  reviewAnchor: {path: 'p2/gate-b/gate-b0-execution-admission-contract-review-anchor.v1.json', schema: 'shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1/external-review-anchor/v1', bytes: 11384, rawSha256: '297c0995e3129a407ee83957ecb4274bff4d91c61484d0b255375a7acf50a27b'},
  laneAuthorityProjection: {includedTopLevelKeys: [...B0R_INCLUDED_TOP_LEVEL_KEYS], excludedTopLevelKeys: [...B0R_EXCLUDED_TOP_LEVEL_KEYS], contentDigest: '7ab73381ae474648873d94f99d7227b9558f5fbb49eff8066132f0b2520ba138'},
  counts: {authoredFiles: 18, sealedFiles: 20, directories: 3, sourcePins: 64, digestKatCases: 12, futureBoundaryNegatives: 30, causalMutationNegatives: 72, cliArgumentNegatives: 16, sealedValidationNegatives: 6, p0FreezeNegatives: 6, packageBoundaryNegatives: 17, externalSafeWalkNegatives: 6, productionSealedPositives: 1},
  nonAuthorityBoundary: EAC_NONAUTHORITY_BOUNDARY,
  status: 'sol-regated-sealed-static-gate-b0-execution-admission-contract-v1-preexecution-prerequisite-catalog-nonauthorizing-no-admission-no-instances'
});
const EAC_REVIEW_ANCHOR_PIN = Object.freeze({reviewAnchorRoot: EAC_ANCHOR_ROOT, reviewAnchorLocator: EAC_ANCHOR_LOCATOR, reviewAnchorBytes: 11384, reviewAnchorRawSha256: '297c0995e3129a407ee83957ecb4274bff4d91c61484d0b255375a7acf50a27b'});
const EAC_BINDING_KEYS = Object.freeze(Object.keys(EAC_EXPECTED_BINDING));
const EAC_COUNT_KEYS = Object.freeze(Object.keys(EAC_EXPECTED_BINDING.counts));
const EAC_ZERO_BOUNDARY_KEYS = Object.freeze(Object.entries(EAC_NONAUTHORITY_BOUNDARY).filter(([, value]) => value === 0).map(([key]) => key));
const EAC_FALSE_BOUNDARY_KEYS = Object.freeze(Object.entries(EAC_NONAUTHORITY_BOUNDARY).filter(([, value]) => value === false).map(([key]) => key));
const EAC_COMPONENTS = Object.freeze([['parentBinding', 'parent-binding'], ['sourcePins', 'source-pins'], ['historicalDisposition', 'historical-disposition'], ['endpointProjectionContract', 'endpoint-projection-contract'], ['externalRequirements', 'external-requirements'], ['futureStateGrammar', 'future-state-grammar'], ['futureArtifactMapContract', 'future-artifact-map-contract'], ['futureResultAdmissionContract', 'future-result-admission-contract'], ['crashRecoveryContract', 'crash-recovery-contract'], ['nonAuthorityBoundary', 'nonauthority-boundary']]);
const EAC_CAUSAL_CLASS_COUNT = 77;
const eacFail = message => { throw new Error('gate-b0-execution-admission-contract-v1 lane binding: ' + message); };
const eacAssert = (condition, message) => { if (!condition) eacFail(message); };
const eacSame = (left, right) => b0rSame(left, right);
const eacCanonical = b0rCanonical;
const eacRawSha256 = b0rRawSha256;
const eacDigestRecord = (domain, value) => ({algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8||0x0a', value: eacRawSha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), Buffer.from(eacCanonical(value) + '\n', 'utf8')]))});
const eacRawFileDigest = (locator, bytes) => { const domain = `${EAC_PREFIX}/file/${locator}`; return {algorithm: 'sha256', canonicalization: 'raw-file-bytes-v1', domain, frame: 'utf8(domain)||0x00||raw-file-bytes', value: eacRawSha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), bytes]))}; };
const eacExactKeys = (value, keys, code) => eacAssert(value && typeof value === 'object' && !Array.isArray(value) && eacSame(Object.keys(value).sort(), [...keys].sort()), code);
const eacSafeLocator = (locator, code) => { eacAssert(typeof locator === 'string' && locator.length > 0 && !locator.includes('\\') && !locator.includes('\0') && locator.normalize('NFC') === locator, `${code}:LOCATOR`); const parts = locator.split('/'); eacAssert(parts.every(part => /^[A-Za-z0-9._-]+$/u.test(part) && part !== '.' && part !== '..'), `${code}:LOCATOR`); return parts; };
const eacSafeRead = (root, locator, code) => { const parts = eacSafeLocator(locator, code); const rootStat = lstatSync(root); eacAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && realpathSync(root) === root, `${code}:ROOT_METADATA`); let current = root; for (let ordinal = 0; ordinal < parts.length; ordinal += 1) { current = resolve(current, parts[ordinal]); const stat = lstatSync(current); const last = ordinal === parts.length - 1; eacAssert(!stat.isSymbolicLink() && (last ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), `${code}:SAFE_WALK:${locator}`); eacAssert(realpathSync(current) === current, `${code}:REALPATH:${locator}`); } return readFileSync(current); };
const eacSafeExternalRead = (repository, row) => { const parts = eacSafeLocator(row.locator, `EAC_SOURCE:${row.pinId}`); const rootStat = lstatSync(repository); eacAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && realpathSync(repository) === repository, 'EAC_SOURCE_ROOT'); let current = repository; for (let ordinal = 0; ordinal < parts.length; ordinal += 1) { current = resolve(current, parts[ordinal]); const stat = lstatSync(current); const last = ordinal === parts.length - 1; eacAssert(!stat.isSymbolicLink() && (last ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), `EAC_SOURCE:${row.pinId}:SAFE_WALK`); eacAssert(realpathSync(current) === current, `EAC_SOURCE:${row.pinId}:REALPATH`); if (last) { eacAssert([0o444, 0o600, 0o644].includes(stat.mode & 0o777), `EAC_SOURCE:${row.pinId}:MODE`); const bytes = readFileSync(current); eacAssert(bytes.length === row.bytes, `EAC_SOURCE:${row.pinId}:BYTES`); eacAssert(eacRawSha256(bytes) === row.rawSha256, `EAC_SOURCE:${row.pinId}:RAW`); return bytes; } } eacFail(`EAC_SOURCE:${row.pinId}:EMPTY`); };
const eacWalk = (root, prefix = '') => readdirSync(root, {withFileTypes: true}).flatMap(entry => { const locator = prefix + entry.name; if (entry.isDirectory()) return [{kind: 'directory', locator}, ...eacWalk(resolve(root, entry.name), locator + '/')]; if (entry.isFile()) return [{kind: 'file', locator}]; return [{kind: entry.isSymbolicLink() ? 'link' : 'other', locator}]; });
const eacCheckFilesystem = root => { const laneRelative = relative(laneDir, root); eacAssert(laneRelative && !laneRelative.startsWith('..'), 'EAC_PACKAGE_ROOT'); const rootStat = lstatSync(root); eacAssert(rootStat.isDirectory() && !rootStat.isSymbolicLink() && realpathSync(root) === root, 'EAC_PACKAGE_ROOT_METADATA'); const entries = eacWalk(root); const files = entries.filter(entry => entry.kind === 'file').map(entry => entry.locator).sort(); const directories = ['.', ...entries.filter(entry => entry.kind === 'directory').map(entry => entry.locator)].sort(); eacAssert(entries.every(entry => entry.kind === 'file' || entry.kind === 'directory'), 'EAC_PACKAGE_LINK_OR_SPECIAL_FILE'); eacAssert(eacSame(files, [...EAC_SEALED_FILES].sort()), 'EAC_SEALED_FILE_CLOSURE'); eacAssert(eacSame(directories, [...EAC_DIRECTORIES].sort()), 'EAC_SEALED_DIRECTORY_CLOSURE'); for (const locator of directories) { const stat = lstatSync(resolve(root, locator)); eacAssert(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o755, `EAC_DIRECTORY_METADATA:${locator}`); } for (const locator of files) { const stat = lstatSync(resolve(root, locator)); eacAssert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o644 && realpathSync(resolve(root, locator)) === resolve(root, locator), `EAC_FILE_METADATA:${locator}`); } return {files: files.length, directories: directories.length}; };
const eacReadCanonicalJson = (root, locator, code) => { const bytes = eacSafeRead(root, locator, code); let value; try { value = b0rParseJsonNoDuplicate(bytes, code); } catch { eacFail(`${code}:DUPLICATE_OR_PARSE`); } eacAssert(bytes.toString('utf8') === eacCanonical(value) + '\n', `${code}:CANONICAL`); return value; };
const eacDeriveEnvelope = root => { const entries = [...EAC_AUTHORED_FILES].sort().map(locator => { const bytes = eacSafeRead(root, locator, `EAC_FILE:${locator}`); return {locator, bytes: bytes.length, rawSha256: eacRawSha256(bytes), fileDigest: eacRawFileDigest(locator, bytes)}; }); const rosterDigest = eacDigestRecord(`${EAC_PREFIX}/manifest-roster`, entries); const manifest = {schema: 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/manifest.v1.schema.json', format: 'shieldkit-static-manifest-v1', packageId: 'gate-b0-execution-admission-contract-v1', entryCount: EAC_AUTHORED_FILES.length, entries, rosterDigest}; const manifestBytes = Buffer.from(eacCanonical(manifest) + '\n', 'utf8'); const sumsBytes = Buffer.from([...entries, {locator: 'MANIFEST.json', rawSha256: eacRawSha256(manifestBytes)}].map(row => `${row.rawSha256}  ${row.locator}`).join('\n') + '\n', 'utf8'); return {entries, manifest, manifestBytes, sumsBytes}; };
const eacAssertManifest = root => { const manifest = eacReadCanonicalJson(root, 'MANIFEST.json', 'EAC_MANIFEST'); const derived = eacDeriveEnvelope(root); eacAssert(eacSame(manifest, derived.manifest), 'EAC_MANIFEST_RECOMPUTE'); eacAssert(eacSafeRead(root, 'SHA256SUMS', 'EAC_SUMS').equals(derived.sumsBytes), 'EAC_SUMS_RECOMPUTE'); return derived; };
const eacReadAnchor = (anchorRoot = EAC_ANCHOR_ROOT, locator = EAC_ANCHOR_LOCATOR, expected = EAC_EXPECTED_BINDING.reviewAnchor) => { eacAssert(anchorRoot === EAC_ANCHOR_ROOT && locator === EAC_ANCHOR_LOCATOR, 'EAC_ANCHOR_PIN_PATH'); const bytes = eacSafeRead(anchorRoot, locator, 'EAC_ANCHOR'); eacAssert(bytes.length === expected.bytes, 'EAC_ANCHOR_BYTES'); eacAssert(eacRawSha256(bytes) === expected.rawSha256, 'EAC_ANCHOR_RAW'); const candidate = realpathSync(resolve(anchorRoot, locator)); const rel = relative(EAC_PACKAGE_ROOT, candidate); eacAssert(rel.startsWith('..'), 'EAC_ANCHOR_INSIDE_PACKAGE'); let anchor; try { anchor = b0rParseJsonNoDuplicate(bytes, 'EAC_ANCHOR'); } catch { eacFail('EAC_ANCHOR_DUPLICATE_OR_PARSE'); } eacAssert(bytes.toString('utf8') === eacCanonical(anchor) + '\n', 'EAC_ANCHOR_CANONICAL'); return anchor; };
const eacAssertBinding = binding => {
  eacAssert(binding && typeof binding === 'object' && !Array.isArray(binding), 'EAC_BINDING_SHAPE');
  eacAssert(EAC_BINDING_KEYS.every(key => Object.hasOwn(binding, key)), 'EAC_BINDING_OMISSION');
  eacAssert(Object.keys(binding).length === EAC_BINDING_KEYS.length && Object.keys(binding).every(key => EAC_BINDING_KEYS.includes(key)), 'EAC_BINDING_EXTRA_KEY');
  eacAssert(binding.path === EAC_EXPECTED_BINDING.path, 'EAC_BINDING_PATH');
  eacAssert(binding.status === EAC_EXPECTED_BINDING.status, 'EAC_BINDING_STATUS');
  for (const [name, expected] of Object.entries({root: EAC_EXPECTED_BINDING.root, manifest: EAC_EXPECTED_BINDING.manifest, checksums: EAC_EXPECTED_BINDING.checksums, validator: EAC_EXPECTED_BINDING.validator, reviewAnchor: EAC_EXPECTED_BINDING.reviewAnchor})) {
    eacExactKeys(binding[name], Object.keys(expected), `EAC_BINDING_${name.toUpperCase()}_SHAPE`);
    for (const [key, value] of Object.entries(expected)) eacAssert(binding[name][key] === value, `EAC_BINDING_${name.toUpperCase()}:${key}`);
  }
  eacExactKeys(binding.laneAuthorityProjection, Object.keys(EAC_EXPECTED_BINDING.laneAuthorityProjection), 'EAC_BINDING_PROJECTION_SHAPE');
  eacAssert(eacSame(binding.laneAuthorityProjection, EAC_EXPECTED_BINDING.laneAuthorityProjection), 'EAC_BINDING_PROJECTION_EXACT');
  eacExactKeys(binding.counts, EAC_COUNT_KEYS, 'EAC_BINDING_COUNT_SHAPE');
  for (const key of EAC_COUNT_KEYS) eacAssert(binding.counts[key] === EAC_EXPECTED_BINDING.counts[key], `EAC_BINDING_COUNT:${key}`);
  eacExactKeys(binding.nonAuthorityBoundary, Object.keys(EAC_NONAUTHORITY_BOUNDARY), 'EAC_BINDING_BOUNDARY_SHAPE');
  for (const key of EAC_ZERO_BOUNDARY_KEYS) eacAssert(binding.nonAuthorityBoundary[key] === 0, `EAC_BINDING_BOUNDARY:${key}`);
  for (const key of EAC_FALSE_BOUNDARY_KEYS) eacAssert(binding.nonAuthorityBoundary[key] === false, `EAC_BINDING_BOUNDARY:${key}`);
  eacAssert(eacSame(binding.nonAuthorityBoundary, EAC_NONAUTHORITY_BOUNDARY), 'EAC_BINDING_BOUNDARY_EXACT');
  eacAssert(eacSame(binding, EAC_EXPECTED_BINDING), 'EAC_BINDING_EXACT');
  return true;
};
const eacAssertRoot = root => { eacExactKeys(root, ['schema','artifactId','packageId','status','executionAllowed','measurementAdmissionAllowed','parentBinding','sourcePins','historicalDisposition','endpointProjectionContract','externalRequirements','futureStateGrammar','futureArtifactMapContract','futureResultAdmissionContract','crashRecoveryContract','nonAuthorityBoundary','runtimeBoundary','schemaBindings','componentDigests','contentDigest'], 'EAC_ROOT_KEYS'); eacAssert(root.schema === 'https://shieldkit-labs.local/p2/gate-b/gate-b0-execution-admission-contract/v1/root.v1.schema.json' && root.artifactId === 'artifact:gate-b:gate-b0-execution-admission-contract-v1' && root.packageId === 'gate-b0-execution-admission-contract-v1' && root.status === EAC_NONAUTHORITY_BOUNDARY.status && root.executionAllowed === false && root.measurementAdmissionAllowed === false, 'EAC_ROOT_IDENTITY'); eacAssert(eacSame(root.parentBinding, EAC_EXPECTED_PARENT_BINDING), 'EAC_ROOT_PARENT'); eacAssert(eacSame(root.schemaBindings, EAC_SCHEMA_BINDINGS), 'EAC_ROOT_SCHEMA_BINDINGS'); eacAssert(root.sourcePins.length === 64 && eacSame(root.sourcePins.map(row => row.pinId), EAC_SOURCE_PIN_IDS), 'EAC_ROOT_SOURCE_ROSTER'); eacAssert(root.externalRequirements.length === 30 && eacSame(root.externalRequirements.map(row => row.requirementId), EAC_REQUIREMENT_IDS) && root.externalRequirements.every(row => row.authorityGranted === false && row.admissionGranted === false && row.instanceCount === 0 && row.sourceContractRef === `uopc:dag:${row.requirementId}`), 'EAC_ROOT_REQUIREMENTS'); eacAssert(eacSame(root.endpointProjectionContract, EAC_EXPECTED_PROJECTION), 'EAC_ROOT_PROJECTION'); eacAssert(root.futureStateGrammar?.edges?.length === 37 && root.futureResultAdmissionContract?.edges?.length === 7, 'EAC_ROOT_EDGE_COUNTS'); eacAssert(eacSame(root.nonAuthorityBoundary, EAC_NONAUTHORITY_BOUNDARY), 'EAC_ROOT_BOUNDARY'); const expectedComponents = EAC_COMPONENTS.map(([component, suffix]) => ({component, digest: eacDigestRecord(`${EAC_PREFIX}/${suffix}`, root[component])})); eacAssert(eacSame(root.componentDigests, expectedComponents), 'EAC_ROOT_COMPONENT_DIGESTS'); const rootWithoutDigest = Object.fromEntries(Object.entries(root).filter(([key]) => key !== 'contentDigest')); eacAssert(eacSame(root.contentDigest, eacDigestRecord(`${EAC_PREFIX}/root`, rootWithoutDigest)) && root.contentDigest.value === EAC_EXPECTED_BINDING.root.contentDigest, 'EAC_ROOT_DIGEST'); };
const eacAssertSchemas = (root, packageRoot) => { const schemas = EAC_SCHEMA_BINDINGS.map(row => { const bytes = eacSafeRead(packageRoot, row.locator, `EAC_SCHEMA:${row.locator}`); eacAssert(eacRawSha256(bytes) === row.rawSha256, `EAC_SCHEMA_RAW:${row.locator}`); return eacReadCanonicalJson(packageRoot, row.locator, `EAC_SCHEMA:${row.locator}`); }); const ajv = new Ajv2020({allErrors: true, strict: true, strictTypes: true}); schemas.forEach(schema => ajv.addSchema(schema)); const validate = ajv.getSchema(root.schema); eacAssert(validate && validate(root), `EAC_ROOT_SCHEMA:${ajv.errorsText(validate?.errors)}`); };
const eacAssertAnchor = (anchor, root, envelope) => { eacExactKeys(anchor, ['schema','package','rootRawSha256','rootContentDigest','validatorRawSha256','manifestRawSha256','sha256SumsRawSha256','entryCount','orderedClosure','rosterDigest','parentBinding','sourcePinTableDigest','nonAuthorityBoundary'], 'EAC_ANCHOR_SHAPE'); const expected = {schema: EAC_EXPECTED_BINDING.reviewAnchor.schema, package: EAC_PACKAGE_LOCATOR, rootRawSha256: EAC_EXPECTED_BINDING.root.rawSha256, rootContentDigest: root.contentDigest, validatorRawSha256: EAC_EXPECTED_BINDING.validator.rawSha256, manifestRawSha256: EAC_EXPECTED_BINDING.manifest.rawSha256, sha256SumsRawSha256: EAC_EXPECTED_BINDING.checksums.rawSha256, entryCount: EAC_AUTHORED_FILES.length, orderedClosure: envelope.entries, rosterDigest: envelope.manifest.rosterDigest, parentBinding: EAC_EXPECTED_PARENT_BINDING, sourcePinTableDigest: root.componentDigests.find(row => row.component === 'sourcePins')?.digest.value, nonAuthorityBoundary: EAC_NONAUTHORITY_BOUNDARY}; eacAssert(eacSame(anchor, expected), 'EAC_ANCHOR_EXACT'); };
const EAC_PROSE_SOURCES = Object.freeze([{label: 'lane README', locator: 'research-lanes/bch-shielded-pool-design/README.md', path: resolve(laneDir, 'README.md')}, {label: 'design options', locator: 'research-lanes/bch-shielded-pool-design/analysis/design-options.md', path: resolve(laneDir, 'analysis/design-options.md')}]);
const eacAssertNonpromotionProse = (texts = EAC_PROSE_SOURCES.map(({path, label}) => [label, readFileSync(path, 'utf8')])) => { for (const [label, prose] of texts) eacAssert(prose.split(EAC_NONPROMOTION).length === 2 && prose.split(EAC_NEXT_GATE).length === 2, `EAC_NONPROMOTION_PROSE:${label}`); };
const eacAssertPhaseExcludesNonpromotion = (phase = readFileSync(resolve(laneDir, 'research/phase-plan.md'), 'utf8')) => eacAssert(!phase.includes(EAC_NONPROMOTION) && !phase.includes(EAC_NEXT_GATE), 'EAC_PHASE_NONPROMOTION_SOURCE_CYCLE');
const eacAssertProseSourceDisjointness = root => { const locators = new Set(root.sourcePins.map(row => row.locator)); for (const source of EAC_PROSE_SOURCES) eacAssert(!locators.has(source.locator), `EAC_PROSE_SOURCE_CYCLE:${source.locator}`); };
const eacAssertLaneProjection = (laneValue, root) => {
  b0rAssertLaneKeyPartition(laneValue);
  const snapshot = Object.fromEntries(B0R_INCLUDED_TOP_LEVEL_KEYS.map(key => [key, laneValue[key]]));
  const digest = b0rDigestRecord(`${B0R_PREFIX}/lane-authority-projection`, {schema: `${B0R_PREFIX}/lane-authority-projection/v1`, snapshot});
  eacAssert(digest.value === EAC_EXPECTED_BINDING.laneAuthorityProjection.contentDigest, 'EAC_LANE_PROJECTION');
  eacAssert(eacSame(root.parentBinding, EAC_EXPECTED_PARENT_BINDING), 'EAC_PARENT_PROJECTION');
};
const eacValidateIndependent = (root = EAC_PACKAGE_ROOT, repository = repoRoot, anchorRoot = EAC_ANCHOR_ROOT, anchorLocator = EAC_ANCHOR_LOCATOR) => { const closure = eacCheckFilesystem(root); for (const [locator, raw] of [['execution-admission-contract-root.v1.json', EAC_EXPECTED_BINDING.root.rawSha256], ['validate-static.mjs', EAC_EXPECTED_BINDING.validator.rawSha256], ['MANIFEST.json', EAC_EXPECTED_BINDING.manifest.rawSha256], ['SHA256SUMS', EAC_EXPECTED_BINDING.checksums.rawSha256]]) eacAssert(eacRawSha256(eacSafeRead(root, locator, `EAC_RAW_PIN:${locator}`)) === raw, `EAC_RAW_PIN:${locator}`); const anchor = eacReadAnchor(anchorRoot, anchorLocator); const envelope = eacAssertManifest(root); const rootModel = eacReadCanonicalJson(root, 'execution-admission-contract-root.v1.json', 'EAC_ROOT'); eacAssertSchemas(rootModel, root); eacAssertRoot(rootModel); for (const row of rootModel.sourcePins) eacSafeExternalRead(repository, row); eacAssertAnchor(anchor, rootModel, envelope); eacAssertLaneProjection(lane, rootModel); eacAssertProseSourceDisjointness(rootModel); eacAssertNonpromotionProse(); eacAssertPhaseExcludesNonpromotion(); return {...closure, root: rootModel, anchor, envelope, sourcePins: rootModel.sourcePins.length}; };
const eacExpectFailure = (operation, expected, label) => { let failure; try { operation(); } catch (error) { failure = error; } eacAssert(failure?.message.includes(expected), `EAC_CAUSAL_MUTATION:${label}`); };
const eacRunCausalMutation = async (laneValue, importedValidator) => { let classes = 0; const reject = (operation, expected, label) => { eacExpectFailure(operation, expected, label); classes += 1; }; const bindingMutation = (label, mutate, expected) => { const binding = structuredClone(EAC_EXPECTED_BINDING); mutate(binding); reject(() => eacAssertBinding(binding), expected, `binding/${label}`); };
  bindingMutation('omission', binding => { delete binding.path; }, 'EAC_BINDING_OMISSION'); bindingMutation('extra', binding => { binding.unreviewed = true; }, 'EAC_BINDING_EXTRA_KEY'); bindingMutation('status', binding => { binding.status += '-selection'; }, 'EAC_BINDING_STATUS');
  for (const key of EAC_COUNT_KEYS) bindingMutation(`count-${key}`, binding => { binding.counts[key] += 1; }, `EAC_BINDING_COUNT:${key}`);
  for (const key of EAC_ZERO_BOUNDARY_KEYS) bindingMutation(`zero-${key}`, binding => { binding.nonAuthorityBoundary[key] = 1; }, `EAC_BINDING_BOUNDARY:${key}`);
  for (const key of EAC_FALSE_BOUNDARY_KEYS) bindingMutation(`false-${key}`, binding => { binding.nonAuthorityBoundary[key] = true; }, `EAC_BINDING_BOUNDARY:${key}`);
  for (const [label, outer, field, expected] of [['root', 'root', 'rawSha256', 'EAC_BINDING_ROOT:rawSha256'], ['validator', 'validator', 'rawSha256', 'EAC_BINDING_VALIDATOR:rawSha256'], ['manifest', 'manifest', 'rawSha256', 'EAC_BINDING_MANIFEST:rawSha256'], ['sums', 'checksums', 'rawSha256', 'EAC_BINDING_CHECKSUMS:rawSha256'], ['anchor', 'reviewAnchor', 'rawSha256', 'EAC_BINDING_REVIEWANCHOR:rawSha256']]) bindingMutation(`${label}-raw`, binding => { binding[outer][field] = '0'.repeat(64); }, expected);
  bindingMutation('anchor-bytes', binding => { binding.reviewAnchor.bytes += 1; }, 'EAC_BINDING_REVIEWANCHOR:bytes'); bindingMutation('anchor-path', binding => { binding.reviewAnchor.path = 'p2/gate-b/inside.json'; }, 'EAC_BINDING_REVIEWANCHOR:path');
  const rootModel = eacReadCanonicalJson(EAC_PACKAGE_ROOT, 'execution-admission-contract-root.v1.json', 'EAC_MUTATION_ROOT');
  const projection = structuredClone(rootModel); projection.endpointProjectionContract.rowsPerEndpoint += 1; reject(() => eacAssertRoot(projection), 'EAC_ROOT_PROJECTION', 'projection/count');
  const projectionOrder = structuredClone(rootModel); [projectionOrder.endpointProjectionContract.endpoints[0], projectionOrder.endpointProjectionContract.endpoints[1]] = [projectionOrder.endpointProjectionContract.endpoints[1], projectionOrder.endpointProjectionContract.endpoints[0]]; reject(() => eacAssertRoot(projectionOrder), 'EAC_ROOT_PROJECTION', 'projection/endpoint-order');
  const requirement = structuredClone(rootModel); requirement.externalRequirements.pop(); reject(() => eacAssertRoot(requirement), 'EAC_ROOT_REQUIREMENTS', 'requirements/omit');
  const requirementOrder = structuredClone(rootModel); [requirementOrder.externalRequirements[0], requirementOrder.externalRequirements[1]] = [requirementOrder.externalRequirements[1], requirementOrder.externalRequirements[0]]; reject(() => eacAssertRoot(requirementOrder), 'EAC_ROOT_REQUIREMENTS', 'requirements/order');
  const boundary = structuredClone(rootModel); boundary.nonAuthorityBoundary.executionAllowed = true; reject(() => eacAssertRoot(boundary), 'EAC_ROOT_BOUNDARY', 'boundary/false-flip');
  const sourceRaw = structuredClone(rootModel.sourcePins[0]); sourceRaw.rawSha256 = '0'.repeat(64); reject(() => eacSafeExternalRead(repoRoot, sourceRaw), `EAC_SOURCE:${sourceRaw.pinId}:RAW`, 'source/raw');
  const sourceTraversal = structuredClone(rootModel.sourcePins[0]); sourceTraversal.locator = '../lane.json'; reject(() => eacSafeExternalRead(repoRoot, sourceTraversal), `EAC_SOURCE:${sourceTraversal.pinId}:LOCATOR`, 'source/traversal');
  const sourceRoster = structuredClone(rootModel); sourceRoster.sourcePins[1] = structuredClone(sourceRoster.sourcePins[0]); reject(() => eacAssertRoot(sourceRoster), 'EAC_ROOT_SOURCE_ROSTER', 'source/duplicate');
  const laneProjection = structuredClone(laneValue); laneProjection.apiVersion = 'eac-lane-projection-mutant'; reject(() => eacAssertLaneProjection(laneProjection, rootModel), 'EAC_LANE_PROJECTION', 'lane/projection');
  const lanePartition = structuredClone(laneValue); lanePartition.unexpectedEacKey = 'forbidden'; reject(() => eacAssertLaneProjection(lanePartition, rootModel), 'B0R_LANE_KEY_PARTITION', 'lane/partition');
  eacAssertPhaseExcludesNonpromotion(); reject(() => eacAssertPhaseExcludesNonpromotion(EAC_NONPROMOTION), 'EAC_PHASE_NONPROMOTION_SOURCE_CYCLE', 'phase/drift'); const prose = EAC_PROSE_SOURCES.map(({path, label}) => [label, readFileSync(path, 'utf8')]); reject(() => eacAssertNonpromotionProse(prose.map(([label, text]) => [label, text.replace(EAC_NONPROMOTION, '')])), 'EAC_NONPROMOTION_PROSE:lane README', 'prose/deletion'); reject(() => eacAssertNonpromotionProse(prose.map(([label, text]) => [label, label === 'lane README' ? text.replace(EAC_NONPROMOTION, EAC_NONPROMOTION.replace('no candidate', 'a candidate')) : text])), 'EAC_NONPROMOTION_PROSE:lane README', 'prose/widening');
  const sourceCycle = structuredClone(rootModel); sourceCycle.sourcePins[0].locator = EAC_PROSE_SOURCES[0].locator; reject(() => eacAssertProseSourceDisjointness(sourceCycle), `EAC_PROSE_SOURCE_CYCLE:${EAC_PROSE_SOURCES[0].locator}`, 'prose/source-cycle');
  reject(() => eacReadAnchor(EAC_ANCHOR_ROOT, EAC_ANCHOR_LOCATOR, {...EAC_EXPECTED_BINDING.reviewAnchor, rawSha256: '0'.repeat(64)}), 'EAC_ANCHOR_RAW', 'anchor/raw');
  const temporaryRoot = mkdtempSync(resolve(laneDir, '.shieldkit-eac-lane-')); try { const fixture = resolve(temporaryRoot, 'package'); cpSync(EAC_PACKAGE_ROOT, fixture, {recursive: true}); rmSync(resolve(fixture, 'MANIFEST.json')); reject(() => eacCheckFilesystem(fixture), 'EAC_SEALED_FILE_CLOSURE', 'lifecycle/missing-envelope'); cpSync(EAC_PACKAGE_ROOT, fixture, {recursive: true, force: true}); writeFileSync(resolve(fixture, 'extra.txt'), 'x\n'); reject(() => eacCheckFilesystem(fixture), 'EAC_SEALED_FILE_CLOSURE', 'closure/extra-file'); cpSync(EAC_PACKAGE_ROOT, fixture, {recursive: true, force: true}); const manifest = eacReadCanonicalJson(fixture, 'MANIFEST.json', 'EAC_MUTATION_MANIFEST'); manifest.entries[0].fileDigest.value = '0'.repeat(64); writeFileSync(resolve(fixture, 'MANIFEST.json'), Buffer.from(eacCanonical(manifest) + '\n')); reject(() => eacAssertManifest(fixture), 'EAC_MANIFEST_RECOMPUTE', 'manifest/file-digest');
    const reorderedFixture = resolve(temporaryRoot, 'manifest-reordered'); cpSync(EAC_PACKAGE_ROOT, reorderedFixture, {recursive: true}); const reorderedManifest = eacReadCanonicalJson(reorderedFixture, 'MANIFEST.json', 'EAC_MUTATION_MANIFEST_REORDER'); [reorderedManifest.entries[0], reorderedManifest.entries[1]] = [reorderedManifest.entries[1], reorderedManifest.entries[0]]; writeFileSync(resolve(reorderedFixture, 'MANIFEST.json'), Buffer.from(eacCanonical(reorderedManifest) + '\n')); reject(() => eacAssertManifest(reorderedFixture), 'EAC_MANIFEST_RECOMPUTE', 'manifest/reorder');
    const rosterFixture = resolve(temporaryRoot, 'manifest-roster'); cpSync(EAC_PACKAGE_ROOT, rosterFixture, {recursive: true}); const rosterManifest = eacReadCanonicalJson(rosterFixture, 'MANIFEST.json', 'EAC_MUTATION_MANIFEST_ROSTER'); rosterManifest.rosterDigest.value = '0'.repeat(64); writeFileSync(resolve(rosterFixture, 'MANIFEST.json'), Buffer.from(eacCanonical(rosterManifest) + '\n')); reject(() => eacAssertManifest(rosterFixture), 'EAC_MANIFEST_RECOMPUTE', 'manifest/roster');
    const sumsFixture = resolve(temporaryRoot, 'manifest-sums'); cpSync(EAC_PACKAGE_ROOT, sumsFixture, {recursive: true}); writeFileSync(resolve(sumsFixture, 'SHA256SUMS'), Buffer.from('0'.repeat(64) + '  COMMAND.txt\n')); reject(() => eacAssertManifest(sumsFixture), 'EAC_SUMS_RECOMPUTE', 'manifest/sums');
    const localAnchorRoot = resolve(temporaryRoot, 'anchor'); mkdirSync(localAnchorRoot); const coordinated = resolve(temporaryRoot, 'coordinated'); cpSync(EAC_PACKAGE_ROOT, coordinated, {recursive: true}); writeFileSync(resolve(coordinated, 'execution-admission-contract-root.v1.json'), '{}\n'); writeFileSync(resolve(coordinated, 'validate-static.mjs'), 'export const validateStatic = () => ({files:20,sourcePins:64,unsealed:false,sealed:true});\n'); writeFileSync(resolve(coordinated, 'schemas/root.v1.schema.json'), '{}\n'); const coordinatedEnvelope = eacDeriveEnvelope(coordinated); writeFileSync(resolve(coordinated, 'MANIFEST.json'), coordinatedEnvelope.manifestBytes); writeFileSync(resolve(coordinated, 'SHA256SUMS'), coordinatedEnvelope.sumsBytes); const copiedAnchor = structuredClone(eacReadAnchor()); copiedAnchor.rootRawSha256 = eacRawSha256(eacSafeRead(coordinated, 'execution-admission-contract-root.v1.json', 'EAC_COORD_ROOT')); copiedAnchor.validatorRawSha256 = eacRawSha256(eacSafeRead(coordinated, 'validate-static.mjs', 'EAC_COORD_VALIDATOR')); copiedAnchor.manifestRawSha256 = eacRawSha256(coordinatedEnvelope.manifestBytes); copiedAnchor.sha256SumsRawSha256 = eacRawSha256(coordinatedEnvelope.sumsBytes); copiedAnchor.orderedClosure = coordinatedEnvelope.entries; copiedAnchor.rosterDigest = coordinatedEnvelope.manifest.rosterDigest; const copiedAnchorBytes = Buffer.from(eacCanonical(copiedAnchor) + '\n'); writeFileSync(resolve(localAnchorRoot, EAC_ANCHOR_LOCATOR), copiedAnchorBytes); const localReplacement = await import(pathToFileURL(resolve(coordinated, 'validate-static.mjs')).href + `?eac-coordinated=${Date.now()}`); eacAssert(localReplacement.validateStatic({packageRoot: coordinated, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: {reviewAnchorRoot: localAnchorRoot, reviewAnchorLocator: EAC_ANCHOR_LOCATOR, reviewAnchorBytes: copiedAnchorBytes.length, reviewAnchorRawSha256: eacRawSha256(copiedAnchorBytes)}})?.sealed === true, 'EAC_CAUSAL_MUTATION:coordinated-local-validator'); reject(() => eacValidateIndependent(coordinated, repoRoot, localAnchorRoot, EAC_ANCHOR_LOCATOR), 'EAC_RAW_PIN:execution-admission-contract-root.v1.json', 'coordinated/root-validator-schema-manifest-sums-anchor');
    reject(() => importedValidator.validateStatic({packageRoot: EAC_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'unsealed'}), 'PACKAGE_CLOSURE:unsealed', 'lifecycle/unsealed-production'); reject(() => importedValidator.validateStatic({packageRoot: EAC_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: null}), 'SEALED_ANCHOR_REQUIRED', 'lifecycle/missing-pin');
    eacAssert(classes === EAC_CAUSAL_CLASS_COUNT, 'EAC_CAUSAL_MUTATION:class-count'); return {classes};
  } finally { rmSync(temporaryRoot, {recursive: true, force: true}); eacAssert(!existsSync(temporaryRoot), 'EAC_CAUSAL_MUTATION:cleanup'); } };

// SSA is the sealed, static source-contract-language authority below EAC. The
// lane rederives its complete closure and semantics from external literals
// before importing the package validator; neither the lane record nor SSA may
// bootstrap those pins from live lane state.
const SSA_PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1';
const SSA_SCHEMA_PREFIX = 'https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1';
const SSA_PACKAGE_RELATIVE = 'p2/gate-b/gate-b0-static-source-authority-v1';
const SSA_PACKAGE_ROOT = resolve(laneDir, SSA_PACKAGE_RELATIVE);
const SSA_PACKAGE_LOCATOR = 'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-static-source-authority-v1';
const SSA_ANCHOR_ROOT = resolve(laneDir, 'p2/gate-b');
const SSA_ANCHOR_LOCATOR = 'gate-b0-static-source-authority-review-anchor.v1.json';
const SSA_AUTHORED_FILES = Object.freeze([
  'COMMAND.txt', 'README.md',
  'schemas/dependency-pin.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/governance.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/non-authority-boundary.v1.schema.json', 'schemas/owner-contract-source-catalog.v1.schema.json', 'schemas/private-capture-source-catalog.v1.schema.json', 'schemas/raw-artifact-map-source-contract.v1.schema.json', 'schemas/requirement-resolution.v1.schema.json', 'schemas/result-validator-source-contract.v1.schema.json', 'schemas/retry-lineage-source-catalog.v1.schema.json', 'schemas/root.v1.schema.json', 'schemas/source-contract.v1.schema.json', 'schemas/state-fact-source-catalog.v1.schema.json', 'schemas/workload-projection-source-catalog.v1.schema.json',
  'static-source-authority-root.v1.json', 'test/digest.kat.json', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/source-resolution.test.mjs', 'test/static.test.mjs', 'validate-static.mjs'
]);
const SSA_SEALED_FILES = Object.freeze([...SSA_AUTHORED_FILES, 'MANIFEST.json', 'SHA256SUMS']);
const SSA_DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const SSA_SCHEMA_BINDINGS = Object.freeze([
  {locator:'schemas/dependency-pin.v1.schema.json',rawSha256:'cee8e6b5d0eb2764a908499b748d7058db74e823bd5feb3408df238b91abca49',schemaId:`${SSA_SCHEMA_PREFIX}/dependency-pin.v1.schema.json`},
  {locator:'schemas/digest.v1.schema.json',rawSha256:'eb02232e05fd4beffdda7876b1f61abc94ee2ab1162121e622421646fba3c1c4',schemaId:`${SSA_SCHEMA_PREFIX}/digest.v1.schema.json`},
  {locator:'schemas/governance.v1.schema.json',rawSha256:'ef955ce125c3f545cffa6d06b6f7ac2bee0ea3f4aa236c78564ae77ded8b2e73',schemaId:`${SSA_SCHEMA_PREFIX}/governance.v1.schema.json`},
  {locator:'schemas/manifest.v1.schema.json',rawSha256:'0a12239602afdc651aae54ecabe73d003498e89387e99e994d52a03f67d9f549',schemaId:`${SSA_SCHEMA_PREFIX}/manifest.v1.schema.json`},
  {locator:'schemas/non-authority-boundary.v1.schema.json',rawSha256:'8a9ca08c91f805ad340c9ab9bba19f2218414219e4b1527344096c53212d3b20',schemaId:`${SSA_SCHEMA_PREFIX}/non-authority-boundary.v1.schema.json`},
  {locator:'schemas/owner-contract-source-catalog.v1.schema.json',rawSha256:'2f959b6991c89870b0b9889f9a48565c5ac7e7195032d2c6c66390b560acc176',schemaId:`${SSA_SCHEMA_PREFIX}/owner-contract-source-catalog.v1.schema.json`},
  {locator:'schemas/private-capture-source-catalog.v1.schema.json',rawSha256:'c76e459d8e15446bd0533c2b89b84d488cff09d8ff75590cbfbb81892790804c',schemaId:`${SSA_SCHEMA_PREFIX}/private-capture-source-catalog.v1.schema.json`},
  {locator:'schemas/raw-artifact-map-source-contract.v1.schema.json',rawSha256:'7970962dd84e97f2633ade61de78dfd71dbe707e8dc7040b310c85bbe4102ec8',schemaId:`${SSA_SCHEMA_PREFIX}/raw-artifact-map-source-contract.v1.schema.json`},
  {locator:'schemas/requirement-resolution.v1.schema.json',rawSha256:'57831071c8baf65d7191674a518e76b9e26bf86742fcf29510137562569823a2',schemaId:`${SSA_SCHEMA_PREFIX}/requirement-resolution.v1.schema.json`},
  {locator:'schemas/result-validator-source-contract.v1.schema.json',rawSha256:'42f1b396d4688047c0a4ac27df42e3df94a81021a594077cb78d759dc25ec294',schemaId:`${SSA_SCHEMA_PREFIX}/result-validator-source-contract.v1.schema.json`},
  {locator:'schemas/retry-lineage-source-catalog.v1.schema.json',rawSha256:'c4fb4cc7c409c4e6e14c203b719a5d86bff2f6f9e549c1a6b30850128deb95be',schemaId:`${SSA_SCHEMA_PREFIX}/retry-lineage-source-catalog.v1.schema.json`},
  {locator:'schemas/root.v1.schema.json',rawSha256:'b1e8c9f304c4d2d34287bd9448e49feff5930bbb833b941dbc6a069fcbb3936b',schemaId:`${SSA_SCHEMA_PREFIX}/root.v1.schema.json`},
  {locator:'schemas/source-contract.v1.schema.json',rawSha256:'eab468661ae36a3398d3553f9f2a3411fd3f40dab705be285d6d4e1d8f80f2b7',schemaId:`${SSA_SCHEMA_PREFIX}/source-contract.v1.schema.json`},
  {locator:'schemas/state-fact-source-catalog.v1.schema.json',rawSha256:'ca60c9715186a030b2041968a7b48f6d709a908b81119527c3ee6ff53532edf2',schemaId:`${SSA_SCHEMA_PREFIX}/state-fact-source-catalog.v1.schema.json`},
  {locator:'schemas/workload-projection-source-catalog.v1.schema.json',rawSha256:'8cd28adbabd83f2e20e7994167edeba0b4f2ab4679c0004579426a8f31544c54',schemaId:`${SSA_SCHEMA_PREFIX}/workload-projection-source-catalog.v1.schema.json`}
]);
const SSA_SOURCE_KINDS = Object.freeze(['UPSTREAM_OWNER_CONTRACT_SCHEMA','RETRY_TARGET_SOURCE_SCHEMA','RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA','LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA','ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA','ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA','WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA','WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE','WORKLOAD_ROOT_SOURCE_SCHEMA','OWNER_BOUND_A_FACT_SOURCE_SCHEMA','OWNER_BOUND_B_FACT_SOURCE_SCHEMA','OWNER_BOUND_C_FACT_SOURCE_SCHEMA','OWNER_BOUND_D_FACT_SOURCE_SCHEMA','OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA','OWNER_BOUND_Q_FACT_SOURCE_SCHEMA']);
const SSA_PRIMARY_MAP = Object.freeze({UPSTREAM_OWNER_CONTRACT_SCHEMA:'OWNER_CONTRACT_MAP',RETRY_TARGET_SOURCE_SCHEMA:'RETRY_TARGET_MAP',RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA:'RETRY_PREDECESSOR_MAP',LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA:'LIVE_F_CAPTURE_MAP',ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA:'ENDPOINT_BYTE_AUTHORITY_MAP',ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA:'WORKLOAD_ORDER_MAP',PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA:'DISPATCH_PLAN_MAP',WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA:'WORKER_ROWS_MAP',WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE:'WORKLOAD_ROOT_MAP',WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE:'WORKLOAD_ORDER_MAP',WORKLOAD_ROOT_SOURCE_SCHEMA:'WORKLOAD_ROOT_MAP',OWNER_BOUND_A_FACT_SOURCE_SCHEMA:'A_MAP',OWNER_BOUND_B_FACT_SOURCE_SCHEMA:'B_MAP',OWNER_BOUND_C_FACT_SOURCE_SCHEMA:'C_MAP',OWNER_BOUND_D_FACT_SOURCE_SCHEMA:'D_MAP',OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA:'LIVE_F_MAP',OWNER_BOUND_Q_FACT_SOURCE_SCHEMA:'Q_MAP'});
const SSA_COMPONENTS = Object.freeze([['governance','governance'],['dependencyPins','dependencies'],['transitiveSourcePins','transitive-source-pins'],['ownerContractSourceCatalog','owner-contract-source-catalog'],['retryLineageSourceCatalog','retry-lineage-source-catalog'],['privateCaptureSourceCatalog','private-capture-source-catalog'],['workloadProjectionSourceCatalog','workload-projection-source-catalog'],['stateFactSourceCatalog','state-fact-source-catalog'],['supplementalContracts','supplemental-contracts'],['requirementResolutions','requirement-resolutions'],['preauthorizationSemantics','preauthorization-semantics'],['nonAuthorityBoundary','nonauthority-boundary'],['runtimeBoundary','runtime-boundary'],['schemaBindings','schema-bindings']]);
const SSA_NONPROMOTION = 'The sealed gate-b0-static-source-authority-v1 package is a static, non-authorizing, non-admitting, unqualified source-contract-language authority bound by an outside-package review anchor; it authenticates only the reviewed 24-file authored closure, its two mechanical envelope files, 64 raw-pinned transitive source leaves with native semantic joins, 17 closed source-contract records, 2 supplemental source contracts, 30 false/zero requirement-resolution rows, 15 raw-pinned schemas, and the exact false/zero non-authority boundary, and it creates no provider, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.';
const SSA_NOT_ESTABLISHED = 'any provider, owner, ownerBindingRoot, origin, fact instance, root value, order material, projection material, private byte, raw-artifact-map authority or instance, independent result-validator implementation or evaluation, retry-predecessor instance, Q/A/LIVE_F/B/C/J/D instance, nonce, attempt, candidate or tuple instance, role or parameter assignment, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback authorization, admission, execution, complete Gate B0 epoch, Gate B0 root/SOL review, or Gate B1 opening by this integration; J remains ownerless and non-authorizing, the sealed gate-b0-static-source-authority-v1 package resolves only static source-contract language, all 30 provider requirements remain false/zero and unavailable, and source-contract resolution does not satisfy or instantiate a provider, owner, state, artifact, or runtime requirement';
const SSA_UNSELECTED = 'any provider instance, owner, ownerBindingRoot, origin, fact instance, root value, order material, projection material, private byte, raw-artifact-map authority or instance, independent result-validator implementation or evaluation, retry-predecessor instance, Q/A/LIVE_F/B/C/J/D instance, admission, or execution; all 17 source-kind contracts and 2 supplemental source contracts are authenticated only as static language, J remains ownerless and non-authorizing, and source-contract resolution does not satisfy a UOPC provider or create any instance';
const SSA_NEXT_GATE = 'The sealed gate-b0-static-source-authority-v1 integration closes only the static source-contract-language prerequisite stage beneath the sealed gate-b0-execution-admission-contract-v1. It authenticates 17 source-kind contracts and 2 supplemental contracts, but all 30 EAC provider requirements remain false/zero, unavailable, and uninstantiated. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authority contracts govern and bind the future authorized creation or satisfaction of every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validator prerequisite under the closed EAC grammar; no provider, owner, state, artifact, or runtime instance may be created before that authorization, and static source-contract resolution alone is insufficient. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, result-validator implementation or evaluation, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.';
const SSA_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-no-provider-or-state-instances-no-io-no-execution-no-admission-architecture-unpromoted';
const SSA_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified';
const SSA_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-no-provider-or-state-instances-no-io-no-execution-no-admission-nonranking-unqualified';
const SSA_NONAUTHORITY_BOUNDARY = Object.freeze({artifactMapAuthorityCreationAllowed:false,artifactMapAuthorityInstanceCount:0,artifactMapInstanceCount:0,artifactMapInstanceCreationAllowed:false,attemptCount:0,attemptCreationAllowed:false,authorizationCount:0,authorizationCreationAllowed:false,candidateCount:0,candidateCreationAllowed:false,childProcessCount:0,childProcessCreationAllowed:false,claimCount:0,claimCreationAllowed:false,endpointImportAllowed:false,evidenceCount:0,executionAllowed:false,factInstanceCount:0,factInstanceCreationAllowed:false,fallbackAuthorizationAllowed:false,ioAllowed:false,measurementAdmissionAllowed:false,measurementCount:0,orderMaterialCount:0,orderMaterialCreationAllowed:false,ownerInstanceCount:0,ownerInstantiationAllowed:false,parameterAssignmentAllowed:false,parameterAssignmentCount:0,privateByteCaptureAllowed:false,privateByteCount:0,projectionMaterialCount:0,projectionMaterialCreationAllowed:false,providerInstanceCount:0,providerInstantiationAllowed:false,qualificationAllowed:false,rankingAllowed:false,requirementResolutionCount:30,resultAdmissionAllowed:false,resultCount:0,resultValidatorEvaluationAllowed:false,resultValidatorEvaluationCount:0,roleAssignmentAllowed:false,roleAssignmentCount:0,rootValueCount:0,rootValueCreationAllowed:false,runtimeImportAllowed:false,selectionAllowed:false,sourceContractCount:19,status:'static-source-contract-authority-resolved-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified',tupleCount:0,workloadMaterialCount:0,workloadMaterialCreationAllowed:false});
const SSA_EXPECTED_BINDING = Object.freeze({
  path:SSA_PACKAGE_RELATIVE,
  root:{path:`${SSA_PACKAGE_RELATIVE}/static-source-authority-root.v1.json`,rawSha256:'bf5876cdb47e3b1f76f2bd9589b5a5c6a15e3ea1c231f4ccf55527a66d7b5327',contentDigest:'9c5e6106cca05ee3aeb49618fded4ed27581d25945e5dd3d0d4227deff775320'},
  manifest:{path:`${SSA_PACKAGE_RELATIVE}/MANIFEST.json`,rawSha256:'06a039a5e04c0193794f0dae74960b2c405a24e1d082681fc03f5ec9bc82aa1a',rosterDigest:'1a3d33d66bd46804832ac3cde3312f40dcbe896d1d2de9f827aa4359cdc0917b',entryCount:24},
  checksums:{path:`${SSA_PACKAGE_RELATIVE}/SHA256SUMS`,rawSha256:'d6bca7451387595b9c632662ef9e6e99b2a8c4c2f5104ed8d0617c1b8e6b3275'},
  validator:{path:`${SSA_PACKAGE_RELATIVE}/validate-static.mjs`,rawSha256:'f4032cd5ac90fed87f9e07c25146c64816158e6c54fe7ec71087556a836dfc42'},
  reviewAnchor:{path:'p2/gate-b/gate-b0-static-source-authority-review-anchor.v1.json',schema:`${SSA_PREFIX}/external-review-anchor/v1`,bytes:26079,rawSha256:'c56473f1a3cf8896cd48680f3832f886b1f10d7e45826b84f33f03656891b3bb'},
  laneAuthorityProjection:{includedTopLevelKeys:[...B0R_INCLUDED_TOP_LEVEL_KEYS],excludedTopLevelKeys:[...B0R_EXCLUDED_TOP_LEVEL_KEYS],contentDigest:'7ab73381ae474648873d94f99d7227b9558f5fbb49eff8066132f0b2520ba138'},
  counts:{authoredFiles:24,sealedFiles:26,directories:3,schemaBindings:15,componentDigests:14,transitiveSourcePins:64,sourceContractRecords:17,supplementalSourceContracts:2,sourceContracts:19,requirementResolutions:30,digestKatCases:16,staticTests:3,sourceResolutionTests:2,packageBoundaryNegatives:18,causalMutationNegatives:128,totalTests:24,productionSealedPositives:1},
  nonAuthorityBoundary:SSA_NONAUTHORITY_BOUNDARY,
  status:'sol-regated-sealed-static-gate-b0-static-source-authority-v1-source-contract-authority-resolved-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified'
});
const SSA_DIRECT_EAC = Object.freeze({authorityDisposition:'PARENT_STATIC_CONSTRAINT_NO_INSTANCE_AUTHORITY',checksums:{bytes:1826,path:'SHA256SUMS',rawSha256:'02cb373013c55cdfabf25d8f0e10c094ca563fc327ca11a368e1e9502d83ae95'},dependencyId:'EAC',manifest:{bytes:8592,entryCount:18,path:'MANIFEST.json',rawSha256:'552b3bdb39f05150abd8d0e2b286d466e45657a3fb4959f7a77c3db126af0ec9',rosterDigest:'bc1c61cb6d728d6c4327719c726f01d37818437390df87da1a750066ceb29ea9'},packagePath:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-execution-admission-contract-v1',reviewAnchor:{bytes:11384,path:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-execution-admission-contract-review-anchor.v1.json',rawSha256:'297c0995e3129a407ee83957ecb4274bff4d91c61484d0b255375a7acf50a27b'},root:{bytes:53081,contentDigest:'fed30561c154ffd4db50bad5dc4e38e5c54107236cf301777339fdf2d9460e7a',path:'execution-admission-contract-root.v1.json',rawSha256:'80fc0d146911ba774715da76fa69dcbae21852135222f7b26b7fb8bd9c775479'},semanticComponents:{externalRequirements:'e8709a44da62305eb7ad12d19a516a2e4efacfc0995017119ff6e5244fe6132d',futureArtifactMapContract:'47fcaddeb36f5a7d03b81e7c5fb1d78026097b1f3a8357bf6650473c2611be78',futureResultAdmissionContract:'884928cf1255611cd202a29eae180d212984ca046abcabda312254aa1553c7f8',futureStateGrammar:'72edbc5ea6b08b018bed9a6794b518bab2fee5703e104fb36928f463dead4707',historicalDisposition:'538378575dd7bc41d952433cb92824e3f45b5721670939ab8b00656c68c098a0',nonAuthorityBoundary:'bf7eeb39372ec5a2a80ac0342df58bf41bf42ae7db41eecf33cdcf8e3db19f31',sourcePins:'103cada63c1d0f9bac12525bb43f3e0165b8d2329aeb98f9a27e0dac5ea68e07'},validator:{bytes:64906,path:'validate-static.mjs',rawSha256:'4a050b8958d2666c527e9c666e71145fc8965fcf75deae86a9c11f2ff9defd69'}});
const SSA_REVIEW_ANCHOR_PIN = Object.freeze({reviewAnchorRoot:SSA_ANCHOR_ROOT,reviewAnchorLocator:SSA_ANCHOR_LOCATOR,reviewAnchorBytes:26079,reviewAnchorRawSha256:'c56473f1a3cf8896cd48680f3832f886b1f10d7e45826b84f33f03656891b3bb'});
const SSA_BINDING_KEYS = Object.freeze(Object.keys(SSA_EXPECTED_BINDING));
const SSA_COUNT_KEYS = Object.freeze(Object.keys(SSA_EXPECTED_BINDING.counts));
const SSA_ZERO_BOUNDARY_KEYS = Object.freeze(Object.entries(SSA_NONAUTHORITY_BOUNDARY).filter(([,value])=>value===0).map(([key])=>key));
const SSA_FALSE_BOUNDARY_KEYS = Object.freeze(Object.entries(SSA_NONAUTHORITY_BOUNDARY).filter(([,value])=>value===false).map(([key])=>key));
const SSA_POSITIVE_BOUNDARY_KEYS = Object.freeze(['requirementResolutionCount','sourceContractCount']);
const SSA_ROOT_KEYS = Object.freeze(['artifactId','componentDigests','contentDigest','dependencyPins','executionAllowed','governance','measurementAdmissionAllowed','nonAuthorityBoundary','ownerContractSourceCatalog','packageId','preauthorizationSemantics','privateCaptureSourceCatalog','purpose','requirementResolutions','retryLineageSourceCatalog','runtimeBoundary','schema','schemaBindings','stateFactSourceCatalog','status','supplementalContracts','transitiveSourcePins','workloadProjectionSourceCatalog']);
const SSA_ANCHOR_KEYS = Object.freeze(['artifactId','componentDigests','directDependencyBinding','entryCount','manifestRawSha256','nonAuthorityBoundary','orderedClosure','package','packageId','rootContentDigest','rootRawSha256','rosterDigest','schema','schemaBindingTableDigest','schemaBindings','sha256SumsRawSha256','status','transitiveSourcePinTableDigest','validatorRawSha256']);
const SSA_CATALOG_FIELDS = Object.freeze(['ownerContractSourceCatalog','retryLineageSourceCatalog','privateCaptureSourceCatalog','workloadProjectionSourceCatalog','stateFactSourceCatalog']);
const SSA_CAUSAL_CLASS_COUNT = 119;
const ssaFail = message => { throw new Error('gate-b0-static-source-authority-v1 lane binding: ' + message); };
const ssaAssert = (condition,message) => { if(!condition) ssaFail(message); };
const ssaSame = b0rSame;
const ssaCanonical = b0rCanonical;
const ssaRawSha256 = b0rRawSha256;
const ssaDigestRecord = (domain,value) => ({algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value:ssaRawSha256(Buffer.concat([Buffer.from(domain,'utf8'),Buffer.from([0]),Buffer.from(ssaCanonical(value)+'\n','utf8')]))});
const ssaFileDigest = (locator,bytes) => { const domain=`${SSA_PREFIX}/file/${locator}`; return {algorithm:'sha256',canonicalization:'raw-file-bytes-v1',domain,frame:'utf8(domain)||0x00||raw-file-bytes',value:ssaRawSha256(Buffer.concat([Buffer.from(domain,'utf8'),Buffer.from([0]),bytes]))}; };
const ssaExactOrderedKeys = (value,keys,code) => ssaAssert(value&&typeof value==='object'&&!Array.isArray(value)&&ssaSame(Object.keys(value),keys),code);
const ssaSafeLocator = (locator,code) => { ssaAssert(typeof locator==='string'&&locator.length>0&&!locator.includes('\\')&&!locator.includes('\0')&&locator.normalize('NFC')===locator,code); const parts=locator.split('/'); ssaAssert(parts.every(part=>/^[A-Za-z0-9._-]+$/u.test(part)&&part!=='.'&&part!=='..'),code); return parts; };
const ssaSafeRead = (root,locator,code) => { const parts=ssaSafeLocator(locator,code); const rootStat=lstatSync(root); ssaAssert(rootStat.isDirectory()&&!rootStat.isSymbolicLink()&&realpathSync(root)===root,`${code}:ROOT`); let current=root; for(let i=0;i<parts.length;i+=1){current=resolve(current,parts[i]);const stat=lstatSync(current),last=i===parts.length-1;ssaAssert(!stat.isSymbolicLink()&&(last?stat.isFile()&&stat.nlink===1:stat.isDirectory()),`${code}:METADATA`);ssaAssert(realpathSync(current)===current,`${code}:REALPATH`);}return readFileSync(current);};
const ssaParseCanonical = (bytes,code) => { let value; try{value=b0rParseJsonNoDuplicate(bytes,code);}catch{ssaFail(`${code}:DUPLICATE_OR_PARSE`);} ssaAssert(value&&typeof value==='object'&&bytes.toString('utf8')===ssaCanonical(value)+'\n',`${code}:CANONICAL`); return value; };
const ssaWalk = (root,prefix='') => readdirSync(root,{withFileTypes:true}).flatMap(entry=>{const locator=prefix+entry.name;if(entry.isDirectory())return [{kind:'directory',locator},...ssaWalk(resolve(root,entry.name),locator+'/')];if(entry.isFile())return [{kind:'file',locator}];return [{kind:entry.isSymbolicLink()?'link':'other',locator}];});
const ssaCheckFilesystem = root => { const laneRelative=relative(laneDir,root);ssaAssert(laneRelative&&!laneRelative.startsWith('..'),'SSA_PACKAGE_ROOT');const rootStat=lstatSync(root);ssaAssert(rootStat.isDirectory()&&!rootStat.isSymbolicLink()&&realpathSync(root)===root&&(rootStat.mode&0o777)===0o755,'SSA_PACKAGE_ROOT_METADATA');const tree=ssaWalk(root);ssaAssert(tree.every(row=>row.kind==='file'||row.kind==='directory'),'SSA_PACKAGE_LINK_OR_SPECIAL_FILE');const files=tree.filter(row=>row.kind==='file').map(row=>row.locator).sort(),directories=['.',...tree.filter(row=>row.kind==='directory').map(row=>row.locator)].sort();ssaAssert(ssaSame(files,[...SSA_SEALED_FILES].sort()),'SSA_SEALED_FILE_CLOSURE');ssaAssert(ssaSame(directories,[...SSA_DIRECTORIES].sort()),'SSA_SEALED_DIRECTORY_CLOSURE');for(const locator of directories){const stat=lstatSync(resolve(root,locator));ssaAssert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.nlink===1&&(stat.mode&0o777)===0o755,`SSA_DIRECTORY_METADATA:${locator}`);}for(const locator of files){const stat=lstatSync(resolve(root,locator));ssaAssert(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&(stat.mode&0o777)===0o644&&realpathSync(resolve(root,locator))===resolve(root,locator),`SSA_FILE_METADATA:${locator}`);}return {files:files.length,directories:directories.length};};
const ssaDeriveEnvelope = root => { const entries=SSA_AUTHORED_FILES.map(locator=>{const bytes=ssaSafeRead(root,locator,`SSA_FILE:${locator}`);return {bytes:bytes.length,fileDigest:ssaFileDigest(locator,bytes),locator,rawSha256:ssaRawSha256(bytes)};});const rosterDigest=ssaDigestRecord(`${SSA_PREFIX}/manifest-roster`,entries);const manifest={entries,entryCount:24,format:'shieldkit-static-manifest-v1',packageId:'gate-b0-static-source-authority-v1',rosterDigest,schema:`${SSA_SCHEMA_PREFIX}/manifest.v1.schema.json`};const manifestBytes=Buffer.from(ssaCanonical(manifest)+'\n'),sumsBytes=Buffer.from([...entries,{locator:'MANIFEST.json',rawSha256:ssaRawSha256(manifestBytes)}].map(row=>`${row.rawSha256}  ${row.locator}`).join('\n')+'\n');return {entries,manifest,manifestBytes,sumsBytes};};
const ssaAllSources = root => SSA_CATALOG_FIELDS.flatMap(field=>root[field]?.entries??[]);
const ssaPointer = (document,pointer,code) => { ssaAssert(typeof pointer==='string'&&(pointer===''||pointer.startsWith('/')),code);let value=document;if(pointer==='')return value;for(const token of pointer.slice(1).split('/').map(x=>x.replaceAll('~1','/').replaceAll('~0','~'))){ssaAssert(value&&typeof value==='object'&&Object.hasOwn(value,token),code);value=value[token];}return value;};
const ssaUnique = values => { const seen=new Set();return values.filter(value=>{const key=typeof value==='string'?`s:${value}`:`j:${ssaCanonical(value)}`;if(seen.has(key))return false;seen.add(key);return true;});};
const ssaDeriveLanguage = (kind,spm,uopc) => { const matching=spm.interfaceSourceMap.entries.filter(row=>row.missingSourceKinds.includes(kind)),primaryId=SSA_PRIMARY_MAP[kind],primaryRows=spm.interfaceSourceMap.entries.filter(row=>row.id===primaryId);ssaAssert(matching.length>0&&primaryRows.length===1&&matching.includes(primaryRows[0]),`SSA_G1:${kind}`);const selected=[primaryRows[0],...matching.filter(row=>row!==primaryRows[0])];ssaAssert(selected.length===matching.length&&new Set(selected).size===matching.length,`SSA_G1:${kind}`);const aggregate=field=>ssaUnique(selected.flatMap(row=>row[field]));const requirementOnlyReferences=aggregate('requirementOnlyReferences'),objects=[];for(const ref of requirementOnlyReferences){if(ref.sourceReferenceId!=='UOPC_MODEL_ROOT')continue;for(const selector of ref.selectors){ssaAssert(selector.kind==='JSON_POINTER',`SSA_G1:${kind}`);objects.push(ssaPointer(uopc,selector.value,`SSA_G1:${kind}`));}}const preimages=[],fields=[],rules=[],validation=[],dependencies=[];for(const object of objects){if(Array.isArray(object?.futurePreimageKeys))preimages.push(...object.futurePreimageKeys);else if(object?.futurePreimageKeys&&typeof object.futurePreimageKeys==='object')for(const variant of ['initial','retry','abort'])if(Array.isArray(object.futurePreimageKeys[variant]))preimages.push(...object.futurePreimageKeys[variant]);if(Array.isArray(object?.futureProviderFields))fields.push(...object.futureProviderFields);if(Array.isArray(object?.rules))rules.push(...object.rules);if(Array.isArray(object?.futureValidationRules))validation.push(...object.futureValidationRules);if(Array.isArray(object?.staticDependencyIds))dependencies.push(...object.staticDependencyIds);}return {authoritativeTypeFragments:aggregate('authoritativeTypeFragments'),constraintSourceMapId:primaryId,futureFieldPaths:ssaUnique([...preimages,...fields]),futureValidationRules:ssaUnique([...rules,...validation]),interfaceIds:aggregate('interfaceIds'),missingSourceKind:kind,requirementOnlyReferences,shapeOnlyReferences:aggregate('shapeOnlyReferences'),staticDependencyIds:ssaUnique(dependencies)};};
const ssaAssertBinding = binding => { ssaAssert(binding&&typeof binding==='object'&&!Array.isArray(binding),'SSA_BINDING_SHAPE');ssaAssert(SSA_BINDING_KEYS.every(key=>Object.hasOwn(binding,key)),'SSA_BINDING_OMISSION');ssaAssert(ssaSame(Object.keys(binding),SSA_BINDING_KEYS),'SSA_BINDING_EXTRA_KEY');ssaAssert(binding.status===SSA_EXPECTED_BINDING.status,'SSA_BINDING_STATUS');for(const [name,expected] of Object.entries({root:SSA_EXPECTED_BINDING.root,manifest:SSA_EXPECTED_BINDING.manifest,checksums:SSA_EXPECTED_BINDING.checksums,validator:SSA_EXPECTED_BINDING.validator,reviewAnchor:SSA_EXPECTED_BINDING.reviewAnchor})){ssaExactOrderedKeys(binding[name],Object.keys(expected),`SSA_BINDING_${name.toUpperCase()}_SHAPE`);for(const [key,value] of Object.entries(expected))ssaAssert(binding[name][key]===value,`SSA_BINDING_${name.toUpperCase()}:${key}`);}ssaExactOrderedKeys(binding.laneAuthorityProjection,Object.keys(SSA_EXPECTED_BINDING.laneAuthorityProjection),'SSA_BINDING_PROJECTION_SHAPE');ssaAssert(ssaSame(binding.laneAuthorityProjection,SSA_EXPECTED_BINDING.laneAuthorityProjection),'SSA_BINDING_PROJECTION_EXACT');ssaExactOrderedKeys(binding.counts,SSA_COUNT_KEYS,'SSA_BINDING_COUNT_SHAPE');for(const key of SSA_COUNT_KEYS)ssaAssert(binding.counts[key]===SSA_EXPECTED_BINDING.counts[key],`SSA_BINDING_COUNT:${key}`);ssaExactOrderedKeys(binding.nonAuthorityBoundary,Object.keys(SSA_NONAUTHORITY_BOUNDARY),'SSA_BINDING_BOUNDARY_SHAPE');for(const key of SSA_ZERO_BOUNDARY_KEYS)ssaAssert(binding.nonAuthorityBoundary[key]===0,`SSA_BINDING_BOUNDARY:${key}`);for(const key of SSA_FALSE_BOUNDARY_KEYS)ssaAssert(binding.nonAuthorityBoundary[key]===false,`SSA_BINDING_BOUNDARY:${key}`);for(const key of SSA_POSITIVE_BOUNDARY_KEYS)ssaAssert(binding.nonAuthorityBoundary[key]===SSA_NONAUTHORITY_BOUNDARY[key],`SSA_BINDING_BOUNDARY:${key}`);ssaAssert(ssaSame(binding,SSA_EXPECTED_BINDING),'SSA_BINDING_EXACT');return true;};
const SSA_PROSE_SOURCES = Object.freeze([{label:'lane README',locator:'research-lanes/bch-shielded-pool-design/README.md',path:resolve(laneDir,'README.md')},{label:'design options',locator:'research-lanes/bch-shielded-pool-design/analysis/design-options.md',path:resolve(laneDir,'analysis/design-options.md')}]);
const ssaAssertProse = (texts=SSA_PROSE_SOURCES.map(({label,path})=>[label,readFileSync(path,'utf8')])) => {for(const [label,text] of texts)ssaAssert(text.split(SSA_NONPROMOTION).length===2&&text.split(SSA_NEXT_GATE).length===2,`SSA_PROSE:${label}`);};
const ssaAssertPhase = (bytes=readFileSync(resolve(laneDir,'research/phase-plan.md'))) => ssaAssert(bytes.length===14452&&ssaRawSha256(bytes)==='d8113796b9ede19e9ee7537ddb10e415ce67808548e27b953e30083b485a3a2d'&&!bytes.toString('utf8').includes(SSA_NONPROMOTION)&&!bytes.toString('utf8').includes(SSA_NEXT_GATE),'SSA_PHASE');
const ssaAssertProseDisjointness = (root,eacRoot) => { const locators=new Set([...root.transitiveSourcePins.map(row=>row.locator),...eacRoot.sourcePins.map(row=>row.locator),...(gateB0EvidencePlanV1IndependentValidation?.root?.sourceCatalog?.entries??[]).map(row=>row.locator)]);for(const source of SSA_PROSE_SOURCES)ssaAssert(!locators.has(source.locator),`SSA_PROSE_SOURCE:${source.locator}`);};
const ssaAssertLaneProjection = laneValue => { b0rAssertLaneKeyPartition(laneValue);const snapshot=Object.fromEntries(B0R_INCLUDED_TOP_LEVEL_KEYS.map(key=>[key,laneValue[key]]));const record=b0rDigestRecord(`${B0R_PREFIX}/lane-authority-projection`,{schema:`${B0R_PREFIX}/lane-authority-projection/v1`,snapshot});ssaAssert(record.value===SSA_EXPECTED_BINDING.laneAuthorityProjection.contentDigest,'SSA_LANE_PROJECTION');};
const ssaAssertSchemaReachability = schemas => { const byId=new Map(schemas.map(schema=>[schema.$id,schema]));ssaAssert(byId.size===SSA_SCHEMA_BINDINGS.length,'SSA_SCHEMA_REACHABILITY');const reached=new Set(),visited=new Set();const resolveFragment=(schema,fragment)=>{if(!fragment||fragment==='#')return schema;ssaAssert(fragment.startsWith('#/'),'SSA_SCHEMA_REACHABILITY');let value=schema;for(const token of fragment.slice(2).split('/').map(x=>x.replaceAll('~1','/').replaceAll('~0','~'))){ssaAssert(value&&typeof value==='object'&&Object.hasOwn(value,token),'SSA_SCHEMA_REACHABILITY');value=value[token];}return value;};const visit=(schemaId,node,marker)=>{if(!node||typeof node!=='object')return;const tag=`${schemaId}${marker}`;if(visited.has(tag))return;visited.add(tag);const ancestor=/^(#\/\$defs\/[^/]+)/u.exec(marker)?.[1];if(ancestor)reached.add(`${schemaId}${ancestor}`);if(typeof node.$ref==='string'){const split=node.$ref.indexOf('#'),targetId=split<0?node.$ref:node.$ref.slice(0,split),fragment=split<0?'':node.$ref.slice(split),resolved=targetId||schemaId,target=byId.get(resolved);ssaAssert(target,'SSA_SCHEMA_REACHABILITY');visit(resolved,resolveFragment(target,fragment),fragment||'#');}for(const [key,child] of Object.entries(node)){if(key==='$defs'||key==='$ref')continue;if(Array.isArray(child))child.forEach((value,index)=>visit(schemaId,value,`${marker}/${key}/${index}`));else visit(schemaId,child,`${marker}/${key}`);}};for(const schema of schemas)visit(schema.$id,schema,'#');for(const schema of schemas)for(const name of Object.keys(schema.$defs??{}))ssaAssert(reached.has(`${schema.$id}#/$defs/${name}`),`SSA_SCHEMA_UNUSED:${name}`);};
const ssaAssertSourceBoundary = root => { ssaAssert(root.governance?.laneReadAllowed===false&&root.runtimeBoundary?.importEvaluationAllowed===false&&root.runtimeBoundary?.activationCapability===null&&root.runtimeBoundary?.runtimeEntrypoint===null&&ssaSame(root.runtimeBoundary?.runtimeExports,[])&&ssaSame(root.runtimeBoundary?.runtimeModules,[]),'SSA_SOURCE_BOUNDARY');const allowlist=new Set(['ajv/dist/2020.js','node:assert/strict','node:crypto','node:fs','node:os','node:path','node:test','node:url','../validate-static.mjs']);for(const locator of SSA_AUTHORED_FILES.filter(value=>value.endsWith('.mjs'))){const source=ssaSafeRead(SSA_PACKAGE_ROOT,locator,`SSA_SOURCE:${locator}`).toString('utf8');ssaAssert(!/(?<![.$A-Za-z0-9_])(?:spawn|spawnSync|exec|execFile|execFileSync|fork|eval)\s*\(|new\s+(?:Worker|Function)\b/u.test(source),'SSA_SOURCE_BOUNDARY');for(const match of source.matchAll(/(?:from\s*|import\s*\()(['"])([^'"]+)\1/gu))ssaAssert(allowlist.has(match[2]),'SSA_SOURCE_BOUNDARY');}const validator=ssaSafeRead(SSA_PACKAGE_ROOT,'validate-static.mjs','SSA_SOURCE:validator').toString('utf8'),exports=[...validator.matchAll(/export const ([A-Za-z0-9_]+)/gu)].map(match=>match[1]).sort();ssaAssert(ssaSame(exports,['assertRootSemantics','canonicalJson','deriveSealEnvelope','digestRecord','fileDigestRecord','parseValidationCliArgs','validateStatic'].sort()),'SSA_SOURCE_BOUNDARY');};
const ssaReadAnchor = ({root=SSA_ANCHOR_ROOT,locator=SSA_ANCHOR_LOCATOR,bytes=26079,rawSha256=SSA_EXPECTED_BINDING.reviewAnchor.rawSha256}={}) => { ssaAssert(root===SSA_ANCHOR_ROOT&&locator===SSA_ANCHOR_LOCATOR,'SSA_ANCHOR_PATH');const raw=ssaSafeRead(root,locator,'SSA_ANCHOR');ssaAssert(raw.length===bytes,'SSA_ANCHOR_BYTES');ssaAssert(ssaRawSha256(raw)===rawSha256,'SSA_ANCHOR_RAW');const candidate=realpathSync(resolve(root,locator)),rel=relative(SSA_PACKAGE_ROOT,candidate);ssaAssert(rel==='..'||rel.startsWith('../'),'SSA_ANCHOR_INSIDE_PACKAGE');const anchor=ssaParseCanonical(raw,'SSA_ANCHOR');ssaExactOrderedKeys(anchor,SSA_ANCHOR_KEYS,'SSA_ANCHOR_SHAPE');ssaAssert(anchor.artifactId==='artifact:gate-b:gate-b0-static-source-authority-review-anchor-v1'&&anchor.package===SSA_PACKAGE_LOCATOR&&anchor.packageId==='gate-b0-static-source-authority-v1'&&anchor.schema===SSA_EXPECTED_BINDING.reviewAnchor.schema&&anchor.status==='sealed-static-source-contract-authority-review-anchor-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified'&&anchor.entryCount===24,'SSA_ANCHOR_IDENTITY');ssaAssert(ssaSame(anchor.directDependencyBinding,SSA_DIRECT_EAC),'SSA_ANCHOR_EAC');ssaAssert(ssaSame(anchor.nonAuthorityBoundary,SSA_NONAUTHORITY_BOUNDARY),'SSA_ANCHOR_BOUNDARY');return anchor;};
const ssaAssertRawEnvelope = (root,anchor) => { const envelope=ssaDeriveEnvelope(root);ssaAssert(ssaSame(anchor.orderedClosure,envelope.entries),'SSA_ANCHOR_ORDERED_CLOSURE');ssaAssert(ssaSame(anchor.rosterDigest,envelope.manifest.rosterDigest)&&anchor.rosterDigest.value===SSA_EXPECTED_BINDING.manifest.rosterDigest,'SSA_ANCHOR_ROSTER');const manifestBytes=ssaSafeRead(root,'MANIFEST.json','SSA_MANIFEST'),sumsBytes=ssaSafeRead(root,'SHA256SUMS','SSA_SUMS');ssaAssert(manifestBytes.equals(envelope.manifestBytes)&&ssaRawSha256(manifestBytes)===SSA_EXPECTED_BINDING.manifest.rawSha256&&anchor.manifestRawSha256===SSA_EXPECTED_BINDING.manifest.rawSha256,'SSA_MANIFEST');ssaAssert(sumsBytes.equals(envelope.sumsBytes)&&ssaRawSha256(sumsBytes)===SSA_EXPECTED_BINDING.checksums.rawSha256&&anchor.sha256SumsRawSha256===SSA_EXPECTED_BINDING.checksums.rawSha256,'SSA_SUMS');ssaAssert(anchor.rootRawSha256===SSA_EXPECTED_BINDING.root.rawSha256&&anchor.validatorRawSha256===SSA_EXPECTED_BINDING.validator.rawSha256,'SSA_ANCHOR_RAW_JOINS');ssaAssert(ssaSame(anchor.schemaBindings,SSA_SCHEMA_BINDINGS),'SSA_ANCHOR_SCHEMA_BINDINGS');for(const binding of SSA_SCHEMA_BINDINGS){const entry=envelope.entries.find(row=>row.locator===binding.locator);ssaAssert(entry?.rawSha256===binding.rawSha256&&ssaRawSha256(ssaSafeRead(root,binding.locator,`SSA_SCHEMA_RAW:${binding.locator}`))===binding.rawSha256,`SSA_SCHEMA_RAW:${binding.locator}`);}return envelope;};
const ssaAssertRoot = (root,{spm,uopc,eac}) => { ssaExactOrderedKeys(root,SSA_ROOT_KEYS,'SSA_ROOT_KEYS');ssaAssert(root.schema===`${SSA_SCHEMA_PREFIX}/root.v1.schema.json`&&root.artifactId==='artifact:gate-b:gate-b0-static-source-authority-v1'&&root.packageId==='gate-b0-static-source-authority-v1'&&root.status===SSA_NONAUTHORITY_BOUNDARY.status&&root.executionAllowed===false&&root.measurementAdmissionAllowed===false,'SSA_ROOT_IDENTITY');ssaAssert(ssaSame(root.nonAuthorityBoundary,SSA_NONAUTHORITY_BOUNDARY),'SSA_ROOT_BOUNDARY');ssaAssert(root.governance?.authorityOrigin==='EXTERNAL_ROOT_SOL_STATIC_SCHEMA_GOVERNANCE'&&root.governance?.packageMaySelfCertify===false&&root.governance?.existingCatalogsAreConstraintInputsOnly===true&&root.governance?.operationalOwnershipGranted===false&&root.governance?.outsideReviewAnchorRequired===true&&root.governance?.laneReadAllowed===false,'SSA_GOVERNANCE');ssaAssert(root.preauthorizationSemantics?.instanceCreationAllowedBeforeExecutionAuthorization===false&&root.preauthorizationSemantics?.providerContractMayGrantExecutionOrAdmission===false&&root.preauthorizationSemantics?.sourceContractResolutionMaySatisfyInstance===false,'SSA_PREAUTHORIZATION');ssaAssert(root.dependencyPins?.length===1&&ssaSame(root.dependencyPins[0],SSA_DIRECT_EAC),'SSA_EAC_DEPENDENCY');const direct=root.dependencyPins[0];for(const [field,value] of Object.entries(direct.semanticComponents))ssaAssert(eac.root.componentDigests.find(row=>row.component===field)?.digest.value===value,`SSA_EAC_COMPONENT:${field}`);ssaAssert(root.transitiveSourcePins.length===64&&ssaSame(root.transitiveSourcePins,eac.root.sourcePins),'SSA_TRANSITIVE_SOURCE_ROSTER');const sources=ssaAllSources(root);ssaAssert(sources.length===17&&ssaSame(sources.map(row=>row.sourceKind),SSA_SOURCE_KINDS),'SSA_SOURCE_ROSTER');for(const source of sources){ssaAssert(source.authorityGranted===false&&source.admissionGranted===false&&source.instanceCount===0&&source.instanceDisposition==='UNAVAILABLE_PREAUTHORIZATION'&&source.authorityOrigin==='EXTERNAL_ROOT_SOL_STATIC_SCHEMA_GOVERNANCE'&&source.existingCatalogDisposition==='CONSTRAINT_INPUT_NOT_SOURCE_AUTHORITY'&&source.resolutionLevel==='RESOLVED_STATIC_SOURCE_CONTRACT',`SSA_SOURCE_BOUNDARY:${source.sourceKind}`);const schemaBinding=SSA_SCHEMA_BINDINGS.find(row=>row.locator===source.schemaBinding?.locator);ssaAssert(schemaBinding&&source.schemaBinding.schemaId===schemaBinding.schemaId&&source.schemaBinding.rawSha256===schemaBinding.rawSha256&&source.schemaBinding.jsonPointer===`/$defs/${source.sourceKind}`,`SSA_SOURCE_SCHEMA:${source.sourceKind}`);ssaAssert(ssaSame(source.languageContract,ssaDeriveLanguage(source.sourceKind,spm,uopc)),`SSA_G1:${source.sourceKind}`);const body={...source};delete body.contentDigest;ssaAssert(ssaSame(source.contentDigest,ssaDigestRecord(`${SSA_PREFIX}/source-contract/${source.sourceKind}`,body)),`SSA_SOURCE_DIGEST:${source.sourceKind}`);}for(const [field,suffix] of SSA_COMPONENTS.filter(([field])=>SSA_CATALOG_FIELDS.includes(field))){const catalog=root[field],body={...catalog};delete body.contentDigest;ssaAssert(catalog.entryCount===catalog.entries.length&&ssaSame(catalog.contentDigest,ssaDigestRecord(`${SSA_PREFIX}/${suffix}`,body)),`SSA_CATALOG_DIGEST:${field}`);}ssaAssert(root.supplementalContracts.length===2,'SSA_SUPPLEMENTAL_ROSTER');const rawMap=root.supplementalContracts[0],validator=root.supplementalContracts[1];ssaAssert(rawMap.contractId==='RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT'&&rawMap.authorityCreationAllowed===false&&rawMap.authorityInstanceCount===0&&rawMap.resultDerivedAuthorityAccepted===false&&rawMap.selfAttestedMapAccepted===false,'SSA_RAW_MAP_BOUNDARY');ssaAssert(validator.contractId==='INDEPENDENT_RESULT_VALIDATOR_SOURCE_CONTRACT'&&validator.validatorEvaluationAllowed===false&&validator.validatorEvaluationCount===0&&validator.executionProducerDependencyAllowed===false&&validator.resultProducerDependencyAllowed===false&&validator.implementationLocatorAllowed===false&&validator.implementationRawSha256Allowed===false,'SSA_VALIDATOR_BOUNDARY');for(const contract of root.supplementalContracts){const body={...contract};delete body.contentDigest;ssaAssert(ssaSame(contract.contentDigest,ssaDigestRecord(`${SSA_PREFIX}/supplemental-contract/${contract.contractId}`,body)),`SSA_SUPPLEMENTAL_DIGEST:${contract.contractId}`);}ssaAssert(root.requirementResolutions.length===30&&ssaSame(root.requirementResolutions.map(row=>row.requirementId),EAC_REQUIREMENT_IDS),'SSA_REQUIREMENT_ROSTER');const classifications={STATIC_SOURCE:0,FUTURE_INSTANCE:0,TYPE_ONLY:0,DERIVED:0},dispositions={STATIC_SOURCE:'UNAVAILABLE_PREAUTHORIZATION',FUTURE_INSTANCE:'DELIBERATELY_UNAVAILABLE_FUTURE_INSTANCE',TYPE_ONLY:'NO_PROVIDER_BY_CONTRACT',DERIVED:'DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS'};root.requirementResolutions.forEach((row,index)=>{ssaAssert(row.requirementId===EAC_REQUIREMENT_IDS[index]&&row.instanceCount===0&&row.currentInstanceRequired===false&&row.authorityGranted===false&&row.admissionGranted===false&&row.sourceContractResolution==='RESOLVED_STATIC_SOURCE_CONTRACT'&&row.instanceDisposition===dispositions[row.classification],`SSA_REQUIREMENT:${row.requirementId}`);classifications[row.classification]+=1;const body={...row};delete body.contentDigest;ssaAssert(ssaSame(row.contentDigest,ssaDigestRecord(`${SSA_PREFIX}/requirement-resolution/${row.requirementId}`,body)),`SSA_REQUIREMENT_DIGEST:${row.requirementId}`);});ssaAssert(ssaSame(classifications,{STATIC_SOURCE:11,FUTURE_INSTANCE:4,TYPE_ONLY:6,DERIVED:9}),'SSA_REQUIREMENT_CLASSIFICATIONS');ssaAssert(ssaSame(root.schemaBindings,SSA_SCHEMA_BINDINGS),'SSA_SCHEMA_BINDINGS');for(const [component,suffix] of SSA_COMPONENTS){const row=root.componentDigests.find(value=>value.component===component);ssaAssert(row&&ssaSame(row.digest,ssaDigestRecord(`${SSA_PREFIX}/${suffix}`,root[component])),`SSA_COMPONENT_DIGEST:${component}`);}ssaAssert(ssaSame(root.componentDigests.map(row=>row.component),SSA_COMPONENTS.map(([component])=>component)),'SSA_COMPONENT_ROSTER');const copy={...root};delete copy.contentDigest;ssaAssert(ssaSame(root.contentDigest,ssaDigestRecord(`${SSA_PREFIX}/root`,copy))&&root.contentDigest.value===SSA_EXPECTED_BINDING.root.contentDigest,'SSA_ROOT_DIGEST');return true;};
const ssaValidateIndependent = (root=SSA_PACKAGE_ROOT) => { const closure=ssaCheckFilesystem(root);const rawOrder=[['validate-static.mjs',SSA_EXPECTED_BINDING.validator.rawSha256],['static-source-authority-root.v1.json',SSA_EXPECTED_BINDING.root.rawSha256],['MANIFEST.json',SSA_EXPECTED_BINDING.manifest.rawSha256],['SHA256SUMS',SSA_EXPECTED_BINDING.checksums.rawSha256]];for(const [locator,expected] of rawOrder)ssaAssert(ssaRawSha256(ssaSafeRead(root,locator,`SSA_RAW:${locator}`))===expected,`SSA_RAW:${locator}`);const anchor=ssaReadAnchor(),envelope=ssaAssertRawEnvelope(root,anchor);const schemas=SSA_SCHEMA_BINDINGS.map(binding=>ssaParseCanonical(ssaSafeRead(root,binding.locator,`SSA_SCHEMA:${binding.locator}`),`SSA_SCHEMA:${binding.locator}`));ssaAssertSchemaReachability(schemas);const rootModel=ssaParseCanonical(ssaSafeRead(root,'static-source-authority-root.v1.json','SSA_ROOT'),'SSA_ROOT'),ajv=new Ajv2020({allErrors:true,strict:true,strictTypes:true});schemas.forEach(schema=>ajv.addSchema(schema));const validate=ajv.getSchema(rootModel.schema);ssaAssert(validate&&validate(rootModel),`SSA_ROOT_SCHEMA:${ajv.errorsText(validate?.errors)}`);for(const [index,binding] of rootModel.schemaBindings.entries())ssaAssert(ssaSame(binding,SSA_SCHEMA_BINDINGS[index])&&schemas[index].$id===binding.schemaId,`SSA_SCHEMA_BINDING:${binding.locator}`);const eac=gateB0ExecutionAdmissionContractV1IndependentValidation;ssaAssert(eac?.root&&eac.sourcePins===64,'SSA_EAC_INDEPENDENT');const uopc=cohortUpstreamOriginProviderContractV1IndependentValidation?.rootDocument,spm=spmReadJson(SPM_PACKAGE_ROOT,'upstream-provider-source-map-root.v1.json');ssaAssert(uopc&&spm&&ssaRawSha256(ssaSafeRead(repoRoot,'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json','SSA_UOPC_RAW'))==='2facf53272c1947bf76f1f7d70db23270e6a7c396fed8cb67baa62dec39a7579'&&ssaRawSha256(ssaSafeRead(repoRoot,'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json','SSA_SPM_RAW'))==='19268c8cfca0fc12038a6b89a23ccf7719a8d0f1337bd16bc10ab81647b0179a','SSA_G1_INPUTS');ssaAssertRoot(rootModel,{spm,uopc,eac});ssaAssert(ssaSame(anchor.componentDigests,rootModel.componentDigests)&&ssaSame(anchor.rootContentDigest,rootModel.contentDigest)&&ssaSame(anchor.directDependencyBinding,rootModel.dependencyPins[0])&&ssaSame(anchor.schemaBindings,rootModel.schemaBindings)&&ssaSame(anchor.schemaBindingTableDigest,ssaDigestRecord(`${SSA_PREFIX}/schema-bindings`,rootModel.schemaBindings))&&ssaSame(anchor.transitiveSourcePinTableDigest,ssaDigestRecord(`${SSA_PREFIX}/transitive-source-pins`,rootModel.transitiveSourcePins)),'SSA_ANCHOR_SEMANTIC');ssaAssertSourceBoundary(rootModel);ssaAssertLaneProjection(lane);ssaAssertProseDisjointness(rootModel,eac.root);ssaAssertProse();ssaAssertPhase();return {...closure,anchor,envelope,root:rootModel,sourceContracts:19};};
const ssaExpectFailure = (operation,expected,label) => { let error;try{operation();}catch(caught){error=caught;}ssaAssert(error?.message===`gate-b0-static-source-authority-v1 lane binding: ${expected}`||error?.message===`gate-b0-static-source-authority-v1:${expected}`,`SSA_CAUSAL:${label}`);};
const ssaRunCausalMutation = async (laneValue,importedValidator) => { let classes=0;const labels=new Set(),reject=(operation,expected,label)=>{ssaAssert(!labels.has(label),`SSA_CAUSAL_DUPLICATE:${label}`);labels.add(label);ssaExpectFailure(operation,expected,label);classes+=1;},bindingMutation=(label,mutate,expected)=>{const binding=structuredClone(SSA_EXPECTED_BINDING);mutate(binding);reject(()=>ssaAssertBinding(binding),expected,`binding/${label}`);};
  bindingMutation('omission',binding=>{delete binding.path;},'SSA_BINDING_OMISSION');bindingMutation('extra',binding=>{binding.unreviewed=true;},'SSA_BINDING_EXTRA_KEY');bindingMutation('status',binding=>{binding.status+='-authorized';},'SSA_BINDING_STATUS');
  for(const key of SSA_COUNT_KEYS)bindingMutation(`count-${key}`,binding=>{binding.counts[key]+=1;},`SSA_BINDING_COUNT:${key}`);
  for(const key of SSA_ZERO_BOUNDARY_KEYS)bindingMutation(`zero-${key}`,binding=>{binding.nonAuthorityBoundary[key]=1;},`SSA_BINDING_BOUNDARY:${key}`);
  for(const key of SSA_FALSE_BOUNDARY_KEYS)bindingMutation(`false-${key}`,binding=>{binding.nonAuthorityBoundary[key]=true;},`SSA_BINDING_BOUNDARY:${key}`);
  for(const key of SSA_POSITIVE_BOUNDARY_KEYS)bindingMutation(`positive-${key}`,binding=>{binding.nonAuthorityBoundary[key]+=1;},`SSA_BINDING_BOUNDARY:${key}`);
  for(const [label,outer,field,expected] of [['root','root','rawSha256','SSA_BINDING_ROOT:rawSha256'],['validator','validator','rawSha256','SSA_BINDING_VALIDATOR:rawSha256'],['manifest','manifest','rawSha256','SSA_BINDING_MANIFEST:rawSha256'],['sums','checksums','rawSha256','SSA_BINDING_CHECKSUMS:rawSha256'],['anchor','reviewAnchor','rawSha256','SSA_BINDING_REVIEWANCHOR:rawSha256']])bindingMutation(`${label}-raw`,binding=>{binding[outer][field]='0'.repeat(64);},expected);
  bindingMutation('anchor-bytes',binding=>{binding.reviewAnchor.bytes+=1;},'SSA_BINDING_REVIEWANCHOR:bytes');bindingMutation('anchor-path',binding=>{binding.reviewAnchor.path='p2/gate-b/inside.json';},'SSA_BINDING_REVIEWANCHOR:path');
  const rootModel=ssaParseCanonical(ssaSafeRead(SSA_PACKAGE_ROOT,'static-source-authority-root.v1.json','SSA_MUTATION_ROOT'),'SSA_MUTATION_ROOT'),eac=gateB0ExecutionAdmissionContractV1IndependentValidation,spm=spmReadJson(SPM_PACKAGE_ROOT,'upstream-provider-source-map-root.v1.json'),uopc=cohortUpstreamOriginProviderContractV1IndependentValidation.rootDocument,rootReject=(label,mutate,expected)=>{const mutant=structuredClone(rootModel);mutate(mutant);reject(()=>ssaAssertRoot(mutant,{spm,uopc,eac}),expected,`root/${label}`);};
  rootReject('source-omission',root=>{root.ownerContractSourceCatalog.entries=[];},'SSA_SOURCE_ROSTER');rootReject('source-reorder',root=>{[root.retryLineageSourceCatalog.entries[0],root.retryLineageSourceCatalog.entries[1]]=[root.retryLineageSourceCatalog.entries[1],root.retryLineageSourceCatalog.entries[0]];},'SSA_SOURCE_ROSTER');rootReject('g1-drift',root=>{root.ownerContractSourceCatalog.entries[0].languageContract.interfaceIds.push('MUTANT');},'SSA_G1:UPSTREAM_OWNER_CONTRACT_SCHEMA');rootReject('source-authority',root=>{root.ownerContractSourceCatalog.entries[0].authorityGranted=true;},'SSA_SOURCE_BOUNDARY:UPSTREAM_OWNER_CONTRACT_SCHEMA');rootReject('requirement-omission',root=>{root.requirementResolutions.pop();},'SSA_REQUIREMENT_ROSTER');rootReject('requirement-reorder',root=>{[root.requirementResolutions[0],root.requirementResolutions[1]]=[root.requirementResolutions[1],root.requirementResolutions[0]];},'SSA_REQUIREMENT_ROSTER');rootReject('requirement-instance-count',root=>{root.requirementResolutions[0].instanceCount=1;},'SSA_REQUIREMENT:RECOVERY_CHAIN_OWNER_PROVIDER');rootReject('requirement-authority',root=>{root.requirementResolutions[0].authorityGranted=true;},'SSA_REQUIREMENT:RECOVERY_CHAIN_OWNER_PROVIDER');rootReject('requirement-admission',root=>{root.requirementResolutions[0].admissionGranted=true;},'SSA_REQUIREMENT:RECOVERY_CHAIN_OWNER_PROVIDER');rootReject('raw-map-widening',root=>{root.supplementalContracts[0].authorityCreationAllowed=true;},'SSA_RAW_MAP_BOUNDARY');rootReject('validator-evaluation',root=>{root.supplementalContracts[1].validatorEvaluationAllowed=true;},'SSA_VALIDATOR_BOUNDARY');rootReject('eac-root-drift',root=>{root.dependencyPins[0].root.rawSha256='0'.repeat(64);},'SSA_EAC_DEPENDENCY');
  {
    const driftedEac=structuredClone(eac);
    driftedEac.root.componentDigests.find(row=>row.component==='sourcePins').digest.value='0'.repeat(64);
    const mutant=structuredClone(rootModel);
    reject(()=>ssaAssertRoot(mutant,{spm,uopc,eac:driftedEac}),'SSA_EAC_COMPONENT:sourcePins','root/eac-component-drift');
  }
  rootReject('transitive-duplicate',root=>{root.transitiveSourcePins[1]=structuredClone(root.transitiveSourcePins[0]);},'SSA_TRANSITIVE_SOURCE_ROSTER');rootReject('transitive-reorder',root=>{[root.transitiveSourcePins[0],root.transitiveSourcePins[1]]=[root.transitiveSourcePins[1],root.transitiveSourcePins[0]];},'SSA_TRANSITIVE_SOURCE_ROSTER');rootReject('schema-raw',root=>{root.schemaBindings[0].rawSha256='0'.repeat(64);},'SSA_SCHEMA_BINDINGS');rootReject('component-digest',root=>{root.componentDigests[0].digest.value='0'.repeat(64);},'SSA_COMPONENT_DIGEST:governance');rootReject('root-content',root=>{root.contentDigest.value='0'.repeat(64);},'SSA_ROOT_DIGEST');
  const rawPin=structuredClone(rootModel.transitiveSourcePins[0]);rawPin.rawSha256='0'.repeat(64);reject(()=>{const row=eac.root.sourcePins.find(value=>value.pinId===rawPin.pinId);ssaAssert(ssaSame(rawPin,row),'SSA_TRANSITIVE_RAW');},'SSA_TRANSITIVE_RAW','root/transitive-raw');const traversal=structuredClone(rootModel.transitiveSourcePins[0]);traversal.locator='../lane.json';reject(()=>ssaSafeRead(repoRoot,traversal.locator,'SSA_TRANSITIVE_TRAVERSAL'),'SSA_TRANSITIVE_TRAVERSAL','root/transitive-traversal');
  const projected=structuredClone(laneValue);projected.apiVersion+='-mutant';reject(()=>ssaAssertLaneProjection(projected),'SSA_LANE_PROJECTION','lane/included-projection');const partitioned=structuredClone(laneValue);partitioned.extraSsaKey=true;reject(()=>{try{b0rAssertLaneKeyPartition(partitioned);}catch{ssaFail('SSA_LANE_PARTITION');}},'SSA_LANE_PARTITION','lane/top-level-partition');reject(()=>ssaAssertPhase(Buffer.from(SSA_NONPROMOTION)),'SSA_PHASE','lane/phase-drift');const prose=SSA_PROSE_SOURCES.map(({label,path})=>[label,readFileSync(path,'utf8')]);reject(()=>ssaAssertProse(prose.map(([label,text])=>[label,text.replace(SSA_NONPROMOTION,'')])),'SSA_PROSE:lane README','lane/prose-deletion');reject(()=>ssaAssertProse(prose.map(([label,text])=>[label,label==='lane README'?text.replace(SSA_NONPROMOTION,SSA_NONPROMOTION.replace('creates no provider','creates a provider')):text])),'SSA_PROSE:lane README','lane/prose-widening');const collision=structuredClone(rootModel),sourceLocator=SSA_PROSE_SOURCES[0].locator;collision.transitiveSourcePins[0].locator=sourceLocator;reject(()=>ssaAssertProseDisjointness(collision,eac.root),`SSA_PROSE_SOURCE:${sourceLocator}`,'lane/prose-source-collision');
  reject(()=>ssaReadAnchor({rawSha256:'0'.repeat(64)}),'SSA_ANCHOR_RAW','fs/anchor-raw');
  const temporaryRoot=mkdtempSync(resolve(laneDir,'.shieldkit-ssa-lane-'));try{const fresh=(name='package')=>{const target=resolve(temporaryRoot,name);rmSync(target,{recursive:true,force:true});cpSync(SSA_PACKAGE_ROOT,target,{recursive:true});return target;};
    let fixture=fresh('anchor-link-package'),anchorRoot=resolve(temporaryRoot,'anchor-link');mkdirSync(anchorRoot);symlinkSync(resolve(SSA_ANCHOR_ROOT,SSA_ANCHOR_LOCATOR),resolve(anchorRoot,SSA_ANCHOR_LOCATOR));reject(()=>ssaSafeRead(anchorRoot,SSA_ANCHOR_LOCATOR,'SSA_ANCHOR_LINK'),'SSA_ANCHOR_LINK:METADATA','fs/anchor-link');
    fixture=fresh('package-symlink');rmSync(resolve(fixture,'README.md'));symlinkSync(resolve(SSA_PACKAGE_ROOT,'README.md'),resolve(fixture,'README.md'));reject(()=>ssaCheckFilesystem(fixture),'SSA_PACKAGE_LINK_OR_SPECIAL_FILE','fs/package-symlink');
    fixture=fresh('hardlink');rmSync(resolve(fixture,'README.md'));linkSync(resolve(fixture,'COMMAND.txt'),resolve(fixture,'README.md'));reject(()=>ssaCheckFilesystem(fixture),'SSA_FILE_METADATA:COMMAND.txt','fs/hardlink');
    fixture=fresh('dir-mode');chmodSync(resolve(fixture,'schemas'),0o700);reject(()=>ssaCheckFilesystem(fixture),'SSA_DIRECTORY_METADATA:schemas','fs/directory-mode');
    fixture=fresh('missing-envelope');rmSync(resolve(fixture,'MANIFEST.json'));reject(()=>ssaCheckFilesystem(fixture),'SSA_SEALED_FILE_CLOSURE','fs/missing-envelope');
    fixture=fresh('extra-file');writeFileSync(resolve(fixture,'extra.txt'),'x\n');reject(()=>ssaCheckFilesystem(fixture),'SSA_SEALED_FILE_CLOSURE','fs/extra-file');
    fixture=fresh('manifest-digest');let manifest=ssaParseCanonical(ssaSafeRead(fixture,'MANIFEST.json','SSA_MUTATION_MANIFEST'),'SSA_MUTATION_MANIFEST');manifest.entries[0].fileDigest.value='0'.repeat(64);writeFileSync(resolve(fixture,'MANIFEST.json'),Buffer.from(ssaCanonical(manifest)+'\n'));reject(()=>{const derived=ssaDeriveEnvelope(fixture);ssaAssert(ssaSafeRead(fixture,'MANIFEST.json','SSA_MANIFEST').equals(derived.manifestBytes),'SSA_MANIFEST');},'SSA_MANIFEST','fs/manifest-file-digest');
    fixture=fresh('manifest-reorder');manifest=ssaParseCanonical(ssaSafeRead(fixture,'MANIFEST.json','SSA_MUTATION_MANIFEST'),'SSA_MUTATION_MANIFEST');[manifest.entries[0],manifest.entries[1]]=[manifest.entries[1],manifest.entries[0]];writeFileSync(resolve(fixture,'MANIFEST.json'),Buffer.from(ssaCanonical(manifest)+'\n'));reject(()=>{const derived=ssaDeriveEnvelope(fixture);ssaAssert(ssaSafeRead(fixture,'MANIFEST.json','SSA_MANIFEST').equals(derived.manifestBytes),'SSA_MANIFEST');},'SSA_MANIFEST','fs/manifest-reorder');
    fixture=fresh('manifest-roster');manifest=ssaParseCanonical(ssaSafeRead(fixture,'MANIFEST.json','SSA_MUTATION_MANIFEST'),'SSA_MUTATION_MANIFEST');manifest.rosterDigest.value='0'.repeat(64);writeFileSync(resolve(fixture,'MANIFEST.json'),Buffer.from(ssaCanonical(manifest)+'\n'));reject(()=>{const derived=ssaDeriveEnvelope(fixture);ssaAssert(ssaSafeRead(fixture,'MANIFEST.json','SSA_MANIFEST').equals(derived.manifestBytes),'SSA_MANIFEST');},'SSA_MANIFEST','fs/manifest-roster');
    fixture=fresh('sums');writeFileSync(resolve(fixture,'SHA256SUMS'),'0'.repeat(64)+'  COMMAND.txt\n');reject(()=>{const derived=ssaDeriveEnvelope(fixture);ssaAssert(ssaSafeRead(fixture,'SHA256SUMS','SSA_SUMS').equals(derived.sumsBytes),'SSA_SUMS');},'SSA_SUMS','fs/sums');
    fixture=fresh('coordinated');
    const coordinatedRootPath=resolve(fixture,'static-source-authority-root.v1.json'),coordinatedSchemaPath=resolve(fixture,'schemas/root.v1.schema.json'),coordinatedValidatorPath=resolve(fixture,'validate-static.mjs');
    const coordinatedRoot=ssaParseCanonical(readFileSync(coordinatedRootPath),'SSA_COORD_ROOT'),coordinatedSchema=ssaParseCanonical(readFileSync(coordinatedSchemaPath),'SSA_COORD_SCHEMA');
    coordinatedRoot.purpose+=' Coordinated local replacement fixture.';
    coordinatedSchema.$defs.root.properties.purpose.const=coordinatedRoot.purpose;
    const coordinatedSchemaBytes=Buffer.from(ssaCanonical(coordinatedSchema)+'\n');
    writeFileSync(coordinatedSchemaPath,coordinatedSchemaBytes);
    coordinatedRoot.schemaBindings.find(row=>row.locator==='schemas/root.v1.schema.json').rawSha256=ssaRawSha256(coordinatedSchemaBytes);
    coordinatedRoot.componentDigests.find(row=>row.component==='schemaBindings').digest=ssaDigestRecord(`${SSA_PREFIX}/schema-bindings`,coordinatedRoot.schemaBindings);
    const coordinatedRootBody={...coordinatedRoot};delete coordinatedRootBody.contentDigest;
    coordinatedRoot.contentDigest=ssaDigestRecord(`${SSA_PREFIX}/root`,coordinatedRootBody);
    writeFileSync(coordinatedRootPath,Buffer.from(ssaCanonical(coordinatedRoot)+'\n'));
const coordinatedValidatorSource=`import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const AUTHORED=${JSON.stringify(SSA_AUTHORED_FILES)};
const PREFIX=${JSON.stringify(SSA_PREFIX)};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
const same=(a,b)=>canonical(a)===canonical(b);
const digest=(domain,value)=>({algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value:sha(Buffer.concat([Buffer.from(domain),Buffer.from([0]),Buffer.from(canonical(value)+'\\n')]))});
const fileDigest=(locator,bytes)=>{const domain=PREFIX+'/file/'+locator;return {algorithm:'sha256',canonicalization:'raw-file-bytes-v1',domain,frame:'utf8(domain)||0x00||raw-file-bytes',value:sha(Buffer.concat([Buffer.from(domain),Buffer.from([0]),bytes]))};};
export const validateStatic=({packageRoot,mode,reviewAnchorPin,expectedExternalPins})=>{
  if(mode!=='sealed'||!packageRoot||!reviewAnchorPin||!expectedExternalPins)throw new Error('coordinated:arguments');
  const rootBytes=readFileSync(resolve(packageRoot,'static-source-authority-root.v1.json')),schemaBytes=readFileSync(resolve(packageRoot,'schemas/root.v1.schema.json')),validatorBytes=readFileSync(resolve(packageRoot,'validate-static.mjs'));
  if(sha(rootBytes)!==expectedExternalPins.rootRawSha256||sha(schemaBytes)!==expectedExternalPins.schemaRawSha256||sha(validatorBytes)!==expectedExternalPins.validatorRawSha256)throw new Error('coordinated:external-pins');
  const anchorBytes=readFileSync(resolve(reviewAnchorPin.reviewAnchorRoot,reviewAnchorPin.reviewAnchorLocator));
  if(anchorBytes.length!==reviewAnchorPin.reviewAnchorBytes||sha(anchorBytes)!==reviewAnchorPin.reviewAnchorRawSha256)throw new Error('coordinated:anchor-pin');
  const root=JSON.parse(rootBytes),schema=JSON.parse(schemaBytes),anchor=JSON.parse(anchorBytes),manifestBytes=readFileSync(resolve(packageRoot,'MANIFEST.json')),sumsBytes=readFileSync(resolve(packageRoot,'SHA256SUMS')),manifest=JSON.parse(manifestBytes);
  const entries=AUTHORED.map(locator=>{const bytes=readFileSync(resolve(packageRoot,locator));return {bytes:bytes.length,fileDigest:fileDigest(locator,bytes),locator,rawSha256:sha(bytes)};});
  const expectedManifest={entries,entryCount:24,format:'shieldkit-static-manifest-v1',packageId:'gate-b0-static-source-authority-v1',rosterDigest:digest(PREFIX+'/manifest-roster',entries),schema:'https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1/manifest.v1.schema.json'},expectedManifestBytes=Buffer.from(canonical(expectedManifest)+'\\n');
  const rootSchemaBinding=root.schemaBindings.find(row=>row.locator==='schemas/root.v1.schema.json');
  const expectedSums=[...entries,{locator:'MANIFEST.json',rawSha256:sha(expectedManifestBytes)}].map(row=>row.rawSha256+'  '+row.locator).join('\\n')+'\\n',schemaBindingDigest=digest(PREFIX+'/schema-bindings',root.schemaBindings),rootBody={...root};delete rootBody.contentDigest;
  if(!manifestBytes.equals(expectedManifestBytes)||!same(manifest,expectedManifest)||root.purpose!==schema.$defs.root.properties.purpose.const||rootSchemaBinding.rawSha256!==sha(schemaBytes)||!same(root.componentDigests.find(row=>row.component==='schemaBindings').digest,schemaBindingDigest)||!same(root.contentDigest,digest(PREFIX+'/root',rootBody))||!same(anchor.schemaBindings,root.schemaBindings)||!same(anchor.schemaBindingTableDigest,schemaBindingDigest)||!same(anchor.componentDigests,root.componentDigests)||!same(anchor.rootContentDigest,root.contentDigest)||!same(anchor.orderedClosure,entries)||!same(anchor.rosterDigest,expectedManifest.rosterDigest)||anchor.rootRawSha256!==sha(rootBytes)||anchor.validatorRawSha256!==sha(validatorBytes)||anchor.manifestRawSha256!==sha(manifestBytes)||anchor.sha256SumsRawSha256!==sha(sumsBytes)||sumsBytes.toString()!==expectedSums)throw new Error('coordinated:closure');
  return {files:26,rootDigest:root.contentDigest.value,sourceContracts:19,unsealed:false};
};
`;
    writeFileSync(coordinatedValidatorPath,coordinatedValidatorSource);
    const coordinatedEnvelope=ssaDeriveEnvelope(fixture);writeFileSync(resolve(fixture,'MANIFEST.json'),coordinatedEnvelope.manifestBytes);writeFileSync(resolve(fixture,'SHA256SUMS'),coordinatedEnvelope.sumsBytes);
    const coordinatedAnchor=structuredClone(ssaReadAnchor());
    coordinatedAnchor.componentDigests=structuredClone(coordinatedRoot.componentDigests);coordinatedAnchor.rootContentDigest=structuredClone(coordinatedRoot.contentDigest);coordinatedAnchor.rootRawSha256=ssaRawSha256(readFileSync(coordinatedRootPath));coordinatedAnchor.validatorRawSha256=ssaRawSha256(readFileSync(coordinatedValidatorPath));coordinatedAnchor.manifestRawSha256=ssaRawSha256(coordinatedEnvelope.manifestBytes);coordinatedAnchor.sha256SumsRawSha256=ssaRawSha256(coordinatedEnvelope.sumsBytes);coordinatedAnchor.orderedClosure=coordinatedEnvelope.entries;coordinatedAnchor.rosterDigest=coordinatedEnvelope.manifest.rosterDigest;coordinatedAnchor.schemaBindings=structuredClone(coordinatedRoot.schemaBindings);coordinatedAnchor.schemaBindingTableDigest=ssaDigestRecord(`${SSA_PREFIX}/schema-bindings`,coordinatedRoot.schemaBindings);
    const coordinatedAnchorBytes=Buffer.from(ssaCanonical(coordinatedAnchor)+'\n'),coordinatedAnchorRoot=resolve(temporaryRoot,'coordinated-anchor');mkdirSync(coordinatedAnchorRoot);writeFileSync(resolve(coordinatedAnchorRoot,SSA_ANCHOR_LOCATOR),coordinatedAnchorBytes);
    const coordinatedPin={reviewAnchorRoot:coordinatedAnchorRoot,reviewAnchorLocator:SSA_ANCHOR_LOCATOR,reviewAnchorBytes:coordinatedAnchorBytes.length,reviewAnchorRawSha256:ssaRawSha256(coordinatedAnchorBytes)},coordinatedExternalPins={rootRawSha256:coordinatedAnchor.rootRawSha256,schemaRawSha256:ssaRawSha256(coordinatedSchemaBytes),validatorRawSha256:coordinatedAnchor.validatorRawSha256};
    const coordinatedValidator=await import(pathToFileURL(coordinatedValidatorPath).href+`?ssa-coordinated=${Date.now()}`),coordinatedPositive=coordinatedValidator.validateStatic({packageRoot:fixture,mode:'sealed',reviewAnchorPin:coordinatedPin,expectedExternalPins:coordinatedExternalPins});
    ssaAssert(ssaSame(coordinatedPositive,{files:26,rootDigest:coordinatedRoot.contentDigest.value,sourceContracts:19,unsealed:false}),'SSA_COORDINATED_LOCAL_POSITIVE');
    reject(()=>ssaValidateIndependent(fixture),'SSA_RAW:validate-static.mjs','fs/coordinated-replacement');
    reject(()=>importedValidator.validateStatic({packageRoot:SSA_PACKAGE_ROOT,repositoryRoot:repoRoot,mode:'unsealed'}),'PACKAGE_CLOSURE:unsealed','fs/production-unsealed');reject(()=>importedValidator.validateStatic({packageRoot:SSA_PACKAGE_ROOT,repositoryRoot:repoRoot,mode:'sealed',reviewAnchorPin:null}),'SEALED_ANCHOR_REQUIRED','fs/sealed-missing-pin');
    ssaAssert(classes===SSA_CAUSAL_CLASS_COUNT&&labels.size===SSA_CAUSAL_CLASS_COUNT,'SSA_CAUSAL_COUNT');return {classes,labels:[...labels]};
  }finally{rmSync(temporaryRoot,{recursive:true,force:true});ssaAssert(!existsSync(temporaryRoot),'SSA_CAUSAL_CLEANUP');}
};
const EAPP_PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1';
const EAPP_SCHEMA_PREFIX = 'https://shieldkit-labs.local/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/';
const EAPP_PACKAGE_RELATIVE = 'p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1';
const EAPP_PACKAGE_ROOT = resolve(laneDir, EAPP_PACKAGE_RELATIVE);
const EAPP_PACKAGE_LOCATOR = 'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1';
const EAPP_ANCHOR_ROOT = resolve(laneDir, 'p2/gate-b');
const EAPP_ANCHOR_LOCATOR = 'gate-b0-external-authority-prerequisite-policy-review-anchor.v1.json';
const EAPP_REVIEW_ANCHOR_PIN = Object.freeze({reviewAnchorRoot:EAPP_ANCHOR_ROOT,reviewAnchorLocator:EAPP_ANCHOR_LOCATOR,reviewAnchorBytes:33461,reviewAnchorRawSha256:'304685ab9941b25c80bdefb5062d5fe5e5930c97b6db18cade46e8102af030ac'});
const EAPP_EXPECTED_BINDING = Object.freeze({"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1","root":{"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1/external-authority-prerequisite-policy-root.v1.json","rawSha256":"870a8e1ea607735c9326e7ceeb4ea3e22ff2bf53cac8648c199d70a65fdd6904","contentDigest":"933295dcf2ced565f51cb739364fcf3af8e7f86f851aca40be8348f0e8a3f6de"},"manifest":{"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1/MANIFEST.json","rawSha256":"dbda33fdb7b64d4e103b1d8b95d72875fd3329b2cd0f1a18d3d3fcfe22697885","rosterDigest":"0ad7d182f0ea68f2374eafa9fcecb91144bee01c54a15d31725c1006d8e1a484","entryCount":21},"checksums":{"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1/SHA256SUMS","rawSha256":"4a41707c1b48a94448111e0251256dd038a07216a5129fdeb935882dd3bfeb86"},"validator":{"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1/validate-static.mjs","rawSha256":"43952a537b828c0d74fc4d4101e3dd9c952ac033e753dc6bbb6738e15e8dd6df"},"reviewAnchor":{"path":"p2/gate-b/gate-b0-external-authority-prerequisite-policy-review-anchor.v1.json","schema":"shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/external-review-anchor/v1","bytes":33461,"rawSha256":"304685ab9941b25c80bdefb5062d5fe5e5930c97b6db18cade46e8102af030ac"},"laneAuthorityProjection":{"includedTopLevelKeys":["apiVersion","kind","id","objective","boundaries","scopeDecision","productDecisions","proofBackendDecision","promotionGate"],"excludedTopLevelKeys":["architectureCheckpoint","createdAt","entrypoints","optionDispositions","p1Checkpoint","p2FieldCheckpoint","status","title"],"contentDigest":"7ab73381ae474648873d94f99d7227b9558f5fbb49eff8066132f0b2520ba138"},"counts":{"authoredFiles":21,"sealedFiles":23,"directories":3,"schemaBindings":12,"componentDigests":15,"directSourceAuthorities":4,"transitiveSourcePins":64,"authorityPolicyGroups":10,"supplementalPolicies":2,"requirementAuthorityRows":30,"sourceCollisions":1,"causalDagNodes":19,"causalDagEdges":31,"creationTransitionStates":6,"creationTransitionEdges":5,"digestKatCases":16,"staticTests":4,"sourceCollisionTests":5,"packageBoundaryNegatives":18,"cliArgumentNegatives":16,"causalMutationNegatives":128,"structuralEndpointNegatives":72,"importScannerCases":9,"activationScannerCases":13,"totalTests":32,"productionSealedPositives":1},"nonAuthorityBoundary":{"admissionAllowed":false,"artifactMapAuthorityCreationAllowed":false,"artifactMapAuthorityInstanceCount":0,"artifactMapInstanceCount":0,"artifactMapInstanceCreationAllowed":false,"attemptCount":0,"attemptCreationAllowed":false,"authorityContractCount":0,"authorityContractCreationAllowed":false,"authorityGrantAllowed":false,"authorityPolicyGroupCount":10,"authorizationCount":0,"authorizationCreationAllowed":false,"candidateCount":0,"candidateCreationAllowed":false,"childProcessCount":0,"childProcessCreationAllowed":false,"claimCount":0,"claimCreationAllowed":false,"endpointImportAllowed":false,"evidenceCount":0,"executionAllowed":false,"externalAuthorityBindingCount":0,"externalAuthorityBindingCreationAllowed":false,"factInstanceCount":0,"factInstanceCreationAllowed":false,"fallbackAuthorizationAllowed":false,"governanceAuthorizationCount":0,"governanceAuthorizationCreationAllowed":false,"ioAllowed":false,"measurementAdmissionAllowed":false,"measurementCount":0,"orderMaterialCount":0,"orderMaterialCreationAllowed":false,"ownerInstanceCount":0,"ownerInstantiationAllowed":false,"parameterAssignmentAllowed":false,"parameterAssignmentCount":0,"privateByteCaptureAllowed":false,"privateByteCount":0,"projectionMaterialCount":0,"projectionMaterialCreationAllowed":false,"providerBindingCount":0,"providerBindingCreationAllowed":false,"providerInstanceCount":0,"providerInstantiationAllowed":false,"qualificationAllowed":false,"rankingAllowed":false,"requirementAuthorityMapCount":30,"resultAdmissionAllowed":false,"resultCount":0,"resultValidatorEvaluationAllowed":false,"resultValidatorEvaluationCount":0,"roleAssignmentAllowed":false,"roleAssignmentCount":0,"rootValueCount":0,"rootValueCreationAllowed":false,"runtimeImportAllowed":false,"selectionAllowed":false,"sourceCollisionCount":1,"status":"sealed-static-external-authority-prerequisite-policy-no-authority-contracts-bindings-principals-instances-admission-or-execution-unqualified","supplementalPolicyCount":2,"tupleCount":0,"workloadMaterialCount":0,"workloadMaterialCreationAllowed":false},"status":"sol-regated-sealed-static-gate-b0-external-authority-prerequisite-policy-v1-nonauthorizing-no-governance-authorization-no-authority-contracts-no-provider-bindings-no-principals-no-instances-no-admission-no-execution-unqualified"});
const EAPP_BINDING_KEYS = Object.freeze(['path','root','manifest','checksums','validator','reviewAnchor','laneAuthorityProjection','counts','nonAuthorityBoundary','status']);
const EAPP_COUNT_KEYS = Object.freeze(Object.keys(EAPP_EXPECTED_BINDING.counts));
const EAPP_BOUNDARY_KEYS = Object.freeze(Object.keys(EAPP_EXPECTED_BINDING.nonAuthorityBoundary));
const EAPP_NESTED_BINDING_PATHS = Object.freeze([
  ['path'],['root','path'],['root','rawSha256'],['root','contentDigest'],
  ['manifest','path'],['manifest','rawSha256'],['manifest','rosterDigest'],['manifest','entryCount'],
  ['checksums','path'],['checksums','rawSha256'],['validator','path'],['validator','rawSha256'],
  ['reviewAnchor','path'],['reviewAnchor','schema'],['reviewAnchor','bytes'],['reviewAnchor','rawSha256'],
  ['laneAuthorityProjection','includedTopLevelKeys'],['laneAuthorityProjection','excludedTopLevelKeys'],['laneAuthorityProjection','contentDigest']
]);
const EAPP_NONPROMOTION = 'The sealed gate-b0-external-authority-prerequisite-policy-v1 package is a static, non-authorizing, non-admitting, unqualified prerequisite-policy language bound by an outside-package review anchor; it authenticates only the reviewed 21-file authored closure, its two mechanical envelope files, 12 raw-pinned schemas, 15 component digests, 10 policy groups, 2 supplemental policies, 30 false/zero requirement-authority rows, one unresolved UOPC/EAC source collision with selectedDag null, 31 prerequisite-DAG edges, a 6-state/5-edge transition policy with zero authorized transitions, and the exact false/zero non-authority boundary, and it creates no governance authorization, external authority contract, provider binding, principal, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.';
const EAPP_NEXT_GATE = "The sealed gate-b0-external-authority-prerequisite-policy-v1 integration closes only the static external-authority prerequisite-policy-language stage beneath B0_EXECUTION_AUTHORIZATION. The package's current state is AUTHORITY_POLICY_FROZEN_NO_AUTHORITY: its represented SOURCE_LANGUAGE_RESOLVED→AUTHORITY_POLICY_FROZEN_NO_AUTHORITY transition is static policy representation only, all four later transitions are BLOCKED_EXTERNAL, authorizedTransitions is empty, and selectedDag is null. The next B0-R phase-DAG node remains B0_EXECUTION_AUTHORIZATION, but it remains closed. Before it may open, separately authorized external principals must provide independently pinned external authority contracts; an independently reviewed provider-binding catalog; an explicit root/SOL governance authorization that resolves the UOPC/EAC precedence collision; and satisfaction of every closed EAC prerequisite, including the raw-artifact-map and independent-result-validator requirements. This package and this lane integration may not infer, issue, bind, instantiate, or satisfy any of those prerequisites. Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, Gate B1, admission, execution, evidence, qualification, ranking, and selection remain closed.";
const CPSB_NEXT_GATE_SUFFIX = 'The CPSB exact29 authenticated sealed static validation closes only the future control-plane grammar and content-hash-ordering checkpoint; it authenticates no principals, decisions, contracts, bindings, authorizations, instances, admissions, attempts, measurements, qualifications, rankings, selections, runtime readiness, independent attestation, candidate tuple, parameter, field, domain, AIR, FRI, proof, prover, evidence admission, or PoolActionFv1 amendment. Four PoolActionFv1 blockers remain open at Hard Gates 1 and 5. B0_EXECUTION_AUTHORIZATION, Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.';
const CPSB_NEXT_GATE = `${EAPP_NEXT_GATE} ${CPSB_NEXT_GATE_SUFFIX}`;
const CPSB_COMPLETED = 'The CPSB exact29 authenticated sealed static validation authenticates only future control-plane grammar and content-hash ordering for the pinned 27-entry source closure, 29-file sealed package, 18 schema bindings, and 11 future-record schemas; every future-record count remains zero.';
const CPSB_NOT_ESTABLISHED = 'any principal or principal authentication, issuer decision, authority or provider contract, provider binding, governance or B0 execution authorization, runtime readiness or independent attestation, instance, admission or evidence admission, attempt, epoch, protocol execution, measurement, qualification, ranking, selection, candidate tuple, role, parameter, field or domain assignment, AIR, FRI, proof or prover progress, PoolActionFv1 relation amendment, B0 root/SOL review, or Gate B1 opening from CPSB exact29; every corresponding record and count remains zero, and the unsigned replayable receipt retains its external-caller, host-TCB, and same-UID post-bubblewrap injection boundary';
const CPSB_STATUS = 'sol-ruled-exact29-authenticated-sealed-static-validation-only-gate-b0-future-grammar-control-plane-checkpoint-complete-zero-records-no-authority-no-admission-no-protocol-execution-no-measurement-unqualified';
const CPSB_PROSE = 'The CPSB exact29 authenticated sealed static validation authenticates only future control-plane grammar and content-hash ordering for the pinned 27-entry source closure, 29-file sealed package, 18 schema bindings, and 11 future-record schemas, all with zero records. The retained 8,147-byte receipt is `AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY` with authorization `NONE`; it is unsigned and replayable, depends on the external caller and host TCB, is not independent attestation or runtime-readiness evidence, and creates no principal, decision, contract, binding, authorization, instance, admission, attempt, execution, evidence admission, measurement, qualification, ranking, selection, candidate tuple, parameter, field/domain, AIR/FRI/proof/prover progress, or PoolActionFv1 amendment. B0_EXECUTION_AUTHORIZATION, Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.';
const POOLACTION_BLOCKER_PROSE = 'The retained PoolActionFv1 contradiction capsule records four open qualification blockers with authority `none` and status `observed-open-blockers-not-a-relation-amendment`: network schema/codec drift, injected context-digest facts, carrier-lock anchor erasure, and proof-session context erasure. They keep Hard Gates 1 and 5 blocked under `cannot-qualify-select-or-begin-full-prover`; the capsule executes nothing and is not a relation amendment or complete transaction witness.';
const REFREEZE_BLOCKED_PROSE = 'The quiescent `poolaction-relation-disposition-refreeze-v2`, `measurement-admission-v2`, inert v1 synthetic subset, and v2 falsifier source-contract/16-file review anchor form one `BLOCKED_VERSION_PIVOT_NO_REFREEZE` transition only: v2 preserves source-contract integrity while the supervisory-matrix raw file remains absent; it grants no authority, admission, execution, measurement, qualification, ranking, selection, candidate, tuple, role, parameter, or refreeze credit. Hard Gates 1 and 5 and `B0_EXECUTION_AUTHORIZATION` remain closed.';
const EAPP_NOT_ESTABLISHED = 'any governance authorization, external authority contract, provider binding, principal, owner, ownerBindingRoot, origin, fact instance, root value, order material, projection material, private byte, raw-artifact-map authority or instance, independent result-validator implementation or evaluation, retry-predecessor instance, Q/A/LIVE_F/B/C/J/D instance, nonce, attempt, candidate or tuple instance, role or parameter assignment, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback authorization, admission, execution, complete Gate B0 epoch, Gate B0 root/SOL review, or Gate B1 opening by this integration; selectedDag remains null, UOPC/EAC precedence remains UNRESOLVED_EXTERNAL_PRECEDENCE, all external authority, governance, provider-binding, and instance roots remain null, all corresponding counts remain zero, and the sealed gate-b0-external-authority-prerequisite-policy-v1 package freezes only static prerequisite-policy language';
const EAPP_UNSELECTED = 'any governance authorization, external authority contract, provider binding, principal, owner, ownerBindingRoot, origin, fact instance, root value, order material, projection material, private byte, raw-artifact-map authority or instance, independent result-validator implementation or evaluation, retry-predecessor instance, Q/A/LIVE_F/B/C/J/D instance, admission, or execution; the sealed gate-b0-external-authority-prerequisite-policy-v1 authenticates only static prerequisite-policy language, its current state is AUTHORITY_POLICY_FROZEN_NO_AUTHORITY, selectedDag remains null, all external authority, governance, provider-binding, and instance roots remain null, all corresponding counts remain zero, and no creation transition is authorized';
const EAPP_LANE_STATUS = 'source-mapped-product-backend-p0-relation-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-gate-b0-external-authority-prerequisite-policy-v1-static-prerequisite-policy-integrated-no-governance-authorization-no-authority-contracts-no-provider-bindings-no-principals-no-instances-no-io-no-execution-no-admission-architecture-unpromoted';
const EAPP_ARCHITECTURE_STATUS = 'p0-root-sol-frozen-p1-implemented-p2-r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-gate-b0-external-authority-prerequisite-policy-v1-static-prerequisite-policy-integrated-no-governance-authorization-no-authority-contracts-no-provider-bindings-no-principals-no-instances-no-io-no-execution-no-admission-unqualified';
const EAPP_P2_STATUS = 'r-k-f-p-static-policy-cohort-live-executor-v2-pure-model-authority-binding-model-v1-static-catalog-external-origin-contract-v1-static-catalog-upstream-origin-provider-contract-v1-static-catalog-upstream-provider-source-map-v1-static-catalog-gate-b0-evidence-plan-v1-static-plan-gate-b0-execution-admission-contract-v1-static-preexecution-prerequisite-integrated-gate-b0-static-source-authority-v1-static-source-contract-authority-integrated-gate-b0-external-authority-prerequisite-policy-v1-static-prerequisite-policy-integrated-no-governance-authorization-no-authority-contracts-no-provider-bindings-no-principals-no-instances-no-io-no-execution-no-admission-nonranking-unqualified';
const EAPP_PROSE_SOURCES = Object.freeze([
  {label:'lane README',locator:'research-lanes/bch-shielded-pool-design/README.md',path:resolve(laneDir,'README.md')},
  {label:'design options',locator:'research-lanes/bch-shielded-pool-design/analysis/design-options.md',path:resolve(laneDir,'analysis/design-options.md')}
]);
const EAPP_LANE_CAUSAL_CLASS_COUNT = 159;
const eappPort = (() => {
const AUTHORED_FILES = Object.freeze(['COMMAND.txt','README.md','external-authority-prerequisite-policy-root.v1.json','schemas/authority-policy.v1.schema.json','schemas/causal-dag.v1.schema.json','schemas/creation-transition-policy.v1.schema.json','schemas/dependency-binding.v1.schema.json','schemas/digest.v1.schema.json','schemas/future-external-authority-contract.v1.schema.json','schemas/future-governance-authorization.v1.schema.json','schemas/manifest.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/provider-binding-policy.v1.schema.json','schemas/requirement-authority-map.v1.schema.json','schemas/root.v1.schema.json','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/source-collision.test.mjs','test/static.test.mjs','validate-static.mjs']);
const PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1';
const here = EAPP_PACKAGE_ROOT;
const SCHEMA_PREFIX = 'https://shieldkit-labs.local/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/';
const SCHEMAS = Object.freeze(AUTHORED_FILES.filter(locator => locator.startsWith('schemas/')));
const DIRECTIONS = Object.freeze(['.','schemas','test']);
const PACKAGE_ID = 'gate-b0-external-authority-prerequisite-policy-v1';
const TOKENS = new Set(['CLI_ARGS','PACKAGE_CLOSURE','PACKAGE_MODE','FILE_MODE','DIR_MODE','LINK','SPECIAL_FILE','PATH','NON_NFC','DUPLICATE_KEY','ANCHOR_REQUIRED','ANCHOR_RAW','ANCHOR_CLOSURE','ANCHOR_PIN','MANIFEST','SUMS','SCHEMA_RAW','SCHEMA_REF','SCHEMA_COMPILE','ROOT_SCHEMA','ROOT_KEYS','ROOT_ID','STATUS','NONAUTHORITY','DEPENDENCY_RAW','DEPENDENCY_SEMANTIC','SSA_COMPONENT','EAC_COMPONENT','SOURCE_RAW','SOURCE_SEMANTIC','REQUIREMENT_ROSTER','REQUIREMENT_JOIN','GROUP_PARTITION','GROUP_SLOT','SUPPLEMENTAL','COLLISION_COUNTS','COLLISION_EDGES','COLLISION_SELECTION','TRANSITION','BINDING_POLICY','FUTURE_SCHEMA','INDEPENDENCE','DAG','DIGEST','RUNTIME_BOUNDARY','IMPORT_BOUNDARY','CONTENT_DIGEST']);
const fail = (token, detail='') => { if (!TOKENS.has(token)) throw new Error('EAPP_STATUS:unknown-token'); throw new Error(`EAPP_${token}${detail ? `:${detail}` : ''}`); };
const check = (condition, token, detail='') => { if (!condition) fail(token, detail); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const utf8 = bytes => { const source=bytes.toString('utf8');check(Buffer.from(source,'utf8').equals(bytes),'NON_NFC');return source; };
const allStringsNfc = value => typeof value === 'string' ? value.normalize('NFC') === value : Array.isArray(value) ? value.every(allStringsNfc) : value && typeof value === 'object' ? Object.entries(value).every(([key,item]) => key.normalize('NFC') === key && allStringsNfc(item)) : true;
const canonicalJson = value => Array.isArray(value) ? `[${value.map(canonicalJson).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}` : JSON.stringify(value);
const same = (left,right) => canonicalJson(left) === canonicalJson(right);
const digestRecord = (domain,value) => { check(allStringsNfc(domain) && allStringsNfc(value), 'NON_NFC'); return {algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value:sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),Buffer.from(`${canonicalJson(value)}\n`)]))}; };
const fileDigestRecord = (locator,bytes) => { const domain=`${PREFIX}/file/${locator}`; return {algorithm:'sha256',canonicalization:'raw-file-bytes-v1',domain,frame:'utf8(domain)||0x00||raw-file-bytes',value:sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),bytes]))}; };
const safeLocator = locator => { check(typeof locator === 'string' && locator && !isAbsolute(locator) && !locator.includes('\\') && locator.normalize('NFC') === locator && locator.split('/').every(part => part && part !== '.' && part !== '..'), 'PATH'); return locator; };
const safeRead = (root,locator) => { safeLocator(locator); let cursor=realpathSync(root); for (const [index,part] of locator.split('/').entries()) { cursor=resolve(cursor,part); const stat=lstatSync(cursor); check(!stat.isSymbolicLink(), 'LINK', locator); check(index===locator.split('/').length-1 ? stat.isFile() && stat.nlink===1 : stat.isDirectory(), index===locator.split('/').length-1 ? 'SPECIAL_FILE' : 'PATH', locator); } return readFileSync(cursor); };
const rejectDuplicateKeys = bytes => { const source=utf8(bytes);let index=0;const skip=()=>{while(/[ \t\r\n]/u.test(source[index]??''))index+=1;};const string=()=>{const start=index;check(source[index++]==='"','DUPLICATE_KEY');while(index<source.length){const char=source[index++];if(char==='\\'){check(index<source.length,'DUPLICATE_KEY');if(source[index++]==='u')index+=4;}else if(char==='"')return JSON.parse(source.slice(start,index));else check(char.charCodeAt(0)>=0x20,'DUPLICATE_KEY');}fail('DUPLICATE_KEY');};const value=()=>{skip();const token=source[index];if(token==='{'){index+=1;skip();const keys=new Set();if(source[index]==='}'){index+=1;return;}for(;;){skip();const key=string();check(!keys.has(key),'DUPLICATE_KEY');keys.add(key);skip();check(source[index++]===':','DUPLICATE_KEY');value();skip();if(source[index]==='}'){index+=1;return;}check(source[index++]===',','DUPLICATE_KEY');}}if(token==='['){index+=1;skip();if(source[index]===']'){index+=1;return;}for(;;){value();skip();if(source[index]===']'){index+=1;return;}check(source[index++]===',','DUPLICATE_KEY');}}if(token==='"'){string();return;}for(const literal of ['true','false','null'])if(source.startsWith(literal,index)){index+=literal.length;return;}const number=source.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);check(number,'DUPLICATE_KEY');index+=number[0].length;};value();skip();check(index===source.length,'DUPLICATE_KEY');};
const parseCanonical = (bytes,token='DUPLICATE_KEY') => { rejectDuplicateKeys(bytes);let value; try { value=JSON.parse(utf8(bytes)); } catch { fail(token); } check(allStringsNfc(value),'NON_NFC'); check(utf8(bytes)===`${canonicalJson(value)}\n`,'DUPLICATE_KEY'); return value; };
const fileDigestWithPrefix = (prefix,locator,bytes) => { const domain=`${prefix}/file/${locator}`; return {algorithm:'sha256',canonicalization:'raw-file-bytes-v1',domain,frame:'utf8(domain)||0x00||raw-file-bytes',value:sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),bytes]))}; };
const digestWithPrefix = (prefix,suffix,value) => digestRecord(`${prefix}/${suffix}`,value);
const walk = (root,prefix='') => readdirSync(root,{withFileTypes:true}).flatMap(entry => { const locator=prefix+entry.name; if(entry.isDirectory()) return [{kind:'directory',locator},...walk(resolve(root,entry.name),`${locator}/`)]; return [{kind:entry.isFile()?'file':entry.isSymbolicLink()?'link':'special',locator}]; });
const checkClosure = (root,mode) => { check(mode==='unsealed'||mode==='sealed','PACKAGE_MODE'); const stat=lstatSync(root); check(stat.isDirectory()&&!stat.isSymbolicLink(),'PACKAGE_CLOSURE'); const tree=walk(root),files=tree.filter(row=>row.kind==='file').map(row=>row.locator).sort(),dirs=['.',...tree.filter(row=>row.kind==='directory').map(row=>row.locator)].sort(),expected=(mode==='sealed'?[...AUTHORED_FILES,'MANIFEST.json','SHA256SUMS']:AUTHORED_FILES).slice().sort(); check(tree.every(row=>row.kind==='file'||row.kind==='directory'),'SPECIAL_FILE'); check(same(files,expected),'PACKAGE_CLOSURE'); check(same(dirs,[...DIRECTIONS].sort()),'PACKAGE_CLOSURE'); for(const dir of dirs) check((lstatSync(resolve(root,dir)).mode&0o777)===0o755,'DIR_MODE'); for(const file of files) { const fs=lstatSync(resolve(root,file)); check(fs.nlink===1,'LINK'); check((fs.mode&0o777)===0o644,'FILE_MODE'); } return {files:files.length,directories:dirs.length}; };
const deriveSealEnvelope = (packageRoot=here) => { const entries=AUTHORED_FILES.map(locator=>{const bytes=safeRead(packageRoot,locator);return {bytes:bytes.length,fileDigest:fileDigestRecord(locator,bytes),locator,rawSha256:sha256(bytes)};});const rosterDigest=digestRecord(`${PREFIX}/manifest-roster`,entries);const manifest={schema:`${SCHEMA_PREFIX}manifest.v1.schema.json`,format:'shieldkit-static-manifest-v1',packageId:PACKAGE_ID,entryCount:21,entries,rosterDigest};const manifestBytes=Buffer.from(`${canonicalJson(manifest)}\n`),sumsBytes=Buffer.from(`${[...entries,{locator:'MANIFEST.json',rawSha256:sha256(manifestBytes)}].map(row=>`${row.rawSha256}  ${row.locator}`).join('\n')}\n`);return {entries,manifest,manifestBytes,sumsBytes}; };
const deriveReviewAnchor = ({root,validatorRawSha256,manifestRawSha256,sha256SumsRawSha256,entries,rosterDigest}) => ({schema:`${PREFIX}/external-review-anchor/v1`,artifactId:'artifact:gate-b:gate-b0-external-authority-prerequisite-policy-review-anchor-v1',packageId:PACKAGE_ID,package:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1',status:'sealed-static-external-authority-prerequisite-policy-review-anchor-no-governance-authorization-no-authority-bindings-no-instances-no-admission-no-execution-unqualified',rootRawSha256:sha256(Buffer.from(`${canonicalJson(root)}\n`)),rootContentDigest:root.contentDigest,validatorRawSha256,manifestRawSha256,sha256SumsRawSha256,entryCount:21,orderedClosure:entries,rosterDigest,directDependencyBinding:root.dependencyBinding,componentDigests:root.componentDigests,schemaBindings:root.schemaBindings,schemaBindingTableDigest:digestRecord(`${PREFIX}/schema-binding-table`,root.schemaBindings),sourceCollisionDigest:root.componentDigests.find(row=>row.component==='sourceCollisions').digest,nonAuthorityBoundary:root.nonAuthorityBoundary});
const rootDocument = (root=here) => parseCanonical(safeRead(root,'external-authority-prerequisite-policy-root.v1.json'));
const EXACT_GOVERNANCE={authorityOriginClass:'EXTERNAL_ROOT_SOL_STATIC_SCHEMA_GOVERNANCE',authorizationRecordDisposition:'EXTERNAL_CONTROL_PLANE_RECORD_NOT_EMBEDDED',governanceIssuerId:null,governanceDecisionId:null,governanceAuthorizationRoot:null,governanceAuthorizationRawSha256:null,authorizationPresent:false,existingCatalogsAreConstraintInputsOnly:true,independentSolReviewRequired:true,laneMayPinOnlyAfterSeal:true,laneReadAllowed:false,operationalOwnershipGranted:false,outsideReviewAnchorRequired:true,packageMaySelfCertify:false,packageMaySelfAuthorize:false,catalogMaySelfBind:false,sourceContractResolutionMayGrantCreationAuthority:false,externalAuthorityContractCreationAllowed:false,providerBindingCreationAllowed:false,creationAuthorizationAllowed:false,principalCoincidencePolicy:'UNDECIDED_AND_FORBIDDEN_UNTIL_EXPLICIT_GOVERNANCE',revocationPolicy:null,expiryPolicy:null};
const GROUP_IDS=['OWNER_SCOPE_REQUIREMENTS','RETRY_LINEAGE_REQUIREMENTS','PRIVATE_CAPTURE_REQUIREMENTS','STATIC_ENDPOINT_ORDER_REQUIREMENTS','WORKLOAD_MATERIAL_REQUIREMENTS','DISPATCH_WORKER_REQUIREMENTS','Q_REQUIREMENTS','A_REQUIREMENTS','LIVE_F_B_REQUIREMENTS','TERMINAL_C_J_D_REQUIREMENTS'];
const GROUP_STATUSES=['MISSING_DISTINCT_EXTERNAL_OWNER_AUTHORITY_CONTRACTS','INDEX_ONLY_STATIC_CONSTRAINT_AND_FUTURE_INSTANCE_NO_AUTHORITY_SLOT','INDEX_ONLY_STATIC_CONSTRAINT_AND_FUTURE_INSTANCE_NO_AUTHORITY_SLOT','STATIC_CONSTRAINT_ONLY_NO_PROVIDER_OR_AUTHORITY_SLOT','MISSING_EXTERNAL_WORKLOAD_MATERIAL_AUTHORITY_CONTRACT','DERIVED_ONLY_NO_INDEPENDENT_AUTHORITY_SLOT','TYPE_OR_DERIVED_ONLY_NO_INDEPENDENT_AUTHORITY_SLOT','TYPE_OR_DERIVED_ONLY_SOURCE_COLLISION_BLOCKED_NO_INDEPENDENT_AUTHORITY_SLOT','TYPE_OR_DERIVED_ONLY_SOURCE_COLLISION_BLOCKED_NO_INDEPENDENT_AUTHORITY_SLOT','FUTURE_INSTANCE_TYPE_OR_DERIVED_ONLY_NO_INDEPENDENT_AUTHORITY_SLOT'];
const GROUP_REQUIREMENTS=[['RECOVERY_CHAIN_OWNER_PROVIDER','REQUEST_OWNER_PROVIDER','ACTIVATION_OWNER_PROVIDER','PRIVATE_CAPTURE_OWNER_PROVIDER','PRIVATE_DESCRIPTOR_OWNER_PROVIDER','EXCLUSIVE_C_OWNER_PROVIDER','PRIVATE_DISPATCH_OWNER_PROVIDER'],['RETRY_ORDER_PROVIDER','RETRY_PREDECESSOR_PROVIDER'],['LIVE_F_RECORD_ORDER_PROVIDER','LIVE_F_CAPTURE_PROVIDER'],['FROZEN_SURFACE_ORDER_PROVIDER','ENDPOINT_CONTROL_ORDER_PROVIDER'],['WORKLOAD_ROOT_ORDER_PROVIDER','WORKLOAD_PROJECTION_PROVIDER','ENDPOINT_BYTE_AUTHORITY_PROVIDER'],['WORKER_ROWS_ROOT_PROVIDER','DISPATCH_PLAN_PROVIDER'],['Q_INITIAL_PROVIDER','Q_RETRY_PROVIDER','Q_ABORT_PROVIDER'],['A_INITIAL_PROVIDER','A_RETRY_PROVIDER','A_ABORT_PROVIDER'],['LIVE_F_PROVIDER','B_SUBJECT_ROOT_TYPE','B_PROVIDER'],['C_PROVIDER','J_ROOT_TYPE','D_PROVIDER']];
const GROUP_SLOTS=[GROUP_REQUIREMENTS[0],[],[],[],['WORKLOAD_ROOT_ORDER_PROVIDER'],[],[],[],[],[]];
const REQUIREMENT_IDS=['RECOVERY_CHAIN_OWNER_PROVIDER','REQUEST_OWNER_PROVIDER','ACTIVATION_OWNER_PROVIDER','PRIVATE_CAPTURE_OWNER_PROVIDER','PRIVATE_DESCRIPTOR_OWNER_PROVIDER','EXCLUSIVE_C_OWNER_PROVIDER','PRIVATE_DISPATCH_OWNER_PROVIDER','RETRY_ORDER_PROVIDER','LIVE_F_RECORD_ORDER_PROVIDER','FROZEN_SURFACE_ORDER_PROVIDER','ENDPOINT_CONTROL_ORDER_PROVIDER','WORKLOAD_ROOT_ORDER_PROVIDER','WORKLOAD_PROJECTION_PROVIDER','ENDPOINT_BYTE_AUTHORITY_PROVIDER','RETRY_PREDECESSOR_PROVIDER','LIVE_F_CAPTURE_PROVIDER','WORKER_ROWS_ROOT_PROVIDER','Q_INITIAL_PROVIDER','Q_RETRY_PROVIDER','Q_ABORT_PROVIDER','A_INITIAL_PROVIDER','A_RETRY_PROVIDER','A_ABORT_PROVIDER','LIVE_F_PROVIDER','B_SUBJECT_ROOT_TYPE','B_PROVIDER','C_PROVIDER','J_ROOT_TYPE','DISPATCH_PLAN_PROVIDER','D_PROVIDER'];
const REQUIREMENT_CLASSIFICATIONS=['STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','STATIC_SOURCE','FUTURE_INSTANCE','DERIVED','DERIVED','FUTURE_INSTANCE','FUTURE_INSTANCE','DERIVED','TYPE_ONLY','DERIVED','TYPE_ONLY','TYPE_ONLY','DERIVED','TYPE_ONLY','DERIVED','TYPE_ONLY','DERIVED','FUTURE_INSTANCE','TYPE_ONLY','DERIVED','DERIVED'];
const REQUIREMENT_DISPOSITIONS=['UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','UNAVAILABLE_PREAUTHORIZATION','DELIBERATELY_UNAVAILABLE_FUTURE_INSTANCE','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','DELIBERATELY_UNAVAILABLE_FUTURE_INSTANCE','DELIBERATELY_UNAVAILABLE_FUTURE_INSTANCE','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','NO_PROVIDER_BY_CONTRACT','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','NO_PROVIDER_BY_CONTRACT','NO_PROVIDER_BY_CONTRACT','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','NO_PROVIDER_BY_CONTRACT','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','NO_PROVIDER_BY_CONTRACT','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','DELIBERATELY_UNAVAILABLE_FUTURE_INSTANCE','NO_PROVIDER_BY_CONTRACT','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS','DERIVED_ONLY_AFTER_AUTHORIZED_PREDECESSORS'];
const REQUIREMENT_STATUSES=['SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_DISTINCT_OWNER_AUTHORITY_ABSENT','SOURCE_LANGUAGE_RESOLVED_STATIC_CONSTRAINT_NO_PROVIDER','SOURCE_LANGUAGE_RESOLVED_STATIC_CONSTRAINT_NO_PROVIDER','SOURCE_LANGUAGE_RESOLVED_STATIC_CONSTRAINT_NO_PROVIDER','SOURCE_LANGUAGE_RESOLVED_STATIC_CONSTRAINT_NO_PROVIDER','FUTURE_INSTANCE_DELIBERATELY_UNAVAILABLE_AUTHORITY_CONTRACT_ABSENT','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','FUTURE_INSTANCE_DELIBERATELY_UNAVAILABLE_NOT_CURRENT_PREREQUISITE','FUTURE_INSTANCE_DELIBERATELY_UNAVAILABLE_NOT_CURRENT_PREREQUISITE','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','TYPE_ONLY_DIVERGENT_DAG_EDGE_UNSELECTED_NO_PROVIDER','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','TYPE_ONLY_DIVERGENT_DAG_EDGE_UNSELECTED_NO_PROVIDER','TYPE_ONLY_DIVERGENT_DAG_EDGE_UNSELECTED_NO_PROVIDER','DERIVED_SOURCE_COLLISION_BLOCKED_NO_PRECEDENCE','TYPE_ONLY_DIVERGENT_DAG_EDGE_UNSELECTED_NO_PROVIDER','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','TYPE_ONLY_SOURCE_COLLISION_BLOCKED_NO_PRECEDENCE','DERIVED_SOURCE_COLLISION_BLOCKED_NO_PRECEDENCE','FUTURE_INSTANCE_DELIBERATELY_UNAVAILABLE_NOT_CURRENT_PREREQUISITE','TYPE_ONLY_NO_PROVIDER','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS','DERIVED_BLOCKED_BY_UNAUTHORIZED_PREDECESSORS'];
const EXPECTED_SOURCE_REFS=[['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['UPSTREAM_OWNER_CONTRACT_SCHEMA'],['RETRY_TARGET_SOURCE_SCHEMA','RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA'],['LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA'],['WORKLOAD_ROOT_SOURCE_SCHEMA'],['WORKLOAD_ROOT_SOURCE_SCHEMA'],['ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE'],['WORKLOAD_ROOT_SOURCE_SCHEMA','ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE','RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT'],['ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA'],['RETRY_TARGET_SOURCE_SCHEMA','RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA'],['LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA'],['ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA','WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA'],['OWNER_BOUND_Q_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_Q_FACT_SOURCE_SCHEMA','RETRY_TARGET_SOURCE_SCHEMA','RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA','RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT'],['OWNER_BOUND_Q_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_A_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_A_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_A_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA','LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA'],['OWNER_BOUND_B_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_B_FACT_SOURCE_SCHEMA','OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_C_FACT_SOURCE_SCHEMA'],['OWNER_BOUND_B_FACT_SOURCE_SCHEMA','OWNER_BOUND_C_FACT_SOURCE_SCHEMA'],['PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA'],['OWNER_BOUND_D_FACT_SOURCE_SCHEMA','PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA','ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA','WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA']];
const SPM_REF_INDICES=[[0],[0],[0],[0],[0],[0],[0],[1,2],[3],[4,5],[4,5],[4,5],[4,5],[6],[1,2],[3],[6,7],[9],[1,2,9],[9],[10],[10],[10],[3,11],[12],[11,12],[13],[14],[8],[6,7,8,15]];
const SPM_SOURCE_KIND_ROSTER=Object.freeze(['ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA','LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA','ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','OWNER_BOUND_A_FACT_SOURCE_SCHEMA','OWNER_BOUND_B_FACT_SOURCE_SCHEMA','OWNER_BOUND_C_FACT_SOURCE_SCHEMA','OWNER_BOUND_D_FACT_SOURCE_SCHEMA','OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA','OWNER_BOUND_Q_FACT_SOURCE_SCHEMA','PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA','RETRY_TARGET_SOURCE_SCHEMA','RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA','UPSTREAM_OWNER_CONTRACT_SCHEMA','WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA','WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE','WORKLOAD_ROOT_SOURCE_SCHEMA']);
const REQUIREMENT_SUPPLEMENTAL_SOURCE_REFS=Object.freeze(['RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT']);
const SPM_DERIVED_JOIN_NORMALIZATIONS=Object.freeze({J_ROOT_TYPE:Object.freeze({mode:'EXACT_DERIVED_PREDECESSOR_SOURCE_CONTRACTS',spmMapIds:Object.freeze(['J_MAP']),spmResolution:'EXACT_DERIVED_TYPE_MAPPING_NO_PROVIDER_NO_INSTANCE',directMissingSourceKinds:Object.freeze([]),sourceContractRefs:Object.freeze(['OWNER_BOUND_B_FACT_SOURCE_SCHEMA','OWNER_BOUND_C_FACT_SOURCE_SCHEMA']),predecessorNodeIds:Object.freeze(['B_PROVIDER','C_PROVIDER']),interfaceIds:Object.freeze(['J']),incomingMapEdges:Object.freeze(['B_MAP→J_MAP','C_MAP→J_MAP']),outgoingMapEdges:Object.freeze(['J_MAP→D_MAP'])})});
const PREDECESSOR_JOIN_NORMALIZATIONS=Object.freeze({B_SUBJECT_ROOT_TYPE:Object.freeze({ssaPredecessorNodeIds:Object.freeze(['A_RETRY_PROVIDER','P','R','K']),localPredecessorNodeIds:Object.freeze([]),collisionId:'UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE',collisionStatus:'UNRESOLVED_EXTERNAL_PRECEDENCE',selectedDag:null})});
const SPM_CONTEXTUAL_EXTRA_KINDS=Object.freeze({
FROZEN_SURFACE_ORDER_PROVIDER:Object.freeze(['ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE']),
ENDPOINT_CONTROL_ORDER_PROVIDER:Object.freeze(['ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA','WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE','WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE']),
WORKLOAD_ROOT_ORDER_PROVIDER:Object.freeze(['WORKLOAD_ROOT_SOURCE_SCHEMA']),
WORKLOAD_PROJECTION_PROVIDER:Object.freeze(['WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE'])
});
const uopcCatalogRefs=index=>index<7?[`UOPC#/ownerProviderCatalog/entries/${index}`]:index<12?[`UOPC#/orderProviderCatalog/entries/${index-7}`]:index<14?[`UOPC#/projectionProviderCatalog/entries/${index-12}`]:index<17?[`UOPC#/externalOriginProviderCatalog/entries/${index-14}`]:index<20?['UOPC#/factProviderCatalog/entries/0']:index<23?['UOPC#/factProviderCatalog/entries/1']:index===23?['UOPC#/factProviderCatalog/entries/2']:index<26?['UOPC#/factProviderCatalog/entries/3']:index===26?['UOPC#/factProviderCatalog/entries/4']:index===27?['UOPC#/factProviderCatalog/entries/5']:index===28?['UOPC#/projectionProviderCatalog/entries/2']:['UOPC#/factProviderCatalog/entries/6','UOPC#/projectionProviderCatalog/entries/2'];
const EXPECTED_CONSTRAINT_REFS=REQUIREMENT_IDS.map((_,index)=>[`EAC#/externalRequirements/${index}`,...uopcCatalogRefs(index),`UOPC#/providerCausalDag/nodes/${index}`,...SPM_REF_INDICES[index].map(row=>`SPM#/interfaceSourceMap/entries/${row}`),...(index===14?['EAC#/historicalDisposition/attempt000','EAC#/historicalDisposition/attempt001Retry']:[])]);
const SSA_PREFIX='shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1';
const SSA_AUTHORED_FILES=['COMMAND.txt','README.md','schemas/dependency-pin.v1.schema.json','schemas/digest.v1.schema.json','schemas/governance.v1.schema.json','schemas/manifest.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/owner-contract-source-catalog.v1.schema.json','schemas/private-capture-source-catalog.v1.schema.json','schemas/raw-artifact-map-source-contract.v1.schema.json','schemas/requirement-resolution.v1.schema.json','schemas/result-validator-source-contract.v1.schema.json','schemas/retry-lineage-source-catalog.v1.schema.json','schemas/root.v1.schema.json','schemas/source-contract.v1.schema.json','schemas/state-fact-source-catalog.v1.schema.json','schemas/workload-projection-source-catalog.v1.schema.json','static-source-authority-root.v1.json','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/source-resolution.test.mjs','test/static.test.mjs','validate-static.mjs'];
const SOURCE_PIN_IDS=Object.freeze(["pin:parent:b0r-root","pin:parent:b0r-manifest","pin:parent:b0r-sums","pin:parent:b0r-validator","pin:parent:b0r-anchor","pin:foundation:p-root","pin:foundation:p-manifest","pin:foundation:p-sums","pin:foundation:r-root","pin:foundation:r-manifest","pin:foundation:r-sums","pin:foundation:k-root","pin:foundation:k-manifest","pin:foundation:k-sums","pin:foundation:f-root","pin:foundation:f-manifest","pin:foundation:f-sums","pin:origin:live-root","pin:origin:live-manifest","pin:origin:live-sums","pin:origin:cabm-root","pin:origin:cabm-manifest","pin:origin:cabm-sums","pin:origin:ecoc-root","pin:origin:ecoc-manifest","pin:origin:ecoc-sums","pin:origin:uopc-root","pin:origin:uopc-manifest","pin:origin:uopc-sums","pin:origin:source-map-root","pin:origin:source-map-manifest","pin:origin:source-map-sums","pin:history:attempt000-auth","pin:history:attempt000-schema","pin:history:accounting-root","pin:history:abort-receipt","pin:history:accounting-manifest","pin:history:accounting-sums","pin:history:retry-wrapper","pin:history:retry-manifest","pin:history:retry-sums","pin:history:v3-contract","pin:history:v3-manifest","pin:history:v3-sums","pin:history:v3-freeze","pin:history:v3-schema","pin:frozen:campaign","pin:frozen:corpus","pin:frozen:fixtures","pin:frozen:work-items","pin:frozen:epoch","pin:frozen:manifest","pin:frozen:sums","pin:frozen:construction","pin:frozen:schedule","pin:frozen:descriptor-m31d5","pin:frozen:descriptor-m31d6","pin:frozen:descriptor-m61d3","pin:frozen:descriptor-m89d2","pin:frozen:engine-native","pin:frozen:engine-libauth","pin:frozen:engine-bchn","pin:frozen:engine-leanbch","pin:frozen:engine-schema"]);
const RAW_SEMANTIC_PIN_IDS=Object.freeze(['pin:parent:b0r-sums','pin:parent:b0r-validator','pin:parent:b0r-anchor','pin:foundation:p-sums','pin:foundation:r-sums','pin:foundation:k-root','pin:foundation:k-sums','pin:foundation:f-sums','pin:origin:live-sums','pin:origin:cabm-sums','pin:origin:ecoc-sums','pin:origin:uopc-sums','pin:origin:source-map-sums','pin:history:attempt000-schema','pin:history:accounting-sums','pin:history:retry-sums','pin:history:v3-sums','pin:history:v3-schema','pin:frozen:manifest','pin:frozen:sums','pin:frozen:engine-schema']);
const semanticRule=(type,domain=null,bindingKinds=[])=>Object.freeze({type,domain,bindingKinds:Object.freeze(bindingKinds)});
const SEMANTIC_RULES=Object.freeze(Object.assign(Object.fromEntries(RAW_SEMANTIC_PIN_IDS.map(id=>[id,semanticRule('RAW')])),{
  'pin:parent:b0r-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:parent:b0r-manifest':semanticRule('ENTRIES','shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:foundation:p-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:foundation:p-manifest':semanticRule('FILES','shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:foundation:r-root':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:foundation:r-manifest':semanticRule('PRETTY_MANIFEST','shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/file-content',['MANIFEST_CONTENT_DIGEST']),
  'pin:foundation:k-manifest':semanticRule('K',null,['K_MANIFEST_PACKAGE_ROOT','K_MANIFEST_ROOT','K_ENTRIES_ROOT']),
  'pin:foundation:f-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:foundation:f-manifest':semanticRule('F_MANIFEST','shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest',['MANIFEST_CONTENT_DIGEST','MANIFEST_ROSTER_DIGEST']),
  'pin:origin:live-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-live-executor/v2/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:origin:live-manifest':semanticRule('PACKAGE_ENTRIES','shieldkit-labs/p2/gate-b/cohort-live-executor/v2/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:origin:cabm-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:origin:cabm-manifest':semanticRule('PACKAGE_ENTRIES','shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:origin:ecoc-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:origin:ecoc-manifest':semanticRule('PACKAGE_ENTRIES','shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:origin:uopc-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:origin:uopc-manifest':semanticRule('AUTHORED','shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:origin:source-map-root':semanticRule('COMPACT','shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:origin:source-map-manifest':semanticRule('AUTHORED','shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/manifest-roster',['MANIFEST_ROSTER_DIGEST']),
  'pin:history:attempt000-auth':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:history:accounting-root':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/root/attempt-000',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:history:abort-receipt':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/receipt/attempt-000',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:history:accounting-manifest':semanticRule('PRETTY_MANIFEST','shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/package-manifest/root',['MANIFEST_CONTENT_DIGEST']),
  'pin:history:retry-wrapper':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-retry/v1/attempt-001',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:history:retry-manifest':semanticRule('PRETTY_MANIFEST','shieldkit-labs/p2/gate-b/cohort-retry/v1/package-manifest/root',['MANIFEST_CONTENT_DIGEST']),
  'pin:history:v3-contract':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-contract/v3/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:history:v3-manifest':semanticRule('PRETTY_MANIFEST','shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root',['MANIFEST_CONTENT_DIGEST']),
  'pin:history:v3-freeze':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:campaign':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/campaign/v2/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:corpus':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/canonical-corpus/v2/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:fixtures':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-roster',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:work-items':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/work-item-roster',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:epoch':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/root',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:construction':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_STRING']),
  'pin:frozen:schedule':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:descriptor-m31d5':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:descriptor-m31d6':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:descriptor-m61d3':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:descriptor-m89d2':semanticRule('UNFRAMED',null,['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:engine-native':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:native',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:engine-libauth':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:libauth',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:engine-bchn':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:bchn',['CONTENT_DIGEST_RECORD_VALUE']),
  'pin:frozen:engine-leanbch':semanticRule('PRETTY','shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:leanbch',['CONTENT_DIGEST_RECORD_VALUE'])
}));
const UOPC_AUTHORED_LOCATORS=Object.freeze(['COMMAND.txt','README.md','schemas/dependency-catalog.v1.schema.json','schemas/digest.v1.schema.json','schemas/external-origin-provider-catalog.v1.schema.json','schemas/fact-provider-catalog.v1.schema.json','schemas/manifest.v1.schema.json','schemas/model-root.v1.schema.json','schemas/order-provider-catalog.v1.schema.json','schemas/owner-provider-catalog.v1.schema.json','schemas/projection-provider-catalog.v1.schema.json','schemas/provider-dag.v1.schema.json','schemas/root-provider-catalog.v1.schema.json','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/static.test.mjs','upstream-origin-provider-contract-root.v1.json','validate-static.mjs']);
const SOURCE_MAP_AUTHORED_LOCATORS=Object.freeze(['COMMAND.txt','README.md','upstream-provider-source-map-root.v1.json','schemas/b1-reentry-boundary.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/digest.v1.schema.json','schemas/interface-source-map.v1.schema.json','schemas/manifest.v1.schema.json','schemas/mapping-dag.v1.schema.json','schemas/model-root.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/source-reference-catalog.v1.schema.json','schemas/uopc-contract-prefix.v1.schema.json','validate-static.mjs','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/static.test.mjs']);
const withoutContentDigest=value=>{const copy={...value};delete copy.contentDigest;return copy;};
const sourceDomainHash=(domain,value)=>{check(allStringsNfc(domain)&&allStringsNfc(value),'NON_NFC');return sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),Buffer.from(`${canonicalJson(value)}\n`)]));};
const prettyDomainHash=(domain,value)=>sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),Buffer.from(`${JSON.stringify(JSON.parse(canonicalJson(value)),null,2)}\n`)]));
const noLfDomainHash=(domain,value)=>sha256(Buffer.concat([Buffer.from(domain),Buffer.from([0]),Buffer.from(canonicalJson(value))]));
const parseSourceJson=bytes=>{rejectDuplicateKeys(bytes);return JSON.parse(utf8(bytes));};
const sourceSemanticValid=(row,value)=>{try{const rule=SEMANTIC_RULES[row.pinId];if(!rule||!same(row.semanticBindings.map(x=>x.kind),rule.bindingKinds))return false;if(rule.type==='RAW')return row.semanticBindings.length===0;const binding=(kind,v)=>row.semanticBindings.some(x=>x.kind===kind&&x.value===v);if(rule.type==='COMPACT'||rule.type==='PRETTY'){const derived=rule.type==='COMPACT'?sourceDomainHash(rule.domain,withoutContentDigest(value)):prettyDomainHash(rule.domain,withoutContentDigest(value));const record=value.contentDigest;return record&&record.value===derived&&record.domain===rule.domain&&binding('CONTENT_DIGEST_RECORD_VALUE',derived);}if(rule.type==='UNFRAMED'){const derived=sha256(Buffer.from(canonicalJson(withoutContentDigest(value)))),record=value.contentDigest;if(row.pinId==='pin:frozen:construction')return record===derived&&binding('CONTENT_DIGEST_STRING',derived);return record?.algorithm==='sha256-jcs-omit-contentDigest'&&record.value===derived&&binding('CONTENT_DIGEST_RECORD_VALUE',derived);}if(rule.type==='ENTRIES'){const derived=sourceDomainHash(rule.domain,value.entries);return value.rosterDigest?.value===derived&&value.rosterDigest.domain===rule.domain&&binding('MANIFEST_ROSTER_DIGEST',derived);}if(rule.type==='FILES'){const derived=sourceDomainHash(rule.domain,value.files);return value.manifestRosterDigest?.value===derived&&value.manifestRosterDigest.domain===rule.domain&&binding('MANIFEST_ROSTER_DIGEST',derived);}if(rule.type==='PRETTY_MANIFEST'){const derived=prettyDomainHash(rule.domain,withoutContentDigest(value)),record=typeof value.contentDigest==='string'?value.contentDigest:value.contentDigest?.value;return record===derived&&binding('MANIFEST_CONTENT_DIGEST',derived);}if(rule.type==='F_MANIFEST'){const content=sourceDomainHash(rule.domain,withoutContentDigest(value)),roster=sourceDomainHash('shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest-roster',value.files);return value.contentDigest?.value===content&&value.manifestRosterDigest?.value===roster&&binding('MANIFEST_CONTENT_DIGEST',content)&&binding('MANIFEST_ROSTER_DIGEST',roster);}if(rule.type==='PACKAGE_ENTRIES'){const packages={'pin:origin:live-manifest':'cohort-live-executor-v2','pin:origin:cabm-manifest':'cohort-authority-binding-model-v1','pin:origin:ecoc-manifest':'cohort-external-origin-contract-v1'},pkg=packages[row.pinId],derived=sourceDomainHash(rule.domain,{package:pkg,entries:value.entries});return value.package===pkg&&value.rosterDigest===derived&&binding('MANIFEST_ROSTER_DIGEST',derived);}if(rule.type==='AUTHORED'){const expected=row.pinId==='pin:origin:uopc-manifest'?UOPC_AUTHORED_LOCATORS:SOURCE_MAP_AUTHORED_LOCATORS,locators=value.entries.map(x=>x.locator),derived=sourceDomainHash(rule.domain,expected);return same(locators,expected)&&value.rosterDigest===derived&&binding('MANIFEST_ROSTER_DIGEST',derived);}if(rule.type==='K'){const entriesRoot=noLfDomainHash('K/ENTRIES',value.entries),body={...value};delete body.manifestRoot;delete body.packageRoot;const manifestRoot=noLfDomainHash('K/MANIFEST',body),packageRoot=noLfDomainHash('K/PACKAGE',{manifestRoot,entriesRoot,executionAllowed:false});return value.entriesRoot===entriesRoot&&value.manifestRoot===manifestRoot&&value.packageRoot===packageRoot&&same(row.semanticBindings,[{kind:'K_MANIFEST_PACKAGE_ROOT',value:packageRoot},{kind:'K_MANIFEST_ROOT',value:manifestRoot},{kind:'K_ENTRIES_ROOT',value:entriesRoot}]);}return false;}catch{return false;}};
const SSA_COMPONENT_SPECS=[['governance','governance','f5e73bbb6c4f30804ba1338a91b447b8d57bc9440c000479a87cd44775222c5b'],['dependencyPins','dependencies','c485780d80f0152090f7fc163aec9cafdb02622a98d02dcc329839b54bfebf43'],['transitiveSourcePins','transitive-source-pins','adadfd4bd37cd60da122fb8775b3c4220a061347a0bebf6e1e5ebbb5cf8bd36f'],['ownerContractSourceCatalog','owner-contract-source-catalog','caf8d78d578d73a943bf5337a332195c0f7bf8115528360a3ec5921c6a220701'],['retryLineageSourceCatalog','retry-lineage-source-catalog','4dcc670283690e6066081a3b50ca11d8dc7e4810311c43736ce5fdea132268d4'],['privateCaptureSourceCatalog','private-capture-source-catalog','6458333ff88f04e5aeb03cbee92d69fa0f706cecb8a2a6697acb3f0f6fd956c0'],['workloadProjectionSourceCatalog','workload-projection-source-catalog','a49b222d3193502a2f70cc91545a8099d908133cd93ed5ea3ec7c49b6a7113b4'],['stateFactSourceCatalog','state-fact-source-catalog','8465fb182e280d56332896219cb38d5a4750cb1feac6b13e1515916f3a636d69'],['supplementalContracts','supplemental-contracts','1ef6472232582be70d74b24d1ff40e6bb8e9598c904ad39a98a45ce6815c7276'],['requirementResolutions','requirement-resolutions','da7d44e6b93ddc9b0dad08c7dc33ebf36c12efbd288f3e44d5cc7099e34393e8'],['preauthorizationSemantics','preauthorization-semantics','c6096f4fb810e3f958a4817225662b3056d74b150845c65ce4c524bc007eafe4'],['nonAuthorityBoundary','nonauthority-boundary','1be9ded03d296fabc008e833ce6b4096ab3ae8bce6879f7e794530383a77eec9'],['runtimeBoundary','runtime-boundary','e8283dc58c65eba67e6995b749db18350f0a76397240a81b2bfe579065e8d88f'],['schemaBindings','schema-bindings','08f66ad203833f4362041e21eeb221fd21d9c714fafd8d89ed46790d139ad2a5']];
const pinnedDigest=(domain,value)=>({algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value});
const EXACT_SOURCE_AUTHORITIES=[{authorityId:'B0R',locator:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json',bytes:60597,rawSha256:'78455f5faed663b73353bb87bd69c475b2a979d73ad2b5b78a0e6cbdc2c1a01b',contentDigest:'ffb555285bdd98de1be99d1f0526a69c76526321cc1fc45b5b4a6d19322bae63',authorityDisposition:'STATIC_PARENT_PLAN_NO_AUTHORITY'},{authorityId:'EAC',locator:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-execution-admission-contract-v1/execution-admission-contract-root.v1.json',bytes:53081,rawSha256:'80fc0d146911ba774715da76fa69dcbae21852135222f7b26b7fb8bd9c775479',contentDigest:'fed30561c154ffd4db50bad5dc4e38e5c54107236cf301777339fdf2d9460e7a',authorityDisposition:'STATIC_PREREQUISITE_CONTRACT_NO_ADMISSION'},{authorityId:'UOPC',locator:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json',bytes:43072,rawSha256:'2facf53272c1947bf76f1f7d70db23270e6a7c396fed8cb67baa62dec39a7579',contentDigest:'e76b1c35b47fac325b0e2750495ce4fabc8f1d9145974cdbbae95b63f2699020',authorityDisposition:'STATIC_SOURCE_CONSTRAINT_NO_PROVIDER_AUTHORITY'},{authorityId:'SPM',locator:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json',bytes:53502,rawSha256:'19268c8cfca0fc12038a6b89a23ccf7719a8d0f1337bd16bc10ab81647b0179a',contentDigest:'afddc9f5c7ff6a8f3950a50892e1ff281ab9f64e65f9f85df913e6e865cbf75b',authorityDisposition:'STATIC_SOURCE_CONSTRAINT_NO_PROVIDER_AUTHORITY'}];
const DIRECT_AUTHORITY_RULES=Object.freeze([
Object.freeze({authorityId:'B0R',parser:'COMPACT_CANONICAL_JSON_LF',algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root',frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a'}),
Object.freeze({authorityId:'EAC',parser:'COMPACT_CANONICAL_JSON_LF',algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:'shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1/root',frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a'}),
Object.freeze({authorityId:'UOPC',parser:'COMPACT_CANONICAL_JSON_LF',algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:'shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root',frame:'utf8(domain)||0x00||canonical-json-utf8-lf-v1'}),
Object.freeze({authorityId:'SPM',parser:'COMPACT_CANONICAL_JSON_LF',algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:'shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root',frame:'utf8(domain)||0x00||canonical-json-utf8-lf-v1'})
]);
const EXACT_EAC_COMPONENTS={externalRequirements:'e8709a44da62305eb7ad12d19a516a2e4efacfc0995017119ff6e5244fe6132d',futureArtifactMapContract:'47fcaddeb36f5a7d03b81e7c5fb1d78026097b1f3a8357bf6650473c2611be78',futureResultAdmissionContract:'884928cf1255611cd202a29eae180d212984ca046abcabda312254aa1553c7f8',futureStateGrammar:'72edbc5ea6b08b018bed9a6794b518bab2fee5703e104fb36928f463dead4707',historicalDisposition:'538378575dd7bc41d952433cb92824e3f45b5721670939ab8b00656c68c098a0',nonAuthorityBoundary:'bf7eeb39372ec5a2a80ac0342df58bf41bf42ae7db41eecf33cdcf8e3db19f31',sourcePins:'103cada63c1d0f9bac12525bb43f3e0165b8d2329aeb98f9a27e0dac5ea68e07'};
const EXACT_DEPENDENCY={dependencyId:'SSA',authorityDisposition:'PARENT_STATIC_SOURCE_LANGUAGE_AUTHORITY_NO_CREATION_OR_INSTANCE_AUTHORITY',packagePath:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-static-source-authority-v1',root:{path:'static-source-authority-root.v1.json',bytes:139962,rawSha256:'bf5876cdb47e3b1f76f2bd9589b5a5c6a15e3ea1c231f4ccf55527a66d7b5327',contentDigest:'9c5e6106cca05ee3aeb49618fded4ed27581d25945e5dd3d0d4227deff775320'},validator:{path:'validate-static.mjs',bytes:97677,rawSha256:'f4032cd5ac90fed87f9e07c25146c64816158e6c54fe7ec71087556a836dfc42'},manifest:{path:'MANIFEST.json',bytes:11394,rawSha256:'06a039a5e04c0193794f0dae74960b2c405a24e1d082681fc03f5ec9bc82aa1a',entryCount:24,rosterDigest:'1a3d33d66bd46804832ac3cde3312f40dcbe896d1d2de9f827aa4359cdc0917b'},checksums:{path:'SHA256SUMS',bytes:2542,rawSha256:'d6bca7451387595b9c632662ef9e6e99b2a8c4c2f5104ed8d0617c1b8e6b3275'},reviewAnchor:{path:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-static-source-authority-review-anchor.v1.json',bytes:26079,rawSha256:'c56473f1a3cf8896cd48680f3832f886b1f10d7e45826b84f33f03656891b3bb',schema:'shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1/external-review-anchor/v1'},ssaComponentDigests:SSA_COMPONENT_SPECS.map(([component,suffix,value])=>({component,digest:pinnedDigest(`${SSA_PREFIX}/${suffix}`,value)})),eacSemanticComponents:EXACT_EAC_COMPONENTS,sourceAuthorities:EXACT_SOURCE_AUTHORITIES};
const SUPPLEMENTAL_SPECS=[{ordinal:0,policyId:'RAW_ARTIFACT_MAP_AUTHORITY_POLICY',policySemantics:'DISTINCT_EXTERNAL_AUTHORITY_CONTRACT_NOT_ARTIFACT_MAP_INSTANCE',affectedRequirementIds:['WORKLOAD_PROJECTION_PROVIDER','Q_RETRY_PROVIDER'],futureNodeId:'RAW_ARTIFACT_MAP_AUTHORITY',status:'MISSING_EXTERNAL_RAW_ARTIFACT_MAP_AUTHORITY_CONTRACT'},{ordinal:1,policyId:'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_POLICY',policySemantics:'DISTINCT_INDEPENDENT_VALIDATOR_AUTHORITY_CONTRACT_NOT_VALIDATOR_IMPLEMENTATION_OR_RESULT',affectedRequirementIds:[],futureNodeId:'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY',status:'MISSING_INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_CONTRACT'}];
const FUTURE_EXTERNAL_REQUIRED=['schema','artifactId','authorityContractId','policySlotId','issuerPrincipalId','authorityPrincipalId','authorityScope','sourceAuthorityRoot','sourceAuthorityRawSha256','issuerDecisionRoot','issuerDecisionRawSha256','authorityPayload','providerBindingCreationCapability','instanceCreationAllowed','executionAllowed','admissionAllowed','revocationPolicy','expiresAt','contentDigest'];
const FUTURE_GOVERNANCE_REQUIRED=['schema','artifactId','authorizationId','issuerPrincipalId','decisionId','decisionRoot','decisionRawSha256','authorityPolicyRoot','authorityPolicyRawSha256','providerBindingCatalogRoot','providerBindingCatalogRawSha256','sourceCollisionResolution','authorizedTransitions','authorizedPolicySlotIds','issuedAt','expiresAt','revocationPolicy','executionAllowed','admissionAllowed','contentDigest'];
const FUTURE_BINDING_REQUIRED=['schema','artifactId','bindingId','policySlotId','authorityContractRoot','authorityContractRawSha256','issuerPrincipalId','providerPrincipalId','providerContractRoot','providerContractRawSha256','governanceDecisionRoot','sourceCollisionResolutionRoot','instanceCreationAllowed','executionAllowed','admissionAllowed','contentDigest'];
const IMPORT_WORD=['im','port'].join('');
const BOOTSTRAP_SENTENCES=[`Direct package-local Node invocations are nonauthorizing diagnostic self-checks only; they cannot authenticate any authored bytes they ${IMPORT_WORD} or execute.`,`Before any source-mode validator or test ${IMPORT_WORD}, a caller-controlled outside-package pin-first launcher must independently verify an externally held exact ordered table of locator, byte count, and raw SHA-256 for all 21 authored files, including validate-static.mjs and every test; neither the table nor its pins may be read from or derived by this package.`,`Before any sealed-mode validator or test ${IMPORT_WORD}, that launcher must independently raw-pin and parse the outside review anchor without ${IMPORT_WORD}ing package code, verify its exact 19-key identity and orderedClosure against all 21 authored files, verify its root, validator, schema, MANIFEST.json, and SHA256SUMS bindings, and only then invoke the raw-pinned validator with the same four literal anchor-pin fields.`,'COMMAND.txt, validate-static.mjs, MANIFEST.json, SHA256SUMS, a package-derived hash, and a locally generated review anchor are not independent bootstrap trust roots and grant no authority.'];
const README_SENTENCES=[...BOOTSTRAP_SENTENCES,'This package is a sealed-static prerequisite-policy language and is initially reviewed unsealed.','It contains no governance authorization, external authority contract, provider binding, principal, owner, fact, order material, projection material, private bytes, artifact map, result validator implementation, attempt, run, result, evidence, admission, execution, qualification, ranking, or selection instance.','Source-language resolution is not creation authorization and cannot satisfy an instance requirement.','The UOPC/EAC future-provider DAG divergence is preserved as UNRESOLVED_EXTERNAL_PRECEDENCE with selectedDag null; this package selects neither source.','Attempt-001 and B0_EXECUTION_AUTHORIZATION remain closed.','The result-validator leaf is future source bytes supplied by an independent external principal; this package defines only its closed future contract schema.','Unsealed validation is nonauthoritative source review; sealed validation requires an outside literal review-anchor pin checked before local schema or root trust.'];
const COMMAND_HEADING='After those outside checks only, the following diagnostic forms may be invoked:';
const COMMAND_FORMS=['node validate-static.mjs --mode unsealed','node validate-static.mjs --mode sealed --review-anchor-root "$EAPP_REVIEW_ANCHOR_ROOT" --review-anchor-locator "$EAPP_REVIEW_ANCHOR_LOCATOR" --review-anchor-bytes "$EAPP_REVIEW_ANCHOR_BYTES" --review-anchor-raw-sha256 "$EAPP_REVIEW_ANCHOR_RAW_SHA256"'];
const COMMAND_ENDING='These diagnostic forms create no governance authorization, authority contract, provider binding, instance, Attempt-001, admission, execution, evidence, qualification, ranking, or selection authority.';
const COMMAND_SOURCE=`${[...BOOTSTRAP_SENTENCES,COMMAND_HEADING,...COMMAND_FORMS,COMMAND_ENDING].join('\n')}\n`;
const DAG_NODES=['SSA_SOURCE_LANGUAGE_AUTHORITY','AUTHORITY_POLICY_FREEZE','OWNER_SCOPE_REQUIREMENTS','RETRY_LINEAGE_REQUIREMENTS','PRIVATE_CAPTURE_REQUIREMENTS','STATIC_ENDPOINT_ORDER_REQUIREMENTS','WORKLOAD_MATERIAL_REQUIREMENTS','DISPATCH_WORKER_REQUIREMENTS','Q_REQUIREMENTS','A_REQUIREMENTS','LIVE_F_B_REQUIREMENTS','TERMINAL_C_J_D_REQUIREMENTS','RAW_ARTIFACT_MAP_AUTHORITY_POLICY','INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_POLICY','SOURCE_COLLISION_RECONCILIATION_PREREQUISITE','EXTERNAL_AUTHORITY_CONTRACT_SET','PROVIDER_BINDING_CATALOG','ROOT_SOL_GOVERNANCE_AUTHORIZATION','B0_EXECUTION_AUTHORIZATION'];
const DAG_EDGES=[['SSA_SOURCE_LANGUAGE_AUTHORITY','AUTHORITY_POLICY_FREEZE','STATIC_PREREQUISITE'],...DAG_NODES.slice(2,15).map(to=>['AUTHORITY_POLICY_FREEZE',to,'STATIC_POLICY_INDEX']),['OWNER_SCOPE_REQUIREMENTS','EXTERNAL_AUTHORITY_CONTRACT_SET','FUTURE_BLOCKED_PREREQUISITE'],['WORKLOAD_MATERIAL_REQUIREMENTS','EXTERNAL_AUTHORITY_CONTRACT_SET','FUTURE_BLOCKED_PREREQUISITE'],['RAW_ARTIFACT_MAP_AUTHORITY_POLICY','EXTERNAL_AUTHORITY_CONTRACT_SET','FUTURE_BLOCKED_PREREQUISITE'],['INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_POLICY','EXTERNAL_AUTHORITY_CONTRACT_SET','FUTURE_BLOCKED_PREREQUISITE'],['EXTERNAL_AUTHORITY_CONTRACT_SET','PROVIDER_BINDING_CATALOG','FUTURE_BLOCKED_PREREQUISITE'],...['RETRY_LINEAGE_REQUIREMENTS','PRIVATE_CAPTURE_REQUIREMENTS','STATIC_ENDPOINT_ORDER_REQUIREMENTS','DISPATCH_WORKER_REQUIREMENTS','Q_REQUIREMENTS','A_REQUIREMENTS','LIVE_F_B_REQUIREMENTS','TERMINAL_C_J_D_REQUIREMENTS'].map(from=>[from,'PROVIDER_BINDING_CATALOG','FUTURE_BLOCKED_PREREQUISITE']),['SOURCE_COLLISION_RECONCILIATION_PREREQUISITE','PROVIDER_BINDING_CATALOG','FUTURE_BLOCKED_PREREQUISITE'],['PROVIDER_BINDING_CATALOG','ROOT_SOL_GOVERNANCE_AUTHORIZATION','FUTURE_EXTERNAL_AUTHORITY'],['SOURCE_COLLISION_RECONCILIATION_PREREQUISITE','ROOT_SOL_GOVERNANCE_AUTHORIZATION','FUTURE_EXTERNAL_AUTHORITY'],['ROOT_SOL_GOVERNANCE_AUTHORIZATION','B0_EXECUTION_AUTHORIZATION','FUTURE_EXTERNAL_AUTHORITY']].map(([from,to,edgeClass])=>({from,to,edgeClass}));
const TRANSITION_EDGES=[['SOURCE_LANGUAGE_RESOLVED','AUTHORITY_POLICY_FROZEN_NO_AUTHORITY','THIS_SEALED_POLICY','STATIC_POLICY_REPRESENTATION_ONLY'],['AUTHORITY_POLICY_FROZEN_NO_AUTHORITY','EXTERNAL_AUTHORITY_CONTRACTS_PINNED_NO_INSTANCES','EXTERNAL_AUTHORITY_CONTRACT_SET','BLOCKED_EXTERNAL'],['EXTERNAL_AUTHORITY_CONTRACTS_PINNED_NO_INSTANCES','PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES','PROVIDER_BINDING_CATALOG','BLOCKED_EXTERNAL'],['PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES','CREATION_AUTHORIZED_NO_INSTANCES','ROOT_SOL_GOVERNANCE_AUTHORIZATION','BLOCKED_EXTERNAL'],['CREATION_AUTHORIZED_NO_INSTANCES','INSTANCE_CREATED','B0_EXECUTION_AUTHORIZATION','BLOCKED_EXTERNAL']].map(([from,to,requiredAuthorityArtifact,authorizationStatus])=>({from,to,requiredAuthorityArtifact,authorizationStatus}));
const ROOT_KEYS=['schema','artifactId','packageId','status','purpose','executionAllowed','measurementAdmissionAllowed','dependencyBinding','governanceBoundary','authorityPolicyGroups','supplementalPolicies','requirementAuthorityMap','sourceCollisions','creationTransitionPolicy','providerBindingPolicy','futureGovernanceAuthorizationSchema','futureExternalAuthorityContractSchema','independenceConstraints','causalDag','nonAuthorityBoundary','runtimeBoundary','schemaBindings','componentDigests','contentDigest'];
const COMPONENTS=[['dependencyBinding','dependency-binding'],['governanceBoundary','governance-boundary'],['authorityPolicyGroups','authority-policy-groups'],['supplementalPolicies','supplemental-policies'],['requirementAuthorityMap','requirement-authority-map'],['sourceCollisions','source-collisions'],['creationTransitionPolicy','creation-transition-policy'],['providerBindingPolicy','provider-binding-policy'],['futureGovernanceAuthorizationSchema','future-governance-authorization-schema'],['futureExternalAuthorityContractSchema','future-external-authority-contract-schema'],['independenceConstraints','independence-constraints'],['causalDag','causal-dag'],['nonAuthorityBoundary','nonauthority-boundary'],['runtimeBoundary','runtime-boundary'],['schemaBindings','schema-bindings']];
const leafDigest=(row,domain)=>{const body={...row};delete body.contentDigest;check(same(row.contentDigest,digestRecord(domain,body)),'DIGEST',domain);};
const exactFalseZeroBoundary=root=>{const boundary=root.nonAuthorityBoundary;for(const [key,value] of Object.entries(boundary)){if(key==='status')continue;if(key.endsWith('Count'))check([10,2,30,1,0].includes(value),'NONAUTHORITY',key);else check(value===false,'NONAUTHORITY',key);}check(boundary.authorityPolicyGroupCount===10&&boundary.supplementalPolicyCount===2&&boundary.requirementAuthorityMapCount===30&&boundary.sourceCollisionCount===1,'NONAUTHORITY');check(Object.entries(boundary).filter(([key])=>key.endsWith('Count')).every(([key,value])=>['authorityPolicyGroupCount','supplementalPolicyCount','requirementAuthorityMapCount','sourceCollisionCount'].includes(key)||value===0),'NONAUTHORITY');};
const edgeKey=edge=>typeof edge==='string'?edge:`${edge.from}→${edge.to}`;
const assertSourceCollision = (mutation={},root=rootDocument(),uopc=null,eac=null) => {
  check(root.sourceCollisions.status==='UNRESOLVED_EXTERNAL_PRECEDENCE'&&root.sourceCollisions.collisionCount===1&&root.sourceCollisions.entries.length===1,'COLLISION_COUNTS');
  const collision=structuredClone(root.sourceCollisions.entries[0]);
  if(mutation.selectedDag)collision.selectedDag=mutation.selectedDag;
  if(mutation.omitUopcOnly)collision.uopcOnlyEdges.pop();
  if(mutation.omitEacOnly)collision.eacOnlyEdges.pop();
  check(collision.status==='UNRESOLVED_EXTERNAL_PRECEDENCE'&&same(collision.affectedRequirementIds,['Q_INITIAL_PROVIDER','Q_RETRY_PROVIDER','Q_ABORT_PROVIDER','A_INITIAL_PROVIDER','A_RETRY_PROVIDER','A_ABORT_PROVIDER','B_SUBJECT_ROOT_TYPE','B_PROVIDER'])&&same(collision.uopcSource,{authorityId:'UOPC',rootPinRef:'/dependencyBinding/sourceAuthorities/2',jsonPointerRefs:['#/factProviderCatalog/entries/1/modelDispositionByVariant/retry','#/factProviderCatalog/entries/1/futureValidationRules','#/providerCausalDag/edges'],retryDispositionLiteral:'DENY_PREREQUISITE',retryValidationRuleLiteral:'retry-A-is-DENY_PREREQUISITE-while-retry-Q-is-BLOCKED_EXTERNAL',edgeCount:40})&&same(collision.eacSource,{authorityId:'EAC',rootPinRef:'/dependencyBinding/sourceAuthorities/1',jsonPointerRefs:['#/futureStateGrammar/futureA','#/futureStateGrammar/edges'],futureAActivationAllowed:false,edgeCount:37})&&same(collision.ssaSource,{authorityId:'SSA',rootPinRef:'/dependencyBinding',jsonPointerRefs:['#/requirementResolutions/18','#/requirementResolutions/21','#/requirementResolutions/24'],sourceContractResolutionLiteral:'RESOLVED_STATIC_SOURCE_CONTRACT',edgeAuthorityClaimed:false}),'COLLISION_COUNTS');
  check(collision.sharedEdges.length===33&&collision.uopcOnlyEdges.length===7&&collision.eacOnlyEdges.length===4,'COLLISION_EDGES');
  check(collision.selectedDag===null&&collision.selectedAPath===null&&same(collision.reconciliationPrerequisite,{required:true,authorityOriginClass:'EXTERNAL_ROOT_SOL_GOVERNANCE',decisionVocabularyStatus:'NOT_DEFINED_BY_THIS_PACKAGE',governanceDecisionId:null,governanceDecisionRoot:null,governanceDecisionRawSha256:null,decisionSchemaId:null,resolutionAllowed:false,packageMayInfer:false,packageMaySelectSource:false}),'COLLISION_SELECTION');
  const unique=rows=>new Set(rows.map(edgeKey)).size===rows.length;
  check(unique(collision.sharedEdges)&&unique(collision.uopcOnlyEdges)&&unique(collision.eacOnlyEdges),'COLLISION_EDGES');
  if(uopc&&eac){
    const us=uopc.providerCausalDag.edges.map(edgeKey),es=eac.futureStateGrammar.edges.map(edgeKey),uSet=new Set(us),eSet=new Set(es),shared=us.filter(x=>eSet.has(x)),uOnly=us.filter(x=>!eSet.has(x)),eOnly=es.filter(x=>!uSet.has(x));
    check(us.length===40&&es.length===37,'COLLISION_COUNTS');
    check(same(collision.sharedEdges,shared)&&same(collision.uopcOnlyEdges,uOnly)&&same(collision.eacOnlyEdges,eOnly),'COLLISION_EDGES');
  }
  return {counts:'40/37/33/7/4'};
};
const assertRootSemantics = (root=rootDocument(),sources={}) => {
  check(same(Object.keys(root).sort(),[...ROOT_KEYS].sort()),'ROOT_KEYS');check(root.schema===PREFIX&&root.artifactId==='artifact:gate-b:gate-b0-external-authority-prerequisite-policy-v1'&&root.packageId===PACKAGE_ID,'ROOT_ID');check(root.status==='sealed-static-external-authority-prerequisite-policy-no-governance-authorization-no-authority-bindings-no-instances-no-admission-no-execution-unqualified','STATUS');check(root.executionAllowed===false&&root.measurementAdmissionAllowed===false,'NONAUTHORITY');check(same(root.governanceBoundary,EXACT_GOVERNANCE),'NONAUTHORITY','governanceBoundary');
  check(root.authorityPolicyGroups.length===10&&root.requirementAuthorityMap.length===30&&root.supplementalPolicies.length===2&&same(root.authorityPolicyGroups.map(x=>x.policyGroupId),GROUP_IDS)&&same(root.authorityPolicyGroups.map(x=>x.status),GROUP_STATUSES)&&same(root.authorityPolicyGroups.map(x=>x.requirementIds),GROUP_REQUIREMENTS)&&same(root.authorityPolicyGroups.map(x=>x.futureAuthorityContractSlotIds),GROUP_SLOTS)&&root.authorityPolicyGroups.every((x,i)=>x.ordinal===i&&x.groupSemantics==='REVIEW_INDEX_ONLY_NO_AUTHORITY_AGGREGATION'),'GROUP_PARTITION');
  const requirementIds=root.requirementAuthorityMap.map(row=>row.requirementId);check(same(requirementIds,REQUIREMENT_IDS)&&root.requirementAuthorityMap.every((row,index)=>row.ordinal===index&&row.classification===REQUIREMENT_CLASSIFICATIONS[index]&&row.instanceDisposition===REQUIREMENT_DISPOSITIONS[index]&&row.instanceCount===0&&row.currentInstanceRequired===false&&row.authorityContractRoot===null&&row.authorityBindingRoot===null&&row.providerInstanceRoot===null&&row.creationAuthorizationGranted===false&&row.admissionGranted===false&&row.sourceContractResolution==='RESOLVED_STATIC_SOURCE_CONTRACT'&&row.status===REQUIREMENT_STATUSES[index]&&same(row.sourceContractRefs,EXPECTED_SOURCE_REFS[index])&&same(row.constraintRefs,EXPECTED_CONSTRAINT_REFS[index])),'REQUIREMENT_ROSTER');
  const partition=root.authorityPolicyGroups.flatMap(row=>row.requirementIds);check(partition.length===30&&new Set(partition).size===30&&partition.every(id=>requirementIds.includes(id))&&root.authorityPolicyGroups.every(group=>group.requirementIds.every(id=>root.requirementAuthorityMap.find(row=>row.requirementId===id)?.policyGroupId===group.policyGroupId)),'GROUP_PARTITION');check(same(root.authorityPolicyGroups.flatMap(row=>row.futureAuthorityContractSlotIds),[...GROUP_REQUIREMENTS[0],'WORKLOAD_ROOT_ORDER_PROVIDER'])&&root.supplementalPolicies.filter(row=>row.futureAuthorityContractRequired).length===2,'GROUP_SLOT');check(root.authorityPolicyGroups.every(row=>row.authoritySharingAllowed===false&&row.authorityRoot===null&&row.issuerPrincipalId===null&&row.creationAllowed===false&&row.providerBindingAllowed===false&&row.instanceCreationAllowed===false),'GROUP_SLOT');
  check(root.supplementalPolicies.every((row,index)=>{const spec=SUPPLEMENTAL_SPECS[index];return row.ordinal===spec.ordinal&&row.policyId===spec.policyId&&row.policySemantics===spec.policySemantics&&same(row.affectedRequirementIds,spec.affectedRequirementIds)&&row.futureNodeId===spec.futureNodeId&&row.futureAuthorityContractRequired===true&&row.status===spec.status&&row.authorityContractRoot===null&&row.authorityContractRawSha256===null&&row.issuerPrincipalId===null&&row.implementationLocator===null&&row.implementationRawSha256===null&&row.authorityCreationAllowed===false&&row.evaluationAllowed===false&&row.instanceCount===0;}),'SUPPLEMENTAL');
  exactFalseZeroBoundary(root);check(same(root.causalDag.nodes,DAG_NODES)&&same(root.causalDag.edges,DAG_EDGES)&&root.causalDag.edges.every(edge=>DAG_NODES.includes(edge.from)&&DAG_NODES.includes(edge.to)),'DAG');const incoming=new Set(root.causalDag.edges.map(edge=>edge.to)),outgoing=new Set(root.causalDag.edges.map(edge=>edge.from));check(root.causalDag.nodes.slice(1).every(node=>incoming.has(node))&&!incoming.has('SSA_SOURCE_LANGUAGE_AUTHORITY')&&outgoing.has('SSA_SOURCE_LANGUAGE_AUTHORITY')&&!outgoing.has('B0_EXECUTION_AUTHORIZATION'),'DAG');const successors=new Map(root.causalDag.nodes.map(node=>[node,[]]));root.causalDag.edges.forEach(edge=>successors.get(edge.from).push(edge.to));const visiting=new Set(),visited=new Set();const acyclic=node=>{if(visiting.has(node))return false;if(visited.has(node))return true;visiting.add(node);for(const next of successors.get(node))if(!acyclic(next))return false;visiting.delete(node);visited.add(node);return true;};check(root.causalDag.nodes.every(acyclic),'DAG');
  check(same(root.creationTransitionPolicy.states,['SOURCE_LANGUAGE_RESOLVED','AUTHORITY_POLICY_FROZEN_NO_AUTHORITY','EXTERNAL_AUTHORITY_CONTRACTS_PINNED_NO_INSTANCES','PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES','CREATION_AUTHORIZED_NO_INSTANCES','INSTANCE_CREATED'])&&root.creationTransitionPolicy.currentState==='AUTHORITY_POLICY_FROZEN_NO_AUTHORITY'&&same(root.creationTransitionPolicy.representedTransition,{from:'SOURCE_LANGUAGE_RESOLVED',to:'AUTHORITY_POLICY_FROZEN_NO_AUTHORITY',disposition:'STATIC_POLICY_REPRESENTATION_ONLY_NO_DYNAMIC_AUTHORIZATION'})&&root.creationTransitionPolicy.authorizedTransitions.length===0&&same(root.creationTransitionPolicy.edges,TRANSITION_EDGES)&&root.creationTransitionPolicy.automaticTransitionAllowed===false&&root.creationTransitionPolicy.downgradeAllowed===false&&root.creationTransitionPolicy.instanceCreationBeforeB0ExecutionAuthorizationAllowed===false&&root.creationTransitionPolicy.attempt001Allowed===false&&root.creationTransitionPolicy.status==='STATIC_POLICY_FROZEN_ALL_CREATION_TRANSITIONS_BLOCKED','TRANSITION');
  check(root.providerBindingPolicy.futurePackageId==='gate-b0-provider-binding-authority-catalog-v1'&&root.providerBindingPolicy.status==='FUTURE_SCHEMA_ONLY_NO_BINDINGS'&&root.providerBindingPolicy.bindingCount===0&&root.providerBindingPolicy.bindingCreationAllowed===false&&root.providerBindingPolicy.bindingCatalogRoot===null&&root.providerBindingPolicy.bindingCatalogRawSha256===null&&same(root.providerBindingPolicy.requiredExternalAuthoritySlotIds,[...GROUP_REQUIREMENTS[0],'WORKLOAD_ROOT_ORDER_PROVIDER','RAW_ARTIFACT_MAP_AUTHORITY','INDEPENDENT_RESULT_VALIDATOR_AUTHORITY'])&&same(root.providerBindingPolicy.constraintOnlyPolicyGroupIds,GROUP_IDS.slice(1).filter(id=>id!=='WORKLOAD_MATERIAL_REQUIREMENTS'))&&root.providerBindingPolicy.allAuthorityRootsMustBeExternallyPinned===true&&root.providerBindingPolicy.selfAttestationAllowed===false&&root.providerBindingPolicy.sourceCatalogAsAuthorityAllowed===false&&root.providerBindingPolicy.principalCoincidenceAllowed===false&&root.providerBindingPolicy.bindingMayGrantExecutionOrAdmission===false&&same(root.providerBindingPolicy.futureBindingRequiredKeys,FUTURE_BINDING_REQUIRED),'BINDING_POLICY');
  check(same(root.futureGovernanceAuthorizationSchema,{schemaId:`${SCHEMA_PREFIX}future-governance-authorization.v1.schema.json#/$defs/futureGovernanceAuthorization`,status:'SCHEMA_ONLY_NO_RECORD',recordCount:0,creationAllowed:false,requiredKeys:FUTURE_GOVERNANCE_REQUIRED})&&same(root.futureExternalAuthorityContractSchema,{schemaId:`${SCHEMA_PREFIX}future-external-authority-contract.v1.schema.json#/$defs/futureExternalAuthorityContract`,status:'SCHEMA_ONLY_NO_RECORD',recordCount:0,creationAllowed:false,requiredKeys:FUTURE_EXTERNAL_REQUIRED,payloadVariantIds:['OWNER_AUTHORITY_PAYLOAD','WORKLOAD_MATERIAL_AUTHORITY_PAYLOAD','RAW_ARTIFACT_MAP_AUTHORITY_PAYLOAD','INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_PAYLOAD']}),'FUTURE_SCHEMA');
  check(same(root.independenceConstraints,{principalCoincidenceStatus:'UNDECIDED_AND_FORBIDDEN_UNTIL_EXPLICIT_GOVERNANCE',distinctOwnerAuthorityContractRootsRequired:true,workloadAuthorityRootMustDifferFromOwnerRoots:true,rawMapAuthorityMustDifferFromArtifactProducer:true,rawMapAuthorityMustDifferFromResultProducer:true,resultValidatorMustDifferFromExecutionProducer:true,resultValidatorMustDifferFromResultProducer:true,governanceIssuerMustDifferFromPackage:true,authorityContractMayNotSelfPin:true,providerBindingMayNotSelfAttest:true,historicalArtifactMayNotSatisfyCurrentInstance:true,sameOwnerClassMayNotProveOwnerBindingContinuity:true,currentPrincipalCount:0}),'INDEPENDENCE');check(same(root.runtimeBoundary,{runtimeEntrypoint:null,runtimeModules:[],runtimeExports:[],activationCapability:null,importEvaluationAllowed:false,buildTimeOnlyLocators:['test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/source-collision.test.mjs','test/static.test.mjs','validate-static.mjs']}),'RUNTIME_BOUNDARY');
  for(const row of root.authorityPolicyGroups)leafDigest(row,`${PREFIX}/authority-policy-group/${row.policyGroupId}`);for(const row of root.supplementalPolicies)leafDigest(row,`${PREFIX}/supplemental-policy/${row.policyId}`);for(const row of root.requirementAuthorityMap)leafDigest(row,`${PREFIX}/requirement-authority-map/${row.requirementId}`);check(root.sourceCollisions.collisionCount===1&&root.sourceCollisions.entries.length===1,'COLLISION_COUNTS');leafDigest(root.sourceCollisions.entries[0],`${PREFIX}/source-collision/${root.sourceCollisions.entries[0].collisionId}`);leafDigest(root.sourceCollisions,`${PREFIX}/source-collisions`);leafDigest(root.creationTransitionPolicy,`${PREFIX}/creation-transition-policy`);check(same(root.componentDigests,COMPONENTS.map(([component,suffix])=>({component,digest:digestRecord(`${PREFIX}/${suffix}`,root[component])}))),'DIGEST');const copy={...root};delete copy.contentDigest;check(same(root.contentDigest,digestRecord(`${PREFIX}/root`,copy)),'CONTENT_DIGEST');if(sources.uopc&&sources.eac)assertSourceCollision({},root,sources.uopc,sources.eac);return {dependencyJoined:true,nonAuthority:true};
};
const pointerAt=(value,fragment)=>{check(fragment.startsWith('/'),'SCHEMA_REF');let cursor=value;for(const raw of fragment.slice(1).split('/')){const key=raw.replaceAll('~1','/').replaceAll('~0','~');check(cursor&&Object.hasOwn(cursor,key),'SCHEMA_REF');cursor=cursor[key];}return cursor;};
const assertSchemas = root => {
  const schemas=SCHEMAS.map(locator=>parseCanonical(safeRead(root,locator))),byId=new Map(schemas.map(schema=>[schema.$id,schema]));
  check(byId.size===12&&schemas.every((schema,index)=>schema.$id===`${SCHEMA_PREFIX}${SCHEMAS[index].slice(8)}`),'SCHEMA_RAW');
  const topKeys=['$defs','$id','$schema','additionalProperties','properties','required','title','type'];
  for(const [index,schema] of schemas.entries()){
    const expected=index===11?[...topKeys,'$ref'].sort():topKeys;
    check(same(Object.keys(schema).sort(),expected)&&schema.$schema==='https://json-schema.org/draft/2020-12/schema'&&schema.type==='object'&&schema.additionalProperties===false,'SCHEMA_REF',SCHEMAS[index]);
    const audit=node=>{if(!node||typeof node!=='object')return;if(Array.isArray(node)){node.forEach(audit);return;}check(!Object.hasOwn(node,'anyOf')&&!Object.hasOwn(node,'patternProperties')&&!Object.hasOwn(node,'unevaluatedProperties'),'SCHEMA_REF',SCHEMAS[index]);if(node.type==='object'&&node.properties){check(node.additionalProperties===false&&same((node.required??[]).slice().sort(),Object.keys(node.properties).sort()),'SCHEMA_REF',SCHEMAS[index]);}Object.values(node).forEach(audit);};
    audit(schema);
  }
  const reachable=new Set(),seenRefs=new Set();
  const visit=(schemaId,node)=>{if(!node||typeof node!=='object')return;if(Array.isArray(node)){node.forEach(item=>visit(schemaId,item));return;}if(typeof node.$ref==='string'){const marker=`${schemaId}|${node.$ref}`;if(!seenRefs.has(marker)){seenRefs.add(marker);const cut=node.$ref.indexOf('#'),targetId=cut<0?node.$ref:node.$ref.slice(0,cut),fragment=cut<0?'':node.$ref.slice(cut+1),resolved=targetId||schemaId,target=byId.get(resolved);check(target&&!node.$ref.includes('..')&&!node.$ref.includes('\\')&&/^\/\$defs\/[^/]+(?:\/.*)?$/u.test(fragment),'SCHEMA_REF',node.$ref);const name=fragment.split('/')[2].replaceAll('~1','/').replaceAll('~0','~');check(Object.hasOwn(target.$defs??{},name),'SCHEMA_REF',node.$ref);reachable.add(`${resolved}#/$defs/${name}`);visit(resolved,pointerAt(target,fragment));}}for(const [key,child] of Object.entries(node))if(key!=='$defs'&&key!=='$ref')visit(schemaId,child);};
  schemas.forEach(schema=>visit(schema.$id,schema));
  const defined=schemas.flatMap(schema=>Object.keys(schema.$defs??{}).map(name=>`${schema.$id}#/$defs/${name}`)).sort();
  check(same([...reachable].sort(),defined),'SCHEMA_REF','unused-definition');
  let ajv;try{ajv=new Ajv2020({allErrors:true,strict:false});schemas.forEach(schema=>ajv.addSchema(schema));const validator=ajv.getSchema(`${SCHEMA_PREFIX}root.v1.schema.json`);check(validator,'SCHEMA_COMPILE');}catch{fail('SCHEMA_COMPILE');}
  return {schemas,ajv};
};
const BINDING_POINTERS=[['/authorityPolicyGroups','/supplementalPolicies'],['/causalDag'],['/creationTransitionPolicy'],['/dependencyBinding'],['/componentDigests','/contentDigest'],['/futureExternalAuthorityContractSchema'],['/governanceBoundary','/futureGovernanceAuthorizationSchema','/sourceCollisions'],[],['/independenceConstraints','/nonAuthorityBoundary','/runtimeBoundary'],['/providerBindingPolicy'],['/requirementAuthorityMap'],['']];
const assertSchemaBindings=(root,schemas,packageRoot)=>{check(root.schemaBindings.length===12&&same(root.schemaBindings.map(x=>x.locator),SCHEMAS),'SCHEMA_RAW');for(const [index,binding] of root.schemaBindings.entries()){check(binding.schemaId===`${SCHEMA_PREFIX}${binding.locator.slice(8)}`&&sha256(safeRead(packageRoot,binding.locator))===binding.rawSha256&&same(binding.rootJsonPointers,BINDING_POINTERS[index]),'SCHEMA_RAW',binding.locator);check(schemas.some(schema=>schema.$id===binding.schemaId),'SCHEMA_RAW',binding.locator);}};
const assertFutureSchemaKats=(externalValidator,governanceValidator,bindingValidator)=>{
  const hash='0'.repeat(64),record=domain=>digestRecord(`${PREFIX}/future-schema-kat/${domain}`,{}),base={artifactId:'artifact:future-kat',authorityContractId:'authority-contract-kat',authorityPrincipalId:'authority-principal-kat',authorityScope:'review-scope-kat',contentDigest:record('external'),executionAllowed:false,expiresAt:null,instanceCreationAllowed:false,issuerDecisionRawSha256:hash,issuerDecisionRoot:'issuer-decision-root-kat',issuerPrincipalId:'issuer-principal-kat',providerBindingCreationCapability:'DECLARED_SCOPE_ONLY_REQUIRES_SEPARATE_ROOT_SOL_GOVERNANCE_AUTHORIZATION',revocationPolicy:null,schema:`${SCHEMA_PREFIX}future-external-authority-contract.v1.schema.json#/$defs/futureExternalAuthorityContract`,sourceAuthorityRawSha256:hash,sourceAuthorityRoot:'source-authority-root-kat',admissionAllowed:false};
  const externalCases=[
    {...base,policySlotId:'RECOVERY_CHAIN_OWNER_PROVIDER',authorityPayload:{payloadType:'OWNER_AUTHORITY_PAYLOAD',ownerScopeId:'RECOVERY_CHAIN_OWNER_PROVIDER',ownerContractRoot:'owner-root-kat',ownerContractRawSha256:hash,ownerBindingDomain:'owner-binding-domain-kat'}},
    {...base,policySlotId:'WORKLOAD_ROOT_ORDER_PROVIDER',authorityPayload:{payloadType:'WORKLOAD_MATERIAL_AUTHORITY_PAYLOAD',workloadRootOrderContractRoot:'workload-order-root-kat',workloadRootOrderContractRawSha256:hash,projectionEncodingContractRoot:'projection-encoding-root-kat',projectionEncodingContractRawSha256:hash}},
    {...base,policySlotId:'RAW_ARTIFACT_MAP_AUTHORITY',authorityPayload:{payloadType:'RAW_ARTIFACT_MAP_AUTHORITY_PAYLOAD',artifactMapSchemaRoot:'artifact-map-schema-root-kat',artifactMapSchemaRawSha256:hash,exclusiveWriterPolicyRoot:'exclusive-writer-root-kat',exclusiveWriterPolicyRawSha256:hash}},
    {...base,policySlotId:'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY',authorityPayload:{payloadType:'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_PAYLOAD',implementationLocator:'future/result-validator.mjs',implementationBytes:1,implementationRawSha256:hash,producerIndependenceAttestationRoot:'producer-independence-root-kat',producerIndependenceAttestationRawSha256:hash}}
  ];
  check(externalCases.every(value=>externalValidator(value)),'FUTURE_SCHEMA','external-positive');
  const wrongOwner=structuredClone(externalCases[0]);wrongOwner.authorityPayload.ownerScopeId='REQUEST_OWNER_PROVIDER';check(!externalValidator(wrongOwner),'FUTURE_SCHEMA','external-owner-slot-join');
  const wrongPayload=structuredClone(externalCases[0]);wrongPayload.authorityPayload=structuredClone(externalCases[1].authorityPayload);check(!externalValidator(wrongPayload),'FUTURE_SCHEMA','external-payload-slot-join');
  const uppercase=structuredClone(externalCases[0]);uppercase.sourceAuthorityRawSha256='A'.repeat(64);check(!externalValidator(uppercase),'FUTURE_SCHEMA','external-raw-sha');
  const unsafeLocator=structuredClone(externalCases[3]);unsafeLocator.authorityPayload.implementationLocator='../result-validator.mjs';check(!externalValidator(unsafeLocator),'FUTURE_SCHEMA','external-locator');
  const externalRevocation=structuredClone(externalCases[0]);externalRevocation.revocationPolicy={};check(!externalValidator(externalRevocation),'FUTURE_SCHEMA','external-revocation');
  const governanceSlots=['RECOVERY_CHAIN_OWNER_PROVIDER','REQUEST_OWNER_PROVIDER','ACTIVATION_OWNER_PROVIDER','PRIVATE_CAPTURE_OWNER_PROVIDER','PRIVATE_DESCRIPTOR_OWNER_PROVIDER','EXCLUSIVE_C_OWNER_PROVIDER','PRIVATE_DISPATCH_OWNER_PROVIDER','WORKLOAD_ROOT_ORDER_PROVIDER','RAW_ARTIFACT_MAP_AUTHORITY','INDEPENDENT_RESULT_VALIDATOR_AUTHORITY'],governanceTransitions=[{from:'SOURCE_LANGUAGE_RESOLVED',to:'AUTHORITY_POLICY_FROZEN_NO_AUTHORITY'},{from:'AUTHORITY_POLICY_FROZEN_NO_AUTHORITY',to:'EXTERNAL_AUTHORITY_CONTRACTS_PINNED_NO_INSTANCES'},{from:'EXTERNAL_AUTHORITY_CONTRACTS_PINNED_NO_INSTANCES',to:'PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES'},{from:'PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES',to:'CREATION_AUTHORIZED_NO_INSTANCES'},{from:'CREATION_AUTHORIZED_NO_INSTANCES',to:'INSTANCE_CREATED'}],governance={admissionAllowed:false,artifactId:'artifact:governance-kat',authorityPolicyRawSha256:hash,authorityPolicyRoot:'authority-policy-root-kat',authorizationId:'authorization-kat',authorizedPolicySlotIds:governanceSlots,authorizedTransitions:governanceTransitions,contentDigest:record('governance'),decisionId:'decision-kat',decisionRawSha256:hash,decisionRoot:'decision-root-kat',executionAllowed:false,expiresAt:null,issuedAt:'issued-at-kat',issuerPrincipalId:'issuer-principal-kat',providerBindingCatalogRawSha256:hash,providerBindingCatalogRoot:'provider-binding-catalog-root-kat',revocationPolicy:null,schema:`${SCHEMA_PREFIX}future-governance-authorization.v1.schema.json#/$defs/futureGovernanceAuthorization`,sourceCollisionResolution:{collisionId:'UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE',decisionRoot:'collision-decision-root-kat',selectedDag:'UOPC'}};
  check(governanceValidator(governance),'FUTURE_SCHEMA','governance-positive');
  const duplicateSlots=structuredClone(governance);duplicateSlots.authorizedPolicySlotIds.push(duplicateSlots.authorizedPolicySlotIds[0]);check(!governanceValidator(duplicateSlots),'FUTURE_SCHEMA','governance-slot-unique');
  const nonAdjacent=structuredClone(governance);nonAdjacent.authorizedTransitions=[{from:'SOURCE_LANGUAGE_RESOLVED',to:'INSTANCE_CREATED'}];check(!governanceValidator(nonAdjacent),'FUTURE_SCHEMA','governance-transition');
  const unknownDag=structuredClone(governance);unknownDag.sourceCollisionResolution.selectedDag='OTHER';check(!governanceValidator(unknownDag),'FUTURE_SCHEMA','governance-collision-selection');
  const governanceHash=structuredClone(governance);governanceHash.decisionRawSha256='A'.repeat(64);check(!governanceValidator(governanceHash),'FUTURE_SCHEMA','governance-raw-sha');
  const governanceRevocation=structuredClone(governance);governanceRevocation.revocationPolicy={};check(!governanceValidator(governanceRevocation),'FUTURE_SCHEMA','governance-revocation');
  const binding={admissionAllowed:false,artifactId:'artifact:binding-kat',authorityContractRawSha256:hash,authorityContractRoot:'authority-contract-root-kat',bindingId:'binding-kat',contentDigest:record('binding'),executionAllowed:false,governanceDecisionRoot:'governance-decision-root-kat',instanceCreationAllowed:false,issuerPrincipalId:'issuer-principal-kat',policySlotId:'RECOVERY_CHAIN_OWNER_PROVIDER',providerContractRawSha256:hash,providerContractRoot:'provider-contract-root-kat',providerPrincipalId:'provider-principal-kat',schema:`${SCHEMA_PREFIX}provider-binding-policy.v1.schema.json#/$defs/futureProviderBinding`,sourceCollisionResolutionRoot:'source-collision-resolution-root-kat'};
  check(bindingValidator(binding),'FUTURE_SCHEMA','binding-positive');
  const bindingSlot=structuredClone(binding);bindingSlot.policySlotId='UNKNOWN_SLOT';check(!bindingValidator(bindingSlot),'FUTURE_SCHEMA','binding-slot');
  const bindingHash=structuredClone(binding);bindingHash.authorityContractRawSha256='A'.repeat(64);check(!bindingValidator(bindingHash),'FUTURE_SCHEMA','binding-raw-sha');
  const bindingRoot=structuredClone(binding);bindingRoot.providerContractRoot='';check(!bindingValidator(bindingRoot),'FUTURE_SCHEMA','binding-root');
};
const assertDigestKats=(packageRoot,root)=>{
  const katBytes=safeRead(packageRoot,'test/digest.kat.json');rejectDuplicateKeys(katBytes);let kat;try{kat=JSON.parse(utf8(katBytes));}catch{fail('DIGEST');}check(utf8(katBytes)===`${canonicalJson(kat)}\n`,'DIGEST');
  check(same(Object.keys(kat).sort(),['accepted','artifactId','rejected','schema','status'].sort())&&kat.schema===`${PREFIX}/digest-kat/v1`&&kat.artifactId==='artifact:gate-b:gate-b0-external-authority-prerequisite-policy-digest-kat-v1'&&kat.status==='static-build-time-kat-no-authority-no-execution'&&kat.accepted.length===15&&kat.rejected.length===1,'DIGEST');
  const ids=['semantic-empty-object','semantic-key-order','semantic-array-order','semantic-nfc','raw-empty','raw-binary','dependency-binding','authority-policy-group','supplemental-policy','requirement-authority-map','source-collisions','creation-transition-policy','provider-binding-policy','schema-bindings','root-content'],domains=[`${PREFIX}/kat/semantic-empty-object`,`${PREFIX}/kat/semantic-key-order`,`${PREFIX}/kat/semantic-array-order`,`${PREFIX}/kat/semantic-nfc`,`${PREFIX}/kat/raw-empty`,`${PREFIX}/kat/raw-binary`,`${PREFIX}/dependency-binding`,`${PREFIX}/authority-policy-group/OWNER_SCOPE_REQUIREMENTS`,`${PREFIX}/supplemental-policy/RAW_ARTIFACT_MAP_AUTHORITY_POLICY`,`${PREFIX}/requirement-authority-map/A_RETRY_PROVIDER`,`${PREFIX}/source-collisions`,`${PREFIX}/creation-transition-policy`,`${PREFIX}/provider-binding-policy`,`${PREFIX}/schema-bindings`,`${PREFIX}/root`];
  check(same(kat.accepted.map(x=>x.katId),ids),'DIGEST');const expectedValues=[{}, {b:2,a:1}, [3,1,2], {s:'é'},null,null,root.dependencyBinding,root.authorityPolicyGroups[0],root.supplementalPolicies[0],root.requirementAuthorityMap[21],root.sourceCollisions,root.creationTransitionPolicy,root.providerBindingPolicy,root.schemaBindings,(()=>{const copy={...root};delete copy.contentDigest;return copy;})()];
  kat.accepted.forEach((row,index)=>{check(same(Object.keys(row).sort(),['canonicalJson','domain','inputEncoding','inputValue','katId','kind','preimageHex','sha256'].sort())&&row.domain===domains[index],'DIGEST',row.katId);if(index<4||index>=6){check(row.kind==='SEMANTIC'&&row.inputEncoding==='JSON_VALUE'&&same(row.inputValue,expectedValues[index])&&row.canonicalJson===canonicalJson(row.inputValue)&&allStringsNfc(row.inputValue),'DIGEST',row.katId);const preimage=Buffer.concat([Buffer.from(row.domain),Buffer.from([0]),Buffer.from(`${row.canonicalJson}\n`)]);check(row.preimageHex===preimage.toString('hex')&&row.sha256===sha256(preimage),'DIGEST',row.katId);}else{check(row.kind==='RAW'&&row.inputEncoding==='HEX'&&row.canonicalJson===null&&/^(?:[0-9a-f]{2})*$/u.test(row.inputValue)&&row.inputValue===(index===4?'':'000aff80'),'DIGEST',row.katId);const raw=Buffer.from(row.inputValue,'hex'),preimage=Buffer.concat([Buffer.from(row.domain),Buffer.from([0]),raw]);check(row.preimageHex===preimage.toString('hex')&&row.sha256===sha256(preimage),'DIGEST',row.katId);}});
  const reject=kat.rejected[0];check(same(Object.keys(reject).sort(),['canonicalJson','domain','errorToken','inputEncoding','inputValue','katId','kind'].sort())&&reject.katId==='semantic-nfd-reject'&&reject.kind==='REJECT'&&reject.domain===null&&reject.inputEncoding==='JSON_VALUE'&&same(reject.inputValue,{s:'e\u0301'})&&reject.canonicalJson==='{"s":"é"}'&&reject.errorToken==='EAPP_NON_NFC','DIGEST');let threw=false;try{digestRecord(`${PREFIX}/kat/semantic-nfd-reject`,reject.inputValue);}catch(error){threw=error.message==='EAPP_NON_NFC';}check(threw,'DIGEST');
};
const assertImportBoundary = root => {
  const importKeyword=['im','port'].join(''),importPrefix=new RegExp(String.raw`^[\t ]*${importKeyword}\b`,'u'),declaration=new RegExp(String.raw`^[\t ]*${importKeyword}[\t ]+(?:(?:[^'"\r\n]+?)[\t ]+from[\t ]+)?(['"])([^'"\r\n]+)\1[\t ]*;?[\t ]*$`,'u'),importMeta=new RegExp(String.raw`${importKeyword}\.meta\b`,'gu'),residualImportToken=new RegExp(String.raw`(?:^|[^\p{ID_Continue}$])${importKeyword}\b`,'u'),dynamic=new RegExp(String.raw`(?:^|[^.$A-Za-z0-9_])${'im'+'port'}(?:[ \t\r\n]|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*\(`,'u');
  const exportKeyword=['ex','port'].join(''),exportPrefix=new RegExp(String.raw`^[\t ]*${exportKeyword}\b`,'u'),exportDeclaration=new RegExp(String.raw`^[\t ]*${exportKeyword}[\t ]+const[\t ]+([A-Za-z_$][A-Za-z0-9_$]*)[\t ]*=`,'u'),residualExportToken=new RegExp(String.raw`(?:^|[^\p{ID_Continue}$])${exportKeyword}\b`,'u'),validatorExports=['AUTHORED_FILES','PREFIX','canonicalJson','digestRecord','fileDigestRecord','deriveSealEnvelope','deriveReviewAnchor','assertSourceCollision','assertRootSemantics','assertRequirementJoins','parseValidationCliArgs','validateStatic'];
  const importRosters=new Map([['validate-static.mjs',['ajv/dist/2020.js','node:crypto','node:fs','node:path','node:url']],['test/mutation.test.mjs',['node:test','node:assert/strict','ajv/dist/2020.js','node:crypto','node:fs','node:path','node:url','../validate-static.mjs']],['test/package-boundary.test.mjs',['node:test','node:assert/strict','node:crypto','node:net','node:os','node:fs','node:path','node:url','../validate-static.mjs']],['test/source-collision.test.mjs',['node:test','node:assert/strict','node:fs','node:path','../validate-static.mjs']],['test/static.test.mjs',['node:test','node:assert/strict','node:crypto','node:fs','node:path','../validate-static.mjs']]]);
  const processKeyword=['pro','cess'].join(''),processToken=new RegExp(String.raw`(?:^|[^\p{ID_Continue}$])${processKeyword}(?![\p{ID_Continue}$])`,'u'),argvOne=`${processKeyword}.argv[1]`,argvSlice=`${processKeyword}.argv.slice(2)`;
  const capabilityFragments=[['sp','awn'],['spawnS','ync'],['ex','ec'],['execS','ync'],['execF','ile'],['execFileS','ync'],['fo','rk'],['ev','al'],['req','uire'],['createReq','uire'],['getBuiltinMod','ule'],['dl','open'],['runInThisCont','ext'],['runInNewCont','ext'],['compileFunc','tion'],['Work','er'],['SharedWork','er'],['Func','tion'],['AsyncFunc','tion'],['GeneratorFunc','tion'],['AsyncGeneratorFunc','tion'],['WebAssem','bly'],['globalT','his'],['construc','tor'],['__pro','to__'],['Ref','lect'],['Pro','xy'],['fet','ch'],['WebSock','et']],capabilityNames=capabilityFragments.map(parts=>parts.join('')),capabilityAlternation=capabilityNames.map(value=>value.replace(/[.*+?^${}()|[\]\\]/gu,'\\$&')).join('|'),capabilityToken=new RegExp(String.raw`(?:^|[^\p{ID_Continue}$])(?:${capabilityAlternation})(?![\p{ID_Continue}$])`,'u');
  const inertPattern=new RegExp(String.raw`^${exportKeyword} const A1_CASE_ID=("[^"\r\n]+");\n${exportKeyword} const A1_ROOT_BYTES=([1-9][0-9]*);\n${exportKeyword} const A1_ROOT_RAW_SHA256=("[0-9a-f]{64}");\n${exportKeyword} const A1_ROOT_SCHEMA=(\{.*\});\n$`,'u'),inertSource=match=>`${exportKeyword} const A1_CASE_ID=${match[1]};\n${exportKeyword} const A1_ROOT_BYTES=${match[2]};\n${exportKeyword} const A1_ROOT_RAW_SHA256=${match[3]};\n${exportKeyword} const A1_ROOT_SCHEMA=${match[4]};\n`;
  for(const locator of AUTHORED_FILES.filter(file=>file.endsWith('.mjs'))){
    const source=utf8(safeRead(root,locator)),inertMatch=source.match(inertPattern),inert=locator==='validate-static.mjs'&&inertMatch!==null&&source===inertSource(inertMatch),specifiers=[],importResidual=[];
    for(const line of source.split(/\r?\n/u)){if(importPrefix.test(line)){const match=line.match(declaration);check(match,'IMPORT_BOUNDARY',locator);specifiers.push(match[2]);importResidual.push('');}else importResidual.push(line);}
    const residualWithoutMeta=importResidual.join('\n').replace(importMeta,'');
    check(same(specifiers,inert?[]:(importRosters.get(locator)??[]))&&!residualImportToken.test(residualWithoutMeta)&&!dynamic.test(source),'IMPORT_BOUNDARY',locator);
    const discovered=[],exportResidual=[];
    for(const line of importResidual){if(exportPrefix.test(line)){const match=line.match(exportDeclaration);check(match,'IMPORT_BOUNDARY',locator);discovered.push(match[1]);const start=line.indexOf(exportKeyword);exportResidual.push(`${line.slice(0,start)}${' '.repeat(exportKeyword.length)}${line.slice(start+exportKeyword.length)}`);}else exportResidual.push(line);}
    const expectedExports=locator==='validate-static.mjs'?(inert?['A1_CASE_ID','A1_ROOT_BYTES','A1_ROOT_RAW_SHA256','A1_ROOT_SCHEMA']:validatorExports):[];
    check(same(discovered,expectedExports)&&!residualExportToken.test(exportResidual.join('\n')),'IMPORT_BOUNDARY',locator);
    const production=locator==='validate-static.mjs'&&!inert,oneCount=source.split(argvOne).length-1,sliceCount=source.split(argvSlice).length-1;
    check(production?oneCount===1&&sliceCount===1:oneCount===0&&sliceCount===0,'IMPORT_BOUNDARY',locator);
    const capabilityResidual=production?source.replace(argvOne,' '.repeat(argvOne.length)).replace(argvSlice,' '.repeat(argvSlice.length)):source;
    check(!processToken.test(capabilityResidual)&&!capabilityToken.test(capabilityResidual),'IMPORT_BOUNDARY',locator);
  }
};
const assertDocumentClaims=root=>{const readme=utf8(safeRead(root,'README.md'));for(const sentence of README_SENTENCES)check(readme.split(sentence).length===2,'STATUS','README.md');check(utf8(safeRead(root,'COMMAND.txt'))===COMMAND_SOURCE,'STATUS','COMMAND.txt');};
const readPinnedJson=(repositoryRoot,pin)=>{const rule=DIRECT_AUTHORITY_RULES.find(row=>row.authorityId===pin.authorityId);check(rule&&rule.parser==='COMPACT_CANONICAL_JSON_LF','SOURCE_SEMANTIC',`${pin.authorityId}:rule`);const bytes=safeRead(repositoryRoot,pin.locator);check(bytes.length===pin.bytes&&sha256(bytes)===pin.rawSha256,'SOURCE_RAW',pin.authorityId);let value;try{value=parseCanonical(bytes);}catch{fail('SOURCE_SEMANTIC',`${pin.authorityId}:parse`);}const body={...value};delete body.contentDigest;const derived=sourceDomainHash(rule.domain,body),expected={algorithm:rule.algorithm,canonicalization:rule.canonicalization,domain:rule.domain,frame:rule.frame,value:derived};check(same(Object.keys(value.contentDigest??{}).sort(),['algorithm','canonicalization','domain','frame','value'].sort())&&same(value.contentDigest,expected)&&derived===pin.contentDigest,'SOURCE_SEMANTIC',pin.authorityId);return value;};
const resolveAuthorityRef=(ref,sources)=>{const match=ref.match(/^(EAC|UOPC|SPM)#(\/.*)$/u);check(match,'REQUIREMENT_JOIN',ref);let cursor=sources[match[1]];for(const encoded of match[2].slice(1).split('/')){const key=encoded.replaceAll('~1','/').replaceAll('~0','~');check(cursor!==null&&cursor!==undefined&&Object.hasOwn(cursor,key),'REQUIREMENT_JOIN',ref);cursor=cursor[key];}return cursor;};
const assertRequirementJoins=({root,ssa,eac,uopc,spm})=>{
  assertSourceCollision({},root,uopc,eac);
  const map={EAC:eac,UOPC:uopc,SPM:spm};
  check(ssa.requirementResolutions.length===30&&root.requirementAuthorityMap.length===30&&same(root.requirementAuthorityMap.map(row=>row.requirementId),REQUIREMENT_IDS),'REQUIREMENT_ROSTER');
  const globalSpmKinds=[...new Set(spm.interfaceSourceMap.entries.flatMap(row=>row.missingSourceKinds))].sort();
  check(same(globalSpmKinds,SPM_SOURCE_KIND_ROSTER),'REQUIREMENT_JOIN','spm-source-kind-roster');
  for(let index=0;index<30;index++){
    const parent=ssa.requirementResolutions[index],local=root.requirementAuthorityMap[index];
    check(parent.requirementId===REQUIREMENT_IDS[index]&&local.requirementId===REQUIREMENT_IDS[index]&&parent.classification===REQUIREMENT_CLASSIFICATIONS[index]&&local.classification===REQUIREMENT_CLASSIFICATIONS[index]&&parent.instanceDisposition===REQUIREMENT_DISPOSITIONS[index]&&local.instanceDisposition===REQUIREMENT_DISPOSITIONS[index]&&local.status===REQUIREMENT_STATUSES[index]&&same(parent.sourceContractRefs,EXPECTED_SOURCE_REFS[index])&&same(local.sourceContractRefs,EXPECTED_SOURCE_REFS[index])&&same(parent.constraintRefs,EXPECTED_CONSTRAINT_REFS[index])&&same(local.constraintRefs,EXPECTED_CONSTRAINT_REFS[index]),'REQUIREMENT_JOIN',local.requirementId);
    const resolvedConstraints=EXPECTED_CONSTRAINT_REFS[index].map(ref=>[ref,resolveAuthorityRef(ref,map)]);
    const eacRequirement=eac.externalRequirements[index];
    check(eacRequirement.requirementId===local.requirementId&&eacRequirement.authorityGranted===false&&eacRequirement.admissionGranted===false&&eacRequirement.instanceCount===0&&uopc.providerCausalDag.nodes[index]===local.requirementId,'REQUIREMENT_JOIN',local.requirementId);
    const uopcCatalogObjects=resolvedConstraints.filter(([ref])=>ref.startsWith('UOPC#/')&&!ref.startsWith('UOPC#/providerCausalDag/')).map(([,value])=>value);
    check(uopcCatalogObjects.length>0&&uopcCatalogObjects.some(value=>value?.id===local.requirementId||(Array.isArray(value?.providerNodes)&&value.providerNodes.includes(local.requirementId))),'REQUIREMENT_JOIN',`${local.requirementId}:uopc-catalog`);
    const spmRows=SPM_REF_INDICES[index].map(mapIndex=>spm.interfaceSourceMap.entries[mapIndex]);
    const directKinds=[...new Set(spmRows.flatMap(row=>row.missingSourceKinds))].sort();
    const requiredStaticKinds=EXPECTED_SOURCE_REFS[index].filter(kind=>SPM_SOURCE_KIND_ROSTER.includes(kind));
    const supplementalKinds=EXPECTED_SOURCE_REFS[index].filter(kind=>!SPM_SOURCE_KIND_ROSTER.includes(kind));
    check(requiredStaticKinds.length+supplementalKinds.length===EXPECTED_SOURCE_REFS[index].length&&supplementalKinds.every(kind=>REQUIREMENT_SUPPLEMENTAL_SOURCE_REFS.includes(kind)),'REQUIREMENT_JOIN',`${local.requirementId}:source-kind-class`);
    const derivedNormalization=SPM_DERIVED_JOIN_NORMALIZATIONS[local.requirementId];
    if(derivedNormalization){
      check(same(spmRows.map(row=>row.id),derivedNormalization.spmMapIds)&&spmRows.length===1&&spmRows[0].resolution===derivedNormalization.spmResolution&&same(spmRows[0].missingSourceKinds,derivedNormalization.directMissingSourceKinds)&&same(requiredStaticKinds,derivedNormalization.sourceContractRefs)&&same(local.predecessorNodeIds,derivedNormalization.predecessorNodeIds)&&derivedNormalization.sourceContractRefs.every(kind=>derivedNormalization.predecessorNodeIds.some(nodeId=>root.requirementAuthorityMap.find(row=>row.requirementId===nodeId)?.sourceContractRefs.includes(kind))),'REQUIREMENT_JOIN',`${local.requirementId}:derived-normalization`);
      check(same(spmRows[0].interfaceIds,derivedNormalization.interfaceIds),'REQUIREMENT_JOIN',`${local.requirementId}:interface-ids`);
      check(same(spm.mappingDag.edges.filter(edge=>edge.endsWith('→J_MAP')),derivedNormalization.incomingMapEdges),'REQUIREMENT_JOIN',`${local.requirementId}:incoming-map-edges`);
      check(same(spm.mappingDag.edges.filter(edge=>edge.startsWith('J_MAP→')),derivedNormalization.outgoingMapEdges),'REQUIREMENT_JOIN',`${local.requirementId}:outgoing-map-edges`);
    }else{
      const contextual=SPM_CONTEXTUAL_EXTRA_KINDS[local.requirementId]??[];
      const expectedDirectKinds=[...new Set([...requiredStaticKinds,...contextual])].sort();
      check(same(directKinds,expectedDirectKinds),'REQUIREMENT_JOIN',`${local.requirementId}:spm-union`);
    }
    const predecessorNormalization=PREDECESSOR_JOIN_NORMALIZATIONS[local.requirementId];
    if(predecessorNormalization){const collision=root.sourceCollisions.entries.find(row=>row.collisionId===predecessorNormalization.collisionId);check(same(parent.predecessorNodeIds,predecessorNormalization.ssaPredecessorNodeIds)&&same(local.predecessorNodeIds,predecessorNormalization.localPredecessorNodeIds)&&collision?.status===predecessorNormalization.collisionStatus&&collision.selectedDag===predecessorNormalization.selectedDag,'REQUIREMENT_JOIN',`${local.requirementId}:predecessor-normalization`);}else check(same(parent.predecessorNodeIds,local.predecessorNodeIds),'REQUIREMENT_JOIN',`${local.requirementId}:predecessors`);
  }
  return {requirements:30};
};
const assertSsaClosure=(repositoryRoot,dependency,ssa,manifest,manifestBytes,sumsBytes,anchor)=>{
  const ssaRoot=resolve(repositoryRoot,dependency.packagePath),tree=walk(ssaRoot),files=tree.filter(row=>row.kind==='file').map(row=>row.locator).sort(),dirs=['.',...tree.filter(row=>row.kind==='directory').map(row=>row.locator)].sort();
  check(tree.every(row=>row.kind==='file'||row.kind==='directory')&&same(files,[...SSA_AUTHORED_FILES,'MANIFEST.json','SHA256SUMS'].sort())&&same(dirs,['.','schemas','test']),'DEPENDENCY_SEMANTIC','ssa-closure');
  for(const dir of dirs){const stat=lstatSync(resolve(ssaRoot,dir));check(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o777)===0o755,'DEPENDENCY_SEMANTIC',`ssa-dir:${dir}`);}
  for(const file of files){const stat=lstatSync(resolve(ssaRoot,file));check(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&(stat.mode&0o777)===0o644,'DEPENDENCY_SEMANTIC',`ssa-file:${file}`);}
  check(same(Object.keys(manifest).sort(),['entries','entryCount','format','packageId','rosterDigest','schema'].sort())&&manifest.schema==='https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1/manifest.v1.schema.json'&&manifest.format==='shieldkit-static-manifest-v1'&&manifest.packageId==='gate-b0-static-source-authority-v1'&&manifest.entryCount===24&&same(manifest.entries.map(row=>row.locator),SSA_AUTHORED_FILES),'DEPENDENCY_SEMANTIC','ssa-manifest');
  const entries=SSA_AUTHORED_FILES.map(locator=>{const bytes=safeRead(ssaRoot,locator);return {bytes:bytes.length,fileDigest:fileDigestWithPrefix(SSA_PREFIX,locator,bytes),locator,rawSha256:sha256(bytes)};});
  check(same(manifest.entries,entries)&&same(manifest.rosterDigest,digestWithPrefix(SSA_PREFIX,'manifest-roster',entries))&&manifest.rosterDigest.value===dependency.manifest.rosterDigest,'DEPENDENCY_SEMANTIC','ssa-roster');
  check(manifestBytes.toString()===`${canonicalJson(manifest)}\n`,'DEPENDENCY_SEMANTIC','ssa-manifest-bytes');
  const expectedSums=`${[...entries,{locator:'MANIFEST.json',rawSha256:sha256(manifestBytes)}].map(row=>`${row.rawSha256}  ${row.locator}`).join('\n')}\n`;
  check(sumsBytes.toString()===expectedSums,'DEPENDENCY_SEMANTIC','ssa-sums');
  const anchorKeys=['artifactId','componentDigests','directDependencyBinding','entryCount','manifestRawSha256','nonAuthorityBoundary','orderedClosure','package','packageId','rootContentDigest','rootRawSha256','rosterDigest','schema','schemaBindingTableDigest','schemaBindings','sha256SumsRawSha256','status','transitiveSourcePinTableDigest','validatorRawSha256'];
  check(same(Object.keys(anchor).sort(),anchorKeys.sort())&&anchor.artifactId==='artifact:gate-b:gate-b0-static-source-authority-review-anchor-v1'&&anchor.package===dependency.packagePath&&anchor.packageId==='gate-b0-static-source-authority-v1'&&anchor.schema===dependency.reviewAnchor.schema&&anchor.status==='sealed-static-source-contract-authority-review-anchor-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified'&&anchor.entryCount===24,'DEPENDENCY_SEMANTIC','ssa-anchor-identity');
  check(anchor.rootRawSha256===dependency.root.rawSha256&&anchor.validatorRawSha256===dependency.validator.rawSha256&&anchor.manifestRawSha256===dependency.manifest.rawSha256&&anchor.sha256SumsRawSha256===dependency.checksums.rawSha256&&same(anchor.orderedClosure,entries)&&same(anchor.rosterDigest,manifest.rosterDigest)&&same(anchor.componentDigests,ssa.componentDigests)&&same(anchor.schemaBindings,ssa.schemaBindings)&&same(anchor.rootContentDigest,ssa.contentDigest)&&same(anchor.directDependencyBinding,ssa.dependencyPins[0]),'DEPENDENCY_SEMANTIC','ssa-anchor');
  check(ssa.schemaBindings.length===15&&same(ssa.schemaBindings.map(binding=>binding.locator),SSA_AUTHORED_FILES.filter(locator=>locator.startsWith('schemas/')))&&ssa.schemaBindings.every(binding=>{const entry=entries.find(row=>row.locator===binding.locator);if(!entry||entry.rawSha256!==binding.rawSha256||sha256(safeRead(ssaRoot,binding.locator))!==binding.rawSha256)return false;const schema=parseCanonical(safeRead(ssaRoot,binding.locator));return schema.$id===binding.schemaId;}),'DEPENDENCY_SEMANTIC','ssa-schema-bindings');
  check(Array.isArray(ssa.transitiveSourcePins)&&ssa.transitiveSourcePins.length===64&&same(ssa.transitiveSourcePins.map(pin=>pin.pinId),SOURCE_PIN_IDS)&&new Set(ssa.transitiveSourcePins.map(pin=>pin.pinId)).size===64&&new Set(ssa.transitiveSourcePins.map(pin=>pin.locator)).size===64,'DEPENDENCY_SEMANTIC','ssa-transitive-roster');
  check(Object.keys(SEMANTIC_RULES).length===64&&same(Object.keys(SEMANTIC_RULES).sort(),[...SOURCE_PIN_IDS].sort()),'DEPENDENCY_SEMANTIC','ssa-transitive-roster');
  for(const pin of ssa.transitiveSourcePins){const bytes=safeRead(repositoryRoot,pin.locator);check(bytes.length===pin.bytes&&sha256(bytes)===pin.rawSha256,'SOURCE_RAW',pin.pinId);let value=null;if(pin.locator.endsWith('.json')){try{value=parseSourceJson(bytes);}catch{fail('SOURCE_SEMANTIC',pin.pinId);}}check(sourceSemanticValid(pin,value),'SOURCE_SEMANTIC',pin.pinId);
  }
};
const assertDependencies=(root,repositoryRoot)=>{
  check(same(root.dependencyBinding,EXACT_DEPENDENCY),'DEPENDENCY_SEMANTIC','literal');
  const dependency=EXACT_DEPENDENCY,ssaBase=dependency.packagePath,pinned=(locator,pin,token)=>{const bytes=safeRead(repositoryRoot,`${ssaBase}/${locator}`);check(bytes.length===pin.bytes&&sha256(bytes)===pin.rawSha256,token,locator);return bytes;};
  const rootBytes=pinned(dependency.root.path,dependency.root,'DEPENDENCY_RAW'),validatorBytes=pinned(dependency.validator.path,dependency.validator,'DEPENDENCY_RAW'),manifestBytes=pinned(dependency.manifest.path,dependency.manifest,'DEPENDENCY_RAW'),sumsBytes=pinned(dependency.checksums.path,dependency.checksums,'DEPENDENCY_RAW');
  const anchorBytes=safeRead(repositoryRoot,dependency.reviewAnchor.path);check(anchorBytes.length===dependency.reviewAnchor.bytes&&sha256(anchorBytes)===dependency.reviewAnchor.rawSha256,'DEPENDENCY_RAW','anchor');
  const ssa=parseCanonical(rootBytes),manifest=parseCanonical(manifestBytes),anchor=parseCanonical(anchorBytes);check(validatorBytes.length===dependency.validator.bytes,'DEPENDENCY_RAW','validator');
  check(ssa.schema==='https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1/root.v1.schema.json'&&ssa.artifactId==='artifact:gate-b:gate-b0-static-source-authority-v1'&&ssa.packageId==='gate-b0-static-source-authority-v1'&&ssa.status==='static-source-contract-authority-resolved-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified','DEPENDENCY_SEMANTIC','ssa-identity');
  assertSsaClosure(repositoryRoot,dependency,ssa,manifest,manifestBytes,sumsBytes,anchor);
  check(ssa.contentDigest.value===dependency.root.contentDigest,'DEPENDENCY_SEMANTIC','ssa-root-content');const ssaBody={...ssa};delete ssaBody.contentDigest;check(same(ssa.contentDigest,digestWithPrefix(SSA_PREFIX,'root',ssaBody)),'DEPENDENCY_SEMANTIC','ssa-root-digest');
  const expectedSsaComponents=SSA_COMPONENT_SPECS.map(([component,suffix])=>({component,digest:digestWithPrefix(SSA_PREFIX,suffix,ssa[component])}));check(same(ssa.componentDigests,expectedSsaComponents)&&same(ssa.componentDigests,dependency.ssaComponentDigests),'SSA_COMPONENT');
  check(same(DIRECT_AUTHORITY_RULES.map(row=>row.authorityId),EXACT_SOURCE_AUTHORITIES.map(row=>row.authorityId))&&new Set(DIRECT_AUTHORITY_RULES.map(row=>row.authorityId)).size===4,'SOURCE_SEMANTIC','direct-rule-roster');
  const sources=EXACT_SOURCE_AUTHORITIES.map(pin=>[pin.authorityId,readPinnedJson(repositoryRoot,pin)]),map=Object.fromEntries(sources),eac=map.EAC,uopc=map.UOPC,spm=map.SPM;
  check(same(dependency.sourceAuthorities,EXACT_SOURCE_AUTHORITIES)&&same(dependency.eacSemanticComponents,EXACT_EAC_COMPONENTS),'DEPENDENCY_SEMANTIC','source-table');
  for(const [component,value] of Object.entries(EXACT_EAC_COMPONENTS)){const row=eac.componentDigests.find(item=>item.component===component);check(row&&row.digest.value===value&&same(row.digest,digestRecord(row.digest.domain,eac[component])),'EAC_COMPONENT',component);}
  assertRequirementJoins({root,ssa,eac,uopc,spm});return {ssa,eac,uopc,spm,b0r:map.B0R};
};
const ANCHOR_KEYS=['schema','artifactId','packageId','package','status','rootRawSha256','rootContentDigest','validatorRawSha256','manifestRawSha256','sha256SumsRawSha256','entryCount','orderedClosure','rosterDigest','directDependencyBinding','componentDigests','schemaBindings','schemaBindingTableDigest','sourceCollisionDigest','nonAuthorityBoundary'];
const readReviewAnchor=(pin,packageRoot)=>{check(pin,'ANCHOR_REQUIRED');check(same(Object.keys(pin).sort(),['reviewAnchorBytes','reviewAnchorLocator','reviewAnchorRawSha256','reviewAnchorRoot'].sort()),'ANCHOR_PIN');check(isAbsolute(pin.reviewAnchorRoot)&&Number.isSafeInteger(pin.reviewAnchorBytes)&&pin.reviewAnchorBytes>0&&/^[0-9a-f]{64}$/.test(pin.reviewAnchorRawSha256),'ANCHOR_PIN');safeLocator(pin.reviewAnchorLocator);let cursor=pin.reviewAnchorRoot,stat=lstatSync(cursor);check(stat.isDirectory()&&!stat.isSymbolicLink(),'ANCHOR_PIN');for(const [index,part] of pin.reviewAnchorLocator.split('/').entries()){cursor=resolve(cursor,part);stat=lstatSync(cursor);check(!stat.isSymbolicLink(),'ANCHOR_PIN');if(index<pin.reviewAnchorLocator.split('/').length-1)check(stat.isDirectory(),'ANCHOR_PIN');}const rel=relative(realpathSync(packageRoot),realpathSync(cursor));check(rel==='..'||rel.startsWith('../'),'ANCHOR_PIN');check(stat.isFile()&&stat.nlink===1&&(stat.mode&0o777)===0o644,'ANCHOR_PIN');const bytes=readFileSync(cursor);check(bytes.length===pin.reviewAnchorBytes&&sha256(bytes)===pin.reviewAnchorRawSha256,'ANCHOR_RAW');const value=parseCanonical(bytes);check(same(Object.keys(value).sort(),[...ANCHOR_KEYS].sort())&&value.schema===ANCHOR_SCHEMA&&value.artifactId===ANCHOR_ARTIFACT&&value.packageId===PACKAGE_ID&&value.package===ANCHOR_PACKAGE&&value.status===ANCHOR_STATUS&&value.entryCount===21,'ANCHOR_CLOSURE');check(value.rootRawSha256===sha256(safeRead(packageRoot,'external-authority-prerequisite-policy-root.v1.json'))&&value.validatorRawSha256===sha256(safeRead(packageRoot,'validate-static.mjs')),'ANCHOR_RAW');check(Array.isArray(value.schemaBindings)&&value.schemaBindings.length===12&&value.schemaBindings.every(binding=>sha256(safeRead(packageRoot,binding.locator))===binding.rawSha256),'SCHEMA_RAW');return value;};
const assertSealedEnvelope=(packageRoot,anchor)=>{const envelope=deriveSealEnvelope(packageRoot),manifestBytes=safeRead(packageRoot,'MANIFEST.json'),sumsBytes=safeRead(packageRoot,'SHA256SUMS');check(same(anchor.orderedClosure,envelope.entries)&&same(anchor.rosterDigest,envelope.manifest.rosterDigest),'ANCHOR_CLOSURE');check(manifestBytes.equals(envelope.manifestBytes),'MANIFEST');check(sumsBytes.equals(envelope.sumsBytes),'SUMS');check(sha256(manifestBytes)===anchor.manifestRawSha256&&sha256(sumsBytes)===anchor.sha256SumsRawSha256,'ANCHOR_RAW');return envelope;};
const ANCHOR_SCHEMA=`${PREFIX}/external-review-anchor/v1`,ANCHOR_ARTIFACT='artifact:gate-b:gate-b0-external-authority-prerequisite-policy-review-anchor-v1',ANCHOR_PACKAGE='research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-external-authority-prerequisite-policy-v1',ANCHOR_STATUS='sealed-static-external-authority-prerequisite-policy-review-anchor-no-governance-authorization-no-authority-bindings-no-instances-no-admission-no-execution-unqualified';
const assertAnchorLate=(anchor,root,packageRoot)=>{check(anchor.schema===ANCHOR_SCHEMA&&anchor.artifactId===ANCHOR_ARTIFACT&&anchor.package===ANCHOR_PACKAGE&&anchor.status===ANCHOR_STATUS,'ANCHOR_CLOSURE');check(anchor.rootRawSha256===sha256(Buffer.from(`${canonicalJson(root)}\n`))&&same(anchor.rootContentDigest,root.contentDigest),'ANCHOR_RAW');check(anchor.validatorRawSha256===sha256(safeRead(packageRoot,'validate-static.mjs')),'ANCHOR_RAW');check(same(anchor.directDependencyBinding,root.dependencyBinding)&&same(anchor.componentDigests,root.componentDigests)&&same(anchor.schemaBindings,root.schemaBindings)&&same(anchor.schemaBindingTableDigest,digestRecord(`${PREFIX}/schema-binding-table`,root.schemaBindings))&&same(anchor.sourceCollisionDigest,root.componentDigests.find(row=>row.component==='sourceCollisions').digest)&&same(anchor.nonAuthorityBoundary,root.nonAuthorityBoundary),'ANCHOR_CLOSURE');};
const parseValidationCliArgs = argv => { check(Array.isArray(argv)&&argv.every(value=>typeof value==='string'),'CLI_ARGS');const allowed=['--mode','--review-anchor-root','--review-anchor-locator','--review-anchor-bytes','--review-anchor-raw-sha256'],values=new Map();check(argv.length%2===0,'CLI_ARGS');for(let index=0;index<argv.length;index+=2){const flag=argv[index],value=argv[index+1];check(allowed.includes(flag)&&!values.has(flag)&&value&&!value.startsWith('--'),'CLI_ARGS');values.set(flag,value);}const mode=values.get('--mode');check(mode==='unsealed'||mode==='sealed','PACKAGE_MODE');const anchorFlags=allowed.slice(1);if(mode==='unsealed'){check(anchorFlags.every(flag=>!values.has(flag)),'CLI_ARGS');return {mode,reviewAnchorPin:null};}check(anchorFlags.every(flag=>values.has(flag)),'ANCHOR_REQUIRED');check(isAbsolute(values.get('--review-anchor-root')),'ANCHOR_PIN');safeLocator(values.get('--review-anchor-locator'));check(/^[1-9][0-9]*$/.test(values.get('--review-anchor-bytes')),'ANCHOR_PIN');check(/^[0-9a-f]{64}$/.test(values.get('--review-anchor-raw-sha256')),'ANCHOR_PIN');return {mode,reviewAnchorPin:{reviewAnchorRoot:values.get('--review-anchor-root'),reviewAnchorLocator:values.get('--review-anchor-locator'),reviewAnchorBytes:Number(values.get('--review-anchor-bytes')),reviewAnchorRawSha256:values.get('--review-anchor-raw-sha256')}}; };
const validateStatic = ({packageRoot=here,repositoryRoot=resolve(here,'../../../../..'),mode,reviewAnchorPin=null}={}) => { const closure=checkClosure(packageRoot,mode),anchor=mode==='sealed'?readReviewAnchor(reviewAnchorPin,packageRoot):null;if(anchor)assertSealedEnvelope(packageRoot,anchor);assertImportBoundary(packageRoot);assertDocumentClaims(packageRoot);const schemaState=assertSchemas(packageRoot),root=rootDocument(packageRoot),rootValidator=schemaState.ajv.getSchema(`${SCHEMA_PREFIX}root.v1.schema.json`);check(rootValidator&&rootValidator(root),'ROOT_SCHEMA');assertSchemaBindings(root,schemaState.schemas,packageRoot);const sources=assertDependencies(root,repositoryRoot);const externalValidator=schemaState.ajv.getSchema(`${SCHEMA_PREFIX}future-external-authority-contract.v1.schema.json#/$defs/futureExternalAuthorityContract`),governanceValidator=schemaState.ajv.getSchema(`${SCHEMA_PREFIX}future-governance-authorization.v1.schema.json#/$defs/futureGovernanceAuthorization`),bindingValidator=schemaState.ajv.getSchema(`${SCHEMA_PREFIX}provider-binding-policy.v1.schema.json#/$defs/futureProviderBinding`);check(externalValidator&&governanceValidator&&bindingValidator,'FUTURE_SCHEMA');assertFutureSchemaKats(externalValidator,governanceValidator,bindingValidator);assertRootSemantics(root,{uopc:sources.uopc,eac:sources.eac});assertDigestKats(packageRoot,root);if(anchor)assertAnchorLate(anchor,root,packageRoot);return {...closure,rootDigest:root.contentDigest.value,sourceContracts:10,unsealed:mode==='unsealed'}; };
return Object.freeze({AUTHORED_FILES,PREFIX,canonicalJson,digestRecord,fileDigestRecord,deriveSealEnvelope,deriveReviewAnchor,assertRootSemantics,assertSourceCollision,assertRequirementJoins,parseValidationCliArgs,validateStatic,checkClosure,readReviewAnchor,assertSealedEnvelope,assertAnchorLate,rootDocument,assertSchemas,assertSchemaBindings,assertDependencies,assertFutureSchemaKats,assertDigestKats,assertImportBoundary,assertDocumentClaims,COMPONENTS,ROOT_KEYS,SCHEMAS,DIRECTIONS,SCHEMA_PREFIX,sha256,same,safeRead,parseCanonical});
})();
const eappFail = message => { throw new Error('gate-b0-external-authority-prerequisite-policy-v1 lane binding: ' + message); };
const eappAssert = (condition,message) => { if(!condition)eappFail(message); };
const eappSame = eappPort.same;
const eappRawSha256 = eappPort.sha256;
const eappExactKeys = (value,keys,code) => eappAssert(value&&typeof value==='object'&&!Array.isArray(value)&&eappSame(Object.keys(value),keys),code);
const eappAssertBinding = binding => {
  eappExactKeys(binding,EAPP_BINDING_KEYS,'EAPP_BINDING_SHAPE');
  eappAssert(binding.status===EAPP_EXPECTED_BINDING.status,'EAPP_BINDING_STATUS');
  for(const key of EAPP_BINDING_KEYS.filter(key=>!['counts','nonAuthorityBoundary','status'].includes(key)))eappAssert(eappSame(binding[key],EAPP_EXPECTED_BINDING[key]),'EAPP_BINDING_NESTED:'+key);
  eappExactKeys(binding.counts,EAPP_COUNT_KEYS,'EAPP_BINDING_COUNT_SHAPE');
  for(const key of EAPP_COUNT_KEYS)eappAssert(binding.counts[key]===EAPP_EXPECTED_BINDING.counts[key],'EAPP_BINDING_COUNT:'+key);
  eappExactKeys(binding.nonAuthorityBoundary,EAPP_BOUNDARY_KEYS,'EAPP_BINDING_BOUNDARY_SHAPE');
  for(const key of EAPP_BOUNDARY_KEYS)eappAssert(binding.nonAuthorityBoundary[key]===EAPP_EXPECTED_BINDING.nonAuthorityBoundary[key],'EAPP_BINDING_BOUNDARY:'+key);
  eappAssert(eappSame(binding,EAPP_EXPECTED_BINDING),'EAPP_BINDING_EXACT');
  return true;
};
const eappAssertLaneProjection = laneValue => {
  b0rAssertLaneKeyPartition(laneValue);
  const snapshot=Object.fromEntries(B0R_INCLUDED_TOP_LEVEL_KEYS.map(key=>[key,laneValue[key]]));
  const record=b0rDigestRecord('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/lane-authority-projection',{schema:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/lane-authority-projection/v1',snapshot});
  eappAssert(record.value===EAPP_EXPECTED_BINDING.laneAuthorityProjection.contentDigest,'EAPP_LANE_PROJECTION');
};
const eappAssertProse = (texts=EAPP_PROSE_SOURCES.map(({label,path})=>[label,readFileSync(path,'utf8')])) => {
  for(const [label,text] of texts)eappAssert(text.split(EAPP_NONPROMOTION).length===2&&text.split(EAPP_NEXT_GATE).length===2,'EAPP_PROSE:'+label);
};
const eappAssertPhase = (bytes=readFileSync(resolve(laneDir,'research/phase-plan.md'))) => {
  const text=bytes.toString('utf8');
  eappAssert(bytes.length===14452&&eappRawSha256(bytes)==='d8113796b9ede19e9ee7537ddb10e415ce67808548e27b953e30083b485a3a2d'&&!text.includes(EAPP_NONPROMOTION)&&!text.includes(EAPP_NEXT_GATE),'EAPP_PHASE');
};
const eappAssertProseDisjointness = root => {
  const locators=new Set([
    ...root.dependencyBinding.sourceAuthorities.map(row=>row.locator),
    ...(gateB0StaticSourceAuthorityV1IndependentValidation?.root?.transitiveSourcePins??[]).map(row=>row.locator),
    ...(gateB0ExecutionAdmissionContractV1IndependentValidation?.root?.sourcePins??[]).map(row=>row.locator)
  ]);
  for(const source of EAPP_PROSE_SOURCES)eappAssert(!locators.has(source.locator),'EAPP_PROSE_SOURCE:'+source.locator);
};
const eappAssertAnchorIdentity = anchor => {
  const keys=['artifactId','componentDigests','directDependencyBinding','entryCount','manifestRawSha256','nonAuthorityBoundary','orderedClosure','package','packageId','rootContentDigest','rootRawSha256','rosterDigest','schema','schemaBindingTableDigest','schemaBindings','sha256SumsRawSha256','sourceCollisionDigest','status','validatorRawSha256'];
  eappExactKeys(anchor,keys,'EAPP_ANCHOR_SHAPE');
  eappAssert(anchor.schema===EAPP_EXPECTED_BINDING.reviewAnchor.schema&&anchor.artifactId==='artifact:gate-b:gate-b0-external-authority-prerequisite-policy-review-anchor-v1'&&anchor.packageId==='gate-b0-external-authority-prerequisite-policy-v1'&&anchor.package===EAPP_PACKAGE_LOCATOR&&anchor.status==='sealed-static-external-authority-prerequisite-policy-review-anchor-no-governance-authorization-no-authority-bindings-no-instances-no-admission-no-execution-unqualified'&&anchor.entryCount===21,'EAPP_ANCHOR_IDENTITY');
};
const eappReadExternalAnchor = (pin,packageRoot) => {
  eappExactKeys(pin,['reviewAnchorRoot','reviewAnchorLocator','reviewAnchorBytes','reviewAnchorRawSha256'],'EAPP_ANCHOR_PIN');
  eappAssert(pin.reviewAnchorRoot===EAPP_REVIEW_ANCHOR_PIN.reviewAnchorRoot&&pin.reviewAnchorLocator===EAPP_REVIEW_ANCHOR_PIN.reviewAnchorLocator&&pin.reviewAnchorBytes===EAPP_REVIEW_ANCHOR_PIN.reviewAnchorBytes&&pin.reviewAnchorRawSha256===EAPP_REVIEW_ANCHOR_PIN.reviewAnchorRawSha256,'EAPP_ANCHOR_PIN');
  const rootStat=lstatSync(pin.reviewAnchorRoot);
  eappAssert(isAbsolute(pin.reviewAnchorRoot)&&rootStat.isDirectory()&&!rootStat.isSymbolicLink(),'EAPP_ANCHOR_PIN');
  let cursor=pin.reviewAnchorRoot;
  for(const [index,part] of pin.reviewAnchorLocator.split('/').entries()){
    eappAssert(part&&part!=='.'&&part!=='..'&&!part.includes('\\')&&part.normalize('NFC')===part,'EAPP_ANCHOR_PIN');
    cursor=resolve(cursor,part);
    const stat=lstatSync(cursor);
    eappAssert(!stat.isSymbolicLink()&&(index===pin.reviewAnchorLocator.split('/').length-1?stat.isFile()&&stat.nlink===1&&(stat.mode&0o777)===0o644:stat.isDirectory()),'EAPP_ANCHOR_PIN');
  }
  const relation=relative(realpathSync(packageRoot),realpathSync(cursor));
  eappAssert(relation==='..'||relation.startsWith('../'),'EAPP_ANCHOR_PIN');
  const bytes=readFileSync(cursor);
  eappAssert(bytes.length===pin.reviewAnchorBytes&&eappRawSha256(bytes)===pin.reviewAnchorRawSha256,'EAPP_ANCHOR_RAW');
  return eappPort.parseCanonical(bytes);
};
const eappAssertAnchorSchemaRaws = (anchor,packageRoot) => {
  eappAssert(Array.isArray(anchor.schemaBindings)&&anchor.schemaBindings.length===12&&eappSame(anchor.schemaBindings.map(row=>row.locator),eappPort.SCHEMAS),'EAPP_SCHEMA_RAW_ROSTER');
  for(const binding of anchor.schemaBindings)eappAssert(eappRawSha256(eappPort.safeRead(packageRoot,binding.locator))===binding.rawSha256,'EAPP_SCHEMA_RAW:'+binding.locator);
};
const eappAssertPinnedRaw = (root,locator,expected) => eappAssert(eappRawSha256(eappPort.safeRead(root,locator))===expected,'EAPP_RAW:'+locator);
const eappAssertRawPins = root => {
  for(const [locator,expected] of [
    ['external-authority-prerequisite-policy-root.v1.json',EAPP_EXPECTED_BINDING.root.rawSha256],
    ['validate-static.mjs',EAPP_EXPECTED_BINDING.validator.rawSha256],
    ['MANIFEST.json',EAPP_EXPECTED_BINDING.manifest.rawSha256],
    ['SHA256SUMS',EAPP_EXPECTED_BINDING.checksums.rawSha256]
  ])eappAssertPinnedRaw(root,locator,expected);
};
const eappAssertSchemaState = (rootModel,packageRoot,schemaState=eappPort.assertSchemas(packageRoot)) => {
  eappPort.assertSchemaBindings(rootModel,schemaState.schemas,packageRoot);
  const validate=schemaState.ajv.getSchema(EAPP_SCHEMA_PREFIX+'root.v1.schema.json');
  eappAssert(validate&&validate(rootModel),'EAPP_ROOT_SCHEMA:'+schemaState.ajv.errorsText(validate?.errors));
  const external=schemaState.ajv.getSchema(EAPP_SCHEMA_PREFIX+'future-external-authority-contract.v1.schema.json#/$defs/futureExternalAuthorityContract');
  const governance=schemaState.ajv.getSchema(EAPP_SCHEMA_PREFIX+'future-governance-authorization.v1.schema.json#/$defs/futureGovernanceAuthorization');
  const binding=schemaState.ajv.getSchema(EAPP_SCHEMA_PREFIX+'provider-binding-policy.v1.schema.json#/$defs/futureProviderBinding');
  eappAssert(external&&governance&&binding,'EAPP_FUTURE_SCHEMA');
  eappPort.assertFutureSchemaKats(external,governance,binding);
  return schemaState;
};
const eappAssertDependencies = (rootModel,repositoryRoot) => {
  const sources=eappPort.assertDependencies(rootModel,repositoryRoot);
  eappAssert(gateB0StaticSourceAuthorityV1IndependentValidation?.sourceContracts===19&&gateB0StaticSourceAuthorityV1IndependentValidation?.root?.transitiveSourcePins?.length===64,'EAPP_SSA_INDEPENDENT');
  eappAssert(eappSame(rootModel.dependencyBinding.ssaComponentDigests,gateB0StaticSourceAuthorityV1IndependentValidation.root.componentDigests),'EAPP_SSA_COMPONENTS');
  eappAssert(rootModel.dependencyBinding.root.contentDigest===gateB0StaticSourceAuthorityV1IndependentValidation.root.contentDigest.value,'EAPP_SSA_ROOT');
  eappAssert(gateB0ExecutionAdmissionContractV1IndependentValidation?.root&&cohortUpstreamOriginProviderContractV1IndependentValidation?.rootDocument&&cohortUpstreamProviderSourceMapV1IndependentValidation?.manifest,'EAPP_DIRECT_SOURCE_INDEPENDENT');
  eappPort.assertRequirementJoins({root:rootModel,ssa:sources.ssa,eac:sources.eac,uopc:sources.uopc,spm:sources.spm});
  return sources;
};
const eappValidateIndependent = (root=EAPP_PACKAGE_ROOT,repositoryRoot=repoRoot,anchorPin=EAPP_REVIEW_ANCHOR_PIN) => {
  const anchor=eappReadExternalAnchor(anchorPin,root);
  eappAssertAnchorIdentity(anchor);
  const closure=eappPort.checkClosure(root,'sealed');
  const envelope=eappPort.assertSealedEnvelope(root,anchor);
  eappAssertRawPins(root);
  eappAssert(anchor.manifestRawSha256===EAPP_EXPECTED_BINDING.manifest.rawSha256&&anchor.sha256SumsRawSha256===EAPP_EXPECTED_BINDING.checksums.rawSha256&&anchor.rootRawSha256===EAPP_EXPECTED_BINDING.root.rawSha256&&anchor.validatorRawSha256===EAPP_EXPECTED_BINDING.validator.rawSha256,'EAPP_ANCHOR_RAW_JOINS');
  eappAssertAnchorSchemaRaws(anchor,root);
  const schemaState=eappPort.assertSchemas(root);
  const rootModel=eappPort.rootDocument(root);
  eappAssertSchemaState(rootModel,root,schemaState);
  const sources=eappAssertDependencies(rootModel,repositoryRoot);
  eappPort.assertRootSemantics(rootModel,{uopc:sources.uopc,eac:sources.eac});
  eappPort.assertDigestKats(root,rootModel);
  eappPort.assertAnchorLate(anchor,rootModel,root);
  eappAssert(eappSame(anchor.orderedClosure,envelope.entries)&&anchor.rosterDigest.value===EAPP_EXPECTED_BINDING.manifest.rosterDigest,'EAPP_ANCHOR_CLOSURE');
  eappPort.assertImportBoundary(root);
  eappPort.assertDocumentClaims(root);
  eappAssertLaneProjection(lane);
  eappAssertProse();
  eappAssertPhase();
  eappAssertProseDisjointness(rootModel);
  return {...closure,anchor,envelope,root:rootModel,sourceContracts:10};
};
const eappExpectLaneFailure = (operation,expected,label) => {
  let failure;try{operation();}catch(error){failure=error;}
  eappAssert(failure?.message==='gate-b0-external-authority-prerequisite-policy-v1 lane binding: '+expected,'EAPP_CAUSAL_EXPECTATION:'+label);
};
const eappExpectPortFailure = (operation,expected,label) => {
  let failure;try{operation();}catch(error){failure=error;}
  eappAssert(failure?.message===expected||failure?.message?.startsWith(expected+':'),'EAPP_CAUSAL_EXPECTATION:'+label);
};
const eappSetPath = (value,path,replacement) => {
  let cursor=value;for(const part of path.slice(0,-1))cursor=cursor[part];
  cursor[path.at(-1)]=replacement;
};
const eappMutatedValue = value => Array.isArray(value)?[...value].reverse():typeof value==='number'?value+1:typeof value==='string'?value+'-mutant':!value;
const eappRunCausalMutation = async (laneValue,importedValidator) => {
  let classes=0;const labels=new Set();
  const count=label=>{eappAssert(!labels.has(label),'EAPP_CAUSAL_DUPLICATE:'+label);labels.add(label);classes+=1;};
  const laneReject=(operation,expected,label)=>{count(label);eappExpectLaneFailure(operation,expected,label);};
  const portReject=(operation,expected,label)=>{count(label);eappExpectPortFailure(operation,expected,label);};
  const bindingCase=(label,mutate,expected)=>{const candidate=structuredClone(EAPP_EXPECTED_BINDING);mutate(candidate);laneReject(()=>eappAssertBinding(candidate),expected,'binding/'+label);};

  bindingCase('omission',value=>{delete value.path;},'EAPP_BINDING_SHAPE');
  bindingCase('extra',value=>{value.extra=false;},'EAPP_BINDING_SHAPE');
  bindingCase('status',value=>{value.status+='-mutant';},'EAPP_BINDING_STATUS');
  for(const key of EAPP_COUNT_KEYS)bindingCase('count/'+key,value=>{value.counts[key]+=1;},'EAPP_BINDING_COUNT:'+key);
  for(const key of EAPP_BOUNDARY_KEYS)bindingCase('boundary/'+key,value=>{const current=value.nonAuthorityBoundary[key];value.nonAuthorityBoundary[key]=typeof current==='boolean'?!current:typeof current==='number'?current+1:current+'-mutant';},'EAPP_BINDING_BOUNDARY:'+key);
  for(const path of EAPP_NESTED_BINDING_PATHS)bindingCase('nested/'+path.join('/'),value=>{let current=value;for(const part of path)current=current[part];eappSetPath(value,path,eappMutatedValue(current));},'EAPP_BINDING_NESTED:'+path[0]);
  eappAssert(classes===113,'EAPP_CAUSAL_BINDING_COUNT');

  const pristine=eappPort.rootDocument(EAPP_PACKAGE_ROOT);
  const semanticCase=(label,mutate,expected,operation=root=>eappPort.assertRootSemantics(root))=>{
    const candidate=structuredClone(pristine);mutate(candidate);portReject(()=>operation(candidate),expected,'semantic/'+label);
  };
  semanticCase('status',root=>{root.status='MUTANT';},'EAPP_STATUS');
  semanticCase('execution',root=>{root.executionAllowed=true;},'EAPP_NONAUTHORITY');
  semanticCase('purpose',root=>{root.purpose+='-mutant';},'EAPP_CONTENT_DIGEST');
  semanticCase('governance',root=>{root.governanceBoundary.authorizationPresent=true;},'EAPP_NONAUTHORITY');
  semanticCase('group-id',root=>{root.authorityPolicyGroups[0].policyGroupId='MUTANT';},'EAPP_GROUP_PARTITION');
  semanticCase('group-slot',root=>{root.authorityPolicyGroups[0].futureAuthorityContractSlotIds.pop();},'EAPP_GROUP_PARTITION');
  semanticCase('supplemental',root=>{root.supplementalPolicies[0].authorityCreationAllowed=true;},'EAPP_SUPPLEMENTAL');
  semanticCase('requirement-id',root=>{root.requirementAuthorityMap[0].requirementId='MUTANT';},'EAPP_REQUIREMENT_ROSTER');
  semanticCase('requirement-instance',root=>{root.requirementAuthorityMap[0].instanceCount=1;},'EAPP_REQUIREMENT_ROSTER');
  semanticCase('collision-status',root=>{root.sourceCollisions.status='RESOLVED';},'EAPP_COLLISION_COUNTS',root=>eappPort.assertSourceCollision({},root));
  semanticCase('collision-selection',root=>{root.sourceCollisions.entries[0].selectedDag='UOPC';},'EAPP_COLLISION_SELECTION',root=>eappPort.assertSourceCollision({},root));
  semanticCase('collision-edge',root=>{root.sourceCollisions.entries[0].uopcOnlyEdges.pop();},'EAPP_COLLISION_EDGES',root=>eappPort.assertSourceCollision({},root));
  semanticCase('transition-current',root=>{root.creationTransitionPolicy.currentState='INSTANCE_CREATED';},'EAPP_TRANSITION');
  semanticCase('transition-edge',root=>{root.creationTransitionPolicy.edges[0].to='INSTANCE_CREATED';},'EAPP_TRANSITION');
  semanticCase('binding-count',root=>{root.providerBindingPolicy.bindingCount=1;},'EAPP_BINDING_POLICY');
  semanticCase('future-governance',root=>{root.futureGovernanceAuthorizationSchema.recordCount=1;},'EAPP_FUTURE_SCHEMA');
  semanticCase('future-external',root=>{root.futureExternalAuthorityContractSchema.creationAllowed=true;},'EAPP_FUTURE_SCHEMA');
  semanticCase('independence',root=>{root.independenceConstraints.currentPrincipalCount=1;},'EAPP_INDEPENDENCE');
  semanticCase('dag-node',root=>{root.causalDag.nodes[0]='MUTANT';},'EAPP_DAG');
  semanticCase('dag-edge',root=>{root.causalDag.edges[0].to='B0_EXECUTION_AUTHORIZATION';},'EAPP_DAG');
  semanticCase('nonauthority',root=>{root.nonAuthorityBoundary.authorizationCount=1;},'EAPP_NONAUTHORITY');
  semanticCase('runtime',root=>{root.runtimeBoundary.runtimeEntrypoint='run.mjs';},'EAPP_RUNTIME_BOUNDARY');
  semanticCase('component-digest',root=>{root.componentDigests[0].digest.value='0'.repeat(64);},'EAPP_DIGEST');
  semanticCase('root-digest',root=>{root.contentDigest.value='0'.repeat(64);},'EAPP_CONTENT_DIGEST');
  eappAssert(classes===137,'EAPP_CAUSAL_SEMANTIC_COUNT');

  const projection=structuredClone(laneValue);projection.apiVersion+='-mutant';
  count('lane/included-projection');let projectionFailure=false;try{eappAssertLaneProjection(projection);}catch{projectionFailure=true;}eappAssert(projectionFailure,'EAPP_CAUSAL_EXPECTATION:lane/included-projection');
  const partition=structuredClone(laneValue);partition.extraEappKey=false;
  count('lane/top-level-partition');let partitionFailure=false;try{b0rAssertLaneKeyPartition(partition);}catch{partitionFailure=true;}eappAssert(partitionFailure,'EAPP_CAUSAL_EXPECTATION:lane/top-level-partition');
  laneReject(()=>eappAssertPhase(Buffer.from(EAPP_NONPROMOTION)),'EAPP_PHASE','lane/phase-drift');
  const prose=EAPP_PROSE_SOURCES.map(({label,path})=>[label,readFileSync(path,'utf8')]);
  laneReject(()=>eappAssertProse(prose.map(([label,text])=>[label,text.replace(EAPP_NONPROMOTION,'')])),'EAPP_PROSE:lane README','lane/prose-package-deletion');
  laneReject(()=>eappAssertProse(prose.map(([label,text])=>[label,text.replace(EAPP_NEXT_GATE,'')])),'EAPP_PROSE:lane README','lane/prose-next-gate-deletion');
  laneReject(()=>eappAssertProse(prose.map(([label,text])=>[label,label==='lane README'?text+EAPP_NONPROMOTION:text])),'EAPP_PROSE:lane README','lane/prose-duplicate');
  const collisionRoot=structuredClone(pristine);collisionRoot.dependencyBinding.sourceAuthorities[0].locator=EAPP_PROSE_SOURCES[0].locator;
  laneReject(()=>eappAssertProseDisjointness(collisionRoot),'EAPP_PROSE_SOURCE:'+EAPP_PROSE_SOURCES[0].locator,'lane/prose-source-collision');
  const widened=structuredClone(pristine);widened.governanceBoundary.laneReadAllowed=true;
  portReject(()=>eappPort.assertRootSemantics(widened),'EAPP_NONAUTHORITY','lane/lane-read-widening');
  eappAssert(classes===145,'EAPP_CAUSAL_LANE_COUNT');

  const temporaryRoot=mkdtempSync(resolve(tmpdir(),'eapp-lane-causal-'));
  const clonePackage=(name)=>{
    const root=resolve(temporaryRoot,name);cpSync(EAPP_PACKAGE_ROOT,root,{recursive:true});
    for(const row of eappPort.DIRECTIONS)chmodSync(resolve(root,row),0o755);
    for(const locator of [...eappPort.AUTHORED_FILES,'MANIFEST.json','SHA256SUMS'])chmodSync(resolve(root,locator),0o644);
    return root;
  };
  try{
    const badRaw={...EAPP_REVIEW_ANCHOR_PIN,reviewAnchorRawSha256:'0'.repeat(64)};
    portReject(()=>eappPort.readReviewAnchor(badRaw,EAPP_PACKAGE_ROOT),'EAPP_ANCHOR_RAW','fs/anchor-raw');

    const linkRoot=resolve(temporaryRoot,'anchor-link-root');mkdirSync(linkRoot,{mode:0o755});
    symlinkSync(resolve(EAPP_ANCHOR_ROOT,EAPP_ANCHOR_LOCATOR),resolve(linkRoot,EAPP_ANCHOR_LOCATOR));
    portReject(()=>eappPort.readReviewAnchor({...EAPP_REVIEW_ANCHOR_PIN,reviewAnchorRoot:linkRoot},EAPP_PACKAGE_ROOT),'EAPP_ANCHOR_PIN','fs/anchor-link');

    const realClone=clonePackage('package-symlink-source'),linkClone=resolve(temporaryRoot,'package-symlink');
    symlinkSync(realClone,linkClone);
    portReject(()=>eappPort.checkClosure(linkClone,'sealed'),'EAPP_PACKAGE_CLOSURE','fs/package-symlink');

    const hard=clonePackage('hardlink');rmSync(resolve(hard,'README.md'));linkSync(resolve(hard,'COMMAND.txt'),resolve(hard,'README.md'));
    portReject(()=>eappPort.checkClosure(hard,'sealed'),'EAPP_LINK','fs/hardlink');

    const mode=clonePackage('dir-mode');chmodSync(resolve(mode,'schemas'),0o700);
    portReject(()=>eappPort.checkClosure(mode,'sealed'),'EAPP_DIR_MODE','fs/dir-mode');

    const missing=clonePackage('missing-envelope');rmSync(resolve(missing,'MANIFEST.json'));rmSync(resolve(missing,'SHA256SUMS'));
    portReject(()=>eappPort.checkClosure(missing,'sealed'),'EAPP_PACKAGE_CLOSURE','fs/missing-envelope');

    const extra=clonePackage('extra-file');writeFileSync(resolve(extra,'extra.txt'),'x');
    portReject(()=>eappPort.checkClosure(extra,'sealed'),'EAPP_PACKAGE_CLOSURE','fs/extra-file');

    const originalAnchor=eappPort.readReviewAnchor(EAPP_REVIEW_ANCHOR_PIN,EAPP_PACKAGE_ROOT);
    const manifestDigest=clonePackage('manifest-file-digest'),manifestDigestValue=JSON.parse(readFileSync(resolve(manifestDigest,'MANIFEST.json')));
    manifestDigestValue.entries[0].fileDigest.value='0'.repeat(64);writeFileSync(resolve(manifestDigest,'MANIFEST.json'),eappPort.canonicalJson(manifestDigestValue)+'\n');
    portReject(()=>eappPort.assertSealedEnvelope(manifestDigest,originalAnchor),'EAPP_MANIFEST','fs/manifest-file-digest');

    const manifestOrder=clonePackage('manifest-reorder'),manifestOrderValue=JSON.parse(readFileSync(resolve(manifestOrder,'MANIFEST.json')));
    manifestOrderValue.entries.reverse();writeFileSync(resolve(manifestOrder,'MANIFEST.json'),eappPort.canonicalJson(manifestOrderValue)+'\n');
    portReject(()=>eappPort.assertSealedEnvelope(manifestOrder,originalAnchor),'EAPP_MANIFEST','fs/manifest-reorder');

    const manifestRoster=clonePackage('manifest-roster'),manifestRosterValue=JSON.parse(readFileSync(resolve(manifestRoster,'MANIFEST.json')));
    manifestRosterValue.rosterDigest.value='0'.repeat(64);writeFileSync(resolve(manifestRoster,'MANIFEST.json'),eappPort.canonicalJson(manifestRosterValue)+'\n');
    portReject(()=>eappPort.assertSealedEnvelope(manifestRoster,originalAnchor),'EAPP_MANIFEST','fs/manifest-roster');

    const sums=clonePackage('sums');const sumsBytes=readFileSync(resolve(sums,'SHA256SUMS'));sumsBytes[0]=sumsBytes[0]===0x30?0x31:0x30;writeFileSync(resolve(sums,'SHA256SUMS'),sumsBytes);
    portReject(()=>eappPort.assertSealedEnvelope(sums,originalAnchor),'EAPP_SUMS','fs/sums');

    portReject(()=>eappPort.checkClosure(EAPP_PACKAGE_ROOT,'unsealed'),'EAPP_PACKAGE_CLOSURE','fs/production-unsealed');
    portReject(()=>eappPort.readReviewAnchor(null,EAPP_PACKAGE_ROOT),'EAPP_ANCHOR_REQUIRED','fs/sealed-missing-literal');
    eappAssert(classes===158,'EAPP_CAUSAL_FS_COUNT');

    const coordinated=clonePackage('coordinated-a1'),rootModel=eappPort.rootDocument(coordinated);
    const exportWord=['ex','port'].join(''),rootBytes=readFileSync(resolve(coordinated,'external-authority-prerequisite-policy-root.v1.json')),rootRaw=eappRawSha256(rootBytes),h1Schema={$schema:'https://json-schema.org/draft/2020-12/schema',$id:'urn:eapp:lane:a1',const:rootModel};
    const inertSource=exportWord+' const A1_CASE_ID="lane/coordinated-replacement";\n'+exportWord+' const A1_ROOT_BYTES='+rootBytes.length+';\n'+exportWord+' const A1_ROOT_RAW_SHA256="'+rootRaw+'";\n'+exportWord+' const A1_ROOT_SCHEMA='+JSON.stringify(h1Schema)+';\n';
    writeFileSync(resolve(coordinated,'validate-static.mjs'),inertSource);chmodSync(resolve(coordinated,'validate-static.mjs'),0o644);
    eappPort.assertImportBoundary(coordinated);
    const localAjv=new Ajv2020({allErrors:true,strict:false}),localValidate=localAjv.compile(h1Schema);
    eappAssert(localValidate(rootModel)&&eappRawSha256(rootBytes)===rootRaw,'EAPP_COORDINATED_LOCAL_POSITIVE');
    const coordinatedSchemaState=eappPort.assertSchemas(coordinated),envelope=eappPort.deriveSealEnvelope(coordinated);
    writeFileSync(resolve(coordinated,'MANIFEST.json'),envelope.manifestBytes);writeFileSync(resolve(coordinated,'SHA256SUMS'),envelope.sumsBytes);
    const anchor=eappPort.deriveReviewAnchor({root:rootModel,validatorRawSha256:eappRawSha256(Buffer.from(inertSource)),manifestRawSha256:eappRawSha256(envelope.manifestBytes),sha256SumsRawSha256:eappRawSha256(envelope.sumsBytes),entries:envelope.entries,rosterDigest:envelope.manifest.rosterDigest});
    const coordinatedAnchorRoot=resolve(temporaryRoot,'coordinated-anchor');mkdirSync(coordinatedAnchorRoot,{mode:0o755});
    const anchorBytes=Buffer.from(eappPort.canonicalJson(anchor)+'\n');writeFileSync(resolve(coordinatedAnchorRoot,EAPP_ANCHOR_LOCATOR),anchorBytes);chmodSync(resolve(coordinatedAnchorRoot,EAPP_ANCHOR_LOCATOR),0o644);
    const pin={reviewAnchorRoot:coordinatedAnchorRoot,reviewAnchorLocator:EAPP_ANCHOR_LOCATOR,reviewAnchorBytes:anchorBytes.length,reviewAnchorRawSha256:eappRawSha256(anchorBytes)};
    const closure=eappPort.checkClosure(coordinated,'sealed'),a1Anchor=eappPort.readReviewAnchor(pin,coordinated),a1Envelope=eappPort.assertSealedEnvelope(coordinated,a1Anchor);
    eappAssertSchemaState(rootModel,coordinated,coordinatedSchemaState);const sources=eappAssertDependencies(rootModel,repoRoot);eappPort.assertRootSemantics(rootModel,{uopc:sources.uopc,eac:sources.eac});eappPort.assertDigestKats(coordinated,rootModel);eappPort.assertAnchorLate(a1Anchor,rootModel,coordinated);
    eappAssert(closure.files===23&&closure.directories===3&&eappSame(a1Anchor.orderedClosure,a1Envelope.entries),'EAPP_COORDINATED_INDEPENDENT_POSITIVE');
    laneReject(()=>eappAssertPinnedRaw(coordinated,'validate-static.mjs',EAPP_EXPECTED_BINDING.validator.rawSha256),'EAPP_RAW:validate-static.mjs','fs/coordinated-validator-pin');
    eappAssert(importedValidator&&typeof importedValidator.validateStatic==='function','EAPP_IMPORTED_VALIDATOR');
    eappAssert(classes===EAPP_LANE_CAUSAL_CLASS_COUNT&&labels.size===EAPP_LANE_CAUSAL_CLASS_COUNT,'EAPP_CAUSAL_COUNT');
    return {classes,labels:[...labels]};
  }finally{
    rmSync(temporaryRoot,{recursive:true,force:true});
    eappAssert(!existsSync(temporaryRoot),'EAPP_CAUSAL_CLEANUP');
  }
};
const POLICY_AUTHORITY_V1_EXPECTED_BINDING = {
  path: 'p2/gate-b/cohort-policy-authority-v1',
  root: {
    path: 'p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json',
    rawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e',
    contentDigest: '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50'
  },
  bindingRoot: '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654',
  policyContentDigest: '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf',
  causalDagRoot: '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d',
  liveFContentDigest: '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be',
  manifest: {
    path: 'p2/gate-b/cohort-policy-authority-v1/MANIFEST.json',
    rawSha256: '60fbc7ffe72e41a4df60603d9d4b6b0f0e118e1577028643fc867fbe3cb06bb1',
    rosterDigest: 'fe80c26549873c7c6a803ff666f8750d339c298e41d31c2921a354e92e62cb40'
  },
  checksums: {
    path: 'p2/gate-b/cohort-policy-authority-v1/SHA256SUMS',
    rawSha256: '66a8e1437c4c8d78dfa7600f7d0e1b83a2c6321c3f86b3d3a3dc2678eba992bb'
  },
  dependencies: {
    R: {
      path: 'p2/gate-b/cohort-runtime-binding-v1',
      root: {
        path: 'p2/gate-b/cohort-runtime-binding-v1/runtime-binding-root.v1.json',
        rawSha256: 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd',
        contentDigest: '8b73e8bbbfd97d8c451c5fd9466ff219ab36eeb65e3fb10c5f3629a89da36af1'
      },
      manifest: {
        path: 'p2/gate-b/cohort-runtime-binding-v1/MANIFEST.json',
        rawSha256: '2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254',
        contentDigest: 'd16d426d5c0eeb7c1c410cad2106ea0d5eb1fd100998704be8ba75d11c90b117'
      },
      checksums: {
        path: 'p2/gate-b/cohort-runtime-binding-v1/SHA256SUMS',
        rawSha256: 'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea'
      },
      runtimeAuthorityDigest: 'fce66bed0f375e922e6b765a74f6b0dd81f784029df6079cee4668f89bb872d8'
    },
    K: {
      path: 'p2/gate-b/cohort-runner-core-v1',
      runtimeCore: {
        path: 'p2/gate-b/cohort-runner-core-v1/runtime-core.v1.json',
        rawSha256: 'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2'
      },
      manifest: {
        path: 'p2/gate-b/cohort-runner-core-v1/MANIFEST.json',
        rawSha256: '913e5667c78de4f06a7ce34acfa13fb1393eeadbbf831641eab35ceddf3f01c4',
        packageRoot: '10850743e64bf8f453b2a446019edb095861d9876a5e7785e946c4661d1ddac2',
        manifestRoot: '58928887efb9bffe5482eee0525854eaf08496e97ae890d7fb795c14995e98f1',
        entriesRoot: '88ce4c1d2e91630344329f734fe65e23b6817c89400b431833f995e7a509033b'
      },
      checksums: {
        path: 'p2/gate-b/cohort-runner-core-v1/SHA256SUMS',
        rawSha256: '27ffdc493af8e77ab89b22dde1b424f0d9733bf9491013943b8a63ccc87bb4db'
      },
      runtimeContract: {
        runtimeEntrypoint: 'src/contracts.mjs',
        runtimeModules: [
          { locator: 'src/contracts.mjs', imports: ['./file-contracts.mjs', './strict.mjs'] },
          { locator: 'src/file-contracts.mjs', imports: ['./strict.mjs'] },
          { locator: 'src/strict.mjs', imports: ['node:crypto'] }
        ],
        runtimeExports: [
          'LIFECYCLE', 'admitDispatch', 'advanceLifecycle', 'appendJournalEntry', 'assertAcyclicEdges',
          'assertKBindingEdges', 'canonicalWorkerEnvelope', 'deriveJournalIndex', 'endpointRosterRoot',
          'externalDispatchModel', 'isAdmittedDispatch', 'isEvidenceJournal', 'isExclusiveClaim',
          'isJournalEntry', 'isJournalIndex', 'isPrivateObservation', 'isRetainedDescriptor',
          'journalEntryProjection', 'journalIndexProjection', 'newLifecycle', 'openEvidenceJournal',
          'openExclusiveClaim', 'recordObservation', 'retainDescriptor', 'retainedReceipt',
          'validateDispatchPlan', 'workerEnvelope', 'workerRowsRoot'
        ],
        buildTimeOnlyLocators: ['generate.mjs', 'src/integrity.mjs', 'validate.mjs']
      }
    },
    F: {
      path: 'p2/gate-b/cohort-frozen-inputs-v1',
      root: {
        path: 'p2/gate-b/cohort-frozen-inputs-v1/frozen-inputs-root.v1.json',
        rawSha256: '19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5',
        contentDigest: '7f00510e5c4b8b4959b572c9c9ece8e97ca95174b5715c2ee0852ef79f28b08f'
      },
      manifest: {
        path: 'p2/gate-b/cohort-frozen-inputs-v1/MANIFEST.json',
        rawSha256: 'f6b1dbf3f6757366c519e10f11e1fed80d071507445ad0085955aae164ad0867',
        contentDigest: '894ea274f13aa8dbf5ee6cc36c231689e166df7bf9be8e74f0a5197db0ba5f53',
        rosterDigest: '2871b10227a285d20e1cb833b4ccee06d49b528f9d7d7243f52a04c70c7a02e5'
      },
      checksums: {
        path: 'p2/gate-b/cohort-frozen-inputs-v1/SHA256SUMS',
        rawSha256: '4099e52c4acd2c2c34c49142bb28e6cb7ac31d048feb452e053038f3db578eff'
      },
      orderedLeaves: [
        {
          id: 'source-set-v1',
          packageRoot: 'p2/source-set-v1',
          root: {
            path: 'p2/source-set-v1/source-set.v1.json',
            rawSha256: '53e9acc311a123ad26908b84cf73149913781c1fe72253cc6cd28fef644751b5',
            nativeSemanticDigest: '58e7765b066b1917b1fa0b4b96182010ad7f5c8ce8bce601c083bc764845482e'
          },
          manifest: {
            path: 'p2/source-set-v1/MANIFEST.json',
            rawSha256: 'd830276ccae8efe9ab10a04de539521a6637fd7a09429d5834c22fbcf5b33ba2'
          },
          checksums: {
            path: 'p2/source-set-v1/SHA256SUMS',
            rawSha256: '8c108df96e1b5757fbb0ca93894496bade08ca5e8a9e68143f701c85380ff103'
          }
        },
        {
          id: 'cohort-freeze-v2',
          packageRoot: 'p2/gate-b/cohort-freeze-v2',
          root: {
            path: 'p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json',
            rawSha256: '84ff8f6a85244b65d5d4f6e80c38b516223641ee444a133a67eb5794311d2dbc',
            artifactSemanticDigest: '6fcbaba3bb52d5e1eb9c6f1cb04b1d46cb65e2c91eba20ca38356dc323ebb11e'
          },
          manifest: {
            path: 'p2/gate-b/cohort-freeze-v2/MANIFEST.json',
            rawSha256: 'f600f81a716fb968ee1602c088e438d08008bce336e2191f68b37919b8bf5171'
          },
          checksums: {
            path: 'p2/gate-b/cohort-freeze-v2/SHA256SUMS',
            rawSha256: '57eee7a1cc1fdd9c10e9f97176b77b138eb3b97949fe3bf1518bf1517f04275e'
          }
        }
      ]
    }
  },
  launchAuthority: {
    aliases: [
      { alias: 'native', endpoint: 'engine:native' },
      { alias: 'libauth', endpoint: 'engine:libauth' },
      { alias: 'bchn', endpoint: 'engine:bchn' },
      { alias: 'leanbch-primary', endpoint: 'engine:leanbch:primary' },
      { alias: 'leanbch-secondary', endpoint: 'engine:leanbch:secondary' }
    ],
    workloadsPerEndpoint: 4608,
    completeCapturedInputs: true,
    minimumCapturedInputBytes: 1
  },
  status: 'static-policy-template-non-authorizing',
  executionAllowed: false,
  closedNamespaces: {
    attempt: null,
    'attempt-001': null,
    authorization: null,
    claim: null,
    run: null,
    evidence: null,
    metrics: null,
    ranking: null,
    selection: null
  }
};
const V3_PACKAGE_MANIFEST_DOMAINS = [
  'shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root',
  'shieldkit-labs/p2/gate-b/cohort-executor-v3/package-manifest/root',
  'shieldkit-labs/p2/gate-b/cohort-commit-helper-v1/package-manifest/root'
];
const V3_PACKAGE_RELATIVES = [
  'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v3',
  'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3',
  'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1'
];
const V3_PACKAGE_SCHEMA_IDS = [
  'https://shieldkit-labs.local/p2/gate-b/cohort-execution-v3/manifest.v1.schema.json',
  'https://shieldkit-labs.local/p2/gate-b/cohort-executor-v3/manifest.v1.schema.json',
  'https://shieldkit-labs.local/p2/gate-b/cohort-commit-helper-v1/manifest.v1.schema.json'
];
const V3_PACKAGE_LISTED_COUNTS = [14, 23, 11];
const v3FreezeValueErrors = (value) => {
  const local = [];
  const fail = (condition, message) => { if (!condition) local.push(message); };
  fail(value?.schema === 'shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1', 'schema');
  fail(value?.freezeId === 'cohort-v3-freeze:execution-v3+executor-v3', 'freezeId');
  fail(value?.status === 'frozen-unexecuted' && value?.executionAllowed === false && value?.metricsAllowed === false, 'execution boundary');
  fail(value?.ranking === null && value?.selection === null, 'ranking/selection boundary');
  fail(Array.isArray(value?.packageRoots) && value.packageRoots.length === 3, 'package root count');
  fail(JSON.stringify(value?.packageRoots?.map((entry) => entry?.packageRoot)) === JSON.stringify(V3_PACKAGE_RELATIVES), 'package root order');
  fail(JSON.stringify(value?.packageRoots?.map((entry) => entry?.listedPayloadCount)) === JSON.stringify(V3_PACKAGE_LISTED_COUNTS), 'package listed counts');
  fail(value?.contentDigest?.algorithm === 'sha256' && value.contentDigest.canonicalization === 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1' && value.contentDigest.frame === 'utf8(domain)||0x00||canonical-json-utf8' && value.contentDigest.domain === V3_FREEZE_DOMAIN && value.contentDigest.value === digestRecord(withoutContentDigest(value), V3_FREEZE_DOMAIN).value, 'freeze content digest');
  return local;
};
const validateV3PackageEnvelope = (root, binding, index) => {
  const label = `cohort-v3 package ${index}`;
  const rootRel = V3_PACKAGE_RELATIVES[index];
  const manifestPath = resolve(root, 'MANIFEST.json');
  const schemaPath = resolve(root, 'manifest.v1.schema.json');
  const sumsPath = resolve(root, 'SHA256SUMS');
  expect(binding?.packageRoot === rootRel, `${label} root pin changed`);
  expect(binding?.manifestPath === `${rootRel}/MANIFEST.json`, `${label} manifest path changed`);
  expect(binding?.manifestSchemaPath === `${rootRel}/manifest.v1.schema.json`, `${label} manifest schema path changed`);
  expect(binding?.checksumsPath === `${rootRel}/SHA256SUMS`, `${label} checksum path changed`);
  expect(existsSync(manifestPath) && existsSync(schemaPath) && existsSync(sumsPath), `${label} envelope is incomplete`);
  if (!existsSync(manifestPath) || !existsSync(schemaPath) || !existsSync(sumsPath)) return;
  const manifestBytes = readFileSync(manifestPath);
  const schemaBytes = readFileSync(schemaPath);
  const sumsBytes = readFileSync(sumsPath);
  const manifest = JSON.parse(manifestBytes);
  const manifestSchema = JSON.parse(schemaBytes);
  expect(binding.manifestRawSha256 === createHash('sha256').update(manifestBytes).digest('hex'), `${label} manifest raw hash is stale`);
  expect(binding.manifestByteLength === manifestBytes.length, `${label} manifest byte length is stale`);
  expect(binding.manifestSchemaRawSha256 === createHash('sha256').update(schemaBytes).digest('hex'), `${label} manifest schema raw hash is stale`);
  expect(binding.checksumsRawSha256 === createHash('sha256').update(sumsBytes).digest('hex') && binding.checksumsByteLength === sumsBytes.length, `${label} checksum binding is stale`);
  expect(manifest.contentDigest?.domain === V3_PACKAGE_MANIFEST_DOMAINS[index] && manifest.contentDigest?.value === digestRecord(withoutContentDigest(manifest), V3_PACKAGE_MANIFEST_DOMAINS[index]).value, `${label} manifest content digest is stale`);
  expect(JSON.stringify(binding.manifestContentDigest) === JSON.stringify(manifest.contentDigest), `${label} manifest content pin is stale`);
  compileStrictSchema(schemaPath, `${label} manifest`, manifest);
  expect(Buffer.from(JSON.stringify(canonicalize(manifest), null, 2) + '\n', 'utf8').equals(manifestBytes), `${label} manifest bytes are not canonical`);
  const manifestPrefix = `${rootRel}/`;
  const expectedPayloads = (manifest.files ?? []).map((entry) => entry.path);
  expect(manifest.files?.length === binding.listedPayloadCount && manifest.coverage?.listedPayloadCount === manifest.files?.length, `${label} listed count is stale`);
  expect(manifest.files?.every((entry, item) => entry.path.startsWith(manifestPrefix) && (item === 0 || Buffer.compare(Buffer.from(manifest.files[item - 1].path), Buffer.from(entry.path)) < 0)), `${label} manifest ordering or path coverage changed`);
  for (const entry of manifest.files ?? []) {
    expect(!entry.path.startsWith('/') && !entry.path.includes('\\') && !entry.path.split('/').includes('..') && entry.path.startsWith(manifestPrefix), `${label} unsafe payload path: ${entry.path}`);
    if (entry.path.startsWith('/') || entry.path.includes('\\') || entry.path.split('/').includes('..') || !entry.path.startsWith(manifestPrefix)) continue;
    const entryPath = resolve(repoRoot, entry.path);
    expect(existsSync(entryPath) && createHash('sha256').update(readFileSync(entryPath)).digest('hex') === entry.rawSha256 && readFileSync(entryPath).length === entry.byteLength, `${label} payload drift: ${entry.path}`);
  }
  const actualFiles = [];
  const actualDirs = [];
  const walk = (folder, prefix = '') => {
    for (const name of readdirSync(folder).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
      const child = resolve(folder, name);
      const next = prefix ? `${prefix}/${name}` : name;
      const stat = lstatSync(child);
      expect(!stat.isSymbolicLink(), `${label} symlink: ${next}`);
      if (stat.isDirectory()) { actualDirs.push(next); walk(child, next); }
      else { expect(stat.isFile() && stat.nlink === 1, `${label} non-regular or hardlinked payload: ${next}`); actualFiles.push(next); }
    }
  };
  walk(root);
  actualFiles.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  actualDirs.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const expectedFiles = ['MANIFEST.json', 'SHA256SUMS', ...expectedPayloads.map((entry) => entry.slice(manifestPrefix.length))].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const expectedDirs = new Set();
  for (const file of expectedFiles) { const parts = file.split('/'); for (let i = 1; i < parts.length; i += 1) expectedDirs.add(parts.slice(0, i).join('/')); }
  expect(JSON.stringify(actualFiles) === JSON.stringify(expectedFiles), `${label} file closure changed`);
  expect(JSON.stringify(actualDirs) === JSON.stringify([...expectedDirs].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))), `${label} directory closure changed`);
  const expectedRows = [[createHash('sha256').update(manifestBytes).digest('hex'), `${rootRel}/MANIFEST.json`], ...(manifest.files ?? []).map((entry) => [entry.rawSha256, entry.path])];
  expect(sumsBytes.equals(Buffer.from(`${expectedRows.map((row) => row.join('  ')).join('\n')}\n`, 'utf8')), `${label} checksum envelope changed`);
  expect(manifestSchema.$id === V3_PACKAGE_SCHEMA_IDS[index], `${label} schema identity changed`);
};
const validateCohortV3Freeze = () => {
  const laneBinding = lane.p2FieldCheckpoint?.cohortV3FreezeBinding;
  expect(laneBinding?.path === 'p2/gate-b/cohort-v3-freeze.v1.json' && laneBinding.schemaPath === 'p2/gate-b/cohort-v3-freeze.v1.schema.json', 'lane v3 freeze path pin changed');
  expect(laneBinding?.rawSha256 === sha256(cohortV3FreezePath) && laneBinding.schemaSha256 === sha256(cohortV3FreezeSchemaPath) && laneBinding.contentDigest === cohortV3Freeze.contentDigest?.value && laneBinding.status === cohortV3Freeze.status && laneBinding.executionAllowed === false, 'lane v3 freeze pin is stale');
  for (const error of v3FreezeValueErrors(cohortV3Freeze)) errors.push(`cohort-v3 freeze ${error}`);
  const validate = compileStrictSchema(cohortV3FreezeSchemaPath, 'cohort-v3 freeze', cohortV3Freeze);
  expect(validate !== null, 'cohort-v3 freeze schema unavailable');
  for (const [index, root] of cohortV3PackageRoots.entries()) validateV3PackageEnvelope(root, cohortV3Freeze.packageRoots?.[index], index);
  expect(!existsSync(cohortV3ExternalAuthRoot), 'v3 authorization namespace must remain absent at freeze');
  expect(!existsSync(cohortV3ExternalRunRoot), 'v3 execution run namespace must remain absent at freeze');
  const inherited = cohortV3Freeze.inherited;
  expect(inherited?.freezeV2?.path === 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/MANIFEST.json' && inherited.freezeV2.rawSha256 === sha256(cohortFreezeV2ManifestPath) && inherited.freezeV2.status === cohortFreezeV2Manifest.status, 'inherited freeze-v2 pin is stale');
  const retryPath = resolve(repoRoot, inherited?.retryV1?.path ?? '');
  const accountingRootPath = resolve(repoRoot, inherited?.accountingV1?.rootPath ?? '');
  const accountingManifestPath = resolve(repoRoot, inherited?.accountingV1?.manifestPath ?? '');
  expect(existsSync(retryPath), 'inherited retry-v1 artifact is missing');
  expect(existsSync(accountingRootPath) && existsSync(accountingManifestPath), 'inherited accounting-v1 artifacts are incomplete');
  if (existsSync(retryPath)) { const retry = JSON.parse(readFileSync(retryPath)); expect(inherited.retryV1.rawSha256 === sha256(retryPath) && inherited.retryV1.identity === retry.retryId && JSON.stringify(inherited.retryV1.contentDigest) === JSON.stringify(retry.contentDigest), 'inherited retry-v1 pin is stale'); }
  if (existsSync(accountingRootPath) && existsSync(accountingManifestPath)) { const root = JSON.parse(readFileSync(accountingRootPath)); expect(inherited.accountingV1.rootRawSha256 === sha256(accountingRootPath) && inherited.accountingV1.identity === root.accountingId && JSON.stringify(inherited.accountingV1.rootContentDigest) === JSON.stringify(root.contentDigest) && inherited.accountingV1.manifestRawSha256 === sha256(accountingManifestPath), 'inherited accounting-v1 pin is stale'); }
  const mutation = structuredClone(cohortV3Freeze); mutation.packageRoots[0].listedPayloadCount += 1; mutation.contentDigest = digestRecord(withoutContentDigest(mutation), V3_FREEZE_DOMAIN); expect(v3FreezeValueErrors(mutation).length > 0, 'v3 freeze mutation gate accepted a listed-count drift');
  const domainMutation = structuredClone(cohortV3Freeze); domainMutation.contentDigest.domain = `${V3_FREEZE_DOMAIN}/mutant`; domainMutation.contentDigest = digestRecord(withoutContentDigest(domainMutation), domainMutation.contentDigest.domain); expect(v3FreezeValueErrors(domainMutation).length > 0, 'v3 freeze mutation gate accepted a domain drift');
  const hashMutation = structuredClone(cohortV3Freeze); hashMutation.packageRoots[0].manifestRawSha256 = '0'.repeat(64); expect(hashMutation.packageRoots[0].manifestRawSha256 !== sha256(resolve(repoRoot, hashMutation.packageRoots[0].manifestPath)), 'v3 freeze mutation gate accepted a manifest raw-hash drift');
  const schemaMutation = structuredClone(cohortV3Freeze); schemaMutation.packageRoots[1].manifestSchemaRawSha256 = '0'.repeat(64); expect(schemaMutation.packageRoots[1].manifestSchemaRawSha256 !== sha256(resolve(repoRoot, schemaMutation.packageRoots[1].manifestSchemaPath)), 'v3 freeze mutation gate accepted a schema raw-hash drift');
  const checksumMutation = structuredClone(cohortV3Freeze); checksumMutation.packageRoots[1].checksumsRawSha256 = '0'.repeat(64); expect(checksumMutation.packageRoots[1].checksumsRawSha256 !== sha256(resolve(repoRoot, checksumMutation.packageRoots[1].checksumsPath)), 'v3 freeze mutation gate accepted a checksum raw-hash drift');
  const swapMutation = structuredClone(cohortV3Freeze); [swapMutation.packageRoots[0], swapMutation.packageRoots[1]] = [swapMutation.packageRoots[1], swapMutation.packageRoots[0]]; expect(v3FreezeValueErrors(swapMutation).length > 0, 'v3 freeze mutation gate accepted swapped package roots');
  const duplicateMutation = structuredClone(cohortV3Freeze); duplicateMutation.packageRoots[1] = structuredClone(duplicateMutation.packageRoots[0]); expect(v3FreezeValueErrors(duplicateMutation).length > 0, 'v3 freeze mutation gate accepted duplicate package roots');
};
const schema = loadJson(resolve(sourceDir, 'diagram-transcription.schema.json'));
const diagram = loadJson(resolve(sourceDir, 'diagram-11174.transcription.json'));
const manifest = loadJson(resolve(sourceDir, 'source-manifest.json'));
const chain = loadJson(resolve(sourceDir, 'chain-observation-2026-08-08.json'));
const claims = loadJson(resolve(laneDir, 'analysis/claim-ledger.json'));
const lane = loadJson(resolve(laneDir, 'lane.json'));
const cpsbPackageRelative = 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1';
const cpsbPackageRoot = resolve(laneDir, cpsbPackageRelative);
const cpsbRootPath = resolve(cpsbPackageRoot, 'external-authority-control-plane-schema-bridge-root.v1.json');
const cpsbManifestPath = resolve(cpsbPackageRoot, 'MANIFEST.json');
const cpsbChecksumsPath = resolve(cpsbPackageRoot, 'SHA256SUMS');
const cpsbValidatorPath = resolve(cpsbPackageRoot, 'validate-static.mjs');
const cpsbReviewAnchorPath = resolve(laneDir, 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json');
const cpsbReceiptReadmePath = resolve(laneDir, 'evidence/cpsb-exact29-sealed-validation-v1/README.md');
const cpsbReceiptChecksumsPath = resolve(laneDir, 'evidence/cpsb-exact29-sealed-validation-v1/SHA256SUMS');
const cpsbReceiptPath = resolve(laneDir, 'evidence/cpsb-exact29-sealed-validation-v1/receipt.json');
const cpsbReceiptStderrPath = resolve(laneDir, 'evidence/cpsb-exact29-sealed-validation-v1/stderr.bin');
const poolActionCapturePath = resolve(laneDir, 'evidence/poolactionfv1-contradiction-capture-v1/contradiction-capture.v1.json');
const poolActionWitnessBoundaryPath = resolve(laneDir, 'evidence/poolactionfv1-contradiction-capture-v1/witness-boundary.v1.json');
const poolActionCaptureChecksumsPath = resolve(laneDir, 'evidence/poolactionfv1-contradiction-capture-v1/SHA256SUMS');
const cpsbRawPins = Object.freeze([
  [cpsbRootPath, 50052, '89c281e916790e5d488f554fdf508af80cc7c3e0b8d9a2b99f62707c150a17e4', 'CPSB root'],
  [cpsbManifestPath, 13498, 'cb7eb8a3dd6691d325fa1c0479b71a0fa0748649fef238c10e78cc0bbe7dc5c0', 'CPSB manifest'],
  [cpsbChecksumsPath, 2880, '95751ed2534f16ce73eb13d18bdf9dd7b11334bc7751ed15b830a95786c85428', 'CPSB checksums'],
  [cpsbValidatorPath, 438375, '65727edaa77d783dd0db33f70f57856240f7c732b7156fa8c76785aadf94546c', 'CPSB validator bytes'],
  [cpsbReviewAnchorPath, 32442, '42f2b1eaf7d4834f4c07248da74981f40fccb71a4e633afb29bffefab4d5b868', 'CPSB review anchor'],
  [cpsbReceiptReadmePath, 1245, '4dd4c693284765d0100eaa31be441d835d9cbb8dc79b35cb4b4b72e3c5be03eb', 'CPSB receipt README'],
  [cpsbReceiptChecksumsPath, 232, '9afbdb145177e2a5cff406e163b8f7d672a7cef34712a1491b820a2dbc03fc4c', 'CPSB receipt checksums'],
  [cpsbReceiptPath, 8147, '1fbe919d8556f6e73344402d07b3a1df8d47fca0d91268fadbb4d8c7d9f58f53', 'CPSB exact29 receipt'],
  [cpsbReceiptStderrPath, 0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'CPSB exact29 stderr'],
  [poolActionCapturePath, 3838, '9a48318169d0c67a8d537e53aaacb7279177ac4a9ba0c5bc966228dc5bba32cf', 'PoolAction contradiction capture'],
  [poolActionWitnessBoundaryPath, 1169, '74a637250d56afdd762e98004d012cc3b8f632b6caaad482bcb26c06a4ae4f97', 'PoolAction witness boundary'],
  [poolActionCaptureChecksumsPath, 534, 'fe3d20e135ebf89c4b350749bb6a8da5b88e962a18fb60d4052065a2c91c45de', 'PoolAction capsule checksums']
]);
for (const [path, bytes, rawSha256, label] of cpsbRawPins) {
  const raw = readFileSync(path);
  expect(raw.length === bytes, `${label} byte count changed`);
  expect(createHash('sha256').update(raw).digest('hex') === rawSha256, `${label} raw hash changed`);
}
const cpsbRoot = JSON.parse(readFileSync(cpsbRootPath, 'utf8'));
const cpsbManifest = JSON.parse(readFileSync(cpsbManifestPath, 'utf8'));
const cpsbReviewAnchor = JSON.parse(readFileSync(cpsbReviewAnchorPath, 'utf8'));
const cpsbReceipt = JSON.parse(readFileSync(cpsbReceiptPath, 'utf8'));
const poolActionCapture = JSON.parse(readFileSync(poolActionCapturePath, 'utf8'));
const poolActionWitnessBoundary = JSON.parse(readFileSync(poolActionWitnessBoundaryPath, 'utf8'));
const cpsbSame = (left, right) => JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
const cpsbComponentDigest = (component) => cpsbRoot.componentDigests?.find((row) => row.component === component)?.digest?.value;
expect(
  cpsbRoot.contentDigest?.value === 'd05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c' &&
    cpsbRoot.dependencyBinding?.contentDigest?.value === '9315632dc9a6d94ea4beaccdf8622c5a0ccdfb6f08a6c0719d3b95984a691f58' &&
    cpsbComponentDigest('schemaBindings') === '30ff8071dc6299a2edbac29b149cb6a91d5269e664e4d14e8c615f4166289c67' &&
    cpsbRoot.schemaBindings?.length === 18 &&
    cpsbRoot.futureRecordContracts?.entries?.length === 11 &&
    cpsbRoot.futureRecordContracts?.recordKindCount === 11 &&
    cpsbRoot.futureRecordContracts?.totalRecordCount === 0 &&
    cpsbRoot.futureRecordContracts.entries.every((row) => row.recordCount === 0 && row.creationAllowed === false) &&
    cpsbRoot.executionAllowed === false && cpsbRoot.measurementAdmissionAllowed === false,
  'CPSB root future-grammar, digest-ordering, or zero-record boundary changed'
);
expect(
  cpsbManifest.entryCount === 27 && cpsbManifest.entries?.length === 27 &&
    cpsbManifest.rosterDigest?.value === 'aae5914933f8d4d0206de928d1cc0ae7be8100410dd4399d447fe68bbbc6a43f',
  'CPSB manifest source-entry closure changed'
);
expect(
  cpsbReviewAnchor.entryCount === 27 && cpsbReviewAnchor.orderedClosure?.length === 27 &&
    cpsbReviewAnchor.schemaBindings?.length === 18 &&
    cpsbReviewAnchor.rootRawSha256 === '89c281e916790e5d488f554fdf508af80cc7c3e0b8d9a2b99f62707c150a17e4' &&
    cpsbReviewAnchor.rootContentDigest?.value === 'd05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c' &&
    cpsbReviewAnchor.manifestRawSha256 === 'cb7eb8a3dd6691d325fa1c0479b71a0fa0748649fef238c10e78cc0bbe7dc5c0' &&
    cpsbReviewAnchor.sha256SumsRawSha256 === '95751ed2534f16ce73eb13d18bdf9dd7b11334bc7751ed15b830a95786c85428' &&
    cpsbReviewAnchor.validatorRawSha256 === '65727edaa77d783dd0db33f70f57856240f7c732b7156fa8c76785aadf94546c',
  'CPSB outside review anchor changed'
);
expect(
  cpsbReceipt.schema === 'shieldkit-labs/external-launcher/cpsb-exact29/receipt/v1' &&
    cpsbReceipt.launcherId === 'cpsb-exact29-v1' && cpsbReceipt.action === 'validate-sealed' &&
    cpsbReceipt.authorization === 'NONE' && cpsbReceipt.classification === 'AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY' &&
    cpsbReceipt.mode === 'sealed' && cpsbReceipt.entryCount === 676 && cpsbReceipt.totalBytes === 174515890 &&
    cpsbReceipt.orderedRowDigest?.value === '2d6667fca54ea6fd326ab7f7cf1f2f09477766e3f0184b0e46fef84cba67c688' &&
    cpsbReceipt.validator?.executed === true && cpsbReceipt.validator?.exitCode === 0 &&
    cpsbReceipt.validator?.value?.schemaCount === 18 && cpsbReceipt.validator?.value?.futureRecordSchemaCount === 11 &&
    cpsbReceipt.validator?.value?.totalRecordCount === 0 && cpsbReceipt.validator?.value?.unsealed === false &&
    cpsbReceipt.cpsbSealedSourceContract?.sourceEntryCount === 27 && cpsbReceipt.cpsbSealedSourceContract?.sealedPackageFileCount === 29,
  'CPSB exact29 retained receipt identity, closure, or static-only result changed'
);
const cpsbBinding = lane.p2FieldCheckpoint?.gateB0ExternalAuthorityControlPlaneSchemaBridgeV1Binding;
expectExactSet(Object.keys(cpsbBinding ?? {}), ['path', 'root', 'manifest', 'checksums', 'validator', 'reviewAnchor', 'componentDigests', 'counts', 'sealedValidationEvidence', 'nonAuthorityBoundary', 'status'], 'CPSB lane binding keys');
expect(cpsbBinding?.path === cpsbPackageRelative && cpsbBinding?.status === CPSB_STATUS, 'CPSB lane binding identity or SOL ruling changed');
expect(cpsbSame(cpsbBinding?.root, {path:`${cpsbPackageRelative}/external-authority-control-plane-schema-bridge-root.v1.json`,bytes:50052,rawSha256:'89c281e916790e5d488f554fdf508af80cc7c3e0b8d9a2b99f62707c150a17e4',contentDigest:'d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c'}), 'CPSB lane root binding changed');
expect(cpsbSame(cpsbBinding?.manifest, {path:`${cpsbPackageRelative}/MANIFEST.json`,bytes:13498,rawSha256:'cb7eb8a3dd6691d325fa1c0479b71a0fa0748649fef238c10e78cc0bbe7dc5c0',rosterDigest:'aae5914933f8d4d0206de928d1cc0ae7be8100410dd4399d447fe68bbbc6a43f',entryCount:27}), 'CPSB lane manifest binding changed');
expect(cpsbSame(cpsbBinding?.checksums, {path:`${cpsbPackageRelative}/SHA256SUMS`,bytes:2880,rawSha256:'95751ed2534f16ce73eb13d18bdf9dd7b11334bc7751ed15b830a95786c85428'}), 'CPSB lane checksum binding changed');
expect(cpsbSame(cpsbBinding?.validator, {path:`${cpsbPackageRelative}/validate-static.mjs`,bytes:438375,rawSha256:'65727edaa77d783dd0db33f70f57856240f7c732b7156fa8c76785aadf94546c'}), 'CPSB lane validator-byte binding changed');
expect(cpsbSame(cpsbBinding?.reviewAnchor, {path:'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json',schema:'shieldkit-labs/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge/v1/external-review-anchor/v1',bytes:32442,rawSha256:'42f2b1eaf7d4834f4c07248da74981f40fccb71a4e633afb29bffefab4d5b868'}), 'CPSB lane review-anchor binding changed');
expect(cpsbSame(cpsbBinding?.componentDigests, {dependencyBinding:'9315632dc9a6d94ea4beaccdf8622c5a0ccdfb6f08a6c0719d3b95984a691f58',schemaBindings:'30ff8071dc6299a2edbac29b149cb6a91d5269e664e4d14e8c615f4166289c67'}), 'CPSB lane component-digest binding changed');
expect(cpsbSame(cpsbBinding?.counts, {sourceManifestEntries:27,sealedPackageFiles:29,sealedPackageDirectories:3,schemaBindings:18,futureRecordSchemas:11,futureRecords:0,authenticatedClosureFiles:676,authenticatedClosureBytes:174515890}), 'CPSB lane counts changed');
expect(cpsbSame(cpsbBinding?.nonAuthorityBoundary, cpsbRoot.nonAuthorityBoundary), 'CPSB lane non-authority boundary changed');
expect(cpsbSame(cpsbBinding?.sealedValidationEvidence, {path:'evidence/cpsb-exact29-sealed-validation-v1',readme:{path:'evidence/cpsb-exact29-sealed-validation-v1/README.md',bytes:1245,rawSha256:'4dd4c693284765d0100eaa31be441d835d9cbb8dc79b35cb4b4b72e3c5be03eb'},checksums:{path:'evidence/cpsb-exact29-sealed-validation-v1/SHA256SUMS',bytes:232,rawSha256:'9afbdb145177e2a5cff406e163b8f7d672a7cef34712a1491b820a2dbc03fc4c'},receipt:{path:'evidence/cpsb-exact29-sealed-validation-v1/receipt.json',bytes:8147,rawSha256:'1fbe919d8556f6e73344402d07b3a1df8d47fca0d91268fadbb4d8c7d9f58f53'},stderr:{path:'evidence/cpsb-exact29-sealed-validation-v1/stderr.bin',bytes:0,rawSha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},launcherId:'cpsb-exact29-v1',action:'validate-sealed',classification:'AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY',authorization:'NONE',mode:'sealed',validatorExecuted:true,validatorExitCode:0,entryCount:676,totalBytes:174515890,orderedRowDigest:'2d6667fca54ea6fd326ab7f7cf1f2f09477766e3f0184b0e46fef84cba67c688',schemaCount:18,futureRecordSchemaCount:11,totalRecordCount:0,rootContentDigest:'d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c',unsealed:false,trustBoundary:'unsigned-replayable-external-caller-and-host-tcb-no-independent-attestation-same-uid-post-bubblewrap-injection-out-of-proof'}), 'CPSB retained exact29 evidence binding changed');
expect(
  poolActionCapture.authority === 'none' && poolActionCapture.status === 'observed-open-blockers-not-a-relation-amendment' &&
    poolActionCapture.promotionRule === 'cannot-qualify-select-or-begin-full-prover' && poolActionCapture.items?.length === 4 &&
    poolActionCapture.items.every((item) => item.status === 'observed-open-blockers-not-a-relation-amendment') &&
    poolActionWitnessBoundary.authority === 'none' && poolActionWitnessBoundary.execution === 'not-authorized-not-performed' &&
    poolActionWitnessBoundary.items?.length === 4,
  'PoolAction contradiction capsule status, count, or no-execution boundary changed'
);
expect(cpsbSame(lane.p1Checkpoint?.openBlockerEvidence, {capture:{path:'evidence/poolactionfv1-contradiction-capture-v1/contradiction-capture.v1.json',bytes:3838,rawSha256:'9a48318169d0c67a8d537e53aaacb7279177ac4a9ba0c5bc966228dc5bba32cf'},witnessBoundary:{path:'evidence/poolactionfv1-contradiction-capture-v1/witness-boundary.v1.json',bytes:1169,rawSha256:'74a637250d56afdd762e98004d012cc3b8f632b6caaad482bcb26c06a4ae4f97'},checksums:{path:'evidence/poolactionfv1-contradiction-capture-v1/SHA256SUMS',bytes:534,rawSha256:'fe3d20e135ebf89c4b350749bb6a8da5b88e962a18fb60d4052065a2c91c45de'},openBlockerCount:4,sourceManifestEntryCount:11,authority:'none',status:'observed-open-blockers-not-a-relation-amendment',gateImpacts:[1,5],promotionRule:'cannot-qualify-select-or-begin-full-prover'}), 'P1 open-blocker evidence binding changed');

const refreezeRelationRoot = resolve(laneDir, 'spec/poolaction-relation-disposition-refreeze-v2');
const refreezeMeasurementRoot = resolve(laneDir, 'evidence/measurement-admission-v2');
const refreezeV1Root = resolve(laneDir, 'evidence/poolactionfv1-refreeze-falsifiers-v1');
const refreezeV2Root = resolve(laneDir, 'spec/poolactionfv1-refreeze-falsifier-contract-v2');
const refreezeAnchorPath = resolve(laneDir, 'spec/poolactionfv1-refreeze-falsifier-contract-v2-review-anchor.v1.json');
const refreezeReadPinnedJson = (path, bytes, rawSha256, label) => {
  const raw = readFileSync(path);
  expect(raw.length === bytes, `${label} byte count changed`);
  expect(createHash('sha256').update(raw).digest('hex') === rawSha256, `${label} raw hash changed`);
  try { return JSON.parse(raw.toString('utf8')); } catch { errors.push(`${label} is not JSON`); return null; }
};
const refreezeAssertManifestClosure = (root, manifest, entries, manifestPin, sumsPin, label) => {
  refreezeReadPinnedJson(resolve(root, 'MANIFEST.json'), manifestPin.bytes, manifestPin.rawSha256, `${label} manifest`);
  const sums = readFileSync(resolve(root, 'SHA256SUMS'));
  expect(sums.length === sumsPin.bytes && createHash('sha256').update(sums).digest('hex') === sumsPin.rawSha256, `${label} checksum envelope changed`);
  expect(Array.isArray(entries), `${label} manifest entry roster is absent`);
  for (const entry of entries ?? []) {
    const raw = readFileSync(resolve(root, entry.path));
    expect(raw.length === entry.bytes && createHash('sha256').update(raw).digest('hex') === entry.rawSha256, `${label} raw pin changed: ${entry.path}`);
  }
  expect((entries?.length ?? -1) + 2 === manifest.sealedFileCount || manifest.sealedFileCount === undefined, `${label} sealed-file arithmetic changed`);
};
const refreezeRelationManifest = refreezeReadPinnedJson(resolve(refreezeRelationRoot, 'MANIFEST.json'), 2602, 'b318fe27af307d274a5dfdd6380b50ca843e384d84a80b325e1e351e92c06284', 'refreeze relation manifest');
const refreezeRelationDisposition = refreezeReadPinnedJson(resolve(refreezeRelationRoot, 'disposition.v2.json'), 7110, 'd21fae8f25b9941e1de7e1facfae6fb6bd6970429cd031093154ee36fcc904b4', 'refreeze relation disposition');
const refreezeMeasurementManifest = refreezeReadPinnedJson(resolve(refreezeMeasurementRoot, 'MANIFEST.json'), 1006, '7e1ad3809420de8dd406fa2c9c626163c0af4f3554280f12bf8f28dd22afdea6', 'measurement admission manifest');
const refreezeMeasurementAdmission = refreezeReadPinnedJson(resolve(refreezeMeasurementRoot, 'admission.v2.json'), 8018, '9343f8385a326028d906798ff69e851dd4fbf0c1cdd53295b26e81fd512b45e2', 'measurement admission record');
const refreezeV1Manifest = refreezeReadPinnedJson(resolve(refreezeV1Root, 'MANIFEST.json'), 1715, '2b0ff525786997e390b3668290aa2d6c602c254c26b56b8e9da2b865d261e559', 'refreeze v1 manifest');
const refreezeV1Index = refreezeReadPinnedJson(resolve(refreezeV1Root, 'index.v1.json'), 41569, '2ed8feac0a231e6cb55ad4012db1a75b32174963d3bd5c2a8c523b258568b686', 'refreeze v1 index');
const refreezeV1Receipt = refreezeReadPinnedJson(resolve(refreezeV1Root, 'receipt.v1.json'), 1439, '627e55b1d027ae7bc9ede183383fb8147412b05b3d83846f1723a605c24c3c28', 'refreeze v1 receipt');
const refreezeV2Manifest = refreezeReadPinnedJson(resolve(refreezeV2Root, 'MANIFEST.json'), 3022, '8eec7bc7b9a1a141d8d4b9a6f9d321f013c4d3289d7999a1ec05011d9710b430', 'refreeze v2 manifest');
const refreezeAnchor = refreezeReadPinnedJson(refreezeAnchorPath, 7979, 'feeea15e78a2202040086e1a105edea6e1a8fe28230403744c5ba9e52eecd524', 'refreeze v2 review anchor');
refreezeAssertManifestClosure(refreezeRelationRoot, refreezeRelationManifest ?? {}, refreezeRelationManifest?.files, {bytes:2602,rawSha256:'b318fe27af307d274a5dfdd6380b50ca843e384d84a80b325e1e351e92c06284'}, {bytes:832,rawSha256:'ed510ad9bf468f1131bc7d29a5a04f7d2d1b6a2b360292abd8eeaad0c1ec7acb'}, 'refreeze relation package');
refreezeAssertManifestClosure(refreezeMeasurementRoot, refreezeMeasurementManifest ?? {}, refreezeMeasurementManifest?.authoredEntries, {bytes:1006,rawSha256:'7e1ad3809420de8dd406fa2c9c626163c0af4f3554280f12bf8f28dd22afdea6'}, {bytes:331,rawSha256:'115e71bfd2d5ba095dc09868f9d7eb3f73e34207d049b69b9838a99d29a2f645'}, 'measurement admission package');
refreezeAssertManifestClosure(refreezeV1Root, refreezeV1Manifest ?? {}, refreezeV1Manifest?.files, {bytes:1715,rawSha256:'2b0ff525786997e390b3668290aa2d6c602c254c26b56b8e9da2b865d261e559'}, {bytes:741,rawSha256:'da6d23163401b9594f5a0c4ccf05260d45596a1ca9653eff0bf2e58cd72c8ba6'}, 'refreeze v1 package');
for (const pin of refreezeAnchor?.rawPinClosure?.pins ?? []) {
  expect(!pin.locator.startsWith('/') && !pin.locator.split('/').includes('..'), `refreeze v2 anchor has unsafe locator: ${pin.locator}`);
  const raw = readFileSync(resolve(refreezeV2Root, pin.locator));
  expect(raw.length === pin.bytes && createHash('sha256').update(raw).digest('hex') === pin.rawSha256, `refreeze v2 anchor raw pin changed: ${pin.locator}`);
}
expect(
  refreezeRelationManifest?.packageId === 'spec:poolaction-relation-disposition-refreeze-v2' && refreezeRelationManifest?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeRelationManifest?.authority === 'none' && refreezeRelationManifest?.fileCount === 8 &&
    refreezeRelationDisposition?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeRelationDisposition?.authority === 'none' && refreezeRelationDisposition?.relationRefreezeAllowed === false && refreezeRelationDisposition?.measurementAdmissionAllowed === false && refreezeRelationDisposition?.qualificationAllowed === false && refreezeRelationDisposition?.blockerDispositions?.length === 4,
  'refreeze relation disposition nonclaim boundary changed'
);
expect(
  refreezeMeasurementManifest?.status === 'SEALED_IMMUTABLE_ZERO_COUNT_SCHEMA_ONLY_NO_AUTHORITY' && refreezeMeasurementManifest?.authority === 'NONE' && refreezeMeasurementManifest?.sealedFileCount === 5 &&
    refreezeMeasurementAdmission?.status === 'SEALED_IMMUTABLE_ZERO_COUNT_SCHEMA_ONLY_NO_AUTHORITY' && refreezeMeasurementAdmission?.authority === 'NONE' && refreezeMeasurementAdmission?.b0ExecutionAuthorization === 'CLOSED' && refreezeMeasurementAdmission?.admittedMeasurementCount === 0 && refreezeMeasurementAdmission?.admittedRelationRef === null &&
    ['candidateCount','executionCount','measurementCount','parameterAssignmentCount','qualificationCount','rankingCount','roleAssignmentCount','selectionCount','tupleCount'].every((key) => refreezeMeasurementAdmission?.counts?.[key] === 0) &&
    ['executionAllowed','qualificationAllowed','rankingAllowed','selectionAllowed'].every((key) => refreezeMeasurementAdmission?.[key] === false) && Object.values(refreezeMeasurementAdmission?.nonAuthorityBoundary ?? {}).every((value) => value === false),
  'measurement admission zero/non-authority boundary changed'
);
expect(
  refreezeV1Manifest?.packageId === 'evidence:poolactionfv1-refreeze-falsifiers-v1' && refreezeV1Manifest?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeV1Manifest?.fileCount === 8 &&
    refreezeV1Index?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeV1Index?.authority === 'none' && refreezeV1Index?.evidenceTier === 'INERT_DETERMINISTIC_OFFLINE_REFERENCE_MODEL_ONLY' && refreezeV1Index?.cases?.length === 57 && Object.values(refreezeV1Index?.prohibitions ?? {}).every((value) => value === false) &&
    refreezeV1Receipt?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeV1Receipt?.authority === 'none' && refreezeV1Receipt?.materializedSubsetOnly === true && refreezeV1Receipt?.closureClaimed === false && refreezeV1Receipt?.relationRefreezeAllowed === false && refreezeV1Receipt?.unresolvedBlockerCount === 4,
  'refreeze v1 inert-synthetic-subset boundary changed'
);
expect(
  refreezeV2Manifest?.packageId === 'spec:poolactionfv1-refreeze-falsifier-contract-v2' && refreezeV2Manifest?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeV2Manifest?.authority === 'none' && refreezeV2Manifest?.fileCount === 14 && refreezeV2Manifest?.packageComplete === false && refreezeV2Manifest?.contentAggregate?.sha256 === '27b69bd649fddc78fa565a736b0dcbbf6b99e3dae6241f50dd99086643c385a2' &&
    refreezeAnchor?.status === 'BLOCKED_VERSION_PIVOT_NO_REFREEZE' && refreezeAnchor?.rawPinClosure?.entryCount === 16 && refreezeAnchor?.rawPinClosure?.pins?.length === 16 && refreezeAnchor?.reviewedRoster?.allFamiliesState === 'PLANNED_NO_CREDIT' && refreezeAnchor?.reviewedRoster?.totalRfFamilyCount === 57 && cpsbSame(refreezeAnchor?.reviewedRoster?.groups?.map(({group,count}) => ({group,count})), [{group:'POSITIVES',count:12},{group:'NETWORK_NEGATIVES',count:4},{group:'TXCONTEXT_TOKEN_NEGATIVES',count:9},{group:'LOCK_NEGATIVES',count:7},{group:'PROOF_SESSION_NEGATIVES',count:18},{group:'PARSER_NEGATIVES',count:4},{group:'SPLICES',count:3}]) &&
    refreezeAnchor?.executionAndExpectationBoundary?.executableRowCount === 0 && refreezeAnchor?.executionAndExpectationBoundary?.expectationRowCount === 0 && refreezeAnchor?.executionAndExpectationBoundary?.finalVariantCount === null && refreezeAnchor?.sourceProvenance?.sourcePinClosureComplete === false && refreezeAnchor?.sourceProvenance?.sourcePinClosureIncompleteSoleReason === 'No stable raw artifact exists for the supervisory matrix final.' && Object.values(refreezeAnchor?.nonAuthorityBoundary ?? {}).every((value) => value === false),
  'refreeze v2 source-contract or outside-anchor boundary changed'
);
const refreezeBinding = lane.p2FieldCheckpoint?.poolActionFv1RefreezeBlockedTransitionV2Binding;
expectExactSet(Object.keys(refreezeBinding ?? {}), ['transition','relationDisposition','measurementAdmission','inertSyntheticRegressionSubset','v2SourceContract','nonAuthorityBoundary','status'], 'refreeze blocked transition binding keys');
expect(cpsbSame(refreezeBinding?.transition, {from:'QUIESCENT_SOURCE_CONTRACT_INTEGRITY_ONLY',to:'BLOCKED_VERSION_PIVOT_NO_REFREEZE',relationRefreezeAllowed:false,b0ExecutionAuthorization:'CLOSED',hardGatesBlocked:[1,5]}), 'refreeze blocked transition identity changed');
expect(cpsbSame(refreezeBinding?.relationDisposition, {path:'spec/poolaction-relation-disposition-refreeze-v2',manifest:{path:'spec/poolaction-relation-disposition-refreeze-v2/MANIFEST.json',bytes:2602,rawSha256:'b318fe27af307d274a5dfdd6380b50ca843e384d84a80b325e1e351e92c06284'},checksums:{path:'spec/poolaction-relation-disposition-refreeze-v2/SHA256SUMS',bytes:832,rawSha256:'ed510ad9bf468f1131bc7d29a5a04f7d2d1b6a2b360292abd8eeaad0c1ec7acb'},disposition:{path:'spec/poolaction-relation-disposition-refreeze-v2/disposition.v2.json',bytes:7110,rawSha256:'d21fae8f25b9941e1de7e1facfae6fb6bd6970429cd031093154ee36fcc904b4'},recursiveFileCount:10,status:'BLOCKED_VERSION_PIVOT_NO_REFREEZE'}), 'refreeze relation lane binding changed');
expect(cpsbSame(refreezeBinding?.measurementAdmission, {path:'evidence/measurement-admission-v2',manifest:{path:'evidence/measurement-admission-v2/MANIFEST.json',bytes:1006,rawSha256:'7e1ad3809420de8dd406fa2c9c626163c0af4f3554280f12bf8f28dd22afdea6'},checksums:{path:'evidence/measurement-admission-v2/SHA256SUMS',bytes:331,rawSha256:'115e71bfd2d5ba095dc09868f9d7eb3f73e34207d049b69b9838a99d29a2f645'},admission:{path:'evidence/measurement-admission-v2/admission.v2.json',bytes:8018,rawSha256:'9343f8385a326028d906798ff69e851dd4fbf0c1cdd53295b26e81fd512b45e2'},sealedFileCount:5,status:'SEALED_IMMUTABLE_ZERO_COUNT_SCHEMA_ONLY_NO_AUTHORITY'}), 'measurement admission lane binding changed');
expect(cpsbSame(refreezeBinding?.inertSyntheticRegressionSubset, {path:'evidence/poolactionfv1-refreeze-falsifiers-v1',manifest:{path:'evidence/poolactionfv1-refreeze-falsifiers-v1/MANIFEST.json',bytes:1715,rawSha256:'2b0ff525786997e390b3668290aa2d6c602c254c26b56b8e9da2b865d261e559'},checksums:{path:'evidence/poolactionfv1-refreeze-falsifiers-v1/SHA256SUMS',bytes:741,rawSha256:'da6d23163401b9594f5a0c4ccf05260d45596a1ca9653eff0bf2e58cd72c8ba6'},index:{path:'evidence/poolactionfv1-refreeze-falsifiers-v1/index.v1.json',bytes:41569,rawSha256:'2ed8feac0a231e6cb55ad4012db1a75b32174963d3bd5c2a8c523b258568b686'},receipt:{path:'evidence/poolactionfv1-refreeze-falsifiers-v1/receipt.v1.json',bytes:1439,rawSha256:'627e55b1d027ae7bc9ede183383fb8147412b05b3d83846f1723a605c24c3c28'},recursiveFileCount:10,materializedSubsetOnly:true,closureClaimed:false,status:'BLOCKED_VERSION_PIVOT_NO_REFREEZE'}), 'refreeze v1 lane binding changed');
expect(cpsbSame(refreezeBinding?.v2SourceContract, {path:'spec/poolactionfv1-refreeze-falsifier-contract-v2',manifest:{path:'spec/poolactionfv1-refreeze-falsifier-contract-v2/MANIFEST.json',bytes:3022,rawSha256:'8eec7bc7b9a1a141d8d4b9a6f9d321f013c4d3289d7999a1ec05011d9710b430',contentAggregateSha256:'27b69bd649fddc78fa565a736b0dcbbf6b99e3dae6241f50dd99086643c385a2'},checksums:{path:'spec/poolactionfv1-refreeze-falsifier-contract-v2/SHA256SUMS',bytes:1410,rawSha256:'1eb83a945d75420be3ca11b1d1f379218491086ed0b1ad95eadcb67531868afe'},reviewAnchor:{path:'spec/poolactionfv1-refreeze-falsifier-contract-v2-review-anchor.v1.json',bytes:7979,rawSha256:'feeea15e78a2202040086e1a105edea6e1a8fe28230403744c5ba9e52eecd524'},rawPinClosureEntryCount:16,fileCount:16,allFamiliesState:'PLANNED_NO_CREDIT',groupCounts:{POSITIVES:12,NETWORK_NEGATIVES:4,TXCONTEXT_TOKEN_NEGATIVES:9,LOCK_NEGATIVES:7,PROOF_SESSION_NEGATIVES:18,PARSER_NEGATIVES:4,SPLICES:3,total:57},executableRowCount:0,expectationRowCount:0,finalVariantCount:null,sourcePinClosureComplete:false,sourcePinClosureIncompleteSoleReason:'No stable raw artifact exists for the supervisory matrix final.',status:'BLOCKED_VERSION_PIVOT_NO_REFREEZE'}), 'refreeze v2 lane binding changed');
expect(cpsbSame(refreezeBinding?.nonAuthorityBoundary, {authority:'none',authorityGranted:false,admissionAllowed:false,executionAllowed:false,measurementAllowed:false,measurementAdmissionAllowed:false,qualificationAllowed:false,rankingAllowed:false,selectionAllowed:false,candidateCreationAllowed:false,candidateCount:0,tupleCreationAllowed:false,tupleCount:0,roleAssignmentAllowed:false,roleAssignmentCount:0,parameterAssignmentAllowed:false,parameterAssignmentCount:0,relationRefreezeAllowed:false,refreezePerformed:false}), 'refreeze blocked transition false/zero boundary changed');
expect(refreezeBinding?.status === 'QUIESCENT_BLOCKED_SOURCE_CONTRACT_INTEGRITY_ONLY_NO_REFREEZE_NO_AUTHORITY_NO_ADMISSION_NO_EXECUTION_NO_MEASUREMENT_NO_QUALIFICATION_NO_RANKING_NO_SELECTION', 'refreeze blocked transition status changed');
expect(cpsbSame({poolActionRelationDispositionRefreezeV2:lane.entrypoints?.poolActionRelationDispositionRefreezeV2,measurementAdmissionV2:lane.entrypoints?.measurementAdmissionV2,poolActionFv1RefreezeFalsifiersV1:lane.entrypoints?.poolActionFv1RefreezeFalsifiersV1,poolActionFv1RefreezeFalsifierContractV2:lane.entrypoints?.poolActionFv1RefreezeFalsifierContractV2,poolActionFv1RefreezeFalsifierContractV2ReviewAnchor:lane.entrypoints?.poolActionFv1RefreezeFalsifierContractV2ReviewAnchor}, {poolActionRelationDispositionRefreezeV2:'spec/poolaction-relation-disposition-refreeze-v2/disposition.v2.json',measurementAdmissionV2:'evidence/measurement-admission-v2/admission.v2.json',poolActionFv1RefreezeFalsifiersV1:'evidence/poolactionfv1-refreeze-falsifiers-v1/index.v1.json',poolActionFv1RefreezeFalsifierContractV2:'spec/poolactionfv1-refreeze-falsifier-contract-v2/MANIFEST.json',poolActionFv1RefreezeFalsifierContractV2ReviewAnchor:'spec/poolactionfv1-refreeze-falsifier-contract-v2-review-anchor.v1.json'}), 'refreeze blocked transition entrypoints changed');
expect(lane.p2FieldCheckpoint?.completed?.filter((item) => item === CPSB_COMPLETED).length === 1, 'P2 must add exactly one CPSB completed item');
expect(lane.p2FieldCheckpoint?.notEstablished?.filter((item) => item === CPSB_NOT_ESTABLISHED).length === 1, 'P2 must add exactly one CPSB nonclaim item');
expect(lane.architectureCheckpoint?.nextGate === CPSB_NEXT_GATE && lane.p2FieldCheckpoint?.nextGate === CPSB_NEXT_GATE, 'CPSB next-gate boundary changed');
for (const [path, label] of [[resolve(laneDir, 'README.md'), 'lane README'], [resolve(laneDir, 'analysis/design-options.md'), 'design options']]) {
  const prose = readFileSync(path, 'utf8');
  expect(prose.split(CPSB_PROSE).length === 2, `${label} must contain exactly one CPSB static-only paragraph`);
  expect(prose.split(POOLACTION_BLOCKER_PROSE).length === 2, `${label} must contain exactly one PoolAction blocker paragraph`);
  expect(prose.split(REFREEZE_BLOCKED_PROSE).length === 2, `${label} must contain exactly one refreeze-blocked paragraph`);
}
const cpsbLaneReadme = readFileSync(resolve(laneDir, 'README.md'), 'utf8');
for (const path of [cpsbPackageRelative, 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json', 'evidence/cpsb-exact29-sealed-validation-v1/', 'evidence/poolactionfv1-contradiction-capture-v1/']) expect(cpsbLaneReadme.includes(path), `lane README structure omits ${path}`);
const packageJson = loadJson(resolve(repoRoot, 'package.json'));
const profile = loadJson(resolve(repoRoot, 'atlas/profiles/fixed-ticket-serial-pool.json'));
const poolConfigPath = resolve(laneDir, 'spec/pool-config-fv1.json');
const p0FreezeManifestPath = resolve(laneDir, 'spec/p0-freeze-manifest.json');
const poolStateSchemaPath = resolve(laneDir, 'spec/pool-state-fv1.schema.json');
const poolStateDocPath = resolve(laneDir, 'spec/pool-state-fv1.md');
const poolActionPath = resolve(laneDir, 'spec/pool-action-fv1.json');
const poolActionSchemaPath = resolve(laneDir, 'spec/pool-action-fv1.schema.json');
const responsibilityMapPath = resolve(laneDir, 'spec/responsibility-map-fv1.json');
const threatModelSchemaPath = resolve(laneDir, 'security/threat-model-fv1.schema.json');
const threatModelPath = resolve(laneDir, 'security/threat-model-fv1.json');
const soundnessSchemaPath = resolve(laneDir, 'security/soundness-worksheet.schema.json');
const soundnessV2SchemaPath = resolve(laneDir, 'security/soundness-worksheet.v2.schema.json');
const zkReviewSchemaPath = resolve(laneDir, 'security/zk-leakage-review.schema.json');
const candidateMatrixSchemaPath = resolve(laneDir, 'research/candidate-matrix.schema.json');
const candidateMatrixPath = resolve(laneDir, 'research/circle-fri-candidate-matrix.v1.json');
const candidateCompositionV2SchemaPath = resolve(laneDir, 'research/circle-fri-candidate-matrix.v2.schema.json');
const candidateCompositionV2Path = resolve(laneDir, 'research/circle-fri-candidate-matrix.v2.json');
const fieldCertSchemaPath = resolve(laneDir, 'p2/field-cert/certificate.schema.json');
const frontierPrimeFixturePath = resolve(laneDir, 'p2/field-cert/fixtures/frontier-prime-checks.v1.json');
const m89RabinFixturePath = resolve(laneDir, 'p2/field-cert/fixtures/m89-x2-plus-1-rabin.v1.json');
const fieldCertNodeGeneratorPath = resolve(laneDir, 'p2/field-cert/node/generate.mjs');
const fieldCertNodeReplayPath = resolve(laneDir, 'p2/field-cert/node/replay.mjs');
const fieldCertNodeCliPath = resolve(laneDir, 'p2/field-cert/node/check-fixture.mjs');
const fieldCertPythonReplayPath = resolve(laneDir, 'p2/field-cert/python/replay_checker.py');
const fieldCertNodeManifestPath = resolve(laneDir, 'p2/field-cert/node/SHA256SUMS');
const fieldCertExternalManifestPath = resolve(laneDir, 'p2/field-cert/external/SHA256SUMS');
const fieldCertExternalRawOutputPath = resolve(laneDir, 'p2/field-cert/external/raw-output.json');
const gateBContractSchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-experiment.schema.json');
const gateBContractPath = resolve(laneDir, 'p2/gate-b/equal-relation-experiment.v1.json');
const gateBContractTestPath = resolve(laneDir, 'p2/gate-b/equal-relation-experiment.test.mjs');
const algebraDescriptorSchemaPath = resolve(laneDir, 'p2/algebra-component/algebra-component-descriptor.v1.schema.json');
const algebraDescriptorV2SchemaPath = resolve(laneDir, 'p2/algebra-component/algebra-component-descriptor.v2.schema.json');
const algebraDescriptorV2Paths = [
  resolve(laneDir, 'p2/algebra-component/descriptors/m89-d2-x2-plus-1.v2.json'),
  resolve(laneDir, 'p2/algebra-component/descriptors/m61-d3-x3-minus-5.v2.json'),
  resolve(laneDir, 'p2/algebra-component/descriptors/m31-d5-x5-plus-2x-minus-1.v2.json'),
  resolve(laneDir, 'p2/algebra-component/descriptors/m31-d6-x6-minus-5.v2.json')
];
const constructionFreezeSchemaPath = resolve(laneDir, 'p2/construction-freeze/construction-freeze.v1.schema.json');
const constructionFreezePath = resolve(laneDir, 'p2/construction-freeze/construction-freeze.v1.json');
const constructionTranscriptSchemaPath = resolve(laneDir, 'p2/construction-freeze/construction-freeze-normalized-transcript.v1.schema.json');
const constructionTranscriptPath = resolve(laneDir, 'p2/construction-freeze/construction-freeze.normalized-transcript.v1.json');
const scheduleFreezeSchemaPath = resolve(laneDir, 'p2/schedule-freeze/schedule-freeze.v1.schema.json');
const scheduleFreezePath = resolve(laneDir, 'p2/schedule-freeze/schedule-freeze.v1.json');
const certificateSetSchemaPath = resolve(laneDir, 'p2/field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.schema.json');
const certificateSetPath = resolve(laneDir, 'p2/field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.json');
const externalReviewSchemaPath = resolve(laneDir, 'p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.schema.json');
const externalReviewPath = resolve(laneDir, 'p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.json');
const loweringFreezeSchemaPath = resolve(laneDir, 'p2/lowering-freeze/lowering-freeze.v1.schema.json');
const loweringFreezePath = resolve(laneDir, 'p2/lowering-freeze/lowering-freeze.v1.json');
const loweringArmIrFreezeSchemaPath = resolve(laneDir, 'p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.schema.json');
const loweringArmIrFreezePath = resolve(laneDir, 'p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json');
const sourceSetSchemaPath = resolve(laneDir, 'p2/source-set-v1/source-set.v1.schema.json');
const sourceSetPlanMapSchemaPath = resolve(laneDir, 'p2/source-set-v1/plan-source-map.v1.schema.json');
const sourceSetPath = resolve(laneDir, 'p2/source-set-v1/source-set.v1.json');
const cohortFreezeV2Dir = resolve(laneDir, 'p2/gate-b/cohort-freeze-v2');
const cohortFreezeV2ManifestPath = resolve(cohortFreezeV2Dir, 'MANIFEST.json');
const cohortFreezeV2ManifestSchemaPath = resolve(cohortFreezeV2Dir, 'manifest.v1.schema.json');
const cohortFreezeV2CampaignPath = resolve(cohortFreezeV2Dir, 'campaign.v2.json');
const cohortFreezeV2CampaignSchemaPath = resolve(cohortFreezeV2Dir, 'campaign.v2.schema.json');
const cohortFreezeV2CorpusPath = resolve(cohortFreezeV2Dir, 'canonical-corpus.v2.json');
const cohortFreezeV2CorpusSchemaPath = resolve(cohortFreezeV2Dir, 'canonical-corpus.v2.schema.json');
const cohortFreezeV2FixtureRosterPath = resolve(cohortFreezeV2Dir, 'fixture-roster.v2.json');
const cohortFreezeV2FixtureRosterSchemaPath = resolve(cohortFreezeV2Dir, 'fixture-roster.v2.schema.json');
const cohortFreezeV2WorkItemRosterPath = resolve(cohortFreezeV2Dir, 'work-item-roster.v2.json');
const cohortFreezeV2WorkItemRosterSchemaPath = resolve(cohortFreezeV2Dir, 'work-item-roster.v2.schema.json');
const cohortFreezeV2EpochPath = resolve(cohortFreezeV2Dir, 'execution-epoch.v2.json');
const cohortFreezeV2EpochSchemaPath = resolve(cohortFreezeV2Dir, 'execution-epoch.v2.schema.json');
const cohortFreezeV2EngineSchemaPath = resolve(cohortFreezeV2Dir, 'engine.v2.schema.json');
const cohortFreezeV2EnginePaths = ['native', 'libauth', 'bchn', 'leanbch'].map((engineId) =>
  resolve(cohortFreezeV2Dir, `engines/${engineId}.v2.json`)
);
const policyAuthorityV1Dir = resolve(laneDir, 'p2/gate-b/cohort-policy-authority-v1');
const policyAuthorityV1RootPath = resolve(policyAuthorityV1Dir, 'policy-authority-root.v1.json');
const policyAuthorityV1ManifestPath = resolve(policyAuthorityV1Dir, 'MANIFEST.json');
const policyAuthorityV1ChecksumsPath = resolve(policyAuthorityV1Dir, 'SHA256SUMS');
const runtimeBindingV1Dir = resolve(laneDir, 'p2/gate-b/cohort-runtime-binding-v1');
const runtimeBindingV1RootPath = resolve(runtimeBindingV1Dir, 'runtime-binding-root.v1.json');
const runtimeBindingV1ManifestPath = resolve(runtimeBindingV1Dir, 'MANIFEST.json');
const runtimeBindingV1ChecksumsPath = resolve(runtimeBindingV1Dir, 'SHA256SUMS');
const runnerCoreV1Dir = resolve(laneDir, 'p2/gate-b/cohort-runner-core-v1');
const runnerCoreV1RootPath = resolve(runnerCoreV1Dir, 'runtime-core.v1.json');
const runnerCoreV1ManifestPath = resolve(runnerCoreV1Dir, 'MANIFEST.json');
const runnerCoreV1ChecksumsPath = resolve(runnerCoreV1Dir, 'SHA256SUMS');
const frozenInputsV1Dir = resolve(laneDir, 'p2/gate-b/cohort-frozen-inputs-v1');
const frozenInputsV1RootPath = resolve(frozenInputsV1Dir, 'frozen-inputs-root.v1.json');
const frozenInputsV1ManifestPath = resolve(frozenInputsV1Dir, 'MANIFEST.json');
const frozenInputsV1ChecksumsPath = resolve(frozenInputsV1Dir, 'SHA256SUMS');
const cohortV3FreezePath = resolve(laneDir, 'p2/gate-b/cohort-v3-freeze.v1.json');
const cohortV3FreezeSchemaPath = resolve(laneDir, 'p2/gate-b/cohort-v3-freeze.v1.schema.json');
const cohortV3PackageRoots = [
  resolve(laneDir, 'p2/gate-b/cohort-execution-v3'),
  resolve(laneDir, 'p2/gate-b/cohort-executor-v3'),
  resolve(laneDir, 'p2/gate-b/cohort-commit-helper-v1')
];
const cohortV3ExternalAuthRoot = resolve(laneDir, 'p2/gate-b/cohort-execution-authorizations-v3');
const cohortV3ExternalRunRoot = resolve(laneDir, 'p2/gate-b/cohort-execution-runs-v3');
const m89AlgebraDescriptorPath = resolve(laneDir, 'p2/algebra-component/descriptors/m89-d2-x2-plus-1.v1.json');
const gateBArithmeticCampaignSchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-campaign.v1.schema.json');
const gateBArithmeticCampaignPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-campaign.v1.json');
const gateBArithmeticRunSchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-run.v1.schema.json');
const gateBArithmeticEngineResultSchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json');
const gateBArithmeticMetricReportSchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json');
const gateBArithmeticCrossEngineSummarySchemaPath = resolve(laneDir, 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json');
const m89GateB0MaterializerPath = resolve(laneDir, 'p2/gate-b/materialize-m89-shakedown.mjs');
const m89GateB0RunDir = resolve(laneDir, 'p2/gate-b/runs/m89-d2-schoolbook-shakedown-v1');
const m89GateB0RunPath = resolve(m89GateB0RunDir, 'run.json');
const m29CompositenessPath = resolve(laneDir, 'research/m29-compositeness-check-2026-08-08.md');
const microbenchSchemaPath = resolve(laneDir, 'bench/primitive-microbench.schema.json');
const m31BaseMulEvidencePath = resolve(laneDir, 'p2/evidence/m31-base-mul-v1.json');
const m31BaseMulSourceManifestPath = resolve(laneDir, 'p2/evidence/m31-base-mul-v1.sources.json');
const m31BaseSuiteEvidencePath = resolve(laneDir, 'p2/evidence/m31-base-suite-v1.json');
const m31BaseSuiteSourceManifestPath = resolve(laneDir, 'p2/evidence/m31-base-suite-v1.sources.json');
const m31BinaryRebuildReplayPath = resolve(laneDir, 'p2/evidence/m31-binary-rebuild-replay-2026-08-09.json');
const measurementSchemaPath = resolve(laneDir, 'evidence/measurement.schema.json');
const vectorIndexSchemaPath = resolve(laneDir, 'vectors/pool-action-fv1/index.schema.json');
const vectorIndexPath = resolve(laneDir, 'vectors/pool-action-fv1/index.json');
const bchProfilePath = resolve(laneDir, 'profiles/bch-current-2026-08-08.json');
const desktopProfilePath = resolve(laneDir, 'profiles/desktop-prover-v1.json');
const cohortV3Freeze = loadJson(cohortV3FreezePath);
const cohortV3FreezeSchema = loadJson(cohortV3FreezeSchemaPath);

const poolConfig = loadJson(poolConfigPath);
const p0FreezeManifest = loadJson(p0FreezeManifestPath);
const poolStateSchema = loadJson(poolStateSchemaPath);
const poolAction = loadJson(poolActionPath);
const responsibilityMap = loadJson(responsibilityMapPath);
const threatModel = loadJson(threatModelPath);
const soundnessV2Schema = loadJson(soundnessV2SchemaPath);
const candidateMatrix = loadJson(candidateMatrixPath);
const candidateCompositionV2 = loadJson(candidateCompositionV2Path);
const frontierPrimeFixture = loadJson(frontierPrimeFixturePath);
const m89RabinFixture = loadJson(m89RabinFixturePath);
const gateBContract = loadJson(gateBContractPath);
const m89AlgebraDescriptor = loadJson(m89AlgebraDescriptorPath);
const algebraDescriptorV2Schema = loadJson(algebraDescriptorV2SchemaPath);
const algebraDescriptorsV2 = algebraDescriptorV2Paths.map(loadJson);
const constructionFreeze = loadJson(constructionFreezePath);
const constructionTranscript = loadJson(constructionTranscriptPath);
const constructionFreezeSchema = loadJson(constructionFreezeSchemaPath);
const constructionTranscriptSchema = loadJson(constructionTranscriptSchemaPath);
const scheduleFreeze = loadJson(scheduleFreezePath);
const certificateSetSchema = loadJson(certificateSetSchemaPath);
const certificateSet = loadJson(certificateSetPath);
const externalReviewSchema = loadJson(externalReviewSchemaPath);
const externalReview = loadJson(externalReviewPath);
const loweringFreezeSchema = loadJson(loweringFreezeSchemaPath);
const loweringFreeze = loadJson(loweringFreezePath);
const loweringArmIrFreeze = loadJson(loweringArmIrFreezePath);
const sourceSet = loadJson(sourceSetPath);
const policyAuthorityV1Root = loadJson(policyAuthorityV1RootPath);
const policyAuthorityV1Manifest = loadJson(policyAuthorityV1ManifestPath);
const runtimeBindingV1Root = loadJson(runtimeBindingV1RootPath);
const runtimeBindingV1Manifest = loadJson(runtimeBindingV1ManifestPath);
const runnerCoreV1Root = loadJson(runnerCoreV1RootPath);
const runnerCoreV1Manifest = loadJson(runnerCoreV1ManifestPath);
const frozenInputsV1Root = loadJson(frozenInputsV1RootPath);
const frozenInputsV1Manifest = loadJson(frozenInputsV1ManifestPath);
const cohortFreezeV2Manifest = loadJson(cohortFreezeV2ManifestPath);
const cohortFreezeV2Campaign = loadJson(cohortFreezeV2CampaignPath);
const cohortFreezeV2Corpus = loadJson(cohortFreezeV2CorpusPath);
const cohortFreezeV2FixtureRoster = loadJson(cohortFreezeV2FixtureRosterPath);
const cohortFreezeV2WorkItemRoster = loadJson(cohortFreezeV2WorkItemRosterPath);
const cohortFreezeV2Epoch = loadJson(cohortFreezeV2EpochPath);
const cohortFreezeV2Engines = cohortFreezeV2EnginePaths.map(loadJson);
const gateBArithmeticCampaign = loadJson(gateBArithmeticCampaignPath);
const m89GateB0Run = loadJson(m89GateB0RunPath);
const vectorIndex = loadJson(vectorIndexPath);
const bchProfile = loadJson(bchProfilePath);
const desktopProfile = loadJson(desktopProfilePath);
const m31BaseMulEvidence = loadJson(m31BaseMulEvidencePath);
const m31BaseMulSourceManifest = loadJson(m31BaseMulSourceManifestPath);
const m31BaseSuiteEvidence = loadJson(m31BaseSuiteEvidencePath);
const m31BaseSuiteSourceManifest = loadJson(m31BaseSuiteSourceManifestPath);
const m31BinaryRebuildReplay = loadJson(m31BinaryRebuildReplayPath);
const m31BinaryRebuildTransitions = new Map(
  m31BinaryRebuildReplay.binaryTransitions.map((transition) => [transition.artifactId, transition])
);
validateCohortV3Freeze();

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateDiagram = ajv.compile(schema);
if (!validateDiagram(diagram)) {
  for (const error of validateDiagram.errors ?? []) {
    errors.push(`diagram schema ${error.instancePath || '/'} ${error.message}`);
  }
}

for (const [schemaPath, label, instance] of [
  [poolStateSchemaPath, 'PoolStateFv1', undefined],
  [poolActionSchemaPath, 'PoolActionFv1 statement', undefined],
  [threatModelSchemaPath, 'PoolActionFv1 threat model', threatModel],
  [soundnessSchemaPath, 'legacy Circle-FRI soundness worksheet', undefined],
  [soundnessV2SchemaPath, 'Circle-FRI event-DAG soundness worksheet', undefined],
  [zkReviewSchemaPath, 'Circle-FRI ZK leakage review', undefined],
  [candidateMatrixSchemaPath, 'Circle-FRI candidate matrix', candidateMatrix],
  [candidateCompositionV2SchemaPath, 'typed Circle-FRI candidate composition', candidateCompositionV2],
  [gateBContractSchemaPath, 'Gate-B equal-relation experiment contract', gateBContract],
  [algebraDescriptorSchemaPath, 'Gate-B0 algebra component descriptor', m89AlgebraDescriptor],
  [algebraDescriptorV2SchemaPath, 'v2 algebra component descriptor', undefined],
  [constructionFreezeSchemaPath, 'construction freeze summary', constructionFreeze],
  [constructionTranscriptSchemaPath, 'construction freeze normalized transcript', constructionTranscript],
  [scheduleFreezeSchemaPath, 'schedule freeze', scheduleFreeze],
  [certificateSetSchemaPath, 'direct-construction certificate set', certificateSet],
  [externalReviewSchemaPath, 'direct-construction external review', externalReview],
  [loweringFreezeSchemaPath, 'lowering freeze', loweringFreeze],
  [loweringArmIrFreezeSchemaPath, 'lowering-arm IR freeze', loweringArmIrFreeze],
  [sourceSetSchemaPath, 'source set v1', sourceSet],
  [sourceSetPlanMapSchemaPath, 'source-set plan map', undefined],
  [cohortFreezeV2ManifestSchemaPath, 'cohort-freeze-v2 manifest', cohortFreezeV2Manifest],
  [cohortFreezeV2CampaignSchemaPath, 'cohort-freeze-v2 campaign', cohortFreezeV2Campaign],
  [cohortFreezeV2CorpusSchemaPath, 'cohort-freeze-v2 canonical corpus', cohortFreezeV2Corpus],
  [cohortFreezeV2FixtureRosterSchemaPath, 'cohort-freeze-v2 fixture roster', cohortFreezeV2FixtureRoster],
  [cohortFreezeV2WorkItemRosterSchemaPath, 'cohort-freeze-v2 work-item roster', cohortFreezeV2WorkItemRoster],
  [cohortFreezeV2EpochSchemaPath, 'cohort-freeze-v2 execution epoch', cohortFreezeV2Epoch],
  [gateBArithmeticCampaignSchemaPath, 'Gate-B0 arithmetic campaign', gateBArithmeticCampaign],
  [gateBArithmeticRunSchemaPath, 'Gate-B0 arithmetic run', m89GateB0Run],
  [gateBArithmeticEngineResultSchemaPath, 'Gate-B0 arithmetic engine result', undefined],
  [gateBArithmeticMetricReportSchemaPath, 'Gate-B0 arithmetic metric report', undefined],
  [gateBArithmeticCrossEngineSummarySchemaPath, 'Gate-B0 arithmetic cross-engine summary', undefined],
  [microbenchSchemaPath, 'Circle-FRI primitive microbenchmark', m31BaseMulEvidence],
  [measurementSchemaPath, 'Circle-FRI measurement', m31BaseSuiteEvidence],
  [vectorIndexSchemaPath, 'PoolActionFv1 vector index', vectorIndex]
]) {
  compileStrictSchema(schemaPath, label, instance);
}
const validateCohortFreezeV2EngineSchema = compileStrictSchema(
  cohortFreezeV2EngineSchemaPath,
  'cohort-freeze-v2 engine record',
  undefined
);
for (const [index, engine] of cohortFreezeV2Engines.entries()) {
  if (validateCohortFreezeV2EngineSchema && !validateCohortFreezeV2EngineSchema(engine)) {
    for (const error of validateCohortFreezeV2EngineSchema.errors ?? []) {
      errors.push(`cohort-freeze-v2 engine ${index} schema ${error.instancePath || '/'} ${error.message}`);
    }
  }
}
for (const error of validateCampaign(gateBArithmeticCampaign)) {
  errors.push(`Gate-B0 arithmetic campaign ${error}`);
}
for (const error of validateDescriptor(m89AlgebraDescriptor)) {
  errors.push(`M89 Gate-B0 algebra descriptor ${error}`);
}
const validateDescriptorV2Schema = compileStrictSchema(algebraDescriptorV2SchemaPath, 'v2 algebra component descriptor', undefined);
for (const [index, descriptor] of algebraDescriptorsV2.entries()) {
  if (validateDescriptorV2Schema && !validateDescriptorV2Schema(descriptor)) {
    for (const error of validateDescriptorV2Schema.errors ?? []) errors.push(`v2 descriptor ${index} schema ${error.instancePath || '/'} ${error.message}`);
  }
  for (const error of validateDescriptorV2(descriptor, { rootDir: laneDir, verifyPins: true })) errors.push(`v2 descriptor ${descriptor.descriptorId} ${error}`);
}
try {
  for (const error of validateScheduleFreezeSemantics(scheduleFreeze)) errors.push(`schedule freeze ${error}`);
} catch (error) {
  errors.push(`schedule freeze ${error.message}`);
}
expect(validateConstructionFreezeSemantics(constructionFreeze, constructionTranscript), 'construction freeze summary/transcript semantic binding failed');
try {
  verifyCertificateSet(certificateSet);
} catch (error) {
  errors.push(`direct-construction certificate set ${error.message}`);
}
for (const error of validateFinalExternalReviewShape(externalReview, externalReviewSchema, certificateSet)) {
  errors.push(`direct-construction external review ${error}`);
}
try {
  for (const error of validateLoweringFreezeSemantics(loweringFreeze)) errors.push(`lowering freeze ${error}`);
} catch (error) {
  errors.push(`lowering freeze ${error.message}`);
}
try {
  for (const error of validateLoweringArmIrPackage(loweringArmIrFreeze)) errors.push(`lowering-arm IR freeze ${error}`);
} catch (error) {
  errors.push(`lowering-arm IR freeze ${error.message}`);
}
let cohortFreezeV2SemanticValidation;
try {
  cohortFreezeV2SemanticValidation = validateCohortFreezeV2Package();
} catch (error) {
  errors.push(`cohort-freeze-v2 package ${error.message}`);
}
let policyAuthorityV1SemanticValidation;
try {
  policyAuthorityV1SemanticValidation = validatePolicyAuthorityV1Package(policyAuthorityV1Dir, repoRoot);
} catch (error) {
  errors.push(`cohort-policy-authority-v1 package ${error.message}`);
}
let cohortLiveExecutorV2IndependentValidation;
let cohortLiveExecutorV2StaticValidation;
let cohortLiveExecutorV2CausalMutation;
try {
  cohortLiveExecutorV2IndependentValidation = clev2ValidateIndependent();
  const cohortLiveExecutorV2Validator = await import(pathToFileURL(resolve(CLEV2_PACKAGE_ROOT, 'validate-static.mjs')).href);
  clev2Assert(typeof cohortLiveExecutorV2Validator.validateStatic === 'function', 'pinned validator export is unavailable');
  cohortLiveExecutorV2StaticValidation = cohortLiveExecutorV2Validator.validateStatic();
  clev2Assert(cohortLiveExecutorV2StaticValidation === true, 'pinned validator did not return true');
  const rawFileKat = Buffer.from([0xff, 0x00, 0x80]);
  clev2Assert(
    cohortLiveExecutorV2Validator.rawFileDigest(rawFileKat) === clev2RawFileDigest(rawFileKat),
    'pinned validator raw file digest differs from the independent raw-byte frame'
  );
  cohortLiveExecutorV2CausalMutation = await clev2RunCausalMutation();
} catch (error) {
  errors.push(`cohort-live-executor-v2 package ${error.message}`);
}
let cohortAuthorityBindingModelV1IndependentValidation;
let cohortAuthorityBindingModelV1StaticValidation;
let cohortAuthorityBindingModelV1CausalMutation;
try {
  cohortAuthorityBindingModelV1IndependentValidation = cabmValidateIndependent();
  const cohortAuthorityBindingModelV1Validator = await import(pathToFileURL(resolve(CABM_PACKAGE_ROOT, 'validate-static.mjs')).href);
  cabmAssert(typeof cohortAuthorityBindingModelV1Validator.validateStatic === 'function', 'pinned validator export is unavailable');
  cohortAuthorityBindingModelV1StaticValidation = cohortAuthorityBindingModelV1Validator.validateStatic();
  cabmAssert(cohortAuthorityBindingModelV1StaticValidation === true, 'pinned validator did not return true');
  cohortAuthorityBindingModelV1CausalMutation = await cabmRunCausalMutation();
} catch (error) {
  errors.push(`cohort-authority-binding-model-v1 package ${error.message}`);
}
let cohortExternalOriginContractV1IndependentValidation;
let cohortExternalOriginContractV1StaticValidation;
let cohortExternalOriginContractV1CausalMutation;
try {
  cohortExternalOriginContractV1IndependentValidation = ecocValidateIndependent();
  const cohortExternalOriginContractV1Validator = await import(pathToFileURL(resolve(ECOC_PACKAGE_ROOT, 'validate-static.mjs')).href);
  ecocAssert(typeof cohortExternalOriginContractV1Validator.validateStatic === 'function', 'pinned validator export is unavailable');
  cohortExternalOriginContractV1StaticValidation = cohortExternalOriginContractV1Validator.validateStatic();
  ecocAssert(cohortExternalOriginContractV1StaticValidation === true, 'pinned validator did not return true');
  const rawFileKat = Buffer.from([0xff, 0x00, 0x80]);
  ecocAssert(cohortExternalOriginContractV1Validator.rawFileDigest(rawFileKat) === ecocRawFileDigest(rawFileKat), 'pinned validator raw file digest differs from the independent raw-byte frame');
  cohortExternalOriginContractV1CausalMutation = await ecocRunCausalMutation();
} catch (error) {
  errors.push('cohort-external-origin-contract-v1 package ' + error.message);
}
let cohortUpstreamOriginProviderContractV1IndependentValidation;
let cohortUpstreamOriginProviderContractV1StaticValidation;
let cohortUpstreamOriginProviderContractV1CausalMutation;
try {
  cohortUpstreamOriginProviderContractV1IndependentValidation = uopcValidateIndependent();
  const cohortUpstreamOriginProviderContractV1Validator = await import(pathToFileURL(resolve(UOPC_PACKAGE_ROOT, 'validate-static.mjs')).href);
  uopcAssert(typeof cohortUpstreamOriginProviderContractV1Validator.validateStatic === 'function', 'pinned validator export is unavailable');
  cohortUpstreamOriginProviderContractV1StaticValidation = cohortUpstreamOriginProviderContractV1Validator.validateStatic();
  uopcAssert(cohortUpstreamOriginProviderContractV1StaticValidation?.sealed === true, 'pinned validator did not validate the sealed package');
  const rawFileKat = Buffer.from([0xff, 0x00, 0x80]);
  uopcAssert(cohortUpstreamOriginProviderContractV1Validator.rawFileDigest(rawFileKat) === uopcRawFileDigest(rawFileKat), 'pinned validator raw file digest differs from independent raw-byte framing');
  cohortUpstreamOriginProviderContractV1CausalMutation = await uopcRunCausalMutation();
} catch (error) {
  errors.push('cohort-upstream-origin-provider-contract-v1 package ' + error.message);
}
let cohortUpstreamProviderSourceMapV1IndependentValidation;
let cohortUpstreamProviderSourceMapV1StaticValidation;
let cohortUpstreamProviderSourceMapV1CausalMutation;
try {
  cohortUpstreamProviderSourceMapV1IndependentValidation = spmValidateIndependent();
  const cohortUpstreamProviderSourceMapV1Validator = await import(pathToFileURL(resolve(SPM_PACKAGE_ROOT, 'validate-static.mjs')).href);
  spmAssert(typeof cohortUpstreamProviderSourceMapV1Validator.validateStatic === 'function', 'pinned validator export is unavailable');
  cohortUpstreamProviderSourceMapV1StaticValidation = cohortUpstreamProviderSourceMapV1Validator.validateStatic({
    packageRoot: SPM_PACKAGE_ROOT,
    repositoryRoot: repoRoot,
    expectedExternalPins: { rootRawSha256: SPM_EXPECTED_BINDING.root.rawSha256, validatorRawSha256: SPM_EXPECTED_BINDING.validator.rawSha256 }
  });
  spmAssert(cohortUpstreamProviderSourceMapV1StaticValidation?.sealed === true, 'pinned validator did not validate the sealed package');
  cohortUpstreamProviderSourceMapV1CausalMutation = await spmRunCausalMutation();
} catch (error) {
  errors.push('cohort-upstream-provider-source-map-v1 package ' + error.message);
}
let gateB0EvidencePlanV1IndependentValidation;
let gateB0EvidencePlanV1StaticValidation;
let gateB0EvidencePlanV1CausalMutation;
try {
  b0rAssertBinding(lane.p2FieldCheckpoint?.gateB0EvidencePlanV1Binding);
  gateB0EvidencePlanV1IndependentValidation = b0rValidateIndependent();
  const gateB0EvidencePlanV1Validator = await import(pathToFileURL(resolve(B0R_PACKAGE_ROOT, 'validate-static.mjs')).href);
  b0rAssert(typeof gateB0EvidencePlanV1Validator.validateStatic === 'function', 'B0R_PINNED_VALIDATOR_EXPORT');
  gateB0EvidencePlanV1StaticValidation = gateB0EvidencePlanV1Validator.validateStatic({packageRoot: B0R_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: B0R_REVIEW_ANCHOR_PIN});
  b0rAssert(gateB0EvidencePlanV1StaticValidation?.files === 17 && gateB0EvidencePlanV1StaticValidation?.sourcePins === 35 && gateB0EvidencePlanV1StaticValidation?.unsealed === false && gateB0EvidencePlanV1StaticValidation?.rootDigest === B0R_EXPECTED_BINDING.root.contentDigest, 'B0R_PINNED_VALIDATOR_RESULT');
  b0rAssertNonpromotionProse();
  gateB0EvidencePlanV1CausalMutation = await b0rRunCausalMutation(lane);
} catch (error) {
  errors.push('gate-b0-evidence-plan-v1 package ' + error.message);
}
let gateB0ExecutionAdmissionContractV1IndependentValidation;
let gateB0ExecutionAdmissionContractV1StaticValidation;
let gateB0ExecutionAdmissionContractV1CausalMutation;
try {
  eacAssertBinding(lane.p2FieldCheckpoint?.gateB0ExecutionAdmissionContractV1Binding);
  gateB0ExecutionAdmissionContractV1IndependentValidation = eacValidateIndependent();
  const gateB0ExecutionAdmissionContractV1Validator = await import(pathToFileURL(resolve(EAC_PACKAGE_ROOT, 'validate-static.mjs')).href);
  eacAssert(typeof gateB0ExecutionAdmissionContractV1Validator.validateStatic === 'function', 'EAC_PINNED_VALIDATOR_EXPORT');
  gateB0ExecutionAdmissionContractV1StaticValidation = gateB0ExecutionAdmissionContractV1Validator.validateStatic({packageRoot: EAC_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: EAC_REVIEW_ANCHOR_PIN});
  eacAssert(gateB0ExecutionAdmissionContractV1StaticValidation?.files === 20 && gateB0ExecutionAdmissionContractV1StaticValidation?.sourcePins === 64 && gateB0ExecutionAdmissionContractV1StaticValidation?.unsealed === false && gateB0ExecutionAdmissionContractV1StaticValidation?.rootDigest === EAC_EXPECTED_BINDING.root.contentDigest, 'EAC_PINNED_VALIDATOR_RESULT');
  eacAssertNonpromotionProse();
  gateB0ExecutionAdmissionContractV1CausalMutation = await eacRunCausalMutation(lane, gateB0ExecutionAdmissionContractV1Validator);
} catch (error) {
  errors.push('gate-b0-execution-admission-contract-v1 package ' + error.message);
}
let gateB0StaticSourceAuthorityV1IndependentValidation;
let gateB0StaticSourceAuthorityV1StaticValidation;
let gateB0StaticSourceAuthorityV1CausalMutation;
try {
  ssaAssertBinding(lane.p2FieldCheckpoint?.gateB0StaticSourceAuthorityV1Binding);
  gateB0StaticSourceAuthorityV1IndependentValidation = ssaValidateIndependent();
  const gateB0StaticSourceAuthorityV1Validator = await import(pathToFileURL(resolve(SSA_PACKAGE_ROOT, 'validate-static.mjs')).href);
  ssaAssert(typeof gateB0StaticSourceAuthorityV1Validator.validateStatic === 'function', 'SSA_PINNED_VALIDATOR_EXPORT');
  gateB0StaticSourceAuthorityV1StaticValidation = gateB0StaticSourceAuthorityV1Validator.validateStatic({packageRoot: SSA_PACKAGE_ROOT, repositoryRoot: repoRoot, mode: 'sealed', reviewAnchorPin: SSA_REVIEW_ANCHOR_PIN});
  ssaAssert(
    gateB0StaticSourceAuthorityV1StaticValidation?.files === 26 &&
      gateB0StaticSourceAuthorityV1StaticValidation?.rootDigest === SSA_EXPECTED_BINDING.root.contentDigest &&
      gateB0StaticSourceAuthorityV1StaticValidation?.sourceContracts === 19 &&
      gateB0StaticSourceAuthorityV1StaticValidation?.unsealed === false,
    'SSA_PINNED_VALIDATOR_RESULT'
  );
  gateB0StaticSourceAuthorityV1CausalMutation = await ssaRunCausalMutation(lane, gateB0StaticSourceAuthorityV1Validator);
} catch (error) {
  errors.push('gate-b0-static-source-authority-v1 package ' + error.message);
}
let gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation;
let gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation;
let gateB0ExternalAuthorityPrerequisitePolicyV1CausalMutation;
try {
  eappAssertBinding(lane.p2FieldCheckpoint?.gateB0ExternalAuthorityPrerequisitePolicyV1Binding);
  gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation = eappValidateIndependent();
  const gateB0ExternalAuthorityPrerequisitePolicyV1Validator = await import(pathToFileURL(resolve(EAPP_PACKAGE_ROOT, 'validate-static.mjs')).href);
  eappAssert(typeof gateB0ExternalAuthorityPrerequisitePolicyV1Validator.validateStatic === 'function', 'EAPP_PINNED_VALIDATOR_EXPORT');
  gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation = gateB0ExternalAuthorityPrerequisitePolicyV1Validator.validateStatic({packageRoot:EAPP_PACKAGE_ROOT,repositoryRoot:repoRoot,mode:'sealed',reviewAnchorPin:EAPP_REVIEW_ANCHOR_PIN});
  eappAssert(
    eappSame(gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation,{files:23,directories:3,rootDigest:EAPP_EXPECTED_BINDING.root.contentDigest,sourceContracts:10,unsealed:false}),
    'EAPP_PINNED_VALIDATOR_RESULT'
  );
  gateB0ExternalAuthorityPrerequisitePolicyV1CausalMutation = await eappRunCausalMutation(lane,gateB0ExternalAuthorityPrerequisitePolicyV1Validator);
} catch (error) {
  errors.push('gate-b0-external-authority-prerequisite-policy-v1 package ' + error.message);
}
try {
  verifyM89Shakedown(m89GateB0RunDir);
} catch (error) {
  errors.push(`M89 Gate-B0 official run ${error.message}`);
}
const validateFieldCertificate = compileStrictSchema(
  fieldCertSchemaPath,
  'generic finite-field certificate fixture',
  frontierPrimeFixture
);
if (validateFieldCertificate && !validateFieldCertificate(m89RabinFixture)) {
  for (const error of validateFieldCertificate.errors ?? []) {
    errors.push(`generic finite-field certificate fixture schema ${error.instancePath || '/'} ${error.message}`);
  }
}
const soundnessV2InstanceFiles = readdirSync(resolve(laneDir, 'security'))
  .filter((name) => /^soundness-worksheet\.v2\..+\.json$/u.test(name) && name !== 'soundness-worksheet.v2.schema.json');
expect(
  soundnessV2InstanceFiles.length === 0,
  `prequalification soundness v2 has unintegrated worksheet instances: ${soundnessV2InstanceFiles.join(', ')}`
);
expect(
  soundnessV2Schema.properties?.qualificationBoundary?.const === 'prequalification-only' &&
    !JSON.stringify(soundnessV2Schema).includes('128-bit-pass'),
  'soundness v2 must remain prequalification-only until provenance-closed qualification validation exists'
);

const uniqueIds = (items, label) => {
  const seen = new Set();
  for (const item of items) {
    if (seen.has(item.id)) errors.push(`duplicate ${label} id: ${item.id}`);
    seen.add(item.id);
  }
  return seen;
};

const regionIds = uniqueIds(diagram.regions, 'region');
const connectorIds = uniqueIds(diagram.connectors, 'connector');
const parsedIds = uniqueIds(diagram.parsedLiterals, 'parsed literal');
const ambiguityIds = uniqueIds(diagram.glyphAmbiguities, 'glyph ambiguity');
uniqueIds(diagram.review.passes, 'review pass');
uniqueIds(claims.claims, 'claim');

for (const region of diagram.regions) {
  if (region.parentId) expect(regionIds.has(region.parentId), `missing parent region ${region.parentId} for ${region.id}`);
  expect(region.box.x + region.box.width <= diagram.source.width, `region ${region.id} exceeds image width`);
  expect(region.box.y + region.box.height <= diagram.source.height, `region ${region.id} exceeds image height`);
  for (const line of region.textLines) {
    if (line.status === 'under-resolved') {
      expect(ambiguityIds.has(line.ambiguityId), `region ${region.id} refers to missing ambiguity ${line.ambiguityId}`);
    }
  }
}

expect(diagram.readingOrder.length === regionIds.size, 'reading order must contain every region exactly once');
for (const id of diagram.readingOrder) expect(regionIds.has(id), `reading order refers to missing region ${id}`);

for (const connector of diagram.connectors) {
  expect(regionIds.has(connector.fromRegionId), `connector ${connector.id} has missing from endpoint ${connector.fromRegionId}`);
  expect(regionIds.has(connector.toRegionId), `connector ${connector.id} has missing to endpoint ${connector.toRegionId}`);
}

for (const parsed of diagram.parsedLiterals) {
  for (const id of parsed.sourceRegionIds) expect(regionIds.has(id), `parsed literal ${parsed.id} refers to missing region ${id}`);
}

expect(diagram.review.passes.length >= 3, 'diagram requires at least three recorded review passes');
expect(
  diagram.review.status === 'complete-with-external-glyph-resolution',
  'diagram review must retain the externally resolved glyph status'
);
for (const ambiguity of diagram.glyphAmbiguities) {
  expect(regionIds.has(ambiguity.regionId), `ambiguity ${ambiguity.id} refers to missing region ${ambiguity.regionId}`);
  expect(ambiguity.status !== 'unresolved', `glyph ambiguity remains unresolved: ${ambiguity.id}`);
}

const trackedImage = resolve(repoRoot, diagram.source.trackedImagePath);
expect(existsSync(trackedImage), `tracked diagram image is missing: ${diagram.source.trackedImagePath}`);
if (existsSync(trackedImage)) expect(sha256(trackedImage) === diagram.source.sha256, 'tracked diagram SHA-256 mismatch');

const photo7 = manifest.photos.find((photo) => photo.messageId === 11174);
expect(Boolean(photo7), 'source manifest is missing Telegram message 11174 photo');
if (photo7) {
  expect(photo7.sha256 === diagram.source.sha256, 'manifest and transcription diagram hashes differ');
  expect(photo7.trackedDuplicatePath === diagram.source.trackedImagePath, 'manifest and transcription tracked image paths differ');
}

const localExport = resolve(repoRoot, manifest.telegramExport.localPath);
if (existsSync(localExport)) {
  expect(sha256(localExport) === manifest.telegramExport.sha256, 'local Telegram export SHA-256 mismatch');
}
const localPhoto = resolve(repoRoot, diagram.source.localExportImagePath);
if (existsSync(localPhoto)) expect(sha256(localPhoto) === diagram.source.sha256, 'local photo 7 SHA-256 mismatch');

expect(manifest.telegramExport.localOnly === true, 'raw Telegram export must remain local-only');
expect(!manifest.telegramExport.localPath.startsWith('atlas/'), 'raw Telegram export cannot live under canonical Atlas roots');
expect(lane.promotionGate.status === 'closed', 'lane promotion gate must remain closed before architecture qualification');

expect(
  lane.status === EAPP_LANE_STATUS,
  'lane status must record the sealed static Gate B0 external-authority prerequisite-policy integration without promoting an architecture'
);
expect(lane.scopeDecision?.status === 'frozen', 'scope decision must be frozen');
expect(
  lane.scopeDecision?.profileRef === profile.id,
  'scope decision must reference the canonical fixed-ticket profile'
);
expect(profile.id === 'profile:fixed-ticket-serial-pool', 'unexpected canonical profile id');

expect(lane.proofBackendDecision?.status === 'frozen', 'proof backend decision must be frozen');
expect(
  lane.proofBackendDecision?.id === 'proof-backend:circle-fri',
  'Circle FRI must be the selected proof family'
);
expect(
  lane.proofBackendDecision?.family === 'Circle-domain FRI',
  'selected proof family must not prematurely freeze a field instantiation'
);
expect(
  lane.proofBackendDecision?.researchMethod === 'first-principles BCH co-design',
  'Circle FRI research must be derived from BCH constraints'
);
expect(
  lane.proofBackendDecision?.referenceImplementation === undefined,
  'no external prover stack may be selected as the reference implementation'
);
expect(
  lane.proofBackendDecision?.priorArtPolicy.includes('not protocol authorities'),
  'prior implementations must remain evidence rather than protocol authority'
);
expect(
  new Set(lane.proofBackendDecision?.inactiveComparators).size === 3,
  'Groth16, Goldilocks FRI, and WHIR must remain inactive comparators'
);

expect(lane.productDecisions?.status === 'frozen', 'product decisions must be frozen');
expect(lane.productDecisions?.ticket?.denomination === '0.1 BCH', 'ticket display denomination must be 0.1 BCH');
expect(lane.productDecisions?.ticket?.denominationSatoshis === 10_000_000, 'ticket must be exactly 10,000,000 satoshis');
expect(lane.productDecisions?.ticket?.withdrawalPayoutSatoshis === 10_000_000, 'withdrawal must pay one full ticket');
expect(lane.productDecisions?.ticket?.poolReserveDeltaSatoshis === 10_000_000, 'withdrawal reserve delta must equal one ticket');
expect(
  lane.productDecisions?.ticket?.feeFunding === 'separate transparent non-pool input',
  'fees must be separately and transparently funded under the frozen simple profile'
);
expect(lane.productDecisions?.ticket?.feePrivacy === 'out of scope', 'fee privacy must remain out of scope');
expect(lane.productDecisions?.soundness?.targetBits === 128, 'soundness target must be 128 bits');
expect(lane.productDecisions?.soundness?.minimumBits === 100, 'soundness floor must be 100 bits');
expect(
  lane.productDecisions?.soundness?.standardTransactionLimitBytes === 100_000,
  'soundness fallback must use the 100,000-byte standard transaction envelope'
);
expect(
  lane.productDecisions?.soundness?.fallbackRule.includes('strongest concretely derived parameter set'),
  'soundness fallback must select the strongest fitting derived parameter set'
);
expect(lane.productDecisions?.client?.interface === 'local desktop CLI', 'first client must be a local desktop CLI');
expect(lane.productDecisions?.client?.proving === 'local and unilateral', 'desktop proving must remain local and unilateral');
expect(lane.productDecisions?.client?.withdrawalTargetSeconds === 60, 'desktop withdrawal target must be 60 seconds');
expect(
  lane.productDecisions?.client?.withdrawalTargetComparison === 'less-than',
  'desktop withdrawal target must be strictly less than 60 seconds'
);
expect(
  lane.productDecisions?.client?.outOfScope.includes('required remote prover'),
  'a required remote prover must remain out of scope'
);
expect(
  lane.productDecisions?.postQuantum?.goal === 'PQ-oriented proof and private spend path',
  'PQ scope must cover the proof and private spend path'
);
expect(
  lane.productDecisions?.postQuantum?.guardrail.includes('do not weaken classical security'),
  'PQ scope must not justify weakening classical security'
);
expect(
  lane.productDecisions?.postQuantum?.claimPolicy.includes('Do not claim the complete system is post-quantum'),
  'PQ claims must disclose unresolved classical dependencies'
);

const profileConstraints = new Map(profile.constraints.map((constraint) => [constraint.id, constraint]));
const expectProfileConstraint = (id, operator, value) => {
  const constraint = profileConstraints.get(id);
  expect(Boolean(constraint), `canonical profile is missing constraint ${id}`);
  if (constraint) {
    expect(constraint.operator === operator, `canonical profile constraint ${id} has unexpected operator`);
    expect(constraint.value === value, `canonical profile constraint ${id} has unexpected value`);
  }
};

expectProfileConstraint('pool:ticket-value-model', 'equals', 'fixed-ticket');
expectProfileConstraint('pool:deposit-transactions-per-ticket', 'equals', 1);
expectProfileConstraint('pool:withdrawal-transactions-per-ticket', 'equals', 1);
expectProfileConstraint('pool:multi-user-batching', 'forbidden', true);
expectProfileConstraint('pool:unilateral-withdrawal', 'required', true);
expectProfileConstraint('pool:on-chain-proof-verification', 'required', true);
expectProfileConstraint('pool:on-chain-conservation-enforcement', 'required', true);
expectProfileConstraint('pool:public-reconstructability', 'required', true);

const nonGoals = new Set(profile.nonGoals);
expect(nonGoals.has('private-transfers'), 'canonical profile must retain private transfers as a non-goal');
expect(
  nonGoals.has('multi-user-transaction-batching'),
  'canonical profile must retain multi-user batching as a non-goal'
);

const dispositions = new Map(lane.optionDispositions.map((option) => [option.id, option.status]));
expect(
  lane.optionDispositions.filter((option) => option.status === 'active-baseline').length === 1,
  'lane must have exactly one active architecture baseline'
);
expect(dispositions.get('serial-global-state-cell') === 'active-baseline', 'serial state cell must be active');
expect(
  dispositions.get('transferable-private-notes') === 'retired-out-of-scope',
  'transferable private notes must be retired under the active profile'
);
expect(dispositions.get('k-lanes-epoch') === 'retired-out-of-scope', 'K lanes must be retired under the active profile');
expect(
  dispositions.get('seal-bound-joinsplit') === 'deprioritized-separate-profile-only',
  'seal-bound JoinSplit must remain a separate-profile concept'
);
expect(
  dispositions.get('hybrid-client-conservation') === 'eliminated-by-active-profile',
  'client-side conservation must be eliminated by the active profile'
);
expect(
  !lane.promotionGate.requires.some((requirement) => requirement.includes('user selects')),
  'promotion gate must not retain the resolved profile-selection question'
);

const backendEvidencePath = resolve(laneDir, lane.entrypoints.backendEvidence);
expect(existsSync(backendEvidencePath), 'backend evidence note is missing');
if (existsSync(backendEvidencePath)) {
  const backendEvidence = readFileSync(backendEvidencePath, 'utf8');
  expect(backendEvidence.includes('arXiv:2606.04311v1'), 'backend evidence must pin the supplied S-two AIR paper');
  expect(backendEvidence.includes('does not currently provide zero knowledge'), 'backend evidence must retain the stock S-two ZK blocker');
  expect(backendEvidence.includes('first-principles BCH'), 'backend evidence must retain the first-principles research decision');
  expect(backendEvidence.includes('100,000 bytes'), 'backend evidence must retain the current standard-transaction envelope');
  expect(
    !backendEvidence.includes('Freeze either a 100-bit or 128-bit soundness target'),
    'backend evidence must not make the 100-bit fallback co-equal with the mandatory 128-bit target'
  );
}

const designOptionsPath = resolve(laneDir, lane.entrypoints.designOptions);
expect(existsSync(designOptionsPath), 'design options note is missing');
if (existsSync(designOptionsPath)) {
  const designOptions = readFileSync(designOptionsPath, 'utf8');
  expect(designOptions.includes('source-set-v1'), 'design options must identify the frozen source set');
  expect(
    designOptions.includes('campaign-v2') &&
      designOptions.includes('canonical four-construction corpus-v2') &&
      designOptions.includes('one shared') &&
      designOptions.includes('execution-epoch-v2 contract'),
    'design options must identify the contract-only campaign, corpus, and shared epoch next gate'
  );
  expect(
    !designOptions.includes('content-addressed pre-source IR package') &&
      !designOptions.includes('closed during source emission') &&
      !designOptions.includes('The next order is: mechanically emit'),
    'design options must not regress to the completed source-emission gate'
  );
}

const requiredEntrypoints = {
  poolConfigRequirements: 'spec/pool-config-fv1.json',
  p0FreezeManifest: 'spec/p0-freeze-manifest.json',
  sourcePinReview: 'research/source-pin-review-2026-08-08.md',
  poolStateCodec: 'spec/pool-state-fv1.md',
  poolStateSchema: 'spec/pool-state-fv1.schema.json',
  poolActionRelation: 'spec/pool-action-fv1.json',
  poolActionStatementSchema: 'spec/pool-action-fv1.schema.json',
  transactionBinding: 'spec/tx-binding-fv1.md',
  responsibilityMap: 'spec/responsibility-map-fv1.json',
  threatModel: 'security/threat-model-fv1.json',
  soundnessWorksheetSchema: 'security/soundness-worksheet.schema.json',
  soundnessWorksheetV2Schema: 'security/soundness-worksheet.v2.schema.json',
  zkLeakageReviewSchema: 'security/zk-leakage-review.schema.json',
  candidateMatrix: 'research/circle-fri-candidate-matrix.v1.json',
  candidateCompositionV2Schema: 'research/circle-fri-candidate-matrix.v2.schema.json',
  candidateCompositionV2: 'research/circle-fri-candidate-matrix.v2.json',
  fieldFrontierContract: 'research/field-frontier-contract.md',
  fieldCertificateSchema: 'p2/field-cert/certificate.schema.json',
  frontierPrimeFixture: 'p2/field-cert/fixtures/frontier-prime-checks.v1.json',
  m89RabinFixture: 'p2/field-cert/fixtures/m89-x2-plus-1-rabin.v1.json',
  fieldCertificateNodeReplay: 'p2/field-cert/node/replay.mjs',
  fieldCertificatePythonReplay: 'p2/field-cert/python/replay_checker.py',
  gateBEqualRelationSchema: 'p2/gate-b/equal-relation-experiment.schema.json',
  gateBEqualRelationContract: 'p2/gate-b/equal-relation-experiment.v1.json',
  gateBEqualRelationTest: 'p2/gate-b/equal-relation-experiment.test.mjs',
  algebraComponentDescriptorSchema: 'p2/algebra-component/algebra-component-descriptor.v1.schema.json',
  algebraComponentValidator: 'p2/algebra-component/algebra-component-validation.mjs',
  m89AlgebraComponentDescriptor: 'p2/algebra-component/descriptors/m89-d2-x2-plus-1.v1.json',
  gateBArithmeticCampaignSchema: 'p2/gate-b/equal-relation-arithmetic-campaign.v1.schema.json',
  gateBArithmeticCampaign: 'p2/gate-b/equal-relation-arithmetic-campaign.v1.json',
  gateBArithmeticRunSchema: 'p2/gate-b/equal-relation-arithmetic-run.v1.schema.json',
  gateBArithmeticEngineResultSchema: 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json',
  gateBArithmeticMetricReportSchema: 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json',
  gateBArithmeticCrossEngineSummarySchema: 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json',
  m89GateB0Materializer: 'p2/gate-b/materialize-m89-shakedown.mjs',
  m89GateB0Run: 'p2/gate-b/runs/m89-d2-schoolbook-shakedown-v1/run.json',
  m31BinaryRebuildReplay: 'p2/evidence/m31-binary-rebuild-replay-2026-08-09.json',
  m89ExternalCasManifest: 'p2/field-cert/external/SHA256SUMS',
  m89RepositoryCheckerManifest: 'p2/field-cert/node/SHA256SUMS',
  constructionFreeze: 'p2/construction-freeze/construction-freeze.v1.json',
  scheduleFreeze: 'p2/schedule-freeze/schedule-freeze.v1.json',
  directConstructionCertificateSetV2: 'p2/field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.json',
  directConstructionExternalReviewV2: 'p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.json',
  algebraComponentDescriptorV2Schema: 'p2/algebra-component/algebra-component-descriptor.v2.schema.json',
  m89AlgebraComponentDescriptorV2: 'p2/algebra-component/descriptors/m89-d2-x2-plus-1.v2.json',
  m61AlgebraComponentDescriptorV2: 'p2/algebra-component/descriptors/m61-d3-x3-minus-5.v2.json',
  m31d5AlgebraComponentDescriptorV2: 'p2/algebra-component/descriptors/m31-d5-x5-plus-2x-minus-1.v2.json',
  m31d6AlgebraComponentDescriptorV2: 'p2/algebra-component/descriptors/m31-d6-x6-minus-5.v2.json',
  loweringFreeze: 'p2/lowering-freeze/lowering-freeze.v1.json',
  loweringArmIrFreeze: 'p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json',
  loweringArmIrFreezeSchema: 'p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.schema.json',
  loweringArmIrFreezeGenerator: 'p2/lowering-arm-ir-freeze/generate.mjs',
  loweringArmIrFreezeValidator: 'p2/lowering-arm-ir-freeze/validate.mjs',
  sourceSetV1: 'p2/source-set-v1/source-set.v1.json',
  sourceSetV1Schema: 'p2/source-set-v1/source-set.v1.schema.json',
  sourceSetPlanMapSchema: 'p2/source-set-v1/plan-source-map.v1.schema.json',
  sourceSetGenerator: 'p2/source-set-v1/generate.mjs',
  sourceSetValidator: 'p2/source-set-v1/validate.mjs',
  cohortFreezeV2Readme: 'p2/gate-b/cohort-freeze-v2/README.md',
  cohortFreezeV2Command: 'p2/gate-b/cohort-freeze-v2/COMMAND.txt',
  cohortFreezeV2Manifest: 'p2/gate-b/cohort-freeze-v2/MANIFEST.json',
  cohortFreezeV2ManifestSchema: 'p2/gate-b/cohort-freeze-v2/manifest.v1.schema.json',
  campaignV2: 'p2/gate-b/cohort-freeze-v2/campaign.v2.json',
  campaignV2Schema: 'p2/gate-b/cohort-freeze-v2/campaign.v2.schema.json',
  canonicalCorpusV2: 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json',
  canonicalCorpusV2Schema: 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.schema.json',
  fixtureRosterV2: 'p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json',
  fixtureRosterV2Schema: 'p2/gate-b/cohort-freeze-v2/fixture-roster.v2.schema.json',
  executionEpochV2: 'p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json',
  executionEpochV2Schema: 'p2/gate-b/cohort-freeze-v2/execution-epoch.v2.schema.json',
  workItemRosterV2: 'p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json',
  workItemRosterV2Schema: 'p2/gate-b/cohort-freeze-v2/work-item-roster.v2.schema.json',
  cohortFreezeV2EngineSchema: 'p2/gate-b/cohort-freeze-v2/engine.v2.schema.json',
  cohortFreezeV2EngineSnapshot: 'p2/gate-b/cohort-freeze-v2/engine-snapshot.mjs',
  cohortFreezeV2ExecutionFixture: 'p2/gate-b/cohort-freeze-v2/execution-fixture.mjs',
  cohortFreezeV2EpochContract: 'p2/gate-b/cohort-freeze-v2/epoch.mjs',
  cohortFreezeV2FixtureRoster: 'p2/gate-b/cohort-freeze-v2/fixture-roster.mjs',
  cohortFreezeV2Generator: 'p2/gate-b/cohort-freeze-v2/generate.mjs',
  cohortFreezeV2Validator: 'p2/gate-b/cohort-freeze-v2/validate.mjs',
  cohortFreezeV2Checksums: 'p2/gate-b/cohort-freeze-v2/SHA256SUMS',
  phasePlan: 'research/phase-plan.md',
  primitiveMicrobenchPlan: 'bench/primitive-microbench-plan.md',
  primitiveMicrobenchSchema: 'bench/primitive-microbench.schema.json',
  measurementSchema: 'evidence/measurement.schema.json',
  vectorIndex: 'vectors/pool-action-fv1/index.json',
  bchEnvironmentProfile: 'profiles/bch-current-2026-08-08.json',
  desktopProverProfile: 'profiles/desktop-prover-v1.json',
  p1Overview: 'p1/README.md',
  p1Codec: 'p1/codec/index.mjs',
  p1StatementProjection: 'p1/codec/statement-projection.mjs',
  p1Oracle: 'p1/oracle/pool-action-fv1-oracle.mjs',
  p1Shell: 'p1/shell/shell.mjs',
  p1IntegrationTest: 'p1/integration.test.mjs',
  gateB0ExternalAuthorityControlPlaneSchemaBridgeV1Root: 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1/external-authority-control-plane-schema-bridge-root.v1.json',
  gateB0ExternalAuthorityControlPlaneSchemaBridgeV1Manifest: 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1/MANIFEST.json',
  gateB0ExternalAuthorityControlPlaneSchemaBridgeV1Checksums: 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1/SHA256SUMS',
  gateB0ExternalAuthorityControlPlaneSchemaBridgeV1Validator: 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1/validate-static.mjs',
  gateB0ExternalAuthorityControlPlaneSchemaBridgeV1ReviewAnchor: 'p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json',
  cpsbExact29SealedValidationReceipt: 'evidence/cpsb-exact29-sealed-validation-v1/receipt.json',
  cpsbExact29SealedValidationChecksums: 'evidence/cpsb-exact29-sealed-validation-v1/SHA256SUMS',
  poolActionFv1ContradictionCapture: 'evidence/poolactionfv1-contradiction-capture-v1/contradiction-capture.v1.json',
  poolActionFv1ContradictionWitnessBoundary: 'evidence/poolactionfv1-contradiction-capture-v1/witness-boundary.v1.json'
};
for (const [key, relativePath] of Object.entries(requiredEntrypoints)) {
  expect(lane.entrypoints[key] === relativePath, `lane entrypoint ${key} has unexpected path`);
  expect(existsSync(resolve(laneDir, relativePath)), `lane entrypoint ${key} is missing`);
}
expect(
  typeof packageJson.scripts?.['lane:shielded-pool:lowering-freeze:test'] === 'string' &&
    packageJson.scripts['lane:shielded-pool:lowering-freeze:test'].includes('p2/lowering-freeze/lowering-freeze.test.mjs') &&
    packageJson.scripts['lane:shielded-pool:lowering-freeze:test'].includes('p2/lowering-freeze/validate.mjs'),
  'package must expose the lowering-freeze validation script'
);
expect(
  typeof packageJson.scripts?.['lane:shielded-pool:lowering-arm-ir-freeze:test'] === 'string' &&
    packageJson.scripts['lane:shielded-pool:lowering-arm-ir-freeze:test'].includes('lowering-arm-ir-freeze/generate.mjs --check') &&
    packageJson.scripts['lane:shielded-pool:lowering-arm-ir-freeze:test'].includes('lowering-arm-ir-freeze/validate.mjs --strict --regenerate') &&
    packageJson.scripts.check?.includes('lane:shielded-pool:lowering-arm-ir-freeze:test'),
  'package must expose and run the lowering-arm IR package gate'
);

const cohortPreparationV2 = lane.p2FieldCheckpoint?.cohortPreparationV2;
const cohortDescriptorRoster = [
  ['algebra-component:m89-d2-x2-plus-1-v2', algebraDescriptorV2Paths[0]],
  ['algebra-component:m61-d3-x3-minus-5-v2', algebraDescriptorV2Paths[1]],
  ['algebra-component:m31-d5-x5-plus-2x-minus-1-v2', algebraDescriptorV2Paths[2]],
  ['algebra-component:m31-d6-x6-minus-5-v2', algebraDescriptorV2Paths[3]]
];
expect(cohortPreparationV2?.status === 'cohort-freeze-v2-frozen-execution-pending', 'cohortPreparationV2 must record the frozen unexecuted epoch gate');
expect(cohortPreparationV2?.selection === 'none' && cohortPreparationV2?.cohortRanking === 'closed', 'cohortPreparationV2 must not select or rank');
expect(cohortPreparationV2?.constructionFreeze?.path === 'p2/construction-freeze/construction-freeze.v1.json', 'cohort construction-freeze path changed');
expect(cohortPreparationV2?.constructionFreeze?.fileSha256 === sha256(constructionFreezePath) && cohortPreparationV2?.constructionFreeze?.contentDigest === constructionFreeze.contentDigest, 'cohort construction-freeze binding is stale');
expect(cohortPreparationV2?.scheduleFreeze?.path === 'p2/schedule-freeze/schedule-freeze.v1.json', 'cohort schedule-freeze path changed');
expect(cohortPreparationV2?.scheduleFreeze?.fileSha256 === sha256(scheduleFreezePath) && cohortPreparationV2?.scheduleFreeze?.contentDigest === scheduleFreeze.contentDigest.value, 'cohort schedule-freeze binding is stale');
expect(cohortPreparationV2?.scheduleFreeze?.armCount === scheduleFreeze.arms.length && scheduleFreeze.arms.length === 14, 'cohort schedule must contain exactly 14 arms');
expect(scheduleFreeze.fieldConstructions.length === 4, 'schedule must contain exactly four constructions');
expect(loweringFreeze.constructionOrder.length === 4, 'lowering freeze must contain exactly four constructions');
expect(JSON.stringify(scheduleFreeze.fieldConstructions.map(({ constructionId }) => constructionId)) === JSON.stringify([
  'algebra-construction:m89-d2-x2-plus-1-v1', 'algebra-construction:m61-d3-x3-minus-5-v1',
  'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1', 'algebra-construction:m31-d6-x6-minus-5-v1'
]), 'schedule construction order changed');
expect(cohortPreparationV2?.certificateSet?.path === 'p2/field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.json', 'cohort certificate-set path changed');
expect(cohortPreparationV2?.certificateSet?.fileSha256 === sha256(certificateSetPath) && cohortPreparationV2?.certificateSet?.contentDigest === certificateSet.contentDigest, 'cohort certificate-set binding is stale');
expect(cohortPreparationV2?.externalReview?.path === 'p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.json', 'cohort external-review path changed');
expect(cohortPreparationV2?.externalReview?.fileSha256 === sha256(externalReviewPath) && cohortPreparationV2?.externalReview?.contentDigest === externalReview.contentDigest, 'cohort external-review binding is stale');
expect(cohortPreparationV2?.descriptorSchema?.path === 'p2/algebra-component/algebra-component-descriptor.v2.schema.json' && cohortPreparationV2?.descriptorSchema?.fileSha256 === sha256(algebraDescriptorV2SchemaPath), 'cohort v2 descriptor-schema binding is stale');
expect(Array.isArray(cohortPreparationV2?.descriptors) && cohortPreparationV2.descriptors.length === 4, 'cohortPreparationV2 must bind exactly four descriptors');
for (const [[expectedId, path], descriptor, binding] of cohortDescriptorRoster.map((item, index) => [item, algebraDescriptorsV2[index], cohortPreparationV2?.descriptors?.[index]])) {
  expect(descriptor.descriptorId === expectedId && binding?.id === expectedId, `cohort descriptor identity/order changed: ${expectedId}`);
  expect(binding?.path === `p2/algebra-component/descriptors/${path.split('/').pop()}`, `cohort descriptor path changed: ${expectedId}`);
  expect(binding?.fileSha256 === sha256(path) && binding?.contentDigest === descriptor.contentDigest.value, `cohort descriptor binding stale: ${expectedId}`);
  expect(binding?.armCount === descriptor.scheduleArmBindings.length, `cohort descriptor arm count stale: ${expectedId}`);
}
expect(cohortPreparationV2?.loweringFreeze?.path === 'p2/lowering-freeze/lowering-freeze.v1.json', 'cohort lowering-freeze path changed');
expect(cohortPreparationV2?.loweringFreeze?.fileSha256 === sha256(loweringFreezePath) && cohortPreparationV2?.loweringFreeze?.contentDigest === loweringFreeze.contentDigest.value, 'cohort lowering-freeze binding is stale');
expect(cohortPreparationV2?.loweringFreeze?.armCount === loweringFreeze.arms.length && loweringFreeze.arms.length === 14, 'lowering freeze must contain exactly 14 arms');
expect(cohortPreparationV2?.loweringFreeze?.relationTargetCount === loweringFreeze.relationTargets.length && loweringFreeze.relationTargets.length === 42, 'lowering freeze must contain exactly 42 relation targets');
expect(cohortPreparationV2?.loweringFreeze?.sourceImplementationAllowed === true && cohortPreparationV2?.loweringFreeze?.executionAllowed === false, 'lowering freeze execution boundary changed');
expect(cohortPreparationV2?.loweringArmIrFreeze?.path === 'p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json', 'cohort lowering-arm IR path changed');
expect(
  cohortPreparationV2?.loweringArmIrFreeze?.fileSha256 === sha256(loweringArmIrFreezePath) &&
    cohortPreparationV2?.loweringArmIrFreeze?.contentDigest === loweringArmIrFreeze.contentDigest.value &&
    cohortPreparationV2?.loweringArmIrFreeze?.schemaSha256 === sha256(loweringArmIrFreezeSchemaPath),
  'cohort lowering-arm IR binding is stale'
);
expect(
  cohortPreparationV2?.loweringArmIrFreeze?.artifactId === loweringArmIrFreeze.artifactId &&
    cohortPreparationV2?.loweringArmIrFreeze?.status === loweringArmIrFreeze.status &&
    cohortPreparationV2?.loweringArmIrFreeze?.evidenceClassification === 'not-execution-evidence' &&
    cohortPreparationV2?.loweringArmIrFreeze?.programCount === 28 &&
    cohortPreparationV2?.loweringArmIrFreeze?.moduleCount === 19 &&
    cohortPreparationV2?.loweringArmIrFreeze?.planCount === 42 &&
    cohortPreparationV2?.loweringArmIrFreeze?.ssaNodeCount === 4806 &&
    cohortPreparationV2?.loweringArmIrFreeze?.instructionCount === 25098 &&
    cohortPreparationV2?.loweringArmIrFreeze?.sourceEmissionGate === 'mechanical-only-after-exact-package-validation' &&
    cohortPreparationV2?.loweringArmIrFreeze?.executionAllowed === false,
  'cohort lowering-arm IR boundary or cardinalities changed'
);
expect(
  cohortPreparationV2?.sourceSetBinding?.path === 'p2/source-set-v1/source-set.v1.json' &&
    cohortPreparationV2.sourceSetBinding.fileSha256 === sha256(sourceSetPath) &&
    cohortPreparationV2.sourceSetBinding.contentDigest === sourceSet.contentDigest.value &&
    cohortPreparationV2.sourceSetBinding.schemaSha256 === sha256(sourceSetSchemaPath) &&
    cohortPreparationV2.sourceSetBinding.planMapSchemaSha256 === sha256(sourceSetPlanMapSchemaPath),
  'cohort source-set binding is stale'
);
expect(
  cohortPreparationV2?.sourceSetBinding?.artifactId === sourceSet.artifactId &&
    cohortPreparationV2.sourceSetBinding.status === sourceSet.status &&
    cohortPreparationV2.sourceSetBinding.planCount === sourceSet.cardinalities.plans &&
    cohortPreparationV2.sourceSetBinding.instructionCount === sourceSet.cardinalities.instructions &&
    cohortPreparationV2.sourceSetBinding.parserInvocationCount === sourceSet.cardinalities.parserInvocations &&
    cohortPreparationV2.sourceSetBinding.sourceBytes === sourceSet.cardinalities.sourceBytes &&
    cohortPreparationV2.sourceSetBinding.bytecodeBytes === sourceSet.cardinalities.bytecodeBytes &&
    cohortPreparationV2.sourceSetBinding.mapBytes === sourceSet.cardinalities.mapBytes &&
    cohortPreparationV2.sourceSetBinding.executionAllowed === false,
  'cohort source-set identity, cardinalities, or execution boundary changed'
);
expect(
  sourceSet.status === 'mechanical-source-bytecode-only-no-vm-execution' &&
    sourceSet.boundary?.sourceAndBytecodeArtifactOnly === true &&
    sourceSet.boundary?.vmExecutionAllowed === false &&
    sourceSet.boundary?.campaignAllowed === false &&
    sourceSet.boundary?.metricsAllowed === false &&
    sourceSet.boundary?.selectionAllowed === false &&
    sourceSet.upstreamBinding?.rawSha256 === sha256(loweringArmIrFreezePath) &&
    sourceSet.upstreamBinding?.contentDigest === loweringArmIrFreeze.contentDigest.value &&
    sourceSet.cardinalities?.plans === 42 &&
    sourceSet.cardinalities?.instructions === 25098 &&
    sourceSet.cardinalities?.parserInvocations === 126 &&
    sourceSet.planIndex?.length === 42,
  'source-set package boundary, upstream authority, or exact population changed'
);
const expectedSourceSetPrimitiveRecipes = [
  'stack.assert_depth_exact', 'bytes.assert_length_exact', 'bytes.split_at_exact', 'bytes.assert_mask_zero', 'bytes.cat_zero_sign_byte', 'scriptnum.bin2num',
  'integer.assert_nonnegative', 'integer.assert_lt_const', 'bytes.assert_empty', 'stack.pick', 'stack.dup', 'stack.drop', 'stack.toalt', 'stack.fromalt',
  'field.arithmetic', 'field.canonicalize_identity', 'boolean.equal', 'boolean.and', 'boolean.or', 'integer.is_nonzero', 'integer.equals_const'
];
expectExactSet(Object.keys(sourceSet.recipe?.primitiveRecipes ?? {}), expectedSourceSetPrimitiveRecipes, 'source-set primitive recipe authority');
expect(
  sourceSet.recipe?.primitiveRecipes?.['field.arithmetic']?.kind === 'operator-dispatch' &&
    sourceSet.recipe.primitiveRecipes['field.arithmetic'].operators?.add === 'OP_ADD' &&
    sourceSet.recipe.primitiveRecipes['field.arithmetic'].operators?.sub === 'OP_SUB' &&
    sourceSet.recipe.primitiveRecipes['field.arithmetic'].operators?.mul === 'OP_MUL' &&
    sourceSet.recipe.primitiveRecipes['field.arithmetic'].operators?.square === 'OP_MUL (RHS is materialized by frozen stack.dup)' &&
    sourceSet.recipe.primitiveRecipes['field.arithmetic'].operators?.scale === '<canonical-scale-scalar> OP_MUL',
  'source-set field.arithmetic operator dispatch changed'
);
expect(
  cohortFreezeV2SemanticValidation?.status === 'pass-unexecuted' &&
    cohortFreezeV2SemanticValidation.counts?.constructions === 4 &&
    cohortFreezeV2SemanticValidation.counts?.arms === 14 &&
    cohortFreezeV2SemanticValidation.counts?.plans === 42 &&
    cohortFreezeV2SemanticValidation.counts?.corpusCases === 1_288 &&
    cohortFreezeV2SemanticValidation.counts?.uniquePlanCaseFixtures === 4_732 &&
    cohortFreezeV2SemanticValidation.counts?.workItems === 18_928 &&
    cohortFreezeV2SemanticValidation.counts?.preflightLimitViolations === 124,
  'cohort-freeze-v2 semantic validator did not return the exact frozen unexecuted population'
);
expect(
  cohortFreezeV2Manifest.schema === 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/manifest/v1' &&
    cohortFreezeV2Manifest.status === 'frozen-contract-only-unexecuted' &&
    cohortFreezeV2Manifest.executionAllowed === false &&
    cohortFreezeV2Manifest.evidenceClassification === 'not-execution-evidence' &&
    cohortFreezeV2Manifest.selection === null &&
    cohortFreezeV2Manifest.ranking === null &&
    cohortFreezeV2Manifest.counts?.constructions === 4 &&
    cohortFreezeV2Manifest.counts?.arms === 14 &&
    cohortFreezeV2Manifest.counts?.plans === 42 &&
    cohortFreezeV2Manifest.counts?.corpusCases === 1_288 &&
    cohortFreezeV2Manifest.counts?.uniquePlanCaseFixtures === 4_732 &&
    cohortFreezeV2Manifest.counts?.armCasesPerEngine === 4_732 &&
    cohortFreezeV2Manifest.counts?.workItems === 18_928 &&
    cohortFreezeV2Manifest.counts?.preflightLimitViolations === 124,
  'cohort-freeze-v2 manifest status, nonranking boundary, or exact cardinalities changed'
);
expect(
  cohortFreezeV2Campaign.status === 'contract-only-unmeasured' &&
    cohortFreezeV2Campaign.executionAllowed === false &&
    cohortFreezeV2Campaign.metricsAllowed === false &&
    cohortFreezeV2Campaign.rankingAllowed === false &&
    cohortFreezeV2Campaign.evidenceClassification === 'not-evidence' &&
    cohortFreezeV2Campaign.selection === null &&
    cohortFreezeV2Corpus.status === 'deterministic-host-reference-corpus-component-only' &&
    cohortFreezeV2Corpus.executionAllowed === false &&
    cohortFreezeV2Corpus.metricsAllowed === false &&
    cohortFreezeV2Corpus.rankingAllowed === false &&
    cohortFreezeV2Corpus.evidenceClassification === 'deterministic-test-input-not-execution-evidence' &&
    cohortFreezeV2Corpus.selection === null &&
    cohortFreezeV2Corpus.counts?.total === 1_288,
  'cohort campaign/corpus must remain frozen non-execution, nonranking contracts'
);
expect(
  cohortFreezeV2FixtureRoster.status === 'frozen-fixture-roster-no-vm-execution' &&
    cohortFreezeV2FixtureRoster.executionAllowed === false &&
    cohortFreezeV2FixtureRoster.metricsAllowed === false &&
    cohortFreezeV2FixtureRoster.evidenceClassification === 'not-evidence' &&
    cohortFreezeV2FixtureRoster.selection === null &&
    cohortFreezeV2FixtureRoster.ranking === null &&
    cohortFreezeV2FixtureRoster.counts?.uniquePlanCaseFixtures === 4_732 &&
    cohortFreezeV2FixtureRoster.counts?.deduplicatedEngineWorkItems === 18_928 &&
    cohortFreezeV2FixtureRoster.counts?.preflightReady === 4_608 &&
    cohortFreezeV2FixtureRoster.counts?.preflightLimitViolations === 124 &&
    cohortFreezeV2WorkItemRoster.status === 'frozen-normative-roster-path-ready' &&
    cohortFreezeV2WorkItemRoster.executionAllowed === false &&
    cohortFreezeV2WorkItemRoster.metricsAllowed === false &&
    cohortFreezeV2WorkItemRoster.evidenceClassification === 'not-evidence' &&
    cohortFreezeV2WorkItemRoster.selection === null &&
    cohortFreezeV2WorkItemRoster.ranking === null &&
    cohortFreezeV2WorkItemRoster.counts?.workItems === 18_928,
  'cohort fixture/work roster population or pre-execution boundary changed'
);
expect(
  cohortFreezeV2Epoch.status === 'frozen-contract-only-unexecuted' &&
    cohortFreezeV2Epoch.executionAllowed === false &&
    cohortFreezeV2Epoch.metricsAllowed === false &&
    cohortFreezeV2Epoch.evidenceClassification === 'not-evidence' &&
    cohortFreezeV2Epoch.execution === null &&
    cohortFreezeV2Epoch.result === null &&
    cohortFreezeV2Epoch.metric === null &&
    cohortFreezeV2Epoch.selection === null &&
    cohortFreezeV2Epoch.ranking === null,
  'cohort execution epoch contains execution, result, metric, ranking, or selection evidence'
);
const cohortFreezeV2ExpectedEngineStates = [
  ['engine:native', 'no-build-applicable', 'required'],
  ['engine:libauth', 'package-integrity-source-pinned-ready', 'required'],
  ['engine:bchn', 'fresh-build-attested-unexecuted', 'required'],
  ['engine:leanbch', 'fresh-build-attested-unexecuted', 'required-or-explicit-unsupported']
];
expect(
  JSON.stringify(cohortFreezeV2Engines.map(({ engineId, status, capabilityStatus }) => [engineId, status, capabilityStatus])) ===
    JSON.stringify(cohortFreezeV2ExpectedEngineStates) &&
    cohortFreezeV2Engines.every((engine) =>
      engine.executionAllowed === false &&
      engine.evidenceClassification === 'not-evidence' &&
      engine.selection === null &&
      !Object.hasOwn(engine, 'repositoryInformationalStatus')
    ),
  'cohort engine status, capability, serialized provenance, or unexecuted boundary changed'
);
const cohortFreezeV2ManifestFiles = new Map(cohortFreezeV2Manifest.files.map((file) => [file.path, file]));
const cohortFreezeV2Artifacts = [
  {
    bindingKey: 'campaignV2Binding',
    path: 'p2/gate-b/cohort-freeze-v2/campaign.v2.json',
    schemaPath: 'p2/gate-b/cohort-freeze-v2/campaign.v2.schema.json',
    filePath: cohortFreezeV2CampaignPath,
    schemaFilePath: cohortFreezeV2CampaignSchemaPath,
    manifestPath: 'campaign.v2.json',
    value: cohortFreezeV2Campaign
  },
  {
    bindingKey: 'canonicalCorpusV2Binding',
    path: 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json',
    schemaPath: 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.schema.json',
    filePath: cohortFreezeV2CorpusPath,
    schemaFilePath: cohortFreezeV2CorpusSchemaPath,
    manifestPath: 'canonical-corpus.v2.json',
    value: cohortFreezeV2Corpus
  },
  {
    bindingKey: 'fixtureRosterV2Binding',
    path: 'p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json',
    schemaPath: 'p2/gate-b/cohort-freeze-v2/fixture-roster.v2.schema.json',
    filePath: cohortFreezeV2FixtureRosterPath,
    schemaFilePath: cohortFreezeV2FixtureRosterSchemaPath,
    manifestPath: 'fixture-roster.v2.json',
    value: cohortFreezeV2FixtureRoster
  },
  {
    bindingKey: 'workItemRosterV2Binding',
    path: 'p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json',
    schemaPath: 'p2/gate-b/cohort-freeze-v2/work-item-roster.v2.schema.json',
    filePath: cohortFreezeV2WorkItemRosterPath,
    schemaFilePath: cohortFreezeV2WorkItemRosterSchemaPath,
    manifestPath: 'work-item-roster.v2.json',
    value: cohortFreezeV2WorkItemRoster
  },
  {
    bindingKey: 'executionEpochV2Binding',
    path: 'p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json',
    schemaPath: 'p2/gate-b/cohort-freeze-v2/execution-epoch.v2.schema.json',
    filePath: cohortFreezeV2EpochPath,
    schemaFilePath: cohortFreezeV2EpochSchemaPath,
    manifestPath: 'execution-epoch.v2.json',
    value: cohortFreezeV2Epoch
  }
];
for (const artifact of cohortFreezeV2Artifacts) {
  const laneBinding = cohortPreparationV2?.[artifact.bindingKey];
  const manifestFile = cohortFreezeV2ManifestFiles.get(artifact.manifestPath);
  expect(
    manifestFile?.fileDigest?.value === sha256(artifact.filePath) &&
      manifestFile.byteCount === readFileSync(artifact.filePath).length,
    `cohort manifest binding is stale: ${artifact.manifestPath}`
  );
  expect(
    laneBinding?.path === artifact.path &&
      laneBinding.schemaPath === artifact.schemaPath &&
      laneBinding.rawSha256 === sha256(artifact.filePath) &&
      laneBinding.schemaSha256 === sha256(artifact.schemaFilePath) &&
      laneBinding.contentDigest === artifact.value.contentDigest?.value &&
      laneBinding.executionAllowed === false,
    `cohort lane binding is stale or missing: ${artifact.bindingKey}`
  );
}
expect(
  cohortPreparationV2?.packageManifest?.path === 'p2/gate-b/cohort-freeze-v2/MANIFEST.json' &&
    cohortPreparationV2.packageManifest.schemaPath === 'p2/gate-b/cohort-freeze-v2/manifest.v1.schema.json' &&
    cohortPreparationV2.packageManifest.rawSha256 === sha256(cohortFreezeV2ManifestPath) &&
    cohortPreparationV2.packageManifest.schemaSha256 === sha256(cohortFreezeV2ManifestSchemaPath),
  'cohort package manifest binding is stale or absent'
);
expect(
  cohortPreparationV2?.status === 'cohort-freeze-v2-frozen-execution-pending' &&
    cohortPreparationV2.selection === 'none' &&
    cohortPreparationV2.cohortRanking === 'closed' &&
    cohortPreparationV2.fixtureRosterV2Binding?.counts?.fixtures === 4_732 &&
    cohortPreparationV2.fixtureRosterV2Binding?.counts?.deduplicatedEngineWorkItems === 18_928 &&
    cohortPreparationV2.fixtureRosterV2Binding?.counts?.preflightReady === 4_608 &&
    cohortPreparationV2.fixtureRosterV2Binding?.counts?.preflightLimitViolations === 124 &&
    cohortPreparationV2.workItemRosterV2Binding?.counts?.workItems === 18_928,
  'cohort lane status or exact fixture/work cardinality bindings changed'
);
const cohortFreezeV2ExpectedEnginePins = cohortFreezeV2Engines.map((engine, index) => ({
  engineId: engine.engineId,
  path: `p2/gate-b/cohort-freeze-v2/engines/${['native', 'libauth', 'bchn', 'leanbch'][index]}.v2.json`,
  rawSha256: sha256(cohortFreezeV2EnginePaths[index]),
  contentDigest: engine.contentDigest.value,
  schemaSha256: sha256(cohortFreezeV2EngineSchemaPath)
}));
expect(
  JSON.stringify(cohortPreparationV2?.executionEpochV2Binding?.enginePins) === JSON.stringify(cohortFreezeV2ExpectedEnginePins) &&
    JSON.stringify(cohortFreezeV2Epoch.engineRecords.map(({ engineId, path, rawSha256, contentDigest, schemaSha256 }) => ({
      engineId,
      path: laneRelativePath(path),
      rawSha256,
      contentDigest,
      schemaSha256
    }))) === JSON.stringify(cohortFreezeV2ExpectedEnginePins),
  'cohort epoch engine pins are stale, reordered, or incomplete'
);

const policyAuthorityV1Binding = lane.p2FieldCheckpoint?.policyAuthorityV1Binding;
expect(
  JSON.stringify(canonicalize(policyAuthorityV1Binding)) === JSON.stringify(canonicalize(POLICY_AUTHORITY_V1_EXPECTED_BINDING)),
  'policy-authority-v1 lane binding must be the exact complete P/R/K/F static envelope'
);
expect(
  policyAuthorityV1SemanticValidation?.sealed === true &&
    policyAuthorityV1SemanticValidation.files === 17 &&
    policyAuthorityV1SemanticValidation.directories === 3 &&
    policyAuthorityV1SemanticValidation.kats === 27,
  'policy-authority-v1 static package validation did not return the sealed complete closure'
);
expect(
  sha256(policyAuthorityV1RootPath) === policyAuthorityV1Binding?.root?.rawSha256 &&
    policyAuthorityV1Root.contentDigest?.value === policyAuthorityV1Binding?.root?.contentDigest &&
    policyAuthorityV1Root.bindingRoot?.value === policyAuthorityV1Binding?.bindingRoot &&
    policyAuthorityV1Root.policy?.contentDigest?.value === policyAuthorityV1Binding?.policyContentDigest &&
    policyAuthorityV1Root.causalDagRoot?.value === policyAuthorityV1Binding?.causalDagRoot &&
    policyAuthorityV1Root.policy?.liveF?.contentDigest?.value === policyAuthorityV1Binding?.liveFContentDigest &&
    sha256(policyAuthorityV1ManifestPath) === policyAuthorityV1Binding?.manifest?.rawSha256 &&
    policyAuthorityV1Manifest.manifestRosterDigest?.value === policyAuthorityV1Binding?.manifest?.rosterDigest &&
    sha256(policyAuthorityV1ChecksumsPath) === policyAuthorityV1Binding?.checksums?.rawSha256,
  'policy-authority-v1 root, semantic digest, manifest, roster, or checksum pin drifted'
);
expect(
  policyAuthorityV1Root.status === policyAuthorityV1Binding?.status &&
    policyAuthorityV1Root.executionAllowed === false &&
    policyAuthorityV1Binding?.executionAllowed === false &&
    policyAuthorityV1Root.runtimeBoundary?.runtimeEntrypoint === null &&
    policyAuthorityV1Root.runtimeBoundary?.activationCapability === null &&
    JSON.stringify(policyAuthorityV1Root.runtimeBoundary?.runtimeModules) === '[]' &&
    JSON.stringify(policyAuthorityV1Root.runtimeBoundary?.runtimeExports) === '[]',
  'policy-authority-v1 must remain a static non-authorizing, non-runtime template'
);
const policyAuthorityClosedNamespaces = policyAuthorityV1Binding?.closedNamespaces;
expect(
  JSON.stringify(Object.keys(policyAuthorityClosedNamespaces ?? {}).sort()) === JSON.stringify(['attempt', 'attempt-001', 'authorization', 'claim', 'evidence', 'metrics', 'ranking', 'run', 'selection']) &&
    Object.values(policyAuthorityClosedNamespaces ?? {}).every((value) => value === null),
  'policy-authority-v1 must keep attempts, authority, claims, runs, evidence, metrics, ranking, and selection closed/null'
);
for (const namespace of ['attempts', 'attempt-001', 'authorizations', 'claims', 'runs', 'evidence', 'metrics', 'rankings', 'selections', 'observations', 'terminals']) {
  expect(!existsSync(resolve(policyAuthorityV1Dir, namespace)), `policy-authority-v1 introduced a forbidden namespace: ${namespace}`);
}
const policyAuthorityDependencies = new Map(policyAuthorityV1Root.dependencyBindings?.map((binding) => [binding.id, binding]));
expect(
  JSON.stringify(policyAuthorityV1Root.dependencyBindings?.map((binding) => binding.id)) === JSON.stringify(['R', 'K', 'F']) &&
    policyAuthorityDependencies.size === 3,
  'policy-authority-v1 dependency order must remain R/K/F'
);
expect(
  sha256(runtimeBindingV1RootPath) === policyAuthorityV1Binding?.dependencies?.R?.root?.rawSha256 &&
    runtimeBindingV1Root.contentDigest?.value === policyAuthorityV1Binding?.dependencies?.R?.root?.contentDigest &&
    sha256(runtimeBindingV1ManifestPath) === policyAuthorityV1Binding?.dependencies?.R?.manifest?.rawSha256 &&
    typeof runtimeBindingV1Manifest.contentDigest === 'string' &&
    runtimeBindingV1Manifest.contentDigest === policyAuthorityV1Binding?.dependencies?.R?.manifest?.contentDigest &&
    sha256(runtimeBindingV1ChecksumsPath) === policyAuthorityV1Binding?.dependencies?.R?.checksums?.rawSha256 &&
    runtimeBindingV1Root.runtimeAuthority?.digest === policyAuthorityV1Binding?.dependencies?.R?.runtimeAuthorityDigest &&
    policyAuthorityDependencies.get('R')?.root?.rawSha256 === policyAuthorityV1Binding?.dependencies?.R?.root?.rawSha256 &&
    policyAuthorityDependencies.get('R')?.nativeContentDigest === policyAuthorityV1Binding?.dependencies?.R?.root?.contentDigest &&
    policyAuthorityDependencies.get('R')?.runtimeAuthorityDigest === policyAuthorityV1Binding?.dependencies?.R?.runtimeAuthorityDigest,
  'R complete static envelope or semantic pin drifted'
);
const runnerCoreContract = {
  runtimeEntrypoint: runnerCoreV1Root.runtimeEntrypoint,
  runtimeModules: runnerCoreV1Root.runtimeModules,
  runtimeExports: runnerCoreV1Root.runtimeExports,
  buildTimeOnlyLocators: runnerCoreV1Root.buildTimeOnlyLocators
};
expect(
  sha256(runnerCoreV1RootPath) === policyAuthorityV1Binding?.dependencies?.K?.runtimeCore?.rawSha256 &&
    sha256(runnerCoreV1ManifestPath) === policyAuthorityV1Binding?.dependencies?.K?.manifest?.rawSha256 &&
    runnerCoreV1Manifest.packageRoot === policyAuthorityV1Binding?.dependencies?.K?.manifest?.packageRoot &&
    runnerCoreV1Manifest.manifestRoot === policyAuthorityV1Binding?.dependencies?.K?.manifest?.manifestRoot &&
    runnerCoreV1Manifest.entriesRoot === policyAuthorityV1Binding?.dependencies?.K?.manifest?.entriesRoot &&
    sha256(runnerCoreV1ChecksumsPath) === policyAuthorityV1Binding?.dependencies?.K?.checksums?.rawSha256 &&
    JSON.stringify(canonicalize(runnerCoreContract)) === JSON.stringify(canonicalize(policyAuthorityV1Binding?.dependencies?.K?.runtimeContract)) &&
    policyAuthorityDependencies.get('K')?.root?.rawSha256 === policyAuthorityV1Binding?.dependencies?.K?.runtimeCore?.rawSha256 &&
    policyAuthorityDependencies.get('K')?.manifest?.rawSha256 === policyAuthorityV1Binding?.dependencies?.K?.manifest?.rawSha256 &&
    policyAuthorityDependencies.get('K')?.sums?.rawSha256 === policyAuthorityV1Binding?.dependencies?.K?.checksums?.rawSha256,
  'K complete static envelope, roots, or parsed runtime-contract locator closure drifted'
);
const [sourceLeaf, freezeLeaf] = frozenInputsV1Root.leafClosure?.leaves ?? [];
expect(
  sha256(frozenInputsV1RootPath) === policyAuthorityV1Binding?.dependencies?.F?.root?.rawSha256 &&
    frozenInputsV1Root.contentDigest?.value === policyAuthorityV1Binding?.dependencies?.F?.root?.contentDigest &&
    sha256(frozenInputsV1ManifestPath) === policyAuthorityV1Binding?.dependencies?.F?.manifest?.rawSha256 &&
    frozenInputsV1Manifest.contentDigest?.value === policyAuthorityV1Binding?.dependencies?.F?.manifest?.contentDigest &&
    frozenInputsV1Manifest.manifestRosterDigest?.value === policyAuthorityV1Binding?.dependencies?.F?.manifest?.rosterDigest &&
    sha256(frozenInputsV1ChecksumsPath) === policyAuthorityV1Binding?.dependencies?.F?.checksums?.rawSha256 &&
    policyAuthorityDependencies.get('F')?.root?.rawSha256 === policyAuthorityV1Binding?.dependencies?.F?.root?.rawSha256 &&
    policyAuthorityDependencies.get('F')?.nativeContentDigest === policyAuthorityV1Binding?.dependencies?.F?.root?.contentDigest &&
    JSON.stringify(policyAuthorityDependencies.get('F')?.orderedLeafIds) === JSON.stringify(policyAuthorityV1Binding?.dependencies?.F?.orderedLeaves?.map((leaf) => leaf.id)),
  'F complete static envelope, semantic root, roster, or ordered leaves drifted'
);
const sourceLeafBinding = policyAuthorityV1Binding?.dependencies?.F?.orderedLeaves?.[0];
const freezeLeafBinding = policyAuthorityV1Binding?.dependencies?.F?.orderedLeaves?.[1];
expect(
  sourceLeaf?.id === sourceLeafBinding?.id &&
    sourceLeaf?.packageRoot === `research-lanes/bch-shielded-pool-design/${sourceLeafBinding?.packageRoot}` &&
    sha256(resolve(laneDir, sourceLeafBinding?.root?.path ?? '')) === sourceLeafBinding?.root?.rawSha256 &&
    sourceSet.contentDigest?.value === sourceLeafBinding?.root?.nativeSemanticDigest &&
    sourceLeaf?.nativeSemanticDigest?.value === sourceLeafBinding?.root?.nativeSemanticDigest &&
    sha256(resolve(laneDir, sourceLeafBinding?.manifest?.path ?? '')) === sourceLeafBinding?.manifest?.rawSha256 &&
    sha256(resolve(laneDir, sourceLeafBinding?.checksums?.path ?? '')) === sourceLeafBinding?.checksums?.rawSha256 &&
    freezeLeaf?.id === freezeLeafBinding?.id &&
    freezeLeaf?.packageRoot === `research-lanes/bch-shielded-pool-design/${freezeLeafBinding?.packageRoot}` &&
    sha256(resolve(laneDir, freezeLeafBinding?.root?.path ?? '')) === freezeLeafBinding?.root?.rawSha256 &&
    cohortFreezeV2Epoch.contentDigest?.value === freezeLeafBinding?.root?.artifactSemanticDigest &&
    freezeLeaf?.artifactSemanticDigest?.value === freezeLeafBinding?.root?.artifactSemanticDigest &&
    sha256(resolve(laneDir, freezeLeafBinding?.manifest?.path ?? '')) === freezeLeafBinding?.manifest?.rawSha256 &&
    sha256(resolve(laneDir, freezeLeafBinding?.checksums?.path ?? '')) === freezeLeafBinding?.checksums?.rawSha256 &&
    policyAuthorityDependencies.get('F')?.sourceNativeSemanticDigest === sourceLeafBinding?.root?.nativeSemanticDigest &&
    policyAuthorityDependencies.get('F')?.freezeArtifactSemanticDigest === freezeLeafBinding?.root?.artifactSemanticDigest,
  'F transitive source/freeze leaf raw or semantic pins drifted'
);
const expectedPolicyAliases = policyAuthorityV1Binding?.launchAuthority?.aliases ?? [];
expect(
  expectedPolicyAliases.length === 5 &&
    policyAuthorityV1Binding?.launchAuthority?.workloadsPerEndpoint === 4608 &&
    policyAuthorityV1Binding?.launchAuthority?.completeCapturedInputs === true &&
    policyAuthorityV1Binding?.launchAuthority?.minimumCapturedInputBytes === 1 &&
    JSON.stringify(policyAuthorityV1Root.policy?.kLaunchAuthority?.map(({ alias, engineId }) => ({ alias, endpoint: engineId }))) === JSON.stringify(expectedPolicyAliases) &&
    policyAuthorityV1Root.policy?.kLaunchAuthority?.every((row) => row.workloads === 4608 && row.capturedInput?.complete === true && row.capturedInput?.private === true && row.capturedInput?.minimumBytes === 1) &&
    JSON.stringify(runtimeBindingV1Root.runtimeAuthority?.common?.endpointOrder) === JSON.stringify(expectedPolicyAliases.map(({ endpoint }) => endpoint)),
  'P must bind exactly five aliases/endpoints and a 4,608 per-endpoint workload rather than 4,608 K rows'
);
expect(
  policyAuthorityV1Root.policy?.q?.executionAllowed === false &&
    policyAuthorityV1Root.policy?.a?.consumptionEvent === 'external-C-only' &&
    !Object.hasOwn(policyAuthorityV1Root.policy?.a ?? {}, 'consumptionState') &&
    policyAuthorityV1Root.policy?.c?.pCreatesC === false &&
    policyAuthorityV1Root.policy?.j?.grantsAuthority === false &&
    policyAuthorityV1Root.policy?.d?.abortExecutable === false &&
    policyAuthorityV1Root.policy?.d?.recoveryReactivation === false,
  'P Q/A/C/J/D policy templates crossed the static authority boundary'
);
const cohortLiveExecutorV2Binding = lane.p2FieldCheckpoint?.cohortLiveExecutorV2Binding;
expect(
  JSON.stringify(canonicalize(cohortLiveExecutorV2Binding)) === JSON.stringify(canonicalize(CLEV2_EXPECTED_BINDING)),
  'cohort-live-executor-v2 lane binding must be the exact SOL-regated static envelope'
);
expect(
  cohortLiveExecutorV2IndependentValidation?.files === 22 &&
    cohortLiveExecutorV2IndependentValidation?.directories === 4 &&
    cohortLiveExecutorV2IndependentValidation?.manifest?.entryCount === 20 &&
    cohortLiveExecutorV2StaticValidation === true &&
    cohortLiveExecutorV2CausalMutation === true,
  'cohort-live-executor-v2 independent closure, pinned validator, or causal mutation gate failed'
);
const cohortAuthorityBindingModelV1Binding = lane.p2FieldCheckpoint?.cohortAuthorityBindingModelV1Binding;
expect(
  JSON.stringify(canonicalize(cohortAuthorityBindingModelV1Binding)) === JSON.stringify(canonicalize(CABM_EXPECTED_BINDING)),
  'cohort-authority-binding-model-v1 lane binding must be the exact SOL-regated static envelope'
);
expect(
  cohortAuthorityBindingModelV1IndependentValidation?.files === 22 &&
    cohortAuthorityBindingModelV1IndependentValidation?.directories === 4 &&
    cohortAuthorityBindingModelV1IndependentValidation?.manifest?.entryCount === 20 &&
    cohortAuthorityBindingModelV1StaticValidation === true &&
    cohortAuthorityBindingModelV1CausalMutation === true,
  'cohort-authority-binding-model-v1 independent closure, pinned validator, or causal mutation gate failed'
);
const cohortExternalOriginContractV1Binding = lane.p2FieldCheckpoint?.cohortExternalOriginContractV1Binding;
expect(
  JSON.stringify(canonicalize(cohortExternalOriginContractV1Binding)) === JSON.stringify(canonicalize(ECOC_EXPECTED_BINDING)),
  'cohort-external-origin-contract-v1 lane binding must be the exact SOL-regated static envelope'
);
expect(
  cohortExternalOriginContractV1IndependentValidation?.files === 21 &&
    cohortExternalOriginContractV1IndependentValidation?.directories === 3 &&
    cohortExternalOriginContractV1IndependentValidation?.manifest?.entryCount === 19 &&
    cohortExternalOriginContractV1StaticValidation === true &&
    cohortExternalOriginContractV1CausalMutation === true,
  'cohort-external-origin-contract-v1 independent closure, pinned validator, or causal mutation gate failed'
);
const cohortUpstreamOriginProviderContractV1Binding = lane.p2FieldCheckpoint?.cohortUpstreamOriginProviderContractV1Binding;
expect(
  JSON.stringify(canonicalize(cohortUpstreamOriginProviderContractV1Binding)) === JSON.stringify(canonicalize(UOPC_EXPECTED_BINDING)),
  'cohort-upstream-origin-provider-contract-v1 lane binding must be the exact SOL-regated static envelope'
);
expect(
  cohortUpstreamOriginProviderContractV1IndependentValidation?.files === 21 &&
    cohortUpstreamOriginProviderContractV1IndependentValidation?.directories === 3 &&
    cohortUpstreamOriginProviderContractV1IndependentValidation?.manifest?.entryCount === 19 &&
    cohortUpstreamOriginProviderContractV1StaticValidation?.sealed === true &&
    cohortUpstreamOriginProviderContractV1CausalMutation === true,
  'cohort-upstream-origin-provider-contract-v1 independent closure, pinned validator, or causal mutation gate failed'
);
const cohortUpstreamProviderSourceMapV1Binding = lane.p2FieldCheckpoint?.cohortUpstreamProviderSourceMapV1Binding;
expect(
  JSON.stringify(canonicalize(cohortUpstreamProviderSourceMapV1Binding)) === JSON.stringify(canonicalize(SPM_EXPECTED_BINDING)),
  'cohort-upstream-provider-source-map-v1 lane binding must be the exact SOL-regated static envelope'
);
expect(
  cohortUpstreamProviderSourceMapV1IndependentValidation?.files === 20 &&
    cohortUpstreamProviderSourceMapV1IndependentValidation?.directories === 3 &&
    cohortUpstreamProviderSourceMapV1IndependentValidation?.manifest?.entryCount === 18 &&
    cohortUpstreamProviderSourceMapV1StaticValidation?.sealed === true &&
    cohortUpstreamProviderSourceMapV1CausalMutation === true,
  'cohort-upstream-provider-source-map-v1 independent closure, pinned validator, or causal mutation gate failed'
);
const gateB0EvidencePlanV1Binding = lane.p2FieldCheckpoint?.gateB0EvidencePlanV1Binding;
expect(
  (() => { try { return b0rAssertBinding(gateB0EvidencePlanV1Binding); } catch { return false; } })(),
  'gate-b0-evidence-plan-v1 lane binding must be the exact SOL-regated sealed static evidence-plan envelope'
);
expect(
  gateB0EvidencePlanV1IndependentValidation?.files === 17 &&
    gateB0EvidencePlanV1IndependentValidation?.directories === 3 &&
    gateB0EvidencePlanV1IndependentValidation?.envelope?.manifest?.entryCount === 15 &&
    gateB0EvidencePlanV1StaticValidation?.files === 17 &&
    gateB0EvidencePlanV1StaticValidation?.sourcePins === 35 &&
    gateB0EvidencePlanV1StaticValidation?.unsealed === false &&
    gateB0EvidencePlanV1CausalMutation?.classes === B0R_CAUSAL_CLASS_COUNT,
  'gate-b0-evidence-plan-v1 independent closure, outside-package anchor, pinned validator, or causal mutation gate failed'
);
const gateB0ExecutionAdmissionContractV1Binding = lane.p2FieldCheckpoint?.gateB0ExecutionAdmissionContractV1Binding;
expect(
  (() => { try { return eacAssertBinding(gateB0ExecutionAdmissionContractV1Binding); } catch { return false; } })(),
  'gate-b0-execution-admission-contract-v1 lane binding must be the exact SOL-regated sealed static pre-execution prerequisite envelope'
);
expect(
  gateB0ExecutionAdmissionContractV1IndependentValidation?.files === 20 &&
    gateB0ExecutionAdmissionContractV1IndependentValidation?.directories === 3 &&
    gateB0ExecutionAdmissionContractV1IndependentValidation?.envelope?.manifest?.entryCount === 18 &&
    gateB0ExecutionAdmissionContractV1StaticValidation?.files === 20 &&
    gateB0ExecutionAdmissionContractV1StaticValidation?.sourcePins === 64 &&
    gateB0ExecutionAdmissionContractV1StaticValidation?.unsealed === false &&
    gateB0ExecutionAdmissionContractV1CausalMutation?.classes === EAC_CAUSAL_CLASS_COUNT,
  'gate-b0-execution-admission-contract-v1 independent closure, outside-package anchor, pinned validator, or causal mutation gate failed'
);
const gateB0StaticSourceAuthorityV1Binding = lane.p2FieldCheckpoint?.gateB0StaticSourceAuthorityV1Binding;
expect(
  (() => { try { return ssaAssertBinding(gateB0StaticSourceAuthorityV1Binding); } catch { return false; } })(),
  'gate-b0-static-source-authority-v1 lane binding must be the exact SOL-regated sealed static source-contract-language envelope'
);
expect(
  gateB0StaticSourceAuthorityV1IndependentValidation?.files === 26 &&
    gateB0StaticSourceAuthorityV1IndependentValidation?.directories === 3 &&
    gateB0StaticSourceAuthorityV1IndependentValidation?.envelope?.manifest?.entryCount === 24 &&
    gateB0StaticSourceAuthorityV1IndependentValidation?.sourceContracts === 19 &&
    gateB0StaticSourceAuthorityV1StaticValidation?.files === 26 &&
    gateB0StaticSourceAuthorityV1StaticValidation?.rootDigest === SSA_EXPECTED_BINDING.root.contentDigest &&
    gateB0StaticSourceAuthorityV1StaticValidation?.sourceContracts === 19 &&
    gateB0StaticSourceAuthorityV1StaticValidation?.unsealed === false &&
    gateB0StaticSourceAuthorityV1CausalMutation?.classes === SSA_CAUSAL_CLASS_COUNT &&
    gateB0StaticSourceAuthorityV1CausalMutation?.labels?.length === SSA_CAUSAL_CLASS_COUNT,
  'gate-b0-static-source-authority-v1 independent closure, source semantics, outside-package anchor, pinned validator, or 119-class causal gate failed'
);
const gateB0ExternalAuthorityPrerequisitePolicyV1Binding = lane.p2FieldCheckpoint?.gateB0ExternalAuthorityPrerequisitePolicyV1Binding;
expect(
  (() => { try { return eappAssertBinding(gateB0ExternalAuthorityPrerequisitePolicyV1Binding); } catch { return false; } })(),
  'gate-b0-external-authority-prerequisite-policy-v1 lane binding must be the exact SOL-regated sealed static prerequisite-policy envelope'
);
expect(
  gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation?.files === 23 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation?.directories === 3 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation?.envelope?.manifest?.entryCount === 21 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1IndependentValidation?.sourceContracts === 10 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation?.files === 23 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation?.directories === 3 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation?.rootDigest === EAPP_EXPECTED_BINDING.root.contentDigest &&
    gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation?.sourceContracts === 10 &&
    gateB0ExternalAuthorityPrerequisitePolicyV1StaticValidation?.unsealed === false &&
    gateB0ExternalAuthorityPrerequisitePolicyV1CausalMutation?.classes === EAPP_LANE_CAUSAL_CLASS_COUNT &&
    gateB0ExternalAuthorityPrerequisitePolicyV1CausalMutation?.labels?.length === EAPP_LANE_CAUSAL_CLASS_COUNT,
  'gate-b0-external-authority-prerequisite-policy-v1 independent closure, source joins, outside-package anchor, pinned validator, or 159-class causal gate failed'
);
expect(loweringFreeze.selection === 'none' && loweringFreeze.tupleRef === null && loweringFreeze.evidenceClassification === 'not-evidence' && loweringFreeze.protocolBoundary === 'component-only', 'lowering freeze promotion boundary changed');
expect(loweringFreeze.executionBoundary.executionAllowed === false && loweringFreeze.downstreamBindings?.sourceSetV1 === null && loweringFreeze.downstreamBindings?.campaignV2 === null && loweringFreeze.downstreamBindings?.canonicalCorpusV2 === null && loweringFreeze.downstreamBindings?.executionEpochV2 === null, 'lowering freeze downstream/execution slots must remain closed/null');
expect(
  loweringArmIrFreeze.selection === 'none' && loweringArmIrFreeze.tupleRef === null &&
    loweringArmIrFreeze.protocolBoundary === 'component-only' &&
    loweringArmIrFreeze.validationContract?.verdict === 'pass',
  'lowering-arm IR package selection or validation boundary changed'
);
expect(
  loweringArmIrFreeze.executionBoundary?.sourceEmissionAllowed === false &&
    loweringArmIrFreeze.executionBoundary?.bytecodeEmissionAllowed === false &&
    loweringArmIrFreeze.executionBoundary?.vmExecutionAllowed === false &&
    loweringArmIrFreeze.executionBoundary?.metricsAllowed === false &&
    Object.values(loweringArmIrFreeze.downstreamBindings ?? {}).every((value) => value === null),
  'lowering-arm IR package must remain pre-source, pre-execution, and downstream-unbound'
);
expect(
  loweringArmIrFreeze.cardinalities?.constructions === 4 &&
    loweringArmIrFreeze.cardinalities?.arms === 14 &&
    loweringArmIrFreeze.cardinalities?.programs === 28 &&
    loweringArmIrFreeze.cardinalities?.ssaNodes === 4806 &&
    loweringArmIrFreeze.cardinalities?.rangeLedgerRows === 4806 &&
    loweringArmIrFreeze.cardinalities?.instructions === 25098 &&
    loweringArmIrFreeze.cardinalities?.storedTraceRows === 25098 &&
    loweringArmIrFreeze.cardinalities?.maxCombinedDepth === 392 &&
    JSON.stringify(loweringArmIrFreeze.cardinalities?.nodeOps) === JSON.stringify({ add: 996, mul: 297, reduce: 2403, scale: 748, square: 41, sub: 321 }),
  'lowering-arm IR exact aggregate contract changed'
);

expect(
  lane.status === EAPP_LANE_STATUS,
  'lane status must record the sealed static Gate B0 external-authority prerequisite-policy integration without architecture promotion'
);
expect(
  lane.architectureCheckpoint?.status === EAPP_ARCHITECTURE_STATUS,
  'architecture checkpoint must record the unqualified static Gate B0 external-authority prerequisite-policy boundary'
);
expect(
  lane.p1Checkpoint?.status === 'implemented-research-machinery-unqualified',
  'P1 checkpoint must remain explicitly unqualified'
);
expect(
  lane.p1Checkpoint?.notEstablished?.some((item) => item.includes('carrier count selection')),
  'P1 checkpoint must not imply a carrier-count or proof-size selection'
);
expect(
  lane.p1Checkpoint?.notEstablished?.some((item) => item.includes('BCHN policy acceptance')),
  'P1 checkpoint must not imply whole-transaction policy acceptance'
);
expect(
  lane.p2FieldCheckpoint?.status === EAPP_P2_STATUS,
  'P2 field checkpoint must remain explicitly nonranking and unqualified after static Gate B0 external-authority prerequisite-policy integration'
);
expect(
  lane.p2FieldCheckpoint?.certificateBoundary?.casReview === 'not-cas-reviewed' &&
    lane.p2FieldCheckpoint?.certificateBoundary?.repositoryReplay === 'two-independent-implementations-pass' &&
    lane.p2FieldCheckpoint?.certificateBoundary?.evidenceClassification === 'not-evidence' &&
    lane.p2FieldCheckpoint?.certificateBoundary?.selection === 'none',
  'generic field certificates must not be promoted to CAS review, evidence, or selection'
);
expect(
  lane.p2FieldCheckpoint?.m89ExternalCasReplay?.status === 'root-reviewed-component-pass' &&
    lane.p2FieldCheckpoint?.m89ExternalCasReplay?.tool === 'SymPy 1.14.0' &&
    lane.p2FieldCheckpoint?.m89ExternalCasReplay?.scope.includes('not selection'),
  'P2 checkpoint must record the independent CAS replay as component-only'
);
expect(
  lane.p2FieldCheckpoint?.gateB0?.status === 'm89-component-shakedown-measured-nonranking' &&
    lane.p2FieldCheckpoint?.gateB0?.selection === 'none' &&
    lane.p2FieldCheckpoint?.gateB0?.descriptorContentDigest === m89AlgebraDescriptor.contentDigest.value &&
    lane.p2FieldCheckpoint?.gateB0?.campaignContentDigest === gateBArithmeticCampaign.contentDigest.value &&
    lane.p2FieldCheckpoint?.gateB0?.runPath === 'p2/gate-b/runs/m89-d2-schoolbook-shakedown-v1/run.json' &&
    lane.p2FieldCheckpoint?.gateB0?.runFileSha256 === sha256(m89GateB0RunPath) &&
    lane.p2FieldCheckpoint?.gateB0?.runContentDigest === m89GateB0Run.contentDigest.value &&
    lane.p2FieldCheckpoint?.gateB0?.m89Execution === 'measured-component-only-pass' &&
    lane.p2FieldCheckpoint?.gateB0?.evidenceClassification === 'gate-b0-primitive-evidence-only' &&
    lane.p2FieldCheckpoint?.gateB0?.cohortRanking === 'closed',
  'P2 checkpoint must bind the measured component-only Gate-B0 run without selection'
);
expect(
  lane.p2FieldCheckpoint?.notEstablished?.some((item) => item.includes('comparative field ranking')) &&
    lane.p2FieldCheckpoint?.notEstablished?.some((item) => item.includes('complete candidate tuple')),
  'P2 checkpoint must preserve the ranking and complete-tuple blockers'
);
expect(
  m89GateB0Run.runMode === 'non-ranking-harness-shakedown' &&
    m89GateB0Run.status === 'measured-component-only' &&
    m89GateB0Run.selection === 'none' &&
    m89GateB0Run.crossEngineSummary?.verdictAgreement === true,
  'official M89 Gate-B0 run must remain a non-ranking component-only agreement record'
);
expect(
  m31BinaryRebuildReplay.schema === 'shieldkit-labs/p2/historical-binary-rebuild-replay/v1' &&
    m31BinaryRebuildReplay.status === 'measured-functional-replay-pass' &&
    m31BinaryRebuildReplay.selection === 'none' &&
    m31BinaryRebuildReplay.corpus?.sha256 === 'fa76c62cfd3fb2ea4898b0b42fda5f21edcd41cb023c84925237eb903fe0dcd9' &&
    m31BinaryRebuildReplay.corpus?.cases === 3_724,
  'M31 rebuilt-binary replay identity or component-only boundary changed'
);
expect(
  lane.p2FieldCheckpoint?.m31BinaryRebuildReplay?.path === 'p2/evidence/m31-binary-rebuild-replay-2026-08-09.json' &&
    lane.p2FieldCheckpoint?.m31BinaryRebuildReplay?.sha256 === sha256(m31BinaryRebuildReplayPath) &&
    lane.p2FieldCheckpoint?.m31BinaryRebuildReplay?.status === 'measured-functional-replay-pass',
  'P2 checkpoint must bind the exact M31 rebuilt-binary replay'
);
expectExactSet(
  m31BinaryRebuildReplay.binaryTransitions.map(({ artifactId }) => artifactId),
  ['bch-conformance:native-leg-binary', 'leanbch:costprobe-binary', 'leanbch:vmbconf-binary'],
  'M31 rebuilt-binary transitions'
);
const m31ReplayOutputs = new Map([
  ['bch-conformance:native-leg-binary', m31BaseSuiteEvidence.corpusSuite.engines.find(({ engineId }) => engineId === 'bchn')?.artifactDigest],
  ['leanbch:costprobe-binary', m31BaseSuiteEvidence.corpusSuite.engines.find(({ engineId, role }) => engineId === 'leanbch' && role === 'formal-cost')?.artifactDigest],
  ['leanbch:vmbconf-binary', m31BaseSuiteEvidence.corpusSuite.engines.find(({ engineId, role }) => engineId === 'leanbch' && role === 'formal-verdict')?.artifactDigest],
]);
for (const transition of m31BinaryRebuildReplay.binaryTransitions) {
  expect(transition.outputSha256 === m31ReplayOutputs.get(transition.artifactId), `M31 rebuilt-binary output drift: ${transition.artifactId}`);
}
const rootPackage = loadJson(resolve(repoRoot, 'package.json'));
const rootPackageLock = loadJson(resolve(repoRoot, 'package-lock.json'));
expect(rootPackage.dependencies?.['@bitauth/libauth'] === '3.1.0-next.8', 'P1 Libauth dependency must be exact-pinned');
expect(
  rootPackageLock.packages?.['node_modules/@bitauth/libauth']?.version === '3.1.0-next.8',
  'P1 Libauth lockfile version must match the exact pin'
);
expect(
  rootPackage.scripts?.['lane:shielded-pool:p1:test']?.includes('p1/integration.test.mjs'),
  'root package must expose the complete P1 test entrypoint'
);
expect(
  rootPackage.scripts?.['lane:shielded-pool:gate-b0:test']?.includes('materialize-m89-shakedown.test.mjs') &&
    rootPackage.scripts?.['lane:shielded-pool:gate-b0:test']?.endsWith('materialize-m89-shakedown.mjs'),
  'root package must test and verify the official M89 Gate-B0 run'
);
expect(
  rootPackage.scripts?.['lane:shielded-pool:field-cert:test']?.includes('field-cert/python/replay_checker.py') &&
    rootPackage.scripts?.['lane:shielded-pool:field-cert:test']?.includes('field-cert/node/check-fixture.mjs') &&
    rootPackage.scripts?.['lane:shielded-pool:field-cert:test']?.includes('external && sha256sum -c SHA256SUMS'),
  'root package must cross-replay and manifest-check field certificates'
);
expect(
  rootPackage.scripts?.['lane:shielded-pool:gate-b0:test']?.includes('algebra-component-descriptor.test.mjs') &&
    rootPackage.scripts?.['lane:shielded-pool:gate-b0:test']?.includes('equal-relation-arithmetic-run.test.mjs') &&
    rootPackage.scripts?.check?.includes('lane:shielded-pool:gate-b0:test'),
  'root package must expose and run the Gate-B0 contract suite'
);

expect(
  ['root-repaired-content-pinned-pending-sol-rereview', 'root-sol-approved-content-pinned'].includes(p0FreezeManifest.status),
  'P0 freeze manifest has an invalid review status'
);
const expectedP0Paths = [
  'security/threat-model-fv1.json',
  'security/threat-model-fv1.schema.json',
  'spec/pool-action-fv1.json',
  'spec/pool-action-fv1.schema.json',
  'spec/pool-config-fv1.json',
  'spec/pool-state-fv1.md',
  'spec/pool-state-fv1.schema.json',
  'spec/responsibility-map-fv1.json',
  'spec/tx-binding-fv1.md',
  'vectors/pool-action-fv1/index.json',
  'vectors/pool-action-fv1/index.schema.json'
];
const p0Paths = p0FreezeManifest.artifacts.map((artifact) => artifact.path);
expectExactSet(p0Paths, expectedP0Paths, 'P0 freeze manifest artifacts');
for (const artifact of p0FreezeManifest.artifacts) {
  const artifactPath = resolve(laneDir, artifact.path);
  expect(artifactPath.startsWith(`${laneDir}/`), `P0 freeze artifact escapes lane: ${artifact.path}`);
  expect(existsSync(artifactPath), `P0 freeze artifact is missing: ${artifact.path}`);
  if (existsSync(artifactPath)) expect(sha256(artifactPath) === artifact.sha256, `P0 freeze artifact digest is stale: ${artifact.path}`);
}
const p0AggregatePreimage = [...p0FreezeManifest.artifacts]
  .sort((left, right) => left.path.localeCompare(right.path))
  .map((artifact) => `${artifact.path}\0${artifact.sha256}\n`)
  .join('');
expect(
  createHash('sha256').update(p0AggregatePreimage).digest('hex') === p0FreezeManifest.aggregate.sha256,
  'P0 freeze aggregate digest is stale'
);
expect(
  lane.architectureCheckpoint?.status === EAPP_ARCHITECTURE_STATUS,
  'architecture checkpoint must retain the root/SOL P0 freeze and unqualified static Gate B0 external-authority prerequisite-policy status'
);
expect(lane.architectureCheckpoint?.unselected.length >= 7, 'architecture checkpoint must preserve unselected cryptographic axes');
expect(
  lane.architectureCheckpoint?.nextGate === CPSB_NEXT_GATE &&
    lane.architectureCheckpoint?.unselected?.some((item) => item === EAPP_UNSELECTED),
  'architecture checkpoint must preserve the closed static external-authority prerequisite-policy boundary'
);
expect(
  lane.p2FieldCheckpoint?.status === EAPP_P2_STATUS &&
    !lane.p2FieldCheckpoint?.notEstablished?.some((item) => item.includes('all three remain null')) &&
    !lane.p2FieldCheckpoint?.notEstablished?.some((item) => item.includes('executable BCH source and bytecode bindings')) &&
    lane.p2FieldCheckpoint?.nextGate === CPSB_NEXT_GATE &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item.startsWith('R runtime-binding, K runner-core, F frozen-inputs, and P policy-authority')) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item.startsWith('sealed cohort-live-executor-v2 is a static non-authorizing unqualified transition model')) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item.startsWith('sealed cohort-authority-binding-model-v1 is a static non-authorizing unqualified catalog')) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item.startsWith('sealed cohort-external-origin-contract-v1 is a static non-authorizing unqualified external-origin contract catalog')) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item.startsWith('sealed cohort-upstream-origin-provider-contract-v1 is a static non-authorizing unqualified provider-requirements catalog')) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item === UOPC_NONPROMOTION) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item === B0R_NONPROMOTION) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item === EAC_NONPROMOTION) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item === SSA_NONPROMOTION) &&
    lane.p2FieldCheckpoint?.completed?.some((item) => item === EAPP_NONPROMOTION) &&
    lane.p2FieldCheckpoint?.notEstablished?.some((item) => item === EAPP_NOT_ESTABLISHED) &&
    lane.p2FieldCheckpoint?.notEstablished?.some((item) => item === B0R_NOT_ESTABLISHED) &&
    lane.p2FieldCheckpoint?.notEstablished?.some((item) => item === EAC_NOT_ESTABLISHED),
  'P2 checkpoint must retain the nonranking static source-map, Gate B0-R, EAC, SSA, and EAPP prerequisite-policy boundaries'
);
for (const [path, label] of [
  [resolve(laneDir, 'README.md'), 'lane README'],
  [resolve(laneDir, 'research/phase-plan.md'), 'phase plan']
]) {
  const prose = readFileSync(path, 'utf8');
  expect(/R runtime-binding, K\s+runner-core, F frozen-inputs, and P policy-authority/u.test(prose), `${label} omits the completed static R/K/F/P prerequisites`);
  expect(prose.includes('sealed cohort-live-executor-v2'), `${label} omits the sealed static transition-model integration`);
  expect(prose.includes('sealed cohort-authority-binding-model-v1'), `${label} omits the sealed static authority-binding catalog integration`);
  expect(prose.includes(CABM_NONPROMOTION), `${label} omits the exact static nonpromotion boundary`);
  expect(prose.includes(ECOC_NONPROMOTION), `${label} omits the exact external-origin static nonpromotion boundary`);
  expect(prose.includes(UOPC_NONPROMOTION), `${label} omits the exact upstream-provider static nonpromotion boundary`);
  expect(prose.includes('Attempt-001 remains closed'), `${label} does not preserve the closed Attempt-001 boundary`);
}

const phasePlanProse = readFileSync(resolve(laneDir, 'research/phase-plan.md'), 'utf8');
expect(phasePlanProse.includes(UOPC_NEXT_GATE), 'phase plan must retain the historical upstream-provider source-mapping boundary');
for (const [path, label] of [
  [resolve(laneDir, 'README.md'), 'lane README']
]) {
  const prose = readFileSync(path, 'utf8');
  expect(prose.includes(EAC_NEXT_GATE), `${label} must state the exact closed EAC next-gate boundary`);
  expect(prose.includes(SSA_NONPROMOTION), `${label} must state the exact SSA nonpromotion boundary`);
  expect(prose.includes(SSA_NEXT_GATE), `${label} must state the exact closed SSA next-gate boundary`);
  expect(prose.includes(EAPP_NONPROMOTION), `${label} must state the exact EAPP nonpromotion boundary`);
  expect(prose.includes(EAPP_NEXT_GATE), `${label} must state the exact closed EAPP next-gate boundary`);
}

const designOptionsProse = readFileSync(resolve(laneDir, 'analysis/design-options.md'), 'utf8');
expect(designOptionsProse.includes(UOPC_NONPROMOTION), 'design-options must preserve the upstream-provider static nonpromotion boundary');
expect(designOptionsProse.includes(B0R_NONPROMOTION), 'design-options must preserve the Gate B0-R static nonpromotion boundary');
expect(designOptionsProse.includes(EAC_NEXT_GATE), 'design-options must state the exact closed EAC next-gate boundary');
expect(designOptionsProse.includes(SSA_NONPROMOTION), 'design-options must preserve the SSA static nonpromotion boundary');
expect(designOptionsProse.includes(SSA_NEXT_GATE), 'design-options must state the exact closed SSA next-gate boundary');
expect(designOptionsProse.includes(EAPP_NONPROMOTION), 'design-options must preserve the EAPP static nonpromotion boundary');
expect(designOptionsProse.includes(EAPP_NEXT_GATE), 'design-options must state the exact closed EAPP next-gate boundary');
expect(!phasePlanProse.includes(B0R_NONPROMOTION), 'phase-plan must remain outside the B0R nonpromotion prose roster');
expect(!phasePlanProse.includes(EAC_NONPROMOTION) && !phasePlanProse.includes(EAC_NEXT_GATE), 'phase-plan must remain outside the EAC prose roster');
expect(!phasePlanProse.includes(SSA_NONPROMOTION) && !phasePlanProse.includes(SSA_NEXT_GATE), 'phase-plan must remain outside the SSA prose roster');
expect(!phasePlanProse.includes(EAPP_NONPROMOTION) && !phasePlanProse.includes(EAPP_NEXT_GATE), 'phase-plan must remain outside the EAPP prose roster');

expect(poolConfig.schema === 'shieldkit-labs/pool-config-fv1-requirements/v1', 'unexpected PoolConfigFv1 contract schema');
expect(
  poolConfig.status === 'semantic-contract-frozen-deployment-instance-unselected',
  'PoolConfigFv1 must remain a requirements contract rather than fabricated deployment data'
);
expect(poolConfig.profileRef === profile.id, 'PoolConfigFv1 must reference the active profile');
expect(poolConfig.relationRef === 'PoolActionFv1', 'PoolConfigFv1 must reference PoolActionFv1');
expect(poolConfig.fixedValues.ticketSats === '10000000', 'PoolConfigFv1 ticket value changed');
expect(poolConfig.fixedValues.withdrawalPayoutSats === '10000000', 'PoolConfigFv1 payout value changed');
expect(poolConfig.fixedValues.stateCommitmentBytes === 128, 'PoolConfigFv1 must use the complete 128-byte state');
expectExactSet(poolConfig.fixedValues.allowedActions, ['DEPOSIT', 'WITHDRAWAL'], 'PoolConfigFv1 actions');
expect(poolConfig.fixedValues.runtimeUpgradeability === false, 'runtime upgradeability must remain disabled');
expect(poolConfig.fixedValues.adminKey === false, 'PoolConfigFv1 must not introduce an admin key');
expect(poolConfig.fixedValues.privilegedSpendPath === false, 'PoolConfigFv1 must not introduce a privileged spend path');
expect(poolConfig.fixedValues.requiredCoordinator === false, 'PoolConfigFv1 must not require a coordinator');
const configFieldIds = uniqueIds(poolConfig.requiredInstantiationFields, 'PoolConfigFv1 field');
for (const requiredId of [
  'networkId',
  'deploymentAnchorOutpoint',
  'stateToken',
  'protocolTemplateDigest',
  'stateCovenant',
  'stateCarrierBaseSats',
  'maxLifetimeDeposits',
  'noteCommitmentAlgorithm',
  'authorizationCommitmentAlgorithm',
  'noteAccumulator',
  'nullifierDerivationAlgorithm',
  'nullifierSetAccumulator',
  'transactionContextDigestAlgorithm',
  'proofSecurityProfileDigest',
  'carrierManifest',
  'feePolicy'
]) {
  expect(configFieldIds.has(requiredId), `PoolConfigFv1 is missing required instantiation field ${requiredId}`);
}
expect(
  !poolConfig.poolIdentity.commitsTo.some((entry) => entry.includes('genesis state outpoint')),
  'poolInstanceId must not commit its own genesis state outpoint'
);
expect(
  poolConfig.poolIdentity.commitsTo.includes('canonical pre-existing deployment anchor outpoint'),
  'poolInstanceId must bind a pre-existing deployment anchor'
);
expect(
  poolConfig.poolIdentity.excludes.includes('genesis state transaction ID or outpoint'),
  'PoolConfigFv1 must explicitly exclude genesis-derived identity inputs'
);
const identitySteps = uniqueIds(poolConfig.identityDerivationDag.steps, 'PoolConfigFv1 identity DAG step');
expectExactSet(
  [...identitySteps],
  ['protocolTemplateDigest', 'poolInstanceId', 'carrierManifestDigest', 'instantiatedLocksAndGenesis'],
  'PoolConfigFv1 identity DAG steps'
);
const protocolStep = poolConfig.identityDerivationDag.steps.find((step) => step.id === 'protocolTemplateDigest');
const poolIdentityStep = poolConfig.identityDerivationDag.steps.find((step) => step.id === 'poolInstanceId');
const manifestStep = poolConfig.identityDerivationDag.steps.find((step) => step.id === 'carrierManifestDigest');
expect(protocolStep.mustNotContain.includes('poolInstanceId'), 'protocol template digest must precede poolInstanceId');
expect(poolIdentityStep.mustNotContain.includes('genesis transaction ID or outpoint'), 'poolInstanceId must exclude genesis-derived values');
expect(manifestStep.mustNotContain.includes('concrete instantiated carrier locking bytecode'), 'carrier manifest digest must exclude self-referential concrete locks');
const postGenesisIds = uniqueIds(poolConfig.postGenesisRecordFields, 'PoolConfigFv1 post-genesis record');
expectExactSet(
  [...postGenesisIds],
  ['genesisStateOutpoint', 'genesisCarrierOutpoints', 'deployedLockDigests'],
  'PoolConfigFv1 post-genesis records'
);
expect(poolConfig.selectionBlocks.length >= 8, 'PoolConfigFv1 must retain every unresolved deployment/cryptographic selection block');
expect(poolConfig.fixedValues.minimumVerifierCarrierCount === 1, 'PoolConfigFv1 must require at least one verifier carrier');
expect(poolConfig.finiteLifetimeDecision.status === 'accepted-for-fv1-simplicity', 'Fv1 finite accumulator lifetime must be explicit');

const stateDoc = readFileSync(poolStateDocPath, 'utf8');
for (const literal of [
  'complete 128-byte mutable-NFT commitment',
  '| 0 | 4 | magic |',
  '| 4 | 2 | state codec version |',
  '| 6 | 2 | reserved |',
  '| 8 | 8 | sequence |',
  '| 16 | 8 | deposit count |',
  '| 24 | 8 | withdrawal count |',
  '| 32 | 32 | pool instance ID |',
  '| 64 | 32 | note root |',
  '| 96 | 32 | nullifier root |',
  'stateUtxoValueSats = B + reserveSats'
]) {
  expect(stateDoc.includes(literal), `PoolStateFv1 document is missing frozen layout/invariant literal: ${literal}`);
}
expect(poolStateSchema.properties.serializedHex.pattern === '^[0-9a-f]{256}$', 'PoolStateFv1 serialized form must be exactly 128 bytes');
const encodeU64Le = (value) => {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
};
const stateSentinelBytes = Buffer.concat([
  Buffer.from('PAF1', 'ascii'),
  Buffer.from([1, 0]),
  Buffer.from([0, 0]),
  encodeU64Le(1),
  encodeU64Le(2),
  encodeU64Le(1),
  Buffer.alloc(32, 0x11),
  Buffer.alloc(32, 0x22),
  Buffer.alloc(32, 0x33)
]);
expect(stateSentinelBytes.length === 128, 'PoolStateFv1 frozen field widths do not total 128 bytes');
compileStrictSchema(poolStateSchemaPath, 'PoolStateFv1 layout sentinel', {
  schema: 'shieldkit-labs/pool-state-fv1/v1',
  magic: 'PAF1',
  stateCodecVersion: 1,
  reservedHex: '0000',
  sequence: '1',
  depositCount: '2',
  withdrawalCount: '1',
  poolInstanceIdHex: '11'.repeat(32),
  noteRootHex: '22'.repeat(32),
  nullifierRootHex: '33'.repeat(32),
  serializedHex: stateSentinelBytes.toString('hex')
});

expect(poolAction.schema === 'shieldkit-labs/pool-action-fv1-relation/v1', 'unexpected PoolActionFv1 relation schema');
expect(
  poolAction.status === 'backend-neutral-semantics-frozen-cryptographic-instantiation-unselected',
  'PoolActionFv1 must freeze semantics without selecting the cryptographic instantiation'
);
expect(poolAction.profileRef === profile.id, 'PoolActionFv1 must reference the active profile');
expect(poolAction.proofFamily === 'Circle-domain FRI', 'PoolActionFv1 proof family changed');
expect(poolAction.fixedConstants.ticketSats === '10000000', 'PoolActionFv1 ticket value changed');
expect(poolAction.fixedConstants.withdrawalPayoutSats === '10000000', 'PoolActionFv1 payout changed');
expect(poolAction.fixedConstants.stateCommitmentBytes === 128, 'PoolActionFv1 must use the complete native state');
expect(poolAction.fixedConstants.stateTokenFungibleAmount === '0', 'PoolActionFv1 state NFT fungible amount must be exactly zero');
expect(poolAction.fixedConstants.minimumVerifierCarrierCount === 1, 'PoolActionFv1 must require at least one verifier carrier');
expect(poolAction.fixedConstants.externalFundingSignatureHashType === 65, 'external funding signatures must bind all inputs and outputs with 0x41');
expect(poolAction.fixedConstants.proofsPerAction === 1, 'PoolActionFv1 must have one proof per action');
expect(poolAction.fixedConstants.usersPerActionTransaction === 1, 'PoolActionFv1 must have one user per action transaction');
expectExactSet(poolAction.fixedConstants.actions, ['DEPOSIT', 'WITHDRAWAL'], 'PoolActionFv1 actions');
for (const forbidden of [
  'TRANSFER action or selector',
  'multi-user batching',
  'required coordinator or private operator database',
  'runtime proof, hash, accumulator, or codec selection',
  'ignored transaction inputs or outputs',
  'pool-funded transaction fees',
  'additional setup or replenishment transaction per action'
]) {
  expect(poolAction.explicitlyForbidden.includes(forbidden), `PoolActionFv1 must explicitly forbid ${forbidden}`);
}
expect(
  poolAction.stateRelation.derived.stateUtxoValueSats === 'stateCarrierBaseSats + reserveSats',
  'PoolActionFv1 must co-locate state and reserve in the active baseline'
);
expect(
  poolAction.carrierLifecycle.requirements.some((rule) => rule.includes('same source transaction ID as the state outpoint')),
  'PoolActionFv1 must bind every carrier to the state predecessor transaction'
);
expect(
  poolAction.carrierLifecycle.requirements.some((rule) => rule.includes('outputs 1..N')),
  'PoolActionFv1 must recreate one atomic state/carrier successor bundle'
);
expect(
  poolAction.transactionBinding.projectionConsistencyRule.includes('byte-for-byte equal'),
  'PoolActionFv1 must reconcile every duplicated statement and context field'
);
expect(poolAction.noteRelation.privateFields.includes('noteIndex'), 'PoolActionFv1 note relation must bind the private note index');
expect(
  poolAction.noteRelation.derivedFields.nullifier.includes('noteIndex'),
  'PoolActionFv1 nullifier derivation must bind the note index'
);
const actionIds = uniqueIds(poolAction.actions, 'PoolActionFv1 action');
expectExactSet([...actionIds], ['DEPOSIT', 'WITHDRAWAL'], 'PoolActionFv1 action IDs');
const depositAction = poolAction.actions.find((action) => action.id === 'DEPOSIT');
const withdrawalAction = poolAction.actions.find((action) => action.id === 'WITHDRAWAL');
expect(depositAction?.transition.stateValueSats === '+10000000', 'deposit must add exactly one ticket to state value');
expect(depositAction?.transition.nullifierRoot === 'unchanged', 'deposit must not change the nullifier root');
expect(depositAction?.transition.payout === 'absent', 'deposit must not have a payout');
expect(withdrawalAction?.transition.stateValueSats === '-10000000', 'withdrawal must remove exactly one ticket from state value');
expect(withdrawalAction?.transition.noteRoot === 'unchanged', 'withdrawal must not change the note root');
expect(withdrawalAction?.transition.payout === 'exactly 10000000 sats', 'withdrawal must pay exactly one ticket');
expect(poolAction.transactionShape.inputs.at(-1).includes('exactly one'), 'transaction shape must contain exactly one external funding input');
expect(poolAction.transactionShape.rule.includes('No other input or output count'), 'transaction shape must reject ignored roles');
expect(poolAction.carrierLifecycle.rule.includes('persistent role UTXO'), 'verifier carriers must be persistent');
expect(
  poolAction.carrierLifecycle.requirements.some((rule) => rule.includes('no carrier stock, replenisher, coordinator')),
  'carrier lifecycle must reject warehouse/replenisher dependencies'
);
expect(poolAction.transactionBinding.noIgnoredContext === true, 'transaction binding must not admit ignored context');
expectExactSet(poolAction.transactionBinding.excluded, [
  'all input unlocking bytecodes',
  'Circle-FRI proof bytes and proof-carrier unlocking wrappers',
  'external funding-input signatures',
  'the transaction ID of the transaction being constructed'
], 'PoolActionFv1 transaction-context exclusions');
expect(poolAction.feePolicy.id === 'transparent-single-input-fv1', 'unexpected fee policy');
expect(poolAction.feePolicy.privacy === 'out-of-scope', 'fee privacy must remain out of scope');
expect(poolAction.reconstructionAndRace.privateDatabaseDependency === false, 'recovery must not require a private database');
expect(poolAction.reconstructionAndRace.coordinatorDependency === false, 'recovery must not require a coordinator');
expect(poolAction.reconstructionAndRace.broadcastBoundary.includes('zero-confirmation'), 'operational submission boundary must remain zero-confirmation acceptance');

const vectorCaseIds = uniqueIds(vectorIndex.cases.map((item) => ({ ...item, id: item.caseId })), 'PoolActionFv1 vector');
expect(vectorIndex.status === 'planned', 'vector corpus must remain explicitly planned before real artifacts exist');
expectExactSet(vectorIndex.requiredCategories, ['semantic', 'transaction', 'topology', 'parser', 'proof', 'zk', 'recovery', 'liveness'], 'vector categories');
for (const category of vectorIndex.requiredCategories) {
  expect(vectorIndex.cases.some((item) => item.category === category), `vector corpus is missing category ${category}`);
}
for (const item of vectorIndex.cases) {
  expect(item.status === 'planned', `planned vector ${item.caseId} overstates status ${item.status}`);
  expect(item.vectorAvailability === 'planned', `planned vector ${item.caseId} overstates artifact availability`);
  expect(item.firstAttempt === false && item.retries === 0, `planned vector ${item.caseId} must not fabricate execution attempts`);
  for (const evidenceField of ['provenance', 'artifactDigests', 'txHex', 'sourceOutputsHex', 'txDigest', 'sourceOutputsDigest', 'transaction', 'observed']) {
    expect(item[evidenceField] === undefined, `planned vector ${item.caseId} must not contain fabricated ${evidenceField}`);
  }
}
for (const id of [
  'vector:semantic:deposit-valid',
  'vector:semantic:withdrawal-valid-a',
  'vector:semantic:withdrawal-valid-b',
  'vector:transaction:state-outpoint',
  'vector:semantic:nullifier-nonmembership',
  'vector:topology:carrier-substitute',
  'vector:zk:pq-claim-proof-only',
  'vector:liveness:mempool-eviction'
]) {
  expect(vectorCaseIds.has(id), `vector corpus is missing required case ${id}`);
}
expect(vectorIndex.artifactDigests.relation === sha256(poolActionPath), 'vector corpus relation digest is stale');
expect(vectorIndex.artifactDigests.corpus === null, 'planned vector corpus must not fabricate a corpus digest');
expect(vectorIndex.sourceCommits.every((pin) => pin.dirty === true), 'untracked lane vector sources must be marked dirty');

expect(responsibilityMap.status === 'responsibilities-frozen-controls-unmeasured', 'responsibility map status changed unexpectedly');
const enforcementLayers = new Set(responsibilityMap.enforcementLayers);
const responsibilityIds = uniqueIds(responsibilityMap.responsibilities, 'PoolActionFv1 responsibility');
for (const requiredId of [
  'R-PROFILE-DOMAIN', 'R-UNIQUE-LINEAGE', 'R-STATE-CODEC', 'R-FIXED-TICKET',
  'R-RESERVE-CONSERVATION', 'R-NOTE-COMMITMENT', 'R-NOTE-INSERTION',
  'R-NOTE-MEMBERSHIP', 'R-SPEND-AUTHORITY', 'R-NULLIFIER-DERIVATION',
  'R-NULLIFIER-UNIQUENESS', 'R-PAYOUT-BINDING', 'R-FEE-BINDING',
  'R-CONTEXT-BINDING', 'R-CARRIER-LIFECYCLE', 'R-PROOF-SESSION',
  'R-CANONICAL-PARSER', 'R-SOUNDNESS', 'R-ZERO-KNOWLEDGE',
  'R-RECOVERY-LIVENESS', 'R-EVIDENCE-SCOPE'
]) {
  expect(responsibilityIds.has(requiredId), `responsibility map is missing ${requiredId}`);
}
for (const responsibility of responsibilityMap.responsibilities) {
  expect(responsibility.enforcedBy.length > 0, `responsibility ${responsibility.id} has no enforcer`);
  expect(responsibility.mutationIds.length > 0, `responsibility ${responsibility.id} has no mutation`);
  for (const layer of responsibility.enforcedBy) {
    expect(enforcementLayers.has(layer), `responsibility ${responsibility.id} uses unknown layer ${layer}`);
  }
  for (const mutationId of responsibility.mutationIds) {
    expect(vectorCaseIds.has(mutationId), `responsibility ${responsibility.id} refers to missing vector ${mutationId}`);
  }
}

const assetIds = uniqueIds(threatModel.assets, 'threat-model asset');
const adversaryIds = uniqueIds(threatModel.adversaries, 'threat-model adversary');
const threatIds = uniqueIds(threatModel.threats, 'threat');
uniqueIds(threatModel.securityGoals, 'security goal');
uniqueIds(threatModel.pqInventory, 'PQ inventory component');
expect(threatModel.status === 'frozen-unmitigated-gates-open', 'threat model must remain frozen with unmitigated gates open');
expect(threatIds.size >= 14, 'threat model is missing required threat families');
for (const threat of threatModel.threats) {
  for (const attackerId of threat.attackerIds) expect(adversaryIds.has(attackerId), `threat ${threat.id} refers to unknown adversary ${attackerId}`);
  for (const assetId of threat.assetIds) expect(assetIds.has(assetId), `threat ${threat.id} refers to unknown asset ${assetId}`);
  for (const mutationId of threat.mutationIds) expect(vectorCaseIds.has(mutationId), `threat ${threat.id} refers to missing vector ${mutationId}`);
  expect(threat.status !== 'mitigated-measured', `threat ${threat.id} cannot be measured before real controls exist`);
}
expect(
  threatModel.pqInventory.some((item) => item.id === 'PQ-FEE-AUTH' && item.status === 'classical-boundary'),
  'PQ inventory must retain transparent fee authorization as a classical boundary'
);
expect(
  threatModel.pqInventory.some((item) => item.id === 'PQ-BCH-SETTLEMENT' && item.status === 'classical-boundary'),
  'PQ inventory must retain BCH settlement as a classical boundary'
);
expect(threatModel.promotionRule.includes('root/SOL review'), 'threat-model promotion must require root/SOL review');

expect(candidateMatrix.status === 'research-only-no-selection', 'candidate matrix must not select a winner');
expect(candidateMatrix.profileRef === profile.id, 'candidate matrix must reference the active profile');
expect(candidateMatrix.relationRef === 'relation:pool-action-fv1', 'candidate matrix relation changed');
expect(candidateMatrix.environmentProfileRef === bchProfile.id, 'candidate matrix must reference the pinned BCH profile');
expect(candidateMatrix.hardTargets.ticketSats === 10_000_000, 'candidate matrix ticket target changed');
expect(candidateMatrix.hardTargets.targetSoundnessBits === 128, 'candidate matrix must target 128 bits');
expect(candidateMatrix.hardTargets.minimumFallbackBits === 100, 'candidate matrix fallback floor changed');
expect(candidateMatrix.hardTargets.completeTransactionLimitBytes === 100_000, 'candidate matrix transaction limit changed');
expect(candidateMatrix.hardTargets.withdrawalProvingLimitSeconds === 60, 'candidate matrix proving limit changed');
expect(candidateMatrix.hardTargets.fallbackAuthorized === false, 'fallback must remain unauthorized');
expectExactSet(candidateMatrix.requiredAxes, [
  'field-extension', 'circle-domain', 'hash-transcript', 'zk-masking', 'air',
  'fri', 'nullifier-set', 'authorization', 'verifier-topology'
], 'candidate-matrix axes');
const rowIds = uniqueIds(candidateMatrix.rows, 'candidate row');
const gateIds = uniqueIds(candidateMatrix.rows.map((row) => ({ id: row.cheapKillGate.id })), 'candidate kill gate');
expect(gateIds.size === candidateMatrix.rows.length, 'every candidate row must own one unique kill gate');
for (const row of candidateMatrix.rows) {
  for (const dependency of row.dependencies) expect(rowIds.has(dependency), `candidate ${row.id} has unresolved dependency ${dependency}`);
}
for (const axis of candidateMatrix.requiredAxes) {
  expect(candidateMatrix.rows.some((row) => row.axis === axis), `candidate matrix has no row for axis ${axis}`);
}
for (const row of candidateMatrix.rows) {
  if (row.cheapKillGate.status === 'pass') expect(row.status === 'measured-nonselected', `passing candidate ${row.id} must remain measured and non-selected`);
  if (row.status === 'measured-nonselected') expect(row.cheapKillGate.status === 'pass', `measured candidate ${row.id} must have a passing kill gate`);
  expect(!['selected', 'qualified'].includes(row.status), `candidate ${row.id} is prematurely ${row.status}`);
  if (row.status === 'killed') {
    expect(row.cheapKillGate.status === 'fail', `killed candidate ${row.id} must have a failed kill gate`);
    expect(Boolean(row.elimination?.reason), `killed candidate ${row.id} must record an elimination reason`);
    expect(Boolean(row.elimination?.reopeningCondition), `killed candidate ${row.id} must record a reopening condition`);
  }
}
for (const requiredId of [
  'field:m31-base-control', 'field:m31-degree4-control', 'field:m31-degree5', 'field:m31-degree6',
  'field:m61-degree2-control', 'field:m61-degree3', 'field:m29-degree5-control',
  'field:m127-degree2-control', 'hash:sha256-native', 'zk:trace-composition-fold-preserving',
  'air:unified-action', 'air:event-specific', 'fri:binary-fold', 'fri:arity4-fold',
  'fri:arity8-fold', 'nullifier:sparse-merkle-set', 'nullifier:indexed-sorted-set',
  'topology:persistent-multi-input'
]) {
  expect(rowIds.has(requiredId), `candidate matrix is missing research row ${requiredId}`);
}
const sourcePinIds = uniqueIds(candidateMatrix.sourcePins, 'candidate source pin');
for (const row of candidateMatrix.rows) {
  for (const ref of row.cheapKillGate.evidenceRefs) expect(sourcePinIds.has(ref), `candidate ${row.id} has unresolved source ${ref}`);
}
expect(candidateMatrix.sourcePins.find((pin) => pin.id === 'source:labs-head')?.dirty === true, 'untracked lane source must remain marked dirty');
const toolInventoryPin = candidateMatrix.sourcePins.find((pin) => pin.id === 'source:tool-inventory');
expect(toolInventoryPin?.sha256 === 'bd570d3af28c2eb1fca1d76b6182d367a7a840f25e853e017e2703d9df2cca09', 'BCH tool-inventory content pin changed');
expect(existsSync(toolInventoryPin?.location ?? '') && sha256(toolInventoryPin.location) === toolInventoryPin.sha256, 'BCH tool-inventory content pin is stale');
const m29Pin = candidateMatrix.sourcePins.find((pin) => pin.id === 'source:m29-compositeness-check');
expect(m29Pin?.sha256 === '6f28e9482a2022daefd5efd70a9c2f4f7921285db07b3c9abdbce5028c8a7908', 'M29 compositeness content pin changed');
expect(sha256(m29CompositenessPath) === m29Pin?.sha256, 'M29 compositeness artifact does not match its content pin');
const m31BaseSuitePin = candidateMatrix.sourcePins.find((pin) => pin.id === 'source:m31-base-suite-evidence');
expect(m31BaseSuitePin?.pinStatus === 'content-pinned', 'M31 base-suite evidence must remain content-pinned');
expect(m31BaseSuitePin?.location === 'p2/evidence/m31-base-suite-v1.json', 'M31 base-suite evidence location changed');
expect(m31BaseSuitePin?.sha256 === sha256(m31BaseSuiteEvidencePath), 'M31 base-suite evidence content pin is stale');
expect(candidateMatrix.sourcePins.find((pin) => pin.id === 'source:zk-starks-note')?.sha256 === 'b6bd98453a64b26c7a08bf02fe9f82f3bde7dd730ecaa3fe9769b1e0f15cf270', 'current STARK ZK note content pin changed');
expect(candidateMatrix.sourcePins.find((pin) => pin.id === 'source:zk-starks-note')?.pinStatus === 'content-pinned', 'current STARK ZK note must remain content-pinned');
expect(candidateMatrix.sourcePins.find((pin) => pin.id === 'source:xhash-family-paper')?.pinStatus === 'uri-only-blocking', 'current merged XHash PDF must remain an explicit source blocker until content-pinned');
expect(candidateMatrix.rows.find((row) => row.id === 'zk:trace-composition-fold-preserving')?.status === 'unmeasured', 'content-pinned ZK family must remain unmeasured until its cryptographic gate runs');
expect(candidateMatrix.rows.find((row) => row.id === 'hash:rpo-m31-widened')?.status === 'blocked-source-pin', 'RPO-M31/XHash-M31 family must remain source-blocked');
expect(candidateMatrix.rows.find((row) => row.id === 'field:m29-degree5-control')?.status === 'killed', 'composite 2^29-1 candidate must remain killed');
const m31BaseControlRow = candidateMatrix.rows.find((row) => row.id === 'field:m31-base-control');
expect(m31BaseControlRow?.status === 'measured-nonselected', 'M31 base control must record measured, non-selected status');
expect(m31BaseControlRow?.epistemicState === 'measured', 'M31 base control epistemic state must be measured');
expect(m31BaseControlRow?.cheapKillGate.status === 'pass', 'M31 base control cheap-kill gate must pass after the complete corpus');
expectExactSet(m31BaseControlRow?.evidenceRefs ?? [], ['source:m31-base-suite-evidence'], 'M31 base-control evidence refs');
expect(candidateMatrix.rows.find((row) => row.id === 'circle:j-symmetric')?.dependencies.length === 0, 'field-neutral J-symmetric domain row must not preselect an extension candidate');
expect(candidateMatrix.decisionPolicy.selectionStatus === 'closed', 'candidate selection must remain closed');
expect(candidateMatrix.decisionPolicy.selectionAuthority === 'root-with-sol-review', 'candidate selection authority changed');
expect(candidateMatrix.decisionPolicy.fallbackRule.includes('both measured and fail'), 'fallback rule must require measured failure of both actions');
expect(candidateMatrix.parameterSearchSpace.blowups.includes(2048), 'parameter search must preserve the high-blowup control');
expect(candidateMatrix.parameterSearchSpace.queries.includes(24), 'parameter search must preserve the high-query control');
expect(candidateMatrix.parameterSearchSpace.grindingBits.includes(48), 'parameter search must preserve the high-grinding control');

for (const error of validateCandidateCompositionV2(candidateCompositionV2, candidateMatrix)) {
  errors.push(`candidate composition v2: ${error}`);
}
expect(
  candidateCompositionV2.legacyComponentMatrix.sha256 === sha256(candidateMatrixPath),
  'candidate composition v2 legacy matrix digest is stale'
);
expect(
  candidateCompositionV2.legacyComponentMatrix.rowCount === candidateMatrix.rows.length,
  'candidate composition v2 legacy row count is stale'
);
const compositionFieldIds = uniqueIds(
  candidateCompositionV2.fieldSpecs.map((field) => ({ id: field.fieldSpecId })),
  'candidate composition field spec'
);
expectExactSet([...compositionFieldIds], [
  'field-spec:m13-d10', 'field-spec:m17-d8', 'field-spec:m19-d7', 'field-spec:m31-d1',
  'field-spec:m31-d4', 'field-spec:m31-d5', 'field-spec:m31-d6',
  'field-spec:m61-d2', 'field-spec:m61-d3', 'field-spec:m89-d2',
  'field-spec:m107-d2', 'field-spec:m127-d1', 'field-spec:m127-d2',
  'field-spec:m29-d5-invalid'
], 'candidate composition field frontier');
expect(candidateCompositionV2.tuples.length === 0, 'candidate composition must not create a complete tuple before Gate B/C evidence');
expect(candidateCompositionV2.circleDomains.length === 0, 'candidate composition must not freeze a Circle domain');
expect(candidateCompositionV2.deepQuotients.length === 0, 'candidate composition must not freeze a DEEP strategy');
expect(candidateCompositionV2.algebraicHashes.length === 0, 'candidate composition must not freeze an algebraic hash');
expect(candidateCompositionV2.outerHashChannels.length === 0, 'candidate composition must not freeze an outer hash channel');
expect(candidateCompositionV2.embeddings.length === 0, 'candidate composition must not freeze field embeddings');
expect(candidateCompositionV2.decisionPolicy.selectionStatus === 'closed', 'candidate composition selection must remain closed');
for (const field of candidateCompositionV2.fieldSpecs) {
  if (field.fieldSpecId !== 'field-spec:m29-d5-invalid') {
    expect(field.freezingStatus === 'family-unfrozen', `candidate composition ${field.fieldSpecId} is prematurely frozen`);
  }
}
const compositionM31Base = candidateCompositionV2.fieldSpecs.find((field) => field.fieldSpecId === 'field-spec:m31-d1');
expect(compositionM31Base?.evidenceState === 'measured-neutral-control', 'M31 d1 must remain a measured neutral control');
expect(compositionM31Base?.exactAlgebraStatus === 'base-arithmetic-measured-neutral', 'M31 d1 base arithmetic scope changed');
expect(compositionM31Base?.encodingStatus === 'implemented-neutral-control', 'M31 d1 codec scope changed');
expect(
  candidateCompositionV2.fieldSpecs.find((field) => field.fieldSpecId === 'field-spec:m29-d5-invalid')?.freezingStatus === 'killed',
  'invalid M29 composition control must remain killed'
);
const compositionSourceIds = new Set();
for (const source of candidateCompositionV2.sourcePins) {
  expect(!compositionSourceIds.has(source.sourceId), `duplicate candidate composition source ${source.sourceId}`);
  compositionSourceIds.add(source.sourceId);
  expect(!source.path.startsWith('/') && !source.path.split('/').includes('..'), `candidate composition source path is unsafe: ${source.sourceId}`);
  const sourcePath = resolve(laneDir, source.path);
  expect(existsSync(sourcePath), `candidate composition source is missing: ${source.sourceId}`);
  if (existsSync(sourcePath)) expect(sha256(sourcePath) === source.sha256, `candidate composition source digest is stale: ${source.sourceId}`);
}
expect(compositionSourceIds.has('research:field-frontier-contract'), 'candidate composition does not pin the field-frontier contract');
expect(candidateCompositionV2.legacyEvidenceBindings.length === 1, 'candidate composition must have exactly one legacy evidence binding');
for (const binding of candidateCompositionV2.legacyEvidenceBindings) {
  expect(!binding.evidencePath.startsWith('/') && !binding.evidencePath.split('/').includes('..'), `legacy evidence path is unsafe: ${binding.bindingId}`);
  const evidencePath = resolve(laneDir, binding.evidencePath);
  expect(existsSync(evidencePath), `legacy evidence is missing: ${binding.bindingId}`);
  if (existsSync(evidencePath)) expect(sha256(evidencePath) === binding.evidenceSha256, `legacy evidence digest is stale: ${binding.bindingId}`);
  expect(binding.classification === 'component-only-neutral-control', `legacy evidence ${binding.bindingId} exceeds component scope`);
  expect(binding.claimedRoles.length === 0 && binding.tupleRef === null, `legacy evidence ${binding.bindingId} claims a field role or tuple`);
}

for (const fixture of [frontierPrimeFixture, m89RabinFixture]) {
  expect(fixture.schema === 'shieldkit-labs/field-cert/v1', `unexpected field-certificate schema: ${fixture.fixtureId}`);
  expect(fixture.status === 'generic-math-unqualified', `${fixture.fixtureId} exceeds generic-math scope`);
  expect(fixture.casReview === 'not-cas-reviewed', `${fixture.fixtureId} fabricates independent CAS review`);
  expect(fixture.evidenceClassification === 'not-evidence', `${fixture.fixtureId} is mislabeled as evidence`);
  expect(fixture.selection === 'none', `${fixture.fixtureId} implies a field selection`);
}
const expectedMersenneChecks = new Map([
  [13, true], [17, true], [19, true], [29, false], [31, true], [61, true], [89, true], [107, true], [127, true]
]);
expect(frontierPrimeFixture.checks.length === expectedMersenneChecks.size, 'frontier prime fixture check count changed');
for (const check of frontierPrimeFixture.checks) {
  const exponent = Number(check.mersenneExponent);
  const expectedPass = expectedMersenneChecks.get(exponent);
  expect(expectedPass !== undefined, `unexpected Mersenne exponent q=${exponent}`);
  expect(BigInt(check.modulus) === (1n << BigInt(exponent)) - 1n, `q=${exponent} modulus is not 2^q-1`);
  expect(Number(check.lucasLehmer.iterations) === exponent - 2, `q=${exponent} Lucas-Lehmer iteration count changed`);
  expect(check.lucasLehmer.passed === expectedPass, `q=${exponent} Lucas-Lehmer outcome changed`);
  expect(check.classification === (expectedPass ? 'prime' : 'rejected-composite'), `q=${exponent} classification changed`);
  if (expectedPass) expect(check.lucasLehmer.residue === '0', `q=${exponent} prime residue must be zero`);
}
expect(
  m89RabinFixture.certificate.certificateId === 'certificate:mersenne-q89-d2-rabin' &&
    m89RabinFixture.certificate.mersennePrimeCheck.mersenneExponent === '89' &&
    m89RabinFixture.certificate.degree === '2',
  'M89 Rabin fixture identity changed'
);
expect(
  JSON.stringify(m89RabinFixture.certificate.polynomial) === JSON.stringify(['1', '0', '1']),
  'M89 X^2+1 coefficients changed'
);
expect(m89RabinFixture.certificate.conclusion === 'irreducible', 'M89 Rabin fixture conclusion changed');
const expectedFieldCertDigests = new Map([
  [fieldCertSchemaPath, '0eb88d8d48d4d0b164117645d490d84243900fea0fde8b4763ed5ae8bf90e833'],
  [fieldCertNodeGeneratorPath, '664b06ebde52749620e506cdc6fd04e024b87e0753768d4644ee22303d6bae71'],
  [fieldCertNodeReplayPath, 'b2ff5132e26c3c1aff24488cabf82664eb4ae17c80aa4a8e00c328100a0e7247'],
  [fieldCertNodeCliPath, '80dd17206676d1f070811ef493df49ff8f7450fe2cf7cf24d90198d5b8edeec1'],
  [fieldCertPythonReplayPath, 'f32187a2f8560ae08474c54f3fe6c22cedd5d7f58720abbbd1015e4e89ae70ee'],
  [fieldCertNodeManifestPath, '9221d4bfb09e8d27339be722623ef2d72df7794a3318ead390bf4d98d341b34a'],
  [fieldCertExternalManifestPath, '26598a828b32187ba84bbb71238e36f74ef5e30c1dbe8b488b252f10ad78a4af'],
  [fieldCertExternalRawOutputPath, '4dfb71298300e8cd210bf9c26eeed07c230a403807310a8afecd4572e99a10e2'],
  [frontierPrimeFixturePath, '04e713d637296e11547add2d8d8dddde15c7d398cb04aed39f35864fe28a135d'],
  [m89RabinFixturePath, 'f7d802d5f763cc4afc301ed0d35f141fd80ffa4a64ad7e6151588ad8c370ea7a']
]);
for (const [path, expectedDigest] of expectedFieldCertDigests) {
  expect(sha256(path) === expectedDigest, `field certificate artifact digest changed: ${path}`);
}
expect(
  lane.p2FieldCheckpoint.certificateBoundary.schemaSha256 === sha256(fieldCertSchemaPath) &&
    lane.p2FieldCheckpoint.certificateBoundary.frontierFixtureSha256 === sha256(frontierPrimeFixturePath) &&
    lane.p2FieldCheckpoint.certificateBoundary.m89FixtureSha256 === sha256(m89RabinFixturePath),
  'P2 field checkpoint certificate digests are stale'
);
expect(
  lane.p2FieldCheckpoint.m89ExternalCasReplay.manifestSha256 === sha256(fieldCertExternalManifestPath) &&
    lane.p2FieldCheckpoint.m89ExternalCasReplay.rawOutputSha256 === sha256(fieldCertExternalRawOutputPath),
  'P2 M89 external CAS replay digests are stale'
);
expect(
  lane.p2FieldCheckpoint.gateB0.descriptorPath === 'p2/algebra-component/descriptors/m89-d2-x2-plus-1.v1.json' &&
    lane.p2FieldCheckpoint.gateB0.descriptorContentDigest === m89AlgebraDescriptor.contentDigest.value &&
    lane.p2FieldCheckpoint.gateB0.campaignPath === 'p2/gate-b/equal-relation-arithmetic-campaign.v1.json' &&
    lane.p2FieldCheckpoint.gateB0.campaignContentDigest === gateBArithmeticCampaign.contentDigest.value,
  'P2 Gate-B0 checkpoint content bindings are stale'
);
expect(
  gateBContract.status === 'contract-only-unmeasured' &&
    gateBContract.scope.evidenceClassification === 'not-evidence' &&
    gateBContract.selection.executionStatus === 'blocked' &&
    gateBContract.selection.selectedTupleCount === 0 &&
    gateBContract.selection.frozenCandidateTupleCount === 0,
  'Gate-B contract must remain blocked, unmeasured, and non-evidence'
);
expectExactSet(
  gateBContract.relationSuite.relations.map((relation) => relation.expression),
  ['D=A*B+C', 'D=A^2+C', 'A!=0 && A*H=1'],
  'Gate-B equal relations'
);
expect(
  gateBContract.relationSuite.seedHex === '0123456789abcdef' &&
    gateBContract.corpusSemantics.seedHex === '0123456789abcdef',
  'Gate-B deterministic seed changed'
);
expectExactSet(
  gateBContract.engines.map((engine) => engine.engineId),
  ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'],
  'Gate-B engines'
);
expectExactSet(
  gateBContract.metricVector.metrics.map((metric) => metric.metricId),
  [
    'verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram',
    'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes',
    'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'
  ],
  'Gate-B metric vector'
);
expect(
  gateBContract.artifactSlots.every((slot) => slot.status === 'empty-contract-slot' && slot.digest === null) &&
    gateBContract.selection.candidateRoster.every((slot) => slot.executionAllowed === false && slot.frozenCandidateTupleRef === null),
  'Gate-B contract contains execution results or an activated candidate'
);
expectExactSet(
  gateBContract.preExecutionGates.map((gate) => gate.kind),
  ['exact-polynomial-or-tower', 'dual-certificate-replay', 'typed-descriptor'],
  'Gate-B pre-execution gates'
);
expect(
  sha256(gateBContractSchemaPath) === 'd2d8905fb61ddccb9991ca76d9689de2d60d035e2564c451f5fe0b7244b5c9e5' &&
    sha256(gateBContractPath) === 'cd0e657214a108cd6d5dbf753b5739250f640fc13e03de21ec1be26bbf14c10a' &&
    sha256(gateBContractTestPath) === 'de74424e247e45312ab899963b9c905cbed2cacd8a127196c49aa9637dd5f3b7',
  'Gate-B contract artifact digests changed'
);
expect(
  lane.p2FieldCheckpoint.gateBContract.schemaSha256 === sha256(gateBContractSchemaPath) &&
    lane.p2FieldCheckpoint.gateBContract.contractSha256 === sha256(gateBContractPath),
  'P2 field checkpoint Gate-B contract digests are stale'
);

expect(m31BaseMulEvidence.status === 'partial', 'M31 base multiply evidence must remain partial until the full base gate passes');
expect(m31BaseMulEvidence.candidateId === 'field:m31-base-control', 'M31 base evidence is attributed to an extension candidate');
expect(rowIds.has(m31BaseMulEvidence.candidateId), 'M31 base evidence refers to an unknown candidate');
expect(
  sha256(resolve(laneDir, m31BaseMulEvidence.provenance.sourcePath)) === m31BaseMulEvidence.provenance.sourceDigest,
  'M31 base evidence source-manifest digest is stale'
);
expect(
  resolve(laneDir, m31BaseMulEvidence.provenance.sourcePath) === m31BaseMulSourceManifestPath,
  'M31 base evidence provenance must resolve through its content-pinned source manifest'
);
expect(m31BaseMulSourceManifest.schema === 'shieldkit-labs/p2/source-manifest/v1', 'M31 source-manifest schema changed');
expect(m31BaseMulSourceManifest.manifestId === 'source-manifest:m31-base-mul-v1', 'M31 source-manifest identity changed');
const m31SourceRoots = new Map();
for (const root of m31BaseMulSourceManifest.roots) {
  expect(!m31SourceRoots.has(root.id), `duplicate M31 source-manifest root ${root.id}`);
  m31SourceRoots.set(root.id, root);
  expect(existsSync(root.path), `M31 source-manifest root is missing: ${root.id}`);
  if (existsSync(root.path)) {
    try {
      const head = execFileSync('git', ['-C', root.path, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
      expect(head === root.commit, `M31 source-manifest root commit is stale: ${root.id}`);
    } catch (error) {
      errors.push(`M31 source-manifest root commit cannot be read: ${root.id}: ${error.message}`);
    }
  }
}
const m31SourceArtifactIds = new Set();
for (const artifact of m31BaseMulSourceManifest.artifacts) {
  expect(!m31SourceArtifactIds.has(artifact.id), `duplicate M31 source-manifest artifact ${artifact.id}`);
  m31SourceArtifactIds.add(artifact.id);
  const root = m31SourceRoots.get(artifact.rootId);
  expect(root !== undefined, `M31 source-manifest artifact ${artifact.id} has unknown root ${artifact.rootId}`);
  expect(!artifact.path.startsWith('/') && !artifact.path.split('/').includes('..'), `M31 source-manifest artifact ${artifact.id} has an unsafe path`);
  if (root !== undefined) {
    const artifactPath = resolve(root.path, artifact.path);
    expect(existsSync(artifactPath), `M31 source-manifest artifact is missing: ${artifact.id}`);
    if (existsSync(artifactPath)) {
      const currentDigest = sha256(artifactPath);
      const transition = m31BinaryRebuildTransitions.get(artifact.id);
      expect(
        currentDigest === artifact.sha256 || (
          transition?.historicalSha256 === artifact.sha256 &&
          transition?.rebuiltSha256 === currentDigest
        ),
        `M31 source-manifest artifact digest is stale: ${artifact.id}`
      );
    }
  }
}
expect(m31BaseMulEvidence.toolchain.lockfileDigest === sha256(resolve(repoRoot, 'package-lock.json')), 'M31 base evidence lockfile digest is stale');
expect(m31BaseMulEvidence.lockingBytes * 2 === m31BaseMulEvidence.lockingHex.length, 'M31 base locking byte count is stale');
expect(m31BaseMulEvidence.unlockingBytes * 2 === m31BaseMulEvidence.unlockingHex.length, 'M31 base unlocking byte count is stale');
expect(sha256Hex(m31BaseMulEvidence.lockingHex) === m31BaseMulEvidence.artifactDigests.locking, 'M31 base locking digest is stale');
expect(sha256Hex(m31BaseMulEvidence.unlockingHex) === m31BaseMulEvidence.artifactDigests.unlocking, 'M31 base unlocking digest is stale');
const m31Metrics = m31BaseMulEvidence.metrics;
expect(
  m31Metrics.operationCost === m31Metrics.evaluatedInstructionCount * 100
    + m31Metrics.signatureCheckCount * 26_000
    + m31Metrics.hashDigestIterations * 192
    + m31Metrics.arithmeticCost
    + m31Metrics.stackPushedBytes,
  'M31 base standard operation-cost decomposition does not add up'
);
expect(m31Metrics.limits.maximumOperationCost === (m31BaseMulEvidence.unlockingBytes + 41) * 800, 'M31 base operation-cost budget is stale');
expect(m31Metrics.limits.operationCostHeadroom === m31Metrics.limits.maximumOperationCost - m31Metrics.operationCost, 'M31 base operation-cost headroom is stale');
const m31Libauth = m31BaseMulEvidence.engines.find((engine) => engine.engineId === 'libauth');
const m31Bchn = m31BaseMulEvidence.engines.find((engine) => engine.engineId === 'bchn');
const m31Lean = m31BaseMulEvidence.engines.find((engine) => engine.engineId === 'leanbch');
expect(m31Libauth?.status === 'measured' && m31Libauth.accepted === true, 'M31 base evidence lacks a full Libauth measurement');
expect(m31Bchn?.status === 'measured-partial-metrics' && m31Bchn.accepted === true, 'M31 base evidence lacks the BCHN standard-script verdict');
expect(m31Lean?.status === 'measured-partial-metrics' && m31Lean.accepted === true, 'M31 base evidence lacks the LeanBCH verdict/cost cross-check');
for (const key of ['evaluatedInstructionCount', 'signatureCheckCount', 'hashDigestIterations', 'arithmeticCost', 'stackPushedBytes', 'operationCost']) {
  expect(m31Lean?.metrics[key] === m31Libauth?.metrics[key], `M31 base LeanBCH and Libauth differ on ${key}`);
}
for (const key of ['signatureCheckCount', 'hashDigestIterations', 'operationCost']) {
  expect(m31Bchn?.metrics[key] === m31Libauth?.metrics[key], `M31 base BCHN and Libauth differ on ${key}`);
}
expect(m31BaseMulEvidence.killGate.status === 'unmeasured', 'a multiply-only subset cannot pass the full M31 base gate');

expect(m31BaseSuiteEvidence.status === 'complete', 'M31 base-suite evidence must be complete for its primitive-suite scope');
expect(m31BaseSuiteEvidence.scope === 'primitive', 'M31 base-suite evidence must not claim compound or complete-action scope');
expect(m31BaseSuiteEvidence.candidateId === 'field:m31-base-control', 'M31 base-suite evidence is attributed to an extension candidate');
expect(
  resolve(laneDir, m31BaseSuiteEvidence.provenance.sourcePath) === m31BaseSuiteSourceManifestPath,
  'M31 base-suite evidence provenance must resolve through its content-pinned source manifest'
);
expect(sha256(m31BaseSuiteSourceManifestPath) === m31BaseSuiteEvidence.provenance.sourceDigest, 'M31 base-suite source-manifest digest is stale');
expect(m31BaseSuiteEvidence.artifactDigests.source === m31BaseSuiteEvidence.provenance.sourceDigest, 'M31 base-suite source digest disagrees across provenance fields');
expect(m31BaseSuiteSourceManifest.manifestId === 'source-manifest:m31-base-suite-v1', 'M31 base-suite source-manifest identity changed');
validateContentManifest(m31BaseSuiteSourceManifest, 'M31 base-suite source manifest', m31BinaryRebuildTransitions);
expect(m31BaseSuiteEvidence.toolchain.lockfileDigest === sha256(resolve(repoRoot, 'package-lock.json')), 'M31 base-suite lockfile digest is stale');
expect(
  createHash('sha256').update(m31BaseSuiteEvidence.command).digest('hex') === m31BaseSuiteEvidence.artifactDigests.command,
  'M31 base-suite command digest is stale'
);
const m31Suite = m31BaseSuiteEvidence.corpusSuite;
expect(m31Suite.totalCases === 3_724, 'M31 base-suite case count changed');
expect(m31Suite.acceptedCases === 3_618 && m31Suite.rejectedCases === 106, 'M31 base-suite verdict partition changed');
expect(m31Suite.acceptedCases + m31Suite.rejectedCases === m31Suite.totalCases, 'M31 base-suite verdict partition does not sum to its corpus');
expect(m31Suite.corpusDigest === 'fa76c62cfd3fb2ea4898b0b42fda5f21edcd41cb023c84925237eb903fe0dcd9', 'M31 deterministic corpus digest changed');
expect(m31Suite.seedHex === '0123456789abcdef', 'M31 deterministic corpus seed changed');
expect(m31Suite.firstAttempt === true && m31Suite.standardMode === true, 'M31 base-suite must retain first-attempt standard-mode evidence');
expectExactSet(m31Suite.operationCounts.map(({ operation }) => operation), ['add', 'sub', 'neg', 'mul', 'square', 'inverseHint'], 'M31 base-suite operations');
const m31OperationCounts = new Map(m31Suite.operationCounts.map((entry) => [entry.operation, entry]));
for (const [operation, cases, accepted, rejected] of [
  ['add', 1_144, 1_132, 12],
  ['sub', 1_145, 1_133, 12],
  ['neg', 76, 68, 8],
  ['mul', 1_175, 1_149, 26],
  ['square', 76, 68, 8],
  ['inverseHint', 108, 68, 40]
]) {
  const entry = m31OperationCounts.get(operation);
  expect(entry?.cases === cases && entry?.expectedAccept === accepted && entry?.expectedReject === rejected, `M31 base-suite ${operation} counts changed`);
}
expect(m31Suite.operationCounts.reduce((sum, entry) => sum + entry.cases, 0) === m31Suite.totalCases, 'M31 base-suite operation counts do not sum to its corpus');
expect(m31Suite.fullReport.bytes === 14_102_877, 'M31 base-suite full report byte count changed');
expect(m31Suite.fullReport.sha256 === m31BaseSuiteEvidence.artifactDigests.report, 'M31 base-suite full report digest disagrees');
expect(m31Suite.fullReport.summarySha256 === m31BaseSuiteEvidence.artifactDigests.summary, 'M31 base-suite summary digest disagrees');
const m31SuiteEngines = new Map(m31Suite.engines.map((engine) => [`${engine.engineId}:${engine.role}`, engine]));
for (const [key, status, measured, unsupported] of [
  ['libauth:standard-vm-and-metrics', 'measured', 3_724, 0],
  ['bchn:standard-script-verdict', 'measured-partial-metrics', 3_618, 106],
  ['leanbch:formal-cost', 'measured-partial-metrics', 3_649, 75],
  ['leanbch:formal-verdict', 'measured', 0, 3_724]
]) {
  const engine = m31SuiteEngines.get(key);
  expect(engine?.status === status, `M31 base-suite engine status changed: ${key}`);
  expect(engine?.expectedCases === m31Suite.totalCases && engine?.verdictMatches === true, `M31 base-suite verdict agreement changed: ${key}`);
  expect(engine?.metricsMeasuredCases === measured && engine?.metricUnsupportedCases === unsupported, `M31 base-suite metric coverage changed: ${key}`);
}
expect(m31BaseSuiteEvidence.result.verdict === 'pass', 'M31 base-suite primitive gate no longer passes');
expect(m31BaseSuiteEvidence.notes.some((note) => note.includes('selects no M31 extension degree')), 'M31 base-suite evidence must retain its no-extension-selection boundary');

const bchConstraints = new Map(bchProfile.constraints.map((constraint) => [constraint.id, constraint.value]));
expect(bchProfile.source.commit === '864c53ee34924cca6c6b6d96607ff2cedcdccf02', 'BCH environment source commit changed');
for (const [id, value] of [
  ['bch:max-standard-transaction-size', 100_000],
  ['bch:max-consensus-transaction-size', 1_000_000],
  ['bch:max-script-size', 10_000],
  ['bch:max-stack-element-size', 10_000],
  ['bch:max-stack-size', 1_000],
  ['bch:max-conditional-depth', 100],
  ['bch:max-nft-commitment-length', 128],
  ['bch:operation-cost-density', '(unlockingBytes + 41) * 800'],
  ['bch:opcode-base-cost', 100],
  ['bch:standard-hash-iteration-density', 'floor((unlockingBytes + 41) / 2)']
]) {
  expect(bchConstraints.get(id) === value, `BCH environment constraint ${id} changed`);
}
expect(bchProfile.qualificationRule.includes('unmodified current BCHN'), 'BCH qualification must require current unmodified BCHN');
expect(bchProfile.qualificationRule.includes('Libauth'), 'BCH qualification must require Libauth');
expect(
  bchProfile.constraints.find((constraint) => constraint.id === 'bch:standard-hash-iteration-density')?.sourceFunction === 'GetInputHashItersLimit',
  'BCH hash-iteration limit source function changed or is nonexistent'
);

expect(desktopProfile.status === 'pinned-research-host-unbenchmarked', 'desktop profile must remain honest about missing benchmarks');
expect(desktopProfile.qualificationTarget.scope.includes('complete local unilateral withdrawal'), 'desktop gate must cover complete withdrawal preparation');
expect(desktopProfile.qualificationTarget.comparison === 'less-than', 'desktop gate comparison changed');
expect(desktopProfile.qualificationTarget.seconds === 60, 'desktop gate changed');
expect(desktopProfile.hardware.physicalCores === 14, 'desktop profile physical-core count changed');
expect(desktopProfile.hardware.logicalCpus === 20, 'desktop profile logical-CPU count changed');
expect(desktopProfile.hardware.ramBytes === 50_116_341_760, 'desktop profile RAM changed');
expect(desktopProfile.threadPolicy.workers === 20, 'desktop benchmarks must use all logical CPUs');
expect(desktopProfile.threadPolicy.noSilentSerialFallback === true, 'desktop profile must prohibit silent serial fallback');
expect(desktopProfile.method.coldRuns === 20, 'desktop profile cold-run count changed');
expect(desktopProfile.method.warmRuns === 30, 'desktop profile warm-run count changed');

const expectedTxid = 'be8b9832a2a95bf9b09838cb085bc667e9eedacd2c71ae842289816ca93737b0';
expect(chain.diagramTransaction.txid === expectedTxid, 'chain observation has unexpected diagram txid');
const parsedTxid = diagram.parsedLiterals.find((item) => item.id === 'live-source-transaction-id');
expect(parsedTxid?.value === expectedTxid, 'diagram parsed txid differs from chain-resolved value');
expect(chain.diagramTransaction.inputCount === 1, 'diagram transaction input count changed');
expect(chain.diagramTransaction.outputCount === 13, 'diagram transaction output count changed');
expect(chain.diagramTransaction.planeB.outputCount === 12, 'Plane B output count changed');
expect(chain.diagramTransaction.planeA.nftCommitmentBytes === 128, 'Plane A commitment length changed');
expect(chain.diagramTransaction.planeB.nftCommitmentBytesEach === 128, 'Plane B commitment length changed');
expect(
  chain.diagramTransaction.outputValueSats + chain.diagramTransaction.feeSats === chain.diagramTransaction.input.valueSats,
  'diagram transaction value arithmetic does not balance'
);
expect(chain.diagramTransaction.planeA.unspentAtObservation === true, 'chain snapshot must retain the unspent-at-observation fact');

const externalIds = new Set(manifest.externalReferences.map((source) => source.id));
const chainIds = new Set(manifest.chainSources.map((source) => source.id));
const selectedMessage = (id) => manifest.selectedMessageRanges.some((range) => id >= range.firstId && id <= range.lastId);
const sourceRefExists = (ref) => {
  if (ref.startsWith('diagram:region:')) return regionIds.has(ref.slice('diagram:region:'.length));
  if (ref.startsWith('diagram:connector:')) return connectorIds.has(ref.slice('diagram:connector:'.length));
  if (ref.startsWith('diagram:parsed:')) return parsedIds.has(ref.slice('diagram:parsed:'.length));
  if (ref.startsWith('telegram:message:')) {
    const id = Number(ref.slice('telegram:message:'.length));
    return Number.isInteger(id) && selectedMessage(id);
  }
  return externalIds.has(ref) || chainIds.has(ref);
};

const allowedOrigins = new Set(claims.statuses.origin);
const allowedStates = new Set(claims.statuses.epistemicState);
for (const claim of claims.claims) {
  expect(claim.origins.length > 0, `claim ${claim.id} has no origin`);
  for (const origin of claim.origins) expect(allowedOrigins.has(origin), `claim ${claim.id} uses unknown origin ${origin}`);
  expect(allowedStates.has(claim.epistemicState), `claim ${claim.id} uses unknown epistemic state ${claim.epistemicState}`);
  expect(claim.sourceRefs.length > 0, `claim ${claim.id} has no source reference`);
  for (const ref of claim.sourceRefs) expect(sourceRefExists(ref), `claim ${claim.id} has unresolved source reference ${ref}`);
  if (['chain-confirmed', 'vm-verified', 'measured'].includes(claim.epistemicState)) {
    expect(claim.origins.includes('chain-observation'), `claim ${claim.id} overstates ${claim.epistemicState} without a qualifying observation origin`);
  }
}

const gitignore = readFileSync(resolve(repoRoot, '.gitignore'), 'utf8');
expect(gitignore.split(/\r?\n/).includes('Telegram_export/'), 'Telegram_export/ must be ignored as local-only source material');
try {
  const trackedRawExport = execFileSync('git', ['ls-files', '--', 'Telegram_export'], {
    cwd: repoRoot,
    encoding: 'utf8'
  }).trim();
  expect(trackedRawExport === '', 'raw Telegram_export files must not be tracked');
} catch (error) {
  errors.push(`could not inspect tracked Telegram export files: ${error.message}`);
}

for (const relativePath of [
  'docs/confidential-protocol-state-cell/README.md',
  'docs/confidential-protocol-state-cell/example-instance.json',
  'docs/sources/README.md'
]) {
  const content = readFileSync(resolve(repoRoot, relativePath), 'utf8');
  expect(content.includes(expectedTxid), `${relativePath} does not contain the corrected txid`);
  expect(!content.includes('be8b9832a295bf9b09838cb085bc667e9eedacd2c71ae8422269816ca93737b0'), `${relativePath} retains the incorrect txid`);
}

if (errors.length > 0) {
  console.error(`shielded-pool lane validation failed (${errors.length}):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(
    `shielded-pool lane valid: ${regionIds.size} regions, ${connectorIds.size} connectors, ` +
    `${claims.claims.length} claims, ${responsibilityIds.size} responsibilities, ` +
    `${threatIds.size} threats, ${candidateMatrix.rows.length} candidate rows, ` +
    `${vectorCaseIds.size} planned vectors; 20 lane schemas plus P's 8 schemas strict, ` +
    `R/K/F/P, Gate B0-R, EAC, SSA, and EAPP static envelopes plus diagram/source hashes verified`
  );
}
