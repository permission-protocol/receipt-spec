// Reference implementation of the jcs_v3 public projection (SPEC.md sections
// 3.6 and 3.7). Dependency-free.
//
// A jcs_v3 receipt signs `publicProjectionJson`, an issuer-built allowlist of
// its private request, instead of the request itself. This module holds:
//
//   - the frozen allowlist of every shipped projection tag;
//   - buildPublicProjection(tag, requestJson): the build rule. Byte-for-byte
//     equivalent to the hosted service's buildPublicProjection (app repo,
//     src/lib/permission-protocol-v1/signing/public-projection.ts), which this
//     file mirrors line for line. An owner who holds the request rebuilds the
//     projection with it (SPEC.md section 6.7);
//   - projectionProblem / checkPublicProjection: the check anyone can run on
//     the signed projection alone, without the request: is it a possible
//     output of the build rule for its tag (SPEC.md section 6.7, step 1)?
//
// CONTRACT: a tag's allowlist is frozen once a receipt is signed with it, under
// the same rule as a canonicalization version. A changed allowlist is a new
// tag (`deploy_gate/v2`), never an edit to a shipped one. A verifier that does
// not know a tag fails closed (PROJECTION_UNSUPPORTED).

/** The tag each issuer lane signs. */
export const PROJECTION_TAG_BY_LANE = Object.freeze({
  deploy_gate: "deploy_gate/v1",
  execute: "execute/v1",
  revocation: "revocation/v1",
});

/** Identifier slots copy a string only when it matches this, else omit it. */
export const PROJECTION_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:/-]{1,128}$/;

const VISIBILITY = ["public", "private"];
const REVERSIBILITY = ["REVERSIBLE", "PARTIALLY_REVERSIBLE", "IRREVERSIBLE"];
const EXECUTE_ENVIRONMENTS = ["development", "staging", "production"];

// Field flags: `id` an identifier slot; `oneOf` an enumerated slot;
// `repositoryIdentity` (marked † in SPEC.md) copied only when the request's
// scope.visibility is exactly "public".

/** The deploy-gate request scope, shared by deploy_gate/v1 and revocation/v1. */
const SCOPE_FIELDS = [
  { path: "scope.env", id: true },
  { path: "scope.capability", id: true },
  { path: "scope.commitSha", id: true },
  { path: "scope.artifact_digest", id: true },
  { path: "scope.visibility", oneOf: VISIBILITY },
  { path: "scope.repo", id: true, repositoryIdentity: true },
  { path: "scope.ref", id: true, repositoryIdentity: true },
  { path: "scope.workflow", id: true, repositoryIdentity: true },
];

const DEPLOY_GATE_V1 = [
  { path: "intent.name" },
  { path: "intent.category" },
  { path: "action.tool" },
  { path: "action.operation" },
  { path: "context.environment", id: true },
  { path: "context.reversibility", oneOf: REVERSIBILITY },
  ...SCOPE_FIELDS,
  { path: "policy.expiresAt" },
  { path: "policy.decision.outcome" },
  { path: "policy.decision.ruleId" },
  { path: "policy.decision.ruleVersion" },
  { path: "policy.decision.matchedInputs.changeClass" },
  { path: "policy.decision.matchedInputs.analysisComplete" },
  { path: "policy.decision.matchedInputs.targetBranch", repositoryIdentity: true },
  { path: "policy.decision.matchedInputs.defaultBranch", repositoryIdentity: true },
  { path: "policy.decision.matchedInputs.changedPaths", repositoryIdentity: true },
  { path: "policy.authorizationBinding.version" },
  { path: "policy.authorizationBinding.path" },
  { path: "policy.authorizationBinding.commitSha" },
  { path: "policy.authorizationBinding.rulesHash" },
  { path: "policy.authorizationBinding.repository", repositoryIdentity: true },
  { path: "policy.authorizationBinding.branch", repositoryIdentity: true },
  { path: "policy.authorizationBinding.prNumber", repositoryIdentity: true },
  { path: "policyAuthorization.version" },
  { path: "policyAuthorization.evaluatorVersion" },
  { path: "policyAuthorization.policyBlob" },
  { path: "policyAuthorization.headSha" },
  { path: "policyAuthorization.branch", repositoryIdentity: true },
  { path: "policyAuthorization.recordedDecisions[].displayName" },
  { path: "policyAuthorization.recordedDecisions[].authMethod" },
  { path: "policyAuthorization.recordedDecisions[].at" },
  { path: "metadata.deployGateRequestId" },
  { path: "metadata.denial.category" },
  { path: "metadata.denial.decisionClass" },
  { path: "metadata.denial.ruleId" },
  { path: "metadata.denial.final" },
  { path: "metadata.denial.requireNewRequest" },
  { path: "metadata.denial.decidedAt" },
  { path: "metadata.override.overriddenReceiptId" },
  { path: "metadata.override.overriddenDecisionClass" },
  { path: "metadata.override.ruleId" },
  { path: "metadata.override.ruleVersion" },
  { path: "metadata.override.deniedAt" },
  { path: "metadata.override.grantsAuthorization" },
  { path: "metadata.override.nextState" },
  { path: "metadata.pullRequest", repositoryIdentity: true },
  { path: "metadata.demo" },
  { path: "metadata.demoScope" },
  { path: "metadata.approverDisplayName" },
  { path: "deploymentRenewal.purpose" },
  { path: "deploymentRenewal.previousReceiptId" },
  { path: "deploymentRenewal.mergeCommitSha" },
  { path: "deploymentRenewal.rulesHash" },
  { path: "deploymentRenewal.recordedDecisions[].displayName" },
  { path: "deploymentRenewal.recordedDecisions[].authMethod" },
  { path: "deploymentRenewal.recordedDecisions[].at" },
];

const EXECUTE_V1 = [
  { path: "intent.name", id: true },
  { path: "intent.category", id: true },
  { path: "action.tool", id: true },
  { path: "action.operation", id: true },
  { path: "context.environment", oneOf: EXECUTE_ENVIRONMENTS },
  { path: "context.reversibility", oneOf: REVERSIBILITY },
];

const REVOCATION_V1 = [
  { path: "intent.name" },
  { path: "metadata.revokedReceiptId" },
  { path: "metadata.deployGateRequestId" },
  ...SCOPE_FIELDS,
];

const PATH_KEY = /^[A-Za-z0-9_]+$/;

function compile(tag, fields) {
  const seen = new Set();
  const compiled = fields.map((field) => {
    const segments = field.path.split(".").map((raw, index, all) => {
      const each = raw.endsWith("[]");
      const key = each ? raw.slice(0, -2) : raw;
      if (!PATH_KEY.test(key) || (each && index === all.length - 1)) {
        throw new Error(`${tag}: invalid path "${field.path}"`);
      }
      return Object.freeze({ key, each });
    });
    if (seen.has(field.path)) throw new Error(`${tag}: duplicate path "${field.path}"`);
    seen.add(field.path);
    return Object.freeze({ ...field, ...(field.oneOf ? { oneOf: Object.freeze([...field.oneOf]) } : {}), segments: Object.freeze(segments) });
  });
  // A leaf may not also be a container of another listed path.
  const normalized = compiled.map((field) => field.path.replace(/\[\]/g, ""));
  for (const a of normalized) {
    for (const b of normalized) {
      if (a !== b && b.startsWith(`${a}.`)) throw new Error(`${tag}: "${a}" is both a leaf and a container`);
    }
  }
  return Object.freeze(compiled);
}

/** The frozen allowlist of every shipped tag, in the order SPEC.md section 3.7 lists it. */
export const PROJECTION_ALLOWLISTS = Object.freeze({
  "deploy_gate/v1": compile("deploy_gate/v1", DEPLOY_GATE_V1),
  "execute/v1": compile("execute/v1", EXECUTE_V1),
  "revocation/v1": compile("revocation/v1", REVOCATION_V1),
});

export class PublicProjectionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PublicProjectionError";
    this.code = code;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

export function isProjectionTag(value) {
  return typeof value === "string" && hasOwn(PROJECTION_ALLOWLISTS, value);
}

const OMIT = Symbol("omit");

function isScalar(value) {
  return value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number";
}

function leafValue(value, field) {
  if (field.id) return typeof value === "string" && PROJECTION_IDENTIFIER_PATTERN.test(value) ? value : OMIT;
  if (field.oneOf) return typeof value === "string" && field.oneOf.includes(value) ? value : OMIT;
  if (isScalar(value)) return value;
  if (Array.isArray(value) && value.every(isScalar)) return [...value];
  return OMIT;
}

function copyPath(source, target, segments, field, created) {
  const [head, ...rest] = segments;
  if (!hasOwn(source, head.key)) return;
  const value = source[head.key];

  if (rest.length === 0) {
    const copied = leafValue(value, field);
    if (copied !== OMIT) target[head.key] = copied;
    return;
  }

  if (head.each) {
    if (!Array.isArray(value)) return;
    let elements = target[head.key];
    if (!Array.isArray(elements)) {
      elements = value.map(() => {
        const element = {};
        created.add(element);
        return element;
      });
      created.add(elements);
      target[head.key] = elements;
    }
    value.forEach((element, index) => {
      if (isPlainObject(element)) copyPath(element, elements[index], rest, field, created);
    });
    return;
  }

  if (!isPlainObject(value)) return;
  let child = target[head.key];
  if (!isPlainObject(child)) {
    child = {};
    created.add(child);
    target[head.key] = child;
  }
  copyPath(value, child, rest, field, created);
}

/** Drop containers the build created that received nothing. Returns "keep". */
function prune(value, created) {
  if (Array.isArray(value)) {
    let any = false;
    for (const element of value) {
      if (prune(element, created)) any = true;
    }
    return any;
  }
  if (isPlainObject(value)) {
    for (const key of Object.keys(value)) {
      const child = value[key];
      if (child !== null && typeof child === "object" && created.has(child) && !prune(child, created)) delete value[key];
    }
    return Object.keys(value).length > 0;
  }
  return true;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!isPlainObject(value)) return value;
  const sorted = {};
  for (const key of Object.keys(value).sort()) sorted[key] = sortKeys(value[key]);
  return sorted;
}

/**
 * The build rule (SPEC.md section 3.6): the public projection of a request
 * under a tag, as canonical JSON text.
 *
 * @throws PublicProjectionError REQUEST_NOT_OBJECT when requestJson is not a
 *   JSON object; PROJECTION_UNSUPPORTED for a tag this module does not define.
 */
export function buildPublicProjection(tag, requestJson) {
  if (!isProjectionTag(tag)) throw new PublicProjectionError("PROJECTION_UNSUPPORTED", `Unknown projection tag "${String(tag)}"`);
  let request;
  try {
    request = JSON.parse(requestJson);
  } catch {
    throw new PublicProjectionError("REQUEST_NOT_OBJECT", "The request is not valid JSON");
  }
  if (!isPlainObject(request)) throw new PublicProjectionError("REQUEST_NOT_OBJECT", "The request is not a JSON object");

  const scope = request.scope;
  const repositoryPublic = isPlainObject(scope) && scope.visibility === "public";
  const projection = {};
  const created = new WeakSet();
  for (const field of PROJECTION_ALLOWLISTS[tag]) {
    if (field.repositoryIdentity && !repositoryPublic) continue;
    copyPath(request, projection, field.segments, field, created);
  }
  prune(projection, created);
  projection.projection = tag;
  return JSON.stringify(sortKeys(projection));
}

/** The tag a projection text names, when this module knows it; otherwise null. */
export function readProjectionTag(publicProjectionJson) {
  try {
    const parsed = JSON.parse(publicProjectionJson);
    if (isPlainObject(parsed) && isProjectionTag(parsed.projection)) return parsed.projection;
  } catch {
    // Not JSON: no recognizable tag.
  }
  return null;
}

// ---------------------------------------------------------------------------
// The third-party check (SPEC.md section 6.7, step 1). Everything the build
// rule guarantees about its output that can be decided from the output alone.
// It does not need, and cannot replace, the request: only opening the
// commitment proves the projection was built from the committed request.
// ---------------------------------------------------------------------------

/** A tag's allowlist as a tree: key -> { each, field (leaf) | children (container) }. */
function allowlistTree(fields) {
  const root = new Map();
  for (const field of fields) {
    let level = root;
    field.segments.forEach((segment, index) => {
      const leaf = index === field.segments.length - 1;
      let node = level.get(segment.key);
      if (!node) {
        node = { each: segment.each, field: leaf ? field : null, children: leaf ? null : new Map() };
        level.set(segment.key, node);
      }
      level = node.children;
    });
  }
  return root;
}

const ALLOWLIST_TREES = Object.freeze(
  Object.fromEntries(Object.entries(PROJECTION_ALLOWLISTS).map(([tag, fields]) => [tag, allowlistTree(fields)]))
);

function leafProblem(path, value, field, repositoryPublic) {
  if (field.repositoryIdentity && !repositoryPublic) {
    return `${path} is repository identity and scope.visibility is not "public"`;
  }
  if (field.id) {
    return typeof value === "string" && PROJECTION_IDENTIFIER_PATTERN.test(value) ? null : `${path} is an identifier slot and holds a non-identifier`;
  }
  if (field.oneOf) {
    return typeof value === "string" && field.oneOf.includes(value) ? null : `${path} must be one of ${field.oneOf.join(", ")}`;
  }
  if (isScalar(value) || (Array.isArray(value) && value.every(isScalar))) return null;
  return `${path} must be a scalar or an array of scalars`;
}

function containerProblem(path, value, tree, repositoryPublic) {
  if (!isPlainObject(value)) return `${path} must be an object`;
  const keys = Object.keys(value);
  if (keys.length === 0) return `${path} is an empty object; the build rule omits containers that received nothing`;
  for (const key of keys) {
    const childPath = path ? `${path}.${key}` : key;
    const node = tree.get(key);
    if (!node) return `${childPath} is not in the allowlist`;
    const child = value[key];
    if (node.field) {
      const problem = leafProblem(childPath, child, node.field, repositoryPublic);
      if (problem) return problem;
      continue;
    }
    if (node.each) {
      if (!Array.isArray(child) || child.length === 0) return `${childPath} must be a non-empty array`;
      let any = false;
      for (const [index, element] of child.entries()) {
        if (!isPlainObject(element)) return `${childPath}[${index}] must be an object`;
        // An element that received nothing stays as {} so siblings keep their positions.
        if (Object.keys(element).length === 0) continue;
        any = true;
        const problem = containerProblem(`${childPath}[${index}]`, element, node.children, repositoryPublic);
        if (problem) return problem;
      }
      if (!any) return `${childPath} holds only empty elements; the build rule omits it`;
      continue;
    }
    const problem = containerProblem(childPath, child, node.children, repositoryPublic);
    if (problem) return problem;
  }
  return null;
}

/**
 * Null when the signed projection text could have been produced by the build
 * rule for its tag; otherwise a description of the first violation:
 * not canonical JSON, a key outside the allowlist, a slot value that breaks
 * its rule, a repository-identity (†) path without scope.visibility "public",
 * or a container shape the build rule never emits. The tag must be known
 * (check it with isProjectionTag first).
 */
export function projectionProblem(publicProjectionJson) {
  let projection;
  try {
    projection = JSON.parse(publicProjectionJson);
  } catch {
    return "publicProjectionJson is not JSON";
  }
  if (!isPlainObject(projection)) return "publicProjectionJson is not a JSON object";
  if (JSON.stringify(sortKeys(projection)) !== publicProjectionJson) {
    return "publicProjectionJson is not canonical JSON (recursively sorted keys, no whitespace)";
  }
  const tag = projection.projection;
  if (!isProjectionTag(tag)) return `unknown projection tag ${JSON.stringify(tag)}`;
  const { projection: _tag, ...facts } = projection;
  if (Object.keys(facts).length === 0) return null;
  const repositoryPublic = isPlainObject(facts.scope) && facts.scope.visibility === "public";
  return containerProblem("", facts, ALLOWLIST_TREES[tag], repositoryPublic);
}

/**
 * The verifier's projection step: { ok: true, tag, projection } or
 * { ok: false, code: "PROJECTION_UNSUPPORTED" | "PROJECTION_NOT_ALLOWED", message }.
 */
export function checkPublicProjection(publicProjectionJson) {
  const tag = typeof publicProjectionJson === "string" ? readProjectionTag(publicProjectionJson) : null;
  if (!tag) {
    return { ok: false, code: "PROJECTION_UNSUPPORTED", message: "the signed publicProjectionJson names no projection tag this verifier supports" };
  }
  const problem = projectionProblem(publicProjectionJson);
  if (problem) return { ok: false, code: "PROJECTION_NOT_ALLOWED", message: `${tag}: ${problem}` };
  return { ok: true, tag, projection: JSON.parse(publicProjectionJson) };
}
