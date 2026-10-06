// A deliberately small JSON Schema checker: exactly the keywords the schemas in
// this repository use (type, const, enum, required, properties,
// additionalProperties, pattern, minLength, maxLength, minimum, maximum,
// oneOf). It exists so the conformance
// tests need no dependencies. Any other validator that implements draft
// 2020-12 gives the same answers on these schemas; use one if you prefer.

function typeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

function typeMatches(expected, value) {
  const actual = typeOf(value);
  const allowed = Array.isArray(expected) ? expected : [expected];
  return allowed.some((type) => type === actual || (type === "number" && actual === "integer"));
}

/** Returns a list of error strings; empty means valid. */
export function validate(schema, value, path = "$") {
  const errors = [];
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((branch) => validate(branch, value, path).length === 0).length;
    if (matches !== 1) errors.push(`${path} must match exactly one of ${schema.oneOf.length} shapes (matches ${matches})`);
  }
  if (schema.const !== undefined && value !== schema.const) {
    errors.push(`${path} must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path} must be one of ${schema.enum.join(", ")}`);
  }
  if (schema.type && !typeMatches(schema.type, value)) {
    errors.push(`${path} must be of type ${[].concat(schema.type).join("|")}`);
    return errors;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${path} must be at least ${schema.minLength} characters`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${path} must be at most ${schema.maxLength} characters`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path} must match ${schema.pattern}`);
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path} must be at least ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path} must be at most ${schema.maximum}`);
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required ?? []) {
      if (!(key in value)) errors.push(`${path}.${key} is required`);
    }
    const properties = schema.properties ?? {};
    for (const [key, child] of Object.entries(value)) {
      if (key in properties) {
        errors.push(...validate(properties[key], child, `${path}.${key}`));
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}.${key} is not allowed`);
      }
    }
  }
  return errors;
}
