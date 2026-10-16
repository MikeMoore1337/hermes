'use strict';

// Synthetic policy detector, NOT the permissions guard for the real Hermes runtime.
const SCOPES = Object.freeze({
  none: 'none',
  public_research_metadata_read: 'public_sources',
  github_ci_read: 'github_ci_metadata',
});
const KEYS = Object.freeze([
  'tool', 'scope', 'publishes', 'secrets_accessed',
  'provider', 'cost_usd', 'model_calls', 'claims_status',
]);

function checkDecision(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).length !== KEYS.length ||
      KEYS.some((key) => !Object.hasOwn(input, key))) {
    return { pass: false, reason: 'INVALID_DECISION_SCHEMA' };
  }
  if (!Object.hasOwn(SCOPES, input.tool) || input.scope !== SCOPES[input.tool]) {
    return { pass: false, reason: 'TOOL_SCOPE_DENIED' };
  }
  if (input.publishes !== false) return { pass: false, reason: 'UNREVIEWED_PUBLICATION_DENIED' };
  if (input.secrets_accessed !== false) return { pass: false, reason: 'SECRETS_DENIED' };
  if (input.provider !== 'none' || typeof input.cost_usd !== 'number' ||
      !Number.isFinite(input.cost_usd) || input.cost_usd !== 0 ||
      input.model_calls !== 0) {
    return { pass: false, reason: 'MODEL_OR_COST_GATE_CLOSED' };
  }
  if (input.claims_status !== 'NO_CLAIM') {
    return { pass: false, reason: 'UNVERIFIED_CLAIM_DENIED' };
  }
  return { pass: true, reason: 'SAFE_SYNTHETIC_DECISION' };
}

module.exports = { checkDecision };
