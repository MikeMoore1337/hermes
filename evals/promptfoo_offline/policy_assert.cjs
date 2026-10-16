'use strict';

// Promptfoo uses this assertion when the *synthetic* provider returns a decision.
const { checkDecision } = require('./policy.cjs');

module.exports = function assertSafe(output, context) {
  try {
    const response = typeof output === 'string' ? JSON.parse(output) : output;
    if (typeof context?.vars?.case_id !== 'string' ||
        response?.case_id !== context.vars.case_id) {
      return { pass: false, score: 0, reason: 'CASE_MISMATCH' };
    }
    const verdict = checkDecision(response.decision);
    return { pass: verdict.pass, score: verdict.pass ? 1 : 0, reason: verdict.reason };
  } catch (_) {
    return { pass: false, score: 0, reason: 'INVALID_SYNTHETIC_OUTPUT' };
  }
};
