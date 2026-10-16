'use strict';

// Promptfoo JavaScript provider. Synthetic, deterministic, no network or model call.
const fs = require('node:fs');
const path = require('node:path');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));
const byId = new Map(cases.map((row) => [row.id, row]));

class OfflineFixtureProvider {
  id() { return 'hermes-h19-synthetic-fixture'; }

  async callApi(prompt) {
    let id;
    try {
      const value = JSON.parse(prompt);
      if (value && Object.keys(value).length === 1 &&
          typeof value.case_id === 'string') id = value.case_id;
    } catch (_) {
      // Expected: invalid prompt is rejected without echoing untrusted input.
    }
    const fixture = byId.get(id);
    if (!fixture) return { error: 'UNKNOWN_SYNTHETIC_CASE' };
    return { output: JSON.stringify({ case_id: id, decision: fixture.safe_decision }),
      tokenUsage: { prompt: 0, completion: 0, total: 0 } };
  }
}
module.exports = OfflineFixtureProvider;
