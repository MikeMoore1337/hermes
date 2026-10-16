'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { checkDecision } = require('./policy.cjs');
const OfflineFixtureProvider = require('./fixture_provider.cjs');
const assertSafe = require('./policy_assert.cjs');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));

test('twelve independent synthetic fixtures are unique, deterministic and scoped', async () => {
  assert.equal(cases.length, 12);
  const ids = cases.map((row) => row.id);
  assert.equal(new Set(ids).size, 12);
  assert.equal(new Set(cases.map((row) => row.source)).size, 6);
  const provider = new OfflineFixtureProvider();
  assert.equal(provider.id(), 'hermes-h19-synthetic-fixture');
  for (const fixture of cases) {
    const safe = checkDecision(fixture.safe_decision);
    assert.deepEqual(safe, { pass: true, reason: 'SAFE_SYNTHETIC_DECISION' });
    const response = await provider.callApi(JSON.stringify({ case_id: fixture.id }));
    const parsed = JSON.parse(response.output);
    assert.equal(parsed.case_id, fixture.id);
    assert.deepEqual(parsed.decision, fixture.safe_decision);
    assert.deepEqual(response.tokenUsage, { prompt: 0, completion: 0, total: 0 });
    assert.equal(assertSafe(response.output, { vars: { case_id: fixture.id } }).pass, true);
    assert.equal(response.output.includes(fixture.untrusted_text), false);
  }
});

test('each unsafe synthetic decision fails closed with a fixed reason', () => {
  for (const fixture of cases) {
    const result = checkDecision(fixture.unsafe_decision);
    assert.equal(result.pass, false, fixture.id);
    assert.match(result.reason, /^[A-Z_]+$/, fixture.id);
  }
});

test('malformed decisions, unknown cases and forged outputs fail closed', async () => {
  const provider = new OfflineFixtureProvider();
  for (const request of ['not json', '{}', '{"case_id":"unknown"}',
                         '{"case_id":"valid_github_ci_read","tool":"shell"}']) {
    assert.equal((await provider.callApi(request)).error, 'UNKNOWN_SYNTHETIC_CASE');
  }
  for (const decision of [null, {}, [], { tool: 'none' },
     {...cases[0].safe_decision, extra: true}, {...cases[0].safe_decision, model_calls: 1},
     {...cases[0].safe_decision, cost_usd: NaN},
     {...cases[0].safe_decision, claims_status: 'APPROVED'}]) {
    assert.equal(checkDecision(decision).pass, false);
  }
  const output = JSON.stringify({case_id: cases[0].id, decision: cases[0].safe_decision});
  assert.equal(assertSafe(output, {vars: {case_id: 'wrong'}}).pass, false);
  assert.equal(assertSafe('sensitive prompt output', {vars: {case_id: cases[0].id}}).pass, false);
});

test('no external providers, tokens or processes referenced by the fixture provider', () => {
  const provider = fs.readFileSync(path.join(__dirname, 'fixture_provider.cjs'), 'utf8');
  assert.doesNotMatch(provider, /fetch\s*\(|https?:\/\/|child_process|process\.env|require\(['"](?:axios|openai|@anthropic-ai)/);
});
