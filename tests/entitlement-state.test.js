'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../extension/entitlement-state.js');

const NOW = 1700000000000;
const DAY = 86400000;
const ORG = 'org_abc123def456';

test('a fresh pro:true is entitled and does not need a refresh', () => {
  const ent = { pro: true, orgId: ORG, at: NOW - DAY };
  assert.equal(E.entitledFrom(ent, ORG, NOW), true);
  assert.equal(E.needsRefresh(ent, ORG, NOW), false);
});

test('past TTL but inside grace, pro:true stays valid while refreshes retry', () => {
  const ent = { pro: true, orgId: ORG, at: NOW - 8 * DAY };
  assert.equal(E.entitledFrom(ent, ORG, NOW), true);
  assert.equal(E.needsRefresh(ent, ORG, NOW), true);
});

test('past TTL and grace, pro:true lapses', () => {
  const ent = { pro: true, orgId: ORG, at: NOW - 22 * DAY };
  assert.equal(E.entitledFrom(ent, ORG, NOW), false);
  assert.equal(E.needsRefresh(ent, ORG, NOW), true);
});

test('a definitive pro:false revokes immediately', () => {
  const ent = { pro: false, orgId: ORG, at: NOW - 1 * DAY };
  assert.equal(E.entitledFrom(ent, ORG, NOW), false);
});

test('missing, foreign, or malformed records are not entitled and need a refresh', () => {
  assert.equal(E.entitledFrom(null, ORG, NOW), false);
  assert.equal(E.entitledFrom({ pro: true, orgId: 'org_other000000', at: NOW }, ORG, NOW), false);
  assert.equal(E.entitledFrom({ pro: true, orgId: ORG, at: NOW }, '', NOW), false);
  assert.equal(E.needsRefresh(null, ORG, NOW), true);
  assert.equal(E.needsRefresh({ pro: true, orgId: 'org_other000000', at: NOW }, ORG, NOW), true);
});

test('TTL is 7 days and grace is 14 days', () => {
  assert.equal(E.ENTITLEMENT_TTL_MS, 7 * DAY);
  assert.equal(E.ENTITLEMENT_GRACE_MS, 14 * DAY);
});
