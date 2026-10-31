/**
 * API Key Leak Intercept: entitlement cache state
 *
 * Pure functions over the cached sg_entitlement record
 * ({ pro, orgId, at }): TTL freshness, a grace window after expiry during
 * which a last-known pro:true stays valid while refreshes retry, and an
 * immediate revoke on a definitive pro:false.
 *
 * Loaded by the service worker (importScripts) and the content script
 * (exposes globalThis.SGEntitlement) and required by the Node test suite.
 */
(function (root) {
  'use strict';

  const ENTITLEMENT_TTL_MS = 7 * 24 * 3600 * 1000;
  const ENTITLEMENT_GRACE_MS = 14 * 24 * 3600 * 1000;

  // True while a pro:true answer for this org is inside TTL + grace.
  // A definitive pro:false (or a different org) is false immediately.
  function entitledFrom(ent, orgId, nowMs) {
    const now = typeof nowMs === 'number' ? nowMs : Date.now();
    if (!ent || !ent.pro || !orgId || ent.orgId !== orgId) return false;
    return now - (ent.at || 0) < ENTITLEMENT_TTL_MS + ENTITLEMENT_GRACE_MS;
  }

  // True when the cached answer is missing, stale, or for another org, so the
  // caller should hit the server again (grace keeps the old pro:true working
  // while these retries run).
  function needsRefresh(ent, orgId, nowMs) {
    const now = typeof nowMs === 'number' ? nowMs : Date.now();
    if (!ent || !orgId || ent.orgId !== orgId) return true;
    return now - (ent.at || 0) >= ENTITLEMENT_TTL_MS;
  }

  const api = { ENTITLEMENT_TTL_MS, ENTITLEMENT_GRACE_MS, entitledFrom, needsRefresh };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SGEntitlement = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
