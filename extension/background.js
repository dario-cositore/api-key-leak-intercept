/**
 * API Key Leak Intercept: service worker
 *
 * Handles: storage defaults, month-aware warning counters, badge updates,
 * message routing from popup/content, alert forwarding (team mode) plus
 * cloud relay, license verification, and update checks.
 */
const WORKER_URL = 'https://api.dariocositore.com';
const RESEND_FROM = 'API Key Leak Intercept <alerts@api-key-leak-intercept.dev>';

const DEFAULTS = {
  sg_settings: {
    // Personal installs start with protection off; the welcome page carries
    // the disclosure and the explicit Enable step. Managed installs force it
    // on (see content.js policy handling).
    enabled: false,
    categories: { apiKeys: true, pii: false, network: false },
    customPatterns: [],
    autoRedact: false,
  },
  sg_leaks_stopped: 0,
  sg_leaks_month: '',
  sg_hide_pro_hint: false,
  sg_isPro: false,
  sg_license_key: '',
  sg_license_invalid: false,
  sg_org: {
    teamMode: false,
    orgId: '',
    orgToken: '',
    userEmail: '',
    universalMode: false,
    extraEmails: '',
    alertOnWarn: true,
    alertOnSendAnyway: true,
    alertOnBlock: true,
    alertOnRedact: true,
    heartbeat: false,
    extraSites: [],
    alertEndpoint: '',
    blockSendAnyway: false,
    channels: {
      slack: { enabled: false, webhookUrl: '' },
      teams: { enabled: false, webhookUrl: '' },
      telegram: { enabled: false, botToken: '', chatId: '' },
      webhook: { enabled: false, url: '' },
      email: { enabled: false, apiKey: '', to: '' },
    },
  },
};

/* ------------------------------------------------------------------ */
/* Effective org (managed policy over local settings)                  */
/* ------------------------------------------------------------------ */
// Enterprise policy is the stronger half: policy org fields override the
// stored sg_org, and a policy orgId turns team mode on. Managed installs
// with an org heartbeat unless the policy sets heartbeat:false.
function getEffectiveOrg(cb) {
  chrome.storage.local.get(['sg_org'], (res) => {
    const org = { ...DEFAULTS.sg_org, ...(res.sg_org || {}) };
    const apply = (m) => {
      if (m && Object.keys(m).length > 0) {
        if (m.orgId) { org.orgId = String(m.orgId); org.teamMode = true; }
        if (m.orgToken) org.orgToken = String(m.orgToken);
        if (m.userEmail) org.userEmail = String(m.userEmail);
        if (typeof m.universalMode === 'boolean') org.universalMode = m.universalMode;
        if (m.alertEndpoint) org.alertEndpoint = String(m.alertEndpoint);
        for (const k of ['alertOnWarn', 'alertOnSendAnyway', 'alertOnBlock', 'alertOnRedact']) {
          if (typeof m[k] === 'boolean') org[k] = m[k];
        }
        if (m.orgId && m.heartbeat !== false) org.heartbeat = true;
        else if (typeof m.heartbeat === 'boolean') org.heartbeat = m.heartbeat;
      }
      cb(org);
    };
    try {
      if (chrome.storage && chrome.storage.managed) {
        chrome.storage.managed.get(null, (m) => apply(m));
        return;
      }
    } catch (e) {}
    apply(null);
  });
}

/* ------------------------------------------------------------------ */
/* Pro entitlement (server-confirmed)                                  */
/* ------------------------------------------------------------------ */
// Pro capabilities for team installs require a live license on the org.
// The answer is cached with a TTL plus a grace window (see
// entitlement-state.js) and a definitive pro:false revokes immediately.
async function checkEntitlement() {
  try {
    const org = await new Promise((resolve) => getEffectiveOrg(resolve));
    if (!org.teamMode || !org.orgId || !org.orgToken) return;
    const r = await fetch(WORKER_URL + '/api/entitlement', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId: org.orgId, orgToken: org.orgToken }),
      cache: 'no-store',
    });
    const data = await r.json();
    if (data && data.ok) {
      await new Promise((resolve) => chrome.storage.local.set({
        sg_entitlement: { pro: !!data.pro, orgId: org.orgId, at: Date.now() },
      }, resolve));
      broadcastSettingsUpdated();
    }
  } catch (e) {}
}

/* ------------------------------------------------------------------ */
/* Month-aware warning counter                                         */
/* ------------------------------------------------------------------ */
function currentMonth() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}

function withNormalizedLeaks(cb) {
  chrome.storage.local.get(['sg_leaks_stopped', 'sg_leaks_month'], (res) => {
    const month = currentMonth();
    let n = res.sg_leaks_stopped || 0;
    if (res.sg_leaks_month !== month) {
      n = 0;
      chrome.storage.local.set({ sg_leaks_stopped: 0, sg_leaks_month: month });
    }
    cb(n);
  });
}

/* ------------------------------------------------------------------ */
/* Install / defaults                                                  */
/* ------------------------------------------------------------------ */
chrome.runtime.onInstalled.addListener((details) => {
  chrome.alarms.create('licenseCheck', { periodInMinutes: 1440 });
  chrome.alarms.create('heartbeat', { periodInMinutes: 360 });
  chrome.alarms.create('configCheck', { periodInMinutes: 1440 });
  try { chrome.runtime.setUninstallURL('https://dariocositore.com/tools/api-key-leak-intercept/'); } catch (e) {}
  if (details && details.reason === 'install') {
    try { chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') }); } catch (e) {}
  }
  try { fetchConfig(); } catch (e) {}
  try { syncDynamicContentScript(); } catch (e) {}
  chrome.storage.local.get(Object.keys(DEFAULTS), (res) => {
    const toSet = {};
    for (const k of Object.keys(DEFAULTS)) {
      if (res[k] === undefined) toSet[k] = DEFAULTS[k];
    }
    if (res.sg_leaks_month === undefined) toSet.sg_leaks_month = currentMonth();
    // migrate: PII/network detection is Pro-only from 1.0.0 on
    if (res.sg_settings && res.sg_settings.categories && res.sg_settings.categories.pii && !res.sg_isPro) {
      const cats = { ...res.sg_settings.categories, pii: false, network: false };
      toSet.sg_settings = { ...res.sg_settings, categories: cats };
    }
    if (Object.keys(toSet).length) chrome.storage.local.set(toSet);
  });
  chrome.action.setBadgeText({ text: '' });
  chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
});

/* ------------------------------------------------------------------ */
/* Messaging                                                           */
/* ------------------------------------------------------------------ */
// Handshake from the License & Team Console after sign-in. The page opens from
// the popup's Sign in button, the user signs in on the web, the page passes the
// licence key back here and closes itself. Manifest restricts this to
// dariocositore.com via externally_connectable.
// Guarded: the API is absent from test harness stubs and from runtimes that
// predate it, and the extension must still load there.
if (chrome.runtime && chrome.runtime.onMessageExternal) {
  chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
    try {
      const allowed = !!sender && /^https:\/\/(www\.)?dariocositore\.com\//.test(sender.url || '');
      if (!allowed) { sendResponse({ ok: false, error: 'untrusted sender' }); return; }
      if (msg && msg.type === 'akliAuth' && msg.licenseKey) {
        // A tab opened with chrome.tabs.create is not script-closable, so the
        // extension closes it once the key is verified. That drops the user back
        // into the popup the way the web login flow is meant to feel.
        verifyLicense(msg.licenseKey, (res) => {
          try {
            if (res && res.valid && sender && sender.tab && sender.tab.id != null) {
              chrome.tabs.remove(sender.tab.id).catch(() => {});
            }
          } catch (e) {}
          sendResponse(res);
        });
        return true;
      }
      sendResponse({ ok: false, error: 'unknown message' });
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {  if (!msg) return;

  if (msg.type === 'getSettings') {
    withNormalizedLeaks((n) => {
      chrome.storage.local.get(['sg_settings', 'sg_isPro', 'sg_license_key', 'sg_license_invalid', 'sg_hide_pro_hint', 'sg_entitlement'], (res) => {
        getEffectiveOrg((org) => {
          const entitled = SGEntitlement.entitledFrom(res.sg_entitlement, org.orgId);
          if (SGEntitlement.needsRefresh(res.sg_entitlement, org.orgId) && org.teamMode && org.orgId && org.orgToken) checkEntitlement();
          sendResponse({
            settings: res.sg_settings || DEFAULTS.sg_settings,
            leaksStopped: n,
            isPro: !!res.sg_isPro && !!res.sg_license_key,
            licenseInvalid: !!res.sg_license_invalid,
            org,
            hideProHint: !!res.sg_hide_pro_hint,
            entitled,
          });
        });
      });
    });
    return true;
  }

  if (msg.type === 'getManagedState') {
    withManagedState((managed) => sendResponse({ managed: !!managed }));
    return true;
  }

  if (msg.type === 'saveSettings') {
    isSettingsLocked((locked) => {
      if (locked) { sendResponse({ ok: false, locked: true }); return; }
      chrome.storage.local.set({ sg_settings: msg.settings }, () => {
        broadcastSettingsUpdated();
        sendResponse({ ok: true });
      });
    });
    return true;
  }

  if (msg.type === 'saveOrg') {
    isSettingsLocked((locked) => {
      if (locked) { sendResponse({ ok: false, locked: true }); return; }
      chrome.storage.local.set({ sg_org: msg.org }, () => {
        broadcastSettingsUpdated();
        checkEntitlement().finally(() => sendResponse({ ok: true }));
      });
    });
    return true;
  }

  if (msg.type === 'incrementLeaksStopped') {
    withNormalizedLeaks((n) => {
      const next = n + 1;
      chrome.storage.local.set({ sg_leaks_stopped: next, sg_leaks_month: currentMonth() }, () => {
        sendResponse({ count: next });
      });
    });
    return true;
  }

  if (msg.type === 'verifyLicense') {
    verifyLicense(msg.key, sendResponse);
    return true;
  }

  if (msg.type === 'accountLogin') {
    accountLogin(msg.email, msg.password, sendResponse);
    return true;
  }

  if (msg.type === 'accountLogout') {
    chrome.storage.local.remove(['sg_account_email'], () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'reverifyLicense') {
    chrome.storage.local.get(['sg_license_key'], (res) => {
      if (!res.sg_license_key) { sendResponse({ ok: false, reason: 'no key' }); return; }
      verifyLicense(res.sg_license_key, sendResponse);
    });
    return true;
  }

  if (msg.type === 'sendAlert') {
    handleAlert(msg.alert, sendResponse);
    return true;
  }

  if (msg.type === 'getAuditLog') {
    chrome.storage.local.get(['sg_audit_log'], (res) => {
      sendResponse({ log: res.sg_audit_log || [] });
    });
    return true;
  }

  if (msg.type === 'clearAuditLog') {
    chrome.storage.local.set({ sg_audit_log: [] }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'openPopup') {
    try {
      chrome.runtime.openOptionsPage().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    } catch (e) { sendResponse({ ok: false }); }
    return true;
  }

  if (msg.type === 'openUrl') {
    const ok = typeof msg.url === 'string' && /^https?:\/\//i.test(msg.url);
    if (ok) chrome.tabs.create({ url: msg.url });
    sendResponse({ ok });
    return false;
  }
});

function broadcastSettingsUpdated() {
  chrome.tabs.query({}, (tabs) => {
    for (const t of tabs) {
      if (t.id !== undefined) chrome.tabs.sendMessage(t.id, { type: 'settingsUpdated' }).catch(() => {});
    }
  });
}

/* ------------------------------------------------------------------ */
/* Managed policy (Chrome Enterprise)                                  */
/* ------------------------------------------------------------------ */
// Settings changes from the popup are rejected while policy holds lockSettings
function isSettingsLocked(cb) {
  try {
    if (chrome.storage && chrome.storage.managed) {
      chrome.storage.managed.get(['lockSettings'], (m) => cb(!!(m && m.lockSettings)));
      return;
    }
  } catch (e) {}
  cb(false);
}

// Managed = force-installed by an admin or configured through managed storage
function withManagedState(cb) {
  let admin = false;
  let policy = false;
  let pending = 2;
  const done = () => {
    pending -= 1;
    if (pending === 0) cb(admin || policy);
  };
  try {
    chrome.management.getSelf((info) => {
      if (info && info.installType === 'admin') admin = true;
      done();
    });
  } catch (e) { done(); }
  try {
    if (chrome.storage && chrome.storage.managed) {
      chrome.storage.managed.get(null, (m) => {
        if (m && Object.keys(m).length > 0) policy = true;
        done();
      });
    } else {
      done();
    }
  } catch (e) { done(); }
}

// Enterprise policy overrides the user's org preferences wherever the two
// meet; that merge lives in getEffectiveOrg above.

/* ------------------------------------------------------------------ */
/* Runtime content script registration                                 */
/* ------------------------------------------------------------------ */
// The manifest declares the content script for the built-in AI chat list only,
// so the install permission is scoped to those sites. Universal mode and
// org-supplied extra sites reach further, and that access is optional: the
// popup asks for it when the user turns the feature on, then this keeps the
// registered script in step with whatever is actually enabled.
const DYNAMIC_SCRIPT_ID = 'sg-dynamic-sites';
const DYNAMIC_JS = ['detect.js', 'entitlement-state.js', 'content.js'];
const DYNAMIC_CSS = ['content.css'];

function hostPatterns(hosts) {
  const out = [];
  const seen = new Set();
  for (const raw of hosts) {
    const h = String(raw || '').trim().toLowerCase();
    if (!h || /[^a-z0-9.\-]/.test(h)) continue;
    for (const p of ['*://' + h + '/*', '*://*.' + h + '/*']) {
      if (!seen.has(p)) { seen.add(p); out.push(p); }
    }
  }
  return out;
}

function dynamicMatchesFor(org, cfg) {
  if (org && org.universalMode) return ['<all_urls>'];
  const hosts = [];
  if (org && Array.isArray(org.extraSites)) hosts.push(...org.extraSites);
  if (cfg && Array.isArray(cfg.aiSites)) hosts.push(...cfg.aiSites);
  return hostPatterns(hosts);
}

async function syncDynamicContentScript() {
  if (!chrome.scripting || !chrome.scripting.getRegisteredContentScripts) return;
  let org = null;
  let cfg = null;
  try {
    const res = await new Promise((r) => chrome.storage.local.get(['sg_org', 'sg_config', 'sg_config_exp'], r));
    const cfgExpired = typeof res.sg_config_exp === 'number' && res.sg_config_exp * 1000 <= Date.now();
    org = res.sg_org || {};
    cfg = cfgExpired ? {} : (res.sg_config || {});
  } catch (e) { return; }

  const matches = dynamicMatchesFor(org, cfg);
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [DYNAMIC_SCRIPT_ID] });
    if (!matches.length) {
      if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [DYNAMIC_SCRIPT_ID] });
      return;
    }
    const spec = {
      id: DYNAMIC_SCRIPT_ID,
      js: DYNAMIC_JS,
      css: DYNAMIC_CSS,
      matches,
      runAt: 'document_idle',
      allFrames: false,
      persistAcrossSessions: true,
    };
    if (existing.length) await chrome.scripting.updateContentScripts([spec]);
    else await chrome.scripting.registerContentScripts([spec]);
  } catch (e) {
    // The optional host permission is not granted yet; the popup requests it
    // before flipping Universal on, so there is nothing to do here.
  }
}

chrome.storage.onChanged.addListener((changes) => {
  if (changes.sg_leaks_stopped) {
    const n = changes.sg_leaks_stopped.newValue || 0;
    chrome.action.setBadgeText({ text: n > 0 ? String(n) : '' });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
  }
  if (changes.sg_org || changes.sg_config || changes.sg_config_exp) {
    try { syncDynamicContentScript(); } catch (e) {}
  }
});

/* ------------------------------------------------------------------ */
/* License verification (server-side revalidation included)            */
/* ------------------------------------------------------------------ */
// Account sign-in from the popup: email and password against the portal
// account minted at checkout. The reply carries the licence key, which is then
// pushed through the same verify-and-store path a pasted key takes, so Pro
// state ends up identical whichever way the user signs in.
function accountLogin(email, password, sendResponse) {
  const e = String(email || '').trim().toLowerCase();
  const p = String(password || '');
  if (!e || e.indexOf('@') < 1 || !p) {
    sendResponse({ ok: false, valid: false, error: 'enter your email and password' });
    return;
  }
  fetch(WORKER_URL + '/api/account/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: e, password: p }),
    cache: 'no-store',
  })
    .then(r => r.json().then(data => ({ status: r.status, data })))
    .then(({ status, data }) => {
      if (data && data.ok && data.licenseKey) {
        chrome.storage.local.set({ sg_account_email: e }, () => {
          verifyLicense(data.licenseKey, sendResponse);
        });
        return;
      }
      if (data && data.ok) {
        // signed in fine, but nothing is licensed on this account
        chrome.storage.local.set({ sg_account_email: e }, () => {
          sendResponse({ ok: true, valid: false, noLicense: true, error: 'no license on this account yet' });
        });
        return;
      }
      sendResponse({
        ok: false, valid: false,
        error: (data && data.error) || ('sign in failed (' + status + ')'),
      });
    })
    .catch(() => sendResponse({ ok: false, valid: null, error: 'offline' }));
}

function verifyLicense(key, sendResponse) {
  const k = String(key || '').trim().toUpperCase();
  if (!k) { sendResponse({ ok: false, valid: false, error: 'missing key' }); return; }
  fetch(WORKER_URL + '/api/license/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: k }),
    cache: 'no-store',
  })
    .then(r => r.json().then(data => ({ data })))
    .then(({ data }) => {
      // Revoke only on a definitive { valid: false } from the server.
      // Rate limits, 5xx, and malformed bodies leave Pro untouched.
      if (data && data.valid === true) {
        pruneAuditLog(data.logClearedAt);
        chrome.storage.local.set({ sg_isPro: true, sg_license_key: k, sg_license_invalid: false }, () => {
          broadcastSettingsUpdated();
          sendResponse({ ok: true, valid: true, email: data.email || '' });
        });
      } else if (data && data.valid === false) {
        chrome.storage.local.set({ sg_isPro: false, sg_license_invalid: true }, () => {
          broadcastSettingsUpdated();
          sendResponse({ ok: true, valid: false, error: data.error || 'invalid' });
        });
      } else {
        sendResponse({ ok: false, valid: null, error: (data && data.error) || 'unexpected response' });
      }
    })
    .catch(() => {
      // Offline / server unreachable: keep the current Pro state.
      sendResponse({ ok: false, valid: null, error: 'offline' });
    });
}

/* ------------------------------------------------------------------ */
/* Alert forwarding (team mode) + Pro local history                    */
/* ------------------------------------------------------------------ */
function handleAlert(alert, sendResponse) {
  if (!alert || !alert.action) { sendResponse({ ok: false, reason: 'bad alert' }); return; }

  withManagedState((managed) => {
    chrome.storage.local.get(['sg_isPro'], (res) => {
      const isPro = !!res.sg_isPro;
      getEffectiveOrg((o) => {
      const isTeam = managed || !!(o.teamMode && o.orgId && alert.orgId);

      if (!isPro && !isTeam) { sendResponse({ ok: false, reason: 'personal free mode' }); return; }

      // Local audit log: Pro (personal history) or team mode
      storeAlertLocally(alert);

      if (!isTeam) {
        sendPersonalAlert(alert);
        sendResponse({ ok: true, stored: true });
        return;
      }

      // Alert preferences only control outbound notifications, not the log
        if (alert.action === 'blocked' && o.alertOnBlock === false) {
          sendResponse({ ok: true, stored: true, skipped: 'pref' }); return;
        }
        if (alert.action === 'sent_anyway' && o.alertOnSendAnyway === false) {
          sendResponse({ ok: true, stored: true, skipped: 'pref' }); return;
        }
        if (alert.action === 'warned' && o.alertOnWarn === false) {
          sendResponse({ ok: true, stored: true, skipped: 'pref' }); return;
        }
        if (alert.action === 'redacted' && o.alertOnRedact === false) {
          sendResponse({ ok: true, stored: true, skipped: 'pref' }); return;
        }

        const promises = [];

        if (managed) {
          // Managed installs deliver to the worker only. The worker fans out to
          // the channels the IT admin configured server-side, so forward is true.
          promises.push(sendToWorker(alert, true));
          if (o.alertEndpoint && /^https:\/\//i.test(o.alertEndpoint)) {
            promises.push(fetch(o.alertEndpoint, {
              method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(alert),
            }).then(r => { if (!r.ok) throw new Error('endpoint ' + r.status); }).catch(() => {}));
          }
        } else {
          const channels = o.channels || {};

          if (channels.slack && channels.slack.enabled && channels.slack.webhookUrl) {
            promises.push(sendSlack(channels.slack.webhookUrl, alert));
          }
          if (channels.teams && channels.teams.enabled && channels.teams.webhookUrl) {
            promises.push(sendTeams(channels.teams.webhookUrl, alert));
          }
          if (channels.telegram && channels.telegram.enabled && channels.telegram.botToken && channels.telegram.chatId) {
            promises.push(sendTelegram(channels.telegram.botToken, channels.telegram.chatId, alert));
          }
          if (channels.webhook && channels.webhook.enabled && channels.webhook.url) {
            promises.push(sendWebhook(channels.webhook.url, alert));
          }
          if (channels.email && channels.email.enabled && channels.email.apiKey && channels.email.to) {
            promises.push(sendEmail(channels.email, alert));
          }
          if (o.alertEndpoint && /^https:\/\//i.test(o.alertEndpoint)) {
            promises.push(fetch(o.alertEndpoint, {
              method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(alert),
            }).then(r => { if (!r.ok) throw new Error('endpoint ' + r.status); }).catch(() => {}));
          }
          // Cloud relay: stores the alert for the IT dashboard. forward:false,
          // because the local channels above already handled delivery and the
          // worker must not send duplicates.
          promises.push(sendToWorker(alert, false));
        }

        Promise.allSettled(promises).then((results) => {
          const ok = results.some(r => r.status === 'fulfilled');
          sendResponse({ ok, stored: true, results: results.map(r => r.status) });
        });
      });
    });
  });
}

let auditWriteQueue = Promise.resolve();

function storeAlertLocally(alert) {
  // Serialized on purpose: two catches in the same second used to race the
  // read-modify-write and silently lose the earlier entry.
  auditWriteQueue = auditWriteQueue.then(() => new Promise((resolve) => {
    chrome.storage.local.get(['sg_audit_log'], (r) => {
      const log = r.sg_audit_log || [];
      log.unshift(alert);
      if (log.length > 100) log.length = 100;
      chrome.storage.local.set({ sg_audit_log: log }, () => resolve());
    });
  }));
}

// Every relay result is recorded so the popup can say whether a catch reached
// the console feed. Silent failures were indistinguishable from working sync.
function recordSync(ok, mode, error) {
  try {
    chrome.storage.local.set({
      sg_sync_status: { at: Date.now(), ok: !!ok, mode: mode, error: error ? String(error).slice(0, 120) : '' },
    });
  } catch (e) {}
}

// Clearing the log on the website also clears it here: the console records a
// watermark and every path that talks to the server prunes local rows older
// than it.
function pruneAuditLog(clearedAt) {
  const t = Date.parse(clearedAt || '') || 0;
  if (!t) return;
  chrome.storage.local.get(['sg_audit_log'], (r) => {
    const log = (r.sg_audit_log || []).filter((a) => Date.parse((a && a.timestamp) || '') > t);
    chrome.storage.local.set({ sg_audit_log: log });
  });
}

// Solo Pro: the same catch log lives in the customer console feed, so pushes
// past the warning show up where a team manager would look for them too.
function sendPersonalAlert(alert) {
  try {
    chrome.storage.local.get(['sg_license_key'], (r) => {
      const licenseKey = String(r.sg_license_key || '').trim();
      if (!licenseKey) { recordSync(false, 'personal', 'no license key stored'); return; }
      fetch(WORKER_URL + '/api/license/alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ licenseKey, alert }),
        cache: 'no-store',
      }).then((res) => {
        if (res.ok) {
          recordSync(true, 'personal', '');
          res.json().then((data) => pruneAuditLog(data && data.logClearedAt)).catch(() => {});
        } else {
          recordSync(false, 'personal', 'HTTP ' + res.status);
        }
      }).catch((e) => recordSync(false, 'personal', e && e.message ? e.message : 'network error'));
    });
  } catch (e) {}
}

function formatAlertMessage(alert) {
  const actionLabel = {
    blocked: 'Blocked (user cancelled)',
    sent_anyway: 'Sent anyway (user overrode)',
    redacted: 'Redacted by user',
    warned: 'Warned',
  }[alert.action] || alert.action;

  return [
    '🛡️ API Key Leak Intercept Alert',
    '',
    'Employee: ' + alert.userEmail,
    'Site: ' + alert.site,
    'Secret type: ' + alert.secretTypes.join(', ') + ' (' + String(alert.severity || '').toUpperCase() + ')',
    'Action: ' + actionLabel,
    'Time: ' + alert.timestamp,
    'Org: ' + alert.orgId,
    ...(alert.justification ? ['Reason: ' + String(alert.justification).slice(0, 140)] : []),
  ].join('\n');
}

function sendSlack(webhookUrl, alert) {
  return fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: formatAlertMessage(alert) }),
  }).then(r => { if (!r.ok) throw new Error('Slack ' + r.status); });
}

function sendTeams(webhookUrl, alert) {
  return fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: formatAlertMessage(alert) }),
  }).then(r => { if (!r.ok) throw new Error('Teams ' + r.status); });
}

function sendTelegram(botToken, chatId, alert) {
  return fetch('https://api.telegram.org/bot' + botToken + '/sendMessage', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text: formatAlertMessage(alert) }),
  }).then(r => { if (!r.ok) throw new Error('Telegram ' + r.status); });
}

function sendWebhook(url, alert) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert),
  }).then(r => { if (!r.ok) throw new Error('Webhook ' + r.status); });
}

function sendEmail(channel, alert) {
  const to = String(channel.to || '').split(',').map(e => e.trim()).filter(Boolean);
  if (to.length === 0) return Promise.reject(new Error('Email no recipients'));
  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + channel.apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to,
      subject: 'API Key Leak Intercept Alert: ' + (alert.secretTypes || []).join(', ') + ' on ' + (alert.site || 'unknown'),
      text: formatAlertMessage(alert),
    }),
  }).then(r => { if (!r.ok) throw new Error('Email ' + r.status); });
}

function sendToWorker(alert, forward) {
  return fetch(WORKER_URL + '/api/alerts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert, forward: !!forward }),
    cache: 'no-store',
  }).then(r => {
    recordSync(r.ok, 'org', r.ok ? '' : 'HTTP ' + r.status);
    if (!r.ok) throw new Error('Worker ' + r.status);
  }).catch(e => {
    recordSync(false, 'org', e && e.message ? e.message : 'network error');
    throw e;
  });
}

/* ------------------------------------------------------------------ */
/* Heartbeat                                                           */
/* ------------------------------------------------------------------ */
async function doHeartbeat() {
  try {
    const org = await new Promise((resolve) => getEffectiveOrg(resolve));
    if (!org.teamMode || !org.orgId || !org.heartbeat) return;
    const managed = await new Promise((resolve) => withManagedState(resolve));
    const payload = {
      orgId: org.orgId,
      orgToken: org.orgToken || '',
      userEmail: org.userEmail || 'unknown',
      extensionVersion: chrome.runtime.getManifest().version,
      managed: !!managed,
      timestamp: new Date().toISOString(),
    };
    const url = (org.alertEndpoint && /^https:\/\//i.test(org.alertEndpoint)) ? org.alertEndpoint.replace(/\/$/, '') + '/heartbeat' : (WORKER_URL + '/api/heartbeat');
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), cache: 'no-store' }).catch(() => {});
  } catch (e) {}
}

chrome.runtime.onStartup.addListener(() => { try { doHeartbeat(); } catch (e) {} try { fetchConfig(); } catch (e) {} try { checkEntitlement(); } catch (e) {} try { syncDynamicContentScript(); } catch (e) {} });

const CONFIG_URL = WORKER_URL + '/api/config';

importScripts('configverify.js', 'entitlement-state.js');

async function fetchConfig() {
  try {
    const res = await fetch(CONFIG_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error('fetch ' + res.status);
    const raw = await res.text();
    if (raw.length > 64 * 1024) throw new Error('too large');
    const stored = await new Promise((resolve) => chrome.storage.local.get(['sg_config_seq'], resolve));
    const verified = await SGConfigVerify.verifyEnvelope(JSON.parse(raw), undefined, undefined, stored.sg_config_seq || 0);
    if (!verified.ok) return;
    await new Promise((resolve) => chrome.storage.local.set({
      sg_config: verified.data,
      sg_config_at: Date.now(),
      sg_config_seq: verified.seq,
      sg_config_exp: verified.exp,
    }, resolve));
  } catch (e) {
    // fall back to cached last good config (already in storage)
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'heartbeat') { doHeartbeat(); return; }
  if (alarm.name === 'configCheck') { fetchConfig(); return; }
  if (alarm.name !== 'licenseCheck') return;
  // Daily Pro revalidation: revoke only on a definitive "invalid" answer
  chrome.storage.local.get(['sg_license_key', 'sg_isPro'], (res) => {
    if (res.sg_license_key && res.sg_isPro) verifyLicense(res.sg_license_key, () => {});
  });
  checkEntitlement();
});
