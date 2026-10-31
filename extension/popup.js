(() => {
  'use strict';

  // The approved popup design moved team configuration to the web console, so
  // those controls are no longer in the markup. Anything absent resolves to a
  // harmless stub: the remaining wiring runs instead of throwing on first use.
  const STUB = {
    addEventListener() {}, removeEventListener() {}, click() {}, focus() {}, blur() {},
    setAttribute() {}, getAttribute() { return null; }, removeAttribute() {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    querySelector() { return STUB; }, querySelectorAll() { return []; },
    appendChild() {}, remove() {}, contains() { return false; },
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
    style: {}, dataset: {}, options: [],
    value: '', checked: false, disabled: false, hidden: false,
    textContent: '', innerHTML: '', placeholder: '',
  };
  const $ = (id) => document.getElementById(id) || STUB;
  const UPGRADE_URL = 'https://dariocositore.com/tools/api-key-leak-intercept/upgrade/';
  const CONSOLE_FEED_URL = 'https://dariocositore.com/tools/api-key-leak-intercept/manage/#feed';

  // Two artboards: no pro capability yet (upsell) and unlocked (settings).
  // A team entitlement counts here the same way it counts for detection, or
  // an employee whose org paid sees a sign-in prompt while their Pro
  // features already work.
  function applyShell() {
    const out = document.getElementById('sgp-shell-out');
    const inn = document.getElementById('sgp-shell-in');
    if (!out || !inn) return;
    const cap = isPro || entitled;
    out.style.display = cap ? 'none' : 'flex';
    inn.style.display = cap ? 'flex' : 'none';
  }

  let settings = { enabled: true, categories: { apiKeys: true, pii: false, network: false }, customPatterns: [], autoRedact: false };
  let org = { teamMode: false, orgId: '', orgToken: '', userEmail: '', alertOnWarn: true, alertOnSendAnyway: true, alertOnBlock: true, alertOnRedact: true, heartbeat: false, extraSites: [], alertEndpoint: '', blockSendAnyway: false, universalMode: false, extraEmails: '', channels: { slack: { enabled: false, webhookUrl: '' }, teams: { enabled: false, webhookUrl: '' }, telegram: { enabled: false, botToken: '', chatId: '' }, webhook: { enabled: false, url: '' }, email: { enabled: false, apiKey: '', to: '' } } };
  let leaksStopped = 0;
  let isPro = false;
  let licenseInvalid = false;
  let accountEmail = '';
  let logCache = [];
  let caught = null;
  let isManaged = false;
  let lockState = null; // null | 'managed' | 'full'
  let policyCats = { pii: false, network: false };
  let entitled = false; // server-confirmed paid team entitlement


  function showReviewCard() {
    const card = $('sgp-review-card');
    if (!card) return;
    chrome.storage.local.get(['sg_warnings_shown','sg_review_prompt_count','sg_review_dismissed'], (r) => {
      const shown = r.sg_warnings_shown || 0;
      const prompts = r.sg_review_prompt_count || 0;
      const dismissed = !!r.sg_review_dismissed;
      if (dismissed || prompts >= 2 || shown < 10) { card.style.display = 'none'; return; }
      chrome.storage.local.set({ sg_review_prompt_count: prompts + 1 });
      card.style.display = 'block';
    });
  }

  function load() {
    chrome.runtime.sendMessage({ type: 'getSettings' }, (res) => {
      if (!res) return;
      settings = res.settings || settings;
      settings.hideProHint = !!res.hideProHint;
      leaksStopped = res.leaksStopped || 0;
      isPro = !!res.isPro;
      entitled = !!res.entitled;
      licenseInvalid = !!res.licenseInvalid;
      org = res.org || org;
      try {
        const stored = window.localStorage.getItem('aki_account_email');
        if (stored) accountEmail = stored;
      } catch (e) {}
      chrome.storage.local.get(['sg_account_email'], (r2) => {
        if (r2 && r2.sg_account_email) accountEmail = r2.sg_account_email;
        render();
      });
      chrome.storage.local.get(['sg_sync_status'], (r3) => {
        const el = document.getElementById('sgp-sync-status');
        if (!el) return;
        const sy = r3 && r3.sg_sync_status;
        if (!sy) { el.textContent = 'Nothing sent yet'; return; }
        const when = sy.at ? relTime(new Date(sy.at).toISOString()) : '';
        el.textContent = sy.ok ? 'Last catch reached the console ' + when : 'Not synced: ' + (sy.error || 'unknown error');
      });
      chrome.runtime.sendMessage({ type: 'getAuditLog' }, (r) => {
        logCache = (r && r.log) || [];
        computeCaught();
        render();
        renderTeam();
        showReviewCard();
        reverifyLicense();
        if (isWide()) expandPanels();
      });
    });
  }

  /* --------------------------- hero states --------------------------- */
  const CAUGHT_COPY = {
    blocked:     { title: 'Caught.',     sub: 'Held back before sending.',  note: 'Blocked' },
    redacted:    { title: 'Caught.',     sub: 'Redacted before sending.',   note: 'Redacted' },
    sent_anyway: { title: 'Sent anyway.', sub: 'You overrode the warning.', note: 'Sent anyway' },
    warned:      { title: 'Caught.',     sub: 'A warning was raised.',      note: 'Warned' },
  };

  function computeCaught() {
    caught = null;
    const a = logCache[0];
    if (!a || !a.timestamp) return;
    const age = Date.now() - new Date(a.timestamp).getTime();
    if (age < 0 || age > 15 * 60 * 1000) return;
    const c = CAUGHT_COPY[a.action] || CAUGHT_COPY.warned;
    caught = {
      title: c.title,
      sub: c.sub,
      type: (a.secretTypes || []).join(', ') || 'Secret',
      site: a.site || '',
      note: c.note + ' · ' + relTime(a.timestamp),
    };
  }

  function relTime(ts) {
    const diff = Math.max(0, Date.now() - new Date(ts).getTime());
    const min = Math.floor(diff / 60000);
    if (min < 1) return 'just now';
    if (min < 60) return min + ' min ago';
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + ' h ago';
    return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function resetLabel() {
    const next = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1);
    return next.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function setRing(n) {
    const el = $('sgp-ring');
    if (!el) return;
    if (isPro) { el.removeAttribute('stroke-dasharray'); return; }
    if (n <= 0) { el.setAttribute('stroke-dasharray', '0 415'); return; }
    // each pair is one used segment; the trailing dash closes the run
    let s = '';
    for (let i = 1; i < n; i++) s += '62.9 20 ';
    el.setAttribute('stroke-dasharray', s + '62.9 300');
  }

  function reveal(el) {
    if (!el || !el.getClientRects().length) return;
    const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
    el.scrollIntoView({ block: 'start', behavior });
  }

  function isWide() {
    return window.matchMedia('(min-width: 560px)').matches;
  }

  function panelOpen(id, open) {
    const el = $(id);
    if (!el) return;
    el.style.display = open ? 'block' : 'none';
    const btn = document.querySelector('[data-panel="' + id + '"]');
    if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function expandPanels() {
    panelOpen('sgp-plan', true);
    panelOpen('sgp-team', true);
  }

  function render() {
    applyShell();
    const locked = !!lockState || $('sgp-enabled').disabled;
    const enabled = locked || !!settings.enabled;
    $('sgp-enabled').checked = enabled;

    // The covered row must not claim coverage while protection is paused.
    const coveredLabel = document.getElementById('sgp-covered-label');
    const coveredCheck = document.getElementById('sgp-covered-check');
    if (coveredLabel) coveredLabel.textContent = enabled ? 'Covered now' : 'Paused';
    if (coveredCheck) coveredCheck.classList.toggle('is-off', !enabled);

    // mirror the live readouts into the signed-in artboard
    const setTxt = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
    const enabledIn = document.getElementById('sgp-enabled-in');
    if (enabledIn) enabledIn.checked = enabled;
    setTxt('sgp-status-in', enabled ? 'Guarding.' : 'Paused.');
    setTxt('sgp-month-count', leaksStopped + ' leak' + (leaksStopped === 1 ? '' : 's'));
    const customCount = document.getElementById('sgp-custom-count');
    if (customCount) {
      const n = (settings.customPatterns || []).length;
      customCount.textContent = n ? (n + ' active') : 'None yet';
    }
    const accountLine = document.getElementById('sgp-account-line');
    if (accountLine) {
      accountLine.textContent = accountEmail || 'Signed in';
      const sub = document.createElement('span');
      sub.className = 'sub';
      sub.textContent = accountEmail ? 'Signed in' : 'Pro licence active';
      accountLine.appendChild(sub);
    }
    const evIn = document.getElementById('sgp-event-in');
    if (evIn) {
      if (caught && enabled) {
        setTxt('sgp-event-type-in', caught.type);
        setTxt('sgp-event-site-in', caught.site);
        setTxt('sgp-event-note-in', caught.note);
        evIn.style.display = 'block';
      } else {
        evIn.style.display = 'none';
      }
    }
    $('sgp-cat-api').checked = $('sgp-cat-api').disabled || !!settings.categories.apiKeys;
    $('sgp-cat-pii').checked = !!settings.categories.pii;
    $('sgp-cat-net').checked = !!settings.categories.network;

    // Pro capabilities come with a Pro license or the server-confirmed paid
    // entitlement. Managed installs and typed org IDs never unlock them.
    const proCap = isPro || entitled;
    $('sgp-cat-pii').disabled = !proCap;
    $('sgp-cat-net').disabled = !proCap;
    $('sgp-auto-redact').disabled = !proCap;
    $('sgp-auto-redact').checked = !!settings.autoRedact;
    labelWithPro($('sgp-cat-pii'), 'Personal data (email, phones, cards, national IDs)');
    labelWithPro($('sgp-cat-net'), 'IP addresses');
    const planNote = $('sgp-plan-note');
    if (planNote) {
      planNote.style.display = ((policyCats.pii || policyCats.network) && !proCap) ? 'block' : 'none';
    }

    // Universal mode requires Pro or a configured Org ID (`org_...`)
    $('sgp-universal-mode').disabled = !proCap;
    labelWithPro($('sgp-universal-mode'), 'Universal mode (scan all sites)', ' · Pro/Team');

    // Usage meter: five segments around the dial, plus one plain-language line
    setRing(Math.min(5, leaksStopped));
    const note = $('sgp-usage-note');
    note.textContent = leaksStopped + ' leaks stopped this month.';

    $('sgp-protag').textContent = isPro ? 'Pro plan' : (proCap ? 'Team' : 'Free plan');
    $('sgp-protag-in').textContent = isPro ? 'Pro' : 'Team';
    $('sgp-protag').className = 'chip' + (proCap ? ' is-pro' : '');

    $('sgp-hero').className = 'hero' + (enabled ? ' is-on' : ' is-off');
    $('sgp-disc').className = 'disc' + (enabled ? ' is-on' : '') + (locked ? ' is-locked' : '');
    $('sgp-mark').className = 'mark' + (enabled ? ' is-on' : ' is-off');
    $('sgp-status').className = 'title' + (enabled ? '' : ' is-off');
    $('sgp-status').textContent = enabled ? 'Guarding.' : 'Paused.';
    $('sgp-hero-sub').textContent = locked
      ? 'Managed by your organization. Locked by your administrator.'
      : (!enabled
          ? 'Protection is off. Press the key to resume.'
          : (caught ? caught.sub : '40+ AI chats and work tools. Press the key to pause.'));

    const ev = $('sgp-event');
    if (caught && enabled) {
      $('sgp-event-type').textContent = caught.type;
      $('sgp-event-site').textContent = caught.site;
      $('sgp-event-note').textContent = caught.note;
      ev.style.display = 'block';
    } else {
      ev.style.display = 'none';
    }

    if (proCap) {
      // visibility of the editor belongs to the chevron, not to render()
      $('sgp-custom').value = (settings.customPatterns || []).join('\n');
      $('sgp-cta').style.display = 'none';
    } else {
      $('sgp-custom-section').style.display = 'none';
      $('sgp-cta').style.display = 'block';
      $('sgp-upgrade-label').textContent = 'Unlock Pro';
    }

    const setupBlock = $('sgp-setup-block');
    if (setupBlock) setupBlock.style.display = (!isManaged && org.teamMode && org.orgId) ? 'block' : 'none';

    const ver = $('sgp-version');
    if (ver) ver.textContent = 'v' + chrome.runtime.getManifest().version;
    applyLock();
  }

  function labelWithPro(input, baseText, lockSuffix) {
    const span = input && input.nextElementSibling;
    if (!span) return;
    const suffix = input.disabled ? (lockSuffix || ' · Pro') : '';
    span.textContent = baseText + suffix;
    span.classList.toggle('dim', input.disabled);
  }

  // Runs last inside render(): locked controls stay read-only after every pass
  function applyLock() {
    if (!lockState) return;
    const reason = 'Managed by your organization';
    $('sgp-enabled').checked = true;
    $('sgp-enabled').disabled = true;
    labelWithPro($('sgp-enabled'), 'Extension enabled', ' · ' + reason);
    $('sgp-cat-api').checked = true;
    $('sgp-cat-api').disabled = true;
    labelWithPro($('sgp-cat-api'), 'API keys and tokens', ' · ' + reason);
    if (lockState === 'full') {
      $('sgp-cat-pii').checked = policyCats.pii;
      $('sgp-cat-pii').disabled = true;
      labelWithPro($('sgp-cat-pii'), 'Personal data (email, phones, cards, national IDs)', ' · ' + reason);
      $('sgp-cat-net').checked = policyCats.network;
      $('sgp-cat-net').disabled = true;
      labelWithPro($('sgp-cat-net'), 'IP addresses', ' · ' + reason);
    }
  }

  function applyManagedUI() {
    $('sgp-managed-mode').checked = isManaged;
    const channels = $('sgp-channels');
    if (channels) channels.style.display = isManaged ? 'none' : 'block';
    const setupBlock = $('sgp-setup-block');
    if (setupBlock) setupBlock.style.display = 'none';
    const note = $('sgp-storage-note');
    if (note) note.style.display = isManaged ? 'none' : 'block';
    if (lockState) {
      settings.enabled = true;
      settings.categories.apiKeys = true;
      if (lockState === 'full') {
        settings.categories.pii = policyCats.pii;
        settings.categories.network = policyCats.network;
      }
    }
    if (isManaged && org.teamMode && org.orgId) {
      $('sgp-team-mode').disabled = true;
      $('sgp-org-id').readOnly = true;
    }
    render();
  }

  function renderTeam() {
    $('sgp-team-mode').checked = !!org.teamMode;
    $('sgp-universal-mode').checked = !!org.universalMode;
    $('sgp-team-fields').style.display = org.teamMode ? 'block' : 'none';
    try {
      if (chrome.management && chrome.management.getSelf) {
        chrome.management.getSelf((info) => {
          if (chrome.runtime.lastError) return;
          if (info && info.installType === 'admin') {
            isManaged = true;
            if (!lockState) lockState = 'managed';
            applyManagedUI();
          }
        });
      }
    } catch (e) {}
    try {
      if (chrome.storage.managed) {
        chrome.storage.managed.get(null, (m) => {
          if (m && Object.keys(m).length > 0) {
            isManaged = true;
            if (m.orgId) {
              org.orgId = m.orgId;
              org.teamMode = true;
              $('sgp-team-mode').checked = true;
              $('sgp-org-id').value = m.orgId;
              $('sgp-team-fields').style.display = 'block';
            }
            if (m.orgToken) org.orgToken = String(m.orgToken);
            if (m.userEmail) { org.userEmail = String(m.userEmail); $('sgp-user-email').value = org.userEmail; }
            if (typeof m.universalMode === 'boolean') { org.universalMode = m.universalMode; $('sgp-universal-mode').checked = m.universalMode; }
            if (Array.isArray(m.customPatterns)) settings.customPatterns = m.customPatterns;
            if (typeof m.heartbeat === 'boolean') org.heartbeat = m.heartbeat;
            if (Array.isArray(m.extraSites)) org.extraSites = m.extraSites;
            if (m.alertEndpoint) org.alertEndpoint = String(m.alertEndpoint);
            if (typeof m.blockSendAnyway === 'boolean') org.blockSendAnyway = m.blockSendAnyway;
            if (typeof m.alertOnRedact === 'boolean') org.alertOnRedact = m.alertOnRedact;
            if (typeof m.alertOnWarn === 'boolean') org.alertOnWarn = m.alertOnWarn;
            if (typeof m.alertOnSendAnyway === 'boolean') org.alertOnSendAnyway = m.alertOnSendAnyway;
            if (typeof m.alertOnBlock === 'boolean') org.alertOnBlock = m.alertOnBlock;
            if (typeof m.autoRedact === 'boolean') { settings.autoRedact = m.autoRedact; $('sgp-auto-redact').checked = m.autoRedact; }
            if (m.enforceJustification === true) settings.enforceJustification = true;
            if (typeof m.detectPii === 'boolean') {
              policyCats.pii = m.detectPii;
              settings.categories.pii = m.detectPii;
              $('sgp-cat-pii').checked = m.detectPii;
            }
            if (typeof m.detectNetwork === 'boolean') {
              policyCats.network = m.detectNetwork;
              settings.categories.network = m.detectNetwork;
              $('sgp-cat-net').checked = m.detectNetwork;
            }
            if (m.lockSettings === true) lockState = 'full';
            else if (!lockState) lockState = 'managed';
            applyManagedUI();
          }
        });
      }
    } catch (e) {}
    $('sgp-org-id').value = org.orgId || '';
    $('sgp-user-email').value = org.userEmail || '';
    $('sgp-ch-slack').checked = !!(org.channels && org.channels.slack && org.channels.slack.enabled);
    $('sgp-slack-url').value = (org.channels && org.channels.slack && org.channels.slack.webhookUrl) || '';
    $('sgp-ch-teams').checked = !!(org.channels && org.channels.teams && org.channels.teams.enabled);
    $('sgp-teams-url').value = (org.channels && org.channels.teams && org.channels.teams.webhookUrl) || '';
    $('sgp-ch-telegram').checked = !!(org.channels && org.channels.telegram && org.channels.telegram.enabled);
    $('sgp-tg-token').value = (org.channels && org.channels.telegram && org.channels.telegram.botToken) || '';
    $('sgp-tg-chat').value = (org.channels && org.channels.telegram && org.channels.telegram.chatId) || '';
    $('sgp-ch-webhook').checked = !!(org.channels && org.channels.webhook && org.channels.webhook.enabled);
    $('sgp-webhook-url').value = (org.channels && org.channels.webhook && org.channels.webhook.url) || '';
    $('sgp-ch-email').checked = !!(org.channels && org.channels.email && org.channels.email.enabled);
    $('sgp-email-apikey').value = (org.channels && org.channels.email && org.channels.email.apiKey) || '';
    $('sgp-email-to').value = (org.channels && org.channels.email && org.channels.email.to) || '';
    $('sgp-alert-block').checked = org.alertOnBlock !== false;
    $('sgp-alert-send').checked = org.alertOnSendAnyway !== false;
    $('sgp-alert-warn').checked = org.alertOnWarn !== false;
    $('sgp-extra-emails').value = org.extraEmails || '';
    applyManagedUI();
  }

  function collectSettings() {
    return {
      enabled: $('sgp-enabled').checked,
      categories: {
        apiKeys: $('sgp-cat-api').checked,
        pii: $('sgp-cat-pii').checked,
        network: $('sgp-cat-net').checked,
      },
      customPatterns: settings.customPatterns || [],
      autoRedact: $('sgp-auto-redact').checked,
    };
  }

  function collectOrg() {
    return {
      teamMode: $('sgp-team-mode').checked,
      orgId: $('sgp-org-id').value.trim(),
      orgToken: org.orgToken || '',
      userEmail: $('sgp-user-email').value.trim(),
      universalMode: $('sgp-universal-mode').checked,
      extraEmails: $('sgp-extra-emails').value.trim(),
      alertOnBlock: $('sgp-alert-block').checked,
      alertOnSendAnyway: $('sgp-alert-send').checked,
      alertOnWarn: $('sgp-alert-warn').checked,
      alertOnRedact: org.alertOnRedact !== false,
      heartbeat: !!org.heartbeat,
      extraSites: org.extraSites || [],
      alertEndpoint: org.alertEndpoint || '',
      blockSendAnyway: !!org.blockSendAnyway,
      // Managed installs send alerts to the worker only, so hidden channel
      // fields are not collected and the stored config stays untouched
      channels: isManaged ? (org.channels || {}) : {
        slack: { enabled: $('sgp-ch-slack').checked, webhookUrl: $('sgp-slack-url').value.trim() },
        teams: { enabled: $('sgp-ch-teams').checked, webhookUrl: $('sgp-teams-url').value.trim() },
        telegram: { enabled: $('sgp-ch-telegram').checked, botToken: $('sgp-tg-token').value.trim(), chatId: $('sgp-tg-chat').value.trim() },
        webhook: { enabled: $('sgp-ch-webhook').checked, url: $('sgp-webhook-url').value.trim() },
        email: { enabled: $('sgp-ch-email').checked, apiKey: $('sgp-email-apikey').value.trim(), to: $('sgp-email-to').value.trim() },
      },
    };
  }

  function save() {
    const s = collectSettings();
    settings = { ...settings, ...s };
    chrome.runtime.sendMessage({ type: 'saveSettings', settings: s }, () => {});
  }

  function saveTeam() {
    const o = collectOrg();
    org = o;
    chrome.runtime.sendMessage({ type: 'saveOrg', org: o }, (res) => {
      if (res && res.ok) {
        chrome.runtime.sendMessage({ type: 'getSettings' }, (s) => {
          if (s) { entitled = !!s.entitled; isPro = !!s.isPro; }
          render();
          showToast('Team settings saved');
        });
      } else if (res && res.locked) showToast('Managed by your organization. Settings are read-only.');
    });
  }

  // wire up
  document.querySelectorAll('.navlink[data-panel]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const el = $(btn.dataset.panel);
      if (!el) return;
      const open = el.style.display !== 'block';
      panelOpen(btn.dataset.panel, open);
      if (open) reveal(btn);
    });
  });

  ['sgp-enabled','sgp-cat-api','sgp-cat-pii','sgp-cat-net','sgp-auto-redact'].forEach(id => {
    $(id).addEventListener('change', () => {
      save();
      render(); // hero state, headline and switches follow the new value
    });
  });

  $('sgp-team-mode').addEventListener('change', () => {
    $('sgp-team-fields').style.display = $('sgp-team-mode').checked ? 'block' : 'none';
    saveTeam();
    render(); // universal mode availability depends on team mode
  });

  $('sgp-universal-mode').addEventListener('change', () => {
    // Universal mode scans every site, which needs host access beyond the AI
    // chat list. That grant is optional so the install stays scoped; ask for
    // it now, in the click, and undo the toggle if the user declines.
    if ($('sgp-universal-mode').checked && chrome.permissions && chrome.permissions.request) {
      chrome.permissions.request({ origins: ['<all_urls>'] }, (granted) => {
        if (!granted) {
          $('sgp-universal-mode').checked = false;
          showToast('Universal mode needs access to all sites.');
          render();
          return;
        }
        saveTeam();
      });
      return;
    }
    saveTeam();
  });

  $('sgp-save-custom').addEventListener('click', () => {
    const lines = $('sgp-custom').value.split('\n').map(l => l.trim())
      .filter(l => l && l.length <= 2000)
      .slice(0, 50);
    settings.customPatterns = lines;
    save();
    showToast('Patterns saved');
  });

  $('sgp-apply-setup').addEventListener('click', async () => {
    const raw = ($('sgp-setup-code').value || '').trim();
    const res = await SGSetup.parse(raw);
    if (!res.ok) { showToast(res.error); return; }
    const obj = res.data;
    if (obj.orgId) { org.orgId = obj.orgId; $('sgp-org-id').value = org.orgId; org.teamMode = true; $('sgp-team-mode').checked = true; $('sgp-team-fields').style.display = 'block'; }
    if (obj.orgToken) org.orgToken = obj.orgToken;
    if (obj.userEmail) { org.userEmail = obj.userEmail; $('sgp-user-email').value = org.userEmail; }
    if (typeof obj.universalMode === 'boolean') { org.universalMode = obj.universalMode; $('sgp-universal-mode').checked = org.universalMode; }
    if (Array.isArray(obj.extraSites)) org.extraSites = obj.extraSites;
    if (typeof obj.heartbeat === 'boolean') org.heartbeat = obj.heartbeat;
    if (typeof obj.blockSendAnyway === 'boolean') org.blockSendAnyway = obj.blockSendAnyway;
    if (typeof obj.autoRedact === 'boolean') { settings.autoRedact = obj.autoRedact; }
    saveTeam();
    save();
    showToast('Setup code applied.');
  });

  $('sgp-copy-diagnostics').addEventListener('click', () => {
    chrome.storage.local.get(['sg_license_key', 'sg_sync_status'], (st) => {
      const k = String(st.sg_license_key || '');
      const diag = {
        version: chrome.runtime.getManifest().version,
        isPro: !!isPro,
        licenseInvalid: !!licenseInvalid,
        license: k ? k.slice(0, 3) + '...' + k.slice(-4) : '(none stored)',
        enabled: !!settings.enabled,
        categories: settings.categories,
        autoRedact: !!settings.autoRedact,
        teamMode: !!org.teamMode,
        orgId: org.orgId || '',
        managed: !!isManaged,
        leaksStopped: leaksStopped,
        hideProHint: !!settings.hideProHint,
        sync: st.sg_sync_status || null,
      };
      const text = JSON.stringify(diag, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => showToast('Diagnostics copied.')).catch(() => showToast('Copy failed.'));
      } else {
        showToast('Clipboard unavailable.');
      }
    });
  });

  document.querySelectorAll('[data-upgrade]').forEach((b) => {
    b.addEventListener('click', () => chrome.tabs.create({ url: UPGRADE_URL }));
  });

  $('sgp-save-team').addEventListener('click', () => {
    saveTeam();
    render();
  });

  $('sgp-already-pro').addEventListener('click', () => {
    // Sign in happens on the web. The console passes the licence key back to
    // this extension and the tab closes itself, so the user lands here again
    // with Pro already active. extid is what lets the page address us.
    const extId = chrome.runtime && chrome.runtime.id ? chrome.runtime.id : '';
    const url = 'https://dariocositore.com/tools/api-key-leak-intercept/manage/?ext=1'
      + (extId ? '&extid=' + encodeURIComponent(extId) : '');
    chrome.tabs.create({ url });
  });

  $('sgp-upgrade').addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://dariocositore.com/tools/api-key-leak-intercept/upgrade/' });
  });

  /* ------------- signed-in artboard wiring ------------- */
  // The two artboards carry separate controls, so the second one needs its own
  // handlers and its own readouts. Everything below routes back through the
  // same state the signed-out half already uses.
  (function wireStateB() {
    const on = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };

    // master toggle in the signed-in hero: delegate to the real control so the
    // storage write, render and broadcast logic stay in one place
    const enabledIn = document.getElementById('sgp-enabled-in');
    const enabledMain = document.getElementById('sgp-enabled');
    if (enabledIn && enabledMain) {
      enabledIn.addEventListener('change', () => {
        enabledMain.checked = enabledIn.checked;
        enabledMain.dispatchEvent(new Event('change', { bubbles: true }));
      });
    }

    on('sgp-nav-custom', () => {
      const sec = document.getElementById('sgp-custom-section');
      if (!sec) return;
      const open = !sec.classList.contains('is-open');
      sec.classList.toggle('is-open', open);
      $('sgp-nav-custom').setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    on('sgp-open-console', () => {
      chrome.tabs.create({ url: 'https://dariocositore.com/tools/api-key-leak-intercept/manage/' });
    });
    on('sgp-team-console', () => {
      chrome.tabs.create({ url: 'https://dariocositore.com/tools/api-key-leak-intercept/manage/' });
    });

    on('sgp-signout', () => {
      chrome.storage.local.remove(['sg_license_key', 'sg_isPro', 'sg_account_email', 'sg_license_invalid'], () => {
        isPro = false;
        licenseInvalid = false;
        accountEmail = '';
        render();
        licenseStatus('Signed out.', 'ok');
      });
    });

  })();

  /* --------------------------- Audit log --------------------------- */
  // The audit trail lives in the customer console (Intercept Feed): one place
  // for solo users and team managers alike.
  $('sgp-view-log').addEventListener('click', () => {
    chrome.tabs.create({ url: CONSOLE_FEED_URL });
  });

  function showToast(msg) {
    const old = document.body.querySelector('.sgp-toast-temp');
    if (old) old.remove();
    const t = document.createElement('div');
    t.className = 'sgp-toast-temp';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2000);
  }

  /* --------------------------- License ----------------------------- */
  function licenseStatus(text, kind) {
    const el = $('sgp-license-status');
    el.textContent = text;
    el.className = 'status' + (kind ? ' ' + kind : '');
  }

  // Account sign-in: the checkout account, verified server-side. A successful
  // reply carries the licence key and the background stores it through the same
  // path a pasted key takes, so Pro state is identical either way.
  function accountSignIn() {
    const email = $('sgp-account-email').value.trim();
    const password = $('sgp-account-password').value || '';
    if (!email || email.indexOf('@') < 1) { licenseStatus('Enter your email address.', 'err'); $('sgp-account-email').focus(); return; }
    if (!password) { licenseStatus('Enter your password.', 'err'); $('sgp-account-password').focus(); return; }
    licenseStatus('Signing in...');
    chrome.runtime.sendMessage({ type: 'accountLogin', email, password }, (res) => {
      if (!res) { licenseStatus('Sign in failed. Try again.', 'err'); return; }
      if (res.valid === null) { licenseStatus('Could not reach the server.', 'err'); return; }
      if (res.noLicense) {
        licenseStatus('Signed in. No license on this account yet.', 'err');
        return;
      }
      if (res.valid) {
        isPro = true;
        licenseInvalid = false;
        accountEmail = email;
        $('sgp-account-password').value = '';
        licenseStatus('Signed in. Pro activated.', 'ok');
        render();
      } else {
        licenseStatus(res.error || 'Sign in failed.', 'err');
      }
    });
  }

  $('sgp-account-signin').addEventListener('click', accountSignIn);
  $('sgp-account-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); accountSignIn(); }
  });
  $('sgp-account-email').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('sgp-account-password').focus(); }
  });

  $('sgp-verify-license').addEventListener('click', () => {
    const key = $('sgp-license-key').value.trim().toUpperCase();
    if (!key) { licenseStatus('Enter a license key.', 'err'); return; }
    licenseStatus('Verifying...');
    chrome.runtime.sendMessage({ type: 'verifyLicense', key }, (res) => {
      if (!res) { licenseStatus('Verification failed. Try again.', 'err'); return; }
      if (res.valid === null) { licenseStatus('Could not reach verification server.', 'err'); return; }
      if (res.valid) {
        isPro = true;
        licenseInvalid = false;
        licenseStatus('License verified. Pro activated.', 'ok');
        render();
      } else {
        licenseStatus('Invalid: ' + (res.error || 'unknown error'), 'err');
      }
    });
  });

  function reverifyLicense() {
    chrome.storage.local.get(['sg_license_key'], (res) => {
      if (!res.sg_license_key) return;
      $('sgp-license-key').value = res.sg_license_key;
      chrome.runtime.sendMessage({ type: 'reverifyLicense' }, (r) => {
        if (!r || r.valid === null) return; // offline: leave state untouched
        if (r.valid) {
          const wasInvalid = licenseInvalid;
          isPro = true;
          licenseInvalid = false;
          render();
          if (wasInvalid) licenseStatus('License re-verified. Pro active.', 'ok');
        } else {
          isPro = false;
          licenseInvalid = true;
          render();
          licenseStatus('License no longer valid: ' + (r.error || 'deactivated'), 'err');
        }
      });
    });
  }

  const reviewNow = $('sgp-review-now');
  if (reviewNow) reviewNow.addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://chromewebstore.google.com/detail/' + chrome.runtime.id });
    chrome.storage.local.set({ sg_review_dismissed: true });
    $('sgp-review-card').style.display = 'none';
  });
  const reviewLater = $('sgp-review-later');
  if (reviewLater) reviewLater.addEventListener('click', () => {
    $('sgp-review-card').style.display = 'none';
  });
  const reviewNever = $('sgp-review-never');
  if (reviewNever) reviewNever.addEventListener('click', () => {
    chrome.storage.local.set({ sg_review_dismissed: true });
    $('sgp-review-card').style.display = 'none';
  });

  load();
})();
