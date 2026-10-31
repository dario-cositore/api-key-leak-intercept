/**
 * API Key Leak Intercept: content script
 *
 * Detects API keys / secrets / PII in the text about to be sent and shows a
 * warning modal before the message leaves the browser.
 *
 * Detection is 100% local (regex). Nothing is transmitted in personal mode.
 */
(() => {
  'use strict';

  // The manifest registers this script for the built-in AI chat list, and
  // background.js registers it again at runtime for Universal mode or
  // org-supplied sites. Where those two sets overlap Chrome would inject it
  // twice, so the first instance claims the page and the rest leave.
  if (globalThis.__sgContentScriptLoaded) return;
  globalThis.__sgContentScriptLoaded = true;

  const OVERLAY_ID = 'sg-overlay';
  const DRAWER_ID = 'sg-drawer';
  const KEY_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></svg>';
  const BARS_SVG = '<svg width="20" height="13" viewBox="0 0 22 14" aria-hidden="true"><rect width="22" height="6" rx="2" fill="#C6F24E"/><rect y="8" width="14" height="6" rx="2" fill="#1D1D1F"/></svg>';
  const PIN_SVG = '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 17v5"/><path d="M9 10.8a2 2 0 0 1-1.1 1.8l-1.8.9A2 2 0 0 0 5 15.2V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.8a2 2 0 0 0-1.1-1.8l-1.8-.9A2 2 0 0 1 15 10.8V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>';
  const EXT_VERSION = chrome.runtime.getManifest().version;
  const UPGRADE_URL = 'https://dariocositore.com/tools/api-key-leak-intercept/upgrade/';

  // Detection engine lives in detect.js (loaded first, see manifest)
  const Detect = globalThis.SGDetect;
  // Entitlement cache rules live in entitlement-state.js (also in manifest)
  const Entitlement = globalThis.SGEntitlement;

  /* ------------------------------------------------------------------ */
  /* Known AI chat sites (targeted mode)                                 */
  /* ------------------------------------------------------------------ */
  const KNOWN_AI_SITES = [
    'chatgpt.com', 'chat.openai.com', 'platform.openai.com',
    'claude.ai', 'console.anthropic.com',
    'google.com', 'www.google.com',
    'gemini.google.com', 'bard.google.com', 'aistudio.google.com',
    'copilot.microsoft.com', 'copilot.cloud.microsoft', 'bing.com',
    'perplexity.ai', 'www.perplexity.ai',
    'chat.mistral.ai', 'lechat.mistral.ai',
    'chat.deepseek.com',
    'huggingface.co',
    'poe.com',
    'you.com',
    'phind.com',
    'character.ai', 'beta.character.ai',
    'pi.ai',
    'meta.ai',
    'grok.com', 'x.com',
    'coral.cohere.com', 'dashboard.cohere.com',
    'jasper.ai',
    'copy.ai',
    'writesonic.com',
    'notion.so', 'notion.com',
    'github.com',
    'aws.amazon.com',
    'console.groq.com',
    'fireworks.ai',
    'together.ai', 'api.together.xyz',
    'replicate.com',
    'stability.ai',
    'firefly.adobe.com',
    'canva.com',
    'figma.com',
    'slack.com',
    'teams.microsoft.com',
    'discord.com',
    'web.whatsapp.com',
    'telegram.org', 'web.telegram.org',
  ];

  function isKnownAiSite() {
    if (location.protocol === 'file:' && location.pathname && location.pathname.endsWith('manual.html')) return true;
    const host = location.hostname.toLowerCase();
    if ((settings.extraSites || []).some(s => host === String(s).toLowerCase() || host.endsWith('.' + String(s).toLowerCase()))) return true;
    if ((settings.configAiSites || []).some(s => host === String(s).toLowerCase() || host.endsWith('.' + String(s).toLowerCase()))) return true;
    return KNOWN_AI_SITES.some(s => host === s || host.endsWith('.' + s));
  }

  function shouldScan() {
    if (!settings.enabled) return false;
    const host = location.hostname.toLowerCase();
    if ((settings.configExcludedSites || []).some(s => host === String(s).toLowerCase() || host.endsWith('.' + String(s).toLowerCase()))) return false;
    // Universal mode requires Pro, a managed install, or a paid team entitlement
    if (settings.universalMode && hasProCap()) return true;
    return isKnownAiSite();
  }

  /* ------------------------------------------------------------------ */
  /* State                                                              */
  /* ------------------------------------------------------------------ */
  let settings = {
    enabled: true,
    categories: { apiKeys: true, pii: false, network: false },
    customPatterns: [],
    autoRedact: false,
    entitled: false,
    configAiSites: [],
    configExcludedSites: [],
    isPro: false,
    teamMode: false,
    orgId: '',
    orgToken: '',
    userEmail: '',
    extraEmails: '',
    alertOnWarn: true,
    alertOnSendAnyway: true,
    alertOnBlock: true,
    universalMode: false,
    managedMode: false,
    lockSettings: false,
    enforceJustification: false,
  };
  let leaksStopped = 0;
  let pendingSend = null; // { inputEl, text, sendFn }
  let escHandler = null;
  let tabHandler = null;
  let lastEnt = null;

  function recomputeEntitled() {
    settings.entitled = !!(Entitlement && Entitlement.entitledFrom(lastEnt, settings.orgId));
  }

  /* ------------------------------------------------------------------ */
  /* Storage sync                                                        */
  /* ------------------------------------------------------------------ */
  function loadSettings() {
    try {
      chrome.storage.local.get(['sg_settings', 'sg_leaks_stopped', 'sg_isPro', 'sg_license_key', 'sg_org', 'sg_hide_pro_hint', 'sg_config', 'sg_config_exp', 'sg_entitlement'], (res) => {
        if (res.sg_settings) {
          settings = { ...settings, ...res.sg_settings };
          // normalize shape
          settings.categories = {
            apiKeys: settings.categories && settings.categories.apiKeys !== false,
            pii: !!(settings.categories && settings.categories.pii),
            network: !!(settings.categories && settings.categories.network),
          };
          settings.customPatterns = settings.customPatterns || [];
          settings.autoRedact = !!settings.autoRedact;
        }
        if (typeof res.sg_leaks_stopped === 'number') leaksStopped = res.sg_leaks_stopped;
        // sg_isPro is the single source of truth (set by the service worker
        // after verification, cleared after a definitive revocation)
        if (res.sg_isPro && res.sg_license_key) settings.isPro = true;
        settings.hideProHint = !!res.sg_hide_pro_hint;
        // an expired signed config reverts to the bundled defaults
        const cfgExpired = typeof res.sg_config_exp === 'number' && res.sg_config_exp * 1000 <= Date.now();
        const cfg = cfgExpired ? {} : (res.sg_config || {});
        // cfg.extraPatterns is deliberately ignored: patterns ship in the
        // extension, so the signed config can only steer which sites are
        // scanned and never what counts as a finding.
        settings.configAiSites = Array.isArray(cfg.aiSites) ? cfg.aiSites : [];
        settings.configExcludedSites = Array.isArray(cfg.excludedSites) ? cfg.excludedSites : [];
        if (res.sg_org) {
          settings.teamMode = !!res.sg_org.teamMode;
          settings.orgId = res.sg_org.orgId || '';
          settings.orgToken = res.sg_org.orgToken || '';
          settings.userEmail = res.sg_org.userEmail || '';
          settings.alertOnRedact = res.sg_org.alertOnRedact !== false;
          settings.heartbeat = !!res.sg_org.heartbeat;
          settings.extraSites = res.sg_org.extraSites || [];
          settings.alertEndpoint = res.sg_org.alertEndpoint || '';
          settings.blockSendAnyway = !!res.sg_org.blockSendAnyway;
          settings.extraEmails = res.sg_org.extraEmails || '';
          settings.alertOnWarn = res.sg_org.alertOnWarn !== false;
          settings.alertOnSendAnyway = res.sg_org.alertOnSendAnyway !== false;
          settings.alertOnBlock = res.sg_org.alertOnBlock !== false;
          settings.universalMode = !!res.sg_org.universalMode;
        }
        // server-confirmed paid entitlement (TTL + grace, fails closed)
        lastEnt = res.sg_entitlement || null;
        recomputeEntitled();
        try {
          chrome.runtime.sendMessage({ type: 'getManagedState' }, (r) => {
            if (chrome.runtime.lastError) return;
            if (r && r.managed) {
              settings.managedMode = true;
              settings.enabled = true;
              updateWidget();
            }
          });
        } catch (e) {}
        try {
          if (chrome.storage.managed) {
            chrome.storage.managed.get(null, (m) => {
              if (m && Object.keys(m).length > 0) {
                settings.managedMode = true;
                settings.enabled = true;
                if (m.orgId) { settings.orgId = m.orgId; settings.teamMode = true; }
                if (m.orgToken) settings.orgToken = m.orgToken;
                if (m.userEmail) settings.userEmail = m.userEmail;
                if (typeof m.heartbeat === 'boolean') settings.heartbeat = m.heartbeat;
                if (Array.isArray(m.extraSites)) settings.extraSites = m.extraSites;
                if (m.alertEndpoint) settings.alertEndpoint = m.alertEndpoint;
                if (typeof m.blockSendAnyway === 'boolean') settings.blockSendAnyway = m.blockSendAnyway;
                if (typeof m.alertOnRedact === 'boolean') settings.alertOnRedact = m.alertOnRedact;
                if (typeof m.universalMode === 'boolean') settings.universalMode = m.universalMode;
                if (Array.isArray(m.customPatterns)) settings.customPatterns = m.customPatterns;
                settings.enforceJustification = m.enforceJustification === true;
                if (typeof m.autoRedact === 'boolean') settings.autoRedact = m.autoRedact;
                if (m.lockSettings === true) {
                  settings.lockSettings = true;
                  // Policy lock: local pause and category switches are ignored
                  settings.enabled = true;
                  settings.categories = {
                    apiKeys: true,
                    pii: !!m.detectPii,
                    network: !!m.detectNetwork,
                  };
                }
                // policy may be the only place orgId comes from
                recomputeEntitled();
                updateWidget();
              }
            });
          }
        } catch (e) {}
        updateWidget();
      });
    } catch (e) { /* storage unavailable */ }
  }

  /* ------------------------------------------------------------------ */
  /* Detection                                                          */
  /* ------------------------------------------------------------------ */
  function detectOpts() {
    // Detection patterns ship inside the extension. The signed config can
    // still steer which sites are scanned, but it never contributes regex, so
    // nothing remotely delivered can change what counts as a finding.
    return {
      enabled: settings.enabled,
      categories: settings.categories,
      isPro: settings.isPro,
      entitled: settings.entitled,
      customPatterns: settings.customPatterns || [],
    };
  }

  // Pro capabilities (redaction, PII, IP, custom patterns) come with a Pro
  // license or with a team/managed install
  function hasProCap() {
    return settings.isPro || !!settings.entitled;
  }

  function scan(text) {
    return Detect.scan(text, detectOpts());
  }

  /* ------------------------------------------------------------------ */
  /* Input extraction                                                   */
  /* ------------------------------------------------------------------ */
  function isEditable(el) {
    if (!el) return false;
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'textarea') return true;
    if (tag === 'input') {
      const type = (el.type || 'text').toLowerCase();
      return type !== 'file' && type !== 'checkbox' && type !== 'radio' && type !== 'button' && type !== 'submit';
    }
    if (el.isContentEditable) return true;
    return false;
  }

  function editableRoot(el) {
    if (!el) return null;
    if (el.closest) {
      const ce = el.closest('[contenteditable="true"]');
      if (ce) return ce;
    }
    return isEditable(el) ? el : findInputEl(el);
  }

  function getText(el) {
    if (!el) return '';
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'textarea' || tag === 'input') return el.value || '';
    if (el.isContentEditable) return el.innerText || el.textContent || '';
    return '';
  }

  function setText(el, text) {
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'textarea' || tag === 'input') {
      // Use native setter to trigger React's onChange
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
      setter.call(el, text);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else if (el.isContentEditable) {
      el.focus();
      let replaced = false;
      try {
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        sel.removeAllRanges();
        sel.addRange(range);
        // insertText writes over whatever is selected: when the selection
        // covers only part of the content the output lands at the wrong
        // place (this is how a codice fiscale once came out as [IP_1])
        const covered = (sel.toString() || '').replace(/\s+/g, ' ').trim();
        const current = getText(el).replace(/\s+/g, ' ').trim();
        const partial = covered && current && covered !== current;
        if (!partial) replaced = document.execCommand('insertText', false, text);
      } catch (e) {}
      if (!replaced || getText(el) !== text) {
        // framework editors (Lexical, ProseMirror) can silently ignore
        // execCommand; force the DOM and announce the change
        try {
          el.textContent = text;
          el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertReplacementText', data: text }));
        } catch (e) {
          try { el.innerText = text; } catch (e2) {}
        }
      }
    }
  }

  // Writes text and only reports success when none of the original secrets
  // survive in the editor. Never trust a write that was not verified.
  function writeBack(el, text, secrets) {
    if (!el) return false;
    setText(el, text);
    const now = getText(el);
    // The write only counts if the editor really holds the redaction. An empty
    // read-back is never clean (contenteditables can report nothing while the
    // submitted text still carries the secret), the secret must be gone, and
    // the placeholder has to be in there.
    if (!now.trim()) return false;
    if ((secrets || []).some(s => s && now.includes(s))) return false;
    return /\[[A-Z][A-Z0-9_]*_\d+\]/.test(now);
  }

  function findInputEl(startEl) {
    // Walk up to find the chat input
    let el = startEl;
    for (let i = 0; i < 6 && el; i++) {
      if (isEditable(el)) return el;
      const ta = el.querySelector && el.querySelector('textarea, [contenteditable="true"]');
      if (ta) return ta;
      el = el.parentElement;
    }
    // fallback: editable closest to the viewport bottom (chat inputs sit at the bottom)
    const all = Array.from(document.querySelectorAll('textarea, [contenteditable="true"]'));
    if (all.length === 0) return null;
    all.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
    return all[0];
  }

  /* ------------------------------------------------------------------ */
  /* Send interception                                                  */
  /* ------------------------------------------------------------------ */
  function isSendButton(el) {
    if (!el) return false;
    const btn = el.closest && el.closest('button, [role="button"]');
    if (!btn) return false;
    if (btn.closest && btn.closest('#sg-overlay')) return false;
    const label = (btn.getAttribute('aria-label') || btn.getAttribute('title') || btn.innerText || '').toLowerCase();
    if (/send|submit/.test(label)) return true;
    if (btn.getAttribute('data-testid') && /send/i.test(btn.getAttribute('data-testid'))) return true;
    return false;
  }

  /**
   * Called only when findings exist (callers scan first and let clean
   * messages pass through natively). Shows the modal and parks the action.
   */
  function tryIntercept(findings, text, inputEl, sendFn, opts) {
    // track warnings shown for review prompt
    try {
      chrome.storage.local.get(['sg_warnings_shown'], (r) => {
        const n = (r.sg_warnings_shown || 0) + 1;
        chrome.storage.local.set({ sg_warnings_shown: n });
      });
    } catch (e) {}
    const o = opts || {};
    const mode = o.mode || 'send';
    const safeFindings = findings.map(({ name, sev, preview }) => ({ name, sev, preview }));
    pendingSend = {
      inputEl,
      text: mode === 'attach' ? '' : (text || ''),
      findings: safeFindings,
      secrets: findings.map(f => f.raw).filter(Boolean),
      sendFn,
      redactFn: o.redactFn || null,
      cancelFn: o.cancelFn || null,
      mode,
    };
    showModal(safeFindings, mode);
    updateWidget('warn');
    sendAlert(safeFindings, 'warned');
  }

  function doSend() {
    if (!pendingSend) return;
    const { sendFn, findings, secrets } = pendingSend;
    let justification = '';
    if (settings.enforceJustification) {
      const input = document.getElementById('sg-reason');
      justification = String((input && input.value) || '').replace(/[\r\n]+/g, ' ').trim();
      if (justification.length < 5) {
        if (input && input.focus) input.focus();
        showToast('Add a one-line reason of at least 5 characters before sending.', 'warn');
        return;
      }
      // The reason goes to the IT admin, so the secret itself can never ride along
      for (const s of (secrets || [])) {
        if (s) justification = justification.split(s).join('[REDACTED]');
      }
      justification = justification.slice(0, 140);
    }
    sendAlert(findings, 'sent_anyway', justification);
    pendingSend = null;
    hideModal();
    if (sendFn) sendFn();
  }

  function redactText(text, opts) {
    return Detect.redact(text, detectOpts(), opts || {});
  }

  function doRedact() {
    if (!pendingSend) return;
    const { inputEl, text, findings, secrets, redactFn, mode } = pendingSend;
    const { text: redacted } = redactText(text);
    if (redactFn) {
      redactFn(redacted);
    } else if (inputEl) {
      setText(inputEl, redacted);
    }
    const now = inputEl ? getText(inputEl) : redacted;
    const leaked = (secrets || []).some(s => s && now.includes(s));
    if (leaked) {
      // the editor refused the write: stay in the modal so Cancel still works
      showToast('Redaction could not be written into this editor. The secret is still in the box, remove it by hand.', 'warn');
      return;
    }
    sendAlert(findings, 'redacted');
    try { chrome.runtime.sendMessage({ type: 'incrementLeaksStopped' }, (res) => { if (res && typeof res.count === 'number') leaksStopped = res.count; updateUsage(); renderWidget(); }); } catch (e) {}
    pendingSend = null;
    hideModal();
    const leftover = scan(now);
    if (leftover.length) {
      showToast('Some matches could not be redacted automatically. Review your message before sending.', 'warn');
    } else {
      showToast(mode === 'paste' ? 'Secrets redacted and pasted.' : 'Secrets redacted. Review and send.', 'ok');
    }
  }

  function doCancel() {
    if (pendingSend) {
      const { findings, cancelFn } = pendingSend;
      sendAlert(findings, 'blocked');
      try { chrome.runtime.sendMessage({ type: 'incrementLeaksStopped' }, (res) => { if (res && typeof res.count === 'number') leaksStopped = res.count; updateUsage(); renderWidget(); }); } catch (e) {}
      if (cancelFn) cancelFn();
    }
    pendingSend = null;
    hideModal();
  }

  /* ------------------------------------------------------------------ */
  /* Modal                                                              */
  /* ------------------------------------------------------------------ */
  function showModal(findings, mode) {
    hideModal();
    const isPaste = mode === 'paste';
    const isAttach = mode === 'attach';
    const sendLabel = isPaste ? 'Paste anyway' : (isAttach ? 'Attach anyway' : 'Send anyway');
    const redactLabel = isPaste ? 'Redact and paste' : 'Redact and send';
    const redactActionHtml = isAttach ? '' : (hasProCap()
      ? `<button class="sg-btn-safe" id="sg-redact">${redactLabel}</button>`
      : `<button class="sg-btn-safe is-locked" id="sg-redact-locked" title="Upgrade to Pro for automatic redaction">${redactLabel}<span class="sg-pro">Pro</span></button>`);
    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    const lead = findings.length === 1
      ? 'There is ' + article(findings[0].name) + ' <span class="sg-thing">' + escapeHtml(findings[0].name) + '</span> in this message. Sent to a chat service, it can end up in their logs.'
      : 'There are <span class="sg-thing">' + findings.length + ' sensitive values</span> in this message. Sent to a chat service, they can end up in their logs.';
    const needReason = !!settings.enforceJustification;
    const reasonBlock = needReason ? `
        <div class="sg-reason">
          <input type="text" id="sg-reason" class="sg-reason-input" maxlength="140" autocomplete="off" spellcheck="false" placeholder="Reason for sending (at least 5 characters)" aria-label="Reason for sending anyway">
          <p class="sg-reason-note">One line, up to 140 characters. Your IT admin sees this reason with the alert. The secret itself is never included.</p>
        </div>` : '';
    overlay.innerHTML = `
      <div id="sg-modal" role="dialog" aria-modal="true" aria-labelledby="sg-title">
        <div class="sg-head">
          <span class="sg-disc" aria-hidden="true">${KEY_SVG}</span>
          <div class="sg-headtext">
            <div class="sg-kicker">API Key Leak Intercept</div>
            <h2 id="sg-title">Hold on.</h2>
          </div>
        </div>
        <p class="sg-sub">${lead}</p>
        <div class="sg-findings">
          ${findings.map(f => `
            <div class="sg-finding">
              <span class="sg-sev ${f.sev === 'high' ? 'high' : 'med'}">${f.sev === 'high' ? 'High' : 'Medium'}</span>
              <span class="sg-name">${escapeHtml(f.name)}</span>
              <span class="sg-preview">${escapeHtml(f.preview)}</span>
            </div>`).join('')}
          <div class="sg-card-note">Found in your browser. Nothing was sent.</div>
        </div>
        ${(!hasProCap() && !settings.hideProHint) ? `<div class="sg-pro-hint">Pro: redaction and personal-data checks. <button type="button" id="sg-hide-hint" class="sg-hide-hint">Don't show again</button></div>` : ''}
        <div class="sg-actions">
          <button class="sg-btn-secondary" id="sg-cancel">Cancel<span class="sg-key">Esc</span></button>
          ${redactActionHtml}
        </div>
        ${reasonBlock}
        <div class="sg-foot">
          <button class="sg-danger-link" id="sg-send"${needReason ? ' disabled' : ''}>${sendLabel}</button>
          <div class="sg-meter-wrap">
            <span id="sg-usage">${usageText()}</span>
          </div>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    document.getElementById('sg-cancel').addEventListener('click', doCancel);
    document.getElementById('sg-send').addEventListener('click', doSend);
    const redactBtn = document.getElementById('sg-redact');
    if (redactBtn) redactBtn.addEventListener('click', doRedact);
    const redactLocked = document.getElementById('sg-redact-locked');
    if (redactLocked) redactLocked.addEventListener('click', (e) => { e.preventDefault(); openUpgrade(); });
    const sendBtn = document.getElementById('sg-send');
    if (sendBtn && settings.blockSendAnyway) { sendBtn.style.display = 'none'; }
    const reasonInput = document.getElementById('sg-reason');
    if (reasonInput && sendBtn) {
      const syncReason = () => { sendBtn.disabled = reasonInput.value.trim().length < 5; };
      reasonInput.addEventListener('input', syncReason);
      syncReason();
    }
    const hideHintBtn = document.getElementById('sg-hide-hint');
    if (hideHintBtn) hideHintBtn.addEventListener('click', (e) => {
      e.preventDefault();
      settings.hideProHint = true;
      try { chrome.storage.local.set({ sg_hide_pro_hint: true }); } catch (err) {}
      const el = document.querySelector('.sg-pro-hint');
      if (el) el.remove();
    });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) doCancel(); });
    updateUsage();
    const primary = document.getElementById('sg-redact') || document.getElementById('sg-redact-locked') || document.getElementById('sg-cancel');
    // no preventScroll: on short windows the modal scrolls so the focused
    // primary action is always on screen
    if (primary && primary.focus) primary.focus();
    // Escape key + focus trap (both removed by hideModal)
    escHandler = (e) => { if (e.key === 'Escape') doCancel(); };
    tabHandler = (e) => {
      if (e.key !== 'Tab') return;
      const modal = document.getElementById('sg-modal');
      if (!modal) return;
      const focusables = modal.querySelectorAll('button, a[href], input');
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', escHandler);
    document.addEventListener('keydown', tabHandler);
  }

  function article(name) {
    // "an OpenAI API key", "an IPv4 address", "a US SSN", "a JWT"
    return (/^[AEIO]/.test(name) && !/^U[A-Z]/.test(name)) ? 'an' : 'a';
  }

  function usageText() {
    return leaksStopped + ' leaks stopped this month';
  }

  function updateUsage() {
    const el = document.getElementById('sg-usage');
    if (el) el.textContent = usageText();
  }

  /* ------------------------------------------------------------------ */
  /* IT alerting (team mode) + Pro history                              */
  /* ------------------------------------------------------------------ */
  function sendAlert(findings, action, justification, via) {
    if (!findings || findings.length === 0) return;
    const isTeam = !!settings.managedMode || !!(settings.teamMode && settings.orgId);
    if (!isTeam && !settings.isPro) return;      // personal free: nothing stored, nothing sent
    if (action === 'warned' && !isTeam) return;  // personal history records terminal actions only

    const alert = {
      orgId: settings.orgId || '',
      orgToken: settings.orgToken || '',
      userEmail: settings.userEmail || 'unknown',
      extraEmails: settings.extraEmails || '',
      site: location.hostname,
      // origin + path only: query strings can carry tokens
      url: location.origin + location.pathname,
      secretTypes: findings.map(f => f.name),
      severity: findings.some(f => f.sev === 'high') ? 'high' : 'medium',
      action: action,
      via: via === 'auto' ? 'auto' : 'manual',
      timestamp: new Date().toISOString(),
      extensionVersion: EXT_VERSION,
    };
    if (justification) alert.justification = justification;

    try {
      const p = chrome.runtime.sendMessage({ type: 'sendAlert', alert });
      if (p && p.catch) p.catch(() => {});
    } catch (e) { /* messaging unavailable */ }
  }

  function hideModal() {
    const o = document.getElementById(OVERLAY_ID);
    if (o) o.remove();
    if (escHandler) {
      document.removeEventListener('keydown', escHandler);
      escHandler = null;
    }
    if (tabHandler) {
      document.removeEventListener('keydown', tabHandler);
      tabHandler = null;
    }
  }

  function showToast(msg, type) {
    const old = document.getElementById('sg-toast');
    if (old) old.remove();
    const t = document.createElement('div');
    t.id = 'sg-toast';
    t.textContent = msg;
    if (type === 'warn') t.classList.add('is-warn');
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  function openUpgrade() {
    try {
      const p = chrome.runtime.sendMessage({ type: 'openUrl', url: UPGRADE_URL });
      if (p && p.catch) p.catch(() => {});
    } catch (e) {}
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderWidget() {
    const root = document.getElementById(DRAWER_ID);
    if (!root) return;
    const on = !!settings.enabled;
    const pill = root.querySelector('.sg-drawer-pill');
    if (pill) {
      pill.className = 'sg-drawer-pill ' + (on ? 'on' : 'off');
      pill.innerHTML = '<i></i>' + (on ? 'Active' : 'Paused');
    }
    const count = root.querySelector('.sg-drawer-count');
    if (count) count.textContent = leaksStopped + ' leaks stopped this month';
    const meter = root.querySelector('.sg-drawer-meter');
    if (meter) meter.style.display = 'none';
  }

  function updateWidget(state) {
    let root = document.getElementById(DRAWER_ID);
    if (!shouldScan()) {
      if (root) root.remove();
      return;
    }
    if (!root) {
      root = document.createElement('div');
      root.id = DRAWER_ID;
      root.innerHTML = `
        <div class="sg-drawer-body" id="sg-drawer-body">
          <div class="sg-drawer-head">
            <span class="sg-drawer-mark">${BARS_SVG}</span>
            <div class="sg-drawer-titles">
              <div class="sg-drawer-name">API Key Leak Intercept</div>
              <div class="sg-drawer-sub">Local secret detection</div>
            </div>
            <span class="sg-drawer-pill on"><i></i>Active</span>
          </div>
          <div class="sg-drawer-divider"></div>
          <div class="sg-drawer-row">
            <span class="sg-drawer-cap">Usage</span>
            <span class="sg-drawer-count">0 leaks stopped this month</span>
          </div>
          <div class="sg-drawer-meter"><i></i></div>
          <div class="sg-drawer-actions">
            <button type="button" class="sg-drawer-btn sg-drawer-btn-primary" id="sg-drawer-open">Open extension</button>
          </div>
          <div class="sg-drawer-note">Detection runs locally. Nothing leaves your browser.</div>
        </div>
        <button type="button" class="sg-drawer-tab" id="sg-drawer-tab" aria-expanded="false" aria-controls="sg-drawer-body" title="API Key Leak Intercept" aria-label="API Key Leak Intercept status">${BARS_SVG}<span class="sg-tab-dot" aria-hidden="true"></span><span class="sg-tab-pin" aria-hidden="true">${PIN_SVG}</span></button>`;
      document.body.appendChild(root);

      const tab = root.querySelector('#sg-drawer-tab');
      const openPopup = () => {
        try {
          const p = chrome.runtime.sendMessage({ type: 'openPopup' });
          if (p && p.catch) p.catch(() => {});
        } catch (e) {}
      };
      root.querySelector('#sg-drawer-open').addEventListener('click', openPopup);

      tab.addEventListener('click', () => {
        const isOpen = root.classList.toggle('is-open');
        tab.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      });
      document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (!document.body.contains(root)) return;
        if (root.classList.contains('is-open')) {
          root.classList.remove('is-open');
          tab.setAttribute('aria-expanded', 'false');
        }
      });
      renderWidget();
    }
    root.classList.remove('sg-warn', 'sg-danger');
    if (state === 'warn') root.classList.add('sg-warn');
    if (state === 'danger') root.classList.add('sg-danger');
    renderWidget();
  }

  /* ------------------------------------------------------------------ */
  /* Event interception (capture phase)                                 */
  /* ------------------------------------------------------------------ */
  // Scan FIRST: a clean message is never touched (no preventDefault, no
  // synthetic events), so sites that check e.isTrusted keep working in the
  // normal case. Only a message with findings is parked behind the modal.
  document.addEventListener('keydown', (e) => {
    if (window.__sgBypass) return; // our own synthetic send-through
    if (!shouldScan()) return;
    if (e.target && e.target.closest && e.target.closest('#sg-overlay, #sg-drawer')) return;
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return;
    const target = e.target;
    if (!isEditable(target)) return;
    const inputEl = findInputEl(target);
    if (!inputEl) return;
    const text = getText(inputEl);
    if (!text.trim()) return;
    const findings = scan(text);
    if (findings.length === 0) return; // native pass-through

    const secrets = findings.map(f => f.raw).filter(Boolean);
    const sendThrough = () => {
      window.__sgBypass = true;
      const ev = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true });
      inputEl.dispatchEvent(ev);
      setTimeout(() => {
        if (getText(inputEl).trim() === text.trim()) {
          const allBtns = Array.from(document.querySelectorAll('button'));
          const sendBtn = allBtns.find(b => isSendButton(b) && !b.disabled);
          if (sendBtn) sendBtn.click();
        }
        setTimeout(() => { window.__sgBypass = false; }, 50);
      }, 40);
    };
    if (hasProCap() && settings.autoRedact) {
      try {
        const { text: redacted, count } = redactText(text);
        if (count > 0 && writeBack(inputEl, redacted, secrets)) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
          sendAlert(findings, 'redacted', '', 'auto');
          try { chrome.runtime.sendMessage({ type: 'incrementLeaksStopped' }, (res) => { if (res && typeof res.count === 'number') leaksStopped = res.count; renderWidget(); }); } catch (err) {}
          const before = getText(inputEl);
          window.__sgBypass = true;
          const ev = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true });
          inputEl.dispatchEvent(ev);
          setTimeout(() => {
            // Controlled editors can hand the secret back between the write and
            // the send. If it is back in the box, park behind the modal instead.
            const now = getText(inputEl);
            if ((secrets || []).some(s => s && now.includes(s))) {
              window.__sgBypass = false;
              tryIntercept(findings, text, inputEl, sendThrough);
              return;
            }
            if (now.trim() === before.trim()) {
              const allBtns = Array.from(document.querySelectorAll('button'));
              const sendBtn = allBtns.find(b => isSendButton(b) && !b.disabled);
              if (sendBtn) sendBtn.click();
            }
            setTimeout(() => { window.__sgBypass = false; }, 50);
          }, 40);
          return;
        }
      } catch (err) { /* fall through to the modal, never send unredacted */ }
      // the editor refused the write or handed the secret back: fall through
      // to the modal and never send text that still contains the secret
    }

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    tryIntercept(findings, text, inputEl, sendThrough);
  }, true);

  document.addEventListener('click', (e) => {
    if (window.__sgBypass) return; // our own synthetic send-through
    if (!shouldScan()) return;
    if (!isSendButton(e.target)) return;
    const btn = e.target.closest('button');
    if (!btn) return;
    const inputEl = findInputEl(e.target);
    if (!inputEl) return;
    const text = getText(inputEl);
    if (!text.trim()) return;
    const findings = scan(text);
    if (findings.length === 0) return; // native pass-through

    const secretsC = findings.map(f => f.raw).filter(Boolean);
    if (hasProCap() && settings.autoRedact) {
      try {
        const { text: redacted, count } = redactText(text);
        if (count > 0 && writeBack(inputEl, redacted, secretsC)) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
          // final gate: if the editor handed the secret back, park instead
          const now = getText(inputEl);
          if ((secretsC || []).some(s => s && now.includes(s))) {
            tryIntercept(findings, text, inputEl, sendThrough);
            return;
          }
          sendAlert(findings, 'redacted', '', 'auto');
          try { chrome.runtime.sendMessage({ type: 'incrementLeaksStopped' }, (res) => { if (res && typeof res.count === 'number') leaksStopped = res.count; renderWidget(); }); } catch (err) {}
          window.__sgBypass = true;
          btn.click();
          setTimeout(() => { window.__sgBypass = false; }, 50);
          return;
        }
      } catch (err) { /* fall through to the modal, never send unredacted */ }
      // the editor refused the write or handed the secret back: fall through
      // to the modal and never send text that still contains the secret
    }

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    tryIntercept(findings, text, inputEl, () => {
      window.__sgBypass = true;
      btn.click();
      setTimeout(() => { window.__sgBypass = false; }, 50);
    });
  }, true);

  /* ------------------------------------------------------------------ */
  /* Paste, drop, and file-input interception                           */
  /* ------------------------------------------------------------------ */
  function isTextLikeFile(file) {
    return Detect.isTextLikeFile(file);
  }

  function readFileText(file) {
    return new Promise((resolve) => {
      try {
        const reader = new FileReader();
        reader.onload = () => {
          const res = typeof reader.result === 'string' ? reader.result : '';
          // Ignore binary files masquerading with a text extension
          if (res.includes('\0')) { resolve(''); return; }
          resolve(res);
        };
        reader.onerror = () => resolve('');
        reader.readAsText(file);
      } catch (e) {
        resolve('');
      }
    });
  }

  function scanMultiple(texts) {
    const combined = [];
    const seen = new Set();
    for (const t of texts) {
      if (!t) continue;
      for (const f of scan(t)) {
        const key = f.name + '|' + f.raw;
        if (seen.has(key)) continue;
        seen.add(key);
        combined.push(f);
        if (combined.length >= Detect.MAX_FINDINGS) return combined;
      }
    }
    return combined;
  }

  function saveSelection(el) {
    if (!el) return null;
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'textarea' || tag === 'input') {
      return {
        start: typeof el.selectionStart === 'number' ? el.selectionStart : (el.value || '').length,
        end: typeof el.selectionEnd === 'number' ? el.selectionEnd : (el.value || '').length,
      };
    }
    if (el.isContentEditable) {
      try {
        const sel = window.getSelection();
        if (sel && sel.rangeCount > 0 && el.contains(sel.anchorNode)) {
          return { range: sel.getRangeAt(0).cloneRange() };
        }
      } catch (e) {}
    }
    return null;
  }

  function insertAtSelection(el, str, savedSel) {
    if (!el) return;
    const tag = (el.tagName || '').toLowerCase();
    if (tag === 'textarea' || tag === 'input') {
      const cur = el.value || '';
      const start = (savedSel && typeof savedSel.start === 'number') ? savedSel.start : cur.length;
      const end = (savedSel && typeof savedSel.end === 'number') ? savedSel.end : cur.length;
      const next = cur.slice(0, start) + str + cur.slice(end);
      setText(el, next);
      try {
        el.focus();
        const pos = start + str.length;
        el.setSelectionRange(pos, pos);
      } catch (e) {}
      return;
    }
    if (el.isContentEditable) {
      el.focus();
      if (savedSel && savedSel.range) {
        try {
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(savedSel.range);
        } catch (e) {}
      }
      let inserted = false;
      try {
        inserted = document.execCommand('insertText', false, str);
      } catch (e) {}
      if (!inserted) {
        const cur = getText(el);
        setText(el, cur ? cur + str : str);
      }
    }
  }

  function performPaste(inputEl, str, savedSel) {
    if (!inputEl) return;
    inputEl.focus();
    if (savedSel && savedSel.range) {
      try {
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(savedSel.range);
      } catch (e) {}
    } else if (savedSel && typeof savedSel.start === 'number') {
      try { inputEl.setSelectionRange(savedSel.start, savedSel.end); } catch (e) {}
    }
    const before = getText(inputEl);
    let handled = false;
    window.__sgBypass = true;
    try {
      const dt = new DataTransfer();
      dt.setData('text/plain', str);
      const ev = new ClipboardEvent('paste', {
        bubbles: true,
        cancelable: true,
        clipboardData: dt,
      });
      const notCancelled = inputEl.dispatchEvent(ev);
      if (!notCancelled || getText(inputEl) !== before) {
        handled = true;
      }
    } catch (e) {
    } finally {
      window.__sgBypass = false;
    }
    if (!handled) {
      insertAtSelection(inputEl, str, savedSel);
    }
  }

  function replayFileDrop(dropTarget, files) {
    window.__sgBypass = true;
    try {
      const dt = new DataTransfer();
      files.forEach(f => dt.items.add(f));
      if (dropTarget && (dropTarget.tagName || '').toLowerCase() === 'input' && (dropTarget.type || '').toLowerCase() === 'file') {
        dropTarget.files = dt.files;
        dropTarget.dispatchEvent(new Event('input', { bubbles: true }));
        dropTarget.dispatchEvent(new Event('change', { bubbles: true }));
      } else if (dropTarget) {
        const ev = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt });
        dropTarget.dispatchEvent(ev);
      }
    } catch (e) {
    } finally {
      window.__sgBypass = false;
    }
  }

  function replayTextDrop(dropTarget, inputEl, str) {
    const before = inputEl ? getText(inputEl) : '';
    let handled = false;
    window.__sgBypass = true;
    try {
      const dt = new DataTransfer();
      dt.setData('text/plain', str);
      if (dropTarget) {
        const ev = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt });
        const notCancelled = dropTarget.dispatchEvent(ev);
        if (!notCancelled || (inputEl && getText(inputEl) !== before)) {
          handled = true;
        }
      }
    } catch (e) {
    } finally {
      window.__sgBypass = false;
    }
    if (!handled && inputEl) {
      insertAtSelection(inputEl, str, null);
    }
  }

  // Capture-phase 'paste' listener
  document.addEventListener('paste', (e) => {
    if (window.__sgBypass) return;
    if (!shouldScan()) return;
    if (e.target && e.target.closest && e.target.closest('#sg-overlay, #sg-drawer')) return;
    const cd = e.clipboardData;
    if (!cd) return;
    const text = cd.getData('text/plain') || cd.getData('text') || '';
    if (!text.trim()) return;
    const findings = scan(text);
    if (findings.length === 0) return; // clean paste: pass through untouched

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const inputEl = editableRoot(e.target);
    const savedSel = saveSelection(inputEl);
    tryIntercept(findings, text, inputEl, () => {
      performPaste(inputEl, text, savedSel);
    }, {
      mode: 'paste',
      redactFn: (redacted) => {
        performPaste(inputEl, redacted, savedSel);
      },
    });
  }, true);

  // Capture-phase 'drop' listener (text drops and file drops)
  document.addEventListener('drop', (e) => {
    if (window.__sgBypass) return;
    if (!shouldScan()) return;
    if (e.target && e.target.closest && e.target.closest('#sg-overlay, #sg-drawer')) return;
    const dt = e.dataTransfer;
    if (!dt) return;
    const dropTarget = e.target;
    const files = dt.files ? Array.from(dt.files) : [];

    if (files.length > 0) {
      const inspectable = files.filter(isTextLikeFile);
      if (inspectable.length === 0) return; // binary / oversized: pass through untouched

      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      Promise.all(inspectable.map(readFileText)).then((texts) => {
        const findings = scanMultiple(texts);
        if (findings.length === 0) {
          replayFileDrop(dropTarget, files);
          return;
        }
        tryIntercept(findings, '', null, () => {
          replayFileDrop(dropTarget, files);
        }, { mode: 'attach' });
      });
      return;
    }

    const text = dt.getData('text/plain') || dt.getData('text') || '';
    if (!text.trim()) return;
    const findings = scan(text);
    if (findings.length === 0) return; // clean text drop: pass through untouched

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const inputEl = editableRoot(dropTarget);
    tryIntercept(findings, text, inputEl, () => {
      replayTextDrop(dropTarget, inputEl, text);
    }, {
      mode: 'paste',
      redactFn: (redacted) => {
        replayTextDrop(dropTarget, inputEl, redacted);
      },
    });
  }, true);

  // Capture-phase <input type=file> 'change' listener
  document.addEventListener('change', (e) => {
    if (window.__sgBypass) return;
    if (!shouldScan()) return;
    const el = e.target;
    if (!el || (el.tagName || '').toLowerCase() !== 'input' || (el.type || '').toLowerCase() !== 'file') return;
    const files = el.files ? Array.from(el.files) : [];
    const inspectable = files.filter(isTextLikeFile);
    if (inspectable.length === 0) return; // binary / oversized: pass through untouched

    e.stopPropagation();
    e.stopImmediatePropagation();

    Promise.all(inspectable.map(readFileText)).then((texts) => {
      const findings = scanMultiple(texts);
      if (findings.length === 0) {
        window.__sgBypass = true;
        try {
          el.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (err) {
        } finally {
          window.__sgBypass = false;
        }
        return;
      }
      try { el.value = ''; } catch (err) {}
      tryIntercept(findings, '', el, () => {
        window.__sgBypass = true;
        try {
          const dt = new DataTransfer();
          files.forEach(f => dt.items.add(f));
          el.files = dt.files;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (err) {
        } finally {
          window.__sgBypass = false;
        }
      }, {
        mode: 'attach',
        cancelFn: () => {
          try { el.value = ''; } catch (err) {}
        },
      });
    });
  }, true);

  /* ------------------------------------------------------------------ */
  /* Init                                                               */
  /* ------------------------------------------------------------------ */
  loadSettings();
  setTimeout(() => updateWidget(), 1500);

  // listen for settings updates from popup
  try {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg && msg.type === 'settingsUpdated') loadSettings();
    });
  } catch (e) {}
  // re-run when the entitlement or org record changes underneath us
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      // Settings changes must reach already-open tabs too. Watching only
      // entitlement and org meant toggling Auto-redact in the popup silently
      // did nothing until the page was reloaded.
      if (area === 'local' && (changes.sg_settings || changes.sg_entitlement || changes.sg_org || changes.sg_isPro || changes.sg_license_invalid)) {
        loadSettings();
      }
    });
  } catch (e) {}

})();
