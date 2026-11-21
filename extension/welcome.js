// Welcome and consent screen. External file because MV3 extension pages
// cannot run inline scripts (CSP).
(function () {
  var consent = document.getElementById('consent');
  var onView = document.getElementById('on-view');
  var status = document.getElementById('consent-status');

  // The same shape background.js writes as its install defaults. The welcome
  // tab is opened at background.js onInstalled *before* those defaults are
  // stored, so Enable could land first and write {enabled:true} on its own;
  // every other surface then read a settings record with no categories,
  // customPatterns or autoRedact in it.
  var DEFAULT_SETTINGS = {
    categories: { apiKeys: true, pii: false, network: false },
    customPatterns: [],
    autoRedact: false,
  };
  function merged(stored) {
    var s = Object.assign({}, DEFAULT_SETTINGS, stored || {});
    // stored wins, but a partially written categories object still comes back
    // complete
    s.categories = Object.assign({}, DEFAULT_SETTINGS.categories, s.categories || {});
    s.customPatterns = Array.isArray(s.customPatterns) ? s.customPatterns : [];
    s.autoRedact = !!s.autoRedact;
    return s;
  }

  function showOn() {
    consent.style.display = 'none';
    onView.style.display = 'block';
  }

  try {
    chrome.storage.local.get(['sg_settings'], function (res) {
      if (res.sg_settings && res.sg_settings.enabled) showOn();
    });
  } catch (e) {}

  document.getElementById('enable-btn').addEventListener('click', function () {
    try {
      chrome.storage.local.get(['sg_settings'], function (res) {
        var s = merged(res.sg_settings);
        s.enabled = true;
        chrome.storage.local.set({ sg_settings: s }, function () {
          showOn();
        });
      });
    } catch (e) {
      status.textContent = 'Could not save the setting. Open the popup and turn protection on there.';
    }
  });

  document.getElementById('later-btn').addEventListener('click', function () {
    status.textContent = 'Protection stays off until you turn it on. Click the extension icon in the toolbar when you are ready.';
  });
})();
