# API Key Leak Intercept: Chrome Extension

Warns you before an API key, secret, or piece of personal data leaves your browser for an AI chat. Detection runs locally as regex in the browser. The free tier is open source, MIT.

## Install

The install page carries the package and the three steps to load it:

https://dariocositore.com/tools/api-key-leak-intercept/install/

Every GitHub Release here carries the same package.

## Test it (30 seconds)

1. Go to https://chatgpt.com.
2. Type: `my key is sk-proj-abcdefghijklmnopqrstuvwxyz123456`
3. Press Enter. The warning modal appears.
4. Click "Cancel". The message is not sent.
5. Type `hello world` and press Enter. No modal, the message goes out untouched.

## What lives in this repository

The full source of the extension you install: detection patterns, the warning modal, redaction, the popup, the team alerting client, and managed-policy support. Read it before you install it. That is the right thing to do with any browser extension.

The licensing and console service behind the paid tiers (accounts, license verification, the IT console and alert routing) is hosted at api.dariocositore.com by Dario Cositore. Its source is not in this repository. The extension asks it whether a license or team entitlement is valid and takes the answer at face value.

## Prices

Pro is $7.99 per month or $59 per year. Team Volume is $4 per seat per month. https://dariocositore.com/pricing/

## Features

### Personal mode (free)
- API key detection: OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Slack, JWT, PEM, Bearer, generic assignments, high-entropy tokens.
- Runs on 40+ AI chats and work tools. Clean messages are never intercepted, so the page behaves exactly as it would without the extension.
- No monthly cap. The popup shows "Leaks stopped this month" (Cancel and Redact outcomes, stored locally).
- Protection stays off until you accept it on the welcome page that opens on first install.

### Pro
- Everything in free, plus PII and IP detection (emails, phones, payment cards, national identity numbers for 20+ countries), custom regex patterns, one-click redaction with numbered placeholders like `[API_KEY_1]`, auto-redact at send time, and the local warning history.

### Team / IT mode
- Universal mode: scan every site in the browser, not just the AI chat list.
- Alert routing configured in the web console: Slack, Microsoft Teams, Telegram, generic webhooks and email.
- Alerts carry metadata only: employee email, site, page URL without the query string, secret types, severity, action, timestamp. The secret itself never leaves the browser.
- Setup codes configure an install in one paste; managed installs read the same settings from Chrome Enterprise policy and can lock them.
- The console keeps the last 500 alerts per organization, shows which installs are alive, and counts seats.

## Enterprise deployment

The IT admin guide covers the rollout end to end: Chrome Enterprise policy, setup codes, policy keys, alert channels, the console, and the lockdown levers.

https://github.com/dario-cositore/api-key-leak-intercept/blob/main/docs/it-admin-guide.md

## Privacy

Detection runs in the browser. Message text and detected secrets are never transmitted. The full data-flow inventory is on the privacy page:

https://dariocositore.com/tools/api-key-leak-intercept/privacy/

## License

MIT for the extension source in this repository.
