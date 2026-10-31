# API Key Leak Intercept: IT Admin Guide

How to put the extension on every employee machine, how to watch what it catches, and how to lock it down. Written for the person who owns the rollout.

The product stops API keys, tokens and personal data from leaving the browser into AI chats. Detection runs on the employee's machine. Nothing about the message or the secret is ever sent anywhere. What your console receives is the fact that a catch happened, who hit it, on which site, and what they did next.

## What you are deploying

- A Chrome extension, installed per machine, either forced by policy or enrolled with a setup code.
- A cloud console where your organization lives: identity, alert channels, the intercept feed, seats and liveness.
- Alerts that carry metadata only: employee email, site hostname, page URL without the query string, secret type names, severity, action taken, timestamp, and the reason text when you require one.

## Step 1. Create your organization

Open the License & Team Console and sign in with the license key from your purchase:

https://dariocositore.com/tools/api-key-leak-intercept/manage/

Create the organization once. You get an organization ID (looks like `org_ab12cd34ef56`) and an ingest token. The token is shown once at creation or rotation. Store both where your team keeps deployment secrets. Everything else on this page is the rollout.

## Step 2. Pick a deployment path

**Chrome Enterprise policy.** Right for Google Admin, Intune, Jamf or any MDM. The install is forced, employees cannot remove it, and the settings arrive as policy.

**Setup code.** Right for a team with no MDM. A one-time code configures a machine in one paste. Employees can still remove the extension, so pair it with your own device policy if that matters.

Both paths can run side by side: policy for managed laptops, setup codes for contractors.

## Deploy with Chrome Enterprise policy

Two pieces go into your browser policy: the force-install entry and the extension's own settings.

Force-install the extension by its Chrome Web Store ID with `ExtensionInstallForcelist`. Once the listing is live the ID is on the store page. Employees cannot uninstall a force-installed extension.

Put the settings under `3rdparty`, keyed by the same extension ID. The console generates this block for you (Policy JSON export), so copy it from there. It looks like this:

```json
{
  "3rdparty": {
    "extensions": {
      "EXTENSION_ID_HERE": {
        "orgId": "org_ab12cd34ef56",
        "orgToken": "tok_your_ingest_token",
        "userEmail": "employee@yourcompany.com",
        "universalMode": true,
        "lockSettings": true,
        "heartbeat": true
      }
    }
  }
}
```

`userEmail` is per machine, so in most fleets you set it through your MDM's per-device variables. Everything else can be uniform.

### Policy keys

| Key | What it does |
| --- | --- |
| `orgId` | Your organization identifier. Required for team alerting. |
| `orgToken` | The ingest token. Alerts without it are rejected, so treat it like a credential. |
| `userEmail` | The name attached to this machine's alerts. |
| `lockSettings` | Protection stays on and the popup toggles are read-only. |
| `universalMode` | Scan every website, not just the AI chat list. |
| `extraSites` | Extra hostnames to scan, for internal tools with their own domains. |
| `customPatterns` | One regular expression per entry, for your internal token formats. |
| `detectPii` | Turn on personal-data detection (emails, phones, cards, national IDs for 20+ countries). |
| `detectNetwork` | Turn on IP address detection. |
| `autoRedact` | Redact high-confidence secrets automatically at send time. |
| `blockSendAnyway` | Remove the override: a warned message cannot be sent. |
| `enforceJustification` | An override needs a one-line reason, and the reason joins the alert. |
| `alertOnWarn`, `alertOnSendAnyway`, `alertOnBlock`, `alertOnRedact` | Which events reach the console and your channels. |
| `heartbeat` | Report liveness so the console shows which installs are running. |
| `alertEndpoint` | A self-hosted HTTPS endpoint to receive alerts instead of, or alongside, the console. |

## Deploy with setup codes

Generate the code in the console (Setup code section). It looks like `SGSETUP1.…` and carries the org identity and policy in one string.

On the employee machine: click the extension, open Setup team, paste the code once. The install is configured from then on. Codes can be regenerated in the console; a new code does not invalidate installs already configured.

To pull an install back, rotate the ingest token in the console. The old token stops being accepted and machines keep scanning without reporting until you push the new code.

## Alert channels

The console routes alerts to five destinations, each with a test-send button so you can prove the pipe before rollout:

- Slack and Microsoft Teams via incoming webhooks.
- Telegram via bot token and chat ID.
- Any HTTPS webhook, for a SIEM or your own tooling.
- Email to a distribution list.

Managed (policy) installs always report to the console first, and the console fans out to whatever channels you enabled. Channel credentials live in the console, never in the employee's browser.

## What the console shows

The Intercept Feed is the record of every catch across the company. It keeps the last 500 alerts per organization and filters by person, site and action. Each row answers three questions at a glance: who, where, and did they send it anyway.

Alongside the feed:

- **Install liveness.** Heartbeats tell you which machines are running the extension and when they last checked in.
- **Seats.** How many installs report against your plan.
- **Org identity.** Your org ID, the ingest token with rotate, the setup code generator, and the policy JSON export.
- **Per-install history.** Each machine keeps its own last 100 catches locally, which the employee can read in the popup.

## What leaves the browser

Message text never leaves the browser. Redaction happens locally before anything is typed back into the page. The alert carries the metadata listed above and the type name of the secret, never the secret itself. The full inventory, including the routine network requests, is on the privacy page:

https://dariocositore.com/tools/api-key-leak-intercept/privacy/

If your security team wants the receipts, that page is written for them.

## Locking it down

The levers, from gentle to absolute:

1. Leave everything open. Employees see warnings and choose.
2. `enforceJustification: true` makes an override cost a written reason, which lands in the feed. Most teams stop there.
3. `blockSendAnyway: true` removes the override entirely. Use it where the data class demands it.
4. `lockSettings: true` freezes the popup, so nobody quietly pauses protection or turns categories off.
5. `universalMode: true` extends coverage past the AI chat list to every site in the browser.

Custom patterns are the quiet one. Every internal token format you add is a catch that regex would otherwise miss.

## Rollout checklist

1. Create the org, store the org ID and ingest token.
2. Set up one alert channel and hit its test-send.
3. Pilot on three machines (setup code is fastest) and read the feed.
4. Decide the lock level for the wider fleet.
5. Push policy through your MDM, or roll setup codes to the team.
6. Watch heartbeats for the first week to catch machines that never enrolled.

## Troubleshooting

- **A machine never shows up.** No heartbeat means no enrollment. Check the policy block is under `3rdparty` keyed by the right extension ID, or that the setup code was applied.
- **Alerts are missing but catches happen.** The employee sees warnings locally but the org has no token, or the token was rotated after deployment. Re-push the code.
- **A site is not being covered.** The AI chat list covers 40+ sites. Anything else needs `universalMode` or an `extraSites` entry.
- **The popup will not open its settings.** That is `lockSettings` doing its job. The same policy key turns it off.
- **You need the raw export.** The console exports the policy JSON, and the feed is the alert record. For anything deeper, email support@dariocositore.com with your org ID.

## Prices

Team Volume is $4 per seat per month. Pro, for individuals, is $7.99 per month or $59 per year. https://dariocositore.com/pricing/
