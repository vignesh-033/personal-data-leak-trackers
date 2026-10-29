# Personal Data Leak Tracker

A responsive full-stack privacy tracker with persistent data, encrypted monitored email addresses, live breach lookups through Have I Been Pwned (HIBP), data-sharing records, in-app exposure alerts, check history, JSON export, and a hash-linked audit trail.

## What works

- **Email breach lookup:** Calls the HIBP API from the server; the API key is never sent to the browser.
- **Monitors:** Add, remove, and re-check monitored addresses individually or all at once. Full addresses are encrypted at rest with AES-256-GCM. SHA-256 fingerprints prevent duplicates. Only masked hints and fingerprints are sent to the browser.
- **Breach history:** Saves returned breach summaries and supports filtering/searching old checks.
- **Data-sharing register:** Create, search, and delete records, including purpose and consent confirmation.
- **In-app alerts:** Generates alerts when a check returns breach records; mark one or all as read.
- **Audit trail:** Records actions in a SHA-256 hash-linked chain and verifies the full chain.
- **Export:** Download stored application data as JSON.
- **Responsive UI:** Desktop sidebar and mobile bottom navigation, empty states, form validation, loading states, and success/error notifications.

## Requirements

- Node.js 20 or newer
- Internet connection for live breach lookups
- A HIBP API key/subscription for live breach lookups (the rest of the app can run without it)

## Start on Windows

1. Extract the ZIP.
2. Open the extracted `personal-data-leak-tracker` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Run `npm install`.
5. Copy `.env.example` to `.env`.
6. In `.env`, set `APP_ENCRYPTION_KEY` to a long, random secret. Keep it unchanged after creating monitors, or existing encrypted email addresses cannot be decrypted.
7. Add your HIBP API key to `HIBP_API_KEY` to enable real breach searches. Leave it empty if you only want to use the sharing register and other local features.
8. Run `npm start`.
9. Open `http://localhost:3000` in your browser.

Example `.env` values (use your own secrets):

```env
HIBP_API_KEY=your_hibp_api_key_here
APP_ENCRYPTION_KEY=replace_with_a_long_random_secret_and_keep_it_safe
PORT=3000
APP_USER_AGENT=PersonalDataLeakTracker/2.0
```

Generate a random encryption secret in PowerShell with:

```powershell
[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

## Important boundaries

- Live breach checking requires a valid HIBP API key/subscription. This project does not fake successful results when the service is unavailable.
- In-app alerts are saved locally; SMTP email and push notifications are not configured.
- The monitor feature supports manual checks and a “Check all” action; it does not run an always-on scheduled background job when the app is closed.
- The audit chain is a local, hash-linked tamper-evident log. It is **not** a decentralized blockchain, and a local administrator could alter the data file and recompute the chain.
- The JSON store is appropriate for a local project demonstration, not a multi-user production service. Before public deployment, add authentication, authorization, a production database, HTTPS, rate limiting, backups, monitoring, and a managed secrets store.
- Do not enter passwords, Aadhaar numbers, bank details, or other highly sensitive information into the tracker.

## Test without a live HIBP key

You can still open the app, add sharing records, view the audit trail, verify the audit chain, export JSON, and use the monitor list after configuring `APP_ENCRYPTION_KEY`. Attempting a live check without `HIBP_API_KEY` displays a clear configuration error instead of a fake result.
