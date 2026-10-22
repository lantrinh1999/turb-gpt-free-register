# Turb GPT Free Register

ChatGPT / OpenAI account auto-registration and Codex OAuth authorization tool. The project currently supports several registration drivers:

- **protocol**: original pure-protocol registration, based on `curl_cffi` + Sentinel/PoW.
- **roxy**: RoxyBrowser fingerprint browser + Selenium automated registration, compatible with the new page flow, for example `create-account/password`, the `about-you` age/birthday form, region-localized pages, and so on.
- **cloak**: CloakBrowser + Playwright adapter layer for automated registration, supporting the free binary, headless mode, humanize, fixed fingerprint seed, and proxy geoip.
- **browser_use**: Browser Use Cloud stealth Chromium + Playwright (optional residential proxy, no local Roxy installation required).
- **skyvern**: Skyvern Browser Sessions cloud browser + Playwright CDP.

The project provides two ways to use it: **CLI** and **local WebUI**. The WebUI is recommended for daily use.

> About the project: this project is based on [xiaoguzuiniu/gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register), with modifications and extensions.

- TG community group:[https://t.me/+uC3Ix0l2E085Njhl](https://t.me/+uC3Ix0l2E085Njhl)

> Open-source edition notes: the repository keeps only source code, config templates and documentation; real runtime data such as accounts, tokens, email pools, Codex credentials and logs are all excluded via `.gitignore`.

---

## Special Thanks

[![IPWO residential proxy](https://raw.githubusercontent.com/myfanhua/turb-gpt-free-register/main/static/telegram-cloud-photo-size-5-6154589162401632962-y.jpg)](https://www.ipwo.net/?code=XEP358YGZ)

IPWO residential proxies provide residential IP resources covering 195+ countries and regions, support multi-region network environment configuration, and suit AI applications, browser automation, overseas service access, data collection and similar scenarios.
Important! 2GB of dynamic residential traffic is available with no threshold, [claim here](https://www.ipwo.net/?code=XEP358YGZ), and IP perks are distributed in the group from time to time.

## Feature Overview

### registration

- Batch registration of ChatGPT accounts.
- Supports registration driver switching:
  - `REGISTRATION_DRIVER = "protocol"`
  - `REGISTRATION_DRIVER = "roxy"`
  - `REGISTRATION_DRIVER = "cloak"`
  - `REGISTRATION_DRIVER = "browser_use"`
  - `REGISTRATION_DRIVER = "skyvern"`
- Supports RoxyBrowser one environment per account: automatically create, open, close and delete Roxy Profiles.
- Supports Roxy headless launch: `ROXY_OPEN_HEADLESS=True`.
- Supports CloakBrowser: free binary, headless mode, humanize, fixed fingerprint seed, and automatic language/timezone/WebRTC matching by exit IP.
- Roxy / Cloak browser registration is already compatible with:
  - Going straight to the email verification code page after entering the email;
  - After entering the email, going to `create-account/password` first, setting the password automatically, then continuing;
  - `about-you/profile` page where the age is entered directly as a number;
  - `about-you/profile` page where the birthday is entered as year/month/day;
  - React Aria birthday select / spinbutton year/month/day controls;
  - Misclicks on third-party login buttons caused by the button order changing across different exit IPs / page languages.

### Email Source

Supports multiple email sources:

- Outlook email pool:`email----password----clientId----refreshToken`
- Cloudflare domain email + QQ email IMAP receiving (`cloudflare_domain`)
- Cloudflare Worker temporary email: auto-creation + JWT code retrieval (`cloudflare`, compatible with cloudflare_temp_email)
- generic API email: `email----code URL`
- generic IMAP email pool: one per line as `email----IMAP password` or `email:IMAP password`; the server, port and SSL are configured uniformly in the import dialog
- GPTMail temporary email API: generates a random email at runtime and receives verification codes automatically
- domain email MailCode: official service, idempotent email purchase, and automatic code receiving by cursor (`mailcode`)
- Remail open API: orders short-lived emails per project and receives verification codes automatically (`remail`)
- `EMAIL_SOURCE` supports combining multiple sources, for example:

```python
EMAIL_SOURCE = "outlook,generic_api,imap"
```

- MailNest-Maichao: Outlook temporary email

### Codex OAuth

- Codex OAuth can run automatically after successful registration.
- Codex authorization driver options:
  - `CODEX_OAUTH_DRIVER = "protocol"`
  - `CODEX_OAUTH_DRIVER = "roxy"`
  - `CODEX_OAUTH_DRIVER = "cloak"`
  - `CODEX_OAUTH_DRIVER = "browser_use"`
  - `CODEX_OAUTH_DRIVER = "same_as_registration"`
- Supports generating the authorization URL through the CPA management API and submitting the OAuth callback.
- Supports code-receiving platforms:
  - GrizzlySMS
  - Local L number-taking service, see `L_API.md`
- Phone verification supports automatic number taking, number entry, code receiving, submission, and switching numbers to retry on failure.
- Codex credentials are saved to the `codex_accounts` table in SQLite.

### WebUI

- Start registration tasks in batches.
- View task logs in real time.
- Dynamically adjust the number of registration threads; new tasks use the latest value immediately after submission.
- Rerun Codex in batches; the rerun thread count takes effect immediately on each submission.
- Manage accounts, email pools and Codex credentials; the accounts page supports changing the email (rebinding) for single or multiple accounts and specifying the new email source, shows both the original and the current email after rebinding, supports viewing rebind logs, and automatically runs a liveness check to refresh the AT.
- Email pool import does not create accounts by default; after checking “Treat imported accounts as successfully registered by default”, the email pool entries are marked as used and also shown on the accounts page, and Codex can be rerun in batches directly.
- Roxy/Cloak browser registration reports the upload, download and total traffic of the whole browser session on completion, and the results are saved in both the task list and the account extended info; Browser Use/Skyvern cloud browsers do not enable local traffic listening, resource blocking or JS coverage collection.
- The config page supports hot reload; no restart is needed after saving.
- Roxy team/project can be fetched and saved on the config page.

### Data Storage

- Accounts, the email library, tasks and Codex credentials are stored uniformly at runtime in `turb.sqlite3` in the project root, split by business function into five tables: `accounts`, `email_pool` (email library), `registration_jobs`, `codex_accounts` and `codex_agent_accounts`.
- The database enables WAL, timeout waiting and indexes on common fields; WebUI pagination for accounts, plan status, the email library, Codex and tasks runs SQLite `COUNT(*) + LIMIT/OFFSET` directly, instead of first reading all data and slicing it in Python.
- On first startup, existing JSON/legacy SQLite data is migrated to the new database automatically; after migration, the account, task, email pool and Codex credential JSON/TXT files are no longer read or written.
- `turb.sqlite3*` is runtime data and has been added to `.gitignore`; please include it in your backup strategy.

### Browser Network Traffic Statistics

The browser driver starts counting when the registration page is opened and finalizes the summary after the post-registration dwell ends and before the browser closes. The result includes:

- Upload bytes, download bytes, total bytes;
- HTTP request count, failed/unfinished request count;
- WebSocket frame payload bytes (if the flow uses WebSocket).

The registration task list in the modern/Legacy WebUI shows total traffic; the full structure is saved in `network_traffic` of the task record and in `extra_json` of successful accounts. When a newly created Roxy environment uses the proxy pool, or Cloak uses the proxy pool or an explicit HTTP/SOCKS5 proxy, bidirectional transfer of the whole browser is counted through a local proxy relay, including TLS, browser startup, extensions and background requests; no upstream proxy configuration is needed. Page-visible counts are stored separately as `browser_observed_*`; resource details still use the page-level measure and cannot be added directly to the total transfer.

When reusing an existing Roxy environment, a hand-filled `proxyInfo`, no proxy, or an unsupported proxy protocol, page-visible statistics are still used and may miss other targets and the startup phase. None of the statistics include TCP/IP headers, retransmissions or provider-specific billing items, nor do they include email API, Roxy API or CDP control channel traffic.

#### Traffic-Saving Mode

In the WebUI, enable “Local browser traffic-saving mode” under “Browser Profile”, or set the following in `.env` (Roxy/Cloak only):

```dotenv
BROWSER_DATA_SAVER_MODE=True
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES=["image", "media"]
# URL glob list; one per line in the WebUI
BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS='["**://auth.openai.com/awe/api/v2/rum**", "**://chatgpt.com/awe/api/v2/rum**", "**://chatgpt.com/ces/statsc/flush**", "**://connect.facebook.net/**", "**://analytics.tiktok.com/**", "**://snap.licdn.com/**", "**://bat.bing.com/**", "**://accounts.google.com/gsi/client**"]'
```

Roxy/Selenium disables image loading in the launch arguments and uses Chrome CDP to block common image, media and other URL suffixes plus the configured URL globs (so extensionless resources are covered too); Cloak uses Playwright to block by resource type and URL glob. Browser Use/Skyvern are cloud browsers and do not install the local traffic-saving interceptor, so they always keep the full page resources. By default only `image` and `media` are blocked, plus the RUM/ad-analytics URLs listed in the config; core scripts, APIs and WebSockets required for login are never blocked by type. Playwright lets through URLs containing captcha/challenge keywords; the Chromium image switch and CDP URL blocklist of Roxy cannot provide URL exception rules, so if a captcha or layout problem appears, turn this mode off and retry.

Job 208 details show that the current rules actually blocked 5 third-party scripts (Google GSI, Facebook, TikTok, LinkedIn, Bing) and 380 RUM requests; email/password registration succeeded. The registration side downloaded about 9.92 MiB, of which scripts were about 8.90 MiB, mainly from the ChatGPT core CDN chunks.

The current default rules only cover RUM/ad analytics and Google GSI. Email/password registration does not use Google login, so the GSI rule can stay; if Google login is enabled in the future, remove the following line from “Traffic-saving URL block rules”:

```text
**://accounts.google.com/gsi/client**
```

The suspected CES telemetry endpoint `**://chatgpt.com/ces/v1/rgstr` costs about 277 KiB per round and can also be added after separately verifying the registration success rate.

Do not block `chatgpt.com/cdn/assets/*.js`, `auth-cdn.oaistatic.com/assets/*.js`, `sentinel.openai.com`, `chatgpt.com/backend-api/sentinel/*`, `ab.chatgpt.com/v1/initialize`, `chatgpt.com/realtime/wm` or the registration/OTP/session APIs. After Job 207 blocked `7aaae702-*.js`, the OTP input box went missing; after Job 208 let that chunk through, it succeeded completely, so CDN chunks must not be blocked based only on a low function execution ratio. Setting the URL rules to `[]` restores blocking by resource type only; leaving it blank uses the built-in default rules.

To also block CSS, add `stylesheet`:

```dotenv
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES=["image", "media", "stylesheet"]
```

CSS is usually not required by the registration APIs, but it affects hidden elements, layout and visibility checks, so test it separately first; if elements cannot be found or clicks misbehave, remove `stylesheet`.

#### Block Google Background Component Downloads

After local browser traffic-saving mode is enabled, the local proxy relay used by Roxy/Cloak rejects `dl.google.com`, `gvt1.com` and their subdomains (including `redirector.gvt1.com` and `rr8---*.gvt1.com`) **before connecting to the upstream proxy**, covering browser startup and background downloads without relying on Selenium/Playwright page interception. Matching is done on domain boundaries, so `notgvt1.com` and `gvt1.com.example.org` are not blocked by mistake; ChatGPT/OpenAI domains are not blocked as a result.

```dotenv
BROWSER_DATA_SAVER_MODE=True
BROWSER_DATA_SAVER_BLOCKED_PROXY_HOSTS="dl.google.com\ngvt1.com"
```

WebUI page “Browser Profile → Traffic-Saving Proxy Domain Block” lets you edit the domains, one per line (do not enter URLs/paths). Enter `[]` to turn off this rule set on its own; turning off traffic-saving mode also disables it. After saving and restarting the service, newly created browser proxy relays use the new rules; connections that are already established are not affected retroactively. It only applies to requests passing through the local relay; reusing an existing Roxy environment or a proxy that does not pass through the relay cannot guarantee blocking.

On a hit, a local HTTP 403 is returned; no remote connection is made and no proxy transfer bytes are produced for that attempt; the browser may retry, and retries are also rejected locally. The first hit logs `[proxy traffic saving]`, and when the task ends it prints `[proxy block] target=dl.google.com:443 blocked=...`; the cumulative count is saved in `network_traffic.proxy_transport.blocked_connection_count` and in the `blocked_connection_count` of each target. Blocked requests are not counted as failed connections, and no “saved bytes” are fabricated from unknown download sizes. This rule blocks component/extension downloads from the matching domains; remove the relevant domains if you need those features.

#### SOCKS5 Connection Failure and Automatic Recovery

A proxy returning `SOCKS5 code 1` means a general connection failure on the proxy side; this code alone cannot tell whether it was caused by an authentication error or by the browser closing. For the transient error codes `1/3/4/6` returned during the CONNECT handshake, the local relay re-establishes the connection with the same proxy and target, up to 3 attempts at 0.25/0.5 second intervals; a retry is allowed only before any browser data has been forwarded to the target, and HTTP requests or TLS data are never replayed. Authentication failures, rule rejections, unsupported commands/addresses and target port refusals are not retried by this mechanism.

A successful recovery logs `proxy reconnect recovered destination=...`; if it still fails after 3 attempts, a WARNING containing the target domain and the meaning of the error code is emitted at the point of failure. `[proxy target]` gains `retries/recovered`, and `connect_retry_count/recovered_connection_count` are kept in the task record. Connection terminations caused by the proxy relay closing are not counted as proxy faults; the cleanup stage prints a connection summary and no longer repeats the historical `last_error` as a current fault alert. If failures persist, diagnose based on the specific target and the proxy provider side; local retries cannot guarantee recovery from a persistent fault of the proxy server.

#### Resource Detail Logs

**Locating traffic outside the page statistics:** Roxy/Cloak tasks that use the local proxy relay automatically print the `[proxy target]` summary, independent of the resource detail switch. It tallies upload, download, total bytes, share, connection count and failure count by the target domain/IP and port of each proxy connection, sorted by consumption from largest to smallest; browser startup and background connections are included. For example:

```text
[Roxy] [proxy target] #1 target=cdn.example.com:443 upload=12000B download=20971520B total=20983520B (20.01 MiB) share=87.90% connections=4 failed=0
```

The full data is saved in `network_traffic.proxy_transport.destinations` of the task and account. The sum of bytes over all targets equals the total proxy transfer of the same snapshot; in-progress connections are also counted, without waiting for the tunnel to close. Targets whose connection failed with no body transferred keep their connection/failure counts, but no zero-consumption `[proxy target]` line is printed; connection failure logs also include `destination` to help locate them.

This is **connection target attribution**, not page request detail: an HTTPS encrypted tunnel only exposes the target host:port, cannot reveal the full path, and traffic alone cannot tell whether an extension, a Service Worker or the page initiated it. Startup and page visits to the same domain are merged; do not treat “proxy target bytes − page bytes” directly as the consumption of some background component. Traffic that does not pass through the local relay cannot be attributed. Tasks that ended earlier did not collect the target dimension and cannot be backfilled.

To analyze which resources consume traffic in the registration flow, enable:

```dotenv
BROWSER_TRAFFIC_DETAIL_LOG=True
BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES=2000
```

After a Roxy/Cloak registration task with statistics enabled ends, the log prints only `[resource detail]` lines that consumed traffic; blocked, zero-byte, local loopback and data/blob accesses are not printed; pure local cache hits consume no network bytes and are not printed either. Accesses that failed or did not complete but already sent or received bytes are still kept. Each entry contains the resource URL, type, HTTP method, status code, upload `upload`, download `download`, total consumption `total` (unit: B), response body/header sizes and failure/cache status, sorted by single-access total consumption from largest to smallest. The summary shows the upload, download and total bytes of all accesses that consumed traffic; even if the details exceed the output limit of `BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES`, the summary is not truncated.

Example:
```text
[resource detail] #1 xhr POST status=201 upload=12B download=28B total=40B ... size_source=playwright.sizes url=https://example.test/api
```

Per-access details use the HTTP/WS byte measure observable by the browser, exclude TLS/IP overhead, and the total proxy transfer of the whole browser cannot be apportioned directly to URLs. `size_source=playwright.sizes` means sizes returned by Playwright, `cdp.encoded+estimated_headers` means CDP transfer bytes combined with estimated request/response headers, `estimated_upload` means an upload estimate when sizes cannot be obtained (it should not be treated as an exact measurement); `resource_timing` means browser Timing data. Browser Use/Skyvern cloud browsers do not enable this listener. `ws_upload/ws_download` mean WebSocket frame payload. URL query parameter values and data/blob URL contents are not written to the log.

After sending back the `[resource detail]` log of one registration round, you can judge from the domain, path, resource type and actual byte count whether further blocking is worthwhile; types such as `stylesheet` and `font` should be enabled only after checking whether registration is affected.

#### JS Executed Function Coverage

To confirm whether a CDN chunk really executes in the Roxy/Cloak registration flow, enable:

```dotenv
BROWSER_JS_COVERAGE_LOG=True
BROWSER_JS_COVERAGE_MAX_ENTRIES=1000
```

Roxy/Selenium enables CDP `Profiler.startPreciseCoverage` on the current Chrome target, and Cloak establishes a CDP session for each discovered Chromium Page; Browser Use/Skyvern do not enable JS coverage listening. When a task ends, the log contains: `[JS execution summary]`, `[JS script]` for each script, `[JS execution]` for functions actually executed (function name, call count, `startOffset-endOffset:count`), and `[JS candidate]` for “execution ranges not observed this time”. `network_traffic.js_coverage` saves a script-level summary and candidate URLs; per-function offsets are written only to the log, and no source code, arguments or return values are saved.

`[JS candidate]` only means that no executed code was observed in the coverage of that round and cannot prove on its own that blocking is safe: first take one successful registration with the core scripts unblocked as a baseline, then block only one candidate at a time and compare OTP, session, profile page and success rate. Scripts from `data:`/`blob:`/extension pages are not listed as URL blocking candidates; Selenium pages across popups/multiple targets only cover the current CDP target. If the CDP Profiler is not supported by the current fingerprint browser, the log marks `supported=False`, which does not affect the registration flow.

---

## Requirements

- Python 3.10+
- Node.js 18+
- Usable proxy, system proxy/VPN, or a RoxyBrowser proxy environment
- If using Roxy for registration: the local RoxyBrowser API must be reachable
- If using Cloak for registration: the Cloak Chromium binary is downloaded automatically on first run; `CLOAK_GEOIP=True` requires the `cloakbrowser[geoip]` dependency
- If Codex auto-authorization is enabled: code-receiving platform configuration is required

Install dependencies:

```bash
# Using a project virtual environment is recommended; do not use the system pip
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
node --version
```

When starting the WebUI, `webui.sh` prefers `.venv/bin/python`:

```bash
./webui.sh start
```

If macOS was upgraded or the Python used to create the virtual environment was uninstalled, the Python symlink in the old `.venv` may be broken. In that case, recreate the environment using a currently installed Python:

```bash
rm -rf .venv
python3.12 -m venv .venv   # you can also replace it with any currently installed Python 3.10+
.venv/bin/python -m pip install -r requirements.txt
./webui.sh start
```

Verify the interpreter and Flask used by the current WebUI:

```bash
.venv/bin/python -c 'import sys, flask; print(sys.executable); print(flask.__version__)'
```

### Key Configuration (.env)

Put important API keys in the `.env` file in the project root, not in `config/*.py`.

```bash
cp .env.example .env
# Edit .env, for example:
# BROWSER_USE_API_KEY=...
# ROXY_API_TOKEN=...
```

Keys currently supported from `.env`:

- `WEBUI_AUTH_CODE`(WebUI login authorization code)
- `WEBUI_SESSION_SECRET`(optional, Session cookie signing key)
- `BROWSER_USE_API_KEY`
- `SKYVERN_API_KEY`
- `ROXY_API_TOKEN`
- `QQ_IMAP_PASSWORD`
- `CLOUDFLARE_API_KEY` / `CLOUDFLARE_CUSTOM_AUTH`(when `EMAIL_SOURCE=cloudflare`)
- `REMAIL_API_KEY`(when `EMAIL_SOURCE=remail`)
- `CPA_MANAGEMENT_KEY`
- `SMS_API_KEY`
- `L_ADMIN_AUTH_CODE`
- `H_ADMIN_AUTH_CODE`

WebUI When these fields are saved on the WebUI config page, they are written to `.env` (not the config source code).

---

## Quick Start

### WebUI Authorization Code

WebUI enforces the authorization code after startup: every page except `/login` and every `/api/*` endpoint checks it. Setting it in `.env` is recommended:

```dotenv
WEBUI_AUTH_CODE=your-auth-code
```

You can also pass it directly at startup:

```bash
python web.py --auth-code your-auth-code
```

Priority: `--auth-code` > `.env`/environment variable. If none is set, a temporary authorization code is generated and printed in the log at startup. API calls can use the Cookie obtained after login, or pass `X-Auth-Code: <authorization code>` / `Authorization: Bearer <authorization code>`.

`WEBUI_SESSION_SECRET` is optional; if not set, a stable Session signing key is derived from the fixed authorization code, and existing logins become invalid automatically after the authorization code is changed.

### 1. Configure the Email Source

#### Outlook Email pool

Copy the example file:

```bash
cp 用于注册的邮箱.txt.example 用于注册的邮箱.txt
```

Format per line:

```text
email----password----clientId----refreshToken
```

They can also be imported on the “Email Pool” page of the WebUI.

#### Generic API Email

Format per line:

```text
email----code_url
```

Set in `config/email.py`:

```python
EMAIL_SOURCE = "generic_api"
```

Or use a combined source:

```python
EMAIL_SOURCE = "outlook,generic_api,mailnest"
```

#### Generic IMAP Email

In the WebUI, go to “Email Pool → Import”, choose “Generic IMAP code-retrieval email”, with one entry per line in this format:

```text
email----imap_password
email:imap_password
```

- After choosing the “Generic IMAP code-retrieval email” import type, fill in the shared IMAP server, port and SSL settings.
- IMAP login username is fixed to the corresponding email address; no extra configuration is needed.
- The port is usually `993`, and SSL is enabled by default.
- Example:`user@example.com----app-password`
- `INBOX` is read by default and can be changed under “Config → Email / OTP → Generic IMAP”.

Set the email source to:

```python
EMAIL_SOURCE = "imap"
```

#### GPTMail temporary email

On the WebUI “Config → Email / OTP” page, fill in `GPTMail API Key`, then set the email source to:

```python
EMAIL_SOURCE = "gptmail"
```

You can also fill it in `.env` in the project root:

```dotenv
GPTMAIL_API_KEY=your_GPTMail_API_Key
```

The service address is fixed to `https://mail.chatgpt.org.uk`. If no Key is filled in, the task prompts you to fill in `GPTMail API Key` and does not use a public test Key.

#### Cloudflare Worker Temporary Email (`cloudflare`)

Compatible with `cloudflare_temp_email`-style Workers: a domain email is created automatically at registration time, and the inbox is polled with a JWT to extract the six-digit OpenAI verification code.  
(Different from the `cloudflare_domain` / QQ IMAP scheme below; do not mix up the identifiers.)

```dotenv
EMAIL_SOURCE=cloudflare
CLOUDFLARE_API_BASE=https://your-worker-api-domain
CLOUDFLARE_API_KEY=your_ADMIN_PASSWORD
CLOUDFLARE_AUTH_MODE=x-admin-auth
# admin creation, commonly used:
# CLOUDFLARE_PATH_ACCOUNTS=/admin/new_address
CLOUDFLARE_DEFAULT_DOMAINS=your-receiving-domain.com
```

For anonymous mode, set `CLOUDFLARE_AUTH_MODE=none` and leave the Key empty; the creation path defaults to `/api/new_address`; if it is blocked by Turnstile, switch to admin mode. More fields are in the WebUI “Config → Email / OTP” or `.env.example`.

#### Cloudflare Domain Email (`cloudflare_domain`)

Set in `config/email.py`:

```python
EMAIL_SOURCE = "cloudflare_domain"
EMAIL_DOMAIN = "your-domain"
QQ_EMAIL = "your-qq-email"
QQ_IMAP_PASSWORD = "QQ email IMAP authorization code"
```

Cloudflare Email Routing needs to forward domain mail to the QQ mailbox. This mode does not call the Worker creation API; it only generates addresses locally and fetches mail through QQ IMAP.

#### MailNest-Maichao Outlook Temporary Email

You can configure the API Key and the project code `MAIL_NEST_PROJECT_CODE` directly in the Web-UI, or in the config file.

- `api-key` retrieval page:https://mailnest.top/account
- Project code retrieval page: https://mailnest.top/buy-email - the default is `chatgpt001`, which can be used directly

#### Domain Email MailCode

Under “Config → Email / OTP → Domain Email MailCode”, fill in the API Key and product ID, and click “Open Official Site” to go to https://mailcode.bzb.qzz.io. The service address is fixed to this official site; no address setting is shown, and the legacy `MAILCODE_API_BASE` environment variable override is not accepted. After saving the key, click “Query Products and Balance” to view product IDs, prices and stock (querying does not purchase).

```dotenv
USE_EMAIL_SERVICE=True
EMAIL_SOURCE="mailcode"
MAILCODE_API_KEY="your_API_KEY"
MAILCODE_PRODUCT_ID="product_a3783a0ead074b4091631b9ad04153f9"
MAILCODE_REQUEST_TIMEOUT=20
MAILCODE_CHANNEL_WAIT_SECONDS=60
```

API Key needs permissions for products, balance, email reading, `orders:write` and so on. Each task claims one email of the specified product, and the purchase result is read from `data.items[0]`; it does not switch products automatically or request refunds. After purchase, the code-retrieval API is called first to initialize IMAP on demand, and the email is returned only after the channel is READY, so that the registration flow triggers the verification code sending.

On network timeouts, 429 or service errors, retries reuse the original idempotency key and request content and honor `Retry-After`. Pending orders are saved in `cache/mailcode/purchases/` and the original request continues after a restart, avoiding double charging; a purchased email whose channel failed to become ready is not purchased again. Do not delete this directory while an order result is unconfirmed. The claim flow of the same service configuration runs serially within this process; do not let multiple processes share the same cache directory and claim at the same time.

The server-side `next_sequence` of verification codes is persisted per email (`cache/mailcode/contexts/`), without adding 1, without deduplicating by the code digits, and keeping leading zeros such as `012345`; old codes are filtered by send time and expiry time. By default queries are at least 5 seconds apart, and pagination continues when `has_more=true`. After a restart it can be recovered from the local context; when the context is missing, purchased emails are queried with pagination, and nothing is purchased again for liveness checks. The cache stores only orders, emails and cursors, not the API Key.

The client also provides functions for products, balance, order list/details, purchased emails, channel status, and exporting/revoking code-retrieval links, for use by local integrations.

#### Remail open API

Remail API documentation: [https://remail.aishop6.com/docs](https://remail.aishop6.com/docs). This service uses API Key
Short-lived code-receiving orders are created per project, and the email and service token returned by the order are used automatically for subsequent code retrieval.

Fill in the following under “Config → Email / OTP” in the WebUI:

- `REMAIL_API_KEY`: API Key generated in the Remail console, starting with `rk-`;
- `REMAIL_PROJECT_ID`: the `projectId` in the Remail “Projects” list used for ChatGPT/OpenAI verification codes;
- `REMAIL_EMAIL_SUFFIX`: order suffix; for Microsoft email it is usually `outlook.com`.

Then set:

```dotenv
USE_EMAIL_SERVICE=True
EMAIL_SOURCE=remail
REMAIL_API_BASE=https://remail.aishop6.com
REMAIL_API_KEY=your_Remail_API_Key
REMAIL_PROJECT_ID=Project ID
REMAIL_EMAIL_SUFFIX=outlook.com
REMAIL_SERVICE_MODE=purchase
REMAIL_SUPPLY_POLICY=public_only
```

`REMAIL_SERVICE_MODE` defaults to `purchase` (long-term purchase, repeatable receiving) and can also be changed to `code` (short-term code receiving).
`REMAIL_SUPPLY_POLICY` defaults to `public_only` and can also be set to `private_first`. Each registration task creates one
order for the matching mode; the verification code is fetched via `/v1/pickup`; the Remail order balance and the stock of the corresponding project must be available.

---

### 2. Configure the Registration Driver

Edit `config/roxybrowser.py`, or change it directly on the WebUI “Config” page.

#### Register with RoxyBrowser

```python
REGISTRATION_DRIVER = "roxy"  # Optional: protocol / roxy / cloak
ROXY_API_BASE = "http://127.0.0.1:50100"
ROXY_API_TOKEN = "your Roxy API Key"
ROXY_WORKSPACE_ID = "your workspaceId"
ROXY_PROJECT_ID = "your projectId"
ROXY_ONE_PROFILE_PER_ACCOUNT = True
ROXY_DELETE_PROFILE_AFTER_RUN = True
ROXY_CREATE_USE_PROXY_POOL = True
```

To run headless:

```python
ROXY_OPEN_HEADLESS = True
```


#### Register with CloakBrowser

To switch to CloakBrowser, install the dependencies first:

```bash
pip install -r requirements.txt
```

Then change the registration driver in `config/roxybrowser.py` or on the WebUI config page to:

```python
REGISTRATION_DRIVER = "cloak"
```

Then set the Codex authorization driver in `config/codex.py` or in the WebUI “CPA / Codex” group:

```python
CODEX_OAUTH_DRIVER = "same_as_registration"  # follow the registration driver
# or specify one separately:"protocol" / "roxy" / "cloak" / "browser_use"
```

CloakBrowser dedicated settings are in `config/cloakbrowser.py`:

```python
CLOAK_HEADLESS = False          # True=headless; False=show window
CLOAK_HUMANIZE = True           # humanized mouse/keyboard/scroll behavior
CLOAK_GEOIP = True              # automatically match to the current exit IP: language/timezone/WebRTC
CLOAK_LOCALE = ""               # leave empty for auto; or force one such as ja-JP / en-US
CLOAK_TIMEZONE = ""             # leave empty for auto; or force one such as Asia/Tokyo
CLOAK_LICENSE_KEY = ""          # leave empty to use the free binary; enter a Pro key to use the latest version
CLOAK_FINGERPRINT_SEED = ""     # leave empty for a random one each time; a fixed value = a fixed fingerprint
CLOAK_USER_DATA_DIR = ""        # leave empty for a temporary environment; set a path to persist the profile
```

Notes:

- `CLOAK_GEOIP=True` automatically generates `locale / timezone / Accept-Language` from the current exit IP and passes them to CloakBrowser and the Playwright context.
- If you use a proxy through the project proxy pool, fill in the proxy in `PROXY_POOL` of `config/proxy.py`; if you use a system proxy/VPN, the location is also determined automatically from the actual current exit IP.
- The free edition does not limit the number of windows on the project side; this project starts one CloakBrowser instance per registration task, i.e. one fingerprint per instance.
- WebUI settings: `Codex Authorization Driver` is in the “CPA / Codex” group and corresponds to `CODEX_OAUTH_DRIVER` in `config/codex.py`.

#### Register with the Protocol Driver

```python
REGISTRATION_DRIVER = "protocol"
```

Protocol registration uses `curl_cffi`, Sentinel/PoW, the proxy pool and other settings, and is forced to go through the
`create-account/password` email-and-password registration flow. The registration password is the same as for the browser drivers:
It uses `REGISTER_PASSWORD` from `config/register.py` first, and generates a random one if it is not configured,
and saves it to `extra_json.registration_password` of the account.

#### Register with Browser Use Cloud

```python
REGISTRATION_DRIVER = "browser_use"
```

and fill in the following in `config/browser_use.py` or in WebUI “Config → Browser Use”:

```python
BROWSER_USE_API_KEY = "your Browser Use API Key"
BROWSER_USE_PROXY_COUNTRY_CODE = "jp"   # Optional:us/sg/de...
BROWSER_USE_USE_PROXY = True
BROWSER_USE_FAST_MODE = True       # Recommended on: reduces extra Browser Use waiting
BROWSER_USE_LOG_TIMING = True      # output stage timing logs to help locate slow spots
BROWSER_USE_SESSION_TIMEOUT = 240  # Browser Use keepAlive/timeout, in minutes; keeps the remote browser alive longer when it is created
```

If you also want Browser Use to run Codex OAuth automatically after successful registration:

```python
ENABLE_CODEX_AUTO = True
CODEX_OAUTH_DRIVER = "browser_use"
# or CODEX_OAUTH_DRIVER = "same_as_registration", which follows automatically when REGISTRATION_DRIVER="browser_use"
```

Dependencies:

```bash
uv pip install playwright --python .venv/bin/python
# or
pip install playwright
```

Notes:

- Browser Use runs on a remote stealth Chromium, controlled through Playwright `connect_over_cdp`.
- `BROWSER_USE_SESSION_TIMEOUT=240` sets a long keepAlive when Browser Use creates/connects the remote browser (the `timeout` parameter of the connect URL, in minutes), so the cloud session is not reclaimed early while waiting for email OTP, SMS or callback; the code limits it to `1~240`.
- If, on first entering the email verification code page, the email actually already contains a verification code but the program did not fetch it, it is usually Outlook retrieval-chain jitter: a round of Graph TLS/REST/IMAP failed, the short polling slice was too short, or the `after_ts` filter boundary was too tight. The Browser Use driver has relaxed the single-round Outlook retrieval slice, records the code filter time earlier, and after the email OTP wait times out it tries clicking resend and keeps waiting; the resend entry is located with DOM structure/position/attribute heuristics, not relying on page copy or OCR/text recognition. You can raise `OTP_MAX_WAIT` to `180~240` under “Email / OTP”, and prefer `auto` for `OUTLOOK_FETCH_MODE`.
- Outlook retrieval logs show the verification code source: `source=graph`, `source=outlook_rest`, `source=imap_new`, `source=imap_entra_outlook`, `source=remote_graph` or `source=remote_imap`, which makes it easy to tell which chain fetched the code successfully.
- `BROWSER_USE_FAST_MODE=True` skips most of the humanized pacing waits; `BROWSER_USE_LOG_TIMING=True` prints the timing of stages such as connection, page opening, email, OTP, phone and callback.
- Supported as a Codex OAuth authorization driver: `CODEX_OAUTH_DRIVER="browser_use"`, which can complete the authorization page, email OTP, phone SMS verification and callback capture.
- Suited to scenarios where you do not want to install Roxy locally but still want session isolation + a cloud proxy.
- Free quota/concurrency is subject to the Browser Use official pricing page.

---

### 3. Configure the Proxy

Edit `config/proxy.py`:

```python
PROXY_POOL = [
    "http://user:pass@host:port",
]
```

Roxy one environment per account: when `ROXY_CREATE_USE_PROXY_POOL=True` is on, a random proxy is taken from here and written into the Roxy Profile.

---

### 4. Config Codex OAuth

If you do not need Codex, turn it off:

```python
ENABLE_CODEX_AUTO = False
```

If you need automatic authorization:

```python
ENABLE_CODEX_AUTO = True
# config/codex.py
CODEX_OAUTH_DRIVER = "browser_use"  # Optional: protocol / roxy / cloak / browser_use / skyvern / same_as_registration
```

Code-receiving settings are in `config/codex.py`:

```python
SMS_PROVIDER = "l"        # Optional: grizzly / l / h
SMS_API_KEY = "your GrizzlySMS key"  # only needed for GrizzlySMS
SMS_SERVICE = "openai"
SMS_COUNTRY = "Country Code"
SMS_MAX_RETRIES = 10
SMS_CODE_WAIT = 120
SMS_POLL_INTERVAL = 5

# If SMS_PROVIDER="h", H always reuses:
#   SMS_SERVICE -> H projectId
#   SMS_COUNTRY -> H country
H_API_BASE = "http://localhost:8788"
H_ADMIN_AUTH_CODE = "your-H-admin-auth-code"
```

CPA Authorization URL source:

```python
CODEX_AUTH_URL_SOURCE = "cpa"
CPA_MANAGEMENT_URL = "your-CPA-management-URL"
CPA_MANAGEMENT_KEY = "your-CPA-management-key"
```

---

## Usage

## WebUI Recommended Way

Single-script background management from the project root is recommended:

```bash
./webui.sh start      # start
./webui.sh stop       # stop
./webui.sh restart    # restart
./webui.sh status     # status
./webui.sh logs       # view live logs
```

By default the script starts `http://127.0.0.1:5000`, writes logs to `logs/webui.log`, and writes the PID to `run/webui.pid`.

It can be adjusted through environment variables:

```bash
PORT=8000 OPEN_BROWSER=1 ./webui.sh start
HOST=0.0.0.0 PORT=5000 ./webui.sh restart
AUTH_CODE=your-auth-code ./webui.sh start
```

You can also start it directly in the foreground:

Start:

```bash
python web.py --open-browser
```

Default address:

```text
http://127.0.0.1:5000
```

Specify a port:

```bash
python web.py --port 8000 --open-browser
```

Allow LAN access:

```bash
python web.py --host 0.0.0.0 --port 5000
```

WebUI page descriptions:

| Page | Function |
|---|---|
| Registration | Set the registration count and thread count, start batch registration, view tasks and logs |
| Accounts | View accounts, copy tokens, rerun Codex, delete accounts in batches |
| Codex Authorization | View/download/delete Codex credentials in SQLite |
| Email Pool | Import emails, filter by source, mark as available/failed, delete emails |
| Config | Edit runtime settings with hot reload, including Roxy, Codex, email, proxy, human pacing, etc. |

### Thread Count Notes

- The registration thread count is read each time “Start Registration” is clicked.
- If the thread count differs from last time, newly submitted tasks use a new thread pool.
- Tasks already queued or running in the old thread pool will run to completion and are not forcibly cancelled.
- Codex batch reruns create an independent thread pool with the rerun thread count submitted each time.

---

## CLI Usage

Register 1 account:

```bash
python main.py
```

Register 10 accounts in batch with 3 threads:

```bash
python main.py -n 10 --workers 3 --continue-on-fail
```

Detailed logs:

```bash
python main.py -n 1 --verbose
```

Parameters:

| Parameter | Description | Default |
|---|---|---|
| `-n, --count` | number of registrations | 1 |
| `--workers` | number of concurrent threads | 1 |
| `--delay` | Interval in seconds after each registration ends | 0 |
| `--continue-on-fail` | continue after a single failure | False |
| `--verbose` | DEBUG log | False |

---

## Codex Rerun

WebUI accounts page can rerun Codex for a single account or in batches.

CLI standalone rerun:

```bash
python tools/test_codex_oauth.py --email <registered-email> --verbose
```

A rerun consumes:

- 1 email OTP
- 1 code-receiving number

Rerun logs are at:

```text
注册日志/codex-retry-邮箱.log
```

---

## Registration Password Notes

Roxy registration, if it encounters the new flow:

```text
/create-account/password
```

The password is set automatically.

Password source:

1. Prefer `config/register.py`:

```python
REGISTER_PASSWORD = "your-fixed-password"
```

2. If empty, a 14-character strong password is generated automatically, containing uppercase, lowercase, digits and symbols.

Saved at:

- Account `extra_json.registration_password`
- SQLite `accounts.payload` containing `extra_json.registration_password`

Note: the `password` field in the accounts table is still used for the Outlook email credential password and is not overwritten by the OpenAI registration password.

---

## Important Config Files

| File | Description |
|---|---|
| `config/roxybrowser.py` | Registration driver, Roxy API, Roxy environment lifecycle |
| `config/cloakbrowser.py` | CloakBrowser headless/humanize/geoip/language-timezone/fingerprint seed |
| `config/codex.py` | Codex OAuth, authorization driver, CPA management API, code-receiving platform |
| `config/email.py` | Email sources, OTP polling, QQ IMAP, domain email, Cloudflare Worker temporary email |
| `config/proxy.py` | Proxy pool |
| `config/register.py` | Default email, password, display name |
| `config/twofa.py` | 2FA switch |
| `config/humanize.py` | Random pauses/human pacing |
| `config/flow_trigger.py` | Post-registration-success trigger Flow |
| `config/browser.py` | Protocol-mode browser fingerprint |
| `config/openai_protocol.py` | OpenAI OAuth/Sentinel parameters |

WebUI After the WebUI config page is saved, hot reload is invoked; common items such as Roxy, Codex, email, proxy and human pacing take effect immediately.

---

## Data and Artifacts

| Path | Contents |
|---|---|
| `turb.sqlite3` | All data for accounts, the email library, tasks, and Codex and Agent credentials |
| Legacy JSON/TXT/Codex files | Used only for the first migration; no longer read or written at runtime |
| `注册日志/` | 注册任务日志、Codex 补跑日志 |

---

## Current Main Flow

### Roxy Registration Flow

```text
Create/open Roxy Profile
  ↓
Open chatgpt.com/auth/login
  ↓
Locate the email input box by DOM technical attributes, avoiding misclicks on Google/Apple/Microsoft
  ↓
Submit the email form
  ↓
If create-account/password is entered: set the password and submit
  ↓
Wait for the email verification code page
  ↓
Read the email OTP and submit it
  ↓
If about-you/profile is entered: fill in name + age or birthday
  ↓
Enter ChatGPT, read /api/auth/session accessToken
  ↓
Optional: 2FA
  ↓
Optional: Codex OAuth
  ↓
Save the account to SQLite
  ↓
Close/delete Roxy Profile
```

### Codex Roxy Authorization Flow

```text
Get the Codex authorization URL (CPA or local PKCE)
  ↓
Roxy Open authorization page
  ↓
Email login + email OTP
  ↓
Phone number verification: take a number → enter the number → send → wait for the SMS → enter OTP
  ↓
Waiting consent/workspace/callback
  ↓
Submit the callback to CPA, or exchange it locally for a token
  ↓
Save the Codex credentials to SQLite
```

---

## FAQ

### Config Saved but Not Taking Effect?

WebUI config page hot-reloads after saving. The config is also hot-reloaded once more before a Codex rerun thread starts.

If you edit `config/*.py` by hand, the CLI process must be restarted; for the WebUI, changing settings on the config page is recommended.

### Roxy Headless Saved but Window Still Pops Up?

Check:

```python
ROXY_OPEN_HEADLESS = True
```

And confirm that your Roxy version supports the `headless` parameter of `/browser/open`. The log prints the `headless` value actually passed in.

### Google Login Clicked When the Exit IP Is Not in Japan?

The current Roxy registration email entry is now located only by DOM technical attributes and excludes third-party login buttons. It no longer matches the button text “Continue”.

### Codex showing `Check your phone` is misjudged as a failure?

Already handled: `Check your phone / Enter the verification code...` is recognized as the phone verification code page and enters the flow of waiting for the SMS verification code.

### Log Showed Failure After Phone OTP Submission, but It Succeeded Later?

Fixed: after the phone OTP is submitted, it waits for the page to leave the phone-number flow or reach the callback, and no longer misjudges failure after 3 seconds based on old page text.

### Codex failed but registration succeeded, what now?

The account is saved and the Codex status is marked as failed. You can click rerun on the WebUI accounts page, or use:

```bash
python tools/test_codex_oauth.py --email <Email> --verbose
```

### Cloudflare Worker How to Configure the Email?

Set `EMAIL_SOURCE` to `cloudflare` and configure `CLOUDFLARE_API_BASE` and so on (see “Cloudflare Worker Temporary Email” above).  
Note that it is not the same source as `cloudflare_domain` (QQ IMAP forwarding).

### Can I Register Without a Code-Receiving Platform?

Yes. Turn off:

```python
ENABLE_CODEX_AUTO = False
```

The main registration flow does not depend on code receiving; only Codex auto-authorization needs it.

---

## Project Structure

```text
.
├── main.py                         # CLI Entry point
├── web.py                          # WebUI Entry point
├── config/                         # Config
│   ├── roxybrowser.py              # RoxyBrowser registration/Codex driver
│   ├── cloakbrowser.py             # CloakBrowser registration driver config
│   ├── browser_use.py              # Browser Use Cloud Config
│   ├── codex.py                    # Codex OAuth / authorization driver / CPA / code receiving
│   ├── email.py                    # Email Source/OTP
│   ├── proxy.py                    # Proxy pool
│   ├── register.py                 # default registration info
│   └── ...
├── core/
│   ├── browser_data_saver.py       # Roxy/Cloak local browser traffic-saving resource blocking
│   ├── browser_traffic.py          # browser registration HTTP/WebSocket traffic statistics
│   ├── roxy_registration.py        # Roxy / browser registration page flow
│   ├── cloakbrowser_registration.py # Cloak registration entry
│   ├── cloakbrowser_driver.py      # Cloak Playwright→Selenium style adapter layer
│   ├── browser_use_registration.py # Browser Use + Playwright Registration Flow
│   ├── browser_use_client.py       # Browser Use CDP client
│   ├── roxy_codex_oauth.py         # Roxy / Cloak browser Codex OAuth page flow
│   ├── roxybrowser_client.py       # Roxy API client
│   ├── registration_service.py     # WebUI registration thread pool
│   ├── codex_oauth.py              # Codex protocol/Roxy/Cloak dispatch
│   ├── email_provider.py           # email source dispatch
│   ├── cf_temp_mail_client.py      # Cloudflare Worker temporary email
│   ├── sms_provider.py             # Code-Receiving Platform
│   ├── account_export.py           # post-registration processing and SQLite saving
│   └── db.py                       # SQLite database and one-time migration
├── webui/
│   ├── app.py                      # Flask API
│   ├── config_editor.py            # config read/write and hot reload
│   └── templates/index.html        # single-page console
├── sentinel/
│   ├── sdk.js
│   └── sentinel-runner.js
├── tools/
│   └── test_codex_oauth.py         # Codex standalone rerun
└── L_API.md                        # Local L code-receiving API notes
```

---

## Usage Tips

- For daily batch use, use the WebUI; running multiple CLI processes at the same time is not recommended.
- The number of registration threads should preferably not exceed the number of available proxies.
- Roxy one environment per account is recommended to stay on, to reduce environment contamination.
- When debugging page problems, you can temporarily set:

```python
ROXY_KEEP_BROWSER_OPEN = True
ROXY_OPEN_HEADLESS = False
```

- After debugging, change back to automatically closing/deleting environments.

---

## 🙏 Acknowledgements

- [LINUX DO](https://linux.do) — Community discussion and user feedback
- [RoxyBrowser](https://roxybrowser.cn/invite/NvH4Jx) — Provides 5 windows for free
- [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) — Stealth Chromium / Playwright automated fingerprint browser support
- [browser-use](https://github.com/browser-use/browser-use) — Browser Use Cloud / Playwright CDP cloud browser capability support
- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) — Codex OAuth credential format reference
- [curl_cffi](https://github.com/yifeikong/curl_cffi) — Underlying HTTP library providing TLS fingerprint impersonation capability

---

## License

MIT
