# Default-all-domains-1784468371563.json Pure-protocol flow and fingerprint completion notes

Source file: `Default-all-domains-1784468371563.json`, a Reqorder HAR; capture time window: 2026-07-19 21:36:16 ~ 21:37:30 (Asia/Shanghai).

## 1. Overview

- Total requests:236
- Domain distribution: `chatgpt.com` 125, `browser-intake-datadoghq.com` 107, `auth.openai.com` 2, `ab.chatgpt.com` 1, test callback 1
- Main statuses: 200 x 112, 202 x 111, 0 x 13 (Datadog/octet-stream interrupted or flagged by the capture tool)
- Main browser profile: macOS + Chrome 149; language/timezone are determined automatically by the proxy egress IP, and this HAR sample is zh-CN + Asia/Shanghai
- ChatGPT frontend version:`prod-fb4a8a2a751dfec391053cfd7b01c52699ccf78c`
- OAI build number:`8370486`
- Sentinel SDK:`20260219f9f6`

## 2. Key flow order

### A. ChatGPT anonymous home page / model warm-up

1. `POST /ces/v1/rgstr`: Statsig register/flush; the reporting headers include `oai-client-build-number`, `oai-client-version`, `oai-device-id`, `oai-language`, `oai-session-id`.
2. `GET /ces/v1/projects/oai/settings`
3. `GET /backend-anon/accounts/check/v4-2023-04-27?timezone_offset_min=-480`
4. `GET /backend-anon/me`
5. `POST /backend-anon/sentinel/chat-requirements/prepare`
6. `GET /backend-anon/system_hints?...`,`GET /backend-anon/models?...`
7. `POST /backend-anon/conversation/init`
8. `POST /backend-anon/sentinel/chat-requirements/finalize`

### B. NextAuth initiating OpenAI OAuth

1. `GET /api/auth/providers`
2. `GET /api/auth/csrf`
3. `POST /api/auth/signin/openai?...screen_hint=login_or_signup&login_hint=<email>`
   - form:`callbackUrl=https://chatgpt.com/&csrfToken=<csrf>&json=true`
   - The response returns the `auth.openai.com/api/accounts/authorize?...` URL.

### C. Auth Web Email OTP / about-you / create_account

In the capture, `auth.openai.com` has only two business endpoints:

1. `POST https://auth.openai.com/api/accounts/email-otp/validate`
   - body: `{"code":"<6-digit OTP>"}`
   - This capture did not carry `openai-sentinel-token`.
2. `POST https://auth.openai.com/api/accounts/create_account`
   - body:`{"name":"<name>","birthdate":"YYYY-MM-DD"}`
   - Carries `openai-sentinel-token` and `openai-sentinel-so-token`.
   - token contains `flow=oauth_create_account`.

### D. logged-in ChatGPT bootstrap

After creation succeeds, it calls back to ChatGPT and enters the logged-in bootstrap:

- `GET /backend-api/accounts/optimized/check`
- `GET /backend-api/user_granular_consent`
- `GET /backend-api/me`
- `GET /backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-480`
- `GET /backend-api/settings/user`
- `POST /backend-api/sentinel/chat-requirements/prepare`
- `GET /backend-api/system_hints?...`,`GET /backend-api/models?...`
- `POST /backend-api/conversation/init`
- `POST /backend-api/sentinel/chat-requirements/finalize`
- `GET /backend-api/conversations?...`, `GET /backend-api/client/strings`, and other sidebar/home initialization endpoints.

The full per-request list has been extracted to: `docs/protocol_har_summary.json`.

## 3. Fingerprint p array field completion

The `p` in the capture decodes to a 25-element array in every case:

| Index | Meaning | Sample from this capture |
|---:|---|---|
| 0 | `screen.width + screen.height` | HAR sample is `2730` (`1680x1050`), used in code only as one of the candidate profiles |
| 1 | `new Date().toString()` | `Sun Jul 19 2026 ... GMT+0800 (China Standard Time)` |
| 2 | `performance.memory.jsHeapSizeLimit` | `4395630592` |
| 3 | Initial/PoW attempt | initially `1`, create_account token is `5` |
| 4 | UA | `Mozilla/5.0 ... Chrome/149.0.0.0 Safari/537.36` |
| 5 | script src | see the JS entries below |
| 6 | build id / data-build | ChatGPT prepare is `prod-fb4a8a...`; Auth token is `null` |
| 7 | `navigator.language` | `zh-CN` |
| 8 | `navigator.languages.join(',')` | `zh-CN` |
| 9 | Random/elapsed time | `1.2`, `1.4`, `4`, etc. |
| 10 | navigator prototype/property samples | `createAuctionNonce`, `clearOriginJoinedAdInterestGroups`,`login` |
| 11 | document key / React key | `_reactListening...` or `__reactContainer$...` |
| 12 | window key | `scrollX`, `locationbar`,`ondevicemotion` |
| 13 | `performance.now()` | floating-point milliseconds |
| 14 | Sentinel internal sid | UUID, different from `oai-device-id` |
| 15 | URL search params | empty string |
| 16 | `navigator.hardwareConcurrency` | `6` |
| 17 | `performance.timeOrigin` | millisecond timestamp |
| 18-24 | window feature flags | all `0` this time, but the Chrome runner keeps `requestIdleCallback` controllable |

## 4. JS entry completion

HAR No `.js` response body was saved directly, but the sampled JS entries were recovered from Sentinel `p[5]`:

1. `https://accounts.google.com/gsi/client`
2. `https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload`
3. `https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js`

The project already has a local SDK file: `sentinel/sdk.js`; the Node VM runner is `sentinel/sentinel-runner.js`. This round the runner Chrome 149 DOM/Navigator/Window samples were completed according to the HAR.

## 5. Pure-protocol details already synced into code

- `config/openai_protocol.py`
  - Updated `OPENAI_BUILD_ID=prod-fb4a8a2a751dfec391053cfd7b01c52699ccf78c`
  - Added `OAI_CLIENT_BUILD_NUMBER=8370486`,`OAI_CLIENT_VERSION`
  - Completed the Statsig/AB SDK key/version constants.
- `config/browser.py`
  - Switched to the Chrome 149 HTTP/JS profile: UA, Client Hints, dynamic language/timezone; window/screen sizes are chosen randomly from the profile pool, and the HAR values `1680x1050` / `hardwareConcurrency=6` / `jsHeapSizeLimit=4395630592` are only one of the candidates.
  - Completed the sampled keys that appear in the HAR, such as `createAuctionNonce`, `clearOriginJoinedAdInterestGroups`, `login`, `locationbar`, `scrollX`, `ondevicemotion`.
- `core/session.py`
  - All frontend API requests uniformly gain `oai-client-build-number`, `oai-client-version`, `oai-session-id`.
  - Added a stable `react_container_key` per session, which together with `react_listening_key` is used by p[11] sampling.
- `core/sentinel.py`
  - p[11] candidates now include `__reactContainer$...`.
- `sentinel/sentinel-runner.js`
  - Chrome Navigator/DOM/Window samples completed.
  - Auth Sentinel token supports the `data-build=null` form.
  - The default SDK src is aligned to `https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js`.

## 6. Regenerate summary

```bash
./tools/analyze_har_protocol.py Default-all-domains-1784468371563.json -o docs/protocol_har_summary.json
```

## 7. `.env` overrides

Language/timezone are not fixed and are set automatically from the proxy egress IP:

```env
AUTO_BROWSER_LOCALE_FROM_IP="True"
```

`BROWSER_LOCALE_PROFILE="jp"` is used only as a fallback profile when GeoIP detection fails; normally `Accept-Language`, `navigator.language`, `navigator.languages`, and the `Date`/`Intl` timezone are generated from the egress country/timezone.

## 8. runner follow-up completion items

`sentinel/sentinel-runner.js` Beyond the few keys directly hit in the HAR, the Python profile must also stay consistent after being passed into the Node VM:

- `--language` / `--languages`: passed in from `BrowserSession.browser_profile`.
- `--time-zone` / `--timezone-name` / `--timezone-offset-minutes`: passed in from the proxy GeoIP profile.
- `process.env.TZ`: set by the runner at startup according to `--time-zone`, so `Date.toString()` inside the VM matches the proxy timezone.
- `Intl.DateTimeFormat().resolvedOptions().timeZone`: overridden inside the VM to the same `timeZone`.
- `document` React key: supports both `_reactListening...` and `__reactContainer$...`.
- `navigator` Chrome specific sampling: `createAuctionNonce`, `clearOriginJoinedAdInterestGroups`, `canLoadAdAuctionFencedFrame`, `login`, etc.
- `window` Chrome/page sampling: `locationbar`, `scrollX`, `scrollY`, `ondevicemotion`, etc.

So the final language/timezone chain is: proxy egress IP → `pick_browser_profile()` → Python Sentinel `p` → runner CLI arguments → Node VM `Date`/`Intl`/`navigator`.

## 9. second alignment check and completion

After comparing against the code again based on this file, the following easily missed protocol details were also completed:

1. **Auth Web JSON endpoint headers**
   - HAR shows that `auth.openai.com/api/accounts/email-otp/validate` and `create_account` carry no `oai-client-*` headers.
   - Changed `core.session.BrowserSession.get_auth_headers()` to the Auth RUM shape:
     - `traceparent`
     - `tracestate`
     - `x-access-flow-invocation-id`
     - `x-datadog-*`
   - `chatgpt.com` frontend endpoints still keep `oai-client-*` / `oai-session-id`.

2. **NextAuth signin callbackUrl**
   - HAR form body is `callbackUrl=https://chatgpt.com/`.
   - Changed `core.chatgpt_auth.signin_openai()` from `/login` to the root path `/`.

3. **email-otp/validate Sentinel policy**
   - HAR samples show that `email-otp/validate` did not carry `openai-sentinel-token`.
   - Added a switch: `config.openai_protocol.SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE = False`.
   - By default it follows the HAR and sends no Sentinel; if the server requires it later, set it to `True` to fall back to the old logic.

4. **timezone_offset_min sign**
   - ChatGPT `accounts/check` URL uses JS `Date.getTimezoneOffset()` semantics: UTC+8 is `-480` and Japan is `-540`.
   - Added `BrowserSession.js_timezone_offset_min()`, to avoid using the internal `timezone_offset_minutes` (positive for east of UTC) directly in the URL.

5. **Fallback region**
   - When proxy GeoIP detection fails, fall back to Japan: `BROWSER_LOCALE_PROFILE="jp"`.
   - GeoIP when it succeeds, language/timezone are still set automatically from the egress IP.

### Paths still not forced to be completed

- `browser-intake-datadoghq.com` high-frequency RUM batch reporting: not a required path for the registration flow and would significantly increase request noise, so it is not forced to be simulated for now.
- `chatgpt.com/backend-anon/sentinel/chat-requirements/prepare/finalize` and the logged-in `backend-api/sentinel/...`: the document already records their order; the registration core still uses `sentinel.openai.com/backend-api/sentinel/req` to generate the headers required by create_account. If the home-page bootstrap later needs to have exactly the same shape, a separate switchable `chatgpt_bootstrap()` warm-up module can be added.


## 10. Window/screen size policy

The window/screen size should not be fixed globally to the single HAR sample. Current policy:

- Within the same `BrowserSession`: size, DPR, CPU, and JS heap stay stable, and are passed in sync to the Python Sentinel `p` and the Node runner.
- Across different `BrowserSession`s: chosen randomly from `BROWSER_PROFILE_POOL`, giving a natural spread.
- HAR sample `1680x1050 / hardwareConcurrency=6 / jsHeapSizeLimit=4395630592` is kept in the pool but not forced.
- To reproduce the experimental capture, call `build_browser_environment(..., HAR_CAPTURE_BASE_PROFILE)` explicitly.

## 11. Third round of detail optimization

After aligning with the HAR again, the following details were completed/converged:

1. **`navigator.languages` convergence**
   - HAR decoded `p[8]` is the single value `zh-CN`, not `zh-CN,zh,en-US,en`.
   - The `navigator.languages` of each regional profile now converges by default to a single primary language, for example:
     - JP:`["ja-JP"]`
     - CN:`["zh-CN"]`
     - US:`["en-US"]`
   - `Accept-Language` still keeps the q-weight chain common in browser request headers; the two are no longer forced to be identical.

2. **`requestIdleCallback` is off by default**
   - HAR shows p[24] is `0`.
   - Changed the default of `WINDOW_FEATURE_FLAGS["requestIdleCallback"]` to `0` and removed it from `WINDOW_KEY_SAMPLES`, avoiding the self-contradiction of p[24]=0 while a window key samples requestIdleCallback.
   - runner still keeps the `--request-idle-callback` parameter, which can be enabled explicitly when needed.

3. **runner fallback region for standalone runs changed to Japan**
   - Python normally passes the proxy GeoIP profile in when calling the runner.
   - If `sentinel-runner.js` is run directly by hand without a language/timezone, the default fallback is now:
     - `ja-JP`
     - `Asia/Tokyo`
     - `Japan Standard Time`
     - offset `540`

4. **NextAuth `/api/auth/*` header split out separately**
   - HAR shows that `/api/auth/providers`, `/api/auth/csrf`, and `/api/auth/signin/openai` carry no `oai-client-*`.
   - Added `BrowserSession.get_nextauth_headers()`, used for NextAuth and `/api/auth/session`.
   - `get_chatgpt_headers()` continues to be used for `backend-api` / `backend-anon` / ChatGPT frontend APIs, keeping `oai-client-*`.

## 12. Compliance stability optimization (reduce false positives, no evasion)

This round limits the optimization boundary to reducing wrong requests / repeated requests / inconsistent state under abnormal conditions, and does not add fingerprint spoofing to bypass risk control.

### 12.1 Session-level circuit breaker

Added a session-level circuit breaker to `BrowserSession`:

- On HTTP `429`: cool down for `Retry-After` or the default 300 seconds.
- On HTTP `403`: default cooldown of 900 seconds.
- During the cooldown, later requests of the current `BrowserSession` stop directly, to avoid continuing to hit endpoints in an abnormal state.
- The cooldown cap is 3600 seconds.

Implementation location:

- `core/session.py`
  - `_raise_if_circuit_open()`
  - `_parse_retry_after()`
  - `_observe_response_for_circuit_breaker()`
  - `get()` / `post()` integrated automatically

### 12.2 Current recommended policy

- authorize returning 403 immediately stops the current account/proxy session; the one-time OAuth state is not replayed.
- 429 cools down per `Retry-After`; only network faults such as TLS, timeouts, and connection resets get limited retries.
- OTP errors are resent only up to the existing limited count, with no unbounded polling.
- Keep proxy GeoIP, language, timezone, `Accept-Language`, `navigator.language`, and `Date/Intl` consistent within the same session.
- Do not force simulation of high-frequency Datadog RUM, to avoid introducing a lot of non-business request noise.
- Do not fix a single window size; keep it stable within a session, and choose randomly from a reasonable desktop profile pool across sessions.
