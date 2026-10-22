# GPTMail email source design

## Goals

Integrate GPTMail (`https://mail.chatgpt.org.uk`) as a new email source for automatic registration. It must be able to generate temporary emails on demand, poll for new messages, and extract OpenAI six-digit verification codes; the Web config page exposes only the GPTMail API Key.

## Scope

- Add the email source identifier `gptmail`, which can be used alone or, within `EMAIL_SOURCE`, fall back in order together with the existing sources.
- Use the fixed public GPTMail service address; no Base URL, email prefix, or domain configuration is provided.
- Use `GET /api/generate-email` to generate a random email, `GET /api/emails?email=...` to query the inbox, and `GET /api/email/{id}` to fetch the body.
- Filter out old emails by the time after the mailbox was claimed, and use the existing project OTP extraction logic to obtain the six-digit code from the subject, plain text, or HTML body.
- Add a hidden field GPTMail API Key to the Email / OTP config group in the Web UI, saved to `GPTMAIL_API_KEY` in `.env` and hot reloaded at runtime.
- When `EMAIL_SOURCE` contains `gptmail` but the API Key is empty, no remote request is sent; the registration task returns the explicit error “please fill in the GPTMail API Key”.

## Non-goals

- Do not use the GPTMail public test key and do not automatically fall back to it.
- Do not manage or delete server-side GPTMail emails.
- Do not pre-import or persist GPTMail addresses in the local email pool; addresses are generated on the fly at runtime.
- Do not change the existing behavior of Outlook, generic API email, or Cloudflare domain email.

## Components and data flow

1. `config/email.py` defines the default empty value of `GPTMAIL_API_KEY` and overrides it from `.env`.
2. `core/gptmail_client.py` is responsible for validating the key, calling the GPTMail API, caching the email context of the current task, and polling for emails and extracting the OTP.
3. `core/email_provider.py` brings `gptmail` into source resolution, claiming, source identification, OTP waiting, and reclamation. GPTMail reclamation only clears the in-memory context, because server-side addresses need no local pool state.
4. `webui/config_editor.py` adds the API Key to the Email / OTP allowlist, marks it secret, and writes it to `.env`; the existing config page renders the field automatically.
5. `.env.example` and `README.md` explain how to configure `GPTMAIL_API_KEY` and how to add `gptmail` to `EMAIL_SOURCE`.

## API contract and error handling

Every request carries `X-API-Key` and a header accepting JSON; the client sets a timeout and converts network errors, HTTP errors, invalid JSON, and `success: false` uniformly into a `GPTMailError` that includes the operation context.

- Generate email: accept only a non-empty `data.email` in a successful response.
- Inbox: accept only the email array in `data`; the common `data.emails` structure is also tolerated.
- Email details: read fields such as subject, text, and HTML from `data` and hand them to the existing `extract_otp`.
- Polling: reuse the global `OTP_MAX_WAIT`, `OTP_POLL_INTERVAL`, and stable-window settings; accept only emails that arrived after the claim time, to avoid reading old verification codes.
- Missing key: fail immediately on the first claim, with error text that can be shown directly in Web task logs and to CLI users.

## Verification strategy

Add unit tests and observe them fail first, covering: source resolution, missing-key error, generate-email request, response errors, extracting the OTP only from emails received after the claim, and multi-source reclamation routing. HTTP calls are isolated with an injectable/mock session, while OTP extraction itself still goes through the real project utility function. After implementation, run the related tests and the full test command available in the project.
