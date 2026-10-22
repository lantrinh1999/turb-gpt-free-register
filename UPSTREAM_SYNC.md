# Update this fork from the upstream project (instructions for an AI agent)

**Task:** bring the newest code of the upstream project into this fork and keep the whole project in English.

* Upstream (Chinese): `https://github.com/myfanhua/turb-gpt-free-register` (git remote `upstream`, push disabled)
* This fork (English): `origin`, branch `main`
* The English text is **generated**: `i18n/zh_en.json` maps every Chinese text segment to English and `i18n/apply.py` rewrites the
  files with it. Never translate files by hand and never `git merge` upstream directly; use the script below, it cannot conflict.

## Run this

```bash
cd <repo root>
git status --short                  # must be clean; commit or stash first
i18n/sync_upstream.sh status        # how many upstream commits are new? (0 = nothing to do, stop)
i18n/sync_upstream.sh               # fetch upstream, replace the tree, re-apply the dictionary
```

The script ends in one of two ways:

1. **"Done."** The merge is committed. Go to *Verify*.
2. **"New or changed Chinese text has no translation yet."** Do *Translate the new text*, then run `i18n/sync_upstream.sh` again
   (it resumes the unfinished merge). Repeat until it prints "Done.". If you want to give up: `i18n/sync_upstream.sh abort`.

## Translate the new text

Missing segments are only the Chinese text that upstream added or changed.

```bash
python3 i18n/apply.py show <files that contain missing text...> 400    # numbered list: "ID<TAB>chinese  <= context"
```

(`python3 i18n/apply.py status` shows how many are missing; `python3 i18n/apply.py extract` writes them all, with file and line,
to `i18n/pending.json`; take the file names from there.)

Write a TSV file with exactly one line per ID: `ID<TAB>English` (use the Write tool, never `echo`), then:

```bash
python3 i18n/apply.py merge-tsv my.tsv      # validates, merges into i18n/zh_en.json (and i18n/keep.json)
```

Re-run `show` (it only lists what is still missing) until `python3 i18n/apply.py status` prints `0 segment(s) missing`.
If a batch has more than 400 items run `show` again after each merge. Large batches may be split across sub-agents if each one
uses its own `I18N_BATCH=/path/batch.json` for `show`/`merge-tsv`, but only one process may write `i18n/*.json` at a time.

### Rules for the English

* A *segment* is the span from the first to the last Chinese/Japanese character on a line. Only that span is replaced, so a fragment
  such as `[Roxy[[注册]] ...` shown with `pre[[segment]]post` context must read correctly between its neighbours. A space is inserted
  automatically where the English would otherwise touch an ASCII letter or digit.
* Keep placeholders exactly: `{name}`, `{x:.1f}`, `%s`, `%d`, `%.1f`, `${x}`, URLs, identifiers, numbers.
* No Chinese characters in the English (the only exception is `用于注册的邮箱`, a runtime file name, see `i18n/protected.json`).
* Inside code strings do not use `'`, `"`, backtick, `<` unless the Chinese segment contained them (the tool swaps the surrounding
  quote type when it can, otherwise it refuses). Write "do not", not "don't".
* Style: comments and logs in natural technical English, sentence case; UI buttons/labels/headers in short Title Case.
* The same Chinese text always gets the same English. For a short ambiguous word that needs a different meaning in one file, add
  `{"path/to/file": {"中文": "English"}}` to `i18n/overrides.json` instead of changing the global entry.
* Use glossary consistently: 注册 registration, 账号 account, 邮箱 email, 代理 proxy, 代理池 proxy pool, 套餐 plan, 查活 liveness check,
  废号/已废 dead/deactivated account, 补跑 rerun, 授权 authorization, 换绑 email change, 提链 link extraction, 巡检 inspection,
  接码 SMS code receiving, 指纹 fingerprint, 风控 risk control, 熔断 circuit breaker, 兜底 fallback, 预热 warm-up.

### Answer `=KEEP=` (leave the Chinese) when the text is *functional*

* keywords/button texts matched against third-party pages or API responses (`has-text('继续')`, error-word lists, OTP e-mail subjects,
  provider responses such as `余额不足`), including Japanese / Traditional Chinese variants in such lists;
* names of files/directories that exist on disk (`用于注册的邮箱.txt/.json`, `注册日志/`, `codex_导出状态.json`, `注册成功的...token.txt`);
* placeholder values users may type in Chinese (`无`, `空`, `未配置`).

Text that is only displayed or logged is translated. A message produced in one place and matched with `in` / `==` / a regex in another
is translated consistently as long as both Chinese segments are identical; when the matcher uses a *substring* of the producer's message
(e.g. matcher `熔断冷却`, producer `当前 BrowserSession 已熔断冷却（剩余 {remain}s）`), make sure the English substring appears in the English
message. Known pairs: `熔断冷却` ↔ `circuit breaker cooldown`; `手动停止` ↔ `manual stop`; SMS provider errors must keep `NO_BALANCE` / `NO_NUMBERS`.
The tests catch most of these (see *Verify*); for JS, compare the string literals used in `webui/templates/index.html` with the backend names
(config group names such as `基础配置`, icon rules `n.includes('...')` in `index.html`).

## Verify (all of it, before pushing)

```bash
python3 i18n/apply.py status                       # 0 segment(s) missing
python3 i18n/apply.py residual | tail -1           # only intentionally kept Chinese may remain
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -5
```

Baseline when the fork was created: 407 tests, **2 pre-existing failures** (also failing upstream):
`test_account_liveness...test_service_403_rotates_proxy_and_never_falls_back_direct_when_pool_exists` and
`test_remail_client...test_restore_context_requires_exact_email_match`. Any other failure is a translation regression, almost always a
test (or code) that matches a substring of a message that was translated differently. Fix it with an entry in `i18n/overrides.json`
(per file) or by making the two English strings share the substring, run `python3 i18n/apply.py apply`, and re-run the tests.

If upstream changed dependencies run `.venv/bin/python -m pip install -r requirements.txt`.
Then restart and smoke-test the WebUI: `./webui.sh restart`, `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5000/login` (expect 200).

## Push

```bash
git status --short                 # clean (the script already committed)
git push origin main
```

Never push to `upstream`. Do not commit `.env`, `logs/`, `run/`, `*.sqlite3` or other local data (they are git-ignored).

## Fork-only code changes

Files that also exist upstream are overwritten on every sync. If you must change one, save the change as a patch of the **English** tree
in `i18n/patches/NN-name.patch` (`git diff > i18n/patches/01-name.patch`); the script applies patches after the translation and stops if
one no longer applies. New fork-only files outside `i18n/` must be added to `FORK_ONLY` in `i18n/sync_upstream.sh`.

## Tooling reference

| Command | Purpose |
|---|---|
| `i18n/sync_upstream.sh [status\|abort]` | start/resume a sync, show how far behind, discard an unfinished sync |
| `python3 i18n/apply.py status` | count of segments missing from the dictionary (exit 1 if any) |
| `python3 i18n/apply.py extract [file]` | write the missing segments with file/line/context to JSON (default `i18n/pending.json`) |
| `python3 i18n/apply.py show FILE... [N]` | numbered list of the first N missing segments of those files (authoring aid) |
| `python3 i18n/apply.py merge-tsv FILE...` | merge `ID<TAB>English` answers; `=KEEP=` records a keep rule |
| `python3 i18n/apply.py apply` | rewrite the tracked text files from the dictionary (idempotent) |
| `python3 i18n/apply.py residual` | list Chinese text that is left |

Data files (all in `i18n/`): `zh_en.json` dictionary, `overrides.json` per-file entries, `keep.json` functional Chinese
(`{"file": glob, "segment": text|"*", "line": regex}`), `protected.json` terms allowed to stay inside English text.
