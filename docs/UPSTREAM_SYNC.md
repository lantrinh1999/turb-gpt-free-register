# Keeping this fork in sync with the upstream project

This repository is an English-language fork of
[myfanhua/turb-gpt-free-register](https://github.com/myfanhua/turb-gpt-free-register), whose source, comments,
UI text and docs are written in Chinese.

Translating the files by hand would make every upstream update a wall of merge conflicts. Instead the translation is
**generated**: a dictionary of Chinese text segments (`i18n/zh_en.json`) is applied to the tracked text files by
`i18n/apply.py`. After taking new upstream code you only translate the *new* Chinese segments, then re-apply.

```
upstream (Chinese)  ──fetch──►  upstream/main
                                   │  tree replaced, history merged (no conflicts)
fork main (English) ◄──────────────┘  + i18n/ (dictionary, tooling)  + apply dictionary
```

## One-time setup (already done in this clone)

```bash
git remote add upstream https://github.com/myfanhua/turb-gpt-free-register.git   # origin = your fork
git remote set-url --push upstream no_push                                      # never push to the original repo
```

## Updating from upstream (the normal workflow)

```bash
i18n/sync_upstream.sh status      # how many upstream commits are new?
i18n/sync_upstream.sh             # start the sync
```

The script:

1. fetches `upstream/main` and starts a merge that records it as a parent (so Git knows what you already have);
2. replaces the working tree with upstream's tree, so **there are never merge conflicts**;
3. restores the fork-only files (`i18n/`, `docs/UPSTREAM_SYNC.md`);
4. applies the dictionary. If upstream added or changed Chinese text that is not translated yet it stops, writes the
   missing segments to `i18n/pending.json` and tells you what to do (next section);
5. applies `i18n/patches/*.patch` if you keep any fork-only code changes there, runs `compileall`, `node --check` and the
   unit tests, and commits the merge.

Then restart the WebUI and push:

```bash
./webui.sh restart
git push origin HEAD
```

If you want to abandon a half-finished sync: `i18n/sync_upstream.sh abort`.

### Translating new text

`i18n/pending.json` lists every untranslated segment with its file, line and context. Segments are numbered per
`show` run:

```bash
python3 i18n/apply.py show core/some_file.py webui/templates/index.html 400     # numbered list, 400 at a time
# create a TSV: one line per ID, "ID<TAB>English translation" ; use "=KEEP=" for text that must stay Chinese
python3 i18n/apply.py merge-tsv my_batch.tsv                                     # validates and merges
python3 i18n/sync_upstream.sh                                                    # resume
```

Easiest is to let Claude Code do it: *"Translate the missing segments of `python3 i18n/apply.py show <files> 400`
following docs/UPSTREAM_SYNC.md, write the TSV and run merge-tsv."* The rules it must follow are below.

Rules for translations (checked by `merge-tsv`):

* Keep placeholders exactly: `{name}`, `%s`, `%.1f`, `${x}` ...
* No Chinese characters in the English value (the only exception is the whitelisted `用于注册的邮箱` in `i18n/protected.json`).
* Inside code strings avoid `'`, `"`, backtick, `<`, `>` unless the Chinese segment had them (`apply` refuses unsafe replacements).
  Write "do not", not "don't".
* A *segment* is the span from the first to the last Chinese character on a line; it never crosses a newline, and in code it never
  crosses a quote. Only that span is replaced, so a fragment must read correctly between the text before and after it.
* The same segment always gets the same English everywhere. For ambiguous short words add a per-file entry in `i18n/overrides.json`.

### What must stay Chinese (`i18n/keep.json`)

Some Chinese text is *functional* and translating it would break the program:

* keywords matched against third-party pages or API responses (`has-text('继续')`, localized error words, OTP e-mail subjects,
  provider responses such as `余额不足`);
* on-disk names such as `用于注册的邮箱.txt/.json`, `注册日志/`, `codex_导出状态.json`;
* placeholder values users may type in Chinese (`无`, `空`, `未配置`).

`i18n/keep.json` holds `{"file": glob, "segment": text|"*", "line": regex}` rules for them.  When you translate and see such text,
answer `=KEEP=` in the TSV and the rule is recorded automatically.

Two pieces of code that must agree (a message produced in one place and matched with `in` in another) are translated
consistently as long as the Chinese segments are identical. Substring matches need a manual look; the known ones are:

* `熔断冷却` (matched in `core/account_export.py`, `core/openai_auth.py`) and the producer in `core/session.py` must both contain
  `circuit breaker cooldown`;
* `手动停止` (matched in `core/browser_use_registration.py`) and the producer in `core/registration_service.py` must both contain `manual stop`;
* the SMS provider errors in `core/sms_provider.py` must keep the tokens `NO_BALANCE` / `NO_NUMBERS` (matched in `core/roxy_codex_oauth.py`).

### Fork-only code changes

Anything you edit in files that also exist upstream is overwritten by the next sync. Keep such changes as patches against the
**English** tree in `i18n/patches/NN-name.patch` (create with `git diff > i18n/patches/01-name.patch`); the sync applies them
after the translation and stops if one no longer applies. Fork-only *new* files outside `i18n/` need to be added to
`FORK_ONLY` in `i18n/sync_upstream.sh`.

## Tooling reference

| Command | Purpose |
|---|---|
| `python3 i18n/apply.py status` | list segments missing from the dictionary (exit 1 if any) |
| `python3 i18n/apply.py extract [file]` | write the missing segments with context to JSON |
| `python3 i18n/apply.py show FILE... [N]` | numbered list of missing segments (authoring aid) |
| `python3 i18n/apply.py merge-tsv FILE...` | merge `ID<TAB>English` answers (`=KEEP=` to keep Chinese) |
| `python3 i18n/apply.py apply` | rewrite the tracked text files using the dictionary |
| `python3 i18n/apply.py residual` | list remaining Chinese text (should only be the kept items) |

`apply` is idempotent: running it again on already translated files changes nothing.

## Verifying a sync

```bash
python3 i18n/apply.py residual | tail -1                      # only intentionally kept Chinese remains
python3 -m unittest discover -s tests -p 'test_*.py'          # baseline: see below
./webui.sh restart && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5000/login
```

Baseline of the original project when this fork was created: 407 tests, 2 pre-existing failures
(`test_account_liveness...test_service_403_rotates_proxy_and_never_falls_back_direct_when_pool_exists`,
`test_remail_client...test_restore_context_requires_exact_email_match`). Any other failure after a sync is a regression of the
translation (most often a substring matched across two differently translated messages).
