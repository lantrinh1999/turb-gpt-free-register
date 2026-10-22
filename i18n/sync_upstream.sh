#!/usr/bin/env bash
# Sync this English fork with the Chinese upstream and re-translate what changed.
#
#   i18n/sync_upstream.sh            start (or resume) a sync
#   i18n/sync_upstream.sh status     show how far behind upstream the fork is
#   i18n/sync_upstream.sh abort      throw away an unfinished sync
#
# How it works (details in docs/UPSTREAM_SYNC.md):
#   1. fetch upstream, start a merge that records upstream as a parent but keeps our tree
#   2. replace the working tree with upstream's tree (so there are never merge conflicts)
#   3. restore the fork-only files (i18n/, docs/UPSTREAM_SYNC.md)
#   4. re-apply the dictionary (i18n/apply.py apply); new Chinese segments that are not in the
#      dictionary yet are written to i18n/pending.json and the script stops so they can be translated
#   5. run the checks, commit the merge
set -euo pipefail

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
FORK_REMOTE="${FORK_REMOTE:-origin}"
# Paths that exist only in the fork and must survive the tree replacement.
FORK_ONLY=(i18n docs/UPSTREAM_SYNC.md)

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; else PY=python3; fi
fi
GIT_DIR_PATH="$(git rev-parse --git-dir)"
merging() { [[ -f "$GIT_DIR_PATH/MERGE_HEAD" ]]; }
say() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cmd_status() {
  git fetch "$UPSTREAM_REMOTE" --quiet
  local behind
  behind="$(git rev-list --count "HEAD..$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")"
  echo "upstream commits not yet in this fork: $behind"
  if [[ "$behind" != "0" ]]; then
    git log --oneline "HEAD..$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" | head -30
  fi
}

cmd_abort() {
  merging || die "no sync in progress"
  git merge --abort
  echo "sync aborted"
}

finish() {
  say "Re-applying the translation dictionary"
  if ! "$PY" i18n/apply.py status; then
    "$PY" i18n/apply.py extract i18n/pending.json || true
    cat <<EOF

New or changed Chinese text has no translation yet. They are listed in i18n/pending.json.
Translate them (see "Translating new text" in docs/UPSTREAM_SYNC.md), e.g.

    $PY i18n/apply.py show <changed files...> 400      # numbered list
    # write "ID<TAB>English" lines to a file, then
    $PY i18n/apply.py merge-tsv that_file.tsv

then run this script again: i18n/sync_upstream.sh
EOF
    exit 1
  fi
  "$PY" i18n/apply.py apply

  shopt -s nullglob
  for patch in i18n/patches/*.patch; do
    say "Applying fork patch $patch"
    git apply --whitespace=nowarn "$patch" || die "patch $patch no longer applies; fix it and re-run"
  done

  say "Checks"
  "$PY" i18n/apply.py residual | tail -1 || true
  "$PY" -m compileall -q -x '(\.venv|node_modules)' . >/dev/null
  if command -v node >/dev/null 2>&1; then
    for f in sentinel/*.js; do node --check "$f"; done
  fi
  if [[ "${SKIP_TESTS:-0}" != "1" ]]; then
    "$PY" -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -5 || true
    echo "(compare with the known baseline in docs/UPSTREAM_SYNC.md)"
  fi

  say "Committing"
  git add -A
  local sha
  sha="$(git rev-parse --short "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")"
  git commit -q -m "Sync upstream $UPSTREAM_REMOTE/$UPSTREAM_BRANCH @ $sha and re-apply English translation"
  echo "Done. Review with 'git show --stat', restart the WebUI, then: git push $FORK_REMOTE HEAD"
}

cmd_start() {
  if merging; then
    say "Resuming the sync that is in progress"
    finish
    return
  fi
  [[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "working tree has uncommitted changes; commit or stash first"

  say "Fetching $UPSTREAM_REMOTE"
  git fetch "$UPSTREAM_REMOTE"
  if git merge-base --is-ancestor "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" HEAD; then
    echo "Already up to date with $UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
    return
  fi

  say "Merging $UPSTREAM_REMOTE/$UPSTREAM_BRANCH (history only, tree replaced below)"
  git merge --no-commit --no-ff -s ours "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" >/dev/null
  git read-tree --reset -u "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  for path in "${FORK_ONLY[@]}"; do
    git checkout HEAD -- "$path"
  done
  git status --short | head -40
  finish
}

case "${1:-start}" in
  start) cmd_start ;;
  status) cmd_status ;;
  abort) cmd_abort ;;
  *) die "usage: $0 [start|status|abort]" ;;
esac
