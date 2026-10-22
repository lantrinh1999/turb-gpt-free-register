#!/usr/bin/env python3
"""Dictionary-driven Chinese -> English translation of the repository.

Why this exists: the project is a fork of an upstream that is written in Chinese.
Hand-editing every file would turn every upstream sync into a wall of merge
conflicts. Instead the translation is a reproducible artifact: a dictionary of
Chinese segments (i18n/zh_en.json) that this script applies to the tracked text
files. After merging upstream, re-run it and only NEW segments need translating.

A "segment" is a maximal span that starts and ends with a CJK character and does
not cross a quote (' " `), a newline, or an angle bracket (< >). Spans may contain
ASCII text, placeholders ({x}, %s, ${x}) and spaces.

Commands (run from anywhere):
  apply.py status             report segments missing from the dictionary (exit 1 if any)
  apply.py extract [FILE]     write missing segments with context to FILE (default i18n/pending.json)
  apply.py merge FILE...      merge {segment: english} files into zh_en.json
  apply.py apply              rewrite tracked files in place using the dictionary
  apply.py show FILE... [N]     list up to N missing segments of FILE with numeric ids (authoring aid)
  apply.py merge-tsv FILE...  merge "ID<TAB>english" lines from the last `show`; "=KEEP=" keeps the Chinese
  apply.py residual           list remaining CJK lines (excluding i18n/keep.json entries)

Files:
  i18n/zh_en.json    {segment: english}               global dictionary
  i18n/overrides.json {path: {segment: english}}      per-file dictionary override
  i18n/protected.json ["term"]                        Chinese terms (runtime file names) a translation may keep verbatim
  i18n/keep.json     [{"file": glob, "segment": s, "line": regex}]   segments that MUST stay Chinese
                                                      (functional strings, runtime file names).
                                                      "file" may be a glob; "segment" may be "*"; optional "line" regex limits it to matching source lines.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "i18n"
DICT_PATH = I18N / "zh_en.json"
OVERRIDES_PATH = I18N / "overrides.json"
KEEP_PATH = I18N / "keep.json"
PROTECTED_PATH = I18N / "protected.json"

TEXT_SUFFIXES = {".py", ".md", ".html", ".js", ".cjs", ".txt", ".sh", ".example", ".gitignore", ".css", ".yml", ".yaml"}
# Never touched: the translation tooling itself and large data captures.
SKIP_PREFIXES = ("i18n/",)

CJK = r"\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\u3000-\u303f\uff00-\uffef"
SEGMENT_RE = re.compile(rf"[{CJK}](?:[^'\"`\n<>]*[{CJK}])?")
# Prose (comments, docstrings, markdown): a segment may cross quotes, backticks and tags.
PROSE_RE = re.compile(rf"[{CJK}](?:[^\n]*[{CJK}])?")
ANY_CJK_RE = re.compile(rf"[{CJK}]")
PROSE_SUFFIXES = {".md", ".txt"}
TRIPLE_RE = re.compile(r'"""|\'\'\'')
COMMENT_START_RE = re.compile(r"(?:(?<=^)|(?<=\s))(?:#|//|/\*|<!--)|^\s*\*")
# In code (non-prose) context a value must not contain these unless the source segment does;
# otherwise it could break out of the string/markup it is placed in. Checked by `apply`.
FORBIDDEN_VALUE_CHARS = set("'\"`<>\n")


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=isinstance(data, dict)) + "\n", encoding="utf-8")


def tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode("utf-8")
    files = []
    for rel in out.split("\0"):
        if not rel or rel.startswith(SKIP_PREFIXES):
            continue
        p = Path(rel)
        if p.suffix.lower() in TEXT_SUFFIXES or p.name.endswith(".gitignore") or p.name == ".gitignore":
            if (ROOT / rel).is_file():
                files.append(rel)
    return files


def kept(keep: list[dict], rel: str, segment: str, line: str = "") -> bool:
    """True when this occurrence must stay Chinese.

    Entry keys: "file" (glob, default "*"), "segment" (exact text or "*", default "*"),
    "line" (optional regex that must match the source line).
    """
    for entry in keep:
        if not fnmatch.fnmatch(rel, entry.get("file", "*")):
            continue
        if entry.get("segment", "*") not in ("*", segment):
            continue
        pattern = entry.get("line")
        if pattern and not re.search(pattern, line):
            continue
        return True
    return False


def spaced(line: str, start: int, end: int, val: str) -> str:
    """Insert a space where the English value would otherwise touch adjacent ASCII text
    (e.g. '[Roxy' + 'registration]' or '5' + 'items'); Chinese needs no such spaces."""
    if val and start > 0 and (line[start - 1].isalnum() or line[start - 1] in ")]}%") and val[0].isalnum() and val[0].isascii():
        val = " " + val
    if val and end < len(line) and (line[end].isalnum() or line[end] in "([{") and val[-1].isalnum() and val[-1].isascii() and line[end].isascii():
        val = val + " "
    return val


def adapt_to_context(rel: str, line: str, start: int, key: str, val: str) -> str | None:
    """Make an English value safe inside the string literal / markup it replaces into (code context only).

    * the quote character that delimits the surrounding literal is swapped for the other quote
      ("resend" inside "..." becomes 'resend'); backticks and a literal containing both are rejected;
    * '<' is rejected inside HTML files (it would open a tag); '>' and '&' are harmless in text.
    """
    if rel.endswith((".html", ".htm")) and "<" in val and "<" not in key:
        return None
    unescaped = lambda q: len(re.findall(rf"(?<!\\){q}", line[:start]))  # noqa: E731
    for q, other in (('"', "'"), ("'", '"')):
        if q in val and q not in key and unescaped(q) % 2 == 1:
            if other in val or unescaped(other) % 2 == 1 and other in line[:start]:
                if other in val:
                    return None
            val = val.replace(q, other)
    if "`" in val and "`" not in key and unescaped("`") % 2 == 1:
        return None
    return val


def lookup(zh_en: dict, overrides: dict, rel: str, segment: str):
    per_file = overrides.get(rel)
    if per_file and segment in per_file:
        return per_file[segment]
    return zh_en.get(segment)


def prose_starts(rel: str, lines: list[str]) -> list[int]:
    """Per line: index from which text counts as prose (comment/docstring/markdown), or -1."""
    if Path(rel).suffix.lower() in PROSE_SUFFIXES:
        return [0] * len(lines)
    is_py = rel.endswith(".py")
    out: list[int] = []
    in_triple = False
    for line in lines:
        start = -1
        if is_py:
            triples = list(TRIPLE_RE.finditer(line))
            if in_triple:
                start = 0
            elif len(triples) % 2 == 1:
                start = triples[-1].start()
            if len(triples) % 2 == 1:
                in_triple = not in_triple
        if start == -1:
            for m in COMMENT_START_RE.finditer(line):
                before = line[: m.start()]
                if before.count('"') % 2 == 0 and before.count("'") % 2 == 0 and before.count("`") % 2 == 0:
                    if m.group(0).strip() == "//" and before.endswith(":"):
                        continue
                    start = m.start()
                    break
        out.append(start)
    return out


class Span:
    __slots__ = ("start", "end", "text", "prose")

    def __init__(self, start: int, end: int, text: str, prose: bool = False):
        self.start, self.end, self.text, self.prose = start, end, text, prose

    def group(self, _: int = 0) -> str:
        return self.text


def find_spans(line: str, prose_start: int) -> list[Span]:
    spans: list[Span] = []
    code = line if prose_start < 0 else line[:prose_start]
    for m in SEGMENT_RE.finditer(code):
        spans.append(Span(m.start(), m.end(), m.group(0), False))
    if prose_start >= 0:
        for m in PROSE_RE.finditer(line, prose_start):
            spans.append(Span(m.start(), m.end(), m.group(0), True))
    return spans


def read_lines(rel: str) -> list[str]:
    with (ROOT / rel).open(encoding="utf-8", newline="") as fh:
        return fh.read().split("\n")


def iter_segments(rel: str):
    lines = read_lines(rel)
    for lineno, (line, ps) in enumerate(zip(lines, prose_starts(rel, lines)), 1):
        for span in find_spans(line, ps):
            yield lineno, line, span


def validate_value(segment: str, value: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "empty translation"
    stripped = value
    for term in load_json(PROTECTED_PATH, []):
        stripped = stripped.replace(term, "")
    if ANY_CJK_RE.search(stripped):
        return "translation still contains CJK"
    for token in re.findall(r"\{[^{}]*\}|%[-+0-9.]*[sdrfx]|\$\{[^{}]*\}", segment):
        if token not in value:
            return f"placeholder {token!r} missing"
    return None


def cmd_status_or_extract(write_to: Path | None) -> int:
    zh_en = load_json(DICT_PATH, {})
    overrides = load_json(OVERRIDES_PATH, {})
    keep = load_json(KEEP_PATH, [])
    pending: dict[str, dict] = {}
    for rel in tracked_text_files():
        for lineno, line, m in iter_segments(rel):
            seg = m.group(0)
            if kept(keep, rel, seg, line) or lookup(zh_en, overrides, rel, seg) is not None:
                continue
            entry = pending.setdefault(seg, {"count": 0, "where": f"{rel}:{lineno}", "context": line.strip()[:200]})
            entry["count"] += 1
    if write_to is not None:
        save_json(write_to, pending)
    print(f"{len(pending)} segment(s) missing from the dictionary")
    if write_to is not None:
        print(f"written to {write_to}")
    return 1 if pending else 0


BATCH_PATH = Path(os.environ.get("I18N_BATCH", "/tmp/i18n_batch.json"))


def cmd_show(files: list[str], limit: int = 400) -> int:
    """List missing segments (deduped across FILES) with numeric ids (authoring aid)."""
    zh_en = load_json(DICT_PATH, {})
    overrides = load_json(OVERRIDES_PATH, {})
    keep = load_json(KEEP_PATH, [])
    seen: dict[str, tuple[str, int, str, str, str]] = {}
    for rel in files:
        for lineno, line, m in iter_segments(rel):
            seg = m.group(0)
            if kept(keep, rel, seg, line) or lookup(zh_en, overrides, rel, seg) is not None or seg in seen:
                continue
            pre, post = line[max(0, m.start - 25) : m.start], line[m.end : m.end + 25]
            seen[seg] = (rel, lineno, pre.lstrip(), post.rstrip(), line.strip())
    items = list(seen.items())[:limit]
    batch = {str(i): {"file": v[0], "segment": seg} for i, (seg, v) in enumerate(items, 1)}
    BATCH_PATH.write_text(json.dumps(batch, ensure_ascii=False), encoding="utf-8")
    last = ""
    for i, (seg, (rel, lineno, pre, post, line)) in enumerate(items, 1):
        if rel != last:
            print(f"## {rel}")
            last = rel
        # Show surrounding text for fragments (mid-line pieces next to ASCII/code).
        near = re.search(r"[A-Za-z0-9_.)\]/]\s{0,2}$", pre) or re.match(r"^\s{0,2}[A-Za-z0-9_.(\[/]", post)
        ctx = f"    <= L{lineno}: {pre}[[{seg[:20]}]]{post}" if near and len(seg) < 30 else (f"    <= L{lineno}: {line[:140]}" if len(seg) < 10 else "")
        print(f"{i}\t{seg}{ctx}")
    print(f"-- {len(items)} of {len(seen)} missing segment(s)")
    return 0


def cmd_merge_tsv(files: list[str]) -> int:
    """Merge 'ID<TAB>english' lines (ids from the last `show`). English '=KEEP=' keeps Chinese."""
    batch = load_json(BATCH_PATH, {})
    keep = load_json(KEEP_PATH, [])
    out: dict[str, str] = {}
    kept_n = 0
    for f in files:
        for raw in Path(f).read_text(encoding="utf-8").split("\n"):
            if not raw.strip():
                continue
            ident, _, val = raw.partition("\t")
            ident = ident.strip()
            if ident not in batch:
                print(f"UNKNOWN id {ident!r}")
                continue
            entry = batch[ident]
            if val.strip() == "=KEEP=":
                keep.append({"file": entry["file"], "segment": entry["segment"]})
                kept_n += 1
            else:
                out[entry["segment"]] = val
    tmp = Path("/tmp/i18n_merge.json")
    tmp.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    save_json_list(KEEP_PATH, keep)
    print(f"{kept_n} kept")
    return cmd_merge([str(tmp)])


def save_json_list(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def cmd_merge(files: list[str]) -> int:
    zh_en = load_json(DICT_PATH, {})
    errors = 0
    added = 0
    for f in files:
        for seg, val in load_json(Path(f), {}).items():
            if isinstance(val, dict):  # tolerate extract-format entries
                val = val.get("en", "")
            problem = validate_value(seg, val)
            if problem:
                print(f"REJECT {seg!r} -> {val!r}: {problem}")
                errors += 1
                continue
            if seg not in zh_en:
                added += 1
            zh_en[seg] = val
    save_json(DICT_PATH, zh_en)
    print(f"merged: {added} new, {len(zh_en)} total, {errors} rejected")
    return 1 if errors else 0


def cmd_apply() -> int:
    zh_en = load_json(DICT_PATH, {})
    overrides = load_json(OVERRIDES_PATH, {})
    keep = load_json(KEEP_PATH, [])
    changed_files = 0
    missing = 0
    for rel in tracked_text_files():
        lines = read_lines(rel)
        file_changed = False
        for i, (line, ps) in enumerate(zip(lines, prose_starts(rel, lines))):
            new = line
            for span in reversed(find_spans(line, ps)):
                if kept(keep, rel, span.text, line):
                    continue
                val = lookup(zh_en, overrides, rel, span.text)
                if val is None:
                    missing += 1
                    continue
                if not span.prose:
                    val = adapt_to_context(rel, line, span.start, span.text, val)
                    if val is None:
                        print(f"UNSAFE {rel}: {span.text!r} (value cannot be placed inside this string literal)")
                        missing += 1
                        continue
                new = new[: span.start] + spaced(line, span.start, span.end, val) + new[span.end :]
            if new != line:
                lines[i] = new
                file_changed = True
        if file_changed:
            with (ROOT / rel).open("w", encoding="utf-8", newline="") as fh:
                fh.write("\n".join(lines))
            changed_files += 1
    print(f"applied: {changed_files} file(s) rewritten, {missing} segment(s) still missing")
    return 1 if missing else 0


def cmd_residual() -> int:
    keep = load_json(KEEP_PATH, [])
    count = 0
    for rel in tracked_text_files():
        for lineno, line, m in iter_segments(rel):
            if kept(keep, rel, m.group(0), line):
                continue
            count += 1
            print(f"{rel}:{lineno}: {line.strip()[:160]}")
    print(f"{count} residual CJK segment(s)")
    return 1 if count else 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "status":
        return cmd_status_or_extract(None)
    if cmd == "extract":
        target = Path(argv[2]) if len(argv) > 2 else I18N / "pending.json"
        return cmd_status_or_extract(target)
    if cmd == "merge":
        return cmd_merge(argv[2:])
    if cmd == "apply":
        return cmd_apply()
    if cmd == "show":
        args = argv[2:]
        limit = int(args.pop()) if args and args[-1].isdigit() else 400
        return cmd_show(args, limit)
    if cmd == "merge-tsv":
        return cmd_merge_tsv(argv[2:])
    if cmd == "residual":
        return cmd_residual()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
