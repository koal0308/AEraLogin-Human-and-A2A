"""Repository audit: which files WOULD be committed under .gitignore.

`git` is not required. The matcher implements the gitignore subset used by
this repository's .gitignore files (globs, `**`, leading `/` anchors,
trailing `/` for directories, `!` negation, nested .gitignore files).
When git is available, `git status --ignored` / `git check-ignore` is the
authority and this script cross-checks against it.

    ./venv/bin/python tools/repo_audit.py            # summary + forbidden check
    ./venv/bin/python tools/repo_audit.py --list     # print every candidate file

Exit code 1 if any file that must never be committed would be.
"""
from __future__ import annotations

import fnmatch
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _compile(pattern: str):
    """gitignore glob -> regex over a '/'-separated relative path."""
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    pat = pattern.lstrip("/")
    i, out = 0, ""
    while i < len(pat):
        if pat[i:i + 3] == "**/":
            out += "(?:.*/)?"
            i += 3
        elif pat[i:i + 2] == "**":
            out += ".*"
            i += 2
        elif pat[i] == "*":
            out += "[^/]*"
            i += 1
        elif pat[i] == "?":
            out += "[^/]"
            i += 1
        elif pat[i] == "[":
            j = pat.find("]", i)
            out += pat[i:j + 1] if j != -1 else re.escape(pat[i])
            i = (j + 1) if j != -1 else i + 1
        else:
            out += re.escape(pat[i])
            i += 1
    prefix = "^" if anchored else "^(?:.*/)?"
    return re.compile(prefix + out + "(?:/.*)?$")


class Rules:
    def __init__(self) -> None:
        self.rules: list[tuple[str, re.Pattern, bool, bool]] = []  # base, rx, neg, dir_only

    def add_file(self, gi: Path) -> None:
        base = gi.parent.relative_to(REPO).as_posix()
        base = "" if base == "." else base + "/"
        for raw in gi.read_text(encoding="utf-8").splitlines():
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            if neg:
                line = line[1:]
            dir_only = line.endswith("/")
            self.rules.append((base, _compile(line.rstrip("/")), neg, dir_only))

    def ignored(self, rel: str, is_dir: bool) -> bool:
        result = False
        for base, rx, neg, dir_only in self.rules:
            if base and not rel.startswith(base):
                continue
            sub = rel[len(base):]
            if dir_only and not is_dir:
                # a dir-only rule still ignores files inside that dir
                parts = sub.split("/")[:-1]
                if not any(rx.match("/".join(parts[:k + 1])) for k in range(len(parts))):
                    continue
            elif not rx.match(sub):
                continue
            result = not neg
        return result


def candidate_files() -> list[str]:
    rules = Rules()
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        d = Path(dirpath)
        if (d / ".gitignore").is_file():
            rules.add_file(d / ".gitignore")
        rel_dir = d.relative_to(REPO).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(n for n in dirnames
                             if n != ".git" and not rules.ignored(rel_dir + n, True))
        for f in sorted(filenames):
            rel = rel_dir + f
            if not rules.ignored(rel, False):
                out.append(rel)
    return out


# Files that must NEVER be committed, whatever the .gitignore says.
FORBIDDEN = [
    (re.compile(r"(^|/)\.env($|\.(?!example$))"), "environment / secrets file"),
    (re.compile(r"\.(db|sqlite3?)($|-wal$|-shm$|\.)"), "database"),
    (re.compile(r"(^|/)aera\.db"), "database copy"),
    (re.compile(r"\.log$"), "log file"),
    (re.compile(r"\.pid$"), "pid file"),
    (re.compile(r"(^|/)agent_key(\.|$)|\.identity\.json$|_private_key\.bin$"), "agent runtime key/identity"),
    (re.compile(r"\.(pem|key|p12|pfx)$"), "private key material"),
    (re.compile(r"(^|/)(venv|venv_new|node_modules|__pycache__|\.pytest_cache)/"), "environment/cache"),
    (re.compile(r"\.backup-|\.old-|\.bak$"), "local backup copy"),
]


def main() -> int:
    files = candidate_files()
    if "--list" in sys.argv:
        print("\n".join(files))
    bad = [(f, why) for f in files for rx, why in FORBIDDEN if rx.search(f)]
    for f, why in bad:
        print(f"FORBIDDEN  {f}  ({why})")
    size = sum((REPO / f).stat().st_size for f in files)
    print(f"candidate files: {len(files)}  total size: {size / 1e6:.1f} MB")
    print(f"forbidden files that would be committed: {len(bad)}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
