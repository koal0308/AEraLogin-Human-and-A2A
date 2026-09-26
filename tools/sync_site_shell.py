"""Sync the AEra global site shell (header + footer) into every public page.

The canonical markup lives in ``tools/site_shell/header.html`` and
``tools/site_shell/footer.html``. Each public page contains the marker pairs

    <!-- AERA:SHELL-HEADER --> ... <!-- /AERA:SHELL-HEADER -->
    <!-- AERA:SHELL-FOOTER --> ... <!-- /AERA:SHELL-FOOTER -->

and this tool replaces whatever is between them with the canonical partial.

Usage:
    ./venv/bin/python tools/sync_site_shell.py          # write
    ./venv/bin/python tools/sync_site_shell.py --check  # exit 1 if out of sync
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARTIALS = ROOT / "tools" / "site_shell"

#: Every public page that carries the global shell.
SHELL_PAGES = [
    "landing.html",
    "security-concept.html",
    "privacy-policy.html",
    "docs/sdk-documentation.html",
    "docs/agent-api.html",
    "docs/a2a.html",
    "docs/agent-card.html",
]

BLOCKS = {
    "HEADER": PARTIALS / "header.html",
    "FOOTER": PARTIALS / "footer.html",
}


def _pattern(name: str) -> re.Pattern[str]:
    return re.compile(
        r"[ \t]*<!-- AERA:SHELL-%s -->.*?<!-- /AERA:SHELL-%s -->[ \t]*\n?" % (name, name),
        re.S,
    )


def canonical(name: str) -> str:
    text = BLOCKS[name].read_text(encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def render(page_text: str) -> str:
    out = page_text
    for name in BLOCKS:
        pat = _pattern(name)
        found = pat.findall(out)
        if len(found) != 1:
            raise ValueError(f"expected exactly one AERA:SHELL-{name} block, found {len(found)}")
        block = canonical(name)
        out = pat.sub(lambda _m: block, out, count=1)
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for rel in SHELL_PAGES:
        path = ROOT / rel
        before = path.read_text(encoding="utf-8")
        after = render(before)
        if before != after:
            stale.append(rel)
            if not check:
                path.write_text(after, encoding="utf-8")
    if check and stale:
        print("out of sync:", ", ".join(stale))
        return 1
    print(("checked" if check else "synced"), len(SHELL_PAGES), "pages;",
          "changed:" if stale else "no changes", ", ".join(stale))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
