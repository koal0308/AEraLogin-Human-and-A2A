"""Static validation of the public AEra website.

No server, no browser: parses the public HTML pages and checks

* the global shell (header + footer) is identical on every page,
* metadata (title, description, canonical) exists,
* structure (one h1, no duplicate ids, main landmark),
* every internal link / asset resolves to a real file or route, and every
  in-page / cross-page #anchor exists,
* the developer CTAs point to documentation pages, not raw artefacts,
* trust is described as monitoring only (no enforcement claims),
* no secrets or credential material is published.
"""
from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sync_site_shell  # noqa: E402

PAGES = sync_site_shell.SHELL_PAGES

#: URL path -> file for page routes served by server.py (explicit @app.get routes).
ROUTE_FILES = {
    "/": "landing.html",
    "/landing": "landing.html",
    "/sdk-docs": "docs/sdk-documentation.html",
    "/security-concept.html": "security-concept.html",
    "/privacy-policy": "privacy-policy.html",
    "/dashboard": "dashboard.html",
    "/dashboard.html": "dashboard.html",
    "/user-dashboard": "user-dashboard.html",
    "/user-dashboard.html": "user-dashboard.html",
    "/logo.html": "logo.html",
    "/join-telegram": "join-telegram.html",
}

#: Dynamic routes that exist but are not files.
DYNAMIC_ROUTES = {"/.well-known/agent-card.json", "/api/a2a", "/join-discord"}

#: Dynamic route prefixes (path parameters). Each must appear verbatim in server.py.
DYNAMIC_PREFIXES = ("/api/gdpr/data/", "/api/gdpr/export/")

#: Paths served outside this application (reverse proxy), so they cannot be
#: verified from the repository. Kept deliberately short and explicit.
EXTERNALLY_SERVED = {"/example-oauth/"}

#: Static mounts in server.py: URL prefix -> directory.
MOUNTS = {"/docs/": "docs", "/examples/": "examples", "/sdk/": "sdk"}

#: Root-level files served by explicit routes.
ROOT_FILES = {"/favicon.png": "favicon.png", "/aera-chat.js": "aera-chat.js",
              "/aera-chat.css": "aera-chat.css"}


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.links: list[tuple[str, str]] = []  # (attr, value)
        self.h1 = 0
        self.main = 0
        self.title = ""
        self._in_title = False
        self.meta: dict[str, str] = {}
        self.canonical = ""
        self.anchors_text: list[tuple[str, str]] = []
        self._a_href: str | None = None
        self._a_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a and a["id"]:
            self.ids.append(a["id"])
        if tag == "h1":
            self.h1 += 1
        if tag == "main":
            self.main += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta" and a.get("name"):
            self.meta[a["name"]] = a.get("content") or ""
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href") or ""
        for attr in ("href", "src"):
            if a.get(attr):
                self.links.append((attr, a[attr]))
        if tag == "a":
            self._a_href = a.get("href")
            self._a_text = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "a" and self._a_href is not None:
            self.anchors_text.append((self._a_href, "".join(self._a_text).strip()))
            self._a_href = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._a_href is not None:
            self._a_text.append(data)


def _parse(rel: str) -> tuple[str, _Collector]:
    text = (ROOT / rel).read_text(encoding="utf-8")
    c = _Collector()
    c.feed(text)
    return text, c


def _file_for(path: str) -> Path | None:
    if path in ROUTE_FILES:
        return ROOT / ROUTE_FILES[path]
    if path in ROOT_FILES:
        return ROOT / ROOT_FILES[path]
    for prefix, directory in MOUNTS.items():
        if path.startswith(prefix):
            return ROOT / directory / path[len(prefix):]
    return None


def _ids_of(file: Path) -> set[str]:
    c = _Collector()
    c.feed(file.read_text(encoding="utf-8"))
    return set(c.ids)


# --------------------------------------------------------------------------- #
def test_dynamic_routes_exist_in_server():
    server = (ROOT / "server.py").read_text(encoding="utf-8")
    for prefix in DYNAMIC_PREFIXES:
        assert f'"{prefix}' in server, prefix
    assert '"/join-discord"' in server


def test_shell_is_in_sync():
    for rel in PAGES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert sync_site_shell.render(text) == text, f"{rel}: run tools/sync_site_shell.py"


@pytest.mark.parametrize("rel", PAGES)
def test_page_structure_and_metadata(rel):
    text, c = _parse(rel)
    assert c.h1 == 1, f"{rel}: expected exactly one <h1>, got {c.h1}"
    assert c.main == 1, f"{rel}: expected exactly one <main>"
    dupes = {i for i in c.ids if c.ids.count(i) > 1}
    assert not dupes, f"{rel}: duplicate ids {dupes}"
    assert c.title.strip().startswith("AEraLogIn - "), f"{rel}: title {c.title!r}"
    assert len(c.meta.get("description", "")) >= 40, f"{rel}: missing meta description"
    assert c.canonical.startswith("https://aeralogin.com/"), f"{rel}: missing canonical"
    assert "main-content" in c.ids, f"{rel}: skip-link target missing"
    assert text.count("/docs/assets/site-shell.css") == 1
    assert text.count("/docs/assets/site-shell.js") == 1
    # legacy per-page menus must be gone, otherwise two menus fight each other
    assert 'id="mobileMenu"' not in text and 'id="menuToggle"' not in text


@pytest.mark.parametrize("rel", PAGES)
def test_internal_links_resolve(rel):
    _text, c = _parse(rel)
    own_ids = set(c.ids)
    broken = []
    for attr, raw in c.links:
        if raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        parts = urlsplit(raw)
        if parts.scheme in ("http", "https"):
            if parts.netloc != "aeralogin.com":
                continue
        path, frag = parts.path, parts.fragment
        if not path:  # pure "#anchor"
            if frag and frag not in own_ids:
                broken.append(raw)
            continue
        if not path.startswith("/"):
            path = "/" + str((Path(rel).parent / path)).lstrip("./")
        if path in DYNAMIC_ROUTES or path in EXTERNALLY_SERVED:
            continue
        if path.startswith(DYNAMIC_PREFIXES):
            continue
        target = _file_for(path)
        if target is None or not target.is_file():
            broken.append(raw)
            continue
        if frag and target.suffix == ".html" and frag not in _ids_of(target):
            broken.append(raw)
    assert not broken, f"{rel}: broken internal links {broken}"


def test_developer_ctas_point_to_documentation_pages():
    _text, c = _parse("landing.html")
    wanted = {
        "Read the Agent API": "/docs/agent-api.html",
        "View the A2A Agent Card": "/docs/agent-card.html",
        "View SDK Documentation": "/sdk-docs",
        "Explore A2A": "/docs/a2a.html",
    }
    found = {t: h for h, t in c.anchors_text}
    for label, href in wanted.items():
        assert found.get(label) == href, f"{label!r} -> {found.get(label)!r}"
    for href, _t in c.anchors_text:
        assert not (href or "").endswith(".md"), f"landing links raw markdown: {href}"


# --------------------------------------------------------------------------- #
_NEGATION = re.compile(r"\b(not|never|no|does not|doesn't|cannot|isn't|without)\b", re.I)
_FORBIDDEN = [
    r"untrusted (agents|peers) are blocked",
    r"trust (grants|determines|decides) (permissions|authori[sz]ation|access)",
    r"trust[- ]based (access|authori[sz]ation) is (enabled|active|enforced)",
    r"trust enforcement (is )?(enabled|active)",
]


def _visible_text(rel: str) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8")
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))


@pytest.mark.parametrize("rel", PAGES)
def test_no_trust_enforcement_claims(rel):
    body = _visible_text(rel)
    for sentence in re.split(r"(?<=[.!?])\s", body):
        for pat in _FORBIDDEN:
            if re.search(pat, sentence, re.I) and not _NEGATION.search(sentence):
                pytest.fail(f"{rel}: overclaim: {sentence.strip()[:160]}")


def test_trust_is_described_as_monitoring_only():
    landing = _visible_text("landing.html")
    assert "Trust assessment: implemented / monitoring" in landing
    assert "Trust enforcement: not enabled" in landing
    a2a = _visible_text("docs/a2a.html")
    assert "Monitoring, not enforcement" in a2a
    assert "not change any access decision" in a2a


# --------------------------------------------------------------------------- #
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # real JWT
    re.compile(r"\baera_a2a_[A-Za-z0-9_-]{8,}"),  # real peer credential
    re.compile(r"\b0x[0-9a-fA-F]{64}\b"),  # raw 32-byte hex (private key sized)
    re.compile(r"(AGENT_JWT_SECRET|OAUTH_JWT_SECRET|TOKEN_SECRET)\s*=\s*\S{8,}"),
]


@pytest.mark.parametrize("rel", PAGES)
def test_no_secrets_published(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    for pat in _SECRET_PATTERNS:
        m = pat.search(text)
        assert m is None, f"{rel}: secret-like material {m.group(0)[:24]}…"


def test_no_env_values_published():
    env = ROOT / ".env"
    if not env.is_file():
        pytest.skip("no .env in this checkout")
    values = []
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            v = line.split("=", 1)[1].strip().strip('"').strip("'")
            # only long, secret-looking values; skip URLs / addresses that are public anyway
            if len(v) >= 20 and not v.startswith(("http", "0x")) and " " not in v:
                values.append(v)
    for rel in PAGES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for v in values:
            assert v not in text, f"{rel}: contains a value from .env"
