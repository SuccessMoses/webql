#!/usr/bin/env python3
"""
webql — crawl JavaScript from URLs and store it in SQLite.

JavaScript is the first-class entity. Each URL is a *source* of JavaScript:

    kind='html'       the JS blob is the concatenation of inline <script> bodies
    kind='js'         the JS blob is the response body
    kind='json'       no JS blob (manifests are parsed for more URLs)
    kind='sourcemap'  no JS blob
    kind='redirect'   this URL redirected; content lives under the target
    kind='other'      no JS blob
    kind='unknown'    discovered but not yet fetched

Cross-URL relationships ("wikipedia.org uses google-analytics.js") live in
the url_references table, keyed on (from_url_id, to_url_id, kind).

Example queries
---------------
-- every URL that references a given JS file
SELECT u_from.url
  FROM url_references r
  JOIN urls u_from ON u_from.id = r.from_url_id
  JOIN urls u_to   ON u_to.id   = r.to_url_id
 WHERE u_to.url = 'https://googleadservices.com/analytics.js';

-- every JS blob reachable from a page (transitive)
WITH RECURSIVE reach(id) AS (
    SELECT id FROM urls WHERE url = 'https://wikipedia.org/'
    UNION
    SELECT r.to_url_id FROM url_references r
    JOIN reach x ON x.id = r.from_url_id
)
SELECT u.url, u.kind FROM urls u JOIN reach r ON r.id = u.id
 WHERE u.kind = 'js';

-- shared JS blobs across hosts (vendor-bundle detection)
SELECT j.content_hash, COUNT(DISTINCT u.domain_id) AS hosts
  FROM javascript j JOIN urls u ON u.javascript_id = j.id
 GROUP BY j.content_hash HAVING hosts > 1 ORDER BY hosts DESC;
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# =========================================================================== #
# schema
# =========================================================================== #

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS domains (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL UNIQUE,
    protocol TEXT
);

CREATE TABLE IF NOT EXISTS javascript (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    content            TEXT NOT NULL,
    content_hash       TEXT NOT NULL UNIQUE,
    webcracked_content TEXT,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS urls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL UNIQUE,
    domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL DEFAULT 'unknown',
    javascript_id INTEGER REFERENCES javascript(id) ON DELETE SET NULL,
    fetched_at    TEXT,
    fetched_ok    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS url_references (
    from_url_id INTEGER NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
    to_url_id   INTEGER NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    PRIMARY KEY (from_url_id, to_url_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain_id);
CREATE INDEX IF NOT EXISTS idx_urls_js     ON urls(javascript_id);
CREATE INDEX IF NOT EXISTS idx_urls_ok     ON urls(fetched_ok);
CREATE INDEX IF NOT EXISTS idx_refs_from   ON url_references(from_url_id);
CREATE INDEX IF NOT EXISTS idx_refs_to     ON url_references(to_url_id);
"""


# =========================================================================== #
# small helpers
# =========================================================================== #

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# =========================================================================== #
# database
# =========================================================================== #

class Database:
    """Thin wrapper around a SQLite connection."""

    def __init__(self, path):
        self.path = Path(path)
        parent = self.path.parent
        if parent and str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- #
    # domains
    # ---------------------------------------------------------------- #

    def get_or_create_domain(self, name: str, protocol: str) -> int:
        name = name.lower()
        self.conn.execute(
            "INSERT OR IGNORE INTO domains(name, protocol) VALUES (?, ?)",
            (name, protocol),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM domains WHERE name = ?", (name,)
        ).fetchone()
        return int(row["id"])

    # ---------------------------------------------------------------- #
    # javascript
    # ---------------------------------------------------------------- #

    def store_javascript(self, content: str, webcracked: Optional[str] = None) -> int:
        """Insert-or-get a JavaScript blob, deduped by content hash."""
        digest = hash_content(content)
        cur = self.conn.execute(
            """
            INSERT OR IGNORE INTO javascript
                (content, content_hash, webcracked_content, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (content, digest, webcracked, utcnow()),
        )
        self.conn.commit()
        if cur.rowcount and cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute(
            "SELECT id FROM javascript WHERE content_hash = ?", (digest,)
        ).fetchone()
        return int(row["id"])

    def get_javascript(self, js_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM javascript WHERE id = ?", (js_id,)
        ).fetchone()

    # ---------------------------------------------------------------- #
    # urls
    # ---------------------------------------------------------------- #

    def get_or_create_url(self, url: str, domain_id: int) -> int:
        """Ensure a URL row exists. New rows start kind='unknown', fetched_ok=0."""
        self.conn.execute(
            """
            INSERT OR IGNORE INTO urls(url, domain_id, kind, fetched_ok)
            VALUES (?, ?, 'unknown', 0)
            """,
            (url, domain_id),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM urls WHERE url = ?", (url,)
        ).fetchone()
        return int(row["id"])

    def mark_url_fetched(
        self, url_id: int, kind: str, javascript_id: Optional[int]
    ) -> None:
        self.conn.execute(
            """
            UPDATE urls
               SET kind = ?, javascript_id = ?, fetched_at = ?, fetched_ok = 1
             WHERE id = ?
            """,
            (kind, javascript_id, utcnow(), url_id),
        )
        self.conn.commit()

    def get_url_id(self, url: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM urls WHERE url = ?", (url,)
        ).fetchone()
        return int(row["id"]) if row else None

    # ---------------------------------------------------------------- #
    # references
    # ---------------------------------------------------------------- #

    def add_reference(self, from_id: int, to_id: int, kind: str) -> None:
        if from_id == to_id:
            return
        self.conn.execute(
            """
            INSERT OR IGNORE INTO url_references(from_url_id, to_url_id, kind)
            VALUES (?, ?, ?)
            """,
            (from_id, to_id, kind),
        )
        self.conn.commit()

    # ---------------------------------------------------------------- #
    # summary
    # ---------------------------------------------------------------- #

    def summary(self) -> dict:
        def one(sql: str, *params) -> int:
            return int(self.conn.execute(sql, params).fetchone()[0])
        return {
            "domains":     one("SELECT COUNT(*) FROM domains"),
            "urls":        one("SELECT COUNT(*) FROM urls"),
            "fetched_ok":  one("SELECT COUNT(*) FROM urls WHERE fetched_ok = 1"),
            "javascripts": one("SELECT COUNT(*) FROM javascript"),
            "references":  one("SELECT COUNT(*) FROM url_references"),
        }


# =========================================================================== #
# classification
# =========================================================================== #

class Resource:
    """The result of processing one fetched URL."""

    __slots__ = ("kind", "js_blob", "references")

    def __init__(self, kind: str, js_blob: Optional[str],
                 references: List[Tuple[str, str]]):
        self.kind = kind
        self.js_blob = js_blob
        self.references = references  # [(absolute_url, edge_kind), ...]


# Inline <script> types we do NOT fold into the page's JS blob.
INLINE_SKIP_TYPES = {
    "importmap",
    "application/json",
    "application/ld+json",
    "application/manifest+json",
    "text/template",
    "text/x-template",
    "text/html",
}

# JS-level URL discovery
RE_DYNAMIC_IMPORT = re.compile(
    r"""\bimport\s*\(\s*['"`]([^'"`\s]+)['"`]\s*\)"""
)
RE_SOURCE_MAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
RE_WEBPACK_CHUNK_E = re.compile(
    r"""__webpack_require__\.e\s*\(\s*['"`]([^'"`]+)['"`]\s*\)"""
)
RE_WEBPACK_CHUNK_T = re.compile(
    r"""__webpack_require__\.t\s*\(\s*['"`]([^'"`]+)['"`]\s*\)"""
)


def _looks_like_url(s: str) -> bool:
    return (
        s.startswith(("http://", "https://", "//", "/", "./", "../"))
        or s.endswith((".js", ".mjs", ".cjs", ".js.map", ".map"))
    )


def _scan_js_refs(source: str, base_url: str) -> List[Tuple[str, str]]:
    """Find URLs referenced from inside JavaScript source."""
    out: List[Tuple[str, str]] = []
    seen: set = set()

    def add(u: str, kind: str) -> None:
        key = (u, kind)
        if key not in seen:
            seen.add(key)
            out.append((u, kind))

    for m in RE_DYNAMIC_IMPORT.finditer(source):
        target = m.group(1)
        if _looks_like_url(target):
            add(urljoin(base_url, target), "dynamic-import")

    for m in RE_SOURCE_MAP.finditer(source):
        add(urljoin(base_url, m.group(1)), "sourcemap")

    for regex in (RE_WEBPACK_CHUNK_E, RE_WEBPACK_CHUNK_T):
        for m in regex.finditer(source):
            chunk = m.group(1)
            if chunk.endswith(".js"):
                add(urljoin(base_url, chunk), "webpack-chunk")
            else:
                add(urljoin(base_url, chunk + ".js"), "webpack-chunk")

    return out


def _parse_importmap(text: str, base_url: str,
                     out: List[Tuple[str, str]]) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return
    if not isinstance(data, dict):
        return
    imports = data.get("imports")
    if isinstance(imports, dict):
        for _spec, addr in imports.items():
            if isinstance(addr, str) and _looks_like_url(addr):
                out.append((urljoin(base_url, addr), "importmap"))
    scopes = data.get("scopes")
    if isinstance(scopes, dict):
        for _scope, mapping in scopes.items():
            if isinstance(mapping, dict):
                for _spec, addr in mapping.items():
                    if isinstance(addr, str) and _looks_like_url(addr):
                        out.append((urljoin(base_url, addr), "importmap"))


def classify_html(content: str, base_url: str) -> Resource:
    soup = BeautifulSoup(content, "html.parser")
    inline_parts: List[str] = []
    refs: List[Tuple[str, str]] = []

    for script in soup.find_all("script"):
        stype = (script.get("type") or "").strip().lower()
        src = script.get("src")

        if src:
            refs.append((urljoin(base_url, src), "script-src"))
            continue

        text = script.string if script.string is not None else script.get_text()

        if stype == "importmap":
            if text:
                _parse_importmap(text, base_url, refs)
            continue

        if stype in INLINE_SKIP_TYPES:
            continue

        if text and text.strip():
            inline_parts.append(text)

    # Concatenate inline scripts into a single JS blob for this page.
    js_blob = "\n\n".join(inline_parts) if inline_parts else None

    # Scan the concatenated inline code for URL references.
    if js_blob:
        for child_url, kind in _scan_js_refs(js_blob, base_url):
            refs.append((child_url, kind))

    return Resource(kind="html", js_blob=js_blob, references=refs)


def classify_js(content: str, base_url: str) -> Resource:
    refs = _scan_js_refs(content, base_url)
    return Resource(kind="js", js_blob=content, references=refs)


def _sourcemap_refs(data: dict, base_url: str) -> List[Tuple[str, str]]:
    refs: List[Tuple[str, str]] = []
    sources = data.get("sources")
    if isinstance(sources, list):
        for s in sources:
            if isinstance(s, str) and _looks_like_url(s):
                refs.append((urljoin(base_url, s), "sourcemap-source"))
    return refs


def classify_json(content: str, base_url: str) -> Resource:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return Resource(kind="json", js_blob=None, references=[])

    # Sourcemaps are also JSON.
    if (isinstance(data, dict)
            and "version" in data
            and "mappings" in data):
        return Resource(kind="sourcemap", js_blob=None,
                        references=_sourcemap_refs(data, base_url))

    refs: List[Tuple[str, str]] = []

    if isinstance(data, dict):
        # Next.js build manifest: {"pages": {"page": ["/chunk1.js", ...]}}
        pages = data.get("pages")
        if isinstance(pages, dict):
            for _page, files in pages.items():
                if isinstance(files, list):
                    for f in files:
                        if isinstance(f, str) and f.endswith(".js"):
                            refs.append((urljoin(base_url, f), "manifest"))

        # Remix: {"entry": {...}, "routes": {"route": {"imports": [...]}}}
        entry = data.get("entry")
        if isinstance(entry, dict):
            for _k, v in entry.items():
                if isinstance(v, str) and v.endswith(".js"):
                    refs.append((urljoin(base_url, v), "manifest"))

        routes = data.get("routes")
        if isinstance(routes, dict):
            for _route, rd in routes.items():
                if isinstance(rd, dict):
                    imports = rd.get("imports")
                    if isinstance(imports, list):
                        for imp in imports:
                            if isinstance(imp, str) and imp.endswith(".js"):
                                refs.append((urljoin(base_url, imp), "manifest"))

    return Resource(kind="json", js_blob=None, references=refs)


def classify(content: str, content_type: str, url: str) -> Resource:
    ct = (content_type or "").lower()
    path = urlparse(url).path.lower()

    if "html" in ct:
        return classify_html(content, url)
    if ("javascript" in ct or "ecmascript" in ct
            or path.endswith((".js", ".mjs", ".cjs"))):
        return classify_js(content, url)
    if path.endswith(".map") or "sourcemap" in ct:
        return classify_json(content, url)
    if "json" in ct or path.endswith(".json"):
        return classify_json(content, url)

    # Fallback sniffing
    stripped = content.lstrip()
    head = stripped[:400].lower()
    if head.startswith(("{", "[")):
        try:
            json.loads(content)
            return classify_json(content, url)
        except json.JSONDecodeError:
            pass
    if "<html" in head or "<!doctype" in head:
        return classify_html(content, url)

    return Resource(kind="other", js_blob=None, references=[])


# =========================================================================== #
# optional webcrack
# =========================================================================== #

def _run_webcrack(source: str) -> Optional[str]:
    """Run webcrack on a JS string. Returns stdout, or None on failure."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(source)
            tmp_path = f.name
        result = subprocess.run(
            ["webcrack", tmp_path],
            capture_output=True, text=True, timeout=180,
        )
    except FileNotFoundError:
        log("[webcrack] not installed; skipping")
        return None
    except subprocess.TimeoutExpired:
        log("[webcrack] timed out")
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if result.returncode != 0:
        if result.stderr.strip():
            log(f"[webcrack] {result.stderr.strip()}")
        return None
    return result.stdout


# =========================================================================== #
# crawler
# =========================================================================== #

def _is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    if not ct:
        return True
    return (
        ct.startswith("text/")
        or "json" in ct
        or "javascript" in ct
        or "ecmascript" in ct
        or "html" in ct
        or "xml" in ct
    )


class Crawler:
    def __init__(
        self,
        db: Database,
        timeout: float = 15.0,
        user_agent: Optional[str] = None,
        run_webcrack: bool = False,
        follow_refs: bool = True,
        verbose: bool = False,
    ):
        self.db = db
        self.timeout = timeout
        self.run_webcrack = run_webcrack
        self.follow_refs = follow_refs
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            user_agent or "webql/0.1 (+https://example.invalid)"
        )
        self.visited: set = set()

    # ---------------------------------------------------------------- #
    # public
    # ---------------------------------------------------------------- #

    def run(self, seeds: Iterable[str]) -> None:
        queue: deque = deque()
        for s in seeds:
            if s not in self.visited:
                queue.append(s)

        while queue:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                children = self._process(url)
            except Exception as e:  # noqa: BLE001
                log(f"[error] {url}: {e!r}")
                continue

            if self.follow_refs:
                for c in children:
                    if c not in self.visited:
                        queue.append(c)

    # ---------------------------------------------------------------- #
    # internals
    # ---------------------------------------------------------------- #

    def _process(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return []

        domain_id = self.db.get_or_create_domain(parsed.netloc, parsed.scheme)
        url_id = self.db.get_or_create_url(url, domain_id)

        if self.verbose:
            log(f"[fetch] {url}")

        try:
            resp = self.session.get(
                url, timeout=self.timeout, allow_redirects=True
            )
        except requests.RequestException as e:
            log(f"[fail] {url}: {e}")
            return []

        if not resp.ok:
            log(f"[http {resp.status_code}] {url}")
            return []

        # ---------------------------------------------------------------- #
        # redirect handling: content belongs to the *final* URL
        # ---------------------------------------------------------------- #
        if resp.url != url:
            fp = urlparse(resp.url)
            if fp.scheme in ("http", "https") and fp.netloc:
                final_domain_id = self.db.get_or_create_domain(
                    fp.netloc, fp.scheme
                )
                final_id = self.db.get_or_create_url(resp.url, final_domain_id)
                self.db.add_reference(url_id, final_id, "redirect")
                self.db.mark_url_fetched(url_id, kind="redirect",
                                         javascript_id=None)
                self.visited.add(resp.url)
                url_id = final_id
                if self.verbose:
                    log(f"  -> redirect: {resp.url}")

        # ---------------------------------------------------------------- #
        # non-textual: record and stop
        # ---------------------------------------------------------------- #
        ctype = resp.headers.get("Content-Type", "")
        if not _is_textual(ctype):
            if self.verbose:
                log(f"  -> skip non-textual ({ctype})")
            self.db.mark_url_fetched(url_id, kind="other", javascript_id=None)
            return []

        content = resp.text
        resource = classify(content, ctype, resp.url)

        # ---------------------------------------------------------------- #
        # store the JS blob (if any)
        # ---------------------------------------------------------------- #
        js_id: Optional[int] = None
        if resource.js_blob:
            webcracked: Optional[str] = None
            if self.run_webcrack and resource.kind in ("js", "html"):
                webcracked = _run_webcrack(resource.js_blob)
            js_id = self.db.store_javascript(resource.js_blob, webcracked)

        self.db.mark_url_fetched(url_id, kind=resource.kind,
                                 javascript_id=js_id)

        if self.verbose:
            js_bytes = len(resource.js_blob) if resource.js_blob else 0
            log(f"  -> kind={resource.kind} js_id={js_id} "
                f"js_bytes={js_bytes} refs={len(resource.references)}")

        # ---------------------------------------------------------------- #
        # store the edges and collect children
        # ---------------------------------------------------------------- #
        new_children: List[str] = []
        for child_url, edge_kind in resource.references:
            cp = urlparse(child_url)
            if cp.scheme not in ("http", "https") or not cp.netloc:
                continue
            child_domain_id = self.db.get_or_create_domain(
                cp.netloc, cp.scheme
            )
            child_id = self.db.get_or_create_url(child_url, child_domain_id)
            self.db.add_reference(url_id, child_id, edge_kind)
            new_children.append(child_url)

        return new_children


# =========================================================================== #
# CLI
# =========================================================================== #

def _read_seeds(args) -> List[str]:
    seeds: List[str] = []

    for a in args.seed_urls:
        if a.strip():
            seeds.append(a.strip())

    if args.url_file:
        try:
            for line in Path(args.url_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    seeds.append(line)
        except OSError as e:
            log(f"[url-file] {e}")

    if not seeds and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                seeds.append(line)

    out: List[str] = []
    for s in seeds:
        p = urlparse(s)
        if p.scheme in ("http", "https") and p.netloc:
            out.append(s)
        else:
            log(f"[skip] not an http(s) URL: {s}")
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webql",
        description="Crawl JavaScript from URLs and store it in SQLite.",
    )
    parser.add_argument("seed_urls", nargs="*",
                        help="URLs to start from (optional if stdin is piped)")
    parser.add_argument("-d", "--db", default="webql.db",
                        help="SQLite file (default: webql.db)")
    parser.add_argument("--url-file",
                        help="Read seed URLs from a file (one per line)")
    parser.add_argument("--no-crawl", action="store_true",
                        help="Only fetch the seeds; don't follow references")
    parser.add_argument("--webcrack", action="store_true",
                        help="Run webcrack on each JS blob (requires webcrack on PATH)")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="Per-request timeout in seconds (default: 15)")
    parser.add_argument("--user-agent", default=None,
                        help="Override the User-Agent header")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (per-fetch logs)")
    parser.add_argument("--summary", action="store_true",
                        help="Print DB counters at the end")
    args = parser.parse_args(argv)

    seeds = _read_seeds(args)
    if not seeds:
        parser.error(
            "no URLs provided "
            "(pass as args, use --url-file, or pipe on stdin)"
        )

    log(f"[webql] {len(seeds)} seed URL(s) → {args.db}")

    with Database(args.db) as db:
        crawler = Crawler(
            db,
            timeout=args.timeout,
            user_agent=args.user_agent,
            run_webcrack=args.webcrack,
            follow_refs=not args.no_crawl,
            verbose=args.verbose,
        )
        crawler.run(seeds)

        if args.summary:
            log("[webql] --- summary ---")
            for k, v in db.summary().items():
                log(f"  {k:12s} {v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())