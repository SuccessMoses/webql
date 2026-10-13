#!/usr/bin/env python3
"""
End-to-end test for webql.

Spins up a local HTTP server serving a deliberately vulnerable JavaScript
app, runs webql.py against it, and asserts the resulting SQLite database
has the expected shape.

If webcrack and codeql are both on PATH, also runs webql_analyze.py
and asserts the findings table is populated.

Run from the project root with the venv active:

    python test_end_to_end.py -v
    # or
    python -m unittest test_end_to_end -v
"""

from __future__ import annotations

import http.server
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from functools import partial
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
WEBQL_CRAWL = REPO_ROOT / "webql.py"
WEBQL_ANALYZE = REPO_ROOT / "webql_analyze.py"


# --------------------------------------------------------------------------- #
# the vulnerable app
# --------------------------------------------------------------------------- #

VULN_INDEX_HTML = """\
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>vuln-app</title>
</head>
<body>
  <div id="output"></div>

  <!-- inline JS with a DOM XSS sink: location.hash -> innerHTML -->
  <script>
    var out = document.getElementById('output');
    out.innerHTML = decodeURIComponent(location.hash.slice(1));
  </script>

  <!-- external JS, discovered by the crawler via <script src> -->
  <script src="/app.js"></script>
</body>
</html>
"""

VULN_APP_JS = """\
// Reads ?name= from the URL and writes it into the DOM via innerHTML.
// Classic DOM-based XSS: source (location.search) -> sink (innerHTML).
function render(name) {
  document.getElementById('output').innerHTML = 'Hello, ' + name;
}

function run() {
  var params = new URLSearchParams(location.search);
  var name = params.get('name');
  if (name) {
    render(name);
  }
}

run();
"""


# --------------------------------------------------------------------------- #
# http server
# --------------------------------------------------------------------------- #

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler that doesn't spam stderr."""

    def log_message(self, format, *args):  # noqa: A002
        pass


def _start_server(directory: Path) -> socketserver.TCPServer:
    handler = partial(_QuietHandler, directory=str(directory))
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def _fetch_all(db_path: Path, sql: str, params=()) -> list:
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return list(conn.execute(sql, params))


def _fetch_one(db_path: Path, sql: str, params=()):
    rows = _fetch_all(db_path, sql, params)
    return rows[0] if rows else None


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #

class TestWebqlPipeline(unittest.TestCase):
    """Crawl a local vulnerable app, then (if possible) analyze it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="webql_e2e_")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.tmp_path = Path(cls.tmp.name)

        # 1. write the vulnerable app to a temp dir
        site_dir = cls.tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text(VULN_INDEX_HTML, encoding="utf-8")
        (site_dir / "app.js").write_text(VULN_APP_JS, encoding="utf-8")

        # 2. serve it on an ephemeral port
        cls.httpd = _start_server(site_dir)
        cls.addClassCleanup(cls.httpd.server_close)
        cls.addClassCleanup(cls.httpd.shutdown)
        cls.port = cls.httpd.server_address[1]
        cls.netloc = f"127.0.0.1:{cls.port}"
        cls.seed = f"http://{cls.netloc}/"
        cls.app_js_url = f"http://{cls.netloc}/app.js"

        # 3. where the DB will go
        cls.db = cls.tmp_path / "scan.db"

        # 4. run the crawler once; tests inspect the result
        cls.crawl = _run(
            [
                sys.executable, str(WEBQL_CRAWL),
                cls.seed,
                "-d", str(cls.db),
                "--webcrack",
                "--summary",
            ]
        )

    # ------------------------------------------------------------------ #
    # crawl assertions
    # ------------------------------------------------------------------ #

    def test_01_crawler_exit_code(self):
        self.assertEqual(
            self.crawl.returncode, 0,
            f"webql.py exited {self.crawl.returncode}\n"
            f"stdout:\n{self.crawl.stdout}\n"
            f"stderr:\n{self.crawl.stderr}",
        )

    def test_02_db_file_created(self):
        self.assertTrue(self.db.exists(), "scan.db was not created")

    def test_03_domain_row(self):
        rows = _fetch_all(self.db, "SELECT name, protocol FROM domains")
        self.assertEqual(len(rows), 1, f"expected 1 domain, got {len(rows)}")
        self.assertEqual(rows[0]["name"], self.netloc)
        self.assertEqual(rows[0]["protocol"], "http")

    def test_04_url_rows(self):
        rows = _fetch_all(
            self.db,
            "SELECT url, kind, fetched_ok, javascript_id FROM urls",
        )
        by_url = {r["url"]: r for r in rows}
        self.assertIn(self.seed, by_url, "seed URL missing")
        self.assertIn(self.app_js_url, by_url, "app.js URL missing")
        self.assertEqual(len(rows), 2, f"expected 2 urls, got {len(rows)}")

    def test_05_html_url_classified(self):
        row = _fetch_one(
            self.db,
            "SELECT kind, fetched_ok, javascript_id FROM urls WHERE url = ?",
            (self.seed,),
        )
        self.assertIsNotNone(row, "seed URL row missing")
        self.assertEqual(row["kind"], "html")
        self.assertEqual(row["fetched_ok"], 1)
        self.assertIsNotNone(
            row["javascript_id"],
            "HTML page's inline JS should be stored as a blob",
        )

    def test_06_js_url_classified(self):
        row = _fetch_one(
            self.db,
            "SELECT kind, fetched_ok, javascript_id FROM urls WHERE url = ?",
            (self.app_js_url,),
        )
        self.assertIsNotNone(row, "app.js row missing")
        self.assertEqual(row["kind"], "js")
        self.assertEqual(row["fetched_ok"], 1)
        self.assertIsNotNone(row["javascript_id"])

    def test_07_javascript_blobs_stored(self):
        rows = _fetch_all(
            self.db,
            "SELECT id, content, content_hash FROM javascript",
        )
        self.assertEqual(len(rows), 2,
                         f"expected 2 JS blobs, got {len(rows)}")
        hashes = {r["content_hash"] for r in rows}
        self.assertEqual(len(hashes), 2, "blobs should have distinct hashes")

    def test_08_inline_blob_contains_dom_sink(self):
        row = _fetch_one(
            self.db,
            "SELECT content FROM javascript WHERE content LIKE '%location.hash%'",
        )
        self.assertIsNotNone(row, "no blob with location.hash")
        self.assertIn("innerHTML", row["content"],
                      "inline HTML blob should contain the innerHTML sink")

    def test_09_app_js_blob_content(self):
        row = _fetch_one(
            self.db,
            "SELECT j.content FROM javascript j "
            "JOIN urls u ON u.javascript_id = j.id "
            "WHERE u.url = ?",
            (self.app_js_url,),
        )
        self.assertIsNotNone(row, "app.js blob missing")
        self.assertIn("URLSearchParams", row["content"])
        self.assertIn("innerHTML", row["content"])

    def test_10_script_src_edge(self):
        rows = _fetch_all(
            self.db,
            """
            SELECT r.kind, u_from.url AS src, u_to.url AS dst
              FROM url_references r
              JOIN urls u_from ON u_from.id = r.from_url_id
              JOIN urls u_to   ON u_to.id   = r.to_url_id
            """,
        )
        self.assertEqual(len(rows), 1, f"expected 1 edge, got {len(rows)}")
        e = rows[0]
        self.assertEqual(e["kind"], "script-src")
        self.assertEqual(e["src"], self.seed)
        self.assertEqual(e["dst"], self.app_js_url)

    def test_15_recrawl_is_idempotent(self):
        before_urls = _fetch_one(self.db, "SELECT COUNT(*) AS n FROM urls")["n"]
        before_js = _fetch_one(self.db, "SELECT COUNT(*) AS n FROM javascript")["n"]

        result = _run(
            [
                sys.executable, str(WEBQL_CRAWL),
                self.seed,
                "-d", str(self.db),
            ]
        )
        self.assertEqual(
            result.returncode, 0,
            f"second crawl failed:\n{result.stderr}",
        )

        after_urls = _fetch_one(self.db, "SELECT COUNT(*) AS n FROM urls")["n"]
        after_js = _fetch_one(self.db, "SELECT COUNT(*) AS n FROM javascript")["n"]
        self.assertEqual(before_urls, after_urls, "urls grew on re-crawl")
        self.assertEqual(before_js, after_js, "javascript grew on re-crawl")

    # ------------------------------------------------------------------ #
    # analyzer assertions (skipped if the external tools aren't installed)
    # ------------------------------------------------------------------ #

    def test_20_analyzer_runs(self):
        if not _has_binary("codeql"):
            self.skipTest("codeql not on PATH")
        if not _has_binary("webcrack"):
            self.skipTest("webcrack not on PATH")

        # The analyzer requires webcracked content. If webcrack failed on
        # every blob, skip rather than fail — that's an environment issue,
        # not a code issue.
        ready = _fetch_one(
            self.db,
            "SELECT COUNT(*) AS n FROM javascript "
            " WHERE webcracked_content IS NOT NULL "
            "   AND webcracked_content != ''",
        )
        if not ready or ready["n"] == 0:
            self.skipTest("no webcracked content — webcrack may have failed")

        result = _run(
            [
                sys.executable, str(WEBQL_ANALYZE),
                "-d", str(self.db),
                "-v",
                "--show-findings",
            ],
            timeout=900,
        )
        self.assertEqual(
            result.returncode, 0,
            f"webql_analyze.py exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}",
        )

        # Every blob should now be marked analyzed.
        unanalyzed = _fetch_one(
            self.db,
            "SELECT COUNT(*) AS n FROM javascript WHERE analyzed_at IS NULL",
        )
        self.assertEqual(
            unanalyzed["n"], 0,
            f"{unanalyzed['n']} blob(s) not marked analyzed",
        )

        # The findings table should exist and have rows.
        findings = _fetch_all(
            self.db,
            "SELECT rule_id, severity, message FROM findings",
        )
        self.assertGreater(
            len(findings), 0,
            "expected at least one finding from CodeQL",
        )

        # At least one XSS finding — this is the whole point of the app.
        xss = [
            f for f in findings
            if "xss" in (f["rule_id"] or "").lower()
        ]
        rule_ids = sorted({f["rule_id"] for f in findings})
        self.assertGreater(
            len(xss), 0,
            f"expected at least one XSS finding, got rule_ids: {rule_ids}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)