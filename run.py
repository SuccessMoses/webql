#!/usr/bin/env python3
"""
webql_analyze — run CodeQL over every unscanned JavaScript blob in a webql DB.

Reads a DB produced by webql.py. On first run it adds an `analyzed_at`
column to the javascript table (NULL = unscanned) and creates a findings
table. Subsequent runs skip blobs where analyzed_at IS NOT NULL.

One blob per CodeQL run. Batching all blobs into a single source directory
causes CodeQL's JS extractor to load them all into memory and OOM on
anything but trivial sites.

Usage:
    python webql_analyze.py -d webql.db
    python webql_analyze.py -d webql.db --limit 20 -v
    python webql_analyze.py -d webql.db --force              # re-analyse everything
    python webql_analyze.py -d webql.db --show-findings

Requires `codeql` on PATH (or --codeql /path/to/codeql) with the
`codeql/javascript-queries` pack installed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Sequence

# =========================================================================== #
# schema bits this CLI owns
# =========================================================================== #

FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    javascript_id INTEGER NOT NULL REFERENCES javascript(id) ON DELETE CASCADE,
    rule_id       TEXT,
    severity      TEXT,
    message       TEXT,
    file_path     TEXT,
    start_line    INTEGER,
    end_line      INTEGER,
    analyzed_at   TEXT NOT NULL,
    UNIQUE (javascript_id, rule_id, file_path, start_line)
);

CREATE INDEX IF NOT EXISTS idx_findings_js       ON findings(javascript_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_QUERY_SUITE = "codeql/javascript-queries"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# =========================================================================== #
# database
# =========================================================================== #

class AnalyzerDB:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"no such DB: {self.path}")
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- #
    # setup / migration
    # ---------------------------------------------------------------- #

    def require_javascript_table(self) -> None:
        row = self.conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='javascript'"
        ).fetchone()
        if row is None:
            raise RuntimeError(
                "this DB has no `javascript` table — run webql.py first"
            )

    def ensure_findings_schema(self) -> None:
        self.conn.executescript(FINDINGS_SCHEMA)
        self.conn.commit()

    def ensure_analyzed_at_column(self) -> bool:
        """Add `analyzed_at` and `analysis_error` to javascript if missing.

        SQLite has no `ADD COLUMN IF NOT EXISTS`, and `CREATE TABLE IF NOT
        EXISTS` won't touch an existing table — so a schema edit upstream
        would silently be ignored here. We check PRAGMA table_info instead.
        Returns True if any column was added.
        """
        cols = {
            r["name"]
            for r in self.conn.execute("PRAGMA table_info(javascript)")
        }
        added = False
        if "analyzed_at" not in cols:
            self.conn.execute(
                "ALTER TABLE javascript ADD COLUMN analyzed_at TEXT"
            )
            added = True
        if "analysis_error" not in cols:
            self.conn.execute(
                "ALTER TABLE javascript ADD COLUMN analysis_error TEXT"
            )
            added = True
        if added:
            self.conn.commit()
        return added

    # ---------------------------------------------------------------- #
    # work queue
    # ---------------------------------------------------------------- #

    def count_total(self) -> int:
        return int(
            self.conn.execute("SELECT COUNT(*) FROM javascript").fetchone()[0]
        )

    def count_pending(self) -> int:
        return int(
            self.conn.execute(
                "SELECT COUNT(*) FROM javascript WHERE analyzed_at IS NULL"
            ).fetchone()[0]
        )

    def get_pending_blobs(
        self, limit: Optional[int] = None, force: bool = False
    ) -> List[sqlite3.Row]:
        """Blobs CodeQL has not yet looked at.

        This is the answer to "how do we know what's been scanned?" —
        `analyzed_at IS NULL`. It works for blobs with zero findings, and
        for blobs whose analysis crashed (they still get marked).
        """
        sql = (
            "SELECT id, content, webcracked_content, content_hash, "
            "       length(content) AS size "
            "  FROM javascript "
        )
        if not force:
            sql += " WHERE analyzed_at IS NULL "
        sql += " ORDER BY id "
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return list(self.conn.execute(sql))

    def mark_blob_analyzed(
        self, js_id: int, error: Optional[str] = None
    ) -> None:
        """Record that we ran CodeQL on this blob — success or failure.

        Marking on failure matters: without it, a blob whose analysis keeps
        crashing stays `analyzed_at IS NULL` and gets retried forever.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE javascript "
            "   SET analyzed_at = ?, analysis_error = ? "
            " WHERE id = ?",
            (now, error[:500] if error else None, js_id),
        )
        self.conn.commit()

    # ---------------------------------------------------------------- #
    # findings
    # ---------------------------------------------------------------- #

    def insert_finding(self, js_id: int, finding: dict) -> bool:
        from datetime import datetime, timezone
        cur = self.conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (javascript_id, rule_id, severity, message,
                 file_path, start_line, end_line, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                js_id,
                finding.get("rule_id"),
                finding.get("severity"),
                finding.get("message"),
                finding.get("file_path"),
                finding.get("start_line"),
                finding.get("end_line"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cur.rowcount > 0

    def commit(self) -> None:
        self.conn.commit()

    def print_findings(self) -> None:
        rows = list(
            self.conn.execute(
                """
                SELECT f.severity, f.rule_id, f.message, f.start_line,
                       f.javascript_id, j.content_hash
                  FROM findings f
                  JOIN javascript j ON j.id = f.javascript_id
                 ORDER BY CASE f.severity
                              WHEN 'critical' THEN 0
                              WHEN 'high'     THEN 1
                              WHEN 'medium'   THEN 2
                              WHEN 'low'      THEN 3
                              ELSE 4
                          END,
                          f.javascript_id, f.rule_id
                """
            )
        )
        if not rows:
            log("[webql-analyze] no findings in DB")
            return
        for r in rows:
            log(
                f"  [{r['severity']:<8}] js={r['javascript_id']:<5} "
                f"L{r['start_line'] or '?':<5} {r['rule_id']}: {r['message']}"
            )


# =========================================================================== #
# CodeQL driver
# =========================================================================== #

def _bucket_severity(raw) -> str:
    """Map SARIF security-severity to a bucket name."""
    if raw is None:
        return "info"
    try:
        score = float(raw)
    except (TypeError, ValueError):
        s = str(raw).strip().lower()
        return s if s in SEVERITIES else "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_sarif(sarif_path: Path) -> List[dict]:
    with sarif_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    runs = data.get("runs") or []
    if not runs:
        return []
    results = runs[0].get("results") or []
    out: List[dict] = []
    for r in results:
        locs = r.get("locations") or [{}]
        phys = locs[0].get("physicalLocation") or {}
        region = phys.get("region") or {}
        artifact = (phys.get("artifactLocation") or {}).get("uri") or "blob.js"
        out.append(
            {
                "rule_id": r.get("ruleId"),
                "severity": _bucket_severity(
                    (r.get("properties") or {}).get("security-severity")
                ),
                "message": (r.get("message") or {}).get("text") or "",
                "file_path": artifact,
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine"),
            }
        )
    return out


def analyze_blob(
    blob_text: str,
    work_dir: Path,
    codeql_cli: str,
    query_suite: str,
    timeout: float,
    verbose: bool,
) -> tuple[Optional[List[dict]], Optional[str]]:
    """Run CodeQL over one blob. Returns (findings, error)."""
    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "blob.js").write_text(blob_text, encoding="utf-8")

    db_path = work_dir / "codeql-db"
    sarif_path = work_dir / "results.sarif"

    # 1. create database
    create_cmd = [
        codeql_cli, "database", "create",
        "--quiet",
        "--language=javascript",
        "--source-root", str(src_dir),
        "--overwrite",
        str(db_path),
    ]
    if verbose:
        log(f"    $ {' '.join(create_cmd)}")
    try:
        r = subprocess.run(
            create_cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, "database create timed out"
    if r.returncode != 0:
        return None, f"database create failed: {r.stderr.strip()[:300]}"

    # 2. analyze
    analyze_cmd = [
        codeql_cli, "database", "analyze",
        "--quiet",
        str(db_path), query_suite,
        "--format=sarif-latest",
        f"--output={sarif_path}",
        "--rerun",
    ]
    if verbose:
        log(f"    $ {' '.join(analyze_cmd)}")
    try:
        r = subprocess.run(
            analyze_cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, "database analyze timed out"
    if r.returncode != 0:
        return None, f"database analyze failed: {r.stderr.strip()[:300]}"

    if not sarif_path.exists():
        return [], None

    try:
        return _parse_sarif(sarif_path), None
    except (json.JSONDecodeError, OSError) as e:
        return None, f"SARIF parse failed: {e}"


# =========================================================================== #
# main
# =========================================================================== #

def _pick_content(row: sqlite3.Row, use_webcracked: bool) -> str:
    """Choose which version of the blob to analyze.

    Webcracked output is un-minified and easier for CodeQL to reason about,
    but if it's absent, fall back to the original. Findings' line numbers
    refer to whichever version was used.
    """
    if use_webcracked and row["webcracked_content"]:
        return row["webcracked_content"]
    return row["content"] or ""


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webql_analyze",
        description="Run CodeQL over unscanned JavaScript blobs in a webql DB.",
    )
    parser.add_argument(
        "-d", "--db", required=True,
        help="webql SQLite file (produced by webql.py)",
    )
    parser.add_argument(
        "--codeql", default="codeql",
        help="Path to the codeql CLI (default: codeql)",
    )
    parser.add_argument(
        "--query-suite", default=DEFAULT_QUERY_SUITE,
        help=f"CodeQL query pack (default: {DEFAULT_QUERY_SUITE})",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Analyze at most N blobs this run",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-analyze every blob, ignoring analyzed_at",
    )
    parser.add_argument(
        "--webcracked", action="store_true",
        help="Analyze the webcracked version when available",
    )
    parser.add_argument(
        "--timeout", type=float, default=600.0,
        help="Per-blob CodeQL timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "--keep-staging", action="store_true",
        help="Keep temp dirs after each blob (for debugging)",
    )
    parser.add_argument(
        "--show-findings", action="store_true",
        help="Print every finding at the end",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print CodeQL commands and per-blob progress",
    )
    args = parser.parse_args(argv)

    try:
        db = AnalyzerDB(args.db)
    except FileNotFoundError as e:
        log(f"[webql-analyze] {e}")
        return 2

    with db:
        # 1. is the source table there?
        try:
            db.require_javascript_table()
        except RuntimeError as e:
            log(f"[webql-analyze] {e}")
            return 2

        # 2. migrations + findings table
        if db.ensure_analyzed_at_column():
            log("[webql-analyze] added analyzed_at / analysis_error to javascript")
        db.ensure_findings_schema()

        # 3. work to do?
        total = db.count_total()
        pending = db.count_pending()
        log(
            f"[webql-analyze] {total} blob(s) total, "
            f"{pending} unscanned"
        )
        if pending == 0 and not args.force:
            log("[webql-analyze] nothing to do "
                "(use --force to re-analyze everything)")
            if args.show_findings:
                db.print_findings()
            return 0

        blobs = db.get_pending_blobs(limit=args.limit, force=args.force)
        if not blobs:
            log("[webql-analyze] no blobs matched")
            return 0

        log(f"[webql-analyze] analysing {len(blobs)} blob(s) one at a time")

        # 4. main loop
        scanned = 0
        failed = 0
        total_findings = 0
        started = time.time()

        for i, row in enumerate(blobs, 1):
            js_id = row["id"]
            size = row["size"] or 0
            header = (
                f"[{i}/{len(blobs)}] js={js_id} "
                f"({size} bytes, hash={(row['content_hash'] or '')[:12]})"
            )
            log(header)

            content = _pick_content(row, args.webcracked)
            if not content.strip():
                if args.verbose:
                    log("    empty blob, skipping")
                db.mark_blob_analyzed(js_id)
                scanned += 1
                continue

            if args.keep_staging:
                work_dir = Path(
                    tempfile.mkdtemp(prefix=f"webql_cq_{js_id}_")
                )
                cleanup = False
            else:
                ctx = tempfile.TemporaryDirectory(
                    prefix=f"webql_cq_{js_id}_"
                )
                work_dir = Path(ctx.name)
                cleanup = True

            t0 = time.time()
            try:
                findings, err = analyze_blob(
                    content,
                    work_dir,
                    args.codeql,
                    args.query_suite,
                    args.timeout,
                    args.verbose,
                )
            finally:
                if cleanup:
                    ctx.cleanup()
                else:
                    log(f"    staging kept at {work_dir}")

            elapsed = time.time() - t0

            if err is not None:
                failed += 1
                log(f"    FAILED in {elapsed:.1f}s: {err}")
                # Mark as analyzed anyway so we don't loop forever.
                db.mark_blob_analyzed(js_id, error=err)
                continue

            inserted = 0
            for f in findings or []:
                if db.insert_finding(js_id, f):
                    inserted += 1
            db.commit()
            db.mark_blob_analyzed(js_id)

            scanned += 1
            total_findings += inserted
            if findings:
                log(f"    {inserted} finding(s) in {elapsed:.1f}s")
            elif args.verbose:
                log(f"    clean in {elapsed:.1f}s")

        # 5. summary
        wall = time.time() - started
        log("")
        log("[webql-analyze] --- summary ---")
        log(f"  blobs analysed : {scanned}")
        log(f"  blobs failed   : {failed}")
        log(f"  findings added : {total_findings}")
        log(f"  elapsed        : {wall:.1f}s")
        log(f"  still pending  : {db.count_pending()}")

        if args.show_findings:
            log("")
            log("[webql-analyze] --- findings ---")
            db.print_findings()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())