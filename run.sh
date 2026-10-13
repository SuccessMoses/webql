#!/usr/bin/env bash
#
# dump.sh — inspect a webql SQLite database.
#
# Usage:
#   ./dump.sh [db] [--schema] [--urls] [--js] [--edges] [--findings] [--all]
#
# Default (no flags): print a short overview + all summary sections.
#
# Requires the `sqlite3` CLI:
#   sudo apt install sqlite3

set -euo pipefail

DB="${1:-webql.db}"
shift || true

if [[ ! -f "$DB" ]]; then
    echo "error: no such DB: $DB" >&2
    exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "error: sqlite3 CLI not found. Install with: sudo apt install sqlite3" >&2
    exit 1
fi

# Pretty output: headers + column alignment, no sqlite3 line noise.
SQL=(sqlite3 -header -column "$DB")

# -- default flags ------------------------------------------------------------
SHOW_SCHEMA=false
SHOW_URLS=false
SHOW_JS=false
SHOW_EDGES=false
SHOW_FINDINGS=false
SHOW_SUMMARY=false

if [[ $# -eq 0 ]]; then
    SHOW_SUMMARY=true
    SHOW_URLS=true
    SHOW_JS=true
    SHOW_EDGES=true
    SHOW_FINDINGS=true
fi

for arg in "$@"; do
    case "$arg" in
        --schema)   SHOW_SCHEMA=true ;;
        --urls)     SHOW_URLS=true ;;
        --js)       SHOW_JS=true ;;
        --edges)    SHOW_EDGES=true ;;
        --findings) SHOW_FINDINGS=true ;;
        --summary)  SHOW_SUMMARY=true ;;
        --all)
            SHOW_SCHEMA=true
            SHOW_URLS=true
            SHOW_JS=true
            SHOW_EDGES=true
            SHOW_FINDINGS=true
            SHOW_SUMMARY=true
            ;;
        *)
            echo "unknown flag: $arg" >&2
            exit 1
            ;;
    esac
done

hr() { printf '%s\n' "────────────────────────────────────────────────────────────────────"; }
h1() { hr; printf ' %s\n' "$1"; hr; }
h2() { printf '\n## %s\n\n' "$1"; }

# -- sections ----------------------------------------------------------------

if $SHOW_SUMMARY; then
    h1 "webql — $DB"

    h2 "counts"
    "${SQL[@]}" <<'SQL'
SELECT
    (SELECT COUNT(*) FROM domains)                          AS domains,
    (SELECT COUNT(*) FROM urls)                             AS urls,
    (SELECT COUNT(*) FROM urls WHERE fetched_ok = 0)        AS urls_pending,
    (SELECT COUNT(*) FROM javascript)                       AS javascripts,
    (SELECT COUNT(*) FROM javascript WHERE analyzed_at IS NULL
                                       OR analyzed_at = '') AS js_unanalyzed,
    (SELECT COUNT(*) FROM url_references)                   AS edges;
SQL

    h2 "findings by severity"
    # Only if the findings table exists — analyzer may not have run yet.
    if "${SQL[@]}" "SELECT name FROM sqlite_master WHERE type='table' AND name='findings';" \
        | grep -q findings; then
        "${SQL[@]}" <<'SQL'
SELECT severity, COUNT(*) AS n
  FROM findings
 GROUP BY severity
 ORDER BY CASE severity
              WHEN 'critical' THEN 0
              WHEN 'high'     THEN 1
              WHEN 'medium'   THEN 2
              WHEN 'low'      THEN 3
              ELSE 4
          END;
SQL
    else
        echo "(no findings table — run webql_analyze.py)"
    fi
fi

if $SHOW_SCHEMA; then
    h1 "schema"
    "${SQL[@]}" ".schema"
fi

if $SHOW_URLS; then
    h1 "urls"
    "${SQL[@]}" <<'SQL'
SELECT u.id,
       substr(u.url, 1, 70)         AS url,
       u.kind,
       u.fetched_ok,
       IFNULL(u.javascript_id, '')  AS js_id,
       substr(IFNULL(u.fetched_at, ''), 1, 19) AS fetched_at
  FROM urls u
 ORDER BY u.id;
SQL
fi

if $SHOW_JS; then
    h1 "javascript blobs"
    "${SQL[@]}" <<'SQL'
SELECT j.id,
       substr(j.content_hash, 1, 12)                 AS hash,
       length(j.content)                             AS bytes,
       CASE WHEN j.webcracked_content IS NULL
              OR j.webcracked_content = '' THEN ''
            ELSE length(j.webcracked_content)
       END                                           AS wc_bytes,
       IFNULL(substr(j.analyzed_at, 1, 19), '')      AS analyzed_at,
       CASE WHEN j.analysis_error IS NULL THEN ''
            ELSE substr(j.analysis_error, 1, 30)
       END                                           AS error,
       (SELECT COUNT(*) FROM urls u WHERE u.javascript_id = j.id) AS used_by
  FROM javascript j
 ORDER BY j.id;
SQL
fi

if $SHOW_EDGES; then
    h1 "url references"
    "${SQL[@]}" <<'SQL'
SELECT r.kind,
       substr(u_from.url, 1, 40) AS from_url,
       substr(u_to.url,   1, 40) AS to_url
  FROM url_references r
  JOIN urls u_from ON u_from.id = r.from_url_id
  JOIN urls u_to   ON u_to.id   = r.to_url_id
 ORDER BY r.kind, u_from.url, u_to.url;
SQL
fi

if $SHOW_FINDINGS; then
    h1 "findings"
    if "${SQL[@]}" "SELECT name FROM sqlite_master WHERE type='table' AND name='findings';" \
        | grep -q findings; then
        "${SQL[@]}" <<'SQL'
SELECT f.id,
       f.severity,
       substr(f.rule_id, 1, 28)        AS rule_id,
       substr(f.message, 1, 40)        AS message,
       f.start_line,
       substr(f.file_path, 1, 12)      AS file,
       f.javascript_id                 AS js_id
  FROM findings f
 ORDER BY CASE f.severity
              WHEN 'critical' THEN 0
              WHEN 'high'     THEN 1
              WHEN 'medium'   THEN 2
              WHEN 'low'      THEN 3
              ELSE 4
          END,
          f.rule_id, f.javascript_id, f.start_line;
SQL
    else
        echo "(no findings table — run webql_analyze.py)"
    fi
fi