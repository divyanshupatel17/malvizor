import os
import sqlite3
import datetime

import config


def get_connection():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the analyses table if it doesn't exist.
    Also runs a safe migration to add columns if missing
    (handles old databases created before columns were added).
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Create table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename        TEXT NOT NULL,
            sha256          TEXT NOT NULL,
            file_size       INTEGER,
            file_type       TEXT,
            threat_score    INTEGER DEFAULT 0,
            classification  TEXT DEFAULT 'unknown',
            report_path     TEXT,
            timestamp       TEXT NOT NULL,
            is_guest        INTEGER DEFAULT 0
        )
    """)

    # Safe migrations: add columns if they don't exist
    for col_def in [
        "ALTER TABLE analyses ADD COLUMN file_type TEXT",
        "ALTER TABLE analyses ADD COLUMN is_guest INTEGER DEFAULT 0",
    ]:
        try:
            cursor.execute(col_def)
        except Exception:
            pass  # Column already exists — that's fine

    conn.commit()
    conn.close()


def save_analysis(report, guest=False):
    """
    Save an analysis result to the database.

    For guest=True the row is flagged with is_guest=1 so it can be
    cleaned up later (or simply excluded from the main history API).

    File type priority:
      1. static_analysis.file_type  (most reliable — from magic bytes)
      2. summary.file_type          (fallback)
      3. None                       (unknown)
    """
    conn   = get_connection()
    cursor = conn.cursor()

    summary        = report.get("summary", {})
    static_results = report.get("static_analysis", {})

    # ── Resolve file_type — prefer the raw static analysis value ──
    raw_ft      = static_results.get("file_type", "")
    summary_ft  = summary.get("file_type", "")

    def is_real(v):
        return bool(v) and str(v).strip().lower() not in ("", "unknown", "n/a", "none")

    if is_real(raw_ft):
        file_type = str(raw_ft).strip()
    elif is_real(summary_ft):
        file_type = str(summary_ft).strip()
    else:
        file_type = None   # store NULL so JS shows "—"

    cursor.execute("""
        INSERT INTO analyses
            (filename, sha256, file_size, file_type,
             threat_score, classification, report_path, timestamp, is_guest)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        summary.get("file_name",       "unknown"),
        summary.get("sha256",          ""),
        static_results.get("file_size", summary.get("file_size", 0)),
        file_type,
        summary.get("threat_score",    0),
        summary.get("classification",  "unknown"),
        report.get("report_path",      ""),
        summary.get("timestamp",       datetime.datetime.now().isoformat()),
        1 if guest else 0,
    ))

    analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return analysis_id


def get_all_analyses():
    """Return all non-guest analyses, newest first."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, sha256, file_size, file_type,
               threat_score, classification, report_path, timestamp
        FROM   analyses
        WHERE  is_guest = 0 OR is_guest IS NULL
        ORDER  BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_analysis(analysis_id):
    """Return a single analysis by ID, or None (works for guest rows too)."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, sha256, file_size, file_type,
               threat_score, classification, report_path, timestamp
        FROM   analyses
        WHERE  id = ?
    """, (analysis_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_analysis(analysis_id):
    """Delete a single analysis by ID."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()


def cleanup_guest_analyses(older_than_hours=24):
    """
    Optional: purge guest rows older than N hours.
    Call this from a scheduled task or on startup if desired.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=older_than_hours)).isoformat()
    cursor.execute("""
        DELETE FROM analyses
        WHERE is_guest = 1 AND timestamp < ?
    """, (cutoff,))
    conn.commit()
    conn.close()
