"""
fix_db.py  –  Safe one-time migration script
Run: python fix_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_data.db")


def get_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return [row[1] for row in cursor.fetchall()]


def add_column_if_missing(cursor, table, column, col_type, default=None):
    cols = get_columns(cursor, table)
    if column not in cols:
        default_clause = f" DEFAULT '{default}'" if default is not None else ""
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}")
        print(f"[{table}] ✅ Added '{column}' column.")
    else:
        print(f"[{table}] ℹ️  '{column}' already exists, skipping.")


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ── Fix `scans` table ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            url        TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            prediction TEXT DEFAULT 'unknown',
            confidence REAL NOT NULL,
            timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    add_column_if_missing(cur, "scans", "username",    "TEXT")
    add_column_if_missing(cur, "scans", "prediction",  "TEXT", default="unknown")
    add_column_if_missing(cur, "scans", "confidence",  "REAL")
    add_column_if_missing(cur, "scans", "timestamp",   "DATETIME")

    # ── Fix `users` table ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active     INTEGER DEFAULT 1,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    add_column_if_missing(cur, "users", "email",         "TEXT")
    add_column_if_missing(cur, "users", "password_hash", "TEXT")
    add_column_if_missing(cur, "users", "is_active",     "INTEGER", default=1)
    add_column_if_missing(cur, "users", "created_at",    "DATETIME")

    # ── Fix `login_history` table ─────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            ip_address   TEXT,
            user_agent   TEXT,
            success      INTEGER DEFAULT 1,
            logged_in_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Fix `predictions` table ───────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT,
            url         TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            confidence  REAL NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("\n✅ Database migration complete. You can now restart uvicorn.")


if __name__ == "__main__":
    main()