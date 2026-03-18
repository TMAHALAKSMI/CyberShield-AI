"""
reset_db.py  —  Run from the Backend folder with uvicorn STOPPED.
Deletes phishing_data.db and recreates all tables cleanly.
"""

import sqlite3
import os
import sys

DB_PATH = "phishing_data.db"

# ── Safety check ──────────────────────────────────────────────────────────────
print("=" * 55)
print("  CyberShield DB Reset Tool")
print("=" * 55)
print(f"\n📁 Working directory : {os.getcwd()}")
print(f"🗄️  Target database   : {os.path.abspath(DB_PATH)}\n")

# ── Step 1: Delete existing DB ────────────────────────────────────────────────
if os.path.exists(DB_PATH):
    try:
        os.remove(DB_PATH)
        print(f"🗑️  Deleted  : {DB_PATH}")
    except PermissionError:
        print("❌ ERROR: The database file is still locked by another process.")
        print("   → Please STOP uvicorn (CTRL+C) and try again.")
        sys.exit(1)

    # Also remove SQLite WAL / SHM sidecar files if present
    for ext in ["-shm", "-wal"]:
        sidecar = DB_PATH + ext
        if os.path.exists(sidecar):
            os.remove(sidecar)
            print(f"🗑️  Deleted  : {sidecar}")
else:
    print(f"ℹ️  No existing DB found — creating fresh.")

# ── Step 2: Create fresh DB ───────────────────────────────────────────────────
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.executescript("""
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    username    TEXT     NOT NULL UNIQUE,
    email       TEXT     NOT NULL UNIQUE,
    password    TEXT     NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    username    TEXT,
    url         TEXT     NOT NULL,
    prediction  TEXT,
    is_phishing INTEGER,
    confidence  REAL,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);

CREATE TABLE IF NOT EXISTS predictions (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    username    TEXT,
    url         TEXT     NOT NULL,
    prediction  TEXT     NOT NULL,
    is_phishing INTEGER,
    confidence  REAL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);
""")

conn.commit()

# ── Step 3: Verify ────────────────────────────────────────────────────────────
print("\n✅ Tables created:\n")
for table in ["users", "scans", "predictions"]:
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    print(f"   📋 {table:15s} → {cols}")

conn.close()

print("\n" + "=" * 55)
print("  ✅ Database reset complete!")
print("=" * 55)
print("\n▶️  Now run:  uvicorn main:app --reload\n")