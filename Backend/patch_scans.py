"""
patch_scans.py  – run once to add missing 'prediction' column to scans table
Usage: python patch_scans.py
"""
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), "phishing_data.db")

conn = sqlite3.connect(DB)
cur  = conn.cursor()

# Check existing columns
cur.execute("PRAGMA table_info(scans)")
cols = [row[1] for row in cur.fetchall()]
print("Current scans columns:", cols)

if "prediction" not in cols:
    cur.execute("ALTER TABLE scans ADD COLUMN prediction TEXT DEFAULT 'unknown'")
    conn.commit()
    print("SUCCESS: 'prediction' column added.")
else:
    print("INFO: 'prediction' column already exists, nothing to do.")

conn.close()