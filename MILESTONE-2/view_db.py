import sqlite3
import os

DB_FILE = "phishing_detection.db"

if not os.path.exists(DB_FILE):
    print("❌ Database not found!")
    exit()

print("📊 DATABASE CONTENTS")
print("=" * 50)

conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

# Users
print("\n👤 USERS:")
c.execute("SELECT * FROM users")
users = c.fetchall()
if users:
    for user in users:
        print(f"  ID: {user[0]}, Email: {user[1]}")
else:
    print("  No users yet")

# Predictions
print("\n🔍 PREDICTIONS:")
c.execute("SELECT * FROM predictions")
preds = c.fetchall()
if preds:
    for pred in preds:
        print(f"  ID: {pred[0]}, URL: {pred[1]}, Result: {pred[2]}")
else:
    print("  No predictions yet")

conn.close()
print("\n✅ Done!")
