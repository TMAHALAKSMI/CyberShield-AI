import sqlite3
import hashlib
import pickle
import numpy as np
from datetime import datetime
from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import hashlib
import pickle
import numpy as np
from datetime import datetime
from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CyberShield AI - Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load your model (ensure model.pkl exists in the same directory)
try:
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)
except Exception:
    model = None

def init_db():
    conn = sqlite3.connect('phishing_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS predictions 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, url TEXT, 
                  is_phishing INTEGER, confidence REAL, timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.post("/signup")
async def signup(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    conn = sqlite3.connect('phishing_data.db')
    try:
        pw_hash = hashlib.sha256(p.encode()).hexdigest()
        conn.execute("INSERT INTO users VALUES (?, ?)", (u, pw_hash))
        conn.commit()
        return {"success": True}
    except:
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        conn.close()

@app.post("/login")
async def login(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    conn = sqlite3.connect('phishing_data.db')
    res = conn.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
    conn.close()
    if not res or res[0] != hashlib.sha256(p.encode()).hexdigest():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "username": u}

@app.post("/predict")
async def predict(data: dict = Body(...)):
    url, username = data.get("url"), data.get("username", "guest")
    # Simple logic for demo; replace with model.predict if model is loaded
    is_phish = 1 if "bad" in url.lower() else 0
    conf = 0.9988 if is_phish == 0 else 0.985
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect('phishing_data.db')
    conn.execute("INSERT INTO predictions (username, url, is_phishing, confidence, timestamp) VALUES (?,?,?,?,?)",
                 (username, url, is_phish, conf, ts))
    conn.commit()
    conn.close()
    return {"url": url, "is_phishing": bool(is_phish), "confidence": conf, "timestamp": ts}

@app.get("/history")
async def get_history(username: str = Query(None)):
    if not username: return []
    conn = sqlite3.connect('phishing_data.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT url, is_phishing, confidence, timestamp FROM predictions WHERE username=? ORDER BY id DESC", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

app = FastAPI(title="CyberShield AI - Integrated Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Model Loading logic
try:
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)
except Exception:
    model = None

def init_db():
    conn = sqlite3.connect('phishing_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS predictions 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, url TEXT, 
                  is_phishing INTEGER, confidence REAL, timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# --- AUTH ROUTES ---
@app.post("/signup")
async def signup(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    conn = sqlite3.connect('phishing_data.db')
    try:
        conn.execute("INSERT INTO users VALUES (?, ?)", (u, hash_password(p)))
        conn.commit()
        return {"success": True}
    except:
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        conn.close()

@app.post("/login")
async def login(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    conn = sqlite3.connect('phishing_data.db')
    res = conn.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
    conn.close()
    if not res or res[0] != hash_password(p):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "username": u}

# --- SCAN & HISTORY ROUTES ---
@app.post("/predict")
async def predict(data: dict = Body(...)):
    url, username = data.get("url"), data.get("username", "guest")
    # Feature extraction logic here...
    prediction = 1 if "bad" in url else 0 # Dummy logic
    confidence = 0.98
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect('phishing_data.db')
    conn.execute("INSERT INTO predictions (username, url, is_phishing, confidence, timestamp) VALUES (?,?,?,?,?)",
                 (username, url, prediction, confidence, ts))
    conn.commit()
    conn.close()
    return {"url": url, "is_phishing": bool(prediction), "confidence": confidence}

@app.get("/history")
async def get_history(username: str = Query(None)):
    if not username: return []
    conn = sqlite3.connect('phishing_data.db')
    conn.row_factory = sqlite3.Row
    # Match lowercase to avoid mismatch errors seen in your screenshot
    cursor = conn.execute("SELECT url, is_phishing, confidence, timestamp FROM predictions WHERE LOWER(username)=LOWER(?) ORDER BY id DESC", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)