"""
main.py - FastAPI entry point
Run: uvicorn main:app --reload
"""

import sqlite3, os, pickle, json, hashlib
import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "phishing_data.db")
MODEL_PATH   = os.path.join(BASE_DIR, "saved_model.pkl")
SCALER_PATH  = os.path.join(BASE_DIR, "saved_scaler.pkl")
META_PATH    = os.path.join(BASE_DIR, "model_meta.json")
HISTORY_PATH = os.path.join(BASE_DIR, "training_history.json")

CLASS_NAMES = ["legitimate", "benign", "phish"]

# ── Global model objects ──────────────────────────────────────────────────────
MODEL  = None
SCALER = None
META   = {}

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="Phishing Detection API", version="3.0.0")

# ── CORS Middleware ───────────────────────────────────────────────────────────
# FIX: List every origin that should be allowed. Add your Vercel URL here.
# If you're still getting CORS errors, temporarily set allow_origins=["*"]
# to confirm CORS is the issue, then lock it down again.

ALLOWED_ORIGINS = [
    "https://frontend-tau-ten-85.vercel.app",   # ✅ Your production Vercel URL
    "https://*.vercel.app",                      # ✅ All Vercel preview deployments
    "http://localhost:5173",                     # ✅ Vite dev server
    "http://localhost:3000",                     # ✅ CRA dev server
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,   # Cache preflight response for 10 minutes
)


# ── Global Exception Handler (returns JSON, never HTML) ───────────────────────
# FIX: This is what caused your "Unexpected token '<'" error.
# Without this, unhandled errors return an HTML page instead of JSON,
# and your frontend crashes trying to parse the '<' of '<!DOCTYPE html>'.

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"},
    )

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=404,
        content={"detail": f"Route not found: {request.url.path}"},
    )


# ── DB helpers ────────────────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables():
    conn = get_conn()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT,
            url         TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            prediction  TEXT DEFAULT 'unknown',
            confidence  REAL NOT NULL,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("PRAGMA table_info(scans)")
    existing_cols = {row[1] for row in cur.fetchall()}
    for col, ddl in [
        ("username",   "TEXT"),
        ("prediction", "TEXT DEFAULT 'unknown'"),
        ("confidence", "REAL"),
        ("timestamp",  "DATETIME DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE scans ADD COLUMN {col} {ddl}")
            print(f"[db] added column scans.{col}")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT,
            password_hash TEXT NOT NULL,
            is_active     INTEGER DEFAULT 1,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            ip_address   TEXT,
            success      INTEGER DEFAULT 1,
            logged_in_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

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


ensure_tables()


# ── Load model ────────────────────────────────────────────────────────────────
def load_model_files():
    global MODEL, SCALER, META
    try:
        MODEL  = joblib.load(MODEL_PATH)
        SCALER = joblib.load(SCALER_PATH)
        if os.path.exists(META_PATH):
            with open(META_PATH, "r") as f:
                META = json.load(f)
        print(f"[startup] Model loaded. Features: {SCALER.n_features_in_}")
    except Exception as e:
        print(f"[startup] WARNING - model not loaded: {e}")
        print(f"[startup] Run: python train_model.py  to generate model files.")


@app.on_event("startup")
def startup_event():
    load_model_files()


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    username: str = "guest"

class SignupRequest(BaseModel):
    username: str
    password: str
    email: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class PredictRequest(BaseModel):
    features: List[float]

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[dict]] = []


# ── /scan ─────────────────────────────────────────────────────────────────────
@app.post("/scan")
def scan(req: ScanRequest):
    if MODEL is None or SCALER is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Run: python train_model.py")
    try:
        from train_model import extract_features, CLASS_NAMES as CN
        features        = extract_features(req.url)
        features_scaled = SCALER.transform(np.array(features, dtype=float).reshape(1, -1))
        proba           = MODEL.predict_proba(features_scaled)[0]
        pred_idx        = int(np.argmax(proba))
        confidence      = float(round(float(np.max(proba)), 4))
        prediction      = CN[pred_idx]
        is_phishing     = 1 if prediction == "phish" else 0
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO scans (username, url, is_phishing, prediction, confidence) VALUES (?, ?, ?, ?, ?)",
            (req.username, req.url, is_phishing, prediction, confidence),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "url":          req.url,
        "is_phishing":  bool(is_phishing),
        "prediction":   prediction,
        "confidence":   confidence,
        "probabilities": {CLASS_NAMES[i]: round(float(p), 4) for i, p in enumerate(proba)},
        "scanned_at":   __import__("datetime").datetime.utcnow().isoformat(),
    }


# ── /signup ───────────────────────────────────────────────────────────────────
@app.post("/signup")
def signup(req: SignupRequest):
    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    conn = get_conn()
    try:
        if conn.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone():
            raise HTTPException(status_code=400, detail="Username already taken")
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (req.username, req.email, pw_hash),
        )
        conn.commit()
        return {"message": "User created successfully", "username": req.username, "token": req.username}
    finally:
        conn.close()


# ── /auth/register (alias) ────────────────────────────────────────────────────
@app.post("/auth/register")
def auth_register(req: SignupRequest):
    return signup(req)


# ── /login ────────────────────────────────────────────────────────────────────
@app.post("/login")
def login(req: LoginRequest):
    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    conn = get_conn()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (req.username, pw_hash),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        conn.execute("INSERT INTO login_history (user_id, success) VALUES (?, 1)", (user["id"],))
        conn.commit()
        return {"message": "Login successful", "username": req.username, "id": user["id"], "token": req.username}
    finally:
        conn.close()


# ── /auth/login (alias) ───────────────────────────────────────────────────────
@app.post("/auth/login")
def auth_login(req: LoginRequest):
    return login(req)


# ── /auth/logout ──────────────────────────────────────────────────────────────
@app.post("/auth/logout")
def auth_logout():
    return {"message": "Logged out successfully"}


# ── /history (all scans) ──────────────────────────────────────────────────────
@app.get("/history")
def get_history_all(limit: int = 100):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, username, url, is_phishing, prediction, confidence, timestamp as scanned_at "
            "FROM scans ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── /history/{username} ───────────────────────────────────────────────────────
@app.get("/history/{username}")
def get_history_user(username: str, limit: int = 50):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, url, is_phishing, prediction, confidence, timestamp as scanned_at "
            "FROM scans WHERE username = ? ORDER BY timestamp DESC LIMIT ?",
            (username, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── /dashboard ────────────────────────────────────────────────────────────────
@app.get("/dashboard")
def dashboard():
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Run: python train_model.py")
    try:
        from train_model import get_metrics, get_training_history

        metrics = get_metrics(MODEL)
        history = get_training_history()

        model_info = {
            "name":         META.get("name", "XGBClassifier"),
            "version":      META.get("version", "1.0"),
            "status":       META.get("status", "ready"),
            "trained_at":   META.get("trained_at", "unknown"),
            "total_params": META.get("total_params", 150),
            "n_features":   SCALER.n_features_in_ if SCALER else 30,
        }

        return {
            "metrics":    metrics,
            "history":    history,
            "model_info": model_info,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dashboard error: {e}")


# ── /retrain ──────────────────────────────────────────────────────────────────
@app.post("/retrain")
def retrain():
    try:
        from train_model import train_model as _train
        _train()
        load_model_files()
        return {"message": "Model retrained successfully! Reload the dashboard to see updated metrics."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrain failed: {e}")


# ── /predict  (raw feature array) ────────────────────────────────────────────
@app.post("/predict")
def predict_features(req: PredictRequest):
    if MODEL is None or SCALER is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")
    try:
        X = np.array(req.features, dtype=float).reshape(1, -1)
        if X.shape[1] != SCALER.n_features_in_:
            raise ValueError(f"Expected {SCALER.n_features_in_} features, got {X.shape[1]}")
        Xs       = SCALER.transform(X)
        proba    = MODEL.predict_proba(Xs)[0]
        pred_idx = int(np.argmax(proba))
        return {
            "prediction":    CLASS_NAMES[pred_idx],
            "confidence":    round(float(np.max(proba)), 4),
            "probabilities": {CLASS_NAMES[i]: round(float(p), 4) for i, p in enumerate(proba)},
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── /chat ─────────────────────────────────────────────────────────────────────
@app.post("/chat")
def chat(req: ChatRequest):
    """Simple rule-based cybersecurity chatbot (no external API needed)."""
    msg = req.message.lower().strip()

    responses = {
        ("what is phishing", "phishing", "define phishing"):
            "Phishing is a cyberattack where criminals disguise themselves as trusted entities to steal credentials, financial data, or personal information — typically via deceptive URLs or emails.",
        ("how does cybershield work", "how does it work", "how does detection work"):
            "CyberShield extracts 30 lexical features from the URL (length, entropy, suspicious keywords, TLD, IP presence, etc.) and feeds them into a trained XGBoost model that classifies the URL as Legitimate, Benign, or Phishing.",
        ("what is xgboost", "xgboost"):
            "XGBoost (Extreme Gradient Boosting) is a high-performance ML algorithm that builds an ensemble of decision trees sequentially, each correcting the errors of the previous one. It's fast, accurate, and ideal for tabular data like URL features.",
        ("safe url", "how to stay safe", "tips", "protect"):
            "Stay safe online: 1) Always check the URL before clicking, 2) Look for HTTPS, 3) Beware of lookalike domains (g00gle.com), 4) Don't click links in unexpected emails, 5) Use CyberShield to scan suspicious URLs!",
        ("what is legitimate", "legitimate"):
            "A Legitimate URL belongs to a verified, trusted domain (e.g. google.com, github.com). These have clean structure, HTTPS, and no suspicious patterns.",
        ("what is benign", "benign"):
            "A Benign URL is generally safe but from an unverified or generic source. It has no phishing indicators but isn't a well-known trusted domain.",
        ("what is phish", "phishing url"):
            "A Phishing URL is malicious — it may mimic a trusted site, use suspicious TLDs (.tk, .ml), contain IP addresses, include auth keywords like 'login/verify/secure', or have high character entropy.",
        ("confidence", "what is confidence"):
            "Confidence is the model's certainty score (0–100%) for its prediction. A confidence of 99% means the model is highly certain. Lower confidence (e.g. 60%) means the URL has mixed signals.",
        ("features", "30 features", "what features"):
            "The 30 URL features include: URL length, domain length, path length, dot/slash/hyphen counts, presence of IP address, auth keywords (login, verify, bank), spam words, HTTPS flag, digit ratio, domain entropy, suspicious TLDs, subdomain depth, and more.",
        ("hello", "hi", "hey"):
            "Hello! I'm CyberShield AI Assistant 🛡️ Ask me about phishing detection, how the model works, or paste a URL to analyze on the Home page!",
        ("thank", "thanks"):
            "You're welcome! Stay safe online 🛡️",
    }

    for keys, reply in responses.items():
        if any(k in msg for k in keys):
            return {"reply": reply}

    return {"reply": f"I specialise in cybersecurity and phishing detection. You asked: '{req.message}'. Try asking: 'What is phishing?', 'How does CyberShield work?', or 'How to stay safe online?'"}


# ── /model-info ───────────────────────────────────────────────────────────────
@app.get("/model-info")
def model_info():
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {
        **META,
        "features_in": SCALER.n_features_in_ if SCALER else "unknown",
        "classes":     CLASS_NAMES,
    }


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "message": "Phishing Detection API running"}
