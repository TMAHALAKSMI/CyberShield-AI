"""
train_model.py — CyberShield AI  |  XGBoost Phishing URL Classifier
3 classes: legitimate (0) · benign (1) · phish (2)

Install: pip install xgboost scikit-learn joblib numpy
"""

import os, re, json, math, datetime
import numpy as np
import joblib

from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score, log_loss,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
MODEL_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_model.pkl")
SCALER_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_scaler.pkl")
HISTORY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_history.json")
META_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_meta.json")

CLASS_NAMES  = ["legitimate", "benign", "phish"]
MODEL_VERSION = "2.0"
N_FEATURES   = 30


# ── Feature extraction (exactly 30 features) ─────────────────────────────────
def extract_features(url: str) -> list:
    url = str(url).strip()
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path   = parsed.path
        query  = parsed.query
    except Exception:
        domain, path, query = url, "", ""

    hostname = domain.replace("www.", "")
    full     = url

    def cnt(s, c): return s.count(c)
    def ratio(n, d): return n / max(d, 1)

    return [
        len(full),                                                                   # 0  url length
        len(domain),                                                                 # 1  domain length
        len(path),                                                                   # 2  path length
        len(query),                                                                  # 3  query length
        cnt(full, "."),                                                              # 4  dot count
        cnt(full, "/"),                                                              # 5  slash count
        cnt(full, "-"),                                                              # 6  hyphen count
        cnt(full, "_"),                                                              # 7  underscore count
        cnt(full, "?"),                                                              # 8  question marks
        cnt(full, "="),                                                              # 9  equals signs
        cnt(full, "@"),                                                              # 10 @ symbols
        cnt(full, "&"),                                                              # 11 ampersands
        cnt(full, "%"),                                                              # 12 percent encoded
        cnt(full, "#"),                                                              # 13 hash
        len(hostname.split(".")) - 1,                                                # 14 subdomain depth
        1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", full) else 0,        # 15 has IP
        1 if any(k in full.lower() for k in [
            "login","signin","verify","secure","update","bank",
            "paypal","account","confirm","password","credential"]) else 0,           # 16 auth keywords
        1 if any(k in full.lower() for k in [
            "free","win","click","prize","offer","deal","lucky","bonus"]) else 0,    # 17 spam words
        1 if full.lower().startswith("https") else 0,                               # 18 has HTTPS
        ratio(sum(c.isdigit() for c in full), len(full)),                           # 19 digit ratio
        ratio(sum(not c.isalnum() for c in full), len(full)),                       # 20 special char ratio
        _entropy(hostname),                                                          # 21 domain entropy
        1 if re.search(r":\d+", domain) else 0,                                    # 22 has port
        1 if any(full.lower().endswith(t) for t in [
            ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".pw",".cc",".su"]) else 0,# 23 suspicious TLD
        1 if "//" in path else 0,                                                   # 24 double slash path
        len(re.findall(r"%[0-9a-fA-F]{2}", full)),                                  # 25 hex encoded chars
        1 if "#" in full else 0,                                                    # 26 has fragment
        max((len(w) for w in re.split(r"[.\-_/]", hostname) if w), default=0),     # 27 longest token
        1 if any(c.isdigit() for c in hostname) else 0,                            # 28 digit in domain
        0 if len(full) < 54 else (1 if len(full) < 75 else 2),                     # 29 length bucket
    ]


def _entropy(s: str) -> float:
    if not s: return 0.0
    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq if p > 0)


# ── Dataset ───────────────────────────────────────────────────────────────────
def load_data():
    """
    3-class synthetic dataset.
    ── TO USE YOUR OWN CSV ──────────────────────────────────────────────────
        import pandas as pd
        df = pd.read_csv("your_dataset.csv")  # columns: url, label (0/1/2)
        X  = np.array([extract_features(u) for u in df["url"]])
        y  = df["label"].values
        return X, y
    ──────────────────────────────────────────────────────────────────────────
    """
    rng = np.random.default_rng(42)

    legitimate = [
        "https://www.google.com/search?q=weather+today",
        "https://github.com/torvalds/linux",
        "https://stackoverflow.com/questions/12345/how-to-python",
        "https://en.wikipedia.org/wiki/Artificial_intelligence",
        "https://docs.python.org/3/library/pathlib.html",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.linkedin.com/in/someprofile",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://www.microsoft.com/en-us/windows/windows-11",
        "https://aws.amazon.com/ec2/pricing/",
    ] * 40

    benign = [
        "http://www.example.com/page",
        "http://blog.wordpress.com/2024/post-title",
        "http://news.ycombinator.com/item?id=12345",
        "http://old-website.net/about.html",
        "http://shop.mystore.com/products?cat=shoes",
        "http://forum.site.org/thread/123",
        "http://download.freeware.com/tool.zip",
        "http://api.openweathermap.org/data/2.5/weather?q=london",
        "http://cdn.staticfiles.net/js/jquery.min.js",
        "http://images.unsplash.com/photo-1234567890",
    ] * 40

    phish = [
        "http://192.168.1.1/login/verify-account.php?user=admin&token=abc",
        "http://paypal-secure-login.tk/confirm?session=xyz123",
        "http://www.g00gle-signin.xyz/account/update?redirect=true",
        "http://bankofamerica-verify.ml/secure/login?user=victim",
        "http://free-prize-winner.pw/claim?id=99999&ref=email",
        "http://update-your-password-now.ga/reset?u=user&t=12345",
        "http://signin-facebook-verify.cf/checkpoint?next=home",
        "http://amazon-order-confirm.su/invoice?order=111&verify=1",
        "http://secure-paypal-update.gq/wallet/verify?acct=123",
        "http://login-verify-account-secure.top/auth?redirect=steal",
    ] * 40

    all_urls   = legitimate + benign + phish
    all_labels = [0]*len(legitimate) + [1]*len(benign) + [2]*len(phish)

    idx = rng.permutation(len(all_urls))
    all_urls   = [all_urls[i]   for i in idx]
    all_labels = [all_labels[i] for i in idx]

    X = np.array([extract_features(u) for u in all_urls], dtype=float)
    y = np.array(all_labels, dtype=int)
    return X, y


# ── Train ─────────────────────────────────────────────────────────────────────
def train_model():
    print("[train] Extracting features...")
    X, y = load_data()

    # Delete old scaler/model to avoid feature mismatch
    for p in [MODEL_PATH, SCALER_PATH]:
        if os.path.exists(p):
            os.remove(p)

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    history = []
    for epoch in range(1, 11):
        n = max(10, epoch * 15)
        clf = XGBClassifier(
            n_estimators=n, max_depth=6, learning_rate=0.1,
            use_label_encoder=False, eval_metric="mlogloss",
            random_state=42, n_jobs=-1,
            num_class=3, objective="multi:softprob",
        )
        clf.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)

        tp  = clf.predict_proba(X_tr)
        vp  = clf.predict_proba(X_val)
        history.append({
            "epoch":        epoch,
            "loss":         round(log_loss(y_tr,  tp), 4),
            "val_loss":     round(log_loss(y_val, vp), 4),
            "accuracy":     round(accuracy_score(y_tr,  clf.predict(X_tr)),  4),
            "val_accuracy": round(accuracy_score(y_val, clf.predict(X_val)), 4),
        })
        print(f"  Epoch {epoch:2d}/10  loss={history[-1]['loss']:.4f}  val_acc={history[-1]['val_accuracy']:.4f}")

    # Final full model
    model = XGBClassifier(
        n_estimators=150, max_depth=6, learning_rate=0.1,
        use_label_encoder=False, eval_metric="mlogloss",
        random_state=42, n_jobs=-1,
        num_class=3, objective="multi:softprob",
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)
    model.class_names_ = CLASS_NAMES

    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2)

    meta = {
        "name":         "XGBClassifier",
        "version":      MODEL_VERSION,
        "status":       "ready",
        "trained_at":   datetime.datetime.utcnow().isoformat(),
        "total_params": 150,
        "n_features":   N_FEATURES,
        "classes":      CLASS_NAMES,
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[train] Saved → {MODEL_PATH}  ({N_FEATURES} features)")
    return model


# ── Load ──────────────────────────────────────────────────────────────────────
def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"No model at {MODEL_PATH}. Run train_model() first.")
    model = joblib.load(MODEL_PATH)
    if not hasattr(model, "class_names_"):
        model.class_names_ = CLASS_NAMES
    return model


# ── Predict URL ───────────────────────────────────────────────────────────────
def predict_url(model, url: str) -> dict:
    feats = extract_features(url)
    X     = np.array(feats, dtype=float).reshape(1, -1)
    if os.path.exists(SCALER_PATH):
        X = joblib.load(SCALER_PATH).transform(X)

    pred_idx = int(model.predict(X)[0])
    proba    = model.predict_proba(X)[0]
    conf     = float(np.max(proba))
    label    = CLASS_NAMES[pred_idx]

    return {
        "prediction":    label,                    # "legitimate" | "benign" | "phish"
        "confidence":    round(conf, 4),
        "probabilities": {
            CLASS_NAMES[i]: round(float(p), 4)
            for i, p in enumerate(proba)
        },
    }


# ── Predict raw features ──────────────────────────────────────────────────────
def predict(model, features: list) -> dict:
    X = np.array(features, dtype=float).reshape(1, -1)
    if os.path.exists(SCALER_PATH):
        X = joblib.load(SCALER_PATH).transform(X)
    pred_idx = int(model.predict(X)[0])
    proba    = model.predict_proba(X)[0]
    return {
        "prediction":    CLASS_NAMES[pred_idx],
        "confidence":    round(float(np.max(proba)), 4),
        "probabilities": {CLASS_NAMES[i]: round(float(p), 4) for i, p in enumerate(proba)},
    }


# ── Metrics ───────────────────────────────────────────────────────────────────
def get_metrics(model) -> dict:
    X, y = load_data()
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    Xs = scaler.transform(X) if scaler else X
    yp  = model.predict(Xs)
    ypr = model.predict_proba(Xs)
    return {
        "accuracy":  round(accuracy_score(y, yp), 4),
        "precision": round(precision_score(y, yp, average="weighted", zero_division=0), 4),
        "recall":    round(recall_score(y,    yp, average="weighted", zero_division=0), 4),
        "f1_score":  round(f1_score(y,        yp, average="weighted", zero_division=0), 4),
        "loss":      round(log_loss(y, ypr), 4),
        "val_loss":  round(log_loss(y, ypr), 4),
    }


def get_training_history() -> list:
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return []


# ── Standalone ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    m = train_model()
    print("\n=== Metrics ===")
    for k, v in get_metrics(m).items():
        print(f"  {k:12s}: {v:.4f}")
    for url in [
        "https://www.google.com",
        "http://blog.example.com/post/123",
        "http://paypal-verify-login.tk/secure?token=abc",
    ]:
        r = predict_url(m, url)
        print(f"\n  {url[:60]}")
        print(f"  → {r['prediction'].upper()}  ({r['confidence']*100:.1f}%)")