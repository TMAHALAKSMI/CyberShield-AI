from datasets import load_dataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier  # Fallback model

# Load data aggressively until we get phishing samples
print("Loading dataset with phishing samples...")
dataset = load_dataset("phreshphish/phreshphish", split="train", streaming=True)

data = []
phishing_count = 0
max_samples = 5000

for i, item in enumerate(dataset):
    data.append(item)
    if item['label'] == 'phish':
        phishing_count += 1
    if len(data) >= max_samples or (phishing_count >= 100 and len(data) >= 500):
        break

df = pd.DataFrame(data)
print(f"Loaded {len(df)} samples (phishing: {phishing_count})")

# Fix labels: convert 'benign'/'phish' to 0/1
le = LabelEncoder()
df['label_numeric'] = le.fit_transform(df['label'])
y = df['label_numeric'].values
print(f"Unique labels after encoding: {np.unique(y)}")
print(f"Phishing ratio: {(y == 1).mean():.3f}")

def extract_url_features(url):
    """Extract handcrafted features from URL"""
    if not isinstance(url, str):
        url = str(url)
    
    parsed = urlparse(url)
    features = {}
    
    # Length features
    features['url_length'] = len(url)
    features['domain_length'] = len(parsed.netloc) if parsed.netloc else 0
    features['path_length'] = len(parsed.path)
    features['query_length'] = len(parsed.query)
    
    # Security features
    features['scheme_https'] = 1 if parsed.scheme == 'https' else 0
    
    # Character counts
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special'] = sum(c in '@?!#/%+-=' for c in url)
    
    # Structural features
    features['num_subdomains'] = max(0, len(parsed.netloc.split('.')) - 2) if parsed.netloc else 0
    features['has_ip'] = 1 if parsed.netloc and all(c in '0123456789.' for c in parsed.netloc) else 0
    
    # Suspicious patterns
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'paypal']
    features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
    
    return list(features.values())

# Extract features
print("Extracting features...")
feature_df = pd.DataFrame(df['url'].apply(extract_url_features).tolist())
X_feat = feature_df.values

# TF-IDF features
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 6), max_features=500)
X_tfidf = vectorizer.fit_transform(df['url'].astype(str))

# Combine features
X = np.hstack((X_feat, X_tfidf.toarray()[:, :200]))

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print(f"Train phishing ratio: {(y_train == 1).mean():.3f}")
print(f"Test phishing ratio: {(y_test == 1).mean():.3f}")

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Model training with fallback
print("Training model...")
num_phish_train = np.sum(y_train == 1)

if num_phish_train == 0:
    print("No phishing samples! Using RandomForest with balanced weights.")
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight='balanced',
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
else:
    print("Using XGBoost...")
    try:
        from xgboost import XGBClassifier
        scale_pos_weight = np.sum(y_train == 0) / num_phish_train
        model = XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            scale_pos_weight=min(scale_pos_weight, 10),  # Cap extreme imbalance
            random_state=42,
            eval_metric='logloss'
        )
    except ImportError:
        print("XGBoost not available, using RandomForest.")
        model = RandomForestClassifier(
            n_estimators=200,
            class_weight='balanced',
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

def predict_url(url):
    """Predict single URL"""
    if not isinstance(url, str):
        url = str(url)
    
    feat_vec = np.array([extract_url_features(url)])
    tfidf_vec = vectorizer.transform([url]).toarray()[:, :200]
    full_vec = np.hstack((feat_vec, tfidf_vec))
    full_vec_scaled = scaler.transform(full_vec)
    
    prediction = model.predict(full_vec_scaled)[0]
    probability = model.predict_proba(full_vec_scaled)[0] if hasattr(model, 'predict_proba') else [1-prediction, prediction]
    
    label = le.inverse_transform([prediction])[0]
    confidence = max(probability)
    
    return f"{label} URL (confidence: {confidence:.3f})"

# Interactive loop
print("\n" + "="*60)
print("URL PHISHING DETECTOR READY!")
print("="*60)
print("Test URLs:")
print("• Legit: https://www.google.com")
print("• Suspicious: http://login-secure-bank.com.update.verify.com")
print("-" * 60)

while True:
    user_url = input("\nEnter URL (or 'exit'): ").strip()
    
    if user_url.lower() in ['exit', 'quit', 'q']:
        print("Goodbye!")
        break
    
    if not user_url.startswith(('http', 'www', '.')):
        print("Please enter a valid URL")
        continue
    
    result = predict_url(user_url)
    print(f" Prediction: {result}")

print("\nProgram completed successfully!")