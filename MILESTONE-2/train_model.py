import pickle
import os
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split

def extract_features(url):
    """
    Extracts 5 specific features. 
    Matches the logic used in your main.py.
    """
    return [
        len(url),                   # Feature 1: Length
        url.count("."),             # Feature 2: Dots
        int('@' in url),            # Feature 3: @ symbol
        int('-' in url),            # Feature 4: Hyphens
        int('https' in url)         # Feature 5: HTTPS presence
    ]

def create_balanced_dataset():
    """
    FIXED: Includes long and hyphenated LEGITIMATE URLs 
    to prevent false positives on Google Meet/Gemini.
    """
    np.random.seed(42)
    X, y = [], []
    
    # ✅ LEGITIMATE SAMPLES (Label 0)
    # Adding hyphens and long paths to teach the model these are common in safe apps.
    legit_urls = [
        "https://www.google.com",
        "https://meet.google.com/xzi-amou-bhx",        # Hyphens are safe here
        "https://gemini.google.com/app/dashboard",      # Long path is safe
        "https://github.com/microsoft/vscode/issues",
        "https://www.amazon.in/gp/cart/view.html",
        "https://stack-overflow.com/questions/tagged",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://docs.microsoft.com/en-us/azure",
        "https://auth.services.adobe.com/login",
        "https://discord.com/channels/987/123"
    ]
    
    # ❌ PHISHING SAMPLES (Label 1)
    phish_urls = [
        "http://login-secure-bank.com-verify.info",
        "http://paypal.com@verification-update.net",  # Uses @ to trick users
        "https://secure-appleid.support-verify.com",
        "http://192.168.1.1/login.html",              # IP-based
        "http://bit.ly/secure-access-token",          # URL shortener
        "http://amaz0n-shopping-reward.xyz",          # Look-alike domain
        "https://microsoft-security-patch.temp.com",
        "http://account-update@web-check.org",
        "http://verify.wallet-metamask.io",
        "https://login.facebook.com-alert.net"
    ]

    # Generate 1000 samples for training
    for _ in range(1000):
        l_url = np.random.choice(legit_urls)
        p_url = np.random.choice(phish_urls)
        
        X.append(extract_features(l_url))
        y.append(0)
        
        X.append(extract_features(p_url))
        y.append(1)
    
    return np.array(X), np.array(y)

def train_and_save():
    print("🚀 Training XGBoost model with rectified dataset...")
    
    X, y = create_balanced_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # XGBoost handles feature weights better than a single Decision Tree
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    accuracy = model.score(X_test, y_test)
    print(f"✅ Training Complete. Test Accuracy: {accuracy:.1%}")
    
    # Save the model as model.pkl
    with open("model.pkl", "wb") as f:
        pickle.dump(model, f)
    print("📁 Model saved as 'model.pkl'")

if __name__ == "__main__":
    train_and_save()