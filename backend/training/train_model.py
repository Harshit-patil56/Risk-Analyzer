"""
Model Training Script for Phishing URL Detection.

Uses the Kaggle phishing URL dataset (UCI ML repository).
Dataset: https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning

Instructions:
1. Download the dataset CSV from Kaggle
2. Place it in backend/training/dataset/ as 'phishing.csv'
3. Run: python training/train_model.py

If no dataset is available, this script generates a synthetic training set
from known URL patterns for demo purposes.
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.url_features import extract_url_features, url_features_to_array, FEATURE_NAMES


DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "phishing.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phishing_model.joblib")


def generate_synthetic_dataset(n_samples=2000):
    """
    Generate a synthetic dataset for demo/hackathon purposes
    when the real Kaggle dataset is not available.
    """
    print("No Kaggle dataset found. Generating synthetic training data...")

    safe_urls = [
        "https://www.google.com", "https://www.github.com", "https://www.stackoverflow.com",
        "https://www.wikipedia.org", "https://www.python.org", "https://www.microsoft.com",
        "https://www.apple.com", "https://www.amazon.com", "https://www.netflix.com",
        "https://www.linkedin.com", "https://www.twitter.com", "https://www.reddit.com",
        "https://www.youtube.com", "https://www.facebook.com", "https://www.instagram.com",
        "https://docs.python.org/3/library/os.html", "https://www.bbc.com/news",
        "https://www.nytimes.com/section/world", "https://www.mozilla.org/en-US/firefox/",
        "https://www.cloudflare.com", "https://www.stripe.com/docs/api",
        "https://www.npmjs.com/package/react", "https://www.w3schools.com/html/",
        "https://developer.mozilla.org/en-US/docs/Web", "https://www.rust-lang.org",
        "https://www.postgresql.org/docs/", "https://www.docker.com/products/docker-desktop",
        "https://www.notion.so", "https://www.figma.com", "https://www.vercel.com",
    ]

    phishing_urls = [
        "http://paypa1-secure.xyz/login/verify", "http://192.168.1.1/banking/login",
        "http://g00gle-verify.tk/account/confirm", "http://amaz0n-security.ml/update",
        "http://micros0ft-support.ga/reset-password", "http://app1e-id.cf/verify",
        "http://netf1ix-billing.top/payment", "http://faceb00k-security.buzz/login",
        "http://secure-banking-update.xyz/account/verify?id=38291&token=abc",
        "http://login.verify-paypal.com@evil.xyz/steal", "http://bit.ly/2xH3mN9",
        "http://www.your-bank-alert.xyz/verify-now/login.php?user=victim",
        "http://update-your-account.suspicious-domain.tk/signin",
        "http://192.168.0.1:8080/phishing/credential-harvest",
        "http://confirm-identity.gq/microsoft/office365/login",
        "http://l1nkedin-verify.work/profile/update-details",
        "http://security-alert.chase-bank.xyz/verify-identity",
        "http://we11sfargo-secure.top/online-banking/login",
        "http://instagram-verify.club/confirm-account-now",
        "http://urgent-verify.stream/your-account/suspended",
        "http://www.account-verify-now.download/netflix/billing",
    ]

    features_list = []
    labels = []

    # Generate safe examples with variations
    for _ in range(n_samples // 2):
        base_url = np.random.choice(safe_urls)
        # Add random path variations
        paths = ["", "/about", "/contact", "/products", "/docs", "/api/v1", "/help"]
        url = base_url.rstrip("/") + np.random.choice(paths)
        features = extract_url_features(url)
        features_list.append(url_features_to_array(features))
        labels.append(0)  # Safe

    # Generate phishing examples with variations
    for _ in range(n_samples // 2):
        base_url = np.random.choice(phishing_urls)
        # Add random obfuscation
        noise = np.random.choice(["", "?ref=urgent", "&session=abc123", "/redirect", "?token=xyz"])
        url = base_url + noise
        features = extract_url_features(url)
        features_list.append(url_features_to_array(features))
        labels.append(1)  # Phishing

    return np.array(features_list), np.array(labels)


def load_kaggle_dataset():
    """Load and process the Kaggle phishing dataset if available."""
    if not os.path.exists(DATASET_PATH):
        return None, None

    print(f"Loading Kaggle dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)

    # The Kaggle dataset has pre-extracted features and a 'Result' column
    # Adapt based on actual column names
    if "Result" in df.columns:
        # UCI format: features are pre-extracted, Result is -1 (phishing) or 1 (safe)
        y = (df["Result"] == -1).astype(int).values  # 1 = phishing, 0 = safe
        X = df.drop(columns=["Result"]).values
        return X, y

    print("Unrecognized dataset format. Falling back to synthetic data.")
    return None, None


def train():
    """Train the phishing detection model."""
    print("=" * 60)
    print("Phishing URL Detection — Model Training")
    print("=" * 60)

    # Try Kaggle dataset first, fallback to synthetic
    X, y = load_kaggle_dataset()
    if X is None:
        X, y = generate_synthetic_dataset(n_samples=3000)

    print(f"\nDataset size: {len(X)} samples")
    print(f"Phishing: {sum(y)} | Safe: {len(y) - sum(y)}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Training: {len(X_train)} | Testing: {len(X_test)}")

    # Train Gradient Boosting
    print("\nTraining Gradient Boosting Classifier...")
    model = GradientBoostingClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\n{'Metric':<15} {'Score':<10}")
    print("-" * 25)
    print(f"{'Accuracy':<15} {accuracy:.4f}")
    print(f"{'Precision':<15} {precision:.4f}")
    print(f"{'Recall':<15} {recall:.4f}")
    print(f"{'F1 Score':<15} {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    # Save
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    train()
