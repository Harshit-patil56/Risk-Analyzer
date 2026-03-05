"""
Social Media / Email Phishing Detection — TF-IDF + Logistic Regression Training Script
Datasets used:
  - phishing_email.csv: 'text_combined' + 'label' (large, 101MB)
  - CEAS_08.csv: 'body' + 'label' (spam challenge dataset)

Approach (from notebook):
  - TF-IDF vectorizer with 5000 features on combined email text
  - Logistic Regression (fast CPU, ~2 min, best for text classification)
  - Feature: TF-IDF + URL presence flag + text length

Output:
  - social_model.joblib
  - social_vectorizer.joblib
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, roc_auc_score
)

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
PHISHING_EMAIL_PATH = os.path.join(DATASET_DIR, "phishing_email.csv")
CEAS_PATH = os.path.join(DATASET_DIR, "CEAS_08.csv")

MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "social_model.joblib")
VECTORIZER_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "social_vectorizer.joblib")


def load_datasets():
    """Load and combine all available email/social datasets."""
    frames = []

    # Dataset 1: phishing_email.csv — has 'text_combined' and 'label'
    if os.path.exists(PHISHING_EMAIL_PATH):
        print(f"Loading phishing_email.csv ...")
        df = pd.read_csv(PHISHING_EMAIL_PATH)
        df = df[["text_combined", "label"]].rename(columns={"text_combined": "text"})
        df = df.dropna(subset=["text"])
        frames.append(df)
        print(f"  Loaded {len(df):,} rows (Phishing: {df['label'].sum():,})")

    # Dataset 2: CEAS_08.csv — has 'body' and 'label'
    if os.path.exists(CEAS_PATH):
        print(f"Loading CEAS_08.csv ...")
        df2 = pd.read_csv(CEAS_PATH)
        if "body" in df2.columns and "label" in df2.columns:
            df2 = df2[["body", "label"]].rename(columns={"body": "text"})
            df2 = df2.dropna(subset=["text"])
            frames.append(df2)
            print(f"  Loaded {len(df2):,} rows (Phishing: {df2['label'].sum():,})")

    if not frames:
        print("ERROR: No datasets found.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=["text"])
    combined["text"] = combined["text"].astype(str)
    return combined


def extract_extra_features(texts):
    """
    Extract simple numeric features to combine with TF-IDF.
    These give the model additional signal beyond word frequencies.
    """
    has_url = np.array([1 if ("http" in t or "www." in t) else 0 for t in texts], dtype=np.float32)
    text_length = np.array([len(t) for t in texts], dtype=np.float32)
    # Normalize length to 0-1 range
    max_len = text_length.max() if text_length.max() > 0 else 1
    text_length = text_length / max_len

    # Count urgency keywords (common in phishing)
    urgency_words = ["urgent", "verify", "suspend", "account", "click", "login",
                     "confirm", "password", "update", "alert", "immediately", "expire"]
    urgency_count = np.array(
        [sum(1 for w in urgency_words if w in t.lower()) for t in texts],
        dtype=np.float32
    )

    return np.column_stack([has_url, text_length, urgency_count])


def train():
    print("=" * 60)
    print("Social/Email Phishing Detection — TF-IDF + Logistic Regression")
    print("=" * 60)

    df = load_datasets()

    print(f"\nTotal samples: {len(df):,}")
    print(f"Phishing: {df['label'].sum():,} | Legitimate: {(df['label'] == 0).sum():,}")

    texts = df["text"].tolist()
    y = df["label"].values

    # Train/Test split
    X_train_texts, X_test_texts, y_train, y_test = train_test_split(
        texts, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train_texts):,} | Test: {len(X_test_texts):,}")

    # TF-IDF vectorizer (from notebook: 5000 features, stop_words='english')
    print("\nFitting TF-IDF vectorizer (5000 features)...")
    vectorizer = TfidfVectorizer(
        stop_words="english",
        max_features=5000,
        ngram_range=(1, 2),      # unigrams + bigrams for better phishing phrase capture
        sublinear_tf=True,       # log normalization
        min_df=2,                # ignore very rare words
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_texts)
    X_test_tfidf = vectorizer.transform(X_test_texts)
    print(f"TF-IDF matrix shape: {X_train_tfidf.shape}")

    # Extra numeric features
    X_train_extra = extract_extra_features(X_train_texts)
    X_test_extra = extract_extra_features(X_test_texts)

    # Combine TF-IDF with extra features
    X_train = sp.hstack([X_train_tfidf, sp.csr_matrix(X_train_extra)])
    X_test = sp.hstack([X_test_tfidf, sp.csr_matrix(X_test_extra)])

    # Logistic Regression — best for TF-IDF, fast, interpretable
    print("\nTraining Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        solver="saga",           # Fast solver for large sparse data
        class_weight="balanced", # Handle any class imbalance
        random_state=42,
        n_jobs=-1,               # Use all CPU cores
        verbose=1,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Top phishing indicator words
    feature_names = vectorizer.get_feature_names_out().tolist() + ["has_url", "text_length", "urgency_count"]
    coefs = model.coef_[0]
    top_phishing = sorted(zip(feature_names, coefs), key=lambda x: x[1], reverse=True)[:15]
    print("Top 15 Phishing Indicator Words/Features:")
    for word, coef in top_phishing:
        print(f"  {word:30s}: {coef:.4f}")

    # Save
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(vectorizer, VECTORIZER_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")
    print(f"Vectorizer saved to: {VECTORIZER_OUTPUT_PATH}")


if __name__ == "__main__":
    train()
