"""
URL Phishing Detection — XGBoost GPU Training Script
Dataset: Phishing_Legitimate_full.csv (10,000 samples, 48 features)
Source: kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning

Uses only URL-extractable features so the trained model works for
live inference without needing to fetch page content.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, roc_auc_score
)

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "Phishing_Legitimate_full.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phishing_model.joblib")
FEATURES_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phishing_url_features.joblib")

# These are the features from the CSV that can be computed from a raw URL
# at inference time — no page fetching required.
URL_EXTRACTABLE_FEATURES = [
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "UrlLength",
    "NumDash",
    "NumDashInHostname",
    "AtSymbol",
    "TildeSymbol",
    "NumUnderscore",
    "NumPercent",
    "NumQueryComponents",
    "NumAmpersand",
    "NumHash",
    "NumNumericChars",
    "NoHttps",
    "IpAddress",
    "DomainInSubdomains",
    "DomainInPaths",
    "HttpsInHostname",
    "HostnameLength",
    "PathLength",
    "QueryLength",
    "DoubleSlashInPath",
    "NumSensitiveWords",
    "EmbeddedBrandName",
    "RandomString",
]


def train():
    print("=" * 60)
    print("Phishing URL Detection — XGBoost GPU Training")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        sys.exit(1)

    print(f"\nLoading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset shape: {df.shape}")

    # Convert to efficient dtypes (from notebook approach)
    for c in df.select_dtypes("float64").columns:
        df[c] = df[c].astype("float32")
    for c in df.select_dtypes("int64").columns:
        df[c] = df[c].astype("int32")

    # Drop id column
    if "id" in df.columns:
        df.drop(columns=["id"], inplace=True)

    # Keep only URL-extractable features for compatibility with live inference
    missing = [f for f in URL_EXTRACTABLE_FEATURES if f not in df.columns]
    if missing:
        print(f"WARNING: Missing columns in dataset: {missing}")
        features_to_use = [f for f in URL_EXTRACTABLE_FEATURES if f in df.columns]
    else:
        features_to_use = URL_EXTRACTABLE_FEATURES

    X = df[features_to_use].values
    y = df["CLASS_LABEL"].values

    print(f"\nFeatures used: {len(features_to_use)}")
    print(f"Phishing: {sum(y == 1):,} | Legitimate: {sum(y == 0):,}")

    # Train / Test split — 80/20, stratified
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train):,} | Test: {len(X_test):,}")

    # XGBoost with GPU (GTX 1650)
    print("\nTraining XGBoost on GPU...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="auc",
        tree_method="hist",
        device="cuda",          # Use GTX 1650
        random_state=42,
        verbosity=1,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )

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

    # Feature importance (top 10)
    print("Top 10 Most Important Features:")
    importance = model.feature_importances_
    feat_imp = sorted(zip(features_to_use, importance), key=lambda x: x[1], reverse=True)
    for name, score in feat_imp[:10]:
        print(f"  {name:35s}: {score:.4f}")

    # Save model and feature names
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(features_to_use, FEATURES_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")
    print(f"Feature list saved to: {FEATURES_OUTPUT_PATH}")


if __name__ == "__main__":
    train()
