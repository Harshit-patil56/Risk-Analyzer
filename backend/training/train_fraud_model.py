"""
Banking Transaction Fraud Detection — XGBoost GPU Training Script
Dataset: creditcard.csv (284,807 transactions, 31 features)
Source: kaggle.com/datasets/mlg-ulb/creditcardfraud

Key challenge: Extremely imbalanced dataset
  - 284,315 legitimate (99.83%)
  - 492 fraud (0.17%)
Solution: scale_pos_weight in XGBoost + SMOTE oversampling
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, roc_auc_score,
    confusion_matrix
)
from imblearn.over_sampling import SMOTE

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "creditcard.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "transaction_fraud_model.joblib")
SCALER_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "fraud_scaler.joblib")


def train():
    print("=" * 60)
    print("Banking Fraud Detection — XGBoost GPU Training")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        sys.exit(1)

    print(f"\nLoading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset shape: {df.shape}")

    # Class distribution
    fraud_count = df["Class"].sum()
    legit_count = len(df) - fraud_count
    print(f"\nLegitimate: {legit_count:,} ({legit_count/len(df)*100:.2f}%)")
    print(f"Fraud:      {fraud_count:,} ({fraud_count/len(df)*100:.2f}%)")

    # Features and label
    # V1-V28 are PCA-transformed (already scaled by the bank)
    # Time and Amount need StandardScaler (from notebook approach)
    X = df.drop("Class", axis=1).values
    y = df["Class"].values

    # Train/Test split BEFORE any oversampling (prevent data leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train):,} | Test: {len(X_test):,}")

    # Scale Time and Amount (V1-V28 are already PCA-scaled)
    # Fit scaler on training set only
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # SMOTE oversampling on training set only
    print("\nApplying SMOTE oversampling on training set...")
    smote = SMOTE(random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    print(f"After SMOTE — Train: {len(X_train_resampled):,} "
          f"(Fraud: {sum(y_train_resampled):,} | Legit: {sum(y_train_resampled==0):,})")

    # scale_pos_weight for additional imbalance handling in XGBoost
    # After SMOTE the classes are balanced, so we set it to 1
    scale_pos_weight = 1

    print("\nTraining XGBoost on GPU (GTX 1650)...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="aucpr",        # Area under Precision-Recall — best for imbalanced data
        tree_method="hist",
        device="cuda",              # Use GTX 1650
        random_state=42,
        verbosity=1,
    )
    model.fit(
        X_train_resampled, y_train_resampled,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )

    # Evaluate on ORIGINAL (unsmoted) test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 60)
    print("TEST RESULTS (on original unsmoted test set)")
    print("=" * 60)
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives  (Legit correctly identified): {cm[0][0]:,}")
    print(f"  False Positives (Legit flagged as Fraud):     {cm[0][1]:,}")
    print(f"  False Negatives (Fraud missed):               {cm[1][0]:,}")
    print(f"  True Positives  (Fraud correctly caught):     {cm[1][1]:,}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Fraud"]))

    # Feature importance
    feature_names = df.drop("Class", axis=1).columns.tolist()
    print("Top 10 Most Important Features:")
    importance = model.feature_importances_
    feat_imp = sorted(zip(feature_names, importance), key=lambda x: x[1], reverse=True)
    for name, score in feat_imp[:10]:
        print(f"  {name:10s}: {score:.4f}")

    # Save model and scaler
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(scaler, SCALER_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")
    print(f"Scaler saved to: {SCALER_OUTPUT_PATH}")


if __name__ == "__main__":
    train()
