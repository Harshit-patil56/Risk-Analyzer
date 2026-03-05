"""
Banking Transaction Fraud ML model inference.
Uses XGBoost trained on creditcard.csv (284,807 transactions).
"""

import os
import joblib
import numpy as np
from config import FRAUD_MODEL_PATH, FRAUD_SCALER_PATH

_model = None
_scaler = None
_loaded = False
_error = None

# Feature order must match training (creditcard.csv columns minus 'Class')
FRAUD_FEATURE_NAMES = [
    "Time", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9",
    "V10", "V11", "V12", "V13", "V14", "V15", "V16", "V17", "V18", "V19",
    "V20", "V21", "V22", "V23", "V24", "V25", "V26", "V27", "V28", "Amount",
]


def _load():
    global _model, _scaler, _loaded, _error
    if _loaded:
        return
    try:
        if not os.path.exists(FRAUD_MODEL_PATH):
            _error = f"Fraud model not found at {FRAUD_MODEL_PATH}. Run training/train_fraud_model.py first."
            _loaded = True
            return
        if not os.path.exists(FRAUD_SCALER_PATH):
            _error = f"Fraud scaler not found at {FRAUD_SCALER_PATH}. Run training/train_fraud_model.py first."
            _loaded = True
            return
        _model = joblib.load(FRAUD_MODEL_PATH)
        _scaler = joblib.load(FRAUD_SCALER_PATH)
        _loaded = True
    except Exception as e:
        _error = f"Failed to load fraud model: {str(e)}"
        _loaded = True


def predict_transaction_fraud(features: dict):
    """
    Predict fraud probability for a transaction.

    Args:
        features: dict with keys matching FRAUD_FEATURE_NAMES
                  (Time, V1-V28, Amount)
    Returns:
        {
            "probability": float (0-1) or None,
            "label": "fraud" | "legitimate",
            "available": bool,
            "error": str or None
        }
    """
    _load()

    if _model is None:
        return {"probability": None, "label": None, "available": False, "error": _error}

    try:
        row = np.array([[features[f] for f in FRAUD_FEATURE_NAMES]], dtype=np.float32)
        row_scaled = _scaler.transform(row)
        proba = _model.predict_proba(row_scaled)
        fraud_prob = float(proba[0][1])
        label = "fraud" if fraud_prob >= 0.5 else "legitimate"
        return {
            "probability": round(fraud_prob, 4),
            "label": label,
            "available": True,
            "error": None,
        }
    except Exception as e:
        return {"probability": None, "label": None, "available": False, "error": f"Prediction failed: {str(e)}"}
