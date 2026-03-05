"""
Social/Email Phishing ML model inference.
Uses TF-IDF + Logistic Regression trained on phishing_email.csv + CEAS_08.csv.
"""

import os
import joblib
import numpy as np
import scipy.sparse as sp
from config import SOCIAL_MODEL_PATH, SOCIAL_VECTORIZER_PATH

_model = None
_vectorizer = None
_loaded = False
_error = None

URGENCY_WORDS = [
    "urgent", "verify", "suspend", "account", "click", "login",
    "confirm", "password", "update", "alert", "immediately", "expire",
]


def _load():
    global _model, _vectorizer, _loaded, _error
    if _loaded:
        return
    try:
        if not os.path.exists(SOCIAL_MODEL_PATH):
            _error = f"Social model not found at {SOCIAL_MODEL_PATH}. Run training/train_social_model.py first."
            _loaded = True
            return
        if not os.path.exists(SOCIAL_VECTORIZER_PATH):
            _error = f"Social vectorizer not found at {SOCIAL_VECTORIZER_PATH}. Run training/train_social_model.py first."
            _loaded = True
            return
        _model = joblib.load(SOCIAL_MODEL_PATH)
        _vectorizer = joblib.load(SOCIAL_VECTORIZER_PATH)
        _loaded = True
    except Exception as e:
        _error = f"Failed to load social model: {str(e)}"
        _loaded = True


def _extra_features(text):
    has_url = 1.0 if ("http" in text or "www." in text) else 0.0
    length = min(1.0, len(text) / 5000.0)
    urgency = float(sum(1 for w in URGENCY_WORDS if w in text.lower()))
    return np.array([[has_url, length, urgency]], dtype=np.float32)


def predict_social_phishing(text):
    """
    Predict phishing probability for email/social media text.
    Returns:
        {
            "probability": float (0-1) or None,
            "available": bool,
            "error": str or None
        }
    """
    _load()

    if _model is None:
        return {"probability": None, "available": False, "error": _error}

    try:
        tfidf = _vectorizer.transform([text])
        extra = _extra_features(text)
        features = sp.hstack([tfidf, sp.csr_matrix(extra)])
        proba = _model.predict_proba(features)
        phishing_prob = float(proba[0][1])
        return {"probability": round(phishing_prob, 4), "available": True, "error": None}
    except Exception as e:
        return {"probability": None, "available": False, "error": f"Prediction failed: {str(e)}"}
