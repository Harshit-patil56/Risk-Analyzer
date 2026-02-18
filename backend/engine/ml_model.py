import os
import joblib
import numpy as np
from utils.url_features import extract_url_features, url_features_to_array
from config import MODEL_PATH


_model = None
_model_loaded = False
_model_error = None


def _load_model():
    """Load the trained model from disk. Called once on first prediction."""
    global _model, _model_loaded, _model_error
    if _model_loaded:
        return

    if not os.path.exists(MODEL_PATH):
        _model_error = f"Model file not found at {MODEL_PATH}. Run training/train_model.py first."
        _model_loaded = True
        return

    try:
        _model = joblib.load(MODEL_PATH)
        _model_loaded = True
    except Exception as e:
        _model_error = f"Failed to load model: {str(e)}"
        _model_loaded = True


def predict_phishing_probability(url):
    """
    Predict phishing probability for a URL using the ML model.
    Returns:
        {
            "probability": float (0-1) or None if model unavailable,
            "available": bool,
            "error": str or None
        }
    """
    _load_model()

    if _model is None:
        return {
            "probability": None,
            "available": False,
            "error": _model_error,
        }

    try:
        features = extract_url_features(url)
        feature_array = np.array([url_features_to_array(features)])
        # predict_proba returns [[prob_safe, prob_phishing]]
        proba = _model.predict_proba(feature_array)
        phishing_prob = float(proba[0][1])
        return {
            "probability": round(phishing_prob, 4),
            "available": True,
            "error": None,
        }
    except Exception as e:
        return {
            "probability": None,
            "available": False,
            "error": f"Prediction failed: {str(e)}",
        }
