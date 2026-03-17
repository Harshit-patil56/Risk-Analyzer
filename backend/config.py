import os
from dotenv import load_dotenv

load_dotenv()


def _normalize_origin(origin: str) -> str:
    return origin.strip().rstrip("/")


def _load_cors_origins():
    defaults = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    configured = os.getenv("CORS_ORIGINS", "")
    frontend_url = os.getenv("FRONTEND_URL", "")

    origins = {_normalize_origin(o) for o in defaults if o.strip()}

    if frontend_url.strip():
        origins.add(_normalize_origin(frontend_url))

    if configured.strip():
        for origin in configured.split(","):
            origin = _normalize_origin(origin)
            if origin:
                origins.add(origin)

    return sorted(origins)

# API Keys - set these in a .env file or environment variables
# If not set, the system works fully via local heuristics + ML only
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Server config
CORS_ORIGINS = _load_cors_origins()

# Scoring thresholds
SAFE_THRESHOLD = 30
SUSPICIOUS_THRESHOLD = 60

# API timeout in seconds
API_TIMEOUT = 5

# Model paths
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.joblib")
PHISHING_URL_FEATURES_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_url_features.joblib")
SOCIAL_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "social_model.joblib")
SOCIAL_VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "models", "social_vectorizer.joblib")
FRAUD_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "transaction_fraud_model.joblib")
FRAUD_SCALER_PATH = os.path.join(os.path.dirname(__file__), "models", "fraud_scaler.joblib")
