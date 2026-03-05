import os
from dotenv import load_dotenv

load_dotenv()

# API Keys - set these in a .env file or environment variables
# If not set, the system works fully via local heuristics + ML only
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Server config
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

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
