"""
Banking Transaction Fraud Detection endpoint.
POST /scan/transaction
"""

from fastapi import APIRouter
from pydantic import BaseModel, field_validator
from typing import Optional
from engine.fraud_model import predict_transaction_fraud, FRAUD_FEATURE_NAMES

router = APIRouter()


class TransactionScanRequest(BaseModel):
    # Core fields the user knows
    amount: float
    time: float = 0.0  # seconds from first transaction in dataset; 0 is fine for demo

    # V1–V28 are PCA-transformed bank features; optional for demo usage
    # In a real deployment these come from the bank's internal system.
    V1: float = 0.0
    V2: float = 0.0
    V3: float = 0.0
    V4: float = 0.0
    V5: float = 0.0
    V6: float = 0.0
    V7: float = 0.0
    V8: float = 0.0
    V9: float = 0.0
    V10: float = 0.0
    V11: float = 0.0
    V12: float = 0.0
    V13: float = 0.0
    V14: float = 0.0
    V15: float = 0.0
    V16: float = 0.0
    V17: float = 0.0
    V18: float = 0.0
    V19: float = 0.0
    V20: float = 0.0
    V21: float = 0.0
    V22: float = 0.0
    V23: float = 0.0
    V24: float = 0.0
    V25: float = 0.0
    V26: float = 0.0
    V27: float = 0.0
    V28: float = 0.0

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v):
        if v < 0:
            raise ValueError("Transaction amount cannot be negative")
        if v > 1_000_000:
            raise ValueError("Transaction amount exceeds maximum allowed value")
        return v


def _risk_label(prob: float) -> str:
    if prob >= 0.7:
        return "dangerous"
    elif prob >= 0.4:
        return "suspicious"
    return "safe"


def _build_indicators(request: TransactionScanRequest, prob: float):
    indicators = []

    # High amount heuristic
    if request.amount > 5000:
        indicators.append({
            "name": "Unusually High Transaction Amount",
            "severity": "high" if request.amount > 20000 else "medium",
            "explanation": f"Transaction amount ${request.amount:,.2f} is significantly above typical values. "
                           "Large one-time transactions are a common fraud signal."
        })

    # Odd hours heuristic (time in seconds; 86400s = 1 day)
    hour_of_day = (request.time % 86400) / 3600
    if hour_of_day < 4 or hour_of_day > 23:
        indicators.append({
            "name": "Unusual Transaction Time",
            "severity": "medium",
            "explanation": f"Transaction occurred at an unusual hour "
                           f"({hour_of_day:.1f}h). Fraudulent transactions often happen late at night."
        })

    # ML model flag
    if prob >= 0.5:
        indicators.append({
            "name": "ML Model Flagged as Fraud",
            "severity": "high" if prob >= 0.7 else "medium",
            "explanation": f"The XGBoost fraud detection model assigned a fraud probability of "
                           f"{prob*100:.1f}%. This model was trained on 284,807 real credit card transactions."
        })

    return indicators


def _education(label: str):
    if label == "dangerous":
        return [
            {
                "title": "What is Credit Card Fraud?",
                "body": "Credit card fraud occurs when someone makes unauthorized transactions using your account. "
                        "This transaction has multiple characteristics matching known fraud patterns."
            },
            {
                "title": "What to do immediately",
                "body": "Contact your bank immediately, freeze the card, request a chargeback, "
                        "and file a report with your local fraud authority."
            }
        ]
    elif label == "suspicious":
        return [
            {
                "title": "Why is this suspicious?",
                "body": "One or more features of this transaction resemble patterns seen in fraudulent transactions. "
                        "This doesn't mean it's fraud, but warrants a closer look."
            }
        ]
    return [
        {
            "title": "Transaction appears legitimate",
            "body": "No strong fraud signals detected. Always monitor your statements for unexpected charges."
        }
    ]


@router.post("/transaction")
def scan_transaction(request: TransactionScanRequest):
    """Analyze a banking transaction for fraud using XGBoost ML model."""

    features = {
        "Time": request.time,
        "Amount": request.amount,
        **{f"V{i}": getattr(request, f"V{i}") for i in range(1, 29)},
    }

    result = predict_transaction_fraud(features)

    if not result["available"]:
        return {
            "overall_score": None,
            "label": "error",
            "fraud_probability": None,
            "indicators": [],
            "education": [],
            "ml_status": "unavailable",
            "error": result["error"],
            "scan_type": "transaction",
            "scanned_input": f"Amount: ${request.amount:,.2f}",
        }

    prob = result["probability"]
    label = _risk_label(prob)
    overall_score = round(prob * 100)

    return {
        "overall_score": overall_score,
        "label": label,
        "fraud_probability": prob,
        "ml_probability": prob,
        "sub_scores": {
            "fraud_ml": overall_score,
        },
        "indicators": _build_indicators(request, prob),
        "education": _education(label),
        "ml_status": "active",
        "scan_type": "transaction",
        "scanned_input": f"${request.amount:,.2f}",
    }
