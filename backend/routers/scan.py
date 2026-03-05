from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
import re

from engine.heuristics import analyze_url_heuristics, analyze_email_heuristics, analyze_social_heuristics
from engine.ml_model import predict_phishing_probability
from engine.social_model import predict_social_phishing
from engine.fraud_model import predict_transaction_fraud, FRAUD_FEATURE_NAMES
from engine.intel import gather_url_intel
from engine.api_checker import check_all_apis
from engine.scorer import (
    compute_domain_score,
    compute_structural_score,
    compute_language_score,
    compute_overall_score,
    generate_education,
)

# ------------------------------------------------------------------
# Financial content detection (auto-triggers fraud model in emails)
# ------------------------------------------------------------------
_FINANCIAL_KW_RE = re.compile(
    r'\b(?:transfer|wire\s+transfer|payment|transaction|credit\s+card|debit\s+card|'
    r'bank\s+account|routing\s+number|swift\s+code|iban|deposit|withdrawal?|'
    r'send\s+(?:the\s+)?(?:money|funds?)|pay\s+(?:now|immediately|asap|us|me)|'
    r'western\s+union|moneygram|bitcoin|btc|ethereum|eth|crypto(?:currency)?|'
    r'binance|coinbase|usdt|tether|litecoin|ltc|ripple|xrp|dogecoin|doge|solana|sol|'
    r'nft|web3|wallet\s+address|blockchain|paypal|venmo|zelle|cashapp|'
    r'money\s+order|wire\s+funds?|urgent\s+payment|immediate\s+transfer|'
    r'financial\s+transaction|bank\s+transfer|invoice\s+(?:due|payment|attached))\b',
    re.IGNORECASE,
)
_CURRENCY_RE = re.compile(
    r'[$\£\€\¥\₹₿]|\b(?:USD|EUR|GBP|AUD|CAD|INR|BTC|ETH|USDT|SOL|XRP|DOGE|LTC)\b',
    re.IGNORECASE,
)
_AMOUNT_RE = re.compile(
    r'(?:[$\£\€\¥\₹₿]\s*\d[\d,]*(?:\.\d{1,8})?|\d[\d,]*(?:\.\d{1,8})?\s*(?:USD|EUR|GBP|dollars?|euros?|pounds?|BTC|ETH|USDT|bitcoin|ethereum|crypto))',
    re.IGNORECASE,
)


def _extract_financial_info(text: str):
    """Detect financial content and extract the largest dollar amount."""
    has_financial = bool(_FINANCIAL_KW_RE.search(text) or _CURRENCY_RE.search(text))
    amount = 0.0
    if has_financial:
        raw_amounts = _AMOUNT_RE.findall(text)
        parsed = []
        for m in raw_amounts:
            clean = re.sub(r'[^0-9.]', '', m.replace(',', ''))
            try:
                parsed.append(float(clean))
            except ValueError:
                pass
        if parsed:
            amount = max(parsed)
    return has_financial, amount

router = APIRouter()


class UrlScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # Add scheme if missing
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        # Basic URL format validation
        url_pattern = re.compile(
            r'^https?://'
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'(?::\d+)?'
            r'(?:/[^\s]*)?$',
            re.IGNORECASE
        )
        if not url_pattern.match(v):
            raise ValueError("Invalid URL format")
        return v


class EmailScanRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Email content cannot be empty")
        if len(v) < 10:
            raise ValueError("Email content is too short to analyze meaningfully")
        return v


@router.post("/url")
def scan_url(request: UrlScanRequest):
    """Scan a URL for phishing indicators."""
    url = request.url

    # Layer 1: Heuristic analysis
    url_indicators = analyze_url_heuristics(url)

    # Layer 2: ML prediction (XGBoost — primary signal, 97.5% ROC-AUC)
    ml_result = predict_phishing_probability(url)

    # Layer 3: External API threat intelligence
    # PhishTank + URLhaus are free (no key needed); GSB + VirusTotal use keys if present
    api_results = check_all_apis(url)
    api_threats = [r for r in api_results if not r.get("unavailable") and r.get("is_threat")]
    api_confidence_max = max((r.get("confidence", 0.0) for r in api_threats), default=0.0)
    api_score = round(api_confidence_max * 100) if api_threats else None

    # Sub-scores
    domain_score = compute_domain_score(url_indicators)
    structural_score = compute_structural_score(url_indicators)
    ml_score = round(ml_result["probability"] * 100) if ml_result.get("available") and ml_result["probability"] is not None else None

    # Overall score: API + ML together when both available (API 25%, ML 45%), else ML-only or heuristic
    overall_score, label = compute_overall_score(domain_score, structural_score, 0, ml_score, api_score)

    education = generate_education(url_indicators, label)

    detected_indicators = []
    for ind in url_indicators:
        if ind["detected"]:
            severity_label = "low"
            if ind["severity"] >= 0.7:
                severity_label = "high"
            elif ind["severity"] >= 0.4:
                severity_label = "medium"
            detected_indicators.append({
                "name": ind["name"],
                "severity": severity_label,
                "explanation": ind["explanation"],
            })

    # Prepend high-severity indicators for each API that confirmed a threat
    _API_DISPLAY_NAMES = {
        "google_safe_browsing": "Google Safe Browsing",
        "virustotal": "VirusTotal",
        "phishtank": "PhishTank",
        "urlhaus": "URLhaus Malware DB",
    }
    for threat in api_threats:
        api_display = _API_DISPLAY_NAMES.get(threat.get("api_name", ""), threat.get("api_name", "Unknown API"))
        detected_indicators.insert(0, {
            "name": f"Flagged by {api_display}",
            "severity": "high",
            "explanation": f"This URL was found in {api_display}'s threat database, which tracks confirmed phishing and malware sites.",
        })

    intel = gather_url_intel(url)

    sub_scores = {
        "domain": domain_score,
        "structural": structural_score,
        "ml": ml_score if ml_score is not None else 0,
    }
    if api_score is not None:
        sub_scores["api_reputation"] = api_score

    return {
        "overall_score": overall_score,
        "label": label,
        "sub_scores": sub_scores,
        "indicators": detected_indicators,
        "education": education,
        "ml_status": "active" if ml_result.get("available") else "unavailable",
        "ml_probability": ml_result.get("probability"),
        "intel": intel,
        "scan_type": "url",
        "scanned_input": url,
    }


@router.post("/email")
def scan_email(request: EmailScanRequest):
    """Scan email content for phishing indicators."""
    content = request.content

    # Layer 1a: Email language heuristics
    email_indicators, extracted_urls = analyze_email_heuristics(content)

    # Layer 1b: Social/email ML model (primary signal, trained on 121,640 emails)
    social_ml = predict_social_phishing(content)

    # Layer 1c: Heuristic analysis of embedded URLs
    all_url_indicators = []
    for url in extracted_urls[:5]:
        url_inds = analyze_url_heuristics(url)
        all_url_indicators.extend(url_inds)

    # Layer 1d: Fraud model — auto-triggered when financial language/amounts detected
    is_financial, extracted_amount = _extract_financial_info(content)
    fraud_result = None
    if is_financial:
        fraud_features = {f: 0.0 for f in FRAUD_FEATURE_NAMES}
        fraud_features["Amount"] = extracted_amount
        fraud_result = predict_transaction_fraud(fraud_features)

    # Sub-scores
    domain_score = compute_domain_score(all_url_indicators) if all_url_indicators else 0
    structural_score = compute_structural_score(all_url_indicators) if all_url_indicators else 0
    language_score = compute_language_score(email_indicators)

    # ML score: use max of social ML and fraud ML when both are available
    social_prob = social_ml.get("probability") if social_ml.get("available") and social_ml.get("probability") is not None else None
    fraud_prob = fraud_result.get("probability") if fraud_result and fraud_result.get("available") and fraud_result.get("probability") is not None else None
    if social_prob is not None and fraud_prob is not None:
        ml_score = round(max(social_prob, fraud_prob) * 100)
    elif social_prob is not None:
        ml_score = round(social_prob * 100)
    elif fraud_prob is not None:
        ml_score = round(fraud_prob * 100)
    else:
        ml_score = None

    # Overall score: social ML dominates (60%) when available
    overall_score, label = compute_overall_score(domain_score, structural_score, language_score, ml_score)

    all_indicators = email_indicators + all_url_indicators
    education = generate_education(all_indicators, label)

    detected_indicators = []
    seen_names = set()
    for ind in all_indicators:
        if ind["detected"] and ind["name"] not in seen_names:
            seen_names.add(ind["name"])
            severity_label = "low"
            if ind["severity"] >= 0.7:
                severity_label = "high"
            elif ind["severity"] >= 0.4:
                severity_label = "medium"
            detected_indicators.append({
                "name": ind["name"],
                "severity": severity_label,
                "explanation": ind["explanation"],
            })

    # Always surface a financial content indicator when money-related language is detected
    if is_financial:
        amount_part = f" It mentions a specific amount of ${extracted_amount:.2f}." if extracted_amount > 0 else ""
        detected_indicators.append({
            "name": "Asks for Money or Payment",
            "severity": "medium",
            "explanation": (
                f"This message is asking you to send, pay, or transfer money.{amount_part} "
                f"If you weren't expecting this, do not send anything before verifying the sender through a separate channel."
            ),
        })

    # Add ML indicator for UI visibility
    if social_ml.get("available") and social_ml["probability"] is not None and social_ml["probability"] >= 0.5:
        detected_indicators.insert(0, {
            "name": "Looks Like a Phishing Email",
            "severity": "high" if social_ml["probability"] >= 0.7 else "medium",
            "explanation": f"Our model has read over 121,000 real phishing and legitimate emails. It's {social_ml['probability']*100:.1f}% sure this one is a scam.",
        })

    # Add high-severity fraud indicator when the fraud model also confirms financial fraud
    if fraud_prob is not None and fraud_prob >= 0.3:
        detected_indicators.insert(0, {
            "name": "High Risk: Financial Fraud Likely",
            "severity": "high" if fraud_prob >= 0.6 else "medium",
            "explanation": (
                f"This message asks for ${extracted_amount:.2f} and matches patterns seen in real banking fraud. "
                f"Our fraud model flagged it at {fraud_prob * 100:.1f}% confidence. Do not send any money."
            ),
        })

    # Build sub_scores — include fraud_ml only when fraud model ran
    sub_scores = {
        "domain": domain_score,
        "structural": structural_score,
        "language": language_score,
        "ml": ml_score if ml_score is not None else 0,
    }
    if fraud_prob is not None:
        sub_scores["fraud_ml"] = round(fraud_prob * 100)

    return {
        "overall_score": overall_score,
        "label": label,
        "sub_scores": sub_scores,
        "indicators": detected_indicators,
        "education": education,
        "ml_status": "active" if (social_ml.get("available") or (fraud_result and fraud_result.get("available"))) else "unavailable",
        "ml_probability": social_ml.get("probability"),
        "fraud_probability": fraud_prob,
        "financial_content_detected": is_financial,
        "scan_type": "email",
        "scanned_input": content,
        "extracted_urls": extracted_urls[:5],
    }


@router.post("/social")
def scan_social(request: EmailScanRequest):
    """Scan a social media post for scams, fraud, and malicious links."""
    content = request.content

    # Layer 1a: Social-specific heuristics
    social_indicators, extracted_urls = analyze_social_heuristics(content)

    # Layer 1b: Social/email ML model
    social_ml = predict_social_phishing(content)

    # Layer 1c: Heuristic analysis of embedded URLs
    all_url_indicators = []
    for url in extracted_urls[:5]:
        url_inds = analyze_url_heuristics(url)
        all_url_indicators.extend(url_inds)

    # Layer 1d: Financial / crypto detection
    is_financial, extracted_amount = _extract_financial_info(content)
    fraud_result = None
    if is_financial:
        fraud_features = {f: 0.0 for f in FRAUD_FEATURE_NAMES}
        fraud_features["Amount"] = extracted_amount
        fraud_result = predict_transaction_fraud(fraud_features)

    # Sub-scores
    domain_score = compute_domain_score(all_url_indicators) if all_url_indicators else 0
    structural_score = compute_structural_score(all_url_indicators) if all_url_indicators else 0
    language_score = compute_language_score(social_indicators)

    social_prob = social_ml.get("probability") if social_ml.get("available") and social_ml.get("probability") is not None else None
    fraud_prob = fraud_result.get("probability") if fraud_result and fraud_result.get("available") and fraud_result.get("probability") is not None else None

    if social_prob is not None and fraud_prob is not None:
        ml_score = round(max(social_prob, fraud_prob) * 100)
    elif social_prob is not None:
        ml_score = round(social_prob * 100)
    elif fraud_prob is not None:
        ml_score = round(fraud_prob * 100)
    else:
        ml_score = None

    overall_score, label = compute_overall_score(domain_score, structural_score, language_score, ml_score)

    all_indicators = social_indicators + all_url_indicators
    education = generate_education(all_indicators, label)

    detected_indicators = []
    seen_names = set()
    for ind in all_indicators:
        if ind["detected"] and ind["name"] not in seen_names:
            seen_names.add(ind["name"])
            severity_label = "low"
            if ind["severity"] >= 0.7:
                severity_label = "high"
            elif ind["severity"] >= 0.4:
                severity_label = "medium"
            detected_indicators.append({
                "name": ind["name"],
                "severity": severity_label,
                "explanation": ind["explanation"],
            })

    # ML indicator
    if social_ml.get("available") and social_prob is not None and social_prob >= 0.5:
        detected_indicators.insert(0, {
            "name": "Looks Like a Scam Post",
            "severity": "high" if social_prob >= 0.7 else "medium",
            "explanation": f"Our model is {social_prob*100:.1f}% sure this post is a scam based on patterns from over 121,000 real messages.",
        })

    # Financial content indicator
    if is_financial:
        amount_part = f" It mentions {extracted_amount:.8g} in crypto or ${extracted_amount:.2f}." if extracted_amount > 0 else ""
        detected_indicators.append({
            "name": "Asks for Money or Crypto",
            "severity": "medium",
            "explanation": (
                f"This post references financial transactions, cryptocurrency, or payment requests.{amount_part} "
                f"Don't send money or crypto to anyone you met online without verifying them through a trusted channel."
            ),
        })

    if fraud_prob is not None and fraud_prob >= 0.3:
        detected_indicators.insert(0, {
            "name": "High Risk: Financial Fraud Likely",
            "severity": "high" if fraud_prob >= 0.6 else "medium",
            "explanation": f"Fraud patterns detected at {fraud_prob*100:.1f}% confidence. Do not send any money or crypto.",
        })

    sub_scores = {
        "domain": domain_score,
        "structural": structural_score,
        "language": language_score,
        "ml": ml_score if ml_score is not None else 0,
    }
    if fraud_prob is not None:
        sub_scores["fraud_ml"] = round(fraud_prob * 100)

    return {
        "overall_score": overall_score,
        "label": label,
        "sub_scores": sub_scores,
        "indicators": detected_indicators,
        "education": education,
        "ml_status": "active" if (social_ml.get("available") or (fraud_result and fraud_result.get("available"))) else "unavailable",
        "ml_probability": social_ml.get("probability"),
        "fraud_probability": fraud_prob,
        "financial_content_detected": is_financial,
        "scan_type": "social",
        "scanned_input": content,
        "extracted_urls": extracted_urls[:5],
    }
