from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
import re

from engine.heuristics import analyze_url_heuristics, analyze_email_heuristics
from engine.ml_model import predict_phishing_probability
from engine.api_checker import check_all_apis
from engine.intel import gather_url_intel
from engine.scorer import (
    compute_domain_score,
    compute_structural_score,
    compute_language_score,
    compute_api_score,
    compute_overall_score,
    generate_education,
)

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


def _build_api_status(api_results):
    """Convert API results to status dict for response."""
    status = {}
    for result in api_results:
        name = result["api_name"]
        status[name] = "unavailable" if result.get("unavailable") else "available"
    return status


@router.post("/url")
def scan_url(request: UrlScanRequest):
    """Scan a URL for phishing indicators."""
    url = request.url

    # Layer 1: Heuristic analysis
    url_indicators = analyze_url_heuristics(url)

    # Layer 2: ML prediction (DISABLED — using heuristics + API only)
    ml_result = {"available": False, "probability": None}

    # Layer 3: External API checks
    api_results = check_all_apis(url)

    # Compute sub-scores
    domain_score = compute_domain_score(url_indicators, ml_result)
    structural_score = compute_structural_score(url_indicators)
    language_score = 0  # No language analysis for plain URL scan
    api_score, api_available = compute_api_score(api_results)

    # Compute overall
    overall_score, label = compute_overall_score(
        domain_score, structural_score, language_score, api_score, api_available
    )

    # Generate education
    education = generate_education(url_indicators, label)

    # Build indicator list for response (only detected ones)
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

    # Layer 4: URL Intelligence gathering
    intel = gather_url_intel(url)

    return {
        "overall_score": overall_score,
        "label": label,
        "sub_scores": {
            "domain": domain_score,
            "structural": structural_score,
            "language": language_score,
            "api_reputation": api_score,
        },
        "indicators": detected_indicators,
        "education": education,
        "api_status": _build_api_status(api_results),
        "ml_status": "disabled",
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

    # Layer 1b + 2 + 3: Analyze extracted URLs
    all_url_indicators = []
    all_api_results = []
    ml_result = {"available": False, "probability": None}

    for url in extracted_urls[:5]:  # Limit to first 5 URLs
        url_inds = analyze_url_heuristics(url)
        all_url_indicators.extend(url_inds)

        # ML prediction disabled
        pass

        api_results = check_all_apis(url)
        all_api_results.extend(api_results)

    # Compute sub-scores
    domain_score = compute_domain_score(all_url_indicators, ml_result) if all_url_indicators else 0
    structural_score = compute_structural_score(all_url_indicators) if all_url_indicators else 0
    language_score = compute_language_score(email_indicators)

    # API score: aggregate all URL API results
    if all_api_results:
        api_score, api_available = compute_api_score(all_api_results)
    else:
        api_score, api_available = 0, False

    # Compute overall
    overall_score, label = compute_overall_score(
        domain_score, structural_score, language_score, api_score, api_available
    )

    # Combine all indicators
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

    # API status from first URL's results (if any)
    api_status = {}
    if all_api_results:
        api_status = _build_api_status(all_api_results[:4])

    return {
        "overall_score": overall_score,
        "label": label,
        "sub_scores": {
            "domain": domain_score,
            "structural": structural_score,
            "language": language_score,
            "api_reputation": api_score,
        },
        "indicators": detected_indicators,
        "education": education,
        "api_status": api_status,
        "ml_status": "disabled",
        "scan_type": "email",
        "scanned_input": content[:200] + ("..." if len(content) > 200 else ""),
        "extracted_urls": extracted_urls[:5],
    }
