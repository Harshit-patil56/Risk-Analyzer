import requests
import hashlib
import base64
from config import GOOGLE_SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY, API_TIMEOUT


def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API.
    Returns: { api_name, is_threat, confidence, unavailable, error }
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"api_name": "google_safe_browsing", "is_threat": False, "confidence": 0, "unavailable": True, "error": "API key not configured"}

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "risk-analyzer", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(api_url, json=payload, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        return {
            "api_name": "google_safe_browsing",
            "is_threat": len(matches) > 0,
            "confidence": 1.0 if matches else 0.0,
            "unavailable": False,
            "error": None,
        }
    except Exception as e:
        return {"api_name": "google_safe_browsing", "is_threat": False, "confidence": 0, "unavailable": True, "error": str(e)}


def check_virustotal(url):
    """
    Check URL against VirusTotal API.
    Returns: { api_name, is_threat, confidence, unavailable, error }
    """
    if not VIRUSTOTAL_API_KEY:
        return {"api_name": "virustotal", "is_threat": False, "confidence": 0, "unavailable": True, "error": "API key not configured"}

    try:
        # URL must be base64 encoded for VT API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(api_url, headers=headers, timeout=API_TIMEOUT)

        if response.status_code == 404:
            # URL not in VT database — not necessarily safe, just unknown
            return {"api_name": "virustotal", "is_threat": False, "confidence": 0.0, "unavailable": False, "error": None}

        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1
        threat_ratio = (malicious + suspicious) / total if total > 0 else 0

        return {
            "api_name": "virustotal",
            "is_threat": threat_ratio > 0.1,
            "confidence": round(threat_ratio, 4),
            "unavailable": False,
            "error": None,
        }
    except Exception as e:
        return {"api_name": "virustotal", "is_threat": False, "confidence": 0, "unavailable": True, "error": str(e)}


def check_phishtank(url):
    """
    Check URL against PhishTank API (no API key required).
    Returns: { api_name, is_threat, confidence, unavailable, error }
    """
    try:
        api_url = "https://checkurl.phishtank.com/checkurl/"
        payload = {"url": url, "format": "json"}
        headers = {"User-Agent": "phishtank/risk-analyzer"}
        response = requests.post(api_url, data=payload, headers=headers, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        results = data.get("results", {})
        # in_database: URL exists in PhishTank DB
        # verified: community has reviewed it
        # valid: confirmed as actual phishing (True = is phish, False = not phish)
        in_db = results.get("in_database", False)
        verified = results.get("verified", False)
        valid = results.get("valid", False)
        is_phish = bool(in_db and verified and valid)
        return {
            "api_name": "phishtank",
            "is_threat": is_phish,
            "confidence": 1.0 if is_phish else 0.0,
            "unavailable": False,
            "error": None,
        }
    except Exception as e:
        return {"api_name": "phishtank", "is_threat": False, "confidence": 0, "unavailable": True, "error": str(e)}


def check_urlhaus(url):
    """
    Check URL against URLhaus API (no API key required).
    Returns: { api_name, is_threat, confidence, unavailable, error }
    """
    try:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": url}
        response = requests.post(api_url, data=payload, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        status = data.get("query_status", "no_results")
        is_threat = status == "listed"
        return {
            "api_name": "urlhaus",
            "is_threat": is_threat,
            "confidence": 1.0 if is_threat else 0.0,
            "unavailable": False,
            "error": None,
        }
    except Exception as e:
        return {"api_name": "urlhaus", "is_threat": False, "confidence": 0, "unavailable": True, "error": str(e)}


def check_all_apis(url):
    """
    Run all API checks and return results.
    Each check is independent — one failure doesn't block others.
    """
    results = [
        check_google_safe_browsing(url),
        check_virustotal(url),
        check_phishtank(url),
        check_urlhaus(url),
    ]
    return results
