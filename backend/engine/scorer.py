from config import SAFE_THRESHOLD, SUSPICIOUS_THRESHOLD


# Default weights when all layers are available
WEIGHTS_FULL = {
    "domain": 0.35,
    "structural": 0.25,
    "language": 0.20,
    "api": 0.20,
}

# Redistributed weights when API layer is unavailable
WEIGHTS_NO_API = {
    "domain": 0.44,
    "structural": 0.31,
    "language": 0.25,
    "api": 0.0,
}


def _classify_label(score):
    """Map overall score to risk label."""
    if score <= SAFE_THRESHOLD:
        return "safe"
    elif score <= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "dangerous"


def compute_domain_score(url_indicators, ml_result):
    """
    Compute domain risk sub-score (0-100) from URL heuristic indicators + ML prediction.
    Domain-related indicators: IP address, suspicious TLD, brand impersonation,
    excessive subdomains, URL shortener.
    """
    domain_indicator_names = {
        "IP Address Instead of Domain",
        "Suspicious Top-Level Domain",
        "Brand Impersonation",
        "Excessive Subdomains",
        "URL Shortener Detected",
    }

    relevant = [ind for ind in url_indicators if ind["name"] in domain_indicator_names and ind["detected"]]
    if not relevant:
        heuristic_score = 0
    else:
        max_severity = max(ind["severity"] for ind in relevant)
        avg_severity = sum(ind["severity"] for ind in relevant) / len(relevant)
        # Blend max and average — high-severity indicators dominate
        blended_severity = (max_severity * 0.6) + (avg_severity * 0.4)
        # More aggressive count boost
        count_boost = min(1.0, 0.5 + len(relevant) * 0.2)
        heuristic_score = blended_severity * 100 * count_boost

    # Blend with ML if available
    if ml_result and ml_result.get("available") and ml_result["probability"] is not None:
        ml_score = ml_result["probability"] * 100
        # Weighted blend: 60% heuristic, 40% ML
        blended = (heuristic_score * 0.6) + (ml_score * 0.4)
    else:
        blended = heuristic_score

    return min(100, max(0, round(blended)))


def compute_structural_score(url_indicators):
    """
    Compute structural risk sub-score (0-100).
    Structural indicators: URL length, @, encoding, suspicious paths, missing HTTPS.
    """
    structural_names = {
        "Excessive URL Length",
        "@ Symbol in URL",
        "URL Encoding / Obfuscation",
        "Suspicious Path Keywords",
        "Missing HTTPS",
    }

    relevant = [ind for ind in url_indicators if ind["name"] in structural_names and ind["detected"]]
    if not relevant:
        return 0

    max_severity = max(ind["severity"] for ind in relevant)
    avg_severity = sum(ind["severity"] for ind in relevant) / len(relevant)
    blended_severity = (max_severity * 0.6) + (avg_severity * 0.4)
    count_boost = min(1.0, 0.5 + len(relevant) * 0.2)
    score = blended_severity * 100 * count_boost
    return min(100, max(0, round(score)))


def compute_language_score(email_indicators):
    """
    Compute language risk sub-score (0-100).
    From email heuristic indicators.
    """
    if not email_indicators:
        return 0

    relevant = [ind for ind in email_indicators if ind["detected"]]
    if not relevant:
        return 0

    avg_severity = sum(ind["severity"] for ind in relevant) / len(relevant)
    count_boost = min(1.0, len(relevant) * 0.2)
    score = avg_severity * 100 * count_boost
    return min(100, max(0, round(score)))


def compute_api_score(api_results):
    """
    Compute API reputation sub-score (0-100).
    Returns score and availability status.
    """
    available_results = [r for r in api_results if not r.get("unavailable", True)]
    if not available_results:
        return 0, False

    threat_count = sum(1 for r in available_results if r["is_threat"])
    total_checked = len(available_results)

    # Weighted by confidence
    total_confidence = sum(r["confidence"] for r in available_results if r["is_threat"])

    if threat_count == 0:
        return 0, True

    # Base score from threat ratio + confidence
    threat_ratio = threat_count / total_checked
    score = (threat_ratio * 60) + (total_confidence / threat_count * 40)
    return min(100, max(0, round(score))), True


def compute_overall_score(domain_score, structural_score, language_score, api_score, api_available):
    """
    Compute weighted overall risk score (0-100) and label.
    """
    weights = WEIGHTS_FULL if api_available else WEIGHTS_NO_API

    overall = (
        domain_score * weights["domain"]
        + structural_score * weights["structural"]
        + language_score * weights["language"]
        + api_score * weights["api"]
    )

    overall = min(100, max(0, round(overall)))
    label = _classify_label(overall)

    return overall, label


def generate_education(indicators, label):
    """
    Generate educational feedback based on detected indicators and risk label.
    """
    education = []

    # Map indicator names to educational content
    education_map = {
        "IP Address Instead of Domain": {
            "title": "Why IP addresses in URLs are suspicious",
            "content": "Legitimate websites use domain names (like google.com) not raw IP addresses. If you see numbers like 192.168.1.1 in a URL, it is likely trying to bypass domain-based security filters."
        },
        "Suspicious Top-Level Domain": {
            "title": "Understanding domain extensions",
            "content": "Domain extensions like .xyz, .tk, or .ml are inexpensive and commonly used for temporary phishing sites. Trusted sites typically use .com, .org, .gov, or country-specific domains."
        },
        "Brand Impersonation": {
            "title": "How to spot fake brand domains",
            "content": "Phishers create domains that look like real brands (e.g., 'paypa1.com' instead of 'paypal.com'). Always check the domain spelling carefully before entering any information."
        },
        "Missing HTTPS": {
            "title": "Why HTTPS matters",
            "content": "HTTPS encrypts your connection. If a site asks for login or payment info without HTTPS (no lock icon), your data could be intercepted. Never enter sensitive information on HTTP sites."
        },
        "Urgency Language Detected": {
            "title": "Recognizing pressure tactics",
            "content": "Phishing messages create panic with phrases like 'Act now!' or 'Your account will be suspended.' Legitimate companies give you time to respond and never threaten immediate consequences via email."
        },
        "Request for Sensitive Information": {
            "title": "When to share personal information",
            "content": "Banks and legitimate services never ask for passwords, credit card numbers, or SSNs via email. If a message asks for this, it is almost certainly a scam."
        },
        "URL Shortener Detected": {
            "title": "Hidden destinations behind short links",
            "content": "URL shorteners (bit.ly, tinyurl) hide the real destination. Before clicking, use a URL expander tool to see where the link actually goes."
        },
        "Excessive URL Length": {
            "title": "Why long URLs can be suspicious",
            "content": "Extremely long URLs often contain hidden parameters or encoded redirects designed to confuse you and bypass security tools."
        },
        "Generic Greeting": {
            "title": "Impersonal messages are a red flag",
            "content": "Emails that start with 'Dear Customer' instead of your name are often mass-sent phishing attempts. Your bank and other services know your name."
        },
        "@ Symbol in URL": {
            "title": "The @ symbol trick in URLs",
            "content": "An '@' in a URL tells the browser to ignore everything before it and go to what follows. So 'http://google.com@evil.com' actually takes you to evil.com."
        },
    }

    detected_names = [ind["name"] for ind in indicators if ind["detected"]]
    for name in detected_names:
        if name in education_map:
            education.append(education_map[name])

    # Always add a general safety tip
    if label == "safe":
        education.append({
            "title": "Good practice: Always verify before trusting",
            "content": "Even though this appears safe, always verify the sender and URL before entering personal information. Bookmark important sites and access them directly."
        })
    elif label in ("suspicious", "dangerous"):
        education.append({
            "title": "What to do with suspicious content",
            "content": "Do not click any links or download attachments. If this claims to be from a company you use, go directly to their website by typing the address yourself. Report the suspicious content to the claimed organization."
        })

    return education
