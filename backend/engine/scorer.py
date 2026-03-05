from config import SAFE_THRESHOLD, SUSPICIOUS_THRESHOLD


# Weights when ML model is available (ML is primary signal)
WEIGHTS_ML = {
    "ml": 0.60,
    "domain": 0.22,
    "structural": 0.12,
    "language": 0.06,
}

# Fallback weights when ML is unavailable (heuristics only)
WEIGHTS_NO_ML = {
    "domain": 0.44,
    "structural": 0.31,
    "language": 0.25,
}


def _classify_label(score):
    """Map overall score to risk label."""
    if score <= SAFE_THRESHOLD:
        return "safe"
    elif score <= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "dangerous"


def compute_domain_score(url_indicators):
    """
    Compute domain risk sub-score (0-100) from URL heuristic indicators.
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
        return 0

    max_severity = max(ind["severity"] for ind in relevant)
    avg_severity = sum(ind["severity"] for ind in relevant) / len(relevant)
    blended_severity = (max_severity * 0.6) + (avg_severity * 0.4)
    count_boost = min(1.0, 0.5 + len(relevant) * 0.2)
    return min(100, max(0, round(blended_severity * 100 * count_boost)))


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


def compute_overall_score(domain_score, structural_score, language_score, ml_score=None):
    """
    Compute weighted overall risk score (0-100) and label.
    ML is the primary signal (60%) when available; heuristics fill the remainder.
    Without ML, falls back to pure heuristic weighting.
    """
    if ml_score is not None:
        overall = (
            ml_score * WEIGHTS_ML["ml"]
            + domain_score * WEIGHTS_ML["domain"]
            + structural_score * WEIGHTS_ML["structural"]
            + language_score * WEIGHTS_ML["language"]
        )
    else:
        overall = (
            domain_score * WEIGHTS_NO_ML["domain"]
            + structural_score * WEIGHTS_NO_ML["structural"]
            + language_score * WEIGHTS_NO_ML["language"]
        )

    overall = min(100, max(0, round(overall)))
    return overall, _classify_label(overall)


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
