import re
from urllib.parse import urlparse


# Known suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".work", ".info", ".click", ".link", ".support",
    ".review", ".country", ".stream", ".download", ".racing",
    ".win", ".bid", ".accountant", ".science", ".party",
}

# URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io", "tiny.cc",
}

# Common brand targets for typosquatting
BRAND_TARGETS = {
    "paypal": ["paypa1", "paypol", "paypaI", "pay-pal", "paypall", "paypal-secure"],
    "google": ["go0gle", "googl3", "g00gle", "goog1e", "google-verify"],
    "apple": ["app1e", "appie", "apple-id", "appl3"],
    "microsoft": ["micros0ft", "mlcrosoft", "microsft", "microsoft-verify"],
    "amazon": ["amaz0n", "arnazon", "amazon-secure", "arnazon"],
    "netflix": ["netf1ix", "netfllx", "netflix-account"],
    "facebook": ["faceb00k", "facebok", "facebook-login"],
    "instagram": ["1nstagram", "lnstagram", "instagram-verify"],
    "linkedin": ["l1nkedin", "linkedln", "linkedin-verify"],
    "chase": ["chas3", "chase-secure", "chase-verify"],
    "wellsfargo": ["we11sfargo", "wellsfarg0", "wells-fargo-secure"],
    "bankofamerica": ["bankofamer1ca", "bank0famerica"],
}

# Urgency keywords (for emails and URL paths)
URGENCY_KEYWORDS = [
    "verify now", "act immediately", "suspended", "unauthorized",
    "confirm your", "update your", "expire", "urgent", "immediately",
    "click here", "limited time", "account locked", "security alert",
    "verify your identity", "unusual activity", "confirm identity",
    "reset your password", "action required", "final warning",
    "your account will be", "failure to", "within 24 hours",
    "within 48 hours", "deactivated", "restricted",
]


def analyze_url_heuristics(url):
    """
    Run heuristic checks on a URL.
    Returns a list of indicator dicts.
    """
    indicators = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_lower = url.lower()

    # 1. URL length check
    if len(url) > 75:
        indicators.append({
            "name": "Excessive URL Length",
            "detected": True,
            "severity": min(1.0, (len(url) - 75) / 100),
            "explanation": f"This URL is {len(url)} characters long. Scammers pad URLs with extra gibberish to bury the real destination."
        })

    # 2. IP address in URL
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        indicators.append({
            "name": "IP Address Instead of Domain",
            "detected": True,
            "severity": 0.85,
            "explanation": "Real websites use a name like 'google.com', not a raw number. If you see an IP address in a link, don't click it."
        })

    # 3. No HTTPS
    if parsed.scheme != "https":
        indicators.append({
            "name": "Missing HTTPS",
            "detected": True,
            "severity": 0.6,
            "explanation": "This link isn't encrypted. Any real bank, shop, or login page uses HTTPS — this one doesn't."
        })

    # 4. Suspicious TLD
    tld = ""
    if "." in hostname:
        tld = "." + hostname.rsplit(".", 1)[-1]
    if tld.lower() in SUSPICIOUS_TLDS:
        indicators.append({
            "name": "Suspicious Top-Level Domain",
            "detected": True,
            "severity": 0.7,
            "explanation": f"The '{tld}' ending is a red flag — it's a cheap domain extension heavily used by scammers."
        })

    # 5. URL shortener
    if hostname.lower() in SHORTENER_DOMAINS:
        indicators.append({
            "name": "URL Shortener Detected",
            "detected": True,
            "severity": 0.5,
            "explanation": "The link is shortened so you can't see where it actually goes. Scammers use this to hide dangerous URLs."
        })

    # 6. Excessive subdomains
    subdomain_count = max(0, hostname.count(".") - 1) if hostname else 0
    if subdomain_count >= 3:
        indicators.append({
            "name": "Excessive Subdomains",
            "detected": True,
            "severity": min(1.0, subdomain_count * 0.2),
            "explanation": f"This URL stacks {subdomain_count} subdomains — a trick to make a fake site look like it belongs to a real company."
        })

    # 7. @ symbol in URL
    if "@" in url:
        indicators.append({
            "name": "@ Symbol in URL",
            "detected": True,
            "severity": 0.9,
            "explanation": "Everything before the '@' in a URL is ignored by your browser — so 'paypal.com@evil.com' takes you to evil.com, not PayPal."
        })

    # 8. Brand impersonation / typosquatting
    for brand, variants in BRAND_TARGETS.items():
        for variant in variants:
            if variant.lower() in hostname.lower() and brand not in hostname.lower():
                indicators.append({
                    "name": "Brand Impersonation",
                    "detected": True,
                    "severity": 0.95,
                    "explanation": f"This domain is pretending to be {brand}. '{variant}' is a fake — one letter swapped hoping you won't notice."
                })
                break
        else:
            continue
        break

    # 9. Suspicious path keywords
    suspicious_paths = ["login", "signin", "verify", "secure", "account", "banking", "update", "confirm"]
    path_lower = path.lower()
    found_path_keywords = [kw for kw in suspicious_paths if kw in path_lower]
    if found_path_keywords and any(ind["name"] in ["Suspicious Top-Level Domain", "Brand Impersonation", "Missing HTTPS"] for ind in indicators):
        indicators.append({
            "name": "Suspicious Path Keywords",
            "detected": True,
            "severity": 0.6,
            "explanation": f"The path uses words like '{', '.join(found_path_keywords)}' to look like a login or account page, while the domain itself already looks fake."
        })

    # 10. Double extension or encoded characters
    if "%2" in url or "%3" in url or ".." in path:
        indicators.append({
            "name": "URL Encoding / Obfuscation",
            "detected": True,
            "severity": 0.7,
            "explanation": "Parts of this URL are scrambled with encoding. That's usually done to disguise where a link actually leads."
        })

    return indicators


def analyze_email_heuristics(content):
    """
    Run heuristic checks on email text content.
    Returns a list of indicator dicts.
    """
    indicators = []
    content_lower = content.lower()

    # 1. Urgency language
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in content_lower]
    if found_urgency:
        severity = min(1.0, len(found_urgency) * 0.15)
        indicators.append({
            "name": "Urgency Language Detected",
            "detected": True,
            "severity": severity,
            "explanation": f"This message tries to panic you with words like '{', '.join(found_urgency[:3])}'. That pressure is designed to make you click before you think."
        })

    # 2. Extract URLs from email content
    urls_in_email = re.findall(r'https?://[^\s<>"\']+', content)
    if len(urls_in_email) > 3:
        indicators.append({
            "name": "Multiple URLs in Message",
            "detected": True,
            "severity": 0.4,
            "explanation": f"There are {len(urls_in_email)} links crammed into this message. Scam emails carpet-bomb links hoping one gets clicked."
        })

    # 3. Mismatched display text vs URL (basic check)
    link_pattern = re.findall(r'(https?://[^\s]+)\s*(?:click here|verify|login|sign in)', content_lower)
    if link_pattern:
        indicators.append({
            "name": "Suspicious Link Context",
            "detected": True,
            "severity": 0.6,
            "explanation": "A link in here uses 'click here' or 'verify' as the bait. That combo is a textbook phishing move."
        })

    # 4. Request for sensitive info
    sensitive_keywords = [
        "password", "credit card", "social security", "ssn", "bank account",
        "routing number", "pin number", "date of birth", "mother's maiden",
    ]
    found_sensitive = [kw for kw in sensitive_keywords if kw in content_lower]
    if found_sensitive:
        indicators.append({
            "name": "Request for Sensitive Information",
            "detected": True,
            "severity": 0.85,
            "explanation": f"This message is asking for your {', '.join(found_sensitive[:3])}. No real company asks for that by email — ever."
        })

    # 5. Generic greeting
    generic_greetings = ["dear customer", "dear user", "dear sir", "dear account holder", "dear valued"]
    if any(g in content_lower for g in generic_greetings):
        indicators.append({
            "name": "Generic Greeting",
            "detected": True,
            "severity": 0.35,
            "explanation": "It says 'Dear Customer' instead of your actual name. Real companies know who you are."
        })

    # 6. Threatening language
    threats = ["will be terminated", "will be closed", "will be suspended", "legal action", "law enforcement"]
    found_threats = [t for t in threats if t in content_lower]
    if found_threats:
        indicators.append({
            "name": "Threatening Language",
            "detected": True,
            "severity": 0.7,
            "explanation": f"This message threatens that your account will be '{found_threats[0]}'. Scammers do this to make you act before you think."
        })

    return indicators, urls_in_email
