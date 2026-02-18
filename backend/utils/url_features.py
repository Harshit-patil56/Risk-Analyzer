import re
import math
from urllib.parse import urlparse


def _shannon_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url):
    """
    Extract numerical features from a URL for the ML model.
    Returns a dict of feature_name -> float.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Basic length features
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)

    # Character counts
    digit_count = sum(1 for c in url if c.isdigit())
    letter_count = sum(1 for c in url if c.isalpha())
    special_count = sum(1 for c in url if not c.isalnum() and c not in ":/.")

    # Structural features
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    underscore_count = url.count("_")
    slash_count = url.count("/") - 2  # subtract protocol slashes
    at_count = url.count("@")
    question_count = url.count("?")
    ampersand_count = url.count("&")
    equals_count = url.count("=")

    # Domain features
    subdomain_count = max(0, hostname.count(".") - 1) if hostname else 0
    path_depth = len([p for p in path.split("/") if p])
    query_param_count = len([q for q in query.split("&") if q]) if query else 0

    # Boolean features (as 0/1)
    has_https = 1 if parsed.scheme == "https" else 0
    has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0

    # Entropy
    domain_entropy = _shannon_entropy(hostname)

    # Ratios
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    special_ratio = special_count / url_length if url_length > 0 else 0

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "special_count": special_count,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": max(0, slash_count),
        "at_count": at_count,
        "question_count": question_count,
        "ampersand_count": ampersand_count,
        "equals_count": equals_count,
        "subdomain_count": subdomain_count,
        "path_depth": path_depth,
        "query_param_count": query_param_count,
        "has_https": has_https,
        "has_ip": has_ip,
        "domain_entropy": domain_entropy,
        "digit_ratio": round(digit_ratio, 4),
        "special_ratio": round(special_ratio, 4),
    }


# Ordered list of feature names — must match training order
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "digit_count",
    "letter_count",
    "special_count",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "at_count",
    "question_count",
    "ampersand_count",
    "equals_count",
    "subdomain_count",
    "path_depth",
    "query_param_count",
    "has_https",
    "has_ip",
    "domain_entropy",
    "digit_ratio",
    "special_ratio",
]


def url_features_to_array(features_dict):
    """Convert features dict to ordered array for model prediction."""
    return [features_dict[name] for name in FEATURE_NAMES]
