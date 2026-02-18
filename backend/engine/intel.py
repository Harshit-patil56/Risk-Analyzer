"""
Intelligence gathering module — enriches scan results with domain/network intel.
All functions return dicts with real data only, no assumptions or placeholders.
"""

import socket
import ssl
import datetime
import requests
from urllib.parse import urlparse
from config import API_TIMEOUT


# ─── WHOIS Lookup ──────────────────────────────────────────────────────

def lookup_whois(url):
    """
    Get WHOIS data for the domain: registration date, expiry, registrar, domain age.
    Returns dict with real data or error.
    """
    try:
        import whois
        hostname = urlparse(url).hostname
        if not hostname:
            return {"available": False, "error": "Could not extract hostname"}

        w = whois.whois(hostname)

        # Extract creation date (sometimes a list)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Calculate domain age in days
        domain_age_days = None
        if creation_date and isinstance(creation_date, datetime.datetime):
            domain_age_days = (datetime.datetime.now() - creation_date).days

        return {
            "available": True,
            "domain_name": w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else hostname),
            "registrar": w.registrar or "Unknown",
            "creation_date": creation_date.isoformat() if creation_date and isinstance(creation_date, datetime.datetime) else None,
            "expiration_date": expiration_date.isoformat() if expiration_date and isinstance(expiration_date, datetime.datetime) else None,
            "domain_age_days": domain_age_days,
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "org": w.org or None,
            "country": w.country or None,
            "error": None,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


# ─── SSL Certificate Info ─────────────────────────────────────────────

def lookup_ssl(url):
    """
    Get SSL certificate info: issuer, expiry, validity.
    Only works for HTTPS URLs.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != "https":
            return {"available": False, "error": "URL is not HTTPS — no SSL certificate"}

        if not hostname:
            return {"available": False, "error": "Could not extract hostname"}

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=API_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return {"available": False, "error": "No certificate returned"}

        # Parse issuer
        issuer_parts = {}
        for rdn in cert.get("issuer", ()):
            for key, val in rdn:
                issuer_parts[key] = val

        # Parse subject
        subject_parts = {}
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                subject_parts[key] = val

        # Parse dates
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        not_before_dt = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z") if not_before else None
        not_after_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None

        is_expired = not_after_dt < datetime.datetime.utcnow() if not_after_dt else None

        return {
            "available": True,
            "subject": subject_parts.get("commonName", "Unknown"),
            "issuer": issuer_parts.get("organizationName", issuer_parts.get("commonName", "Unknown")),
            "issued_date": not_before_dt.isoformat() if not_before_dt else None,
            "expiry_date": not_after_dt.isoformat() if not_after_dt else None,
            "is_expired": is_expired,
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "error": None,
        }
    except ssl.SSLCertVerificationError as e:
        return {"available": True, "subject": None, "issuer": None, "issued_date": None, "expiry_date": None, "is_expired": True, "serial_number": None, "version": None, "error": f"SSL verification failed: {e}"}
    except Exception as e:
        return {"available": False, "error": str(e)}


# ─── URL Unshortening ─────────────────────────────────────────────────

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc",
}


def unshorten_url(url):
    """
    Follow redirects to find the final destination URL.
    Only processes known shortener domains to avoid unnecessary requests.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {"is_shortened": False, "final_url": url, "error": None}

        # Only unshorten known shortener domains
        if hostname not in SHORTENER_DOMAINS:
            return {"is_shortened": False, "final_url": url, "error": None}

        response = requests.head(url, allow_redirects=True, timeout=API_TIMEOUT,
                                  headers={"User-Agent": "Mozilla/5.0"})
        final_url = response.url

        return {
            "is_shortened": final_url != url,
            "final_url": final_url,
            "redirect_chain_length": len(response.history),
            "error": None,
        }
    except Exception as e:
        return {"is_shortened": False, "final_url": url, "error": str(e)}


# ─── DNS / IP Geolocation ─────────────────────────────────────────────

def lookup_dns_geo(url):
    """
    Resolve domain to IP, then get geolocation from ip-api.com (free, no key).
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return {"available": False, "error": "Could not extract hostname"}

        # Resolve DNS
        ip_address = socket.gethostbyname(hostname)

        # Get geolocation from ip-api.com (free, 45 req/min)
        geo_response = requests.get(
            f"http://json.ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,isp,org,as",
            timeout=API_TIMEOUT
        )
        geo_data = geo_response.json()

        if geo_data.get("status") != "success":
            return {
                "available": True,
                "ip_address": ip_address,
                "country": None,
                "region": None,
                "city": None,
                "isp": None,
                "org": None,
                "error": geo_data.get("message", "Geolocation lookup failed"),
            }

        return {
            "available": True,
            "ip_address": ip_address,
            "country": geo_data.get("country"),
            "region": geo_data.get("regionName"),
            "city": geo_data.get("city"),
            "isp": geo_data.get("isp"),
            "org": geo_data.get("org"),
            "asn": geo_data.get("as"),
            "error": None,
        }
    except socket.gaierror:
        return {"available": False, "error": "DNS resolution failed — domain does not exist"}
    except Exception as e:
        return {"available": False, "error": str(e)}


# ─── Page Screenshot URL ──────────────────────────────────────────────

def get_screenshot_url(url):
    """
    Returns a screenshot URL using thum.io (free, no API key required).
    The frontend will load this URL as an image.
    """
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return {"available": False, "url": None, "error": "Invalid URL"}

        # thum.io provides free website screenshots
        screenshot_url = f"https://image.thum.io/get/width/600/crop/800/{url}"

        return {
            "available": True,
            "url": screenshot_url,
            "error": None,
        }
    except Exception as e:
        return {"available": False, "url": None, "error": str(e)}


# ─── Gather All Intel ────────────────────────────────────────────────

def gather_url_intel(url):
    """
    Run all intel gathering in one call.
    Returns a dict with all intel results keyed by type.
    """
    return {
        "whois": lookup_whois(url),
        "ssl": lookup_ssl(url),
        "dns_geo": lookup_dns_geo(url),
        "unshorten": unshorten_url(url),
        "screenshot": get_screenshot_url(url),
    }
