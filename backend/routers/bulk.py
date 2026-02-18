"""
Bulk URL scanning endpoint — scans multiple URLs at once.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import List
from routers.scan import scan_url, UrlScanRequest

router = APIRouter()


class BulkScanRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError("URL list cannot be empty")
        if len(v) > 10:
            raise ValueError("Maximum 10 URLs per bulk scan")
        # Clean each URL
        cleaned = []
        for url in v:
            url = url.strip()
            if url:
                cleaned.append(url)
        if not cleaned:
            raise ValueError("No valid URLs provided")
        return cleaned


@router.post("/bulk")
def scan_bulk(request: BulkScanRequest):
    """
    Scan multiple URLs at once. Returns a list of scan results.
    Limited to 10 URLs per request.
    """
    results = []
    for url in request.urls:
        try:
            url_request = UrlScanRequest(url=url)
            result = scan_url(url_request)
            results.append(result)
        except Exception as e:
            results.append({
                "overall_score": None,
                "label": "error",
                "scanned_input": url,
                "error": str(e),
            })

    # Summary stats
    valid_results = [r for r in results if r.get("overall_score") is not None]
    summary = {
        "total": len(results),
        "scanned": len(valid_results),
        "errors": len(results) - len(valid_results),
        "avg_score": round(sum(r["overall_score"] for r in valid_results) / len(valid_results)) if valid_results else 0,
        "highest_risk": max((r["overall_score"] for r in valid_results), default=0),
        "distribution": {
            "safe": sum(1 for r in valid_results if r.get("label") == "safe"),
            "suspicious": sum(1 for r in valid_results if r.get("label") == "suspicious"),
            "dangerous": sum(1 for r in valid_results if r.get("label") == "dangerous"),
        },
    }

    return {
        "summary": summary,
        "results": results,
    }
