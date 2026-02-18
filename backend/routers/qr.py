"""
QR code scanning endpoint — decodes QR image to extract URL,
follows redirects to find the final destination, then scans it.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from PIL import Image
import requests as http_requests
import io

router = APIRouter()


def decode_qr(image_bytes):
    """Decode QR code from image bytes using pyzbar."""
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        img = Image.open(io.BytesIO(image_bytes))
        results = pyzbar_decode(img)
        if not results:
            return None
        # Return the first QR code data as string
        return results[0].data.decode("utf-8")
    except Exception as e:
        raise ValueError(f"QR decode failed: {str(e)}")


def follow_redirects(url):
    """
    Follow the full redirect chain to find the final destination URL.
    Returns (final_url, redirect_count).
    """
    try:
        response = http_requests.head(
            url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        return response.url, len(response.history)
    except http_requests.exceptions.TooManyRedirects:
        return url, 0
    except Exception:
        # If HEAD fails, try GET (some servers don't support HEAD)
        try:
            response = http_requests.get(
                url,
                allow_redirects=True,
                timeout=10,
                stream=True,  # Don't download full body
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            final = response.url
            count = len(response.history)
            response.close()
            return final, count
        except Exception:
            return url, 0


@router.post("/qr")
async def scan_qr(file: UploadFile = File(...)):
    """
    Upload a QR code image. Extracts the URL, follows redirects
    to find the real destination, then scans it.
    """
    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image (PNG, JPG, etc.)")

    # Read file
    image_bytes = await file.read()
    if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="Image too large (max 10MB)")

    # Decode QR
    try:
        extracted_url = decode_qr(image_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not extracted_url:
        raise HTTPException(status_code=400, detail="No QR code found in image")

    # Add scheme if missing
    if not extracted_url.startswith(("http://", "https://")):
        extracted_url = "http://" + extracted_url

    # Follow redirects to find the real destination
    final_url, redirect_count = follow_redirects(extracted_url)

    # Scan the final destination URL (not the redirect wrapper)
    scan_target = final_url if final_url != extracted_url else extracted_url

    from routers.scan import scan_url, UrlScanRequest

    try:
        request = UrlScanRequest(url=scan_target)
        result = scan_url(request)
        result["qr_extracted_url"] = extracted_url
        result["qr_final_url"] = final_url
        result["qr_redirect_count"] = redirect_count
        result["scan_type"] = "qr"
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
