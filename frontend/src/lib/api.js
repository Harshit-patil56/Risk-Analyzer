const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.[0]?.msg || error.detail || "Scan failed. Please try again.");
  }

  return response.json();
}

export async function scanEmail(content) {
  const response = await fetch(`${API_BASE}/scan/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.[0]?.msg || error.detail || "Scan failed. Please try again.");
  }

  return response.json();
}

export async function scanQr(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE}/scan/qr`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || "QR scan failed. Make sure the image contains a valid QR code.");
  }

  return response.json();
}

export async function scanBulk(urls) {
  const response = await fetch(`${API_BASE}/scan/bulk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.[0]?.msg || error.detail || "Bulk scan failed. Please try again.");
  }

  return response.json();
}
