function getApiBase() {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }

  if (process.env.NODE_ENV !== "production") {
    return "http://127.0.0.1:8000";
  }

  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return "http://127.0.0.1:8000";
    }
  }

  throw new Error("NEXT_PUBLIC_API_URL is not configured.");
}

export async function scanUrl(url) {
  const response = await fetch(`${getApiBase()}/scan/url`, {
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
  const response = await fetch(`${getApiBase()}/scan/email`, {
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

export async function scanSocial(content) {
  const response = await fetch(`${getApiBase()}/scan/social`, {
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

  const response = await fetch(`${getApiBase()}/scan/qr`, {
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
  const response = await fetch(`${getApiBase()}/scan/bulk`, {
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

export async function scanTransaction(data) {
  const response = await fetch(`${getApiBase()}/scan/transaction`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.[0]?.msg || error.detail || "Transaction scan failed. Please try again.");
  }

  return response.json();
}
