const API_BASE = "http://127.0.0.1:8000";
const API_KEY = import.meta.env.VITE_API_KEY || "vapt-prod-key-9f8d7a6b123";

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        ...(options.headers || {})
      }
    });
  } catch {
    throw new Error("Network error: unable to reach backend at http://127.0.0.1:8000");
  }

  const rawBody = await response.text();
  let parsedBody = null;

  if (rawBody) {
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {
      parsedBody = rawBody;
    }
  }

  if (!response.ok) {
    const details =
      (parsedBody && typeof parsedBody === "object" && (parsedBody.detail || parsedBody.message)) ||
      (typeof parsedBody === "string" && parsedBody) ||
      "Request failed";
    throw new Error(`${response.status} ${response.statusText}: ${details}`);
  }

  if (response.status === 204 || !rawBody) {
    return null;
  }

  return parsedBody;
}

export function startScan(target) {
  return request("/api/v1/scan/start", {
    method: "POST",
    body: JSON.stringify({
      target,
      requested_tools: ["nmap", "sqlmap", "zap"]
    })
  });
}

export function getScanStatus(scanId) {
  return request(`/api/v1/scan/status/${scanId}`, {
    method: "GET"
  });
}

export function getScanResults(scanId) {
  return request(`/api/v1/scan/results/${scanId}`, {
    method: "GET"
  });
}

export function getScanReport(scanId) {
  return request(`/api/v1/scan/report/${scanId}`, {
    method: "GET"
  });
}

export function getScanGraph(scanId) {
  return request(`/api/v1/scan/graph/${scanId}`, {
    method: "GET"
  });
}
