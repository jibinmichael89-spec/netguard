import { API_BASE_URL } from "./config";

const NGROK_HEADER = { "ngrok-skip-browser-warning": "true" };
const DEFAULT_TIMEOUT_MS = 10_000;
const API_KEY_STORAGE = "netguard_api_key";

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export type ApiFetchOptions = RequestInit & {
  /** Attach X-API-Key from localStorage on GET (e.g. /settings/api-key). */
  requireAuth?: boolean;
};

export function getStoredApiKey(): string | null {
  try {
    const key = localStorage.getItem(API_KEY_STORAGE);
    return key?.trim() ? key : null;
  } catch {
    return null;
  }
}

export function setStoredApiKey(key: string): void {
  try {
    localStorage.setItem(API_KEY_STORAGE, key.trim());
  } catch {
    /* private browsing or storage disabled */
  }
}

export function clearStoredApiKey(): void {
  try {
    localStorage.removeItem(API_KEY_STORAGE);
  } catch {
    /* ignore */
  }
}

function buildHeaders(options: RequestInit): HeadersInit {
  const headers: Record<string, string> = { ...NGROK_HEADER };

  if (options.body) {
    headers["Content-Type"] = "application/json";
  }

  if (options.headers) {
    const extra =
      options.headers instanceof Headers
        ? Object.fromEntries(options.headers.entries())
        : (options.headers as Record<string, string>);
    Object.assign(headers, extra);
  }

  if (!headers["X-API-Key"]) {
    const stored = getStoredApiKey();
    if (stored) {
      headers["X-API-Key"] = stored;
    }
  }

  return headers;
}

export async function apiFetch<T>(
  path: string,
  options: ApiFetchOptions = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const { requireAuth: _requireAuth, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  if (fetchOptions.signal) {
    fetchOptions.signal.addEventListener("abort", () => controller.abort());
  }

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...fetchOptions,
      signal: controller.signal,
      headers: buildHeaders(fetchOptions),
    });

    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = (await response.json()) as { detail?: string };
        if (typeof body.detail === "string" && body.detail.trim()) {
          detail = body.detail;
        }
      } catch {
        /* response body was not JSON */
      }
      throw new ApiError(detail, response.status);
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    if (
      error instanceof Error &&
      (error.name === "AbortError" || error.message.includes("aborted"))
    ) {
      throw new ApiError("Request timed out — is the API running on port 8000?");
    }
    throw new ApiError(
      error instanceof Error ? error.message : "Network request failed",
    );
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function apiFetchWithTimeout<T>(
  path: string,
  timeoutMs: number,
  options: ApiFetchOptions = {},
): Promise<T> {
  return apiFetch<T>(path, options, timeoutMs);
}

export async function downloadComplianceReport(
  startDate?: string,
  endDate?: string,
): Promise<void> {
  const params = new URLSearchParams();
  if (startDate) {
    params.set("start_date", startDate);
  }
  if (endDate) {
    params.set("end_date", endDate);
  }
  const query = params.toString();
  const path = `/reports/compliance/generate${query ? `?${query}` : ""}`;

  const headers: Record<string, string> = { ...NGROK_HEADER };
  const apiKey = getStoredApiKey();
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (typeof body.detail === "string" && body.detail.trim()) {
        detail = body.detail;
      }
    } catch {
      /* response body was not JSON */
    }
    throw new ApiError(detail, response.status);
  }

  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] ?? "netguard-compliance-report.pdf";

  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}
