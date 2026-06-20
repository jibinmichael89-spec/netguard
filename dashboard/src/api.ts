import { API_BASE_URL } from "./config";

const NGROK_HEADER = { "ngrok-skip-browser-warning": "true" };
const DEFAULT_TIMEOUT_MS = 10_000;

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
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

  return headers;
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  if (options.signal) {
    options.signal.addEventListener("abort", () => controller.abort());
  }

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: buildHeaders(options),
    });

    if (!response.ok) {
      throw new ApiError(`Request failed: ${response.statusText}`, response.status);
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
  options: RequestInit = {},
): Promise<T> {
  return apiFetch<T>(path, options, timeoutMs);
}
