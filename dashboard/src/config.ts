/** NetGuard API base URL — empty in production (API serves the dashboard) */
export const API_BASE_URL = import.meta.env.DEV ? "http://localhost:8000" : "";

/** Devices first seen within this window are tagged as NEW */
export const NEW_DEVICE_WINDOW_HOURS = 24;

/** Dashboard auto-refresh interval (ms) */
export const DASHBOARD_REFRESH_MS = 30_000;

/** DNS page auto-refresh interval (ms) */
export const DNS_REFRESH_MS = 10_000;

/** Device detail port scan fetch timeout (ms) */
export const PORT_FETCH_TIMEOUT_MS = 5_000;
