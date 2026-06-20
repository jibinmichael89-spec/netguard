import { API_BASE_URL } from "../config";
import { apiFetch } from "../api";
import type { SystemInfoResponse } from "../types";

export type BlockPlatform = "windows" | "linux";

export function detectPlatformFallback(): BlockPlatform {
  const hostname = window.location.hostname.toLowerCase();

  if (hostname.includes("raspberrypi")) {
    return "linux";
  }

  if (hostname.includes("ngrok") || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return "linux";
  }

  if (import.meta.env.DEV && API_BASE_URL.includes("localhost")) {
    return "windows";
  }

  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return "windows";
  }

  return "linux";
}

export function normalizePlatform(info: SystemInfoResponse): BlockPlatform {
  return info.platform === "windows" ? "windows" : "linux";
}

export async function fetchSystemPlatform(): Promise<BlockPlatform> {
  try {
    const info = await apiFetch<SystemInfoResponse>("/system/info");
    return normalizePlatform(info);
  } catch {
    return detectPlatformFallback();
  }
}

export function getBlockModalMessage(
  isBlocked: boolean,
  platform: BlockPlatform,
): string {
  if (isBlocked) {
    return platform === "windows"
      ? "This device will reappear in the dashboard."
      : "This device will regain network access within ~5 seconds.";
  }

  return platform === "windows"
    ? "This will hide the device from the dashboard only. To actually disconnect devices, NetGuard must run on a Raspberry Pi with the network_blocker daemon active."
    : "This will immediately disconnect the device from the network (~5 seconds). The network_blocker daemon must be running. Are you sure?";
}

export function getBlockTooltip(platform: BlockPlatform): string {
  return platform === "windows"
    ? "Block = Dashboard filter only"
    : "Block = Network isolation (if daemon running)";
}
