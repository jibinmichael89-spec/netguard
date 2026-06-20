import { useMemo } from "react";
import { API_BASE_URL } from "../config";

export type SystemType = "windows" | "pi" | "unknown";

export interface SystemDetection {
  isLocalhost: boolean;
  isPi: boolean;
  systemType: SystemType;
}

function isPrivateLanIp(hostname: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return false;
  }

  const [a, b] = hostname.split(".").map(Number);
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function detectSystem(): SystemDetection {
  const hostname = window.location.hostname.toLowerCase();
  const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";

  const apiTarget = (API_BASE_URL || window.location.origin).toLowerCase();
  const isNgrok =
    apiTarget.includes(".ngrok") || hostname.includes("ngrok");
  const isPiHost =
    hostname.includes("raspberrypi") || isPrivateLanIp(hostname);

  if (isLocalhost) {
    return { isLocalhost: true, isPi: false, systemType: "windows" };
  }

  if (isNgrok || isPiHost) {
    return { isLocalhost: false, isPi: true, systemType: "pi" };
  }

  return { isLocalhost: false, isPi: false, systemType: "unknown" };
}

export function useSystemDetection(): SystemDetection {
  return useMemo(() => detectSystem(), []);
}
