import type { SystemType } from "../hooks/useSystemDetection";

export function getBlockConfirmMessage(systemType: SystemType): string {
  const routerHint =
    "If router enforcement is configured in Settings → Router, the device will be paused on your router (Linksys/OpenWrt).";

  if (systemType === "windows") {
    return `${routerHint} Otherwise it is marked blocked in the dashboard only. Continue?`;
  }

  if (systemType === "pi") {
    return `${routerHint} On Pi without router API, ARP network blocker may disconnect the device (~5 seconds). Mesh WiFi may limit local blocking. Continue?`;
  }

  return `${routerHint} Continue?`;
}

export function getUnblockConfirmMessage(systemType: SystemType): string {
  if (systemType === "windows" || systemType === "pi") {
    return "This device will be unblocked in NetGuard and resumed on your router if router enforcement is configured.";
  }

  return "This device will be unblocked in NetGuard.";
}

export function getBlockTooltip(systemType: SystemType): string {
  if (systemType === "windows") {
    return "Block = Router pause (Linksys/OpenWrt) when configured, else dashboard filter";
  }

  if (systemType === "pi") {
    return "Block = Router pause or ARP isolation (if network blocker running)";
  }

  return "Block = Router enforcement when configured in Settings";
}
