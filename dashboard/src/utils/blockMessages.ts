import type { SystemType } from "../hooks/useSystemDetection";

export function getBlockConfirmMessage(systemType: SystemType): string {
  if (systemType === "windows") {
    return "This will hide the device from the dashboard only. To actually disconnect devices, NetGuard must run on a Raspberry Pi with the network_blocker daemon active. Continue?";
  }

  if (systemType === "pi") {
    return "This will immediately disconnect the device from the network (~5 seconds). The network_blocker daemon must be running. Continue?";
  }

  return "This will update the blocked status for this device. Continue?";
}

export function getUnblockConfirmMessage(systemType: SystemType): string {
  if (systemType === "windows") {
    return "This device will reappear in the dashboard.";
  }

  if (systemType === "pi") {
    return "This device will regain network access within ~5 seconds.";
  }

  return "This device will be unblocked in NetGuard.";
}

export function getBlockTooltip(systemType: SystemType): string {
  if (systemType === "windows") {
    return "Block = Dashboard filter only";
  }

  if (systemType === "pi") {
    return "Block = Network isolation (if daemon running)";
  }

  return "Block behavior depends on where NetGuard is running";
}
