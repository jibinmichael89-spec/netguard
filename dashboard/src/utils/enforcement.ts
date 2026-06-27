import { apiFetch } from "../api";

export interface EnforcementResponse {
  success: boolean;
  method: string;
  detail: string;
}

export async function enforceDeviceBlock(
  deviceIp: string,
): Promise<EnforcementResponse> {
  return apiFetch<EnforcementResponse>(
    `/enforcement/block/${encodeURIComponent(deviceIp)}`,
    { method: "POST" },
  );
}

export async function enforceDeviceUnblock(
  deviceIp: string,
): Promise<EnforcementResponse> {
  return apiFetch<EnforcementResponse>(
    `/enforcement/unblock/${encodeURIComponent(deviceIp)}`,
    { method: "POST" },
  );
}

export function formatEnforcementMessage(result: EnforcementResponse): string {
  if (result.success) {
    return `Network enforcement applied (${result.method}): ${result.detail}`;
  }
  return `Blocked in dashboard only — network enforcement failed (${result.method}): ${result.detail}`;
}
