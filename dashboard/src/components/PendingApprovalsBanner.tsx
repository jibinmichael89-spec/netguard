import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { UserCheck } from "lucide-react";
import { apiFetch } from "../api";
import type { PendingDevicesResponse } from "../types";

export default function PendingApprovalsBanner() {
  const [pending, setPending] = useState<PendingDevicesResponse["devices"]>([]);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<PendingDevicesResponse>("/devices/pending-approval");
      setPending(res.devices);
    } catch {
      setPending([]);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (pending.length === 0) return null;

  return (
    <div className="rounded-xl border border-ng-warning/40 bg-ng-warning/10 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <UserCheck className="h-5 w-5 text-ng-warning" />
          <p className="font-medium text-white">
            {pending.length} new device{pending.length === 1 ? "" : "s"} waiting for approval
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {pending.slice(0, 3).map((device) => (
            <Link
              key={device.id}
              to={`/device/${device.ip_address}`}
              className="rounded-lg border border-ng-border bg-ng-elevated px-3 py-1.5 text-sm text-ng-accent hover:border-ng-accent/40"
            >
              {device.hostname || device.ip_address}
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
